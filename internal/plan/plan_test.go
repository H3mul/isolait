package plan

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func mustAdd(t *testing.T, p *Plan, es ...Entry) {
	t.Helper()
	for _, e := range es {
		if err := p.Add(e); err != nil {
			t.Fatalf("Add(%+v): %v", e, err)
		}
	}
}

func TestArgsRenderExactly(t *testing.T) {
	var p Plan
	mustAdd(t, &p,
		Entry{Kind: RoBind, Src: "/usr", Dst: "/usr"},
		Entry{Kind: Symlink, Src: "usr/bin", Dst: "/bin"},
		Entry{Kind: Dev, Dst: "/dev"},
		Entry{Kind: Proc, Dst: "/proc"},
		Entry{Kind: Tmpfs, Dst: "/tmp"},
		Entry{Kind: Dir, Dst: "/run"},
		Entry{Kind: Bind, Src: "/state/homes/claude", Dst: "/home/u"},
		Entry{Kind: Bind, Src: "/run/user/1000/isolait/api-a3f9/stage", Dst: "/workspaces"},
		Entry{Kind: Workspace, Src: "/home/u/api", Dst: "/workspaces/api"}, // broker-managed: not in argv
		Entry{Kind: Mask, Src: "/empty", Dst: "/workspaces/api/.isolait"},
	)
	want := []string{
		"--ro-bind", "/usr", "/usr",
		"--symlink", "usr/bin", "/bin",
		"--dev", "/dev",
		"--proc", "/proc",
		"--tmpfs", "/tmp",
		"--dir", "/run",
		"--bind", "/state/homes/claude", "/home/u",
		"--bind", "/run/user/1000/isolait/api-a3f9/stage", "/workspaces",
	}
	if got := p.Args(); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv\n got %v\nwant %v", got, want)
	}
	var dsts []string
	for _, m := range p.Mounts() {
		dsts = append(dsts, m.Dst)
	}
	wantMounts := []string{"/usr", "/dev", "/proc", "/tmp", "/home/u", "/workspaces", "/workspaces/api", "/workspaces/api/.isolait"}
	if !reflect.DeepEqual(dsts, wantMounts) {
		t.Fatalf("mounts %v want %v (symlinks and dirs are not mounts)", dsts, wantMounts)
	}
}

func TestAddRejects(t *testing.T) {
	base := Entry{Kind: RoBind, Src: "/usr", Dst: "/usr"}
	tests := []struct {
		name string
		e    Entry
		want string
	}{
		{"relative dst", Entry{Kind: Tmpfs, Dst: "tmp"}, "clean absolute"},
		{"unclean dst", Entry{Kind: Tmpfs, Dst: "/a/../b"}, "clean absolute"},
		{"root dst", Entry{Kind: Tmpfs, Dst: "/"}, "other than /"},
		{"relative src", Entry{Kind: RoBind, Src: "usr", Dst: "/x"}, "source"},
		{"unclean src", Entry{Kind: Bind, Src: "/a//b", Dst: "/x"}, "source"},
		{"duplicate", base, "already planned"},
		{"empty symlink", Entry{Kind: Symlink, Dst: "/l"}, "target"},
		{"unknown kind", Entry{Kind: "weird", Dst: "/w"}, "unknown kind"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var p Plan
			mustAdd(t, &p, base)
			if err := p.Add(tc.e); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want substring %q", err, tc.want)
			}
		})
	}

	var p Plan
	mustAdd(t, &p, Entry{Kind: Bind, Src: "/s", Dst: "/home/u/.local/share"})
	if err := p.Add(Entry{Kind: Bind, Src: "/h", Dst: "/home/u"}); err == nil || !strings.Contains(err.Error(), "shadow") {
		t.Fatalf("parent added after child must be rejected: %v", err)
	}
}

func TestRemove(t *testing.T) {
	var p Plan
	mustAdd(t, &p, Entry{Kind: Workspace, Src: "/w", Dst: "/workspaces/w"})
	if !p.Remove("/workspaces/w") || p.Remove("/workspaces/w") || len(p.Entries()) != 0 {
		t.Fatal("Remove")
	}
}

func TestEntriesIsACopy(t *testing.T) {
	var p Plan
	mustAdd(t, &p, Entry{Kind: Tmpfs, Dst: "/tmp"})
	p.Entries()[0].Dst = "/evil"
	if p.Entries()[0].Dst != "/tmp" {
		t.Fatal("callers can mutate the plan through Entries()")
	}
}

// Nothing may build bwrap mount arguments except this package: otherwise the plan, and the mountinfo check
// that trusts it, could silently diverge from what is mounted.
func TestNoMountArgumentsOutsidePlan(t *testing.T) {
	root, _ := filepath.Abs("../..")
	// Files allowed to name mount flags, each with the reason. Keep this list tiny.
	exempt := map[string]string{
		filepath.Join(root, "internal", "preflight", "system.go"): "throwaway probe sandbox that only checks bwrap can create a user namespace; it never runs an agent",
	}
	forbidden := []string{`"--bind"`, `"--ro-bind"`, `"--bind-try"`, `"--ro-bind-try"`, `"--dev-bind"`, `"--tmpfs"`, `"--proc"`, `"--dev"`, `"--symlink"`, `"--remount-ro"`, `"--ro-bind-data"`, `"--bind-data"`, `"--overlay"`, `"--ro-overlay"`, `"--tmp-overlay"`}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || path == filepath.Join(root, "internal", "plan")) {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || exempt[path] != "" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, f := range forbidden {
			if strings.Contains(string(b), f) {
				t.Errorf("%s builds the mount argument %s; render it from a plan.Plan instead", path, f)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
