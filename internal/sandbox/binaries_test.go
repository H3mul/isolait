package sandbox

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/H3mul/isolait/internal/plan"
)

func write(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func realTemp(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestAgentBehindSymlink(t *testing.T) {
	home := realTemp(t)
	real := filepath.Join(home, ".local/share/claude/versions/2.1.9")
	write(t, real, "#!/bin/sh\n", 0o755)
	mustSymlink(t, real, filepath.Join(home, ".local/bin/claude"))
	hostPath := filepath.Join(home, ".local/bin") + ":/usr/bin"

	b, err := ResolveBinaries(BinOptions{Agent: "claude", HostPath: hostPath, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	if b.Argv0 != real {
		t.Errorf("Argv0 %q want %q", b.Argv0, real)
	}
	// the resolved install root (its directory), not ~/.local/bin, is exposed and reported for status
	if want := []string{filepath.Dir(real)}; !slices.Equal(b.Roots, want) {
		t.Errorf("Roots %v want %v", b.Roots, want)
	}
	if b.PathDirs[0] != "/isolait/bin" {
		t.Errorf("agent link dir not first on PATH: %v", b.PathDirs)
	}
	var link plan.Entry
	for _, e := range b.Entries {
		if e.Kind == plan.Symlink {
			link = e
		}
	}
	if link.Dst != "/isolait/bin/claude" || link.Src != real {
		t.Errorf("agent symlink %+v", link)
	}
	// the generic bin directory the user launched it from is not part of the sandbox
	for _, e := range b.Entries {
		if strings.HasPrefix(e.Src, filepath.Join(home, ".local/bin")) {
			t.Errorf("exposed the launcher bin dir: %+v", e)
		}
	}
	var p plan.Plan
	if err := AddBinaries(&p, b); err != nil {
		t.Fatalf("entries do not form a valid plan: %v", err)
	}
}

func TestAgentInGenericBinDirBindsOnlyTheFile(t *testing.T) {
	home := realTemp(t)
	tool := filepath.Join(home, ".local/bin/mytool")
	write(t, tool, "#!/bin/sh\n", 0o755)
	write(t, filepath.Join(home, ".local/bin/other"), "#!/bin/sh\n", 0o755)
	b, err := ResolveBinaries(BinOptions{Agent: "mytool", HostPath: filepath.Dir(tool), Home: home})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(b.Roots, []string{tool}) {
		t.Errorf("Roots %v want only the file %s", b.Roots, tool)
	}
}

func TestAgentAlreadyInSystemDirs(t *testing.T) {
	b, err := ResolveBinaries(BinOptions{Agent: "sh", HostPath: os.Getenv("PATH")})
	if err != nil {
		t.Skip("no sh on this host PATH")
	}
	if len(b.Roots) != 0 || len(b.Entries) != 0 || slices.Contains(b.PathDirs, "/isolait/bin") {
		t.Errorf("system agent needs no extra exposure: %+v", b)
	}
	for _, d := range b.PathDirs {
		if !strings.HasPrefix(d, "/usr/") && d != "/bin" && d != "/sbin" {
			t.Errorf("PATH entry %q is not a system directory", d)
		}
	}
}

func TestAgentNotFound(t *testing.T) {
	if _, err := ResolveBinaries(BinOptions{Agent: "no-such-agent-xyz", HostPath: "/usr/bin"}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("got %v", err)
	}
	if _, err := ResolveBinaries(BinOptions{Agent: "", HostPath: "/usr/bin"}); err == nil {
		t.Error("empty agent accepted")
	}
}

func TestInheritPathFilter(t *testing.T) {
	home := realTemp(t)
	agent := filepath.Join(home, "agentdir/agent")
	write(t, agent, "#!/bin/sh\n", 0o755)
	write(t, filepath.Join(home, "tools/bin/hello"), "x", 0o755)
	outside := realTemp(t) // a second temp dir: outside the allowed prefix
	write(t, filepath.Join(outside, "evil"), "x", 0o755)
	mustSymlink(t, outside, filepath.Join(home, "linked-out")) // under home by name, outside by target

	hostPath := strings.Join([]string{"relative/bin", filepath.Join(home, "missing"), filepath.Join(home, "tools/bin"), outside, filepath.Join(home, "linked-out"), filepath.Dir(agent)}, ":")
	opt := BinOptions{Agent: agent, HostPath: hostPath, Home: home, InheritPrefixes: []string{home}}

	without, err := ResolveBinaries(opt)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(without.Roots, filepath.Join(home, "tools/bin")) {
		t.Error("host PATH directory exposed without --inherit-path")
	}

	opt.InheritPath = true
	with, err := ResolveBinaries(opt)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(with.Roots, filepath.Join(home, "tools/bin")) || !slices.Contains(with.PathDirs, filepath.Join(home, "tools/bin")) {
		t.Errorf("allowed dir missing: roots %v path %v", with.Roots, with.PathDirs)
	}
	for _, r := range with.Roots {
		if strings.HasPrefix(r, outside) || strings.Contains(r, "linked-out") || strings.Contains(r, "missing") {
			t.Errorf("filter let %q through", r)
		}
	}
}

func TestToolsRootsAndDedupe(t *testing.T) {
	home := realTemp(t)
	root := filepath.Join(home, "toolchain")
	write(t, filepath.Join(root, "bin/cc"), "x", 0o755)
	plain := filepath.Join(home, "plain")
	write(t, filepath.Join(plain, "tool"), "x", 0o755)
	agent := filepath.Join(root, "agentdir/agent") // inside the tools root: one bind covers both
	write(t, agent, "#!/bin/sh\n", 0o755)

	b, err := ResolveBinaries(BinOptions{Agent: agent, HostPath: "/usr/bin", Tools: []string{root, plain}, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(b.Roots, []string{root, plain}) {
		t.Errorf("Roots %v: the agent root inside a tools root must not be bound twice", b.Roots)
	}
	if !slices.Contains(b.PathDirs, filepath.Join(root, "bin")) || !slices.Contains(b.PathDirs, plain) {
		t.Errorf("tools PATH entries wrong: %v", b.PathDirs)
	}
	var p plan.Plan
	if err := AddBinaries(&p, b); err != nil {
		t.Errorf("plan: %v", err)
	}
	if _, err := ResolveBinaries(BinOptions{Agent: agent, HostPath: "/usr/bin", Tools: []string{filepath.Join(home, "nope")}}); err == nil {
		t.Error("missing tools dir accepted")
	}
}

func TestDanglingLinksWarn(t *testing.T) {
	home := realTemp(t)
	root := filepath.Join(home, "tools")
	write(t, filepath.Join(root, "real"), "x", 0o755)
	mustSymlink(t, "real", filepath.Join(root, "ok"))         // inside the root: fine
	mustSymlink(t, "/usr/bin/sh", filepath.Join(root, "sys")) // into a system dir: fine
	elsewhere := filepath.Join(home, "elsewhere/target")
	write(t, elsewhere, "x", 0o755)
	mustSymlink(t, elsewhere, filepath.Join(root, "escapes"))                // unmounted target
	mustSymlink(t, filepath.Join(home, "gone"), filepath.Join(root, "dead")) // target does not exist

	b, err := ResolveBinaries(BinOptions{Agent: "sh", HostPath: os.Getenv("PATH"), Tools: []string{root}})
	if err != nil {
		t.Skip("no sh on PATH")
	}
	joined := strings.Join(b.Warnings, "\n")
	for _, want := range []string{"escapes", "dead"} {
		if !strings.Contains(joined, filepath.Join(root, want)+" -> ") {
			t.Errorf("missing dangling warning for %s in:\n%s", want, joined)
		}
	}
	for _, bad := range []string{"/ok ->", "/sys ->"} {
		if strings.Contains(joined, bad) {
			t.Errorf("false positive %q in:\n%s", bad, joined)
		}
	}
}
