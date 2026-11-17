//go:build security

package mounts

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/H3mul/isolait/internal/broker"
)

// Spike 1.4 (atomic ro clone, nosuid/nodev, non-recursive) and spike 1.9 (.isolait mask) against the product
// primitive. The scenarios run inside the broker's namespaces; the parent asserts on what they report.

const helperEnv = "ISOLAIT_MOUNTS_HELPER"

type obs struct {
	RWRead, RWWrite, RWErr     string
	RWMasked                   bool
	RWMaskEntries              int
	RWMaskWriteErr             string
	RWHostConfigIntact         bool
	RWOpts                     string
	RWSubmountHidden           bool
	ROWriteErrno               string
	ROOpts                     string
	CollisionErr               string
	SymlinkErr, SymlinkMounted string
	IsolaitFileErr             string
	RollbackLeftover           bool
	UnmountLeavesNothing       bool
	Fatal                      string
}

func TestMain(m *testing.M) {
	if root := os.Getenv(helperEnv); root != "" {
		var o obs
		func() {
			defer func() {
				if r := recover(); r != nil {
					o.Fatal = r.(error).Error()
				}
			}()
			helper(root, &o)
		}()
		json.NewEncoder(os.Stdout).Encode(o)
		return
	}
	os.Exit(m.Run())
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func mountOpts(mp string) string {
	b, _ := os.ReadFile("/proc/self/mountinfo")
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) > 5 && f[4] == mp {
			return f[5]
		}
	}
	return ""
}

func mkSrc(root, name string) string {
	src := filepath.Join(root, name)
	must(os.MkdirAll(filepath.Join(src, ".isolait"), 0o755))
	must(os.WriteFile(filepath.Join(src, "f"), []byte("data"), 0o644))
	must(os.WriteFile(filepath.Join(src, ".isolait", "config"), []byte("secret"), 0o644))
	must(os.MkdirAll(filepath.Join(src, "sub"), 0o755))
	return src
}

func helper(root string, o *obs) {
	stage := filepath.Join(root, "stage")
	empty := filepath.Join(root, "empty")
	must(os.MkdirAll(stage, 0o755))
	must(os.MkdirAll(empty, 0o755))
	must(syscall.Mount("tmpfs", stage, "tmpfs", 0, ""))
	must(syscall.Mount("", stage, "", syscall.MS_SHARED, ""))

	// rw workspace with a host submount (must stay out) and a .isolait directory (must be masked)
	src := mkSrc(root, "src")
	must(syscall.Mount("tmpfs", filepath.Join(src, "sub"), "tmpfs", 0, ""))
	must(os.WriteFile(filepath.Join(src, "sub", "hidden"), []byte("x"), 0o644))
	masked, err := MountWorkspace(stage, "rw", src, false, empty)
	must(err)
	o.RWMasked = masked
	b, _ := os.ReadFile(filepath.Join(stage, "rw", "f"))
	o.RWRead = string(b)
	if err := os.WriteFile(filepath.Join(stage, "rw", "new"), []byte("y"), 0o644); err != nil {
		o.RWErr = err.Error()
	} else {
		o.RWWrite = "ok"
	}
	ents, _ := os.ReadDir(filepath.Join(stage, "rw", ".isolait"))
	o.RWMaskEntries = len(ents)
	if err := os.WriteFile(filepath.Join(stage, "rw", ".isolait", "x"), nil, 0o644); err != nil {
		o.RWMaskWriteErr = err.Error()
	}
	c, _ := os.ReadFile(filepath.Join(src, ".isolait", "config"))
	o.RWHostConfigIntact = string(c) == "secret"
	o.RWOpts = mountOpts(filepath.Join(stage, "rw"))
	_, err = os.Stat(filepath.Join(stage, "rw", "sub", "hidden"))
	o.RWSubmountHidden = err != nil

	// read-only workspace
	src2 := mkSrc(root, "src2")
	_, err = MountWorkspace(stage, "ro", src2, true, empty)
	must(err)
	err = os.WriteFile(filepath.Join(stage, "ro", "new"), nil, 0o644)
	var pe *os.PathError
	if errors.As(err, &pe) {
		o.ROWriteErrno = pe.Err.Error()
	}
	o.ROOpts = mountOpts(filepath.Join(stage, "ro"))

	// collision
	if _, err := MountWorkspace(stage, "rw", src2, false, empty); err != nil {
		o.CollisionErr = err.Error()
	}

	// a .isolait symlink cannot be masked safely: refuse, mount nothing
	src3 := filepath.Join(root, "src3")
	must(os.MkdirAll(src3, 0o755))
	must(os.Symlink("/etc", filepath.Join(src3, ".isolait")))
	if _, err := MountWorkspace(stage, "sym", src3, false, empty); err != nil {
		o.SymlinkErr = err.Error()
	}
	if _, err := os.Stat(filepath.Join(stage, "sym")); err == nil {
		o.SymlinkMounted = "stage/sym exists"
	}
	src4 := filepath.Join(root, "src4")
	must(os.MkdirAll(src4, 0o755))
	must(os.WriteFile(filepath.Join(src4, ".isolait"), []byte("file"), 0o644))
	if _, err := MountWorkspace(stage, "isofile", src4, false, empty); err != nil {
		o.IsolaitFileErr = err.Error()
	}

	// a mask target that cannot be mounted over rolls the workspace mount back
	src5 := mkSrc(root, "src5")
	if _, err := MountWorkspace(stage, "rollback", src5, false, filepath.Join(root, "does-not-exist")); err == nil {
		o.RollbackLeftover = true // should have failed
	}
	if _, err := os.Stat(filepath.Join(stage, "rollback")); err == nil {
		o.RollbackLeftover = true
	}

	// lazy unmount removes the workspace with its mask stacked on it
	must(Unmount(filepath.Join(stage, "rw")))
	ents, _ = os.ReadDir(filepath.Join(stage, "rw"))
	o.UnmountLeavesNothing = len(ents) == 0 && mountOpts(filepath.Join(stage, "rw")) == ""
}

func TestWorkspaceMountPrimitive(t *testing.T) {
	root := t.TempDir()
	cmd := broker.Command(os.Args[0])
	cmd.Env = append(os.Environ(), helperEnv+"="+root)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) || strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("cannot create user namespaces here: %v %s", err, stderr.String())
		}
		t.Fatal(err)
	}
	var o obs
	if err := json.Unmarshal(out, &o); err != nil {
		t.Fatalf("bad report %q: %v", out, err)
	}
	if o.Fatal != "" {
		t.Fatalf("scenario failed: %s", o.Fatal)
	}
	eq := func(name string, got, want any) {
		t.Helper()
		if got != want {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	has := func(name, s string, subs ...string) {
		t.Helper()
		for _, sub := range subs {
			if !strings.Contains(","+s+",", ","+sub+",") {
				t.Errorf("%s options %q lack %q", name, s, sub)
			}
		}
	}
	// 3.7: rw and ro workspace
	eq("rw read", o.RWRead, "data")
	eq("rw write", o.RWWrite, "ok")
	has("rw", o.RWOpts, "rw", "nosuid", "nodev")
	eq("ro write error", o.ROWriteErrno, "read-only file system")
	has("ro", o.ROOpts, "ro", "nosuid", "nodev")
	eq("host submount hidden (spike 1.4 non-recursive)", o.RWSubmountHidden, true)
	// 3.10: .isolait mask
	eq("masked", o.RWMasked, true)
	eq("mask entries", o.RWMaskEntries, 0)
	if !strings.Contains(o.RWMaskWriteErr, "read-only") {
		t.Errorf("write into the mask: %q, want a read-only error", o.RWMaskWriteErr)
	}
	eq("host .isolait/config untouched", o.RWHostConfigIntact, true)
	// refusals
	if !strings.Contains(o.CollisionErr, "already in use") {
		t.Errorf("collision: %q", o.CollisionErr)
	}
	if !strings.Contains(o.SymlinkErr, "not a plain directory") || o.SymlinkMounted != "" {
		t.Errorf("symlinked .isolait: err=%q mounted=%q", o.SymlinkErr, o.SymlinkMounted)
	}
	if !strings.Contains(o.IsolaitFileErr, "not a plain directory") {
		t.Errorf(".isolait file: %q", o.IsolaitFileErr)
	}
	eq("failed mask rolls the workspace back", o.RollbackLeftover, false)
	eq("lazy unmount removes workspace and mask", o.UnmountLeavesNothing, true)
}
