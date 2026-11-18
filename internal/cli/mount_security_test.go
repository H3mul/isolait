//go:build security

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Task 6.5 end to end: mount and unmount through the real binary, and from the leader prompt's runner.
func TestMountAndUnmountCommands(t *testing.T) {
	e := newE2E(t)
	out, err := e.plain("start", "-d", "sh")
	e.requireSandbox(out, err)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	sid := sidRe.FindString(out)
	lib := filepath.Join(filepath.Dir(e.proj), "shared-lib")
	os.MkdirAll(filepath.Join(lib, ".isolait"), 0o755)
	os.WriteFile(filepath.Join(lib, "f.txt"), []byte("from-lib\n"), 0o644)

	// a relative path is resolved against the caller's directory, not the daemon's
	if out, err := e.plain("--sid", sid, "mount", "../shared-lib"); err != nil || !strings.Contains(out, "/workspaces/shared-lib (rw)") {
		t.Fatalf("mount: %v\n%s", err, out)
	}
	if out, err := e.plain("--sid", sid, "mount", "--ro", "--as", "docs", lib); err != nil || !strings.Contains(out, "/workspaces/docs (ro)") {
		t.Fatalf("mount --ro --as: %v\n%s", err, out)
	}
	if out, err := e.plain("--sid", sid, "status"); err != nil || !strings.Contains(out, "/workspaces/shared-lib") || !strings.Contains(out, "/workspaces/docs") {
		t.Fatalf("status lacks the mounts: %v\n%s", err, out)
	}
	p := e.onPTY("--sid", sid, "exec", "--", "sh", "-c", "cat /workspaces/shared-lib/f.txt /workspaces/docs/f.txt")
	p.waitFor("from-lib")
	p.exitCode()

	// errors reach the user as text and a failing status
	if out, err := e.plain("--sid", sid, "mount", "--as", "docs", lib); err == nil || !strings.Contains(out, "already exists") {
		t.Errorf("collision: %v\n%s", err, out)
	}
	if out, err := e.plain("--sid", sid, "unmount", "nothing"); err == nil || !strings.Contains(out, "no mount named") {
		t.Errorf("unmount missing: %v\n%s", err, out)
	}

	// the leader prompt runs the same commands against the attached session
	for _, kv := range e.env { // the prompt runs in this process: give it the test's directories
		if k, v, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "XDG_") {
			t.Setenv(k, v)
		}
	}
	run := promptRunner(realDeps(), sid)
	if got := run("unmount docs"); !strings.Contains(got, "unmounted docs") {
		t.Errorf("prompt unmount: %q", got)
	}
	if got := run("mount --as again " + lib); !strings.Contains(got, "/workspaces/again") {
		t.Errorf("prompt mount: %q", got)
	}
	if out, _ := e.plain("--sid", sid, "unmount", "/workspaces/again"); !strings.Contains(out, "unmounted again") {
		t.Errorf("unmount by path: %s", out)
	}
	if out, _ := e.plain("--sid", sid, "status"); strings.Contains(out, "/workspaces/docs") || strings.Contains(out, "/workspaces/again") {
		t.Errorf("removed mounts still listed:\n%s", out)
	}
}
