//go:build security

package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// Tasks 7.4: allow and deny through the real binary, and from the leader prompt.
func TestAllowAndDenyPortCommands(t *testing.T) {
	e := newE2E(t)
	out, err := e.plain("start", "-d", "sh")
	e.requireSandbox(out, err)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	sid := sidRe.FindString(out)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("host-secret\n"))
			c.Close()
		}
	}()
	port := fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
	probe := "if exec 3<>/dev/tcp/127.0.0.1/" + port + " 2>/dev/null; then read -r l <&3; echo got=$l; else echo got=REFUSED; fi"
	got := func() string {
		p := e.onPTY("--sid", sid, "exec", "--", "bash", "-c", probe)
		defer p.exitCode()
		for i := 0; i < 200; i++ {
			for _, want := range []string{"got=host-secret", "got=REFUSED"} {
				if strings.Contains(p.shown.String(), want) {
					return want
				}
			}
			time.Sleep(25 * time.Millisecond)
		}
		return "nothing"
	}
	if g := got(); g != "got=REFUSED" {
		t.Fatalf("before allow: %s", g)
	}
	out, err = e.plain("--sid", sid, "allow", "port", port)
	if err != nil || !strings.Contains(out, "opened "+port) || !strings.Contains(out, "cannot tell the sandbox's connections from your own") {
		t.Fatalf("allow: %v\n%s", err, out)
	}
	if out, _ := e.plain("--sid", sid, "status"); !strings.Contains(out, "ports       "+port) {
		t.Errorf("status lacks the port:\n%s", out)
	}
	if g := got(); g != "got=host-secret" {
		t.Fatalf("after allow: %s", g)
	}
	if out, err := e.plain("--sid", sid, "allow", "port", "80/udp"); err == nil || !strings.Contains(out, "UDP") {
		t.Errorf("udp grant: %v\n%s", err, out)
	}
	for _, kv := range e.env {
		if k, v, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "XDG_") {
			t.Setenv(k, v)
		}
	}
	if got := promptRunner(realDeps(), sid)("deny port " + port); !strings.Contains(got, "closed "+port) || !strings.Contains(got, "open ports: none") {
		t.Errorf("prompt deny: %q", got)
	}
	if g := got(); g != "got=REFUSED" {
		t.Fatalf("after deny: %s", g)
	}
}
