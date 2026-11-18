//go:build security

package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Task 8.1: the whole user workflow through the real binary, in order: start, detach, attach, exec, add and
// remove a mount, open and close a port, agent exit and restart, stop. `make e2e` runs it; CI runs it on native
// Linux and it is also run on WSL2.
func TestFullWorkflow(t *testing.T) {
	e := newE2E(t)
	step := func(name string) { t.Log("step:", name) }
	run := func(args ...string) string {
		t.Helper()
		out, err := e.plain(args...)
		if err != nil {
			t.Fatalf("isolait %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return out
	}
	execOut := func(sid, script, want string) {
		t.Helper()
		p := e.onPTY("--sid", sid, "exec", "--", "bash", "-c", script)
		p.waitFor(want)
		p.exitCode()
	}

	step("start (attached)")
	p := e.onPTY("start", "sh")
	p.type_("echo r\"\"esult one=$(pwd) en\"\"d\r")
	p.waitFor("result one=/workspaces/api end")
	p.type_("export MARK=alive\r")

	step("detach")
	p.type_(leaderDetach)
	p.exitCode()
	p.waitFor("[detached from ")
	list := run("list")
	sid := sidRe.FindString(list)
	if sid == "" || !strings.Contains(list, "detached") {
		t.Fatalf("list after detach:\n%s", list)
	}

	step("attach: the agent kept running")
	p2 := e.onPTY("attach")
	p2.type_("echo r\"\"esult mark=$MARK en\"\"d\r")
	p2.waitFor("result mark=alive end")
	p2.type_(leaderDetach)
	p2.exitCode()

	step("exec")
	execOut(sid, "echo exec-ok:$(pwd)", "exec-ok:/workspaces/api")

	step("add and remove a mount")
	lib := filepath.Join(filepath.Dir(e.proj), "lib")
	os.MkdirAll(lib, 0o755)
	os.WriteFile(filepath.Join(lib, "f"), []byte("lib-content\n"), 0o644)
	if out := run("--sid", sid, "mount", "--ro", lib); !strings.Contains(out, "/workspaces/lib (ro)") {
		t.Fatalf("mount: %s", out)
	}
	execOut(sid, "cat /workspaces/lib/f", "lib-content")

	step("open and close a port")
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
			c.Write([]byte("host-service\n"))
			c.Close()
		}
	}()
	port := fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
	run("--sid", sid, "allow", "port", port)
	execOut(sid, "exec 3<>/dev/tcp/127.0.0.1/"+port+" && read -r l <&3 && echo port-says:$l", "port-says:host-service")
	run("--sid", sid, "deny", "port", port)
	execOut(sid, "exec 3<>/dev/tcp/127.0.0.1/"+port+" 2>/dev/null && echo STILL-OPEN || echo port-closed", "port-closed")

	step("agent exit and restart in the same sandbox")
	p3 := e.onPTY("attach")
	p3.type_("exit 0\r")
	p3.exitCode()
	if out := run("list"); !strings.Contains(out, "idle") {
		t.Fatalf("after the agent exited:\n%s", out)
	}
	p4 := e.onPTY("attach")
	p4.type_("echo r\"\"esult cat=$(cat /workspaces/lib/f) en\"\"d\r")
	p4.waitFor("result cat=lib-content end")
	p4.type_(leaderDetach)
	p4.exitCode()

	step("unmount")
	run("--sid", sid, "unmount", "lib")
	execOut(sid, "ls /workspaces", "api")

	step("stop leaves nothing behind")
	run("stop", sid)
	if out := run("list"); strings.Contains(out, sid) {
		t.Fatalf("the stopped session is still listed:\n%s", out)
	}
	if out, _ := e.plain("--sid", sid, "status"); !strings.Contains(out, "does not exist") {
		t.Fatalf("status of a stopped session:\n%s", out)
	}
}
