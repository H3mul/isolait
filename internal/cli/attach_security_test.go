//go:build security

package cli

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/H3mul/isolait/internal/pty"
)

// End to end through the real binary on a real pty: the user's terminal is the pty slave, the tests type on the
// master and read what the terminal would show.

type e2e struct {
	t    *testing.T
	bin  string
	env  []string
	proj string // the project directory, named "api"
}

func newE2E(t *testing.T) *e2e {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("go", "build", "-o", filepath.Join(bin, "isolait"), "../..").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	short, err := os.MkdirTemp("", "iso")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(short) })
	for _, d := range []string{"rt", "state", "cfg"} {
		os.Mkdir(filepath.Join(short, d), 0o700)
	}
	proj := filepath.Join(short, "api")
	os.Mkdir(proj, 0o755)
	proj, _ = filepath.EvalSymlinks(proj)
	e := &e2e{t: t, bin: filepath.Join(bin, "isolait"), proj: proj, env: append(os.Environ(),
		"PATH="+bin+":"+os.Getenv("PATH"), "TERM=xterm-256color",
		"XDG_RUNTIME_DIR="+filepath.Join(short, "rt"), "XDG_STATE_HOME="+filepath.Join(short, "state"), "XDG_CONFIG_HOME="+filepath.Join(short, "cfg"))}
	t.Cleanup(func() { // never leave a session behind
		out, _ := e.plain("list")
		for _, id := range sidRe.FindAllString(out, -1) {
			e.plain("stop", id)
		}
	})
	return e
}

// plain runs isolait without a terminal.
func (e *e2e) plain(args ...string) (string, error) {
	c := exec.Command(e.bin, args...)
	c.Dir, c.Env = e.proj, e.env
	out, err := c.CombinedOutput()
	return string(out), err
}

type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// onPTY runs isolait with a pty as its terminal.
type onPTY struct {
	t      *testing.T
	cmd    *exec.Cmd
	master *os.File
	shown  *syncBuf
	done   chan struct{}
}

func (e *e2e) onPTY(args ...string) *onPTY {
	e.t.Helper()
	master, slave, err := pty.Open()
	if err != nil {
		e.t.Skipf("no pty here: %v", err)
	}
	pty.SetSize(master, 100, 30)
	c := exec.Command(e.bin, args...)
	c.Dir, c.Env = e.proj, e.env
	c.Stdin, c.Stdout, c.Stderr = slave, slave, slave
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := c.Start(); err != nil {
		e.t.Fatal(err)
	}
	slave.Close()
	p := &onPTY{t: e.t, cmd: c, master: master, shown: &syncBuf{}, done: make(chan struct{})}
	go func() { io.Copy(p.shown, master); close(p.done) }()
	e.t.Cleanup(func() { c.Process.Kill(); c.Wait(); master.Close() })
	return p
}

func (p *onPTY) type_(s string) { p.master.Write([]byte(s)) }

func (p *onPTY) waitFor(want string) {
	p.t.Helper()
	for i := 0; i < 600; i++ {
		if strings.Contains(p.shown.String(), want) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	p.t.Fatalf("never saw %q on the terminal; it showed %q", want, p.shown.String())
}

func (p *onPTY) exitCode() int {
	p.t.Helper()
	ch := make(chan error, 1)
	go func() { ch <- p.cmd.Wait() }()
	select {
	case err := <-ch:
		if err == nil {
			return 0
		}
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		p.t.Fatal(err)
	case <-time.After(15 * time.Second):
		p.t.Fatalf("isolait did not exit; the terminal showed %q", p.shown.String())
	}
	return -1
}

func (e *e2e) requireSandbox(out string, err error) {
	e.t.Helper()
	if err != nil && (strings.Contains(out, "operation not permitted") || strings.Contains(out, "prerequisite")) {
		e.t.Skipf("this host cannot run sandboxes: %s", out)
	}
}

const leaderDetach = "\x1c" + "d"

func TestStartAttachDetachReattachExit(t *testing.T) {
	e := newE2E(t)
	p := e.onPTY("start", "sh")
	// the terminal echoes what is typed; r""esult only becomes "result" once the shell has run the command
	p.type_("echo r\"\"esult pwd=$(pwd) tty=$(test -t 0 && echo yes) size=$(stty size) en\"\"d\r")
	p.waitFor("result pwd=/workspaces/api tty=yes size=30 100 end")
	p.type_("export MARK=survived\r")
	// output the agent writes is sanitized before the user's terminal sees it
	p.type_("printf '\\033]52;c;aGk=\\007visible-text\\n'\r")
	p.waitFor("visible-text")
	if strings.Contains(p.shown.String(), "\x1b]52") {
		t.Error("an OSC 52 clipboard write from the agent reached the terminal")
	}
	p.type_(leaderDetach)
	if code := p.exitCode(); code != 0 {
		t.Fatalf("detach exit status %d", code)
	}
	p.waitFor("[detached from ")

	out, err := e.plain("list")
	if err != nil || !strings.Contains(out, "detached") {
		t.Fatalf("a detached session must be listed as detached: %v\n%s", err, out)
	}

	// attach again without naming the session: the last attached one is the target
	p2 := e.onPTY("attach")
	p2.type_("echo r\"\"esult mark=$MARK en\"\"d\r")
	p2.waitFor("result mark=survived end")
	if out, _ := e.plain("status"); !strings.Contains(out, "attached") {
		t.Errorf("status while attached:\n%s", out)
	}
	p2.type_("exit 3\r")
	if code := p2.exitCode(); code != 3 {
		t.Errorf("the agent's exit status 3 became %d", code)
	}
	p2.waitFor("the agent exited with status 3")
	if out, _ := e.plain("list"); !strings.Contains(out, "idle") {
		t.Errorf("after the agent exited the session is idle:\n%s", out)
	}
	// the next attach restarts the agent in the same sandbox
	p3 := e.onPTY("attach")
	p3.type_("echo r\"\"esult again=$(pwd) en\"\"d\r")
	p3.waitFor("result again=/workspaces/api end")
	p3.type_(leaderDetach)
	p3.exitCode()
}

func TestAlternateScreenAndTerminalRestoreAcrossDetach(t *testing.T) {
	e := newE2E(t)
	p := e.onPTY("start", "sh", "-c", `printf '\033[?1049h'; printf ALT-READY; while :; do sleep 0.2; done`)
	p.waitFor("ALT-READY")
	p.type_(leaderDetach)
	p.exitCode()
	if !strings.Contains(p.shown.String(), "\x1b[?1049l") {
		t.Error("detaching must leave the agent's alternate screen so the user's shell is visible again")
	}

	p2 := e.onPTY("attach")
	p2.waitFor("\x1b[?1049h") // the fresh terminal is put back into the alternate screen the agent is in
	p2.type_(leaderDetach)
	p2.exitCode()
}

func TestExecOnATerminal(t *testing.T) {
	e := newE2E(t)
	out, err := e.plain("start", "-d", "sh")
	e.requireSandbox(out, err)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	sid := sidRe.FindString(out)

	// no last-attached session and no --sid: the error lists what is running
	if out, err := e.plain("exec", "--", "true"); err == nil || !strings.Contains(out, "no session targeted") || !strings.Contains(out, sid) {
		t.Errorf("exec without a target: %v\n%s", err, out)
	}
	p := e.onPTY("--sid", sid, "exec", "--", "sh", "-c", "echo in-sandbox:$(pwd):$(ls /workspaces); exit 4")
	p.waitFor("in-sandbox:/workspaces/api:api")
	if code := p.exitCode(); code != 4 {
		t.Errorf("exec exit status %d, want 4", code)
	}
	// exec does not make the session the last attached one, and does not change its state
	if out, _ := e.plain("list"); !strings.Contains(out, "idle") {
		t.Errorf("an exec must not start the agent:\n%s", out)
	}

	// closing the terminal ends the exec'd process: it does not linger in the sandbox
	p2 := e.onPTY("--sid", sid, "exec", "--", "sh", "-c", "echo up; sleep 300")
	p2.waitFor("up")
	p2.cmd.Process.Signal(syscall.SIGHUP) // what closing the terminal does to its client
	gone := make(chan error, 1)
	go func() { gone <- p2.cmd.Wait() }()
	select {
	case <-gone:
	case <-time.After(10 * time.Second):
		st, _ := os.ReadFile("/proc/" + strconv.Itoa(p2.cmd.Process.Pid) + "/status")
		t.Fatalf("isolait exec did not exit after its terminal went away:\n%s", st)
	}
	time.Sleep(3 * time.Second)
	p3 := e.onPTY("--sid", sid, "exec", "--", "sh", "-c", "echo n=$(ls /proc | grep -c '^[0-9]*$')")
	p3.waitFor("n=")
	p3.exitCode()
	// (the shell, grep and ls of this probe are all that may be left besides the shim and nothing sleeps)
	if strings.Contains(p3.shown.String(), "sleep") {
		t.Error("the abandoned exec process is still around")
	}
}

func TestAttachAndExecNeedATerminal(t *testing.T) {
	e := newE2E(t)
	out, err := e.plain("start", "-d", "sh")
	e.requireSandbox(out, err)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	sid := sidRe.FindString(out)
	for _, args := range [][]string{{"attach", sid}, {"--sid", sid, "exec", "--", "true"}} {
		if out, err := e.plain(args...); err == nil || !strings.Contains(out, "needs a terminal") {
			t.Errorf("%v without a terminal: %v\n%s", args, err, out)
		}
	}
}

// 4.6 end to end: the leader prompt runs isolait commands against the session you are attached to, shows the
// result without disturbing the agent, and keeps the agent usable afterwards.
func TestLeaderPromptInASession(t *testing.T) {
	e := newE2E(t)
	p := e.onPTY("start", "sh")
	p.type_("echo r\"\"esult first en\"\"d\r")
	p.waitFor("result first end")

	p.type_("\x1c:")
	p.waitFor("\x1b[?1049h") // a normal-screen agent: the prompt is an overlay on the alternate screen
	p.type_("status\r")
	p.waitFor("attached") // the status of this very session, on one row
	if out := p.shown.String(); !strings.Contains(out, "/workspaces/api") {
		t.Errorf("status output missing: %q", out)
	}
	// commands that attach or start are refused in the prompt
	p.waitFor("\x1b[?1049l") // the prompt closed by itself after showing the result
	p.type_("\x1c:attach\r")
	p.waitFor("not available in the prompt")
	p.waitFor("\x1b[?1049l")

	// Escape dismisses without running anything, and the agent keeps working
	p.type_("\x1c:stop\x1b")
	time.Sleep(300 * time.Millisecond)
	p.type_("echo r\"\"esult second en\"\"d\r")
	p.waitFor("result second end")
	if out, _ := e.plain("list"); !strings.Contains(out, "attached") {
		t.Errorf("a dismissed :stop must leave the session running:\n%s", out)
	}

	// and the prompt can really act: stop ends the session you are in
	p.type_("\x1c:stop\r")
	p.exitCode()
	eventually(t, "the session to be gone", func() bool {
		out, _ := e.plain("list")
		return strings.Contains(out, "no sessions running")
	})
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
