package daemon

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/H3mul/isolait/internal/attach"
	"github.com/H3mul/isolait/internal/initshim"
)

// These tests run the terminal manager against a real init shim (this test binary re-executed, outside any
// sandbox) and real PTYs, with a scripted client on a unix socketpair. No kernel features are needed.

func newShim(t *testing.T) *initshim.Client {
	t.Helper()
	d, s, err := initshim.Socketpair()
	if err != nil {
		t.Fatal(err)
	}
	devnull, _ := os.Open(os.DevNull)
	defer devnull.Close()
	cmd := execSelf("__isolait_init__")
	cmd.ExtraFiles = []*os.File{devnull, s} // fd 3, fd 4 = initshim.ControlFD
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	cl, err := initshim.NewClient(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.WaitHello(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close(); cmd.Process.Kill(); cmd.Wait() })
	return cl
}

func newTerms(t *testing.T, agentScript string) *terminals {
	t.Helper()
	tm := newTerminals(newShim(t), []string{"/bin/sh", "-c", agentScript}, []string{"PATH=/usr/bin:/bin", "HOME=/tmp"}, "/")
	t.Cleanup(tm.Close)
	return tm
}

func sockPair(t *testing.T) (a, b net.Conn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	conv := func(fd int) net.Conn {
		f := os.NewFile(uintptr(fd), "pair")
		c, err := net.FileConn(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	a, b = conv(fds[0]), conv(fds[1])
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

type tclient struct {
	t     *testing.T
	conn  *attach.Conn
	raw   net.Conn
	reply attach.Reply
	out   strings.Builder
	exit  *attach.ExitInfo
}

// dial connects a scripted client and performs the hello.
func dial(t *testing.T, tm *terminals, h attach.HelloMsg) *tclient {
	t.Helper()
	srv, cli := sockPair(t)
	go tm.Serve(srv)
	s := &tclient{t: t, conn: attach.NewConn(cli), raw: cli}
	if err := s.conn.SendJSON(attach.Hello, h); err != nil {
		t.Fatal(err)
	}
	f, err := s.conn.Recv()
	if err != nil || f.Type != attach.Hello {
		t.Fatalf("no hello reply: %v %c", err, f.Type)
	}
	if err := json.Unmarshal(f.Payload, &s.reply); err != nil {
		t.Fatal(err)
	}
	return s
}

func agentHello() attach.HelloMsg {
	return attach.HelloMsg{Mode: attach.ModeAgent, Term: "xterm", Cols: 80, Rows: 24}
}

// waitFor reads frames until the accumulated terminal data contains want, or the process exits.
func (s *tclient) waitFor(want string) bool {
	s.t.Helper()
	s.raw.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer s.raw.SetReadDeadline(time.Time{})
	for !strings.Contains(s.out.String(), want) {
		f, err := s.conn.Recv()
		if err != nil {
			return false
		}
		switch f.Type {
		case attach.Data:
			s.out.Write(f.Payload)
		case attach.Exit:
			var e attach.ExitInfo
			json.Unmarshal(f.Payload, &e)
			s.exit = &e
			return strings.Contains(s.out.String(), want)
		}
	}
	return true
}

func (s *tclient) mustSee(want string) {
	s.t.Helper()
	if !s.waitFor(want) {
		s.t.Fatalf("never saw %q; output so far: %q", want, s.out.String())
	}
}

func (s *tclient) waitExit() attach.ExitInfo {
	s.t.Helper()
	s.raw.SetReadDeadline(time.Now().Add(10 * time.Second))
	for s.exit == nil {
		f, err := s.conn.Recv()
		if err != nil {
			s.t.Fatalf("connection ended without an exit frame: %v (output %q)", err, s.out.String())
		}
		switch f.Type {
		case attach.Data:
			s.out.Write(f.Payload)
		case attach.Exit:
			var e attach.ExitInfo
			json.Unmarshal(f.Payload, &e)
			s.exit = &e
		}
	}
	return *s.exit
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// 4.1: every byte from every PTY goes through output(), also while nobody is attached.
func TestAllPTYOutputFlowsThroughTheSingleOutputPath(t *testing.T) {
	tm := newTerms(t, `printf first; sleep 1; printf second; sleep 20`)
	var mu sync.Mutex
	var seen strings.Builder
	tm.outputHook = func(b []byte) { mu.Lock(); seen.Write(b); mu.Unlock() }
	saw := func(s string) func() bool {
		return func() bool { mu.Lock(); defer mu.Unlock(); return strings.Contains(seen.String(), s) }
	}

	c := dial(t, tm, agentHello())
	c.mustSee("first")
	if !saw("first")() {
		t.Error("attached output did not pass through output()")
	}
	c.conn.Send(attach.Frame{Type: attach.Detach})
	eventually(t, "the session to be detached", func() bool { return tm.State() == "detached" })
	eventually(t, "unattended output to reach output()", saw("second"))

	// exec output takes the same path
	e := dial(t, tm, attach.HelloMsg{Mode: attach.ModeExec, Argv: []string{"sh", "-c", "printf from-exec"}, Term: "xterm", Cols: 80, Rows: 24})
	e.mustSee("from-exec")
	if !saw("from-exec")() {
		t.Error("exec output did not pass through output()")
	}
}

func TestAttachStartsAgentAndRelaysInput(t *testing.T) {
	tm := newTerms(t, `cat`)
	if st := tm.State(); st != "idle" {
		t.Fatalf("state before attach: %s", st)
	}
	c := dial(t, tm, agentHello())
	if !c.reply.OK || !c.reply.Restarted {
		t.Fatalf("reply %+v", c.reply)
	}
	if tm.State() != "attached" {
		t.Errorf("state %s", tm.State())
	}
	c.conn.Send(attach.Frame{Type: attach.Data, Payload: []byte("ping\n")})
	c.mustSee("ping")
}

func TestResizeReachesTheTerminal(t *testing.T) {
	tm := newTerms(t, `read x; stty size; sleep 20`)
	c := dial(t, tm, attach.HelloMsg{Mode: attach.ModeAgent, Term: "xterm", Cols: 100, Rows: 30})
	c.conn.Send(attach.Frame{Type: attach.Resize, Payload: attach.ResizePayload(132, 43)})
	time.Sleep(100 * time.Millisecond)
	c.conn.Send(attach.Frame{Type: attach.Data, Payload: []byte("\n")})
	c.mustSee("43 132")
}

func TestAgentExitIsReportedAndReattachRestartsIt(t *testing.T) {
	tm := newTerms(t, `printf bye; exit 7`)
	c := dial(t, tm, agentHello())
	c.mustSee("bye")
	if e := c.waitExit(); e.Code != 7 {
		t.Errorf("exit %+v, want code 7", e)
	}
	eventually(t, "the session to go idle", func() bool { return tm.State() == "idle" })

	c2 := dial(t, tm, agentHello())
	if !c2.reply.OK || !c2.reply.Restarted {
		t.Fatalf("reattach after exit must restart the agent: %+v", c2.reply)
	}
	c2.mustSee("bye")
}

func TestDetachKeepsAgentRunningAndReattachRestoresModes(t *testing.T) {
	tm := newTerms(t, `trap 'printf winched' WINCH; printf '\033[?1049h'; printf ready; while true; do sleep 0.1; done`)
	c := dial(t, tm, agentHello())
	c.mustSee("ready")
	c.conn.Send(attach.Frame{Type: attach.Detach})
	eventually(t, "detached", func() bool { return tm.State() == "detached" })

	c2 := dial(t, tm, agentHello())
	if !c2.reply.OK || c2.reply.Restarted {
		t.Fatalf("reattach to a running agent: %+v", c2.reply)
	}
	c2.mustSee("\x1b[?1049h") // the fresh terminal is put back into the alternate screen the agent is in
	c2.mustSee("winched")     // and the agent was asked to repaint
	if tm.State() != "attached" {
		t.Errorf("state %s", tm.State())
	}
}

func TestRedrawFrameSignalsTheAgent(t *testing.T) {
	tm := newTerms(t, `trap 'printf repainted' WINCH; printf up; while true; do sleep 0.1; done`)
	c := dial(t, tm, agentHello())
	c.mustSee("up")
	c.conn.Send(attach.Frame{Type: attach.Redraw})
	c.mustSee("repainted")
}

func TestUnattendedAgentNeverBlocksOnOutput(t *testing.T) {
	// 3 MB of output with nobody reading would fill the PTY buffer and hang the agent if it were not drained
	tm := newTerms(t, `sleep 0.3; head -c 3000000 /dev/zero | tr '\0' x; sleep 20`)
	var mu sync.Mutex
	total := 0
	tm.outputHook = func(b []byte) { mu.Lock(); total += len(b); mu.Unlock() }
	c := dial(t, tm, agentHello())
	c.conn.Send(attach.Frame{Type: attach.Detach})
	eventually(t, "the unattended output to be drained", func() bool { mu.Lock(); defer mu.Unlock(); return total >= 3000000 })
}

func TestSecondAgentClientIsRejected(t *testing.T) {
	tm := newTerms(t, `cat`)
	c := dial(t, tm, agentHello())
	c2 := dial(t, tm, agentHello())
	if c2.reply.OK || !strings.Contains(c2.reply.Error, "already has a client attached") {
		t.Fatalf("second client: %+v", c2.reply)
	}
	c.conn.Send(attach.Frame{Type: attach.Data, Payload: []byte("still-works\n")})
	c.mustSee("still-works")
}

func TestExecRunsInTheSandboxAndReportsExit(t *testing.T) {
	tm := newTerms(t, `sleep 30`)
	e := dial(t, tm, attach.HelloMsg{Mode: attach.ModeExec, Argv: []string{"sh", "-c", "echo term=$TERM; exit 5"}, Term: "screen-256color", Cols: 80, Rows: 24})
	if !e.reply.OK {
		t.Fatalf("%+v", e.reply)
	}
	e.mustSee("term=screen-256color")
	if x := e.waitExit(); x.Code != 5 {
		t.Errorf("exit %+v", x)
	}
	if tm.State() != "idle" {
		t.Errorf("an exec session must not change the agent state: %s", tm.State())
	}
}

func TestExecDoesNotOutliveItsClient(t *testing.T) {
	tm := newTerms(t, `sleep 30`)
	e := dial(t, tm, attach.HelloMsg{Mode: attach.ModeExec, Argv: []string{"sleep", "30"}, Term: "xterm", Cols: 80, Rows: 24})
	if !e.reply.OK {
		t.Fatalf("%+v", e.reply)
	}
	count := func() int { tm.mu.Lock(); defer tm.mu.Unlock(); return len(tm.execs) }
	eventually(t, "the exec process to be registered", func() bool { return count() == 1 })
	e.raw.Close()
	eventually(t, "the exec process to be killed after its client disconnected", func() bool { return count() == 0 })
}

func TestExecOfAMissingCommandIsRefused(t *testing.T) {
	tm := newTerms(t, `sleep 30`)
	e := dial(t, tm, attach.HelloMsg{Mode: attach.ModeExec, Argv: []string{"no-such-command-xyz"}, Term: "xterm", Cols: 80, Rows: 24})
	if e.reply.OK || !strings.Contains(e.reply.Error, "command not found") {
		t.Fatalf("%+v", e.reply)
	}
}

func TestBadHellosAreRefused(t *testing.T) {
	tm := newTerms(t, `sleep 30`)
	for name, h := range map[string]attach.HelloMsg{
		"unknown mode":           {Mode: "bogus", Term: "xterm"},
		"exec without a command": {Mode: attach.ModeExec, Term: "xterm"},
	} {
		if c := dial(t, tm, h); c.reply.OK || c.reply.Error == "" {
			t.Errorf("%s accepted: %+v", name, c.reply)
		}
	}
	// a first frame that is not a hello ends the connection
	srv, cli := sockPair(t)
	go tm.Serve(srv)
	attach.NewConn(cli).Send(attach.Frame{Type: attach.Data, Payload: []byte("x")})
	cli.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := attach.NewConn(cli).Recv(); err == nil {
		t.Error("a connection that did not start with a hello was kept")
	}
}

func TestTermIsSanitizedAndSizeClamped(t *testing.T) {
	tm := newTerms(t, `echo term=$TERM; stty size; sleep 20`)
	c := dial(t, tm, attach.HelloMsg{Mode: attach.ModeAgent, Term: "x;rm -rf /", Cols: 99999, Rows: 0})
	c.mustSee("term=xterm-256color") // an unsafe value is replaced, never passed on
	c.mustSee("24 80")               // out-of-range sizes fall back to defaults
}

// 3.1: attach and detach record use; an exec does not.
func TestAttachAndDetachRecordUseButExecDoesNot(t *testing.T) {
	tm := newTerms(t, `printf ready; while true; do sleep 0.1; done`)
	var mu sync.Mutex
	uses := 0
	tm.onUse = func() { mu.Lock(); uses++; mu.Unlock() }
	count := func() int { mu.Lock(); defer mu.Unlock(); return uses }

	e := dial(t, tm, attach.HelloMsg{Mode: attach.ModeExec, Argv: []string{"true"}, Term: "xterm", Cols: 80, Rows: 24})
	e.waitExit()
	if count() != 0 {
		t.Errorf("an exec counted as use: %d", count())
	}
	c := dial(t, tm, agentHello())
	c.mustSee("ready")
	if count() != 1 {
		t.Errorf("attach: %d uses, want 1", count())
	}
	c.conn.Send(attach.Frame{Type: attach.Detach})
	eventually(t, "detach recorded", func() bool { return count() == 2 })
}
