package initshim

import (
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/H3mul/isolait/internal/pty"
)

// The shim runs as a separate process (this test binary re-executed), because as PID 1 it reaps every child
// and must not do that inside the test process. No kernel features are needed.

const helperEnv = "ISOLAIT_INITSHIM_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) != "" {
		if err := Run(os.NewFile(ControlFD, "control")); err != nil {
			os.Stderr.WriteString("shim: " + err.Error() + "\n")
			os.Exit(1)
		}
		return
	}
	os.Exit(m.Run())
}

type shimProc struct {
	cmd *exec.Cmd
	cl  *Client
}

func startShim(t *testing.T) *shimProc {
	t.Helper()
	d, s, err := Socketpair()
	if err != nil {
		t.Fatal(err)
	}
	devnull, _ := os.Open(os.DevNull)
	defer devnull.Close()
	cmd := exec.Command(os.Args[0])
	cmd.Env = []string{helperEnv + "=1"}
	cmd.ExtraFiles = []*os.File{devnull, s} // fd 3 and fd 4 = ControlFD
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	cl, err := NewClient(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.WaitHello(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close(); cmd.Process.Kill(); cmd.Wait() })
	return &shimProc{cmd, cl}
}

func pipes(t *testing.T) (stdio [3]*os.File, out *os.File) {
	t.Helper()
	in, _ := os.Open(os.DevNull)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); r.Close() })
	return [3]*os.File{in, w, w}, r
}

func waitExit(t *testing.T, cl *Client, id int) Event {
	t.Helper()
	select {
	case e := <-cl.Exits():
		if e.ID != id {
			t.Fatalf("exit for id %d, want %d", e.ID, id)
		}
		return e
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for exit")
	}
	return Event{}
}

func TestSpawnExitCodeAndOutput(t *testing.T) {
	sh := startShim(t)
	stdio, out := pipes(t)
	id, pid, err := sh.cl.Spawn([]string{"/bin/sh", "-c", "echo hello; exit 3"}, []string{"PATH=/usr/bin:/bin"}, "/", false, stdio)
	stdio[1].Close()
	if err != nil || pid <= 0 {
		t.Fatalf("spawn: %v pid=%d", err, pid)
	}
	e := waitExit(t, sh.cl, id)
	if e.Code != 3 || e.Signal != 0 || e.PID != pid {
		t.Errorf("exit %+v", e)
	}
	if b, _ := io.ReadAll(out); string(b) != "hello\n" {
		t.Errorf("output %q", b)
	}
}

func TestRespawnInSameShim(t *testing.T) {
	sh := startShim(t)
	for i := 0; i < 3; i++ {
		stdio, out := pipes(t)
		id, _, err := sh.cl.Spawn([]string{"/bin/sh", "-c", "echo run"}, nil, "/", false, stdio)
		stdio[1].Close()
		if err != nil {
			t.Fatal(err)
		}
		if e := waitExit(t, sh.cl, id); e.Code != 0 {
			t.Fatalf("run %d: %+v", i, e)
		}
		if b, _ := io.ReadAll(out); string(b) != "run\n" {
			t.Fatalf("run %d output %q", i, b)
		}
	}
}

func TestSignalAndKilledReport(t *testing.T) {
	sh := startShim(t)
	stdio, _ := pipes(t)
	id, _, err := sh.cl.Spawn([]string{"/bin/sleep", "30"}, nil, "/", false, stdio)
	stdio[1].Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := sh.cl.Signal(id, int(syscall.SIGKILL)); err != nil {
		t.Fatal(err)
	}
	if e := waitExit(t, sh.cl, id); e.Signal != int(syscall.SIGKILL) {
		t.Errorf("exit %+v, want SIGKILL", e)
	}
}

// Many instant exits must each be attributed: this is the spawn/reap race.
func TestManyFastExits(t *testing.T) {
	sh := startShim(t)
	want := map[int]bool{}
	for i := 0; i < 40; i++ {
		stdio, _ := pipes(t)
		id, _, err := sh.cl.Spawn([]string{"/bin/true"}, nil, "/", false, stdio)
		stdio[1].Close()
		if err != nil {
			t.Fatal(err)
		}
		want[id] = true
	}
	for range want {
		select {
		case e := <-sh.cl.Exits():
			if !want[e.ID] || e.Code != 0 {
				t.Fatalf("unexpected exit %+v", e)
			}
			delete(want, e.ID)
		case <-time.After(10 * time.Second):
			t.Fatalf("lost exits: %d still missing", len(want))
		}
	}
}

func TestTerminalSession(t *testing.T) {
	m, s, err := pty.Open()
	if err != nil {
		t.Skipf("no pty here: %v", err)
	}
	defer m.Close()
	sh := startShim(t)
	id, _, err := sh.cl.Spawn([]string{"/bin/sh", "-c", "[ -t 0 ] && [ -t 1 ] && echo is-a-tty || echo not-a-tty"}, []string{"PATH=/usr/bin:/bin"}, "/", true, [3]*os.File{s, s, s})
	s.Close()
	if err != nil {
		t.Fatal(err)
	}
	waitExit(t, sh.cl, id)
	buf := make([]byte, 256)
	m.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := m.Read(buf)
	if !strings.Contains(string(buf[:n]), "is-a-tty") {
		t.Errorf("stdio is not a terminal inside the shim's child: %q", buf[:n])
	}
}

func TestBadRequestsDoNotKillTheShim(t *testing.T) {
	sh := startShim(t)
	stdio, _ := pipes(t)
	defer stdio[1].Close()
	if _, _, err := sh.cl.Spawn(nil, nil, "/", false, stdio); err == nil || !strings.Contains(err.Error(), "arguments") {
		t.Errorf("empty argv: %v", err)
	}
	if _, _, err := sh.cl.Spawn([]string{"/no/such/binary"}, nil, "/", false, stdio); err == nil {
		t.Error("missing binary reported as started")
	}
	id, _, err := sh.cl.Spawn([]string{"/bin/true"}, nil, "/", false, stdio) // still alive
	if err != nil {
		t.Fatalf("shim died after bad requests: %v", err)
	}
	waitExit(t, sh.cl, id)
}

func TestShimEndsWhenDaemonDisappears(t *testing.T) {
	sh := startShim(t)
	sh.cl.Close()
	done := make(chan error, 1)
	go func() { done <- sh.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("shim exit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shim kept running after the control socket closed")
	}
}

func TestShutdownKillsChildren(t *testing.T) {
	sh := startShim(t)
	stdio, _ := pipes(t)
	if _, _, err := sh.cl.Spawn([]string{"/bin/sleep", "30"}, nil, "/", false, stdio); err != nil {
		t.Fatal(err)
	}
	stdio[1].Close()
	sh.cl.Shutdown()
	done := make(chan error, 1)
	go func() { done <- sh.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shim did not exit on shutdown")
	}
}

// Regression guard: shutdown from a shim that is not PID 1 must kill only its own children. (A kill(-1, ...)
// here would signal every process the user owns.)
func TestShutdownLeavesUnrelatedProcessesAlone(t *testing.T) {
	bystander := exec.Command("/bin/sleep", "30")
	if err := bystander.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { bystander.Process.Kill(); bystander.Wait() }()

	sh := startShim(t)
	sh.cl.Shutdown()
	sh.cmd.Wait()
	time.Sleep(200 * time.Millisecond)
	if err := bystander.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("shutdown killed an unrelated process: %v", err)
	}
}
