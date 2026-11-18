package relay

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/H3mul/isolait/internal/attach"
	"github.com/H3mul/isolait/internal/pty"
)

const leader = "\x1c"

// syncBuf is a goroutine-safe sink standing in for the terminal.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// fakeDaemon is the other end of the attach socket, driven by the test.
type fakeDaemon struct {
	t     *testing.T
	conn  *attach.Conn
	raw   net.Conn // the daemon's end of the socket
	hello attach.HelloMsg
	ready chan struct{} // closed once the hello has been read
	got   chan attach.Frame
}

func startDaemon(t *testing.T, reply attach.Reply) (*fakeDaemon, net.Conn) {
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
	srv, cli := conv(fds[0]), conv(fds[1])
	t.Cleanup(func() { srv.Close(); cli.Close() })
	d := &fakeDaemon{t: t, conn: attach.NewConn(srv), raw: srv, ready: make(chan struct{}), got: make(chan attach.Frame, 64)}
	go func() {
		f, err := d.conn.Recv()
		if err != nil {
			return
		}
		json.Unmarshal(f.Payload, &d.hello)
		d.conn.SendJSON(attach.Hello, reply)
		close(d.ready) // after the reply, like the real daemon: no terminal data may overtake it
		for {
			f, err := d.conn.Recv()
			if err != nil {
				return
			}
			d.got <- f
		}
	}()
	return d, cli
}

// frame waits for the next frame of the given type from the client.
func (d *fakeDaemon) frame(typ byte) attach.Frame {
	d.t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case f := <-d.got:
			if f.Type == typ {
				return f
			}
		case <-deadline:
			d.t.Fatalf("no %q frame arrived", typ)
		}
	}
}

func (d *fakeDaemon) send(s string) { d.conn.Send(attach.Frame{Type: attach.Data, Payload: []byte(s)}) }

type running struct {
	res  chan Result
	err  chan error
	inW  *io.PipeWriter
	out  *syncBuf
	conn net.Conn
}

func runRelay(t *testing.T, conn net.Conn, mutate func(*Options)) *running {
	t.Helper()
	inR, inW := io.Pipe()
	r := &running{res: make(chan Result, 1), err: make(chan error, 1), inW: inW, out: &syncBuf{}, conn: conn}
	o := Options{Conn: conn, Hello: attach.HelloMsg{Mode: attach.ModeAgent, Term: "xterm"}, Leader: 0x1c, In: inR, Out: r.out, EscapeWait: 20 * time.Millisecond}
	if mutate != nil {
		mutate(&o)
	}
	go func() {
		res, err := Run(o)
		r.res <- res
		r.err <- err
	}()
	t.Cleanup(func() { inW.Close() })
	return r
}

func (r *running) wait(t *testing.T) (Result, error) {
	t.Helper()
	select {
	case res := <-r.res:
		return res, <-r.err
	case <-time.After(5 * time.Second):
		t.Fatal("the relay did not return")
	}
	return Result{}, nil
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestOutputIsSanitizedAndInputForwarded(t *testing.T) {
	d, c := startDaemon(t, attach.Reply{OK: true})
	r := runRelay(t, c, nil)
	<-d.ready
	d.send("hi \x1b[1mbold\x1b[0m")
	d.send("\x1b]52;c;aGVsbG8=")                    // an OSC 52 clipboard write, split across frames...
	d.send("\x07 \x1b]0;title\x1b\\ after\x1b[21t") // ...followed by a title and a title report
	eventually(t, "sanitized output", func() bool { return strings.Contains(r.out.String(), " after") })
	if got, want := r.out.String(), "hi \x1b[1mbold\x1b[0m  after"; got != want {
		t.Errorf("terminal received %q, want %q", got, want)
	}
	r.inW.Write([]byte("ls -la\r"))
	if f := d.frame(attach.Data); string(f.Payload) != "ls -la\r" {
		t.Errorf("agent received %q", f.Payload)
	}
	<-d.ready
	if d.hello.Mode != attach.ModeAgent || d.hello.Term != "xterm" {
		t.Errorf("hello %+v", d.hello)
	}
}

func TestLeaderDetaches(t *testing.T) {
	d, c := startDaemon(t, attach.Reply{OK: true})
	r := runRelay(t, c, nil)
	r.inW.Write([]byte("a" + leader + "d"))
	d.frame(attach.Detach)
	if res, err := r.wait(t); err != nil || !res.Detached {
		t.Fatalf("result %+v err %v", res, err)
	}
}

func TestExitFrameEndsTheRelayWithTheCode(t *testing.T) {
	d, c := startDaemon(t, attach.Reply{OK: true})
	r := runRelay(t, c, nil)
	<-d.ready
	d.send("bye")
	d.conn.SendJSON(attach.Exit, attach.ExitInfo{Code: 3})
	res, err := r.wait(t)
	if err != nil || res.Exit == nil || res.Exit.Code != 3 {
		t.Fatalf("result %+v err %v", res, err)
	}
	if !strings.Contains(r.out.String(), "bye") {
		t.Errorf("output before the exit was lost: %q", r.out.String())
	}
}

func TestRefusedAttachIsAnError(t *testing.T) {
	_, c := startDaemon(t, attach.Reply{Error: "this session already has a client attached"})
	r := runRelay(t, c, nil)
	if _, err := r.wait(t); err == nil || !strings.Contains(err.Error(), "already has a client") {
		t.Fatalf("err %v", err)
	}
}

func TestDroppedConnectionAndClosedInputEndTheRelay(t *testing.T) {
	d, c := startDaemon(t, attach.Reply{OK: true})
	r := runRelay(t, c, nil)
	<-d.ready
	d.raw.Close() // the daemon goes away
	if res, err := r.wait(t); err != nil || res.Exit != nil || res.Detached {
		t.Errorf("dropped connection: %+v %v", res, err)
	}
	d2, c2 := startDaemon(t, attach.Reply{OK: true})
	r2 := runRelay(t, c2, nil)
	<-d2.ready
	r2.inW.Close() // the terminal went away
	if _, err := r2.wait(t); err != nil {
		t.Errorf("closed input: %v", err)
	}
}

func TestPasteMarkersAreStrippedUnlessTheAgentAsked(t *testing.T) {
	paste := "\x1b[200~a" + leader + "db\x1b[201~"
	d, c := startDaemon(t, attach.Reply{OK: true})
	r := runRelay(t, c, nil)
	r.inW.Write([]byte(paste))
	if f := d.frame(attach.Data); string(f.Payload) != "a"+leader+"db" {
		t.Errorf("without bracketed paste the agent received %q", f.Payload)
	}

	d2, c2 := startDaemon(t, attach.Reply{OK: true})
	r2 := runRelay(t, c2, nil)
	<-d2.ready
	d2.send("\x1b[?2004h")
	time.Sleep(50 * time.Millisecond) // let the relay notice the mode before the paste arrives
	r2.inW.Write([]byte(paste))
	if f := d2.frame(attach.Data); string(f.Payload) != paste {
		t.Errorf("with bracketed paste the agent received %q, want the markers kept", f.Payload)
	}
	if strings.Contains(r2.out.String(), "2004") {
		t.Errorf("the agent's paste-mode toggle reached the terminal: %q", r2.out.String())
	}
	select {
	case f := <-d2.got:
		if f.Type == attach.Detach {
			t.Error("a leader inside a paste detached the session")
		}
	case <-time.After(100 * time.Millisecond):
	}
}

func TestLoneEscapeReachesTheAgent(t *testing.T) {
	d, c := startDaemon(t, attach.Reply{OK: true})
	r := runRelay(t, c, nil)
	r.inW.Write([]byte("\x1b"))
	if f := d.frame(attach.Data); string(f.Payload) != "\x1b" {
		t.Errorf("agent received %q", f.Payload)
	}
}

// ---- with a real terminal (a pty): raw mode, bracketed paste, size, restoration ----

func termFlags(t *testing.T, f *os.File) uint32 {
	t.Helper()
	var tio syscall.Termios
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), 0x5401, uintptr(unsafe.Pointer(&tio))); e != 0 {
		t.Fatal(e)
	}
	return tio.Lflag
}

func TestRealTerminalRawModePasteModeSizeAndRestore(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Skipf("no pty here: %v", err)
	}
	defer master.Close()
	defer slave.Close()
	pty.SetSize(master, 120, 40)
	before := termFlags(t, slave)

	// what the user's terminal emulator would show
	shown := &syncBuf{}
	go io.Copy(shown, master)

	d, c := startDaemon(t, attach.Reply{OK: true})
	winch := make(chan os.Signal, 1)
	res := make(chan Result, 1)
	go func() {
		r, _ := Run(Options{Conn: c, Hello: attach.HelloMsg{Mode: attach.ModeAgent, Term: "xterm"}, Leader: 0x1c, In: slave, Out: slave, TTY: slave, Winch: winch})
		res <- r
	}()

	<-d.ready
	if d.hello.Cols != 120 || d.hello.Rows != 40 {
		t.Errorf("hello carries %dx%d, want the terminal's 120x40", d.hello.Cols, d.hello.Rows)
	}
	eventually(t, "raw mode", func() bool { return termFlags(t, slave)&(syscall.ECHO|syscall.ICANON|syscall.ISIG) == 0 })
	eventually(t, "bracketed paste to be enabled on the real terminal", func() bool { return strings.Contains(shown.String(), "\x1b[?2004h") })

	// typing: no local echo, the agent's echo is the only copy that appears
	master.Write([]byte("xyz"))
	if f := d.frame(attach.Data); string(f.Payload) != "xyz" {
		t.Fatalf("agent received %q", f.Payload)
	}
	d.send("xyz")
	eventually(t, "the agent's echo", func() bool { return strings.Contains(shown.String(), "xyz") })
	time.Sleep(100 * time.Millisecond)
	if n := strings.Count(shown.String(), "xyz"); n != 1 {
		t.Errorf("the typed text appeared %d times: the terminal is echoing locally (not raw)", n)
	}

	// a window-size change is forwarded
	pty.SetSize(master, 90, 30)
	winch <- syscall.SIGWINCH
	cols, rows, err := attach.ParseResize(d.frame(attach.Resize).Payload)
	if err != nil || cols != 90 || rows != 30 {
		t.Errorf("forwarded size %dx%d (%v)", cols, rows, err)
	}

	// the agent leaves the alternate screen on and the cursor hidden; the terminal must come back usable
	d.send("\x1b[?1049h\x1b[?25l")
	time.Sleep(50 * time.Millisecond)
	d.conn.SendJSON(attach.Exit, attach.ExitInfo{Code: 0})
	select {
	case <-res:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay did not return")
	}
	eventually(t, "the terminal to be restored", func() bool { return termFlags(t, slave) == before })
	for _, want := range []string{"\x1b[?1049l", "\x1b[?2004l", "\x1b[?25h", "\x1b[0m"} {
		eventually(t, "the cleanup sequence "+strings.ReplaceAll(want, "\x1b", "ESC"), func() bool { return strings.Contains(shown.String(), want) })
	}
}
