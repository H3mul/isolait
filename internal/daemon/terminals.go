package daemon

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/H3mul/isolait/internal/attach"
	"github.com/H3mul/isolait/internal/ctl"
	"github.com/H3mul/isolait/internal/initshim"
	"github.com/H3mul/isolait/internal/pty"
	"github.com/H3mul/isolait/internal/term"
)

// terminals owns the pseudo-terminals of one session: the agent's, and one per `exec`. It starts processes
// through the init shim with a PTY slave as stdio, keeps the master, and streams it to attached clients.
//
// Every byte that comes out of a PTY goes through output(): that is the single path later features (a log tee,
// a VT emulator for scrollback) hook into. With no client attached the bytes are read and dropped, so an
// unattended agent never blocks on a full terminal buffer; Phase 1 keeps no scrollback.
type terminals struct {
	cl   *initshim.Client
	argv []string // the agent command as started inside the sandbox
	env  []string // the sandbox environment; TERM is added per client
	cwd  string

	onUse func() // the user attached or detached (not exec): the session was just used

	// deferred: the agent is started by the first attach (with that terminal's TERM and size) instead of at once.
	deferred bool
	ring     []byte        // the last ringSize bytes of the agent's output, for a start that fails at once
	done     chan struct{} // closed when the agent has exited and its client has been told
	exit     attach.ExitInfo
	started  time.Time // when the agent was started

	mu       sync.Mutex
	agent    *proc
	attached *client
	tracker  term.Sanitizer // only its mode tracking is used, to restore the agent's modes on reattach
	execs    map[*proc]bool
	handlers map[int]*proc
	early    map[int]initshim.Event
	closed   bool

	// outputHook sees every PTY byte before it is routed; tests use it to prove the single path.
	outputHook func([]byte)
}

type proc struct {
	id      int
	master  *os.File
	agent   bool
	client  *client // exec: its only client
	outDone chan struct{}
	exited  chan initshim.Event
}

// client is one attached connection. gate is held while a hello is being answered so no terminal data can
// overtake the reply.
type client struct {
	conn *attach.Conn
	raw  net.Conn
	gate sync.Mutex
}

func (c *client) send(f attach.Frame) {
	c.gate.Lock()
	c.gate.Unlock()
	c.raw.SetWriteDeadline(time.Now().Add(5 * time.Second)) // a stuck client must not stall the PTY reader
	if err := c.conn.Send(f); err != nil {
		c.raw.Close()
	}
}

func newTerminals(cl *initshim.Client, argv, env []string, cwd string) *terminals {
	t := &terminals{cl: cl, argv: argv, env: env, cwd: cwd, execs: map[*proc]bool{}, handlers: map[int]*proc{}, early: map[int]initshim.Event{}}
	go t.dispatchExits()
	t.done = make(chan struct{})
	return t
}

// State is attached or detached: a session exists only while its agent runs (or is about to start with the
// first attach).
func (t *terminals) State() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.attached != nil {
		return "attached"
	}
	return "detached"
}

// neverStarted reports that no agent has been started yet (a deferred session still waiting for its attach).
func (t *terminals) neverStarted() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.deferred && t.agent == nil
}

// ringSize is how much of the agent's output is kept for a start that fails at once.
const ringSize = 2048

// StartNow starts the agent without a client, on a pty of the given size (an attach resizes it).
func (t *terminals) StartNow(termName string, cols, rows int) error {
	a, err := t.spawn(t.argv, t.environ(termName), cols, rows, true, nil)
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.agent = a
	t.started = time.Now()
	t.mu.Unlock()
	return nil
}

// Startup is the answer to "did the agent survive its first moments".
type Startup struct {
	Exited bool   `json:"exited"`
	Code   int    `json:"code,omitempty"`
	Signal int    `json:"signal,omitempty"`
	Tail   string `json:"tail,omitempty"` // the last 2 KiB of the agent's output, control characters removed
}

// WaitStartup blocks until the agent exits or grace has passed since it was started.
func (t *terminals) WaitStartup(grace time.Duration) Startup {
	t.mu.Lock()
	left := grace - time.Since(t.started)
	t.mu.Unlock()
	if left < 0 {
		left = 0
	}
	select {
	case <-t.done:
		t.mu.Lock()
		defer t.mu.Unlock()
		return Startup{Exited: true, Code: t.exit.Code, Signal: t.exit.Signal, Tail: printable(t.ring)}
	case <-time.After(left):
		return Startup{}
	}
}

// printable keeps text and newlines: output of an agent that failed is shown on the user's terminal, so
// escape sequences and other control bytes are dropped.
func printable(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == '\n' || c == '\t' || c >= 0x20 && c != 0x7f {
			out = append(out, c)
		}
	}
	return string(out)
}

// Listen serves the attach socket until the returned listener is closed.
func (t *terminals) Listen(path string) (*net.UnixListener, error) {
	l, err := ctl.ListenUnix(path)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			c, err := l.AcceptUnix()
			if err != nil {
				return
			}
			if !ctl.PeerOK(c) {
				c.Close()
				continue
			}
			go t.Serve(c)
		}
	}()
	return l, nil
}

// Close disconnects every client; the processes die with the sandbox.
func (t *terminals) Close() {
	t.mu.Lock()
	t.closed = true
	var raws []net.Conn
	if t.attached != nil {
		raws = append(raws, t.attached.raw)
	}
	for p := range t.execs {
		raws = append(raws, p.client.raw)
	}
	t.mu.Unlock()
	for _, r := range raws {
		r.Close()
	}
}

func (t *terminals) dispatchExits() {
	for e := range t.cl.Exits() {
		t.mu.Lock()
		p := t.handlers[e.ID]
		if p == nil {
			t.early[e.ID] = e // the exit beat the registration in spawn
		} else {
			delete(t.handlers, e.ID)
		}
		t.mu.Unlock()
		if p != nil {
			p.exited <- e
		}
	}
}

var termRe = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)

func (t *terminals) environ(termName string) []string {
	if !termRe.MatchString(termName) {
		termName = "xterm-256color"
	}
	env := make([]string, 0, len(t.env)+1)
	for _, kv := range t.env {
		if !strings.HasPrefix(kv, "TERM=") {
			env = append(env, kv)
		}
	}
	return append(env, "TERM="+termName)
}

func clampSize(cols, rows int) (int, int) {
	if cols < 1 || cols > 1000 {
		cols = 80
	}
	if rows < 1 || rows > 1000 {
		rows = 24
	}
	return cols, rows
}

// spawn starts argv in the sandbox on a fresh PTY and begins streaming it.
func (t *terminals) spawn(argv []string, env []string, cols, rows int, agent bool, cl *client) (*proc, error) {
	master, slave, err := pty.Open()
	if err != nil {
		return nil, err
	}
	if err := pty.SetSize(master, cols, rows); err != nil {
		master.Close()
		slave.Close()
		return nil, err
	}
	id, _, err := t.cl.Spawn(argv, env, t.cwd, true, [3]*os.File{slave, slave, slave})
	slave.Close()
	if err != nil {
		master.Close()
		return nil, err
	}
	p := &proc{id: id, master: master, agent: agent, client: cl, outDone: make(chan struct{}), exited: make(chan initshim.Event, 1)}
	t.mu.Lock()
	t.handlers[id] = p
	if e, ok := t.early[id]; ok {
		delete(t.early, id)
		delete(t.handlers, id)
		p.exited <- e
	}
	t.mu.Unlock()
	go t.readLoop(p)
	go t.finish(p)
	return p, nil
}

func (t *terminals) readLoop(p *proc) {
	defer close(p.outDone)
	buf := make([]byte, 32<<10)
	for {
		n, err := p.master.Read(buf)
		if n > 0 {
			t.output(p, buf[:n])
		}
		if err != nil {
			return // EIO once every holder of the slave has gone
		}
	}
}

// output is the single path for every PTY byte.
func (t *terminals) output(p *proc, b []byte) {
	if t.outputHook != nil {
		t.outputHook(b)
	}
	var dst *client
	t.mu.Lock()
	if p.agent {
		t.tracker.Write(b)
		t.ring = append(t.ring, b...)
		if len(t.ring) > ringSize {
			t.ring = t.ring[len(t.ring)-ringSize:]
		}
		dst = t.attached
	} else {
		dst = p.client
	}
	t.mu.Unlock()
	if dst != nil {
		dst.send(attach.Frame{Type: attach.Data, Payload: append([]byte(nil), b...)})
	}
}

// finish waits for the process to exit, lets the last output drain, tells the client and cleans up.
func (t *terminals) finish(p *proc) {
	e := <-p.exited
	select {
	case <-p.outDone:
	case <-time.After(time.Second): // a grandchild may still hold the terminal open
	}
	p.master.Close()
	var dst *client
	t.mu.Lock()
	if p.agent {
		t.agent = nil
		t.exit = attach.ExitInfo{Code: e.Code, Signal: e.Signal}
		dst, t.attached = t.attached, nil
	} else {
		delete(t.execs, p)
		dst = p.client
	}
	t.mu.Unlock()
	if dst != nil {
		dst.conn.SendJSON(attach.Exit, attach.ExitInfo{Code: e.Code, Signal: e.Signal})
		dst.raw.Close()
	}
	if p.agent {
		close(t.done) // the session ends with its agent
	}
}

// Serve handles one authenticated connection: hello, then frames until it detaches or the process ends.
func (t *terminals) Serve(raw net.Conn) {
	defer raw.Close()
	c := &client{conn: attach.NewConn(raw), raw: raw}
	reject := func(msg string) { c.conn.SendJSON(attach.Hello, attach.Reply{Error: msg}) }

	raw.SetReadDeadline(time.Now().Add(10 * time.Second))
	f, err := c.conn.Recv()
	if err != nil || f.Type != attach.Hello {
		return
	}
	raw.SetReadDeadline(time.Time{})
	var h attach.HelloMsg
	if err := json.Unmarshal(f.Payload, &h); err != nil {
		reject("bad hello")
		return
	}
	h.Cols, h.Rows = clampSize(h.Cols, h.Rows)
	switch h.Mode {
	case attach.ModeAgent:
		t.serveAgent(c, h)
	case attach.ModeExec:
		if len(h.Argv) == 0 || len(h.Argv) > 4096 {
			reject("exec needs a command")
			return
		}
		t.serveExec(c, h)
	default:
		reject(fmt.Sprintf("unknown mode %q", h.Mode))
	}
}

func (t *terminals) serveAgent(c *client, h attach.HelloMsg) {
	c.gate.Lock() // no terminal data before the reply
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		c.gate.Unlock()
		c.conn.SendJSON(attach.Hello, attach.Reply{Error: "the session is shutting down"})
		return
	}
	if t.attached != nil {
		t.mu.Unlock()
		c.gate.Unlock()
		c.conn.SendJSON(attach.Hello, attach.Reply{Error: "this session already has a client attached; detach it first"})
		return
	}
	a := t.agent
	if a == nil && !t.deferred { // the agent has exited: the session is ending
		t.mu.Unlock()
		c.gate.Unlock()
		c.conn.SendJSON(attach.Hello, attach.Reply{Error: "the session has ended"})
		return
	}
	t.attached = c
	t.mu.Unlock()
	t.used()

	restarted := false
	if a == nil { // first attach of a session started attached: the agent starts with this terminal
		var err error
		a, err = t.spawn(t.argv, t.environ(h.Term), h.Cols, h.Rows, true, nil)
		if err != nil {
			t.mu.Lock()
			t.attached = nil
			t.mu.Unlock()
			c.gate.Unlock()
			c.conn.SendJSON(attach.Hello, attach.Reply{Error: "starting the agent: " + err.Error()})
			return
		}
		t.mu.Lock()
		t.agent, t.deferred, t.started = a, false, time.Now()
		t.mu.Unlock()
		restarted = true
	} else {
		pty.SetSize(a.master, h.Cols, h.Rows)
	}
	c.conn.SendJSON(attach.Hello, attach.Reply{OK: true, Restarted: restarted})
	if !restarted { // a fresh terminal for a running agent: restore its modes, then ask it to repaint
		t.mu.Lock()
		modes := t.tracker.Modes()
		t.mu.Unlock()
		if modes.AltScreen {
			c.conn.Send(attach.Frame{Type: attach.Data, Payload: []byte("\x1b[?1049h")})
		}
		t.cl.Signal(a.id, int(syscall.SIGWINCH))
	}
	c.gate.Unlock()

	t.pump(c, a)
	t.mu.Lock()
	if t.attached == c {
		t.attached = nil
	}
	t.mu.Unlock()
	t.used()
}

func (t *terminals) used() {
	if t.onUse != nil {
		t.onUse()
	}
}

func (t *terminals) serveExec(c *client, h attach.HelloMsg) {
	c.gate.Lock()
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		c.gate.Unlock()
		c.conn.SendJSON(attach.Hello, attach.Reply{Error: "the session is shutting down"})
		return
	}
	p, err := t.spawn(h.Argv, t.environ(h.Term), h.Cols, h.Rows, false, c)
	if err != nil {
		c.gate.Unlock()
		c.conn.SendJSON(attach.Hello, attach.Reply{Error: err.Error()})
		return
	}
	t.mu.Lock()
	t.execs[p] = true
	t.mu.Unlock()
	c.conn.SendJSON(attach.Hello, attach.Reply{OK: true})
	c.gate.Unlock()

	t.pump(c, p)
	// the client is gone (detach, closed terminal): an exec session does not outlive it
	t.cl.Signal(p.id, int(syscall.SIGHUP))
	time.AfterFunc(2*time.Second, func() { t.cl.Signal(p.id, int(syscall.SIGKILL)) })
}

// pump applies a client's frames to a process until the client detaches or disconnects.
func (t *terminals) pump(c *client, p *proc) {
	for {
		f, err := c.conn.Recv()
		if err != nil {
			return
		}
		switch f.Type {
		case attach.Data:
			p.master.Write(f.Payload)
		case attach.Resize:
			if cols, rows, err := attach.ParseResize(f.Payload); err == nil {
				cols, rows = clampSize(cols, rows)
				pty.SetSize(p.master, cols, rows)
			}
		case attach.Redraw:
			t.cl.Signal(p.id, int(syscall.SIGWINCH))
		case attach.Detach:
			return
		}
	}
}
