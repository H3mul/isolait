// Package relay is the client side of an attached session: it connects the user's terminal to the daemon's
// attach socket. Keyboard input goes through the leader-key filter, agent output through the sanitizer before
// it reaches the terminal, window-size changes are forwarded, and the terminal is put back the way it was when
// the session ends or the user detaches.
package relay

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/H3mul/isolait/internal/attach"
	"github.com/H3mul/isolait/internal/pty"
	"github.com/H3mul/isolait/internal/term"
)

// Options configures one attached session.
type Options struct {
	Conn   net.Conn        // the connected attach socket
	Hello  attach.HelloMsg // Mode (and Argv for exec); Cols, Rows and Term are filled in when empty
	Leader byte            // the leader key's control byte
	In     io.Reader       // keyboard input
	Out    io.Writer       // the terminal
	// TTY is the user's terminal. When set the relay puts it in raw mode, enables bracketed paste on it, reads
	// its size and follows SIGWINCH, and restores everything on return. Nil for tests and non-terminals.
	TTY *os.File
	// Winch delivers window-size changes; defaults to SIGWINCH when TTY is set. A test seam.
	Winch <-chan os.Signal
	// EscapeWait is how long a lone Escape is held back in case it starts a paste marker (default 50 ms).
	EscapeWait time.Duration
	// Prompt runs a command line typed in the leader prompt for the current session and returns the text to
	// show. Nil disables the prompt (leader then : does nothing).
	Prompt func(line string) string
	// ResultHold is how long the prompt's result stays on screen before it closes (default 1.5 s).
	ResultHold time.Duration
}

// Result says how the session ended.
type Result struct {
	Exit     *attach.ExitInfo // the process ended
	Detached bool             // the user left with leader, d
}

// Run attaches until the process exits, the user detaches or the connection drops.
func Run(o Options) (Result, error) {
	conn := attach.NewConn(o.Conn)
	h := o.Hello
	if o.TTY != nil {
		if cols, rows, err := pty.GetSize(int(o.TTY.Fd())); err == nil {
			h.Cols, h.Rows = cols, rows
		}
	}
	if h.Term == "" {
		h.Term = os.Getenv("TERM")
	}
	if err := conn.SendJSON(attach.Hello, h); err != nil {
		return Result{}, err
	}
	f, err := conn.Recv()
	if err != nil {
		return Result{}, err
	}
	var reply attach.Reply
	if err := json.Unmarshal(f.Payload, &reply); err != nil {
		return Result{}, err
	}
	if !reply.OK {
		return Result{}, errors.New(reply.Error)
	}
	if o.EscapeWait == 0 {
		o.EscapeWait = 50 * time.Millisecond
	}
	if o.ResultHold == 0 {
		o.ResultHold = 1500 * time.Millisecond
	}

	s := &state{o: o, conn: conn, filter: term.NewInputFilter(o.Leader), done: make(chan struct{}), cols: h.Cols, rows: h.Rows}
	if s.cols < 1 || s.rows < 1 {
		s.cols, s.rows = 80, 24
	}
	restore := s.enterTerminal()
	defer restore()

	go s.readOutput()
	go s.readInput()
	if o.TTY != nil {
		w := o.Winch
		if w == nil {
			ch := make(chan os.Signal, 1)
			signal.Notify(ch, syscall.SIGWINCH)
			defer signal.Stop(ch)
			w = ch
		}
		go s.followWindow(w)
	}
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.result, s.err
}

type state struct {
	o      Options
	conn   *attach.Conn
	filter *term.InputFilter
	san    term.Sanitizer

	cols, rows int
	prompt     promptState

	mu     sync.Mutex // guards filter, san, size, prompt, result, err and timer
	outMu  sync.Mutex // serialises writes to the terminal
	result Result
	err    error
	once   sync.Once
	done   chan struct{}
	timer  *time.Timer
}

func (s *state) finish(r Result, err error) {
	s.once.Do(func() {
		s.mu.Lock()
		s.result, s.err = r, err
		s.mu.Unlock()
		close(s.done)
	})
}

func (s *state) writeOut(b []byte) {
	s.outMu.Lock()
	defer s.outMu.Unlock()
	s.o.Out.Write(b)
}

// enterTerminal makes the real terminal raw and bracketed-paste-enabled and returns the function that undoes it.
func (s *state) enterTerminal() func() {
	if s.o.TTY == nil {
		return func() {}
	}
	fd := int(s.o.TTY.Fd())
	old, err := pty.MakeRaw(fd)
	if err != nil {
		return func() {}
	}
	// The terminal always wraps pastes in markers, whatever the agent wants, so pasted text can never be
	// mistaken for typed keys; the input filter strips the markers unless the agent asked for them.
	s.writeOut([]byte("\x1b[?2004h"))
	return func() {
		s.mu.Lock()
		s.closePromptLocked() // leave the prompt's overlay if the session ended while it was open
		alt := s.san.Modes().AltScreen
		s.mu.Unlock()
		seq := "\x1b[?2004l" // our own paste mode
		if alt {
			seq += "\x1b[?1049l" // leave the agent's alternate screen
		}
		// leave the terminal usable whatever the agent left on: mouse reporting, keypad modes, hidden cursor, colours
		seq += "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1l\x1b>\x1b[?25h\x1b[0m"
		s.writeOut([]byte(seq))
		pty.Restore(fd, old)
	}
}

func (s *state) readOutput() {
	for {
		f, err := s.conn.Recv()
		if err != nil {
			s.finish(Result{}, nil) // the daemon closed the connection: the session is over
			return
		}
		switch f.Type {
		case attach.Data:
			s.mu.Lock()
			clean := append([]byte(nil), s.san.Write(f.Payload)...)
			s.filter.SetAgentPaste(s.san.Modes().BracketedPaste)
			if s.prompt.open {
				s.holdLocked(clean) // the prompt owns the bottom row: show the agent's output once it closes
			} else {
				s.writeOut(clean)
			}
			s.mu.Unlock()
		case attach.Exit:
			var e attach.ExitInfo
			json.Unmarshal(f.Payload, &e)
			s.finish(Result{Exit: &e}, nil)
			return
		}
	}
}

func (s *state) readInput() {
	buf := make([]byte, 4096)
	for {
		n, err := s.o.In.Read(buf)
		if n > 0 {
			s.mu.Lock()
			evs := s.filter.Write(buf[:n])
			pending := s.filter.Pending()
			s.mu.Unlock()
			if s.apply(evs) {
				return
			}
			if pending { // maybe the start of a paste marker, maybe a lone Escape: decide after a short silence
				s.armFlush()
			}
		}
		if err != nil {
			s.finish(Result{}, nil)
			return
		}
	}
}

func (s *state) armFlush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(s.o.EscapeWait, func() {
		s.mu.Lock()
		evs := s.filter.Flush()
		s.mu.Unlock()
		s.apply(evs)
	})
}

// apply carries out the filter's decisions; it reports whether the session is over.
func (s *state) apply(evs []term.Event) bool {
	for _, e := range evs {
		switch e.Kind {
		case term.EvData:
			s.conn.Send(attach.Frame{Type: attach.Data, Payload: e.Data})
		case term.EvDetach:
			s.conn.Send(attach.Frame{Type: attach.Detach})
			s.finish(Result{Detached: true}, nil)
			return true
		case term.EvPrompt:
			s.openPrompt()
		case term.EvPromptInput:
			s.promptInput(e.Data)
		}
	}
	return false
}

func (s *state) followWindow(w <-chan os.Signal) {
	for {
		select {
		case <-w:
			if cols, rows, err := pty.GetSize(int(s.o.TTY.Fd())); err == nil {
				s.mu.Lock()
				s.cols, s.rows = cols, rows
				s.mu.Unlock()
				s.conn.Send(attach.Frame{Type: attach.Resize, Payload: attach.ResizePayload(cols, rows)})
			}
		case <-s.done:
			return
		}
	}
}
