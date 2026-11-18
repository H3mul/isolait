package relay

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/H3mul/isolait/internal/attach"
)

// maxHeld bounds the agent output kept while the prompt is open; beyond it chunks are dropped and the agent is
// asked to repaint when the prompt closes.
const maxHeld = 4 << 20

// promptState is the leader prompt: a one-line editor on the terminal's bottom row.
//
// On a normal screen the prompt opens on the terminal's alternate screen, so closing it brings the agent's
// screen back exactly as it was. When the agent itself is on the alternate screen (which cannot be nested) the
// prompt overwrites the bottom row between a saved and a restored cursor, and the agent is asked to repaint.
// Agent output is held while the prompt is open so it cannot draw over it.
type promptState struct {
	open     bool
	overlay  bool // opened on the alternate screen
	running  bool // Enter was pressed: a command is running or its result is showing
	editor   editor
	held     [][]byte
	heldLen  int
	dropped  bool
	hideTick *time.Timer
}

func (s *state) openPrompt() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.o.Prompt == nil {
		s.filter.ClosePrompt()
		return
	}
	s.prompt = promptState{open: true, overlay: !s.san.Modes().AltScreen}
	var b strings.Builder
	if s.prompt.overlay {
		b.WriteString("\x1b[?1049h\x1b[2J")
	} else {
		b.WriteString("\x1b7")
	}
	s.drawPromptLocked(&b)
	s.writeOut([]byte(b.String()))
}

func (s *state) promptInput(data []byte) {
	s.mu.Lock()
	if !s.prompt.open {
		noPrompt := s.o.Prompt == nil
		s.mu.Unlock()
		if noPrompt { // the leader opened no prompt, so what was typed after it is ordinary input for the agent
			s.conn.Send(attach.Frame{Type: attach.Data, Payload: data})
		}
		return
	}
	if s.prompt.running {
		s.mu.Unlock()
		return
	}
	act, changed := s.prompt.editor.feed(data)
	switch act {
	case actDismiss:
		s.closePromptLocked()
	case actRun:
		line := s.prompt.editor.text()
		s.prompt.running = true
		s.filter.ClosePrompt() // keyboard goes back to the agent while the result is showing
		s.mu.Unlock()
		go s.runPrompt(line)
		return
	default:
		if changed {
			var b strings.Builder
			s.drawPromptLocked(&b)
			s.writeOut([]byte(b.String()))
		}
	}
	s.mu.Unlock()
}

func (s *state) runPrompt(line string) {
	result := s.o.Prompt(line) // outside the lock: it may talk to the daemon
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.prompt.open {
		return
	}
	var b strings.Builder
	s.drawRowLocked(&b, displayText(result, s.cols-1))
	b.WriteString("\x1b[?25l")
	s.writeOut([]byte(b.String()))
	s.prompt.hideTick = time.AfterFunc(s.o.ResultHold, func() {
		s.mu.Lock()
		s.closePromptLocked()
		s.mu.Unlock()
	})
}

// closePromptLocked removes the prompt, puts the cursor and the screen back, and releases the held output.
func (s *state) closePromptLocked() {
	if !s.prompt.open {
		return
	}
	var b strings.Builder
	if s.prompt.overlay {
		b.WriteString("\x1b[?1049l")
	} else {
		b.WriteString("\x1b8")
	}
	if s.san.Modes().CursorHidden {
		b.WriteString("\x1b[?25l")
	} else {
		b.WriteString("\x1b[?25h")
	}
	s.writeOut([]byte(b.String()))
	if !s.prompt.overlay || s.prompt.dropped {
		s.conn.Send(attach.Frame{Type: attach.Redraw}) // the bottom row was overwritten, or output was lost
	}
	for _, h := range s.prompt.held {
		s.writeOut(h)
	}
	if t := s.prompt.hideTick; t != nil {
		t.Stop()
	}
	s.filter.ClosePrompt()
	s.prompt = promptState{}
}

func (s *state) holdLocked(b []byte) {
	if s.prompt.heldLen+len(b) > maxHeld {
		s.prompt.dropped = true
		return
	}
	s.prompt.held = append(s.prompt.held, b)
	s.prompt.heldLen += len(b)
}

func (s *state) drawPromptLocked(b *strings.Builder) {
	text := ":" + s.prompt.editor.text()
	shown := displayText(text, s.cols-1)
	s.drawRowLocked(b, shown)
	col := len([]rune(shown)) + 1
	fmt.Fprintf(b, "\x1b[%d;%dH\x1b[?25h", s.rows, col)
}

// drawRowLocked paints text on the bottom row in reverse video.
func (s *state) drawRowLocked(b *strings.Builder, text string) {
	fmt.Fprintf(b, "\x1b[%d;1H\x1b[2K\x1b[7m%s\x1b[0m", s.rows, text)
}

// displayText makes text safe and short enough for one terminal row: control characters are dropped (so a
// command's output can never inject escape sequences) and it is cut to width runes. Lines are joined with " | ".
func displayText(s string, width int) string {
	var out []rune
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(out) > 0 {
			out = append(out, []rune(" | ")...)
		}
		for _, r := range line {
			if unicode.IsControl(r) {
				continue
			}
			out = append(out, r)
		}
	}
	if width < 1 {
		width = 1
	}
	if len(out) > width {
		out = append(out[:width-1], '…')
	}
	return string(out)
}
