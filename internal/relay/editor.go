package relay

import "unicode/utf8"

// action is what the prompt should do after some input.
type action int

const (
	actNone    action = iota // keep editing (a redraw may be needed: see changed)
	actRun                   // Enter on a non-empty line
	actDismiss               // Escape, Ctrl-C, or Enter on an empty line
)

const maxLine = 256 // runes; a command line longer than this is a mistake

// editor is the one-line editor behind the leader prompt: printable text, Backspace, Ctrl-U, Enter and Escape.
// Arrow keys and other escape sequences are ignored, so they cannot dismiss the prompt or leak into the line.
type editor struct {
	line    []rune
	partial []byte // an incomplete UTF-8 sequence cut by a read boundary
}

func (e *editor) text() string { return string(e.line) }

// feed applies keyboard bytes. It stops at the first Enter or dismissal and reports it; changed says whether the
// visible line differs from before.
func (e *editor) feed(in []byte) (act action, changed bool) {
	b := append(e.partial, in...)
	e.partial = nil
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c == '\r' || c == '\n':
			if len(e.line) == 0 {
				return actDismiss, changed
			}
			return actRun, changed
		case c == 0x03: // Ctrl-C
			return actDismiss, changed
		case c == 0x1b:
			if i+1 >= len(b) {
				return actDismiss, changed // a lone Escape
			}
			switch b[i+1] {
			case '[': // CSI: skip to its final byte
				j := i + 2
				for j < len(b) && !(b[j] >= 0x40 && b[j] <= 0x7e) {
					j++
				}
				i = j + 1
			case 'O': // SS3 (application-mode arrow keys): one more byte
				i += 3
			default: // Alt-key: ignore both bytes
				i += 2
			}
			continue
		case c == 0x7f || c == 0x08: // Backspace
			if len(e.line) > 0 {
				e.line = e.line[:len(e.line)-1]
				changed = true
			}
		case c == 0x15: // Ctrl-U
			if len(e.line) > 0 {
				e.line = e.line[:0]
				changed = true
			}
		case c < 0x20:
			// other control characters are ignored
		default:
			if !utf8.FullRune(b[i:]) {
				e.partial = append([]byte(nil), b[i:]...)
				return actNone, changed
			}
			r, n := utf8.DecodeRune(b[i:])
			if r != utf8.RuneError && len(e.line) < maxLine {
				e.line = append(e.line, r)
				changed = true
			}
			i += n
			continue
		}
		i++
	}
	return actNone, changed
}
