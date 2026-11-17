// Package term holds the terminal-facing pieces of the client: the output sanitizer, the input filter with
// the leader key, and the mode tracker. The sanitizer is a filter, not an emulator: it narrows what an agent
// can do to the user's terminal (clipboard writes, title changes, device controls, window manipulation) and
// does not claim to eliminate terminal injection.
package term

// Modes are the terminal modes the agent has asked for, tracked from its output. The daemon uses them to put a
// fresh terminal back into the agent's state on reattach; the client uses them to place its prompt.
type Modes struct {
	AltScreen      bool // ?1049, ?1047 or ?47
	BracketedPaste bool // ?2004: the client keeps the real terminal in this mode itself, see Sanitizer
}

type state int

const (
	gnd     state = iota
	esc           // after ESC
	escI          // ESC followed by intermediates, e.g. ESC ( B
	csi           // ESC [ ...
	csiDrop       // an over-long CSI: swallow until its final byte, forward nothing
	osc           // ESC ] ...
	oscEsc        // ESC inside an OSC, waiting for the backslash of ST
	str           // DCS, APC, PM, SOS: swallowed until ST
	strEsc        // ESC inside such a string
)

const (
	maxCSI    = 256
	maxOSC    = 2048  // longest OSC 8 hyperlink forwarded
	maxString = 65536 // DCS/APC/PM/SOS and rejected OSC: swallowed up to this size, then abandoned
)

// Sanitizer filters terminal output bytes. It keeps the state of a partly received sequence between calls, so
// sequences split across reads are handled; a sequence is forwarded only once it is complete and allowed.
//
// What is dropped: every OSC except OSC 8 hyperlinks (so clipboard writes, window titles and the reporting
// queries), all DCS, APC, PM and SOS strings (sixel, DECRQSS, graphics protocols), every CSI ... t (window
// manipulation and its title reports) and ENQ. Mode 2004 (bracketed paste) toggles are consumed and tracked,
// not forwarded: the client keeps the real terminal in that mode so pasted text can never be mistaken for typed
// keys. Everything else, including colors, cursor movement and the alternate screen, passes unchanged.
type Sanitizer struct {
	st    state
	buf   []byte // the sequence being collected
	n     int    // bytes swallowed so far in a string state
	modes Modes
	out   []byte
}

// Modes returns the modes the agent has requested so far.
func (s *Sanitizer) Modes() Modes { return s.modes }

// Write filters p and returns the bytes that may be sent to the terminal. The returned slice is only valid
// until the next call.
func (s *Sanitizer) Write(p []byte) []byte {
	s.out = s.out[:0]
	for _, b := range p {
		s.step(b)
	}
	return s.out
}

func (s *Sanitizer) emit(b ...byte) { s.out = append(s.out, b...) }

func (s *Sanitizer) reset() { s.st, s.buf, s.n = gnd, s.buf[:0], 0 }

func (s *Sanitizer) step(b byte) {
	switch s.st {
	case gnd:
		switch b {
		case 0x1b:
			s.st, s.buf = esc, append(s.buf[:0], b)
		case 0x05: // ENQ: asks the terminal for its answerback string
		default:
			s.emit(b)
		}

	case esc:
		switch {
		case b == '[':
			s.st, s.buf = csi, append(s.buf, b)
		case b == ']':
			s.st, s.buf, s.n = osc, append(s.buf, b), 0
		case b == 'P' || b == '_' || b == '^' || b == 'X':
			s.st, s.buf, s.n = str, s.buf[:0], 0
		case b == 0x1b:
			s.buf = append(s.buf[:0], b) // a new ESC replaces the unfinished one
		case b == 0x18 || b == 0x1a:
			s.reset()
		case b >= 0x20 && b <= 0x2f:
			s.st, s.buf = escI, append(s.buf, b)
		case b >= 0x30 && b <= 0x7e:
			s.emit(0x1b, b) // ESC 7, ESC 8, ESC =, ESC c, ESC M, ...
			s.reset()
		default: // a control character inside an escape: fail closed, drop the ESC, treat the byte as plain
			s.reset()
			s.step(b)
		}

	case escI:
		switch {
		case b >= 0x20 && b <= 0x2f:
			s.buf = append(s.buf, b)
		case b >= 0x30 && b <= 0x7e:
			s.emit(s.buf...)
			s.emit(b)
			s.reset()
		case b == 0x1b:
			s.st, s.buf = esc, append(s.buf[:0], b)
		default:
			s.reset()
			s.step(b)
		}

	case csi:
		switch {
		case b == 0x1b:
			s.st, s.buf = esc, append(s.buf[:0], b)
		case b == 0x18 || b == 0x1a:
			s.reset()
		case b >= 0x20 && b <= 0x3f: // parameters and intermediates
			if len(s.buf) >= maxCSI {
				s.st = csiDrop
				return
			}
			s.buf = append(s.buf, b)
		case b >= 0x40 && b <= 0x7e:
			s.finishCSI(b)
			s.reset()
		default: // a control character inside a CSI: fail closed
			s.reset()
			s.step(b)
		}

	case csiDrop:
		switch {
		case b == 0x1b:
			s.st, s.buf = esc, append(s.buf[:0], b)
		case b >= 0x40 && b <= 0x7e, b == 0x18, b == 0x1a:
			s.reset()
		}

	case osc:
		switch {
		case b == 0x07:
			s.finishOSC(b, 0)
		case b == 0x1b:
			s.st = oscEsc
		case b == 0x18 || b == 0x1a:
			s.reset()
		default:
			s.n++
			if s.n <= maxString { // enough to classify and, for OSC 8, to forward
				s.buf = append(s.buf, b)
			}
		}

	case oscEsc:
		if b == '\\' {
			s.finishOSC(0x1b, '\\')
			return
		}
		s.st, s.buf = esc, append(s.buf[:0], 0x1b) // the OSC was abandoned; this ESC starts something new
		s.step(b)

	case str:
		switch {
		case b == 0x1b:
			s.st = strEsc
		case b == 0x18 || b == 0x1a:
			s.reset()
		default:
			if s.n++; s.n > maxString {
				s.reset()
			}
		}

	case strEsc:
		if b == '\\' {
			s.reset()
			return
		}
		s.st, s.buf = esc, append(s.buf[:0], 0x1b)
		s.step(b)
	}
}

// finishCSI decides what to do with a complete CSI sequence held in s.buf (ESC [ params...) ending in final.
func (s *Sanitizer) finishCSI(final byte) {
	body := s.buf[2:] // parameters and intermediates
	if final == 't' {
		return // window manipulation, including title and size reports
	}
	if len(body) > 0 && body[0] == '?' && (final == 'h' || final == 'l') {
		on := final == 'h'
		var keep []byte
		start := 1
		for i := 1; i <= len(body); i++ {
			if i < len(body) && body[i] != ';' {
				continue
			}
			param := body[start:i]
			switch string(param) {
			case "1049", "1047", "47":
				s.modes.AltScreen = on
				keep = appendParam(keep, param)
			case "2004":
				s.modes.BracketedPaste = on // consumed: the client owns the real terminal's setting
			default:
				keep = appendParam(keep, param)
			}
			start = i + 1
		}
		if len(keep) > 0 {
			s.emit(0x1b, '[', '?')
			s.emit(keep...)
			s.emit(final)
		}
		return
	}
	s.emit(s.buf...)
	s.emit(final)
}

func appendParam(keep, param []byte) []byte {
	if len(keep) > 0 {
		keep = append(keep, ';')
	}
	return append(keep, param...)
}

// finishOSC forwards an OSC 8 hyperlink and drops every other OSC (clipboard, titles, colour and other queries).
func (s *Sanitizer) finishOSC(term, term2 byte) {
	body := s.buf[2:]
	ok := s.n <= maxOSC && len(body) >= 2 && body[0] == '8' && body[1] == ';'
	for _, c := range body {
		if c < 0x20 || c == 0x7f {
			ok = false
		}
	}
	if ok {
		s.emit(s.buf...)
		s.emit(term)
		if term2 != 0 {
			s.emit(term2)
		}
	}
	s.reset()
}
