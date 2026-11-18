package term

import (
	"fmt"
	"strings"
)

// EventKind says what the client should do with a piece of keyboard input.
type EventKind int

const (
	EvData        EventKind = iota // send Data to the agent
	EvDetach                       // leader then d
	EvPrompt                       // leader then :, the prompt opens
	EvPromptInput                  // bytes typed while the prompt is open
)

// Event is one decision of the input filter.
type Event struct {
	Kind EventKind
	Data []byte
}

// ParseLeader turns a setting such as "ctrl-\" into its control byte. Letters (either case) and @ [ \ ] ^ _ have
// a control byte; nothing else does.
func ParseLeader(s string) (byte, error) {
	rest, ok := strings.CutPrefix(s, "ctrl-")
	if !ok || len(rest) != 1 {
		return 0, fmt.Errorf(`leader %q must look like "ctrl-\" (ctrl- plus one character)`, s)
	}
	c := rest[0]
	switch {
	case c >= 'a' && c <= 'z':
		c -= 'a' - 'A'
		fallthrough
	case c >= '@' && c <= '_':
		b := c & 0x1f
		if b == 0x1b || b == 0x0d || b == 0x09 || b == 0x08 || b == 0x03 || b == 0x04 {
			return 0, fmt.Errorf("leader %q would collide with Escape, Enter, Tab, Backspace, Ctrl-C or Ctrl-D", s)
		}
		return b, nil
	}
	return 0, fmt.Errorf("leader %q: %q has no control byte", s, c)
}

var (
	pasteStart = []byte("\x1b[200~")
	pasteEnd   = []byte("\x1b[201~")
)

// InputFilter sits between the user's keyboard and the agent. It recognises the leader key (followed by d to
// detach or : for the prompt) only in real keyboard input, never inside a bracketed paste, so pasted text can
// not drive the client. The client keeps the real terminal in bracketed-paste mode itself; the filter strips
// the paste markers unless the agent asked for them (SetAgentPaste).
//
// A partly received paste marker is held back between reads; Flush releases it after a short silence so a
// lone Escape keypress is not delayed.
type InputFilter struct {
	leader     byte
	agentPaste bool
	inPaste    bool
	afterLead  bool
	inPrompt   bool
	held       []byte // a prefix of the paste marker being matched
	events     []Event
}

// NewInputFilter returns a filter for the given leader byte.
func NewInputFilter(leader byte) *InputFilter { return &InputFilter{leader: leader} }

// SetAgentPaste says whether the agent enabled bracketed paste, i.e. whether markers should reach it.
func (f *InputFilter) SetAgentPaste(on bool) { f.agentPaste = on }

// ClosePrompt returns to normal input after the prompt has finished.
func (f *InputFilter) ClosePrompt() { f.inPrompt = false }

// Pending reports whether bytes are held back waiting to see if they are a paste marker.
func (f *InputFilter) Pending() bool { return len(f.held) > 0 }

// Write feeds keyboard bytes and returns the resulting events, with adjacent data merged.
func (f *InputFilter) Write(p []byte) []Event {
	f.events = f.events[:0]
	for _, b := range p {
		f.step(b)
	}
	return f.take()
}

// Flush releases a held partial marker as ordinary input.
func (f *InputFilter) Flush() []Event {
	f.events = f.events[:0]
	if len(f.held) > 0 {
		h := f.held
		f.held = nil
		f.escapeCancelsLeader(h[0])
		f.plain(h...)
	}
	return f.take()
}

func (f *InputFilter) take() []Event {
	out := make([]Event, len(f.events))
	copy(out, f.events)
	return out
}

func (f *InputFilter) addData(kind EventKind, b ...byte) {
	if n := len(f.events); n > 0 && f.events[n-1].Kind == kind {
		f.events[n-1].Data = append(f.events[n-1].Data, b...)
		return
	}
	f.events = append(f.events, Event{Kind: kind, Data: append([]byte(nil), b...)})
}

func (f *InputFilter) add(kind EventKind) { f.events = append(f.events, Event{Kind: kind}) }

// plain handles bytes that are not part of a paste marker.
func (f *InputFilter) plain(bs ...byte) {
	for _, b := range bs {
		switch {
		case f.inPaste:
			f.dest(b)
		case f.inPrompt:
			f.addData(EvPromptInput, b)
		case f.afterLead:
			f.afterLead = false
			switch b {
			case 'd':
				f.add(EvDetach)
			case ':':
				f.inPrompt = true
				f.add(EvPrompt)
			case f.leader:
				f.addData(EvData, f.leader) // leader twice sends one literal leader byte
			}
			// any other key after the leader is swallowed
		case b == f.leader:
			f.afterLead = true
		default:
			f.dest(b)
		}
	}
}

// dest sends a byte to the prompt when it is open, else to the agent.
func (f *InputFilter) dest(b byte) {
	if f.inPrompt {
		f.addData(EvPromptInput, b)
	} else {
		f.addData(EvData, b)
	}
}

func (f *InputFilter) step(b byte) {
	marker := pasteStart
	if f.inPaste {
		marker = pasteEnd
	}
	if len(f.held) > 0 || b == 0x1b {
		cand := append(append([]byte(nil), f.held...), b)
		if len(cand) <= len(marker) && string(marker[:len(cand)]) == string(cand) {
			f.held = cand
			if len(cand) == len(marker) {
				f.held = nil
				f.marker()
			}
			return
		}
		// not a paste marker after all: what was held is ordinary input, then this byte starts afresh
		h := f.held
		f.held = nil
		if len(h) > 0 {
			f.escapeCancelsLeader(h[0])
			f.plain(h...)
			f.step(b)
			return
		}
	}
	f.plain(b)
}

// escapeCancelsLeader makes an Escape after the leader cancel it rather than count as the command key.
func (f *InputFilter) escapeCancelsLeader(b byte) {
	if b == 0x1b && f.afterLead && !f.inPaste {
		f.afterLead = false
	}
}

// marker applies a complete paste start or end marker.
func (f *InputFilter) marker() {
	if f.inPaste {
		f.inPaste = false
		if f.agentPaste && !f.inPrompt {
			f.addData(EvData, pasteEnd...)
		}
		return
	}
	f.afterLead = false // the leader was not followed by a command: a paste cancels it
	f.inPaste = true
	if f.agentPaste && !f.inPrompt {
		f.addData(EvData, pasteStart...)
	}
}
