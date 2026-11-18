package term

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

const leader = "\x1c" // Ctrl-\

// render turns events into a comparable string: data as text, other kinds as tags. Adjacent data merges, so
// the way the input was cut into reads does not matter.
func render(evs []Event) string {
	// merge adjacent events of the same data kind first, so that a rune split across reads is whole again
	var merged []Event
	for _, e := range evs {
		if n := len(merged); n > 0 && merged[n-1].Kind == e.Kind && (e.Kind == EvData || e.Kind == EvPromptInput) {
			merged[n-1].Data = append(append([]byte(nil), merged[n-1].Data...), e.Data...)
			continue
		}
		merged = append(merged, Event{Kind: e.Kind, Data: append([]byte(nil), e.Data...)})
	}
	var sb strings.Builder
	for _, e := range merged {
		switch e.Kind {
		case EvData:
			fmt.Fprintf(&sb, "[D:%s]", strings.Trim(fmt.Sprintf("%q", e.Data), `"`))
		case EvPromptInput:
			fmt.Fprintf(&sb, "[P:%s]", strings.Trim(fmt.Sprintf("%q", e.Data), `"`))
		case EvDetach:
			sb.WriteString("<detach>")
		case EvPrompt:
			sb.WriteString("<prompt>")
		}
	}
	return sb.String()
}

func run(f *InputFilter, chunks ...string) string {
	var all []Event
	for _, c := range chunks {
		all = append(all, f.Write([]byte(c))...)
	}
	all = append(all, f.Flush()...)
	return render(all)
}

func TestLeaderCommands(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain typing", "ls -la\r", `[D:ls -la\r]`},
		{"detach", leader + "d", `<detach>`},
		{"typing around a detach", "a" + leader + "db", `[D:a]<detach>[D:b]`},
		{"prompt opens", leader + ":", `<prompt>`},
		{"keys after the prompt go to the prompt", leader + ":mount x\r", `<prompt>[P:mount x\r]`},
		{"leader twice sends one literal leader", leader + leader, `[D:\x1c]`},
		{"unknown key after the leader is swallowed", leader + "x" + "y", `[D:y]`},
		{"escape after the leader cancels it", leader + "\x1b" + "d", `[D:\x1bd]`},
		{"arrow keys pass through", "\x1b[A\x1b[B", `[D:\x1b[A\x1b[B]`},
		{"utf-8 passes through", "héllo", `[D:héllo]`},
		{"stray end-of-paste marker is ordinary input", "\x1b[201~", `[D:\x1b[201~]`},
		{"escape sequences that start like a marker", "\x1b[200x\x1b[20", `[D:\x1b[200x\x1b[20]`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(NewInputFilter(0x1c), tc.in); got != tc.want {
				t.Errorf("input %q\n got %s\nwant %s", tc.in, got, tc.want)
			}
		})
	}
}

func TestPromptCloseReturnsToNormalInput(t *testing.T) {
	f := NewInputFilter(0x1c)
	got := render(f.Write([]byte(leader + ":ab")))
	f.ClosePrompt()
	got += render(f.Write([]byte("cd" + leader + "d")))
	if got != `<prompt>[P:ab][D:cd]<detach>` {
		t.Errorf("%s", got)
	}
}

// The leader byte inside a bracketed paste is data: it must never detach or open the prompt.
func TestLeaderInsidePasteIsNeverRecognised(t *testing.T) {
	in := "\x1b[200~echo " + leader + "d" + leader + ":\x1b[201~"
	f := NewInputFilter(0x1c)
	if got, want := run(f, in), `[D:echo \x1cd\x1c:]`; got != want {
		t.Errorf("markers stripped when the agent did not ask for them:\n got %s\nwant %s", got, want)
	}
	f = NewInputFilter(0x1c)
	f.SetAgentPaste(true)
	if got, want := run(f, in), `[D:\x1b[200~echo \x1cd\x1c:\x1b[201~]`; got != want {
		t.Errorf("markers forwarded when the agent asked for them:\n got %s\nwant %s", got, want)
	}
	// and the leader works again as soon as the paste is over
	f = NewInputFilter(0x1c)
	if got, want := run(f, in+leader+"d"), `[D:echo \x1cd\x1c:]<detach>`; got != want {
		t.Errorf("after the paste:\n got %s\nwant %s", got, want)
	}
}

func TestPasteIntoThePromptGoesToThePrompt(t *testing.T) {
	f := NewInputFilter(0x1c)
	f.SetAgentPaste(true) // markers must not reach the agent while the prompt is open
	got := run(f, leader+":", "\x1b[200~mount "+leader+"d~/x\x1b[201~", "\r")
	if got != `<prompt>[P:mount \x1cd~/x\r]` {
		t.Errorf("%s", got)
	}
}

func TestPasteCancelsAPendingLeader(t *testing.T) {
	// leader, then a paste: the leader is cancelled, so a d typed afterwards is just a d and not a detach
	if got, want := run(NewInputFilter(0x1c), leader+"\x1b[200~d\x1b[201~"+"d"), `[D:dd]`; got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestLoneEscapeIsReleasedByFlush(t *testing.T) {
	f := NewInputFilter(0x1c)
	if evs := f.Write([]byte("\x1b")); len(evs) != 0 || !f.Pending() {
		t.Fatalf("a lone ESC must be held while it could start a paste marker: %v pending=%v", evs, f.Pending())
	}
	if got := render(f.Flush()); got != `[D:\x1b]` || f.Pending() {
		t.Errorf("flush released %s (pending %v)", got, f.Pending())
	}
	// Escape right after the leader cancels it and is sent on (so an arrow key typed next is not garbled)
	if got := run(NewInputFilter(0x1c), leader+"\x1b", "d"); got != `[D:\x1bd]` {
		t.Errorf("leader, Escape, d: %s", got)
	}
}

// Cutting the input at every point, or one byte at a time, never changes the decisions.
func TestSplitInputGivesTheSameEvents(t *testing.T) {
	corpus := []string{
		"ab" + leader + "d" + "cd",
		leader + ":" + "mount x\r",
		"\x1b[200~paste " + leader + "d here\x1b[201~" + leader + "d",
		"\x1b[A" + leader + leader + "\x1b[200~x\x1b[201~y",
		leader + "\x1b[200~z\x1b[201~" + "\x1b[201~" + "\x1b[20x",
		"héllo\x1b[B" + leader + "q" + leader + ":" + "é",
	}
	for _, agentPaste := range []bool{false, true} {
		for _, in := range corpus {
			mk := func() *InputFilter { f := NewInputFilter(0x1c); f.SetAgentPaste(agentPaste); return f }
			want := run(mk(), in)
			for cut := 0; cut <= len(in); cut++ {
				if got := run(mk(), in[:cut], in[cut:]); got != want {
					t.Fatalf("agentPaste=%v input %q cut at %d:\n got %s\nwant %s", agentPaste, in, cut, got, want)
				}
			}
			f := mk()
			var all []Event
			for i := 0; i < len(in); i++ {
				all = append(all, f.Write([]byte{in[i]})...)
			}
			all = append(all, f.Flush()...)
			if got := render(all); got != want {
				t.Fatalf("byte at a time %q:\n got %s\nwant %s", in, got, want)
			}
		}
	}
}

// Random keyboard and paste traffic: a detach or prompt event only ever comes from a real leader key press
// outside a paste.
func TestRandomPastesNeverTriggerTheLeader(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for i := 0; i < 2000; i++ {
		var in strings.Builder
		for n := r.Intn(6) + 1; n > 0; n-- {
			var body strings.Builder
			for m := r.Intn(8); m > 0; m-- {
				body.WriteString([]string{"a", leader, "d", ":", "\x1b", "[", "x", leader + "d", leader + ":"}[r.Intn(9)])
			}
			if r.Intn(2) == 0 {
				in.WriteString("\x1b[200~" + strings.ReplaceAll(body.String(), "\x1b[201~", "") + "\x1b[201~")
			} else {
				in.WriteString(strings.ReplaceAll(strings.ReplaceAll(body.String(), leader, ""), "\x1b", "")) // typed text without the leader
			}
		}
		f := NewInputFilter(0x1c)
		got := run(f, in.String())
		if strings.Contains(got, "<detach>") || strings.Contains(got, "<prompt>") {
			t.Fatalf("input %q produced %s without a real leader key", in.String(), got)
		}
	}
}

func TestParseLeader(t *testing.T) {
	for in, want := range map[string]byte{`ctrl-\`: 0x1c, "ctrl-]": 0x1d, "ctrl-^": 0x1e, "ctrl-_": 0x1f, "ctrl-a": 0x01, "ctrl-A": 0x01, "ctrl-z": 0x1a, "ctrl-@": 0x00} {
		if got, err := ParseLeader(in); err != nil || got != want {
			t.Errorf("ParseLeader(%q) = %#x, %v; want %#x", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "ctrl-", "ctrl-ab", "alt-x", "x", "ctrl-1", "ctrl-[", "ctrl-m", "ctrl-i", "ctrl-h", "ctrl-c", "ctrl-d", "ctrl- "} {
		if _, err := ParseLeader(bad); err == nil {
			t.Errorf("ParseLeader(%q) accepted", bad)
		}
	}
}
