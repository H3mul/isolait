package term

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
)

const (
	ESC = "\x1b"
	BEL = "\x07"
	ST  = "\x1b\\"
)

func oneShot(in string) (string, Modes) {
	var s Sanitizer
	out := string(s.Write([]byte(in)))
	return out, s.Modes()
}

func TestSanitizeTable(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		// forwarded unchanged: what a normal TUI emits
		{"plain text", "hello, world\r\n", "hello, world\r\n"},
		{"colours", ESC + "[1;31mred" + ESC + "[0m", ESC + "[1;31mred" + ESC + "[0m"},
		{"truecolour", ESC + "[38;2;10;20;30mx", ESC + "[38;2;10;20;30mx"},
		{"cursor movement", ESC + "[2;5H" + ESC + "[K" + ESC + "[3A", ESC + "[2;5H" + ESC + "[K" + ESC + "[3A"},
		{"save and restore cursor", ESC + "7x" + ESC + "8", ESC + "7x" + ESC + "8"},
		{"charset designation", ESC + "(B" + ESC + ")0", ESC + "(B" + ESC + ")0"},
		{"scroll region and erase", ESC + "[1;24r" + ESC + "[2J" + ESC + "[3J", ESC + "[1;24r" + ESC + "[2J" + ESC + "[3J"},
		{"private modes that are fine", ESC + "[?25l" + ESC + "[?7h" + ESC + "[?1000h", ESC + "[?25l" + ESC + "[?7h" + ESC + "[?1000h"},
		{"utf-8 text", "héllo ☃ 日本", "héllo ☃ 日本"},
		{"bell", "a" + BEL + "b", "a" + BEL + "b"},
		{"device attribute query", ESC + "[c" + ESC + "[6n", ESC + "[c" + ESC + "[6n"},
		{"osc 8 hyperlink (BEL)", ESC + "]8;;https://example.com" + BEL + "link" + ESC + "]8;;" + BEL, ESC + "]8;;https://example.com" + BEL + "link" + ESC + "]8;;" + BEL},
		{"osc 8 hyperlink (ST)", ESC + "]8;id=1;https://example.com" + ST + "x", ESC + "]8;id=1;https://example.com" + ST + "x"},

		// dropped: clipboard, titles, queries
		{"osc 52 clipboard write (BEL)", "a" + ESC + "]52;c;aGVsbG8=" + BEL + "b", "ab"},
		{"osc 52 clipboard write (ST)", "a" + ESC + "]52;c;aGVsbG8=" + ST + "b", "ab"},
		{"osc 52 clipboard read request", "a" + ESC + "]52;c;?" + BEL + "b", "ab"},
		{"window title osc 0", ESC + "]0;pwned" + BEL + "x", "x"},
		{"window title osc 2", ESC + "]2;pwned" + ST + "x", "x"},
		{"icon title osc 1", ESC + "]1;pwned" + BEL + "x", "x"},
		{"colour query osc 11", ESC + "]11;?" + BEL + "x", "x"},
		{"osc 4 palette change", ESC + "]4;1;rgb:ff/00/00" + BEL + "x", "x"},
		{"osc with a control character in a link", ESC + "]8;;http://a\x01b" + BEL + "x", "x"},

		// dropped: device control strings and friends
		{"dcs sixel", "a" + ESC + "Pq#0;2;0;0;0#0~~@@vv" + ST + "b", "ab"},
		{"dcs decrqss", ESC + "P$qm" + ST + "x", "x"},
		{"apc kitty graphics", "a" + ESC + "_Gf=100;AAAA" + ST + "b", "ab"},
		{"pm", "a" + ESC + "^privacy" + ST + "b", "ab"},
		{"sos", "a" + ESC + "Xstring" + ST + "b", "ab"},

		// dropped: window manipulation and reports
		{"csi 21 t title report", "a" + ESC + "[21t" + "b", "ab"},
		{"csi 20 t icon report", ESC + "[20t" + "x", "x"},
		{"csi 8 t resize", ESC + "[8;40;100t" + "x", "x"},
		{"csi 22 t push title", ESC + "[22;0t" + "x", "x"},
		{"csi 14 t size report", ESC + "[14t" + "x", "x"},
		{"enq", "a\x05b", "ab"},

		// mode handling
		{"bracketed paste on is consumed", ESC + "[?2004h" + "x", "x"},
		{"bracketed paste off is consumed", ESC + "[?2004l" + "x", "x"},
		{"2004 removed from a list", ESC + "[?1;2004;25h", ESC + "[?1;25h"},
		{"2004 alone in a list", ESC + "[?2004;2004h", ""},
		{"alt screen forwarded", ESC + "[?1049h" + "x" + ESC + "[?1049l", ESC + "[?1049h" + "x" + ESC + "[?1049l"},
		{"old alt screen forwarded", ESC + "[?47h", ESC + "[?47h"},

		// malformed input fails closed
		{"CAN aborts a CSI", "a" + ESC + "[31" + "\x18" + "b", "ab"},
		{"SUB aborts an OSC", "a" + ESC + "]52;c;AAAA" + "\x1a" + "b", "ab"},
		{"ESC restarts an unfinished CSI", ESC + "[31" + ESC + "[1m", ESC + "[1m"},
		{"ESC inside an OSC starts a new sequence", ESC + "]52;c;AAAA" + ESC + "[1m", ESC + "[1m"},
		{"ESC inside a DCS starts a new sequence", ESC + "Pdata" + ESC + "[1m", ESC + "[1m"},
		{"newline inside a CSI drops it", ESC + "[31\nx", "\nx"},
		{"lone ESC at the end is held back", "x" + ESC, "x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := oneShot(tc.in); got != tc.want {
				t.Errorf("sanitize(%q)\n got %q\nwant %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestModesAreTracked(t *testing.T) {
	var s Sanitizer
	s.Write([]byte(ESC + "[?1049h" + ESC + "[?2004h"))
	if m := s.Modes(); !m.AltScreen || !m.BracketedPaste {
		t.Fatalf("%+v", m)
	}
	s.Write([]byte(ESC + "[?1049l"))
	if m := s.Modes(); m.AltScreen || !m.BracketedPaste {
		t.Fatalf("%+v", m)
	}
	s.Write([]byte(ESC + "[?1;2004l"))
	if m := s.Modes(); m.BracketedPaste {
		t.Fatalf("%+v", m)
	}
	s.Write([]byte(ESC + "[?47h"))
	if !s.Modes().AltScreen {
		t.Fatal("?47 not tracked")
	}
	s.Write([]byte(ESC + "[?25l"))
	if !s.Modes().CursorHidden {
		t.Fatal("hidden cursor not tracked")
	}
	s.Write([]byte(ESC + "[?1;25h"))
	if s.Modes().CursorHidden {
		t.Fatal("shown cursor not tracked")
	}
}

func TestOverlongSequencesAreBounded(t *testing.T) {
	// an endless CSI parameter list: nothing forwarded, and normal output resumes after its final byte
	got, _ := oneShot(ESC + "[" + strings.Repeat("1;", 1000) + "mX")
	if got != "X" {
		t.Errorf("over-long CSI: %q", got)
	}
	// an OSC 8 that is too long is dropped, not truncated
	long := ESC + "]8;;http://" + strings.Repeat("a", maxOSC+10) + BEL + "X"
	if got, _ := oneShot(long); got != "X" {
		t.Errorf("over-long hyperlink forwarded: %d bytes", len(got))
	}
	// a never-ending DCS is abandoned after maxString bytes so the terminal is not swallowed for ever
	var s Sanitizer
	s.Write([]byte(ESC + "P"))
	s.Write(bytes.Repeat([]byte("a"), maxString+1))
	if got := string(s.Write([]byte("visible"))); got != "visible" {
		t.Errorf("output after an unterminated DCS: %q", got)
	}
}

// corpus mixes allowed and forbidden sequences with text.
var corpus = []string{
	"plain " + ESC + "[1;31mred" + ESC + "[0m text\r\n",
	"a" + ESC + "]52;c;aGVsbG8=" + BEL + "b" + ESC + "]0;title" + ST + "c",
	ESC + "]8;;https://example.com" + ST + "link" + ESC + "]8;;" + ST,
	ESC + "Pq#0;2;0;0;0~~" + ST + "x" + ESC + "_Gf=1;AA" + ST + "y",
	ESC + "[21t" + ESC + "[?2004h" + ESC + "[?1;2004;25h" + ESC + "[?1049h" + "z",
	ESC + "[31" + ESC + "[1m" + ESC + "]52;c;AA" + ESC + "[2m" + ESC + "7" + ESC + "(B",
	"héllo ☃" + ESC + "[?25l" + ESC + "[2;3H" + "\x05\x18" + ESC + "[K",
}

// Splitting the input at any point, or feeding it a byte at a time, must give exactly the one-shot output.
func TestSplitReadsGiveTheSameOutput(t *testing.T) {
	for _, in := range corpus {
		want, wantModes := oneShot(in)
		for cut := 0; cut <= len(in); cut++ {
			var s Sanitizer
			got := string(s.Write([]byte(in[:cut])))
			got += string(s.Write([]byte(in[cut:])))
			if got != want || s.Modes() != wantModes {
				t.Fatalf("input %q split at %d:\n got %q %+v\nwant %q %+v", in, cut, got, s.Modes(), want, wantModes)
			}
		}
		var s Sanitizer
		var got strings.Builder
		for i := 0; i < len(in); i++ {
			got.Write(s.Write([]byte{in[i]}))
		}
		if got.String() != want {
			t.Fatalf("byte-at-a-time %q:\n got %q\nwant %q", in, got.String(), want)
		}
	}
}

// forbidden finds sequences that must never reach the terminal.
func forbidden(out string) string {
	for _, bad := range []string{ESC + "]0;", ESC + "]1;", ESC + "]2;", ESC + "]52", ESC + "P", ESC + "_", ESC + "^", ESC + "X", "\x05"} {
		if strings.Contains(out, bad) {
			return bad
		}
	}
	// any CSI ... t, and any OSC other than 8
	for i := 0; i+1 < len(out); i++ {
		if out[i] != 0x1b {
			continue
		}
		switch out[i+1] {
		case '[':
			j := i + 2
			for j < len(out) && out[j] >= 0x20 && out[j] <= 0x3f {
				j++
			}
			if j < len(out) && out[j] == 't' {
				return "CSI t"
			}
		case ']':
			if !strings.HasPrefix(out[i+2:], "8;") {
				return "OSC other than 8"
			}
		}
	}
	return ""
}

// Randomly assembled streams of allowed and forbidden sequences, cut at random places: nothing forbidden is
// ever forwarded, nothing panics, and the split never changes the result.
func TestRandomStreamsNeverLeakForbiddenSequences(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	atoms := []string{"a", "text ", "\n", ESC + "[1m", ESC + "[2;3H", ESC + "]52;c;QUJD" + BEL, ESC + "]0;x" + ST, ESC + "]11;?" + BEL,
		ESC + "Pq~" + ST, ESC + "_G1;A" + ST, ESC + "^pm" + ST, ESC + "Xs" + ST, ESC + "[21t", ESC + "[8;1;1t", ESC + "[?2004h",
		ESC + "[?1049h", ESC + "]8;;http://x" + BEL, ESC, ESC + "[", ESC + "]", ESC + "P", "\x18", "\x1a", "\x05", "é", "\x00", ESC + "[31"}
	for i := 0; i < 3000; i++ {
		var in strings.Builder
		for n := r.Intn(12) + 1; n > 0; n-- {
			in.WriteString(atoms[r.Intn(len(atoms))])
		}
		want, _ := oneShot(in.String())
		if bad := forbidden(want); bad != "" {
			t.Fatalf("input %q forwarded %s: %q", in.String(), bad, want)
		}
		var s Sanitizer
		var got strings.Builder
		for rest := []byte(in.String()); len(rest) > 0; {
			n := r.Intn(len(rest)) + 1
			got.Write(s.Write(rest[:n]))
			rest = rest[n:]
		}
		if got.String() != want {
			t.Fatalf("random split changed the output for %q:\n got %q\nwant %q", in.String(), got.String(), want)
		}
	}
}
