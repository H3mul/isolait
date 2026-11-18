package relay

import (
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/H3mul/isolait/internal/attach"
	"github.com/H3mul/isolait/internal/pty"
)

// ttyRelay is a relay on a real pty against a fake daemon, with a prompt callback that records its calls.
type ttyRelay struct {
	d      *fakeDaemon
	master *os.File
	shown  *syncBuf
	calls  chan string
	res    chan Result
}

func newTTYRelay(t *testing.T, promptFn func(string) string) *ttyRelay {
	t.Helper()
	master, slave, err := pty.Open()
	if err != nil {
		t.Skipf("no pty here: %v", err)
	}
	t.Cleanup(func() { master.Close(); slave.Close() })
	pty.SetSize(master, 100, 30)
	r := &ttyRelay{master: master, shown: &syncBuf{}, calls: make(chan string, 8), res: make(chan Result, 1)}
	go io.Copy(r.shown, master)
	d, c := startDaemon(t, attach.Reply{OK: true})
	r.d = d
	fn := promptFn
	if fn == nil {
		fn = func(string) string { return "ok" }
	}
	go func() {
		res, _ := Run(Options{Conn: c, Hello: attach.HelloMsg{Mode: attach.ModeAgent, Term: "xterm"}, Leader: 0x1c, In: slave, Out: slave, TTY: slave,
			Winch: make(chan os.Signal), ResultHold: 60 * time.Millisecond,
			Prompt: func(line string) string { r.calls <- line; return fn(line) }})
		r.res <- res
	}()
	<-d.ready
	// typing before the relay has made the terminal raw would hit the line discipline (which swallows Ctrl-\)
	eventually(t, "raw mode", func() bool { return termFlags(t, slave)&syscall.ICANON == 0 })
	t.Cleanup(func() { d.raw.Close() })
	return r
}

func (r *ttyRelay) type_(s string) { r.master.Write([]byte(s)) }

func (r *ttyRelay) waitShown(t *testing.T, want string) {
	t.Helper()
	eventually(t, "the terminal to show "+strings.ReplaceAll(want, "\x1b", "ESC"), func() bool { return strings.Contains(r.shown.String(), want) })
}

func (r *ttyRelay) call(t *testing.T) string {
	t.Helper()
	select {
	case l := <-r.calls:
		return l
	case <-time.After(5 * time.Second):
		t.Fatal("the prompt command was not run")
	}
	return ""
}

func (r *ttyRelay) noFrame(t *testing.T, typ byte, why string) {
	t.Helper()
	deadline := time.After(250 * time.Millisecond)
	for {
		select {
		case f := <-r.d.got:
			if f.Type == typ {
				t.Errorf("%s (got a %q frame)", why, typ)
				return
			}
		case <-deadline:
			return
		}
	}
}

func TestPromptOnANormalScreenIsAnOverlayThatRestoresTheScreen(t *testing.T) {
	r := newTTYRelay(t, func(line string) string { return "ran " + line + "\nsecond line" })
	r.type_(leader + ":")
	r.waitShown(t, "\x1b[?1049h") // opened on the alternate screen: the agent's screen is untouched underneath
	r.d.send("held-bytes")
	time.Sleep(80 * time.Millisecond)
	if strings.Contains(r.shown.String(), "held-bytes") {
		t.Error("agent output drew over the open prompt")
	}
	r.type_("status\r")
	if got := r.call(t); got != "status" {
		t.Fatalf("command %q", got)
	}
	r.waitShown(t, "ran status | second line")
	r.waitShown(t, "\x1b[?1049l")
	r.waitShown(t, "held-bytes")
	shown := r.shown.String()
	if strings.Index(shown, "held-bytes") < strings.LastIndex(shown, "\x1b[?1049l") {
		t.Error("held output must appear after the prompt has closed, on the restored screen")
	}
	r.noFrame(t, attach.Redraw, "an overlay leaves the screen exactly as it was: no repaint needed")
	r.noFrame(t, attach.Data, "what is typed in the prompt must not reach the agent")
}

func TestPromptOverAnAlternateScreenAppRepaintsIt(t *testing.T) {
	r := newTTYRelay(t, nil)
	r.d.send("\x1b[?1049h\x1b[?25l")
	r.waitShown(t, "\x1b[?1049h")
	r.type_(leader + ":")
	r.waitShown(t, "\x1b7") // cursor saved: the bottom row of the app is overwritten
	r.type_("abc\x1b")      // Escape dismisses
	r.waitShown(t, "\x1b8")
	r.d.frame(attach.Redraw) // the app is asked to repaint what the prompt covered
	if n := strings.Count(r.shown.String(), "\x1b[?1049h"); n != 1 {
		t.Errorf("a second alternate screen was opened over the app's (%d opens)", n)
	}
	shown := r.shown.String()
	if !strings.Contains(shown[strings.LastIndex(shown, "\x1b8"):], "\x1b[?25l") {
		t.Error("the agent had hidden the cursor: it must be hidden again after the prompt")
	}
	select {
	case l := <-r.calls:
		t.Errorf("a dismissed prompt ran %q", l)
	default:
	}
}

func TestEscapeDismissesAndTypingGoesBackToTheAgent(t *testing.T) {
	r := newTTYRelay(t, nil)
	r.type_(leader + ":")
	r.waitShown(t, "\x1b[?1049h")
	r.type_("rm -rf\x1b")
	r.waitShown(t, "\x1b[?1049l")
	r.type_("x")
	if f := r.d.frame(attach.Data); string(f.Payload) != "x" {
		t.Errorf("agent received %q after the prompt closed", f.Payload)
	}
	select {
	case l := <-r.calls:
		t.Errorf("a dismissed prompt ran %q", l)
	default:
	}
}

func TestPromptResultCannotInjectEscapeSequences(t *testing.T) {
	r := newTTYRelay(t, func(string) string { return "x\x1b]52;c;QUJD\x07y\x1b[21t" })
	r.type_(leader + ":ls\r")
	r.call(t)
	r.waitShown(t, "x]52;c;QUJDy[21t") // the printable remnants are harmless text; the ESC and BEL that made them sequences are gone
	if strings.Contains(r.shown.String(), "\x1b]52") || strings.Contains(r.shown.String(), "\x1b[21t") || strings.Contains(r.shown.String(), "\x07") {
		t.Errorf("a command's output reached the terminal with its escape sequences: %q", r.shown.String())
	}
}

func TestWithoutAPromptCallbackTheLeaderColonDoesNothing(t *testing.T) {
	d, c := startDaemon(t, attach.Reply{OK: true})
	r := runRelay(t, c, nil) // Prompt is nil
	<-d.ready
	r.inW.Write([]byte("a" + leader + ":b"))
	got := ""
	for len(got) < 2 {
		got += string(d.frame(attach.Data).Payload)
	}
	if got != "ab" {
		t.Errorf("agent received %q, want the key after the leader kept", got)
	}
}

func TestDisplayText(t *testing.T) {
	for _, tc := range []struct {
		in    string
		width int
		want  string
	}{
		{"hello", 20, "hello"},
		{"a\nb\n\n c ", 20, "a | b | c"},
		{"x\x1b[31my\x07z", 20, "x[31myz"}, // the ESC and BEL are gone, so nothing can start a sequence
		{"abcdefghij", 5, "abcd…"},
		{"héllo ☃", 20, "héllo ☃"},
		{"anything", 0, "…"},
	} {
		if got := displayText(tc.in, tc.width); got != tc.want {
			t.Errorf("displayText(%q, %d) = %q, want %q", tc.in, tc.width, got, tc.want)
		}
	}
}
