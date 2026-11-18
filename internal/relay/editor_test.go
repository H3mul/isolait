package relay

import "testing"

func TestEditor(t *testing.T) {
	tests := []struct {
		name    string
		chunks  []string
		wantAct action
		want    string
	}{
		{"typing", []string{"mount ~/x"}, actNone, "mount ~/x"},
		{"enter runs", []string{"status\r"}, actRun, "status"},
		{"newline runs too", []string{"status\n"}, actRun, "status"},
		{"enter on an empty line dismisses", []string{"\r"}, actDismiss, ""},
		{"backspace", []string{"abc\x7f\x7fd"}, actNone, "ad"},
		{"backspace on an empty line", []string{"\x7f\x08x"}, actNone, "x"},
		{"ctrl-u clears the line", []string{"abc\x15de"}, actNone, "de"},
		{"escape dismisses", []string{"abc\x1b"}, actDismiss, "abc"},
		{"ctrl-c dismisses", []string{"abc\x03"}, actDismiss, "abc"},
		{"arrow keys are ignored", []string{"a\x1b[Ab\x1b[1;5Cc\x1bOBd"}, actNone, "abcd"},
		{"alt keys are ignored", []string{"a\x1bxb"}, actNone, "ab"},
		{"other control characters are ignored", []string{"a\x01\x02b\t"}, actNone, "ab"},
		{"utf-8 text and backspace by character", []string{"é☃日\x7f"}, actNone, "é☃"},
		{"a rune split across reads", []string{"\xe2\x98", "\x83x"}, actNone, "☃x"},
		{"input after enter is not applied", []string{"ls\rmore"}, actRun, "ls"},
		{"a long line is capped", []string{string(make([]byte, 0)) + repeat('a', maxLine+50)}, actNone, repeat('a', maxLine)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var e editor
			var act action
			for _, c := range tc.chunks {
				act, _ = e.feed([]byte(c))
			}
			if act != tc.wantAct || e.text() != tc.want {
				t.Errorf("got action %v text %q, want %v %q", act, e.text(), tc.wantAct, tc.want)
			}
		})
	}
}

func TestEditorReportsWhetherTheLineChanged(t *testing.T) {
	var e editor
	if _, ch := e.feed([]byte("ab")); !ch {
		t.Error("typing changes the line")
	}
	if _, ch := e.feed([]byte("\x1b[A")); ch {
		t.Error("an arrow key does not change the line")
	}
	if _, ch := e.feed([]byte("\x7f")); !ch {
		t.Error("backspace changes the line")
	}
}

func repeat(c byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}
