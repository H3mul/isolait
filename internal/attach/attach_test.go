package attach

import (
	"bytes"
	"strings"
	"testing"
)

type pipe struct{ bytes.Buffer }

func TestFramesRoundTrip(t *testing.T) {
	var p pipe
	c := NewConn(&p)
	for _, f := range []Frame{{Data, []byte("hello\x1b[1m")}, {Redraw, nil}, {Resize, ResizePayload(120, 40)}, {Data, bytes.Repeat([]byte("x"), 70000)}} {
		if err := c.Send(f); err != nil {
			t.Fatal(err)
		}
		got, err := c.Recv()
		if err != nil || got.Type != f.Type || !bytes.Equal(got.Payload, f.Payload) {
			t.Fatalf("round trip of %c: %v type=%c len=%d", f.Type, err, got.Type, len(got.Payload))
		}
	}
	if err := c.SendJSON(Hello, HelloMsg{Mode: ModeExec, Argv: []string{"bash"}, Term: "xterm", Cols: 80, Rows: 24}); err != nil {
		t.Fatal(err)
	}
	f, _ := c.Recv()
	if f.Type != Hello || !strings.Contains(string(f.Payload), `"mode":"exec"`) {
		t.Errorf("%c %s", f.Type, f.Payload)
	}
}

func TestResizePayload(t *testing.T) {
	cols, rows, err := ParseResize(ResizePayload(200, 50))
	if err != nil || cols != 200 || rows != 50 {
		t.Fatalf("%d %d %v", cols, rows, err)
	}
	if _, _, err := ParseResize([]byte{1, 2}); err == nil {
		t.Error("short payload accepted")
	}
}

func TestOversizedAndTruncatedFramesAreRejected(t *testing.T) {
	var p pipe
	c := NewConn(&p)
	if err := c.Send(Frame{Data, make([]byte, MaxPayload+1)}); err == nil {
		t.Error("oversized frame sent")
	}
	p.Write([]byte{'d', 0xff, 0xff, 0xff, 0xff}) // claims 4 GiB
	if _, err := c.Recv(); err == nil || !strings.Contains(err.Error(), "oversized") {
		t.Errorf("oversized header accepted: %v", err)
	}
	p.Reset()
	p.Write([]byte{'d', 0, 0, 0, 5, 'a', 'b'}) // truncated payload
	if _, err := c.Recv(); err == nil {
		t.Error("truncated frame accepted")
	}
}
