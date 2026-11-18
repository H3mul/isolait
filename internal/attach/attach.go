// Package attach is the framed stream between an attached client and the session daemon. A connection starts
// with a hello frame from the client and then carries terminal data, window sizes and control frames in both
// directions. Frames are a type byte, a big-endian uint32 length and the payload.
package attach

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Frame types. Which side sends each is noted.
const (
	Hello  byte = 'h' // client to daemon: JSON Hello; daemon to client: JSON Reply
	Data   byte = 'd' // both: terminal bytes (client: keyboard input; daemon: raw agent output)
	Resize byte = 'w' // client to daemon: 2 bytes columns, 2 bytes rows
	Redraw byte = 'r' // client to daemon: send SIGWINCH to the process so a TUI repaints
	Detach byte = 'k' // client to daemon: leave the session running and close
	Exit   byte = 'x' // daemon to client: JSON ExitInfo; the process is gone
)

// MaxPayload bounds a frame so a broken peer cannot make the other side allocate without limit.
const MaxPayload = 1 << 20

// Frame is one message.
type Frame struct {
	Type    byte
	Payload []byte
}

// Mode says what a client wants to attach to.
const (
	ModeAgent = "agent" // the session's agent, started if it is not running
	ModeExec  = "exec"  // a new process in the sandbox
)

// HelloMsg is the client's first frame.
type HelloMsg struct {
	Mode string   `json:"mode"`
	Argv []string `json:"argv,omitempty"` // exec only
	Term string   `json:"term"`
	Cols int      `json:"cols"`
	Rows int      `json:"rows"`
}

// Reply answers a hello.
type Reply struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	Restarted bool   `json:"restarted,omitempty"` // the agent was started by this attach
}

// ExitInfo reports how the attached process ended.
type ExitInfo struct {
	Code   int `json:"code"`
	Signal int `json:"signal,omitempty"`
}

// Conn writes frames safely from several goroutines.
type Conn struct {
	rw io.ReadWriter
	mu sync.Mutex
}

// NewConn wraps a stream.
func NewConn(rw io.ReadWriter) *Conn { return &Conn{rw: rw} }

// Send writes one frame.
func (c *Conn) Send(f Frame) error {
	if len(f.Payload) > MaxPayload {
		return fmt.Errorf("attach: frame of %d bytes exceeds %d", len(f.Payload), MaxPayload)
	}
	hdr := make([]byte, 5, 5+len(f.Payload))
	hdr[0] = f.Type
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(f.Payload)))
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.rw.Write(append(hdr, f.Payload...))
	return err
}

// SendJSON writes a frame whose payload is v as JSON.
func (c *Conn) SendJSON(t byte, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.Send(Frame{Type: t, Payload: b})
}

// Recv reads one frame.
func (c *Conn) Recv() (Frame, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(c.rw, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > MaxPayload {
		return Frame{}, errors.New("attach: oversized frame")
	}
	f := Frame{Type: hdr[0], Payload: make([]byte, n)}
	if _, err := io.ReadFull(c.rw, f.Payload); err != nil {
		return Frame{}, err
	}
	return f, nil
}

// ResizePayload encodes a window size.
func ResizePayload(cols, rows int) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b, uint16(cols))
	binary.BigEndian.PutUint16(b[2:], uint16(rows))
	return b
}

// ParseResize decodes a window size.
func ParseResize(p []byte) (cols, rows int, err error) {
	if len(p) != 4 {
		return 0, 0, errors.New("attach: bad resize payload")
	}
	return int(binary.BigEndian.Uint16(p)), int(binary.BigEndian.Uint16(p[2:])), nil
}
