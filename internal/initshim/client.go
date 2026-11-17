package initshim

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// Socketpair returns the two ends of the control channel: keep daemon, pass sandbox to the sandbox
// process as ControlFD. SOCK_SEQPACKET keeps each message intact together with its descriptors.
func Socketpair() (daemon, sandbox *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[0]), "initctl-daemon"), os.NewFile(uintptr(fds[1]), "initctl-sandbox"), nil
}

// Client is the daemon's end of the control channel.
type Client struct {
	conn  *net.UnixConn
	mu    sync.Mutex
	next  int
	wait  map[int]chan Event // "started"/"error" replies per spawn id
	exits chan Event
	hello chan Event
	done  chan struct{}
}

// NewClient wraps the daemon end and starts reading events.
func NewClient(f *os.File) (*Client, error) {
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	conn, ok := c.(*net.UnixConn)
	if !ok {
		return nil, errors.New("initshim: not a unix socket")
	}
	cl := &Client{conn: conn, wait: map[int]chan Event{}, exits: make(chan Event, 64), hello: make(chan Event, 1), done: make(chan struct{})}
	go cl.read()
	return cl, nil
}

func (c *Client) read() {
	defer close(c.done)
	buf := make([]byte, maxMsg)
	for {
		n, err := c.conn.Read(buf)
		if err != nil || n == 0 {
			return
		}
		var e Event
		if json.Unmarshal(buf[:n], &e) != nil {
			continue
		}
		switch e.Event {
		case "hello":
			select {
			case c.hello <- e:
			default:
			}
		case "exited":
			c.exits <- e
		default: // started, error
			c.mu.Lock()
			ch := c.wait[e.ID]
			delete(c.wait, e.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- e
			}
		}
	}
}

// WaitHello waits for the shim to announce itself and returns its PID inside the sandbox.
func (c *Client) WaitHello(timeout time.Duration) (int, error) {
	select {
	case e := <-c.hello:
		return e.PID, nil
	case <-c.done:
		return 0, errors.New("init shim exited before it said hello")
	case <-time.After(timeout):
		return 0, errors.New("timed out waiting for the init shim")
	}
}

// Exits delivers one event per finished process started with Spawn.
func (c *Client) Exits() <-chan Event { return c.exits }

// Done is closed when the shim's end of the channel closes (the sandbox is gone).
func (c *Client) Done() <-chan struct{} { return c.done }

// Spawn starts argv in the sandbox with stdin, stdout and stderr taken from stdio (a PTY slave three times
// for a terminal session; pipes otherwise). It returns the id used in the matching Exits event.
func (c *Client) Spawn(argv, env []string, cwd string, tty bool, stdio [3]*os.File) (id, pid int, err error) {
	c.mu.Lock()
	c.next++
	id = c.next
	ch := make(chan Event, 1)
	c.wait[id] = ch
	c.mu.Unlock()

	b, err := json.Marshal(Request{Op: "spawn", ID: id, Argv: argv, Env: env, Cwd: cwd, TTY: tty})
	if err != nil {
		return 0, 0, err
	}
	rights := syscall.UnixRights(int(stdio[0].Fd()), int(stdio[1].Fd()), int(stdio[2].Fd()))
	if _, _, err := c.conn.WriteMsgUnix(b, rights, nil); err != nil {
		return 0, 0, err
	}
	select {
	case e := <-ch:
		if e.Event == "error" {
			return 0, 0, fmt.Errorf("spawn: %s", e.Error)
		}
		return id, e.PID, nil
	case <-c.done:
		return 0, 0, errors.New("sandbox is gone")
	case <-time.After(10 * time.Second):
		return 0, 0, errors.New("timed out waiting for spawn")
	}
}

// Signal delivers sig to a process started with Spawn.
func (c *Client) Signal(id, sig int) error {
	b, _ := json.Marshal(Request{Op: "signal", ID: id, Sig: sig})
	_, err := c.conn.Write(b)
	return err
}

// Shutdown kills everything in the sandbox and ends it.
func (c *Client) Shutdown() error {
	b, _ := json.Marshal(Request{Op: "shutdown"})
	_, err := c.conn.Write(b)
	return err
}

// Close closes the channel; the shim treats that as the daemon going away and ends the sandbox.
func (c *Client) Close() error { return c.conn.Close() }
