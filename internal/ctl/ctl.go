// Package ctl is the control channel between the isolait CLI and a session daemon: newline-delimited JSON
// over a unix socket that lives in the session's private runtime directory (never mounted in the sandbox).
// Defence in depth on top of the 0700 directory: the socket is 0600 and the peer's uid is checked.
package ctl

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

// Request names an operation; Args are its string parameters.
type Request struct {
	Op   string   `json:"op"`
	Args []string `json:"args,omitempty"`
}

// Response carries either an error text or JSON data.
type Response struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// Handler serves one request.
type Handler func(Request) (data any, err error)

// maxPath is below sockaddr_un's 108 bytes.
const maxPath = 100

// Server accepts requests on a unix socket.
type Server struct {
	l    *net.UnixListener
	path string
}

// ListenUnix binds a unix socket at path (0600). A live socket there means the owner is already running; a
// stale file is replaced. Used for the control socket and the attach socket.
func ListenUnix(path string) (*net.UnixListener, error) {
	if len(path) > maxPath {
		return nil, fmt.Errorf("socket path %q is longer than %d bytes", path, maxPath)
	}
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		c.Close()
		return nil, fmt.Errorf("%s: a daemon is already listening", path)
	}
	os.Remove(path)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// PeerOK reports whether the process on the other end of c runs as the current user.
func PeerOK(c *net.UnixConn) bool {
	uid, err := peerUID(c)
	return err == nil && int(uid) == os.Getuid()
}

// Listen binds path (0600) for control requests.
func Listen(path string) (*Server, error) {
	l, err := ListenUnix(path)
	if err != nil {
		return nil, err
	}
	return &Server{l: l, path: path}, nil
}

// Close stops accepting and removes the socket file.
func (s *Server) Close() error {
	err := s.l.Close()
	os.Remove(s.path)
	return err
}

// Serve handles connections until the listener closes. Each connection carries one request.
func (s *Server) Serve(h Handler) error {
	for {
		c, err := s.l.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go serveConn(c, h)
	}
}

func serveConn(c *net.UnixConn, h Handler) {
	defer c.Close()
	if !PeerOK(c) {
		return // silently drop: not our user
	}
	c.SetDeadline(time.Now().Add(30 * time.Second))
	var req Request
	if err := json.NewDecoder(bufio.NewReader(c)).Decode(&req); err != nil {
		json.NewEncoder(c).Encode(Response{Error: "bad request: " + err.Error()})
		return
	}
	data, err := h(req)
	resp := Response{OK: err == nil}
	if err != nil {
		resp.Error = err.Error()
	} else if data != nil {
		if resp.Data, err = json.Marshal(data); err != nil {
			resp = Response{Error: err.Error()}
		}
	}
	json.NewEncoder(c).Encode(resp)
}

// Call sends one request and returns the response; a daemon-side error comes back as the error.
func Call(path string, req Request) (Response, error) {
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return Response{}, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.NewDecoder(bufio.NewReader(c)).Decode(&resp); err != nil {
		return Response{}, err
	}
	if !resp.OK {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if serr != nil {
		return 0, serr
	}
	return cred.Uid, nil
}
