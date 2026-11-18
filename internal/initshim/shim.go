package initshim

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
)

type exit struct{ code, sig int }

type shim struct {
	conn *net.UnixConn
	wmu  sync.Mutex // serialises writes to conn

	mu   sync.Mutex  // held across StartProcess+register+"started", so "started" always precedes "exited"
	jobs map[int]int // pid -> id of processes we started
}

// Run serves the control socket until the daemon closes it or asks for shutdown. It is the body of the
// in-sandbox `isolait init` command and never returns an error for a normal end of the session.
func Run(f *os.File) error {
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return err
	}
	conn, ok := c.(*net.UnixConn)
	if !ok {
		return errors.New("initshim: control fd is not a unix socket")
	}
	s := &shim{conn: conn, jobs: map[int]int{}}

	chld := make(chan os.Signal, 16)
	signal.Notify(chld, syscall.SIGCHLD)
	go func() {
		for range chld {
			s.reap()
		}
	}()

	s.send(Event{Event: "hello", PID: os.Getpid()})
	for {
		req, files, err := recv(conn)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil // daemon is gone: end the sandbox
			}
			return err
		}
		switch req.Op {
		case "spawn":
			s.spawn(req, files)
		case "signal":
			s.signal(req)
		case "shutdown":
			s.killAll()
			return nil
		default:
			closeAll(files)
			s.send(Event{Event: "error", ID: req.ID, Error: fmt.Sprintf("unknown op %q", req.Op)})
		}
	}
}

func recv(conn *net.UnixConn) (Request, []*os.File, error) {
	buf := make([]byte, maxMsg)
	oob := make([]byte, syscall.CmsgSpace(3*4))
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return Request{}, nil, err
	}
	if n == 0 && oobn == 0 {
		return Request{}, nil, io.EOF
	}
	var files []*os.File
	if oobn > 0 {
		msgs, perr := syscall.ParseSocketControlMessage(oob[:oobn])
		if perr == nil {
			for _, m := range msgs {
				if fds, err := syscall.ParseUnixRights(&m); err == nil {
					for _, fd := range fds {
						files = append(files, os.NewFile(uintptr(fd), "stdio"))
					}
				}
			}
		}
	}
	var req Request
	if err := json.Unmarshal(buf[:n], &req); err != nil {
		closeAll(files)
		return Request{Op: "bad"}, nil, nil
	}
	return req, files, nil
}

func closeAll(fs []*os.File) {
	for _, f := range fs {
		f.Close()
	}
}

func (s *shim) send(e Event) {
	b, _ := json.Marshal(e)
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.conn.Write(b)
}

func (s *shim) spawn(req Request, files []*os.File) {
	defer closeAll(files)
	fail := func(msg string) { s.send(Event{Event: "error", ID: req.ID, Error: msg}) }
	switch {
	case len(req.Argv) == 0 || len(req.Argv) > maxArgs:
		fail("spawn needs between 1 and 4096 arguments")
		return
	case len(files) != 3:
		fail(fmt.Sprintf("spawn needs 3 stdio files, got %d", len(files)))
		return
	}
	argv0, err := lookPath(req.Argv[0], req.Env)
	if err != nil {
		fail(err.Error())
		return
	}
	attr := &syscall.ProcAttr{
		Dir:   req.Cwd,
		Env:   req.Env,
		Files: []uintptr{files[0].Fd(), files[1].Fd(), files[2].Fd()},
		Sys:   &syscall.SysProcAttr{Setsid: true, Setctty: req.TTY, Ctty: 0},
	}
	// The reaper takes the same lock before looking a pid up, so even an instant exit is attributed.
	s.mu.Lock()
	defer s.mu.Unlock()
	pid, _, err := syscall.StartProcess(argv0, req.Argv, attr)
	if err != nil {
		fail(err.Error())
		return
	}
	s.jobs[pid] = req.ID
	s.send(Event{Event: "started", ID: req.ID, PID: pid})
}

func (s *shim) signal(req Request) {
	s.mu.Lock()
	var pid int
	for p, id := range s.jobs {
		if id == req.ID {
			pid = p
		}
	}
	s.mu.Unlock()
	if pid == 0 {
		s.send(Event{Event: "error", ID: req.ID, Error: "no such process"})
		return
	}
	syscall.Kill(pid, syscall.Signal(req.Sig))
}

func (s *shim) killAll() {
	s.mu.Lock()
	for pid := range s.jobs {
		syscall.Kill(pid, syscall.SIGKILL)
	}
	s.mu.Unlock()
	// As PID 1 of the sandbox's PID namespace, kill(-1) reaches only processes inside it. Anywhere else
	// (tests run the shim as an ordinary process) it would signal everything the user owns, so never do it.
	if os.Getpid() == 1 {
		syscall.Kill(-1, syscall.SIGKILL)
	}
}

// reap collects every exited child, including orphans reparented to PID 1, and reports the ones we started.
func (s *shim) reap() {
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if pid <= 0 || err != nil {
			return
		}
		e := exit{code: ws.ExitStatus()}
		if ws.Signaled() {
			e = exit{code: -1, sig: int(ws.Signal())}
		}
		s.mu.Lock()
		id, ok := s.jobs[pid]
		delete(s.jobs, pid)
		s.mu.Unlock()
		if ok {
			s.report(pid, id, e) // orphans (not ours) are reaped silently
		}
	}
}

func (s *shim) report(pid, id int, e exit) {
	s.send(Event{Event: "exited", ID: id, PID: pid, Code: e.code, Signal: e.sig})
}

// lookPath resolves a bare command name on the PATH of the environment it will run with, inside the sandbox
// (this process lives there, so it sees exactly the sandbox's filesystem).
func lookPath(name string, env []string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	path := "/usr/bin:/bin"
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			path = v
		}
	}
	for _, dir := range strings.Split(path, ":") {
		if dir == "" || !strings.HasPrefix(dir, "/") {
			continue
		}
		p := dir + "/" + name
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("command not found: %s", name)
}
