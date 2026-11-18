package daemon

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// NetTest routes guest traffic to local fixtures. It is set only by tests, never by the isolait command line or
// the configuration, and is passed to the engine through its TEST ONLY flags.
type NetTest struct {
	Routes         []string // guestIP:port=host:port
	DNSUpstream    string   // host:port
	PermitLoopback bool
}

// netEngine is the network engine process of one session. It runs outside the sandbox, in the daemon's
// namespaces, and ends when the daemon closes its stdin (or dies).
type netEngine struct {
	cmd   *exec.Cmd
	stdin *os.File

	mu       sync.Mutex
	down     string // why the engine is no longer running, empty while it is
	stopping bool
}

// startNetEngine starts the engine for the sandbox whose PID is pid and waits until it reports ready: the
// interface is up in the sandbox's network namespace and the process has dropped its mount authority.
func startNetEngine(exe string, pid int, test *NetTest, stderr *os.File) (*netEngine, error) {
	readyR, readyW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer readyR.Close()
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		readyW.Close()
		return nil, err
	}
	args := []string{"netd", "--netns", fmt.Sprintf("/proc/%d/ns/net", pid), "--ready-fd", "3"}
	if test != nil {
		for _, r := range test.Routes {
			args = append(args, "--test-route", r)
		}
		if test.DNSUpstream != "" {
			args = append(args, "--test-dns", test.DNSUpstream)
		}
		if test.PermitLoopback {
			args = append(args, "--test-permit-loopback")
		}
	}
	cmd := exec.Command(exe, args...)
	cmd.Env = []string{}
	cmd.Stdin = stdinR
	tail := &tailBuffer{max: 2048}
	cmd.Stderr = io.MultiWriter(stderr, tail) // the log, and the reason if the start fails
	cmd.ExtraFiles = []*os.File{readyW}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		readyW.Close()
		stdinR.Close()
		stdinW.Close()
		return nil, fmt.Errorf("starting the network engine: %w", err)
	}
	readyW.Close()
	stdinR.Close()

	n := &netEngine{cmd: cmd, stdin: stdinW}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	ready := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(readyR).ReadString('\n')
		if err != nil || line != "ready\n" {
			ready <- errors.New("the network engine closed its readiness pipe without reporting ready")
			return
		}
		ready <- nil
	}()
	select {
	case err := <-ready:
		if err != nil {
			stdinW.Close()
			cmd.Process.Kill()
			<-exited
			return nil, fmt.Errorf("%v: %s", err, tail.String())
		}
	case err := <-exited:
		stdinW.Close()
		return nil, fmt.Errorf("the network engine exited while starting: %v: %s", err, tail.String())
	case <-time.After(20 * time.Second):
		stdinW.Close()
		cmd.Process.Kill()
		<-exited
		return nil, errors.New("timed out waiting for the network engine")
	}
	go func() {
		err := <-exited
		n.mu.Lock()
		defer n.mu.Unlock()
		if !n.stopping {
			n.down = fmt.Sprintf("the network engine exited: %v", err)
		}
	}()
	return n, nil
}

// status is "up", or "down: <reason>" if the engine died while the session runs.
func (n *netEngine) status() string {
	if n == nil {
		return "none"
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.down != "" {
		return "down: " + n.down
	}
	return "up"
}

// stop ends the engine: closing its stdin is its signal to exit.
func (n *netEngine) stop() {
	if n == nil {
		return
	}
	n.mu.Lock()
	n.stopping = true
	n.mu.Unlock()
	n.stdin.Close()
	time.AfterFunc(3*time.Second, func() { n.cmd.Process.Kill() })
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	mu  sync.Mutex
	max int
	b   []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.b = append(t.b, p...)
	if len(t.b) > t.max {
		t.b = t.b[len(t.b)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.TrimSpace(string(t.b))
}

func (n *netEngine) pid() int {
	if n == nil || n.cmd.Process == nil {
		return 0
	}
	return n.cmd.Process.Pid
}
