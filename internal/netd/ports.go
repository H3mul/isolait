package netd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// MaxGrantPorts caps how many ports one grant may open, so a typo like 1-65535 cannot open the world.
const MaxGrantPorts = 100

// ParsePorts expands a grant such as "8080" or "3000-3010" into its ports. Only TCP exists: any UDP notation is
// an error rather than being ignored.
func ParsePorts(s string) ([]uint16, error) {
	spec := strings.TrimSpace(s)
	low := strings.ToLower(spec)
	if strings.Contains(low, "udp") {
		return nil, fmt.Errorf("%q: UDP ports cannot be granted; only TCP is forwarded", s)
	}
	spec = strings.TrimSuffix(low, "/tcp")
	lo, hi, isRange := strings.Cut(spec, "-")
	if !isRange {
		hi = lo
	}
	a, errA := parsePort(lo)
	b, errB := parsePort(hi)
	if errA != nil || errB != nil {
		return nil, fmt.Errorf("%q is not a port or a port range like 3000-3010 (ports are 1 to 65535)", s)
	}
	if a > b {
		return nil, fmt.Errorf("%q: the range ends before it starts", s)
	}
	if n := int(b) - int(a) + 1; n > MaxGrantPorts {
		return nil, fmt.Errorf("%q opens %d ports; at most %d at once", s, n, MaxGrantPorts)
	}
	var ports []uint16
	for p := int(a); p <= int(b); p++ {
		ports = append(ports, uint16(p))
	}
	return ports, nil
}

func parsePort(s string) (uint16, error) {
	for _, r := range s { // digits only: no sign, no whitespace, no hex
		if r < '0' || r > '9' {
			return 0, errors.New("not a number")
		}
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 {
		return 0, errors.New("out of range")
	}
	return uint16(n), nil
}

// PortForwarder opens listeners on the sandbox's loopback and forwards each connection to the same port on the
// host's 127.0.0.1. The destination is fixed: the sandbox picks nothing but the port it already has a grant
// for, so no other host service or address is reachable through it.
type PortForwarder struct {
	NetnsPath string // the sandbox's network namespace
	Logf      func(string, ...any)

	listen func(port uint16) (net.Listener, error) // test seam
	dial   func(ctx context.Context, port uint16) (net.Conn, error)

	mu     sync.Mutex
	grants map[uint16]*grant
	sem    chan struct{}
}

type grant struct {
	l     net.Listener
	mu    sync.Mutex
	conns map[net.Conn]struct{}
	shut  bool
}

func NewPortForwarder(netnsPath string, logf func(string, ...any)) *PortForwarder {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	f := &PortForwarder{NetnsPath: netnsPath, Logf: logf, grants: map[uint16]*grant{}, sem: make(chan struct{}, defaultMaxConn)}
	f.listen = f.listenInSandbox
	f.dial = func(ctx context.Context, port uint16) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	}
	return f
}

// listenInSandbox creates the listening socket inside the sandbox's network namespace. The socket is bound to
// the namespace it was created in, so the thread that entered it is discarded afterwards (a locked goroutine
// that returns takes its thread with it) and no other work ever runs there.
func (f *PortForwarder) listenInSandbox(port uint16) (net.Listener, error) {
	type res struct {
		l   net.Listener
		err error
	}
	ch := make(chan res, 1)
	go func() {
		runtime.LockOSThread() // deliberately never unlocked
		ns, err := syscall.Open(f.NetnsPath, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			ch <- res{nil, fmt.Errorf("opening the sandbox's network namespace: %w", err)}
			return
		}
		defer syscall.Close(ns)
		if _, _, e := syscall.RawSyscall(setnsNumber(), uintptr(ns), cloneNewnet, 0); e != 0 {
			ch <- res{nil, fmt.Errorf("entering the sandbox's network namespace: %w", e)}
			return
		}
		l, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
		ch <- res{l, err}
	}()
	r := <-ch
	return r.l, r.err
}

// Allow opens port. Opening an open port is a no-op.
func (f *PortForwarder) Allow(port uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.grants[port] != nil {
		return nil
	}
	l, err := f.listen(port)
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			return fmt.Errorf("port %d is already in use inside the sandbox", port)
		}
		return fmt.Errorf("port %d: %w", port, err)
	}
	g := &grant{l: l, conns: map[net.Conn]struct{}{}}
	f.grants[port] = g
	go f.accept(port, g)
	return nil
}

// Deny closes the listener for port and every connection made through it. It reports whether the port was open.
func (f *PortForwarder) Deny(port uint16) bool {
	f.mu.Lock()
	g := f.grants[port]
	delete(f.grants, port)
	f.mu.Unlock()
	if g == nil {
		return false
	}
	g.close()
	return true
}

func (g *grant) close() {
	g.l.Close()
	g.mu.Lock()
	g.shut = true
	for c := range g.conns {
		c.Close()
	}
	g.mu.Unlock()
}

// track registers a connection of this grant; it fails if the grant was closed in the meantime.
func (g *grant) track(c net.Conn) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.shut {
		return false
	}
	g.conns[c] = struct{}{}
	return true
}

func (g *grant) untrack(c net.Conn) { g.mu.Lock(); delete(g.conns, c); g.mu.Unlock() }

// Open lists the open ports in order.
func (f *PortForwarder) Open() []uint16 {
	f.mu.Lock()
	defer f.mu.Unlock()
	var p []uint16
	for k := range f.grants {
		p = append(p, k)
	}
	sort.Slice(p, func(i, j int) bool { return p[i] < p[j] })
	return p
}

// Close shuts every grant.
func (f *PortForwarder) Close() {
	for _, p := range f.Open() {
		f.Deny(p)
	}
}

func (f *PortForwarder) accept(port uint16, g *grant) {
	for {
		c, err := g.l.Accept()
		if err != nil {
			return
		}
		select {
		case f.sem <- struct{}{}:
		default:
			c.Close() // too many connections: refuse rather than queue
			continue
		}
		go func() {
			defer func() { <-f.sem }()
			f.forward(port, g, c)
		}()
	}
}

func (f *PortForwarder) forward(port uint16, g *grant, in net.Conn) {
	defer in.Close()
	if !g.track(in) {
		return
	}
	defer g.untrack(in)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	out, err := f.dial(ctx, port)
	cancel()
	if err != nil {
		f.Logf("port %d: the host service refused the connection: %v", port, err)
		return
	}
	defer out.Close()
	if !g.track(out) {
		return
	}
	defer g.untrack(out)
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(out, in)
	go pipe(in, out)
	<-done
	<-done
}

// ServeControl reads the daemon's commands, one per line, and answers each with one line, until r ends. The
// commands are "allow <port>", "deny <port>" and "list". Replies are "ok [text]" or "err <text>".
func ServeControl(r io.Reader, w io.Writer, f *PortForwarder) {
	sc := bufio.NewScanner(r)
	reply := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	for sc.Scan() {
		verb, arg, _ := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		switch verb {
		case "allow", "deny":
			p, err := parsePort(arg)
			if err != nil {
				reply("err bad port %q", arg)
			} else if verb == "allow" {
				if err := f.Allow(p); err != nil {
					reply("err %s", err)
				} else {
					reply("ok")
				}
			} else if f.Deny(p) {
				reply("ok")
			} else {
				reply("err port %d is not open", p)
			}
		case "list":
			var s []string
			for _, p := range f.Open() {
				s = append(s, strconv.Itoa(int(p)))
			}
			reply("ok %s", strings.Join(s, " "))
		default:
			reply("err unknown command %q", verb)
		}
	}
}
