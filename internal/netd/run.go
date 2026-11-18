package netd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"

	"github.com/H3mul/isolait/internal/harden"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
)

// Options configures the network engine process.
type Options struct {
	NetnsPath  string    // /proc/<pid>/ns/net of the sandbox
	Ready      io.Writer // receives "ready\n" once the interface is up, the engine runs and the process is hardened
	ResolvConf string    // the host's resolver configuration (default /etc/resolv.conf), re-read for every query
	Logf       func(format string, args ...any)

	// Test seams, set only through the test flags of the hidden netd command, never by the product's own launch:
	DNSUpstream    string            // resolve through this host:port instead of the host's resolvers
	Routes         map[string]string // guest-visible "ip:port" -> where to actually connect (fixture servers)
	PermitLoopback bool              // let the engine's own dials reach loopback, for the fixtures
}

// The process runs in two stages. Stage 1 has the daemon's full capabilities: it enters the sandbox's network
// namespace and creates the interface. It then re-executes itself holding only the capabilities the engine
// needs (CAP_NET_ADMIN, and CAP_SYS_ADMIN for setns, so later port grants can enter the namespace again).
// Stage 2 is a fresh process, so the reduction covers every thread, and it installs the seccomp filter that
// denies the mount family before it reports ready. Anything that fails fails the whole start: nothing runs
// un-hardened.

// hostAddrs lists this host's own addresses; tests replace it to give the host a public-looking address.
var hostAddrs = HostAddresses

// productPolicy is the policy the engine runs with: everything blocked by default, including the host itself.
func productPolicy() *Policy { return NewPolicy(hostAddrs(), GatewayAddr) }

// RunStage2 serves the sandbox's network on an already created tap until stop is closed.
func RunStage2(o Options, tapFD int, stop <-chan struct{}) error {
	if o.ResolvConf == "" {
		o.ResolvConf = "/etc/resolv.conf"
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	var up Upstream
	if o.DNSUpstream != "" {
		up = &HostResolver{Servers: []string{o.DNSUpstream}}
	} else {
		h, err := NewHostResolver(o.ResolvConf)
		if err != nil {
			return fmt.Errorf("the host's resolver: %w", err)
		}
		up = h
	}
	if err := syscall.SetNonblock(tapFD, true); err != nil {
		return err
	}
	mac, _ := net.ParseMAC("5a:94:ef:e4:0c:ee")
	link, terr := fdbased.New(&fdbased.Options{FDs: []int{tapFD}, MTU: tapMTU, EthernetHeader: true, Address: tcpip.LinkAddress(mac)})
	if terr != nil {
		return fmt.Errorf("attaching the tap: %v", terr)
	}

	pol := productPolicy()
	cfg := Config{Policy: pol, Gateway: GatewayAddr, Upstream: up, Logf: o.Logf}
	if o.PermitLoopback {
		pol.permit = func(a netip.Addr) bool { return a.IsLoopback() }
	}
	if len(o.Routes) > 0 {
		d := &net.Dialer{Timeout: dialTimeout}
		cfg.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			target, ok := o.Routes[address]
			if !ok {
				return nil, fmt.Errorf("no route for %s", address)
			}
			return d.DialContext(ctx, network, target)
		}
	}
	eng, err := New(link, cfg)
	if err != nil {
		return err
	}
	defer eng.Close()

	if err := harden.DenyDangerousCalls(); err != nil {
		return err
	}
	if o.Ready != nil {
		if _, err := io.WriteString(o.Ready, "ready\n"); err != nil {
			return err
		}
	}
	<-stop
	return nil
}

// Main is the body of the hidden `isolait netd` command. The process lives as long as stdin stays open: when
// the daemon that started it goes away, stdin closes and it exits.
func Main(args []string, stdin io.Reader, stderr io.Writer) error {
	fs := flag.NewFlagSet("netd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	netns := fs.String("netns", "", "network namespace path of the sandbox")
	readyFD := fs.Int("ready-fd", -1, "file descriptor to report readiness on")
	resolv := fs.String("resolv", "", "host resolver configuration")
	stage2 := fs.Bool("stage2", false, "INTERNAL: the re-executed, capability-reduced stage")
	tapFD := fs.Int("tap-fd", -1, "INTERNAL: the tap created by stage 1")
	testDNS := fs.String("test-dns", "", "TEST ONLY: resolve through this host:port")
	testLoop := fs.Bool("test-permit-loopback", false, "TEST ONLY: let the engine dial loopback")
	var routes routeFlags
	fs.Var(&routes, "test-route", "TEST ONLY: guestIP:port=host:port, repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if !*stage2 {
		if *netns == "" {
			return errors.New("netd: --netns is required")
		}
		fd, err := SetupNetns(*netns)
		if err != nil {
			return err
		}
		if _, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, 0); e != 0 { // survive the exec
			return fmt.Errorf("netd: clearing close-on-exec on the tap: %w", e)
		}
		self, err := os.Executable()
		if err != nil {
			return err
		}
		next := append([]string{self, "netd"}, args...)
		next = append(next, "--stage2", "--tap-fd", fmt.Sprint(fd))
		// ExecWithCaps returns only on failure
		return harden.ExecWithCaps([]int{harden.CapNetAdmin, harden.CapSysAdmin}, self, next, []string{})
	}

	if *tapFD < 0 {
		return errors.New("netd: --tap-fd is required in stage 2")
	}
	o := Options{NetnsPath: *netns, ResolvConf: *resolv, DNSUpstream: *testDNS, PermitLoopback: *testLoop, Routes: routes.m,
		Logf: func(f string, a ...any) { fmt.Fprintf(stderr, "netd: "+f+"\n", a...) }}
	if *readyFD >= 0 {
		o.Ready = os.NewFile(uintptr(*readyFD), "ready")
	}
	stop := make(chan struct{})
	go func() { io.Copy(io.Discard, stdin); close(stop) }()
	return RunStage2(o, *tapFD, stop)
}

type routeFlags struct{ m map[string]string }

func (r *routeFlags) String() string { return "" }
func (r *routeFlags) Set(v string) error {
	k, t, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("route %q is not ip:port=host:port", v)
	}
	if r.m == nil {
		r.m = map[string]string{}
	}
	r.m[k] = t
	return nil
}
