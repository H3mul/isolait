package netd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID          = 1
	dialTimeout    = 10 * time.Second
	defaultMaxConn = 512
)

// Config is everything the engine needs from its surroundings.
type Config struct {
	Policy   *Policy
	Gateway  netip.Addr // the address the sandbox sees as its gateway; DNS is answered here
	Upstream Upstream   // the host's resolver
	// Dial connects to an upstream address. The default dials TCP with the policy's dial-time check installed.
	Dial     func(ctx context.Context, network, address string) (net.Conn, error)
	MaxConns int                              // concurrent forwarded connections (default 512)
	Logf     func(format string, args ...any) // refusals and failures; nil discards
}

// Engine is the user-space network stack behind the sandbox's device.
type Engine struct {
	s      *stack.Stack
	cfg    Config
	sem    chan struct{}
	mu     sync.Mutex
	closed bool
}

// New starts the engine on a link endpoint (an Ethernet tap in production). It owns the gateway address,
// accepts packets for any destination and forwards the TCP it sees, answers DNS to the gateway, and drops
// everything else: IPv6, ICMP and UDP other than DNS.
func New(link stack.LinkEndpoint, cfg Config) (*Engine, error) {
	if cfg.Policy == nil || !cfg.Gateway.Is4() || cfg.Upstream == nil {
		return nil, errors.New("netd: policy, an IPv4 gateway and an upstream resolver are required")
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = defaultMaxConn
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	e := &Engine{cfg: cfg, sem: make(chan struct{}, cfg.MaxConns)}
	if e.cfg.Dial == nil {
		e.cfg.Dial = newDialer(cfg.Policy).DialContext
	}

	e.s = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol}, // no IPv6
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := e.s.CreateNIC(nicID, newFilter(link)); err != nil {
		return nil, fmt.Errorf("netd: create nic: %v", err)
	}
	e.s.SetPromiscuousMode(nicID, true) // accept packets for any destination
	e.s.SetSpoofing(nicID, true)        // answer from any source address
	gw := tcpip.AddrFromSlice(cfg.Gateway.AsSlice())
	if err := e.s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: gw.WithPrefix()}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("netd: add address: %v", err)
	}
	e.s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})

	e.s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(e.s, 0, 1024, e.onTCP).HandlePacket)
	e.s.SetTransportProtocolHandler(udp.ProtocolNumber, udp.NewForwarder(e.s, e.onUDP).HandlePacket)
	return e, nil
}

// Close stops the engine.
func (e *Engine) Close() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	e.mu.Unlock()
	e.s.Close()
}

// newDialer is the engine's own dialer: the policy runs on the socket address about to be connected.
func newDialer(p *Policy) *net.Dialer { return &net.Dialer{Timeout: dialTimeout, Control: p.Control} }

// linkFilter drops ICMP before the stack sees it, so the stack never answers a ping for an address it does
// not own (promiscuous mode would otherwise make every address look alive).
type linkFilter struct{ nested.Endpoint }

func newFilter(child stack.LinkEndpoint) *linkFilter {
	f := &linkFilter{}
	f.Endpoint.Init(child, f)
	return f
}

func (f *linkFilter) DeliverNetworkPacket(proto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if proto == ipv4.ProtocolNumber {
		if h := pkt.Data().AsRange().ToSlice(); len(h) >= 10 && h[9] == 1 { // IP protocol 1: ICMP
			return
		}
	}
	f.Endpoint.DeliverNetworkPacket(proto, pkt)
}

// ---- TCP ----

func (e *Engine) onTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	dst = dst.Unmap()
	port := id.LocalPort

	if dst == e.cfg.Gateway {
		if port != 53 {
			e.cfg.Logf("refused tcp to the gateway port %d", port)
			r.Complete(true)
			return
		}
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		go e.dnsTCP(gonet.NewTCPConn(&wq, ep))
		return
	}
	if err := e.cfg.Policy.Check(dst); err != nil {
		e.cfg.Logf("refused tcp: %v", err)
		r.Complete(true)
		return
	}
	select {
	case e.sem <- struct{}{}:
	default:
		e.cfg.Logf("refused tcp to %s:%d: too many connections", dst, port)
		r.Complete(true)
		return
	}
	go func() {
		defer func() { <-e.sem }()
		e.forward(r, dst, port)
	}()
}

// forward dials the upstream first and completes the guest's handshake only if that worked, so a refused or
// blocked upstream is a refused guest connect, not a connect followed by a reset.
func (e *Engine) forward(r *tcp.ForwarderRequest, dst netip.Addr, port uint16) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	up, err := e.cfg.Dial(ctx, "tcp4", net.JoinHostPort(dst.String(), fmt.Sprint(port)))
	if err != nil {
		e.cfg.Logf("tcp to %s:%d failed: %v", dst, port, err)
		r.Complete(true)
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		up.Close()
		r.Complete(true)
		return
	}
	r.Complete(false)
	proxy(up, gonet.NewTCPConn(&wq, ep))
}

type closeWriter interface{ CloseWrite() error }

// proxy copies both ways until both directions end; a read error ends both at once.
func proxy(up net.Conn, guest *gonet.TCPConn) {
	type result struct{ err error }
	done := make(chan result, 2)
	go func() {
		_, err := io.Copy(up, guest)
		if cw, ok := up.(closeWriter); ok && err == nil {
			cw.CloseWrite()
		}
		done <- result{err}
	}()
	go func() {
		_, err := io.Copy(guest, up)
		if err == nil {
			guest.CloseWrite()
		}
		done <- result{err}
	}()
	first := <-done
	if first.err != nil {
		up.Close()
		guest.Close()
		<-done
		return
	}
	<-done
	up.Close()
	guest.Close()
}

// ---- UDP: DNS to the gateway only ----

func (e *Engine) onUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	dst, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if dst.Unmap() != e.cfg.Gateway || id.LocalPort != 53 {
		return false // every other UDP datagram is dropped
	}
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return false
	}
	go e.dnsUDP(gonet.NewUDPConn(&wq, ep))
	return true
}
