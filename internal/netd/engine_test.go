package netd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// The bed wires a guest network stack (standing in for the sandbox) to the engine through two channel
// endpoints, so the whole forwarding path runs in-process with no kernel features. The "internet" is local
// fixture servers: guest-visible public addresses are remapped to them by the engine's Dial.

const (
	guestIP  = "10.0.2.15"
	gatewayS = "10.0.2.2"
	pubIP    = "93.184.216.34" // a public address used as the guest-visible destination in tests
)

type bed struct {
	t        *testing.T
	guest    *stack.Stack
	eng      *Engine
	up       *fakeUpstream
	routes   sync.Map // "ip:port" the guest dials -> "127.0.0.1:port" to connect to instead
	dials    atomic.Int32
	cancel   context.CancelFunc
	tcpDelay time.Duration
}

type fakeUpstream struct {
	calls, tcpCalls atomic.Int32
	mu              sync.Mutex
	answers         map[string]netip.Addr
}

func (f *fakeUpstream) Exchange(ctx context.Context, q []byte, tcp bool) ([]byte, error) {
	f.calls.Add(1)
	if tcp {
		f.tcpCalls.Add(1)
	}
	name, end := qname(q)
	f.mu.Lock()
	a, ok := f.answers[name]
	f.mu.Unlock()
	resp := append([]byte(nil), q[:end]...)
	binary.BigEndian.PutUint16(resp[2:], 0x8180) // response, recursion available
	if !ok {
		binary.BigEndian.PutUint16(resp[2:], 0x8183) // NXDOMAIN
		return resp, nil
	}
	binary.BigEndian.PutUint16(resp[6:], 1) // one answer
	resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
	return append(resp, a.AsSlice()...), nil
}

func qname(q []byte) (string, int) {
	var labels []string
	i := 12
	for i < len(q) && q[i] != 0 {
		n := int(q[i])
		labels = append(labels, string(q[i+1:i+1+n]))
		i += n + 1
	}
	return strings.Join(labels, "."), i + 1 + 4
}

func buildQuery(id uint16, name string) []byte {
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q, id)
	binary.BigEndian.PutUint16(q[2:], 0x0100)
	binary.BigEndian.PutUint16(q[4:], 1)
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

func answerA(resp []byte) (netip.Addr, bool) {
	if len(resp) < 12 || binary.BigEndian.Uint16(resp[6:]) == 0 {
		return netip.Addr{}, false
	}
	a, ok := netip.AddrFromSlice(resp[len(resp)-4:])
	return a, ok
}

type bedOption func(*Config)

func newBed(t *testing.T, opts ...bedOption) *bed {
	t.Helper()
	b := &bed{t: t, up: &fakeUpstream{answers: map[string]netip.Addr{}}}
	ctx, cancel := context.WithCancel(context.Background())
	b.cancel = cancel

	ge, ee := channel.New(1024, 1500, ""), channel.New(1024, 1500, "")
	pump := func(from, to *channel.Endpoint) {
		go func() {
			for {
				pkt := from.ReadContext(ctx)
				if pkt == nil {
					return
				}
				np := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: pkt.ToBuffer()})
				to.InjectInbound(pkt.NetworkProtocolNumber, np)
				np.DecRef()
				pkt.DecRef()
			}
		}()
	}
	pump(ge, ee)
	pump(ee, ge)

	pol := NewPolicy([]netip.Addr{netip.MustParseAddr("198.19.0.7")}, netip.MustParseAddr(gatewayS))
	pol.permit = func(a netip.Addr) bool { return false }
	cfg := Config{Policy: pol, Gateway: netip.MustParseAddr(gatewayS), Upstream: b.up, Logf: func(f string, a ...any) { t.Logf("netd: "+f, a...) },
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			b.dials.Add(1)
			target, ok := b.routes.Load(address)
			if !ok {
				return nil, errors.New("no fixture for " + address)
			}
			if b.tcpDelay > 0 {
				time.Sleep(b.tcpDelay)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, target.(string))
		}}
	for _, o := range opts {
		o(&cfg)
	}
	var err error
	if b.eng, err = New(ee, cfg); err != nil {
		t.Fatal(err)
	}

	b.guest = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})
	if e := b.guest.CreateNIC(1, ge); e != nil {
		t.Fatal(e)
	}
	addr := tcpip.AddrFromSlice(net.ParseIP(guestIP).To4())
	if e := b.guest.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr, PrefixLen: 24}}, stack.AddressProperties{}); e != nil {
		t.Fatal(e)
	}
	gw := tcpip.AddrFromSlice(net.ParseIP(gatewayS).To4())
	b.guest.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, Gateway: gw, NIC: 1}})
	t.Cleanup(func() { cancel(); b.eng.Close(); b.guest.Close() })
	return b
}

func fullAddr(ip string, port uint16) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(net.ParseIP(ip).To4()), Port: port}
}

func (b *bed) dial(ip string, port uint16) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	return gonet.DialContextTCP(ctx, b.guest, fullAddr(ip, port), ipv4.ProtocolNumber)
}

// serve starts a fixture TCP server and routes guest dials of pubIP:port to it.
func (b *bed) serve(port string, handle func(net.Conn)) string {
	b.t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.t.Fatal(err)
	}
	b.t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go handle(c)
		}
	}()
	b.routes.Store(pubIP+":"+port, l.Addr().String())
	return l.Addr().String()
}

func echo(c net.Conn) { defer c.Close(); io.Copy(c, c) }

// ---- TCP forwarding ----

func TestTCPForwardsBothWaysIntact(t *testing.T) {
	b := newBed(t)
	b.serve("80", echo)
	c, err := b.dial(pubIP, 80)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	data := make([]byte, 4<<20)
	rand.New(rand.NewSource(1)).Read(data)
	go func() { c.Write(data) }()
	got := make([]byte, len(data))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("reading the echo: %v", err)
	}
	if sha256.Sum256(got) != sha256.Sum256(data) {
		t.Error("4 MiB did not survive the round trip through the forwarder")
	}
}

func TestHalfCloseIsForwarded(t *testing.T) {
	b := newBed(t)
	b.serve("80", func(c net.Conn) {
		defer c.Close()
		in, _ := io.ReadAll(c) // returns when the guest has half-closed
		c.Write([]byte("bye:" + string(in)))
	})
	c, err := b.dial(pubIP, 80)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("hello"))
	c.(*gonet.TCPConn).CloseWrite()
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "bye:hello" {
		t.Errorf("got %q, %v after the guest half-closed", got, err)
	}
}

func TestRefusedUpstreamIsARefusedGuestConnect(t *testing.T) {
	b := newBed(t)
	l, _ := net.Listen("tcp4", "127.0.0.1:0")
	closed := l.Addr().String()
	l.Close() // nothing listens there now
	b.routes.Store(pubIP+":81", closed)
	start := time.Now()
	c, err := b.dial(pubIP, 81)
	if err == nil {
		c.Close()
		t.Fatal("the guest's connect succeeded although the upstream refused: that is connect-then-reset")
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Errorf("error %v, want connection refused", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("refusal took %v", time.Since(start))
	}
}

// The upstream is dialed before the guest's handshake completes: while the dial is in progress the guest's
// connect is still pending.
func TestHandshakeCompletesOnlyAfterTheUpstreamAnswered(t *testing.T) {
	b := newBed(t)
	b.tcpDelay = 700 * time.Millisecond
	b.serve("80", echo)
	start := time.Now()
	c, err := b.dial(pubIP, 80)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if took := time.Since(start); took < 600*time.Millisecond {
		t.Errorf("the guest's connect completed after %v, before the upstream dial (700 ms) finished", took)
	}
}

// ---- policy at the engine ----

func TestBlockedDestinationsNeverReachTheDialer(t *testing.T) {
	b := newBed(t)
	for _, dst := range []string{"192.168.1.1", "10.9.9.9", "172.20.0.1", "169.254.169.254", "169.254.170.2", "100.64.0.1", "198.19.0.7", "203.0.113.5"} {
		start := time.Now()
		if c, err := b.dial(dst, 80); err == nil {
			c.Close()
			t.Errorf("the guest connected to %s", dst)
		} else if time.Since(start) > 3*time.Second {
			t.Errorf("%s: refusal took %v", dst, time.Since(start))
		}
	}
	if n := b.dials.Load(); n != 0 {
		t.Errorf("the engine dialed %d times for blocked destinations", n)
	}
}

func TestGatewayAcceptsOnlyDNS(t *testing.T) {
	b := newBed(t)
	if c, err := b.dial(gatewayS, 80); err == nil {
		c.Close()
		t.Error("the gateway accepted a connection on port 80")
	}
	if b.dials.Load() != 0 {
		t.Error("a connection to the gateway reached the dialer")
	}
}

func TestConnectionLimit(t *testing.T) {
	b := newBed(t, func(c *Config) { c.MaxConns = 2 })
	b.serve("80", func(c net.Conn) { defer c.Close(); io.Copy(io.Discard, c) })
	c1, err1 := b.dial(pubIP, 80)
	c2, err2 := b.dial(pubIP, 80)
	if err1 != nil || err2 != nil {
		t.Fatalf("the first two connections must work: %v %v", err1, err2)
	}
	if c3, err := b.dial(pubIP, 80); err == nil {
		c3.Close()
		t.Error("a third connection was accepted over the limit of 2")
	}
	c1.Close()
	time.Sleep(300 * time.Millisecond)
	c4, err := b.dial(pubIP, 80)
	if err != nil {
		t.Errorf("a slot freed by closing should be reusable: %v", err)
	} else {
		c4.Close()
	}
	c2.Close()
}

func TestDefaultDialerRefusesLoopbackAtDialTime(t *testing.T) {
	l, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer l.Close()
	d := newDialer(testPol())
	if c, err := d.DialContext(context.Background(), "tcp4", l.Addr().String()); err == nil {
		c.Close()
		t.Fatal("the engine's own dialer connected to loopback")
	}
}

// ---- DNS ----

func TestDNSOverUDPIsAnsweredByTheHostResolver(t *testing.T) {
	b := newBed(t)
	b.up.answers["api.example.test"] = netip.MustParseAddr(pubIP)
	gw := fullAddr(gatewayS, 53)
	c, err := gonet.DialUDP(b.guest, nil, &gw, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(buildQuery(7, "api.example.test"))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no DNS answer: %v", err)
	}
	if a, ok := answerA(buf[:n]); !ok || a != netip.MustParseAddr(pubIP) || binary.BigEndian.Uint16(buf) != 7 {
		t.Errorf("answer %v ok=%v id=%d", a, ok, binary.BigEndian.Uint16(buf))
	}
	if c.RemoteAddr().String() != gatewayS+":53" {
		t.Errorf("the answer came from %s, want the gateway (the host's resolver address must not be exposed)", c.RemoteAddr())
	}
	// a second query on the same socket works too
	c.Write(buildQuery(8, "missing.example.test"))
	n, err = c.Read(buf)
	if err != nil || binary.BigEndian.Uint16(buf) != 8 || buf[3]&0xf != 3 {
		t.Errorf("second query: %v rcode %d", err, buf[3]&0xf)
	}
}

func TestDNSOverTCPIsAnswered(t *testing.T) {
	b := newBed(t)
	b.up.answers["big.example.test"] = netip.MustParseAddr(pubIP)
	c, err := b.dial(gatewayS, 53)
	if err != nil {
		t.Fatalf("the gateway must accept DNS over TCP: %v", err)
	}
	defer c.Close()
	writeFramed(c, buildQuery(9, "big.example.test"))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := readFramed(bufio.NewReader(c))
	if err != nil {
		t.Fatal(err)
	}
	if a, ok := answerA(resp); !ok || a != netip.MustParseAddr(pubIP) {
		t.Errorf("answer %v", a)
	}
	if b.up.tcpCalls.Load() != 1 {
		t.Errorf("the upstream was asked over %d TCP exchanges, want 1: a TCP guest gets a TCP upstream", b.up.tcpCalls.Load())
	}
}

func TestNonDNSUDPIsDropped(t *testing.T) {
	b := newBed(t)
	for _, dst := range []fullAddrT{{pubIP, 53}, {gatewayS, 5353}, {pubIP, 5353}, {pubIP, 443}} {
		fa := fullAddr(dst.ip, dst.port)
		c, err := gonet.DialUDP(b.guest, nil, &fa, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		c.Write(buildQuery(1, "x.example.test"))
		c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := c.Read(make([]byte, 512)); err == nil {
			t.Errorf("a reply came back from %s:%d", dst.ip, dst.port)
		}
		c.Close()
	}
	if n := b.up.calls.Load(); n != 0 {
		t.Errorf("the upstream resolver was asked %d times for traffic that is not DNS to the gateway", n)
	}
}

type fullAddrT struct {
	ip   string
	port uint16
}

func TestMalformedDNSIsDropped(t *testing.T) {
	b := newBed(t)
	gw := fullAddr(gatewayS, 53)
	c, _ := gonet.DialUDP(b.guest, nil, &gw, ipv4.ProtocolNumber)
	defer c.Close()
	resp := buildQuery(1, "a.example.test")
	resp[2] |= 0x80 // a response, not a query
	for _, bad := range [][]byte{{1, 2, 3}, resp, make([]byte, 12) /* no question */} {
		c.Write(bad)
	}
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := c.Read(make([]byte, 512)); err == nil {
		t.Error("a malformed message got an answer")
	}
	if b.up.calls.Load() != 0 {
		t.Error("a malformed message reached the upstream")
	}
}

// A name whose DNS answer is a private address resolves (the answer is the host resolver's) and then the
// connection is refused: the policy runs on the address actually dialed.
func TestNameResolvingToAPrivateAddressIsRefused(t *testing.T) {
	b := newBed(t)
	b.up.answers["internal.example.test"] = netip.MustParseAddr("10.1.2.3")
	gw := fullAddr(gatewayS, 53)
	u, _ := gonet.DialUDP(b.guest, nil, &gw, ipv4.ProtocolNumber)
	u.Write(buildQuery(5, "internal.example.test"))
	u.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, err := u.Read(buf)
	u.Close()
	if err != nil {
		t.Fatal(err)
	}
	a, ok := answerA(buf[:n])
	if !ok || a != netip.MustParseAddr("10.1.2.3") {
		t.Fatalf("the guest should have been told 10.1.2.3, got %v", a)
	}
	if c, err := b.dial(a.String(), 443); err == nil {
		c.Close()
		t.Error("the guest connected to the private address its DNS answer named")
	}
	if b.dials.Load() != 0 {
		t.Error("the dialer was reached for a private address")
	}
}

func TestResolvConfParsing(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := dir + "/resolv.conf"
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	path := write("# comment\nsearch lan\nnameserver 127.0.0.53\nnameserver fe80::1%eth0\noptions edns0\n")
	h, err := NewHostResolver(path)
	if err != nil || len(h.Servers) != 2 || h.Servers[0] != "127.0.0.53:53" || h.Servers[1] != "[fe80::1]:53" {
		t.Errorf("%v %v", h, err)
	}
	// the file is re-read: a change during the session is followed, and a broken file keeps the last good list
	write("nameserver 9.9.9.9\n")
	if s := h.servers(); len(s) != 1 || s[0] != "9.9.9.9:53" {
		t.Errorf("a changed resolv.conf was not followed: %v", s)
	}
	write("# nothing usable\n")
	if s := h.servers(); len(s) != 2 {
		t.Errorf("a resolv.conf without nameservers must not lose the last good list: %v", s)
	}
	if _, err := NewHostResolver(write("search lan\n")); err == nil {
		t.Error("a resolv.conf without a nameserver was accepted")
	}
	if _, err := NewHostResolver(dir + "/nope"); err == nil {
		t.Error("a missing resolv.conf was accepted")
	}
}

// ---- ICMP, IPv6 ----

func TestICMPIsDropped(t *testing.T) {
	b := newBed(t)
	var wq waiter.Queue
	ep, err := b.guest.NewEndpoint(icmp.ProtocolNumber4, ipv4.ProtocolNumber, &wq)
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close()
	we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&we)
	defer wq.EventUnregister(&we)

	echoReq := make([]byte, header.ICMPv4MinimumSize+8)
	h := header.ICMPv4(echoReq)
	h.SetType(header.ICMPv4Echo)
	h.SetIdent(1)
	h.SetSequence(1)
	h.SetChecksum(^checksum(echoReq))
	for _, dst := range []string{pubIP, gatewayS, "8.8.8.8"} {
		fa := fullAddr(dst, 0)
		if _, werr := ep.Write(bytes.NewReader(echoReq), tcpip.WriteOptions{To: &fa}); werr != nil {
			t.Fatalf("sending the echo request to %s: %v", dst, werr)
		}
	}
	select {
	case <-ch:
		t.Error("an ICMP echo reply came back: the engine must not answer pings for any address")
	case <-time.After(500 * time.Millisecond):
	}
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}
