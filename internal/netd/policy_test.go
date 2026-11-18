package netd

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

var (
	gw      = netip.MustParseAddr("10.0.2.2")
	hostLAN = netip.MustParseAddr("203.0.114.77") // a public-looking address that belongs to the host itself
	testPol = func() *Policy { return NewPolicy([]netip.Addr{hostLAN, netip.MustParseAddr("192.168.1.50")}, gw) }
)

func TestPolicyTable(t *testing.T) {
	tests := []struct {
		addr string
		why  string // empty: allowed
	}{
		// allowed: ordinary public addresses, including the edges next to blocked ranges
		{"8.8.8.8", ""}, {"1.1.1.1", ""}, {"93.184.216.34", ""}, {"160.79.104.10", ""},
		{"11.0.0.1", ""}, {"9.255.255.255", ""}, {"172.15.255.255", ""}, {"172.32.0.0", ""},
		{"100.63.255.255", ""}, {"100.128.0.0", ""}, {"192.167.255.255", ""}, {"192.169.0.0", ""},
		{"169.253.255.255", ""}, {"169.255.0.0", ""}, {"198.17.255.255", ""}, {"198.20.0.0", ""},
		{"223.255.255.255", ""}, {"::ffff:8.8.8.8", ""},

		// the specification's list
		{"127.0.0.1", "loopback"}, {"127.255.255.255", "loopback"}, {"127.0.0.53", "loopback"},
		{"10.0.0.0", "RFC 1918"}, {"10.255.255.255", "RFC 1918"},
		{"172.16.0.0", "RFC 1918"}, {"172.31.255.255", "RFC 1918"},
		{"192.168.0.0", "RFC 1918"}, {"192.168.1.1", "RFC 1918"}, {"192.168.255.255", "RFC 1918"},
		{"100.64.0.0", "carrier-grade NAT"}, {"100.127.255.255", "carrier-grade NAT"},
		{"169.254.0.1", "link-local"}, {"169.254.255.255", "link-local"},
		{"224.0.0.1", "multicast"}, {"239.255.255.250", "multicast"},

		// cloud metadata, named as such
		{"169.254.169.254", "cloud metadata"}, {"169.254.170.2", "cloud metadata"}, {"100.100.100.200", "cloud metadata"},
		{"192.0.0.192", "cloud metadata"}, {"168.63.129.16", "cloud metadata"},

		// everything else that is not routable unicast
		{"0.0.0.0", "unspecified"}, {"0.1.2.3", "unspecified"},
		{"255.255.255.255", "reserved or broadcast"}, {"240.0.0.1", "reserved or broadcast"},
		{"192.0.2.1", "documentation"}, {"198.51.100.1", "documentation"}, {"203.0.113.10", "documentation"},
		{"198.18.0.1", "benchmarking"}, {"192.88.99.1", "6to4"}, {"192.0.0.8", "IETF"},

		// the host and the gateway
		{"10.0.2.2", "gateway"}, {"203.0.114.77", "host itself"}, {"192.168.1.50", "host itself"},

		// IPv6 is out; a mapped IPv4 address is judged as the IPv4 address
		{"2001:4860:4860::8888", "IPv6"}, {"::1", "IPv6"}, {"fe80::1", "IPv6"}, {"fd00::1", "IPv6"},
		{"::ffff:192.168.1.1", "RFC 1918"}, {"::ffff:127.0.0.1", "loopback"}, {"::ffff:169.254.169.254", "cloud metadata"},
	}
	p := testPol()
	for _, tc := range tests {
		err := p.Check(netip.MustParseAddr(tc.addr))
		switch {
		case tc.why == "" && err != nil:
			t.Errorf("%s was refused: %v", tc.addr, err)
		case tc.why != "" && err == nil:
			t.Errorf("%s was allowed, want refusal (%s)", tc.addr, tc.why)
		case tc.why != "" && !strings.Contains(err.Error(), tc.why):
			t.Errorf("%s refused as %q, want %q", tc.addr, err, tc.why)
		}
	}
}

// An independent reference built from the standard library's classification: every random IPv4 address must be
// judged the same way by the table in blockedRanges.
func TestPolicyAgreesWithAReferenceOnRandomAddresses(t *testing.T) {
	ref := func(a netip.Addr) bool { // true = must be blocked
		b := a.As4()
		return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() ||
			a.IsLinkLocalMulticast() || (b[0] == 100 && b[1]&0xc0 == 64) || b[0] == 0 || b[0] >= 240 ||
			(b[0] == 192 && b[1] == 0 && b[2] <= 2) || (b[0] == 198 && b[1]&0xfe == 18) ||
			(b[0] == 198 && b[1] == 51 && b[2] == 100) || (b[0] == 203 && b[1] == 0 && b[2] == 113) ||
			(b[0] == 192 && b[1] == 88 && b[2] == 99) || a == netip.MustParseAddr("168.63.129.16")
	}
	p := NewPolicy(nil, gw)
	r := rand.New(rand.NewSource(3))
	for i := 0; i < 200000; i++ {
		a := netip.AddrFrom4([4]byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))})
		if a == gw {
			continue
		}
		if blocked := p.Check(a) != nil; blocked != ref(a) {
			t.Fatalf("%s: policy blocked=%v, reference blocked=%v", a, blocked, ref(a))
		}
	}
}

func TestBlockedErrorNamesTheAddress(t *testing.T) {
	err := testPol().Check(netip.MustParseAddr("192.168.1.1"))
	var be *BlockedError
	if !errors.As(err, &be) || be.Addr != netip.MustParseAddr("192.168.1.1") {
		t.Fatalf("%v", err)
	}
}

// The dial-time hook: it sees the address actually connected, after name resolution. A name that resolves to a
// loopback or private address is refused before a single packet is sent.
func TestControlRefusesAtDialTimeAfterNameResolution(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			accepted <- struct{}{}
			c.Close()
		}
	}()
	port := l.Addr().(*net.TCPAddr).Port

	d := net.Dialer{Timeout: 2 * time.Second, Control: testPol().Control}
	for _, name := range []string{"localhost", "127.0.0.1"} { // localhost resolves to loopback: the "rebinding" case
		_, err := d.DialContext(context.Background(), "tcp4", net.JoinHostPort(name, strconv.Itoa(port)))
		if err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Errorf("dialing %s: %v, want a loopback refusal", name, err)
		}
	}
	select {
	case <-accepted:
		t.Error("a connection reached the server: the policy ran after the connect")
	case <-time.After(200 * time.Millisecond):
	}

	// with the policy permitting loopback (tests only) the same dial works, so the refusal above was the policy
	p := testPol()
	p.permit = func(a netip.Addr) bool { return a.IsLoopback() }
	d.Control = p.Control
	c, err := d.DialContext(context.Background(), "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("control run: %v", err)
	}
	c.Close()
}

func TestControlFailsClosedOnAnUnparsableAddress(t *testing.T) {
	if err := testPol().Control("tcp", "not-an-address", nil); err == nil {
		t.Error("an address that cannot be parsed must be refused")
	}
}

func TestHostAddressesAreIPv4Only(t *testing.T) {
	for _, a := range HostAddresses() {
		if !a.Is4() {
			t.Errorf("%s is not IPv4", a)
		}
	}
}
