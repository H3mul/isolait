// Package netd is the network engine: a user-space TCP/IP stack behind the sandbox's only network device that
// forwards the sandbox's TCP connections to the internet, answers its DNS, and refuses everything else. It
// runs as its own process, outside the sandbox, so a bug in packet parsing cannot reach the daemon's mount
// authority and sandboxed code cannot signal, reconfigure or bypass it.
package netd

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// A blocked range and why. The list is the specification's: loopback, private, carrier-grade NAT, link-local,
// multicast and cloud-metadata space, plus everything that is not a routable unicast address.
var blockedRanges = []struct {
	prefix netip.Prefix
	why    string
}{
	// cloud metadata endpoints first, so they are reported as what they are
	{netip.MustParsePrefix("169.254.169.254/32"), "cloud metadata service"},
	{netip.MustParsePrefix("169.254.170.2/32"), "cloud metadata service"},
	{netip.MustParsePrefix("100.100.100.200/32"), "cloud metadata service"},
	{netip.MustParsePrefix("192.0.0.192/32"), "cloud metadata service"},
	{netip.MustParsePrefix("168.63.129.16/32"), "cloud metadata service"},

	{netip.MustParsePrefix("0.0.0.0/8"), "unspecified or 'this network' address"},
	{netip.MustParsePrefix("10.0.0.0/8"), "private network (RFC 1918)"},
	{netip.MustParsePrefix("100.64.0.0/10"), "carrier-grade NAT"},
	{netip.MustParsePrefix("127.0.0.0/8"), "loopback"},
	{netip.MustParsePrefix("169.254.0.0/16"), "link-local"},
	{netip.MustParsePrefix("172.16.0.0/12"), "private network (RFC 1918)"},
	{netip.MustParsePrefix("192.0.0.0/24"), "IETF protocol assignments"},
	{netip.MustParsePrefix("192.0.2.0/24"), "documentation range (TEST-NET-1)"},
	{netip.MustParsePrefix("192.88.99.0/24"), "6to4 relay anycast"},
	{netip.MustParsePrefix("192.168.0.0/16"), "private network (RFC 1918)"},
	{netip.MustParsePrefix("198.18.0.0/15"), "benchmarking range"},
	{netip.MustParsePrefix("198.51.100.0/24"), "documentation range (TEST-NET-2)"},
	{netip.MustParsePrefix("203.0.113.0/24"), "documentation range (TEST-NET-3)"},
	{netip.MustParsePrefix("224.0.0.0/4"), "multicast"},
	{netip.MustParsePrefix("240.0.0.0/4"), "reserved or broadcast"},
}

// Policy decides which destinations the sandbox may reach. It is applied twice to every connection: on the
// destination the guest asked for, and again on the address actually dialed, after name resolution, so a name
// that resolves to a private address (DNS rebinding) is refused and there is no check-then-use gap.
type Policy struct {
	host    map[netip.Addr]bool // the host's own addresses
	gateway netip.Addr          // the address the sandbox sees as its gateway (where DNS is answered)

	// permit overrides a block; it exists so tests can let the engine reach local fixture servers. It is
	// unexported and never set by product code.
	permit func(netip.Addr) bool
}

// NewPolicy returns the policy for a sandbox whose gateway is gateway, on a host with the given own addresses.
func NewPolicy(hostAddrs []netip.Addr, gateway netip.Addr) *Policy {
	p := &Policy{host: map[netip.Addr]bool{}, gateway: gateway.Unmap()}
	for _, a := range hostAddrs {
		p.host[a.Unmap()] = true
	}
	return p
}

// HostAddresses lists this machine's own IPv4 addresses.
func HostAddresses() []netip.Addr {
	var out []netip.Addr
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok && ip.Unmap().Is4() {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

// BlockedError says why a destination was refused.
type BlockedError struct {
	Addr netip.Addr
	Why  string
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("destination %s refused: %s", e.Addr, e.Why)
}

// Check returns nil when the sandbox may connect to addr, or a *BlockedError.
func (p *Policy) Check(addr netip.Addr) error {
	a := addr.Unmap() // an IPv4-mapped IPv6 address is judged as the IPv4 address it carries
	if p.permit != nil && p.permit(a) {
		return nil
	}
	if !a.Is4() {
		return &BlockedError{addr, "IPv6 is not supported"}
	}
	if a == p.gateway {
		return &BlockedError{a, "the sandbox gateway"}
	}
	if p.host[a] {
		return &BlockedError{a, "an address of the host itself"}
	}
	for _, r := range blockedRanges {
		if r.prefix.Contains(a) {
			return &BlockedError{a, r.why}
		}
	}
	return nil
}

// Control is a net.Dialer.Control function: it runs after name resolution, on the exact socket address about to
// be connected, and fails the connection before any packet is sent if the policy forbids it.
func (p *Policy) Control(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("cannot parse dial address %q: %w", address, err) // fail closed
	}
	return p.Check(ap.Addr())
}
