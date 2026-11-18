package netd

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

const (
	maxDNSMessage   = 4096
	dnsIdle         = 5 * time.Second
	dnsExchangeTime = 5 * time.Second
	maxDNSInFlight  = 64
)

// Upstream resolves DNS queries with the host's resolver. The sandbox never learns its address: it only talks
// to the gateway.
type Upstream interface {
	// Exchange sends one DNS message and returns the response. tcp asks for the stream transport (the guest
	// itself used TCP, or retried after a truncated UDP answer).
	Exchange(ctx context.Context, query []byte, tcp bool) ([]byte, error)
}

// HostResolver forwards queries to the host's nameservers. With a path it re-reads that resolv.conf for every
// query, so a VPN or network change during a long session is followed; with fixed Servers it uses those.
type HostResolver struct {
	Servers []string // host:port, used when path is empty
	path    string
}

// NewHostResolver uses the nameservers in a resolv.conf (the host's /etc/resolv.conf in production). The file
// must name at least one nameserver now, or the session cannot resolve anything.
func NewHostResolver(path string) (*HostResolver, error) {
	servers, err := parseResolvConf(path)
	if err != nil {
		return nil, err
	}
	return &HostResolver{Servers: servers, path: path}, nil
}

func (h *HostResolver) servers() []string {
	if h.path != "" {
		if s, err := parseResolvConf(h.path); err == nil {
			return s
		}
	}
	return h.Servers // the last good list
}

func parseResolvConf(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	h := &HostResolver{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			addr := f[1]
			if i := strings.Index(addr, "%"); i >= 0 { // a zone id on a link-local server
				addr = addr[:i]
			}
			h.Servers = append(h.Servers, net.JoinHostPort(addr, "53"))
		}
	}
	if len(h.Servers) == 0 {
		return nil, fmt.Errorf("no nameserver in %s", path)
	}
	return h.Servers, nil
}

// Exchange asks each nameserver in turn until one answers.
func (h *HostResolver) Exchange(ctx context.Context, q []byte, tcp bool) ([]byte, error) {
	var last error
	for _, srv := range h.servers() {
		var resp []byte
		var err error
		if tcp {
			resp, err = exchangeTCP(ctx, srv, q)
		} else {
			resp, err = exchangeUDP(ctx, srv, q)
		}
		if err == nil {
			return resp, nil
		}
		last = err
	}
	return nil, last
}

func exchangeUDP(ctx context.Context, server string, q []byte) ([]byte, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(dnsExchangeTime))
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func exchangeTCP(ctx context.Context, server string, q []byte) ([]byte, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(dnsExchangeTime))
	if err := writeFramed(c, q); err != nil {
		return nil, err
	}
	return readFramed(bufio.NewReader(c))
}

func writeFramed(w io.Writer, m []byte) error {
	buf := make([]byte, 2+len(m))
	binary.BigEndian.PutUint16(buf, uint16(len(m)))
	copy(buf[2:], m)
	_, err := w.Write(buf)
	return err
}

func readFramed(r *bufio.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n < 12 || n > maxDNSMessage {
		return nil, errors.New("bad DNS message length")
	}
	m := make([]byte, n)
	_, err := io.ReadFull(r, m)
	return m, err
}

// validQuery accepts only a well-formed standard query: a header, not a response, opcode 0, at least one question.
func validQuery(m []byte) bool {
	if len(m) < 12 || len(m) > maxDNSMessage {
		return false
	}
	flags := binary.BigEndian.Uint16(m[2:4])
	qr := flags >> 15
	opcode := (flags >> 11) & 0xf
	return qr == 0 && opcode == 0 && binary.BigEndian.Uint16(m[4:6]) >= 1
}

// dnsUDP serves one guest flow: queries in, host-resolved answers out. Anything that is not a valid query is
// dropped; the number of queries in flight is bounded.
func (e *Engine) dnsUDP(c *gonet.UDPConn) {
	defer c.Close()
	var wg sync.WaitGroup
	defer wg.Wait()
	sem := make(chan struct{}, maxDNSInFlight)
	buf := make([]byte, maxDNSMessage+1)
	for {
		c.SetReadDeadline(time.Now().Add(dnsIdle))
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		if !validQuery(q) {
			e.cfg.Logf("dropped a malformed DNS query (%d bytes)", n)
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			continue // too many in flight: the guest will retry
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), dnsExchangeTime)
			defer cancel()
			resp, err := e.cfg.Upstream.Exchange(ctx, q, false)
			if err != nil {
				e.cfg.Logf("dns upstream: %v", err)
				return
			}
			c.Write(resp)
		}()
	}
}

// dnsTCP serves a guest's DNS-over-TCP connection to the gateway: length-prefixed messages, one at a time.
func (e *Engine) dnsTCP(c *gonet.TCPConn) {
	defer c.Close()
	r := bufio.NewReader(c)
	for {
		c.SetReadDeadline(time.Now().Add(dnsIdle))
		q, err := readFramed(r)
		if err != nil {
			return
		}
		if !validQuery(q) {
			e.cfg.Logf("dropped a malformed DNS query over tcp")
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), dnsExchangeTime)
		resp, err := e.cfg.Upstream.Exchange(ctx, q, true)
		cancel()
		if err != nil {
			e.cfg.Logf("dns upstream: %v", err)
			return
		}
		if writeFramed(c, resp) != nil {
			return
		}
	}
}
