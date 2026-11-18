package netd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParsePorts(t *testing.T) {
	for in, want := range map[string]string{
		"8080":      "8080",
		" 8080 ":    "8080",
		"8080/tcp":  "8080",
		"3000-3002": "3000 3001 3002",
		"65535":     "65535",
		"1":         "1",
		"7-7":       "7",
	} {
		got, err := ParsePorts(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		var s []string
		for _, p := range got {
			s = append(s, strconv.Itoa(int(p)))
		}
		if strings.Join(s, " ") != want {
			t.Errorf("%q = %v, want %s", in, s, want)
		}
	}
	for in, why := range map[string]string{
		"":            "empty",
		"0":           "port zero",
		"65536":       "out of range",
		"-5":          "negative",
		"abc":         "not a number",
		"80,81":       "lists are not supported",
		"+80":         "sign",
		"0x50":        "hex",
		"8080/udp":    "UDP",
		"udp:53":      "UDP",
		"8080/UDP":    "UDP, any case",
		"3010-3000":   "backwards",
		"1-65535":     "over the cap",
		"3000-3100":   "101 ports, over the cap",
		"3000-":       "open range",
		"80 -90":      "whitespace",
		"1e3":         "exponent",
		"99999999999": "overflow",
		"３０００":        "non-ASCII digits",
	} {
		if _, err := ParsePorts(in); err == nil {
			t.Errorf("%q accepted (%s)", in, why)
		}
	}
	if _, err := ParsePorts("3000-3099"); err != nil { // exactly the cap
		t.Errorf("a range of exactly %d ports must be accepted: %v", MaxGrantPorts, err)
	}
	if _, err := ParsePorts("8080/udp"); err == nil || !strings.Contains(err.Error(), "UDP") {
		t.Errorf("the UDP error must say so: %v", err)
	}
}

// a forwarder whose "sandbox" listener is a loopback listener on a free port, with the host side a fixture
func testForwarder(t *testing.T, hostServe func(net.Conn)) (*PortForwarder, func(port uint16) net.Conn) {
	t.Helper()
	f := NewPortForwarder("", nil)
	listeners := map[uint16]net.Listener{}
	f.listen = func(port uint16) (net.Listener, error) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		listeners[port] = l
		return l, err
	}
	host, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { host.Close(); f.Close() })
	go func() {
		for {
			c, err := host.Accept()
			if err != nil {
				return
			}
			go hostServe(c)
		}
	}()
	f.dial = func(ctx context.Context, port uint16) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", host.Addr().String())
	}
	return f, func(port uint16) net.Conn {
		t.Helper()
		c, err := net.Dial("tcp", listeners[port].Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
}

func echoConn(c net.Conn) { defer c.Close(); io.Copy(c, c) }

func TestForwardingAndClosing(t *testing.T) {
	f, connect := testForwarder(t, echoConn)
	if err := f.Allow(8080); err != nil {
		t.Fatal(err)
	}
	before := f.grants[8080]
	if err := f.Allow(8080); err != nil || f.grants[8080] != before { // idempotent: the same grant, no new listener
		t.Fatalf("second allow: %v", err)
	}
	if got := f.Open(); len(got) != 1 || got[0] != 8080 {
		t.Fatalf("open: %v", got)
	}
	c := connect(8080)
	c.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo: %q %v", buf, err)
	}
	if !f.Deny(8080) {
		t.Fatal("deny reported the port closed")
	}
	// the live connection is terminated
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(buf); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a connection survived the deny (read: %v)", err)
	}
	if f.Deny(8080) {
		t.Fatal("denying a closed port reported success")
	}
	if len(f.Open()) != 0 {
		t.Fatalf("open after deny: %v", f.Open())
	}
}

func TestPartialRangeClose(t *testing.T) {
	f, connect := testForwarder(t, echoConn)
	ports, _ := ParsePorts("3000-3004")
	for _, p := range ports {
		if err := f.Allow(p); err != nil {
			t.Fatal(err)
		}
	}
	keep := connect(3004)
	for _, p := range []uint16{3001, 3002} {
		if !f.Deny(p) {
			t.Fatalf("%d not open", p)
		}
	}
	got := f.Open()
	if len(got) != 3 || got[0] != 3000 || got[1] != 3003 || got[2] != 3004 {
		t.Fatalf("after closing part of the range: %v", got)
	}
	keep.Write([]byte("x"))
	b := make([]byte, 1)
	keep.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(keep, b); err != nil {
		t.Fatalf("a connection on a port that stayed open was dropped: %v", err)
	}
}

func TestHostRefusalClosesTheSandboxConnection(t *testing.T) {
	f, connect := testForwarder(t, echoConn)
	f.dial = func(context.Context, uint16) (net.Conn, error) { return nil, io.ErrClosedPipe }
	f.Allow(9000)
	c := connect(9000)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the connection stayed open though the host refused (read: %v)", err)
	}
}

func TestHalfCloseDeliversTheReply(t *testing.T) {
	f, connect := testForwarder(t, func(c net.Conn) { // read until EOF, then answer
		defer c.Close()
		b, _ := io.ReadAll(c)
		c.Write(append([]byte("got:"), b...))
	})
	f.Allow(8081)
	c := connect(8081).(*net.TCPConn)
	c.Write([]byte("req"))
	c.CloseWrite()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b, err := io.ReadAll(c)
	if err != nil || string(b) != "got:req" {
		t.Fatalf("%q %v", b, err)
	}
}

func TestControlProtocol(t *testing.T) {
	f, _ := testForwarder(t, echoConn)
	var out bytes.Buffer
	ServeControl(strings.NewReader("allow 8080\nallow 8080\nlist\ndeny 8080\ndeny 8080\nallow x\nallow 0\nfly\nlist\n"), &out, f)
	want := []string{"ok", "ok", "ok 8080", "ok", "err port 8080 is not open", `err bad port "x"`, `err bad port "0"`, `err unknown command "fly"`, "ok "}
	got := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("replies:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestClosingStopsEverything(t *testing.T) {
	f, _ := testForwarder(t, echoConn)
	f.Allow(1)
	f.Allow(2)
	f.Close()
	if len(f.Open()) != 0 {
		t.Fatalf("%v", f.Open())
	}
}
