//go:build security

package daemon

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// Port grants against the real kernel (tasks 7.2 to 7.4): a listener on the sandbox's loopback forwarded to the
// host's 127.0.0.1, reachable only after allow.

// hostServer accepts connections on addr, greets each with "host-secret" and holds it open until the peer leaves.
func hostServer(t *testing.T, addr string) int {
	t.Helper()
	l, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.Write([]byte("host-secret\n"))
				buf := make([]byte, 64)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// probe connects from inside the sandbox and prints what the host service greeted with.
func probe(port int) string {
	return fmt.Sprintf(`if exec 3<>/dev/tcp/127.0.0.1/%d 2>/dev/null; then read -t 3 -r l <&3; echo "got=$l"; else echo "got=REFUSED"; fi`, port)
}

func TestPortGrantReachableOnlyAfterAllowAndRefusedAfterDeny(t *testing.T) {
	e, spec, run := hotSession(t, nil)
	port := hostServer(t, "127.0.0.1:0")
	if got := line(run(probe(port)), "got"); got != "REFUSED" {
		t.Fatalf("before the grant: %q", got)
	}
	r, err := AllowPorts(e.base, spec.ID, fmt.Sprint(port))
	if err != nil || len(r.Changed) != 1 || len(r.Open) != 1 {
		t.Fatalf("allow: %+v %v", r, err)
	}
	if got := line(run(probe(port)), "got"); got != "host-secret" {
		t.Fatalf("after the grant: %q", got)
	}
	if st, _ := Query(e.base, spec.ID); len(st.Ports) != 1 || st.Ports[0] != port {
		t.Fatalf("status ports: %v", st.Ports)
	}
	if _, err := DenyPorts(e.base, spec.ID, fmt.Sprint(port)); err != nil {
		t.Fatal(err)
	}
	if got := line(run(probe(port)), "got"); got != "REFUSED" {
		t.Fatalf("after deny: %q", got)
	}
	if st, _ := Query(e.base, spec.ID); len(st.Ports) != 0 {
		t.Fatalf("status ports after deny: %v", st.Ports)
	}
	if _, err := DenyPorts(e.base, spec.ID, fmt.Sprint(port)); err == nil || !strings.Contains(err.Error(), "no open grant") {
		t.Fatalf("deny of a closed port: %v", err)
	}
}

func TestPortGrantEndsLiveConnectionsOnDeny(t *testing.T) {
	e, spec, run := hotSession(t, nil)
	port := hostServer(t, "127.0.0.1:0")
	if _, err := AllowPorts(e.base, spec.ID, fmt.Sprint(port)); err != nil {
		t.Fatal(err)
	}
	// a long-lived connection from the sandbox that records when it ends
	run(fmt.Sprintf(`(setsid bash -c 'exec 3<>/dev/tcp/127.0.0.1/%d; echo up > /tmp/st; cat <&3 >/dev/null; echo closed >> /tmp/st' >/dev/null 2>&1 &); sleep 0.5; cat /tmp/st`, port))
	if _, err := DenyPorts(e.base, spec.ID, fmt.Sprint(port)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if out := run(`cat /tmp/st`); strings.Contains(out, "closed") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the connection survived the deny")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestPortRangeGrantAndPartialClose(t *testing.T) {
	e, spec, _ := hotSession(t, nil)
	// three ports that are free on the host, found now (nothing listens: only the sandbox side is checked)
	var base int
	for p := 41000; p < 60000; p += 7 {
		ok := true
		for i := 0; i < 3; i++ {
			if l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", p+i)); err != nil {
				ok = false
			} else {
				l.Close()
			}
		}
		if ok {
			base = p
			break
		}
	}
	rng := fmt.Sprintf("%d-%d", base, base+2)
	r, err := AllowPorts(e.base, spec.ID, rng)
	if err != nil || len(r.Open) != 3 {
		t.Fatalf("allow %s: %+v %v", rng, r, err)
	}
	r, err = DenyPorts(e.base, spec.ID, fmt.Sprintf("%d-%d", base+1, base+5)) // a range that is partly not open
	if err != nil || len(r.Changed) != 2 || len(r.Open) != 1 || r.Open[0] != base {
		t.Fatalf("partial close: %+v %v", r, err)
	}
	for _, bad := range []string{"0", "70000", "80/udp", "1-65535", "abc"} {
		if _, err := AllowPorts(e.base, spec.ID, bad); err == nil {
			t.Errorf("allow %q was accepted", bad)
		}
	}
}

// The grant forwards to the host's 127.0.0.1 only: a service bound to another host address is not reachable
// through it, nor directly.
func TestPortGrantDoesNotReachNonLoopbackHostServices(t *testing.T) {
	var lan string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ip, ok := a.(*net.IPNet); ok && ip.IP.To4() != nil && !ip.IP.IsLoopback() {
			lan = ip.IP.String()
			break
		}
	}
	if lan == "" {
		t.Skip("the host has no non-loopback IPv4 address")
	}
	e, spec, run := hotSession(t, nil)
	port := hostServer(t, lan+":0")
	if _, err := AllowPorts(e.base, spec.ID, fmt.Sprint(port)); err != nil {
		t.Fatal(err)
	}
	if got := line(run(probe(port)), "got"); got == "host-secret" {
		t.Fatal("the grant reached a service bound to a non-loopback host address")
	}
	out := run(fmt.Sprintf(`if exec 4<>/dev/tcp/%s/%d 2>/dev/null; then read -t 3 -r l <&4; echo "direct=$l"; else echo direct=REFUSED; fi`, lan, port))
	if line(out, "direct") == "host-secret" {
		t.Fatal("the sandbox reached a host address directly")
	}
}

func TestStoppingTheSessionClosesGrants(t *testing.T) {
	e, spec, _ := hotSession(t, nil)
	port := hostServer(t, "127.0.0.1:0")
	if _, err := AllowPorts(e.base, spec.ID, fmt.Sprint(port)); err != nil {
		t.Fatal(err)
	}
	if err := Stop(e.base, spec.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := AllowPorts(e.base, spec.ID, "9999"); err == nil {
		t.Fatal("a stopped session accepted a grant")
	}
}
