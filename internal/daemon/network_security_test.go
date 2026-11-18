//go:build security

package daemon

import (
	"bufio"
	"encoding/binary"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/H3mul/isolait/internal/attach"
	"github.com/H3mul/isolait/internal/session"
)

// Real-kernel network tests: a session whose sandbox is wired to the engine, with local fixtures standing in for
// the internet. The sandbox dials 93.184.216.34 (a public-looking address); the engine, told through its
// test-only flags, connects that to a fixture on loopback.

const fixtureIP = "93.184.216.34"

type fixtures struct {
	echoPort, closedPort, dnsPort int
}

// startFixtures runs a line-echo TCP server, a port that refuses connections and a DNS server answering
// api.test with the fixture IP and internal.test with a private address.
func startFixtures(t *testing.T) fixtures {
	t.Helper()
	var f fixtures
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	f.echoPort = l.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				line, _ := r.ReadString('\n')
				c.Write([]byte("echo:" + line))
			}()
		}
	}()
	cl, _ := net.Listen("tcp4", "127.0.0.1:0")
	f.closedPort = cl.Addr().(*net.TCPAddr).Port
	cl.Close() // nothing listens there now

	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	f.dnsPort = pc.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			var labels []string
			i := 12
			for i < n && q[i] != 0 {
				labels = append(labels, string(q[i+1:i+1+int(q[i])]))
				i += int(q[i]) + 1
			}
			end := i + 5
			resp := append([]byte(nil), q[:end]...)
			binary.BigEndian.PutUint16(resp[2:], 0x8180)
			ans := map[string][]byte{"api.test": net.ParseIP(fixtureIP).To4(), "internal.test": {10, 1, 2, 3}}[strings.Join(labels, ".")]
			if ans == nil {
				binary.BigEndian.PutUint16(resp[2:], 0x8183)
			} else {
				binary.BigEndian.PutUint16(resp[6:], 1)
				resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
				resp = append(resp, ans...)
			}
			pc.WriteTo(resp, from)
		}
	}()
	return f
}

func (f fixtures) netTest() *NetTest {
	return &NetTest{
		Routes: []string{
			fixtureIP + ":80=127.0.0.1:" + strconv.Itoa(f.echoPort),
			fixtureIP + ":81=127.0.0.1:" + strconv.Itoa(f.closedPort),
		},
		DNSUpstream:    "127.0.0.1:" + strconv.Itoa(f.dnsPort),
		PermitLoopback: true,
	}
}

// netSession launches a session with the fixtures and returns an exec helper.
func netSession(t *testing.T) (env, Spec, func(script string) string) {
	t.Helper()
	e := newEnv(t)
	f := startFixtures(t)
	spec := e.spec(t, "sh")
	spec.NetTest = f.netTest()
	if err := Launch(spec, os.Args[0]); err != nil {
		if strings.Contains(err.Error(), "operation not permitted") || strings.Contains(err.Error(), "/dev/net/tun") {
			t.Skipf("cannot start the network here: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { Stop(e.base, spec.ID) })
	run := func(script string) string {
		t.Helper()
		c, raw, r := dialAttach(t, e, spec.ID, attach.HelloMsg{Mode: attach.ModeExec, Argv: []string{"bash", "-c", script + "; echo done-exec"}, Term: "xterm", Cols: 200, Rows: 50})
		if !r.OK {
			t.Fatalf("exec: %+v", r)
		}
		return readUntil(t, c, raw, "done-exec\r\n")
	}
	return e, spec, run
}

// line returns the value of a "key=value" line in the output.
func line(out, key string) string {
	for _, l := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), key+"="); ok {
			return v
		}
	}
	return ""
}

func TestSandboxNetworkEndToEnd(t *testing.T) {
	_, _, run := netSession(t)
	out := run(`
echo ifaces=$(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | sort | tr '\n' ,)
echo inet6=$(wc -l < /proc/net/if_inet6)
echo resolv=$(grep -c '^nameserver 10.0.2.2$' /etc/resolv.conf)
echo host=$(getent hosts api.test | awk '{print $1}')
echo internal=$(getent hosts internal.test | awk '{print $1}')
echo nxdomain=$(getent hosts nope.test >/dev/null 2>&1 && echo found || echo missing)
exec 3<>/dev/tcp/` + fixtureIP + `/80 && { echo ping >&3; read -t 5 reply <&3; echo tcp=$reply; } || echo tcp=failed
exec 3>&-
`)
	if got := line(out, "ifaces"); got != "lo,tap0," {
		t.Errorf("the sandbox sees interfaces %q, want only lo and the managed tap0", got)
	}
	if got := line(out, "inet6"); got != "0" {
		t.Errorf("IPv6 is not disabled: %s IPv6 address lines", got)
	}
	if line(out, "resolv") != "1" {
		t.Errorf("/etc/resolv.conf must point at the gateway only: %q", out)
	}
	if got := line(out, "host"); got != fixtureIP {
		t.Errorf("name lookup: %q, want the host resolver's answer %s", got, fixtureIP)
	}
	if got := line(out, "internal"); got != "10.1.2.3" {
		t.Errorf("a name resolving to a private address still resolves (the refusal comes at connect): %q", got)
	}
	if got := line(out, "nxdomain"); got != "missing" {
		t.Errorf("unknown name: %q", got)
	}
	if got := line(out, "tcp"); got != "echo:ping" {
		t.Errorf("TCP through the engine: %q", got)
	}
}

func TestSandboxCannotReachPrivateLocalOrMetadataAddresses(t *testing.T) {
	_, _, run := netSession(t)
	hostLAN := ""
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() {
			hostLAN = ipn.IP.String()
			break
		}
	}
	// a host loopback service the sandbox must not see
	hl, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hl.Close()
	hostPort := strconv.Itoa(hl.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := hl.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	script := `probe() { if timeout 5 bash -c "exec 3<>/dev/tcp/$2" 2>/dev/null; then echo $1=reached; else echo $1=blocked; fi; }
probe lan 192.168.1.1/80
probe tenet 10.0.0.1/80
probe metadata 169.254.169.254/80
probe cgnat 100.64.0.1/80
probe hostloop 127.0.0.1/` + hostPort + `
probe gateway 10.0.2.2/80
probe internalname 10.1.2.3/80
`
	if hostLAN != "" {
		script += "probe hostaddr " + hostLAN + "/" + hostPort + "\n"
	}
	out := run(script)
	for _, k := range []string{"lan", "tenet", "metadata", "cgnat", "hostloop", "gateway", "internalname"} {
		if got := line(out, k); got != "blocked" {
			t.Errorf("%s: %q, want blocked (output %q)", k, got, out)
		}
	}
	if hostLAN != "" {
		if got := line(out, "hostaddr"); got != "blocked" {
			t.Errorf("the host's own address %s:%s reachable from the sandbox: %q", hostLAN, hostPort, got)
		}
	}
}

func TestClosedUpstreamPortIsRefusedNotAccepted(t *testing.T) {
	_, _, run := netSession(t)
	out := run(`
start=$(date +%s%N)
bash -c 'exec 3<>/dev/tcp/` + fixtureIP + `/81' 2>/tmp/err && echo closed=connected || echo closed=failed
echo err=$(tr -d '\n' < /tmp/err)
echo ms=$(( ($(date +%s%N) - start) / 1000000 ))
`)
	if line(out, "closed") != "failed" {
		t.Errorf("the connect to a closed upstream port succeeded: connect-then-reset: %q", out)
	}
	if !strings.Contains(line(out, "err"), "refused") {
		t.Errorf("error %q, want connection refused", line(out, "err"))
	}
	if ms, _ := strconv.Atoi(line(out, "ms")); ms > 3000 {
		t.Errorf("the refusal took %d ms", ms)
	}
}

func TestSandboxCannotChangeItsNetwork(t *testing.T) {
	_, _, run := netSession(t)
	out := run(`python3 - <<'PY'
import socket, fcntl, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
def attempt(name, fn):
    try:
        fn()
        print(name + "=allowed")
    except PermissionError:
        print(name + "=denied")
    except OSError as e:
        print(name + "=error:" + str(e.errno))
attempt("link_down", lambda: fcntl.ioctl(s, 0x8914, struct.pack('16sH', b'tap0', 0)))  # SIOCSIFFLAGS: bring tap0 down
attempt("set_addr", lambda: fcntl.ioctl(s, 0x8916, struct.pack('16sHH4s', b'tap0', socket.AF_INET, 0, socket.inet_aton('10.9.9.9'))))  # SIOCSIFADDR
attempt("raw_socket", lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP))
attempt("packet_socket", lambda: socket.socket(socket.AF_PACKET, socket.SOCK_RAW))
PY
`)
	for _, k := range []string{"link_down", "set_addr", "raw_socket", "packet_socket"} {
		if got := line(out, k); got != "denied" {
			t.Errorf("%s: %q, want denied (the sandbox holds no network capability): %q", k, got, out)
		}
	}
}

func TestEngineProcessIsHardenedAndSurvivesSandboxSignals(t *testing.T) {
	e, spec, run := netSession(t)
	st, err := Query(e.base, spec.ID)
	if err != nil || st.NetPID == 0 || st.Network != "up" {
		t.Fatalf("status %+v %v", st, err)
	}
	// every thread of the engine holds exactly CAP_NET_ADMIN|CAP_SYS_ADMIN, no new privileges, a seccomp filter
	tasks, _ := os.ReadDir("/proc/" + strconv.Itoa(st.NetPID) + "/task")
	if len(tasks) == 0 {
		t.Fatal("no engine threads found")
	}
	for _, task := range tasks {
		b, err := os.ReadFile("/proc/" + strconv.Itoa(st.NetPID) + "/task/" + task.Name() + "/status")
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) < 2 {
				continue
			}
			switch f[0] {
			case "CapEff:", "CapPrm:", "CapBnd:":
				if f[1] != "0000000000201000" {
					t.Errorf("engine thread %s %s %s, want 0000000000201000 (CAP_NET_ADMIN|CAP_SYS_ADMIN)", task.Name(), f[0], f[1])
				}
			case "CapInh:", "CapAmb:":
				if f[1] != "0000000000000000" {
					t.Errorf("engine thread %s %s %s, want none", task.Name(), f[0], f[1])
				}
			case "NoNewPrivs:":
				if f[1] != "1" {
					t.Errorf("engine thread %s: no_new_privs %s", task.Name(), f[1])
				}
			case "Seccomp:":
				if f[1] != "2" {
					t.Errorf("engine thread %s: seccomp mode %s, want 2 (filter)", task.Name(), f[1])
				}
			}
		}
	}

	// sandboxed code cannot see the engine's pid, and killing everything it can see does not touch it
	out := run(`echo visible=$([ -d /proc/` + strconv.Itoa(st.NetPID) + ` ] && echo yes || echo no); kill -9 -1 2>/dev/null; echo killed=ok`)
	if line(out, "visible") != "no" {
		t.Errorf("the engine's pid is visible inside the sandbox: %q", out)
	}
	if syscall.Kill(st.NetPID, 0) != nil {
		t.Error("the engine died when the sandbox signalled every process it could see")
	}
	if st2, err := Query(e.base, spec.ID); err != nil || st2.Network != "up" {
		t.Errorf("after the sandbox's signal storm: %+v %v", st2, err)
	}
}

func TestEngineDeathIsReportedAndDoesNotEndTheSession(t *testing.T) {
	e, spec, _ := netSession(t)
	st, _ := Query(e.base, spec.ID)
	syscall.Kill(st.NetPID, syscall.SIGKILL)
	deadline := time.Now().Add(5 * time.Second)
	for {
		st2, err := Query(e.base, spec.ID)
		if err == nil && strings.HasPrefix(st2.Network, "down") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status never reported the dead engine: %+v %v", st2, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := Query(e.base, spec.ID); err != nil {
		t.Errorf("the session must keep running without its network: %v", err)
	}
}

func TestFailingEngineFailsTheStartAndLeavesNothing(t *testing.T) {
	e := newEnv(t)
	spec := e.spec(t, "sh")
	spec.NetTest = &NetTest{Routes: []string{"garbage"}} // the engine rejects this flag and exits
	err := Launch(spec, os.Args[0])
	if err == nil || !strings.Contains(err.Error(), "network engine") || !strings.Contains(err.Error(), "ip:port=host:port") {
		t.Fatalf("a failing engine must fail the start and say why: %v", err)
	}
	session.Remove(e.base, spec.ID)
	if anyProcessMentions(spec.ID) {
		t.Error("sandbox processes left after the engine failed to start")
	}
}
