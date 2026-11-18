//go:build security

package daemon

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/H3mul/isolait/internal/attach"
	"github.com/H3mul/isolait/internal/session"
)

// Real-kernel lifecycle (task 3.8): the test binary stands in for `isolait` (see main_test.go).

type env struct {
	base, state, work string
}

func newEnv(t *testing.T) env {
	t.Helper()
	base, err := os.MkdirTemp("", "iso")
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(base, "state")
	work := filepath.Join(base, "proj")
	rt := filepath.Join(base, "rt")
	for _, d := range []string{work, filepath.Join(work, ".isolait")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(rt, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	return env{base: rt, state: state, work: work}
}

func (e env) spec(t *testing.T, agent string) Spec {
	t.Helper()
	id, err := session.Create(e.base, e.work)
	if err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	bwrap, _ := exec.LookPath("bwrap")
	return Spec{
		ID: id, RuntimeBase: e.base, StateDir: e.state, Workdir: e.work, Name: "proj",
		Agent: []string{agent}, HostEnv: []string{"AWS_SECRET_ACCESS_KEY=s3cret", "FOO=bar"}, EnvNames: []string{"FOO"},
		HostHome: "/home/fakeuser", HostPath: os.Getenv("PATH"), User: "fakeuser",
		UID: os.Getuid(), GID: os.Getgid(), InitExe: exe, InitArgs: []string{"__isolait_init__"}, Bwrap: bwrap,
	}
}

func daemonPID(t *testing.T, e env, id string) int {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(session.Dir(e.base, id), "pid"))
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

// anyProcessMentions reports whether any process's command line contains s (the sandbox's bwrap carries the
// session's stage path, so this finds leftovers of a session).
func anyProcessMentions(s string) bool {
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err == nil && strings.Contains(string(b), s) {
			return true
		}
	}
	return false
}

func hostMountsMention(s string) bool {
	b, _ := os.ReadFile("/proc/self/mountinfo")
	return strings.Contains(string(b), s)
}

func waitGone(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if !cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s is still there", what)
}

func TestSessionLifecycle(t *testing.T) {
	e := newEnv(t)
	spec := e.spec(t, "sh")
	if err := Launch(spec, os.Args[0]); err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("cannot create user namespaces here: %v", err)
		}
		t.Fatal(err)
	}
	pid := daemonPID(t, e, spec.ID)
	if !alive(pid) {
		t.Fatal("daemon is not running after Launch returned")
	}

	// status: idle, the starting workspace, only declared environment names, no secrets
	st, err := Query(e.base, spec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != "idle" || len(st.Mounts) != 1 || st.Mounts[0].Path != "/workspaces/proj" || st.Mounts[0].Mode != "rw" || st.Workdir != e.work {
		t.Errorf("status %+v", st)
	}
	names := strings.Join(st.EnvNames, ",")
	if !strings.Contains(names, "FOO") || !strings.Contains(names, "PATH") || strings.Contains(names, "AWS_SECRET_ACCESS_KEY") {
		t.Errorf("env names %v", st.EnvNames)
	}
	es, err := List(e.base)
	if err != nil || len(es) != 1 || es[0].ID != spec.ID || es[0].Status == nil {
		t.Fatalf("list: %+v %v", es, err)
	}

	// the sandbox is really there while the session is idle
	if !anyProcessMentions(spec.ID) {
		t.Error("no sandbox process found for a running session")
	}

	began := time.Now()
	if err := Stop(e.base, spec.ID); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(began); took > 5*time.Second {
		t.Errorf("stop took %v: the daemon did not clean up by itself and Stop had to kill it", took)
	}
	// cleanup of everything the session held
	if _, err := os.Stat(session.Dir(e.base, spec.ID)); !os.IsNotExist(err) {
		t.Error("runtime directory (socket, stage, state) still exists after stop")
	}
	waitGone(t, "the daemon process", func() bool { return alive(pid) })
	waitGone(t, "sandbox processes", func() bool { return anyProcessMentions(spec.ID) })
	if hostMountsMention(spec.ID) {
		t.Error("a mount of the session leaked into the host mount namespace")
	}
	if es, _ := List(e.base); len(es) != 0 {
		t.Errorf("stopped session still listed: %+v", es)
	}
	// persistent state stays: the per-agent home
	if _, err := os.Stat(filepath.Join(e.state, "homes", "sh")); err != nil {
		t.Errorf("per-agent home should persist after stop: %v", err)
	}
}

// If the daemon dies the sandbox dies with it (die-with-parent), and the leftover directory is cleaned up.
func TestDaemonKilledTakesTheSandboxWithIt(t *testing.T) {
	e := newEnv(t)
	spec := e.spec(t, "sh")
	if err := Launch(spec, os.Args[0]); err != nil {
		t.Skipf("cannot launch here: %v", err)
	}
	pid := daemonPID(t, e, spec.ID)
	syscall.Kill(pid, syscall.SIGKILL)
	waitGone(t, "sandbox processes after the daemon was killed", func() bool { return anyProcessMentions(spec.ID) })
	waitGone(t, "the leftover session directory (list should remove it)", func() bool {
		List(e.base)
		_, err := os.Stat(session.Dir(e.base, spec.ID))
		return err == nil
	})
}

func TestFailedStartLeavesNothingRunning(t *testing.T) {
	e := newEnv(t)
	spec := e.spec(t, "no-such-agent-xyz")
	err := Launch(spec, os.Args[0])
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("want an agent-not-found error, got %v", err)
	}
	session.Remove(e.base, spec.ID) // the launcher's caller removes the directory
	if anyProcessMentions(spec.ID) {
		t.Error("processes left after a failed start")
	}
	if hostMountsMention(spec.ID) {
		t.Error("mounts left after a failed start")
	}
}

func TestTwoSessionsAreIndependent(t *testing.T) {
	e := newEnv(t)
	a, b := e.spec(t, "sh"), e.spec(t, "sh")
	b.Workdir = e.base // any other existing directory
	b.Name = "other"
	for _, s := range []Spec{a, b} {
		if err := Launch(s, os.Args[0]); err != nil {
			t.Skipf("cannot launch here: %v", err)
		}
	}
	if es, _ := List(e.base); len(es) != 2 {
		t.Fatalf("list: %+v", es)
	}
	if err := Stop(e.base, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := Query(e.base, b.ID); err != nil {
		t.Errorf("stopping one session disturbed the other: %v", err)
	}
	if err := Stop(e.base, b.ID); err != nil {
		t.Fatal(err)
	}
}

func userManagerRunning(t *testing.T) string {
	t.Helper()
	sd, err := exec.LookPath("systemd-run")
	if err != nil {
		t.Skip("no systemd-run on this host")
	}
	out, _ := exec.Command("systemctl", "--user", "is-system-running").Output()
	if st := strings.TrimSpace(string(out)); st != "running" && st != "degraded" {
		t.Skipf("no systemd user manager (%q)", st)
	}
	return sd
}

// 3.13: the daemon, and so everything in the session, lives in a scope that carries the limits.
func TestLimitsAppliedThroughScope(t *testing.T) {
	sd := userManagerRunning(t)
	e := newEnv(t)
	spec := e.spec(t, "sh")
	spec.SystemdRun = sd
	spec.Limits = Limits{Pids: 200, Memory: "512M", CPU: "150%"}
	if err := Launch(spec, os.Args[0]); err != nil {
		t.Fatal(err)
	}
	st, err := Query(e.base, spec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Limits.Available || st.Limits.PidsMax != 200 || st.Limits.MemoryMax != 512<<20 || st.Limits.PidsCurrent < 1 {
		t.Errorf("limits not applied: %+v", st.Limits)
	}
	pid := daemonPID(t, e, spec.ID)
	cg, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	scope := "isolait-" + spec.ID + ".scope"
	if !strings.Contains(string(cg), scope) {
		t.Fatalf("the daemon is not in its session scope %s: %s", scope, cg)
	}
	dir := "/sys/fs/cgroup" + strings.TrimPrefix(strings.TrimSpace(string(cg)), "0::")
	if b, _ := os.ReadFile(dir + "/cpu.max"); !strings.HasPrefix(string(b), "150000 ") {
		t.Errorf("cpu quota not applied: %q", b)
	}
	if err := Stop(e.base, spec.ID); err != nil {
		t.Fatal(err)
	}
	waitGone(t, "the session scope", func() bool { _, err := os.Stat(dir); return err == nil })
}

// Without a systemd user manager, or when the scope cannot be created, the session still starts and says so.
func TestLimitsUnavailableIsVisibleAndNotFatal(t *testing.T) {
	for name, sd := range map[string]string{"no systemd-run": "", "scope fails": "/bin/false"} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			spec := e.spec(t, "sh")
			spec.SystemdRun = sd
			spec.Limits = Limits{Pids: 4096}
			if err := Launch(spec, os.Args[0]); err != nil {
				t.Fatalf("a session must start without limits unless they are required: %v", err)
			}
			defer Stop(e.base, spec.ID)
			st, err := Query(e.base, spec.ID)
			if err != nil {
				t.Fatal(err)
			}
			if st.Limits.Available || !strings.Contains(st.Limits.Reason, "unavailable") {
				t.Errorf("status must say limits are unavailable and why: %+v", st.Limits)
			}
		})
	}
}

// dialAttach connects to a real session's attach socket.
func dialAttach(t *testing.T, e env, id string, h attach.HelloMsg) (*attach.Conn, net.Conn, attach.Reply) {
	t.Helper()
	raw, err := net.Dial("unix", session.AttachPath(e.base, id))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	c := attach.NewConn(raw)
	if err := c.SendJSON(attach.Hello, h); err != nil {
		t.Fatal(err)
	}
	f, err := c.Recv()
	if err != nil {
		t.Fatal(err)
	}
	var r attach.Reply
	if err := json.Unmarshal(f.Payload, &r); err != nil {
		t.Fatal(err)
	}
	return c, raw, r
}

func readUntil(t *testing.T, c *attach.Conn, raw net.Conn, want string) string {
	t.Helper()
	raw.SetReadDeadline(time.Now().Add(15 * time.Second))
	var sb strings.Builder
	for !strings.Contains(sb.String(), want) {
		f, err := c.Recv()
		if err != nil {
			t.Fatalf("connection ended before %q appeared: %v (got %q)", want, err, sb.String())
		}
		if f.Type == attach.Data {
			sb.Write(f.Payload)
		}
		if f.Type == attach.Exit {
			break
		}
	}
	return sb.String()
}

// 4.1/4.5 on the real kernel: the agent and an exec'd shell run inside the sandbox on PTYs, see the same
// mounts, and nothing in the sandbox can find or reach the daemon's sockets.
func TestAttachAndExecInTheRealSandbox(t *testing.T) {
	e := newEnv(t)
	spec := e.spec(t, "sh")
	if err := Launch(spec, os.Args[0]); err != nil {
		t.Skipf("cannot launch here: %v", err)
	}
	defer Stop(e.base, spec.ID)

	c, raw, r := dialAttach(t, e, spec.ID, attach.HelloMsg{Mode: attach.ModeAgent, Term: "xterm", Cols: 100, Rows: 30})
	if !r.OK || !r.Restarted {
		t.Fatalf("attach: %+v", r)
	}
	c.Send(attach.Frame{Type: attach.Data, Payload: []byte("echo r\"\"esult cwd=$(pwd) home=$HOME user=$(id -u) tty=$(test -t 0 && echo yes) size=$(stty size) en\"\"d\n")})
	// the terminal echoes what is typed; r""esult only becomes "result" once the shell has run the command
	out := readUntil(t, c, raw, " end\r\n")
	for _, want := range []string{"cwd=/workspaces/proj", "home=/home/fakeuser", "user=" + strconv.Itoa(os.Getuid()), "tty=yes", "size=30 100"} {
		if !strings.Contains(out, want) {
			t.Errorf("agent shell: missing %q in %q", want, out)
		}
	}
	if st, _ := Query(e.base, spec.ID); st.State != "attached" {
		t.Errorf("state while attached: %s", st.State)
	}

	// a second shell in the same sandbox: same mounts, and the control surface is nowhere to be found. /usr is not
	// scanned (and the search is by type, not by name: runner images ship symlinks named *.sock): it is the host's read-only system tree (huge on CI runner images) and never holds a session socket.
	script := "echo ws=$(ls /workspaces); found=$(find /workspaces /tmp /home /etc /isolait /dev -type s 2>/dev/null); echo sockets=$(echo -n \"$found\" | grep -c .); echo \"$found\" | sed 's/^/socketpath=/'; " +
		"for p in " + session.SocketPath(e.base, spec.ID) + " " + session.AttachPath(e.base, spec.ID) + " " + e.base + "; do [ -e $p ] && echo reachable=$p; done; echo done-exec"
	ec, eraw, er := dialAttach(t, e, spec.ID, attach.HelloMsg{Mode: attach.ModeExec, Argv: []string{"sh", "-c", script}, Term: "xterm", Cols: 80, Rows: 24})
	if !er.OK {
		t.Fatalf("exec: %+v", er)
	}
	eo := readUntil(t, ec, eraw, "done-exec")
	if !strings.Contains(eo, "ws=proj") || !strings.Contains(eo, "sockets=0") || strings.Contains(eo, "reachable=") {
		t.Errorf("exec shell: %q (want the workspace, no sockets, no daemon paths)", eo)
	}

	// detach and reattach: the agent is still the same shell
	c.Send(attach.Frame{Type: attach.Data, Payload: []byte("export MARK=survived\n")})
	c.Send(attach.Frame{Type: attach.Detach})
	waitState(t, e, spec.ID, "detached")
	c2, raw2, r2 := dialAttach(t, e, spec.ID, attach.HelloMsg{Mode: attach.ModeAgent, Term: "xterm", Cols: 80, Rows: 24})
	if !r2.OK || r2.Restarted {
		t.Fatalf("reattach: %+v", r2)
	}
	c2.Send(attach.Frame{Type: attach.Data, Payload: []byte("echo mark=$MARK\n")})
	readUntil(t, c2, raw2, "mark=survived")
}

func waitState(t *testing.T, e env, id, want string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if st, err := Query(e.base, id); err == nil && st.State == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("session never reached state %q", want)
}
