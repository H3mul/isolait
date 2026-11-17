//go:build security

// Package canary holds host-assumption canaries: small tests of the kernel, bubblewrap and systemd behaviours
// the design depends on (the feasibility spikes, as Go tests). They use bwrap and the mount primitive directly
// and almost none of the product, so a kernel, bwrap or systemd upgrade that changes one fails loudly even
// when no isolait code changed. Run them alone with `go test -tags security -run Canary ./internal/canary`.
package canary

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/H3mul/isolait/internal/broker"
	"github.com/H3mul/isolait/internal/mounts"
)

const helperEnv = "ISOLAIT_CANARY_SCENARIO"

func TestMain(m *testing.M) {
	if sc := os.Getenv(helperEnv); sc != "" {
		out := map[string]string{}
		func() {
			defer func() {
				if r := recover(); r != nil {
					out["panic"] = fmt.Sprint(r)
				}
			}()
			scenarios[sc](out)
		}()
		json.NewEncoder(os.Stdout).Encode(out)
		return
	}
	os.Exit(m.Run())
}

var scenarios = map[string]func(map[string]string){
	"mounts": scenarioMounts,
	"userns": scenarioUserns,
	"netns":  scenarioNetns,
}

// inBroker runs a scenario inside the broker's namespaces (a user+mount namespace where we are uid 0).
func inBroker(t *testing.T, scenario string) map[string]string {
	t.Helper()
	cmd := broker.Command(os.Args[0])
	cmd.Env = append(os.Environ(), helperEnv+"="+scenario, "TMPDIR="+shortTmp(t))
	out, err := cmd.Output()
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("cannot create user namespaces here: %v", err)
		}
		t.Fatalf("broker: %v", err)
	}
	var res map[string]string
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("bad scenario output %q: %v", out, err)
	}
	if p := res["panic"]; p != "" {
		t.Fatalf("scenario panicked: %s", p)
	}
	if s := res["skip"]; s != "" {
		t.Skip(s)
	}
	return res
}

func shortTmp(t *testing.T) string {
	d, err := os.MkdirTemp("", "can")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func eq(t *testing.T, res map[string]string, key, want string) {
	t.Helper()
	if res[key] != want {
		t.Errorf("%s = %q, want %q", key, res[key], want)
	}
}

// ---- tools: bwrap features the product's argv relies on -------------------------------------------------

func TestCanaryBwrapFeatures(t *testing.T) {
	path, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("no bwrap")
	}
	ver, _ := exec.Command(path, "--version").Output()
	m := regexp.MustCompile(`(\d+)\.(\d+)`).FindStringSubmatch(string(ver))
	if m == nil {
		t.Fatalf("cannot parse bwrap version %q", ver)
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	if major == 0 && minor < 8 {
		t.Errorf("bwrap %s is older than 0.8 (no --disable-userns)", strings.TrimSpace(string(ver)))
	}
	help, _ := exec.Command(path, "--help").CombinedOutput()
	for _, flag := range []string{"--disable-userns", "--as-pid-1", "--info-fd", "--block-fd", "--unshare-cgroup-try", "--uid", "--gid", "--cap-drop", "--new-session", "--die-with-parent", "--clearenv", "--setenv", "--ro-bind", "--symlink", "--tmpfs", "--proc", "--dev", "--chdir"} {
		if !strings.Contains(string(help), flag) {
			t.Errorf("this bwrap no longer documents %s, which the sandbox argv uses", flag)
		}
	}
}

// ---- kernel: mount propagation, locked mounts, atomic read-only clones (spikes 1.1 to 1.4) --------------

func bwrapSandbox(stage, out, script string, extra ...string) *exec.Cmd {
	args := []string{"--unshare-user", "--unshare-pid", "--die-with-parent",
		"--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
		"--dev", "/dev", "--proc", "/proc", "--bind", stage, "/workspaces", "--bind", out, "/out",
		// keep capabilities so that denials come from the kernel (locked mounts, slave propagation) and not from bwrap
		"--cap-add", "ALL"}
	args = append(append(args, extra...), "sh", "-c", script)
	return exec.Command("bwrap", args...)
}

func waitFor(path string, d time.Duration) bool {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if _, err := os.Lstat(path); err == nil {
			return true
		}
	}
	return false
}

const mountsScript = `
until [ -e /out/go ]; do :; done
until [ -e /workspaces/ws/f ]; do :; done
echo visible=yes > /out/r1
mount -o remount,rw /workspaces/ro 2>/dev/null && echo remount_rw=allowed >> /out/r1 || echo remount_rw=denied >> /out/r1
mkdir -p /workspaces/z && mount -t tmpfs tmpfs /workspaces/z && touch /workspaces/z/leak
grep -c ' shared:' /proc/self/mountinfo | sed 's/^/shared_in_sandbox=/' >> /out/r1
touch /out/step1
until [ -e /workspaces/clone/f ]; do :; done
w=0; i=0; while [ $i -lt 300 ]; do touch /workspaces/clone/w$i 2>/dev/null && w=$((w+1)); i=$((i+1)); done
echo clone_write_windows=$w >> /out/r1
touch /out/step2
until [ ! -e /workspaces/ws/f ]; do :; done
echo unmount_propagated=yes >> /out/r1
touch /out/done
`

func scenarioMounts(out map[string]string) {
	root, err := os.MkdirTemp("", "m")
	must(err)
	stage, o := filepath.Join(root, "stage"), filepath.Join(root, "out")
	for _, d := range []string{stage, o, filepath.Join(root, "src/rw"), filepath.Join(root, "src/ro"), filepath.Join(root, "src/clone")} {
		must(os.MkdirAll(d, 0o755))
	}
	for _, d := range []string{"rw", "ro", "clone"} {
		must(os.WriteFile(filepath.Join(root, "src", d, "f"), []byte("x"), 0o644))
	}
	must(syscall.Mount("tmpfs", stage, "tmpfs", 0, ""))
	must(syscall.Mount("", stage, "", syscall.MS_SHARED, ""))

	sb := bwrapSandbox(stage, o, mountsScript)
	must(sb.Start())
	defer sb.Process.Kill()
	time.Sleep(300 * time.Millisecond) // let bwrap finish mounting before the broker mounts into the stage

	// a writable and a read-only workspace, made with the product primitive, before the sandbox looks
	for _, w := range []struct {
		name string
		ro   bool
	}{{"ws", false}, {"ro", true}} {
		must(os.Mkdir(filepath.Join(stage, w.name), 0o755))
		must(mounts.Attach(filepath.Join(root, "src", map[bool]string{false: "rw", true: "ro"}[w.ro]), filepath.Join(stage, w.name), w.ro))
	}
	must(os.WriteFile(filepath.Join(o, "go"), nil, 0o644))
	if !waitFor(filepath.Join(o, "step1"), 10*time.Second) {
		out["error"] = "sandbox did not reach step 1"
		return
	}
	_, leaked := os.Stat(filepath.Join(stage, "z", "leak"))
	out["sandbox_mount_leaked_to_broker"] = map[bool]string{true: "no", false: "yes"}[leaked != nil]

	// read-only clone: the sandbox hammers writes from the first instant the mount is visible
	must(os.Mkdir(filepath.Join(stage, "clone"), 0o755))
	must(mounts.Attach(filepath.Join(root, "src", "clone"), filepath.Join(stage, "clone"), true))
	if !waitFor(filepath.Join(o, "step2"), 20*time.Second) {
		out["error"] = "sandbox did not reach step 2"
		return
	}
	must(syscall.Unmount(filepath.Join(stage, "ws"), syscall.MNT_DETACH))
	if !waitFor(filepath.Join(o, "done"), 10*time.Second) {
		out["error"] = "sandbox did not finish"
		return
	}
	b, _ := os.ReadFile(filepath.Join(o, "r1"))
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			out[k] = v
		}
	}
}

func TestCanaryMountPropagation(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("no bwrap")
	}
	res := inBroker(t, "mounts")
	if e := res["error"]; e != "" {
		t.Fatal(e)
	}
	eq(t, res, "visible", "yes")                       // 1.1: a mount the broker makes under the stage appears in the sandbox
	eq(t, res, "sandbox_mount_leaked_to_broker", "no") // 1.3: /workspaces is a slave: sandbox mounts never propagate back
	eq(t, res, "shared_in_sandbox", "0")               // 1.3: and nothing in the sandbox is a shared mount
	eq(t, res, "unmount_propagated", "yes")            // 1.1: an unmount in the broker reaches the sandbox
}

func TestCanaryMountsAreLocked(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("no bwrap")
	}
	res := inBroker(t, "mounts")
	eq(t, res, "remount_rw", "denied") // 1.2: MNT_LOCKED: even with capabilities the sandbox cannot make a ro mount rw
}

func TestCanaryReadOnlyCloneIsNeverWritable(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("no bwrap")
	}
	res := inBroker(t, "mounts")
	eq(t, res, "clone_write_windows", "0") // 1.4: open_tree + mount_setattr + move_mount: no writable instant
}

// ---- kernel: nested user namespaces are blockable (spike 1.5) -------------------------------------------

func scenarioUserns(out map[string]string) {
	run := func(extra ...string) string {
		args := append([]string{"--unshare-user", "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev", "--cap-add", "ALL"}, extra...)
		args = append(args, "sh", "-c", "unshare -U true 2>/dev/null && echo allowed || echo denied")
		b, err := exec.Command("bwrap", args...).Output()
		if err != nil {
			return "bwrap failed: " + err.Error()
		}
		return strings.TrimSpace(string(b))
	}
	out["control"] = run()
	out["disabled"] = run("--disable-userns")
}

func TestCanaryNestedUsernsBlocked(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("no bwrap")
	}
	res := inBroker(t, "userns")
	eq(t, res, "control", "allowed") // proves the probe can see an unblocked nested userns
	eq(t, res, "disabled", "denied") // 1.5: --disable-userns holds under the broker's own nesting, even with caps
}

// ---- kernel: a tap device can be created in a private network namespace (spikes 1.6 and 1.7) ------------

const (
	tunsetiff = 0x400454ca
	iffTap    = 0x0002
	iffNoPI   = 0x1000
)

func scenarioNetns(out map[string]string) {
	runtime.LockOSThread() // the namespace belongs to this thread and the thread is never released
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		out["skip"] = "no /dev/net/tun on this host"
		return
	}
	must(syscall.Unshare(syscall.CLONE_NEWNET))
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		out["skip"] = "cannot open /dev/net/tun: " + err.Error()
		return
	}
	defer f.Close()
	var ifr [40]byte
	copy(ifr[:], "canary0")
	*(*uint16)(unsafe.Pointer(&ifr[16])) = iffTap | iffNoPI
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunsetiff, uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		out["tap"] = "failed: " + e.Error()
		return
	}
	out["tap"] = "created"
	// the interface exists only inside the private namespace
	b, _ := os.ReadFile("/proc/net/dev")
	out["tap_visible_here"] = map[bool]string{true: "yes", false: "no"}[strings.Contains(string(b), "canary0")]
}

func TestCanaryTapInPrivateNetns(t *testing.T) {
	res := inBroker(t, "netns")
	eq(t, res, "tap", "created")
	eq(t, res, "tap_visible_here", "yes")
}

// ---- systemd: user scopes carry limits and can be killed as a unit (spike S1) ---------------------------

func TestCanaryCgroupScope(t *testing.T) {
	sd, err := exec.LookPath("systemd-run")
	if err != nil {
		t.Skip("no systemd-run")
	}
	if out, _ := exec.Command("systemctl", "--user", "is-system-running").Output(); !strings.Contains("running degraded", strings.TrimSpace(string(out))) || strings.TrimSpace(string(out)) == "" {
		t.Skipf("no systemd user manager (%q)", strings.TrimSpace(string(out)))
	}
	unit := fmt.Sprintf("isolait-canary-%d", os.Getpid())
	t.Cleanup(func() { exec.Command("systemctl", "--user", "stop", unit+".scope").Run() })
	out, err := exec.Command(sd, "--user", "--scope", "--quiet", "--unit="+unit, "-p", "TasksMax=64", "-p", "MemoryMax=256M", "--",
		"sh", "-c", `setsid sleep 120 </dev/null >/dev/null 2>&1 & echo $!; sed -n 's/^0:://p' /proc/self/cgroup`).Output()
	if err != nil {
		t.Skipf("cannot create a user scope here: %v", err)
	}
	f := strings.Fields(string(out))
	if len(f) != 2 {
		t.Fatalf("unexpected output %q", out)
	}
	pid, _ := strconv.Atoi(f[0])
	dir := "/sys/fs/cgroup" + f[1]
	read := func(n string) string { b, _ := os.ReadFile(filepath.Join(dir, n)); return strings.TrimSpace(string(b)) }
	if read("pids.max") != "64" || read("memory.max") != strconv.Itoa(256<<20) {
		t.Errorf("limits not applied: pids.max=%q memory.max=%q", read("pids.max"), read("memory.max"))
	}
	if !strings.Contains(f[1], unit+".scope") {
		t.Errorf("the detached process is not in the scope: %s", f[1])
	}
	if syscall.Kill(pid, 0) != nil {
		t.Fatal("a process that forked away from its launcher must stay alive in the scope")
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.kill"), []byte("1"), 0o644); err != nil {
		t.Fatalf("cgroup.kill is not writable by the user: %v", err)
	}
	for i := 0; i < 100 && syscall.Kill(pid, 0) == nil; i++ {
		time.Sleep(50 * time.Millisecond)
	}
	if syscall.Kill(pid, 0) == nil {
		t.Error("cgroup.kill did not remove the process")
	}
}
