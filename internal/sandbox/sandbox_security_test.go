//go:build security

package sandbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/H3mul/isolait/internal/broker"
	"github.com/H3mul/isolait/internal/initshim"
	"github.com/H3mul/isolait/internal/mountcheck"
	"github.com/H3mul/isolait/internal/mounts"
	"github.com/H3mul/isolait/internal/plan"
)

// Real-kernel tests for the baseline (spikes 1.3 and 1.5, now against the product code). Each test re-executes
// this test binary inside the broker namespaces, where it builds the plan and starts bwrap exactly as the
// daemon will, then reports what the sandbox printed.

const helperEnv = "ISOLAIT_SANDBOX_HELPER"

type job struct {
	Spec        Spec
	Script      string
	HostEnv     []string
	EnvNames    []string
	InheritEnv  bool
	AllowUserns bool
	Workspace   *workspace
	Bin         *BinOptions
	SeedHome    bool     // seed the agent home from the embedded skeleton, as the daemon does
	SysDirs     []string // extra directories treated as system directories (a wrapper that lives in one)
	InitScripts []string // run the init shim as PID 1 and spawn each script in turn
	Tamper      string   // "extra-bind" or "no-ro": inject a bwrap misconfiguration the mount check must catch
	ScopePids   int      // run the whole session in a systemd user scope with this TasksMax
	// Saturating marks a script that exhausts the session cap on purpose: the shim may be starved of threads
	// and never report the exit, so the output (closed when the script ends) is the result.
	Saturating bool
}

type workspace struct {
	Src, Name string
	RO        bool
}

type spawnResult struct {
	Out  string
	Code int
	Sig  int
}

type result struct {
	Stdout   string
	Stderr   string
	Err      string
	HelloPID int
	Spawns   []spawnResult

	AgentHome string // set by the test runner, not the helper
}

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "__scoped__" { // runs inside the systemd scope, outside any namespace
		c := broker.Command(os.Args[0])
		c.Env, c.Stdout, c.Stderr = os.Environ(), os.Stdout, os.Stderr
		if err := c.Run(); err != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "__isolait_init__" { // this binary, bound at /isolait/init, as the shim
		if err := initshim.Run(os.NewFile(initshim.ControlFD, "control")); err != nil {
			os.Stderr.WriteString("init: " + err.Error() + "\n")
			os.Exit(1)
		}
		return
	}
	if os.Getenv(helperEnv) != "" {
		helper()
		return
	}
	os.Exit(m.Run())
}

// helper runs inside the broker: stage tmpfs, plan, bwrap, wait.
func helper() {
	var j job
	if err := json.Unmarshal([]byte(os.Getenv(helperEnv)), &j); err != nil {
		panic(err)
	}
	var res result
	defer func() { json.NewEncoder(os.Stdout).Encode(res) }()
	fail := func(err error) { res.Err = err.Error() }

	if err := syscall.Mount("tmpfs", j.Spec.Stage, "tmpfs", 0, ""); err != nil {
		fail(err)
		return
	}
	syscall.Mount("", j.Spec.Stage, "", syscall.MS_SHARED, "")
	j.Spec.AllowUserns = j.AllowUserns
	if len(j.InitScripts) > 0 {
		exe, _ := os.Executable()
		j.Spec.InitExe, _ = filepath.EvalSymlinks(exe)
	}
	SystemDirs = append(append([]string{}, j.SysDirs...), SystemDirs...)
	if j.SeedHome {
		if err := SeedHome(j.Spec.AgentHome, "/nonexistent-skel"); err != nil {
			fail(err)
			return
		}
	}
	base := map[string]string{"HOME": j.Spec.HostHome, "PATH": "/usr/bin:/bin"}
	var bins Binaries
	if j.Bin != nil {
		var err error
		if bins, err = ResolveBinaries(*j.Bin); err != nil {
			fail(err)
			return
		}
		base["PATH"] = bins.Path()
	}
	env, err := BuildEnv(j.HostEnv, j.EnvNames, j.InheritEnv, base)
	if err != nil {
		fail(err)
		return
	}
	j.Spec.Env = env
	p, err := BuildPlan(j.Spec)
	if err != nil {
		fail(err)
		return
	}
	if j.Bin != nil {
		if err := AddBinaries(p, bins); err != nil {
			fail(err)
			return
		}
	}
	if w := j.Workspace; w != nil {
		empty := filepath.Join(filepath.Dir(j.Spec.Stage), "empty")
		os.MkdirAll(empty, 0o755)
		masked, err := mounts.MountWorkspace(j.Spec.Stage, w.Name, w.Src, w.RO, empty, nil)
		if err != nil {
			fail(err)
			return
		}
		dst, err := AddWorkspace(p, w.Name, w.Src, w.RO, masked, empty)
		if err != nil {
			fail(err)
			return
		}
		j.Spec.Chdir = dst
	}
	if j.Tamper != "" {
		renderArgs = tamper(j.Tamper, filepath.Dir(j.Spec.Stage))
	}
	if len(j.InitScripts) > 0 {
		runInit(&j, p, &res)
		return
	}
	var out, errb bytes.Buffer
	sb, err := Start(j.Spec, p, []string{"/bin/sh", "-c", j.Script}, nil, nil, &out, &errb)
	if err != nil {
		fail(err)
		res.Stderr = errb.String()
		return
	}
	if err := sb.Wait(); err != nil {
		res.Err = "exit: " + err.Error()
	}
	res.Stdout, res.Stderr = out.String(), errb.String()
}

func runJob(t *testing.T, j job) map[string]string {
	t.Helper()
	r := runRaw(t, j)
	kv := map[string]string{}
	for _, l := range strings.Split(r.Stdout, "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			kv[k] = v
		}
	}
	kv["_agenthome"] = r.AgentHome
	return kv
}

func runRaw(t *testing.T, j job) result {
	t.Helper()
	r := runRawAllowErr(t, j)
	if r.Err != "" {
		t.Fatalf("sandbox failed: %s\nstderr: %s", r.Err, r.Stderr)
	}
	return r
}

func runRawAllowErr(t *testing.T, j job) result {
	t.Helper()
	root := t.TempDir()
	j.Spec.Stage = filepath.Join(root, "stage")
	j.Spec.AgentHome = filepath.Join(root, "agenthome")
	for _, d := range []string{j.Spec.Stage, j.Spec.AgentHome} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	j.Spec.UID, j.Spec.GID = os.Getuid(), os.Getgid()
	if j.Spec.HostHome == "" {
		j.Spec.HostHome = "/home/fakeuser"
	}
	b, _ := json.Marshal(j)
	cmd := broker.Command(os.Args[0])
	if j.ScopePids > 0 {
		sd, err := exec.LookPath("systemd-run")
		if err != nil {
			t.Skip("no systemd-run on this host")
		}
		cmd = exec.Command(sd, "--user", "--scope", "--quiet", "--collect", "-p", "TasksMax="+strconv.Itoa(j.ScopePids), "--", os.Args[0], "__scoped__")
	}
	cmd.Env = append(os.Environ(), helperEnv+"="+string(b))
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("cannot create user namespaces here: %v", err)
		}
		t.Fatalf("broker: %v", err)
	}
	var r result
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("bad helper output %q: %v", out.String(), err)
	}
	if strings.Contains(r.Err, "operation not permitted") || strings.Contains(r.Stderr, "No permissions to create new namespace") {
		t.Skipf("bwrap cannot create namespaces here: %s %s", r.Err, r.Stderr)
	}
	r.AgentHome = j.Spec.AgentHome // for persistence assertions
	return r
}

const probe = `
echo pid=$$
echo uid=$(id -u)
echo gid=$(id -g)
echo capeff=$(grep CapEff /proc/self/status | cut -f2)
echo hostsecret=$([ -e /home/hostsecret/.ssh/id ] && echo visible || echo absent)
echo realhome=$([ -e "$REALHOME" ] && echo visible || echo absent)
echo mount=$(mount -t tmpfs tmpfs /tmp 2>/dev/null && echo allowed || echo denied)
echo userns=$(unshare -U true 2>/dev/null && echo allowed || echo denied)
echo tmpwrite=$(echo x > /tmp/f && echo ok || echo failed)
echo awssecret=${AWS_SECRET_ACCESS_KEY:-absent}
echo foo=${FOO:-absent}
echo sshsock=${SSH_AUTH_SOCK:-absent}
echo home=$HOME
echo nics=$(tail -n +3 /proc/net/dev | grep -vc '^ *lo:')
echo wsentries=$(ls -A /workspaces | wc -l)
echo persist=$(echo kept > $HOME/persist.txt && echo ok)
echo tmppersisted=$([ -e /tmp/leftover ] && echo yes || echo no)
touch /tmp/leftover
`

func baseJob() job {
	realHome, _ := os.UserHomeDir()
	return job{
		Script:  "export REALHOME=" + realHome + "\n" + probe,
		HostEnv: []string{"AWS_SECRET_ACCESS_KEY=s3cret", "FOO=bar", "SSH_AUTH_SOCK=/run/user/1/agent"},
	}
}

func TestBaselineIsolation(t *testing.T) {
	kv := runJob(t, baseJob())
	want := map[string]string{
		"pid":        "1", // private pid namespace
		"uid":        "",  // checked below against the host uid
		"capeff":     "0000000000000000",
		"hostsecret": "absent",
		"realhome":   "absent", // the host home is not mounted anywhere
		"mount":      "denied",
		"userns":     "denied", // spike 1.5 under the broker's nesting
		"tmpwrite":   "ok",
		"awssecret":  "absent", // env allowlist: nothing implicit
		"foo":        "absent",
		"sshsock":    "absent",
		"home":       "/home/fakeuser",
		"nics":       "0", // only loopback: no network device in the sandbox
		"wsentries":  "0",
		"persist":    "ok",
	}
	for k, w := range want {
		if k == "uid" {
			continue
		}
		if kv[k] != w {
			t.Errorf("%s = %q, want %q", k, kv[k], w)
		}
	}
	if kv["uid"] != strconv.Itoa(os.Getuid()) || kv["gid"] != strconv.Itoa(os.Getgid()) {
		t.Errorf("sandbox ids %s/%s, want the host user's %d/%d", kv["uid"], kv["gid"], os.Getuid(), os.Getgid())
	}
	// the persistent agent home is the host dir; /tmp is not
	if b, err := os.ReadFile(filepath.Join(kv["_agenthome"], "persist.txt")); err != nil || string(b) != "kept\n" {
		t.Errorf("agent home did not persist: %v %q", err, b)
	}
}

func TestNestedUsernsOptIn(t *testing.T) {
	j := baseJob()
	j.AllowUserns = true
	kv := runJob(t, j)
	if kv["userns"] != "allowed" {
		t.Errorf("--allow-userns control: userns = %q, want allowed (otherwise the denial above proves nothing)", kv["userns"])
	}
}

func TestEnvAllowlistInSandbox(t *testing.T) {
	j := baseJob()
	j.EnvNames = []string{"FOO"}
	kv := runJob(t, j)
	if kv["foo"] != "bar" || kv["awssecret"] != "absent" || kv["sshsock"] != "absent" {
		t.Errorf("declared FOO only: foo=%q aws=%q ssh=%q", kv["foo"], kv["awssecret"], kv["sshsock"])
	}
	j = baseJob()
	j.InheritEnv = true
	kv = runJob(t, j)
	if kv["awssecret"] != "s3cret" || kv["sshsock"] != "absent" {
		t.Errorf("--inherit-env: aws=%q (want inherited) ssh=%q (want still absent)", kv["awssecret"], kv["sshsock"])
	}
	j = baseJob()
	j.InheritEnv, j.EnvNames = true, []string{"SSH_AUTH_SOCK"}
	if kv = runJob(t, j); kv["sshsock"] != "/run/user/1/agent" {
		t.Errorf("explicitly declared SSH_AUTH_SOCK must pass, got %q", kv["sshsock"])
	}
}

func TestTmpDoesNotPersistAcrossSessions(t *testing.T) {
	// two independent sandboxes: the file one writes to /tmp is never seen by the next
	kv := runJob(t, baseJob())
	if kv["tmppersisted"] != "no" {
		t.Fatalf("first run saw leftovers: %q", kv["tmppersisted"])
	}
	kv = runJob(t, baseJob())
	if kv["tmppersisted"] != "no" {
		t.Errorf("/tmp persisted across sessions: %q", kv["tmppersisted"])
	}
}

// 3.7 and 3.10 end to end: the starting directory appears at /workspaces/<name> (rw or ro), is the working
// directory, and its .isolait is masked while the host copy stays untouched.
func TestStartingWorkspace(t *testing.T) {
	src := filepath.Join(t.TempDir(), "myproj")
	must(t, os.MkdirAll(filepath.Join(src, ".isolait"), 0o755))
	must(t, os.WriteFile(filepath.Join(src, "f"), []byte("data"), 0o644))
	must(t, os.WriteFile(filepath.Join(src, ".isolait", "config"), []byte("secret"), 0o644))
	script := `
echo cwd=$(pwd)
echo read=$(cat f)
echo write=$(echo y > created 2>/dev/null && echo ok || echo failed)
echo maskentries=$(ls -A .isolait | wc -l)
echo maskwrite=$(echo x > .isolait/x 2>/dev/null && echo ok || echo failed)
echo ls=$(ls -A /workspaces)
`
	rw := baseJob()
	rw.Script, rw.Workspace = script, &workspace{Src: src, Name: "myproj"}
	kv := runJob(t, rw)
	for k, w := range map[string]string{"cwd": "/workspaces/myproj", "read": "data", "write": "ok", "maskentries": "0", "maskwrite": "failed", "ls": "myproj"} {
		if kv[k] != w {
			t.Errorf("rw: %s = %q, want %q", k, kv[k], w)
		}
	}
	if b, err := os.ReadFile(filepath.Join(src, "created")); err != nil || string(b) != "y\n" {
		t.Errorf("rw write did not reach the host: %v %q", err, b)
	}
	if b, _ := os.ReadFile(filepath.Join(src, ".isolait", "config")); string(b) != "secret" {
		t.Error("host .isolait/config was modified")
	}
	if _, err := os.Stat(filepath.Join(src, ".isolait", "x")); err == nil {
		t.Error("the agent wrote into the host .isolait")
	}

	os.Remove(filepath.Join(src, "created"))
	ro := rw
	ro.Workspace = &workspace{Src: src, Name: "myproj", RO: true}
	kv = runJob(t, ro)
	if kv["write"] != "failed" || kv["read"] != "data" || kv["cwd"] != "/workspaces/myproj" {
		t.Errorf("ro: %v", kv)
	}
	if _, err := os.Stat(filepath.Join(src, "created")); err == nil {
		t.Error("a --ro workspace accepted a write")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// 3.5 end to end: an agent behind a symlink runs by name from its resolved install root; host PATH
// directories that were not requested are invisible; --inherit-path exposes only the filtered ones.
func TestBinaryExposure(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	real := filepath.Join(root, "home/.local/share/agent/versions/1")
	must(t, os.MkdirAll(filepath.Dir(real), 0o755))
	must(t, os.WriteFile(real, []byte("#!/bin/sh\necho agent-ran $0\n"), 0o755))
	launcher := filepath.Join(root, "home/.local/bin")
	must(t, os.MkdirAll(launcher, 0o755))
	must(t, os.Symlink(real, filepath.Join(launcher, "agent")))
	other := filepath.Join(root, "home/otherbin")
	must(t, os.MkdirAll(other, 0o755))
	must(t, os.WriteFile(filepath.Join(other, "othertool"), []byte("#!/bin/sh\necho other-ran\n"), 0o755))
	hostPath := launcher + ":" + other + ":/usr/bin"

	script := `
echo agent=$(agent 2>&1)
echo agentpath=$(command -v agent)
echo launcher=$([ -e ` + launcher + ` ] && echo visible || echo absent)
echo other=$(othertool 2>&1 | head -c 40)
echo otherdir=$([ -e ` + other + ` ] && echo visible || echo absent)
`
	j := baseJob()
	j.Script = script
	j.Bin = &BinOptions{Agent: "agent", HostPath: hostPath, Home: filepath.Join(root, "home"), InheritPrefixes: []string{filepath.Join(root, "home")}}
	kv := runJob(t, j)
	if !strings.HasPrefix(kv["agent"], "agent-ran") || kv["agentpath"] != "/isolait/bin/agent" {
		t.Errorf("agent behind a symlink does not run by name: agent=%q path=%q", kv["agent"], kv["agentpath"])
	}
	if kv["launcher"] != "absent" {
		t.Error("the host launcher bin directory is visible")
	}
	if kv["otherdir"] != "absent" || strings.Contains(kv["other"], "other-ran") {
		t.Errorf("an unrequested host PATH directory is visible: dir=%q run=%q", kv["otherdir"], kv["other"])
	}

	j.Bin.InheritPath = true
	kv = runJob(t, j)
	if !strings.Contains(kv["other"], "other-ran") {
		t.Errorf("--inherit-path did not expose the allowed directory: %q", kv["other"])
	}
}

// 1.3: a wrapper in a system-looking (already mounted) directory that execs a binary in a non-system directory
// runs by name, and the binary's directory is the only extra exposure.
func TestLauncherInSystemDirRunsInSandbox(t *testing.T) {
	// not under /tmp: the sandbox mounts its own tmpfs there, which would shadow these binds
	root, err := os.MkdirTemp("/var/tmp", "isolait-launcher-")
	if err != nil {
		t.Skipf("no /var/tmp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	root, _ = filepath.EvalSymlinks(root)
	sys := filepath.Join(root, "sys")
	bin := filepath.Join(root, "opt/tool/bin/real")
	must(t, os.MkdirAll(filepath.Dir(bin), 0o755))
	must(t, os.WriteFile(bin, []byte("#!/bin/sh\necho real-ran $*\n"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "opt/tool/bin/sibling"), []byte("#!/bin/sh\n"), 0o755))
	must(t, os.MkdirAll(filepath.Join(sys, "bin"), 0o755))
	must(t, os.WriteFile(filepath.Join(sys, "bin/wrapped"), []byte("#!/bin/sh\nexec "+bin+" \"$@\"\n"), 0o755))

	j := baseJob()
	j.Script = `
echo run=$(` + filepath.Join(sys, "bin/wrapped") + ` a b 2>&1)
echo sibling=$([ -e ` + filepath.Join(root, "opt/tool/bin/sibling") + ` ] && echo visible || echo absent)
`
	j.SysDirs = []string{sys}
	j.Bin = &BinOptions{Agent: "wrapped", HostPath: filepath.Join(sys, "bin") + ":/usr/bin", Home: root}
	kv := runJob(t, j)
	if kv["run"] != "real-ran a b" {
		t.Errorf("the launcher's target does not run in the sandbox: %q", kv["run"])
	}
	if kv["sibling"] != "absent" { // generic bin directory: only the file itself is bound
		t.Error("the launcher target's whole bin directory is exposed")
	}
}

// 2.2: a fresh agent home gives bash a prompt and history settings from the seeded skeleton.
func TestSeededHomeGivesBashAPrompt(t *testing.T) {
	j := baseJob()
	j.SeedHome = true
	j.Script = `
echo rc=$([ -f "$HOME/.bashrc" ] && echo present || echo absent)
echo hc=$(bash -ic 'echo $HISTCONTROL' 2>/dev/null)
echo ps1=$(bash -ic 'echo "$PS1"' 2>/dev/null | head -c 20)
`
	kv := runJob(t, j)
	if kv["rc"] != "present" || kv["hc"] != "ignoreboth" || kv["ps1"] == "" {
		t.Errorf("seeded home: %v", kv)
	}
}

// runInit starts the sandbox with the init shim as PID 1 and runs each script through it, one after the other.
func runInit(j *job, p *plan.Plan, res *result) {
	j.Spec.InitArgs = []string{"__isolait_init__"}
	sb, cl, err := Launch(j.Spec, p, os.Stderr)
	if err != nil {
		res.Err = err.Error()
		return
	}
	res.HelloPID = sb.ShimPID
	env := []string{"PATH=/usr/bin:/bin", "HOME=" + j.Spec.HostHome}
	for _, script := range j.InitScripts {
		in, _ := os.Open(os.DevNull)
		r, w, _ := os.Pipe()
		id, _, err := cl.Spawn([]string{"/bin/sh", "-c", script}, env, j.Spec.Chdir, false, [3]*os.File{in, w, w})
		in.Close()
		w.Close()
		if err != nil {
			res.Err = err.Error()
			return
		}
		if j.Saturating {
			b, _ := io.ReadAll(r) // returns when the script (the only holder of the pipe) is done
			r.Close()
			res.Spawns = append(res.Spawns, spawnResult{Out: string(b)})
			continue
		}
		var e initshim.Event
		select {
		case e = <-cl.Exits():
		case <-time.After(10 * time.Second):
			res.Err = "timed out waiting for the process to be reported as exited"
			return
		}
		if e.ID != id {
			res.Err = "exit for the wrong process"
			return
		}
		b, _ := io.ReadAll(r)
		r.Close()
		res.Spawns = append(res.Spawns, spawnResult{Out: string(b), Code: e.Code, Sig: e.Signal})
	}
	cl.Shutdown()
	sb.Wait()
}

// 3.6: the init shim is PID 1; the agent can exit and be started again in the same sandbox with mounts and
// /tmp intact; orphans are reaped.
func TestInitShimLifecycle(t *testing.T) {
	src := filepath.Join(t.TempDir(), "proj")
	must(t, os.MkdirAll(src, 0o755))
	must(t, os.WriteFile(filepath.Join(src, "f"), []byte("data"), 0o644))

	j := baseJob()
	j.Workspace = &workspace{Src: src, Name: "proj"}
	j.InitScripts = []string{
		`echo first > /tmp/marker; echo pid=$$; exit 3`,
		`echo marker=$(cat /tmp/marker); echo ws=$(ls /workspaces); echo f=$(cat /workspaces/proj/f); (sleep 0.3 &); exit 0`,
		`sleep 0.8; z=0; for p in /proc/[0-9]*; do grep -q '^State:.*Z' $p/status 2>/dev/null && z=$((z+1)); done; echo zombies=$z; echo pid1=$(cat /proc/1/comm)`,
	}
	r := runRaw(t, j)
	if r.HelloPID != 1 {
		t.Errorf("the shim is PID %d inside the sandbox, want 1", r.HelloPID)
	}
	if len(r.Spawns) != 3 {
		t.Fatalf("spawns: %+v", r.Spawns)
	}
	if r.Spawns[0].Code != 3 {
		t.Errorf("first process exit %+v, want code 3 reported", r.Spawns[0])
	}
	second := r.Spawns[1].Out
	for _, want := range []string{"marker=first", "ws=proj", "f=data"} {
		if !strings.Contains(second, want) {
			t.Errorf("after the first process exited the sandbox lost state: want %q in %q", want, second)
		}
	}
	if !strings.Contains(r.Spawns[2].Out, "zombies=0") {
		t.Errorf("orphans were not reaped: %q", r.Spawns[2].Out)
	}
}

// tamper returns an argument renderer that applies a deliberate misconfiguration after the plan was rendered,
// so the plan (the oracle) and the real mounts disagree.
func tamper(kind, dir string) func(Spec, *plan.Plan, ...string) []string {
	return func(s Spec, p *plan.Plan, extra ...string) []string {
		a := Args(s, p, extra...)
		switch kind {
		case "extra-bind":
			os.MkdirAll(filepath.Join(dir, "extra"), 0o755)
			return append(a, "--bind", filepath.Join(dir, "extra"), "/extra")
		case "no-ro":
			for i := range a {
				if a[i] == "--ro-bind" && i+2 < len(a) && a[i+2] == "/etc/passwd" {
					a[i] = "--bind" // /etc/passwd is root-owned: the sandbox user still cannot write it
				}
			}
		}
		return a
	}
}

// 3.12: Launch compares the live mount table with the plan before anything runs. A healthy start passes
// (every init-shim test above goes through it); injected misconfigurations abort the start with a diff.
func TestStartVerificationAbortsOnMisconfiguration(t *testing.T) {
	src := filepath.Join(t.TempDir(), "proj")
	must(t, os.MkdirAll(filepath.Join(src, ".isolait"), 0o755))
	for _, tc := range []struct{ tamper, want string }{
		{"extra-bind", "unplanned mount /extra"},
		{"no-ro", "/etc/passwd (ro-bind) should be ro"},
	} {
		t.Run(tc.tamper, func(t *testing.T) {
			j := baseJob()
			j.Workspace = &workspace{Src: src, Name: "proj"}
			j.InitScripts = []string{"echo should-never-run"}
			j.Tamper = tc.tamper
			r := runRawAllowErr(t, j)
			if !strings.Contains(r.Err, "do not match the plan") || !strings.Contains(r.Err, tc.want) {
				t.Fatalf("start was not aborted with the expected diff; err=%q spawns=%+v", r.Err, r.Spawns)
			}
			if len(r.Spawns) != 0 {
				t.Errorf("a process ran in a sandbox that failed verification: %+v", r.Spawns)
			}
		})
	}
}

// A healthy start with every kind of bind (agent install root, tools root, inherited PATH dir, workspace
// with mask) verifies against its plan.
func TestLaunchVerifiesAllBindKinds(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	home := filepath.Join(root, "home")
	real := filepath.Join(home, ".local/share/agent/versions/1")
	must(t, os.MkdirAll(filepath.Dir(real), 0o755))
	must(t, os.WriteFile(real, []byte("#!/bin/sh\n"), 0o755))
	must(t, os.MkdirAll(filepath.Join(home, ".local/bin"), 0o755))
	must(t, os.Symlink(real, filepath.Join(home, ".local/bin/agent")))
	tools := filepath.Join(root, "toolchain")
	must(t, os.MkdirAll(filepath.Join(tools, "bin"), 0o755))
	extra := filepath.Join(home, "extrabin")
	must(t, os.MkdirAll(extra, 0o755))
	src := filepath.Join(root, "proj")
	must(t, os.MkdirAll(filepath.Join(src, ".isolait"), 0o755))

	j := baseJob()
	j.Workspace = &workspace{Src: src, Name: "proj", RO: true}
	j.Bin = &BinOptions{Agent: "agent", HostPath: filepath.Join(home, ".local/bin") + ":" + extra + ":/usr/bin", Home: home,
		Tools: []string{tools}, InheritPath: true, InheritPrefixes: []string{home}}
	j.InitScripts = []string{"echo ok"}
	r := runRaw(t, j) // fails on any verification mismatch
	if len(r.Spawns) != 1 || !strings.Contains(r.Spawns[0].Out, "ok") {
		t.Errorf("%+v", r.Spawns)
	}
}

// S1 in the product: the session's limits bound a fork bomb inside the sandbox. The control run without a
// scope proves the bomb is real (every fork succeeds), so the cap is what stops it.
func TestForkBombIsBoundedByTheSessionScope(t *testing.T) {
	const cap = 150
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is needed for the fork loop (bash's fork retry/backoff makes a shell loop slow and flaky)")
	}
	bomb := "python3 -c '" + `
import subprocess, os
kids = []
for _ in range(400):
    try:
        kids.append(subprocess.Popen(["sleep", "4"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    except OSError:
        pass
print("forked=%d" % len(kids))
print("count=%d" % len([p for p in os.listdir("/proc") if p.isdigit()]))` + "'"
	count := func(out string) int {
		i := strings.Index(out, "count=")
		if i < 0 {
			t.Fatalf("no process count in the output:\n%s", out)
		}
		n, _ := strconv.Atoi(strings.TrimSpace(strings.SplitN(out[i+len("count="):], "\n", 2)[0]))
		return n
	}

	j := baseJob()
	j.InitScripts = []string{bomb}
	j.Saturating = true
	control := runRaw(t, j)
	if n := count(control.Spawns[0].Out); n < 400 {
		t.Fatalf("control run: only %d processes, the fork bomb must be able to start 400", n)
	}

	j.ScopePids = cap
	capped := runRaw(t, j)
	out := capped.Spawns[0].Out
	if n := count(out); n < 10 || n > cap {
		t.Errorf("with TasksMax=%d the sandbox held %d processes, want between 10 and %d", cap, n, cap)
	}
	if !strings.Contains(out, "fork") && !strings.Contains(out, "Resource temporarily unavailable") {
		t.Errorf("the shell never reported a refused fork:\n%s", out)
	}
}

// Raw system calls from inside a session (python3 ctypes, as the audit did): the deny list answers EPERM, the
// io_uring family answers ENOSYS, and an ordinary ptrace of a child still works.
func TestSeccompDenyListInTheSession(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("no python3 on this host")
	}
	nums := map[string][]int{ // keyctl add_key request_key syslog perf_event_open process_vm_readv io_uring_setup
		"amd64": {250, 248, 249, 103, 298, 310, 425},
		"arm64": {219, 217, 218, 116, 241, 270, 425},
	}[runtime.GOARCH]
	if nums == nil {
		t.Skip("no syscall numbers for " + runtime.GOARCH)
	}
	names := []string{"keyctl", "add_key", "request_key", "syslog", "perf_event_open", "process_vm_readv", "io_uring_setup"}
	var b strings.Builder
	b.WriteString("python3 - <<'PY'\nimport ctypes, os\nlibc = ctypes.CDLL(None, use_errno=True)\n")
	for i, n := range names {
		fmt.Fprintf(&b, "libc.syscall(%d, 0, 0, 0, 0, 0, 0); print('%s=%%d' %% ctypes.get_errno())\n", nums[i], n)
	}
	b.WriteString(`pid = os.fork()
if pid == 0:
    os._exit(0 if libc.ptrace(0, 0, 0, 0) == 0 else 1)
print('ptrace_child=%d' % os.waitpid(pid, 0)[1])
PY
`)
	kv := runJob(t, job{Script: b.String()})
	for _, n := range names {
		want := strconv.Itoa(int(syscall.EPERM))
		if n == "io_uring_setup" {
			want = strconv.Itoa(int(syscall.ENOSYS))
		}
		if kv[n] != want {
			t.Errorf("%s: errno %q, want %s", n, kv[n], want)
		}
	}
	if kv["ptrace_child"] != "0" {
		t.Errorf("ptrace of a child: wait status %q, want 0 (ptrace must keep working)", kv["ptrace_child"])
	}
}

// F1 of the 2026-11-18 audit: the sandbox shared the host user's kernel keyrings. Canary keys are created on the
// host; from inside, /proc/keys must show none of them (masked) and keyctl must be refused (seccomp), and the
// host keys must be unchanged afterwards. Each mechanism is also checked alone by its own assertion.
func TestKeyringsAreNotSharedWithTheHost(t *testing.T) {
	keyringUser := -4 // KEY_SPEC_USER_KEYRING
	add := func(desc, payload string) int {
		d, _ := syscall.BytePtrFromString(desc)
		ty, _ := syscall.BytePtrFromString("user")
		pl := []byte(payload)
		id, _, e := syscall.Syscall6(unix.SYS_ADD_KEY, uintptr(unsafe.Pointer(ty)), uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(&pl[0])), uintptr(len(pl)), uintptr(keyringUser), 0)
		if e != 0 {
			t.Skipf("the host denies add_key: %v", e)
		}
		t.Cleanup(func() {
			syscall.Syscall6(unix.SYS_KEYCTL, 3, id, 0, 0, 0, 0)                    // KEYCTL_REVOKE
			syscall.Syscall6(unix.SYS_KEYCTL, 9, id, uintptr(keyringUser), 0, 0, 0) // KEYCTL_UNLINK
		})
		return int(id)
	}
	ids := []int{add("isolait-canary-default", "host-secret-1"), add("isolait-canary-open", "host-secret-2")}

	nr := map[string]int{"amd64": 250, "arm64": 219}[runtime.GOARCH] // keyctl
	if nr == 0 {
		t.Skip("no syscall numbers for " + runtime.GOARCH)
	}
	script := fmt.Sprintf(`echo listing=$(cat /proc/keys | wc -c)
python3 - <<'PY'
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
buf = ctypes.create_string_buffer(64)
for i in (%d, %d):
    r = libc.syscall(%d, 11, i, buf, 64)   # KEYCTL_READ
    print('read%%d=%%d' %% (i, ctypes.get_errno()))
libc.syscall(%d, 3, %d)                    # KEYCTL_REVOKE
print('revoke=%%d' %% ctypes.get_errno())
PY
`, ids[0], ids[1], nr, nr, ids[0])
	kv := runJob(t, job{Script: script})
	if kv["listing"] != "0" {
		t.Errorf("/proc/keys is not masked: it lists %q bytes", kv["listing"])
	}
	for _, id := range ids {
		if kv["read"+strconv.Itoa(id)] != strconv.Itoa(int(syscall.EPERM)) {
			t.Errorf("keyctl read of host key %d: errno %q, want EPERM", id, kv["read"+strconv.Itoa(id)])
		}
	}
	if kv["revoke"] != strconv.Itoa(int(syscall.EPERM)) {
		t.Errorf("keyctl revoke of a host key: errno %q, want EPERM", kv["revoke"])
	}
	// the host keys survived
	for i, want := range []string{"host-secret-1", "host-secret-2"} {
		buf := make([]byte, 64)
		n, _, e := syscall.Syscall6(unix.SYS_KEYCTL, 11, uintptr(ids[i]), uintptr(unsafe.Pointer(&buf[0])), 64, 0, 0)
		if e != 0 || string(buf[:n]) != want {
			t.Errorf("host canary %d changed: %v %q", ids[i], e, buf[:n])
		}
	}
}

// Compatibility under the filter (audit-findings-hardening 1.5): ordinary developer tools still work. Tools that
// are not installed are reported and skipped, never counted as passing.
func TestDeveloperToolsRunUnderTheFilter(t *testing.T) {
	smoke := []struct{ tool, cmd string }{
		{"git", "cd /tmp && git init -q x && git -C x status -s"},
		{"node", "node -e 'console.log(1+1)'"},
		{"python3", "python3 -c 'print(2)'"},
		{"go", "GOFLAGS=-mod=mod HOME=/tmp go env GOROOT"},
		{"strace", "strace -f true"},
	}
	var script strings.Builder
	var present []string
	for _, s := range smoke {
		if _, err := exec.LookPath(s.tool); err != nil {
			t.Logf("skipped %s: not installed on this host", s.tool)
			continue
		}
		present = append(present, s.tool)
		fmt.Fprintf(&script, "(%s) >/dev/null 2>&1; echo %s=$?\n", s.cmd, s.tool)
	}
	if len(present) == 0 {
		t.Skip("none of the tools is installed")
	}
	kv := runJob(t, job{Script: script.String(), SysDirs: nil})
	for _, tool := range present {
		if kv[tool] != "0" {
			t.Errorf("%s exited %q under the filter (127 = not visible in the sandbox, anything else = denied call?)", tool, kv[tool])
		}
	}
}

// Kernel information (task 3.1): the host kernel log and kernel addresses must not be readable from inside.
func TestKernelLogAndAddressesAreNotReadable(t *testing.T) {
	kv := runJob(t, job{Script: `echo dmesg=$(dmesg 2>&1 | wc -l)
echo kmsg=$([ -e /dev/kmsg ] && echo present || echo absent)
echo kallsyms=$(awk '$1 != "0000000000000000"' /proc/kallsyms 2>/dev/null | wc -l)
`})
	if kv["kmsg"] != "absent" {
		t.Errorf("/dev/kmsg is visible in the sandbox")
	}
	if kv["kallsyms"] != "0" {
		t.Errorf("/proc/kallsyms shows %s real kernel addresses", kv["kallsyms"])
	}
	if kv["dmesg"] != "1" { // the one line is the error message
		t.Errorf("dmesg printed %s lines, want only its refusal", kv["dmesg"])
	}
}

// Foreign host mounts below the system directories (on WSL2 the Windows driver store) are hidden by an empty
// read-only directory, and Launch's mount check accepts that.
func TestForeignSubmountsAreMasked(t *testing.T) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		t.Skip(err)
	}
	table, _ := mountcheck.Parse(f)
	f.Close()
	foreign := ForeignSubmounts(table, SystemDirs)
	if len(foreign) == 0 {
		t.Skip("this host has no foreign mounts below its system directories")
	}
	var s strings.Builder
	for i, pt := range foreign {
		fmt.Fprintf(&s, "echo n%d=$(ls -A %s | wc -l)\necho w%d=$(touch %s/x 2>/dev/null && echo writable || echo readonly)\n", i, pt, i, pt)
	}
	kv := runJob(t, job{Script: s.String()})
	for i, pt := range foreign {
		if kv[fmt.Sprintf("n%d", i)] != "0" || kv[fmt.Sprintf("w%d", i)] != "readonly" {
			t.Errorf("%s: %s entries, %s; want an empty read-only directory", pt, kv[fmt.Sprintf("n%d", i)], kv[fmt.Sprintf("w%d", i)])
		}
	}
}
