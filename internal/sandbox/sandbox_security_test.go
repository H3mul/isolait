//go:build security

package sandbox

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/H3mul/isolait/internal/broker"
	"github.com/H3mul/isolait/internal/initshim"
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
	InitScripts []string // run the init shim as PID 1 and spawn each script in turn
	Tamper      string   // "extra-bind" or "no-ro": inject a bwrap misconfiguration the mount check must catch
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
		masked, err := mounts.MountWorkspace(j.Spec.Stage, w.Name, w.Src, w.RO, empty)
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
