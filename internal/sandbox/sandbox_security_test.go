//go:build security

package sandbox

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/H3mul/isolait/internal/broker"
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
}

type result struct {
	Stdout string
	Stderr string
	Err    string
}

func TestMain(m *testing.M) {
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
	base := map[string]string{"HOME": j.Spec.HostHome, "PATH": "/usr/bin:/bin"}
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
	var out, errb bytes.Buffer
	sb, err := Start(j.Spec, p, []string{"/bin/sh", "-c", j.Script}, nil, &out, &errb)
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
	if r.Err != "" {
		t.Fatalf("sandbox failed: %s\nstderr: %s", r.Err, r.Stderr)
	}
	kv := map[string]string{}
	for _, l := range strings.Split(r.Stdout, "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			kv[k] = v
		}
	}
	// keep the agent home visible to the caller for persistence assertions
	kv["_agenthome"] = j.Spec.AgentHome
	return kv
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
