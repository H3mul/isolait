//go:build security

package broker

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// Spike 1.1 assumption, now against the product recipe: the broker sees the host filesystem, is uid 0 with
// CAP_SYS_ADMIN inside its own user namespace only, can mount, owns the caller's files, and its mounts do not
// reach the host mount namespace.

const helperEnv = "ISOLAIT_BROKER_HELPER"

type report struct {
	UID, GID    int
	CapEff      uint64
	SawHostFile bool
	OwnsTempDir bool
	MountErr    string
	HostnameErr string
	MountDir    string
}

func TestMain(m *testing.M) {
	if dir := os.Getenv(helperEnv); dir != "" {
		helper(dir)
		return
	}
	os.Exit(m.Run())
}

// helper runs inside the broker namespaces and prints a report on stdout.
func helper(dir string) {
	r := report{UID: os.Getuid(), GID: os.Getgid(), MountDir: dir}
	for _, l := range strings.Split(readFile("/proc/self/status"), "\n") {
		if strings.HasPrefix(l, "CapEff:") {
			var v uint64
			for _, c := range strings.TrimSpace(strings.TrimPrefix(l, "CapEff:")) {
				v = v<<4 | uint64(strings.IndexRune("0123456789abcdef", c))
			}
			r.CapEff = v
		}
	}
	r.SawHostFile = readFile("/etc/hostname") != "" || readFile("/etc/passwd") != ""
	var st syscall.Stat_t
	r.OwnsTempDir = syscall.Stat(dir, &st) == nil && st.Uid == 0 // the caller's own dir appears as root's
	if err := syscall.Mount("tmpfs", dir, "tmpfs", 0, ""); err != nil {
		r.MountErr = err.Error()
	}
	// Setting the hostname to its current value is harmless even if it unexpectedly succeeds.
	host, _ := os.Hostname()
	if err := syscall.Sethostname([]byte(host)); err != nil { // host UTS namespace: needs init-ns CAP_SYS_ADMIN
		r.HostnameErr = err.Error()
	}
	json.NewEncoder(os.Stdout).Encode(r)
}

func readFile(p string) string { b, _ := os.ReadFile(p); return string(b) }

func TestBrokerNamespace(t *testing.T) {
	dir := t.TempDir()
	cmd := Command(os.Args[0])
	cmd.Env = append(os.Environ(), helperEnv+"="+dir)
	out, err := cmd.Output()
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") || strings.Contains(err.Error(), "permission denied") {
			t.Skipf("cannot create user namespaces here: %v", err)
		}
		t.Fatalf("broker failed: %v (%s)", err, out)
	}
	var r report
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("bad report %q: %v", out, err)
	}
	if r.UID != 0 || r.GID != 0 || !r.OwnsTempDir {
		t.Errorf("ids %d/%d ownsTempDir=%v: the caller must map to uid/gid 0", r.UID, r.GID, r.OwnsTempDir)
	}
	const sysAdmin = 1 << 21
	if r.CapEff&sysAdmin == 0 {
		t.Errorf("CapEff=%#x lacks CAP_SYS_ADMIN", r.CapEff)
	}
	if !r.SawHostFile {
		t.Error("broker cannot see the host filesystem")
	}
	if r.MountErr != "" {
		t.Errorf("broker cannot mount: %s", r.MountErr)
	}
	if r.HostnameErr == "" {
		t.Error("broker changed the host hostname: its capabilities are not confined to its own namespace")
	}
	if mi, _ := exec.Command("cat", "/proc/self/mountinfo").Output(); strings.Contains(string(mi), dir) {
		t.Error("broker mount leaked into the host mount namespace")
	}
}
