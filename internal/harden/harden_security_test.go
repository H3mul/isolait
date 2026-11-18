//go:build security

package harden

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func init() { helpers["caps"] = helperCaps }

func brokerAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
}

func capLines() map[string]uint64 {
	b, _ := os.ReadFile("/proc/thread-self/status")
	out := map[string]uint64{}
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.HasPrefix(k, "Cap") {
			n, _ := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			out[k] = n
		}
	}
	return out
}

func mountTmpfs(dir string) string {
	err := syscall.Mount("tmpfs", dir, "tmpfs", 0, "")
	if err == nil {
		syscall.Unmount(dir, 0)
		return "ok"
	}
	return err.Error()
}

// helperCaps is stage 1 (full capabilities in the broker namespace): note whether mount works as a control, then
// re-exec with only CAP_NET_ADMIN and CAP_SYS_ADMIN.
func helperCaps(out map[string]string) {
	dir, _ := os.MkdirTemp("", "h")
	defer os.RemoveAll(dir)
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, helperEnv+"=") { // replace the scenario, never add a second value (the first would win)
			env = append(env, kv)
		}
	}
	env = append(env, helperEnv+"=caps2", "ISOLAIT_HARDEN_MOUNT_BEFORE="+mountTmpfs(dir), "ISOLAIT_HARDEN_DIR="+dir)
	if err := ExecWithCaps([]int{CapNetAdmin, CapSysAdmin}, os.Args[0], []string{os.Args[0]}, env); err != nil {
		out["error"] = err.Error()
	}
}

// helperCaps2 is stage 2, the re-executed process: inspect its capabilities on every thread, then the filter.
func helperCaps2(out map[string]string) {
	dir := os.Getenv("ISOLAIT_HARDEN_DIR")
	out["mount_before"] = os.Getenv("ISOLAIT_HARDEN_MOUNT_BEFORE")
	want := uint64(1)<<CapNetAdmin | uint64(1)<<CapSysAdmin
	out["want"] = strconv.FormatUint(want, 16)

	const parked = 8 // goroutines locked to their own OS threads: all of them must show the reduced sets
	release := make(chan struct{})
	results := make(chan map[string]uint64, parked)
	for i := 0; i < parked; i++ {
		go func() {
			runtime.LockOSThread()
			<-release
			results <- capLines()
		}()
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	wrong := 0
	for i := 0; i < parked; i++ {
		c := <-results
		if c["CapEff"] != want || c["CapPrm"] != want || c["CapBnd"] != want || c["CapInh"] != 0 || c["CapAmb"] != 0 {
			wrong++
			out["example_wrong_thread"] = strconv.FormatUint(c["CapEff"], 16) + "/" + strconv.FormatUint(c["CapPrm"], 16) + "/" + strconv.FormatUint(c["CapBnd"], 16)
		}
	}
	out["threads_with_other_caps"] = strconv.Itoa(wrong)
	main := capLines()
	for _, k := range []string{"CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb"} {
		out[k] = strconv.FormatUint(main[k], 16)
	}
	out["mount_with_sysadmin"] = mountTmpfs(dir) // the capability is kept: without the filter mount still works
	if err := DenyDangerousCalls(); err != nil {
		out["error"] = err.Error()
		return
	}
	out["mount_after_filter"] = mountTmpfs(dir)
}

func init() { helpers["caps2"] = helperCaps2 }

func TestExecWithCapsAndNoMountAuthority(t *testing.T) {
	r := runHelper(t, "caps", true)
	if r["error"] != "" {
		t.Fatal(r["error"])
	}
	if r["mount_before"] != "ok" {
		t.Skipf("control: the broker cannot mount here (%s), so a denial would prove nothing", r["mount_before"])
	}
	for _, k := range []string{"CapEff", "CapPrm", "CapBnd"} {
		if r[k] != r["want"] {
			t.Errorf("%s = %s, want exactly CAP_NET_ADMIN|CAP_SYS_ADMIN (%s)", k, r[k], r["want"])
		}
	}
	if r["CapInh"] != "0" || r["CapAmb"] != "0" {
		t.Errorf("inheritable %s ambient %s, want none", r["CapInh"], r["CapAmb"])
	}
	if r["threads_with_other_caps"] != "0" {
		t.Errorf("%s of 8 threads have other capabilities (e.g. %s): the reduction must cover every thread", r["threads_with_other_caps"], r["example_wrong_thread"])
	}
	if r["mount_with_sysadmin"] != "ok" {
		t.Errorf("control: CAP_SYS_ADMIN is kept, so without the filter mount still works: %s", r["mount_with_sysadmin"])
	}
	if r["mount_after_filter"] != syscall.EPERM.Error() {
		t.Errorf("after the filter the process can still mount: %s (this is what seccomp is for: SYS_ADMIN is needed for setns)", r["mount_after_filter"])
	}
}
