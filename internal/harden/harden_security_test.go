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

func helperCaps(out map[string]string) {
	dir, _ := os.MkdirTemp("", "h")
	defer os.RemoveAll(dir)
	mountTmpfs := func() string {
		err := syscall.Mount("tmpfs", dir, "tmpfs", 0, "")
		if err == nil {
			syscall.Unmount(dir, 0)
			return "ok"
		}
		return err.Error()
	}
	before := capLines()
	out["eff_before"] = strconv.FormatUint(before["CapEff"], 16)
	out["mount_before"] = mountTmpfs()

	// threads that already exist when the capabilities are dropped: eight goroutines, each locked to its own OS
	// thread and parked, so at least seven of them are not the thread that calls KeepOnlyCaps
	const parked = 8
	release := make(chan struct{})
	results := make(chan uint64, parked)
	for i := 0; i < parked; i++ {
		go func() {
			runtime.LockOSThread()
			<-release
			results <- capLines()["CapEff"]
		}()
	}
	time.Sleep(100 * time.Millisecond) // let them all park

	if err := KeepOnlyCaps(CapNetAdmin, CapSysAdmin); err != nil {
		out["error"] = err.Error()
		return
	}
	want := uint64(1)<<CapNetAdmin | uint64(1)<<CapSysAdmin
	for _, k := range []string{"CapEff", "CapPrm", "CapBnd"} {
		out[k] = strconv.FormatUint(capLines()[k], 16)
	}
	out["want"] = strconv.FormatUint(want, 16)
	out["CapInh"] = strconv.FormatUint(capLines()["CapInh"], 16)
	out["CapAmb"] = strconv.FormatUint(capLines()["CapAmb"], 16)
	out["mount_with_sysadmin"] = mountTmpfs() // the capability is kept, so the call itself would work

	// every thread: the parked ones must have lost the capabilities too
	close(release)
	kept := 0
	for i := 0; i < parked; i++ {
		if eff := <-results; eff != want {
			kept++
		}
	}
	out["threads_with_other_caps"] = strconv.Itoa(kept)

	if err := DenyDangerousCalls(); err != nil {
		out["error"] = err.Error()
		return
	}
	out["mount_after_filter"] = mountTmpfs()
}

func TestKeepOnlyCapsAndNoMountAuthority(t *testing.T) {
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
		t.Errorf("%s of 8 existing threads kept different capabilities: they must drop on every thread", r["threads_with_other_caps"])
	}
	if r["mount_with_sysadmin"] != "ok" {
		t.Errorf("control: CAP_SYS_ADMIN is kept, so without the filter mount still works: %s", r["mount_with_sysadmin"])
	}
	if r["mount_after_filter"] != syscall.EPERM.Error() {
		t.Errorf("after the filter the process can still mount: %s (this is what seccomp is for: SYS_ADMIN is needed for setns)", r["mount_after_filter"])
	}
}
