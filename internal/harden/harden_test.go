package harden

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"unsafe"
)

// Applying seccomp is irreversible, so each scenario runs in a re-executed copy of the test binary.
const helperEnv = "ISOLAIT_HARDEN_HELPER"

func TestMain(m *testing.M) {
	if sc := os.Getenv(helperEnv); sc != "" {
		out := map[string]string{}
		func() {
			defer func() {
				if r := recover(); r != nil {
					out["panic"] = toString(r)
				}
			}()
			helpers[sc](out)
		}()
		json.NewEncoder(os.Stdout).Encode(out)
		return
	}
	os.Exit(m.Run())
}

func toString(v any) string {
	if e, ok := v.(error); ok {
		return e.Error()
	}
	if s, ok := v.(string); ok {
		return s
	}
	return "panic"
}

var helpers = map[string]func(map[string]string){"filter": helperFilter} // the security tier adds "caps"

func errno(e syscall.Errno) string {
	if e == 0 {
		return "ok"
	}
	return e.Error()
}

// processVMReadSelf reads one byte of our own memory with process_vm_readv: allowed for a process on itself
// unless something denies the call.
func processVMReadSelf() syscall.Errno {
	var dst, src byte = 0, 42
	local := syscall.Iovec{Base: &dst, Len: 1}
	remote := syscall.Iovec{Base: &src, Len: 1}
	nr := uintptr(310) // process_vm_readv on amd64
	if runtime.GOARCH == "arm64" {
		nr = 270
	}
	_, _, e := syscall.Syscall6(nr, uintptr(os.Getpid()), uintptr(unsafe.Pointer(&local)), 1, uintptr(unsafe.Pointer(&remote)), 1, 0)
	return e
}

func helperFilter(out map[string]string) {
	out["before"] = errno(processVMReadSelf())
	if err := DenyDangerousCalls(); err != nil {
		out["install"] = err.Error()
		return
	}
	out["after"] = errno(processVMReadSelf())
	// threads that exist now and threads created later are all filtered
	var wg sync.WaitGroup
	var mu sync.Mutex
	bad := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread() // a dedicated OS thread, created after the filter was installed
			if processVMReadSelf() != syscall.EPERM {
				mu.Lock()
				bad++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	out["threads_unfiltered"] = string(rune('0' + bad))
	// ordinary calls still work
	out["getpid"] = errno(0)
	if _, err := os.ReadFile("/proc/self/status"); err != nil {
		out["read"] = err.Error()
	} else {
		out["read"] = "ok"
	}
	// setns must stay available: the engine enters the sandbox's network namespace after the filter is on
	_, _, e := syscall.Syscall(308, ^uintptr(0), 0, 0) // setns(-1): EBADF means the call itself was permitted
	out["setns"] = errno(e)
	_, _, e = syscall.Syscall(syscall.SYS_MOUNT, 0, 0, 0)
	out["mount"] = errno(e)
}

func runHelper(t *testing.T, name string, broker bool) map[string]string {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), helperEnv+"="+name)
	if broker {
		cmd.SysProcAttr = brokerAttr()
	}
	out, err := cmd.Output()
	if err != nil {
		if broker && strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("cannot create user namespaces here: %v", err)
		}
		t.Fatalf("helper %s: %v", name, err)
	}
	var res map[string]string
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("bad output %q: %v", out, err)
	}
	if p := res["panic"]; p != "" {
		t.Fatalf("helper panicked: %s", p)
	}
	return res
}

func TestSeccompDeniesDangerousCallsOnEveryThread(t *testing.T) {
	r := runHelper(t, "filter", false)
	if r["install"] != "" {
		t.Skipf("seccomp cannot be installed here: %s", r["install"])
	}
	if r["before"] != "ok" {
		t.Skipf("control: process_vm_readv on ourselves does not work here (%s), so a denial would prove nothing", r["before"])
	}
	if r["after"] != syscall.EPERM.Error() {
		t.Errorf("process_vm_readv after the filter: %s, want EPERM", r["after"])
	}
	if r["threads_unfiltered"] != "0" {
		t.Errorf("%s threads escaped the filter", r["threads_unfiltered"])
	}
	if r["read"] != "ok" {
		t.Errorf("an ordinary read failed after the filter: %s", r["read"])
	}
	if r["setns"] != syscall.EBADF.Error() {
		t.Errorf("setns must remain permitted (EBADF from the bad fd, not EPERM): %s", r["setns"])
	}
	if r["mount"] != syscall.EPERM.Error() {
		t.Errorf("mount: %s, want EPERM", r["mount"])
	}
}

func TestProgramLayout(t *testing.T) {
	p := program(0xc000003e, []uint32{10, 20, 30})
	if len(p) != 4+3+2 {
		t.Fatalf("%d instructions", len(p))
	}
	// the last instruction denies, the one before allows, each match jumps to the deny
	deny, allow := len(p)-1, len(p)-2
	if p[deny].K&0xffff != uint32(syscall.EPERM) || p[allow].K != retAllow {
		t.Errorf("tail %+v %+v", p[allow], p[deny])
	}
	for i := 0; i < 3; i++ {
		k := 4 + i
		if target := k + 1 + int(p[k].Jt); target != deny {
			t.Errorf("rule %d jumps to %d, want the deny at %d", i, target, deny)
		}
	}
	if p[1].Jt != 1 || p[2].K != retKill {
		t.Error("an unexpected architecture must be killed")
	}
}

func TestEveryDeniedCallIsDistinctAndTheTableIsComplete(t *testing.T) {
	seen := map[uint32]bool{}
	for _, nr := range deniedCalls {
		if seen[nr] {
			t.Errorf("call %d listed twice", nr)
		}
		seen[nr] = true
	}
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		// the mount family must be in the table on the architectures we support: mount, umount2, pivot_root and the
		// six new-mount-API calls, which have the same numbers everywhere
		for _, nr := range []uint32{428, 429, 430, 431, 432, 433, 442} {
			if !seen[nr] {
				t.Errorf("new mount API call %d is not denied", nr)
			}
		}
		if len(deniedCalls) < 20 {
			t.Errorf("only %d calls denied", len(deniedCalls))
		}
	}
}
