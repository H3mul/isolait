// Package harden narrows what the current process may do: a seccomp filter that denies the mount family and
// other dangerous system calls, and a capability set reduced to what the process needs. It is applied by the
// network engine so that, although it must enter the sandbox's network namespace, it has no authority to touch
// any mount or the host's state.
package harden

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	prSetNoNewPrivs = 38
	prCapbsetDrop   = 24
	prCapAmbient    = 47
	prCapAmbientClr = 4

	seccompSetModeFilter = 1
	seccompFilterTsync   = 1

	retAllow     = 0x7fff0000
	retKill      = 0x80000000 // SECCOMP_RET_KILL_PROCESS
	retErrnoBase = 0x00050000

	bpfLdAbs = 0x20 // BPF_LD | BPF_W | BPF_ABS
	bpfJeq   = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfRet   = 0x06 // BPF_RET | BPF_K
)

type sockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

type sockFprog struct {
	Len    uint16
	_      [6]byte
	Filter *sockFilter
}

// program builds the filter: wrong architecture kills the process, a denied system call returns EPERM, the
// rest is allowed.
func program(arch uint32, denied []uint32) []sockFilter {
	n := len(denied)
	p := []sockFilter{
		{Code: bpfLdAbs, K: 4}, // seccomp_data.arch
		{Code: bpfJeq, Jt: 1, K: arch},
		{Code: bpfRet, K: retKill},
		{Code: bpfLdAbs, K: 0}, // seccomp_data.nr
	}
	for i, nr := range denied {
		p = append(p, sockFilter{Code: bpfJeq, Jt: uint8(n - i), K: nr}) // jump to the final EPERM
	}
	return append(p, sockFilter{Code: bpfRet, K: retAllow}, sockFilter{Code: bpfRet, K: retErrnoBase | uint32(syscall.EPERM)})
}

// DenyDangerousCalls installs the filter on every thread of the process (and so on every thread created later).
// It cannot be removed. The denied set is the mount family (mount, umount2, pivot_root, chroot, the new mount
// API), swap, reboot, kexec, module loading, ptrace, cross-process memory access, unshare and file-handle
// opening; setns is left alone because the engine must enter the sandbox's network namespace.
func DenyDangerousCalls() error {
	if len(deniedCalls) == 0 {
		return errors.New("harden: no seccomp support for this architecture")
	}
	if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); e != 0 {
		return fmt.Errorf("harden: no_new_privs: %w", e)
	}
	prog := program(auditArch, deniedCalls)
	fp := sockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if _, _, e := syscall.Syscall(sysSeccomp, seccompSetModeFilter, seccompFilterTsync, uintptr(unsafe.Pointer(&fp))); e != 0 {
		return fmt.Errorf("harden: installing the seccomp filter: %w", e)
	}
	return nil
}

// Capability numbers (linux/capability.h) used by the engine.
const (
	CapNetAdmin = 12
	CapSysAdmin = 21
)

// KeepOnlyCaps reduces the process to exactly the given capabilities, on every thread: the effective and
// permitted sets, the inheritable and ambient sets (emptied) and the bounding set.
func KeepOnlyCaps(keep ...int) error {
	var mask uint64
	for _, c := range keep {
		mask |= 1 << uint(c)
	}
	hdr := struct {
		version uint32
		pid     int32
	}{version: 0x20080522} // _LINUX_CAPABILITY_VERSION_3
	var data [2]struct{ effective, permitted, inheritable uint32 }
	data[0].effective, data[0].permitted = uint32(mask), uint32(mask)
	data[1].effective, data[1].permitted = uint32(mask>>32), uint32(mask>>32)
	syscall.AllThreadsSyscall(syscall.SYS_PRCTL, prCapAmbient, prCapAmbientClr, 0) // best effort: may be unsupported
	for c := 0; c < 64; c++ {
		if mask&(1<<uint(c)) != 0 {
			continue
		}
		if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, prCapbsetDrop, uintptr(c), 0); e != 0 && e != syscall.EINVAL {
			return fmt.Errorf("harden: dropping capability %d from the bounding set: %w", c, e)
		}
	}
	if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return fmt.Errorf("harden: capset: %w", e)
	}
	return nil
}
