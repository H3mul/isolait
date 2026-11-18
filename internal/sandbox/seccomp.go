package sandbox

import (
	"fmt"
	"syscall"

	"github.com/H3mul/isolait/internal/harden"
)

// denyTable is the syscall deny list every session runs under, installed by bwrap in the sandbox's init so
// every process in the session inherits it. Default errno EPERM. ptrace, clone, unshare, setns, seccomp and
// prctl stay allowed (the pid namespace and YAMA confine ptrace; --disable-userns covers namespaces).
// personality is not filtered yet (Docker allows only two argument values; a plain deny could break setarch).
var denyTable = []struct {
	group string
	errno syscall.Errno
	names []string
}{
	{"keyrings: the kernel keyrings are shared with the host user", syscall.EPERM, []string{"keyctl", "add_key", "request_key"}},
	{"kernel introspection: log and address leaks, side channels, attack surface", syscall.EPERM, []string{"syslog", "perf_event_open", "bpf", "kcmp", "lookup_dcookie"}},
	{"memory and process spying: exploit primitives", syscall.EPERM, []string{"process_vm_readv", "process_vm_writev", "userfaultfd", "move_pages", "migrate_pages", "mbind", "set_mempolicy"}},
	{"file handles: container-escape primitive", syscall.EPERM, []string{"open_by_handle_at", "name_to_handle_at"}},
	{"module, boot and mount: already blocked by missing capabilities, denied for depth and clearer errors", syscall.EPERM, []string{
		"init_module", "finit_module", "delete_module", "kexec_load", "kexec_file_load", "reboot", "swapon", "swapoff", "acct", "quotactl",
		"iopl", "ioperm", "pivot_root", "umount2", "mount", "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr", "move_mount", "open_tree"}},
	// ENOSYS, not EPERM, so runtimes such as libuv fall back to epoll
	{"io_uring: large kernel attack surface", syscall.ENOSYS, []string{"io_uring_setup", "io_uring_enter", "io_uring_register"}},
	{"legacy: obsolete or exploit-prone", syscall.EPERM, []string{"uselib", "ustat", "modify_ldt", "vm86", "vm86old", "nfsservctl", "get_kernel_syms", "query_module", "sysfs", "_sysctl"}},
}

// absentSyscalls (per architecture, in seccomp_<arch>.go) are the names that do not exist there (32-bit only or
// removed); any other name that does not resolve is an error, so a misspelt entry cannot silently weaken the filter.

// seccompDenies resolves denyTable for the native architecture.
func seccompDenies() ([]harden.Deny, error) {
	var out []harden.Deny
	for _, g := range denyTable {
		for _, n := range g.names {
			nr, ok := syscallNumbers[n]
			if !ok {
				if absentSyscalls[n] {
					continue
				}
				return nil, fmt.Errorf("seccomp: unknown system call %q", n)
			}
			out = append(out, harden.Deny{Nr: nr, Errno: g.errno})
		}
	}
	return out, nil
}

// SeccompProgram is the filter handed to bwrap, and the number of calls it denies.
func SeccompProgram() ([]byte, int, error) {
	d, err := seccompDenies()
	if err != nil {
		return nil, 0, err
	}
	return harden.DenyProgram(d), len(d), nil
}
