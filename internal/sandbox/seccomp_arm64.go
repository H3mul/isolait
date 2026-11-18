package sandbox

import "golang.org/x/sys/unix"

// syscallNumbers resolves the names in denyTable for arm64; a name missing here must be in absentSyscalls.
var syscallNumbers = map[string]uint32{
	"keyctl":            unix.SYS_KEYCTL,
	"add_key":           unix.SYS_ADD_KEY,
	"request_key":       unix.SYS_REQUEST_KEY,
	"syslog":            unix.SYS_SYSLOG,
	"perf_event_open":   unix.SYS_PERF_EVENT_OPEN,
	"bpf":               unix.SYS_BPF,
	"kcmp":              unix.SYS_KCMP,
	"lookup_dcookie":    unix.SYS_LOOKUP_DCOOKIE,
	"process_vm_readv":  unix.SYS_PROCESS_VM_READV,
	"process_vm_writev": unix.SYS_PROCESS_VM_WRITEV,
	"userfaultfd":       unix.SYS_USERFAULTFD,
	"move_pages":        unix.SYS_MOVE_PAGES,
	"migrate_pages":     unix.SYS_MIGRATE_PAGES,
	"mbind":             unix.SYS_MBIND,
	"set_mempolicy":     unix.SYS_SET_MEMPOLICY,
	"open_by_handle_at": unix.SYS_OPEN_BY_HANDLE_AT,
	"name_to_handle_at": unix.SYS_NAME_TO_HANDLE_AT,
	"init_module":       unix.SYS_INIT_MODULE,
	"finit_module":      unix.SYS_FINIT_MODULE,
	"delete_module":     unix.SYS_DELETE_MODULE,
	"kexec_load":        unix.SYS_KEXEC_LOAD,
	"kexec_file_load":   unix.SYS_KEXEC_FILE_LOAD,
	"reboot":            unix.SYS_REBOOT,
	"swapon":            unix.SYS_SWAPON,
	"swapoff":           unix.SYS_SWAPOFF,
	"acct":              unix.SYS_ACCT,
	"quotactl":          unix.SYS_QUOTACTL,
	"pivot_root":        unix.SYS_PIVOT_ROOT,
	"umount2":           unix.SYS_UMOUNT2,
	"mount":             unix.SYS_MOUNT,
	"fsopen":            unix.SYS_FSOPEN,
	"fsconfig":          unix.SYS_FSCONFIG,
	"fsmount":           unix.SYS_FSMOUNT,
	"fspick":            unix.SYS_FSPICK,
	"mount_setattr":     unix.SYS_MOUNT_SETATTR,
	"move_mount":        unix.SYS_MOVE_MOUNT,
	"open_tree":         unix.SYS_OPEN_TREE,
	"io_uring_setup":    unix.SYS_IO_URING_SETUP,
	"io_uring_enter":    unix.SYS_IO_URING_ENTER,
	"io_uring_register": unix.SYS_IO_URING_REGISTER,
	"nfsservctl":        unix.SYS_NFSSERVCTL,
}

var absentSyscalls = map[string]bool{
	"iopl": true, "ioperm": true, "uselib": true, "ustat": true, "modify_ldt": true, "vm86": true, "vm86old": true,
	"get_kernel_syms": true, "query_module": true, "sysfs": true, "_sysctl": true,
}
