package harden

const (
	auditArch  = 0xc00000b7 // AUDIT_ARCH_AARCH64
	sysSeccomp = 277
	x32Bit     = 0
)

// deniedCalls are the arm64 numbers of the calls DenyDangerousCalls refuses.
var deniedCalls = []uint32{
	40, 39, 41, 51, // mount, umount2, pivot_root, chroot
	428, 429, 430, 431, 432, 433, 442, // open_tree, move_mount, fsopen, fsconfig, fsmount, fspick, mount_setattr
	224, 225, 142, // swapon, swapoff, reboot
	104, 105, 273, 106, // kexec_load, init_module, finit_module, delete_module
	117, 270, 271, // ptrace, process_vm_readv, process_vm_writev
	97, 265, // unshare, open_by_handle_at
}
