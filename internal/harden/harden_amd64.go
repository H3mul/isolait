package harden

const (
	auditArch  = 0xc000003e // AUDIT_ARCH_X86_64
	sysSeccomp = 317
	x32Bit     = 0x40000000 // the x32 ABI marks its numbers with this bit
)

// deniedCalls are the x86-64 numbers of the calls DenyDangerousCalls refuses.
var deniedCalls = []uint32{
	165, 166, 155, 161, // mount, umount2, pivot_root, chroot
	428, 429, 430, 431, 432, 433, 442, // open_tree, move_mount, fsopen, fsconfig, fsmount, fspick, mount_setattr
	167, 168, 169, // swapon, swapoff, reboot
	246, 175, 313, 176, // kexec_load, init_module, finit_module, delete_module
	101, 310, 311, // ptrace, process_vm_readv, process_vm_writev
	272, 304, // unshare, open_by_handle_at
}
