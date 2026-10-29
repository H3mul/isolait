// probe: clone a directory with open_tree, set attrs on the detached tree, move it into place.
// usage: probe <src> <dst> [ro]
// Stdlib only (raw syscalls) so the spike needs no module downloads.
package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	sysOpenTree     = 428
	sysMoveMount    = 429
	sysMountSetattr = 442

	openTreeClone   = 1
	openTreeCloexec = syscall.O_CLOEXEC
	atEmptyPath     = 0x1000
	atFdcwd         = -100
	moveMountFEmpty = 0x4

	mountAttrRdonly = 0x1
	mountAttrNosuid = 0x2
	mountAttrNodev  = 0x4
)

type mountAttr struct{ set, clr, propagation, userns uint64 }

func die(what string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
	os.Exit(1)
}

func main() {
	src, dst := os.Args[1], os.Args[2]
	ro := len(os.Args) > 3 && os.Args[3] == "ro"

	fd, err := syscall.Open(src, 0x200000|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0) // O_PATH
	if err != nil {
		die("open src", err)
	}
	empty, _ := syscall.BytePtrFromString("")
	// Non-recursive clone: no OPEN_TREE recursive flag (AT_RECURSIVE) so host submounts stay out.
	tree, _, e := syscall.Syscall(sysOpenTree, uintptr(fd), uintptr(unsafe.Pointer(empty)), openTreeClone|openTreeCloexec|atEmptyPath)
	if e != 0 {
		die("open_tree", e)
	}
	a := mountAttr{set: mountAttrNosuid | mountAttrNodev}
	if ro {
		a.set |= mountAttrRdonly
	}
	if _, _, e := syscall.Syscall6(sysMountSetattr, tree, uintptr(unsafe.Pointer(empty)), atEmptyPath, uintptr(unsafe.Pointer(&a)), unsafe.Sizeof(a), 0); e != 0 {
		die("mount_setattr", e)
	}
	d, _ := syscall.BytePtrFromString(dst)
	cwd := atFdcwd // variable: a negative constant cannot convert to uintptr
	if _, _, e := syscall.Syscall6(sysMoveMount, tree, uintptr(unsafe.Pointer(empty)), uintptr(cwd), uintptr(unsafe.Pointer(d)), moveMountFEmpty, 0); e != 0 {
		die("move_mount", e)
	}
}
