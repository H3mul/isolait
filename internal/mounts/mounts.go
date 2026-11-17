// Package mounts implements the broker's mount primitive (design Decision 2): clone the source with
// open_tree, set nosuid/nodev (and rdonly) on the detached tree, then move_mount it into place. The flags
// are set before the mount is visible, so a read-only mount is never observable as writable, which
// `mount --bind` followed by `remount,ro` cannot guarantee because flag changes do not propagate.
//
// All functions must run in the broker's mount namespace (they need CAP_SYS_ADMIN there).
package mounts

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unsafe"
)

const (
	sysOpenTree     = 428
	sysMoveMount    = 429
	sysMountSetattr = 442

	oPath           = 0x200000
	openTreeClone   = 1
	atEmptyPath     = 0x1000
	atFDCWD         = -100
	moveMountFEmpty = 0x4

	attrRdonly = 0x1
	attrNosuid = 0x2
	attrNodev  = 0x4
)

type mountAttr struct{ set, clr, propagation, userns uint64 }

// Attach mounts a non-recursive clone of the directory src at dst (which must exist and be a directory,
// not a symlink). Host submounts of src are not carried along. The mount is nosuid and nodev, and read-only
// when ro is set.
func Attach(src, dst string, ro bool) error {
	fd, err := syscall.Open(src, oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer syscall.Close(fd)
	empty, _ := syscall.BytePtrFromString("")

	tree, _, e := syscall.Syscall(sysOpenTree, uintptr(fd), uintptr(unsafe.Pointer(empty)), openTreeClone|syscall.O_CLOEXEC|atEmptyPath)
	if e != 0 {
		return fmt.Errorf("open_tree %s: %w", src, e)
	}
	defer syscall.Close(int(tree))

	a := mountAttr{set: attrNosuid | attrNodev}
	if ro {
		a.set |= attrRdonly
	}
	if _, _, e := syscall.Syscall6(sysMountSetattr, tree, uintptr(unsafe.Pointer(empty)), atEmptyPath, uintptr(unsafe.Pointer(&a)), unsafe.Sizeof(a), 0); e != 0 {
		return fmt.Errorf("mount_setattr %s: %w", src, e)
	}
	d, err := syscall.BytePtrFromString(dst)
	if err != nil {
		return err
	}
	cwd := atFDCWD // a variable: a negative constant cannot convert to uintptr
	// No MOVE_MOUNT_T_SYMLINKS: a symlink at dst is not followed, so it cannot redirect the mount.
	if _, _, e := syscall.Syscall6(sysMoveMount, tree, uintptr(unsafe.Pointer(empty)), uintptr(cwd), uintptr(unsafe.Pointer(d)), moveMountFEmpty, 0); e != 0 {
		return fmt.Errorf("move_mount to %s: %w", dst, e)
	}
	return nil
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidName reports whether s can be a /workspaces/<name> entry.
func ValidName(s string) bool { return nameRe.MatchString(s) && !strings.Contains(s, "..") }

// NameFor derives a workspace name from a directory: its basename with unsafe characters replaced.
func NameFor(dir string) string {
	b := regexp.MustCompile(`[^A-Za-z0-9._-]+`).ReplaceAllString(filepath.Base(filepath.Clean(dir)), "-")
	b = strings.TrimLeft(strings.Trim(b, "-"), ".")
	if len(b) > 64 {
		b = b[:64]
	}
	if !ValidName(b) {
		return "workspace"
	}
	return b
}

// HasIsolaitDir reports whether src has a .isolait entry at its root (of any type: a symlink or file named
// .isolait is still masked or refused, never ignored).
func HasIsolaitDir(src string) (bool, error) {
	_, err := os.Lstat(filepath.Join(src, ".isolait"))
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

// Unmount lazily detaches dst and everything mounted below it (a workspace with its .isolait mask stacked
// on it cannot be removed with a plain umount; see spike 1.9).
func Unmount(dst string) error { return syscall.Unmount(dst, syscall.MNT_DETACH) }

// MountWorkspace mounts src at stage/name (stage is the broker's shared stage directory), read-only if ro,
// and layers the empty read-only directory emptyDir over src/.isolait if there is one, so the sandbox never
// sees the workspace's isolait config or state. It returns whether a mask was applied. On any failure
// nothing stays mounted. An existing stage/name is a collision error.
func MountWorkspace(stage, name, src string, ro bool, emptyDir string) (masked bool, err error) {
	if !ValidName(name) {
		return false, fmt.Errorf("invalid workspace name %q", name)
	}
	real, err := filepath.EvalSymlinks(src)
	if err != nil {
		return false, err
	}
	hasIsolait, err := HasIsolaitDir(real)
	if err != nil {
		return false, err
	}
	if hasIsolait {
		if fi, err := os.Lstat(filepath.Join(real, ".isolait")); err != nil || !fi.IsDir() {
			return false, fmt.Errorf("%s/.isolait is not a plain directory; refusing to mount a workspace whose isolait config cannot be masked", real)
		}
	}
	dst := filepath.Join(stage, name)
	if err := os.Mkdir(dst, 0o755); err != nil {
		if os.IsExist(err) {
			return false, fmt.Errorf("workspace name %q is already in use", name)
		}
		return false, err
	}
	if err := Attach(real, dst, ro); err != nil {
		os.Remove(dst)
		return false, err
	}
	if hasIsolait {
		if err := Attach(emptyDir, filepath.Join(dst, ".isolait"), true); err != nil {
			Unmount(dst)
			os.Remove(dst)
			return false, fmt.Errorf("masking .isolait: %w", err)
		}
	}
	return hasIsolait, nil
}
