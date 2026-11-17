package preflight

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"unsafe"
)

// Syscall numbers are the same on amd64 and arm64.
const (
	sysOpenTree     = 428
	sysMoveMount    = 429
	sysMountSetattr = 442
)

var bwrapVersion = regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`)

// System returns the probes that inspect the real host.
func System() Probes {
	return Probes{
		Bwrap: func() (string, error) {
			path, err := exec.LookPath("bwrap")
			if err != nil {
				return "", errors.New("bwrap not found in PATH")
			}
			out, err := exec.Command(path, "--version").Output()
			if err != nil {
				return "", fmt.Errorf("%s --version failed: %w", path, err)
			}
			m := bwrapVersion.FindString(string(out))
			if m == "" {
				return "", fmt.Errorf("cannot parse bwrap version from %q", strings.TrimSpace(string(out)))
			}
			return m, nil
		},
		UserNS: func() error {
			var stderr bytes.Buffer
			cmd := exec.Command("bwrap", "--unshare-user", "--ro-bind", "/", "/", "true")
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
			}
			return nil
		},
		Sysctl: func(name string) (string, bool) {
			b, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(name, ".", "/"))
			if err != nil {
				return "", false
			}
			return strings.TrimSpace(string(b)), true
		},
		MountAPI: mountAPI,
		Tun: func() error {
			f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
			if err != nil {
				return err
			}
			return f.Close()
		},
	}
}

// mountAPI probes the three syscalls with harmless arguments. Only ENOSYS (or EPERM on the benign
// open_tree, which is how a seccomp filter shows up) means the API is unavailable; any other errno on
// the invalid-argument calls means the kernel knows the call.
func mountAPI() error {
	root, _ := syscall.BytePtrFromString("/")
	empty, _ := syscall.BytePtrFromString("")
	cwd, bad := -100, -1 // AT_FDCWD and an invalid fd

	fd, _, e := syscall.Syscall(sysOpenTree, uintptr(cwd), uintptr(unsafe.Pointer(root)), 0)
	switch e {
	case 0:
		syscall.Close(int(fd))
	case syscall.ENOSYS, syscall.EPERM:
		return fmt.Errorf("open_tree unavailable: %v", e)
	}
	if _, _, e := syscall.Syscall6(sysMoveMount, uintptr(bad), uintptr(unsafe.Pointer(empty)), uintptr(bad), uintptr(unsafe.Pointer(empty)), 0, 0); e == syscall.ENOSYS {
		return errors.New("move_mount unavailable: function not implemented")
	}
	if _, _, e := syscall.Syscall6(sysMountSetattr, uintptr(bad), uintptr(unsafe.Pointer(empty)), 0, 0, 0, 0); e == syscall.ENOSYS {
		return errors.New("mount_setattr unavailable: function not implemented")
	}
	return nil
}
