// Package pty allocates pseudo-terminals for sandbox processes. The daemon keeps the master and hands the
// slave to the init shim as a file descriptor.
package pty

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// ioctl numbers shared by amd64 and arm64.
const (
	tiocgptn   = 0x80045430
	tiocsptlck = 0x40045431
)

// Open allocates a pseudo-terminal pair. Neither side becomes the caller's controlling terminal.
func Open() (master, slave *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	var unlock int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), tiocsptlck, uintptr(unsafe.Pointer(&unlock))); e != 0 {
		m.Close()
		return nil, nil, fmt.Errorf("unlock pty: %w", e)
	}
	var n uint32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), tiocgptn, uintptr(unsafe.Pointer(&n))); e != 0 {
		m.Close()
		return nil, nil, fmt.Errorf("pty number: %w", e)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	return m, s, nil
}

const tiocswinsz = 0x5414

// SetSize sets the terminal's window size. The kernel delivers SIGWINCH to the foreground process group when
// the size actually changes.
func SetSize(f *os.File, cols, rows int) error {
	ws := [4]uint16{uint16(rows), uint16(cols), 0, 0} // rows, columns, pixel width, pixel height
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tiocswinsz, uintptr(unsafe.Pointer(&ws))); e != 0 {
		return e
	}
	return nil
}
