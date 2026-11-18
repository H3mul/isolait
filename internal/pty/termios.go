package pty

import (
	"syscall"
	"unsafe"
)

// ioctl numbers shared by amd64 and arm64.
const (
	tcgets     = 0x5401
	tcsets     = 0x5402
	tiocgwinsz = 0x5413
)

// TermState is a saved terminal configuration.
type TermState struct{ t syscall.Termios }

func getTermios(fd int) (syscall.Termios, error) {
	var t syscall.Termios
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tcgets, uintptr(unsafe.Pointer(&t))); e != 0 {
		return t, e
	}
	return t, nil
}

func setTermios(fd int, t *syscall.Termios) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tcsets, uintptr(unsafe.Pointer(t))); e != 0 {
		return e
	}
	return nil
}

// IsTerminal reports whether fd is a terminal.
func IsTerminal(fd int) bool {
	_, err := getTermios(fd)
	return err == nil
}

// MakeRaw puts the terminal in raw mode (no echo, no line editing, no signal keys, no output processing) and
// returns the previous state for Restore. Ctrl-C and friends then arrive as ordinary bytes.
func MakeRaw(fd int) (*TermState, error) {
	old, err := getTermios(fd)
	if err != nil {
		return nil, err
	}
	t := old
	t.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	t.Oflag &^= syscall.OPOST
	t.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	t.Cflag &^= syscall.CSIZE | syscall.PARENB
	t.Cflag |= syscall.CS8
	t.Cc[syscall.VMIN] = 1
	t.Cc[syscall.VTIME] = 0
	if err := setTermios(fd, &t); err != nil {
		return nil, err
	}
	return &TermState{old}, nil
}

// Restore puts a terminal back as MakeRaw found it.
func Restore(fd int, s *TermState) error { return setTermios(fd, &s.t) }

// GetSize returns the terminal's size in columns and rows.
func GetSize(fd int) (cols, rows int, err error) {
	var ws [4]uint16
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tiocgwinsz, uintptr(unsafe.Pointer(&ws))); e != 0 {
		return 0, 0, e
	}
	return int(ws[1]), int(ws[0]), nil
}
