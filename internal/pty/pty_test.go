package pty

import (
	"os"
	"reflect"
	"syscall"
	"testing"
)

func openPair(t *testing.T) (m, s *os.File) {
	t.Helper()
	m, s, err := Open()
	if err != nil {
		t.Skipf("no pty here: %v", err)
	}
	t.Cleanup(func() { m.Close(); s.Close() })
	return m, s
}

func TestRawModeAndRestore(t *testing.T) {
	_, s := openPair(t)
	fd := int(s.Fd())
	if !IsTerminal(fd) {
		t.Fatal("a pty slave is a terminal")
	}
	before, _ := getTermios(fd)
	st, err := MakeRaw(fd)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := getTermios(fd)
	if raw.Lflag&(syscall.ECHO|syscall.ICANON|syscall.ISIG) != 0 || raw.Oflag&syscall.OPOST != 0 || raw.Iflag&syscall.ICRNL != 0 {
		t.Errorf("not raw: %+v", raw)
	}
	if raw.Cc[syscall.VMIN] != 1 || raw.Cc[syscall.VTIME] != 0 {
		t.Errorf("a raw read must block for one byte: %+v", raw.Cc)
	}
	if err := Restore(fd, st); err != nil {
		t.Fatal(err)
	}
	if after, _ := getTermios(fd); !reflect.DeepEqual(after, before) {
		t.Errorf("terminal not restored:\n got %+v\nwant %+v", after, before)
	}
}

func TestNotATerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if IsTerminal(int(r.Fd())) {
		t.Error("a pipe is not a terminal")
	}
	if _, err := MakeRaw(int(r.Fd())); err == nil {
		t.Error("MakeRaw accepted a pipe")
	}
}

func TestSizeRoundTrip(t *testing.T) {
	m, s := openPair(t)
	if err := SetSize(m, 132, 43); err != nil {
		t.Fatal(err)
	}
	if cols, rows, err := GetSize(int(s.Fd())); err != nil || cols != 132 || rows != 43 {
		t.Errorf("size %dx%d err %v", cols, rows, err)
	}
}
