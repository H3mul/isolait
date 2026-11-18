package harden

import (
	"encoding/binary"
	"syscall"
	"testing"
)

// run interprets the program for one seccomp_data{nr, arch} and returns the errno it returns (0 = allow).
func run(t *testing.T, prog []byte, nr, arch uint32) syscall.Errno {
	t.Helper()
	var a uint32
	for pc := 0; pc < len(prog)/8; pc++ {
		code := binary.NativeEndian.Uint16(prog[pc*8:])
		jt, jf := prog[pc*8+2], prog[pc*8+3]
		k := binary.NativeEndian.Uint32(prog[pc*8+4:])
		switch code {
		case bpfLdAbs:
			a = map[uint32]uint32{0: nr, 4: arch}[k]
		case bpfJeq, bpfJset:
			ok := a == k
			if code == bpfJset {
				ok = a&k != 0
			}
			if ok {
				pc += int(jt)
			} else {
				pc += int(jf)
			}
		case bpfRet:
			if k == retAllow {
				return 0
			}
			return syscall.Errno(k & 0xffff)
		default:
			t.Fatalf("unknown opcode %#x", code)
		}
	}
	t.Fatal("program fell off the end")
	return 0
}

func TestDenyProgram(t *testing.T) {
	p := DenyProgram([]Deny{{Nr: 250, Errno: syscall.EPERM}, {Nr: 425, Errno: syscall.ENOSYS}})
	for _, c := range []struct {
		name     string
		nr, arch uint32
		want     syscall.Errno
	}{
		{"denied", 250, auditArch, syscall.EPERM},
		{"errno override", 425, auditArch, syscall.ENOSYS},
		{"allowed", 1, auditArch, 0},
		{"foreign architecture", 1, 0x40000003, syscall.EPERM},
		{"x32 bit", 1 | x32Bit, auditArch, syscall.EPERM},
	} {
		if x32Bit == 0 && c.name == "x32 bit" {
			continue
		}
		if got := run(t, p, c.nr, c.arch); got != c.want {
			t.Errorf("%s: got errno %d, want %d", c.name, got, c.want)
		}
	}
}
