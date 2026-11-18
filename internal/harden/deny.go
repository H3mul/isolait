package harden

import (
	"encoding/binary"
	"syscall"
)

const (
	bpfJset = 0x45 // BPF_JMP | BPF_JSET | BPF_K
)

// Deny makes one system call fail with Errno instead of running.
type Deny struct {
	Nr    uint32
	Errno syscall.Errno
}

// DenyProgram builds a classic-BPF seccomp program (the raw sock_filter array bwrap's --seccomp reads) for the
// native architecture: a call from another architecture, or (on amd64) from the x32 ABI, fails with EPERM; each
// listed call fails with its errno; everything else is allowed.
func DenyProgram(rules []Deny) []byte {
	ret := func(e syscall.Errno) sockFilter { return sockFilter{Code: bpfRet, K: retErrnoBase | uint32(e)} }
	p := []sockFilter{
		{Code: bpfLdAbs, K: 4}, // seccomp_data.arch
		{Code: bpfJeq, Jt: 1, K: auditArch},
		ret(syscall.EPERM),
		{Code: bpfLdAbs, K: 0}, // seccomp_data.nr
	}
	if x32Bit != 0 {
		p = append(p, sockFilter{Code: bpfJset, Jf: 1, K: x32Bit}, ret(syscall.EPERM))
	}
	for _, r := range rules {
		p = append(p, sockFilter{Code: bpfJeq, Jf: 1, K: r.Nr}, ret(r.Errno))
	}
	p = append(p, sockFilter{Code: bpfRet, K: retAllow})
	b := make([]byte, 0, 8*len(p))
	for _, f := range p {
		b = binary.NativeEndian.AppendUint16(b, f.Code)
		b = append(b, f.Jt, f.Jf)
		b = binary.NativeEndian.AppendUint32(b, f.K)
	}
	return b
}
