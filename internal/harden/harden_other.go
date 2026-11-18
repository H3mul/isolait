//go:build !amd64 && !arm64

package harden

const (
	auditArch  = 0
	sysSeccomp = 0
)

// deniedCalls is empty on architectures without a table: DenyDangerousCalls then refuses to run.
var deniedCalls []uint32
