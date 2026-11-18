//go:build !security

package harden

import "syscall"

// brokerAttr is only used by the security tier's tests, which need user namespaces.
func brokerAttr() *syscall.SysProcAttr { return nil }
