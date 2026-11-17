// Package broker re-executes the isolait binary inside a fresh user and mount namespace. The daemon runs
// there: it holds capabilities only inside that namespace, sees the host filesystem, and its mounts do not
// leak back to the host. Sandboxes are children of the broker and receive mounts by propagation.
package broker

import (
	"os"
	"os/exec"
	"syscall"
)

// Capability numbers (linux/capability.h) the broker keeps as ambient capabilities.
const capSysAdmin = 21

// Command returns a command that runs exe with args as the broker: new user namespace with an identity
// uid and gid map (the agent keeps the user's real ids), new mount namespace, detached from the caller's
// session. A non-root process loses its capabilities on exec, so they are requested as ambient ones.
func Command(exe string, args ...string) *exec.Cmd {
	cmd := exec.Command(exe, args...)
	uid, gid := os.Getuid(), os.Getgid()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}},
		GidMappingsEnableSetgroups: false,
		AmbientCaps:                []uintptr{capSysAdmin},
		Setsid:                     true,
	}
	return cmd
}
