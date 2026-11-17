// Package broker re-executes the isolait binary inside a fresh user and mount namespace. The daemon runs
// there: it holds capabilities only inside that namespace, sees the host filesystem, and its mounts do not
// leak back to the host. Sandboxes are children of the broker and receive mounts by propagation.
package broker

import (
	"os"
	"os/exec"
	"syscall"
)

// Command returns a command that runs exe with args as the broker: a new user namespace in which uid 0 and
// gid 0 are the calling user (so the process holds all capabilities, but only inside that namespace), a new
// mount namespace, and its own session.
//
// Why root-mapped and not an identity map with ambient capabilities: bwrap refuses to run when it holds
// capabilities but is neither setuid nor uid 0 ("Unexpected capabilities but not setuid"). The sandbox's
// processes still run as the user's real uid and gid: the launcher passes --uid and --gid to bwrap.
func Command(exe string, args ...string) *exec.Cmd {
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
		Setsid:                     true,
	}
	return cmd
}
