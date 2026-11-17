package broker

import (
	"os"
	"syscall"
	"testing"
)

// Fast tier: the namespace recipe itself must not drift (user mapped to uid/gid 0, no ambient caps).
func TestCommandRecipe(t *testing.T) {
	a := Command("/bin/true").SysProcAttr
	if a.Cloneflags != syscall.CLONE_NEWUSER|syscall.CLONE_NEWNS {
		t.Errorf("cloneflags %#x", a.Cloneflags)
	}
	uid, gid := os.Getuid(), os.Getgid()
	if len(a.UidMappings) != 1 || a.UidMappings[0] != (syscall.SysProcIDMap{ContainerID: 0, HostID: uid, Size: 1}) {
		t.Errorf("uid map %+v must map uid 0 to the caller (%d)", a.UidMappings, uid)
	}
	if len(a.GidMappings) != 1 || a.GidMappings[0] != (syscall.SysProcIDMap{ContainerID: 0, HostID: gid, Size: 1}) {
		t.Errorf("gid map %+v must map gid 0 to the caller (%d)", a.GidMappings, gid)
	}
	if a.GidMappingsEnableSetgroups {
		t.Error("setgroups must stay denied")
	}
	if len(a.AmbientCaps) != 0 {
		t.Errorf("ambient caps %v: bwrap refuses to run with capabilities unless uid 0", a.AmbientCaps)
	}
	if !a.Setsid {
		t.Error("broker must run in its own session")
	}
}
