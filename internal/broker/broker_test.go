package broker

import (
	"os"
	"syscall"
	"testing"
)

// Fast tier: the namespace recipe itself must not drift (identity map, ambient SYS_ADMIN, nothing else).
func TestCommandRecipe(t *testing.T) {
	a := Command("/bin/true").SysProcAttr
	if a.Cloneflags != syscall.CLONE_NEWUSER|syscall.CLONE_NEWNS {
		t.Errorf("cloneflags %#x", a.Cloneflags)
	}
	uid, gid := os.Getuid(), os.Getgid()
	if len(a.UidMappings) != 1 || a.UidMappings[0] != (syscall.SysProcIDMap{ContainerID: uid, HostID: uid, Size: 1}) {
		t.Errorf("uid map %+v is not the identity map", a.UidMappings)
	}
	if len(a.GidMappings) != 1 || a.GidMappings[0] != (syscall.SysProcIDMap{ContainerID: gid, HostID: gid, Size: 1}) {
		t.Errorf("gid map %+v is not the identity map", a.GidMappings)
	}
	if a.GidMappingsEnableSetgroups {
		t.Error("setgroups must stay denied")
	}
	if len(a.AmbientCaps) != 1 || a.AmbientCaps[0] != capSysAdmin {
		t.Errorf("ambient caps %v, want only CAP_SYS_ADMIN", a.AmbientCaps)
	}
	if !a.Setsid {
		t.Error("broker must run in its own session")
	}
}
