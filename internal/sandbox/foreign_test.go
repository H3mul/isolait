package sandbox

import (
	"reflect"
	"strings"
	"testing"

	"github.com/H3mul/isolait/internal/mountcheck"
)

func table(t *testing.T, s string) []mountcheck.Mount {
	t.Helper()
	m, err := mountcheck.Parse(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestForeignSubmounts(t *testing.T) {
	wsl := table(t, `1 0 8:1 / / rw - ext4 /dev/sdc rw
2 1 0:30 / /usr/lib/modules/6.18 rw,nosuid - overlay none rw
3 1 0:31 / /usr/lib/wsl/drivers ro,nosuid - 9p drivers ro
4 1 0:32 / /usr/lib/wsl/lib rw,nosuid - overlay none rw
5 4 0:33 / /usr/lib/wsl/lib/nested rw,nosuid - fuse.x x rw
6 1 0:34 / /mnt/c rw - 9p C:\ rw
7 1 0:35 / /usr/share/remote rw - fuse.sshfs u@h:/ rw
`)
	want := []string{"/usr/lib/modules/6.18", "/usr/lib/wsl/drivers", "/usr/lib/wsl/lib", "/usr/share/remote"}
	if got := ForeignSubmounts(wsl, SystemDirs); !reflect.DeepEqual(got, want) {
		t.Errorf("WSL layout: got %v, want %v (nested mount is hidden by its parent's mask; /mnt/c is not a system dir)", got, want)
	}
	plain := table(t, `1 0 8:1 / / rw - ext4 /dev/sdc rw
2 1 8:2 / /usr/local rw - ext4 /dev/sdd rw
3 1 0:5 / /usr/share/x rw - tmpfs tmpfs rw
`)
	if got := ForeignSubmounts(plain, SystemDirs); len(got) != 0 {
		t.Errorf("a separate ext4 /usr/local and a tmpfs are part of the system, got %v", got)
	}
}
