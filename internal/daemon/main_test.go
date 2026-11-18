package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/H3mul/isolait/internal/initshim"
	"github.com/H3mul/isolait/internal/netd"
)

// The test binary stands in for `isolait`: the daemon, the scope helper and the init shim are subcommands, and
// the shim also runs as an ordinary process for the terminal tests (no sandbox needed).
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "daemon":
			if err := RunFromFD(); err != nil {
				os.Stderr.WriteString("daemon: " + err.Error() + "\n")
				os.Exit(1)
			}
			return
		case "_spawn":
			exe, _ := os.Executable()
			exe, _ = filepath.EvalSymlinks(exe)
			if err := SpawnFromStdin(exe); err != nil {
				os.Stderr.WriteString("_spawn: " + err.Error() + "\n")
				os.Exit(1)
			}
			return
		case "netd":
			if err := netd.Main(os.Args[2:], os.Stdin, os.Stderr); err != nil {
				os.Stderr.WriteString("netd: " + err.Error() + "\n")
				os.Exit(1)
			}
			return
		case "__isolait_init__":
			if err := initshim.Run(os.NewFile(initshim.ControlFD, "control")); err != nil {
				os.Exit(1)
			}
			return
		}
	}
	os.Exit(m.Run())
}

// execSelf returns a command that re-executes this test binary with a subcommand and an empty environment
// apart from what the subcommand needs.
func execSelf(arg string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], arg)
	cmd.Env = []string{}
	cmd.Stderr = os.Stderr
	return cmd
}
