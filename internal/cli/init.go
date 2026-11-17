package cli

import (
	"os"

	"github.com/H3mul/isolait/internal/initshim"
	"github.com/spf13/cobra"
)

// initCmd is the in-sandbox PID 1. It is hidden: the daemon starts it inside the sandbox with the control
// socket on fd 4, never a user.
func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "init",
		Short:  "Run as the sandbox's init shim (internal)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return initshim.Run(os.NewFile(initshim.ControlFD, "control"))
		},
	}
}
