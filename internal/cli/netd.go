package cli

import (
	"os"

	"github.com/H3mul/isolait/internal/netd"
	"github.com/spf13/cobra"
)

// netdCmd is the network engine process, started by the session daemon outside the sandbox. It is hidden and
// takes its flags verbatim, including the TEST ONLY ones.
func netdCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "netd",
		Short:              "Run the sandbox's network engine (internal)",
		Hidden:             true,
		DisableFlagParsing: true,
		RunE: func(_ *cobra.Command, args []string) error {
			return netd.Main(args, os.Stdin, os.Stderr)
		},
	}
}
