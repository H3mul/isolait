package cli

import (
	"fmt"

	"github.com/H3mul/isolait/internal/preflight"
	"github.com/spf13/cobra"
)

// preflightCmd is hidden: `start` will run the same checks; this exists to debug a host.
func preflightCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "preflight",
		Short:  "Check that this host can run isolait sessions",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := preflight.Run(preflight.System()); err != nil {
				return err
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "ok: all prerequisites present")
			return err
		},
	}
}
