package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/H3mul/isolait/internal/config"
	"github.com/H3mul/isolait/internal/trust"
	"github.com/spf13/cobra"
)

// trustCmd approves the exact content of a workspace's .isolait/config. paths is injectable for tests.
func trustCmd(paths func() (config.Paths, error)) *cobra.Command {
	return &cobra.Command{
		Use:   "trust [workspace]",
		Short: "Trust the current content of a workspace's .isolait/config",
		Long: "Records the SHA-256 of the workspace's .isolait/config so its settings apply on the next start.\n" +
			"Trust is bound to the exact content: any change makes the file untrusted again.\n" +
			"The file is printed first so you can see what you are trusting.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) == 1 {
				dir = args[0]
			}
			abs, err := filepath.Abs(dir)
			if err != nil {
				return err
			}
			p, err := paths()
			if err != nil {
				return err
			}
			path, data, err := config.ReadWorkspace(abs)
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("no %s/%s in %s: nothing to trust", config.WorkspaceDir, config.FileName, abs)
			}
			if err != nil {
				return err
			}
			if _, err := config.Parse(path, data); err != nil { // never trust a file that would not load
				return err
			}
			sum := trust.Sum(data)
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "--- %s\n%s---\n", path, data)
			if err := trust.Open(p.StateDir).Add(sum, path); err != nil {
				return err
			}
			_, err = fmt.Fprintf(out, "trusted sha256:%s\n", sum)
			return err
		},
	}
}
