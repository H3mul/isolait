// Package cli holds the cobra command tree. Commands stay thin; behaviour lives in the other internal packages.
package cli

import (
	"fmt"
	"runtime/debug"

	"github.com/H3mul/isolait/internal/config"
	"github.com/spf13/cobra"
)

// version is set at build time: go build -ldflags "-X github.com/H3mul/isolait/internal/cli.version=v0.1.0".
var version = ""

// Version returns the build version, falling back to the VCS revision embedded by the Go toolchain.
func Version() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		rev, dirty := "", ""
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
				if len(rev) > 12 {
					rev = rev[:12]
				}
			case "vcs.modified":
				if s.Value == "true" {
					dirty = "-dirty"
				}
			}
		}
		if rev != "" {
			return "dev-" + rev + dirty
		}
	}
	return "dev"
}

// Root builds the command tree. Errors are printed once by cobra; main only maps them to the exit code.
func Root() *cobra.Command {
	root := &cobra.Command{
		Use:           "isolait",
		Short:         "Run AI coding agents in a rootless, zero-trust sandbox",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(versionCmd(), preflightCmd(), trustCmd(config.DefaultPaths), initCmd())
	root.AddCommand(sessionCmds(realDeps())...)
	root.PersistentFlags().String("sid", "", "target this session instead of the last attached one")
	return root
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the isolait version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "isolait %s\n", Version())
			return err
		},
	}
}
