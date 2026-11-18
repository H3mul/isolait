package cli

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/H3mul/isolait/internal/attach"
	"github.com/H3mul/isolait/internal/config"
	"github.com/H3mul/isolait/internal/pty"
	"github.com/H3mul/isolait/internal/relay"
	"github.com/H3mul/isolait/internal/session"
	"github.com/H3mul/isolait/internal/term"
	"github.com/H3mul/isolait/internal/trust"
	"github.com/spf13/cobra"
)

// ExitError carries the exit status of an attached process out to main, which exits with it quietly.
type ExitError struct{ Code int }

func (e *ExitError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }

// terminalFiles returns the command's stdin and stdout as terminals, or an error: attaching needs both.
func terminalFiles(cmd *cobra.Command) (in, out *os.File, err error) {
	in, ok1 := cmd.InOrStdin().(*os.File)
	out, ok2 := cmd.OutOrStdout().(*os.File)
	if !ok1 || !ok2 || !pty.IsTerminal(int(in.Fd())) || !pty.IsTerminal(int(out.Fd())) {
		return nil, nil, errors.New("this needs a terminal: run it from an interactive shell")
	}
	return in, out, nil
}

// leaderKey is the configured leader byte (global config, and the current directory's config if it is trusted).
func leaderKey(d deps) (byte, error) {
	p, err := d.paths()
	if err != nil {
		return 0, err
	}
	wd, _ := os.Getwd()
	res, err := config.Load(p, wd, config.Layer{}, trust.Open(p.StateDir)) // warnings are not repeated on every attach
	if err != nil {
		return 0, err
	}
	return term.ParseLeader(res.Config.Leader)
}

// attachTo connects the terminal to a session and returns when the process ends or the user detaches.
func attachTo(cmd *cobra.Command, d deps, base, id string, hello attach.HelloMsg) error {
	in, out, err := terminalFiles(cmd)
	if err != nil {
		return err
	}
	leader, err := leaderKey(d)
	if err != nil {
		return err
	}
	conn, err := net.Dial("unix", session.AttachPath(base, id))
	if err != nil {
		return fmt.Errorf("session %s is not reachable: %w", id, err)
	}
	defer conn.Close()
	res, err := relay.Run(relay.Options{Conn: conn, Hello: hello, Leader: leader, In: in, Out: out, TTY: out, Prompt: promptRunner(d, id)})
	if err != nil {
		return err
	}
	stderr := cmd.ErrOrStderr()
	switch {
	case res.Detached:
		fmt.Fprintf(stderr, "[detached from %s]\n", id)
	case res.Exit != nil && hello.Mode == attach.ModeAgent:
		fmt.Fprintf(stderr, "[%s: the agent exited with status %d; attach again to restart it]\n", id, exitStatus(res.Exit))
		if code := exitStatus(res.Exit); code != 0 {
			return &ExitError{Code: code}
		}
	case res.Exit != nil:
		if code := exitStatus(res.Exit); code != 0 {
			return &ExitError{Code: code}
		}
	default:
		fmt.Fprintf(stderr, "[connection to %s closed]\n", id)
	}
	return nil
}

// exitStatus maps an exit report to a shell-style status (128 plus the signal for a killed process).
func exitStatus(e *attach.ExitInfo) int {
	if e.Signal != 0 {
		return 128 + e.Signal
	}
	return e.Code
}

func attachCmd(d deps) *cobra.Command {
	return &cobra.Command{
		Use:   "attach [sid]",
		Short: "Attach this terminal to a session's agent (starts the agent if it is not running)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			base, id, err := resolve(cmd, d, args, true)
			if err != nil {
				return err
			}
			return attachTo(cmd, d, base, id, attach.HelloMsg{Mode: attach.ModeAgent})
		},
	}
}

func execCmd(d deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exec [--sid sid] -- command [args...]",
		Short: "Run a command inside a running session's sandbox on this terminal",
		Long: "Runs the command in the session's sandbox with the same mounts, environment and restrictions as the agent.\n" +
			"The process ends when you detach (leader, d) or close the terminal.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			base, id, err := target(cmd, d, nil)
			if err != nil {
				return err
			}
			return attachTo(cmd, d, base, id, attach.HelloMsg{Mode: attach.ModeExec, Argv: args})
		},
	}
	cmd.Flags().SetInterspersed(false) // everything after the first argument belongs to the command
	return cmd
}
