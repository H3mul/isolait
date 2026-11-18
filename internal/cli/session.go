package cli

import (
	"errors"
	"fmt"
	"github.com/H3mul/isolait/internal/sandbox"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/H3mul/isolait/internal/attach"
	"github.com/H3mul/isolait/internal/config"
	"github.com/H3mul/isolait/internal/daemon"
	"github.com/H3mul/isolait/internal/mounts"
	"github.com/H3mul/isolait/internal/preflight"
	"github.com/H3mul/isolait/internal/pty"
	"github.com/H3mul/isolait/internal/session"
	"github.com/H3mul/isolait/internal/trust"
	"github.com/spf13/cobra"
)

// deps are what the session commands need from the host; tests replace them.
type deps struct {
	paths   func() (config.Paths, error)
	runtime func() (string, error)
}

func realDeps() deps { return deps{paths: config.DefaultPaths, runtime: session.RuntimeBase} }

// agentOrShell is the command a session runs: the given one, else bash, to prepare the session from.
func agentOrShell(args []string) []string {
	if len(args) == 0 {
		return []string{"bash"}
	}
	return args
}

func sessionCmds(d deps) []*cobra.Command {
	return []*cobra.Command{startCmd(d), attachCmd(d), execCmd(d), listCmd(d), statusCmd(d), stopCmd(d), killServerCmd(d), mountCmd(d), unmountCmd(d), allowCmd(d), denyCmd(d), daemonCmd(), spawnCmd()}
}

// target resolves the session a command acts on: a positional id, else --sid, else the most recently used.
func target(cmd *cobra.Command, d deps, args []string) (base, id string, err error) {
	return resolve(cmd, d, args, false)
}

func resolve(cmd *cobra.Command, d deps, args []string, forAttach bool) (base, id string, err error) {
	if base, err = d.runtime(); err != nil {
		return "", "", err
	}
	sid, _ := cmd.Flags().GetString("sid")
	if len(args) > 0 {
		sid = args[0]
	}
	id, err = daemon.ResolveTarget(base, sid, forAttach)
	return base, id, err
}

func daemonCmd() *cobra.Command {
	return &cobra.Command{
		Use: "daemon", Short: "Run a session daemon (internal)", Hidden: true, Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error { return daemon.RunFromFD() },
	}
}

// spawnCmd runs inside the session's systemd scope (see daemon.SpawnFromStdin).
func spawnCmd() *cobra.Command {
	return &cobra.Command{
		Use: "_spawn", Short: "Start a session daemon inside its resource scope (internal)", Hidden: true, Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			exe, err := selfExe()
			if err != nil {
				return err
			}
			return daemon.SpawnFromStdin(exe)
		},
	}
}

func listCmd(d deps) *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List running sessions", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			base, err := d.runtime()
			if err != nil {
				return err
			}
			es, err := daemon.List(base)
			if err != nil {
				return err
			}
			if len(es) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no sessions running")
				return nil
			}
			fmt.Fprintln(cmd.OutOrStdout(), daemon.FormatList(es))
			return nil
		},
	}
}

func statusCmd(d deps) *cobra.Command {
	return &cobra.Command{
		Use: "status [sid]", Short: "Show a session's state, mounts, tool roots, ports and environment names", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			base, id, err := target(cmd, d, args)
			if err != nil {
				return err
			}
			st, err := daemon.Query(base, id)
			if err != nil {
				return fmt.Errorf("session %s: %w", id, err)
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "session  %s\nstate    %s\nworkdir  %s\n", st.ID, st.State, st.Workdir)
			fmt.Fprintln(w, "mounts")
			for _, m := range st.Mounts {
				fmt.Fprintf(w, "  %-28s %s  (%s)\n", m.Path, m.Mode, m.Src)
			}
			fmt.Fprintf(w, "tool roots  %s\nports       %s\nenv         %s\n", orNone(st.Roots), orNone(intsToStrings(st.Ports)), orNone(st.EnvNames))
			fmt.Fprintf(w, "limits      %s\n", limitsLine(st.Limits))
			_, denied, _ := sandbox.SeccompProgram() // the same build starts every session, so the count is the session's
			fmt.Fprintf(w, "seccomp     on (%d syscalls denied)\n", denied)
			if len(st.Masked) > 0 {
				fmt.Fprintf(w, "masked      %s\n", strings.Join(st.Masked, ", "))
			}
			for _, warn := range st.Warnings {
				fmt.Fprintf(w, "warning  %s\n", warn)
			}
			return nil
		},
	}
}

func stopCmd(d deps) *cobra.Command {
	return &cobra.Command{
		Use: "stop [sid]", Short: "Stop a session and release everything it holds", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			base, id, err := target(cmd, d, args)
			if err != nil {
				return err
			}
			if err := daemon.Stop(base, id); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "stopped %s\n", id)
			return nil
		},
	}
}

func killServerCmd(d deps) *cobra.Command {
	return &cobra.Command{
		Use: "kill-server", Short: "Stop every session", Args: cobra.NoArgs,
		Long: "Stops all running sessions and sweeps stale ones, printing each id stopped. With no session running it prints\n" +
			"\"no sessions running\" and succeeds; it fails only if a session could not be stopped.",
		RunE: func(cmd *cobra.Command, args []string) error {
			base, err := d.runtime()
			if err != nil {
				return err
			}
			stopped, errs := daemon.StopAll(base)
			for _, id := range stopped {
				fmt.Fprintf(cmd.OutOrStdout(), "stopped %s\n", id)
			}
			if len(stopped) == 0 && len(errs) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no sessions running")
			}
			return errors.Join(errs...)
		},
	}
}

func startCmd(d deps) *cobra.Command {
	var ro, inheritEnv, inheritPath, allowUserns, detached bool
	var envNames []string
	cmd := &cobra.Command{
		Use:   "start [flags] [agent [args...]]",
		Short: "Start a sandboxed session in the current directory",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			args = agentOrShell(args)
			wd, err := os.Getwd()
			if err != nil {
				return err
			}
			p, err := d.paths()
			if err != nil {
				return err
			}
			base, err := d.runtime()
			if err != nil {
				return err
			}
			if err := preflight.Run(preflight.System()); err != nil {
				return err
			}
			flags := config.Layer{Env: envNames}
			if cmd.Flags().Changed("inherit-env") {
				flags.InheritEnv = &inheritEnv
			}
			if cmd.Flags().Changed("inherit-path") {
				flags.InheritPath = &inheritPath
			}
			if cmd.Flags().Changed("allow-userns") {
				flags.AllowUserns = &allowUserns
			}
			res, err := config.Load(p, wd, flags, trust.Open(p.StateDir))
			if err != nil {
				return err
			}
			for _, w := range res.Warnings {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning:", w)
			}
			if err := checkWorkdir(wd, p, base); err != nil {
				return err
			}
			exe, err := selfExe()
			if err != nil {
				return err
			}
			bwrap, err := exec.LookPath("bwrap")
			if err != nil {
				return err
			}
			u, err := user.Current()
			if err != nil {
				return err
			}
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			id, err := session.Create(base, wd)
			if err != nil {
				return err
			}
			in, isFile := cmd.InOrStdin().(*os.File)
			attached := !detached && isFile && pty.IsTerminal(int(in.Fd()))
			spec := daemon.Spec{Detached: !attached, Term: os.Getenv("TERM"),
				ID: id, RuntimeBase: base, GlobalDir: p.GlobalDir, StateDir: p.StateDir, Workdir: wd, Name: mounts.NameFor(wd), RO: ro,
				Agent: args, HostEnv: os.Environ(), EnvNames: res.Config.Env, InheritEnv: res.Config.InheritEnv,
				InheritPath: res.Config.InheritPath, Tools: res.Config.Tools, AllowUserns: res.Config.AllowUserns,
				HostHome: home, HostPath: os.Getenv("PATH"), User: u.Username, UID: os.Getuid(), GID: os.Getgid(), InitExe: exe, Bwrap: bwrap,
				Limits: daemon.Limits{Pids: res.Config.Limits.Pids, Memory: res.Config.Limits.Memory, CPU: res.Config.Limits.CPU, Required: res.Config.Limits.Required},
			}
			if sd, err := exec.LookPath("systemd-run"); err == nil {
				spec.SystemdRun = sd
			}
			if err := daemon.Launch(spec, exe); err != nil {
				session.Remove(base, id)
				return err
			}
			st, err := daemon.Query(base, id)
			if err == nil {
				for _, w := range st.Warnings {
					fmt.Fprintln(cmd.ErrOrStderr(), "warning:", w)
				}
			}
			if attached {
				return attachTo(cmd, d, base, id, attach.HelloMsg{Mode: attach.ModeAgent})
			}
			// detached: the agent is already running; one that fails at once ends the session and fails the start
			up, err := daemon.WaitStartup(base, id)
			if err != nil {
				return fmt.Errorf("session %s: %w", id, err)
			}
			if up.Exited {
				daemon.WaitGone(base, id)
				if up.Tail != "" {
					fmt.Fprintln(cmd.ErrOrStderr(), strings.TrimRight(up.Tail, "\n"))
				}
				code := up.Code
				if up.Signal != 0 {
					code = 128 + up.Signal
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "the agent exited at start with status %d; no session was left\n", code)
				if code == 0 {
					code = 1
				}
				return &ExitError{Code: code}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "started %s (detached)\n", id)
			return nil
		},
	}
	cmd.Flags().SetInterspersed(false) // flags belong to isolait only until the agent command starts
	cmd.Flags().BoolVarP(&detached, "detach", "d", false, "start the session without attaching to it")
	cmd.Flags().BoolVar(&ro, "ro", false, "mount the starting directory read-only")
	cmd.Flags().StringArrayVar(&envNames, "env", nil, "forward this host environment variable into the sandbox (repeatable)")
	cmd.Flags().BoolVar(&inheritEnv, "inherit-env", false, "forward the whole host environment (agent sockets are still withheld)")
	cmd.Flags().BoolVar(&inheritPath, "inherit-path", false, "also expose host PATH directories under /usr/local, /opt and your home")
	cmd.Flags().BoolVar(&allowUserns, "allow-userns", false, "allow nested user namespaces in the sandbox (weakens isolation)")
	return cmd
}

// checkWorkdir refuses starting directories that contain or sit inside isolait's own directories, or that are
// the whole filesystem or home directory. It is a string-based guard until the mount deny list (task 6.1,
// by device and inode) replaces it.
func checkWorkdir(wd string, p config.Paths, runtimeBase string) error {
	home, _ := os.UserHomeDir()
	real, err := filepath.EvalSymlinks(wd)
	if err != nil {
		return err
	}
	if real == "/" || (home != "" && real == home) {
		return fmt.Errorf("refusing to start in %s: it contains everything the sandbox exists to keep away from the agent", real)
	}
	for _, dir := range []string{p.GlobalDir, p.StateDir, runtimeBase} {
		if r, err := filepath.EvalSymlinks(dir); err == nil {
			dir = r
		}
		if related(real, dir) {
			return fmt.Errorf("refusing to start in %s: it contains or is inside isolait's own directory %s", real, dir)
		}
	}
	return nil
}

func related(a, b string) bool {
	in := func(p, dir string) bool { return p == dir || strings.HasPrefix(p, strings.TrimRight(dir, "/")+"/") }
	return in(a, b) || in(b, a)
}

func selfExe() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}

func intsToStrings(n []int) []string {
	var s []string
	for _, v := range n {
		s = append(s, fmt.Sprint(v))
	}
	return s
}

func limitsLine(l daemon.LimitsStatus) string {
	if !l.Available {
		return "unavailable (" + strings.TrimPrefix(l.Reason, "unavailable: ") + ")"
	}
	max := func(n int64) string {
		if n == 0 {
			return "no limit"
		}
		return fmt.Sprint(n)
	}
	mem := fmt.Sprintf("%s used", humanBytes(l.MemoryCurrent))
	if l.MemoryMax > 0 {
		mem += " of " + humanBytes(l.MemoryMax)
	}
	return fmt.Sprintf("processes %d of %s, memory %s", l.PidsCurrent, max(l.PidsMax), mem)
}

func humanBytes(n uint64) string {
	const k = 1024
	switch {
	case n >= k*k*k:
		return fmt.Sprintf("%.1fG", float64(n)/(k*k*k))
	case n >= k*k:
		return fmt.Sprintf("%.0fM", float64(n)/(k*k))
	case n >= k:
		return fmt.Sprintf("%.0fK", float64(n)/k)
	}
	return fmt.Sprintf("%dB", n)
}

func mountCmd(d deps) *cobra.Command {
	var ro bool
	var as string
	cmd := &cobra.Command{
		Use: "mount [--ro] [--as name] <dir>", Short: "Mount a host directory into the running session at /workspaces/<name>", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			base, id, err := target(cmd, d, nil)
			if err != nil {
				return err
			}
			src, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			mi, err := daemon.AddMount(base, id, src, as, ro)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "mounted %s at %s (%s) in session %s\n", mi.Src, mi.Path, mi.Mode, id)
			return nil
		},
	}
	cmd.Flags().BoolVar(&ro, "ro", false, "mount read-only")
	cmd.Flags().StringVar(&as, "as", "", "name under /workspaces (default: the directory's name)")
	return cmd
}

func unmountCmd(d deps) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use: "unmount [--force] <name>", Short: "Remove a mount from the running session", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			base, id, err := target(cmd, d, nil)
			if err != nil {
				return err
			}
			name := strings.TrimPrefix(args[0], "/workspaces/")
			if err := daemon.RemoveMount(base, id, name, force); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "unmounted %s\n", name)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "detach even if processes still use it (they may keep stale handles)")
	return cmd
}

func allowCmd(d deps) *cobra.Command {
	cmd := &cobra.Command{Use: "allow", Short: "Grant the running session access to something on the host"}
	cmd.AddCommand(&cobra.Command{
		Use: "port <port|range>", Short: "Forward sandbox 127.0.0.1:<port> to the host's 127.0.0.1:<port> (TCP)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			base, id, err := target(cmd, d, nil)
			if err != nil {
				return err
			}
			r, err := daemon.AllowPorts(base, id, args[0])
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if len(r.Changed) == 0 {
				fmt.Fprintf(w, "%s is already open\n", args[0])
			} else {
				fmt.Fprintf(w, "opened %s in session %s: sandbox 127.0.0.1 -> host 127.0.0.1 (TCP); open ports: %s\n", portList(r.Changed), id, orNone(intsToStrings(r.Open)))
			}
			fmt.Fprintln(w, "note: the host service cannot tell the sandbox's connections from your own local ones")
			return nil
		},
	})
	return cmd
}

func denyCmd(d deps) *cobra.Command {
	cmd := &cobra.Command{Use: "deny", Short: "Withdraw access granted with allow"}
	cmd.AddCommand(&cobra.Command{
		Use: "port <port|range>", Short: "Close open port grants and end their connections", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			base, id, err := target(cmd, d, nil)
			if err != nil {
				return err
			}
			r, err := daemon.DenyPorts(base, id, args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "closed %s; open ports: %s\n", portList(r.Changed), orNone(intsToStrings(r.Open)))
			return nil
		},
	})
	return cmd
}

// portList renders ports compactly: a run of consecutive ports as a range.
func portList(p []int) string {
	var parts []string
	for i := 0; i < len(p); {
		j := i
		for j+1 < len(p) && p[j+1] == p[j]+1 {
			j++
		}
		if j > i {
			parts = append(parts, fmt.Sprintf("%d-%d", p[i], p[j]))
		} else {
			parts = append(parts, fmt.Sprint(p[i]))
		}
		i = j + 1
	}
	return strings.Join(parts, ",")
}
