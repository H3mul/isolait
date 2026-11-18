// Package daemon runs one session: the broker process that owns the sandbox for its whole life and serves
// the control socket, plus the client side the CLI uses to start, list, query and stop sessions.
package daemon

import "time"

// Spec is everything the daemon needs, written by the launcher and read from a pipe at startup. It never
// touches disk because HostEnv can hold secrets.
type Spec struct {
	ID          string
	RuntimeBase string // parent of the session's runtime directory
	GlobalDir   string // isolait's global config directory (never mountable)
	StateDir    string // isolait's global state directory; the per-agent home lives below it
	Workdir     string // the starting workspace on the host
	Name        string // its name under /workspaces
	RO          bool
	Agent       []string // the agent command and its arguments (Agent[0] is resolved on HostPath)
	HostEnv     []string // host variables available to the allowlist (see sandbox.BuildEnv)
	EnvNames    []string // variables to forward (--env and config env)
	InheritEnv  bool
	InheritPath bool
	Tools       []string
	AllowUserns bool
	HostHome    string
	HostPath    string
	User        string
	UID, GID    int
	Limits      Limits   // resource limits for the session
	SystemdRun  string   // path to systemd-run, empty when there is no systemd user manager
	LimitsNote  string   // set by the launcher when limits could not be applied: why
	Bwrap       string   // path to bwrap, resolved by the launcher (the daemon runs with an empty environment)
	InitExe     string   // host path of the isolait binary, run inside the sandbox as the init shim
	InitArgs    []string // arguments after the shim path (default: init); tests use their own
	RogueMount  bool     // tests only: mount something unplanned during each hot mount, to exercise the rollback
	NetTest     *NetTest // tests only: route the sandbox's traffic to local fixtures
	Started     time.Time
}

// MountInfo is one workspace mount for status output.
type MountInfo struct {
	Path string `json:"path"` // inside the sandbox
	Src  string `json:"src"`
	Mode string `json:"mode"` // rw or ro
}

// Status is what `isolait status` and `isolait list` show.
type Status struct {
	ID       string       `json:"id"`
	State    string       `json:"state"` // idle (no agent running); attached and detached arrive with group 4
	PID      int          `json:"pid"`   // the daemon
	Started  time.Time    `json:"started"`
	Workdir  string       `json:"workdir"`
	Mounts   []MountInfo  `json:"mounts"`
	Roots    []string     `json:"roots"`    // tool roots exposed read-only
	Ports    []int        `json:"ports"`    // open port grants
	EnvNames []string     `json:"env"`      // variable names passed in (never values)
	Warnings []string     `json:"warnings"` // start-time warnings, e.g. dangling links
	Limits   LimitsStatus `json:"limits"`
	Network  string       `json:"network"`           // up, or down with the reason
	NetPID   int          `json:"net_pid,omitempty"` // the network engine process, for debugging
}
