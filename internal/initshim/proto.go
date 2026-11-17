// Package initshim is PID 1 inside the sandbox and its client in the daemon. The daemon asks the shim to
// start processes (agent, extra shells, exec) over a unix socket; stdio file descriptors, including PTY
// slaves, travel as SCM_RIGHTS. The shim has no extra privilege, reaps orphans, and reports exits, so the
// agent can exit and be started again without the sandbox, its mounts or its grants going away.
package initshim

// ControlFD is the descriptor number the daemon passes the control socket as (0-2 are stdio, 3 is bwrap's
// info fd).
const ControlFD = 4

const (
	maxMsg  = 64 << 10
	maxArgs = 4096
)

// Request is a daemon-to-shim message. For "spawn", the three stdio files (stdin, stdout, stderr) are attached
// as SCM_RIGHTS.
type Request struct {
	Op   string   `json:"op"` // "spawn", "signal", "shutdown"
	ID   int      `json:"id,omitempty"`
	Argv []string `json:"argv,omitempty"`
	Env  []string `json:"env,omitempty"`
	Cwd  string   `json:"cwd,omitempty"`
	TTY  bool     `json:"tty,omitempty"` // make stdin the controlling terminal of a new session
	Sig  int      `json:"sig,omitempty"`
}

// Event is a shim-to-daemon message.
type Event struct {
	Event  string `json:"event"` // "hello", "started", "exited", "error"
	ID     int    `json:"id,omitempty"`
	PID    int    `json:"pid,omitempty"` // PID inside the sandbox
	Code   int    `json:"code,omitempty"`
	Signal int    `json:"signal,omitempty"` // terminating signal, 0 if it exited normally
	Error  string `json:"error,omitempty"`
}
