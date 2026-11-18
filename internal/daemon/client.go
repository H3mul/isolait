package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/H3mul/isolait/internal/broker"
	"github.com/H3mul/isolait/internal/ctl"
	"github.com/H3mul/isolait/internal/session"
)

// staleAfter is how long a runtime directory without a pid file may exist before it is treated as the
// leftover of a daemon that never started (a start in progress writes its pid file within milliseconds).
const staleAfter = 30 * time.Second

// Launch starts the daemon for spec in the broker's namespaces, detached from the caller's terminal, and
// waits until its control socket answers. exe is the isolait binary to re-execute. When systemd-run is
// available the daemon starts inside a transient user scope carrying the session's limits; otherwise the
// session starts without limits and says so (or fails when limits are required).
func Launch(spec Spec, exe string) error {
	dir := session.Dir(spec.RuntimeBase, spec.ID)
	spec.Started = time.Now()
	logf, err := os.OpenFile(filepath.Join(dir, "daemon.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()

	if spec.SystemdRun != "" && spec.Limits.Pids > 0 {
		err := runScope(spec, exe, logf)
		if err == nil {
			return waitReady(spec, nil)
		}
		if spec.Limits.Required {
			return fmt.Errorf("limits.required is set but resource limits cannot be applied: %w", err)
		}
		spec.LimitsNote = "unavailable: " + firstLine(err.Error())
	} else {
		reason := "no systemd user manager (systemd-run not found)"
		if spec.Limits.Pids <= 0 {
			reason = "disabled"
		}
		if spec.Limits.Required {
			return fmt.Errorf("limits.required is set but resource limits cannot be applied: %s", reason)
		}
		spec.LimitsNote = "unavailable: " + reason
	}
	cmd, wrote, err := spawnDaemon(spec, exe, logf)
	if err != nil {
		return err
	}
	died := make(chan error, 1)
	go func() { died <- cmd.Wait() }()
	go func() { <-wrote }()
	return waitReady(spec, died)
}

// runScope runs `exe _spawn` under systemd-run with the session's limits, handing it the spec on stdin.
func runScope(spec Spec, exe string, logf *os.File) error {
	dir := session.Dir(spec.RuntimeBase, spec.ID)
	b, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	cmd := exec.Command(spec.SystemdRun, ScopeArgs("isolait-"+spec.ID, spec.Limits, exe)...)
	cmd.Env = pick(os.Environ(), "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS") // enough to reach the user manager
	cmd.Stdin = bytes.NewReader(b)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = io.MultiWriter(&out, logf), io.MultiWriter(&out, logf)
	if err := cmd.Run(); err != nil {
		if _, serr := os.Stat(filepath.Join(dir, "spawned")); serr == nil {
			return nil // the daemon was started; only the exit status of the helper was unexpected
		}
		msg := strings.TrimSpace(out.String())
		if msg == "" {
			msg = err.Error()
		}
		return errors.New(msg)
	}
	return nil
}

func pick(env []string, names ...string) []string {
	var out []string
	for _, kv := range env {
		for _, n := range names {
			if strings.HasPrefix(kv, n+"=") {
				out = append(out, kv)
			}
		}
	}
	return out
}

func firstLine(s string) string { return strings.SplitN(strings.TrimSpace(s), "\n", 2)[0] }

// spawnDaemon starts the daemon process and feeds it the spec through a pipe. The returned channel closes
// once the spec has been written.
func spawnDaemon(spec Spec, exe string, logf *os.File) (*exec.Cmd, <-chan struct{}, error) {
	b, err := json.Marshal(spec)
	if err != nil {
		return nil, nil, err
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	defer r.Close()
	cmd := broker.Command(exe, "daemon")
	cmd.Env = []string{} // the daemon gets what it needs through the spec, never the caller's environment
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.ExtraFiles = []*os.File{r} // fd 3
	if err := cmd.Start(); err != nil {
		w.Close()
		return nil, nil, fmt.Errorf("starting the session daemon: %w", err)
	}
	wrote := make(chan struct{})
	go func() { w.Write(b); w.Close(); close(wrote) }() // blocks only if the spec exceeds the pipe buffer
	return cmd, wrote, nil
}

// SpawnFromStdin is the body of the hidden `_spawn` command: it runs inside the session's systemd scope,
// starts the daemon (which inherits the scope's cgroup and therefore its limits) and exits, leaving a marker
// so the launcher can tell that the scope worked.
func SpawnFromStdin(exe string) error {
	var spec Spec
	if err := json.NewDecoder(os.Stdin).Decode(&spec); err != nil {
		return fmt.Errorf("reading session spec: %w", err)
	}
	dir := session.Dir(spec.RuntimeBase, spec.ID)
	logf, err := os.OpenFile(filepath.Join(dir, "daemon.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	cmd, wrote, err := spawnDaemon(spec, exe, logf)
	if err != nil {
		return err
	}
	<-wrote
	cmd.Process.Release()
	return os.WriteFile(filepath.Join(dir, "spawned"), nil, 0o600)
}

// waitReady waits until the daemon's control socket answers, the daemon reports an error or dies, or time runs out.
// died, when not nil, delivers the daemon's exit if it is our child.
func waitReady(spec Spec, died <-chan error) error {
	dir := session.Dir(spec.RuntimeBase, spec.ID)
	sock := session.SocketPath(spec.RuntimeBase, spec.ID)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := ctl.Call(sock, ctl.Request{Op: "ping"}); err == nil {
			return nil
		}
		select {
		case err := <-died:
			return startFailure(dir, err)
		default:
		}
		if b, err := os.ReadFile(filepath.Join(dir, "error")); err == nil && len(b) > 0 {
			return startFailure(dir, errors.New("the session daemon failed"))
		}
		if stale(spec.RuntimeBase, spec.ID) && pidFileExists(dir) {
			return startFailure(dir, errors.New("the session daemon exited"))
		}
		time.Sleep(50 * time.Millisecond)
	}
	return startFailure(dir, errors.New("timed out waiting for the session daemon"))
}

func pidFileExists(dir string) bool { _, err := os.Stat(filepath.Join(dir, "pid")); return err == nil }

func startFailure(dir string, cause error) error {
	if b, err := os.ReadFile(filepath.Join(dir, "error")); err == nil && len(b) > 0 {
		return errors.New(strings.TrimSpace(string(b)))
	}
	if b, err := os.ReadFile(filepath.Join(dir, "daemon.log")); err == nil && len(bytes.TrimSpace(b)) > 0 {
		return fmt.Errorf("%v: %s", cause, strings.TrimSpace(string(b)))
	}
	return cause
}

// Query asks a running session for its status.
func Query(base, id string) (Status, error) {
	resp, err := ctl.Call(session.SocketPath(base, id), ctl.Request{Op: "status"})
	if err != nil {
		return Status{}, err
	}
	var st Status
	return st, json.Unmarshal(resp.Data, &st)
}

// Entry is one session found in the runtime directory.
type Entry struct {
	ID     string
	Status *Status
	Err    error
	Used   time.Time // when the user last attached or detached; the start time if never
}

// List returns the sessions with a runtime directory, most recently used first. Leftovers of dead daemons
// are removed and not listed.
func List(base string) ([]Entry, error) {
	ids, err := session.List(base)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, id := range ids {
		st, err := Query(base, id)
		if err != nil {
			if stale(base, id) {
				session.Remove(base, id)
				continue
			}
			out = append(out, Entry{ID: id, Err: err}) // starting up, or not answering
			continue
		}
		used, ok := session.Used(base, id)
		if !ok {
			used = st.Started
		}
		out = append(out, Entry{ID: id, Status: &st, Used: used})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Used.After(out[j].Used) })
	return out, nil
}

func stale(base, id string) bool {
	dir := session.Dir(base, id)
	if b, err := os.ReadFile(filepath.Join(dir, "pid")); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 0 {
			return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
		}
	}
	fi, err := os.Stat(dir)
	return err == nil && time.Since(fi.ModTime()) > staleAfter
}

// stopGrace is how long Stop waits for the daemon to finish cleaning up before killing it.
var stopGrace = 15 * time.Second

// Stop ends a session: the daemon is asked to shut down and clean up; one that does not answer is killed.
func Stop(base, id string) error {
	dir := session.Dir(base, id)
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("session %s: %w", id, errNoSuchSession)
	}
	var pid int
	if b, err := os.ReadFile(filepath.Join(dir, "pid")); err == nil {
		pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	_, callErr := ctl.Call(session.SocketPath(base, id), ctl.Request{Op: "stop"})
	deadline := time.Now().Add(stopGrace)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	if pid > 0 { // not answering: killing the daemon takes the sandbox with it (die-with-parent)
		syscall.Kill(pid, syscall.SIGKILL)
		time.Sleep(200 * time.Millisecond)
	}
	if err := session.Remove(base, id); err != nil {
		return err
	}
	if callErr != nil {
		return fmt.Errorf("session %s did not answer (%v); it was killed", id, callErr)
	}
	return nil
}

var errNoSuchSession = errors.New("no such session")

// ResolveTarget picks the session a command acts on, like tmux: --sid, else the most recently used live
// session (attach and detach count; the start time stands in for a session never used). With forAttach it
// prefers the most recently used session nobody is attached to. List sweeps stale sessions first, so a dead
// one is never chosen.
func ResolveTarget(base, sid string, forAttach bool) (string, error) {
	if sid != "" {
		if !session.ValidID(sid) {
			return "", fmt.Errorf("invalid session id %q", sid)
		}
		if _, err := os.Stat(session.Dir(base, sid)); err != nil {
			return "", noTarget(base, fmt.Sprintf("session %s does not exist", sid))
		}
		return sid, nil
	}
	es, _ := List(base) // newest used first
	var first, unattached string
	for _, e := range es {
		if e.Status == nil {
			continue // still starting, or not answering
		}
		if first == "" {
			first = e.ID
		}
		if unattached == "" && e.Status.State != "attached" {
			unattached = e.ID
		}
	}
	switch {
	case forAttach && unattached != "":
		return unattached, nil
	case first != "":
		return first, nil
	}
	return "", errors.New("no sessions running")
}

func noTarget(base, why string) error {
	es, _ := List(base)
	if len(es) == 0 {
		return fmt.Errorf("%s; no sessions are running", why)
	}
	return fmt.Errorf("%s; running sessions:\n%s", why, FormatList(es))
}

// FormatList renders sessions as a table: id, state, workspaces, age.
func FormatList(es []Entry) string {
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATE\tWORKSPACES\tAGE")
	for _, e := range es {
		if e.Status == nil {
			fmt.Fprintf(tw, "%s\tunreachable\t-\t-\n", e.ID)
			continue
		}
		var ws []string
		for _, m := range e.Status.Mounts {
			ws = append(ws, strings.TrimPrefix(m.Path, "/workspaces/")+":"+m.Mode)
		}
		sort.Strings(ws)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.ID, e.Status.State, strings.Join(ws, ","), age(time.Since(e.Status.Started)))
	}
	tw.Flush()
	return strings.TrimRight(b.String(), "\n")
}

func age(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// AddMount mounts the host directory src into a running session as /workspaces/<name> (named after the
// directory when name is empty). src must be absolute.
func AddMount(base, id, src, name string, ro bool) (MountInfo, error) {
	mode := "rw"
	if ro {
		mode = "ro"
	}
	resp, err := ctl.Call(session.SocketPath(base, id), ctl.Request{Op: "mount", Args: []string{src, name, mode}})
	if err != nil {
		return MountInfo{}, err
	}
	var mi MountInfo
	return mi, json.Unmarshal(resp.Data, &mi)
}

// RemoveMount unmounts /workspaces/<name>; without force it refuses while sandbox processes use it.
func RemoveMount(base, id, name string, force bool) error {
	f := ""
	if force {
		f = "force"
	}
	_, err := ctl.Call(session.SocketPath(base, id), ctl.Request{Op: "unmount", Args: []string{name, f}})
	return err
}
