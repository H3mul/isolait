package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
// waits until its control socket answers. exe is the isolait binary to re-execute; it runs `daemon`.
func Launch(spec Spec, exe string) error {
	dir := session.Dir(spec.RuntimeBase, spec.ID)
	spec.Started = time.Now()
	b, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	logf, err := os.OpenFile(filepath.Join(dir, "daemon.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	defer r.Close()

	cmd := broker.Command(exe, "daemon")
	cmd.Env = []string{} // the daemon gets what it needs through the spec, never the caller's environment
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.ExtraFiles = []*os.File{r} // fd 3
	if err := cmd.Start(); err != nil {
		w.Close()
		return fmt.Errorf("starting the session daemon: %w", err)
	}
	go func() { w.Write(b); w.Close() }() // may block briefly if the spec exceeds the pipe buffer

	died := make(chan error, 1)
	go func() { died <- cmd.Wait() }()
	sock := session.SocketPath(spec.RuntimeBase, spec.ID)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-died:
			return startFailure(dir, err)
		default:
		}
		if _, err := ctl.Call(sock, ctl.Request{Op: "ping"}); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	cmd.Process.Kill()
	return startFailure(dir, errors.New("timed out waiting for the session daemon"))
}

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
}

// List returns the sessions with a runtime directory. Leftovers of dead daemons are removed and not listed.
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
		out = append(out, Entry{ID: id, Status: &st})
	}
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

// SetLast records the last attached session, the default target of commands without --sid.
func SetLast(base, id string) error {
	return os.WriteFile(filepath.Join(base, "last"), []byte(id+"\n"), 0o600)
}

// ResolveTarget picks the session a command acts on: --sid, else the last attached one. When neither
// exists it fails with the list of running sessions.
func ResolveTarget(base, sid string) (string, error) {
	if sid != "" {
		if !session.ValidID(sid) {
			return "", fmt.Errorf("invalid session id %q", sid)
		}
		if _, err := os.Stat(session.Dir(base, sid)); err != nil {
			return "", noTarget(base, fmt.Sprintf("session %s does not exist", sid))
		}
		return sid, nil
	}
	if b, err := os.ReadFile(filepath.Join(base, "last")); err == nil {
		last := strings.TrimSpace(string(b))
		if session.ValidID(last) {
			if _, err := os.Stat(session.Dir(base, last)); err == nil {
				return last, nil
			}
		}
		return "", noTarget(base, "the last attached session is gone")
	}
	return "", noTarget(base, "no session targeted: attach to one or pass --sid")
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
