package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/H3mul/isolait/internal/ctl"
	"github.com/H3mul/isolait/internal/session"
)

func shortBase(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "iso") // 0700, short enough for socket paths
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// fakeDaemon registers a session whose control socket answers like the real one. On "stop" it removes the
// runtime directory, as the real daemon does when it finishes cleaning up.
func fakeDaemon(t *testing.T, base string, st Status) string {
	t.Helper()
	id, err := session.Create(base, "/x/"+st.ID)
	if err != nil {
		t.Fatal(err)
	}
	st.ID = id
	srv, err := ctl.Listen(session.SocketPath(base, id))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	os.WriteFile(filepath.Join(session.Dir(base, id), "pid"), []byte("1\n"), 0o600) // alive: init
	go srv.Serve(func(r ctl.Request) (any, error) {
		switch r.Op {
		case "status":
			return st, nil
		case "stop":
			go func() { time.Sleep(50 * time.Millisecond); session.Remove(base, id) }()
			return "stopping", nil
		}
		return "pong", nil
	})
	return id
}

func TestResolveTarget(t *testing.T) {
	base := shortBase(t)
	if _, err := ResolveTarget(base, ""); err == nil || !strings.Contains(err.Error(), "no session targeted") || !strings.Contains(err.Error(), "no sessions are running") {
		t.Fatalf("nothing running: %v", err)
	}
	a := fakeDaemon(t, base, Status{ID: "alpha", State: "idle", Started: time.Now(), Mounts: []MountInfo{{Path: "/workspaces/alpha", Mode: "rw"}}})
	b := fakeDaemon(t, base, Status{ID: "beta", State: "idle", Started: time.Now()})

	if got, err := ResolveTarget(base, b); err != nil || got != b {
		t.Fatalf("explicit sid: %q %v", got, err)
	}
	if _, err := ResolveTarget(base, "nope-0000"); err == nil || !strings.Contains(err.Error(), "does not exist") || !strings.Contains(err.Error(), a) {
		t.Fatalf("missing sid must fail listing the running sessions: %v", err)
	}
	if _, err := ResolveTarget(base, "../etc"); err == nil || !strings.Contains(err.Error(), "invalid session id") {
		t.Fatalf("path-like sid: %v", err)
	}
	if _, err := ResolveTarget(base, ""); err == nil || !strings.Contains(err.Error(), a) || !strings.Contains(err.Error(), b) {
		t.Fatalf("no target with sessions running must list them: %v", err)
	}
	if err := SetLast(base, a); err != nil {
		t.Fatal(err)
	}
	if got, err := ResolveTarget(base, ""); err != nil || got != a {
		t.Fatalf("last attached: %q %v", got, err)
	}
	if got, _ := ResolveTarget(base, b); got != b {
		t.Error("--sid must beat the last attached session")
	}
	session.Remove(base, a) // the last attached session disappears
	if _, err := ResolveTarget(base, ""); err == nil || !strings.Contains(err.Error(), "the last attached session is gone") || !strings.Contains(err.Error(), b) {
		t.Fatalf("stale last pointer: %v", err)
	}
}

func TestListRemovesStaleKeepsStarting(t *testing.T) {
	base := shortBase(t)
	live := fakeDaemon(t, base, Status{ID: "live", State: "idle", Started: time.Now()})

	// a daemon that died: pid file names a process that no longer exists
	dead, _ := session.Create(base, "/x/dead")
	gone := exec.Command("/bin/true")
	gone.Run()
	os.WriteFile(filepath.Join(session.Dir(base, dead), "pid"), []byte(strconv.Itoa(gone.Process.Pid)+"\n"), 0o600)

	// a start in progress: fresh directory, no pid yet
	starting, _ := session.Create(base, "/x/starting")

	// a directory that never got a daemon, old enough to be a leftover
	old, _ := session.Create(base, "/x/old")
	past := time.Now().Add(-2 * staleAfter)
	os.Chtimes(session.Dir(base, old), past, past)

	es, err := List(base)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range es {
		got[e.ID] = e.Status != nil
	}
	if !got[live] || len(got) != 2 {
		t.Fatalf("listed %v, want the live session and the one still starting", got)
	}
	if _, ok := got[starting]; !ok || got[starting] {
		t.Errorf("a start in progress must be listed as unreachable, not removed: %v", got)
	}
	for _, id := range []string{dead, old} {
		if _, err := os.Stat(session.Dir(base, id)); !os.IsNotExist(err) {
			t.Errorf("stale session %s was not cleaned up", id)
		}
	}
}

func TestFormatList(t *testing.T) {
	out := FormatList([]Entry{
		{ID: "api-a3f9", Status: &Status{State: "idle", Started: time.Now().Add(-3 * time.Minute), Mounts: []MountInfo{{Path: "/workspaces/api", Mode: "rw"}, {Path: "/workspaces/lib", Mode: "ro"}}}},
		{ID: "web-1c2d", Err: os.ErrNotExist},
	})
	for _, want := range []string{"ID", "STATE", "WORKSPACES", "AGE", "api-a3f9", "idle", "api:rw,lib:ro", "3m", "web-1c2d", "unreachable"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output lacks %q:\n%s", want, out)
		}
	}
}

func TestStopWaitsForTheDaemonToCleanUp(t *testing.T) {
	base := shortBase(t)
	id := fakeDaemon(t, base, Status{ID: "s", State: "idle", Started: time.Now()})
	if err := Stop(base, id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(session.Dir(base, id)); !os.IsNotExist(err) {
		t.Error("session directory still there after stop")
	}
	if err := Stop(base, id); err == nil || !strings.Contains(err.Error(), "no such session") {
		t.Errorf("stopping a missing session: %v", err)
	}
}

func TestStopKillsAnUnresponsiveDaemon(t *testing.T) {
	base := shortBase(t)
	id, _ := session.Create(base, "/x/hung")
	hung := exec.Command("/bin/sleep", "30") // stands in for a daemon that no longer answers
	if err := hung.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { hung.Process.Kill(); hung.Wait() }()
	os.WriteFile(filepath.Join(session.Dir(base, id), "pid"), []byte(strconv.Itoa(hung.Process.Pid)+"\n"), 0o600)

	defer func(old time.Duration) { stopGrace = old }(stopGrace)
	stopGrace = 300 * time.Millisecond
	start := time.Now()
	err := Stop(base, id)
	if err == nil || !strings.Contains(err.Error(), "killed") {
		t.Fatalf("want a 'killed' error, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("stop took too long")
	}
	hung.Wait()
	if st := hung.ProcessState; st == nil || !st.Sys().(syscall.WaitStatus).Signaled() {
		t.Errorf("the unresponsive daemon was not killed: %v", st)
	}
	if _, err := os.Stat(session.Dir(base, id)); !os.IsNotExist(err) {
		t.Error("runtime directory left behind")
	}
}
