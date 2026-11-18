//go:build security

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/H3mul/isolait/internal/attach"
)

// Hot mounts against the real kernel (tasks 6.3, 6.4, 6.7, 6.8).

func hotSession(t *testing.T, mut func(*Spec)) (env, Spec, func(string) string) {
	t.Helper()
	e := newEnv(t)
	spec := e.spec(t, "sh")
	if mut != nil {
		mut(&spec)
	}
	if err := Launch(spec, os.Args[0]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Stop(e.base, spec.ID) })
	run := func(script string) string {
		t.Helper()
		c, raw, r := dialAttach(t, e, spec.ID, attach.HelloMsg{Mode: attach.ModeExec, Argv: []string{"bash", "-c", script + "; echo done-exec"}, Term: "xterm", Cols: 200, Rows: 50})
		if !r.OK {
			t.Fatalf("exec: %+v", r)
		}
		return strings.ReplaceAll(readUntil(t, c, raw, "done-exec\r\n"), "\r", "")
	}
	return e, spec, run
}

func extraDir(t *testing.T, e env, name string, files map[string]string) string {
	t.Helper()
	d := filepath.Join(filepath.Dir(e.base), name) // beside the runtime dir, outside the workspace
	if err := os.MkdirAll(filepath.Join(d, ".isolait"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(d, ".isolait", "config"), []byte("secret=1\n"), 0o644)
	for n, c := range files {
		os.WriteFile(filepath.Join(d, n), []byte(c+"\n"), 0o644)
	}
	return d
}

func TestHotMountVisibleMaskedAndReadOnlyIsReadOnly(t *testing.T) {
	e, spec, run := hotSession(t, nil)
	rw := extraDir(t, e, "libs", map[string]string{"a.txt": "hello"})
	ro := extraDir(t, e, "docs", map[string]string{"b.txt": "readme"})
	if _, err := AddMount(e.base, spec.ID, rw, "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := AddMount(e.base, spec.ID, ro, "manual", true); err != nil {
		t.Fatal(err)
	}
	out := run(`cat /workspaces/libs/a.txt; echo; echo new > /workspaces/libs/n.txt && echo rw=ok;
		ls -A /workspaces/libs/.isolait | wc -l | sed s/^/masked_entries=/;
		touch /workspaces/libs/.isolait/x 2>&1 | head -1;
		cat /workspaces/manual/b.txt; echo; touch /workspaces/manual/n 2>&1 | head -1;
		mount -o remount,rw /workspaces/manual 2>&1 | head -1; echo remount_rc=${PIPESTATUS[0]}`)
	for _, want := range []string{"hello", "rw=ok", "masked_entries=0", "Read-only file system", "readme"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if line(out, "remount_rc") == "0" {
		t.Errorf("a remount succeeded inside the sandbox:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(rw, "n.txt")); err != nil {
		t.Errorf("a write to the rw mount did not reach the host: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ro, "n")); err == nil {
		t.Error("a read-only mount accepted a write")
	}
	st, err := Query(e.base, spec.ID)
	if err != nil || len(st.Mounts) != 3 {
		t.Fatalf("status mounts: %+v %v", st.Mounts, err)
	}
}

func TestHotMountRefusals(t *testing.T) {
	e, spec, _ := hotSession(t, nil)
	good := extraDir(t, e, "good", nil)
	if _, err := AddMount(e.base, spec.ID, good, "", false); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ src, as, want string }{
		"duplicate name":      {good, "good", "already exists"},
		"starting name":       {good, "proj", "already exists"},
		"bad name":            {good, "../x", "invalid mount name"},
		"state dir":           {e.state, "s", "refusing"},
		"runtime dir":         {e.base, "r", "refusing"},
		"parent of runtime":   {filepath.Dir(e.base), "p", "refusing"},
		"root":                {"/", "root", "refusing"},
		"missing":             {filepath.Join(e.base, "nope"), "n", "no such file"},
		"file, not directory": {filepath.Join(good, ".isolait", "config"), "f", "directory"},
		"relative path":       {"relative/dir", "rel", "absolute"},
	} {
		_, err := AddMount(e.base, spec.ID, tc.src, tc.as, false)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, tc.want)
		}
	}
	st, _ := Query(e.base, spec.ID)
	if len(st.Mounts) != 2 {
		t.Errorf("refused mounts left entries behind: %+v", st.Mounts)
	}
}

func TestHotMountRefusesAnIsolaitFileItCannotMask(t *testing.T) {
	e, spec, _ := hotSession(t, nil)
	d := filepath.Join(filepath.Dir(e.base), "odd")
	os.MkdirAll(d, 0o755)
	os.WriteFile(filepath.Join(d, ".isolait"), []byte("x"), 0o644)
	if _, err := AddMount(e.base, spec.ID, d, "", false); err == nil || !strings.Contains(err.Error(), "cannot be masked") {
		t.Fatalf("got %v", err)
	}
}

func TestRemoveBusyForcedAndSwitch(t *testing.T) {
	e, spec, run := hotSession(t, nil)
	a := extraDir(t, e, "a", map[string]string{"who": "a"})
	b := extraDir(t, e, "b", map[string]string{"who": "b"})
	if _, err := AddMount(e.base, spec.ID, a, "work", false); err != nil {
		t.Fatal(err)
	}
	// a process whose working directory is inside the mount keeps it busy
	run(`cd /workspaces/work && (setsid sleep 300 >/dev/null 2>&1 &) ; sleep 0.3`)
	err := RemoveMount(e.base, spec.ID, "work", false)
	if err == nil || !strings.Contains(err.Error(), "in use by sleep") {
		t.Fatalf("busy remove: %v", err)
	}
	if out := run(`cat /workspaces/work/who`); !strings.Contains(out, "a\n") {
		t.Fatalf("the mount disappeared despite the refusal: %s", out)
	}
	if err := RemoveMount(e.base, spec.ID, "work", true); err != nil {
		t.Fatalf("forced remove: %v", err)
	}
	if out := run(`ls /workspaces/work 2>&1; echo`); strings.Contains(out, "who") {
		t.Fatalf("the forced remove left the content visible: %s", out)
	}
	// the name is free again: switch the workspace to another directory
	if _, err := AddMount(e.base, spec.ID, b, "work", false); err != nil {
		t.Fatalf("re-adding the name: %v", err)
	}
	if out := run(`cat /workspaces/work/who`); !strings.Contains(out, "b\n") {
		t.Fatalf("switched workspace shows the wrong content: %s", out)
	}
	if err := RemoveMount(e.base, spec.ID, "nothing", false); err == nil {
		t.Fatal("removing a missing mount succeeded")
	}
}

func TestUnplannedMountIsRolledBack(t *testing.T) {
	e, spec, run := hotSession(t, func(s *Spec) { s.RogueMount = true })
	d := extraDir(t, e, "x", map[string]string{"f": "1"})
	_, err := AddMount(e.base, spec.ID, d, "", false)
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("got %v", err)
	}
	if out := run(`ls /workspaces/x 2>&1; echo`); strings.Contains(out, "f\n") {
		t.Fatalf("the mount survived the rollback: %s", out)
	}
	if st, _ := Query(e.base, spec.ID); len(st.Mounts) != 1 {
		t.Fatalf("plan kept the rolled-back mount: %+v", st.Mounts)
	}
}
