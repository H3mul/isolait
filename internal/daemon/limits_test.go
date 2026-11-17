package daemon

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/H3mul/isolait/internal/session"
)

func TestScopeArgs(t *testing.T) {
	got := ScopeArgs("isolait-api-a3f9", Limits{Pids: 4096}, "/usr/bin/isolait")
	want := []string{"--user", "--scope", "--quiet", "--collect", "--unit=isolait-api-a3f9", "-p", "TasksMax=4096", "--", "/usr/bin/isolait", "_spawn"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
	got = ScopeArgs("u", Limits{Pids: 100, Memory: "8G", CPU: "200%"}, "/x")
	for _, w := range []string{"TasksMax=100", "MemoryMax=8G", "CPUQuota=200%"} {
		if !slices.Contains(got, w) {
			t.Errorf("missing %s in %v", w, got)
		}
	}
	for _, g := range ScopeArgs("u", Limits{Pids: 100}, "/x") {
		if strings.HasPrefix(g, "MemoryMax") || strings.HasPrefix(g, "CPUQuota") {
			t.Errorf("unset limits must not be passed: %s", g)
		}
	}
}

func TestReadUsage(t *testing.T) {
	fs := t.TempDir()
	cg := "/user.slice/isolait-x.scope"
	dir := filepath.Join(fs, cg)
	os.MkdirAll(dir, 0o755)
	write := func(name, v string) { os.WriteFile(filepath.Join(dir, name), []byte(v+"\n"), 0o644) }
	write("pids.current", "12")
	write("pids.max", "4096")
	write("memory.current", "1048576")
	write("memory.max", "max")

	st := ReadUsage(fs, "0::"+cg)
	if !st.Available || st.PidsCurrent != 12 || st.PidsMax != 4096 || st.MemoryCurrent != 1<<20 || st.MemoryMax != 0 {
		t.Errorf("%+v", st)
	}
	write("memory.max", "536870912")
	if st = ReadUsage(fs, "0::"+cg); st.MemoryMax != 536870912 {
		t.Errorf("memory.max %d", st.MemoryMax)
	}
	if st = ReadUsage(fs, "0::/does/not/exist"); st.Available || !strings.Contains(st.Reason, "cannot read") {
		t.Errorf("missing cgroup: %+v", st)
	}
	if st = ReadUsage(fs, "12:pids:/legacy"); st.Available || !strings.Contains(st.Reason, "cgroup v2") {
		t.Errorf("cgroup v1 line: %+v", st)
	}
}

// limits.required: when limits cannot be applied the start is refused, before any process starts.
func TestRequiredLimitsRefuseToStartWithoutSystemd(t *testing.T) {
	base := shortBase(t)
	id, err := session.Create(base, "/x/api")
	if err != nil {
		t.Fatal(err)
	}
	err = Launch(Spec{ID: id, RuntimeBase: base, Limits: Limits{Pids: 4096, Required: true}}, "/nonexistent")
	if err == nil || !strings.Contains(err.Error(), "limits.required") || !strings.Contains(err.Error(), "systemd-run") {
		t.Fatalf("got %v", err)
	}
	err = Launch(Spec{ID: id, RuntimeBase: base, SystemdRun: "/bin/false", Limits: Limits{Pids: 4096, Required: true}}, "/nonexistent")
	if err == nil || !strings.Contains(err.Error(), "limits.required") {
		t.Fatalf("a failing scope with required limits must refuse to start: %v", err)
	}
}
