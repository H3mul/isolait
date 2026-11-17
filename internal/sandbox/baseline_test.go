package sandbox

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/H3mul/isolait/internal/plan"
)

func testSpec() Spec {
	return Spec{HostHome: "/home/fake", AgentHome: "/state/homes/agent", Stage: "/run/rt/stage", UID: 1000, GID: 1000,
		Env: []string{"HOME=/home/fake", "PATH=/usr/bin"}}
}

func TestHardeningFlags(t *testing.T) {
	s := testSpec()
	a := hardening(s)
	for _, want := range []string{"--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net", "--die-with-parent", "--new-session", "--as-pid-1", "--clearenv", "--disable-userns"} {
		if !slices.Contains(a, want) {
			t.Errorf("missing %s in %v", want, a)
		}
	}
	if i := slices.Index(a, "--cap-drop"); i < 0 || a[i+1] != "ALL" {
		t.Errorf("capabilities not dropped: %v", a)
	}
	if i := slices.Index(a, "--uid"); i < 0 || a[i+1] != "1000" {
		t.Errorf("uid not pinned: %v", a)
	}
	s.AllowUserns = true
	if slices.Contains(hardening(s), "--disable-userns") {
		t.Error("--allow-userns must drop --disable-userns")
	}
}

func TestBaselinePlanExposesOnlyWhatItShould(t *testing.T) {
	s := testSpec()
	p, err := BuildPlan(s)
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	var sawDev, sawProc, sawTmp, sawHome, sawStage bool
	for _, e := range p.Entries() {
		switch e.Kind {
		case plan.Dev:
			sawDev = true
		case plan.Proc:
			sawProc = true
		case plan.Tmpfs:
			sawTmp = e.Dst == "/tmp"
		case plan.Bind:
			// the only writable binds: the per-agent home and the /workspaces stage
			switch e.Dst {
			case s.HostHome:
				sawHome = e.Src == s.AgentHome
			case Workspaces:
				sawStage = e.Src == s.Stage
			default:
				t.Errorf("unexpected writable bind %+v", e)
			}
		case plan.RoBind:
			if !strings.HasPrefix(e.Src, "/etc/") && !slices.Contains(SystemDirs, e.Src) && !strings.HasPrefix(e.Src, "/usr/") && !strings.HasPrefix(e.Src, "/nix/") {
				t.Errorf("read-only bind of %q is neither a system dir nor minimal /etc", e.Src)
			}
		}
		if home != "" && home != "/" && (e.Src == home || strings.HasPrefix(e.Src, home+"/")) {
			t.Errorf("host home content %q is exposed", e.Src)
		}
		if e.Src == "/" || e.Src == "/root" || strings.HasPrefix(e.Src, "/root/") || strings.HasPrefix(e.Src, "/var/run/docker") || e.Src == "/run" {
			t.Errorf("forbidden source %q", e.Src)
		}
	}
	if !sawDev || !sawProc || !sawTmp || !sawHome || !sawStage {
		t.Errorf("baseline incomplete: dev=%v proc=%v tmp=%v home=%v stage=%v", sawDev, sawProc, sawTmp, sawHome, sawStage)
	}
}

func TestArgsOrderAndEnv(t *testing.T) {
	s := testSpec()
	s.Chdir = "/workspaces/api"
	p, _ := BuildPlan(s)
	a := Args(s, p, "--info-fd", "3")
	idx := func(x string) int { return slices.Index(a, x) }
	if idx("--clearenv") > idx("--setenv") || idx("--setenv") < 0 {
		t.Errorf("--clearenv must precede --setenv: %v", a)
	}
	if !slices.Contains(a, "--chdir") || !slices.Contains(a, "--info-fd") {
		t.Errorf("missing chdir or info-fd: %v", a)
	}
	// every setenv pair comes from Spec.Env, nothing implicit
	var got []string
	for i, x := range a {
		if x == "--setenv" {
			got = append(got, a[i+1]+"="+a[i+2])
		}
	}
	if !slices.Equal(got, s.Env) {
		t.Errorf("setenv %v want %v", got, s.Env)
	}
}

func TestBuildEnv(t *testing.T) {
	host := []string{"AWS_SECRET_ACCESS_KEY=s3cret", "FOO=bar", "SSH_AUTH_SOCK=/run/agent", "HOME=/home/real", "EMPTY="}
	base := map[string]string{"HOME": "/home/fake", "PATH": "/usr/bin"}
	tests := []struct {
		name    string
		names   []string
		inherit bool
		want    []string
	}{
		{"default: secrets absent", nil, false, []string{"HOME=/home/fake", "PATH=/usr/bin"}},
		{"declared variable", []string{"FOO"}, false, []string{"FOO=bar", "HOME=/home/fake", "PATH=/usr/bin"}},
		{"declared but unset on host", []string{"NOPE"}, false, []string{"HOME=/home/fake", "PATH=/usr/bin"}},
		{"explicit agent socket", []string{"SSH_AUTH_SOCK"}, false, []string{"HOME=/home/fake", "PATH=/usr/bin", "SSH_AUTH_SOCK=/run/agent"}},
		{"inherit drops agent sockets", nil, true, []string{"AWS_SECRET_ACCESS_KEY=s3cret", "EMPTY=", "FOO=bar", "HOME=/home/fake", "PATH=/usr/bin"}},
		{"inherit plus explicit socket", []string{"SSH_AUTH_SOCK"}, true, []string{"AWS_SECRET_ACCESS_KEY=s3cret", "EMPTY=", "FOO=bar", "HOME=/home/fake", "PATH=/usr/bin", "SSH_AUTH_SOCK=/run/agent"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildEnv(host, tc.names, tc.inherit, base)
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("got %v (%v)\nwant %v", got, err, tc.want)
			}
		})
	}
	if _, err := BuildEnv(host, []string{"A=B"}, false, nil); err == nil {
		t.Error("a name containing = must be rejected")
	}
}

// 3.10: the global config dir, isolait's state dir (apart from the one per-agent home inside it) and the
// runtime dir are never part of the sandbox, not even as an ancestor of a bound path.
func TestIsolaitDirsNeverExposed(t *testing.T) {
	cfg, state, rt := "/home/fake/.config/isolait", "/home/fake/.local/state/isolait", "/run/user/1000/isolait"
	s := testSpec()
	s.AgentHome = state + "/homes/claude"
	s.Stage = rt + "/api-a3f9/stage"
	p, err := BuildPlan(s)
	if err != nil {
		t.Fatal(err)
	}
	under := func(path, dir string) bool { return path == dir || strings.HasPrefix(path, dir+"/") }
	for _, e := range p.Entries() {
		if e.Src == "" {
			continue
		}
		for _, dir := range []string{cfg, state, rt} {
			ancestor := under(dir, e.Src) // binding a parent of a protected dir would expose it
			inside := under(e.Src, dir)
			if ancestor || (inside && e.Src != s.AgentHome && e.Src != s.Stage) {
				t.Errorf("plan entry %+v exposes or contains the protected directory %s", e, dir)
			}
		}
	}
}
