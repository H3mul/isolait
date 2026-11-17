package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/H3mul/isolait/internal/trust"
)

func ptr[T any](v T) *T { return &v }

func TestResolvePrecedenceAndLists(t *testing.T) {
	global := Layer{Leader: ptr("ctrl-a"), MaxPortRange: ptr(100), Tools: []string{"/opt/a", "/opt/b"}, Env: []string{"A"}}
	local := Layer{MaxPortRange: ptr(200), Tools: []string{"/opt/b", "/opt/c"}, InheritPath: ptr(true)}
	flags := Layer{MaxPortRange: ptr(300), Env: []string{"B"}}
	got := Resolve(global, local, flags)
	want := Config{
		Leader:       "ctrl-a",
		Tools:        []string{"/opt/a", "/opt/b", "/opt/c"},
		Env:          []string{"A", "B"},
		InheritPath:  true,
		MaxPortRange: 300,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
	if d := Resolve(); d.Leader != `ctrl-\` || d.MaxPortRange != 1024 || d.InheritEnv || d.AllowUserns {
		t.Fatalf("bad defaults %+v", d)
	}
}

func TestParseErrorsNameFileAndKey(t *testing.T) {
	tests := []struct{ name, body, want string }{
		{"unknown key", "bogus = 1\n", `cfg: unknown key "bogus"`},
		{"wrong type", "max_port_range = \"many\"\n", `cfg: key "max_port_range"`},
		{"range", "max_port_range = 0\n", `cfg: key "max_port_range"`},
		{"leader", "leader = \"F5\"\n", `cfg: key "leader"`},
		{"relative tool", "tools = [\"bin\"]\n", `cfg: key "tools"`},
		{"unclean tool", "tools = [\"/opt/../etc\"]\n", `cfg: key "tools"`},
		{"env name", "env = [\"A=B\"]\n", `cfg: key "env"`},
		{"syntax", "leader = \n", "cfg: line 1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse("cfg", []byte(tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestParseValid(t *testing.T) {
	l, err := Parse("cfg", []byte("leader = \"ctrl-\\\\\"\ntools = [\"/opt/x\"]\nenv = [\"HOME_X\"]\ninherit_env = false\nallow_userns = true\nmax_port_range = 64\n"))
	if err != nil {
		t.Fatal(err)
	}
	if *l.Leader != `ctrl-\` || !*l.AllowUserns || *l.MaxPortRange != 64 || l.Tools[0] != "/opt/x" {
		t.Fatalf("%+v", l)
	}
}

// fixture builds a global dir, a state dir and a workspace, optionally with a workspace config.
type fixture struct {
	paths   Paths
	workdir string
	tr      *trust.Store
}

func newFixture(t *testing.T, global, workspace string) fixture {
	t.Helper()
	root := t.TempDir()
	f := fixture{
		paths:   Paths{GlobalDir: filepath.Join(root, "cfg"), StateDir: filepath.Join(root, "state")},
		workdir: filepath.Join(root, "ws"),
	}
	f.tr = trust.Open(f.paths.StateDir)
	must(t, os.MkdirAll(f.workdir, 0o755))
	if global != "" {
		must(t, os.MkdirAll(f.paths.GlobalDir, 0o755))
		must(t, os.WriteFile(filepath.Join(f.paths.GlobalDir, FileName), []byte(global), 0o644))
	}
	if workspace != "" {
		f.writeWorkspace(t, workspace)
	}
	return f
}

func (f fixture) writeWorkspace(t *testing.T, body string) {
	t.Helper()
	must(t, os.MkdirAll(filepath.Join(f.workdir, WorkspaceDir), 0o755))
	must(t, os.WriteFile(filepath.Join(f.workdir, WorkspaceDir, FileName), []byte(body), 0o644))
}

func (f fixture) load(t *testing.T, flags Layer) (Result, error) {
	t.Helper()
	return Load(f.paths, f.workdir, flags, f.tr)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// A freshly cloned repository ships a hostile config: nothing from it may apply until it is trusted.
const hostile = "allow_userns = true\ninherit_env = true\ninherit_path = true\ntools = [\"/\"]\nmax_port_range = 65535\n"

func TestUntrustedWorkspaceConfigIgnoredEntirely(t *testing.T) {
	f := newFixture(t, "max_port_range = 50\n", hostile)
	res, err := f.load(t, Layer{})
	must(t, err)
	if want := Resolve(Layer{MaxPortRange: ptr(50)}); !reflect.DeepEqual(res.Config, want) {
		t.Fatalf("untrusted config leaked: %+v", res.Config)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "not trusted") {
		t.Fatalf("warnings %v", res.Warnings)
	}
}

func TestUntrustedMalformedConfigIsIgnoredNotParsed(t *testing.T) {
	f := newFixture(t, "", "this is = not [ valid toml\n")
	res, err := f.load(t, Layer{})
	if err != nil || len(res.Warnings) != 1 {
		t.Fatalf("err=%v warnings=%v", err, res.Warnings)
	}
}

func TestTrustAppliesAndModificationRevokes(t *testing.T) {
	body := "max_port_range = 77\ninherit_path = true\n"
	f := newFixture(t, "", body)
	must(t, f.tr.Add(trust.Sum([]byte(body)), "x"))

	res, err := f.load(t, Layer{})
	must(t, err)
	if res.Config.MaxPortRange != 77 || !res.Config.InheritPath || len(res.Warnings) != 0 {
		t.Fatalf("trusted config not applied: %+v %v", res.Config, res.Warnings)
	}

	f.writeWorkspace(t, body+"allow_userns = true\n") // same path, different content
	res, err = f.load(t, Layer{})
	must(t, err)
	if res.Config.AllowUserns || res.Config.MaxPortRange != 1024 || len(res.Warnings) != 1 {
		t.Fatalf("modified file still trusted: %+v %v", res.Config, res.Warnings)
	}
}

func TestTrustedConfigStillValidated(t *testing.T) {
	body := "bogus = 1\n"
	f := newFixture(t, "", body)
	must(t, f.tr.Add(trust.Sum([]byte(body)), "x"))
	if _, err := f.load(t, Layer{}); err == nil || !strings.Contains(err.Error(), "unknown key") || !strings.Contains(err.Error(), WorkspaceDir) {
		t.Fatalf("got %v", err)
	}
}

func TestFlagsBeatTrustedLocal(t *testing.T) {
	body := "max_port_range = 77\n"
	f := newFixture(t, "max_port_range = 10\n", body)
	must(t, f.tr.Add(trust.Sum([]byte(body)), "x"))
	res, err := f.load(t, Layer{MaxPortRange: ptr(5)})
	must(t, err)
	if res.Config.MaxPortRange != 5 {
		t.Fatalf("%+v", res.Config)
	}
}

func TestGlobalConfigErrorNamesFile(t *testing.T) {
	f := newFixture(t, "nope = 1\n", "")
	_, err := f.load(t, Layer{})
	if err == nil || !strings.Contains(err.Error(), filepath.Join(f.paths.GlobalDir, FileName)) {
		t.Fatalf("got %v", err)
	}
}

func TestWorkspaceSymlinksRefused(t *testing.T) {
	f := newFixture(t, "", "")
	secret := filepath.Join(t.TempDir(), "secret")
	must(t, os.WriteFile(secret, []byte("max_port_range = 9\n"), 0o600))

	// config file is a symlink
	must(t, os.MkdirAll(filepath.Join(f.workdir, WorkspaceDir), 0o755))
	must(t, os.Symlink(secret, filepath.Join(f.workdir, WorkspaceDir, FileName)))
	if _, err := f.load(t, Layer{}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked config accepted: %v", err)
	}

	// .isolait itself is a symlink
	f2 := newFixture(t, "", "")
	other := t.TempDir()
	must(t, os.WriteFile(filepath.Join(other, FileName), []byte("max_port_range = 9\n"), 0o600))
	must(t, os.Symlink(other, filepath.Join(f2.workdir, WorkspaceDir)))
	if _, err := f2.load(t, Layer{}); err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Fatalf("symlinked .isolait accepted: %v", err)
	}
}

func TestNoConfigAnywhereGivesDefaults(t *testing.T) {
	f := newFixture(t, "", "")
	res, err := f.load(t, Layer{})
	must(t, err)
	if !reflect.DeepEqual(res.Config, Defaults()) || len(res.Warnings) != 0 {
		t.Fatalf("%+v %v", res.Config, res.Warnings)
	}
}

func TestCorruptTrustStoreFailsLoudly(t *testing.T) {
	f := newFixture(t, "", "max_port_range = 1\n")
	must(t, os.MkdirAll(f.paths.StateDir, 0o700))
	must(t, os.WriteFile(filepath.Join(f.paths.StateDir, "trust.json"), []byte("{broken"), 0o600))
	if _, err := f.load(t, Layer{}); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("got %v", err)
	}
}
