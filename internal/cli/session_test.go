package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/H3mul/isolait/internal/config"
	"github.com/H3mul/isolait/internal/ctl"
	"github.com/H3mul/isolait/internal/daemon"
	"github.com/H3mul/isolait/internal/session"
)

func testDeps(t *testing.T) (deps, string) {
	t.Helper()
	base, err := os.MkdirTemp("", "iso")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	return deps{
		paths: func() (config.Paths, error) {
			return config.Paths{GlobalDir: base + "/cfg", StateDir: base + "/state"}, nil
		},
		runtime: func() (string, error) { return base, nil },
	}, base
}

func fakeSession(t *testing.T, base, workdir string) string {
	t.Helper()
	id, err := session.Create(base, workdir)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := ctl.Listen(session.SocketPath(base, id))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	os.WriteFile(filepath.Join(session.Dir(base, id), "pid"), []byte("1\n"), 0o600)
	st := daemon.Status{ID: id, State: "idle", Started: time.Now(), Workdir: workdir,
		Mounts: []daemon.MountInfo{{Path: "/workspaces/p", Src: workdir, Mode: "ro"}}, Roots: []string{"/opt/tc"}, Ports: []int{8080}, EnvNames: []string{"HOME", "PATH"}, Warnings: []string{"a -> b will be a dangling link"}}
	go srv.Serve(func(r ctl.Request) (any, error) {
		if r.Op == "status" {
			return st, nil
		}
		if r.Op == "stop" {
			go session.Remove(base, id)
		}
		return "ok", nil
	})
	return id
}

func run(t *testing.T, d deps, args ...string) (string, error) {
	t.Helper()
	root := rootWith(d)
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs(args)
	err := root.Execute()
	return out.String() + errb.String(), err
}

func TestListStatusStop(t *testing.T) {
	d, base := testDeps(t)
	out, err := run(t, d, "list")
	if err != nil || !strings.Contains(out, "no sessions running") {
		t.Fatalf("empty list: %v %q", err, out)
	}
	id := fakeSession(t, base, "/work/p")

	out, err = run(t, d, "list")
	if err != nil || !strings.Contains(out, id) || !strings.Contains(out, "p:ro") {
		t.Fatalf("list: %v %q", err, out)
	}
	for _, via := range [][]string{{"status", id}, {"--sid", id, "status"}} {
		out, err = run(t, d, via...)
		if err != nil {
			t.Fatalf("%v: %v", via, err)
		}
		for _, want := range []string{id, "idle", "/workspaces/p", "ro", "/opt/tc", "8080", "HOME, PATH", "warning  a -> b"} {
			if !strings.Contains(out, want) {
				t.Errorf("%v: status lacks %q:\n%s", via, want, out)
			}
		}
	}
	if out, err = run(t, d, "status"); err != nil || !strings.Contains(out, id) {
		t.Errorf("the only session is the default target: %v %q", err, out)
	}
	if out, err = run(t, d, "stop", id); err != nil || !strings.Contains(out, "stopped "+id) {
		t.Errorf("stop: %v %q", err, out)
	}
	if out, _ = run(t, d, "list"); !strings.Contains(out, "no sessions running") {
		t.Errorf("stopped session still listed: %q", out)
	}
}

func TestCheckWorkdir(t *testing.T) {
	root := t.TempDir()
	cfg, state, rt := filepath.Join(root, "cfg"), filepath.Join(root, "state"), filepath.Join(root, "rt")
	for _, d := range []string{cfg, state, rt, filepath.Join(state, "homes"), filepath.Join(root, "proj")} {
		os.MkdirAll(d, 0o755)
	}
	p := config.Paths{GlobalDir: cfg, StateDir: state}
	home, _ := os.UserHomeDir()
	tests := []struct {
		name, dir string
		wantErr   string
	}{
		{"ordinary project", filepath.Join(root, "proj"), ""},
		{"root", "/", "refusing"},
		{"home", home, "refusing"},
		{"the config dir", cfg, "isolait's own directory"},
		{"inside the state dir", filepath.Join(state, "homes"), "isolait's own directory"},
		{"the runtime dir", rt, "isolait's own directory"},
		{"a parent of all of them", root, "isolait's own directory"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkWorkdir(tc.dir, p, rt)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestStartWithoutAnAgentRunsBash(t *testing.T) {
	if got := agentOrShell(nil); strings.Join(got, " ") != "bash" {
		t.Errorf("no agent: %q", got)
	}
	if got := agentOrShell([]string{"claude", "-p"}); strings.Join(got, " ") != "claude -p" {
		t.Errorf("an agent is kept as given: %q", got)
	}
	// both forms are accepted by the command line: `start` and `start -d`
	root := rootWith(realDeps())
	start, _, _ := root.Find([]string{"start"})
	for _, args := range [][]string{{}, {"-d"}} {
		if err := start.ParseFlags(args); err != nil {
			t.Fatal(err)
		}
		if err := start.ValidateArgs(start.Flags().Args()); err != nil {
			t.Errorf("start %v rejected: %v", args, err)
		}
	}
}

func TestTokenize(t *testing.T) {
	tests := []struct {
		in      string
		want    []string
		wantErr bool
	}{
		{"status", []string{"status"}, false},
		{"  mount   ~/x  --ro ", []string{"mount", "~/x", "--ro"}, false},
		{`mount "my dir/x" --as 'a b'`, []string{"mount", "my dir/x", "--as", "a b"}, false},
		{`a\ b c`, []string{"a b", "c"}, false},
		{`say "he said \"hi\""`, []string{"say", `he said "hi"`}, false},
		{`''`, []string{""}, false},
		{"", nil, false},
		{`mount "oops`, nil, true},
		{`mount 'oops`, nil, true},
		{`trailing\`, nil, true},
	}
	for _, tc := range tests {
		got, err := tokenize(tc.in)
		if (err != nil) != tc.wantErr || strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
			t.Errorf("tokenize(%q) = %q, %v; want %q (err %v)", tc.in, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestPromptRunnerTargetsTheCurrentSessionAndRefusesAttaching(t *testing.T) {
	d, base := testDeps(t)
	id := fakeSession(t, base, "/work/p")
	run := promptRunner(d, id)

	if out := run("status"); !strings.Contains(out, id) || !strings.Contains(out, "idle") {
		t.Errorf("status without --sid must target the current session: %q", out)
	}
	if out := run("isolait list"); !strings.Contains(out, id) {
		t.Errorf("list: %q", out)
	}
	for _, cmd := range []string{"start sh", "attach", "exec -- sh", "daemon", "init", "preflight"} {
		if out := run(cmd); !strings.Contains(out, "not available in the prompt") {
			t.Errorf("%q must be refused in the prompt: %q", cmd, out)
		}
	}
	if out := run("nonsense"); !strings.Contains(out, "unknown command") {
		t.Errorf("an unknown command: %q", out)
	}
	if out := run(`status "unterminated`); !strings.Contains(out, "unterminated quote") {
		t.Errorf("a bad line: %q", out)
	}
	if out := run("   "); out != "" {
		t.Errorf("an empty line: %q", out)
	}
}
