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
	root := Root()
	root.ResetCommands()
	root.AddCommand(sessionCmds(d)...)
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
	if _, err = run(t, d, "status"); err == nil || !strings.Contains(err.Error(), "no session targeted") || !strings.Contains(err.Error(), id) {
		t.Errorf("no target: %v", err)
	}
	if err := daemon.SetLast(base, id); err != nil {
		t.Fatal(err)
	}
	if out, err = run(t, d, "status"); err != nil || !strings.Contains(out, id) {
		t.Errorf("last attached should be the default target: %v %q", err, out)
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

func TestStartRequiresAnAgent(t *testing.T) {
	d, _ := testDeps(t)
	if _, err := run(t, d, "start"); err == nil {
		t.Error("start without an agent command accepted")
	}
}
