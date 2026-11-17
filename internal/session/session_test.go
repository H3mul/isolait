package session

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestBase(t *testing.T) {
	for in, want := range map[string]string{
		"/home/u/projects/api":          "api",
		"/home/u/my project/":           "my-project",
		"/home/u/.hidden":               "hidden",
		"/":                             "ws",
		"/home/u/é☃":                    "ws",
		"/a/" + strings.Repeat("x", 80): strings.Repeat("x", 24),
		"/a/we..ird":                    "we..ird",
	} {
		if got := Base(in); got != want {
			t.Errorf("Base(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIDFormatAndValidity(t *testing.T) {
	id, err := NewID("/home/u/projects/api", func(string) bool { return false })
	if err != nil || !regexp.MustCompile(`^api-[0-9a-f]{4}$`).MatchString(id) || !ValidID(id) {
		t.Fatalf("id %q err %v", id, err)
	}
	for _, bad := range []string{"", "api", "api-xyz1", "../x-abcd", "a/b-abcd", "api-ABCD", "a..b-abcd"} {
		if ValidID(bad) {
			t.Errorf("ValidID(%q) should be false", bad)
		}
	}
}

func TestNewIDRetriesOnCollisionAndGivesUp(t *testing.T) {
	calls := 0
	id, err := NewID("/x/api", func(string) bool { calls++; return calls < 5 })
	if err != nil || calls != 5 || id == "" {
		t.Fatalf("id=%q calls=%d err=%v", id, calls, err)
	}
	if _, err := NewID("/x/api", func(string) bool { return true }); err == nil {
		t.Fatal("expected failure when every id is taken")
	}
}

func TestCreateGivesDistinctIDsForSameBasename(t *testing.T) {
	base := filepath.Join(t.TempDir(), "rt")
	seen := map[string]bool{}
	for i := 0; i < 200; i++ { // 65536 ids, 200 draws: collisions are retried, never shared
		id, err := Create(base, "/a/api")
		if err != nil {
			t.Fatal(err)
		}
		if seen[id] {
			t.Fatalf("duplicate id %s", id)
		}
		seen[id] = true
	}
	// a different directory with the same name still gets its own id
	id2, err := Create(base, "/b/api")
	if err != nil || seen[id2] {
		t.Fatalf("id2=%q err=%v", id2, err)
	}
	ids, err := List(base)
	if err != nil || len(ids) != 201 {
		t.Fatalf("list: %d ids, err %v", len(ids), err)
	}
	fi, _ := os.Stat(Dir(base, id2))
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("session dir mode %v", fi.Mode().Perm())
	}
	if err := Remove(base, id2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(Dir(base, id2)); !os.IsNotExist(err) {
		t.Fatalf("not removed: %v", err)
	}
	if Remove(base, "../etc") == nil {
		t.Fatal("Remove accepted a path-like id")
	}
}

func TestEnsurePrivateDirRefusals(t *testing.T) {
	root := t.TempDir()

	loose := filepath.Join(root, "loose")
	os.Mkdir(loose, 0o755)
	os.Chmod(loose, 0o755)
	if err := EnsurePrivateDir(loose); err == nil || !strings.Contains(err.Error(), "0700") {
		t.Errorf("group/other-accessible dir accepted: %v", err)
	}

	target := filepath.Join(root, "target")
	os.Mkdir(target, 0o700)
	link := filepath.Join(root, "link")
	os.Symlink(target, link)
	if err := EnsurePrivateDir(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("symlinked dir accepted: %v", err)
	}

	file := filepath.Join(root, "file")
	os.WriteFile(file, nil, 0o600)
	if err := EnsurePrivateDir(file); err == nil {
		t.Error("regular file accepted")
	}

	ok := filepath.Join(root, "new", "private")
	if err := EnsurePrivateDir(ok); err != nil {
		t.Errorf("creating a private dir failed: %v", err)
	}
	if err := EnsurePrivateDir(ok); err != nil {
		t.Errorf("idempotence: %v", err)
	}
}

func TestRuntimeBaseUsesXDG(t *testing.T) {
	x := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", x)
	b, err := RuntimeBase()
	if err != nil || b != filepath.Join(x, "isolait") {
		t.Fatalf("%q %v", b, err)
	}
	t.Setenv("XDG_RUNTIME_DIR", "relative/path") // ignored: must be absolute
	b, err = RuntimeBase()
	if err != nil || !strings.HasPrefix(b, "/tmp/isolait-") {
		t.Fatalf("%q %v", b, err)
	}
}
