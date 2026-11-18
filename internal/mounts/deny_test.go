package mounts

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func check(t *testing.T, d *DenyList, src string) error {
	t.Helper()
	fd, err := OpenSource(src)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return d.Check(fd)
}

func mk(t *testing.T, p ...string) string {
	t.Helper()
	d := filepath.Join(p...)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDenyList(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	home := mk(t, root, "home", "u")
	state := mk(t, root, "state", "isolait")
	proj := mk(t, home, "proj")
	d, err := NewDenyList([]string{home}, []string{state, filepath.Join(root, "missing")})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, src, want string // want: substring of the error, "" for accepted
	}{
		{"project inside home", proj, ""},
		{"home itself", home, "protected"},
		{"parent of home", filepath.Dir(home), "contains"},
		{"filesystem root", "/", "root"},
		{"state dir", state, "protected"},
		{"inside state dir", mk(t, state, "homes", "x"), "inside"},
		{"parent of state dir", filepath.Dir(state), "contains"},
		{"dotdot path to home", filepath.Join(proj, ".."), "protected"},
		{"file source", filepath.Join(root, "file"), "directory"},
	} {
		if tc.name == "file source" {
			os.WriteFile(tc.src, nil, 0o644)
		}
		err := check(t, d, tc.src)
		if tc.want == "" && err != nil {
			t.Errorf("%s: unexpected error %v", tc.name, err)
		}
		if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: got %v, want an error containing %q", tc.name, err, tc.want)
		}
	}
}

// A symlink or bind-style alias to a protected directory is still that directory: identity is device+inode.
func TestDenyListSeesThroughSymlinks(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	state := mk(t, root, "state")
	sub := mk(t, state, "deep")
	link := filepath.Join(root, "innocent")
	os.Symlink(state, link)
	d, _ := NewDenyList(nil, []string{state})
	for _, src := range []string{link, filepath.Join(link, "deep"), sub} {
		if check(t, d, src) == nil {
			t.Errorf("%s was accepted but is inside the excluded directory", src)
		}
	}
}

// The path is validated through a descriptor: swapping the path for a symlink after OpenSource does not change
// what the descriptor refers to.
func TestOpenSourceDescriptorIsStable(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	good := mk(t, root, "good")
	bad := mk(t, root, "bad")
	d, _ := NewDenyList(nil, []string{bad})
	fd, err := OpenSource(good)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	os.Remove(good)
	os.Symlink(bad, good) // the swap
	if err := d.Check(fd); err != nil {
		t.Fatalf("the descriptor still names the original directory, got %v", err)
	}
	var st1, st2 syscall.Stat_t
	syscall.Fstat(fd, &st1)
	syscall.Stat(bad, &st2)
	if st1.Ino == st2.Ino {
		t.Fatal("descriptor follows the swapped symlink")
	}
	// opening the swapped path now resolves to the excluded directory and is refused
	if check(t, d, good) == nil {
		t.Fatal("swapped symlink to an excluded directory was accepted")
	}
}

func TestCheckPathRefusesInsideExcluded(t *testing.T) {
	d := t.TempDir()
	state, ok := filepath.Join(d, "state"), filepath.Join(d, "opt")
	for _, p := range []string{filepath.Join(state, "bin"), ok} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	dl, err := NewDenyList(nil, []string{state})
	if err != nil {
		t.Fatal(err)
	}
	if err := dl.CheckPath(filepath.Join(state, "bin")); err == nil {
		t.Error("a directory inside the state directory must be refused")
	}
	if err := dl.CheckPath(ok); err != nil {
		t.Errorf("unrelated directory refused: %v", err)
	}
}
