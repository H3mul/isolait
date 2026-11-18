package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSeedHome(t *testing.T) {
	skel := func(t *testing.T) string {
		d := t.TempDir()
		write(t, filepath.Join(d, ".bashrc"), "skel bashrc\n", 0o644)
		write(t, filepath.Join(d, ".profile"), "skel profile\n", 0o644)
		write(t, filepath.Join(d, ".config/app/x"), "nested\n", 0o644)
		return d
	}
	t.Run("empty home", func(t *testing.T) {
		home := t.TempDir()
		if err := SeedHome(home, skel(t)); err != nil {
			t.Fatal(err)
		}
		if readFile(t, filepath.Join(home, ".bashrc")) != "skel bashrc\n" || readFile(t, filepath.Join(home, ".config/app/x")) != "nested\n" {
			t.Error("skeleton not copied")
		}
	})
	t.Run("partial home gets only the missing files", func(t *testing.T) {
		home := t.TempDir()
		write(t, filepath.Join(home, ".profile"), "mine\n", 0o600)
		if err := SeedHome(home, skel(t)); err != nil {
			t.Fatal(err)
		}
		if readFile(t, filepath.Join(home, ".profile")) != "mine\n" || readFile(t, filepath.Join(home, ".bashrc")) != "skel bashrc\n" {
			t.Error("partial home mishandled")
		}
	})
	t.Run("customised file is kept", func(t *testing.T) {
		home := t.TempDir()
		write(t, filepath.Join(home, ".bashrc"), "custom\n", 0o644)
		for i := 0; i < 2; i++ { // and stays so on every later start
			if err := SeedHome(home, skel(t)); err != nil {
				t.Fatal(err)
			}
		}
		if readFile(t, filepath.Join(home, ".bashrc")) != "custom\n" {
			t.Error("customised .bashrc overwritten")
		}
	})
	t.Run("no skeleton uses the embedded set", func(t *testing.T) {
		for _, s := range []string{filepath.Join(t.TempDir(), "absent"), t.TempDir()} {
			home := t.TempDir()
			if err := SeedHome(home, s); err != nil {
				t.Fatal(err)
			}
			for name := range embeddedSkel {
				if _, err := os.Stat(filepath.Join(home, name)); err != nil {
					t.Errorf("%s missing: %v", name, err)
				}
			}
			if !strings.Contains(readFile(t, filepath.Join(home, ".bashrc")), "HISTCONTROL") {
				t.Error("embedded .bashrc lacks history settings")
			}
		}
	})
	t.Run("a symlink in the home is not followed", func(t *testing.T) {
		home, other := t.TempDir(), filepath.Join(t.TempDir(), "victim")
		mustSymlink(t, other, filepath.Join(home, ".bashrc"))
		if err := SeedHome(home, skel(t)); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(other); err == nil {
			t.Error("wrote through a symlink")
		}
	})
}
