package trust

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAddAndIsTrusted(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s := Open(dir)
	sum := Sum([]byte("a = 1\n"))

	if ok, err := s.IsTrusted(sum); err != nil || ok {
		t.Fatalf("empty store: ok=%v err=%v", ok, err)
	}
	if err := s.Add(sum, "/ws/.isolait/config"); err != nil {
		t.Fatal(err)
	}
	if ok, err := Open(dir).IsTrusted(sum); err != nil || !ok {
		t.Fatalf("not persisted: ok=%v err=%v", ok, err)
	}
	if ok, _ := s.IsTrusted(Sum([]byte("a = 2\n"))); ok {
		t.Fatal("different content must not be trusted")
	}
	fi, err := os.Stat(filepath.Join(dir, "trust.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("trust.json mode %v err %v, want 0600", fi.Mode().Perm(), err)
	}
	di, _ := os.Stat(dir)
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("state dir mode %v, want 0700", di.Mode().Perm())
	}
}

func TestTrustIsByContentNotPath(t *testing.T) {
	s := Open(t.TempDir())
	body := []byte("x = 1\n")
	if err := s.Add(Sum(body), "/one/path"); err != nil {
		t.Fatal(err)
	}
	// same content at another path is trusted; that is the documented semantics
	if ok, _ := s.IsTrusted(Sum(body)); !ok {
		t.Fatal("same content should be trusted regardless of path")
	}
}

func TestBadStores(t *testing.T) {
	for name, body := range map[string]string{"garbage": "{nope", "version": `{"version":2,"entries":{}}`} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			os.WriteFile(filepath.Join(dir, "trust.json"), []byte(body), 0o600)
			if _, err := Open(dir).IsTrusted("x"); err == nil {
				t.Fatal("expected an error")
			}
			if err := Open(dir).Add("x", "p"); err == nil {
				t.Fatal("Add must not overwrite a store it cannot read")
			}
		})
	}
}
