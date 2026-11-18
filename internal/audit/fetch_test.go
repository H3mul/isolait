package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fetch.sh against local file:// URLs: a good file is stored 0555 under its checksum, a tampered or missing file is
// refused and leaves nothing behind, and a cached file is re-verified.
func TestFetchScript(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("no curl")
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	os.WriteFile(good, []byte("hello"), 0o644)
	sum := sha256.Sum256([]byte("hello"))
	sha := hex.EncodeToString(sum[:])
	lock := func(lines ...string) string {
		p := filepath.Join(dir, "lock")
		os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
		return p
	}
	run := func(l string) (string, error) {
		cmd := exec.Command("../../scripts/audit/fetch.sh")
		cmd.Env = append(os.Environ(), "LOCK="+l, "XDG_CACHE_HOME="+filepath.Join(dir, "cache"))
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	stored := filepath.Join(dir, "cache", "isolait-audit", sha, "good")

	if out, err := run(lock("# comment", "good 1 file://"+good+" "+sha+" 5")); err != nil {
		t.Fatalf("good file refused: %v\n%s", err, out)
	}
	fi, err := os.Stat(stored)
	if err != nil || fi.Mode().Perm() != 0o555 {
		t.Fatalf("stored file: %v %v, want mode 0555", err, fi)
	}
	// cached: still ok when the source is gone
	os.Remove(good)
	if out, err := run(lock("good 1 file://" + good + " " + sha + " 5")); err != nil || !strings.Contains(out, "cached") {
		t.Errorf("cache not used: %v\n%s", err, out)
	}
	// tampered cache entry is replaced or refused, never trusted
	os.Chmod(filepath.Dir(stored), 0o755)
	os.Chmod(stored, 0o644)
	os.WriteFile(stored, []byte("evil"), 0o644)
	if out, err := run(lock("good 1 file://" + good + " " + sha + " 5")); err == nil {
		t.Errorf("tampered cache entry with no source accepted:\n%s", out)
	}
	if _, err := os.Stat(stored); err == nil {
		t.Error("tampered file left in the cache")
	}
	// tampered download
	bad := filepath.Join(dir, "bad")
	os.WriteFile(bad, []byte("not hello"), 0o644)
	out, err := run(lock("good 1 file://" + bad + " " + sha + " 5"))
	if err == nil || !strings.Contains(out, "sha256") {
		t.Errorf("tampered download accepted: %v\n%s", err, out)
	}
	if _, err := os.Stat(stored); err == nil {
		t.Error("tampered download left in the cache")
	}
	// missing file
	if out, err := run(lock("good 1 file://" + filepath.Join(dir, "nope") + " " + sha + " 5")); err == nil {
		t.Errorf("missing file accepted:\n%s", out)
	}
}
