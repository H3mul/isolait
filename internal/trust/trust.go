// Package trust records which workspace config contents the user has approved. Trust is keyed by the
// SHA-256 of the file content, never by path: replacing a trusted file with different content un-trusts it.
package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Sum returns the hex SHA-256 of data.
func Sum(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

// Store is the trust list in the global state directory (never mounted in the sandbox).
type Store struct{ path string }

// Open returns the store at stateDir/trust.json. Nothing is read or created until it is used.
func Open(stateDir string) *Store { return &Store{filepath.Join(stateDir, "trust.json")} }

type entry struct {
	Path      string    `json:"path"` // where it was first trusted; informational only
	TrustedAt time.Time `json:"trusted_at"`
}

type file struct {
	Version int              `json:"version"`
	Entries map[string]entry `json:"entries"`
}

func (s *Store) read() (file, error) {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return file{Version: 1, Entries: map[string]entry{}}, nil
	}
	if err != nil {
		return file{}, err
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return file{}, fmt.Errorf("trust store %s is corrupt: %w", s.path, err)
	}
	if f.Version != 1 {
		return file{}, fmt.Errorf("trust store %s has unsupported version %d", s.path, f.Version)
	}
	if f.Entries == nil {
		f.Entries = map[string]entry{}
	}
	return f, nil
}

// IsTrusted reports whether content with this sum was approved.
func (s *Store) IsTrusted(sum string) (bool, error) {
	f, err := s.read()
	if err != nil {
		return false, err
	}
	_, ok := f.Entries[sum]
	return ok, nil
}

// Add approves content with this sum. path is recorded for humans only.
func (s *Store) Add(sum, path string) error {
	f, err := s.read()
	if err != nil {
		return err
	}
	f.Entries[sum] = entry{Path: path, TrustedAt: time.Now().UTC()}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "trust-*.tmp") // 0600
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}
