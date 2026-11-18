// Package session names sessions and owns their runtime directories. A session id is
// <workdir-basename>-<4 hex>, fixed for the session's life; its runtime directory (control socket and
// pid file) is private to the user and never mounted into the sandbox.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
)

var (
	badChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
	idRe     = regexp.MustCompile(`^[A-Za-z0-9._-]+-[0-9a-f]{4}$`)
)

// maxBase keeps the control socket path well under the 108-byte sockaddr_un limit.
const maxBase = 24

// Base turns a directory name into the id prefix: unsafe characters become '-', never empty.
func Base(workdir string) string {
	b := badChars.ReplaceAllString(filepath.Base(filepath.Clean(workdir)), "-")
	b = strings.Trim(b, "-.")
	if len(b) > maxBase {
		b = strings.TrimRight(b[:maxBase], "-.")
	}
	if b == "" {
		b = "ws"
	}
	return b
}

// NewID returns <base>-<4 hex> for workdir, retrying while taken reports a collision.
func NewID(workdir string, taken func(id string) bool) (string, error) {
	base := Base(workdir)
	for i := 0; i < 64; i++ {
		var r [2]byte
		if _, err := rand.Read(r[:]); err != nil {
			return "", err
		}
		id := base + "-" + hex.EncodeToString(r[:])
		if !taken(id) {
			return id, nil
		}
	}
	return "", fmt.Errorf("no free session id for %q after 64 tries", base)
}

// ValidID reports whether s has the shape NewID produces (ids are used in paths, so be strict).
func ValidID(s string) bool { return idRe.MatchString(s) && !strings.Contains(s, "..") }

// RuntimeBase is where session runtime directories live: $XDG_RUNTIME_DIR/isolait, else /tmp/isolait-<uid>.
// It is created private (0700) and verified, because /tmp is shared with other users.
func RuntimeBase() (string, error) {
	p := filepath.Join("/tmp", fmt.Sprintf("isolait-%d", os.Getuid()))
	if x := os.Getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(x) {
		p = filepath.Join(x, "isolait")
	}
	return p, EnsurePrivateDir(p)
}

// EnsurePrivateDir creates dir (0700) if missing and fails unless it is a real directory owned by the
// current user with no group or other access. It refuses symlinks.
func EnsurePrivateDir(dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.IsDir():
		return fmt.Errorf("%s is not a directory (symlink or file); refusing to use it", dir)
	case !ok || int(st.Uid) != os.Getuid():
		return fmt.Errorf("%s is not owned by you; refusing to use it", dir)
	case fi.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("%s has mode %o, want 0700; refusing to use it", dir, fi.Mode().Perm())
	}
	return nil
}

// Dir is one session's runtime directory under base.
func Dir(base, id string) string { return filepath.Join(base, id) }

// SocketPath is the session's control socket.
func SocketPath(base, id string) string { return filepath.Join(Dir(base, id), "control.sock") }

// AttachPath is the session's attach socket: the framed terminal stream for attach and exec.
func AttachPath(base, id string) string { return filepath.Join(Dir(base, id), "attach.sock") }

// Create makes the runtime directory for a new session and returns its id. The id is reserved by the
// directory itself (mkdir is atomic), so two concurrent starts cannot share one.
func Create(base, workdir string) (id string, err error) {
	if err := EnsurePrivateDir(base); err != nil {
		return "", err
	}
	for i := 0; i < 64; i++ {
		id, err = NewID(workdir, func(string) bool { return false })
		if err != nil {
			return "", err
		}
		if err = os.Mkdir(Dir(base, id), 0o700); err == nil {
			return id, nil
		} else if !errors.Is(err, os.ErrExist) {
			return "", err
		}
	}
	return "", fmt.Errorf("no free session id for %q", Base(workdir))
}

// List returns the ids that have a runtime directory, sorted.
func List(base string) ([]string, error) {
	ents, err := os.ReadDir(base)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range ents {
		if e.IsDir() && ValidID(e.Name()) {
			ids = append(ids, e.Name())
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// Remove deletes a session's runtime directory.
func Remove(base, id string) error {
	if !ValidID(id) {
		return fmt.Errorf("invalid session id %q", id)
	}
	return os.RemoveAll(Dir(base, id))
}
