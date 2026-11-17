package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/H3mul/isolait/internal/trust"
)

const (
	// WorkspaceDir is the per-workspace directory holding local config and state.
	WorkspaceDir = ".isolait"
	// FileName is the config file inside the global dir and inside WorkspaceDir.
	FileName      = "config"
	maxConfigSize = 64 << 10
)

// Paths are the global locations; tests pass temp dirs.
type Paths struct {
	GlobalDir string // $XDG_CONFIG_HOME/isolait
	StateDir  string // $XDG_STATE_HOME/isolait
}

// DefaultPaths resolves the XDG locations.
func DefaultPaths() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, err
	}
	dir := func(env, fallback string) string {
		if v := os.Getenv(env); filepath.IsAbs(v) {
			return filepath.Join(v, "isolait")
		}
		return filepath.Join(home, fallback, "isolait")
	}
	return Paths{GlobalDir: dir("XDG_CONFIG_HOME", ".config"), StateDir: dir("XDG_STATE_HOME", ".local/state")}, nil
}

// Result is the effective configuration plus anything the user should be told.
type Result struct {
	Config   Config
	Warnings []string
}

// Load resolves flags > trusted workspace config > global config > defaults for a session starting in
// workdir. Only workdir's own .isolait/config is ever read (never sub-directories or hot-added mounts).
func Load(p Paths, workdir string, flags Layer, tr *trust.Store) (Result, error) {
	var res Result
	var layers []Layer

	gpath := filepath.Join(p.GlobalDir, FileName)
	if data, err := readRegular(gpath); err == nil {
		l, err := Parse(gpath, data)
		if err != nil {
			return Result{}, err
		}
		layers = append(layers, l)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Result{}, err
	}

	wpath, data, err := ReadWorkspace(workdir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// no workspace config
	case err != nil:
		return Result{}, err
	default:
		ok, err := tr.IsTrusted(trust.Sum(data))
		if err != nil {
			return Result{}, err
		}
		if !ok {
			res.Warnings = append(res.Warnings, fmt.Sprintf("workspace config %s ignored: not trusted (review it, then run `isolait trust`)", wpath))
			break
		}
		l, err := Parse(wpath, data) // parsed from the same bytes that were hashed
		if err != nil {
			return Result{}, err
		}
		layers = append(layers, l)
	}

	res.Config = Resolve(append(layers, flags)...)
	return res, nil
}

// ReadWorkspace returns the workspace config path and content. It refuses symlinks (a hostile repository
// must not point the config at another file) and returns os.ErrNotExist when there is none.
func ReadWorkspace(workdir string) (path string, data []byte, err error) {
	dir := filepath.Join(workdir, WorkspaceDir)
	path = filepath.Join(dir, FileName)
	if fi, err := os.Lstat(dir); err != nil {
		return path, nil, err
	} else if !fi.IsDir() {
		return path, nil, fmt.Errorf("%s must be a real directory, not a symlink or file", dir)
	}
	data, err = readRegular(path)
	return path, data, err
}

// readRegular reads a regular file without following a final symlink, with a size cap.
func readRegular(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s is a symlink; refusing to follow it", path)
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxConfigSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxConfigSize)
	}
	return b, nil
}
