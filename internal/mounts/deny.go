package mounts

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// id names a directory independent of any path: device and inode.
type id struct{ dev, ino uint64 }

type denied struct {
	path   string
	inside bool // also refuse sources below it (isolait's own directories), not only it and its ancestors
}

// DenyList is the protected-path list for mount sources (task 6.1). Paths are resolved to device+inode when
// the list is built and sources are compared by device+inode, so a symlink, bind mount, `..` or a rename cannot
// disguise a protected directory. Two kinds of entry:
//
//   - Protect: the directory and every directory that contains it are refused (the home directory, so `/home`
//     and `/` cannot be mounted either), while directories inside stay mountable.
//   - Exclude: additionally nothing inside is mountable (isolait's config, state and runtime directories).
type DenyList struct {
	list []denied
	ids  []map[id]bool // per entry: the ids of the directory and all its ancestors
	self []id
}

// NewDenyList resolves the given paths now. Paths that do not exist are skipped: they cannot be mounted
// either, and a directory created later is not protected by a name it did not have.
func NewDenyList(protect, exclude []string) (*DenyList, error) {
	d := &DenyList{}
	add := func(p string, inside bool) error {
		fd, err := syscall.Open(p, oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
		if err != nil {
			if os.IsNotExist(err) || err == syscall.ENOTDIR {
				return nil
			}
			return fmt.Errorf("deny list: %s: %w", p, err)
		}
		defer syscall.Close(fd)
		chain, err := chainOf(fd)
		if err != nil {
			return err
		}
		set := map[id]bool{}
		for _, c := range chain {
			set[c] = true
		}
		d.list = append(d.list, denied{p, inside})
		d.ids = append(d.ids, set)
		d.self = append(d.self, chain[0])
		return nil
	}
	for _, p := range protect {
		if err := add(p, false); err != nil {
			return nil, err
		}
	}
	for _, p := range exclude {
		if err := add(p, true); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// chainOf returns the ids of the directory fd and of each ancestor up to the root, found by walking `..`
// from the descriptor itself (never by path), so the answer describes this directory whatever its names are.
func chainOf(fd int) ([]id, error) {
	cur, err := syscall.Dup(fd)
	if err != nil {
		return nil, err
	}
	var out []id
	for i := 0; i < 4096; i++ {
		var st syscall.Stat_t
		if err := syscall.Fstat(cur, &st); err != nil {
			syscall.Close(cur)
			return nil, err
		}
		here := id{uint64(st.Dev), st.Ino}
		out = append(out, here)
		up, err := syscall.Openat(cur, "..", oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
		syscall.Close(cur)
		if err != nil {
			return nil, err
		}
		var pst syscall.Stat_t
		if err := syscall.Fstat(up, &pst); err != nil {
			syscall.Close(up)
			return nil, err
		}
		if (id{uint64(pst.Dev), pst.Ino}) == here { // the root is its own parent
			syscall.Close(up)
			return out, nil
		}
		cur = up
	}
	syscall.Close(cur)
	return nil, fmt.Errorf("directory nesting too deep")
}

// Check validates an open source directory against the list. It refuses the filesystem root, a protected
// directory or any directory containing one, and anything inside or containing an excluded directory.
func (d *DenyList) Check(fd int) error {
	chain, err := chainOf(fd)
	if err != nil {
		return err
	}
	if len(chain) == 1 {
		return fmt.Errorf("refusing to mount the filesystem root")
	}
	src := chain[0]
	ancestors := map[id]bool{}
	for _, c := range chain {
		ancestors[c] = true
	}
	for i, e := range d.list {
		switch {
		case d.self[i] == src:
			return fmt.Errorf("refusing to mount %s: it is protected", e.path)
		case d.ids[i][src]:
			return fmt.Errorf("refusing to mount a directory that contains %s", e.path)
		case e.inside && ancestors[d.self[i]]:
			return fmt.Errorf("refusing to mount a directory inside %s", e.path)
		}
	}
	return nil
}

// OpenSource opens src as a directory without following a final symlink, after resolving the path once, and
// returns the descriptor. Everything after this (validation, clone) uses the descriptor, so replacing the path
// with a symlink between the check and the mount changes nothing.
func OpenSource(src string) (int, error) {
	real, err := filepath.EvalSymlinks(src)
	if err != nil {
		return -1, err
	}
	fd, err := syscall.Open(real, oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open %s: %w (a mount source must be a directory)", src, err)
	}
	return fd, nil
}

// CheckPath vets the directory dir (symlinks followed) like a mount source.
func (d *DenyList) CheckPath(dir string) error {
	fd, err := OpenSource(dir)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return d.Check(fd)
}
