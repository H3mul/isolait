// Package plan is the single description of what the sandbox's filesystem contains. Every bwrap mount
// argument is rendered from a Plan, every broker mount is recorded in it, and the start-time and
// post-mount checks compare the sandbox's real mountinfo against it. Nothing else may build mount arguments
// (TestNoMountArgumentsOutsidePlan enforces that), so the plan cannot drift from what is actually mounted.
package plan

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Kind is the type of one entry.
type Kind string

const (
	RoBind    Kind = "ro-bind"   // bwrap --ro-bind Src Dst
	Bind      Kind = "bind"      // bwrap --bind Src Dst
	Tmpfs     Kind = "tmpfs"     // bwrap --tmpfs Dst
	Proc      Kind = "proc"      // bwrap --proc Dst
	Dev       Kind = "dev"       // bwrap --dev Dst
	Symlink   Kind = "symlink"   // bwrap --symlink Src Dst; Src is the link target; not a mount
	Dir       Kind = "dir"       // bwrap --dir Dst; not a mount
	Workspace Kind = "workspace" // mounted later by the broker under /workspaces/<name>; Src is the host dir
	RoTmpfs   Kind = "ro-tmpfs"  // bwrap --tmpfs Dst then --remount-ro Dst: an empty read-only directory hiding what is below
	Mask      Kind = "mask"      // empty read-only layer the broker mounts over a workspace's .isolait
)

// Entry is one planned filesystem element.
type Entry struct {
	Kind Kind
	Src  string // host path (or link target for Symlink)
	Dst  string // path inside the sandbox
	RO   bool   // Workspace: mounted read-only (--ro)
}

// IsMount reports whether the entry shows up in the sandbox's mountinfo.
func (e Entry) IsMount() bool { return e.Kind != Symlink && e.Kind != Dir }

// BwrapManaged reports whether bwrap itself creates it (as opposed to the broker, after start).
func (e Entry) BwrapManaged() bool { return e.Kind != Workspace && e.Kind != Mask }

// Plan is an ordered list of entries. Order matters: bwrap applies arguments sequentially.
type Plan struct{ entries []Entry }

// Add appends an entry after validating it. It rejects relative or unclean paths, duplicate destinations
// and destinations that would shadow an earlier entry.
func (p *Plan) Add(e Entry) error {
	if !clean(e.Dst) || e.Dst == "/" {
		return fmt.Errorf("plan: destination %q must be a clean absolute path other than /", e.Dst)
	}
	switch e.Kind {
	case RoBind, Bind, Workspace, Mask:
		if !clean(e.Src) {
			return fmt.Errorf("plan: %s source %q must be a clean absolute path", e.Kind, e.Src)
		}
	case Symlink:
		if e.Src == "" || strings.ContainsRune(e.Src, 0) {
			return fmt.Errorf("plan: symlink %s needs a target", e.Dst)
		}
	case Tmpfs, RoTmpfs, Proc, Dev, Dir:
	default:
		return fmt.Errorf("plan: unknown kind %q", e.Kind)
	}
	for _, o := range p.entries {
		if o.Dst == e.Dst {
			return fmt.Errorf("plan: %s is already planned (%s)", e.Dst, o.Kind)
		}
		if strings.HasPrefix(o.Dst, e.Dst+"/") {
			return fmt.Errorf("plan: %s would shadow the earlier entry %s", e.Dst, o.Dst)
		}
	}
	p.entries = append(p.entries, e)
	return nil
}

// Remove deletes the entry for dst (a workspace or mask being unmounted). It reports whether one existed.
func (p *Plan) Remove(dst string) bool {
	for i, e := range p.entries {
		if e.Dst == dst {
			p.entries = append(p.entries[:i:i], p.entries[i+1:]...)
			return true
		}
	}
	return false
}

// Entries returns a copy of the planned entries in order.
func (p Plan) Entries() []Entry { return append([]Entry(nil), p.entries...) }

// Mounts returns the entries that must appear in mountinfo.
func (p Plan) Mounts() []Entry {
	var m []Entry
	for _, e := range p.entries {
		if e.IsMount() {
			m = append(m, e)
		}
	}
	return m
}

// Args renders the bwrap arguments for the bwrap-managed entries. This is the only place mount arguments
// are produced.
func (p Plan) Args() []string {
	var a []string
	for _, e := range p.entries {
		switch e.Kind {
		case RoBind:
			a = append(a, "--ro-bind", e.Src, e.Dst)
		case Bind:
			a = append(a, "--bind", e.Src, e.Dst)
		case Tmpfs:
			a = append(a, "--tmpfs", e.Dst)
		case RoTmpfs:
			a = append(a, "--tmpfs", e.Dst, "--remount-ro", e.Dst)
		case Proc:
			a = append(a, "--proc", e.Dst)
		case Dev:
			a = append(a, "--dev", e.Dst)
		case Symlink:
			a = append(a, "--symlink", e.Src, e.Dst)
		case Dir:
			a = append(a, "--dir", e.Dst)
		}
	}
	return a
}

func clean(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.ContainsRune(p, 0)
}
