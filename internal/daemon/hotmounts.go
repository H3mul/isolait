package daemon

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/H3mul/isolait/internal/mountcheck"
	"github.com/H3mul/isolait/internal/mounts"
	"github.com/H3mul/isolait/internal/plan"
	"github.com/H3mul/isolait/internal/sandbox"
)

// hotMounts adds and removes workspaces while the agent runs. Every change is made by the broker into the
// shared stage (the sandbox is never entered), and the sandbox's real mount table is compared with the plan
// afterwards; a mismatch is rolled back.
type hotMounts struct {
	mu    sync.Mutex
	stage string
	empty string
	plan  *plan.Plan
	deny  *mounts.DenyList
	box   *sandbox.Sandbox

	beforeVerify func() // tests only: runs between the mount and its verification
}

// Blocker is a sandbox process that still uses a mount.
type Blocker struct {
	PID  int    `json:"pid"`
	Comm string `json:"comm"`
	Use  string `json:"use"` // cwd, an open file or a mapping
}

// BusyError is returned by Remove when processes still use the mount.
type BusyError struct {
	Name     string
	Blockers []Blocker
}

func (e *BusyError) Error() string {
	var parts []string
	for i, b := range e.Blockers {
		if i == 5 {
			parts = append(parts, fmt.Sprintf("and %d more", len(e.Blockers)-5))
			break
		}
		parts = append(parts, fmt.Sprintf("%s (pid %d, %s)", b.Comm, b.PID, b.Use))
	}
	return fmt.Sprintf("%s is in use by %s; stop them or use --force", e.Name, strings.Join(parts, ", "))
}

// Add mounts src as /workspaces/<name> (named after the directory when name is empty).
func (h *hotMounts) Add(src, name string, ro bool) (MountInfo, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if name == "" {
		name = mounts.NameFor(src)
	}
	if !mounts.ValidName(name) {
		return MountInfo{}, fmt.Errorf("invalid mount name %q: use letters, digits, '.', '_' and '-' (at most 64, starting with a letter or digit)", name)
	}
	dst := sandbox.Workspaces + "/" + name
	for _, e := range h.plan.Entries() {
		if e.Dst == dst {
			return MountInfo{}, fmt.Errorf("a mount named %q already exists (%s); choose another name with --as", name, e.Src)
		}
	}
	masked, err := mounts.MountWorkspace(h.stage, name, src, ro, h.empty, h.deny)
	if err != nil {
		return MountInfo{}, err
	}
	real, _ := filepath.EvalSymlinks(src)
	if _, err := sandbox.AddWorkspace(h.plan, name, real, ro, masked, h.empty); err != nil {
		h.detach(name)
		return MountInfo{}, err
	}
	if h.beforeVerify != nil {
		h.beforeVerify()
	}
	if err := mountcheck.Verify(h.box.ChildPID, h.plan); err != nil {
		h.plan.Remove(dst + "/.isolait")
		h.plan.Remove(dst)
		h.detach(name)
		return MountInfo{}, fmt.Errorf("the sandbox's mounts do not match the plan after mounting %s; rolled back: %w", name, err)
	}
	mode := "rw"
	if ro {
		mode = "ro"
	}
	return MountInfo{Path: dst, Src: real, Mode: mode}, nil
}

// detach lazily unmounts stage/name (with anything stacked on it) and removes the directory.
func (h *hotMounts) detach(name string) {
	dir := filepath.Join(h.stage, name)
	mounts.Unmount(dir)
	os.Remove(dir)
}

// Remove unmounts /workspaces/<name>. Without force it refuses while sandbox processes use the mount.
func (h *hotMounts) Remove(name string, force bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	dst := sandbox.Workspaces + "/" + name
	found := false
	for _, e := range h.plan.Entries() {
		if e.Kind == plan.Workspace && e.Dst == dst {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("no mount named %q", name)
	}
	if !force {
		if b := Blockers(h.box.ChildPID, dst); len(b) > 0 {
			return &BusyError{Name: name, Blockers: b}
		}
	}
	h.detach(name)
	h.plan.Remove(dst + "/.isolait")
	h.plan.Remove(dst)
	if err := mountcheck.Verify(h.box.ChildPID, h.plan); err != nil {
		return fmt.Errorf("unmounted %s but the sandbox's mounts do not match the plan: %w", name, err)
	}
	return nil
}

// Blockers lists processes in the sandbox's PID namespace whose working directory, root, open files or
// mappings are at or below dir (a path inside the sandbox). ref is any process of the sandbox, as seen here.
func Blockers(ref int, dir string) []Blocker {
	ns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", ref))
	if err != nil {
		return nil
	}
	under := func(p string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }
	entries, _ := os.ReadDir("/proc")
	var out []Blocker
	for _, de := range entries {
		pid, err := strconv.Atoi(de.Name())
		if err != nil {
			continue
		}
		if n, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid)); err != nil || n != ns {
			continue
		}
		base := fmt.Sprintf("/proc/%d", pid)
		use := ""
		for _, l := range []string{"cwd", "root"} {
			if t, err := os.Readlink(base + "/" + l); err == nil && under(t) {
				use = l
			}
		}
		if fds, err := os.ReadDir(base + "/fd"); err == nil && use == "" {
			for _, f := range fds {
				if t, err := os.Readlink(base + "/fd/" + f.Name()); err == nil && under(t) {
					use = "open file " + t
					break
				}
			}
		}
		if use == "" {
			use = mapped(base+"/maps", under)
		}
		if use != "" {
			comm, _ := os.ReadFile(base + "/comm")
			out = append(out, Blocker{PID: pid, Comm: strings.TrimSpace(string(comm)), Use: use})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

func mapped(maps string, under func(string) bool) string {
	f, err := os.Open(maps)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if i := strings.Index(sc.Text(), "/"); i >= 0 {
			if p := strings.TrimSuffix(sc.Text()[i:], " (deleted)"); under(p) {
				return "mapped file " + p
			}
		}
	}
	return ""
}
