package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/H3mul/isolait/internal/plan"
)

// systemPath lists the directories, in order, that make up the base sandbox PATH if they exist. They all
// live under the read-only system dirs, so they are mounted by construction.
var systemPath = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// BinOptions describe what to expose besides the system directories.
type BinOptions struct {
	Agent       string   // command or path the user asked to run, resolved with HostPath
	HostPath    string   // the host PATH value
	InheritPath bool     // also expose filtered host PATH entries
	Tools       []string // explicit extra read-only roots (clean absolute paths)
	Home        string   // the user's real home, one of the places --inherit-path may take directories from
	// InheritPrefixes overrides where --inherit-path may take directories from (tests); default /usr/local, /opt, Home.
	InheritPrefixes []string
	// Deny, when set, vets the directory of each launcher target before it is bound (the mount deny list).
	Deny func(dir string) error `json:"-"`
}

// Binaries is the resolved exposure: what to add to the plan, the sandbox PATH and what to tell the user.
type Binaries struct {
	Argv0     string       // the agent's resolved path
	AgentPath string       // the path to start it with inside the sandbox: the /isolait/bin link when there is one, so its name is kept
	PathDirs  []string     // sandbox PATH entries, in order
	Roots     []string     // host paths bound read-only, shown by `isolait status`
	Entries   []plan.Entry // plan entries to add (dirs, read-only binds, the agent symlink)
	Warnings  []string
}

// Path renders PathDirs as a PATH value.
func (b Binaries) Path() string { return strings.Join(b.PathDirs, ":") }

// ResolveBinaries decides what the sandbox can execute. Only the system directories, the agent's resolved
// install root, the explicit tools and (opt-in) filtered host PATH entries are exposed; the sandbox PATH is
// built from those mounted locations only.
func ResolveBinaries(o BinOptions) (Binaries, error) {
	var b Binaries
	m := &mounted{}
	for _, d := range SystemDirs {
		m.add(d) // covers merged-usr symlinks too: their targets are inside /usr
	}
	for _, d := range systemPath {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			b.PathDirs = append(b.PathDirs, d)
		}
	}

	// the agent
	agent, err := lookPath(o.Agent, o.HostPath)
	if err != nil {
		return Binaries{}, err
	}
	resolved, err := filepath.EvalSymlinks(agent)
	if err != nil {
		return Binaries{}, fmt.Errorf("resolving %s: %w", agent, err)
	}
	b.Argv0, b.AgentPath = resolved, resolved
	if !m.covers(resolved) {
		root := installRoot(resolved)
		b.bind(m, root)
		name := filepath.Base(agent)
		b.Entries = append(b.Entries, plan.Entry{Kind: plan.Symlink, Src: resolved, Dst: AgentLinkDir + "/" + name})
		b.AgentPath = AgentLinkDir + "/" + name
		b.PathDirs = append([]string{AgentLinkDir}, b.PathDirs...)
	}

	// explicit tools
	for _, t := range o.Tools {
		real, err := filepath.EvalSymlinks(t)
		if err != nil {
			return Binaries{}, fmt.Errorf("tools entry %s: %w", t, err)
		}
		if fi, err := os.Stat(real); err != nil || !fi.IsDir() {
			return Binaries{}, fmt.Errorf("tools entry %s is not a directory", t)
		}
		b.bind(m, real)
		b.PathDirs = append(b.PathDirs, toolPath(real))
		b.Warnings = append(b.Warnings, danglingLinks(real, m)...)
	}

	// targets of a launcher script, exposed like the agent's own install root
	for _, t := range launcherTargets(resolved) {
		if m.covers(t) {
			continue
		}
		root := installRoot(t)
		if o.Deny != nil {
			if err := o.Deny(filepath.Dir(root)); err != nil {
				return Binaries{}, fmt.Errorf("%s is a launcher script that runs %s: %w", agent, t, err)
			}
		}
		b.bind(m, root)
		b.Warnings = append(b.Warnings, fmt.Sprintf("warning: %s is a launcher script; also exposing %s", filepath.Base(agent), root))
	}

	// filtered host PATH, opt-in
	if o.InheritPath {
		prefixes := o.InheritPrefixes
		if prefixes == nil {
			prefixes = []string{"/usr/local", "/opt"}
			if o.Home != "" && o.Home != "/" {
				prefixes = append(prefixes, o.Home)
			}
		}
		for _, e := range filepath.SplitList(o.HostPath) {
			real, ok := inheritable(e, prefixes)
			if !ok || m.covers(real) {
				continue
			}
			b.bind(m, real)
			b.PathDirs = append(b.PathDirs, real)
			b.Warnings = append(b.Warnings, danglingLinks(real, m)...)
		}
	}
	return b, nil
}

// bind records a read-only bind of root at the same path, unless an ancestor is already bound.
func (b *Binaries) bind(m *mounted, root string) {
	if m.covers(root) {
		return
	}
	under := func(p string) bool { return strings.HasPrefix(p, strings.TrimRight(root, "/")+"/") }
	roots := b.Roots[:0:0]
	for _, r := range b.Roots {
		if !under(r) {
			roots = append(roots, r)
		}
	}
	ents := b.Entries[:0:0]
	for _, e := range b.Entries {
		if e.Kind == plan.RoBind && under(e.Dst) {
			continue
		}
		ents = append(ents, e)
	}
	m.add(root)
	b.Roots = append(roots, root)
	b.Entries = append(ents, plan.Entry{Kind: plan.RoBind, Src: root, Dst: root})
}

// installRoot is the directory containing the resolved agent, or the binary file itself when that directory
// is a generic bin directory (binding ~/.local/bin would expose every other tool in it).
func installRoot(resolved string) string {
	dir := filepath.Dir(resolved)
	if filepath.Base(dir) == "bin" || dir == "/" {
		return resolved
	}
	return dir
}

// toolPath is where a tools root contributes to PATH: its bin directory when it has one.
func toolPath(root string) string {
	if fi, err := os.Stat(filepath.Join(root, "bin")); err == nil && fi.IsDir() {
		return filepath.Join(root, "bin")
	}
	return root
}

// inheritable applies the --inherit-path filter: absolute, existing, a directory, and (after following
// symlinks) under one of the allowed prefixes.
func inheritable(entry string, prefixes []string) (string, bool) {
	if !filepath.IsAbs(entry) {
		return "", false
	}
	real, err := filepath.EvalSymlinks(entry)
	if err != nil {
		return "", false
	}
	if fi, err := os.Stat(real); err != nil || !fi.IsDir() {
		return "", false
	}
	for _, p := range prefixes {
		if real == p || strings.HasPrefix(real, strings.TrimRight(p, "/")+"/") {
			return real, true
		}
	}
	return "", false
}

// danglingLinks reports symlinks directly inside dir whose target is not inside anything mounted: they
// would exist in the sandbox but point nowhere.
func danglingLinks(dir string, m *mounted) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var w []string
	for _, e := range ents {
		if e.Type()&os.ModeSymlink == 0 {
			continue
		}
		p := filepath.Join(dir, e.Name())
		target, err := filepath.EvalSymlinks(p)
		if err != nil {
			target, _ = os.Readlink(p)
			if !filepath.IsAbs(target) {
				target = filepath.Join(dir, target)
			}
		}
		if !m.covers(target) {
			w = append(w, fmt.Sprintf("%s -> %s will be a dangling link in the sandbox (target is not mounted)", p, target))
		}
	}
	sort.Strings(w)
	return w
}

// lookPath resolves the agent command: a path is used as given, a bare name is searched in hostPath.
func lookPath(agent, hostPath string) (string, error) {
	if agent == "" {
		return "", fmt.Errorf("no agent command given")
	}
	if strings.Contains(agent, "/") {
		abs, err := filepath.Abs(agent)
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(abs); err != nil {
			return "", fmt.Errorf("agent %s: %w", agent, err)
		}
		return abs, nil
	}
	for _, d := range filepath.SplitList(hostPath) {
		if !filepath.IsAbs(d) {
			continue
		}
		p := filepath.Join(d, agent)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("agent command %q not found on PATH", agent)
}

// mounted tracks the roots visible in the sandbox.
type mounted struct{ roots []string }

func (m *mounted) add(root string) { m.roots = append(m.roots, root) }
func (m *mounted) covers(p string) bool {
	for _, r := range m.roots {
		if p == r || strings.HasPrefix(p, strings.TrimRight(r, "/")+"/") {
			return true
		}
	}
	return false
}

// AddBinaries appends the exposure's entries to the plan.
func AddBinaries(p *plan.Plan, b Binaries) error {
	for _, e := range b.Entries {
		if err := p.Add(e); err != nil {
			return err
		}
	}
	return nil
}
