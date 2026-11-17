// Package mountcheck compares a sandbox's real mount table with its plan.Plan: every planned mount must be
// present with the right filesystem, source identity and flags, and nothing unplanned may be mounted. It is
// the runtime guard that catches a bwrap misconfiguration, a propagation surprise or a mount bug before the
// agent runs (design: sandbox-hardening Decision 5).
package mountcheck

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/H3mul/isolait/internal/plan"
)

// Mount is one line of /proc/<pid>/mountinfo.
type Mount struct {
	Dev    string // major:minor of the underlying filesystem
	Root   string // path of the mount's root within that filesystem
	Point  string // mount point, relative to the reading process's root
	Opts   map[string]bool
	FSType string
}

// Parse reads a mountinfo table.
func Parse(r io.Reader) ([]Mount, error) {
	var out []Mount
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		sep := -1
		for i, x := range f {
			if x == "-" {
				sep = i
				break
			}
		}
		if sep < 6 || len(f) < sep+2 {
			return nil, fmt.Errorf("mountinfo: malformed line %q", sc.Text())
		}
		m := Mount{Dev: f[2], Root: unescape(f[3]), Point: unescape(f[4]), FSType: f[sep+1], Opts: map[string]bool{}}
		for _, o := range strings.Split(f[5], ",") {
			m.Opts[o] = true
		}
		out = append(out, m)
	}
	return out, sc.Err()
}

// unescape decodes the \040-style octal escapes mountinfo uses for spaces and other awkward bytes.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// devChildren are the mounts bwrap itself creates under its /dev.
var devChildren = map[string]bool{"null": true, "zero": true, "full": true, "random": true, "urandom": true, "tty": true, "pts": true, "shm": true, "mqueue": true}

// Verify compares the live mount table of the sandbox process pid (its PID 1 as seen from the broker) with p.
// The host side of the comparison is the broker's own table, because bind sources are host paths.
func Verify(pid int, p *plan.Plan) error {
	sb, err := readTable(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return err
	}
	host, err := readTable("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	if probs := Compare(sb, host, p); len(probs) > 0 {
		return &Error{Problems: probs}
	}
	return nil
}

func readTable(path string) ([]Mount, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Error lists every mismatch between the sandbox and its plan.
type Error struct{ Problems []string }

func (e *Error) Error() string {
	return "sandbox mounts do not match the plan:\n  - " + strings.Join(e.Problems, "\n  - ")
}

// Compare returns one line per mismatch between the sandbox's mounts and the plan (empty when they agree).
// host is the table the plan's bind sources live in.
func Compare(sandbox, host []Mount, p *plan.Plan) []string {
	var probs []string
	bad := func(f string, a ...any) { probs = append(probs, fmt.Sprintf(f, a...)) }

	// last entry per mount point wins; more than one means something is stacked on it
	byPoint := map[string]Mount{}
	count := map[string]int{}
	for _, m := range sandbox {
		if m.Point == "/" {
			continue // bwrap's new root
		}
		byPoint[m.Point] = m
		count[m.Point]++
	}

	expected := map[string]bool{}
	for _, e := range p.Mounts() {
		expected[e.Dst] = true
		m, ok := byPoint[e.Dst]
		if !ok {
			bad("missing mount %s (%s)", e.Dst, e.Kind)
			continue
		}
		checkEntry(e, m, host, bad)

		// bwrap binds are recursive: host submounts under the source reappear under the destination
		if e.Kind == plan.RoBind || e.Kind == plan.Bind {
			for _, h := range host {
				if strings.HasPrefix(h.Point, strings.TrimRight(e.Src, "/")+"/") {
					child := e.Dst + strings.TrimPrefix(h.Point, e.Src)
					if !expected[child] {
						expected[child] = true
						expectChild(e, child, byPoint, bad)
					}
				}
			}
		}
		if e.Kind == plan.Dev {
			for name := range devChildren {
				expected[e.Dst+"/"+name] = true
			}
		}
	}
	for pt, n := range count {
		if n > 1 {
			bad("%d mounts are stacked on %s", n, pt)
		}
	}
	var unplanned []string
	for pt, m := range byPoint {
		if !expected[pt] {
			unplanned = append(unplanned, fmt.Sprintf("unplanned mount %s (%s, root %s, dev %s)", pt, m.FSType, m.Root, m.Dev))
		}
	}
	sort.Strings(unplanned)
	probs = append(probs, unplanned...)
	sort.Strings(probs)
	return probs
}

func expectChild(parent plan.Entry, child string, byPoint map[string]Mount, bad func(string, ...any)) {
	m, ok := byPoint[child]
	if !ok {
		bad("missing host submount %s under %s", child, parent.Dst)
		return
	}
	if parent.Kind == plan.RoBind && !m.Opts["ro"] {
		bad("submount %s under read-only %s is writable", child, parent.Dst)
	}
	if !m.Opts["nosuid"] {
		bad("submount %s lacks nosuid", child)
	}
}

func checkEntry(e plan.Entry, m Mount, host []Mount, bad func(string, ...any)) {
	want := func(flag string) {
		if !m.Opts[flag] {
			bad("%s (%s) should be %s but options are %s", e.Dst, e.Kind, flag, optString(m))
		}
	}
	forbid := func(flag string) {
		if m.Opts[flag] {
			bad("%s (%s) must not be %s but options are %s", e.Dst, e.Kind, flag, optString(m))
		}
	}
	switch e.Kind {
	case plan.RoBind:
		want("ro")
		want("nosuid")
		want("nodev")
		checkSource(e, m, host, bad)
	case plan.Bind:
		forbid("ro")
		want("nosuid")
		want("nodev")
		checkSource(e, m, host, bad)
	case plan.Workspace:
		want("nosuid")
		want("nodev")
		if e.RO {
			want("ro")
		} else {
			forbid("ro")
		}
		checkSource(e, m, host, bad)
	case plan.Mask:
		want("ro")
		checkSource(e, m, host, bad)
	case plan.Tmpfs:
		want("nosuid")
		want("nodev")
		if m.FSType != "tmpfs" {
			bad("%s should be tmpfs but is %s", e.Dst, m.FSType)
		}
	case plan.Proc:
		if m.FSType != "proc" {
			bad("%s should be proc but is %s", e.Dst, m.FSType)
		}
		want("nosuid")
	case plan.Dev:
		if m.FSType != "tmpfs" {
			bad("%s should be a tmpfs /dev but is %s", e.Dst, m.FSType)
		}
	}
}

// checkSource verifies the mount is the planned host path: same filesystem device and the same path within it.
func checkSource(e plan.Entry, m Mount, host []Mount, bad func(string, ...any)) {
	dev, root, ok := locate(e.Src, host)
	if !ok {
		bad("cannot locate source %s of %s in the host mount table", e.Src, e.Dst)
		return
	}
	if m.Dev != dev || m.Root != root {
		bad("%s is dev %s root %s, want the source %s (dev %s root %s)", e.Dst, m.Dev, m.Root, e.Src, dev, root)
	}
}

// locate finds which host mount contains path and returns its device and the path's root within it.
func locate(path string, host []Mount) (dev, root string, ok bool) {
	best := -1
	for i, h := range host {
		pt := strings.TrimRight(h.Point, "/")
		if path == h.Point || h.Point == "/" || strings.HasPrefix(path, pt+"/") {
			if best < 0 || len(h.Point) >= len(host[best].Point) {
				best = i
			}
		}
	}
	if best < 0 {
		return "", "", false
	}
	h := host[best]
	rel := strings.TrimPrefix(path, strings.TrimRight(h.Point, "/"))
	return h.Dev, filepath.Clean(h.Root + "/" + rel), true
}

func optString(m Mount) string {
	var o []string
	for k := range m.Opts {
		o = append(o, k)
	}
	sort.Strings(o)
	return strings.Join(o, ",")
}
