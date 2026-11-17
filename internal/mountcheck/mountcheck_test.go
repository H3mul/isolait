package mountcheck

import (
	"strings"
	"testing"

	"github.com/H3mul/isolait/internal/plan"
)

// hostTable is the broker's view: root fs, host submounts under /usr (as on WSL), a tmpfs holding the
// per-agent home and the stage, and the workspace sources.
const hostTable = `
1 0 8:48 / / rw,relatime - ext4 /dev/sdd rw
2 1 0:36 / /usr/lib/wsl/drivers ro,nosuid,nodev,noatime - 9p drivers ro
3 1 0:75 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw
4 3 0:87 / /tmp/t/stage rw,nosuid,nodev - tmpfs tmpfs rw
`

// sandboxTable is what a healthy sandbox shows (shape taken from a real bwrap run).
const sandboxTable = `
547 489 0:89 /newroot / rw,nosuid,nodev,relatime - tmpfs tmpfs rw
551 547 8:48 /usr /usr ro,nosuid,nodev,relatime - ext4 /dev/sdd rw
552 551 0:36 / /usr/lib/wsl/drivers ro,nosuid,nodev,noatime - 9p drivers ro
556 547 8:48 /etc/passwd /etc/passwd ro,nosuid,nodev,relatime - ext4 /dev/sdd rw
568 547 0:90 / /dev rw,nosuid,nodev,relatime - tmpfs tmpfs rw
569 568 0:6 /null /dev/null rw,nosuid,relatime master:14 - devtmpfs none rw
575 568 0:91 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw
576 547 0:92 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
577 547 0:93 / /tmp rw,nosuid,nodev,relatime - tmpfs tmpfs rw
578 547 0:75 /t/agenthome /home/fake rw,nosuid,nodev - tmpfs tmpfs rw
579 547 0:87 / /workspaces rw,nosuid,nodev,relatime master:250 - tmpfs tmpfs rw
`

func basePlan(t *testing.T) *plan.Plan {
	t.Helper()
	var p plan.Plan
	for _, e := range []plan.Entry{
		{Kind: plan.RoBind, Src: "/usr", Dst: "/usr"},
		{Kind: plan.RoBind, Src: "/etc/passwd", Dst: "/etc/passwd"},
		{Kind: plan.Dev, Dst: "/dev"},
		{Kind: plan.Proc, Dst: "/proc"},
		{Kind: plan.Tmpfs, Dst: "/tmp"},
		{Kind: plan.Bind, Src: "/tmp/t/agenthome", Dst: "/home/fake"},
		{Kind: plan.Bind, Src: "/tmp/t/stage", Dst: "/workspaces"},
	} {
		if err := p.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	return &p
}

func parse(t *testing.T, s string) []Mount {
	t.Helper()
	m, err := Parse(strings.NewReader(strings.TrimSpace(s)))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func problems(t *testing.T, sandbox string, p *plan.Plan) string {
	t.Helper()
	return strings.Join(Compare(parse(t, sandbox), parse(t, hostTable), p), "\n")
}

func TestHealthySandboxMatchesItsPlan(t *testing.T) {
	if got := problems(t, sandboxTable, basePlan(t)); got != "" {
		t.Fatalf("healthy sandbox reported problems:\n%s", got)
	}
}

func TestMismatchesAreReported(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(string) string
		want   string
	}{
		{"extra bind injected", func(s string) string { return s + "580 547 8:48 /home /home/x rw,nosuid,nodev - ext4 /dev/sdd rw\n" }, "unplanned mount /home/x"},
		{"extra tmpfs injected", func(s string) string { return s + "580 547 0:99 / /extra rw,nosuid,nodev - tmpfs tmpfs rw\n" }, "unplanned mount /extra"},
		{"ro omitted on a system dir", func(s string) string { return strings.Replace(s, "/usr /usr ro,nosuid", "/usr /usr rw,nosuid", 1) }, "/usr (ro-bind) should be ro"},
		{"nosuid omitted", func(s string) string {
			return strings.Replace(s, "/etc/passwd /etc/passwd ro,nosuid,nodev", "/etc/passwd /etc/passwd ro,nodev", 1)
		}, "/etc/passwd (ro-bind) should be nosuid"},
		{"rw bind became ro", func(s string) string { return strings.Replace(s, "/home/fake rw,nosuid", "/home/fake ro,nosuid", 1) }, "/home/fake (bind) must not be ro"},
		{"wrong source dir on the right device", func(s string) string { return strings.Replace(s, "8:48 /usr /usr", "8:48 /usr/local /usr", 1) }, "/usr is dev 8:48 root /usr/local, want the source /usr"},
		{"wrong filesystem", func(s string) string { return strings.Replace(s, "0:75 /t/agenthome", "0:11 /t/agenthome", 1) }, "/home/fake is dev 0:11"},
		{"planned mount missing", func(s string) string {
			return strings.Replace(s, "556 547 8:48 /etc/passwd /etc/passwd ro,nosuid,nodev,relatime - ext4 /dev/sdd rw\n", "", 1)
		}, "missing mount /etc/passwd"},
		{"host submount dropped", func(s string) string {
			return strings.Replace(s, "552 551 0:36 / /usr/lib/wsl/drivers ro,nosuid,nodev,noatime - 9p drivers ro\n", "", 1)
		}, "missing host submount /usr/lib/wsl/drivers"},
		{"host submount writable", func(s string) string {
			return strings.Replace(s, "/usr/lib/wsl/drivers ro,", "/usr/lib/wsl/drivers rw,", 1)
		}, "submount /usr/lib/wsl/drivers under read-only /usr is writable"},
		{"stacked mount", func(s string) string { return s + "581 547 0:98 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw\n" }, "2 mounts are stacked on /tmp"},
		{"unknown device node mount", func(s string) string { return s + "582 568 0:6 /sda /dev/sda rw,nosuid - devtmpfs none rw\n" }, "unplanned mount /dev/sda"},
		{"/tmp not a tmpfs", func(s string) string {
			return strings.Replace(s, "0:93 / /tmp rw,nosuid,nodev,relatime - tmpfs tmpfs", "0:93 / /tmp rw,nosuid,nodev,relatime - ext4 /dev/x", 1)
		}, "/tmp should be tmpfs"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := problems(t, tc.mutate(sandboxTable), basePlan(t))
			if !strings.Contains(got, tc.want) {
				t.Fatalf("want a problem containing %q, got:\n%s", tc.want, got)
			}
		})
	}
}

func TestWorkspaceAndMaskEntries(t *testing.T) {
	// /srv/proj and /srv/empty are plain directories on the root filesystem (8:48)
	const ws = "590 579 8:48 /srv/proj /workspaces/proj rw,nosuid,nodev,relatime - ext4 /dev/sdd rw\n"
	const mask = "591 590 8:48 /srv/empty /workspaces/proj/.isolait ro,nosuid,nodev,relatime - ext4 /dev/sdd rw\n"
	withWorkspace := func(ro bool) *plan.Plan {
		p := basePlan(t)
		if err := p.Add(plan.Entry{Kind: plan.Workspace, Src: "/srv/proj", Dst: "/workspaces/proj", RO: ro}); err != nil {
			t.Fatal(err)
		}
		if err := p.Add(plan.Entry{Kind: plan.Mask, Src: "/srv/empty", Dst: "/workspaces/proj/.isolait", RO: true}); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if got := problems(t, sandboxTable+ws+mask, withWorkspace(false)); got != "" {
		t.Fatalf("healthy rw workspace with mask reported problems:\n%s", got)
	}
	tests := []struct {
		name, table string
		ro          bool
		want        string
	}{
		{"ro workspace that is writable", sandboxTable + ws + mask, true, "/workspaces/proj (workspace) should be ro"},
		{"rw workspace that is read-only", sandboxTable + strings.Replace(ws, "rw,nosuid", "ro,nosuid", 1) + mask, false, "/workspaces/proj (workspace) must not be ro"},
		{"mask that is writable", sandboxTable + ws + strings.Replace(mask, "ro,nosuid", "rw,nosuid", 1), false, "(mask) should be ro"},
		{"mask missing", sandboxTable + ws, false, "missing mount /workspaces/proj/.isolait"},
		{"workspace from the wrong directory", sandboxTable + strings.Replace(ws, "/srv/proj", "/srv/other", 1) + mask, false, "want the source /srv/proj"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := problems(t, tc.table, withWorkspace(tc.ro)); !strings.Contains(got, tc.want) {
				t.Fatalf("want %q, got:\n%s", tc.want, got)
			}
		})
	}
	// a mount the broker made that the plan does not know about
	if got := problems(t, sandboxTable+ws+mask, basePlan(t)); !strings.Contains(got, "unplanned mount /workspaces/proj ") || !strings.Contains(got, "unplanned mount /workspaces/proj/.isolait") {
		t.Errorf("unrecorded workspace mounts must be reported:\n%s", got)
	}
}

func TestParseUnescapesSpaces(t *testing.T) {
	m := parse(t, `1 0 8:1 /my\040dir /mnt/a\040b rw,nosuid - ext4 /dev/x rw`)
	if m[0].Root != "/my dir" || m[0].Point != "/mnt/a b" {
		t.Errorf("%+v", m[0])
	}
	if _, err := Parse(strings.NewReader("garbage")); err == nil {
		t.Error("malformed line accepted")
	}
}

func TestLocate(t *testing.T) {
	host := parse(t, hostTable)
	dev, root, ok := locate("/usr/bin/ls", host)
	if !ok || dev != "8:48" || root != "/usr/bin/ls" {
		t.Errorf("locate under root fs: %s %s %v", dev, root, ok)
	}
	dev, root, _ = locate("/tmp/t/agenthome", host)
	if dev != "0:75" || root != "/t/agenthome" {
		t.Errorf("locate under tmpfs: %s %s", dev, root)
	}
	dev, root, _ = locate("/tmp/t/stage", host)
	if dev != "0:87" || root != "/" {
		t.Errorf("locate a mount point itself: %s %s", dev, root)
	}
}
