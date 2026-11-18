//go:build security

package daemon

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/H3mul/isolait/internal/session"
)

// The isolation regression gate (task 8.2): one live session, one probe from inside, and an assertion per
// property the sandbox exists to guarantee. `make isolation` runs this with the other isolation tests listed in
// the Makefile; CI must keep it green.
func TestIsolationRegressionSuite(t *testing.T) {
	e, spec, run := hotSession(t, nil)
	hostHome, _ := os.UserHomeDir()
	runtimeDir := session.Dir(e.base, spec.ID)
	me, _ := user.Current()
	out := run(`
echo capeff=$(grep CapEff /proc/self/status | awk '{print $2}')
echo capbnd=$(grep CapBnd /proc/self/status | awk '{print $2}')
echo nonewprivs=$(grep NoNewPrivs /proc/self/status | awk '{print $2}')
mount -t tmpfs none /tmp >/dev/null 2>&1; echo mount_rc=$?
unshare -U true >/dev/null 2>&1; echo userns_rc=$?
echo ifaces=$(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | tr '\n' ',')
echo hosthome=$(test -e ` + shq(hostHome) + `/.ssh && echo VISIBLE || echo absent)
echo runtimedir=$(test -e ` + shq(runtimeDir) + ` && echo VISIBLE || echo absent)
echo runtimebase=$(test -e ` + shq(e.base) + ` && echo VISIBLE || echo absent)
echo statedir=$(test -e ` + shq(e.state) + ` && echo VISIBLE || echo absent)
echo sockets=$(find / -xdev \( -path /proc -o -path /sys \) -prune -o -type s -print 2>/dev/null | head -5 | tr '\n' ',')
echo secret=${AWS_SECRET_ACCESS_KEY:-absent}
echo pid1=$(cat /proc/1/comm)
echo uid=$(id -u)
`)
	want := map[string]string{
		"capeff": "0000000000000000", "capbnd": "0000000000000000", "nonewprivs": "1",
		"hosthome": "absent", "runtimedir": "absent", "runtimebase": "absent", "statedir": "absent",
		"secret": "absent", "sockets": "",
	}
	for k, v := range want {
		if got := line(out, k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	for _, k := range []string{"mount_rc", "userns_rc"} {
		if got := line(out, k); got == "0" || got == "" {
			t.Errorf("%s = %q: the operation must fail inside the sandbox", k, got)
		}
	}
	if got := line(out, "ifaces"); got != "lo,tap0," {
		t.Errorf("network interfaces = %q, want only lo and the managed tap0", got)
	}
	if got := line(out, "uid"); got != me.Uid {
		t.Errorf("uid inside = %q, want the caller's %s", got, me.Uid)
	}
	if t.Failed() {
		t.Logf("probe output:\n%s", out)
	}
	// the control and attach sockets exist on the host, in a directory the sandbox cannot reach
	for _, p := range []string{session.SocketPath(e.base, spec.ID), session.AttachPath(e.base, spec.ID)} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("the host-side socket %s is missing: %v", filepath.Base(p), err)
		}
		if got := line(run(`test -e `+shq(p)+` && echo n=VISIBLE || echo n=absent`), "n"); got != "absent" {
			t.Errorf("%s is visible inside the sandbox", filepath.Base(p))
		}
	}
}

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
