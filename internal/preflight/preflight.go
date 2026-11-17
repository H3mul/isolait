// Package preflight checks the host prerequisites before a session starts and reports every missing one
// with a cause and a fix. All host access goes through Probes so each failure can be faked in tests.
package preflight

import (
	"fmt"
	"strconv"
	"strings"
)

// MinBwrap is the oldest bubblewrap with --disable-userns.
const MinBwrap = "0.8.0"

// Probes is the host surface the checks read. System() returns the real one.
type Probes struct {
	Bwrap    func() (version string, err error) // locate bwrap and return its version number, e.g. "0.13.1"
	UserNS   func() error                       // try an unprivileged user namespace through bwrap
	Sysctl   func(name string) (string, bool)   // read a sysctl such as "user.max_user_namespaces"
	MountAPI func() error                       // nil if open_tree, move_mount and mount_setattr exist
	Tun      func() error                       // nil if /dev/net/tun can be opened
}

// Problem is one failed prerequisite.
type Problem struct{ Check, Detail, Fix string }

// Error aggregates every failed prerequisite so the user fixes them in one pass.
type Error struct{ Problems []Problem }

func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d prerequisite(s) missing:", len(e.Problems))
	for _, p := range e.Problems {
		fmt.Fprintf(&b, "\n  - %s: %s\n    fix: %s", p.Check, p.Detail, p.Fix)
	}
	return b.String()
}

// Run executes all checks and returns nil or an *Error.
func Run(p Probes) error {
	var out []Problem
	add := func(check, detail, fix string) { out = append(out, Problem{check, detail, fix}) }

	bwrapOK := false
	if v, err := p.Bwrap(); err != nil {
		add("bubblewrap", err.Error(), "install bubblewrap >= "+MinBwrap+" (apt install bubblewrap, pacman -S bubblewrap)")
	} else if cmpVersion(v, MinBwrap) < 0 {
		add("bubblewrap", fmt.Sprintf("version %s is older than %s (no --disable-userns)", v, MinBwrap), "upgrade bubblewrap to >= "+MinBwrap)
	} else {
		bwrapOK = true
	}

	if bwrapOK { // the probe runs bwrap, so it is meaningless without it
		if err := p.UserNS(); err != nil {
			detail, fix := usernsCause(p.Sysctl)
			add("user namespaces", fmt.Sprintf("%s (%v)", detail, err), fix)
		}
	}
	if err := p.MountAPI(); err != nil {
		add("new mount API", err.Error(), "needs Linux >= 5.12 (open_tree, move_mount, mount_setattr); on WSL2 run `wsl --update`; in a container, check the seccomp profile")
	}
	if err := p.Tun(); err != nil {
		add("/dev/net/tun", err.Error(), "load the driver (`sudo modprobe tun`), and make /dev/net/tun accessible to your user (udev rule or group); in a container pass --device /dev/net/tun")
	}
	if len(out) > 0 {
		return &Error{out}
	}
	return nil
}

// usernsCause turns sysctl state into the most specific explanation available.
func usernsCause(sysctl func(string) (string, bool)) (detail, fix string) {
	if v, ok := sysctl("kernel.apparmor_restrict_unprivileged_userns"); ok && v == "1" {
		return "AppArmor restricts unprivileged user namespaces (kernel.apparmor_restrict_unprivileged_userns=1)",
			"check with `sysctl kernel.apparmor_restrict_unprivileged_userns`; allow bwrap with an AppArmor profile that grants `userns`, or set the sysctl to 0"
	}
	if v, ok := sysctl("kernel.unprivileged_userns_clone"); ok && v == "0" {
		return "unprivileged user namespaces are disabled (kernel.unprivileged_userns_clone=0)",
			"check with `sysctl kernel.unprivileged_userns_clone`; set it to 1 (`sudo sysctl -w kernel.unprivileged_userns_clone=1`)"
	}
	if v, ok := sysctl("user.max_user_namespaces"); ok && v == "0" {
		return "user namespaces are disabled (user.max_user_namespaces=0)",
			"check with `sysctl user.max_user_namespaces`; raise it (`sudo sysctl -w user.max_user_namespaces=15000`)"
	}
	return "bwrap could not create an unprivileged user namespace",
		"run `bwrap --unshare-user --ro-bind / / true` to see the kernel error; see sysctl kernel.apparmor_restrict_unprivileged_userns, kernel.unprivileged_userns_clone and user.max_user_namespaces"
}

// cmpVersion compares dotted numeric versions; missing or non-numeric parts count as 0.
func cmpVersion(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		x, y := part(pa, i), part(pb, i)
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func part(p []string, i int) int {
	if i >= len(p) {
		return 0
	}
	n, _ := strconv.Atoi(p[i])
	return n
}
