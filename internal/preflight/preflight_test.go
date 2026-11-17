package preflight

import (
	"errors"
	"strings"
	"testing"
)

func good() Probes {
	return Probes{
		Bwrap:    func() (string, error) { return "0.13.1", nil },
		UserNS:   func() error { return nil },
		Sysctl:   func(string) (string, bool) { return "", false },
		MountAPI: func() error { return nil },
		Tun:      func() error { return nil },
	}
}

func problems(t *testing.T, p Probes) []Problem {
	t.Helper()
	err := Run(p)
	if err == nil {
		return nil
	}
	var pe *Error
	if !errors.As(err, &pe) {
		t.Fatalf("unexpected error type %T", err)
	}
	return pe.Problems
}

func TestAllGood(t *testing.T) {
	if got := problems(t, good()); got != nil {
		t.Fatalf("expected no problems, got %v", got)
	}
}

func TestEachFailure(t *testing.T) {
	sysctl := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	tests := []struct {
		name      string
		mutate    func(*Probes)
		check     string
		detailHas string
		fixHas    string
	}{
		{"bwrap missing", func(p *Probes) { p.Bwrap = func() (string, error) { return "", errors.New("bwrap not found in PATH") } }, "bubblewrap", "not found", "install bubblewrap"},
		{"bwrap too old", func(p *Probes) { p.Bwrap = func() (string, error) { return "0.7.9", nil } }, "bubblewrap", "older than 0.8.0", "upgrade"},
		{"userns apparmor", func(p *Probes) {
			p.UserNS = func() error { return errors.New("exit 1") }
			p.Sysctl = sysctl(map[string]string{"kernel.apparmor_restrict_unprivileged_userns": "1"})
		}, "user namespaces", "AppArmor", "kernel.apparmor_restrict_unprivileged_userns"},
		{"userns clone sysctl", func(p *Probes) {
			p.UserNS = func() error { return errors.New("exit 1") }
			p.Sysctl = sysctl(map[string]string{"kernel.unprivileged_userns_clone": "0"})
		}, "user namespaces", "unprivileged_userns_clone=0", "sysctl -w"},
		{"userns max zero", func(p *Probes) {
			p.UserNS = func() error { return errors.New("exit 1") }
			p.Sysctl = sysctl(map[string]string{"user.max_user_namespaces": "0"})
		}, "user namespaces", "max_user_namespaces=0", "raise it"},
		{"userns unknown cause", func(p *Probes) { p.UserNS = func() error { return errors.New("exit 1") } }, "user namespaces", "could not create", "bwrap --unshare-user"},
		{"mount api", func(p *Probes) {
			p.MountAPI = func() error { return errors.New("open_tree unavailable: function not implemented") }
		}, "new mount API", "open_tree", "5.12"},
		{"tun", func(p *Probes) {
			p.Tun = func() error { return errors.New("open /dev/net/tun: no such file or directory") }
		}, "/dev/net/tun", "no such file", "modprobe tun"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := good()
			tc.mutate(&p)
			got := problems(t, p)
			if len(got) != 1 {
				t.Fatalf("want exactly 1 problem, got %v", got)
			}
			if got[0].Check != tc.check || !strings.Contains(got[0].Detail, tc.detailHas) || !strings.Contains(got[0].Fix, tc.fixHas) {
				t.Fatalf("unexpected problem %+v", got[0])
			}
		})
	}
}

func TestUsernsProbeSkippedWithoutBwrap(t *testing.T) {
	p := good()
	p.Bwrap = func() (string, error) { return "", errors.New("bwrap not found in PATH") }
	p.UserNS = func() error { t.Fatal("userns probe must not run without bwrap"); return nil }
	if got := problems(t, p); len(got) != 1 {
		t.Fatalf("want 1 problem, got %v", got)
	}
}

func TestAllProblemsReportedTogether(t *testing.T) {
	p := Probes{
		Bwrap:    func() (string, error) { return "", errors.New("missing") },
		UserNS:   func() error { return nil },
		Sysctl:   func(string) (string, bool) { return "", false },
		MountAPI: func() error { return errors.New("x") },
		Tun:      func() error { return errors.New("y") },
	}
	err := Run(p)
	if err == nil || !strings.Contains(err.Error(), "3 prerequisite(s) missing") {
		t.Fatalf("got %v", err)
	}
}

func TestCmpVersion(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"0.8.0", "0.8.0", 0}, {"0.13.1", "0.8.0", 1}, {"0.8", "0.8.0", 0}, {"0.7.9", "0.8.0", -1}, {"1.0", "0.99.9", 1}} {
		if got := cmpVersion(c.a, c.b); got != c.want {
			t.Errorf("cmpVersion(%s,%s)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}
