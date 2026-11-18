package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/H3mul/isolait/internal/daemon"
)

func TestVersionCommand(t *testing.T) {
	var out bytes.Buffer
	cmd := Root()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.HasPrefix(got, "isolait ") || !strings.HasSuffix(got, "\n") {
		t.Fatalf("unexpected output %q", got)
	}
}

func TestVersionRejectsArgs(t *testing.T) {
	cmd := Root()
	cmd.SetArgs([]string{"version", "extra"})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for extra arguments")
	}
}

// Internal commands exist but stay out of the help text.
func TestInternalCommandsAreHidden(t *testing.T) {
	root := Root()
	for _, name := range []string{"init", "preflight", "netd"} {
		c, _, err := root.Find([]string{name})
		if err != nil || c.Name() != name || !c.Hidden {
			t.Errorf("%s: %v hidden=%v", name, err, c != nil && c.Hidden)
		}
	}
}

func TestLimitsLine(t *testing.T) {
	for _, tc := range []struct {
		in   daemon.LimitsStatus
		want string
	}{
		{daemon.LimitsStatus{Available: true, PidsCurrent: 12, PidsMax: 4096, MemoryCurrent: 3 << 20}, "processes 12 of 4096, memory 3M used"},
		{daemon.LimitsStatus{Available: true, PidsCurrent: 3, MemoryCurrent: 2 << 30, MemoryMax: 8 << 30}, "processes 3 of no limit, memory 2.0G used of 8.0G"},
		{daemon.LimitsStatus{Reason: "unavailable: no systemd user manager (systemd-run not found)"}, "unavailable (no systemd user manager (systemd-run not found))"},
	} {
		if got := limitsLine(tc.in); got != tc.want {
			t.Errorf("limitsLine = %q, want %q", got, tc.want)
		}
	}
}
