package cli

import (
	"bytes"
	"strings"
	"testing"
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
	for _, name := range []string{"init", "preflight"} {
		c, _, err := root.Find([]string{name})
		if err != nil || c.Name() != name || !c.Hidden {
			t.Errorf("%s: %v hidden=%v", name, err, c != nil && c.Hidden)
		}
	}
}
