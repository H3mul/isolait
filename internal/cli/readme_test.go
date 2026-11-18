package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// The README must cover every user-facing command and flag: a command or flag that is added without
// documentation fails here.
func TestReadmeDocumentsEveryCommandAndFlag(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(b)
	root := rootWith(realDeps())
	for _, c := range root.Commands() {
		if c.Hidden || c.Name() == "help" || c.Name() == "completion" || c.Name() == "version" || c.Name() == "trust" {
			continue // trust is documented in docs/config.md
		}
		if !strings.Contains(readme, "isolait "+c.Name()) {
			t.Errorf("README does not mention `isolait %s`", c.Name())
		}
	}
	start, _, _ := root.Find([]string{"start"})
	start.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Name == "help" {
			return
		}
		if !strings.Contains(readme, "--"+f.Name) {
			t.Errorf("README does not document start's --%s", f.Name)
		}
	})
	for _, want := range []string{"no scrollback", "tmux", "Ctrl-\\", "bracketed-paste", "alternate screen", "OSC 52"} {
		if !strings.Contains(readme, want) {
			t.Errorf("README lacks %q", want)
		}
	}
}
