package sandbox

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestLauncherTargets(t *testing.T) {
	d := realTemp(t)
	bin := filepath.Join(d, "opt/x/bin/real")
	write(t, bin, "\x7fELF\x00\x01binary", 0o755)
	other := filepath.Join(d, "opt/y/tool")
	write(t, other, "\x7fELF\x00", 0o755)
	sh := func(name, body string) string {
		p := filepath.Join(d, "launch", name)
		write(t, p, body, 0o755)
		return p
	}
	cases := []struct {
		name, body string
		want       []string
	}{
		{"exec form", "#!/bin/sh\nexec " + bin + " \"$@\"\n", []string{bin}},
		{"bare command", "#!/bin/sh\n" + bin + " --flag\n", []string{bin}},
		{"quoted", "#!/bin/sh\nexec \"" + bin + "\" \"$@\"\n", []string{bin}},
		{"comment lines", "#!/bin/sh\n# exec " + other + "\n  # " + other + "\nexec " + bin + "\n", []string{bin}},
		{"variable path", "#!/bin/sh\nexec $HOME/bin/real \"$@\"\nexec " + d + "/opt/${X}/bin/real\n", nil},
		{"substitution", "#!/bin/sh\nexec $(dirname \"$0\")/real\n", nil},
		{"missing target", "#!/bin/sh\nexec " + d + "/nope\n", nil},
		{"directory target", "#!/bin/sh\nexec " + d + "/opt\n", nil},
		{"not a script", "exec " + bin + "\n", nil},
		{"binary file", "#!/bin/sh\x00\nexec " + bin + "\n", nil},
		{"oversized", "#!/bin/sh\n" + strings.Repeat("# pad\n", 12000) + "exec " + bin + "\n", nil},
		{"two targets", "#!/bin/sh\n" + other + " a\nexec " + bin + "\n", []string{other, bin}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := launcherTargets(sh(strings.ReplaceAll(c.name, " ", "_"), c.body))
			if !slices.Equal(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestLauncherNestedLoopAndLimits(t *testing.T) {
	d := realTemp(t)
	real := filepath.Join(d, "real")
	write(t, real, "\x7fELF\x00", 0o755)

	// nested: a -> b -> real; both launcher and final target are reported
	a, b := filepath.Join(d, "a"), filepath.Join(d, "b")
	write(t, a, "#!/bin/sh\nexec "+b+"\n", 0o755)
	write(t, b, "#!/bin/sh\nexec "+real+"\n", 0o755)
	if got := launcherTargets(a); !slices.Equal(got, []string{b, real}) {
		t.Errorf("nested: %v", got)
	}

	// loop: x -> y -> x terminates
	x, y := filepath.Join(d, "x"), filepath.Join(d, "y")
	write(t, x, "#!/bin/sh\nexec "+y+"\n", 0o755)
	write(t, y, "#!/bin/sh\nexec "+x+"\n", 0o755)
	if got := launcherTargets(x); !slices.Equal(got, []string{y}) {
		t.Errorf("loop: %v", got)
	}

	// depth: chain l0 -> l1 -> l2 -> l3 -> real; targets beyond depth 3 are not scanned
	l := func(i int) string { return filepath.Join(d, fmt.Sprintf("l%d", i)) }
	for i := 0; i < 4; i++ {
		next := real
		if i < 3 {
			next = l(i + 1)
		}
		write(t, l(i), "#!/bin/sh\nexec "+next+"\n", 0o755)
	}
	// l3 is the 3rd target found; it is a launcher but depth 3 is spent, so real is not reached
	if got := launcherTargets(l(0)); !slices.Equal(got, []string{l(1), l(2), l(3)}) {
		t.Errorf("depth: %v", got)
	}

	// count: at most 8 targets
	var body strings.Builder
	body.WriteString("#!/bin/sh\n")
	for i := 0; i < 12; i++ {
		p := filepath.Join(d, fmt.Sprintf("t%d", i))
		write(t, p, "\x7fELF\x00", 0o755)
		body.WriteString(p + "\n")
	}
	many := filepath.Join(d, "many")
	write(t, many, body.String(), 0o755)
	if got := launcherTargets(many); len(got) != 8 {
		t.Errorf("count: %d targets, want 8", len(got))
	}
}

// launcherFixture builds a wrapper in "sys" (made a system dir for the test) that execs a binary in "opt".
func launcherFixture(t *testing.T) (wrapper, bin, sys string) {
	d := realTemp(t)
	sys = filepath.Join(d, "sys")
	bin = filepath.Join(d, "opt/claude-code/bin/claude")
	write(t, bin, "\x7fELF\x00", 0o755)
	wrapper = filepath.Join(sys, "bin/claude")
	write(t, wrapper, "#!/bin/sh\nexec "+bin+" \"$@\"\n", 0o755)
	old := SystemDirs
	SystemDirs = append([]string{sys}, old...)
	t.Cleanup(func() { SystemDirs = old })
	return
}

func TestLauncherInSystemDirExposesTarget(t *testing.T) {
	wrapper, bin, _ := launcherFixture(t)
	b, err := ResolveBinaries(BinOptions{Agent: "claude", HostPath: filepath.Dir(wrapper)})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(b.Roots, []string{bin}) { // the file itself: its directory is a generic bin
		t.Errorf("Roots %v, want [%s]", b.Roots, bin)
	}
	if len(b.Warnings) != 1 || !strings.Contains(b.Warnings[0], "launcher script; also exposing "+bin) {
		t.Errorf("warnings %v", b.Warnings)
	}
}

func TestLauncherTargetAlreadyMountedIsSilent(t *testing.T) {
	wrapper, bin, _ := launcherFixture(t)
	b, err := ResolveBinaries(BinOptions{Agent: "claude", HostPath: filepath.Dir(wrapper), Tools: []string{filepath.Dir(filepath.Dir(bin))}})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Warnings) != 0 || len(b.Roots) != 1 {
		t.Errorf("roots %v warnings %v", b.Roots, b.Warnings)
	}
}

func TestLauncherTargetRefusedByDenyList(t *testing.T) {
	wrapper, bin, _ := launcherFixture(t)
	var vetted string
	deny := func(dir string) error { vetted = dir; return fmt.Errorf("refusing to mount a directory inside /state") }
	_, err := ResolveBinaries(BinOptions{Agent: "claude", HostPath: filepath.Dir(wrapper), Deny: deny})
	if err == nil || !strings.Contains(err.Error(), bin) || !strings.Contains(err.Error(), "refusing to mount a directory inside /state") {
		t.Fatalf("err %v", err)
	}
	if vetted != filepath.Dir(bin) {
		t.Errorf("vetted %q", vetted)
	}
}
