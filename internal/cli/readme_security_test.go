//go:build security

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The README's quick start is executed as written against the real binary: every `$ isolait ...` command must
// succeed and print the documented output, with <sid>, <dir> and <age> standing for the values that vary.

type step struct {
	cmd    string
	expect []string
}

func readmeSteps(t *testing.T) []step {
	t.Helper()
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile("(?s)```console\n(.*?)```").FindAllStringSubmatch(string(b), -1)
	if len(block) == 0 {
		t.Fatal("no console block in README.md")
	}
	var steps []step
	for _, m := range block {
		for _, line := range strings.Split(strings.TrimRight(m[1], "\n"), "\n") {
			if strings.HasPrefix(line, "$ ") {
				steps = append(steps, step{cmd: strings.TrimPrefix(line, "$ ")})
			} else if len(steps) > 0 {
				steps[len(steps)-1].expect = append(steps[len(steps)-1].expect, line)
			}
		}
	}
	return steps
}

var sidRe = regexp.MustCompile(`[A-Za-z0-9._-]+-[0-9a-f]{4}\b`)

// normalize replaces the values that vary between runs with the placeholders the README uses.
func normalize(lines []string, dir string) []string {
	var out []string
	for _, l := range lines {
		l = strings.ReplaceAll(l, dir, "<dir>")
		l = sidRe.ReplaceAllString(l, "<sid>")
		f := strings.Fields(l)
		for i, x := range f {
			if regexp.MustCompile(`^\d+[smhd]$`).MatchString(x) {
				f[i] = "<age>"
			}
		}
		l = strings.Join(f, " ")
		if l == "" || strings.HasPrefix(l, "limits") || strings.HasPrefix(l, "seccomp") { // limits depend on the host's systemd; the denied count on the build
			continue
		}
		out = append(out, l)
	}
	return out
}

func TestReadmeQuickStartRunsAsWritten(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.Mkdir(bin, 0o755))
	build := exec.Command("go", "build", "-o", filepath.Join(bin, "isolait"), "../..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	short, err := os.MkdirTemp("", "iso") // short, private paths: the control socket path has a length limit
	must(err)
	t.Cleanup(func() { os.RemoveAll(short) })
	for _, d := range []string{"rt", "state", "cfg"} {
		must(os.Mkdir(filepath.Join(short, d), 0o700))
	}
	proj := filepath.Join(short, "api")
	must(os.Mkdir(proj, 0o755))
	proj, _ = filepath.EvalSymlinks(proj)

	env := append(os.Environ(),
		"PATH="+bin+":"+os.Getenv("PATH"),
		"XDG_RUNTIME_DIR="+filepath.Join(short, "rt"),
		"XDG_STATE_HOME="+filepath.Join(short, "state"),
		"XDG_CONFIG_HOME="+filepath.Join(short, "cfg"))
	run := func(command string) (string, error) {
		c := exec.Command("bash", "-c", command)
		c.Dir, c.Env = proj, env
		out, err := c.CombinedOutput()
		return string(out), err
	}
	t.Cleanup(func() { // never leave a session behind, whatever happened
		out, _ := run("isolait list")
		for _, id := range sidRe.FindAllString(out, -1) {
			run("isolait stop " + id)
		}
	})

	var sid string
	for _, s := range readmeSteps(t) {
		command := strings.ReplaceAll(s.cmd, "<sid>", sid)
		out, err := run(command)
		if err != nil {
			if strings.Contains(out, "operation not permitted") || strings.Contains(out, "prerequisite") {
				t.Skipf("this host cannot run sandboxes: %s", out)
			}
			t.Fatalf("`%s` failed: %v\n%s", s.cmd, err, out)
		}
		if strings.HasPrefix(command, "isolait start") {
			sid = sidRe.FindString(out)
			if sid == "" {
				t.Fatalf("no session id in the output of `%s`:\n%s", command, out)
			}
		}
		got := normalize(strings.Split(out, "\n"), proj)
		want := normalize(s.expect, "<never>")
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("`%s` output differs from the README.\n--- documented\n%s\n--- actual\n%s", s.cmd, strings.Join(want, "\n"), strings.Join(got, "\n"))
		}
	}
}
