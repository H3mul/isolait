package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = "testdata/audit/sample"

// copySample copies the saved sample run (the 2026-11-18 manual run, ANSI stripped, user name redacted) to a temp dir
// where a test can change one file.
func copySample(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	es, _ := os.ReadDir(sample)
	for _, e := range es {
		b, _ := os.ReadFile(filepath.Join(sample, e.Name()))
		os.WriteFile(filepath.Join(d, e.Name()), b, 0o644)
	}
	return d
}

func edit(t *testing.T, dir, file, old, new string) {
	t.Helper()
	p := filepath.Join(dir, file)
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), old) {
		t.Fatalf("%s lacks %q: the sample changed", file, old)
	}
	os.WriteFile(p, []byte(strings.Replace(string(b), old, new, 1)), 0o644)
}

func ids(fs []Finding) string {
	var s []string
	for _, f := range fs {
		s = append(s, f.ID)
	}
	return strings.Join(s, ",")
}

func TestSampleRunPasses(t *testing.T) {
	r, err := Check(sample, nil)
	if err != nil || len(r.Findings) != 0 {
		t.Fatalf("the saved clean run fails: %v %v", err, ids(r.Findings))
	}
	if len(r.Passed) < 12 {
		t.Errorf("only %d assertions ran: an extractor silently stopped matching", len(r.Passed))
	}
}

func TestEachExtractorCatchesItsFinding(t *testing.T) {
	for _, c := range []struct{ name, file, old, new, id string }{
		{"seccomp missing", "linpeas.txt", "Seccomp enabled? ............... enabled", "Seccomp enabled? ............... disabled", "linpeas:seccomp"},
		{"nonewprivs", "linpeas.txt", "enabled (1)", "disabled (0)", "linpeas:nonewprivs"},
		{"kernel exploit", "linpeas.txt", "No rule matched current kernel/version prerequisites in embedded datasets.", "[!] CVE-2099-0001 likely vulnerable", "linpeas:kernel-cve:CVE-2099-0001"},
		{"docker sock", "deepce.txt", "Docker Sock ............. Not Found", "Docker Sock ............. /var/run/docker.sock", "deepce:docker-sock"},
		{"docker group", "deepce.txt", "User in Docker group .... No", "User in Docker group .... Yes", "deepce:docker-group"},
		{"botb exit", "botb-metadata.exit", "0", "1", "botb:metadata"},
	} {
		d := copySample(t)
		edit(t, d, c.file, c.old, c.new)
		r, _ := Check(d, nil)
		if !strings.Contains(ids(r.Findings), c.id) {
			t.Errorf("%s: want finding %s, got %q", c.name, c.id, ids(r.Findings))
		}
	}
}

// The gpg-agent lesson: a socket that appears after the tools started is their own side effect; one that existed
// before is a host leak.
func TestSocketCreatedDuringTheRunIsNotALeak(t *testing.T) {
	d := copySample(t)
	if r, _ := Check(d, nil); len(r.Findings) != 0 {
		t.Fatalf("created-during-run sockets failed: %s", ids(r.Findings))
	}
}

func TestSocketThatExistedBeforeIsALeak(t *testing.T) {
	d := copySample(t)
	os.WriteFile(filepath.Join(d, "sockets-before.txt"), []byte("/run/user/UID/gnupg/S.gpg-agent\n"), 0o644)
	r, _ := Check(d, nil)
	if !strings.Contains(ids(r.Findings), "botb:find-sockets:/run/user/UID/gnupg/S.gpg-agent") {
		t.Errorf("a pre-existing socket was not flagged: %q", ids(r.Findings))
	}
}

func TestAllowListBothDirections(t *testing.T) {
	d := copySample(t)
	edit(t, d, "deepce.txt", "User in Docker group .... No", "User in Docker group .... Yes")
	allow := ParseAllow("# c\ndeepce:docker-group | test | me\nlinpeas:kernel-cve:CVE-2000-1 | gone | me\n")
	r, _ := Check(d, allow)
	if len(r.Findings) != 0 || ids(r.Allowed) != "deepce:docker-group" {
		t.Errorf("allowed finding not allowed: findings %q allowed %q", ids(r.Findings), ids(r.Allowed))
	}
	if len(r.Stale) != 1 || r.Stale[0] != "linpeas:kernel-cve:CVE-2000-1" {
		t.Errorf("stale allow entry not reported: %v", r.Stale)
	}
}

func TestIncompleteRunIsAnError(t *testing.T) {
	if _, err := Check(t.TempDir(), nil); err == nil {
		t.Error("an empty run directory was judged")
	}
}
