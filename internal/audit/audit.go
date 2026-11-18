// Package audit judges the output of a `make audit` run: it parses what the pinned third-party tools (linpeas,
// deepce, botb) printed inside a throwaway isolait session and turns it into pass or fail assertions. The tools
// are heuristics; the assertions are only the ones in the security-audit-tests design.
package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Finding is one failed assertion. ID is stable ("tool:check") so it can be allow-listed.
type Finding struct{ ID, Detail string }

// Result is the judgement of one run directory.
type Result struct {
	Findings []Finding // failed assertions that are not allowed
	Allowed  []Finding // failed assertions that known-findings.txt allows
	Stale    []string  // allowed ids that did not occur: the list should shrink
	Passed   []string  // assertions that held
}

func read(dir, name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	return string(b), err
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

type run struct {
	res    *Result
	failed map[string]bool
	allow  map[string]string
}

func (r *run) check(id string, ok bool, detail string) {
	if ok {
		r.res.Passed = append(r.res.Passed, id)
		return
	}
	r.failed[id] = true
	f := Finding{id, detail}
	if _, allowed := r.allow[id]; allowed {
		r.res.Allowed = append(r.res.Allowed, f)
	} else {
		r.res.Findings = append(r.res.Findings, f)
	}
}

// ParseAllow reads known-findings.txt: `id | reason | owner` per line, `#` comments.
func ParseAllow(s string) map[string]string {
	m := map[string]string{}
	for _, l := range lines(s) {
		if strings.HasPrefix(l, "#") {
			continue
		}
		p := strings.SplitN(l, "|", 2)
		id := strings.TrimSpace(p[0])
		if len(p) == 2 {
			m[id] = strings.TrimSpace(p[1])
		} else {
			m[id] = ""
		}
	}
	return m
}

// Check judges the run directory dir against the allow list (id -> reason).
func Check(dir string, allow map[string]string) (*Result, error) {
	r := &run{res: &Result{}, failed: map[string]bool{}, allow: allow}
	for _, f := range []string{"linpeas.txt", "deepce.txt", "sockets-before.txt", "sockets-after.txt"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			return nil, fmt.Errorf("incomplete run: %w", err)
		}
	}
	lin, _ := read(dir, "linpeas.txt")
	r.linpeas(lin)
	dc, _ := read(dir, "deepce.txt")
	r.deepce(dc)
	r.botb(dir)
	for id := range allow {
		if !r.failed[id] {
			r.res.Stale = append(r.res.Stale, id)
		}
	}
	sort.Strings(r.res.Stale)
	return r.res, nil
}

var cveRe = regexp.MustCompile(`CVE-\d{4}-\d+`)

func (r *run) linpeas(s string) {
	has := func(sub string) bool { return strings.Contains(s, sub) }
	r.check("linpeas:seccomp", regexp.MustCompile(`Seccomp enabled\? \.+ enabled`).MatchString(s), "linpeas does not report a seccomp filter")
	r.check("linpeas:nonewprivs", regexp.MustCompile(`NoNewPrivs \(this process\)\? \.+ enabled \(1\)`).MatchString(s), "NoNewPrivs is not set")
	// Kernel Exploit Registry: no rule may match, except documented CVEs
	if i := strings.Index(s, "Kernel Exploit Registry"); i >= 0 {
		sec := s[i:]
		if j := strings.Index(sec[10:], "╔══"); j >= 0 {
			sec = sec[:j+10]
		}
		matched := cveRe.FindAllString(sec, -1)
		r.check("linpeas:kernel-registry", has("No rule matched") || len(matched) == 0, "a kernel exploit rule matched")
		for _, c := range matched {
			r.check("linpeas:kernel-cve:"+c, false, "kernel exploit registry matched "+c)
		}
	} else {
		r.check("linpeas:kernel-registry", false, "section missing from the output (format change?)")
	}
	// the runtime-socket line must be empty
	for _, l := range strings.Split(s, "\n") {
		if i := strings.Index(l, "Interesting runtime sockets ..."); i >= 0 {
			rest := strings.TrimSpace(strings.TrimPrefix(l[i:], "Interesting runtime sockets ..."))
			r.check("linpeas:runtime-sockets", rest == "" || strings.HasPrefix(rest, "═╣"), "container runtime socket found: "+rest)
		}
	}
}

func (r *run) deepce(s string) {
	r.check("deepce:docker-sock", regexp.MustCompile(`Docker Sock \.+ Not Found`).MatchString(s), "a docker socket is reachable")
	r.check("deepce:docker-group", regexp.MustCompile(`User in Docker group \.+ No`).MatchString(s), "user is in the docker group")
	for _, l := range lines(s) {
		if strings.HasPrefix(l, "[+] CVE") {
			r.check("deepce:"+strings.Fields(l)[1], strings.HasSuffix(l, "No"), l)
		}
	}
}

func (r *run) botb(dir string) {
	for _, m := range []string{"recon", "find-docker", "metadata", "k8secrets", "scrape-gcp"} {
		code, _ := read(dir, "botb-"+m+".exit")
		r.check("botb:"+m, strings.TrimSpace(code) == "0", "exit status "+strings.TrimSpace(code))
	}
	// sockets: a path that existed before the tools started is a host leak; one created during the run is a side
	// effect of a tool (the gpg-agent case) and is only recorded
	before, _ := read(dir, "sockets-before.txt")
	existed := map[string]bool{}
	for _, l := range lines(before) {
		existed[l] = true
	}
	for _, m := range []string{"find-sockets", "find-http"} {
		out, _ := read(dir, "botb-"+m+".txt")
		for _, l := range lines(out) {
			if p, ok := strings.CutPrefix(l, "[!] Valid Socket: "); ok {
				r.check("botb:"+m+":"+p, !existed[p], "socket "+p+" existed before the tools started")
			}
		}
	}
}

// Summary renders the result as Markdown for the README section.
func (r *Result) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Audit summary\n\n%d assertions held, %d failed, %d known findings allowed.\n", len(r.Passed), len(r.Findings), len(r.Allowed))
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "\n- FAIL `%s`: %s", f.ID, f.Detail)
	}
	for _, f := range r.Allowed {
		fmt.Fprintf(&b, "\n- allowed `%s`: %s", f.ID, f.Detail)
	}
	for _, id := range r.Stale {
		fmt.Fprintf(&b, "\n- stale allow-list entry `%s` (no longer occurs; remove it)", id)
	}
	return b.String() + "\n"
}
