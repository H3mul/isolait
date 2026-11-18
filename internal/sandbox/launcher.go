package sandbox

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

const (
	launcherMaxSize    = 64 << 10 // larger files are not scanned
	launcherMaxDepth   = 3
	launcherMaxTargets = 8
)

// launcherTargets reports the absolute executables a launcher script runs, following nested launchers to
// depth 3 and stopping at 8 targets. The result is every target reached (nested launchers included), in
// discovery order, without duplicates. A file that is not a short `#!` text script yields nothing. Only
// commands whose first word is a literal absolute path are found: variables and substitutions are not
// followed (documented limit; use `tools`).
func launcherTargets(script string) []string {
	var out []string
	seen := map[string]bool{script: true}
	var walk func(path string, depth int)
	walk = func(path string, depth int) {
		for _, t := range scriptTargets(path) {
			if len(out) >= launcherMaxTargets {
				return
			}
			if seen[t] {
				continue
			}
			seen[t] = true
			out = append(out, t)
			if depth < launcherMaxDepth {
				walk(t, depth+1)
			}
		}
	}
	walk(script, 1)
	return out
}

// scriptTargets scans one file; it returns nothing unless the file is a launcher script.
func scriptTargets(path string) []string {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > launcherMaxSize {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.HasPrefix(data, []byte("#!")) || bytes.IndexByte(data, 0) >= 0 {
		return nil
	}
	var out []string
	lines := strings.Split(string(data), "\n")
	for _, ln := range lines[1:] { // line 0 is the shebang
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		w := strings.Fields(ln)
		if w[0] == "exec" {
			w = w[1:]
		}
		if len(w) == 0 {
			continue
		}
		p := strings.Trim(w[0], `"'`)
		if !filepath.IsAbs(p) || strings.ContainsAny(p, "$`\\*?[{(") || filepath.Clean(p) != p {
			continue
		}
		if fi, err := os.Stat(p); err != nil || fi.IsDir() || fi.Mode()&0o111 == 0 {
			continue
		}
		out = append(out, p)
	}
	return out
}
