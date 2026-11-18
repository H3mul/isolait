// Command cmd judges a `make audit` run directory: go run ./internal/audit/cmd build/audit/<date>
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/H3mul/isolait/internal/audit"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: audit <run directory>")
		os.Exit(2)
	}
	dir := os.Args[1]
	b, _ := os.ReadFile(filepath.Join("internal", "audit", "testdata", "audit", "known-findings.txt"))
	res, err := audit.Check(dir, audit.ParseAllow(string(b)))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	s := res.Summary()
	os.WriteFile(filepath.Join(dir, "summary.md"), []byte(s), 0o644)
	fmt.Print(s)
	if len(res.Findings) > 0 {
		os.Exit(1)
	}
}
