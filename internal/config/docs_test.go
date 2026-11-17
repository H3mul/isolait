package config

import (
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every key in docs/config.md (key table and example block) must be a real key, and every real key must
// be documented; the example block must load.
func TestDocumentedKeysMatchLoader(t *testing.T) {
	raw, err := os.ReadFile("../../docs/config.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)

	var fromTable []string
	for _, m := range regexp.MustCompile("(?m)^\\| `([a-z_]+)` \\|").FindAllStringSubmatch(doc, -1) {
		fromTable = append(fromTable, m[1])
	}
	block := regexp.MustCompile("(?s)```toml\n(.*?)```").FindStringSubmatch(doc)
	if block == nil {
		t.Fatal("no toml example block in docs/config.md")
	}
	var fromExample []string
	for _, m := range regexp.MustCompile("(?m)^([a-z_]+) = ").FindAllStringSubmatch(block[1], -1) {
		fromExample = append(fromExample, m[1])
	}

	var real []string
	rt := reflect.TypeOf(Layer{})
	for i := 0; i < rt.NumField(); i++ {
		real = append(real, rt.Field(i).Tag.Get("toml"))
	}
	for _, s := range [][]string{fromTable, fromExample, real} {
		sort.Strings(s)
	}
	if !reflect.DeepEqual(fromTable, real) {
		t.Errorf("key table %v != loader keys %v", fromTable, real)
	}
	if !reflect.DeepEqual(fromExample, real) {
		t.Errorf("example keys %v != loader keys %v", fromExample, real)
	}
	if _, err := Parse("docs/config.md example", []byte(block[1])); err != nil {
		t.Errorf("documented example does not load: %v", err)
	}
	if !strings.Contains(doc, "isolait trust") {
		t.Error("trust model not documented")
	}
}
