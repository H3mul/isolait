package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/H3mul/isolait/internal/config"
	"github.com/H3mul/isolait/internal/trust"
)

func runTrust(t *testing.T, p config.Paths, args ...string) (string, error) {
	t.Helper()
	cmd := trustCmd(func() (config.Paths, error) { return p, nil })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestTrustThenLoadApplies(t *testing.T) {
	root := t.TempDir()
	p := config.Paths{GlobalDir: filepath.Join(root, "cfg"), StateDir: filepath.Join(root, "state")}
	ws := filepath.Join(root, "ws")
	body := "max_port_range = 33\n"
	if err := os.MkdirAll(filepath.Join(ws, ".isolait"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, ".isolait", "config"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := trust.Open(p.StateDir)

	res, err := config.Load(p, ws, config.Layer{}, tr)
	if err != nil || res.Config.MaxPortRange == 33 || len(res.Warnings) != 1 {
		t.Fatalf("before trust: %v %+v", err, res)
	}
	out, err := runTrust(t, p, ws)
	if err != nil || !strings.Contains(out, body) || !strings.Contains(out, "trusted sha256:") {
		t.Fatalf("trust: %v %q", err, out)
	}
	res, err = config.Load(p, ws, config.Layer{}, tr)
	if err != nil || res.Config.MaxPortRange != 33 || len(res.Warnings) != 0 {
		t.Fatalf("after trust: %v %+v", err, res)
	}
}

func TestTrustRefusals(t *testing.T) {
	root := t.TempDir()
	p := config.Paths{StateDir: filepath.Join(root, "state")}

	if _, err := runTrust(t, p, root); err == nil || !strings.Contains(err.Error(), "nothing to trust") {
		t.Fatalf("no config: %v", err)
	}

	os.MkdirAll(filepath.Join(root, ".isolait"), 0o755)
	os.WriteFile(filepath.Join(root, ".isolait", "config"), []byte("bogus = 1\n"), 0o644)
	if _, err := runTrust(t, p, root); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("invalid config trusted: %v", err)
	}
	if ok, _ := trust.Open(p.StateDir).IsTrusted(trust.Sum([]byte("bogus = 1\n"))); ok {
		t.Fatal("an invalid config was recorded as trusted")
	}
}
