package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDemoAndReport(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	p := filepath.Join(base, "case")
	var out, err bytes.Buffer
	code := Run(context.Background(), []string{"demo", "--case", p, "--format", "json", "--shareable"}, &out, &err, nil)
	if code != 2 {
		t.Fatalf("expected scoped partial demo: %d %s", code, err.String())
	}
	var report map[string]any
	if json.Unmarshal(out.Bytes(), &report) != nil {
		t.Fatal("invalid JSON output")
	}
	if strings.Contains(out.String(), "KEYRADAR_SYNTHETIC_NEVER_VALID_27d8d9") {
		t.Fatal("canary leak")
	}
	out.Reset()
	err.Reset()
	code = Run(context.Background(), []string{"report", "--case", p, "--format", "json", "--shareable"}, &out, &err, nil)
	if code != 2 {
		t.Fatal("report failed")
	}
}
func TestLocalCLIAndInvalidFlags(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	p := filepath.Join(base, "input.env")
	os.WriteFile(p, []byte("API_KEY=CLI_SOURCE_CANARY\n"), 0600)
	var out, err bytes.Buffer
	code := Run(context.Background(), []string{"scan", "--local-file", p, "--incident", "custom", "--format", "json", "--shareable"}, &out, &err, nil)
	if code != 0 {
		t.Fatalf("scan failed: %s", err.String())
	}
	if strings.Contains(out.String()+err.String(), "CLI_SOURCE_CANARY") {
		t.Fatal("canary leak")
	}
	out.Reset()
	err.Reset()
	code = Run(context.Background(), []string{"scan", "--token=SHOULD_NOT_ECHO"}, &out, &err, nil)
	if code != 1 || strings.Contains(out.String()+err.String(), "SHOULD_NOT_ECHO") {
		t.Fatal("unsafe argument diagnostic")
	}
}
