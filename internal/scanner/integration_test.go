package scanner_test

import (
	"os"
	"testing"

	"github.com/wingaturumqi/mcp-shieldwall/internal/parser"
	"github.com/wingaturumqi/mcp-shieldwall/internal/scanner"
)

func TestScanIntegration_VulnerableConfig(t *testing.T) {
	fixture := "../../testdata/fixtures/vulnerable.json"
	if _, err := os.Stat(fixture); err != nil {
		t.Skip("fixture not found")
	}

	cfg, err := parser.Parse(fixture, "claude")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	// Debug: check parsed servers
	for _, s := range cfg.Servers {
		t.Logf("server: %s, cmd: %s, args: %v, url: %s", s.Name, s.Command, s.Args, s.URL)
	}

	findings := scanner.Scan(cfg)

	for _, f := range findings {
		t.Logf("finding: [%s] %s - %s", f.OWASP, f.Severity, f.Title)
	}

	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings from vulnerable config, got %d", len(findings))
	}

	hasSecret := false
	for _, f := range findings {
		if f.OWASP == "MCP01" {
			hasSecret = true
		}
	}
	if !hasSecret {
		t.Error("expected MCP01 (secret) finding from vulnerable config")
	}
}

func TestScanIntegration_CleanConfig(t *testing.T) {
	cleanJSON := []byte(`{
		"mcpServers": {
			"safe-server": {
				"command": "node",
				"args": ["server.js"],
				"env": { "NODE_ENV": "production" }
			}
		}
	}`)

	tmpFile := t.TempDir() + "/clean.json"
	if err := os.WriteFile(tmpFile, cleanJSON, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := parser.Parse(tmpFile, "claude")
	if err != nil {
		t.Fatal(err)
	}

	findings := scanner.Scan(cfg)
	for _, f := range findings {
		if f.Severity.String() == "CRITICAL" || f.Severity.String() == "HIGH" {
			t.Errorf("unexpected %s finding in clean config: %s", f.Severity, f.Title)
		}
	}
}
