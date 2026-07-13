package parser_test

import (
	"os"
	"testing"

	"github.com/wingaturumqi/mcp-shieldwall/internal/parser"
)

func TestParseStandard(t *testing.T) {
	configJSON := []byte(`{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user"],
				"env": {}
			},
			"github": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-github"],
				"env": {
					"GITHUB_TOKEN": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop"
				}
			},
			"remote-db": {
				"url": "https://db.example.com/mcp",
				"type": "sse"
			}
		}
	}`)

	tmpFile := t.TempDir() + "/test.json"
	if err := os.WriteFile(tmpFile, configJSON, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := parser.Parse(tmpFile, "claude")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Servers) != 3 {
		t.Fatalf("expected 3 servers, got %d", len(cfg.Servers))
	}

	names := make(map[string]bool)
	for _, s := range cfg.Servers {
		names[s.Name] = true
	}
	for _, expected := range []string{"filesystem", "github", "remote-db"} {
		if !names[expected] {
			t.Errorf("server %q not found", expected)
		}
	}
}

func TestParseVSCode(t *testing.T) {
	configJSON := []byte(`{
		"editor.fontSize": 14,
		"mcp": {
			"servers": {
				"test-server": {
					"command": "node",
					"args": ["server.js"]
				}
			}
		}
	}`)

	tmpFile := t.TempDir() + "/settings.json"
	if err := os.WriteFile(tmpFile, configJSON, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := parser.Parse(tmpFile, "vscode")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(cfg.Servers))
	}

	if cfg.Servers[0].Name != "test-server" {
		t.Errorf("expected name 'test-server', got '%s'", cfg.Servers[0].Name)
	}
}

func TestParseNoMCP(t *testing.T) {
	configJSON := []byte(`{"editor.fontSize": 14}`)

	tmpFile := t.TempDir() + "/settings.json"
	if err := os.WriteFile(tmpFile, configJSON, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := parser.Parse(tmpFile, "vscode")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Servers) != 0 {
		t.Fatalf("expected 0 servers, got %d", len(cfg.Servers))
	}
}
