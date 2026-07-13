package scanner_test

import (
	"testing"

	"github.com/wingaturumqi/mcp-shieldwall/internal/model"
	"github.com/wingaturumqi/mcp-shieldwall/internal/scanner"
)

func TestCheckSecrets_GitHubToken(t *testing.T) {
	cfg := &model.MCPConfig{Path: "test.json"}
	server := model.MCPServer{
		Name:      "github",
		Transport: "stdio",
		Env: map[string]string{
			"GITHUB_TOKEN": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop",
		},
	}

	findings := scanner.CheckSecrets(cfg, server)

	if len(findings) == 0 {
		t.Fatal("expected findings for GitHub token, got none")
	}

	found := false
	for _, f := range findings {
		if f.Severity == model.CRITICAL && f.OWASP == "MCP01" {
			found = true
		}
	}
	if !found {
		t.Error("expected CRITICAL finding with OWASP MCP01")
	}
}

func TestCheckSecrets_CleanEnv(t *testing.T) {
	cfg := &model.MCPConfig{Path: "test.json"}
	server := model.MCPServer{
		Name:      "clean",
		Transport: "stdio",
		Env: map[string]string{
			"NODE_ENV": "production",
			"DEBUG":    "false",
		},
	}

	findings := scanner.CheckSecrets(cfg, server)

	if len(findings) != 0 {
		t.Errorf("expected no findings for clean env, got %d", len(findings))
	}
}

func TestCheckSecrets_VarReference(t *testing.T) {
	cfg := &model.MCPConfig{Path: "test.json"}
	server := model.MCPServer{
		Name:      "safe",
		Transport: "stdio",
		Env: map[string]string{
			"GITHUB_TOKEN": "${GITHUB_TOKEN}",
		},
	}

	findings := scanner.CheckSecrets(cfg, server)

	// Variable references should not be flagged as secrets
	for _, f := range findings {
		if f.Severity == model.CRITICAL {
			t.Error("variable reference should not be flagged as CRITICAL")
		}
	}
}

func TestCheckPermissions_BroadAccess(t *testing.T) {
	cfg := &model.MCPConfig{Path: "test.json"}
	server := model.MCPServer{
		Name:      "filesystem",
		Transport: "stdio",
		Command:   "npx",
		Args:      []string{"-y", "@modelcontextprotocol/server-filesystem", "C:\\"},
	}

	findings := scanner.CheckPermissions(cfg, server)

	if len(findings) == 0 {
		t.Fatal("expected findings for broad access, got none")
	}
}

func TestCheckCommandInjection_ShellCommand(t *testing.T) {
	cfg := &model.MCPConfig{Path: "test.json"}
	server := model.MCPServer{
		Name:      "shell",
		Transport: "stdio",
		Command:   "bash",
		Args:      []string{"-c", "echo hello"},
	}

	findings := scanner.CheckCommandInjection(cfg, server)

	if len(findings) == 0 {
		t.Fatal("expected findings for shell command, got none")
	}
}

func TestCheckAuth_RemoteNoAuth(t *testing.T) {
	cfg := &model.MCPConfig{Path: "test.json"}
	server := model.MCPServer{
		Name:      "remote",
		Transport: "sse",
		URL:       "https://db.example.com/mcp",
	}

	findings := scanner.CheckAuth(cfg, server)

	if len(findings) == 0 {
		t.Fatal("expected findings for remote server without auth, got none")
	}
}

func TestCheckAuth_Localhost(t *testing.T) {
	cfg := &model.MCPConfig{Path: "test.json"}
	server := model.MCPServer{
		Name:      "local",
		Transport: "sse",
		URL:       "http://localhost:3000/mcp",
	}

	findings := scanner.CheckAuth(cfg, server)

	// Localhost should not require auth
	if len(findings) != 0 {
		t.Errorf("expected no findings for localhost, got %d", len(findings))
	}
}
