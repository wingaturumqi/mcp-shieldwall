package scanner

import (
	"strings"

	"github.com/wingaturumqi/mcp-shieldwall/internal/model"
)

// CheckCommandInjection checks if a server's args allow shell command injection
func CheckCommandInjection(cfg *model.MCPConfig, server model.MCPServer) []model.Finding {
	var findings []model.Finding

	if server.Transport != "stdio" {
		return findings
	}

	// Check if command is a shell interpreter
	shellCommands := []string{"sh", "bash", "cmd", "powershell", "pwsh", "zsh", "fish"}
	cmd := strings.ToLower(server.Command)
	for _, shell := range shellCommands {
		if cmd == shell || strings.HasSuffix(cmd, "/"+shell) || strings.HasSuffix(cmd, "\\"+shell) {
			findings = append(findings, model.Finding{
				ServerName: server.Name,
				Severity:   model.MEDIUM,
				OWASP:      "MCP05",
				Title:      "Shell interpreter used as command",
				Detail:     "Server uses " + server.Command + " as the base command, which may allow arbitrary command execution",
				Suggestion: "Use the target program directly instead of wrapping in a shell",
				FilePath:   cfg.Path,
			})
			break
		}
	}

	// Check for shell flags in args
	shellFlags := []string{"-c", "/c", "-Command", "-EncodedCommand"}
	for _, arg := range server.Args {
		for _, flag := range shellFlags {
			if arg == flag {
				findings = append(findings, model.Finding{
					ServerName: server.Name,
					Severity:   model.HIGH,
					OWASP:      "MCP05",
					Title:      "Shell command execution flag detected",
					Detail:     "Argument " + flag + " enables shell command execution, which can be exploited via prompt injection",
					Suggestion: "Avoid shell flags; use direct command invocation instead",
					FilePath:   cfg.Path,
				})
			}
		}
	}

	return findings
}

// CheckAuth checks if the MCP server has proper authentication configured
func CheckAuth(cfg *model.MCPConfig, server model.MCPServer) []model.Finding {
	var findings []model.Finding

	// For SSE/HTTP servers, check if URL has auth indicators
	if server.Transport == "sse" || server.Transport == "streamable-http" {
		if server.URL != "" {
			// Check if URL uses localhost (lower risk) or remote
			if !isLocalhost(server.URL) {
				hasAuth := false
				// Check env for auth tokens
				for key := range server.Env {
					lower := strings.ToLower(key)
					if strings.Contains(lower, "token") || strings.Contains(lower, "key") ||
						strings.Contains(lower, "auth") || strings.Contains(lower, "secret") {
						hasAuth = true
						break
					}
				}
				// Check URL for embedded credentials
				if strings.Contains(server.URL, "@") {
					hasAuth = true
				}

				if !hasAuth {
					findings = append(findings, model.Finding{
						ServerName: server.Name,
						Severity:   model.MEDIUM,
						OWASP:      "MCP07",
						Title:      "Remote MCP server without authentication",
						Detail:     "Server connects to " + server.URL + " but has no authentication configured",
						Suggestion: "Add authentication tokens to environment variables or URL",
						FilePath:   cfg.Path,
					})
				}
			}
		}
	}

	return findings
}

func isLocalhost(url string) bool {
	localhostPatterns := []string{
		"localhost", "127.0.0.1", "::1", "0.0.0.0",
	}
	lower := strings.ToLower(url)
	for _, p := range localhostPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

