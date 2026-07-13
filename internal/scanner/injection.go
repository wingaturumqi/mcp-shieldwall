package scanner

import (
	"regexp"
	"strings"

	"github.com/wingaturumqi/mcp-shieldwall/internal/model"
)

// injectionPattern defines a pattern for detecting prompt injection in tool descriptions
type injectionPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

var injectionPatterns = []injectionPattern{
	// Direct instruction override
	{"Instruction override", regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions`)},
	{"Instruction disregard", regexp.MustCompile(`(?i)disregard\s+(all\s+)?(previous|prior|above)`)},
	{"Instruction forget", regexp.MustCompile(`(?i)forget\s+(all\s+)?(previous|prior|above)`)},
	{"Instruction override v2", regexp.MustCompile(`(?i)override\s+(all\s+)?(previous|prior|above|system)`)},

	// Role hijacking
	{"Role hijack", regexp.MustCompile(`(?i)you\s+are\s+now\s+`)},
	{"Role act as", regexp.MustCompile(`(?i)act\s+as\s+(if|a)\s+`)},
	{"Role pretend", regexp.MustCompile(`(?i)pretend\s+(you\s+)?(are|to\s+be)\s+`)},
	{"New instructions", regexp.MustCompile(`(?i)new\s+instructions\s*:`)},
	{"System prompt injection", regexp.MustCompile(`(?i)system\s*prompt\s*[:=]`)},

	// Tag injection (LLM-specific)
	{"System tag", regexp.MustCompile(`<\s*/?\s*system\s*>`)},
	{"System marker", regexp.MustCompile(`<\|system\|>`)},
	{"INST marker", regexp.MustCompile(`\[/INST\]`)},
	{"SYS marker", regexp.MustCompile(`<<SYS>>`)},
	{"INST bracket", regexp.MustCompile(`\[\[INST\]\]`)},

	// Code/command execution
	{"Execute instruction", regexp.MustCompile(`(?i)(execute|run|eval)\s+(this\s+)?(code|command|script)`)},

	// Data exfiltration hints
	{"Exfiltrate to URL", regexp.MustCompile(`(?i)(send|post|upload|transmit)\s+(this|all|the)\s+(data|info|content)\s+to\s+(https?://|ftp://)`)},
	{"Include in response", regexp.MustCompile(`(?i)(include|append|add)\s+(this|all|the)\s+(data|info|content|secret|token|key)\s+in\s+(your\s+)?(response|output|reply)`)},
}

// CheckInjection scans MCP server tool descriptions for prompt injection patterns
// Note: For local configs, we can only check the server's arguments and metadata.
// Full tool description scanning requires connecting to the server (future feature).
func CheckInjection(cfg *model.MCPConfig, server model.MCPServer) []model.Finding {
	var findings []model.Finding

	// Check all string values that could contain injected content
	valuesToCheck := collectStringValues(server)

	for _, val := range valuesToCheck {
		for _, ip := range injectionPatterns {
			if ip.Pattern.MatchString(val) {
				findings = append(findings, model.Finding{
					ServerName: server.Name,
					Severity:   model.HIGH,
					OWASP:      "MCP03",
					Title:      "Possible prompt injection detected",
					Detail:     "Pattern matched: " + ip.Name + " in server configuration",
					Suggestion: "Review and sanitize the server configuration. Remove any instruction-override patterns.",
					FilePath:   cfg.Path,
				})
				break // one finding per value, avoid spam
			}
		}
	}

	// Check for homoglyph/unicode tricks in server name
	if containsHomoglyphs(server.Name) {
		findings = append(findings, model.Finding{
			ServerName: server.Name,
			Severity:   model.MEDIUM,
			OWASP:      "MCP03",
			Title:      "Suspicious unicode characters in server name",
			Detail:     "Server name contains non-ASCII characters that may be used for impersonation",
			Suggestion: "Use ASCII-only server names to prevent homoglyph attacks",
			FilePath:   cfg.Path,
		})
	}

	return findings
}

// collectStringValues gathers all string values from a server config for scanning
func collectStringValues(server model.MCPServer) []string {
	var values []string

	values = append(values, server.Name)
	values = append(values, server.Command)
	values = append(values, server.Args...)
	values = append(values, server.URL)

	for _, v := range server.Env {
		values = append(values, v)
	}

	return values
}

// containsHomoglyphs checks for non-ASCII characters that could be used for impersonation
func containsHomoglyphs(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}

// CheckSupplyChain does basic supply chain checks on server dependencies
func CheckSupplyChain(cfg *model.MCPConfig, server model.MCPServer) []model.Finding {
	var findings []model.Finding

	if server.Transport != "stdio" {
		return findings
	}

	// Check for npx without version pin
	if server.Command == "npx" || strings.HasSuffix(server.Command, "/npx") {
		hasVersionPin := false
		for _, arg := range server.Args {
			// Check for @scope/package@version or package@version
			if strings.Contains(arg, "@") && !strings.HasPrefix(arg, "-") {
				parts := strings.Split(arg, "@")
				if len(parts) >= 2 && parts[len(parts)-1] != "" {
					hasVersionPin = true
				}
			}
		}
		if !hasVersionPin {
			findings = append(findings, model.Finding{
				ServerName: server.Name,
				Severity:   model.MEDIUM,
				OWASP:      "MCP04",
				Title:      "Unpinned dependency version",
				Detail:     "npx command runs packages without pinning a specific version",
				Suggestion: "Pin package versions (e.g., @modelcontextprotocol/server-filesystem@0.5.0)",
				FilePath:   cfg.Path,
			})
		}
	}

	return findings
}
