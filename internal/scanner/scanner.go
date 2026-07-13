package scanner

import (
	"github.com/wingaturumqi/mcp-shieldwall/internal/model"
)

// Scan runs all security checks on a parsed MCP config and returns findings
func Scan(cfg *model.MCPConfig) []model.Finding {
	var findings []model.Finding

	for _, server := range cfg.Servers {
		// MCP01: Secret/token leakage
		findings = append(findings, CheckSecrets(cfg, server)...)

		// MCP02: Permission scope
		findings = append(findings, CheckPermissions(cfg, server)...)

		// MCP05: Command injection risk
		findings = append(findings, CheckCommandInjection(cfg, server)...)

		// MCP07: Authentication check
		findings = append(findings, CheckAuth(cfg, server)...)
	}

	return findings
}
