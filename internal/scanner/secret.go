package scanner

import (
	"regexp"
	"strings"

	"github.com/wingaturumqi/mcp-shieldwall/internal/model"
)

// secretPattern defines a regex pattern for detecting leaked secrets
type secretPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

// Known secret patterns
var secretPatterns = []secretPattern{
	{"GitHub Token", regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`)},
	{"GitHub Fine-grained PAT", regexp.MustCompile(`github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`)},
	{"OpenAI API Key", regexp.MustCompile(`sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}`)},
	{"Anthropic API Key", regexp.MustCompile(`sk-ant-[a-zA-Z0-9\-]{93}`)},
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)},
	{"Slack Token", regexp.MustCompile(`xox[bpors]-[0-9A-Za-z\-]+`)},
	{"Stripe Secret Key", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`)},
	{"Stripe Publishable Key", regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`)},
	{"Heroku API Key", regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)},
	{"SendGrid API Key", regexp.MustCompile(`SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}`)},
	{"Twilio API Key", regexp.MustCompile(`SK[0-9a-fA-F]{32}`)},
	{"Mailgun API Key", regexp.MustCompile(`key-[0-9a-zA-Z]{32}`)},
	{"NPM Token", regexp.MustCompile(`npm_[a-zA-Z0-9]{36}`)},
	{"PyPI Token", regexp.MustCompile(`pypi-[a-zA-Z0-9\-]{100,}`)},
}

// CheckSecrets scans environment variables and command arguments for leaked secrets
func CheckSecrets(cfg *model.MCPConfig, server model.MCPServer) []model.Finding {
	var findings []model.Finding

	// Check environment variables
	for key, value := range server.Env {
		for _, sp := range secretPatterns {
			if sp.Pattern.MatchString(value) {
				findings = append(findings, model.Finding{
					ServerName: server.Name,
					Severity:   model.CRITICAL,
					OWASP:      "MCP01",
					Title:      "Secret leaked in environment variable",
					Detail:     "Environment variable " + key + " contains what appears to be a " + sp.Name,
					Suggestion: "Move secrets to a secure store or use variable references (e.g., ${" + key + "})",
					FilePath:   cfg.Path,
				})
			}
		}

		// Generic check for suspiciously named env vars with hardcoded values
		if isSuspiciousEnvKey(key) && len(value) >= 8 && looksLikeSecret(value) {
			findings = append(findings, model.Finding{
				ServerName: server.Name,
				Severity:   model.HIGH,
				OWASP:      "MCP01",
				Title:      "Possible hardcoded secret in environment variable",
				Detail:     "Environment variable " + key + " contains a hardcoded value that looks like a secret",
				Suggestion: "Use variable references (e.g., ${" + key + "}) instead of hardcoded values",
				FilePath:   cfg.Path,
			})
		}
	}

	// Check command arguments for inline secrets
	for _, arg := range server.Args {
		for _, sp := range secretPatterns {
			if sp.Pattern.MatchString(arg) {
				findings = append(findings, model.Finding{
					ServerName: server.Name,
					Severity:   model.CRITICAL,
					OWASP:      "MCP01",
					Title:      "Secret leaked in command argument",
					Detail:     "Command argument contains what appears to be a " + sp.Name,
					Suggestion: "Move secrets to environment variables and reference them via ${VAR_NAME}",
					FilePath:   cfg.Path,
				})
			}
		}
	}

	return findings
}

// isSuspiciousEnvKey checks if an env var name suggests it holds a secret
func isSuspiciousEnvKey(key string) bool {
	key = strings.ToLower(key)
	suspicious := []string{
		"key", "secret", "token", "password", "passwd", "pwd",
		"auth", "credential", "api_key", "apikey", "access_token",
	}
	for _, s := range suspicious {
		if strings.Contains(key, s) {
			return true
		}
	}
	return false
}

// looksLikeSecret checks if a value has characteristics of a secret
func looksLikeSecret(value string) bool {
	// Skip empty, short, or obvious non-secrets
	if len(value) < 8 {
		return false
	}
	// Skip environment variable references
	if strings.HasPrefix(value, "${") || strings.HasPrefix(value, "$") {
		return false
	}
	// Skip common non-secret values
	lower := strings.ToLower(value)
	nonSecrets := []string{"true", "false", "null", "none", "debug", "info", "warn", "error"}
	for _, ns := range nonSecrets {
		if lower == ns {
			return false
		}
	}
	// Check for mix of letters and digits (common in keys/tokens)
	hasLetter := false
	hasDigit := false
	for _, c := range value {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			hasLetter = true
		}
		if c >= '0' && c <= '9' {
			hasDigit = true
		}
	}
	return hasLetter && hasDigit && len(value) >= 16
}
