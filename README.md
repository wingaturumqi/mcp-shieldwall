# MCP Shieldwall

**Security audit CLI for Model Context Protocol (MCP) servers.**

Scans your MCP configurations, detects security issues based on [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/), and provides actionable fixes.

```
$ shieldwall scan

🔍 Scanning MCP configurations...

📁 ~/.config/claude/claude_desktop_config.json (claude)
  🔴 [CRITICAL] Secret leaked in environment variable
     Environment variable GITHUB_TOKEN contains what appears to be a GitHub Token
     💡 Move secrets to a secure store or use variable references
  🟠 [HIGH] Overly broad filesystem access
     Server configured to access /home which may expose sensitive system files
     💡 Restrict access to a specific project directory
  🟡 [MEDIUM] Unpinned dependency version
     npx command runs packages without pinning a specific version
     💡 Pin package versions (e.g., @modelcontextprotocol/server-filesystem@0.5.0)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  📊 Summary: 3 server(s) scanned, 5 issue(s) found
```

## Install

```bash
# Go
go install github.com/wingaturumqi/mcp-shieldwall@latest

# macOS / Linux (Homebrew)
brew install wingaturumqi/tap/mcp-shieldwall

# Windows (Scoop)
scoop install mcp-shieldwall

# Binary releases
# https://github.com/wingaturumqi/mcp-shieldwall/releases
```

## Commands

| Command | Description |
|---------|-------------|
| `shieldwall scan` | Scan all MCP configurations for security issues |
| `shieldwall score` | Show A-F security score with dimension breakdown |
| `shieldwall fix` | Interactive auto-fix for common issues |
| `shieldwall export` | Export results as JSON or SARIF 2.1.0 |

### Scan

```bash
shieldwall scan                    # Scan all known MCP config locations
shieldwall score                   # Show security score
shieldwall fix                     # Interactive fix
shieldwall fix -y                  # Auto-fix without confirmation
shieldwall export -f json          # JSON output
shieldwall export -f sarif         # SARIF 2.1.0 (GitHub Code Scanning)
shieldwall export -f json -o report.json  # Save to file
```

## Security Checks

Based on OWASP MCP Top 10:

| ID | Check | Severity |
|----|-------|----------|
| MCP01 | Secret/token leakage in config | CRITICAL |
| MCP02 | Overly broad filesystem permissions | HIGH |
| MCP03 | Prompt injection in tool descriptions | HIGH |
| MCP04 | Unpinned dependency versions | MEDIUM |
| MCP05 | Shell command injection risk | HIGH |
| MCP07 | Missing authentication on remote servers | MEDIUM |

## Detected Configurations

Shieldwall automatically discovers MCP configurations from:

- **Claude Desktop** — `claude_desktop_config.json`
- **Cursor** — `.cursor/mcp.json`
- **VS Code** — `settings.json` (mcp section)
- **Windsurf** — `mcp_config.json`
- **Project-level** — `.mcp.json`

## CI/CD Integration

```yaml
# .github/workflows/mcp-security.yml
name: MCP Security Audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - run: go install github.com/wingaturumqi/mcp-shieldwall@latest
      - run: shieldwall export -f sarif -o results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Scoring

The score is calculated across 5 dimensions (each 0-20, total 0-100):

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 90-100 | Excellent |
| B | 75-89 | Good |
| C | 60-74 | Fair |
| D | 40-59 | Dangerous |
| F | 0-39 | Critical |

## Pro Version

MCP Shieldwall Pro adds:

- 🔄 **Rule database updates** — continuous updates for new CVEs and attack patterns
- 📊 **HTML compliance reports** — visual reports for teams
- 🔧 **Custom rules** — define your own security policies

Learn more: [mcp-shieldwall.pro](https://github.com/wingaturumqi/mcp-shieldwall#pro-version)

## License

MIT
