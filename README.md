# MCP Shieldwall

**Security audit CLI for Model Context Protocol (MCP) servers.**

Scans your MCP configurations, detects security issues based on [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/), and provides actionable fixes.

[中文文档](README_zh.md)

```
$ shieldwall scan

🔍 Scanning MCP configurations...

📁 ~/.config/claude/claude_desktop_config.json (claude)
  🔴 [CRITICAL] Secret leaked in environment variable
     Environment variable GITHUB_TOKEN contains what appears to be a GitHub Personal Access Token
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

---

## Install

```bash
# Go (requires Go 1.22+)
go install github.com/wingaturumqi/mcp-shieldwall@latest

# macOS / Linux (Homebrew)
brew install wingaturumqi/tap/mcp-shieldwall

# Windows (Scoop)
scoop install mcp-shieldwall

# Binary releases
# https://github.com/wingaturumqi/mcp-shieldwall/releases
```

---

## Commands

| Command | Description |
|---------|-------------|
| `shieldwall scan` | Scan all MCP configurations for security issues |
| `shieldwall score` | Show A-F security score with dimension breakdown |
| `shieldwall fix` | Interactive auto-fix for hardcoded secrets |
| `shieldwall export` | Export results as JSON or SARIF 2.1.0 |
| `shieldwall history` | View scan history and score trends |

### Scan

Discover and scan all MCP server configurations across Claude Desktop, Cursor, VS Code, Windsurf, and project-level `.mcp.json` files.

```bash
shieldwall scan                    # Scan all known MCP config locations
```

42 built-in rules detect issues across 6 OWASP categories:

| OWASP | Category | Examples |
|-------|----------|---------|
| MCP01 | Secret leakage | GitHub tokens, API keys, AWS credentials (14 patterns) |
| MCP02 | Permission scope | Root filesystem access, home directory access |
| MCP03 | Prompt injection | Instruction override, role hijacking, tag injection (17 patterns) |
| MCP04 | Supply chain | Unpinned npx dependencies |
| MCP05 | Command injection | Shell interpreters, shell flags (-c, /c, -Command) |
| MCP07 | Authentication | Remote servers without auth |

### Score

Calculate a security score across 5 dimensions (each 0-20, total 0-100) with letter grade.

```bash
shieldwall score

📊 MCP Security Score

  Configuration files: 1
  MCP servers: 3
  Issues found: 5

  Overall: C Fair (55/100)

  Config security  ██░░░░░░░░   5/20
  Permissions      ███████░░░  15/20
  Authentication  ███████░░░  15/20
  Supply chain    █████░░░░░  10/20
  Injection       █████░░░░░  10/20

  Severity: 🔴 1 critical  🟠 1 high  🟡 2 medium  🔵 1 low
```

| Grade | Score | Meaning |
|:-----:|:-----:|---------|
| A | 90-100 | Excellent |
| B | 75-89 | Good |
| C | 60-74 | Fair |
| D | 40-59 | Dangerous |
| F | 0-39 | Critical |

### Fix

Interactive mode to fix common security issues. Currently supports replacing hardcoded secrets with environment variable references.

```bash
shieldwall fix                     # Interactive fix (Y/n per issue)
shieldwall fix -y                  # Auto-fix all without confirmation
```

### Export

Export scan results for CI/CD integration.

```bash
shieldwall export -f json          # JSON output (stdout)
shieldwall export -f sarif         # SARIF 2.1.0 (GitHub Code Scanning)
shieldwall export -f json -o report.json  # Save to file
```

### History

Track your security posture over time. Each `shieldwall score` run automatically records results.

```bash
shieldwall history

📊 Scan History (3 records)

  Date                  Grade  Score   Srv  Findings
  ──────────────────────────────────────────────────────
  2026-07-10 14:30         C     55     3  🔴1 🟠1 🟡2 🔵1
  2026-07-12 09:15         B     80     3  🟡1
  2026-07-13 16:00         A    100     3  ✅ clean

  📈 Trend: +45 points (55 → 100)
```

---

## Supported Configurations

Shieldwall automatically discovers MCP configurations from:

- **Claude Desktop** — `%APPDATA%\Claude\claude_desktop_config.json` (Windows)
- **Cursor** — `~/.cursor/mcp.json`
- **VS Code** — `%APPDATA%\Code\User\settings.json` (Windows)
- **Windsurf** — `~/.codeium/windsurf/mcp_config.json`
- **Project-level** — `.mcp.json`, `.mcp/config.json`

---

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

---

## Pro Version

MCP Shieldwall Pro adds:

- 📊 **HTML compliance reports** — visual reports for teams
- 🔍 **MCP server log audit** — detect suspicious activity in server logs
- 🔄 **Rules library updates** — continuous updates for new CVEs and attack patterns
- 🔑 **Ed25519 license system** — secure asymmetric license validation

Learn more: [mcp-shieldwall.pro](https://github.com/wingaturumqi/mcp-shieldwall#pro-version)

---

## Architecture

```
mcp-shieldwall/
├── cmd/                    # CLI commands (Cobra)
├── internal/
│   ├── rules/              # Rule engine (42 YAML rules, embedded)
│   ├── scanner/            # Security scanners
│   ├── scorer/             # A-F scoring engine
│   ├── parser/             # Config file parser
│   ├── finder/             # Config file discovery
│   └── model/              # Data models
└── .goreleaser.yml         # Multi-platform build config
```

---

## License

MIT
