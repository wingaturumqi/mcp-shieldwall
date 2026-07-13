# MCP Shieldwall

Security audit CLI for Model Context Protocol (MCP) servers.

## Features (planned)

- `shieldwall scan` – Security scan of MCP configurations
- `shieldwall score` – A-F security scoring (OWASP MCP Top 10)
- `shieldwall fix` – Auto-fix common security issues
- `shieldwall export` – JSON/SARIF report export

## Install

```bash
go install github.com/wingaturumqi/mcp-shieldwall@latest
```

## Usage

```bash
shieldwall scan    # Scan all MCP configurations
shieldwall score   # Show security score
shieldwall fix     # Auto-fix security issues
```

## License

MIT
