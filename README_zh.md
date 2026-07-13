# MCP Shieldwall

**MCP 服务器安全审计 CLI 工具**

扫描你的 MCP 配置，基于 [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) 检测安全问题，并提供修复建议。

[English](README.md)

```
$ shieldwall scan

🔍 Scanning MCP configurations...

📁 ~/.config/claude/claude_desktop_config.json (claude)
  🔴 [CRITICAL] 环境变量中泄露密钥
     环境变量 GITHUB_TOKEN 包含疑似 GitHub Personal Access Token
     💡 使用变量引用替代硬编码密钥
  🟠 [HIGH] 文件系统权限过大
     服务器可访问 /home 目录，可能暴露敏感文件
     💡 限制为特定项目目录
  🟡 [MEDIUM] 依赖版本未锁定
     npx 命令未指定具体版本
     💡 锁定包版本（如 @modelcontextprotocol/server-filesystem@0.5.0）

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  📊 Summary: 3 server(s) scanned, 5 issue(s) found
```

---

## 安装

```bash
# Go（需要 Go 1.22+）
go install github.com/wingaturumqi/mcp-shieldwall@latest

# macOS / Linux (Homebrew)
brew install wingaturumqi/tap/mcp-shieldwall

# Windows (Scoop)
scoop install mcp-shieldwall

# 二进制下载
# https://github.com/wingaturumqi/mcp-shieldwall/releases
```

---

## 命令

| 命令 | 说明 |
|------|------|
| `shieldwall scan` | 扫描所有 MCP 配置的安全问题 |
| `shieldwall score` | 显示 A-F 安全评分及维度分解 |
| `shieldwall fix` | 交互式自动修复硬编码密钥 |
| `shieldwall export` | 导出 JSON 或 SARIF 2.1.0 报告 |
| `shieldwall history` | 查看扫描历史和评分趋势 |

### scan — 安全扫描

发现并扫描所有 MCP 服务器配置，覆盖 Claude Desktop、Cursor、VS Code、Windsurf 和项目级 `.mcp.json` 文件。

```bash
shieldwall scan                    # 扫描所有已知 MCP 配置位置
```

42 条内置规则，覆盖 6 个 OWASP 类别：

| OWASP | 类别 | 检测内容 |
|:-----:|------|---------|
| MCP01 | 密钥泄露 | GitHub Token、API Key、AWS 凭证（14 条规则） |
| MCP02 | 权限范围 | 根文件系统访问、home 目录访问 |
| MCP03 | Prompt 注入 | 指令覆盖、角色劫持、标签注入（17 条规则） |
| MCP04 | 供应链 | npx 依赖版本未锁定 |
| MCP05 | 命令注入 | Shell 解释器、Shell 标志（-c, /c, -Command） |
| MCP07 | 认证缺失 | 远程服务器无认证配置 |

### score — 安全评分

5 个维度各 0-20 分，总分 0-100，自动记录历史。

```bash
shieldwall score

📊 MCP Security Score

  Configuration files: 1
  MCP servers: 3
  Issues found: 5

  Overall: C 及格 (55/100)

  配置安全    ██░░░░░░░░   5/20
  权限控制    ███████░░░  15/20
  认证强度    ███████░░░  15/20
  供应链      █████░░░░░  10/20
  注入防护    █████░░░░░  10/20

  严重度: 🔴 1 严重  🟠 1 高危  🟡 2 中危  🔵 1 低危
```

| 等级 | 分数 | 含义 |
|:----:|:----:|------|
| A | 90-100 | 优秀 |
| B | 75-89 | 良好 |
| C | 60-74 | 及格 |
| D | 40-59 | 危险 |
| F | 0-39 | 严重 |

### fix — 自动修复

交互式修复常见安全问题。当前支持将硬编码密钥替换为环境变量引用。

```bash
shieldwall fix                     # 交互式修复（逐条确认 Y/n）
shieldwall fix -y                  # 自动修复所有问题（无需确认）
```

### export — 报告导出

导出扫描结果用于 CI/CD 集成。

```bash
shieldwall export -f json          # JSON 输出（stdout）
shieldwall export -f sarif         # SARIF 2.1.0（兼容 GitHub Code Scanning）
shieldwall export -f json -o report.json  # 保存到文件
```

### history — 扫描历史

跟踪安全态势变化趋势。每次运行 `shieldwall score` 自动记录结果。

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

## 支持的配置文件

Shieldwall 自动发现以下位置的 MCP 配置：

- **Claude Desktop** — `%APPDATA%\Claude\claude_desktop_config.json`（Windows）
- **Cursor** — `~/.cursor/mcp.json`
- **VS Code** — `%APPDATA%\Code\User\settings.json`（Windows）
- **Windsurf** — `~/.codeium/windsurf/mcp_config.json`
- **项目级** — `.mcp.json`、`.mcp/config.json`

---

## CI/CD 集成

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

## Pro 版

MCP Shieldwall Pro 提供：

- 📊 **HTML 合规报告** — 可视化安全报告
- 🔍 **MCP Server 日志审计** — 检测服务器日志中的可疑活动
- 🔄 **规则库持续更新** — 追踪新 CVE 和攻击模式
- 🔑 **Ed25519 License 系统** — 安全的非对称签名验证

了解更多：[mcp-shieldwall.pro](https://github.com/wingaturumqi/mcp-shieldwall#pro-版)

---

## 项目架构

```
mcp-shieldwall/
├── cmd/                    # CLI 命令层（Cobra）
├── internal/
│   ├── rules/              # 规则引擎（42 条 YAML 规则，embed）
│   ├── scanner/            # 安全扫描器
│   ├── scorer/             # A-F 评分引擎
│   ├── parser/             # 配置文件解析器
│   ├── finder/             # 配置文件发现
│   └── model/              # 数据模型
└── .goreleaser.yml         # 多平台构建配置
```

---

## 开源协议

MIT
