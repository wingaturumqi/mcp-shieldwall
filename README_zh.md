# MCP Shieldwall

**MCP 服务器安全审计 CLI 工具**

扫描你的 MCP 配置，基于 [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) 检测安全问题，并提供修复建议。

```
$ shieldwall scan

🔍 Scanning MCP configurations...

📁 ~/.config/claude/claude_desktop_config.json (claude)
  🔴 [CRITICAL] 环境变量中泄露密钥
     环境变量 GITHUB_TOKEN 包含疑似 GitHub Token
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

## 安装

```bash
# Go
go install github.com/wingaturumqi/mcp-shieldwall@latest

# macOS / Linux (Homebrew)
brew install wingaturumqi/tap/mcp-shieldwall

# Windows (Scoop)
scoop install mcp-shieldwall

# 二进制下载
# https://github.com/wingaturumqi/mcp-shieldwall/releases
```

## 命令

| 命令 | 说明 |
|------|------|
| `shieldwall scan` | 扫描所有 MCP 配置的安全问题 |
| `shieldwall score` | 显示 A-F 安全评分及维度分解 |
| `shieldwall fix` | 交互式自动修复 |
| `shieldwall export` | 导出 JSON 或 SARIF 2.1.0 报告 |

### 使用示例

```bash
shieldwall scan                    # 扫描所有已知 MCP 配置位置
shieldwall score                   # 显示安全评分
shieldwall fix                     # 交互式修复
shieldwall fix -y                  # 自动修复（无需确认）
shieldwall export -f json          # JSON 输出
shieldwall export -f sarif         # SARIF 2.1.0（兼容 GitHub Code Scanning）
shieldwall export -f json -o report.json  # 保存到文件
```

## 安全检查项

基于 OWASP MCP Top 10：

| 编号 | 检查项 | 严重度 |
|:----:|--------|:------:|
| MCP01 | 配置中的密钥/token 泄露 | CRITICAL |
| MCP02 | 文件系统权限过大 | HIGH |
| MCP03 | 工具描述中的 Prompt Injection | HIGH |
| MCP04 | 依赖版本未锁定 | MEDIUM |
| MCP05 | Shell 命令注入风险 | HIGH |
| MCP07 | 远程服务器缺少认证 | MEDIUM |

## 支持的配置文件

Shieldwall 自动发现以下位置的 MCP 配置：

- **Claude Desktop** — `claude_desktop_config.json`
- **Cursor** — `.cursor/mcp.json`
- **VS Code** — `settings.json`（mcp 节）
- **Windsurf** — `mcp_config.json`
- **项目级** — `.mcp.json`

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

## 评分体系

5 个维度各 0-20 分，总分 0-100：

| 等级 | 分数 | 含义 |
|:----:|:----:|------|
| A | 90-100 | 优秀 |
| B | 75-89 | 良好 |
| C | 60-74 | 及格 |
| D | 40-59 | 危险 |
| F | 0-39 | 严重 |

## Pro 版本

MCP Shieldwall Pro 提供：

- 🔄 **规则库持续更新** — 追踪新 CVE 和攻击模式
- 📊 **HTML 合规报告** — 可视化安全报告
- 🔧 **自定义规则** — 定义你自己的安全策略

了解更多：[mcp-shieldwall.pro](https://github.com/wingaturumqi/mcp-shieldwall#pro-版本)

## 开源协议

MIT
