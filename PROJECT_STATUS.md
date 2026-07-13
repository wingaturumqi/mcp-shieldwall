# MCP Shieldwall — 项目状态

> 最后更新：2026-07-13
> 仓库：https://github.com/wingaturumqi/mcp-shieldwall

---

## 项目简介

MCP Shieldwall 是一个 MCP（Model Context Protocol）服务器安全审计 CLI 工具。
基于 OWASP MCP Top 10 安全标准，扫描 MCP 配置文件中的安全问题。

- **技术栈**：Go 1.22+
- **目录**：`D:\project\mcpsw`
- **模块**：`github.com/wingaturumqi/mcp-shieldwall`

---

## 当前进度

### Phase 1：MVP（已完成 ✅）

| 天 | 任务 | Commit |
|:--:|------|--------|
| D1 | 项目骨架 + 配置文件发现（Claude/Cursor/VS Code/Windsurf） | 4105e33 |
| D4 | Prompt injection 检测 + A-F 评分算法 | 70c3556 |
| D5 | fix 命令 + JSON/SARIF 导出 | a60dae2 |
| D6 | 集成测试 + /home 路径检测 | 2cec4c5 |
| D7 | README 中英文 + GoReleaser + CI + v0.1.0 tag | f2fd990 |

**最新 tag**：`v0.1.0`

### 已实现的命令

| 命令 | 说明 |
|------|------|
| `shieldwall scan` | 扫描所有 MCP 配置的安全问题 |
| `shieldwall score` | A-F 安全评分 + 5 维度分解 |
| `shieldwall fix` | 交互式自动修复（-y 免确认） |
| `shieldwall export -f json/sarif` | JSON/SARIF 2.1.0 报告导出 |

### 已实现的安全检测（OWASP MCP Top 10）

| 编号 | 检测项 | 严重度 | 文件 |
|:----:|--------|:------:|------|
| MCP01 | 密钥/token 泄露（20+ 种模式） | CRITICAL | `internal/scanner/secret.go` |
| MCP02 | 权限范围过大（路径越界） | HIGH | `internal/scanner/permission.go` |
| MCP03 | Prompt injection（15+ 种模式） | HIGH | `internal/scanner/injection.go` |
| MCP04 | 供应链（版本未锁定） | MEDIUM | `internal/scanner/injection.go` |
| MCP05 | 命令注入（shell 标志） | HIGH | `internal/scanner/auth.go` |
| MCP07 | 认证检查（远程服务器） | MEDIUM | `internal/scanner/auth.go` |

### 测试

20 个单元测试，全部通过：
- `internal/parser/parser_test.go` — 3 个
- `internal/scanner/scanner_test.go` — 7 个
- `internal/scanner/integration_test.go` — 2 个
- `internal/scorer/scorer_test.go` — 4 个

---

## 代码审查（CODE_REVIEW.md）

**2 个严重 Bug 需要修复**：

1. **scorer 双重计分**（`internal/scorer/scorer.go:15-54`）
   - OWASP switch 和 severity switch 各计数一次，严重度统计翻倍
   - 修复：删除 OWASP switch 里的 `result.Severities.*++`

2. **Heroku UUID 误报**（`internal/scanner/secret.go:27`）
   - 正则匹配任何 UUID，不是 Heroku 特有 key
   - 修复：删除或加前缀限定

**4 个中等问题**：死代码、home 检查逻辑、版本硬编码、null findings
**4 个优化建议**：静默错误、homoglyph、正则锚定、缺少 config flag

详见：`D:\project\mcpsw\CODE_REVIEW.md`

---

## Phase 2：Pro 版本（待开始）

| 天 | 任务 | 状态 |
|:--:|------|:----:|
| D8 | 规则引擎 + 远程规则更新（类病毒库） | ⬜ |
| D9 | HTML 合规报告 | ⬜ |
| D10 | License 激活 + Gumroad 支付 | ⬜ |
| D11 | Homebrew/Scoop 包管理分发 | ⬜ |
| D12 | Show HN + Reddit 推广 | ⬜ |
| D13 | 掘金/V2EX/知乎 推广 | ⬜ |
| D14 | 反馈收集 + 修 bug | ⬜ |

### Pro 核心卖点

- 🔄 **规则库持续更新** — 新 CVE、新攻击模式即时推送
- 📊 **HTML 合规报告** — 可视化安全报告
- 🔧 **自定义规则引擎** — 用户自定义检测规则

### 定价

| 版本 | 价格 | 功能 |
|------|:----:|------|
| Free | $0 | scan + score + fix + export |
| Pro | $29 买断（首发 $19） | + 规则库更新 + HTML 报告 + 自定义规则 |

---

## 项目结构

```
D:\project\mcpsw\
├── main.go                          # 入口，版本注入
├── go.mod / go.sum
├── cmd/
│   ├── root.go                      # Cobra 根命令
│   ├── scan.go                      # scan 命令
│   ├── score.go                     # score 命令（lipgloss 美化）
│   ├── fix.go                       # fix 命令（交互式）
│   └── export.go                    # export 命令（JSON/SARIF）
├── internal/
│   ├── finder/finder.go             # 配置文件发现
│   ├── model/
│   │   ├── config.go                # MCPConfig / MCPServer 结构
│   │   ├── finding.go               # Finding + Severity 定义
│   │   └── score.go                 # ScoreResult + GradeFromScore
│   ├── parser/parser.go             # 标准格式 + VS Code 格式解析
│   ├── scanner/
│   │   ├── scanner.go               # 扫描调度器
│   │   ├── secret.go                # MCP01 密钥检测
│   │   ├── permission.go            # MCP02 权限检查
│   │   ├── injection.go             # MCP03 注入检测 + MCP04 供应链
│   │   ├── auth.go                  # MCP05 命令注入 + MCP07 认证
│   │   ├── scanner_test.go
│   │   └── integration_test.go
│   └── scorer/
│       ├── scorer.go                # A-F 评分算法
│       └── scorer_test.go
├── testdata/fixtures/vulnerable.json
├── rules/                           # 规则定义（待填充）
├── .goreleaser.yml                  # 多平台构建
├── .github/workflows/ci.yml        # CI + Release
├── README.md                        # 英文文档
├── README_zh.md                     # 中文文档
├── CODE_REVIEW.md                   # 代码审查报告
├── LICENSE                          # MIT
└── CHANGELOG.md
```

---

## 产品定位

> MCP 生态的安全哨兵 — 一键扫描、评分、修复你的 MCP server 配置

- **目标用户**：使用 Claude Desktop / Cursor / VS Code + MCP 的个人开发者
- **差异化**：Go 单二进制、A-F 评分、持续规则更新、CI/CD 友好
- **竞品**：mcp-doctor（TS/Python，0 star）、SecureMCP（Go，140 star）、MCPSentinel（Python，0 star）

---

## 下一步

1. 修复 CODE_REVIEW.md 中的 2 个严重 Bug
2. 开始 Phase 2 Pro 版本开发（D8：规则引擎）
3. 推广计划（D12-13：Show HN + 中文社区）
