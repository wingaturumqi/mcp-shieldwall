# MCP Shieldwall 代码审查报告

> 审查时间：2026年7月13日
> 审查范围：21 个 Go 文件，约 1200 行代码
> 仓库：https://github.com/wingaturumqi/mcp-shieldwall

---

## 🔴 严重问题（2 个）

### BUG-1：scorer 严重度双重计分

**文件**：`internal/scorer/scorer.go:15-54`

**问题**：每个 finding 的严重度被计数了两次。OWASP switch 里计数一次，severity switch 里又计数一次。导致 `shieldwall score` 输出的严重度统计翻倍。

```go
// 第一次计数（在 OWASP switch 里）
case "MCP01":
    result.Dimensions.Config -= deduction
    result.Severities.Critical++    // ← 第一次

// 第二次计数（在 severity switch 里）
case model.CRITICAL:
    result.Severities.Critical++    // ← 第二次！
```

**影响**：一个 CRITICAL finding 会被显示为 2 个 critical。评分维度扣分正确，但严重度计数翻倍。

**修复方案**：删除 OWASP switch 里的 `result.Severities.*++` 行，只保留 severity switch 里的计数。

---

### BUG-2：Heroku API Key 正则误报率极高

**文件**：`internal/scanner/secret.go:27`

**问题**：正则模式 `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}` 匹配的是任何 UUID 格式，不是 Heroku 特有的 key。

**影响**：`$HOMEDRIVE`、数据库连接字符串中的 UUID、任何包含 UUID 的环境变量都会被误报为 CRITICAL 级别的密钥泄露。在实际使用中会产生大量误报，降低用户信任度。

**修复方案**：删除这条规则，或改为匹配 Heroku 特征前缀（如 `heroku:` 开头的值）。

---

## 🟠 中等问题（4 个）

### ISSUE-3：auth.go 死代码

**文件**：`internal/scanner/auth.go:112-113`

```go
// unused but keeping for future use
var _ = regexp.MustCompile
```

`regexp` 包只用于这行死代码，增加了不必要的编译依赖。

**修复**：删除这行和 `import "regexp"`。

---

### ISSUE-4：permission.go home 目录检查逻辑缺陷

**文件**：`internal/scanner/permission.go:42`

```go
remaining := strings.Replace(allArgs, home, "", 1)  // 只替换第一次出现
```

`strings.Replace` 只替换第一次出现。如果 args 是 `-y server /home/user /home/user/projects`，只替换第一个 `/home/user`，剩余部分仍有 `/home/user/projects`，导致检查误判为"不是 home 根目录"。

**修复**：改用 `strings.ReplaceAll`，或改为检查 args 列表中最后一个参数是否等于 home 目录。

---

### ISSUE-5：export.go 版本号硬编码

**文件**：`cmd/export.go:151`

```go
run.Tool.Driver.Version = "0.1.0"  // 硬编码
```

版本号应该通过 ldflags 注入（`main.go` 中的 `version` 变量），而不是硬编码。每次发版都需要手动修改此文件。

**修复**：将 `versionStr` 传入 export 函数，或使用包级变量。

---

### ISSUE-6：JSON 导出 findings 为 null

**文件**：`cmd/export.go:90`

```go
"findings": result.Findings,  // nil 时输出 JSON "null"
```

当没有发现时，JSON 输出 `"findings": null` 而非 `"findings": []`。部分 CI 工具解析 JSON 时，`null` 和空数组行为不同。

**修复**：在 `runExport` 中初始化 `allFindings := make([]model.Finding, 0)`。

---

## 🟡 建议优化（4 个）

### SUGGEST-7：解析错误静默吞没

**文件**：`cmd/scan.go:47`、`cmd/score.go:44`、`cmd/export.go:42`

```go
if err != nil {
    continue  // ← 静默跳过，用户无感知
}
```

配置文件解析失败时直接跳过，不输出任何信息。用户不知道为什么某些配置被跳过。

**建议**：至少输出一行 `fmt.Fprintf(os.Stderr, "⚠️ Failed to parse %s: %v\n", cfg.Path, err)`。

---

### SUGGEST-8：homoglyph 检测过于简单

**文件**：`internal/scanner/injection.go:104-110`

```go
func containsHomoglyphs(s string) bool {
    for _, r := range s {
        if r > 127 { return true }
    }
    return false
}
```

任何非 ASCII 字符都会触发，包括合法的中文/日文服务器名。真正的 homoglyph 攻击是用西里尔字母 `а`（U+0430）冒充拉丁字母 `a`（U+0061），不是简单的大于 127 判断。

**建议**：暂时删除此检查避免误报，后续用 Unicode confusable 字符映射表（UTR39）实现。

---

### SUGGEST-9：密钥正则缺少边界锚定

**文件**：`internal/scanner/secret.go:17-33`

所有正则都没有 `\b`（word boundary）锚定。如果环境变量值恰好包含匹配模式的子串（如长 URL 或 base64 编码），可能误报。

**建议**：对关键模式（GitHub Token、OpenAI Key 等）加上 `\b` 或检查整个值是否匹配。

---

### SUGGEST-10：缺少 `--config` flag

用户无法指定自定义配置文件路径。如果 MCP 配置在非标准位置（如企业定制路径），工具无法覆盖。

**建议**：给 rootCmd 加 `--config` / `-c` flag，允许手动指定一个或多个配置文件路径。

---

## 📋 汇总

| 级别 | 数量 | 关键项 |
|:----:|:----:|--------|
| 🔴 严重 | 2 | scorer 双重计分、Heroku UUID 误报 |
| 🟠 中等 | 4 | 死代码、home 检查逻辑、版本硬编码、null findings |
| 🟡 建议 | 4 | 静默错误、homoglyph、正则锚定、缺少 config flag |

## 修复优先级

1. **立即修复**：BUG-1（双重计分）、BUG-2（UUID 误报）
2. **本周修复**：ISSUE-4（home 检查）、ISSUE-6（null findings）、SUGGEST-7（静默错误）
3. **下个版本**：其余问题
