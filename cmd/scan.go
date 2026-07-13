package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/wingaturumqi/mcp-shieldwall/internal/finder"
	"github.com/wingaturumqi/mcp-shieldwall/internal/model"
	"github.com/wingaturumqi/mcp-shieldwall/internal/parser"
	"github.com/wingaturumqi/mcp-shieldwall/internal/scanner"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan MCP configurations for security issues",
	Long:  "Discover and scan all MCP server configurations for security vulnerabilities based on OWASP MCP Top 10.",
	RunE:  runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	fmt.Println("🔍 Scanning MCP configurations...")
	fmt.Println()

	configs, err := finder.FindAll()
	if err != nil {
		return fmt.Errorf("error finding configs: %w", err)
	}

	if len(configs) == 0 {
		fmt.Println("  No MCP configuration files found.")
		fmt.Println("  Searched: Claude Desktop, Cursor, VS Code, Windsurf, .mcp.json")
		return nil
	}

	fmt.Printf("  Found %d configuration file(s)\n\n", len(configs))

	totalFindings := 0
	serverCount := 0

	for _, cfg := range configs {
		parsed, err := parser.Parse(cfg.Path, cfg.Source)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠️  Failed to parse %s: %v\n", cfg.Path, err)
			continue
		}

		fmt.Printf("📁 %s (%s)\n", cfg.Path, cfg.Source)

		if len(parsed.Servers) == 0 {
			fmt.Println("  No MCP servers configured.")
			fmt.Println()
			continue
		}

		for _, server := range parsed.Servers {
			serverCount++
			findings := scanner.Scan(&model.MCPConfig{
				Path:    cfg.Path,
				Source:  cfg.Source,
				Servers: []model.MCPServer{server},
			})

			printServerResult(server.Name, findings)
			totalFindings += len(findings)
		}
		fmt.Println()
	}

	printSummary(serverCount, totalFindings)
	return nil
}

func printServerResult(name string, findings []model.Finding) {
	if len(findings) == 0 {
		fmt.Printf("  ✅ %s — No issues found\n", name)
		return
	}

	for _, f := range findings {
		icon := severityIcon(f.Severity)
		fmt.Printf("  %s [%s] %s\n", icon, f.Severity, f.Title)
		fmt.Printf("     %s\n", f.Detail)
		fmt.Printf("     💡 %s\n", f.Suggestion)
	}
}

func severityIcon(s model.Severity) string {
	switch s {
	case model.CRITICAL:
		return "🔴"
	case model.HIGH:
		return "🟠"
	case model.MEDIUM:
		return "🟡"
	case model.LOW:
		return "🔵"
	default:
		return "⚪"
	}
}

func printSummary(serverCount, findingCount int) {
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  📊 Summary: %d server(s) scanned, %d issue(s) found\n", serverCount, findingCount)
	if findingCount > 0 {
		fmt.Println("  Run 'shieldwall score' for detailed scoring")
		fmt.Println("  Run 'shieldwall fix' for auto-fix suggestions")
	}
}
