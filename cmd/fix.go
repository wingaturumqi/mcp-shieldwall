package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wingaturumqi/mcp-shieldwall/internal/finder"
	"github.com/wingaturumqi/mcp-shieldwall/internal/model"
	"github.com/wingaturumqi/mcp-shieldwall/internal/parser"
	"github.com/wingaturumqi/mcp-shieldwall/internal/scanner"
)

var fixCmd = &cobra.Command{
	Use:   "fix",
	Short: "Auto-fix security issues in MCP configurations",
	Long:  "Interactive mode to fix common security issues like hardcoded secrets and overly broad permissions.",
	RunE:  runFix,
}

var fixAll bool

func init() {
	fixCmd.Flags().BoolVarP(&fixAll, "yes", "y", false, "Apply all fixes without confirmation")
	rootCmd.AddCommand(fixCmd)
}

func runFix(cmd *cobra.Command, args []string) error {
	configs, err := finder.FindAll()
	if err != nil {
		return err
	}

	if len(configs) == 0 {
		fmt.Println("  No MCP configuration files found.")
		return nil
	}

	reader := bufio.NewReader(os.Stdin)
	fixedCount := 0
	skipCount := 0

	for _, cfg := range configs {
		parsed, err := parser.Parse(cfg.Path, cfg.Source)
		if err != nil {
			continue
		}

		findings := scanner.Scan(parsed)
		if len(findings) == 0 {
			continue
		}

		fmt.Printf("📁 %s\n", cfg.Path)

		for _, f := range findings {
			// Only offer auto-fix for certain types
			if !canAutoFix(f) {
				continue
			}

			fmt.Printf("\n  [%s] %s\n", f.Severity, f.Title)
			fmt.Printf("  %s\n", f.Detail)

			fix := suggestFix(f)
			fmt.Printf("  → Fix: %s\n", fix)

			if fixAll {
				fmt.Println("  ✅ Applied")
				fixedCount++
				continue
			}

			fmt.Print("  Apply? [Y/n]: ")
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(strings.ToLower(input))

			if input == "" || input == "y" || input == "yes" {
				fmt.Println("  ✅ Applied")
				fixedCount++
			} else {
				fmt.Println("  ⏭️ Skipped")
				skipCount++
			}
		}
		fmt.Println()
	}

	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("  🔧 %d fixed, %d skipped\n", fixedCount, skipCount)
	if fixedCount > 0 {
		fmt.Println("  Run 'shieldwall scan' to verify fixes")
	}

	return nil
}

// canAutoFix returns true if the finding has an automatic fix available
func canAutoFix(f model.Finding) bool {
	switch f.OWASP {
	case "MCP01": // Secret leakage
		return true
	case "MCP02": // Permissions
		return false // needs manual review
	case "MCP07": // Auth
		return false // needs manual setup
	default:
		return false
	}
}

// suggestFix returns a human-readable fix suggestion
func suggestFix(f model.Finding) string {
	switch f.OWASP {
	case "MCP01":
		return "Replace hardcoded secret with environment variable reference"
	default:
		return f.Suggestion
	}
}
