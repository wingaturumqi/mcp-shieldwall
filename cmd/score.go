package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"github.com/wingaturumqi/mcp-shieldwall/internal/finder"
	"github.com/wingaturumqi/mcp-shieldwall/internal/model"
	"github.com/wingaturumqi/mcp-shieldwall/internal/parser"
	"github.com/wingaturumqi/mcp-shieldwall/internal/scanner"
	"github.com/wingaturumqi/mcp-shieldwall/internal/scorer"
)

var scoreCmd = &cobra.Command{
	Use:   "score",
	Short: "Show security score for MCP configurations",
	Long:  "Analyze all MCP configurations and display an A-F security score with dimension breakdown.",
	RunE:  runScore,
}

func init() {
	rootCmd.AddCommand(scoreCmd)
}

func runScore(cmd *cobra.Command, args []string) error {
	configs, err := finder.FindAll()
	if err != nil {
		return fmt.Errorf("error finding configs: %w", err)
	}

	if len(configs) == 0 {
		fmt.Println("  No MCP configuration files found.")
		return nil
	}

	// Collect all findings across all configs
	var allFindings []model.Finding
	serverCount := 0

	for _, cfg := range configs {
		parsed, err := parser.Parse(cfg.Path, cfg.Source)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠️  Failed to parse %s: %v\n", cfg.Path, err)
			continue
		}
		for range parsed.Servers {
			serverCount++
		}
		findings := scanner.Scan(parsed)
		allFindings = append(allFindings, findings...)
	}

	// Calculate score
	result := scorer.Calculate(allFindings)

	// Print score report
	printScoreReport(result, serverCount, len(configs))

	return nil
}

func printScoreReport(result model.ScoreResult, serverCount, configCount int) {
	// Styles
	gradeStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15"))
	barFill := lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	barEmpty := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	fmt.Println("📊 MCP Security Score")
	fmt.Println()
	fmt.Printf("  Configuration files: %d\n", configCount)
	fmt.Printf("  MCP servers: %d\n", serverCount)
	fmt.Printf("  Issues found: %d\n", len(result.Findings))
	fmt.Println()

	// Grade with color
	gradeColor := gradeColor(result.Overall)
	styledGrade := gradeStyle.Foreground(lipgloss.Color(gradeColor)).Render(result.Overall)
	fmt.Printf("  Overall: %s %s (%d/100)\n", styledGrade, model.GradeDescription(result.Overall), result.Total)
	fmt.Println()

	// Dimension bars
	dims := []struct {
		Name  string
		Score int
	}{
		{"Config security", result.Dimensions.Config},
		{"Permissions    ", result.Dimensions.Permission},
		{"Authentication", result.Dimensions.Auth},
		{"Supply chain  ", result.Dimensions.Supply},
		{"Injection     ", result.Dimensions.Injection},
	}

	for _, d := range dims {
		filled := d.Score / 2
		empty := 10 - filled
		bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)
		fmt.Printf("  %s  %s%s%s  %d/20\n", d.Name, barFill.Render(bar[:filled]), barEmpty.Render(bar[filled:]), "", d.Score)
	}

	fmt.Println()

	// Severity summary
	if len(result.Findings) > 0 {
		fmt.Print("  Severity: ")
		parts := []string{}
		if result.Severities.Critical > 0 {
			parts = append(parts, fmt.Sprintf("🔴 %d critical", result.Severities.Critical))
		}
		if result.Severities.High > 0 {
			parts = append(parts, fmt.Sprintf("🟠 %d high", result.Severities.High))
		}
		if result.Severities.Medium > 0 {
			parts = append(parts, fmt.Sprintf("🟡 %d medium", result.Severities.Medium))
		}
		if result.Severities.Low > 0 {
			parts = append(parts, fmt.Sprintf("🔵 %d low", result.Severities.Low))
		}
		fmt.Println(strings.Join(parts, "  "))
		fmt.Println()
		fmt.Println("  Run 'shieldwall scan' for detailed findings")
		fmt.Println("  Run 'shieldwall fix' for auto-fix suggestions")
	}
}

func gradeColor(grade string) string {
	switch grade {
	case "A":
		return "10" // green
	case "B":
		return "12" // light blue
	case "C":
		return "11" // yellow
	case "D":
		return "208" // orange
	default:
		return "9" // red
	}
}
