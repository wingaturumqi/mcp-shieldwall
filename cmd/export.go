package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/wingaturumqi/mcp-shieldwall/internal/finder"
	"github.com/wingaturumqi/mcp-shieldwall/internal/model"
	"github.com/wingaturumqi/mcp-shieldwall/internal/parser"
	"github.com/wingaturumqi/mcp-shieldwall/internal/scanner"
	"github.com/wingaturumqi/mcp-shieldwall/internal/scorer"
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export scan results in JSON or SARIF format",
	Long:  "Export security scan results for CI/CD integration. Supports JSON and SARIF 2.1.0 formats.",
	RunE:  runExport,
}

var exportFormat string
var exportOutput string

func init() {
	exportCmd.Flags().StringVarP(&exportFormat, "format", "f", "json", "Output format: json, sarif")
	exportCmd.Flags().StringVarP(&exportOutput, "output", "o", "", "Output file (default: stdout)")
	rootCmd.AddCommand(exportCmd)
}

func runExport(cmd *cobra.Command, args []string) error {
	configs, err := finder.FindAll()
	if err != nil {
		return err
	}

	allFindings := make([]model.Finding, 0)
	for _, cfg := range configs {
		parsed, err := parser.Parse(cfg.Path, cfg.Source)
		if err != nil {
			continue
		}
		allFindings = append(allFindings, scanner.Scan(parsed)...)
	}

	result := scorer.Calculate(allFindings)

	var output []byte
	switch exportFormat {
	case "json":
		output, err = exportJSON(result)
	case "sarif":
		output, err = exportSARIF(result)
	default:
		return fmt.Errorf("unsupported format: %s (use json or sarif)", exportFormat)
	}
	if err != nil {
		return err
	}

	if exportOutput != "" {
		return os.WriteFile(exportOutput, output, 0644)
	}

	fmt.Println(string(output))
	return nil
}

func exportJSON(result model.ScoreResult) ([]byte, error) {
	report := map[string]interface{}{
		"score": map[string]interface{}{
			"overall": result.Overall,
			"total":   result.Total,
			"dimensions": map[string]int{
				"config":     result.Dimensions.Config,
				"permission": result.Dimensions.Permission,
				"auth":       result.Dimensions.Auth,
				"supply":     result.Dimensions.Supply,
				"injection":  result.Dimensions.Injection,
			},
		},
		"summary": map[string]int{
			"critical": result.Severities.Critical,
			"high":     result.Severities.High,
			"medium":   result.Severities.Medium,
			"low":      result.Severities.Low,
			"info":     result.Severities.Info,
		},
		"findings": result.Findings,
	}
	return json.MarshalIndent(report, "", "  ")
}

func exportSARIF(result model.ScoreResult) ([]byte, error) {
	// SARIF 2.1.0 format for GitHub Code Scanning
	type sarifMessage struct {
		Text string `json:"text"`
	}

	type sarifLocation struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
	}

	type sarifResult struct {
		RuleID    string          `json:"ruleId"`
		Level     string          `json:"level"`
		Message   sarifMessage    `json:"message"`
		Locations []sarifLocation `json:"locations"`
	}

	type sarifRule struct {
		ID               string            `json:"id"`
		Name             string            `json:"name"`
		ShortDescription sarifMessage       `json:"shortDescription"`
		FullDescription   sarifMessage       `json:"fullDescription"`
		DefaultConfiguration struct {
			Level string `json:"level"`
		} `json:"defaultConfiguration"`
	}

	type sarifRun struct {
		Tool struct {
			Driver struct {
				Name            string       `json:"name"`
				Version         string       `json:"version"`
				InformationURI  string       `json:"informationUri"`
				Rules           []sarifRule  `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []sarifResult `json:"results"`
	}

	type sarifLog struct {
		Version string     `json:"version"`
		Schema  string     `json:"$schema"`
		Runs    []sarifRun `json:"runs"`
	}

	sarif := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
	}

	run := sarifRun{}
	run.Tool.Driver.Name = "mcp-shieldwall"
	run.Tool.Driver.Version = versionStr
	run.Tool.Driver.InformationURI = "https://github.com/wingaturumqi/mcp-shieldwall"
	run.Tool.Driver.Rules = make([]sarifRule, 0)
	run.Results = make([]sarifResult, 0)

	// Build rules from findings
	ruleSeen := make(map[string]bool)
	for _, f := range result.Findings {
		if !ruleSeen[f.OWASP] {
			ruleSeen[f.OWASP] = true
			rule := sarifRule{
				ID:   f.OWASP,
				Name: f.Title,
			}
			rule.ShortDescription.Text = f.Title
			rule.FullDescription.Text = f.Detail
			rule.DefaultConfiguration.Level = severityToSARIF(f.Severity)
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
		}

		sr := sarifResult{
			RuleID:  f.OWASP,
			Level:   severityToSARIF(f.Severity),
			Message: sarifMessage{Text: f.Detail + "\n💡 " + f.Suggestion},
		}
		loc := sarifLocation{}
		loc.PhysicalLocation.ArtifactLocation.URI = f.FilePath
		sr.Locations = []sarifLocation{loc}
		run.Results = append(run.Results, sr)
	}

	sarif.Runs = []sarifRun{run}
	return json.MarshalIndent(sarif, "", "  ")
}

func severityToSARIF(s model.Severity) string {
	switch s {
	case model.CRITICAL, model.HIGH:
		return "error"
	case model.MEDIUM:
		return "warning"
	case model.LOW, model.INFO:
		return "note"
	default:
		return "none"
	}
}
