package scorer

import (
	"github.com/wingaturumqi/mcp-shieldwall/internal/model"
)

// Calculate computes a security score from a list of findings
func Calculate(findings []model.Finding) model.ScoreResult {
	result := model.ScoreResult{
		Findings:   findings,
		Dimensions: model.DimensionScore{Config: 20, Permission: 20, Auth: 20, Supply: 20, Injection: 20},
	}

	// Count severities and deduct points from dimensions
	for _, f := range findings {
		deduction := f.Severity.Deduction()

		switch f.OWASP {
		case "MCP01": // Secret/token leakage → Config dimension
			result.Dimensions.Config -= deduction
			result.Severities.Critical++
		case "MCP02": // Permission scope → Permission dimension
			result.Dimensions.Permission -= deduction
			result.Severities.High++
		case "MCP03": // Prompt injection → Injection dimension
			result.Dimensions.Injection -= deduction
			result.Severities.High++
		case "MCP04": // Supply chain → Supply dimension
			result.Dimensions.Supply -= deduction
			result.Severities.Medium++
		case "MCP05": // Command injection → Permission dimension
			result.Dimensions.Permission -= deduction
			result.Severities.High++
		case "MCP07": // Auth → Auth dimension
			result.Dimensions.Auth -= deduction
			result.Severities.Medium++
		default:
			// Distribute to the most relevant dimension
			result.Dimensions.Config -= deduction
		}

		// Count by severity
		switch f.Severity {
		case model.CRITICAL:
			result.Severities.Critical++
		case model.HIGH:
			result.Severities.High++
		case model.MEDIUM:
			result.Severities.Medium++
		case model.LOW:
			result.Severities.Low++
		case model.INFO:
			result.Severities.Info++
		}
	}

	// Clamp dimensions to 0-20
	clamp(&result.Dimensions.Config)
	clamp(&result.Dimensions.Permission)
	clamp(&result.Dimensions.Auth)
	clamp(&result.Dimensions.Supply)
	clamp(&result.Dimensions.Injection)

	// Calculate total (each dimension max 20, total max 100)
	result.Total = result.Dimensions.Config +
		result.Dimensions.Permission +
		result.Dimensions.Auth +
		result.Dimensions.Supply +
		result.Dimensions.Injection

	result.Overall = model.GradeFromScore(result.Total)

	return result
}

func clamp(v *int) {
	if *v < 0 {
		*v = 0
	}
	if *v > 20 {
		*v = 20
	}
}
