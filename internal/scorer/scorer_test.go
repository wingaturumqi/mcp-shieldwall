package scorer_test

import (
	"testing"

	"github.com/wingaturumqi/mcp-shieldwall/internal/model"
	"github.com/wingaturumqi/mcp-shieldwall/internal/scorer"
)

func TestCalculateClean(t *testing.T) {
	result := scorer.Calculate(nil)

	if result.Total != 100 {
		t.Errorf("expected 100 for clean config, got %d", result.Total)
	}
	if result.Overall != "A" {
		t.Errorf("expected grade A, got %s", result.Overall)
	}
}

func TestCalculateWithCriticalFinding(t *testing.T) {
	findings := []model.Finding{
		{ServerName: "test", Severity: model.CRITICAL, OWASP: "MCP01", Title: "secret leaked"},
	}

	result := scorer.Calculate(findings)

	if result.Total >= 100 {
		t.Error("score should decrease with critical finding")
	}
	if result.Total < 50 {
		t.Errorf("score too low for single critical: %d", result.Total)
	}
	if result.Severities.Critical == 0 {
		t.Error("expected critical count > 0")
	}
}

func TestCalculateGradeBoundaries(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{100, "A"},
		{90, "A"},
		{89, "B"},
		{75, "B"},
		{74, "C"},
		{60, "C"},
		{59, "D"},
		{40, "D"},
		{39, "F"},
		{0, "F"},
	}

	for _, tt := range tests {
		got := model.GradeFromScore(tt.score)
		if got != tt.want {
			t.Errorf("GradeFromScore(%d) = %s, want %s", tt.score, got, tt.want)
		}
	}
}

func TestDimensionClamping(t *testing.T) {
	// Many critical findings should not go below 0
	findings := make([]model.Finding, 20)
	for i := range findings {
		findings[i] = model.Finding{
			Severity: model.CRITICAL,
			OWASP:    "MCP01",
		}
	}

	result := scorer.Calculate(findings)

	if result.Dimensions.Config < 0 {
		t.Error("dimension should not go below 0")
	}
	if result.Total < 0 {
		t.Error("total should not go below 0")
	}
}
