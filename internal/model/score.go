package model

// ScoreResult represents the security score for an MCP configuration
type ScoreResult struct {
	// Overall letter grade (A-F)
	Overall string
	// Total score (0-100)
	Total int
	// Dimension scores (each 0-20)
	Dimensions DimensionScore
	// Findings is the list of all findings
	Findings []Finding
	// Severities is the count by severity level
	Severities SeverityCount
}

// DimensionScore breaks down the score into 5 dimensions
type DimensionScore struct {
	Config     int // Configuration security (secrets, plaintext)
	Permission int // Permission control (paths, shell, network)
	Auth       int // Authentication strength (token, OAuth)
	Supply     int // Supply chain (dependency versions, vulns)
	Injection  int // Injection resistance (prompt injection)
}

// SeverityCount counts findings by severity
type SeverityCount struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

// GradeFromScore returns a letter grade from a numeric score
func GradeFromScore(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

// GradeDescription returns a human-readable description of the grade
func GradeDescription(grade string) string {
	switch grade {
	case "A":
		return "Excellent"
	case "B":
		return "Good"
	case "C":
		return "Fair"
	case "D":
		return "Dangerous"
	case "F":
		return "Critical"
	default:
		return "Unknown"
	}
}
