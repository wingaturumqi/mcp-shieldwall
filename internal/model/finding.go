package model

import "fmt"

// Severity levels for security findings
type Severity int

const (
	INFO Severity = iota
	LOW
	MEDIUM
	HIGH
	CRITICAL
)

func (s Severity) String() string {
	switch s {
	case CRITICAL:
		return "CRITICAL"
	case HIGH:
		return "HIGH"
	case MEDIUM:
		return "MEDIUM"
	case LOW:
		return "LOW"
	case INFO:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}

// Deduction points per severity level
func (s Severity) Deduction() int {
	switch s {
	case CRITICAL:
		return 25
	case HIGH:
		return 15
	case MEDIUM:
		return 8
	case LOW:
		return 3
	case INFO:
		return 1
	default:
		return 0
	}
}

// Finding represents a single security issue discovered during scanning
type Finding struct {
	// ServerName is the MCP server where the issue was found
	ServerName string
	// Severity is the severity level
	Severity Severity
	// OWASP maps to OWASP MCP Top 10 (e.g., "MCP01")
	OWASP string
	// Title is a short description of the issue
	Title string
	// Detail provides more context about the issue
	Detail string
	// Suggestion is the recommended fix
	Suggestion string
	// FilePath is the config file where the issue was found
	FilePath string
}

func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s: %s", f.Severity, f.ServerName, f.Title)
}
