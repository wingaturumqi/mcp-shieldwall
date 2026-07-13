package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/wingaturumqi/mcp-shieldwall/internal/model"
)

// CheckPermissions checks if an MCP server has overly broad file system permissions
func CheckPermissions(cfg *model.MCPConfig, server model.MCPServer) []model.Finding {
	var findings []model.Finding

	if server.Transport != "stdio" {
		return findings
	}

	allArgs := strings.Join(server.Args, " ")

	// Check for broad directory access
	dangerousPaths := getDangerousPaths()
	for _, dp := range dangerousPaths {
		if strings.Contains(allArgs, dp) {
			findings = append(findings, model.Finding{
				ServerName: server.Name,
				Severity:   model.HIGH,
				OWASP:      "MCP02",
				Title:      "Overly broad filesystem access",
				Detail:     "Server configured to access " + dp + " which may expose sensitive system files",
				Suggestion: "Restrict access to a specific project directory",
				FilePath:   cfg.Path,
			})
		}
	}

	// Check for home directory root access
	home := getHome()
	if home != "" && strings.Contains(allArgs, home) {
		// Check if it's the home root (not a subdirectory)
		remaining := strings.Replace(allArgs, home, "", 1)
		remaining = strings.Trim(remaining, " /\\")
		if remaining == "" {
			findings = append(findings, model.Finding{
				ServerName: server.Name,
				Severity:   model.HIGH,
				OWASP:      "MCP02",
				Title:      "Access to entire home directory",
				Detail:     "Server can access " + home + " which includes all user files",
				Suggestion: "Restrict to a specific subdirectory (e.g., " + filepath.Join(home, "documents") + ")",
				FilePath:   cfg.Path,
			})
		}
	}

	return findings
}

func getDangerousPaths() []string {
	if runtime.GOOS == "windows" {
		return []string{
			"C:\\", "C:/",
			"C:\\Windows", "C:/Windows",
			"C:\\Users", "C:/Users",
			"C:\\Program Files", "C:/Program Files",
			"C:\\ProgramData", "C:/ProgramData",
		}
	}
	return []string{
		"/etc", "/var", "/usr", "/root", "/tmp", "/sys", "/proc", "/dev",
	}
}

func getHome() string {
	if runtime.GOOS == "windows" {
		if h := os.Getenv("USERPROFILE"); h != "" {
			return h
		}
		return os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
	}
	return os.Getenv("HOME")
}
