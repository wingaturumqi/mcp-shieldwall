package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "shieldwall",
	Short: "MCP Shieldwall – Security audit for MCP servers",
	Long: `MCP Shieldwall is a security audit CLI tool for Model Context Protocol (MCP) servers.
It scans your MCP configurations, detects security issues, and provides actionable fixes.

Based on OWASP MCP Top 10 security standards.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
