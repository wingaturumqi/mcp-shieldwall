package main

import (
	"github.com/wingaturumqi/mcp-shieldwall/cmd"
)

// Set by goreleaser ldflags
var (
	version = "dev"
	commit  = "none"
)

func main() {
	cmd.SetVersion(version, commit)
	cmd.Execute()
}
