// Command blindfold keeps credentials out of a coding agent's transcript.
//
// It stores named bundles of environment variables and hands them to a command
// via `blindfold exec <name> -- <cmd>`, so the value reaches the process that
// needs it without passing through the conversation.
package main

import (
	"context"
	"os"

	"github.com/magroski/blindfold/internal/cli"
)

// version is overridden at build time via -ldflags.
var version = "dev"

func main() {
	os.Exit(cli.Run(context.Background(), cli.Env{
		Stdin:   os.Stdin,
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		Version: version,
	}, os.Args[1:]))
}
