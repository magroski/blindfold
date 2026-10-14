//go:build !unix

package cli

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
)

// replaceProcess approximates exec(2) where it does not exist: run the command
// on this process's stdio, then exit with its status. It returns only if the
// command could not be started.
func replaceProcess(path string, argv, envv []string) error {
	cmd := &exec.Cmd{Path: path, Args: argv, Env: envv, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
	// The console delivers Ctrl-C to the command too; outliving it lets the
	// command decide what an interrupt means and report its own status.
	signal.Ignore(os.Interrupt)

	var exitErr *exec.ExitError
	if err := cmd.Run(); err != nil && !errors.As(err, &exitErr) {
		return err
	}
	os.Exit(cmd.ProcessState.ExitCode())
	return nil
}
