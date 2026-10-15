package boxsync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"syscall"
	"time"

	"github.com/magroski/blindfold/internal/vault"
)

// sshCommand is the ssh client every session runs: the user's own, so their
// ~/.ssh/config, agent, known_hosts and prompts all apply. Tests swap it.
var sshCommand = "ssh"

// sshArgs are fixed: no tty, so the stream stays binary-clean; no agent, X11
// or port forwarding, which a sync session never needs and a box should not
// be handed. "--" keeps the destination from ever reading as an option.
var sshArgs = []string{"-T", "-a", "-x", "-o", "ClearAllForwardings=yes", "--"}

// serveCommand is what the box runs.
const serveCommand = "sync-serve"

// stopDelay is how long ssh has to exit after a timeout before it is killed.
const stopDelay = 5 * time.Second

// Dial opens a session with a box by running `<bin> sync-serve` there over
// ssh. The box's stderr — ssh's own errors included — goes to stderr as it
// arrives. Values travel only on the encrypted stream, never in argv.
func Dial(remote vault.Remote, version string, stderr io.Writer) (*Session, error) {
	ctx, cancel := context.WithCancel(context.Background())
	// The bin was held to characters every shell reads literally when the box
	// was added, so it needs no quoting for whichever shell the box runs.
	cmd := exec.CommandContext(ctx, sshCommand, append(sshArgs, remote.Destination, remote.Bin+" "+serveCommand)...)
	// SIGTERM, not SIGKILL: ssh then restores a terminal it was prompting on.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = stopDelay
	cmd.Stderr = stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("running ssh: %w", err)
	}

	// abort stops ssh and closes both pipes, so a read or write blocked on the
	// box returns now rather than when ssh exits.
	abort := func() {
		cancel()
		stdin.Close()
		stdout.Close()
	}
	var session *Session
	err = withinTimeout(abort, func() (err error) {
		session, err = Connect(stdout, stdin, version)
		return err
	})
	if err != nil {
		stdin.Close()
		waitErr := cmd.Wait()
		cancel()
		return nil, dialError(remote, err, waitErr)
	}
	session.abort = abort
	session.closer = closerFunc(func() error {
		stdin.Close()
		defer cancel()
		return cmd.Wait()
	})
	return session, nil
}

// sshFailed is the status ssh exits with when it fails itself — host
// unresolved, connection refused, authentication — rather than the box's command.
const sshFailed = 255

// dialError explains a session that never started. A box that hung up before
// answering most often has no blindfold where a non-interactive ssh session
// looks.
func dialError(remote vault.Remote, handshake, exit error) error {
	if errors.Is(handshake, errTimeout) {
		return fmt.Errorf("%w. Check that `ssh %s` connects, and that `%s %s` starts there",
			handshake, remote.Destination, remote.Bin, serveCommand)
	}
	if !errors.Is(handshake, ErrNoAnswer) {
		return handshake
	}
	var exited *exec.ExitError
	if errors.As(exit, &exited) && exited.ExitCode() == sshFailed {
		return fmt.Errorf("ssh to %s failed; its message is above. Check that `ssh %s` works from here",
			remote.Destination, remote.Destination)
	}
	reason := "it exited without answering"
	if exit != nil {
		reason = exit.Error()
	}
	return fmt.Errorf("`%s %s` did not start (%s). Is blindfold installed there, new enough to have "+
		"%s, and on the PATH of a non-interactive ssh session? Point at it with "+
		"`blindfold remote rm %s && blindfold remote add %s %s --bin /path/to/blindfold`",
		remote.Bin, serveCommand, reason, serveCommand, remote.Name, remote.Name, remote.Destination)
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }
