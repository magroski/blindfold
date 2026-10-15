package boxsync

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/magroski/blindfold/internal/vault"
)

// serveHelperEnv marks a re-run of this test binary as the box's server;
// hangHelperEnv makes that server go silent after the handshake.
const (
	serveHelperEnv = "BOXSYNC_SERVE_HELPER"
	hangHelperEnv  = "BOXSYNC_SERVE_HANG"
)

// fakeSSH swaps ssh for a script that records its arguments and then runs
// script as the "remote" command. It returns where the arguments land.
func fakeSSH(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	argv := filepath.Join(dir, "argv")
	path := filepath.Join(dir, "ssh")
	body := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + argv + "'\n" + script + "\n"
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	original := sshCommand
	sshCommand = path
	t.Cleanup(func() { sshCommand = original })
	return argv
}

// A session through ssh: the arguments carry the destination and the remote
// command and nothing else; agent and X11 forwarding are off.
func TestDialRunsServeOverSSH(t *testing.T) {
	local, box := newVault(t), newVault(t)
	put(t, local, bundle(), map[string]string{"ES_API_KEY": apiKey, "ES_TOKEN": apiToken})
	t.Setenv(serveHelperEnv, box.Dir())
	argvFile := fakeSSH(t, `exec "`+os.Args[0]+`" -test.run='^TestServeHelper$'`)

	var stderr bytes.Buffer
	session, err := Dial(vault.Remote{Name: "box", Destination: "me@box", Bin: "~/bin/blindfold"}, "test", &stderr)
	if err != nil {
		t.Fatalf("Dial: %v\n%s", err, stderr.String())
	}
	if _, err := session.Push(local, []string{"cdp-es"}, false); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Errorf("Close: %v\n%s", err, stderr.String())
	}

	recorded, _ := os.ReadFile(argvFile)
	argv := strings.Split(strings.TrimSuffix(string(recorded), "\n"), "\n")
	want := []string{"-T", "-a", "-x", "-o", "ClearAllForwardings=yes", "--", "me@box", "~/bin/blindfold sync-serve"}
	if !slices.Equal(argv, want) {
		t.Errorf("ssh argv = %q, want %q", argv, want)
	}
	if strings.Contains(string(recorded), apiKey) {
		t.Error("a value reached ssh's argv")
	}
	// The helper process wrote the box's vault; read it from disk.
	reopened, err := vault.Open(box.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if values, err := reopened.Unseal("cdp-es"); err != nil || values["ES_API_KEY"] != apiKey {
		t.Errorf("box unsealed %v, %v", values, err)
	}
}

// A box without blindfold on the non-interactive PATH: the shell's own message
// reaches the user, and the error says how to point at the binary.
func TestDialExplainsAMissingRemoteBinary(t *testing.T) {
	fakeSSH(t, `echo "sh: blindfold: command not found" >&2; exit 127`)

	var stderr bytes.Buffer
	_, err := Dial(vault.Remote{Name: "box", Destination: "box", Bin: vault.DefaultRemoteBin}, "test", &stderr)
	if err == nil || !strings.Contains(err.Error(), "--bin") {
		t.Errorf("Dial = %v, want a hint naming --bin", err)
	}
	if !strings.Contains(stderr.String(), "command not found") {
		t.Errorf("the box's own message was not shown: %q", stderr.String())
	}
}

// ssh failing on its own is a connection problem, not a missing binary: the
// hint points at ssh, not at --bin.
func TestDialExplainsAnSSHFailure(t *testing.T) {
	fakeSSH(t, `echo "ssh: Could not resolve hostname box" >&2; exit 255`)

	_, err := Dial(vault.Remote{Name: "box", Destination: "box", Bin: vault.DefaultRemoteBin}, "test", io.Discard)
	if err == nil || strings.Contains(err.Error(), "--bin") || !strings.Contains(err.Error(), "`ssh box`") {
		t.Errorf("Dial = %v, want a hint to try `ssh box`", err)
	}
}

// shortTimeout gives a box only a moment to answer, for one test.
func shortTimeout(t *testing.T) {
	original := answerTimeout
	answerTimeout = 200 * time.Millisecond
	t.Cleanup(func() { answerTimeout = original })
}

// A box that never answers the handshake ends the command after the timeout
// instead of hanging it.
func TestDialGivesUpOnASilentBox(t *testing.T) {
	shortTimeout(t)
	fakeSSH(t, `exec sleep 600`)

	_, err := Dial(vault.Remote{Name: "box", Destination: "box", Bin: vault.DefaultRemoteBin}, "test", io.Discard)
	if !errors.Is(err, errTimeout) || !strings.Contains(err.Error(), "`ssh box`") {
		t.Errorf("Dial = %v, want a timeout naming `ssh box`", err)
	}
}

// A box that stops answering mid-session ends the request after the timeout.
// An idle session — the picker waiting on a person — has nothing pending, so
// it stays open however long it waits.
func TestCallGivesUpOnAHungBox(t *testing.T) {
	local := newVault(t)
	put(t, local, bundle(), map[string]string{"ES_API_KEY": apiKey, "ES_TOKEN": apiToken})
	t.Setenv(serveHelperEnv, newVault(t).Dir())
	t.Setenv(hangHelperEnv, "1")
	fakeSSH(t, `exec "`+os.Args[0]+`" -test.run='^TestServeHelper$'`)

	session, err := Dial(vault.Remote{Name: "box", Destination: "box", Bin: vault.DefaultRemoteBin}, "test", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	shortTimeout(t) // after the handshake, which a slow runner may need time for

	time.Sleep(2 * answerTimeout)
	// Ended while idle, the push would fail on a closed pipe, not time out.
	if _, err := session.Push(local, []string{"cdp-es"}, false); !errors.Is(err, errTimeout) {
		t.Errorf("Push = %v, want a timeout", err)
	}
}

// A box command that exits cleanly without answering still gets a reason.
func TestDialExplainsASilentExit(t *testing.T) {
	fakeSSH(t, `exit 0`)

	_, err := Dial(vault.Remote{Name: "box", Destination: "box", Bin: vault.DefaultRemoteBin}, "test", io.Discard)
	if err == nil || strings.Contains(err.Error(), "<nil>") {
		t.Errorf("Dial = %v, want a reason, not <nil>", err)
	}
}

// TestServeHelper is not a test: it is `blindfold sync-serve` on a box whose
// vault is in serveHelperEnv, when that is set.
func TestServeHelper(t *testing.T) {
	dir := os.Getenv(serveHelperEnv)
	if dir == "" {
		return
	}
	if os.Getenv(hangHelperEnv) != "" {
		if _, err := Accept(os.Stdin, os.Stdout, "test"); err != nil {
			os.Exit(1)
		}
		io.Copy(io.Discard, os.Stdin) // reads every request, answers none
		os.Exit(0)
	}
	v, err := vault.Open(dir)
	if err != nil {
		os.Exit(1)
	}
	if err := Serve(v, os.Stdin, os.Stdout, "test", func(Access) {}); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
