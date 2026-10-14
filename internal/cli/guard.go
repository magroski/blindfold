package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/magroski/blindfold/internal/audit"
	"github.com/magroski/blindfold/internal/vault"
)

// agentShellMarkers are set by agent harnesses in every shell they spawn. A pty
// makes such a shell look like a terminal; the marker is what gives it away.
//
// Best-effort: a harness not listed, or one that scrubs its environment, goes
// undetected. The real control is a Claude Code `ask` permission rule on
// `blindfold get` and `blindfold export` (README, Install step 3).
var agentShellMarkers = []string{
	"CLAUDECODE",                     // Claude Code
	"CODEX_SANDBOX",                  // Codex CLI
	"CODEX_SANDBOX_NETWORK_DISABLED", // Codex CLI
}

const (
	notTerminal = "stdout is not a terminal"
	// reasonSep joins conditions, e.g. "stdout is not a terminal; CLAUDECODE is set".
	reasonSep = "; "
)

// plaintextRefusal decides whether `get` and `export` may print plaintext. It
// returns the conditions that forbid it, or "" when it is allowed: at a
// terminal outside any agent's shell, or with --force. A marker counts when set
// at all: `CLAUDECODE= blindfold get x` is still an agent's shell.
func plaintextRefusal(isTerminal bool, lookupEnv func(string) (string, bool), force bool) string {
	if force {
		return ""
	}
	var reasons []string
	if !isTerminal {
		reasons = append(reasons, notTerminal)
	}
	for _, marker := range agentShellMarkers {
		if _, set := lookupEnv(marker); set {
			reasons = append(reasons, marker+" is set (an agent's shell)")
		}
	}
	return strings.Join(reasons, reasonSep)
}

// guardPlaintext refuses, unless forced, to print plaintext where it may be
// captured, and records the refusal. It runs before the vault is opened, so a
// refusal never unseals anything.
func guardPlaintext(env Env, tool, name string, force bool) error {
	reason := plaintextRefusal(stdoutIsTerminal(env), os.LookupEnv, force)
	if reason == "" {
		return nil
	}
	logDenial(env, tool, name, reason)
	return fmt.Errorf("refusing to print plaintext: %s.\n"+
		"Pass --force to print anyway; the output lands in whatever captured it.\n"+
		"To hand credentials to a command, use `%s exec` or `%s env` instead — the values\n"+
		"reach the command without passing through your terminal or your transcript",
		reason, Bin, Bin)
}

// logDenial records a refusal under the name the caller gave.
func logDenial(env Env, tool, name, reason string) {
	// The name comes straight from argv, unchecked against the vault. Quoting an
	// unusable one keeps it on one line, e.g. "x\n1999-01-01 ..." cannot forge a
	// row of `blindfold audit`.
	if vault.ValidateEntryName(name) != nil {
		name = strconv.Quote(name)
	}

	dir, err := vault.DefaultDir()
	if err != nil {
		fmt.Fprintf(env.Stderr, "%s: audit log not written: %v\n", Bin, err)
		return
	}
	auditLog(env, dir).Log(audit.Event{
		Tool: tool, Secret: name, Decision: audit.Denied, Reason: reason,
	})
}

// auditLog returns a logger that reports write failures on the command's stderr.
func auditLog(env Env, dir string) *audit.Logger {
	log := audit.New(dir)
	log.Stderr = env.Stderr
	return log
}
