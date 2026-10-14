package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/magroski/blindfold/internal/audit"
)

// fakeEnv is a getenv backed by a map, so the decision does not depend on the
// shell running the tests — inside Claude Code, CLAUDECODE is set.
func fakeEnv(vars map[string]string) func(string) string {
	return func(name string) string { return vars[name] }
}

// clearAgentMarkers unsets every marker for one test, so a harness test sees
// only the conditions it sets up.
func clearAgentMarkers(t *testing.T) {
	t.Helper()
	for _, name := range agentShellMarkers {
		t.Setenv(name, "")
	}
}

// Plaintext is refused unless forced when stdout is not a terminal or the shell
// belongs to an agent: a pty makes an agent's shell look like a terminal.
func TestPlaintextRefusal(t *testing.T) {
	agent := fakeEnv(map[string]string{"CLAUDECODE": "1"})
	clean := fakeEnv(nil)

	cases := []struct {
		name   string
		tty    bool
		getenv func(string) string
		force  bool
		want   []string // conditions the reason names; none means allowed
	}{
		{"person at a terminal", true, clean, false, nil},
		{"pipe", false, clean, false, []string{"not a terminal"}},
		{"agent with a pty", true, agent, false, []string{"CLAUDECODE"}},
		{"agent with a pipe", false, agent, false, []string{"not a terminal", "CLAUDECODE"}},
		{"forced at a terminal", true, clean, true, nil},
		{"forced pipe", false, clean, true, nil},
		{"forced agent with a pty", true, agent, true, nil},
		{"forced agent with a pipe", false, agent, true, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reason := plaintextRefusal(c.tty, c.getenv, c.force)
			if len(c.want) == 0 && reason != "" {
				t.Fatalf("refused (%s), want allowed", reason)
			}
			if len(c.want) > 0 && reason == "" {
				t.Fatal("allowed, want refused")
			}
			for _, w := range c.want {
				if !strings.Contains(reason, w) {
					t.Errorf("reason %q does not name %q", reason, w)
				}
			}
		})
	}
}

// Each supported harness is detected on its own, even at a terminal.
func TestPlaintextRefusalDetectsEachHarness(t *testing.T) {
	for _, marker := range []string{"CLAUDECODE", "CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED"} {
		reason := plaintextRefusal(true, fakeEnv(map[string]string{marker: "1"}), false)
		if !strings.Contains(reason, marker) {
			t.Errorf("%s set: reason %q, want a refusal naming it", marker, reason)
		}
	}
}

// The refusal says why, offers both ways forward, and carries no value.
func TestPlaintextRefusalMessage(t *testing.T) {
	for _, tool := range []string{"get", "export"} {
		t.Run(tool, func(t *testing.T) {
			h := newHarness(t)
			clearAgentMarkers(t)
			t.Setenv("CLAUDECODE", "1")
			h.mustRun("the-value", "add", "TOKEN")

			code, stdout, stderr := h.run("", tool, "TOKEN")
			if code == 0 {
				t.Fatalf("%s printed inside an agent's shell: %s", tool, stdout)
			}
			if strings.Contains(stdout+stderr, "the-value") {
				t.Error("the refusal leaked the value")
			}
			for _, want := range []string{"not a terminal", "CLAUDECODE", "--force", Bin + " exec", Bin + " env"} {
				if !strings.Contains(stderr, want) {
					t.Errorf("refusal %q does not mention %q", stderr, want)
				}
			}
		})
	}
}

// A refusal is an attempt on a credential; the log is the only trail of it.
func TestRefusalIsRecordedAsADenial(t *testing.T) {
	for _, tool := range []string{"get", "export"} {
		t.Run(tool, func(t *testing.T) {
			h := newHarness(t)
			clearAgentMarkers(t)
			h.mustRun("the-value", "add", "TOKEN")
			h.run("", tool, "TOKEN")

			log := h.mustRun("", "audit")
			if strings.Contains(log, "the-value") {
				t.Error("audit log contains the value")
			}
			for _, line := range strings.Split(log, "\n") {
				if !strings.Contains(line, string(audit.Denied)) {
					continue
				}
				if !strings.Contains(line, " "+tool+" ") || !strings.Contains(line, "TOKEN") ||
					!strings.Contains(line, "not a terminal") {
					t.Errorf("denial row %q does not name the command, credential and condition", line)
				}
				return
			}
			t.Errorf("audit shows no denial:\n%s", log)
		})
	}
}

// The name is recorded before the vault is consulted, so it comes straight from
// argv. A crafted one must not forge a row of `blindfold audit`.
func TestDenialCannotForgeAuditRows(t *testing.T) {
	h := newHarness(t)
	clearAgentMarkers(t)
	const forgedDate = "1999-01-01"
	h.run("", "get", "x\n"+forgedDate+" 00:00:00  env  prod-db  DATABASE_URL")

	log := h.mustRun("", "audit")
	for _, line := range strings.Split(log, "\n") {
		if strings.HasPrefix(line, forgedDate) {
			t.Errorf("a caller-supplied name forged an audit row: %q", line)
		}
	}
}

// An unwritable log must not stop the command — an auditing problem is not an
// outage — and must not pass silently either.
func TestUnwritableAuditLogWarnsButDoesNotFail(t *testing.T) {
	h := newHarness(t)
	clearAgentMarkers(t)
	h.mustRun("the-value", "add", "TOKEN")
	if err := os.Mkdir(filepath.Join(h.dir, audit.FileName), 0o700); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := h.run("", "get", "TOKEN", "--force")
	if code != 0 {
		t.Fatalf("get failed because the audit log is unwritable: %s", stderr)
	}
	if strings.TrimSpace(stdout) != "the-value" {
		t.Errorf("get --force = %q", stdout)
	}
	if !strings.Contains(stderr, "audit log not written") {
		t.Errorf("stderr %q does not warn that the access went unrecorded", stderr)
	}

	if _, _, stderr := h.run("", "get", "TOKEN"); !strings.Contains(stderr, "audit log not written") {
		t.Errorf("an unrecorded denial passed silently: %q", stderr)
	}
}
