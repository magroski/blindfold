package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/magroski/blindfold/internal/audit"
)

// launch is what `exec` would have handed the kernel.
type launch struct {
	path string
	argv []string
	env  []string
}

// captureExec swaps the process replacement for a recorder, so a test sees what
// would have run instead of being replaced by it.
func captureExec(t *testing.T) *[]launch {
	t.Helper()
	var launches []launch
	original := execProcess
	execProcess = func(path string, argv, env []string) error {
		launches = append(launches, launch{path: path, argv: argv, env: env})
		return nil
	}
	t.Cleanup(func() { execProcess = original })
	return &launches
}

// lookup returns every value env gives name. More than one means the command
// sees whichever its libc happens to pick.
func lookup(env []string, name string) []string {
	var values []string
	for _, kv := range env {
		if k, v, _ := strings.Cut(kv, "="); k == name {
			values = append(values, v)
		}
	}
	return values
}

// The point of `exec`: the command gets the values, the transcript gets nothing
// but their names.
func TestExecHandsValuesToTheCommandAndNothingToStdout(t *testing.T) {
	h := newHarness(t)
	launches := captureExec(t)
	const value = "extremely-secret-value"
	h.mustRun(value, "add", "cdp-es", "--var", "ES_ENDPOINT=https://x", "--secret", "ES_API_KEY")

	code, stdout, stderr := h.run("", "exec", "cdp-es", "--", "sh", "-c", "true")
	if code != 0 {
		t.Fatalf("exec exited %d: %s", code, stderr)
	}
	if stdout != "" {
		t.Errorf("exec wrote %q to stdout, which is the transcript", stdout)
	}
	if strings.Contains(stderr, value) {
		t.Errorf("summary %q contains the secret value", stderr)
	}
	if !strings.Contains(stderr, "ES_API_KEY") || !strings.Contains(stderr, "ES_ENDPOINT") {
		t.Errorf("summary %q does not name the loaded variables", stderr)
	}

	if len(*launches) != 1 {
		t.Fatalf("exec launched %d commands, want 1", len(*launches))
	}
	got := (*launches)[0]
	if !slices.Equal(got.argv, []string{"sh", "-c", "true"}) {
		t.Errorf("argv = %q, want the command exactly as given", got.argv)
	}
	if !filepath.IsAbs(got.path) || filepath.Base(got.path) != "sh" {
		t.Errorf("path = %q, want sh resolved through PATH", got.path)
	}
	if v := lookup(got.env, "ES_API_KEY"); !slices.Equal(v, []string{value}) {
		t.Errorf("child ES_API_KEY = %q, want exactly [%s]", v, value)
	}
	if v := lookup(got.env, "ES_ENDPOINT"); !slices.Equal(v, []string{"https://x"}) {
		t.Errorf("child ES_ENDPOINT = %q, want exactly [https://x]", v)
	}
}

// A stale value already in the environment must lose to the credential, and
// must not survive alongside it as a duplicate.
func TestExecReplacesInheritedVariablesAndKeepsTheRest(t *testing.T) {
	h := newHarness(t)
	launches := captureExec(t)
	t.Setenv("DATABASE_URL", "postgres://stale")
	t.Setenv("BLINDFOLD_TEST_UNRELATED", "kept")
	h.mustRun("postgres://fresh", "add", "pg-ro", "--secret", "DATABASE_URL")

	h.mustRun("", "exec", "--set", "DATABASE_URL=pg-ro", "--", "true")

	env := (*launches)[0].env
	if v := lookup(env, "DATABASE_URL"); !slices.Equal(v, []string{"postgres://fresh"}) {
		t.Errorf("child DATABASE_URL = %q, want only the vault's value", v)
	}
	if v := lookup(env, "BLINDFOLD_TEST_UNRELATED"); !slices.Equal(v, []string{"kept"}) {
		t.Errorf("child lost an unrelated variable: %q", v)
	}
}

// The same value from two sources is not a conflict, and not two variables.
func TestExecLoadsAHarmlessDuplicateOnce(t *testing.T) {
	h := newHarness(t)
	launches := captureExec(t)
	h.mustRun("v", "add", "one", "--secret", "TOKEN")

	h.mustRun("", "exec", "one", "one", "--", "true")

	if v := lookup((*launches)[0].env, "TOKEN"); !slices.Equal(v, []string{"v"}) {
		t.Errorf("child TOKEN = %q, want exactly [v]", v)
	}
}

// The command was given one credential, not the key that opens all of them.
func TestExecKeepsTheMasterPassphraseFromTheCommand(t *testing.T) {
	h := newHarness(t)
	launches := captureExec(t)
	h.mustRun("v", "add", "TOKEN")
	// The harness's key file outranks the passphrase, so this one is only inherited.
	t.Setenv("BLINDFOLD_PASSPHRASE", "master-passphrase")

	h.mustRun("", "exec", "TOKEN", "--", "true")

	if v := lookup((*launches)[0].env, "BLINDFOLD_PASSPHRASE"); len(v) != 0 {
		t.Errorf("the master passphrase reached the command: %q", v)
	}
}

func TestExecRefusesConflictingVariableNames(t *testing.T) {
	h := newHarness(t)
	launches := captureExec(t)
	h.mustRun("first", "add", "one", "--secret", "SHARED_NAME")
	h.mustRun("second", "add", "two", "--secret", "SHARED_NAME")

	code, _, stderr := h.run("", "exec", "one", "two", "--", "true")
	if code == 0 || len(*launches) != 0 {
		t.Fatal("exec ran a command with a conflict resolved silently")
	}
	if !strings.Contains(stderr, "SHARED_NAME would be set twice") {
		t.Errorf("error = %q, want it to name the conflicting variable", stderr)
	}
}

// Malformed invocations are refused before anything is unsealed: a typo should
// cost nothing, not even a keychain prompt.
func TestExecRefusesBadArgumentsBeforeUnsealing(t *testing.T) {
	h := newHarness(t)
	launches := captureExec(t)
	h.mustRun("v", "add", "TOKEN")

	// Without its key the vault cannot unseal, so reaching that step would
	// surface as a key error instead of the refusal under test.
	t.Setenv("BLINDFOLD_KEK_FILE", filepath.Join(t.TempDir(), "missing"))
	if code, _, stderr := h.run("", "exec", "TOKEN", "--", "true"); code == 0 || !strings.Contains(stderr, "not initialized") {
		t.Fatalf("premise: exec should fail to unseal without the key, got %d: %s", code, stderr)
	}

	cases := map[string]struct {
		args []string
		want string
	}{
		"no separator":    {[]string{"exec", "TOKEN", "true"}, `missing "--"`},
		"no command":      {[]string{"exec", "TOKEN", "--"}, "no command"},
		"no credential":   {[]string{"exec", "--", "true"}, "nothing to load"},
		"unknown command": {[]string{"exec", "TOKEN", "--", "blindfold-no-such-command"}, "blindfold-no-such-command"},
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			code, stdout, stderr := h.run("", c.args...)
			if code == 0 {
				t.Fatalf("exec %q succeeded: %s", c.args, stdout)
			}
			if !strings.Contains(stderr, c.want) {
				t.Errorf("error = %q, want it to mention %s", stderr, c.want)
			}
		})
	}
	if len(*launches) != 0 {
		t.Errorf("a refused invocation still launched %d commands", len(*launches))
	}
}

func TestExecQuietPrintsNothing(t *testing.T) {
	h := newHarness(t)
	captureExec(t)
	h.mustRun("v", "add", "TOKEN")

	if code, stdout, stderr := h.run("", "exec", "--quiet", "TOKEN", "--", "true"); code != 0 || stdout+stderr != "" {
		t.Errorf("exec --quiet exited %d and printed %q", code, stdout+stderr)
	}
}

func TestExecIsAuditedWithoutValues(t *testing.T) {
	h := newHarness(t)
	captureExec(t)
	const value = "extremely-secret-value"
	h.mustRun(value, "add", "cdp-es", "--secret", "ES_API_KEY")

	h.mustRun("", "exec", "cdp-es", "--", "true")

	events, err := audit.Read(h.dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	last := events[len(events)-1]
	if last.Tool != "exec" || last.Secret != "cdp-es" || last.Field != "ES_API_KEY" {
		t.Errorf("last audit event = %+v, want exec of cdp-es.ES_API_KEY", last)
	}
	raw, err := os.ReadFile(filepath.Join(h.dir, audit.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), value) {
		t.Error("audit log contains the value")
	}
}

// helperEnv marks a re-run of this test binary as the blindfold process itself.
const helperEnv = "BLINDFOLD_EXEC_HELPER"

// End to end, with the real process replacement: this test binary re-runs as
// blindfold, becomes /bin/sh, and the shell's exit status must come back as is.
func TestExecRunsTheRealCommandAndKeepsItsExitStatus(t *testing.T) {
	const wantStatus = 7
	h := newHarness(t)
	h.mustRun("the-value", "add", "TOKEN")

	cmd := exec.Command(os.Args[0], "-test.run=^TestExecHelperProcess$", "--",
		"exec", "TOKEN", "--", "sh", "-c", fmt.Sprintf(`test "$TOKEN" = the-value && exit %d`, wantStatus))
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	out, err := cmd.CombinedOutput()

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != wantStatus {
		t.Fatalf("exec finished with %v, want status %d from the command: %s", err, wantStatus, out)
	}
	if strings.Contains(string(out), "the-value") {
		t.Errorf("output %q contains the value", out)
	}
}

// TestExecHelperProcess is not a test: it is blindfold, when helperEnv says so.
func TestExecHelperProcess(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		return
	}
	args := os.Args[slices.Index(os.Args, "--")+1:]
	os.Exit(Run(context.Background(), Env{
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Version: "test",
	}, args))
}
