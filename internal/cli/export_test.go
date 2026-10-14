package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// `export` prints every value in the clear, so it is guarded like `get`: an
// agent's shell is a pipe, and a pipe leads to the transcript.
func TestExportRefusesAPipeWithoutForce(t *testing.T) {
	h := newHarness(t)
	h.mustRun("the-value", "add", "TOKEN")

	code, stdout, stderr := h.run("", "export", "TOKEN")
	if code == 0 {
		t.Fatalf("export printed to a pipe: %s", stdout)
	}
	if strings.Contains(stdout+stderr, "the-value") {
		t.Error("the refusal itself leaked the value")
	}
	if !strings.Contains(stderr, "--force") || !strings.Contains(stderr, "env") {
		t.Errorf("refusal %q does not offer --force or point at env", stderr)
	}
}

// Single-quoted, in declaration order: a sourcing shell, python-dotenv, node
// dotenv and compose all read the quoted text literally.
func TestExportPrintsEveryVariableAsKeyValue(t *testing.T) {
	h := newHarness(t)
	h.mustRun(`a=b$c "d" #e`, "add", "cdp-es",
		"--var", "ES_ENDPOINT=https://logs.internal:9200", "--secret", "ES_API_KEY")

	got := h.mustRun("", "export", "cdp-es", "--force")
	want := "ES_ENDPOINT='https://logs.internal:9200'\nES_API_KEY='a=b$c \"d\" #e'\n"
	if got != want {
		t.Errorf("export = %q, want %q", got, want)
	}

	if log := h.mustRun("", "audit"); !strings.Contains(log, "export") {
		t.Errorf("audit does not record the export: %s", log)
	}
}

// sourcingShells read env files with `set -a; . ./.env`; fish cannot.
var sourcingShells = []string{"sh", "dash", "bash", "zsh"}

// Sourcing executes the file, so a value must arrive as itself and run nothing.
func TestExportedFileIsInertWhenSourced(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "pwned")
	values := map[string]string{
		"command substitution": "x$(touch " + marker + ")",
		"backtick":             "x`touch " + marker + "`",
		"separator":            "x; touch " + marker,
		"expansion":            "$HOME ${PATH}",
		"comment":              "a #b",
		"backslash":            `back\slash\\`,
		"double quote":         `say "hi"`,
	}

	for label, value := range values {
		t.Run(label, func(t *testing.T) {
			h := newHarness(t)
			h.mustRun(value, "add", "TOKEN")
			file := filepath.Join(t.TempDir(), ".env")
			writeFile(t, file, h.mustRun("", "export", "TOKEN", "--force"))

			forEachShell(t, sourcingShells, func(t *testing.T, shell string) {
				script := "set -a; . '" + file + "'; printf '%s' \"$TOKEN\""
				out, err := exec.Command(shell, "-c", script).Output()
				if err != nil {
					t.Fatalf("%s could not source the export: %v", shell, err)
				}
				if string(out) != value {
					t.Errorf("%s sourced %q, want %q", shell, out, value)
				}
				// Removed on detection, so each shell is judged on its own.
				if err := os.Remove(marker); err == nil {
					t.Errorf("sourcing under %s executed part of the value", shell)
				}
			})
		})
	}
}

// No escape for ' reads the same in shells and every dotenv parser, so the
// quoted format refuses it rather than emit something one of them misreads.
func TestExportRefusesASingleQuote(t *testing.T) {
	h := newHarness(t)
	h.mustRun("it's-extremely-secret", "add", "pair", "--var", "FIRST=ok", "--secret", "KEY")

	code, stdout, stderr := h.run("", "export", "pair", "--force")
	if code == 0 {
		t.Fatalf("export emitted a value containing ': %q", stdout)
	}
	if stdout != "" {
		t.Errorf("export wrote %q before refusing; a partial file is still a file", stdout)
	}
	if strings.Contains(stderr, "extremely-secret") {
		t.Errorf("error %q leaked the value", stderr)
	}
	for _, want := range []string{"pair.KEY", "--raw", "env"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("error %q does not mention %s", stderr, want)
		}
	}
}

// --raw is for `docker run --env-file`, which keeps quotes as part of the value
// and takes everything after the first = literally.
func TestExportRawPrintsTheExactBytes(t *testing.T) {
	h := newHarness(t)
	h.mustRun(`a=b$c 'd' #e`, "add", "cdp-es",
		"--var", "ES_ENDPOINT=https://logs.internal:9200", "--secret", "ES_API_KEY")

	got := h.mustRun("", "export", "cdp-es", "--force", "--raw")
	want := "ES_ENDPOINT=https://logs.internal:9200\nES_API_KEY=a=b$c 'd' #e\n"
	if got != want {
		t.Errorf("export --raw = %q, want %q", got, want)
	}
}

// A line break would end the value early and start a line of the attacker's
// choosing, e.g. one that sets LD_PRELOAD.
func TestExportRefusesALineBreakInAValue(t *testing.T) {
	for label, value := range map[string]string{
		"newline":         "x\nLD_PRELOAD=/tmp/evil.so",
		"carriage return": "x\rLD_PRELOAD=/tmp/evil.so",
	} {
		t.Run(label, func(t *testing.T) {
			h := newHarness(t)
			h.mustRun("public", "add", "pair", "--var", "FIRST=ok", "--secret", "KEY")
			h.mustRun(value, "edit", "pair", "--set", "KEY")

			// Quoting does not help: dotenv parsers disagree on multi-line values.
			for _, mode := range [][]string{{"--force"}, {"--force", "--raw"}} {
				code, stdout, stderr := h.run("", append([]string{"export", "pair"}, mode...)...)
				if code == 0 {
					t.Fatalf("export %v emitted a value with a line break: %q", mode, stdout)
				}
				if stdout != "" {
					t.Errorf("export %v wrote %q before refusing; a partial file is still a file", mode, stdout)
				}
				if !strings.Contains(stderr, "pair.KEY") {
					t.Errorf("export %v error %q does not name the variable", mode, stderr)
				}
				if strings.Contains(stderr, "evil") {
					t.Errorf("export %v error %q leaked the value", mode, stderr)
				}
			}
		})
	}
}
