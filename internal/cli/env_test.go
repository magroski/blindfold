package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/magroski/blindfold/internal/vault"
)

// harness drives commands against a throwaway vault, exactly as main does.
type harness struct {
	t   *testing.T
	dir string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("BLINDFOLD_DIR", dir)
	t.Setenv("BLINDFOLD_KEK_FILE", filepath.Join(t.TempDir(), "kek"))
	t.Setenv("BLINDFOLD_PASSPHRASE", "")

	h := &harness{t: t, dir: dir}
	if code, _, stderr := h.run("", "init"); code != 0 {
		t.Fatalf("init failed: %s", stderr)
	}
	return h
}

// run executes one command with stdin, returning the exit code and both streams.
// stdout is a buffer rather than a file, so the terminal guards see a pipe —
// which is what an agent's shell looks like.
func (h *harness) run(stdin string, args ...string) (int, string, string) {
	h.t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), Env{
		Stdin:   strings.NewReader(stdin),
		Stdout:  &stdout,
		Stderr:  &stderr,
		Version: "test",
	}, args)
	return code, stdout.String(), stderr.String()
}

// mustRun fails the test if the command did not succeed.
func (h *harness) mustRun(stdin string, args ...string) string {
	h.t.Helper()
	code, stdout, stderr := h.run(stdin, args...)
	if code != 0 {
		h.t.Fatalf("%v exited %d: %s", args, code, stderr)
	}
	return stdout
}

// evalAndEcho runs the emitted shell in a real /bin/sh and prints back one
// variable, which is the only honest way to test that quoting holds.
func evalAndEcho(t *testing.T, exports, varName string) string {
	t.Helper()
	return evalIn(t, "/bin/sh", exports, varName)
}

// evalShells are the shells the README's eval "$(blindfold env x)" works in.
// They disagree on quoting: fish, unlike POSIX, honours \' inside '...'.
var evalShells = []string{"sh", "dash", "bash", "zsh", "fish"}

// forEachShell runs fn as a subtest under each of shells installed here.
func forEachShell(t *testing.T, shells []string, fn func(t *testing.T, shell string)) {
	t.Helper()
	for _, name := range shells {
		t.Run(name, func(t *testing.T) {
			path, err := exec.LookPath(name)
			// CI installs every shell: a skip there would leave a quoting rule
			// unchecked in the release gate.
			if err != nil && os.Getenv("CI") != "" {
				t.Fatalf("%s is not installed, and CI must test every shell", name)
			}
			if err != nil {
				t.Skipf("%s is not installed", name)
			}
			fn(t, path)
		})
	}
}

// evalIn evaluates the exports in shell the way the README does, then prints
// back one variable. The text is valid fish too, which has $(...) since 3.4.
// It runs in an empty directory, so a stray `touch ./x` litters nothing.
func evalIn(t *testing.T, shell, exports, varName string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "exports")
	writeFile(t, file, exports)

	script := `eval "$(cat '` + file + `')"` + "\nprintf '%s' \"$" + varName + "\""
	cmd := exec.Command(shell, "-c", script)
	cmd.Dir = t.TempDir()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s rejected the emitted exports: %v\n%s\n%s", shell, err, stderr.String(), exports)
	}
	return string(out)
}

// The value goes into a string a shell will execute. Anything that survives
// quoting incorrectly is either a corrupted credential or arbitrary code.
func TestEnvQuotingSurvivesARealShell(t *testing.T) {
	nasty := map[string]string{
		"plain":           "hunter2",
		"single quote":    `it's-a-secret`,
		"quote and semi":  `x'; touch ./pwned; echo '`,
		"double quote":    `say "hello"`,
		"dollar":          `$HOME and ${PATH} and $(id)`,
		"backtick":        "`id`",
		"backslash":       `back\slash\\double`,
		"newline":         "line one\nline two",
		"bang":            "history!expansion!",
		"ampersand":       "a && b || c ; d | e",
		"redirect":        "> /etc/passwd < /dev/zero",
		"glob":            "*?[a-z]",
		"unicode":         "pÄssword-ünïcode-🔑",
		"leading hyphen":  "--not-a-flag",
		"whitespace only": "   \t  ",
		// fish reads \' and \\ inside single quotes as escapes.
		"fish quote escape":  `\'; touch ./pwned; #`,
		"escaped quotes":     `\'\'`,
		"trailing backslash": `x\`,
		"backslash pair":     `a\\b`,
	}

	for label, value := range nasty {
		t.Run(label, func(t *testing.T) {
			h := newHarness(t)
			h.mustRun(value, "add", "TEST_SECRET")
			exports := h.mustRun("", "env", "TEST_SECRET")

			forEachShell(t, evalShells, func(t *testing.T, shell string) {
				if got := evalIn(t, shell, exports, "TEST_SECRET"); got != value {
					t.Errorf("value round-tripped through %s as %q, want %q\nexports: %s",
						shell, got, value, exports)
				}
			})
		})
	}
}

// The escape that matters most, checked against the file system rather than the
// variable: a crafted value must not be able to run a command.
func TestEnvValueCannotExecuteCommands(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "pwned")
	attacks := map[string]string{
		"posix breakout": `'; touch ` + marker + `; echo '`,
		// Under fish, the POSIX escape '\'' leaves the quote open, not closed.
		"fish breakout": `\'; touch ` + marker + `; #`,
	}

	for label, attack := range attacks {
		t.Run(label, func(t *testing.T) {
			h := newHarness(t)
			h.mustRun(attack, "add", "TEST_SECRET")
			exports := h.mustRun("", "env", "TEST_SECRET")

			forEachShell(t, evalShells, func(t *testing.T, shell string) {
				evalIn(t, shell, exports, "TEST_SECRET")
				// Removed on detection, so each shell is judged on its own.
				if err := os.Remove(marker); err == nil {
					t.Errorf("under %s the value escaped its quotes and executed a command", shell)
				}
			})
		})
	}
}

// A variable name cannot be quoted, so it must be rejected before it is stored.
func TestAddRejectsUnusableVariableNames(t *testing.T) {
	h := newHarness(t)
	for _, name := range []string{"BAD NAME", "x;id", "1DIGIT", "a-b", "$(id)"} {
		code, _, stderr := h.run("value", "add", "entry-"+"x", "--secret", name)
		if code == 0 {
			t.Errorf("add accepted the variable name %q", name)
		}
		if !strings.Contains(stderr, "environment variable name") {
			t.Errorf("add %q said %q, want an explanation of what a name may contain", name, stderr)
		}
	}
}

func TestEnvExportsEveryVariableOfABundle(t *testing.T) {
	h := newHarness(t)
	h.mustRun("secret-key", "add", "cdp-es",
		"--var", "ES_ENDPOINT=https://logs.internal:9200", "--secret", "ES_API_KEY")

	exports := h.mustRun("", "env", "cdp-es")
	if got := evalAndEcho(t, exports, "ES_API_KEY"); got != "secret-key" {
		t.Errorf("ES_API_KEY = %q", got)
	}
	if got := evalAndEcho(t, exports, "ES_ENDPOINT"); got != "https://logs.internal:9200" {
		t.Errorf("ES_ENDPOINT = %q", got)
	}
}

func TestEnvSetRenamesAndSelects(t *testing.T) {
	h := newHarness(t)
	h.mustRun("dsn-value", "add", "pg-ro", "--secret", "DATABASE_URL")
	h.mustRun("secret-key", "add", "cdp-es",
		"--var", "ES_ENDPOINT=https://logs.internal:9200", "--secret", "ES_API_KEY")

	// Unqualified: the entry's only secret.
	exports := h.mustRun("", "env", "--set", "PGURL=pg-ro")
	if got := evalAndEcho(t, exports, "PGURL"); got != "dsn-value" {
		t.Errorf("PGURL = %q, want dsn-value", got)
	}

	// Qualified: a named variable within a bundle.
	exports = h.mustRun("", "env", "--set", "KEY=cdp-es.ES_API_KEY")
	if got := evalAndEcho(t, exports, "KEY"); got != "secret-key" {
		t.Errorf("KEY = %q, want secret-key", got)
	}
	if strings.Contains(exports, "ES_ENDPOINT") {
		t.Errorf("--set exported more than the variable asked for: %s", exports)
	}
}

// An entry exporting several variables cannot answer "which one" on its own.
func TestEnvSetRefusesToGuessWithinABundle(t *testing.T) {
	h := newHarness(t)
	h.mustRun("k", "add", "pair", "--var", "A=1", "--secret", "B")
	h.mustRun("k2", "add", "trio", "--secret", "C")

	// Two secrets is genuinely ambiguous.
	h.mustRun("k3", "edit", "trio", "--set", "D")
	code, _, stderr := h.run("", "env", "--set", "X=trio")
	if code == 0 {
		t.Fatal("--set picked one of two secrets instead of asking")
	}
	if !strings.Contains(stderr, "trio.C") {
		t.Errorf("error %q does not show how to name a variable", stderr)
	}

	// One secret among public variables is not ambiguous.
	if _, _, stderr := h.run("", "env", "--set", "X=pair"); strings.Contains(stderr, "cannot tell") {
		t.Errorf("--set refused an unambiguous entry: %s", stderr)
	}
}

// Two credentials silently competing for one variable name would connect a
// command to something other than what the caller named.
func TestEnvRefusesConflictingVariableNames(t *testing.T) {
	h := newHarness(t)
	h.mustRun("first", "add", "one", "--secret", "SHARED_NAME")
	h.mustRun("second", "add", "two", "--secret", "SHARED_NAME")

	code, stdout, stderr := h.run("", "env", "one", "two")
	if code == 0 {
		t.Fatalf("env exported a conflict silently: %s", stdout)
	}
	if !strings.Contains(stderr, "SHARED_NAME would be set twice") {
		t.Errorf("error = %q, want it to name the conflicting variable", stderr)
	}
}

// The same value from two sources is not a conflict.
func TestEnvAllowsHarmlessDuplicates(t *testing.T) {
	h := newHarness(t)
	h.mustRun("v", "add", "one", "--secret", "TOKEN")
	h.mustRun("", "env", "one", "one")
}

func TestEnvByTag(t *testing.T) {
	h := newHarness(t)
	h.mustRun("a", "add", "one", "--secret", "FIRST", "--tags", "cdp")
	h.mustRun("b", "add", "two", "--secret", "SECOND", "--tags", "cdp,other")
	h.mustRun("c", "add", "three", "--secret", "THIRD", "--tags", "unrelated")

	exports := h.mustRun("", "env", "--tag", "cdp")
	for _, want := range []string{"FIRST", "SECOND"} {
		if !strings.Contains(exports, want) {
			t.Errorf("--tag cdp did not export %s: %s", want, exports)
		}
	}
	if strings.Contains(exports, "THIRD") {
		t.Errorf("--tag cdp exported an untagged credential: %s", exports)
	}

	if code, _, stderr := h.run("", "env", "--tag", "nobody"); code == 0 {
		t.Error("an empty tag selection succeeded silently")
	} else if !strings.Contains(stderr, "nobody") {
		t.Errorf("error = %q, want the tag named", stderr)
	}
}

// The stderr summary is what the agent sees; it must confirm the load without
// containing any part of the value.
func TestEnvSummaryNamesVariablesButNotValues(t *testing.T) {
	h := newHarness(t)
	const value = "extremely-secret-value"
	h.mustRun(value, "add", "cdp-es", "--var", "ES_ENDPOINT=https://x", "--secret", "ES_API_KEY")

	_, stdout, stderr := h.run("", "env", "cdp-es")
	if !strings.Contains(stderr, "ES_API_KEY") || !strings.Contains(stderr, "ES_ENDPOINT") {
		t.Errorf("summary %q does not name the exported variables", stderr)
	}
	if strings.Contains(stderr, value) {
		t.Errorf("summary %q contains the secret value", stderr)
	}
	if !strings.Contains(stdout, value) {
		t.Error("stdout does not carry the value; nothing would be exported")
	}
}

func TestEnvUnknownNameListsWhatExists(t *testing.T) {
	h := newHarness(t)
	h.mustRun("v", "add", "cdp-es", "--secret", "ES_API_KEY")

	code, _, stderr := h.run("", "env", "cdp-e")
	if code == 0 {
		t.Fatal("env succeeded for a name that does not exist")
	}
	if !strings.Contains(stderr, "cdp-es") {
		t.Errorf("error %q does not list what is available", stderr)
	}
}

// `get` prints a bare value, which inside an agent's shell means a value in the
// transcript. `env` is the path that exists for that.
func TestGetRefusesAPipeWithoutForce(t *testing.T) {
	h := newHarness(t)
	h.mustRun("the-value", "add", "TOKEN")

	code, stdout, stderr := h.run("", "get", "TOKEN")
	if code == 0 {
		t.Fatalf("get printed to a pipe: %s", stdout)
	}
	if strings.Contains(stdout+stderr, "the-value") {
		t.Error("the refusal itself leaked the value")
	}
	if !strings.Contains(stderr, "env") {
		t.Errorf("refusal %q does not point at the command that does work here", stderr)
	}

	if out := h.mustRun("", "get", "TOKEN", "--force"); strings.TrimSpace(out) != "the-value" {
		t.Errorf("get --force = %q", out)
	}
}

func TestAddRefusesDuplicateName(t *testing.T) {
	h := newHarness(t)
	h.mustRun("v", "add", "TOKEN")

	code, _, stderr := h.run("other", "add", "TOKEN")
	if code == 0 {
		t.Fatal("add overwrote an existing credential")
	}
	if !strings.Contains(stderr, "edit") {
		t.Errorf("error %q does not say how to change it instead", stderr)
	}
}

// Reading two secrets from one pipe would hand the whole stream to the first.
func TestAddRefusesTwoPipedSecrets(t *testing.T) {
	h := newHarness(t)
	code, _, stderr := h.run("value", "add", "pair", "--secret", "A", "--secret", "B")
	if code == 0 {
		t.Fatal("add read two secrets from one pipe")
	}
	if !strings.Contains(stderr, "--from-file") {
		t.Errorf("error %q does not suggest the way that works", stderr)
	}
}

func TestEditRotatesAndRemoves(t *testing.T) {
	h := newHarness(t)
	h.mustRun("old", "add", "cdp-es", "--var", "ES_ENDPOINT=https://old", "--secret", "ES_API_KEY")

	h.mustRun("new", "edit", "cdp-es", "--set", "ES_API_KEY")
	exports := h.mustRun("", "env", "cdp-es")
	if got := evalAndEcho(t, exports, "ES_API_KEY"); got != "new" {
		t.Errorf("after rotation ES_API_KEY = %q, want new", got)
	}

	h.mustRun("", "edit", "cdp-es", "--var", "ES_ENDPOINT=https://new")
	exports = h.mustRun("", "env", "cdp-es")
	if got := evalAndEcho(t, exports, "ES_ENDPOINT"); got != "https://new" {
		t.Errorf("ES_ENDPOINT = %q, want the updated URL", got)
	}

	h.mustRun("", "edit", "cdp-es", "--rm-var", "ES_ENDPOINT")
	exports = h.mustRun("", "env", "cdp-es")
	if strings.Contains(exports, "ES_ENDPOINT") {
		t.Errorf("removed variable is still exported: %s", exports)
	}
}

func TestEditWithNoFlagsChangesNothing(t *testing.T) {
	h := newHarness(t)
	h.mustRun("v", "add", "TOKEN")
	if code, _, _ := h.run("", "edit", "TOKEN"); code == 0 {
		t.Error("edit with no flags reported success")
	}
}

func TestImportKeepsPublicVariablesInTheClear(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(t.TempDir(), ".env")
	writeFile(t, path, "# a comment\nexport ES_ENDPOINT=https://logs.internal:9200\nES_API_KEY='sealed-value'\n\n")

	h.mustRun("", "import", path, "--as", "cdp", "--public", "ES_ENDPOINT")

	listing := h.mustRun("", "ls")
	if !strings.Contains(listing, "ES_API_KEY*") {
		t.Errorf("listing does not mark ES_API_KEY as sealed: %s", listing)
	}
	if !strings.Contains(listing, "ES_ENDPOINT") || strings.Contains(listing, "ES_ENDPOINT*") {
		t.Errorf("ES_ENDPOINT should be public: %s", listing)
	}

	exports := h.mustRun("", "env", "cdp")
	if got := evalAndEcho(t, exports, "ES_API_KEY"); got != "sealed-value" {
		t.Errorf("ES_API_KEY = %q; quotes should have been stripped", got)
	}
}

// A listing is what an agent reads to decide what to use, and gets pasted into
// issues. It must carry names, not values.
func TestListShowsNoSealedValues(t *testing.T) {
	h := newHarness(t)
	const value = "extremely-secret-value"
	h.mustRun(value, "add", "cdp-es", "--secret", "ES_API_KEY", "--describe", "the cluster")

	for _, args := range [][]string{{"ls"}, {"ls", "--json"}, {"show", "cdp-es"}, {"show", "cdp-es", "--json"}} {
		out := h.mustRun("", args...)
		if strings.Contains(out, value) {
			t.Errorf("%v printed the sealed value", args)
		}
		if !strings.Contains(out, "ES_API_KEY") {
			t.Errorf("%v does not name the variable", args)
		}
	}
}

func TestAuditRecordsAccessWithoutValues(t *testing.T) {
	h := newHarness(t)
	const value = "extremely-secret-value"
	h.mustRun(value, "add", "cdp-es", "--secret", "ES_API_KEY")
	h.mustRun("", "env", "cdp-es")

	log := h.mustRun("", "audit")
	if !strings.Contains(log, "cdp-es") || !strings.Contains(log, "env") {
		t.Errorf("audit does not record the access: %s", log)
	}
	if strings.Contains(log, value) {
		t.Error("audit log contains the value")
	}
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

// An audit row must say how a value left: --force means it may have gone into
// a pipe or a transcript, not onto the owner's screen.
func TestForcedGetIsAuditedAsForced(t *testing.T) {
	h := newHarness(t)
	h.mustRun("the-value", "add", "TOKEN")
	h.mustRun("", "get", "TOKEN", "--force")

	if log := h.mustRun("", "audit"); !strings.Contains(log, "--force") {
		t.Errorf("audit does not record that get was forced: %s", log)
	}
}

// A .env that fails to parse is a file of secrets; the error must say where,
// never what. This parser does not support multi-line values, so a PEM key
// would otherwise be echoed one body line at a time.
func TestImportNeverEchoesTheFile(t *testing.T) {
	const needle = "MIIEowIBAAKCAQEAsuperSECRETkeyMATERIAL"
	files := []struct{ label, contents, line string }{
		{"quoted multi-line value",
			"PRIVATE_KEY=\"-----BEGIN RSA PRIVATE KEY-----\n" + needle + "\n-----END RSA PRIVATE KEY-----\"\n", "line 1"},
		{"bare continuation line", "PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\n" + needle + "\n", "line 2"},
		{"unusable key", needle + " more=1\n", "line 1"},
	}
	for _, file := range files {
		t.Run(file.label, func(t *testing.T) {
			h := newHarness(t)
			path := filepath.Join(t.TempDir(), ".env")
			writeFile(t, path, file.contents)

			code, stdout, stderr := h.run("", "import", path, "--as", "svc")
			if code == 0 {
				t.Fatal("import accepted a file it cannot parse")
			}
			if strings.Contains(stdout+stderr, needle) {
				t.Errorf("the error echoes the file: %s", stderr)
			}
			if !strings.Contains(stderr, file.line) {
				t.Errorf("the error does not point at %s: %s", file.line, stderr)
			}
			if listing := h.mustRun("", "ls"); strings.Contains(listing, needle) {
				t.Errorf("part of the file was stored as metadata: %s", listing)
			}
		})
	}
}

// Public values sit in cleartext metadata, which needs no key to edit. An
// endpoint rewritten there must not still unseal the API key that would be
// sent to it.
func TestEnvRefusesHandEditedMetadata(t *testing.T) {
	h := newHarness(t)
	h.mustRun("the-key", "add", "cdp-es", "--var", "ES_ENDPOINT=https://logs.internal", "--secret", "ES_API_KEY")

	path := filepath.Join(h.dir, vault.MetadataFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(data), "https://logs.internal", "https://attacker.example", 1)
	if edited == string(data) {
		t.Fatal("metadata does not hold the endpoint in the clear")
	}
	writeFile(t, path, edited)

	code, stdout, stderr := h.run("", "env", "cdp-es")
	if code == 0 {
		t.Fatal("env unsealed a credential whose metadata was edited by hand")
	}
	if strings.Contains(stdout, "the-key") || strings.Contains(stdout, "attacker") {
		t.Errorf("env printed exports anyway: %s", stdout)
	}
	if !strings.Contains(stderr, "edited") {
		t.Errorf("error does not name the cause: %s", stderr)
	}
}

// A listing is what an agent reads to choose a credential. Free text that can
// break a line could forge a row of it.
func TestAddRejectsControlCharactersInFreeText(t *testing.T) {
	forged := "staging only\nprod-db  DATABASE_URL*  production primary"
	for _, args := range [][]string{
		{"add", "staging-db", "--var", "DB_HOST=staging", "--describe", forged},
		{"add", "staging-db", "--var", "DB_HOST=staging", "--tags", "a,b\x1b[31m"},
	} {
		h := newHarness(t)
		if code, _, _ := h.run("", args...); code == 0 {
			t.Errorf("%q accepted a control character", args)
		}
		if listing := h.mustRun("", "ls"); strings.Contains(listing, "prod-db") || strings.Contains(listing, "\x1b") {
			t.Errorf("listing carries the forged text: %q", listing)
		}
	}

	h := newHarness(t)
	h.mustRun("", "add", "staging-db", "--var", "DB_HOST=staging")
	if code, _, _ := h.run("", "edit", "staging-db", "--describe", forged); code == 0 {
		t.Error("edit accepted a control character in the description")
	}
}

// Public values are not free text, so a newline is allowed in one — but
// nothing a listing prints may drive the terminal or forge a row, including
// metadata edited by hand, which no input check sees.
func TestListingsNeutralizeControlCharacters(t *testing.T) {
	h := newHarness(t)
	const osc52 = "https://x\x1b]52;c;ZXZpbA==\x07"
	h.mustRun("", "add", "cdp-es", "--var", "ES_ENDPOINT="+osc52, "--describe", "PLACEHOLDER")

	path := filepath.Join(h.dir, vault.MetadataFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, strings.Replace(string(data), "PLACEHOLDER",
		`\u001b[2J\nprod-db  DATABASE_URL*  production primary`, 1))

	for _, args := range [][]string{{"show", "cdp-es"}, {"ls"}} {
		out := h.mustRun("", args...)
		if strings.ContainsAny(out, "\x1b\x07") {
			t.Errorf("%v printed a control character: %q", args, out)
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "prod-db") {
				t.Errorf("%v printed a forged row: %q", args, out)
			}
		}
	}
}

// An entry name is unambiguous on a command line only if it cannot be read as
// a flag.
func TestAddRejectsEntryNamesThatLookLikeFlags(t *testing.T) {
	h := newHarness(t)
	if code, _, _ := h.run("v", "add", "--secret", "V", "--", "-force"); code == 0 {
		t.Error("add accepted an entry named -force")
	}
}

// Variable names never contain a dot, so in --set VAR=entry.VAR the entry is
// everything before the last one — and an entry named with a dot is still
// reachable on its own.
func TestEnvSetResolvesDottedEntryNames(t *testing.T) {
	h := newHarness(t)
	h.mustRun("postgres://primary", "add", "prod.db", "--secret", "DATABASE_URL")

	for _, set := range []string{"URL=prod.db", "URL=prod.db.DATABASE_URL"} {
		if got := evalAndEcho(t, h.mustRun("", "env", "--set", set, "--quiet"), "URL"); got != "postgres://primary" {
			t.Errorf("--set %s gave %q", set, got)
		}
	}

	// "prod.db" now also reads as variable db of entry prod: refuse to guess.
	h.mustRun("", "add", "prod", "--var", "db=replica")
	if code, stdout, _ := h.run("", "env", "--set", "URL=prod.db"); code == 0 {
		t.Errorf("an ambiguous --set was resolved: %s", stdout)
	}
}

// An entry added to vault.json by hand was never bound to the master key, so
// nothing vouches for it. Joining a load beside a sealed value, HTTPS_PROXY
// would send the API key through whoever wrote it.
func TestLoadsRefuseEntriesAddedByHand(t *testing.T) {
	h := newHarness(t)
	h.mustRun("the-key", "add", "cdp-es", "--var", "ES_ENDPOINT=https://logs.internal",
		"--secret", "ES_API_KEY", "--tags", "cdp")

	path := filepath.Join(h.dir, vault.MetadataFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var meta vault.Metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatal(err)
	}
	meta.Entries = append(meta.Entries, vault.Entry{
		Name: "zz-proxy", Tags: []string{"cdp"},
		Vars: []vault.Var{{Name: "HTTPS_PROXY", Value: "http://attacker.example:8080"}},
	})
	if data, err = json.Marshal(meta); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(data))

	for _, args := range [][]string{
		{"env", "--tag", "cdp"}, {"env", "cdp-es", "zz-proxy"}, {"env", "zz-proxy"},
		{"env", "cdp-es", "--set", "HTTPS_PROXY=zz-proxy"},
	} {
		code, stdout, _ := h.run("", args...)
		if code == 0 || strings.Contains(stdout, "attacker") {
			t.Errorf("%v loaded an entry added by hand (exit %d): %s", args, code, stdout)
		}
	}
}
