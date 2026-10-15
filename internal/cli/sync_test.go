package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	boxSecret   = "box-api-key-never-in-the-clear"
	localSecret = "local-api-key-never-in-the-clear"
)

// box is a dev box for tests: its own vault and master key, reached through
// a fake ssh that runs this test binary as `blindfold sync-serve` there.
type box struct {
	t   *testing.T
	dir string
	kek string
}

// sshWorld puts a fake ssh first on PATH. It records every argv and every byte
// both ways, and routes destination <d> to the box registered under <d>.
// A remote command starting with "missing " fails as a shell would; one
// starting with "future " is a blindfold that speaks another protocol; one
// starting with "noisy " writes terminal control sequences to stderr; one
// starting with "cut " hangs up once the first request arrives. An unregistered destination
// fails as ssh would, so no test reaches the real ~/.blindfold.
type sshWorld struct {
	argv string // file: every ssh argument, one per line
	wire string // file: every byte between the two blindfolds
}

func newSSHWorld(t *testing.T) *sshWorld {
	t.Helper()
	dir := t.TempDir()
	w := &sshWorld{argv: filepath.Join(dir, "argv"), wire: filepath.Join(dir, "wire")}
	// sshd passes no agent markers to the box, so neither does this.
	script := `#!/bin/sh
unset CLAUDECODE CODEX_SANDBOX CODEX_SANDBOX_NETWORK_DISABLED
printf '%s\n' "$@" >> "` + w.argv + `"
dest=$7
case "$8" in
  missing\ *) echo "sh: missing: command not found" >&2; exit 127;;
  future\ *) read -r _; printf '%s\n' '{"proto":99,"version":"v9\u001b]0;owned\u0007","pub":"AAAA"}'; exit 1;;
  noisy\ *) printf 'motd \033]0;owned\007\033[31m\n' >&2; exit 1;;
  cut\ *) read -r _; printf '%s\n' '{"proto":1,"version":"cut","pub":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="}'
    read -r _; exit 1;;
esac
case "$dest" in *[!A-Za-z0-9_]* | '') dir= ;; *) eval "dir=\$BOX_DIR_$dest kek=\$BOX_KEK_$dest" ;; esac
if [ -z "$dir" ]; then echo "ssh: Could not resolve hostname $dest" >&2; exit 255; fi
tee -a "` + w.wire + `" | BLINDFOLD_DIR="$dir" BLINDFOLD_KEK_FILE="$kek" ` + helperEnv + `=1 \
  "` + os.Args[0] + `" -test.run='^TestExecHelperProcess$' -- sync-serve | tee -a "` + w.wire + `"
`
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return w
}

// newBox creates and initializes a box reachable as destination name.
func (w *sshWorld) newBox(t *testing.T, name string) *box {
	t.Helper()
	dir := t.TempDir()
	b := &box{t: t, dir: filepath.Join(dir, "vault"), kek: filepath.Join(dir, "kek")}
	t.Setenv("BOX_DIR_"+name, b.dir)
	t.Setenv("BOX_KEK_"+name, b.kek)
	b.mustRun("", "init")
	return b
}

// run executes blindfold on the box, as its own process with its own vault.
func (b *box) run(stdin string, args ...string) (string, error) {
	b.t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestExecHelperProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), helperEnv+"=1", "BLINDFOLD_DIR="+b.dir, "BLINDFOLD_KEK_FILE="+b.kek)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (b *box) mustRun(stdin string, args ...string) string {
	b.t.Helper()
	out, err := b.run(stdin, args...)
	if err != nil {
		b.t.Fatalf("on the box, %v: %v\n%s", args, err, out)
	}
	return out
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(data)
}

func TestPushAndPullBetweenBoxes(t *testing.T) {
	h := newHarness(t)
	world := newSSHWorld(t)
	mac := world.newBox(t, "mac")
	h.mustRun(localSecret, "add", "cdp-es", "--secret", "ES_API_KEY",
		"--var", "ES_ENDPOINT=https://logs.internal", "--describe", "candidate cluster", "--tags", "search-team")
	h.mustRun("", "remote", "add", "mac-box", "mac")

	if out := h.mustRun("", "push", "mac-box", "cdp-es"); !strings.Contains(out, "created") {
		t.Errorf("push said %q", out)
	}
	if got := mac.mustRun("", "get", "cdp-es", "--var", "ES_API_KEY", "--force"); strings.TrimSpace(got) != localSecret {
		t.Errorf("the box holds %q", got)
	}
	shown := mac.mustRun("", "show", "cdp-es")
	for _, want := range []string{"candidate cluster", "search-team", "https://logs.internal"} {
		if !strings.Contains(shown, want) {
			t.Errorf("%q did not travel: %s", want, shown)
		}
	}

	// Several secrets in one entry all arrive.
	dotenv := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(dotenv, []byte("BOX_TOKEN="+boxSecret+"\nBOX_SIGNING_KEY="+localSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mac.mustRun("", "add", "box-pair", "--from-file", dotenv)
	// The output names every variable stored, so a planted one is seen.
	if out := h.mustRun("", "pull", "mac-box", "box-pair"); !strings.Contains(out, "created: BOX_TOKEN, BOX_SIGNING_KEY") {
		t.Errorf("pull said %q", out)
	}
	for variable, want := range map[string]string{"BOX_TOKEN": boxSecret, "BOX_SIGNING_KEY": localSecret} {
		if got := h.mustRun("", "get", "box-pair", "--var", variable, "--force"); strings.TrimSpace(got) != want {
			t.Errorf("pulled %s = %q", variable, got)
		}
	}
}

func TestPushRefusesConflict(t *testing.T) {
	h := newHarness(t)
	world := newSSHWorld(t)
	mac := world.newBox(t, "mac")
	h.mustRun("rotated", "add", "API_KEY")
	mac.mustRun("stale", "add", "API_KEY")
	h.mustRun("", "remote", "add", "mac-box", "mac")

	code, stdout, stderr := h.run("", "push", "mac-box", "API_KEY")
	if code == 0 || !strings.Contains(stdout+stderr, "--overwrite") {
		t.Errorf("push onto a differing entry exited %d: %s%s", code, stdout, stderr)
	}
	if got := mac.mustRun("", "get", "API_KEY", "--force"); strings.TrimSpace(got) != "stale" {
		t.Errorf("the box's entry was replaced: %q", got)
	}

	if out := h.mustRun("", "push", "mac-box", "API_KEY", "--overwrite"); !strings.Contains(out, "updated") {
		t.Errorf("push --overwrite said %q", out)
	}
	if got := mac.mustRun("", "get", "API_KEY", "--force"); strings.TrimSpace(got) != "rotated" {
		t.Errorf("the box holds %q after --overwrite", got)
	}
}

func TestSyncStatus(t *testing.T) {
	h := newHarness(t)
	world := newSSHWorld(t)
	mac := world.newBox(t, "mac")
	linux := world.newBox(t, "linux")
	h.mustRun("same", "add", "SAME")
	h.mustRun("here", "add", "DIFFERS")
	h.mustRun("only", "add", "ONLY_HERE")
	mac.mustRun("same", "add", "SAME")
	mac.mustRun("there", "add", "DIFFERS")
	linux.mustRun("x", "add", "ONLY_LINUX")
	h.mustRun("", "remote", "add", "mac-box", "mac")
	h.mustRun("", "remote", "add", "linux-box", "linux")

	out := h.mustRun("", "sync")
	rows := map[string][]string{}
	for _, line := range strings.Split(out, "\n") {
		if fields := strings.Fields(line); len(fields) >= 5 {
			rows[fields[1]] = fields[2:5] // here, linux-box, mac-box
		}
	}
	want := map[string][]string{
		"SAME":       {"●", "—", "●"},
		"DIFFERS":    {"●", "—", "≠"},
		"ONLY_HERE":  {"●", "—", "—"},
		"ONLY_LINUX": {"—", "●", "—"},
	}
	for name, cells := range want {
		if strings.Join(rows[name], " ") != strings.Join(cells, " ") {
			t.Errorf("%s = %v, want %v\n%s", name, rows[name], cells, out)
		}
	}
}

// One run of every command that moves or compares values, then a search for
// both values in everything a person or an agent could read.
func TestSyncNeverExposesValues(t *testing.T) {
	h := newHarness(t)
	world := newSSHWorld(t)
	mac := world.newBox(t, "mac")
	h.mustRun(localSecret, "add", "LOCAL_KEY")
	mac.mustRun(boxSecret, "add", "BOX_KEY")
	h.mustRun("", "remote", "add", "mac-box", "mac")

	var outputs strings.Builder
	for _, args := range [][]string{
		{"sync"}, {"push", "mac-box", "LOCAL_KEY"}, {"pull", "mac-box", "BOX_KEY"}, {"sync"},
	} {
		code, stdout, stderr := h.run("", args...)
		if code != 0 { // a failed transfer would prove nothing
			t.Fatalf("%v exited %d: %s%s", args, code, stdout, stderr)
		}
		outputs.WriteString(stdout + stderr)
	}

	readable := map[string]string{
		"ssh argv":        readFile(t, world.argv),
		"the wire":        readFile(t, world.wire),
		"command output":  outputs.String(),
		"local audit log": readFile(t, filepath.Join(h.dir, "audit.log")),
		"box audit log":   readFile(t, filepath.Join(mac.dir, "audit.log")),
	}
	if readable["the wire"] == "" || readable["box audit log"] == "" {
		t.Fatal("nothing was recorded; the check would pass vacuously")
	}
	for where, text := range readable {
		for _, secret := range []string{localSecret, boxSecret} {
			if strings.Contains(text, secret) {
				t.Errorf("a value is readable in %s", where)
			}
		}
	}
	if !strings.Contains(readable["local audit log"], "mac-box") || !strings.Contains(readable["box audit log"], "LOCAL_KEY") {
		t.Errorf("audit logs do not name the transfers:\nlocal: %s\nbox: %s",
			readable["local audit log"], readable["box audit log"])
	}
}

// Each way a box can fail exits non-zero, explains itself, and leaves the box
// as it was.
func TestSyncRemoteFailures(t *testing.T) {
	h := newHarness(t)
	world := newSSHWorld(t)
	h.mustRun(localSecret, "add", "LOCAL_KEY")

	ready := world.newBox(t, "ready")
	locked := world.newBox(t, "locked")
	if err := os.Chmod(locked.kek, 0o644); err != nil { // the box's key will not load
		t.Fatal(err)
	}
	empty := filepath.Join(t.TempDir(), "never-initialized")
	t.Setenv("BOX_DIR_empty", empty)
	t.Setenv("BOX_KEK_empty", filepath.Join(t.TempDir(), "kek"))

	h.mustRun("", "remote", "add", "no-binary", "ready", "--bin", "missing")
	h.mustRun("", "remote", "add", "not-initialized", "empty")
	h.mustRun("", "remote", "add", "key-unavailable", "locked")
	h.mustRun("", "remote", "add", "other-protocol", "ready", "--bin", "future")

	cases := map[string]string{
		"no-binary":       "--bin",
		"not-initialized": "init",
		"key-unavailable": "chmod 600",
		"other-protocol":  "same version",
	}
	for remote, hint := range cases {
		t.Run(remote, func(t *testing.T) {
			code, stdout, stderr := h.run("", "push", remote, "LOCAL_KEY")
			if code == 0 || !strings.Contains(stdout+stderr, hint) {
				t.Errorf("push to %s exited %d, want a hint naming %q:\n%s%s", remote, code, hint, stdout, stderr)
			}
			if strings.ContainsAny(stdout+stderr, "\x1b\a") {
				t.Errorf("box text reached the terminal raw: %q", stdout+stderr)
			}
		})
	}
	for name, b := range map[string]*box{"ready": ready, "locked": locked} {
		if out := b.mustRun("", "ls"); strings.Contains(out, "LOCAL_KEY") {
			t.Errorf("a failed push changed %s", name)
		}
	}
	if _, err := os.Stat(empty); !os.IsNotExist(err) {
		t.Errorf("a failed push created a vault on the box: %v", err)
	}
}

// What a box writes to stderr reaches this terminal escaped: a box cannot
// retitle the window or recolor what follows.
func TestBoxStderrIsEscaped(t *testing.T) {
	h := newHarness(t)
	world := newSSHWorld(t)
	world.newBox(t, "mac")
	h.mustRun(localSecret, "add", "LOCAL_KEY")
	h.mustRun("", "remote", "add", "mac-box", "mac", "--bin", "noisy")

	_, stdout, stderr := h.run("", "push", "mac-box", "LOCAL_KEY")
	if strings.ContainsAny(stdout+stderr, "\x1b\a") || !strings.Contains(stderr, `motd \x1b]0;owned\a`) {
		t.Errorf("box text reached the terminal raw: %q", stderr)
	}
}

// A character split across two writes arrives whole; an invalid byte does not.
func TestBoxTextKeepsSplitCharacters(t *testing.T) {
	var out bytes.Buffer
	w := &boxText{w: &out}
	euro := []byte("€")
	w.Write(append([]byte("price "), euro[:1]...))
	w.Write(append(euro[1:], "\x9b\n"...))
	if got, want := out.String(), "price €\\x9b\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ssh ends its messages with \r\n: that is a newline, not text. A lone \r, or
// a bidi control that would reorder what follows, is escaped.
func TestBoxTextReadsCRLFAsANewline(t *testing.T) {
	var out bytes.Buffer
	w := &boxText{w: &out}
	w.Write([]byte("ssh: connect failed\r"))
	w.Write([]byte("\nover\rwritten \u202eeman\n"))
	if got, want := out.String(), "ssh: connect failed\nover\\rwritten \\u202eeman\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := printable("evil\u202etxt.exe"); !strings.Contains(got, `\u202e`) {
		t.Errorf("printable passed a bidi control: %q", got)
	}
}

// A registry sealed under another key — copied in from another vault — stops
// every command that reads it before ssh runs.
func TestSyncRefusesForeignRegistry(t *testing.T) {
	h := newHarness(t)
	world := newSSHWorld(t)
	mac := world.newBox(t, "mac")
	h.mustRun("", "remote", "add", "mac-box", "mac")
	mac.mustRun("", "remote", "add", "mac-box", "attacker")

	splice := func(from, to string) {
		var source, target map[string]json.RawMessage
		if err := json.Unmarshal([]byte(readFile(t, from)), &source); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(readFile(t, to)), &target); err != nil {
			t.Fatal(err)
		}
		target["remotes"] = source["remotes"]
		data, err := json.Marshal(target)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(to, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	splice(filepath.Join(mac.dir, "vault.sealed"), filepath.Join(h.dir, "vault.sealed"))

	for _, args := range [][]string{
		{"sync"}, {"sync", "mac-box"}, {"push", "mac-box", "X"}, {"pull", "mac-box", "X"},
		{"remote", "ls"}, {"remote", "add", "other", "elsewhere"}, {"remote", "rm", "mac-box"},
	} {
		code, _, stderr := h.run("", args...)
		if code == 0 || !strings.Contains(stderr, "edited by hand") {
			t.Errorf("%v exited %d: %s", args, code, stderr)
		}
	}
	if argv := readFile(t, world.argv); argv != "" {
		t.Errorf("ssh ran on a foreign registry: %q", argv)
	}
}

func TestRemoteCommands(t *testing.T) {
	h := newHarness(t)
	h.mustRun("", "remote", "add", "mac-box", "me@mac.local")
	h.mustRun("", "remote", "add", "linux-box", "dev-linux", "--bin", "~/go/bin/blindfold")

	out := h.mustRun("", "remote", "ls")
	if !strings.Contains(out, "me@mac.local") || !strings.Contains(out, "~/go/bin/blindfold") {
		t.Errorf("remote ls = %q", out)
	}
	if code, _, stderr := h.run("", "remote", "add", "evil", "-oProxyCommand=sh"); code == 0 {
		t.Errorf("an option-like destination was accepted: %s", stderr)
	}
	if code, _, stderr := h.run("", "push", "nowhere", "X"); code == 0 || !strings.Contains(stderr, "mac-box") {
		t.Errorf("an unknown box did not list the registered ones: %s", stderr)
	}
	h.mustRun("", "remote", "rm", "mac-box")
	if out := h.mustRun("", "remote", "ls"); strings.Contains(out, "mac-box") {
		t.Errorf("removed box still listed: %q", out)
	}
}

// At a terminal, sync becomes a picker. A differing entry is replaced only
// after an explicit yes; a no leaves it as it was.
func TestPickerConfirmsOverwrite(t *testing.T) {
	h := newHarness(t)
	world := newSSHWorld(t)
	mac := world.newBox(t, "mac")
	h.mustRun("rotated", "add", "API_KEY")
	mac.mustRun("stale", "add", "API_KEY")
	mac.mustRun("from-box", "add", "BOX_ONLY")
	h.mustRun("", "remote", "add", "mac-box", "mac")

	v, err := openVault()
	if err != nil {
		t.Fatal(err)
	}
	remotes, err := findRemotes(v, nil)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	env := lockStderr(Env{Stdout: &stdout, Stderr: &stderr, Version: "test"})
	view := openSyncView(env, v, remotes)

	// pick runs the picker over lines; Enter at the end quits it.
	pick := func(lines ...string) {
		p := &prompter{out: env.Stderr, buf: bufio.NewReader(strings.NewReader(strings.Join(lines, "\n") + "\n\n"))}
		if err := runPicker(env, view, p); err != nil {
			t.Fatalf("picker: %v\n%s", err, stderr.String())
		}
	}
	// Rows: 1 API_KEY (differs), 2 BOX_ONLY (only on the box).
	pick("push 9 mac-box", // no such row: reported, the loop goes on
		"push 1 mac-box", "n")
	if got := mac.mustRun("", "get", "API_KEY", "--force"); strings.TrimSpace(got) != "stale" {
		t.Errorf("the box holds %q after a no", got)
	}
	pick("push 1 mac-box", "y", "pull 2 mac-box")
	view.close() // waits for ssh, so its stderr is all in

	if asked := strings.Count(stderr.String(), "Replace it?"); asked != 2 {
		t.Errorf("asked %d times before overwriting, want 2:\n%s", asked, stderr.String())
	}
	if !strings.Contains(stdout.String(), "left as it was") || !strings.Contains(stdout.String(), "updated") {
		t.Errorf("picker output:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "9") {
		t.Errorf("a bad row number was not reported:\n%s", stderr.String())
	}
	if got := mac.mustRun("", "get", "API_KEY", "--force"); strings.TrimSpace(got) != "rotated" {
		t.Errorf("the box holds %q after a confirmed overwrite", got)
	}
	if got := h.mustRun("", "get", "BOX_ONLY", "--force"); strings.TrimSpace(got) != "from-box" {
		t.Errorf("pulled %q", got)
	}
}

// The picker's errors carry box text escaped, like everything else from a box.
func TestPickerEscapesBoxErrors(t *testing.T) {
	h := newHarness(t)
	world := newSSHWorld(t)
	world.newBox(t, "mac")
	h.mustRun(localSecret, "add", "API_KEY")
	h.mustRun("", "remote", "add", "old-box", "mac", "--bin", "future")

	v, err := openVault()
	if err != nil {
		t.Fatal(err)
	}
	remotes, err := findRemotes(v, nil)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	env := lockStderr(Env{Stdout: &stdout, Stderr: &stderr, Version: "test"})
	view := openSyncView(env, v, remotes)
	p := &prompter{out: env.Stderr, buf: bufio.NewReader(strings.NewReader("push 1 old-box\n\n"))}
	_ = runPicker(env, view, p) // fails: the box is unreachable, as sync would
	view.close()

	if !strings.Contains(stderr.String(), "unreachable") || strings.ContainsAny(stdout.String()+stderr.String(), "\x1b\a") {
		t.Errorf("box text reached the terminal raw: %q", stderr.String())
	}
}

// sync-serve hands values to whoever completes the handshake. In an agent's
// shell, nothing legitimate runs it: ssh starts it on the box, without the
// agent's markers.
func TestSyncServeRefusesAgentShell(t *testing.T) {
	h := newHarness(t)
	t.Setenv("CLAUDECODE", "1")
	var stdout, stderr bytes.Buffer
	code := Run(t.Context(), Env{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr}, []string{"sync-serve"})
	if code == 0 || !strings.Contains(stderr.String(), "CLAUDECODE") {
		t.Errorf("sync-serve in an agent's shell exited %d: %s", code, stderr.String())
	}
	if log := readFile(t, filepath.Join(h.dir, "audit.log")); !strings.Contains(log, `"sync-serve"`) || !strings.Contains(log, "denied") {
		t.Errorf("the refusal was not audited as denied: %s", log)
	}
}

// A push the box never answered still handed it the values: it is audited.
func TestPushWithoutAnAnswerIsAudited(t *testing.T) {
	h := newHarness(t)
	world := newSSHWorld(t)
	world.newBox(t, "mac")
	h.mustRun(localSecret, "add", "LOCAL_KEY")
	h.mustRun("", "remote", "add", "mac-box", "mac", "--bin", "cut")

	if code, _, stderr := h.run("", "push", "mac-box", "LOCAL_KEY"); code == 0 {
		t.Fatalf("a push without an answer succeeded: %s", stderr)
	}
	if log := readFile(t, filepath.Join(h.dir, "audit.log")); !strings.Contains(log, "LOCAL_KEY") || !strings.Contains(log, "no answer") {
		t.Errorf("the push was not audited: %s", log)
	}
}
