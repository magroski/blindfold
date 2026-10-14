// Package cli implements the blindfold command surface.
//
// There are two audiences. A person manages the vault: adding, editing, and
// inspecting credentials. An agent uses two commands and no others — `ls` to
// discover what exists, and `exec` (or `env`) to load a credential into the
// environment of the command it is about to run.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/magroski/blindfold/internal/vault"
)

// Bin is the command name, used in every usage string and hint. macOS already
// ships a /usr/sbin/sa, so the name is deliberately not that.
const Bin = "blindfold"

// Env carries the process context a command needs, so tests can drive commands
// without touching the real terminal.
type Env struct {
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Version string
}

const usage = `blindfold — keep credentials out of your agent's transcript

  blindfold init                    create the vault and its master key
  blindfold add <name>              store a credential
  blindfold ls                      list stored credentials
  blindfold show <name>             show one credential, values masked
  blindfold exec <name>... -- <cmd> run a command with the variables set
  blindfold env <name>...           print shell that exports the variables
  blindfold get <name>              print one value (terminal only)
  blindfold export <name>           print KEY='VALUE' lines (terminal only)
  blindfold edit <name>             change metadata or rotate a value
  blindfold rm <name>               remove a credential
  blindfold import <file> --as <n>  store a .env file as one credential
  blindfold audit                   show recent credential access
  blindfold doctor                  report vault and key-source health

Using a credential — the variables land in the environment of one command,
not in the conversation:

  blindfold exec cdp-es -- python3 report.py

Run 'blindfold <command> -h' for the flags of a command.`

// Run dispatches a command and returns a process exit code.
func Run(_ context.Context, env Env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(env.Stdout, usage)
		return 0
	}

	command, rest := args[0], args[1:]

	var err error
	switch command {
	case "init":
		err = cmdInit(env, rest)
	case "add":
		err = cmdAdd(env, rest)
	case execCommand:
		err = cmdExec(env, rest)
	case "env":
		err = cmdEnv(env, rest)
	case "get":
		err = cmdGet(env, rest)
	case "export":
		err = cmdExport(env, rest)
	case "list", "ls":
		err = cmdList(env, rest)
	case "show", "describe":
		err = cmdShow(env, rest)
	case "edit":
		err = cmdEdit(env, rest)
	case "rm", "remove":
		err = cmdRemove(env, rest)
	case "import":
		err = cmdImport(env, rest)
	case "audit":
		err = cmdAudit(env, rest)
	case "doctor":
		err = cmdDoctor(env, rest)
	case "help", "-h", "--help":
		fmt.Fprintln(env.Stdout, usage)
		return 0
	case "version", "--version":
		fmt.Fprintln(env.Stdout, env.Version)
		return 0
	default:
		fmt.Fprintf(env.Stderr, "%s: unknown command %q\n\n%s\n", Bin, command, usage)
		return 2
	}

	if err != nil {
		fmt.Fprintf(env.Stderr, "%s: %v\n", Bin, err)
		return 1
	}
	return 0
}

// openVault loads the vault from its default location.
func openVault() (*vault.Vault, error) {
	dir, err := vault.DefaultDir()
	if err != nil {
		return nil, err
	}
	return vault.Open(dir)
}

// mustFind returns an entry or an error that lists what does exist, so a typo
// is self-correcting rather than a dead end.
func mustFind(v *vault.Vault, name string) (*vault.Entry, error) {
	if entry, ok := v.Get(name); ok {
		return entry, nil
	}
	entries := v.List()
	if len(entries) == 0 {
		return nil, fmt.Errorf("no credential named %q; the vault is empty. Add one with `%s add %s`",
			name, Bin, name)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	return nil, fmt.Errorf("no credential named %q. Available: %s", name, strings.Join(names, ", "))
}

func cmdInit(env Env, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}

	v, err := openVault()
	if err != nil {
		return err
	}
	if err := v.Init(); err != nil {
		return err
	}

	fmt.Fprintf(env.Stdout, "Vault created at %s\n", v.Dir())
	fmt.Fprintf(env.Stdout, "Master key: %s\n\n", v.KeySourceDescription())
	fmt.Fprintf(env.Stdout, "That key is the only thing that decrypts your values. If it goes away,\n")
	fmt.Fprintf(env.Stdout, "so does every credential in the vault.\n\n")
	fmt.Fprintf(env.Stdout, "Add your first credential with:\n  %s add my-api-key\n", Bin)
	return nil
}

func cmdRemove(env Env, args []string) error {
	fs := flag.NewFlagSet("rm", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("usage: %s rm <name>", Bin)
	}

	v, err := openVault()
	if err != nil {
		return err
	}
	if err := v.Remove(positional[0]); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Removed %q.\n", positional[0])
	return nil
}

func cmdDoctor(env Env, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	showKeychain := fs.Bool("keychain", false, "show exactly which keychain item is read")
	if err := fs.Parse(args); err != nil {
		return err
	}

	v, err := openVault()
	if err != nil {
		return err
	}

	fmt.Fprintf(env.Stdout, "vault dir     %s\n", v.Dir())
	fmt.Fprintf(env.Stdout, "master key    %s\n", v.KeySourceDescription())
	// An env passphrase reaches every child process, so a stray `env` leaks it.
	if vault.PassphraseFromEnv() {
		fmt.Fprintf(env.Stdout, "warning       $BLINDFOLD_PASSPHRASE is inherited by every command the shell runs, "+
			"an agent's included; prefer BLINDFOLD_PASSPHRASE_FILE\n")
	}
	fmt.Fprintf(env.Stdout, "initialized   %t\n", v.Initialized())
	fmt.Fprintf(env.Stdout, "credentials   %d\n", len(v.List()))

	if *showKeychain {
		fmt.Fprintf(env.Stdout, "\nThis binary reads exactly one keychain item and never enumerates:\n")
		fmt.Fprintf(env.Stdout, "  class    generic password\n")
		fmt.Fprintf(env.Stdout, "  service  %s\n", vault.KeychainService)
		fmt.Fprintf(env.Stdout, "  account  %s\n", vault.KeychainAccount)
		fmt.Fprintf(env.Stdout, "\nVerify independently with:\n")
		fmt.Fprintf(env.Stdout, "  security find-generic-password -s %s -a %s\n",
			vault.KeychainService, vault.KeychainAccount)
	}
	return nil
}

// parseFlags parses args allowing flags and positional arguments to be
// interspersed, and returns the positional ones.
//
// Go's flag package stops at the first non-flag argument, which would make
// `blindfold add my-key --describe x` fail while `blindfold add --describe x
// my-key` worked. People type both, so both must work.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// stringList collects a flag that may be repeated.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// splitList parses a comma-separated flag value, ignoring empty entries.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// readSecret reads one secret value, so it never appears in argv or shell
// history. With a terminal it prompts without echoing; otherwise it consumes
// stdin whole, so that a multi-line value such as a private key survives intact.
//
// A caller reading several values must pass the same prompter to each call:
// building a new one per read would discard whatever the previous one had
// buffered.
func readSecret(env Env, p *prompter, prompt string) (string, error) {
	if p != nil {
		return p.hidden(prompt)
	}
	data, err := io.ReadAll(env.Stdin)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(data), "\r\n"), nil
}

// stdinIsTerminal reports whether we can prompt interactively.
func stdinIsTerminal(env Env) bool {
	f, ok := env.Stdin.(*os.File)
	return ok && isTerminal(f)
}

// stdoutIsTerminal reports whether output is going to a human's screen rather
// than into a pipe, a file, or a command substitution.
func stdoutIsTerminal(env Env) bool {
	f, ok := env.Stdout.(*os.File)
	return ok && isTerminal(f)
}

var errNoChange = errors.New("nothing to change; pass at least one flag")
