package cli

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/magroski/blindfold/internal/vault"
)

// execCommand names the subcommand, and its events in the audit log.
const execCommand = "exec"

// commandSeparator ends blindfold's arguments; everything after it is the command.
const commandSeparator = "--"

// helpFlags are the spellings the flag package reads as a request for usage.
var helpFlags = []string{"-h", "-help", "--h", "--help"}

// passphraseVar carries the vault's master passphrase. The command was given
// some credentials, not the key to all of them.
const passphraseVar = "BLINDFOLD_PASSPHRASE"

const execUsage = Bin + " exec [name...] [--set VAR=name[.VAR]] [--tag TAG] [--quiet] -- <command> [args...]"

const execDescription = `Run a command with a credential's variables in its environment.

Only the command sees the values; blindfold prints just the names it loaded:

  ` + Bin + ` exec cdp-es -- python3 report.py
  ` + Bin + ` exec --set DATABASE_URL=pg-ro -- ./migrate

No shell runs in between, so $VAR on the command line is expanded by your shell
before anything is loaded. Prefer programs that read the environment (psql
reads PGPASSWORD). One that only takes an argument can get it from a shell
inside the new environment — but argv is visible to every process on this
machine while the command runs:

  ` + Bin + ` exec pg-ro -- sh -c 'psql "$DATABASE_URL"'`

// execProcess replaces this process with the command. Tests swap it to capture
// what would have run instead of being replaced themselves.
var execProcess = replaceProcess

func cmdExec(env Env, args []string) error {
	fs := flag.NewFlagSet(execCommand, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(env.Stderr, "usage: %s\n\n%s\n\nFlags:\n", execUsage, execDescription)
		fs.PrintDefaults()
	}

	var sets stringList
	fs.Var(&sets, "set", "load one value under a name of your choosing: VAR=name[.VAR]; repeatable")
	tag := fs.String("tag", "", "include every credential carrying this tag")
	quiet := fs.Bool("quiet", false, "do not print the summary of what was loaded to stderr")

	// Split first: the command's own flags are not ours to parse.
	separator := slices.Index(args, commandSeparator)
	if separator < 0 {
		// Without it, our flags and the command's are indistinguishable; -h is
		// the one request that is still unambiguous.
		if slices.ContainsFunc(args, func(arg string) bool { return slices.Contains(helpFlags, arg) }) {
			fs.Usage()
			return flag.ErrHelp
		}
		return fmt.Errorf("missing %q before the command\nusage: %s", commandSeparator, execUsage)
	}
	command := args[separator+1:]

	names, err := parseFlags(fs, args[:separator])
	if err != nil {
		return err
	}
	if len(command) == 0 {
		return fmt.Errorf("no command after %q\nusage: %s", commandSeparator, execUsage)
	}
	if len(names) == 0 && len(sets) == 0 && *tag == "" {
		return fmt.Errorf("nothing to load; name a credential, or use --set or --tag\nusage: %s", execUsage)
	}

	// Resolved before anything is unsealed, so a typo costs no keychain prompt.
	path, err := exec.LookPath(command[0])
	if err != nil {
		return err
	}

	v, err := openVault()
	if err != nil {
		return err
	}
	bindings, err := resolveBindings(v, names, sets, *tag)
	if err != nil {
		return err
	}
	childEnv, err := commandEnviron(os.Environ(), bindings)
	if err != nil {
		return err
	}

	// Logged and announced now: on success, execProcess does not return.
	logEnvAccess(v, execCommand, bindings)
	if !*quiet {
		fmt.Fprintf(env.Stderr, "%s: exported %s\n", Bin, strings.Join(exportedNames(bindings), ", "))
	}
	if err := execProcess(path, command, childEnv); err != nil {
		return fmt.Errorf("running %s: %w", command[0], err)
	}
	return nil
}

// commandEnviron is the inherited environment minus the master passphrase, with
// each binding replacing any variable of the same name. A duplicate would leave
// the command reading whichever copy its libc finds first, e.g.
//
//	DATABASE_URL=postgres://stale ... DATABASE_URL=postgres://from-vault
func commandEnviron(inherited []string, bindings []binding) ([]string, error) {
	dropped := map[string]bool{passphraseVar: true}
	for _, b := range bindings {
		// Re-validated on the way out: "A=B" as a name would smuggle in a
		// variable of its own.
		if err := vault.ValidateVarName(b.Name); err != nil {
			return nil, err
		}
		dropped[b.Name] = true
	}

	out := make([]string, 0, len(inherited)+len(bindings))
	for _, kv := range inherited {
		if name, _, _ := strings.Cut(kv, "="); dropped[name] {
			continue
		}
		out = append(out, kv)
	}
	added := map[string]bool{}
	for _, b := range bindings {
		// dedupe already refused differing values; skip a harmless repeat.
		if added[b.Name] {
			continue
		}
		added[b.Name] = true
		out = append(out, b.Name+"="+b.Value)
	}
	return out, nil
}
