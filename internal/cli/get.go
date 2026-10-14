package cli

import (
	"flag"
	"fmt"
	"strings"

	"github.com/magroski/blindfold/internal/audit"
	"github.com/magroski/blindfold/internal/vault"
)

func cmdGet(env Env, args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	varName := fs.String("var", "", "which variable to print; defaults to the only secret one")
	force := fs.Bool("force", false,
		"print even when output is not a terminal (the value lands in whatever captured it)")

	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("usage: %s get <name> [--var NAME]", Bin)
	}

	// `get` prints a bare value, which is what you want when copying one into a
	// web form and never what you want inside an agent's shell. The guard does
	// not make capture impossible — an unlisted harness with a pty defeats it —
	// but it keeps the value from being piped somewhere by accident, and makes
	// doing so a deliberate act.
	if err := guardPlaintext(env, "get", positional[0], *force); err != nil {
		return err
	}

	v, err := openVault()
	if err != nil {
		return err
	}
	entry, err := mustFind(v, positional[0])
	if err != nil {
		return err
	}

	variable, err := pickVar(entry, *varName)
	if err != nil {
		return err
	}

	value := variable.Value
	if variable.Secret {
		value, err = v.UnsealVar(entry.Name, variable.Name)
	} else {
		// Nothing to unseal, but opening the data key vouches for the value.
		_, err = v.Unseal(entry.Name)
	}
	if err != nil {
		return err
	}

	// --force skips the guard, so the value may have gone anywhere.
	reason := "printed at a terminal"
	if *force {
		reason = "printed with --force"
	}
	auditLog(env, v.Dir()).Log(audit.Event{
		Tool: "get", Secret: entry.Name, Field: variable.Name,
		Decision: audit.Allowed, Reason: reason,
	})

	// The value alone on stdout, so `blindfold get x --force | pbcopy` behaves.
	fmt.Fprintln(env.Stdout, value)
	return nil
}

// pickVar resolves which variable the caller meant, refusing to guess when an
// entry exports several.
func pickVar(entry *vault.Entry, name string) (vault.Var, error) {
	if name != "" {
		variable, ok := entry.Var(name)
		if !ok {
			return vault.Var{}, fmt.Errorf("%q has no variable %s; it has %s",
				entry.Name, name, strings.Join(entry.VarNames(), ", "))
		}
		return variable, nil
	}

	variable, ok := entry.PrimaryVar()
	if !ok {
		return vault.Var{}, fmt.Errorf("%q exports %s; say which you want with --var",
			entry.Name, strings.Join(entry.VarNames(), ", "))
	}
	return variable, nil
}
