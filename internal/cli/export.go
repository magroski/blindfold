package cli

import (
	"flag"
	"fmt"
	"strings"

	"github.com/magroski/blindfold/internal/audit"
	"github.com/magroski/blindfold/internal/vault"
)

// lineBreaks end a KEY=VALUE line wherever they appear in a value.
const lineBreaks = "\r\n"

// singleQuote cannot sit inside KEY='VALUE', and no escape for it reads the
// same in shells, python-dotenv, node dotenv and compose.
const singleQuote = "'"

// cmdExport prints a credential as KEY='VALUE' lines for env files:
//
//	blindfold export pg-ro --force > .env
//	docker run --env-file <(blindfold export pg-ro --force --raw) app
//
// Single quotes keep `set -a; . ./.env` from running a value as code, and
// dotenv parsers and compose strip them. --raw prints values unquoted, which
// docker --env-file reads literally; raw output must never be sourced by a
// shell, where a value like $(cmd) runs.
func cmdExport(env Env, args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	force := fs.Bool("force", false,
		"print even when output is not a terminal (the values land in whatever captured it)")
	raw := fs.Bool("raw", false,
		"print values unquoted, for docker run --env-file; never source raw output in a shell, it can run a value as code")

	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("usage: %s export <name> [--force] [--raw]", Bin)
	}

	// Every value in the clear: guarded like `get`, for the same reason.
	if err := guardPlaintext(env, "export", positional[0], *force); err != nil {
		return err
	}

	v, err := openVault()
	if err != nil {
		return err
	}
	bindings, err := resolveBindings(v, positional, nil, "")
	if err != nil {
		return err
	}

	// Built whole before writing, so a refusal never leaves half a file behind.
	var out strings.Builder
	for _, b := range bindings {
		if err := vault.ValidateVarName(b.Name); err != nil {
			return err
		}
		// A line break would end the value and start a line of its own choosing:
		// "x\nLD_PRELOAD=/tmp/evil.so" sets two variables.
		if strings.ContainsAny(b.Value, lineBreaks) {
			return fmt.Errorf("%s.%s contains a line break, which KEY=VALUE cannot carry; "+
				"load it with `%s env %s` instead", b.Entry, b.Var, Bin, b.Entry)
		}
		if *raw {
			fmt.Fprintf(&out, "%s=%s\n", b.Name, b.Value)
			continue
		}
		if strings.Contains(b.Value, singleQuote) {
			return fmt.Errorf("%s.%s contains a single quote, which a quoted env file cannot carry "+
				"portably; pass --raw for docker run --env-file, or load it with `%s env %s`",
				b.Entry, b.Var, Bin, b.Entry)
		}
		fmt.Fprintf(&out, "%s='%s'\n", b.Name, b.Value)
	}
	fmt.Fprint(env.Stdout, out.String())

	auditLog(env, v.Dir()).Log(audit.Event{
		Tool: "export", Secret: positional[0], Field: strings.Join(exportedNames(bindings), ","),
		Decision: audit.Allowed,
	})
	return nil
}
