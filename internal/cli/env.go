package cli

import (
	"flag"
	"fmt"
	"strings"

	"github.com/magroski/blindfold/internal/audit"
	"github.com/magroski/blindfold/internal/vault"
)

// binding is one variable about to be exported.
type binding struct {
	Name   string // the variable name to export under
	Value  string
	Secret bool
	Entry  string // where it came from, for messages and the audit log
	Var    string // its name within that entry, which may differ from Name
}

const envDescription = `Print shell that exports a credential's variables.

The output is meant to be evaluated, not read:

  eval "$(` + Bin + ` env cdp-es)" && python3 report.py

Everything the credential declares is exported. To place a single value under a
name of your choosing, use --set:

  eval "$(` + Bin + ` env --set DATABASE_URL=pg-ro)"
  eval "$(` + Bin + ` env --set ES_KEY=cdp-es.ES_API_KEY)"`

func cmdEnv(env Env, args []string) error {
	fs := flag.NewFlagSet("env", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(env.Stderr, "usage: %s env [name...] [--set VAR=name[.VAR]] [--tag TAG]\n\n%s\n\nFlags:\n",
			Bin, envDescription)
		fs.PrintDefaults()
	}

	var sets stringList
	fs.Var(&sets, "set", "export one value under a name of your choosing: VAR=name[.VAR]; repeatable")
	tag := fs.String("tag", "", "include every credential carrying this tag")
	quiet := fs.Bool("quiet", false, "do not print the summary of what was exported to stderr")
	force := fs.Bool("force", false, "print real values even when the output is a terminal")

	names, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(names) == 0 && len(sets) == 0 && *tag == "" {
		return fmt.Errorf("usage: %s env <name>... [--set VAR=name[.VAR]] [--tag TAG]\n\n%s",
			Bin, envDescription)
	}

	v, err := openVault()
	if err != nil {
		return err
	}

	bindings, err := resolveBindings(v, names, sets, *tag)
	if err != nil {
		return err
	}

	// A terminal means a person ran this by hand rather than through eval, so
	// printing the real values would only splatter them across the scrollback.
	if stdoutIsTerminal(env) && !*force {
		for _, b := range bindings {
			fmt.Fprintf(env.Stdout, "export %s=%s\n", b.Name, shellQuote(displayOf(b)))
		}
		fmt.Fprintf(env.Stderr, "\nValues are masked because this is a terminal. To actually load them:\n")
		fmt.Fprintf(env.Stderr, "  eval \"$(%s env %s)\"\n", Bin, strings.Join(args, " "))
		fmt.Fprintf(env.Stderr, "To see a real value, use `%s get`.\n", Bin)
		return nil
	}

	var out strings.Builder
	for _, b := range bindings {
		// Re-validated on the way out: this string is about to be executed by a
		// shell, and a name is the one part of it that quoting cannot contain.
		if err := vault.ValidateVarName(b.Name); err != nil {
			return err
		}
		fmt.Fprintf(&out, "export %s=%s\n", b.Name, shellQuote(b.Value))
	}
	fmt.Fprint(env.Stdout, out.String())

	logEnvAccess(v, "env", bindings)
	if !*quiet {
		fmt.Fprintf(env.Stderr, "%s: exported %s\n", Bin, strings.Join(exportedNames(bindings), ", "))
	}
	return nil
}

// resolveBindings turns the command line into the exact set of variables to
// export, refusing anything ambiguous.
func resolveBindings(v *vault.Vault, names []string, sets []string, tag string) ([]binding, error) {
	var bindings []binding

	appendAll := func(entry *vault.Entry) error {
		values, err := secretValues(v, entry)
		if err != nil {
			return err
		}
		for _, variable := range entry.Vars {
			value := variable.Value
			if variable.Secret {
				value = values[variable.Name]
			}
			bindings = append(bindings, binding{
				Name: variable.Name, Value: value, Secret: variable.Secret,
				Entry: entry.Name, Var: variable.Name,
			})
		}
		return nil
	}

	for _, name := range names {
		entry, err := mustFind(v, name)
		if err != nil {
			return nil, err
		}
		if err := appendAll(entry); err != nil {
			return nil, err
		}
	}

	if tag != "" {
		matched := 0
		entries := v.List()
		for i := range entries {
			entry := &entries[i]
			if !entry.HasTag(tag) {
				continue
			}
			matched++
			if err := appendAll(entry); err != nil {
				return nil, err
			}
		}
		if matched == 0 {
			return nil, fmt.Errorf("no credential carries the tag %q", tag)
		}
	}

	for _, set := range sets {
		b, err := resolveSet(v, set)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, b)
	}

	return bindings, dedupe(bindings)
}

// resolveSet parses one --set VAR=name[.VAR] argument.
func resolveSet(v *vault.Vault, set string) (binding, error) {
	target, ref, found := strings.Cut(set, "=")
	if !found || target == "" || ref == "" {
		return binding{}, fmt.Errorf("--set %q is not VAR=name[.VAR], e.g. --set DATABASE_URL=pg-ro", set)
	}
	if err := vault.ValidateVarName(target); err != nil {
		return binding{}, err
	}

	entryName, varName, qualified, err := splitRef(v, ref)
	if err != nil {
		return binding{}, err
	}
	entry, err := mustFind(v, entryName)
	if err != nil {
		return binding{}, err
	}

	var variable vault.Var
	if qualified {
		var ok bool
		if variable, ok = entry.Var(varName); !ok {
			return binding{}, fmt.Errorf("%q has no variable %s; it has %s",
				entry.Name, varName, strings.Join(entry.VarNames(), ", "))
		}
	} else {
		var ok bool
		if variable, ok = entry.PrimaryVar(); !ok {
			return binding{}, fmt.Errorf(
				"%q exports %s, so --set cannot tell which you mean; name one, e.g. --set %s=%s.%s",
				entry.Name, strings.Join(entry.VarNames(), ", "), target, entry.Name, entry.VarNames()[0])
		}
	}

	// Unsealed for a public variable too: opening the data key vouches for it.
	values, err := secretValues(v, entry)
	if err != nil {
		return binding{}, err
	}
	value := variable.Value
	if variable.Secret {
		value = values[variable.Name]
	}
	return binding{
		Name: target, Value: value, Secret: variable.Secret,
		Entry: entry.Name, Var: variable.Name,
	}, nil
}

// splitRef reads name[.VAR]. Variable names hold no dot, so the variable is
// whatever follows the last one, and a ref naming an entry outright means that
// entry. When both readings exist, refuse rather than pick:
//
//	prod.db.DATABASE_URL → DATABASE_URL of prod.db
//	prod.db              → entry prod.db, or variable db of entry prod?
func splitRef(v *vault.Vault, ref string) (entryName, varName string, qualified bool, err error) {
	dot := strings.LastIndex(ref, ".")
	_, whole := v.Get(ref)
	if dot < 0 || (whole && !hasVar(v, ref[:dot], ref[dot+1:])) {
		return ref, "", false, nil
	}
	if whole {
		return "", "", false, fmt.Errorf("%q names both the credential %s and variable %s of %s; "+
			"say which with %s.<VAR>", ref, ref, ref[dot+1:], ref[:dot], ref)
	}
	return ref[:dot], ref[dot+1:], true, nil
}

func hasVar(v *vault.Vault, entryName, varName string) bool {
	entry, ok := v.Get(entryName)
	if !ok {
		return false
	}
	_, ok = entry.Var(varName)
	return ok
}

// dedupe rejects two different values competing for one variable name. Silently
// letting the last one win would mean a command connecting to something other
// than the credential the caller thought it named.
func dedupe(bindings []binding) error {
	seen := map[string]binding{}
	for _, b := range bindings {
		if prior, ok := seen[b.Name]; ok && prior.Value != b.Value {
			return fmt.Errorf("%s would be set twice, by %s.%s and %s.%s, with different values",
				b.Name, prior.Entry, prior.Var, b.Entry, b.Var)
		}
		seen[b.Name] = b
	}
	return nil
}

// secretValues unseals an entry's values. An entry with no secret is unsealed
// too, for nothing: opening its data key is what proves vault.json was not
// edited by hand to add or change it.
func secretValues(v *vault.Vault, entry *vault.Entry) (map[string]string, error) {
	return v.Unseal(entry.Name)
}

func exportedNames(bindings []binding) []string {
	names := make([]string, 0, len(bindings))
	for _, b := range bindings {
		names = append(names, b.Name)
	}
	return names
}

func displayOf(b binding) string {
	if b.Secret {
		return vault.Mask
	}
	return b.Value
}

// logEnvAccess records one event per credential touched, never a value.
func logEnvAccess(v *vault.Vault, tool string, bindings []binding) {
	log := audit.New(v.Dir())
	byEntry := map[string][]string{}
	var order []string
	for _, b := range bindings {
		if _, seen := byEntry[b.Entry]; !seen {
			order = append(order, b.Entry)
		}
		byEntry[b.Entry] = append(byEntry[b.Entry], b.Var)
	}
	for _, name := range order {
		log.Log(audit.Event{
			Tool: tool, Secret: name, Field: strings.Join(byEntry[name], ","),
			Decision: audit.Allowed,
		})
	}
}

// shellQuoter escapes for single quotes that POSIX shells and fish read alike.
// POSIX takes '...' literally, but fish honours \' and \\ inside it, so the
// usual escape for ' (close, \', reopen) lets `\'; touch x; #` run under fish.
// Both ' and \ therefore close the quote, appear double-quoted, and reopen:
// it's → 'it'"'"'s', a\b → 'a'"\\"'b'. One pass, so a replacement's own
// quotes are never escaped again.
var shellQuoter = strings.NewReplacer(`\`, `'"\\"'`, `'`, `'"'"'`)

// shellQuote wraps a value so no shell interprets any part of it.
func shellQuote(s string) string {
	return "'" + shellQuoter.Replace(s) + "'"
}
