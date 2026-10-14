package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/magroski/blindfold/internal/vault"
)

const addDescription = `Store a credential: a named bundle of environment variables.

  ` + Bin + ` add ES_API_KEY                       one secret, named after the variable
  ` + Bin + ` add cdp-es --secret ES_API_KEY \
        --var ES_ENDPOINT=https://logs.internal:9200
  ` + Bin + ` add flux --from-file .env             every KEY=VALUE in a file

Secret values are read from the terminal without being echoed, or from stdin
when piped. They never appear in argv, which every process on this machine can
read.`

func cmdAdd(env Env, args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(env.Stderr, "usage: %s add <name> [flags]\n\n%s\n\nFlags:\n", Bin, addDescription)
		fs.PrintDefaults()
	}

	var secrets, publics stringList
	fs.Var(&secrets, "secret", "a secret variable; its value is prompted for. Repeatable")
	fs.Var(&publics, "var", "a non-secret variable, as NAME=value. Repeatable")
	fromFile := fs.String("from-file", "", "read KEY=VALUE lines from a file; all are treated as secret")
	public := fs.String("public", "", "comma-separated names from --from-file to keep in cleartext")
	description := fs.String("describe", "", "what this credential is for")
	tags := fs.String("tags", "", "comma-separated tags")

	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("usage: %s add <name> [flags]", Bin)
	}

	entry := vault.Entry{
		Name:        positional[0],
		Description: *description,
		Tags:        splitList(*tags),
	}
	if err := vault.ValidateEntryName(entry.Name); err != nil {
		return err
	}

	values := map[string]string{}
	declared := 0

	for _, spec := range publics {
		name, value, found := strings.Cut(spec, "=")
		if !found {
			return fmt.Errorf("--var %q is not NAME=value", spec)
		}
		if err := vault.ValidateVarName(name); err != nil {
			return err
		}
		entry.Vars = append(entry.Vars, vault.Var{Name: name, Value: value})
		declared++
	}

	if *fromFile != "" {
		parsed, order, err := readDotenv(*fromFile)
		if err != nil {
			return err
		}
		cleartext := map[string]bool{}
		for _, name := range splitList(*public) {
			cleartext[name] = true
		}
		for _, name := range order {
			if cleartext[name] {
				entry.Vars = append(entry.Vars, vault.Var{Name: name, Value: parsed[name]})
			} else {
				entry.Vars = append(entry.Vars, vault.Var{Name: name, Secret: true})
				values[name] = parsed[name]
			}
			declared++
		}
	}

	// One prompter for the whole command: see readSecret.
	prompt, _ := newPrompter(env)

	// Piped input is consumed whole, so that a multi-line value like a private
	// key survives intact. That makes reading two secrets from one pipe
	// ambiguous rather than merely awkward, so refuse it outright.
	if len(secrets) > 1 && prompt == nil {
		return fmt.Errorf("cannot read %d secrets from a pipe — the first would consume all of it.\n"+
			"Use --from-file, or add them one at a time", len(secrets))
	}

	// Named secrets are prompted for one at a time, in the order given.
	for _, name := range secrets {
		if err := vault.ValidateVarName(name); err != nil {
			return err
		}
		value, err := readSecret(env, prompt, fmt.Sprintf("%s: ", name))
		if err != nil {
			return err
		}
		if value == "" {
			return fmt.Errorf("no value supplied for %s", name)
		}
		entry.Vars = append(entry.Vars, vault.Var{Name: name, Secret: true})
		values[name] = value
		declared++
	}

	if declared == 0 {
		if err := collectInteractively(env, prompt, &entry, values); err != nil {
			return err
		}
	}

	if len(entry.Vars) == 0 {
		return errors.New("no variables given; nothing to store")
	}

	v, err := openVault()
	if err != nil {
		return err
	}
	if !v.Initialized() {
		return fmt.Errorf("vault is not initialized — run `%s init` first", Bin)
	}
	if _, exists := v.Get(entry.Name); exists {
		return fmt.Errorf("%q already exists; change it with `%s edit %s` or remove it first",
			entry.Name, Bin, entry.Name)
	}
	if err := v.Put(entry, values); err != nil {
		return err
	}

	fmt.Fprintf(env.Stdout, "\nAdded %q.\n\n", entry.Name)
	printEntry(env.Stdout, &entry)
	fmt.Fprintf(env.Stdout, "\nUse it with:\n  %s exec %s -- <command>\n", Bin, entry.Name)
	return nil
}

// collectInteractively fills in an entry by asking, for the common case of
// `blindfold add <name>` with no flags at all.
func collectInteractively(env Env, p *prompter, entry *vault.Entry, values map[string]string) error {
	if p == nil {
		// A single secret named after the entry is the one thing we can do
		// without asking, and only when the name is a usable variable name.
		if err := vault.ValidateVarName(entry.Name); err != nil {
			return fmt.Errorf("no variables given. Pass --secret NAME, --var NAME=value, or --from-file")
		}
		value, err := readSecret(env, nil, "")
		if err != nil {
			return err
		}
		if value == "" {
			return fmt.Errorf("no value supplied on stdin for %s", entry.Name)
		}
		entry.Vars = append(entry.Vars, vault.Var{Name: entry.Name, Secret: true})
		values[entry.Name] = value
		return nil
	}

	if entry.Description == "" {
		fmt.Fprintln(env.Stderr, "Description (an agent reads this to decide whether to use it):")
		entry.Description = p.line("> ", "")
	}

	fmt.Fprintln(env.Stderr, "\nVariables this credential exports. Leave the name blank to finish.")
	suggested := suggestVarName(entry.Name)
	for {
		question := "  Name: "
		if len(entry.Vars) == 0 && suggested != "" {
			question = fmt.Sprintf("  Name [%s]: ", suggested)
		}
		name := p.line(question, "")
		if name == "" && len(entry.Vars) == 0 {
			name = suggested
		}
		if name == "" {
			break
		}
		if err := vault.ValidateVarName(name); err != nil {
			fmt.Fprintf(env.Stderr, "  %v\n", err)
			continue
		}
		if _, exists := entry.Var(name); exists {
			fmt.Fprintf(env.Stderr, "  %s is already declared.\n", name)
			continue
		}

		if p.yesNo(fmt.Sprintf("  Is %s secret? [Y/n]: ", name), true) {
			value, err := p.hidden("  Value: ")
			if err != nil {
				return err
			}
			if value == "" {
				fmt.Fprintln(env.Stderr, "  Empty; skipped.")
				continue
			}
			entry.Vars = append(entry.Vars, vault.Var{Name: name, Secret: true})
			values[name] = value
		} else {
			entry.Vars = append(entry.Vars, vault.Var{Name: name, Value: p.line("  Value: ", "")})
		}
	}
	return nil
}

// suggestVarName derives a plausible variable name from an entry name, so the
// common `add SOME_TOKEN` and `add some-service` cases are one keypress.
func suggestVarName(entryName string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(entryName) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	name := b.String()
	if vault.ValidateVarName(name) != nil {
		return ""
	}
	return name
}

func cmdImport(env Env, args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	name := fs.String("as", "", "name to store the imported variables under")
	public := fs.String("public", "", "comma-separated names to keep in cleartext")
	description := fs.String("describe", "", "what this credential is for")
	tags := fs.String("tags", "", "comma-separated tags")

	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 || *name == "" {
		return fmt.Errorf("usage: %s import <file> --as <name>", Bin)
	}

	forwarded := []string{"--from-file", positional[0]}
	if *public != "" {
		forwarded = append(forwarded, "--public", *public)
	}
	if *description != "" {
		forwarded = append(forwarded, "--describe", *description)
	}
	if *tags != "" {
		forwarded = append(forwarded, "--tags", *tags)
	}
	return cmdAdd(env, append(forwarded, *name))
}

// readDotenv reads KEY=VALUE lines, tolerating comments, blank lines, `export`
// prefixes, and quoted values. It returns the values and the order they appeared
// in, so an imported file keeps its shape.
//
// Errors name a line, never quote it: in a file of secrets, the line that failed
// to parse is as likely a value as a key. Multi-line values are not supported,
// and a quote left open is refused rather than read on, line by line.
func readDotenv(path string) (map[string]string, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	values := map[string]string{}
	var order []string

	for i, line := range strings.Split(string(data), "\n") {
		lineNo := i + 1
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")

		key, value, found := strings.Cut(line, "=")
		if !found {
			return nil, nil, fmt.Errorf("%s line %d is not KEY=VALUE", path, lineNo)
		}
		key = strings.TrimSpace(key)
		if vault.ValidateVarName(key) != nil {
			return nil, nil, fmt.Errorf("%s line %d: the key is not a usable environment variable name", path, lineNo)
		}
		value = strings.TrimSpace(value)
		if opensQuote(value) {
			return nil, nil, fmt.Errorf("%s line %d opens a quote that does not close on the same line; "+
				"multi-line values are not supported here. Store it alone with `%s add <name> --secret %s < file`",
				path, lineNo, Bin, key)
		}
		if _, seen := values[key]; !seen {
			order = append(order, key)
		}
		values[key] = unquote(value)
	}
	if len(values) == 0 {
		return nil, nil, fmt.Errorf("%s has no KEY=VALUE pairs", path)
	}
	return values, order, nil
}

// opensQuote reports a value that starts a quote and never closes it: the first
// line of a multi-line value.
func opensQuote(s string) bool {
	if s == "" || (s[0] != '"' && s[0] != '\'') {
		return false
	}
	return strings.Count(s, s[:1]) == 1
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
