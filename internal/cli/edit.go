package cli

import (
	"flag"
	"fmt"
	"strings"

	"github.com/magroski/blindfold/internal/vault"
)

func cmdEdit(env Env, args []string) error {
	fs := flag.NewFlagSet("edit", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)

	description := fs.String("describe", "", "replace the description")
	tags := fs.String("tags", "", "replace the tag list")

	var rotate, publics, remove stringList
	fs.Var(&rotate, "set", "rotate or add a secret variable; its value is prompted for. Repeatable")
	fs.Var(&publics, "var", "set or add a non-secret variable, as NAME=value. Repeatable")
	fs.Var(&remove, "rm-var", "remove a variable entirely. Repeatable")

	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("usage: %s edit <name> [--set VAR] [--var NAME=value] [--rm-var NAME] [--describe ...]", Bin)
	}

	v, err := openVault()
	if err != nil {
		return err
	}
	existing, err := mustFind(v, positional[0])
	if err != nil {
		return err
	}
	entry := *existing
	entry.Vars = append([]vault.Var(nil), existing.Vars...)

	// Only flags actually passed take effect, so editing one attribute never
	// silently clears another.
	seen := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	if len(seen) == 0 {
		return errNoChange
	}

	if seen["describe"] {
		entry.Description = *description
	}
	if seen["tags"] {
		entry.Tags = splitList(*tags)
	}

	for _, name := range remove {
		if _, ok := entry.Var(name); !ok {
			return fmt.Errorf("%q has no variable %s; it has %s",
				entry.Name, name, strings.Join(entry.VarNames(), ", "))
		}
		entry.Vars = withoutVar(entry.Vars, name)
	}

	for _, spec := range publics {
		name, value, found := strings.Cut(spec, "=")
		if !found {
			return fmt.Errorf("--var %q is not NAME=value", spec)
		}
		if err := vault.ValidateVarName(name); err != nil {
			return err
		}
		// --var would store a secret's value in cleartext metadata. Unsealing
		// must be deliberate: --rm-var NAME, applied above, removes it first.
		if current, ok := entry.Var(name); ok && current.Secret {
			return fmt.Errorf("%s of %q is secret; --var would store its value in cleartext. Nothing changed.\n"+
				"Rotate it with --set %s (prompted, never in argv), or unseal it deliberately with --rm-var %s.\n"+
				"The value you passed is in argv and shell history: if it is real, treat it as exposed and rotate it",
				name, entry.Name, name, name)
		}
		entry.Vars = upsertVar(entry.Vars, vault.Var{Name: name, Value: value})
	}

	prompt, _ := newPrompter(env)
	if len(rotate) > 1 && prompt == nil {
		return fmt.Errorf("cannot read %d secrets from a pipe — the first would consume all of it.\n"+
			"Rotate them one at a time", len(rotate))
	}

	values := map[string]string{}
	for _, name := range rotate {
		if err := vault.ValidateVarName(name); err != nil {
			return err
		}
		value, err := readSecret(env, prompt, fmt.Sprintf("New value for %s: ", name))
		if err != nil {
			return err
		}
		if value == "" {
			return fmt.Errorf("no value supplied for %s", name)
		}
		entry.Vars = upsertVar(entry.Vars, vault.Var{Name: name, Secret: true})
		values[name] = value
	}

	if err := v.Put(entry, values); err != nil {
		return err
	}

	fmt.Fprintf(env.Stdout, "Updated %q.\n\n", entry.Name)
	printEntry(env.Stdout, &entry)
	return nil
}

// upsertVar replaces a variable in place, keeping declaration order stable, or
// appends it when it is new.
func upsertVar(vars []vault.Var, replacement vault.Var) []vault.Var {
	for i := range vars {
		if vars[i].Name == replacement.Name {
			vars[i] = replacement
			return vars
		}
	}
	return append(vars, replacement)
}

func withoutVar(vars []vault.Var, name string) []vault.Var {
	out := vars[:0]
	for _, v := range vars {
		if v.Name != name {
			out = append(out, v)
		}
	}
	return out
}
