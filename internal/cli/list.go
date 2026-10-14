package cli

import (
	"flag"
	"fmt"
	"strings"

	"github.com/magroski/blindfold/internal/audit"
	"github.com/magroski/blindfold/internal/vault"
)

func cmdList(env Env, args []string) error {
	fs := flag.NewFlagSet("ls", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	tag := fs.String("tag", "", "only show credentials carrying this tag")
	asJSON := fs.Bool("json", false, "emit JSON instead of a table")
	if err := fs.Parse(args); err != nil {
		return err
	}

	v, err := openVault()
	if err != nil {
		return err
	}

	var entries []vault.Entry
	for _, e := range v.List() {
		if *tag == "" || e.HasTag(*tag) {
			entries = append(entries, e)
		}
	}

	if *asJSON {
		if entries == nil {
			entries = []vault.Entry{}
		}
		return writeJSON(env.Stdout, entries)
	}
	if len(entries) == 0 {
		if *tag != "" {
			fmt.Fprintf(env.Stdout, "No credentials carry the tag %q.\n", *tag)
			return nil
		}
		fmt.Fprintln(env.Stdout, "No credentials yet. Add one with:")
		fmt.Fprintf(env.Stdout, "  %s add MY_API_KEY\n", Bin)
		return nil
	}

	rows := [][]string{{"NAME", "VARIABLES", "DESCRIPTION"}}
	for _, e := range entries {
		rows = append(rows, []string{e.Name, markedVarNames(&e), e.Description})
	}
	writeTable(env.Stdout, rows)
	fmt.Fprintf(env.Stdout, "\n* = sealed. Load one with: %s exec %s -- <command>\n",
		Bin, entries[0].Name)
	return nil
}

// markedVarNames renders an entry's variables with a star on the sealed ones, so
// a listing shows at a glance what is a secret and what is merely configuration.
func markedVarNames(e *vault.Entry) string {
	names := make([]string, 0, len(e.Vars))
	for _, variable := range e.Vars {
		if variable.Secret {
			names = append(names, variable.Name+"*")
		} else {
			names = append(names, variable.Name)
		}
	}
	return strings.Join(names, " ")
}

func cmdShow(env Env, args []string) error {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	asJSON := fs.Bool("json", false, "emit JSON instead of text")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("usage: %s show <name>", Bin)
	}

	v, err := openVault()
	if err != nil {
		return err
	}
	entry, err := mustFind(v, positional[0])
	if err != nil {
		return err
	}

	if *asJSON {
		return writeJSON(env.Stdout, entry)
	}
	printEntry(env.Stdout, entry)
	return nil
}

func cmdAudit(env Env, args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	limit := fs.Int("n", 50, "show at most this many recent events")
	asJSON := fs.Bool("json", false, "emit JSON instead of a table")
	if err := fs.Parse(args); err != nil {
		return err
	}

	v, err := openVault()
	if err != nil {
		return err
	}
	events, err := audit.Read(v.Dir(), *limit)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		fmt.Fprintln(env.Stdout, "No credential access recorded yet.")
		return nil
	}
	if *asJSON {
		return writeJSON(env.Stdout, events)
	}

	rows := [][]string{{"WHEN", "COMMAND", "CREDENTIAL", "VARIABLES"}}
	for _, e := range events {
		detail := e.Field
		if e.Reason != "" {
			detail = e.Reason
		}
		// Refusals read "denied: <condition>" so they stand out from accesses.
		if e.Decision == audit.Denied {
			detail = string(audit.Denied) + ": " + detail
		}
		rows = append(rows, []string{
			e.Time.Local().Format("2006-01-02 15:04:05"), e.Tool, e.Secret, detail,
		})
	}
	writeTable(env.Stdout, rows)
	return nil
}
