package cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/magroski/blindfold/internal/boxsync"
)

const (
	pickerPrompt = "\npush <#,#> <box>...  |  pull <#,#> <box>  |  Enter to quit\n> "
	pickerUsage  = "say `push 1,3 mac-box linux-box` or `pull 2 mac-box`"
	quitWord     = "q"
	quitCommand  = "quit"
)

// pick lets a person at a terminal copy entries from the sync table.
func pick(env Env, view *syncView) error {
	p, ok := newPrompter(env)
	if !ok {
		return view.err()
	}
	return runPicker(env, view, p)
}

// runPicker reads commands until Enter or q, redrawing the table after each.
// A command that fails is reported and the loop goes on.
func runPicker(env Env, view *syncView, p *prompter) error {
	for {
		fields := strings.Fields(p.line(pickerPrompt, ""))
		// Unreachable boxes still fail the command, picker or not.
		if len(fields) == 0 || fields[0] == quitWord || fields[0] == quitCommand {
			return view.err()
		}
		if err := pickOnce(env, view, p, fields); err != nil {
			fmt.Fprintln(env.Stderr, err)
			continue
		}
		view.refresh()
		fmt.Fprintln(env.Stdout)
		view.print(env.Stdout)
	}
}

// pickOnce runs one command: an operation, row numbers, and boxes.
func pickOnce(env Env, view *syncView, p *prompter, fields []string) error {
	op := fields[0]
	if (op != pushCommand && op != pullCommand) || len(fields) < 3 {
		return errors.New(pickerUsage)
	}
	names, err := view.rows(fields[1])
	if err != nil {
		return err
	}
	boxes := fields[2:]
	// Entries come from one place: here for a push, one box for a pull.
	if op == pullCommand && len(boxes) != 1 {
		return errors.New("pull from one box at a time")
	}
	// One box failing does not stop the others.
	for _, name := range boxes {
		b, err := view.box(name)
		if err == nil {
			err = pickTransfer(env, view, p, b, op, names)
		}
		if err != nil {
			fmt.Fprintf(env.Stderr, "%v\n", err)
		}
	}
	return nil
}

// pickTransfer copies entries one way, then asks about each one that differs
// on the receiving side before replacing it.
func pickTransfer(env Env, view *syncView, p *prompter, b *boxView, op string, names []string) error {
	results, err := transfer(env, view.local, b.session, b.remote.Name, op, names, false)
	if err != nil {
		return err
	}
	where := "on " + b.remote.Name
	if op == pullCommand {
		where = "here"
	}

	var replace []string
	for _, r := range results {
		if r.Outcome != boxsync.Conflict {
			printResult(env.Stdout, view.local, r)
			continue
		}
		if p.yesNo(fmt.Sprintf("%s differs %s. Replace it? [y/N] ", printable(r.Name), where), false) {
			replace = append(replace, r.Name)
			continue
		}
		printResult(env.Stdout, view.local, r)
	}
	if len(replace) == 0 {
		return nil
	}
	results, err = transfer(env, view.local, b.session, b.remote.Name, op, replace, true)
	if err != nil {
		return err
	}
	for _, r := range results {
		printResult(env.Stdout, view.local, r)
	}
	return nil
}

// rows resolves "1,3" to entry names, by the numbers the table shows.
func (s *syncView) rows(spec string) ([]string, error) {
	var names []string
	for _, field := range strings.Split(spec, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || n < 1 || n > len(s.names) {
			return nil, fmt.Errorf("no row %q; rows are 1 to %d", field, len(s.names))
		}
		names = append(names, s.names[n-1])
	}
	return names, nil
}
