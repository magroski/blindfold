package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/magroski/blindfold/internal/vault"
)

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// writeTable prints rows in aligned columns. The final column is not padded, so
// a long value cannot push trailing whitespace across the terminal width.
func writeTable(w io.Writer, rows [][]string) {
	if len(rows) == 0 {
		return
	}

	widths := make([]int, len(rows[0]))
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len([]rune(cell)) > widths[i] {
				widths[i] = len([]rune(cell))
			}
		}
	}

	for _, row := range rows {
		var b strings.Builder
		for i, cell := range row {
			if i == len(row)-1 {
				b.WriteString(cell)
				break
			}
			pad := widths[i] - len([]rune(cell))
			b.WriteString(cell)
			b.WriteString(strings.Repeat(" ", pad+2))
		}
		fmt.Fprintln(w, strings.TrimRight(b.String(), " "))
	}
}

// printEntry renders one credential for a human. Sealed values are masked: this
// output is routinely pasted into issues and chat.
func printEntry(w io.Writer, e *vault.Entry) {
	fmt.Fprintln(w, e.Name)
	if e.Description != "" {
		fmt.Fprintf(w, "  %s\n", e.Description)
	}
	fmt.Fprintln(w)

	rows := [][]string{}
	for _, variable := range e.Vars {
		kind := "public"
		if variable.Secret {
			kind = "sealed"
		}
		rows = append(rows, []string{"  " + variable.Name, variable.Display(), kind})
	}
	writeTable(w, rows)

	if len(e.Tags) > 0 {
		fmt.Fprintf(w, "\n  tags: %s\n", strings.Join(e.Tags, " "))
	}
}
