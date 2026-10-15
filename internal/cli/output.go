package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

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
			cell = printable(cell)
			if i < len(widths) && len([]rune(cell)) > widths[i] {
				widths[i] = len([]rune(cell))
			}
		}
	}

	for _, row := range rows {
		var b strings.Builder
		for i, cell := range row {
			cell = printable(cell)
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
	fmt.Fprintln(w, printable(e.Name))
	if e.Description != "" {
		fmt.Fprintf(w, "  %s\n", printable(e.Description))
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
		fmt.Fprintf(w, "\n  tags: %s\n", printable(strings.Join(e.Tags, " ")))
	}
}

// printable escapes text that would otherwise reach the terminal as control:
// "a\nb" forges a row, "\x1b]52;c;…" writes the clipboard. Input checks catch
// most of it; metadata edited by hand, and public values, skip them.
//
//	"ok"         → ok
//	"x\x1b[2J"   → "x\x1b[2J" (quoted, escaped)
func printable(s string) string {
	if utf8.ValidString(s) && strings.IndexFunc(s, unsafeRune) < 0 {
		return s
	}
	return strconv.Quote(s)
}

// unsafeRune is a control character, or a bidi control that would reorder
// what follows it on screen: "‮" makes "evil‮txt.exe" read as
// "eviltxt.exe" backwards.
func unsafeRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r)
}
