// Package vault stores credential metadata in cleartext and credential values
// under envelope encryption.
//
// The split is deliberate: discovery (what credentials exist, which variables
// they export) must work without ever touching the master key, so listing the
// vault needs no unlock, no prompt, and no exposure.
package vault

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Mask is the fixed-width placeholder shown wherever a value would appear. Its
// width is constant so it leaks neither the value nor its length.
const Mask = "••••••••"

// Var is one environment variable an entry exports.
//
// A variable is either sealed (Secret, value in vault.sealed) or public (value
// stored in cleartext alongside the metadata). Public variables exist because
// the useful unit is usually a pair — an endpoint and the key that opens it —
// and splitting them across two stores would mean remembering to fetch both.
type Var struct {
	Name string `json:"name"`
	// Value is the cleartext value, and is empty for a secret variable.
	Value  string `json:"value,omitempty"`
	Secret bool   `json:"secret,omitempty"`
}

// Entry is a named bundle of environment variables.
type Entry struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	Vars        []Var     `json:"vars"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ValidateVarName rejects anything that is not a POSIX environment variable
// name.
//
// This is the load-bearing check of the whole tool. `blindfold env` emits shell
// that a caller evaluates, so a name containing a space, a quote, or a
// semicolon would not merely be malformed — it would be executed. Names are
// therefore validated on the way in and again on the way out.
func ValidateVarName(name string) error {
	if name == "" {
		return fmt.Errorf("vault: a variable name is required")
	}
	for i, r := range name {
		alpha := r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if alpha || (i > 0 && r >= '0' && r <= '9') {
			continue
		}
		return fmt.Errorf("vault: %q is not a usable environment variable name; "+
			"use letters, digits and underscores, starting with a letter or underscore", name)
	}
	return nil
}

// ValidateEntryName keeps entry names to characters that are unambiguous on a
// command line and in the audit log.
func ValidateEntryName(name string) error {
	if name == "" {
		return fmt.Errorf("vault: an entry name is required")
	}
	// "-force" would read as a flag wherever the name is typed.
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("vault: %q is not a usable entry name; it may not start with -", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("vault: %q is not a usable entry name; "+
				"use letters, digits, and - _ .", name)
		}
	}
	return nil
}

// validateText rejects control characters in free text that listings print.
// A newline would forge a row in `ls`, which an agent reads to choose a
// credential; an escape sequence would drive the terminal. The text is not
// echoed back, for the same reason.
func validateText(what, s string) error {
	for _, r := range s {
		if unicode.IsControl(r) {
			return fmt.Errorf("vault: the %s contains a control character, which a listing cannot show", what)
		}
	}
	return nil
}

// validateValue rejects a NUL, which no environment variable can carry: the
// value would be cut short, or exec would fail after the access was logged.
// The value is not echoed.
func validateValue(name, value string) error {
	if strings.ContainsRune(value, 0) {
		return fmt.Errorf("vault: the value of %s contains a NUL byte, which an environment variable cannot carry", name)
	}
	return nil
}

// Validate checks an entry is internally consistent before it is stored.
func (e *Entry) Validate() error {
	if err := ValidateEntryName(e.Name); err != nil {
		return err
	}
	if len(e.Vars) == 0 {
		return fmt.Errorf("vault: %q exports no variables", e.Name)
	}
	if err := validateText("description", e.Description); err != nil {
		return err
	}
	for _, tag := range e.Tags {
		if err := validateText("tag", tag); err != nil {
			return err
		}
	}

	seen := map[string]bool{}
	for _, v := range e.Vars {
		if err := ValidateVarName(v.Name); err != nil {
			return err
		}
		if seen[v.Name] {
			return fmt.Errorf("vault: %q declares %s twice", e.Name, v.Name)
		}
		seen[v.Name] = true

		// A secret variable's value belongs in the sealed file and nowhere else;
		// carrying one here would write it into cleartext metadata.
		if v.Secret && v.Value != "" {
			return fmt.Errorf("vault: %s is marked secret but carries a cleartext value", v.Name)
		}
		if err := validateValue(v.Name, v.Value); err != nil {
			return err
		}
	}
	return nil
}

// Var returns one variable by name.
func (e *Entry) Var(name string) (Var, bool) {
	for _, v := range e.Vars {
		if v.Name == name {
			return v, true
		}
	}
	return Var{}, false
}

// VarNames lists every variable this entry exports, in declaration order.
func (e *Entry) VarNames() []string {
	names := make([]string, 0, len(e.Vars))
	for _, v := range e.Vars {
		names = append(names, v.Name)
	}
	return names
}

// SecretNames lists the sealed variables, in declaration order.
func (e *Entry) SecretNames() []string {
	var names []string
	for _, v := range e.Vars {
		if v.Secret {
			names = append(names, v.Name)
		}
	}
	return names
}

// PrimaryVar is the variable meant when a caller names the entry but not a
// variable. It is the sole secret one, or — for an entry with no secrets at
// all — the sole variable. An ambiguous entry has no primary, and callers must
// say which they want rather than be given a guess.
func (e *Entry) PrimaryVar() (Var, bool) {
	if secrets := e.SecretNames(); len(secrets) == 1 {
		return e.Var(secrets[0])
	}
	if len(e.Vars) == 1 {
		return e.Vars[0], true
	}
	return Var{}, false
}

// HasTag reports whether the entry carries a tag.
func (e *Entry) HasTag(tag string) bool {
	for _, t := range e.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// Summary renders the entry's variables with every sealed value masked. This is
// what listings show, so it must never interpolate a real secret.
func (e *Entry) Summary() string {
	parts := make([]string, 0, len(e.Vars))
	for _, v := range e.Vars {
		parts = append(parts, v.Name+"="+v.Display())
	}
	return strings.Join(parts, " ")
}

// Display is the value as it may be shown: the mask for a secret, the real
// value for a public variable.
func (v Var) Display() string {
	if v.Secret {
		return Mask
	}
	return v.Value
}

// Metadata is the cleartext vault index, persisted as vault.json.
type Metadata struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// metadataVersion is 2: version 1 was the kind-based model (database, http,
// elasticsearch, env) that this replaced.
const metadataVersion = 2

// Find returns the entry with the given name.
func (m *Metadata) Find(name string) (*Entry, bool) {
	for i := range m.Entries {
		if m.Entries[i].Name == name {
			return &m.Entries[i], true
		}
	}
	return nil, false
}

// Upsert inserts or replaces an entry, keeping entries sorted by name so the
// on-disk file diffs cleanly.
func (m *Metadata) Upsert(e Entry) {
	if existing, ok := m.Find(e.Name); ok {
		e.CreatedAt = existing.CreatedAt
		*existing = e
	} else {
		m.Entries = append(m.Entries, e)
	}
	sort.Slice(m.Entries, func(i, j int) bool { return m.Entries[i].Name < m.Entries[j].Name })
}

// Remove deletes an entry by name, reporting whether it existed.
func (m *Metadata) Remove(name string) bool {
	for i := range m.Entries {
		if m.Entries[i].Name == name {
			m.Entries = append(m.Entries[:i], m.Entries[i+1:]...)
			return true
		}
	}
	return false
}
