package boxsync

import (
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/magroski/blindfold/internal/vault"
)

// Operations a client asks of a box.
const (
	OpStatus = "status" // digests of every entry
	OpPull   = "pull"   // entries, with values, from the box
	OpPush   = "push"   // entries, with values, to the box
)

type request struct {
	Op        string       `json:"op"`
	Names     []string     `json:"names,omitempty"`
	Entries   []Credential `json:"entries,omitempty"`
	Overwrite bool         `json:"overwrite,omitempty"`
}

type response struct {
	Error   string        `json:"error,omitempty"`
	Digests []entryDigest `json:"digests,omitempty"`
	Entries []Credential  `json:"entries,omitempty"`
	Results []Result      `json:"results,omitempty"`
}

// Credential is one whole entry as it travels: metadata and its sealed values,
// only ever inside a sealed frame.
type Credential struct {
	Entry  vault.Entry       `json:"entry"`
	Values map[string]string `json:"values"`
}

type entryDigest struct {
	Name   string `json:"name"`
	Digest []byte `json:"digest"`
}

// Outcome is what storing one copied entry did.
type Outcome string

const (
	Created   Outcome = "created"
	Updated   Outcome = "updated"
	Unchanged Outcome = "unchanged"
	Conflict  Outcome = "conflict" // differs, and overwrite was not given
	Failed    Outcome = "failed"
)

// Result is the outcome for one entry.
type Result struct {
	Name    string  `json:"name"`
	Outcome Outcome `json:"outcome"`
	Error   string  `json:"error,omitempty"`
}

// Access is one entry a box sent or received, or a comparison of all of them
// (OpStatus, no Entry), for its audit log. Names only.
type Access struct {
	Op    string
	Entry string
	Vars  []string
}

// digest is a session-keyed hash of everything a copy carries but the name,
// which is compared directly: equal digests in one session mean the same
// credential, secret values included.
func digest(ch *Channel, e vault.Entry, values map[string]string) []byte {
	type variable struct {
		Name   string `json:"n"`
		Secret bool   `json:"s,omitempty"`
		Value  string `json:"v"`
	}
	canonical := struct {
		Description string     `json:"d,omitempty"`
		Tags        []string   `json:"t,omitempty"`
		Vars        []variable `json:"v"`
	}{Description: e.Description, Tags: e.Tags}
	for _, v := range e.Vars {
		value := v.Value
		if v.Secret {
			value = values[v.Name]
		}
		canonical.Vars = append(canonical.Vars, variable{Name: v.Name, Secret: v.Secret, Value: value})
	}
	data, _ := json.Marshal(canonical) // strings and bools: cannot fail
	return ch.Digest(data)
}

// export reads whole entries, values unsealed, ready to travel.
func export(v *vault.Vault, names []string) ([]Credential, error) {
	credentials := make([]Credential, 0, len(names))
	for _, name := range names {
		entry, ok := v.Get(name)
		if !ok {
			return nil, unknownEntry(v, name)
		}
		values, err := v.Unseal(name)
		if err != nil {
			return nil, err
		}
		copied := *entry
		copied.CreatedAt, copied.UpdatedAt = time.Time{}, time.Time{} // the receiver stamps its own
		credentials = append(credentials, Credential{Entry: copied, Values: values})
	}
	return credentials, nil
}

func unknownEntry(v *vault.Vault, name string) error {
	entries := v.List()
	if len(entries) == 0 {
		return fmt.Errorf("no credential named %q; the vault is empty", name)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	return fmt.Errorf("no credential named %q. Available: %s", name, strings.Join(names, ", "))
}

// store writes one copied entry into v through Put, so it is validated and
// sealed under v's own master key. An entry already there is replaced only
// when it differs and overwrite is set.
func store(v *vault.Vault, ch *Channel, c Credential, overwrite bool) Result {
	result := Result{Name: c.Entry.Name, Outcome: Created}
	if existing, found := v.Get(c.Entry.Name); found {
		current, err := v.Unseal(existing.Name)
		if err != nil {
			return failed(result, err)
		}
		if hmac.Equal(digest(ch, *existing, current), digest(ch, c.Entry, c.Values)) {
			result.Outcome = Unchanged
			return result
		}
		if !overwrite {
			result.Outcome = Conflict
			return result
		}
		result.Outcome = Updated
	}
	if err := v.Put(c.Entry, c.Values); err != nil {
		return failed(result, err)
	}
	return result
}

func failed(r Result, err error) Result {
	r.Outcome, r.Error = Failed, err.Error()
	return r
}
