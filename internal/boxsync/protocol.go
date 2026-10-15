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
// only ever inside a sealed frame. Values are bytes, so one that is not valid
// UTF-8 is not rewritten by the JSON encoding on the way.
type Credential struct {
	Entry  vault.Entry       `json:"entry"`
	Values map[string][]byte `json:"values"`
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

// valid reports whether o is one of the outcomes above: a box reports them,
// and they reach the terminal and the audit log.
func (o Outcome) valid() bool {
	switch o {
	case Created, Updated, Unchanged, Conflict, Failed:
		return true
	}
	return false
}

// codeLoadingVars make a program load or run code of the variable's choosing.
// A copied entry may not declare one: a box could otherwise turn a credential
// into code run by the next `exec` here, and this machine could do the same
// to a box. Names ending in "_" are prefixes. Add one locally to use it.
var codeLoadingVars = []string{
	"LD_", "DYLD_", "PATH", "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "PROMPT_COMMAND", "PS4", "ZDOTDIR",
	"NODE_OPTIONS", "NODE_PATH", "PYTHONSTARTUP", "PYTHONPATH", "PYTHONHOME", "PERL5OPT", "PERL5LIB", "PERLLIB",
	"RUBYOPT", "RUBYLIB", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH",
	"GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXEC_PATH", "GIT_ASKPASS", "GIT_CONFIG_", "SSH_ASKPASS", "GCONV_PATH",
}

// loadsCode reports whether name is, or starts with, one of codeLoadingVars.
func loadsCode(name string) bool {
	for _, v := range codeLoadingVars {
		if name == v || (strings.HasSuffix(v, "_") && strings.HasPrefix(name, v)) {
			return true
		}
	}
	return false
}

// Result is the outcome for one entry.
type Result struct {
	Name    string  `json:"name"`
	Outcome Outcome `json:"outcome"`
	Error   string  `json:"error,omitempty"`
}

// Access is one entry a box sent or received, or a comparison of all of them
// (OpStatus, no Entry), for its audit log. Names only; a received entry
// carries what storing it did.
type Access struct {
	Op      string
	Entry   string
	Vars    []string
	Outcome Outcome
}

// digest is a session-keyed hash of everything a copy carries but the name,
// which is compared directly: equal digests in one session mean the same
// credential, secret values included, byte for byte.
func digest(ch *Channel, e vault.Entry, values map[string]string) []byte {
	type variable struct {
		Name   string `json:"n"`
		Secret bool   `json:"s,omitempty"`
		Value  []byte `json:"v"`
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
		canonical.Vars = append(canonical.Vars, variable{Name: v.Name, Secret: v.Secret, Value: []byte(value)})
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
		raw := make(map[string][]byte, len(values))
		for name, value := range values {
			raw[name] = []byte(value)
		}
		credentials = append(credentials, Credential{Entry: copied, Values: raw})
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
	values, err := whole(c)
	if err != nil {
		return failed(result, err)
	}
	if existing, found := v.Get(c.Entry.Name); found {
		current, err := v.Unseal(existing.Name)
		if err != nil {
			return failed(result, err)
		}
		if hmac.Equal(digest(ch, *existing, current), digest(ch, c.Entry, values)) {
			result.Outcome = Unchanged
			return result
		}
		if !overwrite {
			result.Outcome = Conflict
			return result
		}
		result.Outcome = Updated
	}
	if err := v.Put(c.Entry, values); err != nil {
		return failed(result, err)
	}
	return result
}

// whole checks a copy can be stored as it came, and returns its values.
//
// Put keeps a sealed value the call leaves out, so a copy missing one would
// merge: the receiver's secret under the sender's endpoint. A copy declaring
// a code-loading variable is refused outright. Errors name variables, never
// values.
func whole(c Credential) (map[string]string, error) {
	for _, variable := range c.Entry.VarNames() {
		if loadsCode(variable) {
			return nil, fmt.Errorf("it declares %s, which makes programs load code; "+
				"a copy may not carry one. Add it by hand on the machine that needs it", variable)
		}
	}
	values := make(map[string]string, len(c.Values))
	for name, value := range c.Values {
		values[name] = string(value)
	}
	for _, secret := range c.Entry.SecretNames() {
		if _, ok := values[secret]; !ok {
			return nil, fmt.Errorf("the copy has no value for %s; nothing was stored", secret)
		}
	}
	return values, nil
}

func failed(r Result, err error) Result {
	r.Outcome, r.Error = Failed, err.Error()
	return r
}
