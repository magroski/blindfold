package boxsync

import (
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"path"
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

// hijackingVars make a program run code of the variable's choosing, load its
// configuration or libraries from elsewhere, stop checking whom it talks to,
// or send its traffic elsewhere. A copied entry may not declare one: a box
// could otherwise turn a credential into code run by the next `exec` here —
// or redirect the entries loaded beside it — and this machine could do the
// same to a box. Endpoints and registries (OPENAI_BASE_URL, PIP_INDEX_URL,
// PGHOST) are not here: they are often the credential itself.
//
// Patterns, matched against the name in upper case: "LD_*" is every LD_
// variable. It is a list, so it cannot be complete; each stored entry prints
// its variables for a person to read. Add one by hand where it is meant.
var hijackingVars = []string{
	// Loaders, interpreter and compiler options.
	"LD_*", "DYLD_*", "GCONV_PATH", "PATH", "BASH_ENV", "ENV", "SHELL", "SHELLOPTS", "BASHOPTS", "IFS",
	"CDPATH", "FPATH", "PROMPT_COMMAND", "PS4", "ZDOTDIR", "NODE_OPTIONS", "NODE_PATH",
	"NODE_REPL_EXTERNAL_MODULE", "NPM_CONFIG_*", "YARN_YARN_PATH", "PYTHONSTARTUP", "PYTHONPATH",
	"PYTHONHOME", "PYTHONUSERBASE", "PYTHONWARNINGS", "PERL5OPT", "PERL5LIB", "PERLLIB", "PERL5DB", "RUBYOPT",
	"RUBYLIB", "GEM_HOME", "GEM_PATH", "BUNDLE_GEMFILE", "RUBYGEMS_GEMDEPS", "LUA_INIT*", "LUA_PATH*",
	"LUA_CPATH*", "PHPRC", "PHP_INI_SCAN_DIR", "R_PROFILE*", "R_ENVIRON*", "JAVA_HOME", "JAVA_TOOL_OPTIONS",
	"_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "JAVA_OPTS", "MAVEN_OPTS", "GRADLE_OPTS", "GRADLE_USER_HOME",
	"CLASSPATH", "DOTNET_STARTUP_HOOKS", "DOTNET_ADDITIONAL_DEPS", "CORECLR_*", "COR_PROFILER*",
	"ERL_FLAGS", "ERL_AFLAGS", "ERL_ZFLAGS", "ELIXIR_ERL_OPTIONS", "GOFLAGS", "GOENV", "GOCACHEPROG",
	"GOAUTH", "CGO_*FLAGS", "CC", "CXX", "CFLAGS", "CPPFLAGS", "CXXFLAGS", "LDFLAGS", "MAKEFLAGS", "MAKEFILES",
	"CMAKE_*_COMPILER_LAUNCHER", "CCACHE_PREFIX", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
	"RUSTDOC", "RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_HOME", "CARGO_BUILD_*", "CARGO_TARGET_*_RUNNER",
	"CARGO_TARGET_*_LINKER", "GTK_MODULES", "GTK_PATH", "QT_PLUGIN_PATH", "CLOUDSDK_PYTHON",
	// Commands run straight from a value.
	"PAGER", "MANPAGER", "MANOPT", "SYSTEMD_PAGER", "LESSOPEN", "LESSCLOSE", "EDITOR", "VISUAL", "FCEDIT",
	"BROWSER", "SUDO_ASKPASS", "SUDO_EDITOR", "SSH_ASKPASS", "KUBE_EDITOR", "PSQL_PAGER", "PSQL_EDITOR",
	"GH_PAGER", "GH_EDITOR", "GH_BROWSER", "HGEDITOR", "TAR_OPTIONS", "RSYNC_RSH", "RSYNC_CONNECT_PROG",
	"SVN_SSH", "CVS_RSH", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_ASKPASS", "GIT_EXEC_PATH", "GIT_EXTERNAL_DIFF",
	"GIT_PAGER", "GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "GIT_PROXY_COMMAND",
	// Configuration read from elsewhere: every tool's dotfiles, plugins, helpers.
	"HOME", "XDG_CONFIG_HOME", "XDG_CONFIG_DIRS", "XDG_DATA_HOME", "XDG_DATA_DIRS", "GIT_DIR",
	"GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
	"GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_TEMPLATE_DIR", "GIT_CONFIG", "GIT_CONFIG_*", "GNUPGHOME",
	"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "DOCKER_CONFIG", "TF_CLI_CONFIG_FILE",
	"HELM_PLUGINS", "PSQLRC", "HGRCPATH", "OPENSSL_CONF", "OPENSSL_ENGINES", "OPENSSL_MODULES",
	// Checks turned off, trust or traffic sent elsewhere, traffic logged.
	"NODE_TLS_REJECT_UNAUTHORIZED", "GIT_SSL_NO_VERIFY", "PYTHONHTTPSVERIFY", "VAULT_SKIP_VERIFY",
	"PIP_TRUSTED_HOST", "GOSUMDB", "GONOSUMDB", "GOINSECURE", "SSL_CERT_FILE", "SSL_CERT_DIR",
	"CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO", "GIT_SSL_CAPATH",
	"AWS_CA_BUNDLE", "PIP_CERT", "CARGO_HTTP_CAINFO", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY",
	"GRPC_PROXY", "RSYNC_PROXY", "CARGO_HTTP_PROXY", "HOSTALIASES", "LOCALDOMAIN", "RES_OPTIONS",
	"SSLKEYLOGFILE", "GIT_TRACE*",
}

// hijacks reports whether name matches one of hijackingVars.
func hijacks(name string) bool {
	name = strings.ToUpper(name)
	for _, pattern := range hijackingVars {
		if matched, _ := path.Match(pattern, name); matched {
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
// a variable from hijackingVars is refused outright. Errors name variables,
// never values.
func whole(c Credential) (map[string]string, error) {
	for _, variable := range c.Entry.VarNames() {
		if hijacks(variable) {
			return nil, fmt.Errorf("it declares %s, which can make a program run code or send its traffic "+
				"elsewhere; a copy may not carry one. Add it by hand on the machine that needs it", variable)
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
