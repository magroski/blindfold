package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// Remote is a dev box this vault pushes to and pulls from.
type Remote struct {
	Name string `json:"name"`
	// Destination is what ssh connects to: host, user@host, or a
	// ~/.ssh/config alias.
	Destination string `json:"destination"`
	// Bin is blindfold on the box, for a PATH that a non-interactive SSH
	// session does not search.
	Bin string `json:"bin,omitempty"`
}

// DefaultRemoteBin is the command run on a box that names no other.
const DefaultRemoteBin = "blindfold"

// remotesAAD binds the sealed registry. It holds no "/", so it can be neither a
// field's AAD nor a data key's.
var remotesAAD = []byte("remotes")

// The registry is sealed rather than kept in cleartext beside vault.json: it
// decides where `push` sends values, and a hand edit that repointed a box would
// send them to whoever it named.

// validate refuses what could read as an ssh option, split a word, or reach a
// terminal: the destination is an ssh argument, the bin a word for the remote
// shell.
func (r Remote) validate() error {
	if ValidateEntryName(r.Name) != nil {
		return fmt.Errorf("vault: %q is not a usable box name; use letters, digits, and - _ ., "+
			"not starting with -", r.Name)
	}
	if r.Destination == "" {
		return errors.New("vault: a box needs an ssh destination")
	}
	// "-oProxyCommand=…" would be an ssh option, not a host.
	if strings.HasPrefix(r.Destination, "-") {
		return errors.New("vault: an ssh destination may not start with -")
	}
	if strings.IndexFunc(r.Destination, isSpaceOrControl) >= 0 {
		return errors.New("vault: an ssh destination may not contain spaces or control characters")
	}
	// A ProxyCommand's %h hands the destination to a shell; "box;touch x"
	// would run there.
	if strings.IndexFunc(r.Destination, isUnsafeInDestination) >= 0 {
		return errors.New("vault: an ssh destination may hold only letters, digits and . _ - @ : / [ ] % +")
	}
	// The bin reaches the box's login shell — sh, zsh or fish — unquoted, so
	// it is held to characters every one of them reads literally, plus a
	// leading ~ they all expand: ~/go/bin/blindfold, /opt/bin/blindfold.
	if strings.HasPrefix(r.Bin, "-") || strings.IndexFunc(r.Bin, isUnsafeInBin) >= 0 {
		return errors.New("vault: the remote blindfold path may hold only letters, digits and / . _ - ~ +, " +
			"and may not start with -")
	}
	return nil
}

func isUnsafeInBin(r rune) bool {
	safe := r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("/._-~+", r))
	return !safe
}

func isSpaceOrControl(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }

// isUnsafeInDestination is anything a shell reads as syntax. What is left
// still spells every destination ssh takes: alias, user@host, ssh://h:22,
// [fe80::1%en0].
func isUnsafeInDestination(r rune) bool {
	safe := r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._-@:/[]%+", r))
	return !safe
}

// Remotes lists the registered boxes, sorted by name. It needs the master key:
// the registry is sealed.
func (v *Vault) Remotes() ([]Remote, error) {
	kek, err := v.masterKey()
	if err != nil {
		return nil, err
	}
	sealed, err := v.openSealed(kek)
	if err != nil {
		return nil, err
	}
	return sealed.remotes(kek)
}

// AddRemote registers a box.
func (v *Vault) AddRemote(r Remote) error {
	if err := r.validate(); err != nil {
		return err
	}
	if r.Bin == DefaultRemoteBin {
		r.Bin = ""
	}
	return v.updateRemotes(func(remotes []Remote) ([]Remote, error) {
		for _, existing := range remotes {
			if existing.Name == r.Name {
				return nil, fmt.Errorf("vault: a box named %q exists; remove it first", r.Name)
			}
		}
		return append(remotes, r), nil
	})
}

// RemoveRemote forgets a box. The box's own vault is untouched.
func (v *Vault) RemoveRemote(name string) error {
	return v.updateRemotes(func(remotes []Remote) ([]Remote, error) {
		for i, existing := range remotes {
			if existing.Name == name {
				return append(remotes[:i], remotes[i+1:]...), nil
			}
		}
		return nil, fmt.Errorf("vault: no box named %q", name)
	})
}

// updateRemotes applies change to the registry and seals the result.
func (v *Vault) updateRemotes(change func([]Remote) ([]Remote, error)) error {
	if !v.exists {
		return errors.New("vault: not initialized — run `blindfold init` first")
	}
	kek, err := v.masterKey()
	if err != nil {
		return err
	}
	sealed, err := v.openSealed(kek)
	if err != nil {
		return err
	}
	remotes, err := sealed.remotes(kek)
	if err != nil {
		return err
	}
	if remotes, err = change(remotes); err != nil {
		return err
	}
	if err := sealed.setRemotes(kek, remotes); err != nil {
		return err
	}
	return v.saveSealed(sealed)
}

// remotes unseals the registry, filling in the default bin.
func (s *sealedFile) remotes(kek []byte) ([]Remote, error) {
	if s.Remotes == nil {
		return []Remote{}, nil
	}
	data, err := open(kek, *s.Remotes, remotesAAD)
	if err != nil {
		return nil, fmt.Errorf("vault: the box registry in %s was edited by hand, and will not be used", SealedFile)
	}
	var remotes []Remote
	if err := json.Unmarshal(data, &remotes); err != nil {
		return nil, fmt.Errorf("vault: the box registry is corrupt: %w", err)
	}
	for i := range remotes {
		if remotes[i].Bin == "" {
			remotes[i].Bin = DefaultRemoteBin
		}
	}
	return remotes, nil
}

func (s *sealedFile) setRemotes(kek []byte, remotes []Remote) error {
	sort.Slice(remotes, func(i, j int) bool { return remotes[i].Name < remotes[j].Name })
	data, err := json.Marshal(remotes)
	if err != nil {
		return err
	}
	box, err := seal(kek, data, remotesAAD)
	if err != nil {
		return err
	}
	s.Remotes = &box
	return nil
}
