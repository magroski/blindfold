package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// File names within the vault directory.
const (
	MetadataFile = "vault.json"   // cleartext index; readable without the master key
	SealedFile   = "vault.sealed" // encrypted values
	AuditFile    = "audit.log"
)

// DefaultDir is where the vault lives regardless of the working directory. It is
// deliberately not project-relative: a per-repo vault would end up committed.
//
// BLINDFOLD_DIR overrides it, which tests and CI need in order to run against
// a throwaway vault.
func DefaultDir() (string, error) {
	if dir := os.Getenv("BLINDFOLD_DIR"); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("vault: locating home directory: %w", err)
	}
	return filepath.Join(home, ".blindfold"), nil
}

// Vault is an open vault. Construction loads only the cleartext metadata; the
// master key is fetched lazily, so listing never touches it.
type Vault struct {
	dir  string
	meta *Metadata
	keys KeySource

	kek []byte // cached after first unseal, for the life of this process

	// exists is true once dir holds a vault that init created. A key alone does
	// not make one: it may have been made for another directory, or planted.
	exists bool
}

// Open loads vault metadata from dir, creating neither files nor keys. A missing
// vault opens as an empty one so `list` works before `init`.
func Open(dir string) (*Vault, error) {
	v := &Vault{
		dir:  dir,
		meta: &Metadata{Version: metadataVersion},
		keys: NewKeySource(dir),
	}
	if err := v.loadMetadata(); err != nil {
		return nil, err
	}
	return v, nil
}

// loadMetadata reads vault.json, if there is one, over v's metadata.
func (v *Vault) loadMetadata() error {
	data, err := os.ReadFile(filepath.Join(v.dir, MetadataFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	meta := &Metadata{Version: metadataVersion}
	if err := json.Unmarshal(data, meta); err != nil {
		return fmt.Errorf("vault: %s is corrupt: %w", MetadataFile, err)
	}
	if meta.Version != metadataVersion {
		return fmt.Errorf("vault: %s has version %d, this build supports %d. "+
			"Version 1 vaults were written by the kind-based (database/http/env) layout; "+
			"there is no automatic migration — re-add the entries",
			MetadataFile, meta.Version, metadataVersion)
	}
	v.meta, v.exists = meta, true
	return nil
}

// Dir reports the vault directory.
func (v *Vault) Dir() string { return v.dir }

// KeySourceDescription reports where the master key comes from, for `blindfold doctor`.
func (v *Vault) KeySourceDescription() string { return v.keys.Describe() }

// Exists reports whether init has run here. Unlike Initialized, it never
// touches the master key.
func (v *Vault) Exists() bool { return v.exists }

// Initialized reports whether init has run here and the master key loads.
func (v *Vault) Initialized() bool {
	if !v.exists {
		return false
	}
	_, err := v.keys.Load()
	return err == nil
}

// Init creates the vault directory and a fresh master key. It refuses to run
// inside a git work tree: a vault committed by accident is the failure this
// project exists to prevent.
func (v *Vault) Init() error {
	if repo, inRepo := enclosingGitRepo(v.dir); inRepo {
		return fmt.Errorf("vault: refusing to create a vault inside the git repository at %s; "+
			"vaults belong outside version control", repo)
	}
	_, err := v.keys.Load()
	if err == nil && v.exists {
		return errors.New("vault: a master key already exists; `blindfold init` would orphan the current vault")
	}
	// The key is adopted by no vault but the one it was made with: a planted
	// one would see every secret sealed from here on.
	if err == nil {
		return fmt.Errorf("vault: a master key already exists (%s), but %s holds no vault; "+
			"blindfold will not adopt a key it did not create here. If it is left over from a vault "+
			"you removed, delete it first, or point BLINDFOLD_DIR at the vault it belongs to",
			v.keys.Describe(), v.dir)
	}
	if !errors.Is(err, ErrNoKey) {
		return err
	}
	// Values sealed under a key that is gone would sit beside new ones sealed
	// under the next, and no single key would open the vault.
	sealed, err := v.loadSealed()
	if err != nil {
		return err
	}
	if len(sealed.Entries) > 0 || sealed.Check != nil {
		return fmt.Errorf("vault: %s was sealed under a master key that cannot be found; "+
			"restore that key, or move %s and %s out of %s to start over",
			SealedFile, SealedFile, MetadataFile, v.dir)
	}

	if err := os.MkdirAll(v.dir, 0o700); err != nil {
		return err
	}

	key, err := newKey()
	if err != nil {
		return err
	}
	if err := v.keys.Store(key); err != nil {
		return err
	}
	// A passphrase source recomputes its key from the salt it just wrote, so
	// reload rather than trusting the value we generated.
	if v.kek, err = v.keys.Load(); err != nil {
		return err
	}
	if err := sealed.addCheck(v.kek); err != nil {
		return err
	}
	if err := v.saveSealed(sealed); err != nil {
		return err
	}
	if err := v.saveMetadata(); err != nil {
		return err
	}
	v.exists = true
	return nil
}

// masterKey fetches and caches the master key.
func (v *Vault) masterKey() ([]byte, error) {
	if v.kek != nil {
		return v.kek, nil
	}
	key, err := v.keys.Load()
	if errors.Is(err, ErrNoKey) {
		return nil, errors.New("vault: not initialized — run `blindfold init` first")
	}
	if err != nil {
		return nil, err
	}
	v.kek = key
	return key, nil
}

// List returns every entry, sorted by name. No master key required.
func (v *Vault) List() []Entry { return v.meta.Entries }

// Get returns one entry's metadata. No master key required.
func (v *Vault) Get(name string) (*Entry, bool) { return v.meta.Find(name) }

// Put stores an entry together with its secret values. Variables absent from
// values keep whatever was previously sealed, so a metadata edit need not
// resupply the password.
//
// Sealed values for variables the entry no longer declares are dropped, so
// removing a variable really removes it rather than leaving ciphertext behind.
func (v *Vault) Put(entry Entry, values map[string]string) error {
	if !v.exists {
		return errors.New("vault: not initialized — run `blindfold init` first")
	}
	if err := entry.Validate(); err != nil {
		return err
	}
	for name, value := range values {
		if v, ok := entry.Var(name); !ok || !v.Secret {
			return fmt.Errorf("vault: %q supplies a value for %s, which it does not declare as secret",
				entry.Name, name)
		}
		if err := validateValue(name, value); err != nil {
			return err
		}
	}

	kek, err := v.masterKey()
	if err != nil {
		return err
	}
	sealed, err := v.openSealed(kek)
	if err != nil {
		return err
	}
	// Start from vault.json as it is now, as the sealed file just was: a
	// process held open — the sync picker, a box's sync-serve — would
	// otherwise write back what it read at start over changes made since.
	if err := v.loadMetadata(); err != nil {
		return err
	}
	if old, ok := v.meta.Find(entry.Name); ok {
		// The data key is bound to the declared variables: a change made here
		// re-binds it, where one made to vault.json by hand would not.
		if err := sealed.rebind(kek, old, &entry); err != nil {
			return err
		}
	} else {
		// A sealed entry with no metadata is left over from an interrupted write.
		sealed.remove(entry.Name)
	}
	// Every entry gets a data key, secrets or not: it is what vouches for it.
	if err := sealed.setFields(kek, &entry, values); err != nil {
		return err
	}
	sealed.retainFields(entry.Name, entry.SecretNames())

	// Every declared secret must actually have ciphertext, or the entry would
	// promise a variable that `env` cannot produce.
	for _, name := range entry.SecretNames() {
		if !sealed.hasField(entry.Name, name) {
			return fmt.Errorf("vault: %s of %q has no value; supply one", name, entry.Name)
		}
	}

	now := time.Now().UTC()
	entry.UpdatedAt = now
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = now
	}
	v.meta.Upsert(entry)

	if err := v.saveSealed(sealed); err != nil {
		return err
	}
	return v.saveMetadata()
}

// UnsealVar unseals a single variable's value.
func (v *Vault) UnsealVar(name, field string) (string, error) {
	entry, kek, sealed, err := v.unsealer(name)
	if err != nil {
		return "", err
	}
	return sealed.getField(kek, entry, field)
}

// Unseal returns every sealed value for an entry. Callers must not log the
// result.
func (v *Vault) Unseal(name string) (map[string]string, error) {
	entry, kek, sealed, err := v.unsealer(name)
	if err != nil {
		return nil, err
	}
	return sealed.getFields(kek, entry)
}

// unsealer gathers what unsealing needs: the entry's metadata, which its data
// key is bound to, the master key, and the sealed file.
func (v *Vault) unsealer(name string) (*Entry, []byte, *sealedFile, error) {
	entry, ok := v.meta.Find(name)
	if !ok {
		return nil, nil, nil, fmt.Errorf("vault: no entry named %q", name)
	}
	kek, err := v.masterKey()
	if err != nil {
		return nil, nil, nil, err
	}
	sealed, err := v.openSealed(kek)
	if err != nil {
		return nil, nil, nil, err
	}
	return entry, kek, sealed, nil
}

// Remove deletes an entry and its sealed values.
func (v *Vault) Remove(name string) error {
	if !v.meta.Remove(name) {
		return fmt.Errorf("vault: no entry named %q", name)
	}
	sealed, err := v.loadSealed()
	if err != nil {
		return err
	}
	sealed.remove(name)
	if err := v.saveSealed(sealed); err != nil {
		return err
	}
	return v.saveMetadata()
}

func (v *Vault) loadSealed() (*sealedFile, error) {
	data, err := os.ReadFile(filepath.Join(v.dir, SealedFile))
	if errors.Is(err, os.ErrNotExist) {
		return unmarshalSealed(nil)
	}
	if err != nil {
		return nil, err
	}
	return unmarshalSealed(data)
}

// openSealed loads the sealed file for a caller holding the master key. A
// version-1 file is upgraded in place first: its data keys were bound to entry
// names alone, and must be re-bound to the metadata they belong to.
func (v *Vault) openSealed(kek []byte) (*sealedFile, error) {
	sealed, err := v.loadSealed()
	if err != nil {
		return nil, err
	}
	upgrade, verified := sealed.Version != sealedVersion, false
	if upgrade {
		if verified, err = sealed.migrate(kek, v.meta); err != nil {
			return nil, err
		}
	}
	// A wrong key stops here, before anything is sealed under it.
	if err := sealed.verifyKey(kek, v.meta); err != nil {
		return nil, err
	}
	// An upgrade is saved, check included, once an old data key vouched for the
	// master key. With none to vouch, a read must not make a mistyped
	// passphrase the vault's key; the next write saves the upgrade instead.
	if upgrade && verified {
		if err := v.saveSealed(sealed); err != nil {
			return nil, err
		}
	}
	return sealed, nil
}

func (v *Vault) saveSealed(s *sealedFile) error {
	data, err := s.marshal()
	if err != nil {
		return err
	}
	return writePrivate(filepath.Join(v.dir, SealedFile), data)
}

func (v *Vault) saveMetadata() error {
	v.meta.Version = metadataVersion
	data, err := json.MarshalIndent(v.meta, "", "  ")
	if err != nil {
		return err
	}
	return writePrivate(filepath.Join(v.dir, MetadataFile), append(data, '\n'))
}

// writePrivate writes data atomically with 0600 permissions, so a reader never
// observes a half-written vault and no file is briefly world-readable.
func writePrivate(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// checkPrivatePerms rejects a key file that others can read.
func checkPrivatePerms(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("vault: %s has permissions %04o; run `chmod 600 %s`", path, mode, path)
	}
	return nil
}

// enclosingGitRepo reports the nearest ancestor of dir containing a .git entry.
func enclosingGitRepo(dir string) (string, bool) {
	path, err := filepath.Abs(dir)
	if err != nil {
		return "", false
	}
	for {
		if _, err := os.Stat(filepath.Join(path, ".git")); err == nil {
			return path, true
		}
		parent := filepath.Dir(path)
		if parent == path {
			return "", false
		}
		path = parent
	}
}
