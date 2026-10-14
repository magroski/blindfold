package vault

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
)

// KeySource supplies the master key (KEK) that wraps every entry's data key.
type KeySource interface {
	// Load returns the master key, or ErrNoKey if none has been created yet.
	Load() ([]byte, error)
	// Store persists a newly generated master key.
	Store(key []byte) error
	// Describe reports exactly where this source reads from, so `blindfold doctor` can
	// show the user precisely what will be touched.
	Describe() string
}

// ErrNoKey means no master key exists yet — the vault has not been initialized.
var ErrNoKey = errors.New("vault: no master key found")

// Keychain identity. Both attributes are always supplied together; see
// kek_darwin.go for why that matters.
const (
	KeychainService = "com.magroski.blindfold"
	KeychainAccount = "vault-kek"
)

// keyFileHelp names the key sources that need no OS keychain.
const keyFileHelp = "point BLINDFOLD_PASSPHRASE_FILE at a 0600 passphrase file, or BLINDFOLD_KEK_FILE at a 0600 key file"

// Environment variables that select the key source; see NewKeySource.
const (
	envKEKFile        = "BLINDFOLD_KEK_FILE"
	envPassphraseFile = "BLINDFOLD_PASSPHRASE_FILE"
	envPassphrase     = "BLINDFOLD_PASSPHRASE"
)

// NewKeySource picks a key source from the environment, most explicit first.
//
//	BLINDFOLD_KEK_FILE         a 0600 file holding a base64 master key
//	BLINDFOLD_PASSPHRASE_FILE  a 0600 file holding a passphrase (CI, Linux, SSH)
//	BLINDFOLD_PASSPHRASE       the passphrase itself; every child process inherits it
//	(default)                 the OS keychain: macOS Keychain, or Secret Service on Linux
func NewKeySource(dir string) KeySource {
	saltPath := filepath.Join(dir, "kek.salt")
	if path := os.Getenv(envKEKFile); path != "" {
		return &fileSource{path: path}
	}
	if path := os.Getenv(envPassphraseFile); path != "" {
		return &passphraseSource{file: path, saltPath: saltPath}
	}
	if passphrase := os.Getenv(envPassphrase); passphrase != "" {
		return &passphraseSource{passphrase: passphrase, saltPath: saltPath}
	}
	return newOSKeySource()
}

// PassphraseFromEnv reports whether the master key is derived from
// $BLINDFOLD_PASSPHRASE. Every command the shell runs inherits that variable, an
// agent's included, so `blindfold doctor` warns about it.
func PassphraseFromEnv() bool {
	source, ok := NewKeySource("").(*passphraseSource)
	return ok && source.file == ""
}

// fileSource keeps the master key in a 0600 file. It has no keychain surface at
// all, which some people prefer; at rest it is only as strong as the filesystem.
type fileSource struct{ path string }

func (f *fileSource) Describe() string { return "key file " + f.path }

func (f *fileSource) Load() ([]byte, error) {
	data, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, err
	}
	if err := checkPrivatePerms(f.path); err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("vault: key file %s is not valid base64: %w", f.path, err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("vault: key file %s holds %d bytes, want %d", f.path, len(key), KeySize)
	}
	return key, nil
}

func (f *fileSource) Store(key []byte) error {
	// Committed by accident, the key would open every copy of the vault.
	if repo, inRepo := enclosingGitRepo(filepath.Dir(f.path)); inRepo {
		return fmt.Errorf("vault: refusing to write the master key inside the git repository at %s; "+
			"keys belong outside version control", repo)
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	return writePrivate(f.path, []byte(encoded+"\n"))
}

// passphraseSource derives the master key from a passphrase with argon2id. The
// salt is stored alongside the vault; it is not secret.
type passphraseSource struct {
	passphrase string // from $BLINDFOLD_PASSPHRASE, when file is unset
	file       string // $BLINDFOLD_PASSPHRASE_FILE, read on every load
	saltPath   string
}

func (p *passphraseSource) Describe() string {
	if p.file != "" {
		return "passphrase file " + p.file + " (salt " + p.saltPath + ")"
	}
	return "passphrase from $" + envPassphrase + " (salt " + p.saltPath + ")"
}

// read returns the passphrase. A file is held to the key file's permission
// rule and loses trailing newlines exactly as `$(cat file)` would, so moving a
// passphrase from the environment into a file derives the same key.
func (p *passphraseSource) read() (string, error) {
	if p.file == "" {
		return p.passphrase, nil
	}
	if err := checkPrivatePerms(p.file); err != nil {
		return "", err
	}
	data, err := os.ReadFile(p.file)
	if err != nil {
		return "", err
	}
	passphrase := strings.TrimRight(string(data), "\n")
	if passphrase == "" {
		return "", fmt.Errorf("vault: passphrase file %s is empty", p.file)
	}
	return passphrase, nil
}

// Argon2id parameters, chosen for an interactive-latency unlock on a laptop.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	saltSize     = 16
)

// Load reads the passphrase before the salt, so a bad passphrase file stops
// `init` before it writes one.
func (p *passphraseSource) Load() ([]byte, error) {
	passphrase, err := p.read()
	if err != nil {
		return nil, err
	}
	salt, err := os.ReadFile(p.saltPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, err
	}
	return derive(passphrase, salt), nil
}

// Store records a fresh salt. The key itself is never written: it is recomputed
// from the passphrase on every load, so the supplied key is discarded.
func (p *passphraseSource) Store([]byte) error {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.saltPath), 0o700); err != nil {
		return err
	}
	return writePrivate(p.saltPath, salt)
}

func derive(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, KeySize)
}
