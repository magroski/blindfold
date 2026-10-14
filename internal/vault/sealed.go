package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// The sealed file uses envelope encryption: every entry owns a random data key
// (DEK) which encrypts that entry's fields, and each DEK is itself wrapped by the
// master key (KEK). Rotating the KEK therefore rewraps a handful of small keys
// instead of re-encrypting every value.
//
// Each ciphertext is bound to its identity via AEAD additional data. A field is
// bound to "<entry>/<field>", so a value cannot be moved between entries or
// fields. The wrapped DEK is bound to the entry's name and declared variables,
// public values included, so cleartext metadata cannot be rewritten by hand and
// still unseal the secrets that go with it:
//
//	vault.json (cleartext)              vault.sealed
//	┌──────────────────────────┐        ┌────────────────────────────┐
//	│ cdp-es                   │  AAD   │ wrapped_dek   (under KEK)  │
//	│   ES_ENDPOINT=https://…  │ ─────▶ │   fields                   │
//	│   ES_API_KEY   (sealed)  │        │     ES_API_KEY (under DEK) │
//	└──────────────────────────┘        └────────────────────────────┘
//
// Point ES_ENDPOINT elsewhere without going through Put, and the DEK no longer
// opens — the API key stays sealed instead of being sent to the new host.

const (
	// sealedVersionLegacy bound each wrapped DEK to the entry name alone.
	sealedVersionLegacy = 1
	// sealedVersion binds it to the declared variables as well.
	sealedVersion = 2
)

// KeySize is the length of both the KEK and each DEK.
const KeySize = chacha20poly1305.KeySize

type sealedBox struct {
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ct"`
}

type sealedEntry struct {
	// WrappedDEK is this entry's data key, encrypted under the KEK.
	WrappedDEK sealedBox `json:"wrapped_dek"`
	// Fields maps a field name to its value encrypted under the DEK.
	Fields map[string]sealedBox `json:"fields"`
}

type sealedFile struct {
	Version int                    `json:"version"`
	Entries map[string]sealedEntry `json:"entries"`
}

var (
	// ErrWrongKey means the master key did not decrypt the vault. Usually the
	// Keychain item was replaced, or the wrong passphrase was supplied.
	ErrWrongKey = errors.New("vault: master key does not decrypt this vault")
	// ErrNoSuchField means the entry exists but carries no such sealed field.
	ErrNoSuchField = errors.New("vault: no such field")
)

func seal(key, plaintext, aad []byte) (sealedBox, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return sealedBox{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return sealedBox{}, fmt.Errorf("generate nonce: %w", err)
	}
	return sealedBox{Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, plaintext, aad)}, nil
}

func open(key []byte, box sealedBox, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(box.Nonce) != aead.NonceSize() {
		return nil, ErrWrongKey
	}
	out, err := aead.Open(nil, box.Nonce, box.Ciphertext, aad)
	if err != nil {
		return nil, ErrWrongKey
	}
	return out, nil
}

// aad binds a ciphertext to the entry and field it belongs to.
func aad(entry, field string) []byte { return []byte(entry + "/" + field) }

// dekAAD binds a wrapped data key to its entry: the name and every declared
// variable, public values included. Put re-binds on every change it makes;
// a change made to vault.json by hand leaves the key unopenable.
func dekAAD(e *Entry) []byte {
	vars, _ := json.Marshal(e.Vars) // strings and a bool: cannot fail
	return append([]byte("dek/"+e.Name+"/"), vars...)
}

// legacyDekAAD is what version-1 files bound a wrapped data key to.
func legacyDekAAD(entry string) []byte { return []byte("dek/" + entry) }

func newKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return key, nil
}

// dek unwraps an entry's data key under the metadata it is bound to.
func (s *sealedFile) dek(kek []byte, e *Entry) (sealedEntry, []byte, error) {
	entry, ok := s.Entries[e.Name]
	if !ok {
		return sealedEntry{}, nil, fmt.Errorf("vault: %q has no sealed values", e.Name)
	}
	dek, err := open(kek, entry.WrappedDEK, dekAAD(e))
	if err != nil {
		return sealedEntry{}, nil, fmt.Errorf("%w, or %s was edited by hand: %q will not unseal",
			err, MetadataFile, e.Name)
	}
	return entry, dek, nil
}

// setFields seals values for one entry, replacing any fields of the same name
// and preserving the rest. It reuses the entry's existing DEK when present so
// unchanged fields keep their ciphertext.
func (s *sealedFile) setFields(kek []byte, e *Entry, values map[string]string) error {
	if s.Entries == nil {
		s.Entries = map[string]sealedEntry{}
	}

	entry, exists := s.Entries[e.Name]
	var dek []byte
	if exists {
		var err error
		if entry, dek, err = s.dek(kek, e); err != nil {
			return err
		}
	} else {
		var err error
		if dek, err = newKey(); err != nil {
			return err
		}
		wrapped, err := seal(kek, dek, dekAAD(e))
		if err != nil {
			return err
		}
		entry = sealedEntry{WrappedDEK: wrapped, Fields: map[string]sealedBox{}}
	}
	if entry.Fields == nil {
		entry.Fields = map[string]sealedBox{}
	}

	for field, value := range values {
		box, err := seal(dek, []byte(value), aad(e.Name, field))
		if err != nil {
			return err
		}
		entry.Fields[field] = box
	}

	s.Entries[e.Name] = entry
	return nil
}

// rebind re-wraps an entry's data key under changed metadata. An unchanged
// binding, or no sealed entry at all, is left alone.
func (s *sealedFile) rebind(kek []byte, old, updated *Entry) error {
	entry, ok := s.Entries[updated.Name]
	if !ok || bytes.Equal(dekAAD(old), dekAAD(updated)) {
		return nil
	}
	_, dek, err := s.dek(kek, old)
	if err != nil {
		return err
	}
	if entry.WrappedDEK, err = seal(kek, dek, dekAAD(updated)); err != nil {
		return err
	}
	s.Entries[updated.Name] = entry
	return nil
}

// migrate re-wraps every data key of a version-1 file under the current
// binding. A sealed entry the metadata no longer lists is unreachable, and is
// dropped.
//
// This runs the first time the master key is in hand after upgrading, which is
// also the one window a tamperer has: a copy of the version-1 file taken before
// then still opens under the old binding.
func (s *sealedFile) migrate(kek []byte, meta *Metadata) error {
	if s.Version == sealedVersion {
		return nil
	}
	for name, entry := range s.Entries {
		e, ok := meta.Find(name)
		if !ok {
			delete(s.Entries, name)
			continue
		}
		dek, err := open(kek, entry.WrappedDEK, legacyDekAAD(name))
		if err != nil {
			return err
		}
		if entry.WrappedDEK, err = seal(kek, dek, dekAAD(e)); err != nil {
			return err
		}
		s.Entries[name] = entry
	}
	s.Version = sealedVersion
	return nil
}

// getFields unseals every field of one entry.
func (s *sealedFile) getFields(kek []byte, e *Entry) (map[string]string, error) {
	entry, dek, err := s.dek(kek, e)
	if err != nil {
		return nil, err
	}

	out := make(map[string]string, len(entry.Fields))
	for field, box := range entry.Fields {
		value, err := open(dek, box, aad(e.Name, field))
		if err != nil {
			return nil, fmt.Errorf("vault: field %q of %q: %w", field, e.Name, err)
		}
		out[field] = string(value)
	}
	return out, nil
}

// getField unseals a single field, avoiding the cost of the whole entry.
func (s *sealedFile) getField(kek []byte, e *Entry, field string) (string, error) {
	entry, ok := s.Entries[e.Name]
	if !ok {
		return "", fmt.Errorf("vault: %q has no sealed values", e.Name)
	}
	box, ok := entry.Fields[field]
	if !ok {
		return "", ErrNoSuchField
	}
	_, dek, err := s.dek(kek, e)
	if err != nil {
		return "", err
	}
	value, err := open(dek, box, aad(e.Name, field))
	if err != nil {
		return "", err
	}
	return string(value), nil
}

// hasField reports whether ciphertext exists for one field.
func (s *sealedFile) hasField(entryName, field string) bool {
	entry, ok := s.Entries[entryName]
	if !ok {
		return false
	}
	_, ok = entry.Fields[field]
	return ok
}

// retainFields drops any sealed field the entry no longer declares, so a removed
// variable leaves no ciphertext behind.
func (s *sealedFile) retainFields(entryName string, keep []string) {
	entry, ok := s.Entries[entryName]
	if !ok {
		return
	}
	wanted := make(map[string]bool, len(keep))
	for _, name := range keep {
		wanted[name] = true
	}
	for field := range entry.Fields {
		if !wanted[field] {
			delete(entry.Fields, field)
		}
	}
	s.Entries[entryName] = entry
}

func (s *sealedFile) remove(entryName string) { delete(s.Entries, entryName) }

// marshal keeps the file's version: a version-1 file touched without the master
// key, by Remove, stays version 1 until a key-holding command upgrades it.
func (s *sealedFile) marshal() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

func unmarshalSealed(data []byte) (*sealedFile, error) {
	if len(data) == 0 {
		return &sealedFile{Version: sealedVersion, Entries: map[string]sealedEntry{}}, nil
	}
	s := &sealedFile{}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("vault: sealed file is corrupt: %w", err)
	}
	if s.Version != sealedVersionLegacy && s.Version != sealedVersion {
		return nil, fmt.Errorf("vault: sealed file version %d is not supported", s.Version)
	}
	if s.Entries == nil {
		s.Entries = map[string]sealedEntry{}
	}
	return s, nil
}
