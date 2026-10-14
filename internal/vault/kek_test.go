package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// decoyPassphrase sits in $BLINDFOLD_PASSPHRASE whenever a passphrase file is in
// use. The file must outrank it, and a regression then fails on the decoy
// instead of falling through to the real keychain.
const decoyPassphrase = "decoy-must-never-derive-the-key"

// usePassphraseFile points BLINDFOLD_PASSPHRASE_FILE at a new file with the
// given contents and permissions, and returns its path.
func usePassphraseFile(t *testing.T, contents string, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(path, []byte(contents), perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil { // WriteFile is subject to umask
		t.Fatal(err)
	}
	t.Setenv("BLINDFOLD_KEK_FILE", "")
	t.Setenv("BLINDFOLD_PASSPHRASE_FILE", path)
	t.Setenv("BLINDFOLD_PASSPHRASE", decoyPassphrase)
	return path
}

// Moving a passphrase from the environment into a file must not orphan the
// vault: same passphrase, same salt, same key. The newline is what
// `echo "$pw" > file` leaves behind.
func TestPassphraseFileUnlocksAVaultMadeWithTheEnvPassphrase(t *testing.T) {
	const passphrase, secret = "correct horse battery staple", "s3cr3t"
	dir := t.TempDir()
	t.Setenv("BLINDFOLD_KEK_FILE", "")
	t.Setenv("BLINDFOLD_PASSPHRASE_FILE", "")
	t.Setenv("BLINDFOLD_PASSPHRASE", passphrase)

	v, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := v.Put(sampleEntry(), map[string]string{"ES_API_KEY": secret}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	usePassphraseFile(t, passphrase+"\n", 0o600)
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.UnsealVar("cdp-es", "ES_API_KEY")
	if err != nil {
		t.Fatalf("UnsealVar with the passphrase file: %v", err)
	}
	if got != secret {
		t.Errorf("value = %q, want %q", got, secret)
	}
}

// BLINDFOLD_KEK_FILE is the most explicit source; a passphrase file must not
// shadow it, nor even be read.
func TestKEKFileOutranksPassphraseFile(t *testing.T) {
	dir := t.TempDir()
	usePassphraseFile(t, "", 0o644) // refused if it were read
	t.Setenv("BLINDFOLD_KEK_FILE", filepath.Join(dir, "kek"))

	v, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Init(); err != nil {
		t.Errorf("Init with a key file = %v; the passphrase file was consulted", err)
	}
}

// A passphrase file is refused, before init writes anything, when others can
// read it or when it holds no passphrase — an empty one would derive a key
// from nothing.
func TestPassphraseFileRefusals(t *testing.T) {
	cases := []struct {
		name     string
		contents string
		perm     os.FileMode
		missing  bool
		want     string
	}{
		{name: "readable by others", contents: "pw\n", perm: 0o644, want: "permissions"},
		{name: "empty", contents: "", perm: 0o600, want: "empty"},
		{name: "only a newline", contents: "\n", perm: 0o600, want: "empty"},
		{name: "missing", contents: "pw\n", perm: 0o600, missing: true, want: "no such file"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := usePassphraseFile(t, tc.contents, tc.perm)
			if tc.missing {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}

			v, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := v.Init(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Init error = %v, want one mentioning %q", err, tc.want)
			}
			if _, err := os.Stat(filepath.Join(dir, "kek.salt")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("Init wrote a salt despite refusing the passphrase file (stat: %v)", err)
			}
		})
	}
}

// A mistyped passphrase derives a key that opens nothing. Sealing a new entry
// under it would split the vault between two keys, so every write is refused
// until the right one is supplied — empty vault included.
func TestWrongPassphraseCannotWrite(t *testing.T) {
	cases := []struct {
		name     string
		existing bool
	}{
		{name: "vault with an entry", existing: true},
		{name: "empty vault", existing: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("BLINDFOLD_KEK_FILE", "")
			t.Setenv("BLINDFOLD_PASSPHRASE_FILE", "")
			t.Setenv("BLINDFOLD_PASSPHRASE", "right passphrase")
			v, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := v.Init(); err != nil {
				t.Fatalf("Init: %v", err)
			}
			if tc.existing {
				if err := v.Put(sampleEntry(), map[string]string{"ES_API_KEY": "s3cr3t"}); err != nil {
					t.Fatalf("Put: %v", err)
				}
			}
			sealedPath := filepath.Join(dir, SealedFile)
			before, _ := os.ReadFile(sealedPath)

			t.Setenv("BLINDFOLD_PASSPHRASE", "wrong passphrase")
			reopened, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			entry := Entry{Name: "pg-ro", Vars: []Var{{Name: "DATABASE_URL", Secret: true}}}
			err = reopened.Put(entry, map[string]string{"DATABASE_URL": "postgres://x"})
			if !errors.Is(err, ErrWrongKey) {
				t.Errorf("Put under the wrong passphrase = %v, want ErrWrongKey", err)
			}
			if after, _ := os.ReadFile(sealedPath); string(after) != string(before) {
				t.Error("the sealed file changed despite the refusal")
			}
		})
	}
}

// A vault whose key is gone cannot be adopted by a new one: init would seal new
// entries beside ciphertext no key opens any more.
func TestInitRefusesAnOrphanedVault(t *testing.T) {
	v := newTestVault(t)
	if err := v.Put(sampleEntry(), map[string]string{"ES_API_KEY": "s3cr3t"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(os.Getenv("BLINDFOLD_KEK_FILE")); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(v.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Init(); err == nil || !strings.Contains(err.Error(), SealedFile) {
		t.Errorf("Init over an orphaned vault = %v, want a refusal naming %s", err, SealedFile)
	}
}

// A version-2 vault of public entries has no data key to check a passphrase
// against. Reading it under a typo must not make the typo its key.
func TestWrongPassphraseCannotClaimAnUnverifiableUpgrade(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BLINDFOLD_KEK_FILE", "")
	t.Setenv("BLINDFOLD_PASSPHRASE_FILE", "")
	t.Setenv("BLINDFOLD_PASSPHRASE", "right passphrase")
	v, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Init(); err != nil {
		t.Fatal(err)
	}
	// As version 2 left it: metadata only, an empty sealed file with no check.
	v.meta.Upsert(Entry{Name: "flags", Vars: []Var{{Name: "FEATURE_X", Value: "on"}}})
	if err := v.saveMetadata(); err != nil {
		t.Fatal(err)
	}
	if err := v.saveSealed(&sealedFile{Version: sealedVersionVars, Entries: map[string]sealedEntry{}}); err != nil {
		t.Fatal(err)
	}

	t.Setenv("BLINDFOLD_PASSPHRASE", "wrong passphrase")
	typo, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := typo.Unseal("flags"); err != nil {
		t.Fatalf("read under the typo: %v", err)
	}

	t.Setenv("BLINDFOLD_PASSPHRASE", "right passphrase")
	right, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := right.Unseal("flags"); err != nil {
		t.Errorf("the right passphrase no longer opens the vault: %v", err)
	}
}
