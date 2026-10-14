//go:build linux

package vault

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

// envTestSecretService opts in to the tests that need a real Secret Service,
// and they delete items. scripts/test.sh starts gnome-keyring on a private bus
// with a throwaway XDG_DATA_HOME, and sets this to that same directory: a
// value that does not match is refused, so a keyring of yours is never touched.
const envTestSecretService = "BLINDFOLD_TEST_SECRET_SERVICE"

const methodDeleteItem = "org.freedesktop.Secret.Item.Delete"

// secretServiceForTest skips unless opted in, and leaves no blindfold item
// behind before or after the test.
func secretServiceForTest(t *testing.T) *secretService {
	t.Helper()
	keyringData := os.Getenv(envTestSecretService)
	if keyringData == "" {
		t.Skipf("run through scripts/test.sh, which provides a disposable Secret Service")
	}
	if keyringData != os.Getenv("XDG_DATA_HOME") {
		t.Fatalf("%s must name the throwaway XDG_DATA_HOME the test keyring runs from", envTestSecretService)
	}
	s, err := connectSecretService()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		deleteKeyItems(t, s)
		s.close()
	})
	deleteKeyItems(t, s)
	return s
}

func deleteKeyItems(t *testing.T, s *secretService) {
	t.Helper()
	var unlocked, locked []dbus.ObjectPath
	if err := s.call(secretsPath, methodSearchItems, []any{keyAttributes()}, &unlocked, &locked); err != nil {
		t.Fatal(err)
	}
	for _, item := range append(unlocked, locked...) {
		var prompt dbus.ObjectPath
		if err := s.call(item, methodDeleteItem, nil, &prompt); err != nil {
			t.Fatal(err)
		}
	}
}

// createItem plants an item carrying blindfold's attributes, as any other
// program running as the user could.
func createItem(t *testing.T, s *secretService, value string) {
	t.Helper()
	var collection, item, prompt dbus.ObjectPath
	if err := s.call(secretsPath, methodReadAlias, []any{defaultAlias}, &collection); err != nil {
		t.Fatal(err)
	}
	properties := map[string]dbus.Variant{
		propLabel:      dbus.MakeVariant("planted"),
		propAttributes: dbus.MakeVariant(keyAttributes()),
	}
	planted := secret{Session: s.session, Parameters: []byte{}, Value: []byte(value), ContentType: keyContentType}
	if err := s.call(collection, methodCreateItem, []any{properties, planted, false}, &item, &prompt); err != nil {
		t.Fatal(err)
	}
}

func TestSecretServiceStoresAndLoadsTheKey(t *testing.T) {
	secretServiceForTest(t)
	source := &secretServiceSource{}

	if _, err := source.Load(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Load before Store = %v, want ErrNoKey", err)
	}
	key, err := newKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Store(key); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, err := source.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Error("Load returned a different key than Store was given")
	}
}

// Overwriting the key would orphan every value sealed under it.
func TestSecretServiceRefusesToOverwriteTheKey(t *testing.T) {
	secretServiceForTest(t)
	source := &secretServiceSource{}
	first, _ := newKey()
	second, _ := newKey()
	if err := source.Store(first); err != nil {
		t.Fatal(err)
	}

	if err := source.Store(second); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("second Store = %v, want a refusal", err)
	}
	if got, _ := source.Load(); !bytes.Equal(got, first) {
		t.Error("the original key was replaced")
	}
}

// Any program can create an item with blindfold's attributes. Two matches are
// refused, not guessed between.
func TestSecretServiceRefusesAmbiguousItems(t *testing.T) {
	s := secretServiceForTest(t)
	source := &secretServiceSource{}
	key, _ := newKey()
	if err := source.Store(key); err != nil {
		t.Fatal(err)
	}
	planted, _ := newKey()
	createItem(t, s, base64.StdEncoding.EncodeToString(planted))

	if _, err := source.Load(); err == nil || !strings.Contains(err.Error(), "refusing to guess") {
		t.Errorf("Load with two matching items = %v, want a refusal", err)
	}
}

// An item that does not hold a key is reported without echoing its contents.
func TestSecretServiceRejectsAMalformedItem(t *testing.T) {
	s := secretServiceForTest(t)
	const contents = "not-a-key-and-not-for-printing"
	createItem(t, s, contents)

	_, err := (&secretServiceSource{}).Load()
	if err == nil || strings.Contains(err.Error(), contents) {
		t.Errorf("Load of a malformed item = %v, want an error that does not quote it", err)
	}
}

// With no key-source variables set, Linux uses the Secret Service end to end.
func TestVaultUsesTheSecretServiceByDefault(t *testing.T) {
	secretServiceForTest(t)
	t.Setenv("BLINDFOLD_KEK_FILE", "")
	t.Setenv("BLINDFOLD_PASSPHRASE_FILE", "")
	t.Setenv("BLINDFOLD_PASSPHRASE", "")
	dir := filepath.Join(t.TempDir(), "vault")

	v, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := v.Put(sampleEntry(), map[string]string{"ES_API_KEY": "s3cr3t"}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reopened.UnsealVar("cdp-es", "ES_API_KEY"); err != nil || got != "s3cr3t" {
		t.Errorf("UnsealVar = %q, %v", got, err)
	}
}

// Without a session bus there is no keyring to fall back on, and the error
// says what to use instead.
func TestNoSessionBusExplainsTheAlternatives(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	_, err := (&secretServiceSource{}).Load()
	if err == nil || !strings.Contains(err.Error(), "BLINDFOLD_PASSPHRASE_FILE") {
		t.Errorf("Load with no session bus = %v, want one naming the alternatives", err)
	}
}
