//go:build darwin

package vault

import (
	"errors"
	"fmt"

	"github.com/keybase/go-keychain"
)

// keychainSource holds the master key in one macOS Keychain generic-password
// item.
//
// Every query below supplies BOTH the service and the account attribute and sets
// MatchLimitOne. That is the whole safety story on our side: this package never
// issues a query that could match an item it did not create, and never uses a
// match-limit-all query. macOS enforces the rest — an item's ACL only grants
// silent access to the binary that created it, so reading anything else would
// raise a user-visible prompt rather than succeeding quietly.
//
// keychain_guard_test.go asserts the absence of enumeration APIs so this property
// cannot regress unnoticed.
type keychainSource struct{}

func newOSKeySource() KeySource { return &keychainSource{} }

func (k *keychainSource) Describe() string {
	return fmt.Sprintf("macOS Keychain item (service=%q account=%q) — the only item this binary reads",
		KeychainService, KeychainAccount)
}

// query builds the one exact-match query this package ever performs.
func (k *keychainSource) query() keychain.Item {
	q := keychain.NewItem()
	q.SetSecClass(keychain.SecClassGenericPassword)
	q.SetService(KeychainService)
	q.SetAccount(KeychainAccount)
	q.SetMatchLimit(keychain.MatchLimitOne)
	return q
}

func (k *keychainSource) Load() ([]byte, error) {
	q := k.query()
	q.SetReturnData(true)

	results, err := keychain.QueryItem(q)
	if err != nil {
		return nil, fmt.Errorf("vault: reading keychain: %w", err)
	}
	if len(results) == 0 {
		return nil, ErrNoKey
	}

	key := results[0].Data
	if len(key) != KeySize {
		return nil, fmt.Errorf("vault: keychain item holds %d bytes, want %d "+
			"(delete it with `security delete-generic-password -s %s -a %s` and restore from a backup)",
			len(key), KeySize, KeychainService, KeychainAccount)
	}
	return key, nil
}

func (k *keychainSource) Store(key []byte) error {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(KeychainService)
	item.SetAccount(KeychainAccount)
	item.SetLabel("blindfold master key")
	item.SetData(key)
	// The key is machine-local and must never sync to iCloud.
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlockedThisDeviceOnly)

	err := keychain.AddItem(item)
	if errors.Is(err, keychain.ErrorDuplicateItem) {
		return fmt.Errorf("vault: a master key already exists in the keychain; " +
			"refusing to overwrite it because that would make the existing vault unreadable")
	}
	if err != nil {
		return fmt.Errorf("vault: writing keychain: %w", err)
	}
	return nil
}
