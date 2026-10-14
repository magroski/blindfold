//go:build !darwin

package vault

// unsupportedOSKeySource stands in on platforms with no keychain integration.
// Rather than silently falling back to something weaker, it explains the two
// supported alternatives — failing loudly beats quietly downgrading how a master
// key is protected.
type unsupportedOSKeySource struct{}

func newOSKeySource() KeySource { return &unsupportedOSKeySource{} }

const noKeychainHelp = "vault: no OS keychain on this platform; " +
	"point BLINDFOLD_PASSPHRASE_FILE at a 0600 passphrase file, or BLINDFOLD_KEK_FILE at a 0600 key file"

func (unsupportedOSKeySource) Describe() string { return "unavailable (no OS keychain)" }

func (unsupportedOSKeySource) Load() ([]byte, error) { return nil, errNoKeychain{} }

func (unsupportedOSKeySource) Store([]byte) error { return errNoKeychain{} }

type errNoKeychain struct{}

func (errNoKeychain) Error() string { return noKeychainHelp }
