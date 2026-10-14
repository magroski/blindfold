//go:build !darwin && !linux

package vault

// unsupportedOSKeySource stands in on platforms with no keychain integration.
// Rather than silently falling back to something weaker, it explains the two
// supported alternatives — failing loudly beats quietly downgrading how a master
// key is protected.
type unsupportedOSKeySource struct{}

func newOSKeySource() KeySource { return &unsupportedOSKeySource{} }

const noKeychainHelp = "vault: no OS keychain on this platform; " + keyFileHelp

// KeychainInspect is empty: there is no keychain item to inspect.
const KeychainInspect = ""

func (unsupportedOSKeySource) Describe() string { return "unavailable (no OS keychain)" }

func (unsupportedOSKeySource) Load() ([]byte, error) { return nil, errNoKeychain{} }

func (unsupportedOSKeySource) Store([]byte) error { return errNoKeychain{} }

type errNoKeychain struct{}

func (errNoKeychain) Error() string { return noKeychainHelp }
