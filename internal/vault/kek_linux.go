//go:build linux

package vault

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/godbus/dbus/v5"
)

// secretServiceSource holds the master key in one Secret Service item: GNOME
// Keyring, KWallet or KeePassXC, whichever owns org.freedesktop.secrets on the
// session bus.
//
// The item is found by exactly two attributes, the service and account the
// macOS Keychain item carries. Secret Service has no match limit, so this file
// enforces one: no match means no vault yet, one is the key, and more than one
// is refused rather than guessed between — any program can create an item with
// the same attributes.
//
//	blindfold ──session bus──▶ org.freedesktop.secrets
//	  SearchItems {service, account}   exactly one item, or none
//	  Unlock                           the keyring prompts if locked
//	  GetSecret                        base64 master key
//
// Unlike the macOS Keychain, Secret Service has no per-application access
// control: while the keyring is unlocked, any process running as you can read
// the item. It protects the key at rest, behind your login, and no more.
//
// secret_service_guard_test.go confines D-Bus to this file and to the methods
// below, so enumeration or deletion cannot be added unnoticed.
type secretServiceSource struct{}

func newOSKeySource() KeySource { return &secretServiceSource{} }

// KeychainInspect lists the item's object path without its secret.
const KeychainInspect = "busctl --user call org.freedesktop.secrets /org/freedesktop/secrets " +
	"org.freedesktop.Secret.Service SearchItems a{ss} 2 service " + KeychainService + " account " + KeychainAccount

// The Secret Service API surface this file uses, and nothing else.
const (
	secretsBusName = "org.freedesktop.secrets"
	secretsPath    = dbus.ObjectPath("/org/freedesktop/secrets")

	methodOpenSession = "org.freedesktop.Secret.Service.OpenSession"
	methodSearchItems = "org.freedesktop.Secret.Service.SearchItems"
	methodUnlock      = "org.freedesktop.Secret.Service.Unlock"
	methodReadAlias   = "org.freedesktop.Secret.Service.ReadAlias"
	methodCreateItem  = "org.freedesktop.Secret.Collection.CreateItem"
	methodGetSecret   = "org.freedesktop.Secret.Item.GetSecret"
	methodPrompt      = "org.freedesktop.Secret.Prompt.Prompt"

	promptIface     = "org.freedesktop.Secret.Prompt"
	promptCompleted = "Completed"
	signalCompleted = promptIface + "." + promptCompleted

	propLabel      = "org.freedesktop.Secret.Item.Label"
	propAttributes = "org.freedesktop.Secret.Item.Attributes"
)

const (
	// plainAlgorithm sends the secret unencrypted over the session bus. The
	// bus belongs to your user, and every process that could read it there can
	// ask the service for the item outright; encrypting the hop adds no barrier.
	plainAlgorithm = "plain"
	// The key is stored as base64 text: some backends, KeePassXC among them,
	// keep secrets as text and would mangle raw bytes.
	keyContentType  = "text/plain"
	itemLabel       = "blindfold master key"
	defaultAlias    = "default"
	noObject        = dbus.ObjectPath("/") // "no prompt needed", "no such alias"
	callTimeout     = 30 * time.Second     // the D-Bus default; activation can be slow
	promptTimeout   = 5 * time.Minute      // a person typing a keyring password
	signalQueueSize = 4
)

// secretService is one connection with an open session.
type secretService struct {
	conn    *dbus.Conn
	session dbus.ObjectPath
}

// secret is the Secret Service (oayays) struct.
type secret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

func (k *secretServiceSource) Describe() string {
	return fmt.Sprintf("Secret Service item (service=%q account=%q) — the only item this binary reads",
		KeychainService, KeychainAccount)
}

func (k *secretServiceSource) Load() ([]byte, error) {
	s, err := connectSecretService()
	if err != nil {
		return nil, err
	}
	defer s.close()

	item, found, err := s.find()
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNoKey
	}
	if err := s.unlock(item); err != nil {
		return nil, err
	}

	var value secret
	if err := s.call(item, methodGetSecret, []any{s.session}, &value); err != nil {
		return nil, fmt.Errorf("vault: reading the Secret Service item: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(string(value.Value))
	if err != nil || len(key) != KeySize {
		return nil, fmt.Errorf("vault: the Secret Service item labelled %q does not hold a %d-byte key "+
			"(remove it in your keyring manager and restore from a backup)", itemLabel, KeySize)
	}
	return key, nil
}

func (k *secretServiceSource) Store(key []byte) error {
	s, err := connectSecretService()
	if err != nil {
		return err
	}
	defer s.close()

	// CreateItem with replace=false still adds a second item beside an
	// existing one, so existence is checked first.
	_, found, err := s.find()
	if err != nil {
		return err
	}
	if found {
		return errors.New("vault: a master key already exists in the Secret Service; " +
			"refusing to overwrite it because that would make the existing vault unreadable")
	}

	var collection dbus.ObjectPath
	if err := s.call(secretsPath, methodReadAlias, []any{defaultAlias}, &collection); err != nil {
		return fmt.Errorf("vault: finding the default keyring: %w", err)
	}
	if collection == noObject {
		return errors.New("vault: the Secret Service has no default keyring; create one in your keyring manager, or " +
			keyFileHelp)
	}
	if err := s.unlock(collection); err != nil {
		return err
	}

	properties := map[string]dbus.Variant{
		propLabel:      dbus.MakeVariant(itemLabel),
		propAttributes: dbus.MakeVariant(keyAttributes()),
	}
	value := secret{
		Session:     s.session,
		Parameters:  []byte{},
		Value:       []byte(base64.StdEncoding.EncodeToString(key)),
		ContentType: keyContentType,
	}
	var item, prompt dbus.ObjectPath
	if err := s.call(collection, methodCreateItem, []any{properties, value, false}, &item, &prompt); err != nil {
		return fmt.Errorf("vault: writing the Secret Service item: %w", err)
	}
	return s.prompt(prompt)
}

// keyAttributes identifies the one item this binary reads.
func keyAttributes() map[string]string {
	return map[string]string{"service": KeychainService, "account": KeychainAccount}
}

// connectSecretService opens a session on the user's session bus.
func connectSecretService() (*secretService, error) {
	address, err := sessionBusAddress()
	if err != nil {
		return nil, err
	}
	conn, err := dbus.Connect(address)
	if err != nil {
		return nil, noSecretService(err)
	}
	s := &secretService{conn: conn}

	var output dbus.Variant
	err = s.call(secretsPath, methodOpenSession, []any{plainAlgorithm, dbus.MakeVariant("")}, &output, &s.session)
	if err != nil {
		conn.Close()
		return nil, noSecretService(err)
	}
	return s, nil
}

// close ends the session along with the connection that owns it.
func (s *secretService) close() { s.conn.Close() }

// sessionBusAddress finds the session bus without starting one. A bus
// autolaunched here would have no Secret Service behind it, and would outlive
// this process.
func sessionBusAddress() (string, error) {
	if address := os.Getenv("DBUS_SESSION_BUS_ADDRESS"); address != "" {
		return address, nil
	}
	if runtime := os.Getenv("XDG_RUNTIME_DIR"); runtime != "" {
		socket := filepath.Join(runtime, "bus")
		if _, err := os.Stat(socket); err == nil {
			return "unix:path=" + socket, nil
		}
	}
	return "", noSecretService(errors.New("no session bus"))
}

// noSecretService explains the alternatives rather than falling back to
// something weaker on its own.
func noSecretService(cause error) error {
	return fmt.Errorf("vault: no Secret Service available (%v); %s", cause, keyFileHelp)
}

// find returns the one item carrying keyAttributes, if there is one.
func (s *secretService) find() (dbus.ObjectPath, bool, error) {
	var unlocked, locked []dbus.ObjectPath
	if err := s.call(secretsPath, methodSearchItems, []any{keyAttributes()}, &unlocked, &locked); err != nil {
		return "", false, fmt.Errorf("vault: searching the Secret Service: %w", err)
	}
	items := append(unlocked, locked...)
	switch len(items) {
	case 0:
		return "", false, nil
	case 1:
		return items[0], true, nil
	}
	return "", false, fmt.Errorf("vault: %d Secret Service items carry service=%q account=%q; "+
		"refusing to guess which holds the master key. Inspect them with: %s",
		len(items), KeychainService, KeychainAccount, KeychainInspect)
}

// unlock opens an item or collection, through the keyring's own prompt when
// it is locked.
func (s *secretService) unlock(object dbus.ObjectPath) error {
	var unlocked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := s.call(secretsPath, methodUnlock, []any{[]dbus.ObjectPath{object}}, &unlocked, &prompt); err != nil {
		return fmt.Errorf("vault: unlocking the keyring: %w", err)
	}
	return s.prompt(prompt)
}

// prompt shows a keyring prompt and waits for the person to answer it.
func (s *secretService) prompt(path dbus.ObjectPath) error {
	if path == noObject || path == "" {
		return nil
	}

	// Subscribed before prompting, so a fast answer is not missed.
	signals := make(chan *dbus.Signal, signalQueueSize)
	s.conn.Signal(signals)
	defer s.conn.RemoveSignal(signals)
	match := []dbus.MatchOption{
		dbus.WithMatchObjectPath(path), dbus.WithMatchInterface(promptIface), dbus.WithMatchMember(promptCompleted),
	}
	if err := s.conn.AddMatchSignal(match...); err != nil {
		return fmt.Errorf("vault: waiting for the keyring prompt: %w", err)
	}
	defer s.conn.RemoveMatchSignal(match...)

	// The window id is unknown to a CLI; "" lets the keyring place the prompt.
	if err := s.call(path, methodPrompt, []any{""}); err != nil {
		return fmt.Errorf("vault: showing the keyring prompt: %w", err)
	}

	timeout := time.After(promptTimeout)
	for {
		select {
		case signal, ok := <-signals:
			// godbus closes the channel when the connection drops.
			if !ok {
				return errors.New("vault: the session bus closed during the keyring prompt")
			}
			if signal.Path != path || signal.Name != signalCompleted || len(signal.Body) == 0 {
				continue
			}
			if dismissed, _ := signal.Body[0].(bool); dismissed {
				return errors.New("vault: the keyring prompt was dismissed")
			}
			return nil
		case <-timeout:
			return errors.New("vault: the keyring prompt was not answered")
		}
	}
}

// call invokes one Secret Service method and stores its results.
func (s *secretService) call(object dbus.ObjectPath, method string, args []any, results ...any) error {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	return s.conn.Object(secretsBusName, object).CallWithContext(ctx, method, 0, args...).Store(results...)
}
