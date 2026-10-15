package boxsync

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/magroski/blindfold/internal/vault"
)

// State is how an entry on a box compares with the same entry here.
type State int

const (
	Missing   State = iota // here, not on the box
	Equal                  // on both, identical, secret values included
	Differs                // on both, not identical
	OnlyThere              // on the box, not here
)

func (s State) String() string {
	return [...]string{"missing", "equal", "differs", "only there"}[s]
}

// Session is this machine's side of a conversation with one box. Every
// operation moves data between this vault and that box, never between boxes.
type Session struct {
	ch     *Channel
	closer io.Closer
	// abort ends the session from outside a blocked read or write; nil when
	// nothing can, as over in-memory pipes.
	abort func()
}

// Connect opens a session over r and w, the box's stdout and stdin.
func Connect(r io.Reader, w io.Writer, version string) (*Session, error) {
	ch, err := Open(r, w, version)
	if err != nil {
		return nil, err
	}
	return &Session{ch: ch}, nil
}

// PeerVersion is the blindfold version on the box.
func (s *Session) PeerVersion() string { return s.ch.PeerVersion }

// Close ends the session.
func (s *Session) Close() error {
	if s.closer == nil {
		return nil
	}
	return s.closer.Close()
}

// Status compares every entry here and on the box, by digest.
func (s *Session) Status(local *vault.Vault) (map[string]State, error) {
	resp, err := s.call(request{Op: OpStatus})
	if err != nil {
		return nil, err
	}
	remote := make(map[string][]byte, len(resp.Digests))
	for _, d := range resp.Digests {
		remote[d.Name] = d.Digest
	}

	states := map[string]State{}
	for _, e := range local.List() {
		theirs, ok := remote[e.Name]
		if !ok {
			states[e.Name] = Missing
			continue
		}
		values, err := local.Unseal(e.Name)
		if err != nil {
			return nil, err
		}
		states[e.Name] = Differs
		if hmac.Equal(theirs, digest(s.ch, e, values)) {
			states[e.Name] = Equal
		}
	}
	for name := range remote {
		if _, ok := states[name]; !ok {
			states[name] = OnlyThere
		}
	}
	return states, nil
}

// Push copies whole entries from here to the box. Names are resolved here
// before anything is sent.
func (s *Session) Push(local *vault.Vault, names []string, overwrite bool) ([]Result, error) {
	credentials, err := export(local, names)
	if err != nil {
		return nil, err
	}
	resp, err := s.call(request{Op: OpPush, Entries: credentials, Overwrite: overwrite})
	if err != nil {
		return nil, err
	}
	answered := make([]string, 0, len(resp.Results))
	for _, r := range resp.Results {
		answered = append(answered, r.Name)
	}
	missing, err := onlyAskedFor(answered, names)
	if err != nil {
		return nil, err
	}
	return append(resp.Results, unanswered(missing)...), nil
}

// Pull copies whole entries from the box to here.
func (s *Session) Pull(local *vault.Vault, names []string, overwrite bool) ([]Result, error) {
	resp, err := s.call(request{Op: OpPull, Names: names})
	if err != nil {
		return nil, err
	}
	answered := make([]string, 0, len(resp.Entries))
	for _, c := range resp.Entries {
		answered = append(answered, c.Entry.Name)
	}
	missing, err := onlyAskedFor(answered, names)
	if err != nil {
		return nil, fmt.Errorf("%w; nothing was stored", err)
	}
	results := make([]Result, 0, len(names))
	for _, c := range resp.Entries {
		results = append(results, store(local, s.ch, c, overwrite))
	}
	return append(results, unanswered(missing)...), nil
}

// onlyAskedFor refuses an answer naming anything but the entries asked for,
// each no more often than asked: a box could otherwise plant an entry here,
// replace one beside an overwrite confirmed for another, or report on entries
// it was never sent. It returns the names the answer left out.
func onlyAskedFor(answered, names []string) ([]string, error) {
	asked := make(map[string]int, len(names))
	for _, name := range names {
		asked[name]++
	}
	for _, name := range answered {
		if asked[name] == 0 {
			return nil, fmt.Errorf("the box answered for %q, which was not asked for, or twice", name)
		}
		asked[name]--
	}
	var missing []string
	for _, name := range names {
		if asked[name] > 0 {
			missing = append(missing, name)
			asked[name]--
		}
	}
	return missing, nil
}

// unanswered is a failure for each entry a box left out of its answer.
func unanswered(names []string) []Result {
	results := make([]Result, 0, len(names))
	for _, name := range names {
		results = append(results, Result{Name: name, Outcome: Failed, Error: "the box did not answer for it"})
	}
	return results
}

// answerTimeout bounds how long a box may take to answer once asked: the
// handshake, ssh's own prompts included, or any one request. An idle session
// — the picker waiting on a person — has nothing pending and never times out.
// A variable so tests can shorten it.
var answerTimeout = 60 * time.Second

// errTimeout ends a session whose box took longer than answerTimeout.
var errTimeout = errors.New("no answer from the box in time")

// RemoteError is a failure the box reported, as opposed to one here.
type RemoteError struct{ Msg string }

func (e *RemoteError) Error() string { return e.Msg }

// call sends one request and returns its answer, or the box's error.
func (s *Session) call(req request) (response, error) {
	var resp response
	err := withinTimeout(s.abort, func() error {
		if err := s.ch.Send(req); err != nil {
			return err
		}
		return s.ch.Receive(&resp)
	})
	if err != nil {
		return response{}, err
	}
	if resp.Error != "" {
		return response{}, &RemoteError{Msg: resp.Error}
	}
	return resp, nil
}

// withinTimeout runs exchange, calling abort if it outlasts answerTimeout.
// Once abort has run the session is over, whatever exchange returned.
func withinTimeout(abort func(), exchange func() error) error {
	if abort == nil {
		return exchange()
	}
	timer := time.AfterFunc(answerTimeout, abort)
	err := exchange()
	if !timer.Stop() {
		return fmt.Errorf("%w (%v); the session was ended", errTimeout, answerTimeout)
	}
	return err
}
