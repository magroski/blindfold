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
	// ended is why the session stopped working; every later call returns it.
	ended error
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
	if err := local.Reload(); err != nil {
		return nil, err
	}
	resp, err := s.call(request{Op: OpStatus})
	if err != nil {
		return nil, err
	}
	remote := make(map[string][]byte, len(resp.Digests))
	for _, d := range resp.Digests {
		// The names land in the table and in picker commands: hold them to
		// the rules every vault does.
		if err := vault.ValidateEntryName(d.Name); err != nil {
			return nil, fmt.Errorf("the box listed an entry no vault would accept: %w", err)
		}
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
// before anything is sent; a failure doing so is a NotSentError.
func (s *Session) Push(local *vault.Vault, names []string, overwrite bool) ([]Result, error) {
	if err := local.Reload(); err != nil {
		return nil, &NotSentError{Err: err}
	}
	credentials, err := export(local, names)
	if err != nil {
		return nil, &NotSentError{Err: err}
	}
	resp, err := s.call(request{Op: OpPush, Entries: credentials, Overwrite: overwrite})
	if err != nil {
		return nil, err
	}
	answered := make([]string, 0, len(resp.Results))
	for _, r := range resp.Results {
		if !r.Outcome.valid() {
			return nil, fmt.Errorf("the box answered for %q with an outcome that is not one of %s, %s, %s, %s or %s",
				r.Name, Created, Updated, Unchanged, Conflict, Failed)
		}
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
	if err := local.Reload(); err != nil {
		return nil, err
	}
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

// NotSentError is a push that failed here, before anything left this machine.
type NotSentError struct{ Err error }

func (e *NotSentError) Error() string { return e.Err.Error() }
func (e *NotSentError) Unwrap() error { return e.Err }

// RemoteError is a failure the box reported, as opposed to one here.
type RemoteError struct{ Msg string }

func (e *RemoteError) Error() string { return e.Msg }

// call sends one request and returns its answer, or the box's error. A
// failure to exchange ends the session; an error the box answered with does
// not.
func (s *Session) call(req request) (response, error) {
	if s.ended != nil {
		return response{}, &NotSentError{Err: s.ended}
	}
	var resp response
	var sendErr error
	err := withinTimeout(s.abort, func() error {
		if sendErr = s.ch.Send(req); sendErr != nil {
			return sendErr
		}
		return s.ch.Receive(&resp)
	})
	// Refused before a byte was written: the session goes on.
	if errors.Is(sendErr, errTooLargeToSend) {
		return response{}, &NotSentError{Err: sendErr}
	}
	if err != nil {
		s.ended = err
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
		return fmt.Errorf("%w (%v); the session was ended, and what was sent may still be stored there", errTimeout, answerTimeout)
	}
	return err
}
