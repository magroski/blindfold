package boxsync

import (
	"errors"
	"io"

	"github.com/magroski/blindfold/internal/vault"
)

// errNoVault answers every request to a box where init never ran.
const errNoVault = "there is no vault on this box; run `blindfold init` there first"

// Serve answers one client session on r and w — the box's side of `push`,
// `pull` and `sync`, reached as `blindfold sync-serve` over SSH. It returns
// when the client hangs up. observe hears of every entry sent or received.
func Serve(v *vault.Vault, r io.Reader, w io.Writer, version string, observe func(Access)) error {
	ch, err := Accept(r, w, version)
	if err != nil {
		return err
	}
	for {
		var req request
		if err := ch.Receive(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := ch.Send(handle(v, ch, req, observe)); err != nil {
			return err
		}
	}
}

// handle answers one request. Failures travel back as errors; vault errors
// never quote a value.
func handle(v *vault.Vault, ch *Channel, req request, observe func(Access)) response {
	// The session may be long; other processes may have changed the vault.
	if err := v.Reload(); err != nil {
		// A push arrived all the same: its values are here, unstored.
		for _, c := range req.Entries {
			observe(Access{Op: OpPush, Entry: c.Entry.Name, Vars: c.Entry.VarNames(), Outcome: Failed})
		}
		return response{Error: err.Error()}
	}
	if !v.Exists() {
		return response{Error: errNoVault}
	}
	switch req.Op {
	case OpStatus:
		digests, err := digests(v, ch)
		if err != nil {
			return response{Error: err.Error()}
		}
		observe(Access{Op: OpStatus})
		return response{Digests: digests}
	case OpPull:
		credentials, err := export(v, req.Names)
		if err != nil {
			return response{Error: err.Error()}
		}
		for _, c := range credentials {
			observe(Access{Op: OpPull, Entry: c.Entry.Name, Vars: c.Entry.VarNames()})
		}
		return response{Entries: credentials}
	case OpPush:
		results := make([]Result, 0, len(req.Entries))
		for _, c := range req.Entries {
			result := store(v, ch, c, req.Overwrite)
			// Stored or not, the values arrived here.
			observe(Access{Op: OpPush, Entry: c.Entry.Name, Vars: c.Entry.VarNames(), Outcome: result.Outcome})
			results = append(results, result)
		}
		return response{Results: results}
	}
	return response{Error: "unknown sync operation " + req.Op}
}

// digests hashes every entry under the session's digest key.
func digests(v *vault.Vault, ch *Channel) ([]entryDigest, error) {
	entries := v.List()
	out := make([]entryDigest, 0, len(entries))
	for _, e := range entries {
		values, err := v.Unseal(e.Name)
		if err != nil {
			return nil, err
		}
		out = append(out, entryDigest{Name: e.Name, Digest: digest(ch, e, values)})
	}
	return out, nil
}
