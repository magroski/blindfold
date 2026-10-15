package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/magroski/blindfold/internal/audit"
	"github.com/magroski/blindfold/internal/boxsync"
	"github.com/magroski/blindfold/internal/vault"
)

// Sync commands. Every transfer runs between this machine and one box, never
// between two boxes:
//
//	here ──push──▶ box        values sealed end to end inside ssh, then
//	here ◀──pull── box        sealed again under the receiving vault's own key
const (
	pushCommand  = "push"
	pullCommand  = "pull"
	syncCommand  = "sync"
	serveCommand = "sync-serve"
)

// Cells of the sync table.
const (
	cellPresent     = "●"
	cellDiffers     = "≠"
	cellMissing     = "—"
	cellUnreachable = "?"
	syncLegend      = cellPresent + " present  " + cellDiffers + " differs from here  " +
		cellMissing + " missing  " + cellUnreachable + " unreachable"
)

func cmdPush(env Env, args []string) error { return cmdTransfer(env, pushCommand, args) }

func cmdPull(env Env, args []string) error { return cmdTransfer(env, pullCommand, args) }

// cmdTransfer runs one push or pull against one box.
func cmdTransfer(env Env, op string, args []string) error {
	env = lockStderr(env)
	fs := flag.NewFlagSet(op, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	overwrite := fs.Bool("overwrite", false, "replace an entry that differs on the receiving side")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) < 2 {
		return fmt.Errorf("usage: %s %s <box> <name>... [--overwrite]", Bin, op)
	}

	v, err := openVault()
	if err != nil {
		return err
	}
	remotes, err := findRemotes(v, positional[:1])
	if err != nil {
		return err
	}
	remote := remotes[0]
	session, err := boxsync.Dial(remote, env.Version, &boxText{w: env.Stderr})
	if err != nil {
		// A handshake error can quote the box's hello.
		return fmt.Errorf("%s: %s", remote.Name, printable(err.Error()))
	}
	defer session.Close()

	results, err := transfer(env, v, session, remote.Name, op, positional[1:], *overwrite)
	if err != nil {
		return err
	}
	return reportTransfer(env.Stdout, op, remote.Name, results)
}

// transfer moves entries one way and records each in the audit log.
func transfer(env Env, v *vault.Vault, session *boxsync.Session, box, op string, names []string, overwrite bool) ([]boxsync.Result, error) {
	run, preposition := session.Push, "to "
	if op == pullCommand {
		run, preposition = session.Pull, "from "
	}
	log := auditLog(env, v.Dir())
	results, err := run(v, names, overwrite)
	// A box that refused a push was still sent the values, sealed.
	var refused *boxsync.RemoteError
	if op == pushCommand && errors.As(err, &refused) {
		for _, name := range names {
			log.Log(audit.Event{
				Tool: op, Secret: name, Decision: audit.Allowed,
				Reason: preposition + box + ": refused by the box",
			})
		}
	}
	if err != nil {
		// The box wrote part of this; it may not reach the terminal as control.
		return nil, fmt.Errorf("%s: %s", box, printable(err.Error()))
	}
	for _, r := range results {
		var vars string
		if entry, ok := v.Get(r.Name); ok {
			vars = strings.Join(entry.VarNames(), ",")
		}
		log.Log(audit.Event{
			Tool: op, Secret: r.Name, Field: vars, Decision: audit.Allowed,
			Reason: preposition + box + ": " + string(r.Outcome),
		})
	}
	return results, nil
}

// reportTransfer prints one line per entry, and fails when any entry was not
// stored: a conflict left as it was, or an error.
func reportTransfer(w io.Writer, op, box string, results []boxsync.Result) error {
	conflicts, failures := 0, 0
	for _, r := range results {
		printResult(w, r)
		switch r.Outcome {
		case boxsync.Conflict:
			conflicts++
		case boxsync.Failed:
			failures++
		}
	}
	switch {
	case failures > 0:
		return fmt.Errorf("%s %s: %d of %d not stored", op, box, failures+conflicts, len(results))
	case conflicts > 0:
		return fmt.Errorf("%s %s: %d left as they were because they differ; "+
			"compare with `%s sync %s`, then pass --overwrite to replace them", op, box, conflicts, Bin, box)
	}
	return nil
}

// printResult prints one entry's outcome, e.g. "API_KEY  conflict: differs,
// left as it was".
func printResult(w io.Writer, r boxsync.Result) {
	name := printable(r.Name) // a box's answer: never raw to the terminal
	switch r.Outcome {
	case boxsync.Conflict:
		fmt.Fprintf(w, "%s  %s: differs, left as it was\n", name, r.Outcome)
	case boxsync.Failed:
		fmt.Fprintf(w, "%s  %s: %s\n", name, r.Outcome, printable(r.Error))
	default:
		fmt.Fprintf(w, "%s  %s\n", name, printable(string(r.Outcome)))
	}
}

// boxView is one box's column of the sync table.
type boxView struct {
	remote  vault.Remote
	session *boxsync.Session
	states  map[string]boxsync.State
	err     error
}

// syncView is the table: every entry here or on any box, against each box.
type syncView struct {
	local *vault.Vault
	log   *audit.Logger
	boxes []*boxView
	names []string
}

func cmdSync(env Env, args []string) error {
	env = lockStderr(env)
	fs := flag.NewFlagSet(syncCommand, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}

	v, err := openVault()
	if err != nil {
		return err
	}
	remotes, err := findRemotes(v, positional)
	if err != nil {
		return err
	}
	view := openSyncView(env, v, remotes)
	defer view.close()
	view.print(env.Stdout)

	// A person at a terminal picks what to copy; a script gets the table.
	if stdinIsTerminal(env) && stdoutIsTerminal(env) {
		return pick(env, view)
	}
	return view.err()
}

// openSyncView connects to each box in turn — one at a time, so ssh prompts
// never interleave — and compares.
func openSyncView(env Env, v *vault.Vault, remotes []vault.Remote) *syncView {
	view := &syncView{local: v, log: auditLog(env, v.Dir())}
	for _, r := range remotes {
		b := &boxView{remote: r}
		b.session, b.err = boxsync.Dial(r, env.Version, &boxText{w: env.Stderr})
		view.boxes = append(view.boxes, b)
	}
	view.refresh()
	return view
}

// refresh compares again, after a transfer.
func (s *syncView) refresh() {
	names := map[string]bool{}
	for _, e := range s.local.List() {
		names[e.Name] = true
	}
	for _, b := range s.boxes {
		if b.session == nil {
			continue
		}
		if b.states, b.err = b.session.Status(s.local); b.err != nil {
			continue
		}
		// Comparing unseals every value on both sides, though none travels.
		s.log.Log(audit.Event{Tool: syncCommand, Decision: audit.Allowed, Reason: "compared with " + b.remote.Name})
		for name := range b.states {
			names[name] = true
		}
	}
	s.names = s.names[:0]
	for name := range names {
		s.names = append(s.names, name)
	}
	sort.Strings(s.names)
}

func (s *syncView) print(w io.Writer) {
	header := []string{"#", "ENTRY", "here"}
	for _, b := range s.boxes {
		header = append(header, b.remote.Name)
	}
	rows := [][]string{header}
	for i, name := range s.names {
		here := cellMissing
		if _, ok := s.local.Get(name); ok {
			here = cellPresent
		}
		row := []string{fmt.Sprint(i + 1), name, here}
		for _, b := range s.boxes {
			row = append(row, b.cell(name))
		}
		rows = append(rows, row)
	}
	writeTable(w, rows)
	fmt.Fprintf(w, "\n%s\n", syncLegend)
	for _, b := range s.boxes {
		if b.err != nil {
			fmt.Fprintf(w, "%s: %s\n", b.remote.Name, printable(b.err.Error()))
		}
	}
}

func (b *boxView) cell(name string) string {
	if b.err != nil {
		return cellUnreachable
	}
	switch b.states[name] {
	case boxsync.Equal, boxsync.OnlyThere:
		return cellPresent
	case boxsync.Differs:
		return cellDiffers
	}
	return cellMissing
}

// err reports boxes the table could not show.
func (s *syncView) err() error {
	unreachable := 0
	for _, b := range s.boxes {
		if b.err != nil {
			unreachable++
		}
	}
	if unreachable > 0 {
		return fmt.Errorf("%d of %d boxes could not be compared", unreachable, len(s.boxes))
	}
	return nil
}

func (s *syncView) close() {
	for _, b := range s.boxes {
		if b.session != nil {
			b.session.Close()
		}
	}
}

// box finds a connected box of the view by name.
func (s *syncView) box(name string) (*boxView, error) {
	for _, b := range s.boxes {
		if b.remote.Name != name {
			continue
		}
		if b.session == nil {
			return nil, fmt.Errorf("%s is unreachable: %s", name, printable(b.err.Error()))
		}
		return b, nil
	}
	return nil, fmt.Errorf("%s is not in this table", name)
}

// lockStderr serializes writes to a stderr that is not a file. Each box's ssh
// copies its stderr from a goroutine of its own; a file needs no lock, because
// concurrent writes to one are safe.
func lockStderr(env Env) Env {
	if _, ok := env.Stderr.(*os.File); ok {
		return env
	}
	env.Stderr = &lockedWriter{w: env.Stderr}
	return env
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// boxText escapes what a box writes to stderr — its shell, its blindfold,
// ssh itself — so a box cannot drive this terminal: "\x1b]0;title\a" prints
// as those characters. Newlines and tabs pass. One per box: it holds the
// start of a character split across writes.
type boxText struct {
	w       io.Writer
	pending []byte
}

func (b *boxText) Write(p []byte) (int, error) {
	data := append(b.pending, p...)
	b.pending = nil
	var out strings.Builder
	for len(data) > 0 {
		if !utf8.FullRune(data) {
			b.pending = append([]byte(nil), data...) // the rest is in the next write
			break
		}
		r, size := utf8.DecodeRune(data)
		out.WriteString(escapeRune(r, data[:size]))
		data = data[size:]
	}
	if _, err := io.WriteString(b.w, out.String()); err != nil {
		return 0, err
	}
	return len(p), nil
}

// escapeRune spells a control character or invalid byte the way Go source
// would: '\x1b' as `\x1b`, an invalid 0x9b as `\x9b`.
func escapeRune(r rune, raw []byte) string {
	switch {
	case r == '\n' || r == '\t':
		return string(r)
	case r == utf8.RuneError && len(raw) == 1:
		return fmt.Sprintf(`\x%02x`, raw[0])
	case unicode.IsControl(r):
		quoted := strconv.QuoteRune(r)
		return quoted[1 : len(quoted)-1]
	}
	return string(raw)
}

// cmdSyncServe is the box's side of a session, run over ssh by push, pull and
// sync. Its stdout carries only the encrypted stream.
func cmdSyncServe(env Env, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("%s takes no arguments; push, pull and sync run it over ssh", serveCommand)
	}
	// Whoever completes the handshake gets values. ssh starts this on a box
	// without an agent's markers; an agent's shell has no business running it.
	if reason := agentShellReason(os.LookupEnv); reason != "" {
		return fmt.Errorf("refusing to serve credentials: %s. %s is started by push, pull and sync over ssh",
			reason, serveCommand)
	}
	v, err := openVault()
	if err != nil {
		return err
	}
	peer := sshPeer()
	log := auditLog(env, v.Dir())
	err = boxsync.Serve(v, env.Stdin, env.Stdout, env.Version, func(a boxsync.Access) {
		reason := "received from " + peer
		switch a.Op {
		case boxsync.OpPull:
			reason = "sent to " + peer
		case boxsync.OpStatus:
			reason = "compared by " + peer
		}
		log.Log(audit.Event{
			Tool: serveCommand, Secret: a.Entry, Field: strings.Join(a.Vars, ","),
			Decision: audit.Allowed, Reason: reason,
		})
	})
	if errors.Is(err, io.EOF) {
		return fmt.Errorf("%s speaks only to push, pull and sync over ssh", serveCommand)
	}
	return err
}

// sshPeer names the machine on the other end, from the address sshd sets:
// SSH_CLIENT="203.0.113.7 51234 22".
func sshPeer() string {
	if client, _, _ := strings.Cut(os.Getenv("SSH_CLIENT"), " "); client != "" {
		return client
	}
	return "a local process"
}
