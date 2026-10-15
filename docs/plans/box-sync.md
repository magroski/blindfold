# Push and pull credentials between dev boxes

Status: Done

## Problem
A developer with vaults on several dev boxes (e.g. one macOS, one Linux)
cannot see which credentials each box holds. Copying a new one means
re-entering it on every box, or piping `get --force` plaintext through `ssh`
one secret at a time, which entries with two or more secrets cannot do.

## Evidence
- Supports: the user's own workflow: a new API key added locally must reach two
  remote boxes (request).
- Supports: piped `add` refuses a second secret (`internal/cli/add.go`, "cannot
  read %d secrets from a pipe"), so `get --force | ssh box blindfold add` only
  works for single-secret entries, and is audited as forced.
- Supports: `import` needs a plaintext `.env` file on the target, which this
  project exists to avoid.
- Supports: nothing lists another box's vault; `ls` is local only
  (`internal/cli/list.go`).
- Unknown: how each remote vault unlocks over a non-interactive SSH session
  (locked Keychain, no session bus). Settled by design: fail with the remote's
  error and a fix hint (Decisions).

## Goal
From the current machine, see which credentials each registered box holds and
copy whole credentials to or from one box at a time, without any value leaving
a vault in plaintext.

1. `blindfold push <box> <entry>...` copies whole entries (description, tags,
   every variable) to the box, sealed there under the box's own master key;
   `blindfold pull <box> <entry>...` copies them here. | check:
   `go test -run 'TestPush|TestPull' ./internal/cli` — the target vault, opened
   with its own key, unseals the copied values.
2. `blindfold sync` prints one table, entries by boxes, marking each cell
   present-and-equal, differs, or missing; equality covers secret values,
   compared by session-keyed digests. | check: `go test -run TestSyncStatus
   ./internal/cli`.
3. An entry that differs on the target is never replaced without `--overwrite`
   (CLI) or an explicit `y` (picker). | check: `go test -run
   'TestPushRefusesConflict|TestPickerConfirmsOverwrite' ./internal/cli`.
4. No value appears in the `ssh` argv, in the bytes on the SSH stream, on stdout
   or stderr of either side, or in either audit log. | check: `go test -run
   TestSyncNeverExposesValues ./internal/cli` asserts all five.
5. The box registry is bound to the master key: a registry sealed under
   another key (forged, or copied from another vault) makes every sync and
   remote command refuse before ssh runs. Rolling back to a registry this
   vault sealed earlier is not detected, and `docs/security.md` says so. |
   check: `go test -run TestRemotesTamperRefused ./internal/vault` and `go test
   -run TestSyncRefusesForeignRegistry ./internal/cli`; read
   `docs/security.md`, "Between dev boxes".
6. Remote failures — blindfold missing, vault not initialized, key unavailable,
   protocol mismatch — exit non-zero with the remote's message and a fix hint,
   and change nothing. | check: `go test -run TestSyncRemoteFailures
   ./internal/cli`.
7. Across operating systems over real OpenSSH: from this Mac, `remote add`,
   `sync`, `push` and `pull` against a Linux box succeed. | check:
   `scripts/sync-e2e.sh` (Docker Linux container running sshd).
8. `scripts/test.sh` passes on macOS and Linux; `docs/usage.md`,
   `docs/security.md`, `docs/install.md` permission rules and
   `.claude/settings.json` cover the new commands. | check: run it in both;
   read the docs.

## Context
- Commands dispatch in `internal/cli/cli.go:58` (`Run`), usage text at
  `cli.go:34`.
- The vault API: `Get`/`List` need no key (`internal/vault/vault.go:174-177`),
  `Unseal` returns every value of an entry (`vault.go:258`), `Put` stores an
  entry with its values and re-binds its data key (`vault.go:185`). Each vault
  seals under its own master key; nothing is shared between boxes.
- `vault.sealed` holds per-entry data keys and a key check
  (`internal/vault/sealed.go:66`); AEAD helpers `seal`/`open` live there.
- Prompts go through one `prompter` (`internal/cli/term.go:32`); the picker only
  needs visible lines.
- Audit events: `internal/audit/audit.go`; `auditLog(env, dir)` in
  `internal/cli/guard.go`.
- Subprocess test pattern: the test binary re-runs as blindfold
  (`internal/cli/exec_test.go`, `TestExecHelperProcess`).
- Constraints (AGENTS.md): values never in argv; plaintext stays awkward;
  vault-changing commands go in the `ask` list; layers talk only to neighbors.

## Approach

```
 this machine                                          target box (macOS or Linux)
 ┌─────────────────────────────────┐  ssh -T -- <dest>  ┌──────────────────────────────┐
 │ internal/cli     sync push pull │  <bin> sync-serve  │ internal/cli     sync-serve  │
 │                  remote, picker │ ──────────────────▶│                              │
 │ internal/boxsync Session        │  stdin / stdout:   │ internal/boxsync Serve       │
 │   ├ ssh.go     exec ssh         │   hello {X25519}   │   ├ channel.go               │
 │   ├ channel.go E2E frames       │   sealed frames    │   └ protocol.go              │
 │   └ protocol.go status/pull/push│   (XChaCha20-      │ internal/vault Put / Unseal  │
 │ internal/vault Unseal / Put     │    Poly1305)       │   under its own master key   │
 └─────────────────────────────────┘                    └──────────────────────────────┘
```

- **Transport: the system `ssh`.** It honors `~/.ssh/config`, agents,
  `known_hosts` and 2FA prompts (on `/dev/tty`, not our stream). The local
  process runs `ssh -T -a -x -o ClearAllForwardings=yes -- <destination>
  "<bin> sync-serve"`; the destination is validated (no leading `-`, no
  whitespace) and `<bin>` is held to characters every shell reads literally.
  Nothing secret is in argv.
- **End-to-end encryption inside SSH.** The remote helper's stdout would
  otherwise be plaintext any agent could read with
  `ssh box blindfold sync-serve`. Each session does an ephemeral X25519
  exchange; HKDF-SHA256 over the shared secret and both public keys yields a
  key per direction plus a digest key. Frames are XChaCha20-Poly1305 with AAD =
  sequence number under a separate key per direction, so a reordered, replayed
  or reflected frame fails.
  SSH authenticates the peer; the inner exchange only keeps plaintext off the
  pipe.
- **Protocol v1**, line-delimited JSON: `hello {proto, version, pub}` each way,
  then sealed requests `status`, `pull {names}`, `push {entries, overwrite}`.
  `status` returns `[{name, digest}]`, where digest = HMAC(digest key,
  canonical entry + values); values travel only in `pull` and `push`.
- **Writes reuse `vault.Put`** on the receiving side, so validation, binding and
  sealing under that box's key are unchanged. Conflict = an existing entry whose
  digest differs; refused unless overwrite. Equal digests are a no-op.
- **Box registry sealed in `vault.sealed`** (`remotes` box, AAD `"remotes"`):
  `{name, destination, bin}` per box. A hand edit cannot repoint `push` at
  another host. Every sync command needs the master key anyway.
- **UI:** `blindfold sync` prints the table; at a terminal a prompt loop follows
  (`push 1,3 mac-box linux-box`, `pull 2 mac-box`, Enter or `q` to quit;
  the table redraws after each command), asking
  before each overwrite. Pull takes one box per command: always box → here.
- **Audit both sides:** local `push`/`pull` events name the box; the remote
  logs `sync-serve` sent/received. Names only.

Rejected:
- `golang.org/x/crypto/ssh`: would reimplement config, agent, known_hosts and
  prompts the user already has working.
- Plain JSON over SSH: the remote helper's stdout would carry plaintext into any
  agent that runs it.
- Full-screen TUI (bubbletea): about 15 new dependencies in a credential store
  (user chose the prompt picker).
- Registry in cleartext `remotes.json`: editable by hand to redirect pushes.

## Steps
1. [x] Box registry: `Remote{Name, Destination, Bin}`, validation, sealed
   storage, `Remotes`/`AddRemote`/`RemoveRemote`; tamper test first |
   `internal/vault/remotes.go`, `internal/vault/sealed.go`,
   `internal/vault/remotes_test.go` | vault
2. [x] Encrypted channel: handshake, sealed frames, per-direction key + sequence AAD;
   tests for round trip, tamper, replay, reflection, no plaintext on the wire |
   `internal/boxsync/channel.go`, `internal/boxsync/channel_test.go` | sync
   (transport)
3. [x] Protocol: messages, digest, `Serve(v, rw)` and client
   `Session.Status/Pull/Push`, conflict rule; tested over in-memory pipes
   between two vaults | `internal/boxsync/protocol.go`, `server.go`, `client.go`,
   `sync_test.go` | sync
4. [x] SSH transport: `Dial(remote)` runs `ssh -T -- dest 'bin' sync-serve`,
   surfaces remote stderr on failure with a fix hint; `sshCommand` swappable in
   tests | `internal/boxsync/ssh.go` | sync (transport)
5. [x] CLI: `remote add|ls|rm`, `push`, `pull`, `sync` (table), `sync-serve`,
   audit events, usage text; integration tests through a fake `ssh` that runs
   the test binary as the remote with its own vault and key |
   `internal/cli/remote.go`, `internal/cli/sync.go`, `internal/cli/cli.go:34,58`,
   `internal/cli/sync_test.go` | cli
6. [x] Picker loop on `sync` at a terminal, with overwrite confirmation; tested
   on scripted input | `internal/cli/sync.go`, `internal/cli/sync_test.go` | cli
7. [x] Cross-OS end to end: Linux container with sshd and a passphrase-file
   vault; this Mac adds it as a remote, then status, push, pull |
   `scripts/sync-e2e.sh` | scripts
8. [x] Docs and rules: usage section, security section (channel, registry,
   what the remote sees), install `ask` list, `.claude/settings.json`,
   AGENTS.md layout and rules; skill tells agents not to run sync |
   `docs/usage.md`, `docs/security.md`, `docs/install.md`,
   `.claude/settings.json`, `AGENTS.md`, `skills/using-secrets/SKILL.md` | docs

## Tests
- Happy: push a bundle (public + two secrets) to an empty box; the box unseals
  it under its own key. Pull one back. Status shows equal after both.
- Happy: equal entry pushed again is a no-op, not a conflict.
- Sad: push onto a differing entry without `--overwrite` changes nothing and
  exits non-zero; with it, the target matches the source.
- Sad: remote blindfold missing, remote not initialized, remote key unavailable,
  protocol version mismatch: each exits non-zero with a hint, target unchanged.
- Sad: registry hand-edited (destination repointed) → refused before any ssh.
- Sad: tampered, replayed or reflected frame → session aborts.
- Edge: destination starting with `-` or containing whitespace refused at
  `remote add`; unknown box or entry names list what exists.
- Edge: no value in ssh argv, wire bytes, stdout/stderr of either side, or audit
  logs (one test, five assertions).

## Risks
- Remote non-interactive SSH env lacks `PATH` or key-source variables: surface
  the remote's own error; hint `--bin` and setting `BLINDFOLD_PASSPHRASE_FILE`
  in `~/.zshenv` / `~/.bashrc`.
- macOS Keychain locked in an SSH session: same path; hint
  `security unlock-keychain` or a key file.
- Custom crypto protocol: kept to standard primitives (X25519, HKDF-SHA256,
  XChaCha20-Poly1305) already in `golang.org/x/crypto`; tamper, replay and
  reflection tests; independent verify pass.
- Version skew between boxes: protocol version in the hello, mismatch names both
  versions.

## Out of scope
- Propagating deletions or renames.
- Box-to-box transfers; background or automatic sync.
- Per-variable diff or merging two differing entries.
- Windows remotes.

## Decisions
- Q: Interactive UI? A: prompt picker on the existing prompter, because it adds
  no dependencies to a credential store and is testable.
- Q: How are boxes known? A: named remotes saved by `blindfold remote add`, so
  `sync` can show every box at once.
- Q: Remote unlock over non-interactive SSH? A: fail with the remote's error and
  a fix hint, because it covers every setup without a tty in the data channel.
- Q: Target already holds a differing entry? A: ask before overwrite (`--overwrite`
  on the CLI), because silently replacing a rotated key is the costly mistake.
- Assumed: the base is `main` after PR #1 (Linux support, format v3).
- Assumed: values are end-to-end encrypted inside SSH, so the remote helper never
  prints plaintext (AGENTS.md: plaintext stays awkward).
- Assumed: whole entries travel (description, tags, every variable); status is
  per entry, not per variable.
- Assumed: `sync` with stdout not a terminal prints the table only, for scripts.
- Assumed: the remote runs a blindfold with protocol v1; older ones fail with an
  upgrade hint.
- Learned while building: a package named `sync` shadows the standard library's
  in every importer; the package is `internal/boxsync` instead. Goal and
  Approach unchanged.
- Learned while building: the remote command passes through the box's login
  shell, which may be fish; rather than quote for every shell, `--bin` is held
  to `[A-Za-z0-9/._~+-]`, not starting with `-` (a leading `~` still expands).
  ssh also gets `-a -x -o ClearAllForwardings=yes`: a sync session forwards no
  agent, X11 or ports to a box. Goal and Approach unchanged.
- Learned while building: with several boxes, each ssh child copies its stderr
  from its own goroutine; a stderr that is not a file is now serialized
  (`lockStderr`). And a box without blindfold can surface as a broken pipe as
  well as EOF, depending on timing (seen on Linux only); both now map to
  `boxsync.ErrNoAnswer`, which carries the `--bin` hint. Goal and Approach
  unchanged.
- Learned in verification (round 1): criteria 6 and 8 failed on Linux because
  the test's fake "future" box answered without reading the client's hello,
  which no blindfold server does; the fake now reads first. The reviewer also
  found a pull stored entries it never asked for; box text reached the
  terminal raw; frames were unbounded; `sync-serve` ran in agent shells;
  comparisons and refused pushes went unaudited; quitting the picker hid
  unreachable boxes. All fixed with tests. Goal and Approach unchanged.
- Learned in verification (round 2): criterion 5 fails as written. Splicing an
  older `remotes` blob that this vault itself sealed back into `vault.sealed`
  repoints a box without refusal; only blobs sealed under another key are
  refused. Also fixed, tests first: a box's stderr reached the terminal raw
  (now escaped by `boxText`); an ssh failure (exit 255) got the `--bin` hint;
  a silent exit printed `(<nil>)`; the test fake ssh fell through to the real
  `~/.blindfold` on an unknown destination (the reviewer's copy of it did,
  and upgraded the user's vault to sealed v3). The Approach text now matches
  the `--bin` and picker decisions above.
- Q: Bind the registry to more state, or rescope criterion 5? A: rescope
  (user, 2026-10-15): refuse a registry sealed under another key; document
  that rollback to one this vault sealed is not detected, because full
  rollback protection needs state outside the vault file, a rollback only
  restores a box the user added, and `~/.ssh/config` — unsealed — already
  decides where a destination connects. Goal criterion 5 changed; approved
  with that answer.
- Learned in verification (round 3, after the rescope): all 8 criteria pass.
  The reviewer found box text still raw in a handshake error, the picker's
  unreachable-box error and its overwrite prompt; push results unchecked
  against what was sent; and an entry left out of an answer passing silently.
  Fixed, tests first: those paths now escape; push results go through the
  same check as pull, and an unanswered entry fails. Two tests were tightened
  (exit codes in `TestSyncNeverExposesValues`, the box's value after a "no" in
  the picker). Goal and Approach unchanged.
- Follow-ups (user, 2026-10-15), closing three open points: a box gets 60
  seconds to answer each request or the handshake (`answerTimeout`; ssh gets
  SIGTERM so it restores a terminal it was prompting on, and the pipes close);
  an idle session never times out, because the picker waits on a person. CI
  runs `scripts/sync-e2e.sh` on Ubuntu (Linux ⇄ Linux; macOS runners have no
  docker). `ssh_guard_test.go` confines ssh to the one call in `ssh.go`, fixed
  arguments first. Goal and Approach unchanged.
