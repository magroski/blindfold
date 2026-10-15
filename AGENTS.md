# blindfold

One Go binary, `blindfold`: a credential store that runs a command with
credentials in its environment (`exec`), or prints shell for one to evaluate
(`env`), so a value reaches a command without passing through an agent's
transcript.

## Layout

```
cmd/blindfold/          main; dispatches to internal/cli
internal/vault/        metadata (cleartext) + sealed values, key sources
internal/cli/          every command
internal/audit/        append-only access log
internal/boxsync/      push/pull between dev boxes: ssh transport, E2E channel, protocol
scripts/               test.sh (what CI runs), build-*.sh (what ships), leak-test.sh,
                       sync-e2e.sh (push/pull to a Linux box over real OpenSSH)
docs/                  install, usage, security model — README stays a pitch
```

Supported platforms: macOS and Linux. The master key lives in the macOS
Keychain (`kek_darwin.go`, cgo) or the Linux Secret Service over D-Bus
(`kek_linux.go`, pure Go); elsewhere, only in a key or passphrase file.

## Rules that are not negotiable

- **`env` output is executed.** Values are wrapped in single quotes, with `'`
  and `\` each emitted double-quoted (`'"'"'`, `'"\\"'`) because fish, unlike
  POSIX, honours `\'` inside single quotes; variable names are validated
  against the POSIX name rules on the way in *and* again on the way out,
  because a name is the one part of that string quoting cannot contain.
  `TestEnvQuotingSurvivesARealShell` runs the emitted shell through every
  installed shell among sh, dash, bash, zsh and fish — extend it rather than
  reasoning about it.
- **Secrets never reach argv.** Not when adding them, not when using them. argv
  is readable by every process on the machine.
- **Metadata must stay free of secret material** so `ls` needs no key. A
  variable marked `Secret` may not carry a `Value`; `vault.Entry.Validate`
  enforces it and a test asserts the metadata file never contains plaintext.
- **Metadata is bound to the data key.** `dekAAD` covers the entry name,
  description, tags and every declared variable, so `vault.json` edited by hand
  cannot unseal; `Put` re-binds on every change made through the CLI. Every
  entry has a data key, secrets or not, and every load opens it — an entry
  added by hand has none and is refused. Older sealed files (versions 1 and 2)
  are upgraded the first time the master key is in hand.
- **A wrong key writes nothing.** `init` seals a check value under the master
  key and `openSealed` verifies it before any write. `init` never adopts a key
  it did not create for that directory, and `Put` refuses a directory `init`
  never ran in.
- **Errors never quote input that may be a value.** `readDotenv` names the line
  that failed, not its content: in a `.env`, a line is as likely a value as a key.
- **Keychain access stays in one file, one exact-match query.** See
  `internal/vault/kek_darwin.go`; `keychain_guard_test.go` enforces it. On
  Linux the same holds for the Secret Service: D-Bus only in `kek_linux.go`,
  search by exactly service and account, more than one match refused;
  `secret_service_guard_test.go` enforces it, and a new D-Bus method must be
  added to its allowlist by hand.
- **`get` and `export` refuse plaintext** unless `--force` when stdout is not a
  terminal *or* an agent-shell marker (`CLAUDECODE`, `CODEX_SANDBOX`, …) is set
  — a pty makes an agent's shell look like a terminal. One decision,
  `plaintextRefusal` in `internal/cli/guard.go`; each refusal is audited as
  denied. The marker list is best-effort; the Claude Code `ask` rule is the real
  control. Plaintext should stay awkward; `exec` is the path that should be easy.
- **No `blindfold` command goes in a permission `allow` list.** `exec:*` would
  approve whatever command it wraps; bare `env` prints every value. `exec`
  also drops `BLINDFOLD_PASSPHRASE` from the command's environment. The commands
  that change the vault — `add`, `edit`, `rm`, `import`, `init` — go in `ask`
  beside `env`, `get` and `export`: `edit --var` can repoint a public endpoint,
  and the secret beside it would follow. So do `remote`, `sync`, `push`, `pull`
  and `sync-serve`: they copy credentials to other machines. So do `ssh`,
  `scp`, `sftp` and `rsync`: a box set up for sync opens its vault to any ssh
  session.
- **Values cross between boxes only inside the encrypted channel.**
  `internal/boxsync` runs the system `ssh` and, inside it, its own X25519 +
  XChaCha20-Poly1305 session, so `sync-serve`'s stdout is never plaintext.
  Transfers are always here ⇄ one box. The box list is sealed in
  `vault.sealed`; a box's `--bin` is held to characters every shell reads
  literally, because it reaches the box's login shell unquoted.
  `scripts/sync-e2e.sh` proves it against a Linux box over real OpenSSH.
  ssh runs from one call in `internal/boxsync/ssh.go`, fixed arguments first,
  without `BLINDFOLD_PASSPHRASE`; `ssh_guard_test.go` enforces it, and a new
  file that starts programs must be added to its allowlist by hand. A copy is
  whole — a missing secret is refused, never merged — and may not declare a
  variable that runs code or redirects traffic (`hijackingVars` in
  `internal/boxsync/protocol.go`). A held-open vault calls `Reload` before
  each operation, so it decides on what is on disk now.
  A box gets 60 seconds to answer each request; an idle session never times
  out, because the picker waits on a person.

## Reading several secrets

Piped input is consumed whole so a multi-line value survives, which makes two
piped secrets ambiguous — `add` and `edit` refuse it rather than silently
handing the whole stream to the first.

At a terminal, hidden reads bypass the buffered line reader, so a command that
mixes visible and hidden prompts must share **one** `prompter` (see
`internal/cli/term.go`). Building a second one discards whatever the first had
buffered, which desynchronizes every prompt after it.

## Testing

```bash
scripts/test.sh      # gofmt, vet, go test -race; what CI runs
```

On Linux it starts a throwaway gnome-keyring — private session bus, temporary
`XDG_DATA_HOME` and `XDG_RUNTIME_DIR` — and points
`BLINDFOLD_TEST_SECRET_SERVICE` at that data directory. The Secret Service
tests delete items, so they refuse to run against any other. Under `CI`, a missing shell (sh, dash, bash, zsh, fish) fails the run
instead of skipping. `.github/workflows/ci.yml` runs it on Ubuntu and macOS,
plus govulncheck, and `scripts/sync-e2e.sh` on Ubuntu (macOS runners have no
docker).

The tests that matter most are the adversarial ones: shell escaping and variable
name validation in `internal/cli`, and AAD binding in `internal/vault`. When
changing those, add the attack you thought of before adding the feature.

`scripts/leak-test.sh` is the end-to-end claim: it runs a real agent session
against a disposable database and greps the resulting transcript for the
password in six encodings. It needs docker and the `claude` CLI.

## Releasing

```bash
git tag v0.2.0 && git push origin v0.2.0
```

`.github/workflows/release.yml` runs the tests on each OS, then
`scripts/build-macos.sh` (macOS universal) and `scripts/build-linux.sh` (static
amd64 and arm64), and attaches the results to a GitHub release with one
`checksums.txt` and a build attestation. Run those scripts locally to get the
same artifacts in `dist/` — the workflow calls them rather than reimplementing
the build, so there is one definition of what ships.

Two things about the macOS build are easy to break:

- **cgo is mandatory.** `go-keychain` binds the Security framework, so
  `CGO_ENABLED=0` does not produce a working darwin binary. Each arch is
  compiled with `CGO_CFLAGS`/`CGO_LDFLAGS` forcing the target arch.
- **`lipo` invalidates signatures.** Merging the two arches writes a fresh
  Mach-O without the signature the Go linker applied, and an unsigned arm64
  binary will not execute at all. The script re-signs ad-hoc afterwards; the
  workflow's verify step fails if that stops happening.

Bump `version` in `.claude-plugin/plugin.json`, its `marketplace.json` entry, and
`.codex-plugin/plugin.json` together — `claude plugin tag` checks the first two
agree before tagging.
