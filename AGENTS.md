# blindfold

One Go binary, `blindfold`: a credential store that runs a command with
credentials in its environment (`exec`), or prints shell for one to evaluate
(`env`), so a value reaches a command without passing through an agent's
transcript.

## Layout

```
cmd/blindfold/          main; dispatches to internal/cli
internal/vault/        metadata (cleartext) + sealed values, keychain
internal/cli/          every command
internal/audit/        append-only access log
```

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
- **Public values are bound to the data key.** `dekAAD` covers the entry name
  and every declared variable, so `vault.json` edited by hand cannot unseal;
  `Put` re-binds on every change made through the CLI. Version-1 sealed files
  are upgraded the first time the master key is in hand. An entry with no
  secret has no data key and is not covered.
- **Errors never quote input that may be a value.** `readDotenv` names the line
  that failed, not its content: in a `.env`, a line is as likely a value as a key.
- **Keychain access stays in one file, one exact-match query.** See
  `internal/vault/kek_darwin.go`; `keychain_guard_test.go` enforces it.
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
  and the secret beside it would follow.

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
go test ./...
```

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

`.github/workflows/release.yml` runs the tests, then `scripts/build-macos.sh`,
and attaches the result to a GitHub release. Run that script locally to get the
same artifacts in `dist/` — the workflow calls it rather than reimplementing the
build, so there is one definition of what ships.

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
