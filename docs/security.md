# Security model

A security tool that overpromises is worse than none, so plainly.

## What it protects against

Plaintext reaching the LLM context, the on-disk transcript
(`~/.claude/projects/**/*.jsonl`, `~/.codex/sessions/`) and the model
provider's logs by accident or by default. The value goes from the vault into
one command's environment without being rendered anywhere the agent reads.

`scripts/leak-test.sh` checks that claim end to end: a real agent session
queries a disposable Postgres through blindfold, then every transcript the
session wrote — subagents' included — is searched for the password in six
encodings.

## What it does not

- **An agent that wants the value can get it.** Once a variable is exported,
  `echo "$ES_API_KEY"` prints it, and `blindfold get --force` returns it
  outright. The audit log leaves a trail; it is not a wall.
- **There is no output scrubbing.** Anything a command prints reaches the agent
  verbatim. A client that echoes its connection string in an error, or a
  `curl -v`, puts the credential in the transcript.
- **argv is public.** blindfold never puts a value in argv, but
  `sh -c 'psql "$DATABASE_URL"'` makes the inner shell do it. Prefer programs
  that read the environment.
- **Processes running as you are trusted.** They can read `~/.blindfold`, your
  key file, and — on Linux — the Secret Service item. See
  [key sources](#key-sources).

Use credentials that are read-only and cheap to rotate. To have the harness
police the agent rather than trusting it, use the
[permission rules](install.md#3-permission-rules).

## The plaintext guard

`get` and `export` refuse to print unless stdout is a terminal *and* no
agent-shell marker (`CLAUDECODE`, `CODEX_SANDBOX`,
`CODEX_SANDBOX_NETWORK_DISABLED`) is set, even to an empty string — a pty makes
an agent's shell look like a terminal. `--force` overrides it. Every refusal is
audited as `denied`.

The marker list is best-effort: a harness not listed, or one that scrubs its
environment, goes undetected. The permission rule is the real control.

## How values are stored

```
~/.blindfold/                 (0700; files 0600; vault files replaced atomically)
  vault.json      cleartext metadata: names, descriptions, tags, variable
                  names, public values. `ls` reads only this, so it needs no key.
  vault.sealed    encrypted values
  audit.log       every load and refusal, append-only. Never a value.
  kek.salt        argon2id salt, only with a passphrase key source
```

Envelope encryption, XChaCha20-Poly1305 throughout:

```
master key (KEK) ── wraps ──▶ one data key (DEK) per entry ── encrypts ──▶ that entry's values
   Keychain /                   AAD: name + description +                AAD: "<entry>/<variable>"
   Secret Service / file        tags + variables (public values too)
```

- **Values are bound to their place.** A ciphertext moved to another entry or
  variable does not decrypt.
- **Metadata is bound to its key.** Each data key is bound to everything
  `vault.json` says about its entry except timestamps. Repoint `ES_ENDPOINT` by
  hand and the key stays sealed instead of being sent to the new host. Changes
  made through `blindfold edit` re-bind.
- **Every entry is vouched for.** An entry with no secret still owns a data key,
  and every load opens it. One added to `vault.json` by hand has none, so it
  cannot slip `HTTPS_PROXY` into a `--tag` load beside a real secret.
- **A wrong key writes nothing.** `init` seals a check value under the master
  key. A mistyped passphrase fails that check before anything is sealed, rather
  than splitting the vault between two keys.
- **Older vaults upgrade once.** The first command that holds the master key
  re-binds a vault written by an earlier version. That is the one window a
  tamperer has: metadata edited before then is bound as it stands. A file
  relabelled as older afterwards is refused. The upgrade is one-way: earlier
  versions of blindfold cannot read the new format.

There is no backup command. If the master key goes away, `vault.sealed` is
unrecoverable — treat the vault as a cache of credentials you can re-issue.

## Key sources

Most explicit first:

| Variable | Master key |
|---|---|
| `BLINDFOLD_KEK_FILE` | base64 key in a 0600 file |
| `BLINDFOLD_PASSPHRASE_FILE` | derived with argon2id (t=3, 64 MiB, p=4) from the passphrase in a 0600 file |
| `BLINDFOLD_PASSPHRASE` | the same, from the variable — avoid: every command the shell runs inherits it, an agent's included. `exec` drops it from the command's environment, and `doctor` warns |
| *(none)* | the OS keychain, below |

`BLINDFOLD_DIR` moves the vault away from `~/.blindfold`. A passphrase file
derives the same key as the same passphrase in the variable (trailing newlines
are ignored), so switching needs no re-init.

| Source | At rest | Who can read it while you are logged in |
|---|---|---|
| macOS Keychain | encrypted by the login keychain; never synced to iCloud | blindfold silently; any other program only after a macOS prompt |
| Linux Secret Service | encrypted by your login keyring | any process running as you, while the keyring is unlocked — Secret Service has no per-application access control |
| Key file | as strong as the filesystem | any process running as you |
| Passphrase file | as strong as the filesystem | any process running as you |

**One item, exact match.** On macOS the binary issues one Keychain query, always
naming both service (`com.magroski.blindfold`) and account (`vault-kek`), and
never enumerates. On Linux it searches the Secret Service by the same two
attributes and refuses if more than one item matches, rather than guess. Parsing
tests (`keychain_guard_test.go`, `secret_service_guard_test.go`) fail the build
if any other file reaches either API, or if a query is widened, an item deleted
or a collection listed. `blindfold doctor --keychain` prints a command that
shows the item without its secret.

## Between dev boxes

`push`, `pull` and `sync` run the system `ssh` — your config, agent and
`known_hosts` — with agent, X11 and port forwarding off, and start
`blindfold sync-serve` on the box. Inside that SSH channel the two blindfolds
encrypt again, end to end:

```
here                                         box
  hello: X25519 public key  ──────────────▶
                            ◀──────────────  hello: X25519 public key
  HKDF-SHA256 → one key per direction, one for digests
  XChaCha20-Poly1305 frames, numbered       ◀──────▶
```

- **No plaintext on any stdout.** Without the inner layer, an agent running
  `ssh box blindfold sync-serve` could read values off the stream. A frame
  altered, replayed, reordered or reflected ends the session, as does one over
  16 MiB. `sync-serve` refuses to run in a shell carrying an agent marker.
- **A box set up for sync is readable over ssh.** Its vault must open in a
  non-interactive ssh session, so anything that can ssh in as you can read
  it: `ssh box blindfold get NAME --force`, or a pull into a throwaway vault.
  Agent markers do not cross ssh, and a `blindfold` permission rule does not
  match a command that starts with `ssh`. Keep `ssh` in the `ask` list
  ([install](install.md#3-permission-rules)), and trust a box as you trust
  this machine.
- **A box answers only for what was asked.** A pull answered with another
  entry, or one twice, is refused before anything is stored; so are push
  results for an entry never sent, an unknown outcome, and an entry name no
  vault would accept. An entry left out of an answer fails. Text from a box
  is escaped before it reaches the terminal, bidi controls included.
- **A copy is whole, and carries no known hijack.** An entry missing a value
  for a secret it declares is refused rather than merged with the one already
  there: a box cannot keep your key under its endpoint. An entry declaring a
  variable that can make a program run code or send its traffic elsewhere —
  `LD_PRELOAD`, `NODE_OPTIONS`, `GIT_SSH_COMMAND`, `GIT_EXTERNAL_DIFF`,
  `PAGER`, `HTTPS_PROXY`, `PATH` and the like, any case — is refused both
  ways; add it by hand where it is meant. That is a list, and no list is
  complete: every entry stored prints its variable names, for you to read.
- **Nothing secret in argv.** ssh's arguments are fixed options, the
  destination and `<bin> sync-serve`.
- **Each vault keeps its own key.** Values are re-sealed on arrival under the
  receiving vault's master key; no key leaves a machine.
- **Comparison without values.** `sync` exchanges keyed digests, valid only in
  that session.
- **The box list is sealed.** It lives in `vault.sealed` under the master
  key, so a list written or copied in from elsewhere is refused before ssh
  runs. Rolling back to a list this vault sealed earlier is not detected: it
  can only restore a box you once added, and whoever can write
  `~/.blindfold` can as easily edit `~/.ssh/config`, which decides where a
  destination connects.
- **Both sides audit.** Here: `push`, `pull` and each `sync` comparison,
  naming the box; a push refused or never answered is logged too, since its
  values were sent. On the box: `sync-serve`, naming the ssh client's
  address, every entry received with what storing it did, and a refusal in
  an agent's shell.

A push hands the credential to that box and to anyone who controls it. blindfold
trusts your SSH setup to reach the right machine; it cannot do better than
`known_hosts`.

## What blindfold refuses

Failing loudly beats quietly downgrading:

- `init` inside a git work tree, or with a key file inside one.
- `init` adopting a master key it did not create for this directory, or a
  `vault.sealed` left behind by a key that is gone.
- Writing to a directory `init` never ran in.
- Running with no keychain and no key file configured.
- Two Secret Service items claiming to be the master key.
- Variable names outside POSIX rules, on the way in and again on the way out:
  `env` output is executed, and a name is the one part quoting cannot contain.
- Entry names that read as flags, values containing NUL, control characters in
  descriptions and tags.
- Two loaded entries setting one variable to different values.
- Replacing an entry that differs on the receiving box without `--overwrite`
  or a yes in the picker; a copied entry missing a secret value, or declaring
  a variable that runs code or redirects traffic; a box list sealed under
  another key; an ssh destination that reads as an option.
- Echoing a secret when the terminal cannot hide input.

Errors never quote a value. Listings escape control characters, so a hand-edited
`vault.json` cannot drive the terminal or forge a row of `ls`.

## Reporting a vulnerability

Report privately through
[GitHub security advisories](https://github.com/magroski/blindfold/security/advisories/new),
not a public issue. Include the version (`blindfold version`), platform, and the
smallest reproduction you have.
