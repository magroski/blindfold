# blindfold

Give a coding agent the credentials it needs without the values landing in the
transcript.

The agent loads a credential into the environment of the command it is about to
run. The command sees the value; the conversation never does.

```
you    $ blindfold add cdp-es --var ES_ENDPOINT=https://logs.internal:9200 \
             --secret ES_API_KEY
         ES_API_KEY: ••••••••

agent  $ blindfold ls
         NAME    VARIABLES                DESCRIPTION
         cdp-es  ES_ENDPOINT ES_API_KEY*  candidate ES cluster (read-only)

agent  $ blindfold exec cdp-es -- python3 report.py
         blindfold: exported ES_ENDPOINT, ES_API_KEY
         42 candidates matched.

       the answer is in the transcript. the API key never was.
```

Works as a plugin for both **Claude Code** and **Codex CLI** from the same repo,
and works just as well with no plugin at all — it is a normal command-line tool.

## Why

The usual ways to hand an agent a credential are all bad: paste it in the
prompt, drop it in a `.env` the agent reads, or let it find your `~/.pgpass`.
All of them write plaintext into `~/.claude/projects/**/*.jsonl` or
`~/.codex/sessions/` — files that are permanent, greppable, and whose contents
were sent to a model provider.

`blindfold exec` makes the convenient path the safe one. The agent gets a working
environment in one line, and never has a reason to look at the value.

## Install

**1. The binary.** On macOS, download the release — a universal build that runs
on both Apple Silicon and Intel, with no Go toolchain needed. It is a credential
store, so verify it rather than piping a download straight into a shell.
`gh attestation verify` proves the tarball was built by this repository's
release workflow. The checksum ships from the same place as the tarball, so it
only catches a corrupted download:

```bash
cd "$(mktemp -d)"
base=https://github.com/magroski/blindfold/releases/latest/download
curl -fsSLO "$base/blindfold_darwin_universal.tar.gz"
curl -fsSLO "$base/checksums.txt"
gh attestation verify blindfold_darwin_universal.tar.gz -R magroski/blindfold
shasum -a 256 -c checksums.txt      # blindfold_darwin_universal.tar.gz: OK
tar -xzf blindfold_darwin_universal.tar.gz
sudo mv blindfold /usr/local/bin/
```

From source instead — any platform, needs Go 1.26 or newer and
`$(go env GOPATH)/bin` on your `PATH`:

```bash
go install github.com/magroski/blindfold/cmd/blindfold@latest
```

Then create the vault:

```bash
blindfold init
```

`init` creates `~/.blindfold` and the master key. On macOS that key is a Keychain
item; elsewhere, set `BLINDFOLD_PASSPHRASE_FILE` or `BLINDFOLD_KEK_FILE` first —
see [Where things live](#where-things-live). `blindfold doctor` confirms what it
found.

The release binary is ad-hoc signed, not notarized. Downloading it with `curl`
as above sets no quarantine flag and it just runs; if you fetch it through a
browser instead, macOS will refuse it until you clear that flag with
`xattr -d com.apple.quarantine blindfold`. Because the Keychain grants silent
access per-binary, macOS also prompts once after you replace `blindfold` with a
new build — choose *Always Allow*, or avoid it entirely with
`BLINDFOLD_KEK_FILE`.

**2. The agent instructions.** Both plugins ship the same skill, which teaches
the agent the `blindfold exec <name> -- <cmd>` pattern so it stops asking you to paste
credentials. Install whichever agents you use — the binary above is a
prerequisite for both, and neither plugin carries it.

```bash
# Claude Code
claude plugin marketplace add magroski/blindfold
claude plugin install blindfold@blindfold

# Codex CLI
codex plugin marketplace add magroski/blindfold
codex plugin add blindfold@blindfold
```

Inside a running Claude Code session, the same thing without leaving the REPL:

```
/plugin marketplace add magroski/blindfold
/plugin install blindfold@blindfold
```

Restart the agent afterwards, then confirm the skill is loaded:

```bash
claude plugin details blindfold    # Skills (1)  using-secrets
codex plugin list                 # blindfold@blindfold  installed, enabled
```

**3. Optional — make every value-printing path, and every change to the vault,
deliberate.** Claude Code permission rules can stop an agent from printing
values unprompted, and from rewriting a credential: a public value such as an
endpoint, repointed with `edit --var`, would take the secret beside it along the
next time `exec` runs. In `~/.claude/settings.json`, or per-project in
`.claude/settings.json`:

```json
{
  "permissions": {
    "ask": [
      "Bash(blindfold env:*)", "Bash(blindfold get:*)", "Bash(blindfold export:*)",
      "Bash(blindfold add:*)", "Bash(blindfold edit:*)", "Bash(blindfold rm:*)",
      "Bash(blindfold remove:*)", "Bash(blindfold import:*)", "Bash(blindfold init:*)"
    ]
  }
}
```

Neither `env` nor `exec` belongs in `allow`: run without `eval`, `env` prints
every value into the transcript, and a prefix rule for `exec` approves whatever
it wraps — `blindfold exec pg-ro -- env` included. Left unlisted, `exec` prompts
with the full command, which is the check you want.

## Storing credentials

A credential is a **named bundle of environment variables**. Each variable is
either sealed or public — public ones are things like an endpoint URL, which
belong with the key but are not themselves secret.

```bash
# One secret, named after the variable it sets
blindfold add STRIPE_SECRET_KEY

# A bundle: the endpoint travels with the key that opens it
blindfold add cdp-es --secret ES_API_KEY \
  --var ES_ENDPOINT=https://logs.internal:9200 \
  --describe "Candidate ES cluster. Read-only." --tags cdp

# A connection string
blindfold add pg-ro --secret DATABASE_URL --describe "Read-only replica"

# A .env file you already have
blindfold import .env --as flux --public API_BASE_URL

# Rotate a value
blindfold edit pg-ro --set DATABASE_URL
```

Values are read from the terminal without being echoed, or from stdin when
piped. They never appear in argv, which every process on this machine can read.

Running `blindfold add <name>` with no flags asks for the description and the
variables one at a time.

## Using them

```bash
blindfold exec cdp-es -- python3 report.py
```

`exec` runs the command with everything the credential declares in its
environment, minus `BLINDFOLD_PASSPHRASE`. blindfold itself prints nothing but the
names it loaded, to stderr, so the agent gets confirmation without the values.
To place a single value under a name of your choosing:

```bash
blindfold exec --set DATABASE_URL=pg-ro -- ./migrate     # the entry's only secret
blindfold exec --set ES_KEY=cdp-es.ES_API_KEY -- ./sync  # one variable of a bundle
blindfold exec --tag cdp -- python3 report.py            # everything tagged cdp
```

No shell sits between `exec` and the command, so `$VAR` on the command line is
expanded by your shell before anything is loaded. To pass a value as an
argument, let a shell inside the new environment expand it:

```bash
blindfold exec pg-ro -- sh -c 'psql "$DATABASE_URL"'
```

To load credentials once for several commands, `env` takes the same arguments
and prints shell that exports them:

```bash
eval "$(blindfold env cdp-es)" && python3 extract.py && python3 report.py
```

Only ever run `env` inside `eval`: its stdout is the values, so run bare in an
agent's shell it prints them into the transcript. At a terminal it masks them
instead of splattering them across your scrollback.

Scripts should read their credentials from the environment and never from a
file:

```python
import os
key = os.environ["ES_API_KEY"]      # set by blindfold exec, absent otherwise
```

| Command | Returns |
|---|---|
| `blindfold ls` | names, variable names, descriptions — never a value |
| `blindfold show <name>` | one credential, sealed values masked |
| `blindfold exec <name> -- <cmd>` | nothing; runs `<cmd>` with the variables set |
| `blindfold env <name>` | shell that exports the variables, for `eval` only |
| `blindfold get <name>` | one bare value, at a terminal only |
| `blindfold export <name>` | `KEY='VALUE'` lines for an env file, at a terminal only; `--raw` prints them unquoted for `docker run --env-file` and must never be sourced |

## What this actually protects against

A security tool that overpromises is worse than none, so plainly:

**It prevents** plaintext landing in the LLM context, the on-disk transcript,
and the model provider's logs by accident or by default. The value goes from the
vault into one command's environment without being rendered anywhere the agent
reads. This is the real win and it is the reason to use it.

**It does not prevent** an agent that wants the value from getting it. Once a
variable is exported, `echo "$ES_API_KEY"` prints it, and `blindfold get --force`
returns it outright. The audit log records that a credential was loaded, which
leaves a trail; it is not a wall.

**There is no scrubbing.** Anything a command prints goes to the agent verbatim.
A client that echoes its own connection string in an error message will put that
credential in the transcript. Prefer credentials that are read-only and cheap to
rotate.

If you want the harness to police this rather than trusting the agent to behave,
Claude Code permission rules are the place — see step 3 of
[Install](#install). `get` and `export` also refuse inside a shell carrying a
known agent marker (`CLAUDECODE`, `CODEX_SANDBOX`), but that list is
best-effort; the permission rule is the control.

## Where things live

```
~/.blindfold/
  vault.json      cleartext metadata — names, variable names, public values
  vault.sealed    encrypted values (XChaCha20-Poly1305, per-entry data keys,
                  each bound to its entry's metadata)
  audit.log       every load, append-only. Never contains values.
```

Metadata is deliberately separate so `ls` needs no key and never prompts. Each
entry's data key is bound to that metadata, public values included, so an edit
to `vault.json` made by hand stops the entry unsealing rather than redirecting
its secret. An entry with no sealed value has no data key and is not covered.
A vault written by 0.3.0 is rewritten in the new format by the first command
that holds the master key.

The master key is one macOS Keychain item. This binary issues exactly one
keychain query, always naming both the service and the account, and never
enumerates — `blindfold doctor --keychain` prints exactly what it touches, and a
test parses the tree and fails if any other file imports the keychain library,
or if that one file enumerates or builds a query missing either attribute.

Four environment variables override the defaults, most explicit first:

| Variable | Effect |
|---|---|
| `BLINDFOLD_KEK_FILE` | read the master key from a 0600 file holding base64 |
| `BLINDFOLD_PASSPHRASE_FILE` | derive it with argon2id from the passphrase in a 0600 file; the salt sits next to the vault |
| `BLINDFOLD_PASSPHRASE` | the same, from the variable itself — avoid: every command the shell runs inherits it, an agent's included, and `doctor` warns |
| `BLINDFOLD_DIR` | put the vault somewhere other than `~/.blindfold` |

There is no keychain outside macOS, and `blindfold` says so rather than quietly
falling back to something weaker — on Linux and in CI, set
`BLINDFOLD_PASSPHRASE_FILE` or `BLINDFOLD_KEK_FILE`. A passphrase file derives
the same key as the same passphrase in `BLINDFOLD_PASSPHRASE` (trailing newlines
are ignored), so switching needs no re-init.

**There is no backup command.** If the Keychain item goes away, `vault.sealed`
is unrecoverable — treat the vault as a convenience cache for credentials you
can re-issue, not as the only copy of anything.

## Auditing

```bash
blindfold audit -n 20
```

```
WHEN                 COMMAND  CREDENTIAL  VARIABLES
2026-08-06 15:05:13  env      cdp-es      ES_ENDPOINT,ES_API_KEY
2026-08-06 15:05:28  get      pg-ro       DATABASE_URL
2026-08-06 15:05:41  get      pg-ro       denied: stdout is not a terminal
```

Refused `get` and `export` calls are recorded as `denied`, with the condition
that triggered the refusal. A log that cannot be written never blocks a command;
it prints `blindfold: audit log not written: …` on stderr instead.

## License

MIT
