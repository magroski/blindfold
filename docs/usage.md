# Usage

## Storing credentials

A credential is a **named bundle of environment variables**. Each variable is
sealed or public. Public ones — an endpoint URL, a database host — belong with
the key but are not secret themselves.

```bash
# One secret, named after the variable it sets
blindfold add STRIPE_SECRET_KEY

# A bundle: the endpoint travels with the key that opens it
blindfold add cdp-es --secret ES_API_KEY \
  --var ES_ENDPOINT=https://logs.internal:9200 \
  --describe "Candidate ES cluster. Read-only." --tags cdp

# Postgres the way libpq reads it, so no command line ever carries the password
blindfold add pg-ro --var PGHOST=replica.internal --var PGUSER=ro \
  --var PGDATABASE=analytics --secret PGPASSWORD

# A .env file you already have
blindfold import .env --as flux --public API_BASE_URL

# Rotate a value
blindfold edit pg-ro --set PGPASSWORD
```

Values are read from the terminal without echo, or from stdin when piped. They
never appear in argv, which every process on the machine can read. A terminal
that cannot hide input is refused rather than echoed to; pipe the value in
instead.

`blindfold add <name>` with no flags asks for the description and variables one
at a time.

## Using them

```bash
blindfold exec cdp-es -- python3 report.py
```

`exec` runs the command with everything the credential declares in its
environment, minus `BLINDFOLD_PASSPHRASE`. blindfold prints only the names it
loaded, to stderr.

```bash
blindfold exec --set DATABASE_URL=pg-ro -- ./migrate     # the entry's only secret
blindfold exec --set ES_KEY=cdp-es.ES_API_KEY -- ./sync  # one variable of a bundle
blindfold exec --tag cdp -- python3 report.py            # every entry tagged cdp
```

Scripts read credentials from the environment, never from a file:

```python
import os
key = os.environ["ES_API_KEY"]      # set by blindfold exec, absent otherwise
```

### Arguments

No shell sits between `exec` and the command, so `$VAR` on the command line is
expanded by your shell before anything is loaded — to nothing. Prefer programs
that read the environment (`psql` reads `PGPASSWORD`). When one only takes an
argument, let a shell inside the new environment expand it:

```bash
blindfold exec pg-ro -- sh -c 'psql "$DATABASE_URL"'
```

That keeps the value out of the conversation, but it is in `psql`'s argv —
visible to every process on the machine — while it runs.

### Several commands: `env`

`env` takes the same arguments and prints shell that exports them:

```bash
eval "$(blindfold env cdp-es)" && python3 extract.py && python3 report.py
```

Only ever run `env` inside `eval`. Its stdout is the values: run bare in an
agent's shell, it prints them into the transcript. At a terminal it masks them.
The output is safe to evaluate in sh, dash, bash, zsh and fish.

## Reading a value yourself

| Command | Prints |
|---|---|
| `blindfold ls` | names, variable names, descriptions — never a value |
| `blindfold show <name>` | one credential, sealed values masked |
| `blindfold get <name>` | one bare value |
| `blindfold export <name>` | `KEY='VALUE'` lines for an env file |

`get` and `export` print plaintext only to a terminal, and not in a shell
marked as an agent's (`CLAUDECODE`, `CODEX_SANDBOX`). `--force` overrides both,
and is audited as forced.

```bash
blindfold get stripe | pbcopy          # refused: stdout is a pipe
blindfold get stripe --force | pbcopy  # allowed, logged
blindfold export pg-ro --force > .env
docker run --env-file <(blindfold export pg-ro --force --raw) app
```

`--raw` prints values unquoted for `docker --env-file`. Never source raw output
in a shell: a value like `$(cmd)` would run.

## Across dev boxes

Copy credentials between this machine and your other dev boxes over SSH. Every
transfer runs between here and one box, never box to box.

```bash
blindfold remote add mac-box me@mac.local          # any ssh destination or ~/.ssh/config alias
blindfold remote add linux-box dev-linux --bin ~/go/bin/blindfold
blindfold sync                                      # compare every box with this one
```

```
#  ENTRY    here  linux-box  mac-box
1  openai   ●     —          —
2  pg-ro    ●     ≠          ●
3  stripe   —     ●          ●

● present  ≠ differs from here  — missing  ? unreachable

push <#,#> <box>...  |  pull <#,#> <box>  |  Enter to quit
> push 1 mac-box linux-box
```

At a terminal, `sync` asks what to copy, and asks again before replacing an
entry that differs. From a script it prints the table only. The same, without
the picker:

```bash
blindfold push mac-box openai                 # here → box
blindfold pull mac-box stripe                 # box → here
blindfold push linux-box pg-ro --overwrite    # replace an entry that differs
```

A credential travels whole — description, tags, every variable — and is sealed
on arrival under the receiving vault's own master key. `≠` compares secret
values too, without sending them. Removing an entry is never copied. Each
entry stored prints its variable names (`stripe  created: STRIPE_KEY`); read
them. One declaring a variable that can make a program run code, load its
configuration from elsewhere, skip certificate checks or send its traffic
elsewhere — `LD_PRELOAD`, `GIT_SSH_COMMAND`, `MAKEFLAGS`, `HOME`,
`HTTPS_PROXY` and the like — is refused; add it by hand where it is meant.
Endpoints such as `OPENAI_BASE_URL` travel. That is a list, and no list is
complete.

### Setting up a box

Each box needs blindfold, an initialized vault, and a master key that loads in
a **non-interactive** ssh session, which reads fewer startup files than your
terminal does:

- **blindfold not found:** point at it with `--bin` when adding the box.
- **Linux without a desktop session:** use a passphrase file, exported where
  `ssh box cmd` sees it — `~/.zshenv` for zsh; for bash, the first line of
  `~/.bashrc`, above any line that returns early for non-interactive shells.
- **macOS:** the Keychain may be locked in an ssh session; unlock it with
  `security unlock-keychain`, or use a key or passphrase file.

A box set up this way opens its vault to anything that can ssh in as you,
an agent included: keep `ssh`, `scp`, `sftp` and `rsync` in the `ask` list
(see [security](security.md#between-dev-boxes)). Install the same blindfold
on every machine: an older one that writes the vault forgets the box list
(`remote add` again; no credential is lost).

Check a box with `ssh <box> blindfold doctor`. When a box fails, `sync` and
`push` show its own message and change nothing. A box gets 60 seconds to
answer each request, ssh's own prompts included; one that does not is
dropped — though a push it had received may still be stored once it gets
there, so check with `sync`. The picker waiting on you is not a request and
never times out. One push carries up to about 9 MiB of values.

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

Refused `get` and `export` calls are recorded as `denied`, with the reason. A
log that cannot be written never blocks a command; it prints
`blindfold: audit log not written: …` on stderr.

## Commands

| Command | Does |
|---|---|
| `init` | create the vault and its master key |
| `add <name>` | store a credential |
| `import <file> --as <name>` | store a `.env` file as one credential |
| `edit <name>` | change metadata, rotate a value, add or remove a variable |
| `rm <name>` | remove a credential |
| `ls` | list credentials |
| `show <name>` | one credential, values masked |
| `exec <name>... -- <cmd>` | run a command with the variables set |
| `env <name>...` | print shell that exports the variables |
| `get <name>` | print one value (terminal only) |
| `export <name>` | print `KEY='VALUE'` lines (terminal only) |
| `audit` | recent credential access |
| `remote add <box> <dest>` | register a dev box; `remote ls`, `remote rm <box>` |
| `sync [box...]` | compare boxes with this one; at a terminal, push and pull |
| `push <box> <name>...` | copy credentials to a box |
| `pull <box> <name>...` | copy credentials from a box |
| `doctor` | vault and key-source health; `--keychain` shows the one item read |

`blindfold <command> -h` lists a command's flags.
