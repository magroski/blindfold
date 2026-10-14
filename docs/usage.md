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
| `doctor` | vault and key-source health; `--keychain` shows the one item read |

`blindfold <command> -h` lists a command's flags.
