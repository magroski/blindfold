# blindfold

**Let coding agents use your credentials without ever seeing them.**

The agent runs `blindfold exec <name> -- <command>`. The command gets the
credential in its environment. The conversation, the transcript on disk and the
model provider never get the value.

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

## Why

Pasting a key into the prompt, pointing the agent at `.env`, letting it read
`~/.pgpass` — each writes plaintext into session transcripts that are
permanent, greppable, and were sent to a model provider. blindfold makes the
convenient path the safe one.

- **Values stay out of the conversation.** `exec` hands them to one process;
  `ls` shows names only.
- **Encrypted at rest.** XChaCha20-Poly1305 per entry; the master key lives in
  the macOS Keychain or the Linux Secret Service.
- **Tamper-evident.** Edit the metadata by hand to repoint an endpoint, and the
  secret stops unsealing instead of following it.
- **Audited.** Every load is logged — names, never values.
- **Across dev boxes.** `blindfold sync` compares this machine with your other
  boxes over SSH; push or pull a credential without it ever leaving a vault in
  plaintext.
- **Agent-ready.** A skill for Claude Code and Codex CLI teaches the pattern.
  Without one, it is a plain CLI.

## Install

macOS (universal) and Linux (amd64, arm64). Verify before you install: it is a
credential store.

```bash
f=blindfold_darwin_universal.tar.gz   # or blindfold_linux_amd64.tar.gz, blindfold_linux_arm64.tar.gz
curl -fsSLO "https://github.com/magroski/blindfold/releases/latest/download/$f"
gh attestation verify "$f" -R magroski/blindfold   # built by this repo's release workflow
tar -xzf "$f" && sudo mv blindfold /usr/local/bin/
blindfold init
```

Then the agent skill:

```bash
claude plugin marketplace add magroski/blindfold && claude plugin install blindfold@blindfold
codex plugin marketplace add magroski/blindfold && codex plugin add blindfold@blindfold
```

From source, headless Linux, and permission rules: [docs/install.md](docs/install.md).

## Use

```bash
blindfold add pg-ro --secret DATABASE_URL     # prompts without echo; never in argv
blindfold exec pg-ro -- ./migrate             # what the agent runs
```

More: [docs/usage.md](docs/usage.md).

## Limits

blindfold stops credentials leaking by accident or by default. It does not stop
an agent set on reading one: a command that prints its environment prints the
secret. Use read-only, rotatable credentials and the
[permission rules](docs/install.md#3-permission-rules). The full threat model is
in [docs/security.md](docs/security.md).

## License

MIT
