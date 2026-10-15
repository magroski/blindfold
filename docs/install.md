# Install

1. [The binary](#1-the-binary)
2. [The agent skill](#2-the-agent-skill)
3. [Permission rules](#3-permission-rules)

## 1. The binary

### Release download

| Platform | Tarball |
|---|---|
| macOS, Apple Silicon and Intel | `blindfold_darwin_universal.tar.gz` |
| Linux x86-64 | `blindfold_linux_amd64.tar.gz` |
| Linux ARM64 | `blindfold_linux_arm64.tar.gz` |

The Linux binaries are static: any distribution, glibc or musl.

blindfold is a credential store, so verify it rather than piping a download into
a shell. `gh attestation verify` proves the tarball was built by this
repository's release workflow. `checksums.txt` ships from the same place as the
tarball, so on its own it only catches a corrupted download.

```bash
cd "$(mktemp -d)"
f=blindfold_linux_amd64.tar.gz      # pick yours from the table
base=https://github.com/magroski/blindfold/releases/latest/download
curl -fsSLO "$base/$f"
curl -fsSLO "$base/checksums.txt"
gh attestation verify "$f" -R magroski/blindfold
grep " $f\$" checksums.txt | shasum -a 256 -c      # <file>: OK
tar -xzf "$f"
sudo mv blindfold /usr/local/bin/
```

**macOS notes.** The binary is ad-hoc signed, not notarized. Downloaded with
`curl` it carries no quarantine flag and runs; fetched through a browser, macOS
refuses it until you run `xattr -d com.apple.quarantine blindfold`. The Keychain
grants silent access per binary, so after replacing `blindfold` with a new build
macOS prompts once — choose *Always Allow*.

### From source

Go 1.26 or newer, with `$(go env GOPATH)/bin` on your `PATH`. On macOS, cgo must
be available (the Xcode command line tools), because the Keychain is reached
through the Security framework.

```bash
go install github.com/magroski/blindfold/cmd/blindfold@latest
```

### Create the vault

```bash
blindfold init
blindfold doctor      # what it found, and where the master key lives
```

`init` creates `~/.blindfold` and a random master key. Where that key lives
depends on the machine:

| Machine | Master key | Setup |
|---|---|---|
| macOS | Keychain item, this device only, never synced | none |
| Linux desktop (GNOME Keyring, KWallet, KeePassXC) | Secret Service item in the default keyring | none |
| Linux server, SSH, WSL, containers, CI | passphrase or key file | set `BLINDFOLD_PASSPHRASE_FILE` or `BLINDFOLD_KEK_FILE` first |

With no keyring available, `blindfold` says so and names both alternatives
rather than falling back to something weaker:

```bash
umask 077
printf '%s' 'a long passphrase' > ~/.config/blindfold-passphrase
export BLINDFOLD_PASSPHRASE_FILE=~/.config/blindfold-passphrase   # in your shell profile
blindfold init
```

The trade-offs between these are in [security.md](security.md#key-sources).

## 2. The agent skill

Both plugins ship the same skill, which teaches the agent the
`blindfold exec <name> -- <cmd>` pattern so it stops asking you to paste
credentials. Neither carries the binary; install that first.

```bash
# Claude Code
claude plugin marketplace add magroski/blindfold
claude plugin install blindfold@blindfold

# Codex CLI
codex plugin marketplace add magroski/blindfold
codex plugin add blindfold@blindfold
```

Inside a running Claude Code session:

```
/plugin marketplace add magroski/blindfold
/plugin install blindfold@blindfold
```

Restart the agent, then confirm:

```bash
claude plugin details blindfold    # Skills (1)  using-secrets
codex plugin list                  # blindfold@blindfold  installed, enabled
```

## 3. Permission rules

Optional, recommended. Claude Code permission rules make every value-printing
path, every change to the vault, and every copy to another box a deliberate
act. A change matters as much as a print: a public endpoint repointed with
`edit --var` takes the secret beside it along the next time `exec` runs.

In `~/.claude/settings.json`, or per project in `.claude/settings.json`:

```json
{
  "permissions": {
    "ask": [
      "Bash(blindfold env:*)", "Bash(blindfold get:*)", "Bash(blindfold export:*)",
      "Bash(blindfold add:*)", "Bash(blindfold edit:*)", "Bash(blindfold rm:*)",
      "Bash(blindfold remove:*)", "Bash(blindfold import:*)", "Bash(blindfold init:*)",
      "Bash(blindfold remote:*)", "Bash(blindfold sync:*)", "Bash(blindfold push:*)",
      "Bash(blindfold pull:*)", "Bash(blindfold sync-serve:*)",
      "Bash(ssh:*)", "Bash(scp:*)", "Bash(sftp:*)", "Bash(rsync:*)"
    ]
  }
}
```

No `blindfold` command belongs in `allow`. Run without `eval`, `env` prints
every value, and a prefix rule for `exec` approves whatever it wraps —
`blindfold exec pg-ro -- env` included. Left unlisted, `exec` prompts with the
full command, which is the check you want.

Prefix rules match how a command starts. A wrapper — `sh -c '…'`, `env -u X …`,
`script … blindfold get` — starts differently, so keep broad rules such as
`Bash(sh:*)` out of `allow` too. `ssh` is the wrapper that matters once you
sync: a box set up for it opens its vault to any ssh session, so
`ssh box blindfold get NAME --force` prints a value, and no `blindfold` rule
sees it. The rules above make every command that starts with `ssh`, `scp`,
`sftp` or `rsync` a deliberate act; one that reaches ssh another way
(`/usr/bin/ssh`, `git -c core.sshCommand=…`) starts differently and is not
caught.
