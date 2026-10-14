#!/usr/bin/env bash
#
# Run every check CI runs: formatting, vet, and the tests under the race
# detector. CI and the release workflow call this, so a green run here is a
# green run there.
#
# On Linux the Secret Service tests run too, against a throwaway gnome-keyring
# on a private session bus. A private bus is not enough on its own: the daemon
# would still open the keyrings in ~/.local/share, and the tests delete items.
# Its data and runtime directories are therefore throwaway too:
#
#   dbus-run-session ── gnome-keyring-daemon   XDG_DATA_HOME, XDG_RUNTIME_DIR: mktemp
#                    └─ go test                BLINDFOLD_TEST_SECRET_SERVICE=$XDG_DATA_HOME
#
# Usage: scripts/test.sh
# Requires: go. On Linux, dbus-run-session and gnome-keyring-daemon for the
# Secret Service tests; without them those tests skip, except under CI.
# The shell-quoting tests want sh, dash, bash, zsh and fish; under CI
# (CI is set) a missing one fails the run instead of skipping.

set -euo pipefail

cd "$(dirname "$0")/.."

readonly IN_SESSION=--in-session
readonly KEYRING_PASSWORD=throwaway-test-keyring
readonly SECRETS_BUS_NAME=org.freedesktop.secrets
readonly READY_ATTEMPTS=50 # tenths of a second

run_checks() {
  local unformatted
  unformatted="$(gofmt -l .)"
  if [[ -n "${unformatted}" ]]; then
    printf 'gofmt: these files need formatting:\n%s\n' "${unformatted}" >&2
    exit 1
  fi
  go vet ./...
  go test -race -count=1 ./...
}

# Inside the private bus: start the keyring, wait for it to own its name, test.
if [[ "${1:-}" == "${IN_SESSION}" ]]; then
  keyring_home="$(mktemp -d)"
  trap 'rm -rf "${keyring_home}"' EXIT
  mkdir -m 700 "${keyring_home}/data" "${keyring_home}/runtime"
  export XDG_DATA_HOME="${keyring_home}/data" XDG_RUNTIME_DIR="${keyring_home}/runtime"
  printf '%s' "${KEYRING_PASSWORD}" | gnome-keyring-daemon --unlock --components=secrets >/dev/null
  for _ in $(seq "${READY_ATTEMPTS}"); do
    if dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
      org.freedesktop.DBus.NameHasOwner "string:${SECRETS_BUS_NAME}" 2>/dev/null | grep -q 'boolean true'; then
      break
    fi
    sleep 0.1
  done
  export BLINDFOLD_TEST_SECRET_SERVICE="${XDG_DATA_HOME}"
  run_checks
  exit 0
fi

if [[ "$(uname -s)" == Linux ]] && command -v dbus-run-session >/dev/null && command -v gnome-keyring-daemon >/dev/null; then
  exec dbus-run-session -- "$0" "${IN_SESSION}"
fi
if [[ "$(uname -s)" == Linux && -n "${CI:-}" ]]; then
  echo "CI on Linux must run the Secret Service tests; install dbus and gnome-keyring" >&2
  exit 1
fi
run_checks
