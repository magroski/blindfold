#!/usr/bin/env bash
#
# Push and pull between this machine and a Linux box over real OpenSSH.
#
# The unit tests fake ssh; this does not. A Linux container runs sshd and a
# static blindfold whose vault unlocks from a passphrase file, exported the way
# docs/usage.md says a box must: where a non-interactive ssh session sees it.
#
#   this machine                         container (Linux, sshd on 127.0.0.1)
#   blindfold push/pull/sync ── ssh ──▶  dev@box: blindfold sync-serve
#   vault: key file in $WORK             vault: passphrase file, from ~/.bashrc
#
# Usage: scripts/sync-e2e.sh
# Requires: docker, go, ssh, ssh-keygen.

set -euo pipefail

cd "$(dirname "$0")/.."

readonly IMAGE=blindfold-sync-e2e
readonly CONTAINER=blindfold-sync-e2e
readonly LOCAL_SECRET='local-key-not-for-transcripts'
readonly BOX_SECRET='box-token-not-for-transcripts'
readonly BOX_PASSPHRASE='box passphrase for the e2e test'

WORK="$(mktemp -d)"
cleanup() {
  docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
  rm -rf "${WORK}"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

echo "==> building blindfold for here and for the box"
go build -o "${WORK}/bin/blindfold" ./cmd/blindfold
arch="$(docker info --format '{{.Architecture}}')"
case "${arch}" in
  x86_64 | amd64) goarch=amd64 ;;
  aarch64 | arm64) goarch=arm64 ;;
  *) fail "unsupported docker architecture ${arch}" ;;
esac
CGO_ENABLED=0 GOOS=linux GOARCH="${goarch}" go build -o "${WORK}/blindfold-linux" ./cmd/blindfold

echo "==> starting a Linux box with sshd"
ssh-keygen -q -t ed25519 -N '' -f "${WORK}/id"
docker build -q -t "${IMAGE}" - >/dev/null <<'EOF'
FROM debian:stable-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends openssh-server >/dev/null \
 && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd && useradd -m -s /bin/bash dev
CMD ["/usr/sbin/sshd", "-D", "-e"]
EOF
docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
docker run -d --name "${CONTAINER}" -p 127.0.0.1::22 "${IMAGE}" >/dev/null
docker cp "${WORK}/blindfold-linux" "${CONTAINER}:/usr/local/bin/blindfold"
docker cp "${WORK}/id.pub" "${CONTAINER}:/home/dev/authorized_keys"
docker exec -i "${CONTAINER}" bash -s <<EOF
set -e
mkdir -p -m 700 /home/dev/.ssh /home/dev/.config
mv /home/dev/authorized_keys /home/dev/.ssh/authorized_keys
printf '%s' '${BOX_PASSPHRASE}' > /home/dev/.config/blindfold-passphrase
chmod 600 /home/dev/.ssh/authorized_keys /home/dev/.config/blindfold-passphrase
# First line: Debian's .bashrc returns early for non-interactive shells.
sed -i '1i export BLINDFOLD_PASSPHRASE_FILE=~/.config/blindfold-passphrase' /home/dev/.bashrc
chown -R dev:dev /home/dev
EOF
port="$(docker port "${CONTAINER}" 22 | head -1 | sed 's/.*://')"

# blindfold runs plain `ssh`; this one reads a config naming the box.
cat > "${WORK}/ssh_config" <<EOF
Host linuxbox
  HostName 127.0.0.1
  Port ${port}
  User dev
  IdentityFile ${WORK}/id
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
  UserKnownHostsFile ${WORK}/known_hosts
  LogLevel ERROR
EOF
cat > "${WORK}/bin/ssh" <<EOF
#!/bin/sh
exec $(command -v ssh) -F '${WORK}/ssh_config' "\$@"
EOF
chmod +x "${WORK}/bin/ssh"
export PATH="${WORK}/bin:${PATH}"
for _ in $(seq 50); do ssh linuxbox true 2>/dev/null && break; sleep 0.2; done

on_box() { ssh linuxbox "$@"; }

echo "==> initializing both vaults"
export BLINDFOLD_DIR="${WORK}/vault" BLINDFOLD_KEK_FILE="${WORK}/kek" BLINDFOLD_PASSPHRASE=
unset BLINDFOLD_PASSPHRASE_FILE CLAUDECODE
blindfold init >/dev/null
on_box blindfold init >/dev/null
on_box blindfold doctor | grep -q 'passphrase file' || fail "the box's vault does not unlock from its passphrase file"

echo "==> remote add, sync, push"
printf '%s' "${LOCAL_SECRET}" | blindfold add cdp-es --secret ES_API_KEY \
  --var ES_ENDPOINT=https://logs.internal --describe "candidate cluster" --tags cdp >/dev/null
blindfold remote add linux linuxbox >/dev/null
out="$(blindfold sync)"
echo "${out}"
echo "${out}" | grep -Eq 'cdp-es +● +—' || fail "sync did not show cdp-es missing on the box"
blindfold push linux cdp-es | grep -q created || fail "push did not create cdp-es"
[[ "$(on_box blindfold get cdp-es --var ES_API_KEY --force)" == "${LOCAL_SECRET}" ]] ||
  fail "the box does not hold the pushed value"

echo "==> pull"
printf '%s' "${BOX_SECRET}" | on_box blindfold add BOX_TOKEN >/dev/null
blindfold pull linux BOX_TOKEN | grep -q created || fail "pull did not create BOX_TOKEN"
[[ "$(blindfold get BOX_TOKEN --force)" == "${BOX_SECRET}" ]] || fail "the pulled value differs"

echo "==> conflict"
printf 'rotated' | blindfold edit cdp-es --set ES_API_KEY >/dev/null
if blindfold push linux cdp-es >/dev/null 2>&1; then
  fail "a differing entry was replaced without --overwrite"
fi
blindfold push linux cdp-es --overwrite | grep -q updated || fail "--overwrite did not update"
[[ "$(on_box blindfold get cdp-es --var ES_API_KEY --force)" == rotated ]] || fail "the box kept the old value"

out="$(blindfold sync)"
echo "${out}"
echo "${out}" | grep -Eq 'cdp-es +● +●' || fail "sync does not show cdp-es equal after the push"

echo "==> searching what a person or agent could read for the values"
logs="$(cat "${BLINDFOLD_DIR}/audit.log"; on_box cat .blindfold/audit.log)"
for secret in "${LOCAL_SECRET}" "${BOX_SECRET}"; do
  if grep -qF -- "${secret}" <<<"${logs}"; then fail "a value is in an audit log"; fi
done
echo
echo "PASS: $(uname -s) ⇄ Linux over OpenSSH: sync, push, pull, conflict."
