#!/usr/bin/env bash
#
# Build the Linux release artifacts: one static binary per architecture, each
# in its own tarball under dist/. The release workflow runs exactly this
# script, so what ships is what you can reproduce here — on Linux or macOS.
#
# Usage: scripts/build-linux.sh [version]
# Requires: go.

set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${1:-${VERSION:-dev}}"
OUT=dist

# Pure Go: the Secret Service is reached over D-Bus with no C library, so the
# binary is static and runs on any distribution, glibc or musl.
build_arch() {
  local goarch="$1"
  local stage="${OUT}/linux_${goarch}"
  echo "==> building linux/${goarch}"
  rm -rf "${stage}"
  mkdir -p "${stage}"
  CGO_ENABLED=0 GOOS=linux GOARCH="${goarch}" \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o "${stage}/blindfold" ./cmd/blindfold

  # Versionless, like the macOS tarball, so /releases/latest/download/ URLs
  # stay stable.
  tar -czf "${OUT}/blindfold_linux_${goarch}.tar.gz" -C "${stage}" blindfold
}

mkdir -p "${OUT}"
build_arch amd64
build_arch arm64

echo "==> checksums"
(cd "${OUT}" && shasum -a 256 blindfold_*.tar.gz > checksums.txt)
cat "${OUT}/checksums.txt"
