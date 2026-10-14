#!/usr/bin/env bash
#
# Build the macOS release artifacts.
#
# Produces a universal binary — one file that runs on both Apple Silicon and
# Intel — plus a tarball and a checksum, all under dist/. The release workflow
# runs exactly this script, so what ships is what you can reproduce here.
#
# Usage: scripts/build-macos.sh [version]
# Requires: go, and the Xcode command line tools for lipo and codesign.

set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${1:-${VERSION:-dev}}"
OUT=dist
BIN="${OUT}/blindfold"

# go-keychain reaches the Security framework through cgo, so a darwin build
# cannot be built with CGO_ENABLED=0. Each arch is compiled against the host SDK
# with the arch forced through to the C toolchain.
build_arch() {
  local goarch="$1" carch="$2"
  echo "==> building darwin/${goarch}"
  CGO_ENABLED=1 GOOS=darwin GOARCH="${goarch}" \
    CGO_CFLAGS="-arch ${carch}" CGO_LDFLAGS="-arch ${carch}" \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o "${BIN}-${goarch}" ./cmd/blindfold
}

rm -rf "${OUT}"
mkdir -p "${OUT}"

build_arch arm64 arm64
build_arch amd64 x86_64

echo "==> merging into a universal binary"
lipo -create -output "${BIN}" "${BIN}-arm64" "${BIN}-amd64"
rm -f "${BIN}-arm64" "${BIN}-amd64"

# lipo writes a fresh Mach-O, which drops the per-arch signatures the Go linker
# applied. An arm64 binary with no signature at all will not execute, so the
# merged file has to be signed again. Ad-hoc is enough to run; it is not
# notarization, and the README says so.
echo "==> ad-hoc signing"
codesign --force --sign - "${BIN}"
codesign --verify --verbose=1 "${BIN}"

# The tarball name carries no version, so that
# /releases/latest/download/blindfold_darwin_universal.tar.gz is a stable URL the
# README can hardcode. The version lives in the tag and in `blindfold version`.
echo "==> packaging"
readonly TARBALL=blindfold_darwin_universal.tar.gz
tar -czf "${OUT}/${TARBALL}" -C "${OUT}" blindfold
(cd "${OUT}" && shasum -a 256 "${TARBALL}" > checksums.txt)

echo
lipo -archs "${BIN}"
"${BIN}" version
ls -la "${OUT}"
