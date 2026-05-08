#!/usr/bin/env bash
#
# verify-vendor.sh
#
# CI guard: re-fetch the upstream SPECTER repo at the SHA pinned in
# vendor/VENDORED_AT.json and diff against the locally vendored crate sources.
# Exits non-zero if any drift is detected.
#
# Run via: pnpm vendor:verify
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIN_FILE="$REPO_ROOT/vendor/VENDORED_AT.json"

log() { printf '\033[1;36m[verify-vendor]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[verify-vendor][error]\033[0m %s\n' "$*" >&2; }

require() {
  command -v "$1" >/dev/null 2>&1 || { err "missing required command: $1"; exit 1; }
}

require git
require jq
require diff

if [ ! -f "$PIN_FILE" ]; then
  err "vendor/VENDORED_AT.json missing; run pnpm vendor:sync <sha> first"
  exit 1
fi

BACKEND_REPO="$(jq -er .repo "$PIN_FILE")"
BACKEND_SHA="$(jq -er .sha "$PIN_FILE")"
CRATES=()
while IFS= read -r line; do CRATES+=("$line"); done < <(jq -er '.vendored_crates[]' "$PIN_FILE")
SUBDIRS=()
while IFS= read -r line; do SUBDIRS+=("$line"); done < <(jq -er '.source_subdirs[]' "$PIN_FILE")

if [ "${#CRATES[@]}" -ne "${#SUBDIRS[@]}" ]; then
  err "VENDORED_AT.json is malformed: vendored_crates and source_subdirs differ in length"
  exit 1
fi

log "verifying vendor/ matches $BACKEND_REPO @ $BACKEND_SHA"

TMP="$(mktemp -d -t specter-sdk-verify.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

git clone --quiet --filter=blob:none --no-checkout \
  "https://github.com/${BACKEND_REPO}.git" "$TMP/upstream"
(
  cd "$TMP/upstream"
  git fetch --quiet --depth=1 origin "$BACKEND_SHA"
  git checkout --quiet "$BACKEND_SHA"
)

drift=0
for i in "${!CRATES[@]}"; do
  vendored="$REPO_ROOT/${CRATES[$i]}"
  upstream="$TMP/upstream/${SUBDIRS[$i]}"

  if [ ! -d "$upstream" ]; then
    err "upstream missing ${SUBDIRS[$i]} at SHA $BACKEND_SHA"
    drift=1
    continue
  fi

  log "diffing ${CRATES[$i]} <-> ${SUBDIRS[$i]}"

  # Compare every src/ file byte-for-byte. We intentionally skip Cargo.toml
  # because the sync script rewrites workspace.true inheritance to literal
  # versions, which is a deterministic transform and not real drift.
  # Compare every src/ file byte-for-byte. We intentionally skip Cargo.toml
  # (sync rewrites workspace.true inheritance to literal versions), benches/
  # and tests/ (excluded from vendoring), and platform cruft.
  diff_output="$(
    diff -r \
      --exclude='target' \
      --exclude='.DS_Store' \
      --exclude='Cargo.toml' \
      --exclude='benches' \
      --exclude='tests' \
      "$vendored" "$upstream" \
      || true
  )"

  if [ -n "$diff_output" ]; then
    err "drift detected in ${CRATES[$i]}:"
    printf '%s\n' "$diff_output" >&2
    drift=1
  fi
done

if [ "$drift" -ne 0 ]; then
  err "vendor/ does not match the pinned SHA. Either rebase your branch onto the latest sync, or run pnpm vendor:sync <new-sha> and commit."
  exit 1
fi

log "vendor/ matches upstream SHA exactly."
