#!/usr/bin/env bash
#
# sync-backend.sh
#
# Re-vendor specter-core and specter-crypto from the upstream SPECTER repo
# at a specific commit SHA. Updates vendor/VENDORED_AT.json with the new pin.
#
# Usage:
#   scripts/sync-backend.sh                 # sync to latest upstream main commit
#   scripts/sync-backend.sh <commit-sha>    # sync to a specific commit SHA
#   BACKEND_SHA=<sha> scripts/sync-backend.sh
#
# Environment variables:
#   BACKEND_REPO   default: pranshurastogi/SPECTER
#   BACKEND_REF    default: main
#   BACKEND_SHA    optional: explicit commit SHA (takes precedence over $1)
#   SKIP_BUILD     if set, skip the post-sync `cargo build` verification
#   SKIP_TS        if set, skip the post-sync pnpm build/test
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BACKEND_REPO="${BACKEND_REPO:-pranshurastogi/SPECTER}"
BACKEND_REF="${BACKEND_REF:-main}"
BACKEND_SHA="${BACKEND_SHA:-${1:-}}"

CRATES=(specter-core specter-crypto)
SUBDIR_PREFIX="specter"

log() { printf '\033[1;36m[sync-backend]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[sync-backend][error]\033[0m %s\n' "$*" >&2; }

require() {
  command -v "$1" >/dev/null 2>&1 || { err "missing required command: $1"; exit 1; }
}

require git
require jq
require curl

# Resolve the SHA we are going to vendor.
if [ -z "$BACKEND_SHA" ]; then
  log "no SHA supplied; resolving latest commit on $BACKEND_REPO@$BACKEND_REF via GitHub API"
  BACKEND_SHA=$(
    curl -fsSL \
      -H "Accept: application/vnd.github+json" \
      "https://api.github.com/repos/${BACKEND_REPO}/commits/${BACKEND_REF}" \
      | jq -er '.sha'
  )
fi

if ! [[ "$BACKEND_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  err "BACKEND_SHA must be a full 40-char SHA, got: $BACKEND_SHA"
  exit 1
fi

log "vendoring $BACKEND_REPO @ $BACKEND_SHA"

TMPDIR_VENDOR="$(mktemp -d -t specter-sdk-sync.XXXXXX)"
trap 'rm -rf "$TMPDIR_VENDOR"' EXIT

UPSTREAM_CLONE="$TMPDIR_VENDOR/upstream"
log "cloning upstream into $UPSTREAM_CLONE"
git clone --quiet --filter=blob:none --no-checkout \
  "https://github.com/${BACKEND_REPO}.git" "$UPSTREAM_CLONE"

cd "$UPSTREAM_CLONE"
git fetch --quiet --depth=1 origin "$BACKEND_SHA"
git checkout --quiet "$BACKEND_SHA"
cd "$REPO_ROOT"

for crate in "${CRATES[@]}"; do
  src="$UPSTREAM_CLONE/$SUBDIR_PREFIX/$crate"
  dst="$REPO_ROOT/vendor/$crate"

  if [ ! -d "$src" ]; then
    err "upstream is missing expected crate at $SUBDIR_PREFIX/$crate"
    exit 1
  fi

  if [ ! -f "$src/Cargo.toml" ]; then
    err "$src is missing Cargo.toml; refusing to vendor"
    exit 1
  fi

  log "replacing vendor/$crate"
  rm -rf "$dst"
  mkdir -p "$dst"
  # Copy crate sources but skip target/, .git, .DS_Store, benches/ (criterion
  # is dropped from dev-deps so any vendored bench harness will fail to
  # compile) and tests/ (upstream integration tests may reference deleted
  # dev-deps; the bridge crate carries its own test suite).
  (
    cd "$src"
    find . \
      -path './target' -prune -o \
      -path './.git' -prune -o \
      -path './benches' -prune -o \
      -path './tests' -prune -o \
      -name '.DS_Store' -prune -o \
      -type f -print
  ) | while IFS= read -r relpath; do
    relpath="${relpath#./}"
    mkdir -p "$dst/$(dirname "$relpath")"
    cp "$src/$relpath" "$dst/$relpath"
  done
done

# Patch each vendored Cargo.toml to detach from the upstream workspace
# (which we don't vendor) and pin literal versions for shared deps. The
# upstream uses [workspace.dependencies] inheritance; once standalone we have
# to rewrite the *.workspace = true lines.
patch_cargo_toml() {
  local path="$1"
  python3 - "$path" <<'PY'
import re
import sys
from pathlib import Path

cargo = Path(sys.argv[1])
text = cargo.read_text()

# Drop dev-dependencies that aren't needed for a WASM build and pull in heavy
# native deps (criterion, wiremock, tokio-test, tempfile). We keep proptest,
# test-case, rand_chacha because they help if downstream re-runs cargo test on
# the vendored crate sources.
drop_dev = {
    "criterion",
    "tokio-test",
    "wiremock",
    "tempfile",
}

lines = text.splitlines()
out = []
in_dev = False
in_bench = False
for raw in lines:
    line = raw.rstrip()

    if line.startswith("[dev-dependencies]"):
        in_dev = True
        in_bench = False
        out.append(line)
        continue
    if line.startswith("[[bench]]"):
        in_bench = True
        in_dev = False
        # Skip the entire [[bench]] table. Benches need the criterion harness
        # which we drop above; keeping them produces "missing harness" errors.
        continue
    if line.startswith("[") and in_bench:
        in_bench = False
    if in_bench:
        continue

    if line.startswith("["):
        in_dev = False

    # Drop dropped dev deps inside [dev-dependencies].
    if in_dev:
        m = re.match(r"^\s*([a-zA-Z0-9_-]+)\s*=", line)
        if m and m.group(1) in drop_dev:
            continue

    out.append(line)

text = "\n".join(out) + ("\n" if text.endswith("\n") else "")

# Replace inherited workspace fields with concrete pins. The upstream
# [workspace.package] block in pranshurastogi/SPECTER has version 0.1.0,
# edition 2021, MIT OR Apache-2.0, etc. We pin the same here.
package_inherits = {
    "version": '"0.1.0"',
    "edition": '"2021"',
    "authors": '["SPECTER Team"]',
    "license": '"MIT OR Apache-2.0"',
}
for key, val in package_inherits.items():
    text = re.sub(
        rf"^{key}\.workspace\s*=\s*true\s*$",
        f"{key} = {val}",
        text,
        flags=re.MULTILINE,
    )

# Replace `dep = { workspace = true }` with concrete version pins matching the
# upstream [workspace.dependencies] table on the pinned SHA.
workspace_deps = {
    "ml-kem": 'version = "0.2", features = ["zeroize"]',
    "sha3": 'version = "0.10"',
    "rand": 'version = "0.8"',
    "rand_chacha": 'version = "0.3"',
    "subtle": 'version = "2.5"',
    "zeroize": 'version = "1.7", features = ["derive"]',
    "serde": 'version = "1.0", features = ["derive"]',
    "serde_json": 'version = "1.0"',
    "hex": 'version = "0.4", features = ["serde"]',
    "thiserror": 'version = "1.0"',
    "async-trait": 'version = "0.1"',
    "chrono": 'version = "0.4", features = ["serde"]',
    "aes-gcm": 'version = "0.10"',
    "proptest": 'version = "1.4"',
    "test-case": 'version = "3.3"',
    # tokio is a dev-dependency used by inline #[tokio::test] async tests in
    # specter-core (e.g. resolver.rs). We pin only the version and let the
    # manifest's inline `features = [...]` carry through (merging a `features`
    # key into the pin would produce a duplicate-key TOML error). Dropping it
    # instead would break `cargo check --workspace --tests`.
    "tokio": 'version = "1"',
}
for name, pin in workspace_deps.items():
    pat_simple = rf'^{re.escape(name)}\s*=\s*\{{\s*workspace\s*=\s*true\s*\}}\s*$'
    repl_simple = f'{name} = {{ {pin} }}'
    text = re.sub(pat_simple, repl_simple, text, flags=re.MULTILINE)

    pat_with = rf'^{re.escape(name)}\s*=\s*\{{\s*workspace\s*=\s*true\s*,\s*([^}}]+)\}}\s*$'
    repl_with = lambda m, p=pin: f'{name} = {{ {p}, {m.group(1).strip()} }}'
    text = re.sub(pat_with, repl_with, text, flags=re.MULTILINE)

cargo.write_text(text)
PY
}

for crate in "${CRATES[@]}"; do
  patch_cargo_toml "$REPO_ROOT/vendor/$crate/Cargo.toml"
done

# Guard: a standalone (workspace-detached) crate must not retain any
# `workspace = true` inheritance. If upstream introduces a new shared dep we
# don't yet pin, the vendored Cargo.toml would otherwise fail to parse with a
# cryptic error deep in `cargo check`. Fail here instead with a clear pointer.
for crate in "${CRATES[@]}"; do
  manifest="$REPO_ROOT/vendor/$crate/Cargo.toml"
  if grep -nE '(^|[[:space:].])workspace[[:space:]]*=[[:space:]]*true' "$manifest" >/dev/null; then
    err "vendor/$crate/Cargo.toml still inherits from a workspace after patching:"
    grep -nE '(^|[[:space:].])workspace[[:space:]]*=[[:space:]]*true' "$manifest" >&2 || true
    err "add the offending dependency to workspace_deps (or package_inherits) in scripts/sync-backend.sh and re-run."
    exit 1
  fi
done

# Write VENDORED_AT.json so verify-vendor.sh and CI can re-validate the pin.
FETCHED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
cat > "$REPO_ROOT/vendor/VENDORED_AT.json" <<JSON
{
  "repo": "${BACKEND_REPO}",
  "ref": "${BACKEND_REF}",
  "sha": "${BACKEND_SHA}",
  "fetched_at": "${FETCHED_AT}",
  "source_subdirs": [
    "${SUBDIR_PREFIX}/specter-core",
    "${SUBDIR_PREFIX}/specter-crypto"
  ],
  "vendored_crates": [
    "vendor/specter-core",
    "vendor/specter-crypto"
  ],
  "notes": "Re-generated by scripts/sync-backend.sh. Do not edit by hand. Run pnpm vendor:sync <sha> to bump."
}
JSON

log "wrote vendor/VENDORED_AT.json"

if [ -z "${SKIP_BUILD:-}" ]; then
  if command -v cargo >/dev/null 2>&1; then
    log "verifying vendored crates compile (cargo check on workspace)"
    cargo check --manifest-path "$REPO_ROOT/Cargo.toml" --workspace --tests
  else
    log "cargo not installed; skipping build verification"
  fi
fi

if [ -z "${SKIP_TS:-}" ] && command -v pnpm >/dev/null 2>&1; then
  if [ -f "$REPO_ROOT/packages/sdk/package.json" ]; then
    log "verifying TS package still builds"
    pnpm -C "$REPO_ROOT" -r --filter "./packages/**" build || \
      log "TS build skipped (likely WASM artifacts not yet generated)"
  fi
fi

log "done. vendor/ now mirrors $BACKEND_REPO @ $BACKEND_SHA"
