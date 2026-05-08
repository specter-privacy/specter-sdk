#!/usr/bin/env bash
#
# pre-publish.sh
#
# Guard run by `pnpm prepublishOnly` and the release workflow before any npm
# publish. Confirms the vendor pin still matches upstream, the WASM bridge
# compiles for both web and nodejs targets, all Rust + TS tests pass, and
# the resulting tarball contains the expected files.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

log() { printf '\033[1;36m[pre-publish]\033[0m %s\n' "$*"; }

log "verifying vendor pin"
scripts/verify-vendor.sh

log "rust fmt + clippy"
cargo fmt --manifest-path rust/specter-wasm/Cargo.toml -- --check
cargo clippy --manifest-path rust/specter-wasm/Cargo.toml --all-targets -- -D warnings

log "rust unit tests"
cargo test --manifest-path rust/specter-wasm/Cargo.toml

log "wasm-pack build (web + nodejs)"
pnpm --filter @specterpq/sdk build:wasm

log "ts build + tests + lint"
pnpm --filter @specterpq/sdk build
pnpm --filter @specterpq/sdk test
pnpm --filter @specterpq/sdk lint

log "tarball preview"
pnpm --filter @specterpq/sdk pack --dry-run

log "all pre-publish checks passed"
