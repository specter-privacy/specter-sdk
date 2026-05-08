# Contributing to specter-sdk

Thanks for your interest. This SDK is the browser-facing face of the SPECTER post-quantum stealth address protocol, so the bar for changes is high. Read this whole file before opening a PR.

## Layout

```
specter-sdk/
  rust/specter-wasm/    # wasm-bindgen bridge crate
  vendor/               # synced from pranshurastogi/SPECTER (pinned SHA)
    specter-core/
    specter-crypto/
    VENDORED_AT.json
  packages/sdk/         # @specterpq/sdk TypeScript package
  scripts/              # sync + verify + pre-publish helpers
  .github/workflows/    # CI, release, sync
```

The crates under `vendor/` are read-only mirrors of the SPECTER backend. **Do not edit them by hand.** Open a PR against [pranshurastogi/SPECTER](https://github.com/pranshurastogi/SPECTER), then bump the pin here via `scripts/sync-backend.sh`.

## Prerequisites

- Node.js 20 or 22 (LTS). See `package.json` `engines`.
- pnpm 10. Install via `corepack enable` or `npm i -g pnpm`.
- Rust pinned by `rust-toolchain.toml` (currently 1.82.0). `rustup` will install it automatically on first build.
- `wasm-pack` for WASM builds: `cargo install wasm-pack` or `brew install wasm-pack`.
- For browser tests: a recent Chrome and Firefox installation. `wasm-pack test --headless` drives them via WebDriver.

## First-time setup

```bash
pnpm install
pnpm vendor:verify   # confirm vendor/ matches the pinned upstream SHA
pnpm build:wasm      # builds rust/specter-wasm and emits to packages/sdk/src/wasm/{web,node}
pnpm build           # tsup-builds the TypeScript package
pnpm test            # vitest
```

## Day-to-day commands

| Command | What it does |
| --- | --- |
| `pnpm build:wasm` | Compile the WASM bridge (web + nodejs targets). |
| `pnpm build` | Build everything (wasm + ts). |
| `pnpm test` | Run vitest in `packages/sdk`. |
| `pnpm test:browser` | Run wasm-bindgen-test in headless Chrome + Firefox. |
| `pnpm lint` | ESLint + `cargo fmt --check`. |
| `pnpm clippy` | `cargo clippy -- -D warnings`. |
| `pnpm rust:test` | `cargo test` on the bridge crate. |
| `pnpm vendor:verify` | Fail if `vendor/` drifts from the pinned upstream SHA. |
| `pnpm vendor:sync [SHA]` | Re-sync `vendor/` from upstream at the given SHA (or update to latest main if omitted). |
| `pnpm ci:full` | Run the full local matrix (vendor verify + clippy + rust tests + build + ts tests + lint). |

## Branch and commit policy

- `main` is always releasable.
- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`, `ci:`, `build:`, `perf:`, `revert:`.
- Each user-facing change requires a [Changeset](https://github.com/changesets/changesets): `pnpm changeset` and commit the generated note.
- Squash-merge PRs into `main`. The merge commit message becomes the changelog source for that change.

## PR checklist (paste into the PR description)

```
- [ ] CI is green (rust fmt/clippy/test, wasm build, browser tests, ts build/test/lint, vendor-verify)
- [ ] Test evidence attached (screenshots or terminal logs for new behavior)
- [ ] No new secret-leaking surface (no logging of secret_key, eth_private_key, shared_secret)
- [ ] Compatibility impact assessed (any signature change of an exported function = changeset MINOR or MAJOR)
- [ ] Security impact assessed (any change to crypto bridge requires a SECURITY.md review)
- [ ] Changeset added (pnpm changeset)
```

## Bumping the backend pin

```bash
# From repo root
pnpm vendor:sync <commit-sha-from-pranshurastogi-SPECTER>
pnpm ci:full
git checkout -b chore/vendor-sync-<short-sha>
git add vendor/
git commit -m "chore(vendor): sync backend to <sha>"
gh pr create --fill
```

The nightly `sync-backend.yml` workflow does this automatically against the latest `main` of the backend.

## Release flow

1. Land changes on `main` with changesets.
2. The `release.yml` workflow opens a "Version Packages" PR or directly publishes.
3. Merging the Version Packages PR triggers `pnpm changeset publish --provenance` on a GitHub-hosted runner using OIDC. The published artifact carries an attestation linking it back to this repo and commit.

## Code style

- TypeScript: `strict` + `strictTypeChecked` ESLint config. Branded `Hex<T>` types are not optional for cryptographic byte strings.
- Rust: `cargo fmt`. Clippy clean. `forbid(unsafe_code)` is non-negotiable for the bridge crate.
- No emojis in code. No marketing copy in comments. Comments explain non-obvious intent only.

## Reporting security issues

Security issues do **not** go in GitHub issues or PRs. Email **hello@specterpq.com**. See `SECURITY.md`.
