# SPECTER SDK Cheatsheet

Quick operator guide for working in this monorepo.

---

## 1) Repo map

```text
specter-sdk/
  rust/specter-wasm/      Rust WASM bridge crate
  vendor/
    specter-core/         Vendored backend crate (read-only mirror)
    specter-crypto/       Vendored backend crate (read-only mirror)
    VENDORED_AT.json      Pinned upstream SHA metadata
  packages/sdk/           @specterpq/sdk npm package (TS API surface)
  scripts/                sync-backend.sh, verify-vendor.sh, pre-publish.sh
  .github/workflows/      ci.yml, release.yml, sync-backend.yml
  .changeset/             Release notes + changeset config
```

---

## 2) Golden rules

- Do not manually edit `vendor/specter-core` or `vendor/specter-crypto`.
- If backend logic changes, update upstream first, then re-sync vendor pin.
- Run `pnpm ci:full` before opening a PR.
- Add a changeset for user-facing changes: `pnpm changeset`.

---

## 3) Setup (first time)

```bash
pnpm install
pnpm vendor:verify
pnpm build:wasm
pnpm build
pnpm test
```

Optional browser verification:

```bash
pnpm test:browser
```

---

## 4) Day-to-day commands

## Build / test / lint

- Build WASM only:
  ```bash
  pnpm build:wasm
  ```
- Build package (WASM + TS):
  ```bash
  pnpm build
  ```
- Run tests:
  ```bash
  pnpm test
  ```
- Run coverage:
  ```bash
  pnpm test:coverage
  ```
- Browser WASM tests (Chrome + Firefox):
  ```bash
  pnpm test:browser
  ```
- Lint + fmt check:
  ```bash
  pnpm lint
  ```
- Auto-fix lint and format:
  ```bash
  pnpm lint:fix
  ```
- Typecheck:
  ```bash
  pnpm typecheck
  ```

## Rust-only checks

- Clippy strict:
  ```bash
  pnpm clippy
  ```
- Rust tests:
  ```bash
  pnpm rust:test
  ```

## Full local CI matrix

```bash
pnpm ci:full
```

---

## 5) Common task runbooks

## A) I changed TypeScript only (`packages/sdk/src/**`)

```bash
pnpm typecheck
pnpm test
pnpm lint
```

If touching public API/docs:

```bash
pnpm changeset
```

## B) I changed Rust bridge (`rust/specter-wasm/**`)

```bash
pnpm build:wasm
pnpm rust:test
pnpm clippy
pnpm test
pnpm test:browser
```

## C) I updated vendored backend pin

```bash
pnpm vendor:sync <40-char-sha>
pnpm vendor:verify
pnpm ci:full
```

Then commit vendor changes and updated pin metadata in `vendor/VENDORED_AT.json`.

## D) I am preparing a release

```bash
pnpm ci:full
pnpm changeset status
```

Then let `release.yml` handle version/publish on merge to `main`.

---

## 6) Vendor sync commands

- Verify vendor integrity:
  ```bash
  pnpm vendor:verify
  ```
- Sync to latest backend `main`:
  ```bash
  pnpm vendor:sync
  ```
- Sync to explicit backend SHA:
  ```bash
  pnpm vendor:sync <sha>
  ```

---

## 7) Release/versioning quick notes

- Add release note:
  ```bash
  pnpm changeset
  ```
- Preview release impact:
  ```bash
  pnpm changeset status
  ```
- Local version-file generation (usually CI does this):
  ```bash
  pnpm version
  ```

The `release.yml` workflow uses Changesets + npm provenance and publishes `@specterpq/sdk`.

---

## 8) Security checks before merge

- No secret values logged (`secretKey`, `sharedSecret`, `ethPrivateKey`).
- No network calls introduced in SDK runtime path.
- Validate all new byte/hex inputs and output lengths.
- Preserve redaction behavior for secret-bearing fields.
- Keep bridge Rust crate free of `unsafe`.

---

## 9) Useful docs

- Project overview: `README.md`
- Contributor workflow: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`
- NPM package docs: `packages/sdk/README.md`

