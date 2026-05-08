# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability in `@specterpq/sdk`, **please do not open a public issue**.

Email **hello@specterpq.com** with:

- A description of the vulnerability and its impact
- Steps to reproduce (PoC code, browser, OS, package version)
- The commit SHA or release tag affected
- Your contact information (optional but appreciated)

You will receive a response within **72 hours**. We coordinate disclosure on a 90-day window unless an active in-the-wild exploit requires faster action.

## Supported Versions

Until 1.0.0 ships, only the latest minor version of the `0.x` series receives security fixes. Once 1.x ships, the latest minor and the previous minor will both receive backports for security issues.

| Version | Status |
| ------- | ------ |
| 0.x     | Active |

## Threat Model

`@specterpq/sdk` is designed to be **offline-by-construction**. The package surface contains:

- No network calls (`fetch`, `XMLHttpRequest`, `WebSocket`, etc. are not used).
- No telemetry.
- No remote code loading. The WASM bytes ship inside the npm tarball and are loaded from a local URL or the package's own bytes.
- No persistent storage. Generated keys live in memory until the consumer explicitly serializes them. The SDK does not call `localStorage`, `IndexedDB`, `sessionStorage`, or `cookies`.

What this SDK assumes you will do:

- Generate ML-KEM-768 secret keys **only** in trusted contexts (the user's own browser tab, an Electron renderer you control, a Node service you operate).
- Persist secrets only with consumer-controlled at-rest encryption (e.g. `aes-gcm`, OS keychain, hardware-backed key store). The SDK does **not** ship persistence.
- Treat the returned `secretKey`, `ethPrivateKey`, and `sharedSecret` strings as toxic. Although the SDK marks them non-enumerable and redacts them in `toString` / `JSON.stringify` / Node's `util.inspect`, you are still responsible for not copying them into application logs, error reporters, analytics events, or remote crash dumps.

## Cryptographic Properties

- **ML-KEM-768** key generation, encapsulation, and decapsulation come from the upstream RustCrypto [`ml-kem`](https://crates.io/crates/ml-kem) crate, FIPS 203 compliant.
- **SHAKE256** with domain separation drives view-tag and stealth derivation. Domain separators are pinned in `vendor/specter-core/src/constants.rs` and asserted by the upstream test suite.
- **Constant-time comparisons** are used for view-tag verification and key-pair round-trip verification (`subtle` crate).
- **Zeroization on drop** is enforced for `KyberSecretKey` and `StealthPrivateKey` in upstream Rust code. The `wasm-bindgen` boundary copies bytes into JS-owned `Uint8Array` buffers; once those are converted to redacted hex strings inside the SDK, the original Rust buffers are dropped and zeroized.
- **`#![forbid(unsafe_code)]`** is set in upstream `specter-core` and `specter-crypto`, and the bridge crate `rust/specter-wasm` sets it as well.
- **Browser RNG**: in WASM, randomness comes from `crypto.getRandomValues` via `getrandom = { version = "0.2", features = ["js"] }`.
- **Panics abort**: the WASM build profile sets `panic = "abort"` and `strip = true` so panic strings are not leaked to JS error messages.

## Supply Chain

- Backend Rust crates are vendored, not pulled at build time. The pinned upstream commit is recorded in `vendor/VENDORED_AT.json`.
- CI (`vendor-verify` job) re-fetches the pinned SHA on every PR and fails if `vendor/` differs from upstream without an updated pin.
- Releases are published with **npm provenance** (`--provenance`) from `.github/workflows/release.yml` using GitHub OIDC.
- The repository uses [Changesets](https://github.com/changesets/changesets) so every published version has an explicit changelog entry.

## What This SDK Does NOT Do

- It does **not** generate, hold, or transmit Ethereum or Sui transaction signatures. Pass the returned `ethPrivateKey` to `viem`, `ethers`, or `@mysten/sui` to sign.
- It does **not** resolve ENS or SuiNS names. That responsibility lives in the consumer (or the SPECTER backend API).
- It does **not** publish or fetch announcements. The consumer must wire the returned `ephemeralCiphertext` and `viewTag` into their announcement transport (the SPECTER registry API or any other backend).
- It does **not** ship persistent storage for generated keys.
