# @specterpq/sdk

## 0.2.0

### Minor Changes

- Added an explicit trusted SPECTER API client via `createSpecterApiClient`.

  The new HTTP surface supports remote key generation, server-authoritative
  stealth payment creation with `payment_id`, registry announcement publishing,
  and remote scanning. Local crypto helpers remain offline-by-default, and
  secret-bearing remote fields keep the same redaction behavior as local WASM
  results.

- Hardened protocol tests and documentation around the updated key roles.

  Full payment flows now exercise encapsulation to the recipient viewing public
  key and decapsulation with the viewing secret key, while stealth address
  derivation remains bound to the spending public key.

## 0.1.0

### Minor Changes

- 92018a8: Initial public release of `@specterpq/sdk`.

  The SDK exposes the full SPECTER v1 protocol surface — ML-KEM-768 keypair
  generation, encapsulation/decapsulation, view-tag computation and
  verification, stealth Eth/Sui address derivation, spendable secp256k1 key
  derivation, and 2369-byte meta-address construction/parsing — entirely on
  the user's device via a Rust core compiled to WebAssembly.

  Highlights:
  - Browser-first: works in modern browsers and Node 20+, no server.
  - Strict input validation via `zod`; every output is length-checked
    against the protocol constants.
  - Secret-bearing fields (`secretKey`, `sharedSecret`, `ethPrivateKey`)
    are non-enumerable and redacted in `JSON.stringify`, `console.log`,
    and `util.inspect`.
  - High-level helpers `createStealthPayment`, `scanAnnouncement`, and
    `scanAnnouncements` cover sender and recipient flows.
  - Vendored from `pranshurastogi/SPECTER` at a pinned SHA, with a nightly
    CI workflow that opens PRs to bump the pin.
  - Published with [npm provenance](https://docs.npmjs.com/generating-provenance-statements).
