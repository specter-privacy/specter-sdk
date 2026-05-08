---
'@specterpq/sdk': minor
---

Initial public release of `@specterpq/sdk`.

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
