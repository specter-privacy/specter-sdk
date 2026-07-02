# @specterpq/sdk

## 1.0.0

### Major Changes

- a44c7e9: Fix a critical stealth-key derivation flaw (sender-derivability) and stop the HTTP client from transmitting secret keys. **Breaking change** to the meta-address wire format and the spending-key type.

  ## Security fixes

  **Issue #1 — sender could reconstruct the recipient's stealth private key.** The previous derivation computed the stealth secp256k1 key as `SHAKE256(shared_secret ‖ spending_pk)`. Both inputs are known to the sender (it chooses the shared secret via ML-KEM encapsulation and the spending public key is public), so the sender could derive the private key for every payment it created and drain the funds. A pure hash cannot separate "derive the address" from "derive the private key".

  The fix adopts the standard stealth-address construction (ERC-5564 style additive tweak). The recipient now owns a **secp256k1 spending keypair** `(b, B = b·G)`:
  - Sender: `t = H(shared_secret)`, stealth address from `P = B + t·G` (needs only the public `B`).
  - Recipient: stealth private key `p = b + t (mod n)` (needs the secret `b`).

  Only the holder of `b` can compute the spend key. The ML-KEM viewing keypair is unchanged and still provides post-quantum scanning privacy.

  **Issue #2 — secret keys could leave the device.** Removed `generateKeysRemote` (server-generated secrets) and `scanRemote` (which serialised the viewing/spending secret keys onto the wire) from `createSpecterApiClient`. The HTTP client is now public-data only (`createStealthPaymentRemote`, `publishAnnouncement`). Generate keys with `generateSpecterKeys` and scan with `scanAnnouncement`, both fully local.

  ## Breaking API changes
  - `SpecterKeys.spending` is now a `Secp256k1KeyPair` (33-byte public, 32-byte secret) instead of an ML-KEM keypair.
  - Meta-address format is v2: `version(1) ‖ secp256k1 spend pub(33) ‖ ML-KEM view pub(1184) = 1218 bytes` (was 2369). `META_ADDRESS_SIZE` is now `1218`; `META_ADDRESS_VERSION` is `2`.
  - `deriveStealthKeys(spendingSk, sharedSecret)` now takes the spending **secret** key (was the public key — that was the vulnerability).
  - `deriveStealthAddress` / `deriveStealthSuiAddress` take the 33-byte secp256k1 spending **public** key.
  - `scanAnnouncement(announcement, viewingKeys, spendingPublicKey, spendingSecretKey?)`: detection needs only the viewing secret + spending public key; pass the spending secret to also receive `result.stealthKeys` (the spendable private key). The match result now exposes `detected` (addresses + stealth public key) and optional `stealthKeys`.
  - Removed types `RemoteGeneratedKeys`, `RemoteScanRequest`, `RemoteScanResponse`, `RemoteDiscovery`.

  ## New API
  - `generateSpendKey()` → `Secp256k1KeyPair`.
  - `deriveStealthPublic(spendingPk, sharedSecret)` → `DetectedStealth` (addresses + stealth public key, no secret).
  - New types `Secp256k1KeyPair`, `Secp256k1SpendPublicHex`, `Secp256k1SpendSecretHex`, `DetectedStealth`.
  - New constants `SPEND_PUBLIC_KEY_SIZE` (33), `SPEND_SECRET_KEY_SIZE` (32), `META_ADDRESS_VERSION` (2).

## 0.3.0

### Minor Changes

- a29c390: Add announcement-metadata encryption, and re-vendor the backend crates to `pranshurastogi/SPECTER@8294c2f`.

  **New public API** (browser-local, post-quantum):
  - `sealAnnouncementMetadata(input, sharedSecret)` / `openAnnouncementMetadata(encrypted, sharedSecret)` — high-level seal/open of the 77-byte announcement metadata block (tx hash, amount, source chain id) using AES-256-GCM keyed from the ML-KEM shared secret. The 1-byte view tag stays in the clear so scanners can filter without decrypting.
  - `encodeAnnouncementMetadata` / `decodeAnnouncementMetadata` — structured ↔ 77-byte wire layout.
  - `encryptAnnouncementMetadata` / `decryptAnnouncementMetadata` — low-level AES-256-GCM primitives over the raw block.
  - New types `AnnouncementMetadata`, `AnnouncementMetadataInput`, `EncryptedMetadataHex`, `MetadataPlaintextHex`, `TxHashHex`, `AmountHex`.
  - New constants `PLAINTEXT_METADATA_SIZE` (77), `ENCRYPTED_METADATA_SIZE` (93), and the per-field metadata sizes.
  - New error codes `INVALID_METADATA_SIZE`, `INVALID_METADATA_FIELD`, `METADATA_DECRYPTION_FAILED`.

  No breaking changes to existing APIs.

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
