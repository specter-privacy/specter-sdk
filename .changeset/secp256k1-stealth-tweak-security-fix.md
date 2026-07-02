---
'@specterpq/sdk': minor
---

Fix a critical stealth-key derivation flaw (sender-derivability) and stop the HTTP client from transmitting secret keys. **Breaking change** to the meta-address wire format and the spending-key type.

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
