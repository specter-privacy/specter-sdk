---
'@specterpq/sdk': minor
---

Add announcement-metadata encryption, and re-vendor the backend crates to `pranshurastogi/SPECTER@8294c2f`.

**New public API** (browser-local, post-quantum):

- `sealAnnouncementMetadata(input, sharedSecret)` / `openAnnouncementMetadata(encrypted, sharedSecret)` — high-level seal/open of the 77-byte announcement metadata block (tx hash, amount, source chain id) using AES-256-GCM keyed from the ML-KEM shared secret. The 1-byte view tag stays in the clear so scanners can filter without decrypting.
- `encodeAnnouncementMetadata` / `decodeAnnouncementMetadata` — structured ↔ 77-byte wire layout.
- `encryptAnnouncementMetadata` / `decryptAnnouncementMetadata` — low-level AES-256-GCM primitives over the raw block.
- New types `AnnouncementMetadata`, `AnnouncementMetadataInput`, `EncryptedMetadataHex`, `MetadataPlaintextHex`, `TxHashHex`, `AmountHex`.
- New constants `PLAINTEXT_METADATA_SIZE` (77), `ENCRYPTED_METADATA_SIZE` (93), and the per-field metadata sizes.
- New error codes `INVALID_METADATA_SIZE`, `INVALID_METADATA_FIELD`, `METADATA_DECRYPTION_FAILED`.

No breaking changes to existing APIs.
