//! Announcement-metadata encryption bindings.
//!
//! SPECTER announcements can carry a 77-byte metadata block describing the
//! payment (view tag, source-chain tx hash, amount, source chain id). The
//! payload bytes `[1..77]` are encrypted with AES-256-GCM under a key and
//! nonce derived from the ML-KEM shared secret via SHAKE-256, yielding a
//! 93-byte block; byte 0 (the view tag) stays in the clear so scanners can
//! filter ~255/256 events without decrypting.
//!
//! This module exposes only the cryptographic primitives. The fixed 77-byte
//! field layout (encode/decode of the structured metadata) is handled in the
//! TypeScript layer, which has no crypto and is trivial to audit.
//!
//! See `vendor/specter-crypto/src/metadata.rs` for the wire format and key
//! derivation spec.

use specter_core::constants::KYBER_SHARED_SECRET_SIZE;
use specter_crypto::metadata::{
    decrypt_announcement_metadata, encrypt_announcement_metadata, ENCRYPTED_METADATA_SIZE,
    PLAINTEXT_METADATA_SIZE,
};
use wasm_bindgen::prelude::*;

use crate::error::WasmError;

/// Coerce a JS byte slice into the fixed 32-byte shared-secret array.
fn as_shared_secret(shared_secret: &[u8]) -> Result<[u8; KYBER_SHARED_SECRET_SIZE], WasmError> {
    shared_secret
        .try_into()
        .map_err(|_| WasmError::InvalidSharedSecretSize {
            expected: KYBER_SHARED_SECRET_SIZE,
            actual: shared_secret.len(),
        })
}

/// Encrypt a 77-byte plaintext metadata block for an on-chain announcement.
///
/// Returns the 93-byte encrypted block (`[view_tag 1B][ciphertext 76B][tag
/// 16B]`). The `view_tag` byte must already match the one derived from
/// `shared_secret`; the TypeScript wrapper enforces this.
///
/// # Errors
///
/// - [`WasmError::InvalidMetadataSize`] if `plaintext` is not exactly 77 bytes.
/// - [`WasmError::InvalidSharedSecretSize`] if `shared_secret` is not 32 bytes.
#[wasm_bindgen(js_name = encryptAnnouncementMetadata)]
pub fn encrypt_announcement_metadata_js(
    plaintext: &[u8],
    shared_secret: &[u8],
) -> Result<Vec<u8>, WasmError> {
    let pt: [u8; PLAINTEXT_METADATA_SIZE] =
        plaintext
            .try_into()
            .map_err(|_| WasmError::InvalidMetadataSize {
                expected: PLAINTEXT_METADATA_SIZE,
                actual: plaintext.len(),
                field: "plaintext",
            })?;
    let ss = as_shared_secret(shared_secret)?;

    let encrypted = encrypt_announcement_metadata(&pt, &ss);
    debug_assert_eq!(encrypted.len(), ENCRYPTED_METADATA_SIZE);
    Ok(encrypted.to_vec())
}

/// Decrypt a 93-byte encrypted metadata block after ML-KEM decapsulation.
///
/// Returns the recovered 77-byte plaintext. Trailing bytes beyond the first
/// 93 are ignored (matching the upstream contract), so callers may pass the
/// raw on-chain field verbatim.
///
/// # Errors
///
/// - [`WasmError::InvalidMetadataSize`] if `encrypted` is shorter than 93 bytes.
/// - [`WasmError::InvalidSharedSecretSize`] if `shared_secret` is not 32 bytes.
/// - [`WasmError::MetadataDecryptionFailed`] if the AES-GCM authentication tag
///   does not verify (wrong recipient or tampered data) — the expected result
///   for non-matching announcements.
#[wasm_bindgen(js_name = decryptAnnouncementMetadata)]
pub fn decrypt_announcement_metadata_js(
    encrypted: &[u8],
    shared_secret: &[u8],
) -> Result<Vec<u8>, WasmError> {
    if encrypted.len() < ENCRYPTED_METADATA_SIZE {
        return Err(WasmError::InvalidMetadataSize {
            expected: ENCRYPTED_METADATA_SIZE,
            actual: encrypted.len(),
            field: "encrypted",
        });
    }
    let ss = as_shared_secret(shared_secret)?;

    let plaintext = decrypt_announcement_metadata(encrypted, &ss)
        .map_err(|e| WasmError::MetadataDecryptionFailed(e.to_string()))?;
    debug_assert_eq!(plaintext.len(), PLAINTEXT_METADATA_SIZE);
    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> [u8; KYBER_SHARED_SECRET_SIZE] {
        [0x42u8; KYBER_SHARED_SECRET_SIZE]
    }

    fn plaintext() -> Vec<u8> {
        let mut p = vec![0u8; PLAINTEXT_METADATA_SIZE];
        p[0] = 0xAB; // view tag
        p[1..33].copy_from_slice(&[0x11u8; 32]); // tx_hash
        p[33..65].copy_from_slice(&[0x22u8; 32]); // amount
        p[65..73].copy_from_slice(&42161u64.to_be_bytes()); // source chain id
        p
    }

    #[test]
    fn round_trip_recovers_plaintext() {
        let pt = plaintext();
        let enc = encrypt_announcement_metadata_js(&pt, &secret()).unwrap();
        assert_eq!(enc.len(), ENCRYPTED_METADATA_SIZE);
        // view tag stays in the clear at byte 0.
        assert_eq!(enc[0], pt[0]);
        let dec = decrypt_announcement_metadata_js(&enc, &secret()).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn rejects_wrong_plaintext_size() {
        let err = encrypt_announcement_metadata_js(&[0u8; 10], &secret()).unwrap_err();
        assert_eq!(err.code(), "INVALID_METADATA_SIZE");
    }

    #[test]
    fn rejects_short_shared_secret_on_encrypt() {
        let err = encrypt_announcement_metadata_js(&plaintext(), &[0u8; 16]).unwrap_err();
        assert_eq!(err.code(), "INVALID_SHARED_SECRET_SIZE");
    }

    #[test]
    fn rejects_short_encrypted_block() {
        let err = decrypt_announcement_metadata_js(&[0u8; 50], &secret()).unwrap_err();
        assert_eq!(err.code(), "INVALID_METADATA_SIZE");
    }

    #[test]
    fn wrong_secret_fails_authentication() {
        let enc = encrypt_announcement_metadata_js(&plaintext(), &secret()).unwrap();
        let wrong = [0x99u8; KYBER_SHARED_SECRET_SIZE];
        let err = decrypt_announcement_metadata_js(&enc, &wrong).unwrap_err();
        assert_eq!(err.code(), "METADATA_DECRYPTION_FAILED");
    }
}
