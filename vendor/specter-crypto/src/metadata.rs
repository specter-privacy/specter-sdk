//! Metadata encryption/decryption for SPECTER on-chain announcements.
//!
//! Encrypts the 76-byte payload (bytes [1..76]) of a 77-byte metadata block
//! using AES-256-GCM with keys derived deterministically from the ML-KEM
//! shared secret via SHAKE-256.
//!
//! # Wire format
//!
//! ```text
//! Plaintext  (77B): [view_tag 1B] [tx_hash 32B] [amount 32B] [chain_id 8B] [reserved 4B]
//! Encrypted  (93B): [view_tag 1B] [AES-GCM ciphertext 76B] [Poly1305 tag 16B]
//! ```
//!
//! `view_tag` is kept plaintext so scanners can filter 255/256 events without
//! any decryption. The 16-byte authentication tag guarantees integrity — any
//! tampered ciphertext produces a decryption error rather than corrupt data.
//!
//! # Key derivation
//!
//! Both the AES key (32 bytes) and GCM nonce (12 bytes) are derived from the
//! shared secret using SHAKE-256 with distinct domain separators:
//!
//! ```text
//! key   = SHAKE256("SPECTER_META_ENC_KEY_V1"   || shared_secret)[..32]
//! nonce = SHAKE256("SPECTER_META_ENC_NONCE_V1" || shared_secret)[..12]
//! ```
//!
//! Because each ML-KEM encapsulation produces a unique shared secret, the
//! (key, nonce) pair is unique per announcement — nonce reuse is impossible.

// aes-gcm 0.10 builds its Key/Nonce on generic-array 0.14, whose `from_slice`
// is marked deprecated in favor of generic-array 1.x (not yet adopted upstream
// by aes-gcm). The calls are correct for this version; silence the transitive
// deprecation rather than pin an unreleased dependency.
#![allow(deprecated)]

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use specter_core::{
    constants::{DOMAIN_META_ENC_KEY, DOMAIN_META_ENC_NONCE},
    error::{Result, SpecterError},
};
use zeroize::Zeroize;

/// Encrypted metadata size in bytes: 1 (view_tag) + 76 (cipher) + 16 (tag).
pub const ENCRYPTED_METADATA_SIZE: usize = 93;

/// Plaintext metadata size in bytes (matches AnnouncementMetadata::encode output).
pub const PLAINTEXT_METADATA_SIZE: usize = 77;

/// Derives the AES-256-GCM key and nonce from the shared secret.
///
/// Uses SHAKE-256 with distinct domain separators to prevent any overlap
/// with the view_tag or stealth-key derivation paths.
fn derive_key_nonce(shared_secret: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let mut key = [0u8; 32];
    {
        let mut xof = Shake256::default();
        xof.update(DOMAIN_META_ENC_KEY);
        xof.update(shared_secret);
        xof.finalize_xof().read(&mut key);
    }

    let mut nonce = [0u8; 12];
    {
        let mut xof = Shake256::default();
        xof.update(DOMAIN_META_ENC_NONCE);
        xof.update(shared_secret);
        xof.finalize_xof().read(&mut nonce);
    }

    (key, nonce)
}

/// Encrypts a 77-byte plaintext metadata block for on-chain announcement.
///
/// The `view_tag` (byte 0) is passed through unchanged. Bytes [1..76] are
/// encrypted with AES-256-GCM; the 16-byte authentication tag is appended.
///
/// # Arguments
///
/// * `plaintext` – Output of `AnnouncementMetadata::encode()` (exactly 77 bytes).
/// * `shared_secret` – 32-byte shared secret from `ML-KEM.Encaps`.
///
/// # Returns
///
/// 93-byte encrypted block ready to pass as `metadata` to `announce()`.
pub fn encrypt_announcement_metadata(
    plaintext: &[u8; PLAINTEXT_METADATA_SIZE],
    shared_secret: &[u8; 32],
) -> [u8; ENCRYPTED_METADATA_SIZE] {
    let (mut key_bytes, nonce_bytes) = derive_key_nonce(shared_secret);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt bytes [1..77] → 76B ciphertext + 16B Poly1305 tag = 92B
    let encrypted = cipher
        .encrypt(nonce, &plaintext[1..])
        .expect("AES-256-GCM: fixed-size key and nonce are always valid");

    key_bytes.zeroize();

    let mut out = [0u8; ENCRYPTED_METADATA_SIZE];
    out[0] = plaintext[0]; // view_tag: plaintext for scanner filtering
    out[1..].copy_from_slice(&encrypted); // [1..93] = 76B cipher + 16B tag

    out
}

/// Decrypts a 93-byte encrypted metadata block after ML-KEM decapsulation.
///
/// Returns the 77-byte plaintext if the authentication tag verifies, or an
/// error if the tag is invalid (wrong recipient, tampered data, or wrong key).
///
/// # Arguments
///
/// * `encrypted` – Raw metadata bytes from the on-chain event (≥ 93 bytes).
/// * `shared_secret` – 32-byte shared secret from `ML-KEM.Decaps`.
///
/// # Errors
///
/// Returns `SpecterError::CryptoError` if authentication fails — this is the
/// normal outcome for ~255/256 scan attempts (wrong recipient, tag mismatch).
pub fn decrypt_announcement_metadata(
    encrypted: &[u8],
    shared_secret: &[u8; 32],
) -> Result<[u8; PLAINTEXT_METADATA_SIZE]> {
    if encrypted.len() < ENCRYPTED_METADATA_SIZE {
        return Err(SpecterError::ValidationError(format!(
            "encrypted metadata too short: {} < {} bytes",
            encrypted.len(),
            ENCRYPTED_METADATA_SIZE,
        )));
    }

    let (mut key_bytes, nonce_bytes) = derive_key_nonce(shared_secret);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext_payload = cipher
        .decrypt(nonce, &encrypted[1..ENCRYPTED_METADATA_SIZE])
        .map_err(|_| SpecterError::DecapsulationError("metadata authentication failed".into()));

    key_bytes.zeroize();

    let plaintext_payload = plaintext_payload?;

    let mut out = [0u8; PLAINTEXT_METADATA_SIZE];
    out[0] = encrypted[0]; // view_tag
    out[1..].copy_from_slice(&plaintext_payload);

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn test_plaintext() -> [u8; PLAINTEXT_METADATA_SIZE] {
        let mut p = [0u8; 77];
        p[0] = 0xAB; // view_tag
        p[1..33].copy_from_slice(&[0x11u8; 32]); // tx_hash
        p[33..65].copy_from_slice(&[0x22u8; 32]); // amount
        p[65..73].copy_from_slice(&42161u64.to_be_bytes()); // source_chain_id (Arbitrum)
        p
    }

    #[test]
    fn test_encrypt_produces_93_bytes() {
        let enc = encrypt_announcement_metadata(&test_plaintext(), &test_secret());
        assert_eq!(enc.len(), ENCRYPTED_METADATA_SIZE);
    }

    #[test]
    fn test_view_tag_preserved_plaintext() {
        let enc = encrypt_announcement_metadata(&test_plaintext(), &test_secret());
        // Byte 0 must be the plaintext view_tag — scanner must read it without decryption
        assert_eq!(enc[0], 0xAB);
    }

    #[test]
    fn test_payload_is_encrypted() {
        let pt = test_plaintext();
        let enc = encrypt_announcement_metadata(&pt, &test_secret());
        // The ciphertext [1..77] must NOT equal the plaintext payload
        assert_ne!(&enc[1..77], &pt[1..77]);
    }

    #[test]
    fn test_roundtrip() {
        let pt = test_plaintext();
        let secret = test_secret();
        let enc = encrypt_announcement_metadata(&pt, &secret);
        let dec = decrypt_announcement_metadata(&enc, &secret).expect("decrypt must succeed");
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_different_secrets_produce_different_ciphertext() {
        let pt = test_plaintext();
        let secret1 = [0x01u8; 32];
        let secret2 = [0x02u8; 32];
        let enc1 = encrypt_announcement_metadata(&pt, &secret1);
        let enc2 = encrypt_announcement_metadata(&pt, &secret2);
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_wrong_secret_fails_auth() {
        let pt = test_plaintext();
        let enc = encrypt_announcement_metadata(&pt, &[0x01u8; 32]);
        let result = decrypt_announcement_metadata(&enc, &[0x02u8; 32]);
        assert!(result.is_err(), "wrong secret must fail authentication");
    }

    #[test]
    fn test_tampered_ciphertext_fails_auth() {
        let pt = test_plaintext();
        let mut enc = encrypt_announcement_metadata(&pt, &test_secret());
        enc[10] ^= 0xFF; // flip bits in ciphertext
        let result = decrypt_announcement_metadata(&enc, &test_secret());
        assert!(
            result.is_err(),
            "tampered ciphertext must fail authentication"
        );
    }

    #[test]
    fn test_tampered_tag_fails_auth() {
        let pt = test_plaintext();
        let mut enc = encrypt_announcement_metadata(&pt, &test_secret());
        enc[80] ^= 0xFF; // flip bits in auth tag
        let result = decrypt_announcement_metadata(&enc, &test_secret());
        assert!(result.is_err(), "tampered tag must fail authentication");
    }

    #[test]
    fn test_too_short_returns_error() {
        let result = decrypt_announcement_metadata(&[0u8; 77], &test_secret());
        assert!(result.is_err());
    }

    #[test]
    fn test_deterministic_encryption() {
        // Same inputs must always produce the same ciphertext (no random nonce)
        let pt = test_plaintext();
        let secret = test_secret();
        let enc1 = encrypt_announcement_metadata(&pt, &secret);
        let enc2 = encrypt_announcement_metadata(&pt, &secret);
        assert_eq!(enc1, enc2);
    }

    #[test]
    fn test_view_tag_only_plaintext_survives_roundtrip() {
        // Minimal metadata: view_tag only, all other bytes zero
        let mut pt = [0u8; 77];
        pt[0] = 0x7F;
        let secret = test_secret();
        let enc = encrypt_announcement_metadata(&pt, &secret);
        assert_eq!(enc[0], 0x7F); // view_tag plaintext
        let dec = decrypt_announcement_metadata(&enc, &secret).unwrap();
        assert_eq!(dec, pt);
    }
}
