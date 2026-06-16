//! Server-side key material derived from a single master key (`SPECTER_DB_ENC_KEY`).
//!
//! One 32-byte master derives three purpose-specific subkeys via SHAKE-256 with
//! distinct domain separators — a keyed MAC for double-announce dedup, a daily
//! salt for telemetry IP hashing, and an AEAD-wrap key for the pending ML-KEM
//! shared secret. Subkeys never overlap and are never persisted.

// aes-gcm 0.10 builds Key/Nonce on generic-array 0.14 (from_slice deprecated
// upstream in favor of generic-array 1.x, not yet adopted). Calls are correct.
#![allow(deprecated)]

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use specter_core::constants::{
    DOMAIN_DB_HMAC_KEY, DOMAIN_DB_IP_HASH, DOMAIN_DB_PAYMENT_MAC, DOMAIN_DB_PENDING_WRAP,
    DOMAIN_DB_TELEMETRY_SALT,
};
use specter_core::error::{Result, SpecterError};
use zeroize::Zeroize;

use crate::hash::{shake256, shake256_multi};

/// Wrapped-secret layout: 12-byte nonce || 32-byte ciphertext || 16-byte tag.
pub const WRAPPED_SECRET_SIZE: usize = 12 + 32 + 16;

/// Purpose-separated server subkeys derived from the DB master key.
pub struct DbKeys {
    hmac_key: [u8; 32],
    pending_wrap: [u8; 32],
    telemetry_salt: [u8; 32],
}

impl DbKeys {
    /// Derives all subkeys from the 32-byte master key.
    pub fn from_master(master: &[u8; 32]) -> Self {
        let mut hmac_key = [0u8; 32];
        hmac_key.copy_from_slice(&shake256(DOMAIN_DB_HMAC_KEY, master, 32));
        let mut pending_wrap = [0u8; 32];
        pending_wrap.copy_from_slice(&shake256(DOMAIN_DB_PENDING_WRAP, master, 32));
        let mut telemetry_salt = [0u8; 32];
        telemetry_salt.copy_from_slice(&shake256(DOMAIN_DB_TELEMETRY_SALT, master, 32));
        Self {
            hmac_key,
            pending_wrap,
            telemetry_salt,
        }
    }

    /// Keyed MAC over a normalized payment tx hash — the dedup key.
    /// SHAKE-256 is not length-extendable, so prefix-keying is a sound MAC.
    pub fn payment_hmac(&self, normalized_tx_hash: &str) -> Vec<u8> {
        shake256_multi(
            DOMAIN_DB_PAYMENT_MAC,
            &[&self.hmac_key, normalized_tx_hash.as_bytes()],
            32,
        )
    }

    /// Daily-rotating telemetry IP hash. `unix_secs` is the event time.
    pub fn telemetry_ip_hash(&self, ip: &str, unix_secs: u64) -> Vec<u8> {
        let day = (unix_secs / 86_400).to_be_bytes();
        shake256_multi(
            DOMAIN_DB_IP_HASH,
            &[&self.telemetry_salt, &day, ip.as_bytes()],
            32,
        )
    }

    /// AEAD-wrap a 32-byte secret for at-rest storage (random nonce, prepended).
    pub fn wrap_secret(&self, secret: &[u8; 32]) -> Vec<u8> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.pending_wrap));
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, secret.as_slice())
            .expect("AES-256-GCM: fixed key/nonce sizes are always valid");
        let mut out = Vec::with_capacity(WRAPPED_SECRET_SIZE);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        out
    }

    /// Unwrap a secret produced by `wrap_secret`. Errors on auth failure/tamper.
    pub fn unwrap_secret(&self, wrapped: &[u8]) -> Result<[u8; 32]> {
        if wrapped.len() != WRAPPED_SECRET_SIZE {
            return Err(SpecterError::ValidationError(format!(
                "wrapped secret must be {WRAPPED_SECRET_SIZE} bytes, got {}",
                wrapped.len()
            )));
        }
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.pending_wrap));
        let nonce = Nonce::from_slice(&wrapped[..12]);
        let pt = cipher
            .decrypt(nonce, &wrapped[12..])
            .map_err(|_| SpecterError::DecapsulationError("pending secret unwrap failed".into()))?;
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&pt);
        Ok(secret)
    }
}

impl Drop for DbKeys {
    fn drop(&mut self) {
        self.hmac_key.zeroize();
        self.pending_wrap.zeroize();
        self.telemetry_salt.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> DbKeys {
        DbKeys::from_master(&[0x11u8; 32])
    }

    #[test]
    fn payment_hmac_is_deterministic_and_keyed() {
        let k = keys();
        assert_eq!(k.payment_hmac("0xabc"), k.payment_hmac("0xabc"));
        assert_ne!(k.payment_hmac("0xabc"), k.payment_hmac("0xabd"));
        let other = DbKeys::from_master(&[0x22u8; 32]);
        assert_ne!(k.payment_hmac("0xabc"), other.payment_hmac("0xabc"));
        assert_eq!(k.payment_hmac("0xabc").len(), 32);
    }

    #[test]
    fn telemetry_hash_rotates_daily_and_hides_ip() {
        let k = keys();
        let ip = "203.0.113.7";
        let day1 = k.telemetry_ip_hash(ip, 100);
        let day1b = k.telemetry_ip_hash(ip, 86_399);
        let day2 = k.telemetry_ip_hash(ip, 86_400);
        assert_eq!(day1, day1b, "same day → same hash");
        assert_ne!(day1, day2, "next day → different hash");
        assert_ne!(day1, ip.as_bytes(), "hash must not equal raw ip");
    }

    #[test]
    fn wrap_unwrap_roundtrip_and_tamper_fails() {
        let k = keys();
        let secret = [0x42u8; 32];
        let wrapped = k.wrap_secret(&secret);
        assert_eq!(wrapped.len(), WRAPPED_SECRET_SIZE);
        assert_eq!(k.unwrap_secret(&wrapped).unwrap(), secret);
        let mut bad = wrapped.clone();
        bad[20] ^= 0xFF;
        assert!(k.unwrap_secret(&bad).is_err());
        let other = DbKeys::from_master(&[0x99u8; 32]);
        assert!(other.unwrap_secret(&wrapped).is_err());
    }

    #[test]
    fn wrap_uses_random_nonce() {
        let k = keys();
        let secret = [0x42u8; 32];
        assert_ne!(
            k.wrap_secret(&secret),
            k.wrap_secret(&secret),
            "nonce must be random"
        );
    }

    #[test]
    fn subkeys_are_distinct() {
        let k = keys();
        assert_ne!(k.hmac_key, k.pending_wrap);
        assert_ne!(k.hmac_key, k.telemetry_salt);
        assert_ne!(k.pending_wrap, k.telemetry_salt);
    }
}
