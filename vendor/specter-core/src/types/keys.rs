//! Key types for SPECTER.
//!
//! This module defines the key structures used in the protocol:
//!
//! - [`KyberPublicKey`]: Public key for encapsulation (1184 bytes)
//! - [`KyberSecretKey`]: Secret key for decapsulation (2400 bytes, zeroized on drop)
//! - [`KeyPair`]: Combined public + secret key
//! - [`SpendingKeyPair`]: Keys for spending from stealth addresses
//! - [`ViewingKeyPair`]: Keys for scanning announcements

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::constants::{
    KYBER_PUBLIC_KEY_SIZE, KYBER_SECRET_KEY_SIZE, SECP256K1_PUBLIC_KEY_SIZE,
    SECP256K1_SECRET_KEY_SIZE,
};
use crate::error::{Result, SpecterError};

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC KEY
// ═══════════════════════════════════════════════════════════════════════════════

/// ML-KEM-768 public key (encapsulation key).
///
/// This is safe to share publicly and is used by senders to create stealth addresses.
#[derive(Clone, PartialEq, Eq)]
pub struct KyberPublicKey {
    bytes: [u8; KYBER_PUBLIC_KEY_SIZE],
}

impl KyberPublicKey {
    /// Creates a new public key from raw bytes.
    ///
    /// # Errors
    /// Returns error if bytes length doesn't match `KYBER_PUBLIC_KEY_SIZE`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KYBER_PUBLIC_KEY_SIZE {
            return Err(SpecterError::InvalidKeySize {
                expected: KYBER_PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let mut arr = [0u8; KYBER_PUBLIC_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Creates a public key from a fixed-size array.
    pub fn from_array(bytes: [u8; KYBER_PUBLIC_KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Returns the raw bytes of the public key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the public key as a fixed-size array reference.
    pub fn as_array(&self) -> &[u8; KYBER_PUBLIC_KEY_SIZE] {
        &self.bytes
    }

    /// Returns the hex-encoded public key.
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Creates a public key from hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        Self::from_bytes(&bytes)
    }
}

impl std::fmt::Debug for KyberPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Only show first/last 8 bytes for readability
        write!(
            f,
            "KyberPublicKey({}...{})",
            hex::encode(&self.bytes[..8]),
            hex::encode(&self.bytes[KYBER_PUBLIC_KEY_SIZE - 8..])
        )
    }
}

impl Default for KyberPublicKey {
    fn default() -> Self {
        Self {
            bytes: [0u8; KYBER_PUBLIC_KEY_SIZE],
        }
    }
}

// Serde implementation that uses hex encoding
impl Serialize for KyberPublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for KyberPublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECRET KEY
// ═══════════════════════════════════════════════════════════════════════════════

/// ML-KEM-768 secret key (decapsulation key).
///
/// This key is sensitive and will be automatically zeroized when dropped.
/// Never expose this key in logs or error messages.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KyberSecretKey {
    bytes: [u8; KYBER_SECRET_KEY_SIZE],
}

impl KyberSecretKey {
    /// Creates a new secret key from raw bytes.
    ///
    /// # Errors
    /// Returns error if bytes length doesn't match `KYBER_SECRET_KEY_SIZE`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KYBER_SECRET_KEY_SIZE {
            return Err(SpecterError::InvalidKeySize {
                expected: KYBER_SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let mut arr = [0u8; KYBER_SECRET_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Creates a secret key from a fixed-size array.
    pub fn from_array(bytes: [u8; KYBER_SECRET_KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Returns the raw bytes of the secret key.
    ///
    /// # Security
    /// Handle the returned bytes carefully - do not log or expose them.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the secret key as a fixed-size array reference.
    pub fn as_array(&self) -> &[u8; KYBER_SECRET_KEY_SIZE] {
        &self.bytes
    }
}

impl std::fmt::Debug for KyberSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose secret key content
        write!(f, "KyberSecretKey([REDACTED])")
    }
}

impl Default for KyberSecretKey {
    fn default() -> Self {
        Self {
            bytes: [0u8; KYBER_SECRET_KEY_SIZE],
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEY PAIR
// ═══════════════════════════════════════════════════════════════════════════════

/// A complete ML-KEM-768 key pair (public + secret).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyPair {
    /// Public key (safe to share)
    #[zeroize(skip)]
    pub public: KyberPublicKey,
    /// Secret key (keep private, auto-zeroized)
    pub secret: KyberSecretKey,
}

impl KeyPair {
    /// Creates a new key pair from public and secret keys.
    pub fn new(public: KyberPublicKey, secret: KyberSecretKey) -> Self {
        Self { public, secret }
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &self.public)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECP256K1 SPENDING KEYS (PROTOCOL v2)
// ═══════════════════════════════════════════════════════════════════════════════

/// A compressed secp256k1 public key (33 bytes) — the recipient's *spending*
/// public key as published in a v2 meta-address.
///
/// The sender uses this to derive the stealth *address* (`P = B + t·G`). It is
/// safe to share publicly and is validated to be a valid on-curve point.
#[derive(Clone, PartialEq, Eq)]
pub struct Secp256k1PublicKey {
    bytes: [u8; SECP256K1_PUBLIC_KEY_SIZE],
}

impl Secp256k1PublicKey {
    /// Creates a public key from raw bytes, validating it is a canonical,
    /// on-curve, compressed secp256k1 point.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECP256K1_PUBLIC_KEY_SIZE {
            return Err(SpecterError::InvalidKeySize {
                expected: SECP256K1_PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        // Reject garbage / off-curve / identity points at the boundary.
        k256::PublicKey::from_sec1_bytes(bytes).map_err(|_| {
            SpecterError::InvalidMetaAddress("spending key is not a valid secp256k1 point".into())
        })?;
        let mut arr = [0u8; SECP256K1_PUBLIC_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Creates a public key from a fixed-size array without curve validation.
    ///
    /// Prefer [`Secp256k1PublicKey::from_bytes`] for untrusted input.
    pub fn from_array(bytes: [u8; SECP256K1_PUBLIC_KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Returns the raw compressed bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the compressed bytes as a fixed-size array reference.
    pub fn as_array(&self) -> &[u8; SECP256K1_PUBLIC_KEY_SIZE] {
        &self.bytes
    }

    /// Returns the hex-encoded compressed public key (no `0x` prefix).
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Parses from a hex string (with or without `0x` prefix), validating the point.
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s)?;
        Self::from_bytes(&bytes)
    }

    /// Returns the underlying `k256::PublicKey`. Infallible because the bytes
    /// were validated on construction (via `from_bytes`/`from_hex`).
    pub fn to_k256(&self) -> Result<k256::PublicKey> {
        k256::PublicKey::from_sec1_bytes(&self.bytes).map_err(|_| {
            SpecterError::InvalidMetaAddress("spending key is not a valid secp256k1 point".into())
        })
    }
}

impl std::fmt::Debug for Secp256k1PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secp256k1PublicKey({})", self.to_hex())
    }
}

impl Default for Secp256k1PublicKey {
    fn default() -> Self {
        Self {
            bytes: [0u8; SECP256K1_PUBLIC_KEY_SIZE],
        }
    }
}

impl Serialize for Secp256k1PublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Secp256k1PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// A secp256k1 secret scalar (32 bytes) — the recipient's *spending* secret key.
///
/// This is the crown-jewel secret: it controls **every** stealth address the
/// recipient will ever receive. It must never leave the owner's device. Zeroized
/// on drop; never logged.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secp256k1SecretKey {
    bytes: [u8; SECP256K1_SECRET_KEY_SIZE],
}

impl Secp256k1SecretKey {
    /// Creates a secret key from raw bytes, validating it is a non-zero scalar
    /// in `[1, n)`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECP256K1_SECRET_KEY_SIZE {
            return Err(SpecterError::InvalidKeySize {
                expected: SECP256K1_SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        k256::SecretKey::from_slice(bytes).map_err(|_| SpecterError::InvalidKeySize {
            expected: SECP256K1_SECRET_KEY_SIZE,
            actual: bytes.len(),
        })?;
        let mut arr = [0u8; SECP256K1_SECRET_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Returns the raw secret bytes. Handle with care — never log or transmit.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the underlying `k256::SecretKey`.
    pub fn to_k256(&self) -> Result<k256::SecretKey> {
        k256::SecretKey::from_slice(&self.bytes).map_err(|_| SpecterError::InvalidKeySize {
            expected: SECP256K1_SECRET_KEY_SIZE,
            actual: self.bytes.len(),
        })
    }
}

impl std::fmt::Debug for Secp256k1SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secp256k1SecretKey([REDACTED])")
    }
}

/// A complete secp256k1 spending key pair (public + secret).
#[derive(ZeroizeOnDrop)]
pub struct Secp256k1KeyPair {
    /// Public key — part of the meta-address (safe to share).
    #[zeroize(skip)]
    pub public: Secp256k1PublicKey,
    /// Secret key — never leaves the device (auto-zeroized).
    pub secret: Secp256k1SecretKey,
}

impl Secp256k1KeyPair {
    /// Creates a spending key pair from public and secret keys.
    pub fn new(public: Secp256k1PublicKey, secret: Secp256k1SecretKey) -> Self {
        Self { public, secret }
    }
}

impl std::fmt::Debug for Secp256k1KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secp256k1KeyPair")
            .field("public", &self.public)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SPECTER KEY TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// Spending key pair (v2) — a secp256k1 keypair used to spend from stealth
/// addresses. The public key is part of the meta-address; the secret key is used
/// to derive stealth spend keys and must never leave the owner's device.
pub type SpendingKeyPair = Secp256k1KeyPair;

/// Viewing key pair — an ML-KEM-768 keypair used to scan for incoming payments.
///
/// The viewing public key is part of the meta-address. The viewing secret key
/// can be shared with third parties (e.g. an auditor or a scanning service) to
/// allow them to *detect* incoming payments without any ability to spend.
pub type ViewingKeyPair = KeyPair;

/// Complete SPECTER key set (secp256k1 spending + ML-KEM viewing).
#[derive(ZeroizeOnDrop)]
pub struct SpecterKeys {
    /// secp256k1 keys for spending from stealth addresses
    pub spending: SpendingKeyPair,
    /// ML-KEM keys for viewing/scanning announcements
    pub viewing: ViewingKeyPair,
}

impl SpecterKeys {
    /// Creates a new SPECTER key set.
    pub fn new(spending: SpendingKeyPair, viewing: ViewingKeyPair) -> Self {
        Self { spending, viewing }
    }
}

impl std::fmt::Debug for SpecterKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpecterKeys")
            .field("spending", &self.spending)
            .field("viewing", &self.viewing)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_from_bytes() {
        let bytes = [42u8; KYBER_PUBLIC_KEY_SIZE];
        let pk = KyberPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk.as_bytes(), &bytes);
    }

    #[test]
    fn test_public_key_wrong_size() {
        let bytes = [0u8; 100];
        let result = KyberPublicKey::from_bytes(&bytes);
        assert!(matches!(result, Err(SpecterError::InvalidKeySize { .. })));
    }

    #[test]
    fn test_public_key_hex_roundtrip() {
        let bytes = [0xAB; KYBER_PUBLIC_KEY_SIZE];
        let pk = KyberPublicKey::from_bytes(&bytes).unwrap();
        let hex = pk.to_hex();
        let pk2 = KyberPublicKey::from_hex(&hex).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_secret_key_debug_redacted() {
        let sk = KyberSecretKey::default();
        let debug = format!("{:?}", sk);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("00")); // No actual bytes exposed
    }

    #[test]
    fn test_public_key_serde() {
        let bytes = [0x12; KYBER_PUBLIC_KEY_SIZE];
        let pk = KyberPublicKey::from_bytes(&bytes).unwrap();
        let json = serde_json::to_string(&pk).unwrap();
        let pk2: KyberPublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(pk, pk2);
    }
}
