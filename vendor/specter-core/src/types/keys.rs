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

use crate::constants::{KYBER_PUBLIC_KEY_SIZE, KYBER_SECRET_KEY_SIZE};
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
// SPECTER KEY TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// Spending key pair - used to spend from stealth addresses.
///
/// The spending public key is part of the meta-address.
/// The spending secret key is used to derive stealth private keys.
pub type SpendingKeyPair = KeyPair;

/// Viewing key pair - used to scan for incoming payments.
///
/// The viewing public key is part of the meta-address.
/// The viewing secret key can be shared with third parties (e.g., tax auditors)
/// to allow them to see incoming payments without spending ability.
pub type ViewingKeyPair = KeyPair;

/// Complete SPECTER key set (spending + viewing).
#[derive(ZeroizeOnDrop)]
pub struct SpecterKeys {
    /// Keys for spending from stealth addresses
    pub spending: SpendingKeyPair,
    /// Keys for viewing/scanning announcements
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
