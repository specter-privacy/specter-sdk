//! Address types for SPECTER.
//!
//! - [`MetaAddress`]: The public address published to ENS for receiving payments
//! - [`StealthAddress`]: A one-time Ethereum address derived for a specific payment

use serde::{Deserialize, Serialize};

use super::{KyberPublicKey, Secp256k1PublicKey};
use crate::constants::{
    ETH_ADDRESS_SIZE, KYBER_PUBLIC_KEY_SIZE, META_ADDRESS_SERIALIZED_SIZE, PROTOCOL_VERSION,
    SECP256K1_PUBLIC_KEY_SIZE, SUI_ADDRESS_SIZE,
};
use crate::error::{Result, SpecterError};

// ═══════════════════════════════════════════════════════════════════════════════
// META-ADDRESS
// ═══════════════════════════════════════════════════════════════════════════════

/// A SPECTER meta-address that is published for receiving private payments.
///
/// This is what gets stored on IPFS and linked from ENS text records.
/// Senders use this to create stealth addresses.
///
/// # Structure (protocol v2)
/// - `version`: Protocol version (must be 2)
/// - `spending_pub`: secp256k1 spending public key (33 bytes) — used to derive
///   the stealth *address*. Only the holder of the matching secret scalar can
///   derive the stealth spend key.
/// - `viewing_pk`: ML-KEM-768 viewing public key (1184 bytes) — used for
///   post-quantum payment discovery / third-party auditing.
///
/// # Example
/// ```ignore
/// use specter_core::MetaAddress;
///
/// // Create meta-address from generated keys
/// let meta = MetaAddress::new(spending_pub, viewing_pk);
///
/// // Serialize for ENS storage
/// let encoded = meta.to_hex();
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetaAddress {
    /// Protocol version (must be 2)
    pub version: u8,
    /// secp256k1 spending public key - used to derive stealth addresses
    pub spending_pub: Secp256k1PublicKey,
    /// ML-KEM viewing public key - used for scanning announcements
    pub viewing_pk: KyberPublicKey,
    /// Optional metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MetaAddressMetadata>,
}

/// Optional metadata for a meta-address.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MetaAddressMetadata {
    /// Human-readable description
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Avatar URL or IPFS CID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    /// Creation timestamp (Unix seconds)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
}

impl MetaAddress {
    /// Creates a new meta-address with the current protocol version.
    pub fn new(spending_pub: Secp256k1PublicKey, viewing_pk: KyberPublicKey) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            spending_pub,
            viewing_pk,
            metadata: None,
        }
    }

    /// Creates a meta-address with metadata.
    pub fn with_metadata(
        spending_pub: Secp256k1PublicKey,
        viewing_pk: KyberPublicKey,
        metadata: MetaAddressMetadata,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            spending_pub,
            viewing_pk,
            metadata: Some(metadata),
        }
    }

    /// Validates the meta-address structure.
    pub fn validate(&self) -> Result<()> {
        if self.version != PROTOCOL_VERSION {
            return Err(SpecterError::InvalidMetaAddress(format!(
                "unsupported protocol version {} (expected {}); v1 meta-addresses are \
                 insecure and no longer accepted — regenerate keys",
                self.version, PROTOCOL_VERSION
            )));
        }

        // Reject an on-curve-but-uninitialised (all-zero) spending key. A real
        // secp256k1 point is validated at construction time in Secp256k1PublicKey.
        if self.spending_pub.as_bytes().iter().all(|&b| b == 0) {
            return Err(SpecterError::InvalidMetaAddress(
                "spending key is all zeros".into(),
            ));
        }

        if self.viewing_pk.as_bytes().iter().all(|&b| b == 0) {
            return Err(SpecterError::InvalidMetaAddress(
                "viewing key is all zeros".into(),
            ));
        }

        Ok(())
    }

    /// Serializes to compact binary format.
    ///
    /// Format (v2): version (1) || spending_pub (33) || viewing_pk (1184)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(META_ADDRESS_SERIALIZED_SIZE);
        bytes.push(self.version);
        bytes.extend_from_slice(self.spending_pub.as_bytes());
        bytes.extend_from_slice(self.viewing_pk.as_bytes());
        bytes
    }

    /// Deserializes from compact binary format (v2 only).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < META_ADDRESS_SERIALIZED_SIZE {
            return Err(SpecterError::InvalidMetaAddress(format!(
                "too short: {} bytes, expected {}",
                bytes.len(),
                META_ADDRESS_SERIALIZED_SIZE
            )));
        }

        let version = bytes[0];
        let spending_end = 1 + SECP256K1_PUBLIC_KEY_SIZE;
        let viewing_end = spending_end + KYBER_PUBLIC_KEY_SIZE;
        let spending_pub = Secp256k1PublicKey::from_bytes(&bytes[1..spending_end])?;
        let viewing_pk = KyberPublicKey::from_bytes(&bytes[spending_end..viewing_end])?;

        let meta = Self {
            version,
            spending_pub,
            viewing_pk,
            metadata: None,
        };

        meta.validate()?;
        Ok(meta)
    }

    /// Encodes to hex string (for ENS text records).
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decodes from hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        Self::from_bytes(&bytes)
    }
}

impl Default for MetaAddress {
    fn default() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            spending_pub: Secp256k1PublicKey::default(),
            viewing_pk: KyberPublicKey::default(),
            metadata: None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEALTH ADDRESS
// ═══════════════════════════════════════════════════════════════════════════════

/// An Ethereum address derived for a specific stealth payment.
///
/// This is a standard 20-byte Ethereum address that can receive ETH/tokens.
/// The recipient can derive the private key using their viewing key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EthAddress {
    bytes: [u8; ETH_ADDRESS_SIZE],
}

impl EthAddress {
    /// Creates an address from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ETH_ADDRESS_SIZE {
            return Err(SpecterError::InvalidStealthAddress(format!(
                "expected {} bytes, got {}",
                ETH_ADDRESS_SIZE,
                bytes.len()
            )));
        }

        let mut arr = [0u8; ETH_ADDRESS_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Creates from a fixed-size array.
    pub fn from_array(bytes: [u8; ETH_ADDRESS_SIZE]) -> Self {
        Self { bytes }
    }

    /// Returns the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns checksummed hex string (EIP-55).
    pub fn to_checksum_string(self) -> String {
        // Simple implementation - could add full EIP-55 checksum later
        format!("0x{}", hex::encode(self.bytes))
    }

    /// Parses from hex string (with or without 0x prefix).
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s)?;
        Self::from_bytes(&bytes)
    }

    /// Returns the zero address.
    pub fn zero() -> Self {
        Self {
            bytes: [0u8; ETH_ADDRESS_SIZE],
        }
    }

    /// Returns true if this is the zero address.
    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }
}

impl std::fmt::Debug for EthAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EthAddress({})", self.to_checksum_string())
    }
}

impl std::fmt::Display for EthAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_checksum_string())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUI ADDRESS
// ═══════════════════════════════════════════════════════════════════════════════

/// A 32-byte Sui address derived from the same secp256k1 key as the Ethereum address.
///
/// Sui uses blake2b-256(scheme_flag || compressed_pubkey) where scheme_flag is 0x01 for secp256k1.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SuiAddress {
    bytes: [u8; SUI_ADDRESS_SIZE],
}

impl SuiAddress {
    /// Creates an address from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SUI_ADDRESS_SIZE {
            return Err(SpecterError::InvalidStealthAddress(format!(
                "expected {} bytes for Sui address, got {}",
                SUI_ADDRESS_SIZE,
                bytes.len()
            )));
        }

        let mut arr = [0u8; SUI_ADDRESS_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Creates from a fixed-size array.
    pub fn from_array(bytes: [u8; SUI_ADDRESS_SIZE]) -> Self {
        Self { bytes }
    }

    /// Returns the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns hex string with 0x prefix (Sui format).
    pub fn to_hex_string(self) -> String {
        format!("0x{}", hex::encode(self.bytes))
    }

    /// Parses from hex string (with or without 0x prefix).
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s)?;
        Self::from_bytes(&bytes)
    }

    /// Returns the zero address.
    pub fn zero() -> Self {
        Self {
            bytes: [0u8; SUI_ADDRESS_SIZE],
        }
    }

    /// Returns true if this is the zero address.
    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }
}

impl std::fmt::Debug for SuiAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SuiAddress({})", self.to_hex_string())
    }
}

impl std::fmt::Display for SuiAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex_string())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEALTH ADDRESS RESULT
// ═══════════════════════════════════════════════════════════════════════════════

/// Complete result of stealth address derivation.
///
/// Contains everything the sender needs to make a payment
/// and everything for the announcement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StealthAddressResult {
    /// The Ethereum address to send funds to
    pub address: EthAddress,
    /// The Sui address (same key, derived via blake2b-256)
    pub sui_address: SuiAddress,
    /// The ephemeral ciphertext (for announcement)
    #[serde(with = "hex")]
    pub ephemeral_ciphertext: Vec<u8>,
    /// View tag for efficient scanning
    pub view_tag: u8,
    /// The stealth public key (for verification)
    #[serde(with = "hex")]
    pub stealth_pk: Vec<u8>,
}

impl StealthAddressResult {
    /// Creates a new stealth address result.
    pub fn new(
        address: EthAddress,
        sui_address: SuiAddress,
        ephemeral_ciphertext: Vec<u8>,
        view_tag: u8,
        stealth_pk: Vec<u8>,
    ) -> Self {
        Self {
            address,
            sui_address,
            ephemeral_ciphertext,
            view_tag,
            stealth_pk,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DISCOVERED STEALTH ADDRESS
// ═══════════════════════════════════════════════════════════════════════════════

/// A stealth address discovered during scanning.
///
/// Contains the address and the derived private key for spending.
#[derive(Debug)]
pub struct DiscoveredAddress {
    /// The stealth Ethereum address
    pub address: EthAddress,
    /// The derived private key for this address (32 bytes)
    /// WARNING: Handle with care - this is sensitive!
    pub private_key: [u8; 32],
    /// The announcement ID that led to this discovery
    pub announcement_id: u64,
    /// Timestamp of the announcement
    pub timestamp: u64,
}

impl Drop for DiscoveredAddress {
    fn drop(&mut self) {
        // Zeroize the private key on drop
        self.private_key.iter_mut().for_each(|b| *b = 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::KYBER_PUBLIC_KEY_SIZE;

    /// A deterministic, valid compressed secp256k1 public key for tests.
    fn test_spending_pub(seed: u8) -> Secp256k1PublicKey {
        let sk = k256::SecretKey::from_slice(&[seed; 32]).unwrap();
        let compressed = sk.public_key().to_sec1_bytes();
        Secp256k1PublicKey::from_bytes(&compressed).unwrap()
    }

    #[test]
    fn test_meta_address_creation() {
        let spending_pub = test_spending_pub(1);
        let viewing_pk = KyberPublicKey::from_array([2u8; KYBER_PUBLIC_KEY_SIZE]);

        let meta = MetaAddress::new(spending_pub.clone(), viewing_pk.clone());
        assert_eq!(meta.version, PROTOCOL_VERSION);
        assert_eq!(meta.spending_pub, spending_pub);
        assert_eq!(meta.viewing_pk, viewing_pk);
    }

    #[test]
    fn test_meta_address_bytes_roundtrip() {
        let spending_pub = test_spending_pub(0xAA);
        let viewing_pk = KyberPublicKey::from_array([0xBB; KYBER_PUBLIC_KEY_SIZE]);

        let meta = MetaAddress::new(spending_pub, viewing_pk);
        let bytes = meta.to_bytes();
        assert_eq!(bytes.len(), META_ADDRESS_SERIALIZED_SIZE);
        let meta2 = MetaAddress::from_bytes(&bytes).unwrap();

        assert_eq!(meta.version, meta2.version);
        assert_eq!(meta.spending_pub, meta2.spending_pub);
        assert_eq!(meta.viewing_pk, meta2.viewing_pk);
    }

    #[test]
    fn test_meta_address_hex_roundtrip() {
        let spending_pub = test_spending_pub(0x12);
        let viewing_pk = KyberPublicKey::from_array([0x34; KYBER_PUBLIC_KEY_SIZE]);

        let meta = MetaAddress::new(spending_pub, viewing_pk);
        let hex = meta.to_hex();
        let meta2 = MetaAddress::from_hex(&hex).unwrap();

        assert_eq!(meta.spending_pub, meta2.spending_pub);
    }

    #[test]
    fn test_meta_address_validation() {
        // Valid meta-address
        let valid = MetaAddress::new(
            test_spending_pub(1),
            KyberPublicKey::from_array([2u8; KYBER_PUBLIC_KEY_SIZE]),
        );
        assert!(valid.validate().is_ok());

        // Invalid: zero spending key
        let mut invalid = valid.clone();
        invalid.spending_pub = Secp256k1PublicKey::default();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_meta_address_rejects_v1() {
        let mut meta = MetaAddress::new(
            test_spending_pub(7),
            KyberPublicKey::from_array([3u8; KYBER_PUBLIC_KEY_SIZE]),
        );
        meta.version = 1;
        assert!(meta.validate().is_err(), "v1 meta-address must be rejected");
    }

    #[test]
    fn test_eth_address_formatting() {
        let addr = EthAddress::from_array([0xAB; 20]);
        let s = addr.to_checksum_string();
        assert!(s.starts_with("0x"));
        assert_eq!(s.len(), 42); // "0x" + 40 hex chars
    }

    #[test]
    fn test_eth_address_hex_roundtrip() {
        let addr = EthAddress::from_array([0x12; 20]);
        let hex = addr.to_checksum_string();
        let addr2 = EthAddress::from_hex(&hex).unwrap();
        assert_eq!(addr, addr2);
    }

    #[test]
    fn test_eth_address_zero() {
        let zero = EthAddress::zero();
        assert!(zero.is_zero());

        let non_zero = EthAddress::from_array([1; 20]);
        assert!(!non_zero.is_zero());
    }
}
