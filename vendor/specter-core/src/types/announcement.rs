//! Announcement types for the SPECTER registry.
//!
//! Announcements are published by senders and contain the ephemeral key
//! and view tag needed for recipients to discover payments.

use serde::{Deserialize, Serialize};

use crate::constants::{KYBER_CIPHERTEXT_SIZE, VIEW_TAG_SIZE};
use crate::error::{Result, SpecterError};

/// serde adapter: `Option<Vec<u8>>` <-> `Option<hex string>`.
mod opt_hex {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => s.serialize_str(&hex::encode(bytes)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            Some(s) => hex::decode(s).map(Some).map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

/// An announcement published to the registry.
///
/// Senders create announcements containing their ephemeral key and view tag.
/// Recipients scan these to find payments addressed to them.
///
/// # Wire Format (binary)
/// ```text
/// ephemeral_key (1088) || view_tag (1) || timestamp (8)
/// ```
/// Note: `source_chain_id` and other optional fields are encoded in the on-chain
/// metadata bytes, not in this binary format.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Announcement {
    /// Unique identifier (assigned by registry)
    pub id: u64,
    /// Kyber ciphertext - the encapsulated ephemeral key
    #[serde(with = "hex")]
    pub ephemeral_key: Vec<u8>,
    /// keccak256(ciphertext) emitted by the new contract event. Present for
    /// chain-indexed rows; the full `ephemeral_key` is fetched from calldata
    /// on view-tag match and verified against this hash.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex")]
    pub ephemeral_key_hash: Option<Vec<u8>>,
    /// AEAD-encrypted on-chain metadata blob (opaque to the registry/indexer;
    /// only the recipient with the shared secret can decrypt it).
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex")]
    pub metadata_blob: Option<Vec<u8>>,
    /// HMAC(server_key, normalize(payment_tx_hash)) — the double-announce dedup key.
    /// Write-only: never read back into an Announcement, only used by the UNIQUE
    /// index. Never reveals the payment tx (only the API holding the key can compute it).
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex")]
    pub payment_tx_hash_hmac: Option<Vec<u8>>,
    /// View tag for efficient filtering (first byte of hash)
    pub view_tag: u8,
    /// Unix timestamp when announcement was created
    pub timestamp: u64,
    /// EIP-155 chain ID of the chain where the payment originated.
    /// Examples: 42161 = Arbitrum One, 10143 = Monad testnet, 1 = Ethereum mainnet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_chain_id: Option<u64>,
    /// Optional: Block number on Monad where the announcement was published
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    /// Monad announce tx hash — the tx that called SPECTERAnnouncer.announce().
    /// Used as the dedup key in Turso (always unique, always present for on-chain announcements).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    /// Source-chain payment tx hash — the tx that transferred funds on `source_chain_id`.
    /// Decoded from metadata bytes [1..33]. May be None if the sender omitted it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_tx_hash: Option<String>,
    /// Optional: Payment amount (raw hex uint256, e.g. "0x0000...0de0b6b3a7640000" = 1 ETH in wei)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    /// Optional: Human-readable chain name (e.g. "monad-testnet", "arbitrum-one")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
    /// Optional: Stealth address for this payment (checksummed)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stealth_address: Option<String>,
}

impl Announcement {
    /// Creates a new announcement.
    pub fn new(ephemeral_key: Vec<u8>, view_tag: u8) -> Self {
        Self {
            id: 0, // Assigned by registry
            ephemeral_key,
            ephemeral_key_hash: None,
            metadata_blob: None,
            payment_tx_hash_hmac: None,
            view_tag,
            timestamp: Self::current_timestamp(),
            source_chain_id: None,
            block_number: None,
            tx_hash: None,
            payment_tx_hash: None,
            amount: None,
            chain: None,
            stealth_address: None,
        }
    }

    /// True once the full 1088-byte ciphertext is present (calldata fetched).
    pub fn is_resolved(&self) -> bool {
        self.ephemeral_key.len() == KYBER_CIPHERTEXT_SIZE
    }

    /// Validates the announcement structure.
    pub fn validate(&self) -> Result<()> {
        // A hash-only row (indexed from chain, ciphertext not yet fetched) is
        // valid as long as the hash is a 32-byte keccak256 digest.
        if self.ephemeral_key.is_empty() {
            match &self.ephemeral_key_hash {
                Some(h) if h.len() == 32 => return Ok(()),
                _ => {
                    return Err(SpecterError::InvalidAnnouncement(
                        "announcement has neither ciphertext nor a 32-byte key hash".into(),
                    ))
                }
            }
        }

        // Resolved row: full ciphertext must be exactly KYBER_CIPHERTEXT_SIZE
        // and not all zeros.
        if self.ephemeral_key.len() != KYBER_CIPHERTEXT_SIZE {
            return Err(SpecterError::InvalidAnnouncement(format!(
                "ephemeral key size mismatch: expected {}, got {}",
                KYBER_CIPHERTEXT_SIZE,
                self.ephemeral_key.len()
            )));
        }
        if self.ephemeral_key.iter().all(|&b| b == 0) {
            return Err(SpecterError::InvalidAnnouncement(
                "ephemeral key is all zeros".into(),
            ));
        }

        // Timestamp validation (not in the future by more than 1 hour)
        let now = Self::current_timestamp();
        if self.timestamp > now + 3600 {
            return Err(SpecterError::InvalidAnnouncement(
                "timestamp is too far in the future".into(),
            ));
        }

        Ok(())
    }

    /// Serializes to compact binary format.
    ///
    /// Format: `ephemeral_key (1088) || view_tag (1) || timestamp (8)`
    /// Note: `source_chain_id` is not encoded here — it lives in the on-chain
    /// metadata bytes and is populated when indexing from the chain.
    pub fn to_bytes(&self) -> Vec<u8> {
        let size = KYBER_CIPHERTEXT_SIZE + VIEW_TAG_SIZE + 8;
        let mut bytes = Vec::with_capacity(size);
        bytes.extend_from_slice(&self.ephemeral_key);
        bytes.push(self.view_tag);
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes
    }

    /// Deserializes from compact binary format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let min_size = KYBER_CIPHERTEXT_SIZE + VIEW_TAG_SIZE + 8;
        if bytes.len() < min_size {
            return Err(SpecterError::InvalidAnnouncement(format!(
                "too short: {} bytes, minimum {}",
                bytes.len(),
                min_size
            )));
        }

        let ephemeral_key = bytes[0..KYBER_CIPHERTEXT_SIZE].to_vec();
        let view_tag = bytes[KYBER_CIPHERTEXT_SIZE];

        let timestamp_start = KYBER_CIPHERTEXT_SIZE + VIEW_TAG_SIZE;
        let timestamp = u64::from_le_bytes(
            bytes[timestamp_start..timestamp_start + 8]
                .try_into()
                .map_err(|_| SpecterError::InvalidAnnouncement("invalid timestamp".into()))?,
        );

        let announcement = Self {
            id: 0, // ID is assigned by registry, not serialized
            ephemeral_key,
            ephemeral_key_hash: None,
            metadata_blob: None,
            payment_tx_hash_hmac: None,
            view_tag,
            timestamp,
            source_chain_id: None,
            block_number: None,
            tx_hash: None,
            payment_tx_hash: None,
            amount: None,
            chain: None,
            stealth_address: None,
        };

        announcement.validate()?;
        Ok(announcement)
    }

    /// Returns current Unix timestamp in seconds.
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Builder for creating announcements with optional fields.
#[derive(Default)]
pub struct AnnouncementBuilder {
    ephemeral_key: Option<Vec<u8>>,
    ephemeral_key_hash: Option<Vec<u8>>,
    metadata_blob: Option<Vec<u8>>,
    payment_tx_hash_hmac: Option<Vec<u8>>,
    view_tag: Option<u8>,
    timestamp: Option<u64>,
    source_chain_id: Option<u64>,
    block_number: Option<u64>,
    tx_hash: Option<String>,
    payment_tx_hash: Option<String>,
    amount: Option<String>,
    chain: Option<String>,
    stealth_address: Option<String>,
}

impl AnnouncementBuilder {
    /// Creates a new announcement builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the ephemeral key (required).
    pub fn ephemeral_key(mut self, key: Vec<u8>) -> Self {
        self.ephemeral_key = Some(key);
        self
    }

    /// Sets the keccak256 ephemeral key hash (chain-indexed rows).
    pub fn ephemeral_key_hash(mut self, h: Vec<u8>) -> Self {
        self.ephemeral_key_hash = Some(h);
        self
    }

    /// Sets the encrypted on-chain metadata blob.
    pub fn metadata_blob(mut self, b: Vec<u8>) -> Self {
        self.metadata_blob = Some(b);
        self
    }

    /// Sets the dedup HMAC (computed by the API from the payment tx hash).
    pub fn payment_tx_hash_hmac(mut self, h: Vec<u8>) -> Self {
        self.payment_tx_hash_hmac = Some(h);
        self
    }

    /// Sets the view tag (required).
    pub fn view_tag(mut self, tag: u8) -> Self {
        self.view_tag = Some(tag);
        self
    }

    /// Sets a custom timestamp (optional, defaults to now).
    pub fn timestamp(mut self, ts: u64) -> Self {
        self.timestamp = Some(ts);
        self
    }

    /// Sets the Yellow channel ID (optional).
    /// Sets the source chain ID (optional, EIP-155 chain ID).
    pub fn source_chain_id(mut self, id: u64) -> Self {
        self.source_chain_id = Some(id);
        self
    }

    /// Sets the block number (optional).
    pub fn block_number(mut self, num: u64) -> Self {
        self.block_number = Some(num);
        self
    }

    /// Sets the Monad announce tx hash (dedup key).
    pub fn tx_hash(mut self, hash: String) -> Self {
        self.tx_hash = Some(hash);
        self
    }

    /// Sets the source-chain payment tx hash (from metadata bytes [1..33]).
    pub fn payment_tx_hash(mut self, hash: impl Into<String>) -> Self {
        self.payment_tx_hash = Some(hash.into());
        self
    }

    /// Sets the amount (optional, human-readable e.g. "0.1").
    pub fn amount(mut self, amount: impl Into<String>) -> Self {
        self.amount = Some(amount.into());
        self
    }

    /// Sets the chain (optional, e.g. "ethereum", "sui").
    pub fn chain(mut self, chain: impl Into<String>) -> Self {
        self.chain = Some(chain.into());
        self
    }

    /// Sets the stealth address (optional, for validation purposes).
    pub fn stealth_address(mut self, addr: impl Into<String>) -> Self {
        self.stealth_address = Some(addr.into());
        self
    }

    /// Builds the announcement.
    pub fn build(self) -> Result<Announcement> {
        let ephemeral_key = self
            .ephemeral_key
            .ok_or_else(|| SpecterError::ValidationError("ephemeral_key is required".into()))?;

        let view_tag = self
            .view_tag
            .ok_or_else(|| SpecterError::ValidationError("view_tag is required".into()))?;

        let mut announcement = Announcement::new(ephemeral_key, view_tag);

        if let Some(ts) = self.timestamp {
            announcement.timestamp = ts;
        }
        announcement.source_chain_id = self.source_chain_id;
        announcement.block_number = self.block_number;
        announcement.tx_hash = self.tx_hash;
        announcement.payment_tx_hash = self.payment_tx_hash;
        announcement.amount = self.amount;
        announcement.chain = self.chain;
        announcement.stealth_address = self.stealth_address;
        announcement.ephemeral_key_hash = self.ephemeral_key_hash;
        announcement.metadata_blob = self.metadata_blob;
        announcement.payment_tx_hash_hmac = self.payment_tx_hash_hmac;

        announcement.validate()?;
        Ok(announcement)
    }
}

/// Statistics about announcements in a registry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnnouncementStats {
    /// Total number of announcements
    pub total_count: u64,
    /// Announcements per view tag (for distribution analysis)
    pub view_tag_distribution: Vec<u64>,
    /// Earliest announcement timestamp
    pub earliest_timestamp: Option<u64>,
    /// Latest announcement timestamp
    pub latest_timestamp: Option<u64>,
}

impl Default for AnnouncementStats {
    fn default() -> Self {
        Self {
            total_count: 0,
            view_tag_distribution: vec![0; 256],
            earliest_timestamp: None,
            latest_timestamp: None,
        }
    }
}

impl AnnouncementStats {
    /// Creates empty stats.
    pub fn new() -> Self {
        Self::default()
    }

    /// Updates stats with a new announcement.
    pub fn add(&mut self, announcement: &Announcement) {
        self.total_count += 1;
        self.view_tag_distribution[announcement.view_tag as usize] += 1;

        match self.earliest_timestamp {
            Some(t) if announcement.timestamp < t => {
                self.earliest_timestamp = Some(announcement.timestamp);
            }
            None => {
                self.earliest_timestamp = Some(announcement.timestamp);
            }
            _ => {}
        }

        match self.latest_timestamp {
            Some(t) if announcement.timestamp > t => {
                self.latest_timestamp = Some(announcement.timestamp);
            }
            None => {
                self.latest_timestamp = Some(announcement.timestamp);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_ephemeral_key() -> Vec<u8> {
        vec![0x42u8; KYBER_CIPHERTEXT_SIZE]
    }

    #[test]
    fn test_announcement_creation() {
        let ann = Announcement::new(make_valid_ephemeral_key(), 0x42);
        assert_eq!(ann.view_tag, 0x42);
        assert!(ann.timestamp > 0);
        assert!(ann.source_chain_id.is_none());
    }

    #[test]
    fn test_announcement_validation() {
        let valid = Announcement::new(make_valid_ephemeral_key(), 0x42);
        assert!(valid.validate().is_ok());

        let mut invalid = valid.clone();
        invalid.ephemeral_key = vec![0u8; 100];
        assert!(invalid.validate().is_err());

        let mut invalid2 = valid.clone();
        invalid2.ephemeral_key = vec![0u8; KYBER_CIPHERTEXT_SIZE];
        assert!(invalid2.validate().is_err());
    }

    #[test]
    fn test_announcement_bytes_roundtrip() {
        let ann = Announcement::new(make_valid_ephemeral_key(), 0xAB);
        let bytes = ann.to_bytes();
        let ann2 = Announcement::from_bytes(&bytes).unwrap();

        assert_eq!(ann.ephemeral_key, ann2.ephemeral_key);
        assert_eq!(ann.view_tag, ann2.view_tag);
        assert_eq!(ann.timestamp, ann2.timestamp);
    }

    #[test]
    fn test_announcement_builder_with_source_chain_id() {
        let ann = AnnouncementBuilder::new()
            .ephemeral_key(make_valid_ephemeral_key())
            .view_tag(0x55)
            .source_chain_id(42161) // Arbitrum
            .build()
            .unwrap();

        assert_eq!(ann.view_tag, 0x55);
        assert_eq!(ann.source_chain_id, Some(42161));
    }

    #[test]
    fn test_announcement_builder() {
        let ann = AnnouncementBuilder::new()
            .ephemeral_key(make_valid_ephemeral_key())
            .view_tag(0x55)
            .build()
            .unwrap();

        assert_eq!(ann.view_tag, 0x55);
        assert!(ann.source_chain_id.is_none());
    }

    #[test]
    fn test_announcement_builder_missing_required() {
        // Missing ephemeral_key
        let result = AnnouncementBuilder::new().view_tag(0x42).build();
        assert!(result.is_err());

        // Missing view_tag
        let result = AnnouncementBuilder::new()
            .ephemeral_key(make_valid_ephemeral_key())
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_announcement_stats() {
        let mut stats = AnnouncementStats::new();

        stats.add(&Announcement::new(make_valid_ephemeral_key(), 0x42));
        stats.add(&Announcement::new(make_valid_ephemeral_key(), 0x42));
        stats.add(&Announcement::new(make_valid_ephemeral_key(), 0x00));

        assert_eq!(stats.total_count, 3);
        assert_eq!(stats.view_tag_distribution[0x42], 2);
        assert_eq!(stats.view_tag_distribution[0x00], 1);
    }

    #[test]
    fn test_announcement_stealth_address_default_none() {
        let ann = Announcement::new(make_valid_ephemeral_key(), 0x42);
        assert!(ann.stealth_address.is_none());
    }

    #[test]
    fn test_announcement_builder_with_stealth_address() {
        let stealth_addr = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let ann = AnnouncementBuilder::new()
            .ephemeral_key(make_valid_ephemeral_key())
            .view_tag(0x42)
            .stealth_address(stealth_addr)
            .build()
            .unwrap();

        assert_eq!(ann.stealth_address, Some(stealth_addr.to_string()));
        assert_eq!(ann.view_tag, 0x42);
    }

    #[test]
    fn test_announcement_builder_stealth_address_chaining() {
        let ann = AnnouncementBuilder::new()
            .ephemeral_key(make_valid_ephemeral_key())
            .view_tag(0xFF)
            .amount("0x0000000000000000000000000000000000000000000000000de0b6b3a7640000")
            .stealth_address("0xabcd")
            .source_chain_id(10143)
            .build()
            .unwrap();

        assert_eq!(ann.stealth_address, Some("0xabcd".to_string()));
        assert!(ann.amount.is_some());
        assert_eq!(ann.source_chain_id, Some(10143));
    }

    #[test]
    fn test_announcement_stealth_address_serialization() {
        let stealth_addr = "0x1234567890abcdef";
        let ann = AnnouncementBuilder::new()
            .ephemeral_key(make_valid_ephemeral_key())
            .view_tag(0x42)
            .stealth_address(stealth_addr)
            .build()
            .unwrap();

        let json = serde_json::to_string(&ann).unwrap();
        assert!(json.contains("stealth_address"));
        assert!(json.contains("0x1234567890abcdef"));

        let ann_deserialized: Announcement = serde_json::from_str(&json).unwrap();
        assert_eq!(
            ann_deserialized.stealth_address,
            Some(stealth_addr.to_string())
        );
    }

    #[test]
    fn test_announcement_stealth_address_skipped_when_none() {
        let ann = Announcement::new(make_valid_ephemeral_key(), 0x42);
        let json = serde_json::to_string(&ann).unwrap();

        // stealth_address should not be serialized when None due to skip_serializing_if
        assert!(!json.contains("stealth_address"));
    }

    #[test]
    fn hash_only_announcement_is_valid_pending_resolution() {
        // A freshly-indexed announcement has only the keccak256 hash, no ciphertext.
        let mut ann = Announcement::new(Vec::new(), 0x42);
        ann.ephemeral_key_hash = Some(vec![0x11u8; 32]);
        assert!(!ann.is_resolved());
        assert!(ann.validate().is_ok(), "hash-only row must validate");
    }

    #[test]
    fn resolved_announcement_requires_full_ciphertext() {
        let ann = Announcement::new(make_valid_ephemeral_key(), 0x42);
        assert!(ann.is_resolved());
        assert!(ann.validate().is_ok());
    }

    #[test]
    fn empty_with_no_hash_is_invalid() {
        let ann = Announcement::new(Vec::new(), 0x42);
        assert!(
            ann.validate().is_err(),
            "no ciphertext and no hash is invalid"
        );
    }

    #[test]
    fn payment_hmac_roundtrips_through_serde() {
        let mut ann = Announcement::new(make_valid_ephemeral_key(), 0x42);
        ann.payment_tx_hash_hmac = Some(vec![0x33u8; 32]);
        let json = serde_json::to_string(&ann).unwrap();
        let back: Announcement = serde_json::from_str(&json).unwrap();
        assert_eq!(back.payment_tx_hash_hmac, Some(vec![0x33u8; 32]));
    }

    #[test]
    fn metadata_blob_roundtrips_through_serde() {
        let mut ann = Announcement::new(make_valid_ephemeral_key(), 0x42);
        ann.ephemeral_key_hash = Some(vec![0xAAu8; 32]);
        ann.metadata_blob = Some(vec![0x01, 0x02, 0x03]);
        let json = serde_json::to_string(&ann).unwrap();
        let back: Announcement = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ephemeral_key_hash, Some(vec![0xAAu8; 32]));
        assert_eq!(back.metadata_blob, Some(vec![0x01, 0x02, 0x03]));
    }

    #[test]
    fn test_announcement_binary_format_unchanged() {
        // Verify that to_bytes/from_bytes doesn't include stealth_address
        let ann = AnnouncementBuilder::new()
            .ephemeral_key(make_valid_ephemeral_key())
            .view_tag(0x42)
            .stealth_address("0xabcd")
            .build()
            .unwrap();

        let bytes = ann.to_bytes();
        let ann2 = Announcement::from_bytes(&bytes).unwrap();

        // stealth_address should not be preserved in binary format
        assert!(ann2.stealth_address.is_none());
        // but ephemeral_key and view_tag should be
        assert_eq!(ann2.ephemeral_key, ann.ephemeral_key);
        assert_eq!(ann2.view_tag, ann.view_tag);
    }
}
