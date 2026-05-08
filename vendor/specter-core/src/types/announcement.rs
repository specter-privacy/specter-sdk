//! Announcement types for the SPECTER registry.
//!
//! Announcements are published by senders and contain the ephemeral key
//! and view tag needed for recipients to discover payments.

use serde::{Deserialize, Serialize};

use crate::constants::{KYBER_CIPHERTEXT_SIZE, VIEW_TAG_SIZE};
use crate::error::{Result, SpecterError};

/// An announcement published to the registry.
///
/// Senders create announcements containing their ephemeral key and view tag.
/// Recipients scan these to find payments addressed to them.
///
/// # Wire Format (binary)
/// ```text
/// ephemeral_key (1088) || view_tag (1) || timestamp (8) || [channel_id (32)]
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Announcement {
    /// Unique identifier (assigned by registry)
    pub id: u64,
    /// Kyber ciphertext - the encapsulated ephemeral key
    #[serde(with = "hex")]
    pub ephemeral_key: Vec<u8>,
    /// View tag for efficient filtering (first byte of hash)
    pub view_tag: u8,
    /// Unix timestamp when announcement was created
    pub timestamp: u64,
    /// Optional: Yellow channel ID for trading integration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<[u8; 32]>,
    /// Optional: Block number if stored on-chain
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    /// Optional: Transaction hash if stored on-chain
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    /// Optional: Amount (human-readable, e.g. "0.1" ETH or "1.5" SUI)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    /// Optional: Chain identifier (e.g. "ethereum", "sui")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
}

impl Announcement {
    /// Creates a new announcement.
    pub fn new(ephemeral_key: Vec<u8>, view_tag: u8) -> Self {
        Self {
            id: 0, // Assigned by registry
            ephemeral_key,
            view_tag,
            timestamp: Self::current_timestamp(),
            channel_id: None,
            block_number: None,
            tx_hash: None,
            amount: None,
            chain: None,
        }
    }

    /// Creates an announcement with a Yellow channel ID.
    pub fn with_channel(ephemeral_key: Vec<u8>, view_tag: u8, channel_id: [u8; 32]) -> Self {
        Self {
            id: 0,
            ephemeral_key,
            view_tag,
            timestamp: Self::current_timestamp(),
            channel_id: Some(channel_id),
            block_number: None,
            tx_hash: None,
            amount: None,
            chain: None,
        }
    }

    /// Validates the announcement structure.
    pub fn validate(&self) -> Result<()> {
        // Check ephemeral key size
        if self.ephemeral_key.len() != KYBER_CIPHERTEXT_SIZE {
            return Err(SpecterError::InvalidAnnouncement(format!(
                "ephemeral key size mismatch: expected {}, got {}",
                KYBER_CIPHERTEXT_SIZE,
                self.ephemeral_key.len()
            )));
        }

        // Check for obviously invalid ephemeral key (all zeros)
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
    pub fn to_bytes(&self) -> Vec<u8> {
        let has_channel = self.channel_id.is_some();
        let size = KYBER_CIPHERTEXT_SIZE + VIEW_TAG_SIZE + 8 + 1 + if has_channel { 32 } else { 0 };

        let mut bytes = Vec::with_capacity(size);
        bytes.extend_from_slice(&self.ephemeral_key);
        bytes.push(self.view_tag);
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.push(if has_channel { 1 } else { 0 });

        if let Some(channel_id) = &self.channel_id {
            bytes.extend_from_slice(channel_id);
        }

        bytes
    }

    /// Deserializes from compact binary format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let min_size = KYBER_CIPHERTEXT_SIZE + VIEW_TAG_SIZE + 8 + 1;
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

        let has_channel = bytes[timestamp_start + 8] == 1;
        let channel_id = if has_channel {
            if bytes.len() < min_size + 32 {
                return Err(SpecterError::InvalidAnnouncement(
                    "missing channel_id bytes".into(),
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes[min_size..min_size + 32]);
            Some(arr)
        } else {
            None
        };

        let announcement = Self {
            id: 0, // ID is assigned by registry, not serialized
            ephemeral_key,
            view_tag,
            timestamp,
            channel_id,
            block_number: None,
            tx_hash: None,
            amount: None,
            chain: None,
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
    view_tag: Option<u8>,
    timestamp: Option<u64>,
    channel_id: Option<[u8; 32]>,
    block_number: Option<u64>,
    tx_hash: Option<String>,
    amount: Option<String>,
    chain: Option<String>,
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
    pub fn channel_id(mut self, id: [u8; 32]) -> Self {
        self.channel_id = Some(id);
        self
    }

    /// Sets the block number (optional).
    pub fn block_number(mut self, num: u64) -> Self {
        self.block_number = Some(num);
        self
    }

    /// Sets the transaction hash (optional).
    pub fn tx_hash(mut self, hash: String) -> Self {
        self.tx_hash = Some(hash);
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
        announcement.channel_id = self.channel_id;
        announcement.block_number = self.block_number;
        announcement.tx_hash = self.tx_hash;
        announcement.amount = self.amount;
        announcement.chain = self.chain;

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
    /// Number of announcements with Yellow channel IDs
    pub yellow_channel_count: u64,
}

impl Default for AnnouncementStats {
    fn default() -> Self {
        Self {
            total_count: 0,
            view_tag_distribution: vec![0; 256],
            earliest_timestamp: None,
            latest_timestamp: None,
            yellow_channel_count: 0,
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

        if announcement.channel_id.is_some() {
            self.yellow_channel_count += 1;
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
        assert!(ann.channel_id.is_none());
    }

    #[test]
    fn test_announcement_validation() {
        // Valid announcement
        let valid = Announcement::new(make_valid_ephemeral_key(), 0x42);
        assert!(valid.validate().is_ok());

        // Invalid: wrong ephemeral key size
        let mut invalid = valid.clone();
        invalid.ephemeral_key = vec![0u8; 100];
        assert!(invalid.validate().is_err());

        // Invalid: all-zero ephemeral key
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
    fn test_announcement_with_channel() {
        let channel_id = [0xCC; 32];
        let ann = Announcement::with_channel(make_valid_ephemeral_key(), 0x42, channel_id);

        let bytes = ann.to_bytes();
        let ann2 = Announcement::from_bytes(&bytes).unwrap();

        assert_eq!(ann2.channel_id, Some(channel_id));
    }

    #[test]
    fn test_announcement_builder() {
        let ann = AnnouncementBuilder::new()
            .ephemeral_key(make_valid_ephemeral_key())
            .view_tag(0x55)
            .channel_id([0xAA; 32])
            .build()
            .unwrap();

        assert_eq!(ann.view_tag, 0x55);
        assert!(ann.channel_id.is_some());
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
}
