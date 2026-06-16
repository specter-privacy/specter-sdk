//! Announcement metadata encoding/decoding for on-chain compatibility.
//!
//! This module defines the 77-byte fixed-width metadata layout matching the
//! SPECTERAnnouncer Solidity contract event encoding.
//!
//! # Binary Layout (77 bytes)
//!
//! ```text
//! [0]       view_tag         uint8   1 byte   (always present)
//! [1..33]   tx_hash          bytes32 32 bytes (optional: 0x00..00 = absent)
//! [33..65]  amount           uint256 32 bytes (optional: all zeros = absent)
//! [65..73]  source_chain_id  uint64  8 bytes  (big-endian; 0 = absent)
//! [73..77]  reserved         bytes4  4 bytes  (always zero)
//! ```

use serde::{Deserialize, Serialize};

/// Fixed 77-byte metadata layout for on-chain announcement events.
///
/// Encodes the payment details embedded in each SPECTERAnnouncer `announce()` call.
/// The `source_chain_id` field identifies which chain the actual payment originated on
/// (e.g., 42161 = Arbitrum, 10143 = Monad testnet, 1 = Ethereum mainnet).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnnouncementMetadata {
    /// View tag for efficient filtering — first byte of SHAKE-256(shared_secret).
    /// Recipients compute their own tag; matching tags avoid expensive decapsulation.
    pub view_tag: u8,
    /// Optional source-chain transaction hash (32 bytes, big-endian H256).
    /// All-zero = absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<[u8; 32]>,
    /// Optional payment amount (32 bytes, Solidity uint256 big-endian).
    /// All-zero = absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<[u8; 32]>,
    /// Optional EIP-155 chain ID of the chain where funds were sent from.
    /// Examples: 42161 = Arbitrum One, 10143 = Monad testnet, 1 = Ethereum mainnet.
    /// Zero = absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_chain_id: Option<u64>,
}

impl AnnouncementMetadata {
    /// Creates new metadata with only a view tag set.
    pub fn new(view_tag: u8) -> Self {
        Self {
            view_tag,
            tx_hash: None,
            amount: None,
            source_chain_id: None,
        }
    }

    /// Encodes metadata to the fixed 77-byte wire format.
    ///
    /// # Layout
    ///
    /// - Byte 0:    `view_tag`
    /// - Bytes 1–32:  `tx_hash` (all-zero if None)
    /// - Bytes 33–64: `amount` (all-zero if None)
    /// - Bytes 65–72: `source_chain_id` big-endian u64 (all-zero if None)
    /// - Bytes 73–76: reserved (always zero)
    pub fn encode(&self) -> [u8; 77] {
        let mut buf = [0u8; 77];

        buf[0] = self.view_tag;

        if let Some(hash) = &self.tx_hash {
            buf[1..33].copy_from_slice(hash);
        }

        if let Some(amt) = &self.amount {
            buf[33..65].copy_from_slice(amt);
        }

        if let Some(chain_id) = self.source_chain_id {
            buf[65..73].copy_from_slice(&chain_id.to_be_bytes());
        }
        // [73..77] reserved — already zero from initialization

        buf
    }

    /// Decodes metadata from raw bytes.
    ///
    /// Optional fields whose bytes are all-zero are decoded as `None`.
    ///
    /// # Panics
    ///
    /// Panics if `raw.len() < 77`.
    pub fn decode(raw: &[u8]) -> Self {
        assert!(
            raw.len() >= 77,
            "metadata must be at least 77 bytes, got {}",
            raw.len()
        );

        let view_tag = raw[0];

        let tx_hash = {
            let slice = &raw[1..33];
            if slice.iter().all(|&b| b == 0) {
                None
            } else {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(slice);
                Some(arr)
            }
        };

        let amount = {
            let slice = &raw[33..65];
            if slice.iter().all(|&b| b == 0) {
                None
            } else {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(slice);
                Some(arr)
            }
        };

        let source_chain_id = {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&raw[65..73]);
            let val = u64::from_be_bytes(arr);
            if val == 0 {
                None
            } else {
                Some(val)
            }
        };

        Self {
            view_tag,
            tx_hash,
            amount,
            source_chain_id,
        }
    }

    /// Builder-style setter for `tx_hash`.
    pub fn with_tx_hash(mut self, hash: [u8; 32]) -> Self {
        self.tx_hash = Some(hash);
        self
    }

    /// Builder-style setter for `amount`.
    pub fn with_amount(mut self, amount: [u8; 32]) -> Self {
        self.amount = Some(amount);
        self
    }

    /// Builder-style setter for `source_chain_id`.
    pub fn with_source_chain_id(mut self, id: u64) -> Self {
        self.source_chain_id = Some(id);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_new() {
        let meta = AnnouncementMetadata::new(0x42);
        assert_eq!(meta.view_tag, 0x42);
        assert!(meta.tx_hash.is_none());
        assert!(meta.amount.is_none());
        assert!(meta.source_chain_id.is_none());
    }

    #[test]
    fn test_metadata_encode_all_none() {
        let meta = AnnouncementMetadata::new(0x42);
        let bytes = meta.encode();

        assert_eq!(bytes.len(), 77);
        assert_eq!(bytes[0], 0x42);
        assert!(bytes[1..33].iter().all(|&b| b == 0));
        assert!(bytes[33..65].iter().all(|&b| b == 0));
        assert!(bytes[65..73].iter().all(|&b| b == 0)); // source_chain_id absent
        assert!(bytes[73..77].iter().all(|&b| b == 0)); // reserved
    }

    #[test]
    fn test_metadata_encode_with_tx_hash() {
        let mut meta = AnnouncementMetadata::new(0x99);
        meta.tx_hash = Some([0xAB; 32]);

        let bytes = meta.encode();
        assert_eq!(bytes[0], 0x99);
        assert_eq!(&bytes[1..33], &[0xAB; 32]);
        assert!(bytes[33..65].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_metadata_encode_with_amount() {
        let mut meta = AnnouncementMetadata::new(0x11);
        meta.amount = Some([0xCD; 32]);

        let bytes = meta.encode();
        assert_eq!(bytes[0], 0x11);
        assert!(bytes[1..33].iter().all(|&b| b == 0));
        assert_eq!(&bytes[33..65], &[0xCD; 32]);
    }

    #[test]
    fn test_metadata_encode_with_source_chain_id_arbitrum() {
        let mut meta = AnnouncementMetadata::new(0xEE);
        meta.source_chain_id = Some(42161); // Arbitrum One

        let bytes = meta.encode();
        assert_eq!(bytes[0], 0xEE);
        assert!(bytes[1..33].iter().all(|&b| b == 0));
        assert!(bytes[33..65].iter().all(|&b| b == 0));
        // 42161 = 0x0000_0000_0000_A4B1
        let encoded_id = u64::from_be_bytes(bytes[65..73].try_into().unwrap());
        assert_eq!(encoded_id, 42161);
        assert!(bytes[73..77].iter().all(|&b| b == 0)); // reserved
    }

    #[test]
    fn test_metadata_encode_with_source_chain_id_monad() {
        let meta = AnnouncementMetadata::new(0x01).with_source_chain_id(10143); // Monad testnet

        let bytes = meta.encode();
        let encoded_id = u64::from_be_bytes(bytes[65..73].try_into().unwrap());
        assert_eq!(encoded_id, 10143);
    }

    #[test]
    fn test_metadata_encode_all_fields() {
        let mut meta = AnnouncementMetadata::new(0x77);
        meta.tx_hash = Some([0x01; 32]);
        meta.amount = Some([0x02; 32]);
        meta.source_chain_id = Some(1); // Ethereum mainnet

        let bytes = meta.encode();
        assert_eq!(bytes[0], 0x77);
        assert_eq!(&bytes[1..33], &[0x01; 32]);
        assert_eq!(&bytes[33..65], &[0x02; 32]);
        let encoded_id = u64::from_be_bytes(bytes[65..73].try_into().unwrap());
        assert_eq!(encoded_id, 1);
        assert!(bytes[73..77].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_metadata_decode_all_none() {
        let bytes = [0u8; 77];
        let meta = AnnouncementMetadata::decode(&bytes);

        assert_eq!(meta.view_tag, 0);
        assert!(meta.tx_hash.is_none());
        assert!(meta.amount.is_none());
        assert!(meta.source_chain_id.is_none()); // 0 decodes as None
    }

    #[test]
    fn test_metadata_decode_with_tx_hash() {
        let mut bytes = [0u8; 77];
        bytes[0] = 0x42;
        bytes[1..33].copy_from_slice(&[0xAB; 32]);

        let meta = AnnouncementMetadata::decode(&bytes);
        assert_eq!(meta.view_tag, 0x42);
        assert_eq!(meta.tx_hash, Some([0xAB; 32]));
        assert!(meta.amount.is_none());
        assert!(meta.source_chain_id.is_none());
    }

    #[test]
    fn test_metadata_decode_with_source_chain_id() {
        let mut bytes = [0u8; 77];
        bytes[0] = 0xCC;
        // Encode 42161 (Arbitrum) at [65..73]
        bytes[65..73].copy_from_slice(&42161u64.to_be_bytes());

        let meta = AnnouncementMetadata::decode(&bytes);
        assert_eq!(meta.view_tag, 0xCC);
        assert!(meta.tx_hash.is_none());
        assert!(meta.amount.is_none());
        assert_eq!(meta.source_chain_id, Some(42161));
    }

    #[test]
    fn test_metadata_decode_all_fields() {
        let mut bytes = [0u8; 77];
        bytes[0] = 0x77;
        bytes[1..33].copy_from_slice(&[0x01; 32]);
        bytes[33..65].copy_from_slice(&[0x02; 32]);
        bytes[65..73].copy_from_slice(&10143u64.to_be_bytes()); // Monad testnet

        let meta = AnnouncementMetadata::decode(&bytes);
        assert_eq!(meta.view_tag, 0x77);
        assert_eq!(meta.tx_hash, Some([0x01; 32]));
        assert_eq!(meta.amount, Some([0x02; 32]));
        assert_eq!(meta.source_chain_id, Some(10143));
    }

    #[test]
    fn test_metadata_roundtrip_all_none() {
        let meta = AnnouncementMetadata::new(0x42);
        let bytes = meta.encode();
        let meta2 = AnnouncementMetadata::decode(&bytes);
        assert_eq!(meta, meta2);
    }

    #[test]
    fn test_metadata_roundtrip_all_fields() {
        let mut meta = AnnouncementMetadata::new(0xAA);
        meta.tx_hash = Some([0x11; 32]);
        meta.amount = Some([0x22; 32]);
        meta.source_chain_id = Some(42161);

        let bytes = meta.encode();
        let meta2 = AnnouncementMetadata::decode(&bytes);
        assert_eq!(meta, meta2);
    }

    #[test]
    fn test_metadata_source_chain_id_zero_is_none() {
        // Explicitly writing zero bytes should decode as None
        let mut bytes = [0u8; 77];
        bytes[0] = 0x55;
        // [65..73] are already zero

        let meta = AnnouncementMetadata::decode(&bytes);
        assert!(meta.source_chain_id.is_none());
    }

    #[test]
    fn test_metadata_reserved_bytes_always_zero() {
        let meta = AnnouncementMetadata::new(0x42)
            .with_source_chain_id(42161)
            .with_tx_hash([0xAA; 32]);
        let bytes = meta.encode();
        assert!(bytes[73..77].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_metadata_builder_pattern() {
        let meta = AnnouncementMetadata::new(0x77)
            .with_tx_hash([0xAA; 32])
            .with_amount([0xBB; 32])
            .with_source_chain_id(1); // Ethereum mainnet

        assert_eq!(meta.view_tag, 0x77);
        assert_eq!(meta.tx_hash, Some([0xAA; 32]));
        assert_eq!(meta.amount, Some([0xBB; 32]));
        assert_eq!(meta.source_chain_id, Some(1));
    }

    #[test]
    fn test_metadata_serialization_none_skipped() {
        let meta = AnnouncementMetadata::new(0x42);
        let json = serde_json::to_string(&meta).unwrap();

        assert!(!json.contains("tx_hash"));
        assert!(!json.contains("amount"));
        assert!(!json.contains("source_chain_id"));
        assert!(json.contains("view_tag"));
    }

    #[test]
    fn test_metadata_serialization_with_fields() {
        let mut meta = AnnouncementMetadata::new(0x42);
        meta.tx_hash = Some([0x11; 32]);
        meta.amount = Some([0x22; 32]);
        meta.source_chain_id = Some(42161);

        let json = serde_json::to_string(&meta).unwrap();
        let meta2: AnnouncementMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, meta2);
    }

    #[test]
    fn test_metadata_no_channel_id_field() {
        // Verify the old "channel_id" field is gone
        let meta = AnnouncementMetadata::new(0x42);
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("channel_id"));
    }

    #[test]
    #[should_panic(expected = "metadata must be at least 77 bytes")]
    fn test_metadata_decode_too_short() {
        let bytes = [0u8; 76];
        AnnouncementMetadata::decode(&bytes);
    }

    #[test]
    fn test_metadata_decode_ignores_extra_bytes() {
        let mut bytes = vec![0u8; 100];
        bytes[0] = 0x42;
        bytes[65..73].copy_from_slice(&42161u64.to_be_bytes());

        let meta = AnnouncementMetadata::decode(&bytes);
        assert_eq!(meta.view_tag, 0x42);
        assert_eq!(meta.source_chain_id, Some(42161));
    }

    #[test]
    fn test_metadata_partial_zero_detection() {
        let mut bytes = [0u8; 77];
        bytes[0] = 0x42;
        bytes[32] = 0x01; // Last byte of tx_hash is non-zero

        let meta = AnnouncementMetadata::decode(&bytes);
        assert!(meta.tx_hash.is_some());

        let bytes2 = meta.encode();
        assert_eq!(bytes2[32], 0x01);
    }
}
