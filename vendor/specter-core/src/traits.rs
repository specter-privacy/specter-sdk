//! Common traits for SPECTER.
//!
//! These traits define the interfaces that different implementations can satisfy,
//! enabling modularity and testing.

use async_trait::async_trait;

use crate::error::Result;
use crate::types::{Announcement, DiscoveredAddress, MetaAddress};

// ═══════════════════════════════════════════════════════════════════════════════
// REGISTRY TRAIT
// ═══════════════════════════════════════════════════════════════════════════════

/// Interface for announcement storage and retrieval.
///
/// Implementations might use:
/// - In-memory storage (for testing/development)
/// - SQLite/PostgreSQL (for production)
/// - On-chain storage (smart contract events)
#[async_trait]
pub trait AnnouncementRegistry: Send + Sync {
    /// Publishes a new announcement to the registry.
    ///
    /// Returns the assigned announcement ID.
    async fn publish(&self, announcement: Announcement) -> Result<u64>;

    /// Retrieves announcements by view tag.
    ///
    /// This is the primary query pattern - view tags enable 99.6% filtering.
    async fn get_by_view_tag(&self, view_tag: u8) -> Result<Vec<Announcement>>;

    /// Retrieves announcements within a time range.
    async fn get_by_time_range(&self, start: u64, end: u64) -> Result<Vec<Announcement>>;

    /// Retrieves a specific announcement by ID.
    async fn get_by_id(&self, id: u64) -> Result<Option<Announcement>>;

    /// Returns total announcement count.
    async fn count(&self) -> Result<u64>;

    /// Returns the next available announcement ID.
    async fn next_id(&self) -> Result<u64>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCANNER TRAIT
// ═══════════════════════════════════════════════════════════════════════════════

/// Progress update during scanning.
#[derive(Clone, Debug)]
pub struct ScanProgress {
    /// Total announcements to scan
    pub total: u64,
    /// Announcements scanned so far
    pub scanned: u64,
    /// Announcements that matched view tag
    pub matched_view_tag: u64,
    /// Discoveries found so far
    pub discoveries: u64,
}

/// Callback for scan progress updates.
pub type ProgressCallback = Box<dyn Fn(ScanProgress) + Send + Sync>;

/// Interface for scanning announcements to find payments.
#[async_trait]
pub trait Scanner: Send + Sync {
    /// Scans announcements for payments addressed to the given viewing key.
    ///
    /// # Arguments
    /// * `viewing_sk` - The viewing secret key for decapsulation
    /// * `spending_pk` - The spending public key for address derivation
    /// * `registry` - The announcement registry to scan
    ///
    /// # Returns
    /// List of discovered stealth addresses with their private keys.
    async fn scan(
        &self,
        viewing_sk: &[u8],
        spending_pk: &[u8],
        registry: &dyn AnnouncementRegistry,
    ) -> Result<Vec<DiscoveredAddress>>;

    /// Scans with progress reporting.
    async fn scan_with_progress(
        &self,
        viewing_sk: &[u8],
        spending_pk: &[u8],
        registry: &dyn AnnouncementRegistry,
        progress: ProgressCallback,
    ) -> Result<Vec<DiscoveredAddress>>;

    /// Computes the view tag for the given viewing public key.
    ///
    /// This is used to filter announcements efficiently.
    fn compute_view_tag(&self, viewing_pk: &[u8]) -> u8;
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENS RESOLVER TRAIT
// ═══════════════════════════════════════════════════════════════════════════════

/// Interface for ENS name resolution.
#[async_trait]
pub trait EnsResolver: Send + Sync {
    /// Resolves an ENS name to a SPECTER meta-address.
    ///
    /// # Flow
    /// 1. Query ENS for text record "specter"
    /// 2. Parse IPFS CID from record
    /// 3. Fetch meta-address from IPFS
    /// 4. Deserialize and validate
    async fn resolve(&self, name: &str) -> Result<MetaAddress>;

    /// Checks if an ENS name has a SPECTER record.
    async fn has_specter_record(&self, name: &str) -> Result<bool>;

    /// Gets the raw text record value (IPFS CID).
    async fn get_text_record(&self, name: &str) -> Result<Option<String>>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// IPFS CLIENT TRAIT
// ═══════════════════════════════════════════════════════════════════════════════

/// Interface for IPFS operations.
#[async_trait]
pub trait IpfsClient: Send + Sync {
    /// Uploads data to IPFS and returns the CID.
    async fn upload(&self, data: &[u8]) -> Result<String>;

    /// Downloads data from IPFS by CID.
    async fn download(&self, cid: &str) -> Result<Vec<u8>>;

    /// Pins a CID to ensure it's not garbage collected.
    async fn pin(&self, cid: &str) -> Result<()>;

    /// Unpins a CID.
    async fn unpin(&self, cid: &str) -> Result<()>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEY STORAGE TRAIT
// ═══════════════════════════════════════════════════════════════════════════════

/// Encrypted key data.
#[derive(Clone)]
pub struct EncryptedKeys {
    /// Encrypted key material
    pub ciphertext: Vec<u8>,
    /// Nonce/IV used for encryption
    pub nonce: [u8; 12],
    /// Salt used for key derivation
    pub salt: [u8; 32],
}

/// Interface for secure key storage.
#[async_trait]
pub trait KeyStorage: Send + Sync {
    /// Saves keys encrypted with password.
    async fn save(&self, keys: &crate::types::SpecterKeys, password: &str) -> Result<()>;

    /// Loads and decrypts keys.
    async fn load(&self, password: &str) -> Result<crate::types::SpecterKeys>;

    /// Checks if keys exist in storage.
    async fn exists(&self) -> Result<bool>;

    /// Deletes stored keys.
    async fn delete(&self) -> Result<()>;

    /// Exports encrypted keys (for backup).
    async fn export(&self, password: &str) -> Result<EncryptedKeys>;

    /// Imports encrypted keys.
    async fn import(&self, encrypted: EncryptedKeys, password: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_progress() {
        let progress = ScanProgress {
            total: 1000,
            scanned: 500,
            matched_view_tag: 4,
            discoveries: 1,
        };
        assert_eq!(progress.total, 1000);
        assert_eq!(progress.scanned, 500);
    }
}
