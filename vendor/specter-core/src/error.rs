//! Error types for SPECTER.
//!
//! This module provides a comprehensive error hierarchy using `thiserror`.
//! All errors include context and are designed to be actionable.

use thiserror::Error;

/// Result type alias using `SpecterError`.
pub type Result<T> = std::result::Result<T, SpecterError>;

/// Main error type for all SPECTER operations.
#[derive(Debug, Error)]
pub enum SpecterError {
    // ═══════════════════════════════════════════════════════════════════════════
    // CRYPTOGRAPHIC ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Error in Kyber key generation.
    #[error("Key generation failed: {0}")]
    KeyGenerationError(String),

    /// Error in Kyber encapsulation.
    #[error("Encapsulation failed: {0}")]
    EncapsulationError(String),

    /// Error in Kyber decapsulation.
    #[error("Decapsulation failed: {0}")]
    DecapsulationError(String),

    /// Invalid key size or format.
    #[error("Invalid key: expected {expected} bytes, got {actual}")]
    InvalidKeySize {
        /// Expected key length in bytes.
        expected: usize,
        /// Actual key length in bytes.
        actual: usize,
    },

    /// Invalid ciphertext size or format.
    #[error("Invalid ciphertext: expected {expected} bytes, got {actual}")]
    InvalidCiphertextSize {
        /// Expected ciphertext length in bytes.
        expected: usize,
        /// Actual ciphertext length in bytes.
        actual: usize,
    },

    /// Cryptographic verification failed.
    #[error("Cryptographic verification failed: {0}")]
    VerificationFailed(String),

    // ═══════════════════════════════════════════════════════════════════════════
    // STEALTH ADDRESS ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Invalid meta-address format or content.
    #[error("Invalid meta-address: {0}")]
    InvalidMetaAddress(String),

    /// Invalid stealth address format.
    #[error("Invalid stealth address: {0}")]
    InvalidStealthAddress(String),

    /// View tag mismatch during scanning.
    #[error("View tag mismatch: expected {expected}, got {actual}")]
    ViewTagMismatch {
        /// Expected view tag.
        expected: u8,
        /// Actual view tag.
        actual: u8,
    },

    /// Failed to derive stealth keys.
    #[error("Stealth key derivation failed: {0}")]
    StealthDerivationError(String),

    // ═══════════════════════════════════════════════════════════════════════════
    // REGISTRY ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Invalid announcement format.
    #[error("Invalid announcement: {0}")]
    InvalidAnnouncement(String),

    /// Announcement not found.
    #[error("Announcement not found: {0}")]
    AnnouncementNotFound(String),

    /// Registry is full or corrupted.
    #[error("Registry error: {0}")]
    RegistryError(String),

    /// Duplicate announcement ID.
    #[error("Duplicate announcement ID: {0}")]
    DuplicateAnnouncement(u64),

    // ═══════════════════════════════════════════════════════════════════════════
    // ENS ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// ENS name not found.
    #[error("ENS name not found: {0}")]
    EnsNameNotFound(String),

    /// ENS resolution failed.
    #[error("ENS resolution failed for '{name}': {reason}")]
    EnsResolutionFailed {
        /// ENS name that failed to resolve.
        name: String,
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// No SPECTER record found in ENS.
    #[error("No SPECTER record found for ENS name: {0}")]
    NoSpecterRecord(String),

    /// Invalid ENS text record format.
    #[error("Invalid ENS text record: {0}")]
    InvalidEnsRecord(String),

    // ═══════════════════════════════════════════════════════════════════════════
    // SUINS ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// SuiNS name not found.
    #[error("SuiNS name not found: {0}")]
    SuinsNameNotFound(String),

    /// SuiNS resolution failed.
    #[error("SuiNS resolution failed for '{name}': {reason}")]
    SuinsResolutionFailed {
        /// SuiNS name that failed to resolve.
        name: String,
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// No SPECTER record found in SuiNS.
    #[error("No SPECTER record found for SuiNS name: {0}")]
    NoSuinsSpecterRecord(String),

    // ═══════════════════════════════════════════════════════════════════════════
    // IPFS ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// IPFS upload failed.
    #[error("IPFS upload failed: {0}")]
    IpfsUploadFailed(String),

    /// IPFS download failed.
    #[error("IPFS download failed for CID '{cid}': {reason}")]
    IpfsDownloadFailed {
        /// CID that failed to download.
        cid: String,
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// Invalid IPFS CID format.
    #[error("Invalid IPFS CID: {0}")]
    InvalidIpfsCid(String),

    /// IPFS gateway timeout.
    #[error("IPFS gateway timeout after {seconds}s")]
    IpfsTimeout {
        /// Timeout duration in seconds.
        seconds: u64,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // SERIALIZATION ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Binary serialization error.
    #[error("Binary serialization error: {0}")]
    BinarySerializationError(String),

    /// Invalid hex encoding.
    #[error("Invalid hex encoding: {0}")]
    HexError(#[from] hex::FromHexError),

    /// Protocol version mismatch.
    #[error("Protocol version mismatch: expected {expected}, got {actual}")]
    VersionMismatch {
        /// Expected protocol version.
        expected: u8,
        /// Actual protocol version.
        actual: u8,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // NETWORK ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// HTTP request failed.
    #[error("HTTP request failed: {0}")]
    HttpError(String),

    /// Connection timeout.
    #[error("Connection timeout: {0}")]
    ConnectionTimeout(String),

    /// RPC call failed.
    #[error("RPC call failed: {0}")]
    RpcError(String),

    // ═══════════════════════════════════════════════════════════════════════════
    // STORAGE ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// File I/O error.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Key storage encryption/decryption failed.
    #[error("Key storage error: {0}")]
    KeyStorageError(String),

    /// Invalid password for key decryption.
    #[error("Invalid password")]
    InvalidPassword,

    // ═══════════════════════════════════════════════════════════════════════════
    // VALIDATION ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Input validation failed.
    #[error("Validation error: {0}")]
    ValidationError(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    ConfigError(String),

    // ═══════════════════════════════════════════════════════════════════════════
    // INTERNAL ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Internal invariant violation (should never happen).
    #[error("Internal error: {0}")]
    InternalError(String),

    /// Feature not yet implemented.
    #[error("Not implemented: {0}")]
    NotImplemented(String),

    // ═══════════════════════════════════════════════════════════════════════════
    // YELLOW NETWORK ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Yellow Network error.
    #[error("Yellow Network error: {0}")]
    YellowError(String),
}

impl SpecterError {
    /// Returns true if this error is recoverable (can retry).
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            SpecterError::HttpError(_)
                | SpecterError::ConnectionTimeout(_)
                | SpecterError::IpfsTimeout { .. }
                | SpecterError::RpcError(_)
        )
    }

    /// Returns true if this is a cryptographic error.
    pub fn is_crypto_error(&self) -> bool {
        matches!(
            self,
            SpecterError::KeyGenerationError(_)
                | SpecterError::EncapsulationError(_)
                | SpecterError::DecapsulationError(_)
                | SpecterError::VerificationFailed(_)
                | SpecterError::InvalidKeySize { .. }
                | SpecterError::InvalidCiphertextSize { .. }
        )
    }

    /// Returns true if this is a validation error.
    pub fn is_validation_error(&self) -> bool {
        matches!(
            self,
            SpecterError::ValidationError(_)
                | SpecterError::InvalidMetaAddress(_)
                | SpecterError::InvalidStealthAddress(_)
                | SpecterError::InvalidAnnouncement(_)
                | SpecterError::VersionMismatch { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = SpecterError::InvalidKeySize {
            expected: 1184,
            actual: 100,
        };
        assert!(err.to_string().contains("1184"));
        assert!(err.to_string().contains("100"));
    }

    #[test]
    fn test_error_classification() {
        assert!(SpecterError::HttpError("test".into()).is_recoverable());
        assert!(SpecterError::ConnectionTimeout("test".into()).is_recoverable());
        assert!(!SpecterError::InvalidPassword.is_recoverable());

        assert!(SpecterError::KeyGenerationError("test".into()).is_crypto_error());
        assert!(SpecterError::DecapsulationError("test".into()).is_crypto_error());
        assert!(!SpecterError::HttpError("test".into()).is_crypto_error());
    }

    #[test]
    fn test_json_error_conversion() {
        let json_result: std::result::Result<serde_json::Value, _> =
            serde_json::from_str("invalid");
        let specter_result: Result<serde_json::Value> = json_result.map_err(SpecterError::from);
        assert!(matches!(specter_result, Err(SpecterError::JsonError(_))));
    }
}
