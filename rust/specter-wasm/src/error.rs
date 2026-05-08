//! Error mapping between `specter-core::SpecterError` and JS-facing errors.
//!
//! Every fallible bridge function returns `Result<JsValue, WasmError>` where
//! `WasmError` serialises to a stable JSON shape:
//!
//! ```json
//! {
//!   "code": "INVALID_KEY_SIZE",
//!   "message": "Invalid key: expected 1184 bytes, got 64",
//!   "recoverable": false,
//!   "category": "validation"
//! }
//! ```
//!
//! The TypeScript layer wraps this in a `SpecterSdkError` class so the JS
//! `code` is the source of truth for user-level discrimination.

use serde::{Deserialize, Serialize};
use specter_core::error::SpecterError;
use thiserror::Error;
use wasm_bindgen::JsValue;

/// Stable, machine-readable category for grouping error codes.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    /// Input did not pass type / length / format validation.
    Validation,
    /// A cryptographic primitive failed (encap, decap, derivation).
    Crypto,
    /// Hex decoding or general serialisation failure.
    Encoding,
    /// Programmer error: state precondition violated (e.g. WASM not init'd).
    Internal,
}

/// Error returned by every fallible bridge entry point.
#[derive(Clone, Debug, Error)]
pub enum WasmError {
    /// A key argument did not match the expected fixed length.
    #[error("invalid key: expected {expected} bytes, got {actual}")]
    InvalidKeySize {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length supplied by the caller.
        actual: usize,
        /// Which logical key field (e.g. `spending_pk`, `viewing_sk`).
        field: &'static str,
    },

    /// A ciphertext argument did not match the ML-KEM-768 size.
    #[error("invalid ciphertext: expected {expected} bytes, got {actual}")]
    InvalidCiphertextSize {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length supplied by the caller.
        actual: usize,
    },

    /// A shared secret argument did not match the 32-byte size.
    #[error("invalid shared secret: expected {expected} bytes, got {actual}")]
    InvalidSharedSecretSize {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length supplied by the caller.
        actual: usize,
    },

    /// Hex string failed to decode.
    #[error("invalid hex encoding")]
    InvalidHex,

    /// Meta-address binary payload failed validation.
    #[error("invalid meta-address: {0}")]
    InvalidMetaAddress(String),

    /// ML-KEM-768 encapsulation failed.
    #[error("encapsulation failed: {0}")]
    EncapsulationFailed(String),

    /// ML-KEM-768 decapsulation failed.
    #[error("decapsulation failed: {0}")]
    DecapsulationFailed(String),

    /// Stealth-key derivation failed (invalid secp256k1 scalar etc.).
    #[error("stealth derivation failed: {0}")]
    StealthDerivationFailed(String),

    /// Optional metadata JSON was present but failed to parse.
    #[error("invalid metadata JSON: {0}")]
    InvalidMetadataJson(String),

    /// A defensive check that should be unreachable in practice fired.
    #[error("internal error: {0}")]
    Internal(String),
}

impl WasmError {
    /// Returns the stable JS-facing string code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidKeySize { .. } => "INVALID_KEY_SIZE",
            Self::InvalidCiphertextSize { .. } => "INVALID_CIPHERTEXT_SIZE",
            Self::InvalidSharedSecretSize { .. } => "INVALID_SHARED_SECRET_SIZE",
            Self::InvalidHex => "INVALID_HEX",
            Self::InvalidMetaAddress(_) => "INVALID_META_ADDRESS",
            Self::EncapsulationFailed(_) => "ENCAPSULATION_FAILED",
            Self::DecapsulationFailed(_) => "DECAPSULATION_FAILED",
            Self::StealthDerivationFailed(_) => "STEALTH_DERIVATION_FAILED",
            Self::InvalidMetadataJson(_) => "INVALID_METADATA_JSON",
            Self::Internal(_) => "INTERNAL_ERROR",
        }
    }

    /// Whether retrying with the same input could plausibly succeed.
    #[must_use]
    pub const fn recoverable(&self) -> bool {
        // Every WasmError is deterministic given its inputs; nothing here is
        // a transient failure (no I/O, no time, no network in this crate).
        false
    }

    /// Coarse-grained category for grouping in TS error handling.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::InvalidKeySize { .. }
            | Self::InvalidCiphertextSize { .. }
            | Self::InvalidSharedSecretSize { .. }
            | Self::InvalidMetaAddress(_)
            | Self::InvalidMetadataJson(_) => ErrorCategory::Validation,
            Self::InvalidHex => ErrorCategory::Encoding,
            Self::EncapsulationFailed(_)
            | Self::DecapsulationFailed(_)
            | Self::StealthDerivationFailed(_) => ErrorCategory::Crypto,
            Self::Internal(_) => ErrorCategory::Internal,
        }
    }
}

/// Wire shape that gets serialised to JS via `serde-wasm-bindgen`.
#[derive(Serialize, Deserialize)]
struct WireError<'a> {
    code: &'a str,
    message: String,
    recoverable: bool,
    category: ErrorCategory,
}

impl From<WasmError> for JsValue {
    fn from(err: WasmError) -> Self {
        let wire = WireError {
            code: err.code(),
            message: err.to_string(),
            recoverable: err.recoverable(),
            category: err.category(),
        };
        // Serialising to JsValue cannot fail for a struct of plain primitives;
        // if it does (e.g. a future serde-wasm-bindgen version regresses),
        // fall back to a string so we never panic across the FFI boundary.
        serde_wasm_bindgen::to_value(&wire).unwrap_or_else(|_| JsValue::from_str(err.code()))
    }
}

/// Map an upstream `SpecterError` into a bridge-level error so JS sees a
/// stable code rather than the upstream variant name.
impl From<SpecterError> for WasmError {
    fn from(err: SpecterError) -> Self {
        match err {
            SpecterError::InvalidKeySize { expected, actual } => Self::InvalidKeySize {
                expected,
                actual,
                field: "key",
            },
            SpecterError::InvalidCiphertextSize { expected, actual } => {
                Self::InvalidCiphertextSize { expected, actual }
            }
            SpecterError::HexError(_) => Self::InvalidHex,
            SpecterError::InvalidMetaAddress(msg) => Self::InvalidMetaAddress(msg),
            SpecterError::KeyGenerationError(msg) => Self::Internal(format!("keygen: {msg}")),
            SpecterError::EncapsulationError(msg) => Self::EncapsulationFailed(msg),
            SpecterError::DecapsulationError(msg) => Self::DecapsulationFailed(msg),
            SpecterError::StealthDerivationError(msg)
            | SpecterError::InvalidStealthAddress(msg) => Self::StealthDerivationFailed(msg),
            SpecterError::JsonError(e) => Self::InvalidMetadataJson(e.to_string()),
            other => Self::Internal(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable_strings() {
        // The TS SDK has these codes hard-coded in its discriminated union,
        // so this test guards against accidental rename.
        assert_eq!(
            WasmError::InvalidKeySize {
                expected: 1184,
                actual: 0,
                field: "spending_pk"
            }
            .code(),
            "INVALID_KEY_SIZE"
        );
        assert_eq!(WasmError::InvalidHex.code(), "INVALID_HEX");
        assert_eq!(
            WasmError::EncapsulationFailed("x".into()).code(),
            "ENCAPSULATION_FAILED"
        );
        assert_eq!(
            WasmError::DecapsulationFailed("x".into()).code(),
            "DECAPSULATION_FAILED"
        );
    }

    #[test]
    fn upstream_error_maps_to_invalid_key_size() {
        let mapped: WasmError = SpecterError::InvalidKeySize {
            expected: 1184,
            actual: 32,
        }
        .into();
        assert_eq!(mapped.code(), "INVALID_KEY_SIZE");
    }
}
