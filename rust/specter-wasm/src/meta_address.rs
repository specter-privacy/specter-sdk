//! Meta-address bindings (hybrid v2 format).
//!
//! A meta-address is the public payload a recipient publishes (e.g. to an ENS
//! or `SuiNS` text record) so senders can pay them. The v2 layout carries the
//! secp256k1 spending public key alongside the ML-KEM-768 viewing public key:
//!
//! ```text
//! byte  0        : version (2)
//! bytes 1..34    : spending_pk   (33-byte compressed secp256k1 point)
//! bytes 34..1218 : viewing_pk    (1184-byte ML-KEM-768 public key)
//! ```
//!
//! Total: `1 + 33 + 1184 = 1218` bytes. Optional metadata
//! (`description` / `avatar` / `created_at`) travels alongside the struct but
//! is not part of the canonical serialized payload.

use k256::PublicKey;
use serde::{Deserialize, Serialize};
use specter_core::constants::KYBER_PUBLIC_KEY_SIZE;
use wasm_bindgen::prelude::*;

use crate::derive::SPEND_PUBLIC_SIZE;
use crate::error::WasmError;

/// Meta-address wire-format version (hybrid secp256k1 + ML-KEM).
pub const META_ADDRESS_VERSION: u8 = 2;
/// Serialized meta-address size in bytes (`1 + 33 + 1184`).
pub const META_ADDRESS_V2_SIZE: usize = 1 + SPEND_PUBLIC_SIZE + KYBER_PUBLIC_KEY_SIZE;

/// Wire shape returned by `meta_address_from_public_keys` / `parse_meta_address`.
#[derive(Serialize, Deserialize)]
pub struct WasmMetaAddress {
    /// Format version (currently 2).
    pub version: u8,
    /// 33-byte compressed secp256k1 spending public key.
    pub spending_pk: Vec<u8>,
    /// 1184-byte ML-KEM-768 viewing public key.
    pub viewing_pk: Vec<u8>,
    /// Optional metadata (`description` / `avatar` / `created_at`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<WasmMetaAddressMetadata>,
    /// Canonical serialized payload (1218 bytes).
    pub bytes: Vec<u8>,
}

/// Optional metadata field within a meta-address.
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmMetaAddressMetadata {
    /// Free-form description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Avatar URL or IPFS CID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    /// Creation timestamp (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
}

fn serialize_bytes(spending_pk: &[u8], viewing_pk: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(META_ADDRESS_V2_SIZE);
    out.push(META_ADDRESS_VERSION);
    out.extend_from_slice(spending_pk);
    out.extend_from_slice(viewing_pk);
    out
}

fn validate_spend_pub(spending_pk: &[u8]) -> Result<(), WasmError> {
    if spending_pk.len() != SPEND_PUBLIC_SIZE {
        return Err(WasmError::InvalidKeySize {
            expected: SPEND_PUBLIC_SIZE,
            actual: spending_pk.len(),
            field: "spending_pk",
        });
    }
    // Reject a non-curve point up front so downstream derivation can't fail.
    PublicKey::from_sec1_bytes(spending_pk).map_err(|_| {
        WasmError::InvalidMetaAddress("spending_pk is not a valid secp256k1 point".into())
    })?;
    Ok(())
}

fn validate_viewing_pk(viewing_pk: &[u8]) -> Result<(), WasmError> {
    if viewing_pk.len() != KYBER_PUBLIC_KEY_SIZE {
        return Err(WasmError::InvalidKeySize {
            expected: KYBER_PUBLIC_KEY_SIZE,
            actual: viewing_pk.len(),
            field: "viewing_pk",
        });
    }
    if viewing_pk.iter().all(|&b| b == 0) {
        return Err(WasmError::InvalidMetaAddress(
            "viewing_pk must not be all zero".into(),
        ));
    }
    Ok(())
}

/// Construct a meta-address from a compressed secp256k1 spending public key, an
/// ML-KEM-768 viewing public key, and optional metadata JSON.
///
/// # Errors
///
/// - [`WasmError::InvalidKeySize`] if either key has the wrong length.
/// - [`WasmError::InvalidMetaAddress`] if `spending_pk` is not a valid curve
///   point or `viewing_pk` is all zero.
/// - [`WasmError::InvalidMetadataJson`] if `metadata_json` is malformed.
#[wasm_bindgen(js_name = metaAddressFromPublicKeys)]
pub fn meta_address_from_public_keys(
    spending_pk: &[u8],
    viewing_pk: &[u8],
    metadata_json: Option<String>,
) -> Result<JsValue, WasmError> {
    validate_spend_pub(spending_pk)?;
    validate_viewing_pk(viewing_pk)?;

    let metadata = match metadata_json {
        Some(raw) => Some(
            serde_json::from_str::<WasmMetaAddressMetadata>(&raw)
                .map_err(|e| WasmError::InvalidMetadataJson(e.to_string()))?,
        ),
        None => None,
    };

    let wire = WasmMetaAddress {
        version: META_ADDRESS_VERSION,
        spending_pk: spending_pk.to_vec(),
        viewing_pk: viewing_pk.to_vec(),
        metadata,
        bytes: serialize_bytes(spending_pk, viewing_pk),
    };
    serde_wasm_bindgen::to_value(&wire)
        .map_err(|e| WasmError::Internal(format!("serde failure: {e}")))
}

/// Parse a 1218-byte serialized meta-address back into the JS shape.
///
/// # Errors
///
/// [`WasmError::InvalidMetaAddress`] if the payload is the wrong size, has an
/// unexpected version byte, or contains an invalid key.
#[wasm_bindgen(js_name = parseMetaAddress)]
pub fn parse_meta_address(bytes: &[u8]) -> Result<JsValue, WasmError> {
    if bytes.len() != META_ADDRESS_V2_SIZE {
        return Err(WasmError::InvalidMetaAddress(format!(
            "expected {META_ADDRESS_V2_SIZE} bytes, got {}",
            bytes.len()
        )));
    }
    let version = bytes[0];
    if version != META_ADDRESS_VERSION {
        return Err(WasmError::InvalidMetaAddress(format!(
            "unsupported meta-address version {version}, expected {META_ADDRESS_VERSION}"
        )));
    }
    let spending_pk = &bytes[1..=SPEND_PUBLIC_SIZE];
    let viewing_pk = &bytes[1 + SPEND_PUBLIC_SIZE..];
    validate_spend_pub(spending_pk)?;
    validate_viewing_pk(viewing_pk)?;

    let wire = WasmMetaAddress {
        version,
        spending_pk: spending_pk.to_vec(),
        viewing_pk: viewing_pk.to_vec(),
        metadata: None,
        bytes: bytes.to_vec(),
    };
    serde_wasm_bindgen::to_value(&wire)
        .map_err(|e| WasmError::Internal(format!("serde failure: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::generate_spend_keypair;

    fn viewing() -> Vec<u8> {
        specter_crypto::generate_keypair()
            .public
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn size_constant_is_1218() {
        assert_eq!(META_ADDRESS_V2_SIZE, 1218);
    }

    #[test]
    fn round_trip_serialize_parse() {
        let (_sk, spend_pub) = generate_spend_keypair();
        let view = viewing();
        let bytes = serialize_bytes(&spend_pub, &view);
        assert_eq!(bytes.len(), META_ADDRESS_V2_SIZE);
        assert_eq!(bytes[0], META_ADDRESS_VERSION);
        assert_eq!(&bytes[1..=SPEND_PUBLIC_SIZE], &spend_pub[..]);
        assert_eq!(&bytes[1 + SPEND_PUBLIC_SIZE..], &view[..]);
    }

    #[test]
    fn rejects_bad_spend_pub_size() {
        assert_eq!(
            validate_spend_pub(&[0u8; 10]).unwrap_err().code(),
            "INVALID_KEY_SIZE"
        );
    }

    #[test]
    fn rejects_non_curve_spend_pub() {
        // Right size, but not a valid compressed point.
        assert_eq!(
            validate_spend_pub(&[0xFFu8; SPEND_PUBLIC_SIZE])
                .unwrap_err()
                .code(),
            "INVALID_META_ADDRESS"
        );
    }

    #[test]
    fn rejects_zero_viewing_pk() {
        assert_eq!(
            validate_viewing_pk(&[0u8; KYBER_PUBLIC_KEY_SIZE])
                .unwrap_err()
                .code(),
            "INVALID_META_ADDRESS"
        );
    }
}
