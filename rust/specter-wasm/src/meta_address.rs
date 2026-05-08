//! Meta-address bindings.
//!
//! A meta-address is the public payload (1184 + 1184 + 1 = 2369 bytes) that
//! recipients publish to a name service so senders can encapsulate to them.
//! This module exposes serialise / parse / validate helpers.

use serde::{Deserialize, Serialize};
use specter_core::constants::{KYBER_PUBLIC_KEY_SIZE, META_ADDRESS_SERIALIZED_SIZE};
use specter_core::types::{KyberPublicKey, MetaAddress, MetaAddressMetadata};
use wasm_bindgen::prelude::*;

use crate::error::WasmError;

/// Wire shape returned by `meta_address_from_public_keys` /
/// `parse_meta_address`.
#[derive(Serialize, Deserialize)]
pub struct WasmMetaAddress {
    /// Protocol version (currently 1).
    pub version: u8,
    /// 1184-byte spending public key.
    pub spending_pk: Vec<u8>,
    /// 1184-byte viewing public key.
    pub viewing_pk: Vec<u8>,
    /// Optional metadata (`description` / `avatar` / `created_at`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<WasmMetaAddressMetadata>,
    /// Canonical serialised payload (2369 bytes).
    pub bytes: Vec<u8>,
}

/// Optional metadata field within a meta-address.
#[derive(Serialize, Deserialize)]
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

impl From<MetaAddressMetadata> for WasmMetaAddressMetadata {
    fn from(m: MetaAddressMetadata) -> Self {
        Self {
            description: m.description,
            avatar: m.avatar,
            created_at: m.created_at,
        }
    }
}

impl From<WasmMetaAddressMetadata> for MetaAddressMetadata {
    fn from(m: WasmMetaAddressMetadata) -> Self {
        Self {
            description: m.description,
            avatar: m.avatar,
            created_at: m.created_at,
        }
    }
}

fn meta_to_wasm(meta: &MetaAddress) -> WasmMetaAddress {
    WasmMetaAddress {
        version: meta.version,
        spending_pk: meta.spending_pk.as_bytes().to_vec(),
        viewing_pk: meta.viewing_pk.as_bytes().to_vec(),
        metadata: meta.metadata.clone().map(WasmMetaAddressMetadata::from),
        bytes: meta.to_bytes(),
    }
}

/// Construct a [`MetaAddress`] from two ML-KEM-768 public keys and an
/// optional metadata JSON object.
///
/// `metadata_json` accepts either a JSON-encoded
/// `{ description?, avatar?, created_at? }` payload or `None`.
///
/// # Errors
///
/// - [`WasmError::InvalidKeySize`] if either key is not 1184 bytes.
/// - [`WasmError::InvalidMetaAddress`] if the resulting meta-address fails
///   validation (e.g. an all-zero key was supplied).
/// - [`WasmError::InvalidMetadataJson`] if `metadata_json` is malformed.
#[wasm_bindgen(js_name = metaAddressFromPublicKeys)]
pub fn meta_address_from_public_keys(
    spending_pk: &[u8],
    viewing_pk: &[u8],
    metadata_json: Option<String>,
) -> Result<JsValue, WasmError> {
    if spending_pk.len() != KYBER_PUBLIC_KEY_SIZE {
        return Err(WasmError::InvalidKeySize {
            expected: KYBER_PUBLIC_KEY_SIZE,
            actual: spending_pk.len(),
            field: "spending_pk",
        });
    }
    if viewing_pk.len() != KYBER_PUBLIC_KEY_SIZE {
        return Err(WasmError::InvalidKeySize {
            expected: KYBER_PUBLIC_KEY_SIZE,
            actual: viewing_pk.len(),
            field: "viewing_pk",
        });
    }

    let spending = KyberPublicKey::from_bytes(spending_pk).map_err(WasmError::from)?;
    let viewing = KyberPublicKey::from_bytes(viewing_pk).map_err(WasmError::from)?;

    let meta = if let Some(raw) = metadata_json {
        let metadata: MetaAddressMetadata = serde_json::from_str(&raw)
            .map_err(|e| WasmError::InvalidMetadataJson(e.to_string()))?;
        MetaAddress::with_metadata(spending, viewing, metadata)
    } else {
        MetaAddress::new(spending, viewing)
    };

    meta.validate().map_err(WasmError::from)?;

    debug_assert_eq!(meta.to_bytes().len(), META_ADDRESS_SERIALIZED_SIZE);

    serde_wasm_bindgen::to_value(&meta_to_wasm(&meta))
        .map_err(|e| WasmError::Internal(format!("serde failure: {e}")))
}

/// Parse a 2369-byte serialised meta-address back into the JS shape.
///
/// # Errors
///
/// - [`WasmError::InvalidMetaAddress`] if the payload is the wrong size,
///   contains an all-zero key, or otherwise fails validation.
#[wasm_bindgen(js_name = parseMetaAddress)]
pub fn parse_meta_address(bytes: &[u8]) -> Result<JsValue, WasmError> {
    if bytes.len() != META_ADDRESS_SERIALIZED_SIZE {
        return Err(WasmError::InvalidMetaAddress(format!(
            "expected {META_ADDRESS_SERIALIZED_SIZE} bytes, got {}",
            bytes.len()
        )));
    }
    let meta = MetaAddress::from_bytes(bytes).map_err(WasmError::from)?;
    serde_wasm_bindgen::to_value(&meta_to_wasm(&meta))
        .map_err(|e| WasmError::Internal(format!("serde failure: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(byte: u8) -> Vec<u8> {
        vec![byte; KYBER_PUBLIC_KEY_SIZE]
    }

    #[test]
    fn meta_to_wasm_size_matches_constant() {
        let meta = MetaAddress::new(
            KyberPublicKey::from_bytes(&pk(0xAA)).unwrap(),
            KyberPublicKey::from_bytes(&pk(0xBB)).unwrap(),
        );
        let wasm = meta_to_wasm(&meta);
        assert_eq!(wasm.bytes.len(), META_ADDRESS_SERIALIZED_SIZE);
        assert_eq!(wasm.bytes.len(), 2369);
    }

    #[test]
    fn round_trip_via_to_bytes() {
        let meta = MetaAddress::new(
            KyberPublicKey::from_bytes(&pk(0x12)).unwrap(),
            KyberPublicKey::from_bytes(&pk(0x34)).unwrap(),
        );
        let bytes = meta.to_bytes();
        let parsed = MetaAddress::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.spending_pk, meta.spending_pk);
        assert_eq!(parsed.viewing_pk, meta.viewing_pk);
        assert_eq!(parsed.version, meta.version);
    }

    #[test]
    fn rejects_zero_spending_pk() {
        let meta = MetaAddress::new(
            KyberPublicKey::default(),
            KyberPublicKey::from_bytes(&pk(0xBB)).unwrap(),
        );
        assert!(meta.validate().is_err());
    }
}
