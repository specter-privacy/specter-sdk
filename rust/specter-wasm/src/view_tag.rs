//! View-tag bindings.
//!
//! The view tag is a 1-byte filter recipients use to skip ~99.6% of
//! announcements without doing a full ML-KEM decapsulation. See
//! `vendor/specter-crypto/src/view_tag.rs` for the spec.

use specter_core::constants::KYBER_SHARED_SECRET_SIZE;
use specter_crypto::compute_view_tag;
use specter_crypto::view_tag::verify_view_tag as upstream_verify_view_tag;
use wasm_bindgen::prelude::*;

use crate::error::WasmError;

/// Compute the 1-byte view tag for a 32-byte shared secret.
///
/// # Errors
///
/// Returns [`WasmError::InvalidSharedSecretSize`] if `shared_secret` is not
/// exactly 32 bytes.
#[wasm_bindgen(js_name = computeViewTag)]
pub fn compute_view_tag_js(shared_secret: &[u8]) -> Result<u8, WasmError> {
    if shared_secret.len() != KYBER_SHARED_SECRET_SIZE {
        return Err(WasmError::InvalidSharedSecretSize {
            expected: KYBER_SHARED_SECRET_SIZE,
            actual: shared_secret.len(),
        });
    }
    Ok(compute_view_tag(shared_secret))
}

/// Verify, in constant time, that an expected view tag matches the one
/// derived from `shared_secret`.
///
/// # Errors
///
/// Returns [`WasmError::InvalidSharedSecretSize`] if `shared_secret` is not
/// exactly 32 bytes.
#[wasm_bindgen(js_name = verifyViewTag)]
pub fn verify_view_tag_js(shared_secret: &[u8], expected_tag: u8) -> Result<bool, WasmError> {
    if shared_secret.len() != KYBER_SHARED_SECRET_SIZE {
        return Err(WasmError::InvalidSharedSecretSize {
            expected: KYBER_SHARED_SECRET_SIZE,
            actual: shared_secret.len(),
        });
    }
    Ok(upstream_verify_view_tag(shared_secret, expected_tag))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_tag_deterministic() {
        let secret = [42u8; 32];
        let a = compute_view_tag_js(&secret).unwrap();
        let b = compute_view_tag_js(&secret).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn view_tag_size_is_validated() {
        let bad = vec![0u8; 16];
        let err = compute_view_tag_js(&bad).unwrap_err();
        assert_eq!(err.code(), "INVALID_SHARED_SECRET_SIZE");
    }

    #[test]
    fn verify_returns_true_for_matching_tag() {
        let secret = [7u8; 32];
        let tag = compute_view_tag_js(&secret).unwrap();
        assert!(verify_view_tag_js(&secret, tag).unwrap());
    }

    #[test]
    fn verify_returns_false_for_mismatch() {
        let secret = [7u8; 32];
        let tag = compute_view_tag_js(&secret).unwrap();
        assert!(!verify_view_tag_js(&secret, tag.wrapping_add(1)).unwrap());
    }
}
