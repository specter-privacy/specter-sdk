//! ML-KEM-768 encapsulation and decapsulation bindings.

use serde::{Deserialize, Serialize};
use specter_core::constants::{
    KYBER_CIPHERTEXT_SIZE, KYBER_PUBLIC_KEY_SIZE, KYBER_SECRET_KEY_SIZE, KYBER_SHARED_SECRET_SIZE,
};
use specter_core::types::{KyberPublicKey, KyberSecretKey};
use specter_crypto::{decapsulate, encapsulate, KyberCiphertext};
use wasm_bindgen::prelude::*;

use crate::error::WasmError;

/// Output of `encapsulate`: ciphertext to publish + shared secret to use
/// locally for stealth-address derivation.
#[derive(Serialize, Deserialize)]
pub struct WasmEncapsulationResult {
    /// Ephemeral ML-KEM-768 ciphertext (1088 bytes).
    pub ciphertext: Vec<u8>,
    /// 32-byte shared secret. The TS wrapper marks this non-enumerable.
    pub shared_secret: Vec<u8>,
}

/// Output of `decapsulate`: the recovered shared secret.
#[derive(Serialize, Deserialize)]
pub struct WasmDecapsulationResult {
    /// 32-byte shared secret recovered from `ciphertext` by the holder of
    /// the corresponding secret key.
    pub shared_secret: Vec<u8>,
}

/// Encapsulate a fresh shared secret to a recipient's ML-KEM-768 public key.
///
/// # Errors
///
/// Returns [`WasmError::InvalidKeySize`] if `public_key` is not exactly
/// 1184 bytes; [`WasmError::EncapsulationFailed`] if the underlying KEM call
/// fails for any other reason (the upstream implementation is constant-time
/// and infallible for valid inputs, so this should not fire in practice).
#[wasm_bindgen(js_name = encapsulate)]
pub fn encapsulate_js(public_key: &[u8]) -> Result<JsValue, WasmError> {
    if public_key.len() != KYBER_PUBLIC_KEY_SIZE {
        return Err(WasmError::InvalidKeySize {
            expected: KYBER_PUBLIC_KEY_SIZE,
            actual: public_key.len(),
            field: "public_key",
        });
    }

    let pk = KyberPublicKey::from_bytes(public_key).map_err(WasmError::from)?;
    let (ciphertext, shared_secret) = encapsulate(&pk).map_err(WasmError::from)?;

    debug_assert_eq!(ciphertext.as_bytes().len(), KYBER_CIPHERTEXT_SIZE);
    debug_assert_eq!(shared_secret.len(), KYBER_SHARED_SECRET_SIZE);

    let result = WasmEncapsulationResult {
        ciphertext: ciphertext.into_bytes(),
        shared_secret: shared_secret.to_vec(),
    };
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| WasmError::Internal(format!("serde failure: {e}")))
}

/// Decapsulate a ciphertext to recover its shared secret.
///
/// # Errors
///
/// Returns [`WasmError::InvalidCiphertextSize`] if `ciphertext` is not
/// 1088 bytes; [`WasmError::InvalidKeySize`] if `secret_key` is not 2400
/// bytes; [`WasmError::DecapsulationFailed`] for any underlying ML-KEM error.
///
/// Note: the FIPS 203 KEM is *implicitly authenticated*. Decapsulating a
/// ciphertext that was not encapsulated under the matching public key
/// returns a deterministic but pseudo-random shared secret, **not** an error.
/// Callers must verify the resulting view-tag or stealth address before
/// trusting the secret.
#[wasm_bindgen(js_name = decapsulate)]
pub fn decapsulate_js(ciphertext: &[u8], secret_key: &[u8]) -> Result<JsValue, WasmError> {
    if ciphertext.len() != KYBER_CIPHERTEXT_SIZE {
        return Err(WasmError::InvalidCiphertextSize {
            expected: KYBER_CIPHERTEXT_SIZE,
            actual: ciphertext.len(),
        });
    }
    if secret_key.len() != KYBER_SECRET_KEY_SIZE {
        return Err(WasmError::InvalidKeySize {
            expected: KYBER_SECRET_KEY_SIZE,
            actual: secret_key.len(),
            field: "secret_key",
        });
    }

    let ct = KyberCiphertext::from_bytes(ciphertext).map_err(WasmError::from)?;
    let sk = KyberSecretKey::from_bytes(secret_key).map_err(WasmError::from)?;
    let shared_secret = decapsulate(&ct, &sk).map_err(WasmError::from)?;

    debug_assert_eq!(shared_secret.len(), KYBER_SHARED_SECRET_SIZE);

    let result = WasmDecapsulationResult {
        shared_secret: shared_secret.to_vec(),
    };
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| WasmError::Internal(format!("serde failure: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use specter_crypto::generate_keypair;

    #[test]
    fn round_trip_pure_rust() {
        let kp = generate_keypair();
        let pk_bytes = kp.public.as_bytes().to_vec();
        let sk_bytes = kp.secret.as_bytes().to_vec();

        // Drive the upstream layer directly because we cannot serialise to
        // JsValue outside of a WASM context.
        let pk = KyberPublicKey::from_bytes(&pk_bytes).unwrap();
        let (ct, ss_send) = encapsulate(&pk).unwrap();

        let sk = KyberSecretKey::from_bytes(&sk_bytes).unwrap();
        let ss_recv = decapsulate(&ct, &sk).unwrap();

        assert_eq!(ss_send, ss_recv);
    }

    #[test]
    fn invalid_pk_size_rejected() {
        // We assert via the upstream type to avoid touching JsValue in
        // host-side tests. The bridge function delegates to from_bytes, so
        // this is a valid contract test.
        let bad = vec![0u8; 100];
        assert!(KyberPublicKey::from_bytes(&bad).is_err());
    }
}
