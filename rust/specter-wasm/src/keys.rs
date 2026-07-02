//! Key-pair generation bindings.
//!
//! A SPECTER recipient identity is a *hybrid* pair:
//!
//!   - **spending** — a secp256k1 keypair `(b, B)`. It controls funds on
//!     Ethereum/Sui and is the base point for the stealth tweak
//!     (`derive.rs`). Ethereum/Sui verify secp256k1 signatures, so the spend
//!     key must live on that curve for a wallet to be able to spend.
//!   - **viewing** — an ML-KEM-768 keypair. It provides *post-quantum*
//!     scanning privacy: senders encapsulate to the viewing public key and
//!     recipients decapsulate to detect payments without ever touching the
//!     spending secret.
//!
//! `generate_keys` still returns a single ML-KEM-768 keypair (used for the
//! viewing role or standalone KEM). `generate_spend_key` returns a secp256k1
//! spending keypair. `generate_specter_keys` bundles both roles.

use serde::{Deserialize, Serialize};
use specter_crypto::generate_keypair;
use wasm_bindgen::prelude::*;

use crate::derive::generate_spend_keypair;
use crate::error::WasmError;

/// JS-shaped ML-KEM-768 keypair (viewing role). Both fields cross the FFI
/// boundary as `Uint8Array`; the TS wrapper marks `secret_key` non-enumerable.
#[derive(Serialize, Deserialize)]
pub struct WasmKyberKeyPair {
    /// ML-KEM-768 public key (1184 bytes).
    pub public_key: Vec<u8>,
    /// ML-KEM-768 secret key (2400 bytes).
    pub secret_key: Vec<u8>,
}

/// JS-shaped secp256k1 spending keypair.
#[derive(Serialize, Deserialize)]
pub struct WasmSpendKeyPair {
    /// Compressed secp256k1 public key (33 bytes).
    pub public_key: Vec<u8>,
    /// secp256k1 secret key (32 bytes). Marked non-enumerable in TS.
    pub secret_key: Vec<u8>,
}

/// JS-shaped hybrid recipient identity: secp256k1 spending + ML-KEM viewing.
#[derive(Serialize, Deserialize)]
pub struct WasmSpecterKeys {
    /// secp256k1 spending keypair (controls funds; stealth tweak base point).
    pub spending: WasmSpendKeyPair,
    /// ML-KEM-768 viewing keypair (post-quantum scanning).
    pub viewing: WasmKyberKeyPair,
}

fn keypair_to_wasm(kp: &specter_core::types::KeyPair) -> WasmKyberKeyPair {
    WasmKyberKeyPair {
        public_key: kp.public.as_bytes().to_vec(),
        secret_key: kp.secret.as_bytes().to_vec(),
    }
}

fn spend_keypair_wasm() -> WasmSpendKeyPair {
    let (sk, pk) = generate_spend_keypair();
    WasmSpendKeyPair {
        public_key: pk,
        secret_key: sk.to_vec(),
    }
}

/// Generate a single ML-KEM-768 keypair (viewing role / standalone KEM).
///
/// # Errors
///
/// Currently infallible; returns a `Result` so the JS surface stays uniform
/// and future upstream panics get translated into a typed error.
#[wasm_bindgen(js_name = generateKeys)]
pub fn generate_keys() -> Result<JsValue, WasmError> {
    let kp = generate_keypair();
    let wasm = keypair_to_wasm(&kp);
    serde_wasm_bindgen::to_value(&wasm)
        .map_err(|e| WasmError::Internal(format!("serde failure: {e}")))
}

/// Generate a single secp256k1 spending keypair.
///
/// # Errors
///
/// Same as [`generate_keys`].
#[wasm_bindgen(js_name = generateSpendKey)]
pub fn generate_spend_key() -> Result<JsValue, WasmError> {
    serde_wasm_bindgen::to_value(&spend_keypair_wasm())
        .map_err(|e| WasmError::Internal(format!("serde failure: {e}")))
}

/// Generate a complete SPECTER recipient identity: a secp256k1 spending
/// keypair and an independent ML-KEM-768 viewing keypair.
///
/// # Errors
///
/// Same as [`generate_keys`].
#[wasm_bindgen(js_name = generateSpecterKeys)]
pub fn generate_specter_keys() -> Result<JsValue, WasmError> {
    let viewing_kp = generate_keypair();
    let bundle = WasmSpecterKeys {
        spending: spend_keypair_wasm(),
        viewing: keypair_to_wasm(&viewing_kp),
    };
    serde_wasm_bindgen::to_value(&bundle)
        .map_err(|e| WasmError::Internal(format!("serde failure: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::{SPEND_PUBLIC_SIZE, SPEND_SECRET_SIZE};
    use specter_core::constants::{KYBER_PUBLIC_KEY_SIZE, KYBER_SECRET_KEY_SIZE};

    #[test]
    fn viewing_keypair_sizes() {
        let kp = generate_keypair();
        let wasm = keypair_to_wasm(&kp);
        assert_eq!(wasm.public_key.len(), KYBER_PUBLIC_KEY_SIZE);
        assert_eq!(wasm.secret_key.len(), KYBER_SECRET_KEY_SIZE);
    }

    #[test]
    fn spend_keypair_sizes() {
        let kp = spend_keypair_wasm();
        assert_eq!(kp.public_key.len(), SPEND_PUBLIC_SIZE);
        assert_eq!(kp.secret_key.len(), SPEND_SECRET_SIZE);
    }

    #[test]
    fn two_spend_keys_are_distinct() {
        let a = spend_keypair_wasm();
        let b = spend_keypair_wasm();
        assert_ne!(a.public_key, b.public_key);
        assert_ne!(a.secret_key, b.secret_key);
    }
}
