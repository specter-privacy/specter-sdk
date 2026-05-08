//! Key-pair generation bindings.
//!
//! `generate_keys` returns a single ML-KEM-768 keypair; `generate_specter_keys`
//! returns the (spending, viewing) pair the protocol uses to construct a
//! meta-address. Both call into the upstream `specter_crypto::generate_keypair`
//! which uses `rand::thread_rng()` — in WASM that resolves to the browser /
//! Node `crypto.getRandomValues` via `getrandom` with the `js` feature.

use serde::{Deserialize, Serialize};
use specter_crypto::generate_keypair;
use wasm_bindgen::prelude::*;

use crate::error::WasmError;

/// JS-shaped keypair. Both fields are owned `Vec<u8>` so they cross the
/// FFI boundary as `Uint8Array` and are marked non-enumerable in the TS
/// wrapper.
#[derive(Serialize, Deserialize)]
pub struct WasmKyberKeyPair {
    /// ML-KEM-768 public key (1184 bytes).
    pub public_key: Vec<u8>,
    /// ML-KEM-768 secret key (2400 bytes).
    pub secret_key: Vec<u8>,
}

/// JS-shaped pair of keypairs covering the SPECTER protocol's spending and
/// viewing roles. Returned by `generate_specter_keys`.
#[derive(Serialize, Deserialize)]
pub struct WasmSpecterKeys {
    /// Spending keypair (used to derive stealth private keys).
    pub spending: WasmKyberKeyPair,
    /// Viewing keypair (used to scan announcements).
    pub viewing: WasmKyberKeyPair,
}

fn keypair_to_wasm(kp: &specter_core::types::KeyPair) -> WasmKyberKeyPair {
    WasmKyberKeyPair {
        public_key: kp.public.as_bytes().to_vec(),
        secret_key: kp.secret.as_bytes().to_vec(),
    }
}

/// Generate a single ML-KEM-768 keypair.
///
/// # Errors
///
/// Currently infallible. The function returns a `Result` so the JS surface
/// stays uniform across functions and so future panics from upstream get
/// translated into a typed error rather than crashing the runtime.
#[wasm_bindgen(js_name = generateKeys)]
pub fn generate_keys() -> Result<JsValue, WasmError> {
    let kp = generate_keypair();
    let wasm = keypair_to_wasm(&kp);
    serde_wasm_bindgen::to_value(&wasm)
        .map_err(|e| WasmError::Internal(format!("serde failure: {e}")))
}

/// Generate a complete SPECTER key set: a spending keypair and an independent
/// viewing keypair.
///
/// # Errors
///
/// Same as [`generate_keys`].
#[wasm_bindgen(js_name = generateSpecterKeys)]
pub fn generate_specter_keys() -> Result<JsValue, WasmError> {
    let spending_kp = generate_keypair();
    let viewing_kp = generate_keypair();
    let bundle = WasmSpecterKeys {
        spending: keypair_to_wasm(&spending_kp),
        viewing: keypair_to_wasm(&viewing_kp),
    };
    serde_wasm_bindgen::to_value(&bundle)
        .map_err(|e| WasmError::Internal(format!("serde failure: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use specter_core::constants::{KYBER_PUBLIC_KEY_SIZE, KYBER_SECRET_KEY_SIZE};

    #[test]
    fn keypair_to_wasm_preserves_lengths() {
        let kp = generate_keypair();
        let wasm = keypair_to_wasm(&kp);
        assert_eq!(wasm.public_key.len(), KYBER_PUBLIC_KEY_SIZE);
        assert_eq!(wasm.secret_key.len(), KYBER_SECRET_KEY_SIZE);
    }

    #[test]
    fn two_calls_produce_distinct_keypairs() {
        let a_kp = generate_keypair();
        let b_kp = generate_keypair();
        let a = keypair_to_wasm(&a_kp);
        let b = keypair_to_wasm(&b_kp);
        assert_ne!(a.public_key, b.public_key);
        assert_ne!(a.secret_key, b.secret_key);
    }
}
