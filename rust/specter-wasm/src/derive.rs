//! Stealth address derivation bindings.
//!
//! All three functions here are deterministic: `(spending_pk, shared_secret)`
//! always produces the same stealth Ethereum and Sui addresses, and the
//! receiver-side `derive_stealth_keys` adds a 32-byte secp256k1 private key
//! that, when imported into a wallet, controls funds sent to those
//! addresses.
//!
//! The upstream implementation uses domain-separated SHAKE256 + a
//! retry-until-valid loop on the secp256k1 scalar; both are constant in
//! expected work and infallible for non-pathological inputs.

use serde::{Deserialize, Serialize};
use specter_core::constants::{
    ETH_ADDRESS_SIZE, KYBER_PUBLIC_KEY_SIZE, KYBER_SHARED_SECRET_SIZE, SUI_ADDRESS_SIZE,
};
use specter_crypto::derive::{
    derive_stealth_address, derive_stealth_keys, derive_stealth_sui_address,
};
use wasm_bindgen::prelude::*;

use crate::error::WasmError;

/// Output of `derive_stealth_keys`: everything the recipient needs to spend.
#[derive(Serialize, Deserialize)]
pub struct WasmStealthKeys {
    /// 20-byte Ethereum address (no `0x` prefix).
    pub eth_address: Vec<u8>,
    /// 32-byte Sui address (no `0x` prefix).
    pub sui_address: Vec<u8>,
    /// 65-byte uncompressed secp256k1 public key (`0x04 || X || Y`).
    pub public_key: Vec<u8>,
    /// 32-byte secp256k1 private key. The TS wrapper marks this
    /// non-enumerable.
    pub eth_private_key: Vec<u8>,
}

fn validate_inputs(spending_pk: &[u8], shared_secret: &[u8]) -> Result<(), WasmError> {
    if spending_pk.len() != KYBER_PUBLIC_KEY_SIZE {
        return Err(WasmError::InvalidKeySize {
            expected: KYBER_PUBLIC_KEY_SIZE,
            actual: spending_pk.len(),
            field: "spending_pk",
        });
    }
    if shared_secret.len() != KYBER_SHARED_SECRET_SIZE {
        return Err(WasmError::InvalidSharedSecretSize {
            expected: KYBER_SHARED_SECRET_SIZE,
            actual: shared_secret.len(),
        });
    }
    Ok(())
}

/// Derive only the stealth Ethereum address.
///
/// # Errors
///
/// See [`validate_inputs`] for size errors;
/// [`WasmError::StealthDerivationFailed`] for any underlying failure.
#[wasm_bindgen(js_name = deriveStealthAddress)]
pub fn derive_stealth_address_js(
    spending_pk: &[u8],
    shared_secret: &[u8],
) -> Result<Vec<u8>, WasmError> {
    validate_inputs(spending_pk, shared_secret)?;
    let address = derive_stealth_address(spending_pk, shared_secret).map_err(WasmError::from)?;
    let bytes = address.as_bytes().to_vec();
    debug_assert_eq!(bytes.len(), ETH_ADDRESS_SIZE);
    Ok(bytes)
}

/// Derive only the stealth Sui address.
///
/// # Errors
///
/// See [`validate_inputs`] for size errors;
/// [`WasmError::StealthDerivationFailed`] for any underlying failure.
#[wasm_bindgen(js_name = deriveStealthSuiAddress)]
pub fn derive_stealth_sui_address_js(
    spending_pk: &[u8],
    shared_secret: &[u8],
) -> Result<Vec<u8>, WasmError> {
    validate_inputs(spending_pk, shared_secret)?;
    let address =
        derive_stealth_sui_address(spending_pk, shared_secret).map_err(WasmError::from)?;
    let bytes = address.as_bytes().to_vec();
    debug_assert_eq!(bytes.len(), SUI_ADDRESS_SIZE);
    Ok(bytes)
}

/// Derive the stealth Ethereum + Sui addresses **and** the spendable
/// secp256k1 private key.
///
/// The returned `eth_private_key` is the same scalar that derives both
/// addresses; importing it into `MetaMask` / `viem` signs valid Ethereum
/// transactions for `eth_address`, and signing under Sui's secp256k1 scheme
/// produces transactions for `sui_address`.
///
/// # Errors
///
/// See [`validate_inputs`] for size errors;
/// [`WasmError::StealthDerivationFailed`] for any underlying failure.
#[wasm_bindgen(js_name = deriveStealthKeys)]
pub fn derive_stealth_keys_js(
    spending_pk: &[u8],
    shared_secret: &[u8],
) -> Result<JsValue, WasmError> {
    validate_inputs(spending_pk, shared_secret)?;
    // The upstream API takes `_spending_sk` as a parameter for backwards
    // compatibility but the secp256k1 derivation does not use it. We pass
    // an empty slice rather than expose a dead parameter on the JS side.
    let keys = derive_stealth_keys(spending_pk, &[], shared_secret).map_err(WasmError::from)?;

    let result = WasmStealthKeys {
        eth_address: keys.address.as_bytes().to_vec(),
        sui_address: keys.sui_address.as_bytes().to_vec(),
        public_key: keys.public_key,
        eth_private_key: keys.private_key.to_eth_private_key().to_vec(),
    };
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| WasmError::Internal(format!("serde failure: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use specter_crypto::derive::derive_eth_address_from_seed;

    fn fake_pk() -> Vec<u8> {
        vec![0x42u8; KYBER_PUBLIC_KEY_SIZE]
    }

    fn fake_secret() -> [u8; 32] {
        [0xAB; 32]
    }

    #[test]
    fn deterministic_eth_address() {
        let pk = fake_pk();
        let ss = fake_secret();
        let a = derive_stealth_address_js(&pk, &ss).unwrap();
        let b = derive_stealth_address_js(&pk, &ss).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_short_pk() {
        let bad = vec![0u8; 100];
        let ss = fake_secret();
        let err = derive_stealth_address_js(&bad, &ss).unwrap_err();
        assert_eq!(err.code(), "INVALID_KEY_SIZE");
    }

    #[test]
    fn rejects_short_shared_secret() {
        let pk = fake_pk();
        let bad = vec![0u8; 16];
        let err = derive_stealth_address_js(&pk, &bad).unwrap_err();
        assert_eq!(err.code(), "INVALID_SHARED_SECRET_SIZE");
    }

    #[test]
    fn private_key_derives_back_to_eth_address() {
        // Mirrors the upstream `test_derive_stealth_keys` invariant: the
        // returned eth_private_key, when re-derived into an Eth address,
        // matches the eth_address field. This is the wallet-import contract.
        let pk = fake_pk();
        let ss = fake_secret();
        let keys = derive_stealth_keys(&pk, &[], &ss).unwrap();
        let eth_sk: [u8; 32] = keys.private_key.to_eth_private_key();
        let rederived = derive_eth_address_from_seed(&eth_sk).unwrap();
        assert_eq!(keys.address.as_bytes(), rederived.as_bytes());
    }
}
