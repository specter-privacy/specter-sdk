//! Re-export protocol constants under stable JS-accessible names.
//!
//! Keeping these wired through `wasm_bindgen` (rather than just literals on
//! the TS side) lets contract tests assert that the WASM bridge sees the
//! same numbers the upstream Rust crates do. If someone bumps `KYBER_*` in
//! `vendor/specter-core/src/constants.rs` without also bumping the TS layer,
//! the contract test fails.

use specter_core::constants as upstream;
use wasm_bindgen::prelude::*;

/// Returns the ML-KEM-768 public key size in bytes (1184).
#[wasm_bindgen(js_name = kyberPublicKeySize)]
#[must_use]
pub fn kyber_public_key_size() -> usize {
    upstream::KYBER_PUBLIC_KEY_SIZE
}

/// Returns the ML-KEM-768 secret key size in bytes (2400).
#[wasm_bindgen(js_name = kyberSecretKeySize)]
#[must_use]
pub fn kyber_secret_key_size() -> usize {
    upstream::KYBER_SECRET_KEY_SIZE
}

/// Returns the ML-KEM-768 ciphertext size in bytes (1088).
#[wasm_bindgen(js_name = kyberCiphertextSize)]
#[must_use]
pub fn kyber_ciphertext_size() -> usize {
    upstream::KYBER_CIPHERTEXT_SIZE
}

/// Returns the shared-secret size in bytes (32).
#[wasm_bindgen(js_name = kyberSharedSecretSize)]
#[must_use]
pub fn kyber_shared_secret_size() -> usize {
    upstream::KYBER_SHARED_SECRET_SIZE
}

/// Returns the view-tag size in bytes (1).
#[wasm_bindgen(js_name = viewTagSize)]
#[must_use]
pub fn view_tag_size() -> usize {
    upstream::VIEW_TAG_SIZE
}

/// Returns the Ethereum address size in bytes (20).
#[wasm_bindgen(js_name = ethAddressSize)]
#[must_use]
pub fn eth_address_size() -> usize {
    upstream::ETH_ADDRESS_SIZE
}

/// Returns the Sui address size in bytes (32).
#[wasm_bindgen(js_name = suiAddressSize)]
#[must_use]
pub fn sui_address_size() -> usize {
    upstream::SUI_ADDRESS_SIZE
}

/// Returns the meta-address serialised payload size in bytes (2369).
#[wasm_bindgen(js_name = metaAddressSize)]
#[must_use]
pub fn meta_address_size() -> usize {
    upstream::META_ADDRESS_SERIALIZED_SIZE
}

/// Returns the SPECTER protocol version (1).
#[wasm_bindgen(js_name = protocolVersion)]
#[must_use]
pub fn protocol_version() -> u8 {
    upstream::PROTOCOL_VERSION
}
