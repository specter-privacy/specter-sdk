//! Browser-side integration tests for the WASM bridge.
//!
//! Run with `wasm-pack test rust/specter-wasm --headless --chrome --firefox`.
//! The same tests can run in Node via `--node` if browser browsers are
//! unavailable, but CI uses both Chrome and Firefox so we exercise the
//! browser RNG and `crypto.getRandomValues` path explicitly.

#![cfg(target_arch = "wasm32")]

use serde::Deserialize;
use specter_core::constants::{
    KYBER_CIPHERTEXT_SIZE, KYBER_PUBLIC_KEY_SIZE, KYBER_SECRET_KEY_SIZE, KYBER_SHARED_SECRET_SIZE,
    META_ADDRESS_SERIALIZED_SIZE,
};
use specter_wasm::derive::{
    derive_stealth_address_js, derive_stealth_keys_js, derive_stealth_sui_address_js,
};
use specter_wasm::error::WasmError;
use specter_wasm::kem::{decapsulate_js, encapsulate_js};
use specter_wasm::keys::{generate_keys, generate_specter_keys};
use specter_wasm::meta_address::{meta_address_from_public_keys, parse_meta_address};
use specter_wasm::view_tag::{compute_view_tag_js, verify_view_tag_js};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

// The test suite uses no DOM / window APIs, so it runs fine under both
// `wasm-pack test --node` and `wasm-pack test --headless --chrome|--firefox`.
// CI exercises the browser flavours; local dev usually uses --node.

#[derive(Deserialize)]
struct WireKeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

#[derive(Deserialize)]
struct WireSpecter {
    spending: WireKeyPair,
    viewing: WireKeyPair,
}

#[derive(Deserialize)]
struct WireEncap {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

#[derive(Deserialize)]
struct WireDecap {
    shared_secret: Vec<u8>,
}

#[derive(Deserialize)]
struct WireMeta {
    version: u8,
    spending_pk: Vec<u8>,
    viewing_pk: Vec<u8>,
    bytes: Vec<u8>,
}

#[derive(Deserialize)]
struct WireStealthKeys {
    eth_address: Vec<u8>,
    sui_address: Vec<u8>,
    public_key: Vec<u8>,
    eth_private_key: Vec<u8>,
}

fn from_value<T: for<'de> Deserialize<'de>>(v: JsValue) -> T {
    serde_wasm_bindgen::from_value(v).expect("deserialise from JsValue")
}

/// Convert a `WasmError` through the JsValue conversion the JS API uses,
/// then read out the stable `code` string.
fn err_code(err: WasmError) -> String {
    #[derive(Deserialize)]
    struct Wire {
        code: String,
    }
    let value: JsValue = err.into();
    from_value::<Wire>(value).code
}

#[wasm_bindgen_test]
fn keygen_returns_correct_sizes() {
    let value = generate_keys().expect("generate_keys");
    let kp: WireKeyPair = from_value(value);
    assert_eq!(kp.public_key.len(), KYBER_PUBLIC_KEY_SIZE);
    assert_eq!(kp.secret_key.len(), KYBER_SECRET_KEY_SIZE);
}

#[wasm_bindgen_test]
fn keygen_is_random_across_calls() {
    let a: WireKeyPair = from_value(generate_keys().unwrap());
    let b: WireKeyPair = from_value(generate_keys().unwrap());
    assert_ne!(a.public_key, b.public_key, "public keys must differ");
    assert_ne!(a.secret_key, b.secret_key, "secret keys must differ");
}

#[wasm_bindgen_test]
fn specter_keys_returns_two_independent_keypairs() {
    let bundle: WireSpecter = from_value(generate_specter_keys().unwrap());
    assert_eq!(bundle.spending.public_key.len(), KYBER_PUBLIC_KEY_SIZE);
    assert_eq!(bundle.spending.secret_key.len(), KYBER_SECRET_KEY_SIZE);
    assert_eq!(bundle.viewing.public_key.len(), KYBER_PUBLIC_KEY_SIZE);
    assert_eq!(bundle.viewing.secret_key.len(), KYBER_SECRET_KEY_SIZE);
    assert_ne!(bundle.spending.public_key, bundle.viewing.public_key);
}

#[wasm_bindgen_test]
fn encapsulate_decapsulate_round_trips_in_browser() {
    let kp: WireKeyPair = from_value(generate_keys().unwrap());

    let encap: WireEncap = from_value(encapsulate_js(&kp.public_key).unwrap());
    assert_eq!(encap.ciphertext.len(), KYBER_CIPHERTEXT_SIZE);
    assert_eq!(encap.shared_secret.len(), KYBER_SHARED_SECRET_SIZE);

    let decap: WireDecap = from_value(decapsulate_js(&encap.ciphertext, &kp.secret_key).unwrap());
    assert_eq!(decap.shared_secret, encap.shared_secret);
}

#[wasm_bindgen_test]
fn encapsulate_rejects_wrong_pk_size() {
    let bad = vec![0u8; 100];
    let err = encapsulate_js(&bad).unwrap_err();
    assert_eq!(err_code(err), "INVALID_KEY_SIZE");
}

#[wasm_bindgen_test]
fn decapsulate_rejects_wrong_ct_size() {
    let kp: WireKeyPair = from_value(generate_keys().unwrap());
    let bad_ct = vec![0u8; 100];
    let err = decapsulate_js(&bad_ct, &kp.secret_key).unwrap_err();
    assert_eq!(err_code(err), "INVALID_CIPHERTEXT_SIZE");
}

#[wasm_bindgen_test]
fn view_tag_is_deterministic_in_browser() {
    let kp: WireKeyPair = from_value(generate_keys().unwrap());
    let encap: WireEncap = from_value(encapsulate_js(&kp.public_key).unwrap());
    let tag_a = compute_view_tag_js(&encap.shared_secret).unwrap();
    let tag_b = compute_view_tag_js(&encap.shared_secret).unwrap();
    assert_eq!(tag_a, tag_b);
    assert!(verify_view_tag_js(&encap.shared_secret, tag_a).unwrap());
}

#[wasm_bindgen_test]
fn view_tag_rejects_short_secret() {
    let bad = vec![0u8; 10];
    let err = compute_view_tag_js(&bad).unwrap_err();
    assert_eq!(err_code(err), "INVALID_SHARED_SECRET_SIZE");
}

#[wasm_bindgen_test]
fn meta_address_round_trips_in_browser() {
    let bundle: WireSpecter = from_value(generate_specter_keys().unwrap());
    let built: WireMeta = from_value(
        meta_address_from_public_keys(
            &bundle.spending.public_key,
            &bundle.viewing.public_key,
            None,
        )
        .unwrap(),
    );

    assert_eq!(built.version, 1);
    assert_eq!(built.bytes.len(), META_ADDRESS_SERIALIZED_SIZE);
    assert_eq!(built.spending_pk, bundle.spending.public_key);
    assert_eq!(built.viewing_pk, bundle.viewing.public_key);

    let reparsed: WireMeta = from_value(parse_meta_address(&built.bytes).unwrap());
    assert_eq!(reparsed.spending_pk, built.spending_pk);
    assert_eq!(reparsed.viewing_pk, built.viewing_pk);
    assert_eq!(reparsed.version, built.version);
}

#[wasm_bindgen_test]
fn meta_address_with_metadata_json() {
    let bundle: WireSpecter = from_value(generate_specter_keys().unwrap());
    let metadata = r#"{"description":"alice","avatar":"ipfs://Qm","created_at":1700000000}"#;
    let built: WireMeta = from_value(
        meta_address_from_public_keys(
            &bundle.spending.public_key,
            &bundle.viewing.public_key,
            Some(metadata.to_string()),
        )
        .unwrap(),
    );
    assert_eq!(built.version, 1);
}

#[wasm_bindgen_test]
fn meta_address_rejects_invalid_metadata_json() {
    let bundle: WireSpecter = from_value(generate_specter_keys().unwrap());
    let err = meta_address_from_public_keys(
        &bundle.spending.public_key,
        &bundle.viewing.public_key,
        Some("not json".to_string()),
    )
    .unwrap_err();
    assert_eq!(err_code(err), "INVALID_METADATA_JSON");
}

#[wasm_bindgen_test]
fn parse_meta_address_rejects_bad_size() {
    let err = parse_meta_address(&[0u8; 32]).unwrap_err();
    assert_eq!(err_code(err), "INVALID_META_ADDRESS");
}

#[wasm_bindgen_test]
fn full_payment_flow_in_browser() {
    // End-to-end: generate keys, build meta-address, sender encaps + derives
    // stealth address, recipient scans matching view-tag and re-derives the
    // stealth keys. The recipient's eth_private_key must produce the same
    // eth_address as the sender's derivation.
    let bundle: WireSpecter = from_value(generate_specter_keys().unwrap());

    // Sender.
    let encap: WireEncap = from_value(encapsulate_js(&bundle.viewing.public_key).unwrap());
    let sender_view_tag = compute_view_tag_js(&encap.shared_secret).unwrap();
    let sender_eth_addr =
        derive_stealth_address_js(&bundle.spending.public_key, &encap.shared_secret).unwrap();
    let sender_sui_addr =
        derive_stealth_sui_address_js(&bundle.spending.public_key, &encap.shared_secret).unwrap();

    // Recipient.
    let decap: WireDecap =
        from_value(decapsulate_js(&encap.ciphertext, &bundle.viewing.secret_key).unwrap());
    assert_eq!(decap.shared_secret, encap.shared_secret);

    let receiver_view_tag = compute_view_tag_js(&decap.shared_secret).unwrap();
    assert_eq!(sender_view_tag, receiver_view_tag);

    let stealth: WireStealthKeys = from_value(
        derive_stealth_keys_js(&bundle.spending.public_key, &decap.shared_secret).unwrap(),
    );
    assert_eq!(stealth.eth_address, sender_eth_addr);
    assert_eq!(stealth.sui_address, sender_sui_addr);
    assert_eq!(stealth.eth_address.len(), 20);
    assert_eq!(stealth.sui_address.len(), 32);
    assert_eq!(stealth.public_key.len(), 65);
    assert_eq!(stealth.eth_private_key.len(), 32);
}

#[wasm_bindgen_test]
fn wrong_secret_key_decap_does_not_match_view_tag() {
    // FIPS 203 implicit auth: decap with wrong SK gives a pseudo-random
    // shared secret. The resulting view-tag should (with overwhelming
    // probability) differ from the sender's. We don't make this strict
    // because there's a 1/256 chance of accidental match per protocol.
    let alice: WireSpecter = from_value(generate_specter_keys().unwrap());
    let bob: WireSpecter = from_value(generate_specter_keys().unwrap());

    let encap_to_alice: WireEncap = from_value(encapsulate_js(&alice.viewing.public_key).unwrap());
    let alice_tag = compute_view_tag_js(&encap_to_alice.shared_secret).unwrap();

    let bob_decap: WireDecap =
        from_value(decapsulate_js(&encap_to_alice.ciphertext, &bob.viewing.secret_key).unwrap());
    let bob_tag = compute_view_tag_js(&bob_decap.shared_secret).unwrap();

    // We can only assert the *secrets* differ deterministically; the tags
    // themselves collide 1-in-256 of the time.
    assert_ne!(encap_to_alice.shared_secret, bob_decap.shared_secret);
    let _ = (alice_tag, bob_tag);
}
