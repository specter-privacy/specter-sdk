//! Stealth address derivation — secp256k1 additive-tweak scheme (ERC-5564).
//!
//! # Why this replaces the vendored hash-only derivation
//!
//! The upstream `specter_crypto::derive` computes the stealth secp256k1 key as
//! `SHAKE256(shared_secret || spending_pk)`. Both of those inputs are known to
//! the *sender* (the sender chooses `shared_secret` via ML-KEM encapsulation
//! and `spending_pk` is public), so the sender can reconstruct the recipient's
//! spending key and drain every payment it creates. A pure hash has no
//! trapdoor: you cannot let the sender derive the *address* without also
//! letting it derive the *private key*.
//!
//! The fix is the standard stealth-address construction. The recipient owns a
//! secp256k1 spending keypair `(b, B = b·G)`:
//!
//! ```text
//! t  = H(shared_secret)                      (tweak scalar, mod n)
//! P  = B + t·G          (sender: needs only the public B)
//! p  = b + t   (mod n)  (recipient: needs the secret b)
//! ```
//!
//! Because `P = p·G`, both parties derive the same stealth address, but only
//! the holder of `b` can compute the spend key `p`. The ML-KEM viewing keypair
//! is unchanged and still provides post-quantum *scanning* privacy; the
//! on-chain spend key is secp256k1 because that is what Ethereum/Sui verify.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{NonZeroScalar, ProjectivePoint, PublicKey, Scalar, SecretKey};
use serde::{Deserialize, Serialize};
use specter_core::constants::{ETH_ADDRESS_SIZE, KYBER_SHARED_SECRET_SIZE, SUI_ADDRESS_SIZE};
use specter_crypto::hash::{keccak256, shake256};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::error::WasmError;

/// Compressed secp256k1 spending public key size (`0x02|0x03 || X`).
pub const SPEND_PUBLIC_SIZE: usize = 33;
/// secp256k1 spending secret key size.
pub const SPEND_SECRET_SIZE: usize = 32;
/// Uncompressed stealth public key size (`0x04 || X || Y`).
pub const STEALTH_PUBLIC_SIZE: usize = 65;

/// Domain separator for the stealth tweak scalar. Distinct from every vendored
/// separator so the tweak can never collide with another protocol hash.
const DOMAIN_STEALTH_TWEAK: &[u8] = b"SPECTER_STEALTH_TWEAK_V2";
/// Sui signature-scheme flag for ECDSA secp256k1.
const SUI_SCHEME_SECP256K1: u8 = 0x01;

/// Sender-side output: the two stealth addresses plus the stealth public key.
/// No secret material — safe to compute from the recipient's *public* identity.
#[derive(Serialize, Deserialize)]
pub struct WasmStealthPublic {
    /// 20-byte Ethereum address (no `0x` prefix).
    pub eth_address: Vec<u8>,
    /// 32-byte Sui address (no `0x` prefix).
    pub sui_address: Vec<u8>,
    /// 65-byte uncompressed secp256k1 stealth public key.
    pub public_key: Vec<u8>,
}

/// Recipient-side output: everything in [`WasmStealthPublic`] plus the spendable
/// 32-byte secp256k1 private key. Requires the recipient's spending *secret*.
#[derive(Serialize, Deserialize)]
pub struct WasmStealthKeys {
    /// 20-byte Ethereum address (no `0x` prefix).
    pub eth_address: Vec<u8>,
    /// 32-byte Sui address (no `0x` prefix).
    pub sui_address: Vec<u8>,
    /// 65-byte uncompressed secp256k1 stealth public key.
    pub public_key: Vec<u8>,
    /// 32-byte secp256k1 private key. The TS wrapper marks this non-enumerable.
    pub eth_private_key: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure-Rust core (host-testable; no wasm_bindgen)
// ─────────────────────────────────────────────────────────────────────────────

/// Derive the tweak scalar `t = H(shared_secret) mod n`, rejecting the
/// (cryptographically impossible) zero result so `P` never collapses to `B`.
fn tweak_scalar(shared_secret: &[u8]) -> Scalar {
    // MUST match the backend `derive_stealth_tweak` byte-for-byte, or the
    // address this SDK derives will differ from the one the sender funded
    // (see specter-crypto::derive). Two things are load-bearing here and were
    // the cause of the "balance shows empty" bug in ≤ v1.0.1:
    //   1. the hash input is `shared_secret || counter` (counter starts at 0),
    //      NOT the bare shared_secret, and
    //   2. the scalar is produced by rejection sampling via
    //      `SecretKey::from_slice` (retry with counter+1 if the 32-byte
    //      candidate is ≥ n), NOT modular reduction.
    let mut counter: u8 = 0;
    loop {
        let mut input = Vec::with_capacity(shared_secret.len() + 1);
        input.extend_from_slice(shared_secret);
        input.push(counter);
        let candidate = shake256(DOMAIN_STEALTH_TWEAK, &input, 32);
        input.zeroize();
        if let Ok(sk) = SecretKey::from_slice(&candidate) {
            // from_slice guarantees a non-zero scalar in [1, n).
            return *sk.to_nonzero_scalar().as_ref();
        }
        counter = counter.wrapping_add(1);
    }
}

/// `(eth_address, sui_address, uncompressed_public_key)`.
type StealthAddresses = ([u8; ETH_ADDRESS_SIZE], [u8; SUI_ADDRESS_SIZE], Vec<u8>);

/// Compute the (eth, sui) addresses and uncompressed encoding of a stealth
/// public key. Mirrors the vendored address formats byte-for-byte so wallets
/// and the legacy Sui path agree.
fn addresses_from_public(point: &PublicKey) -> Result<StealthAddresses, WasmError> {
    let uncompressed = point.to_encoded_point(false);
    let uncompressed_bytes = uncompressed.as_bytes();
    // Ethereum: keccak256 over the 64-byte (X||Y) body, take the last 20 bytes.
    let hash = keccak256(&uncompressed_bytes[1..]);
    let mut eth = [0u8; ETH_ADDRESS_SIZE];
    eth.copy_from_slice(&hash[32 - ETH_ADDRESS_SIZE..]);

    // Sui: blake2b-256 over scheme_flag || compressed pubkey.
    let compressed = point.to_encoded_point(true);
    let mut hasher = Blake2bVar::new(SUI_ADDRESS_SIZE)
        .map_err(|_| WasmError::StealthDerivationFailed("blake2b init failed".into()))?;
    hasher.update(&[SUI_SCHEME_SECP256K1]);
    hasher.update(compressed.as_bytes());
    let mut sui = [0u8; SUI_ADDRESS_SIZE];
    hasher
        .finalize_variable(&mut sui)
        .map_err(|_| WasmError::StealthDerivationFailed("blake2b finalize failed".into()))?;

    Ok((eth, sui, uncompressed_bytes.to_vec()))
}

/// Generate a fresh secp256k1 spending keypair `(b, B)`.
///
/// Returns `(secret_key_bytes[32], compressed_public_key_bytes[33])`.
#[must_use]
pub fn generate_spend_keypair() -> ([u8; SPEND_SECRET_SIZE], Vec<u8>) {
    let secret = SecretKey::random(&mut rand::thread_rng());
    let public = secret.public_key();
    let mut sk = [0u8; SPEND_SECRET_SIZE];
    sk.copy_from_slice(&secret.to_bytes());
    let pk = public.to_encoded_point(true).as_bytes().to_vec();
    (sk, pk)
}

/// Sender / detection path: `P = B + t·G` from the recipient's public spend key.
///
/// # Errors
///
/// [`WasmError::StealthDerivationFailed`] if `spend_pub` is not a valid
/// secp256k1 point or the resulting stealth point is the identity.
pub fn stealth_public(spend_pub: &[u8], shared_secret: &[u8]) -> Result<PublicKey, WasmError> {
    let base = PublicKey::from_sec1_bytes(spend_pub)
        .map_err(|_| WasmError::StealthDerivationFailed("invalid spending public key".into()))?;
    let t = tweak_scalar(shared_secret);
    let point = ProjectivePoint::from(*base.as_affine()) + ProjectivePoint::GENERATOR * t;
    PublicKey::from_affine(point.to_affine())
        .map_err(|_| WasmError::StealthDerivationFailed("stealth point at infinity".into()))
}

/// Recipient path: `p = b + t (mod n)` from the recipient's secret spend key.
///
/// Returns `(stealth_secret_key, stealth_public_key)`.
///
/// # Errors
///
/// [`WasmError::StealthDerivationFailed`] if `spend_secret` is not a valid
/// scalar or the tweaked scalar `b + t` is zero.
pub fn stealth_secret(
    spend_secret: &[u8],
    shared_secret: &[u8],
) -> Result<(SecretKey, PublicKey), WasmError> {
    let base = SecretKey::from_slice(spend_secret)
        .map_err(|_| WasmError::StealthDerivationFailed("invalid spending secret key".into()))?;
    let t = tweak_scalar(shared_secret);
    let b_scalar: Scalar = *base.to_nonzero_scalar();
    let p_scalar = b_scalar + t;
    let nz = NonZeroScalar::new(p_scalar);
    if nz.is_none().into() {
        // b + t ≡ 0 (mod n): impossible for honest inputs; reject rather than
        // emit a zero key.
        return Err(WasmError::StealthDerivationFailed(
            "stealth scalar is zero".into(),
        ));
    }
    let stealth_sk = SecretKey::from(nz.unwrap());
    let stealth_pk = stealth_sk.public_key();
    Ok((stealth_sk, stealth_pk))
}

fn validate_shared_secret(shared_secret: &[u8]) -> Result<(), WasmError> {
    if shared_secret.len() != KYBER_SHARED_SECRET_SIZE {
        return Err(WasmError::InvalidSharedSecretSize {
            expected: KYBER_SHARED_SECRET_SIZE,
            actual: shared_secret.len(),
        });
    }
    Ok(())
}

fn validate_spend_pub(spend_pub: &[u8]) -> Result<(), WasmError> {
    if spend_pub.len() != SPEND_PUBLIC_SIZE {
        return Err(WasmError::InvalidKeySize {
            expected: SPEND_PUBLIC_SIZE,
            actual: spend_pub.len(),
            field: "spending_pk",
        });
    }
    Ok(())
}

fn validate_spend_secret(spend_secret: &[u8]) -> Result<(), WasmError> {
    if spend_secret.len() != SPEND_SECRET_SIZE {
        return Err(WasmError::InvalidKeySize {
            expected: SPEND_SECRET_SIZE,
            actual: spend_secret.len(),
            field: "spending_sk",
        });
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// wasm_bindgen bridge
// ─────────────────────────────────────────────────────────────────────────────

/// Derive only the stealth Ethereum address (sender / detection).
///
/// `spending_pk` is the 33-byte compressed secp256k1 spending public key.
///
/// # Errors
///
/// [`WasmError::InvalidKeySize`] / [`WasmError::InvalidSharedSecretSize`] on
/// bad inputs; [`WasmError::StealthDerivationFailed`] on a bad curve point.
#[wasm_bindgen(js_name = deriveStealthAddress)]
pub fn derive_stealth_address_js(
    spending_pk: &[u8],
    shared_secret: &[u8],
) -> Result<Vec<u8>, WasmError> {
    validate_spend_pub(spending_pk)?;
    validate_shared_secret(shared_secret)?;
    let point = stealth_public(spending_pk, shared_secret)?;
    let (eth, _sui, _pub) = addresses_from_public(&point)?;
    Ok(eth.to_vec())
}

/// Derive only the stealth Sui address (sender / detection).
///
/// # Errors
///
/// See [`derive_stealth_address_js`].
#[wasm_bindgen(js_name = deriveStealthSuiAddress)]
pub fn derive_stealth_sui_address_js(
    spending_pk: &[u8],
    shared_secret: &[u8],
) -> Result<Vec<u8>, WasmError> {
    validate_spend_pub(spending_pk)?;
    validate_shared_secret(shared_secret)?;
    let point = stealth_public(spending_pk, shared_secret)?;
    let (_eth, sui, _pub) = addresses_from_public(&point)?;
    Ok(sui.to_vec())
}

/// Derive both stealth addresses **and** the stealth public key from the
/// recipient's *public* spend key. This is the sender path and the recipient's
/// detection path — it contains no secret material.
///
/// # Errors
///
/// See [`derive_stealth_address_js`].
#[wasm_bindgen(js_name = deriveStealthPublic)]
pub fn derive_stealth_public_js(
    spending_pk: &[u8],
    shared_secret: &[u8],
) -> Result<JsValue, WasmError> {
    validate_spend_pub(spending_pk)?;
    validate_shared_secret(shared_secret)?;
    let point = stealth_public(spending_pk, shared_secret)?;
    let (eth, sui, public_key) = addresses_from_public(&point)?;
    let result = WasmStealthPublic {
        eth_address: eth.to_vec(),
        sui_address: sui.to_vec(),
        public_key,
    };
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| WasmError::Internal(format!("serde failure: {e}")))
}

/// Derive the stealth addresses **and** the spendable secp256k1 private key
/// from the recipient's *secret* spend key. Only the recipient can call this.
///
/// # Errors
///
/// [`WasmError::InvalidKeySize`] / [`WasmError::InvalidSharedSecretSize`] on
/// bad inputs; [`WasmError::StealthDerivationFailed`] on a bad scalar/point.
#[wasm_bindgen(js_name = deriveStealthKeys)]
pub fn derive_stealth_keys_js(
    spending_sk: &[u8],
    shared_secret: &[u8],
) -> Result<JsValue, WasmError> {
    validate_spend_secret(spending_sk)?;
    validate_shared_secret(shared_secret)?;
    let (stealth_sk, stealth_pk) = stealth_secret(spending_sk, shared_secret)?;
    let (eth, sui, public_key) = addresses_from_public(&stealth_pk)?;
    let mut priv_bytes = stealth_sk.to_bytes();
    let result = WasmStealthKeys {
        eth_address: eth.to_vec(),
        sui_address: sui.to_vec(),
        public_key,
        eth_private_key: priv_bytes.to_vec(),
    };
    priv_bytes.zeroize();
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| WasmError::Internal(format!("serde failure: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared() -> [u8; 32] {
        [0xAB; 32]
    }

    /// Cross-implementation known-answer test: the address this SDK derives
    /// from a fixed (`spend_pub`, `shared_secret`) MUST equal the address the
    /// backend `specter-crypto::derive::derive_stealth_address` produces for
    /// the same inputs. If this fails, the SDK and server disagree and every
    /// scanned payment resolves to an unfunded address (the ≤ v1.0.1 bug).
    ///
    /// Expected value generated by running the inputs through the backend
    /// crate directly (secp256k1 additive tweak, DOMAIN `..._V2`, counter +
    /// rejection sampling).
    #[test]
    fn matches_backend_known_answer_vector() {
        let spend_pub =
            hex::decode("03ed72f59870c0462ac4655f058ea742c60b88ccb68e7e46839245d554d6b34ae4")
                .unwrap();
        let shared_secret =
            hex::decode("1b546d39098ed663c59cd55d2fdc55d9da2b19a90cd68173ed32d9593758787e")
                .unwrap();

        let point = stealth_public(&spend_pub, &shared_secret).unwrap();
        let (eth, _sui, _pub) = addresses_from_public(&point).unwrap();

        assert_eq!(
            hex::encode(eth),
            "f9571a5091510a2b9fce2d6a05dfa041b65cb741",
            "SDK stealth address must match the backend derivation"
        );
    }

    #[test]
    fn sender_and_recipient_agree_on_addresses() {
        let (sk, pk) = generate_spend_keypair();
        let ss = shared();

        // Sender / detection: address from the public spend key.
        let sender_point = stealth_public(&pk, &ss).unwrap();
        let (sender_eth, sender_sui, sender_pub) = addresses_from_public(&sender_point).unwrap();

        // Recipient: address + private key from the secret spend key.
        let (stealth_sk, stealth_pk) = stealth_secret(&sk, &ss).unwrap();
        let (recip_eth, recip_sui, recip_pub) = addresses_from_public(&stealth_pk).unwrap();

        assert_eq!(sender_eth, recip_eth, "eth address must match");
        assert_eq!(sender_sui, recip_sui, "sui address must match");
        assert_eq!(sender_pub, recip_pub, "stealth pubkey must match");

        // The recovered private key must re-derive the same public key/address.
        let rederived = SecretKey::from_slice(&stealth_sk.to_bytes())
            .unwrap()
            .public_key();
        let (rederived_eth, _, _) = addresses_from_public(&rederived).unwrap();
        assert_eq!(rederived_eth, recip_eth);
    }

    /// Regression test for Issue #1: a party holding only the recipient's
    /// *public* identity (spend pub + shared secret) can compute the address
    /// but must NOT be able to reconstruct the spendable private key.
    #[test]
    fn sender_cannot_derive_private_key() {
        let (sk, pk) = generate_spend_keypair();
        let ss = shared();

        // The recipient's actual spend key.
        let (stealth_sk, _pk) = stealth_secret(&sk, &ss).unwrap();
        let recipient_priv = stealth_sk.to_bytes();

        // Everything a sender holds: the *public* spend key and shared secret.
        // There is no API that turns these into a private key. The closest a
        // sender can get is the public point, whose x-coordinate is not the
        // private scalar.
        let sender_point = stealth_public(&pk, &ss).unwrap();
        let sender_view = sender_point.to_encoded_point(false).as_bytes().to_vec();

        assert_ne!(
            &sender_view[1..33],
            &recipient_priv[..],
            "public point x-coordinate must not equal the private key"
        );

        // Sanity: derivation is deterministic for the recipient, so the key is
        // reproducible only *with* the secret.
        let (again, _) = stealth_secret(&sk, &ss).unwrap();
        assert_eq!(again.to_bytes(), recipient_priv);
    }

    #[test]
    fn different_secrets_give_different_addresses() {
        let (_sk, pk) = generate_spend_keypair();
        let a = stealth_public(&pk, &[1u8; 32]).unwrap();
        let b = stealth_public(&pk, &[2u8; 32]).unwrap();
        assert_ne!(
            a.to_encoded_point(true).as_bytes(),
            b.to_encoded_point(true).as_bytes()
        );
    }

    #[test]
    fn rejects_bad_sizes() {
        let ss = shared();
        assert_eq!(
            derive_stealth_address_js(&[0u8; 10], &ss)
                .unwrap_err()
                .code(),
            "INVALID_KEY_SIZE"
        );
        let (_sk, pk) = generate_spend_keypair();
        assert_eq!(
            derive_stealth_address_js(&pk, &[0u8; 8])
                .unwrap_err()
                .code(),
            "INVALID_SHARED_SECRET_SIZE"
        );
    }
}
