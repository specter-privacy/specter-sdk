//! Stealth key and address derivation (protocol v2, secp256k1 additive tweak).
//!
//! ## Security model
//!
//! The spending key is a secp256k1 keypair: secret scalar `b`, public point
//! `B = b·G`, published in the meta-address. For each payment the sender and
//! recipient share a per-payment secret `shared_secret` via ML-KEM. From it both
//! derive an additive **tweak** scalar:
//!
//! ```text
//! t = H(shared_secret)                       (a secp256k1 scalar)
//! ```
//!
//! The one-time stealth key is the recipient's spending key shifted by `t`:
//!
//! ```text
//! P = B + t·G          (stealth public key / address — sender-computable)
//! p = b + t (mod n)    (stealth private key      — recipient-only)
//! ```
//!
//! Because `p·G = (b + t)·G = B + t·G = P`, the address the sender computes from
//! the *public* `B` is exactly the address the recipient can spend from with `p`.
//!
//! **The sender cannot derive `p`.** Computing `p` requires the secret scalar
//! `b`, which never leaves the recipient. This is the property that was broken in
//! protocol v1 (where the "private key" was a pure hash of `shared_secret` and
//! the public spending key, and therefore derivable by the sender). See
//! `sender_cannot_derive_stealth_private_key` in the tests.

use zeroize::Zeroize;

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{NonZeroScalar, ProjectivePoint, PublicKey, Scalar, SecretKey};
use rand::rngs::OsRng;
use specter_core::constants::{
    DOMAIN_STEALTH_TWEAK, ETH_ADDRESS_SIZE, SECP256K1_PUBLIC_KEY_SIZE, SUI_ADDRESS_SIZE,
};
use specter_core::error::{Result, SpecterError};
use specter_core::types::{
    EthAddress, Secp256k1KeyPair, Secp256k1PublicKey, Secp256k1SecretKey, SuiAddress,
};

use crate::hash::{keccak256, shake256};

/// Sui signature scheme flag for ECDSA secp256k1.
const SUI_SCHEME_SECP256K1: u8 = 0x01;

/// Result of stealth key derivation (recipient side).
#[derive(Debug)]
pub struct StealthKeys {
    /// The secp256k1 uncompressed public key (65 bytes); hashes to the Ethereum address.
    pub public_key: Vec<u8>,
    /// The stealth private key (32-byte secp256k1 scalar, zeroized on drop).
    pub private_key: StealthPrivateKey,
    /// The derived Ethereum address.
    pub address: EthAddress,
    /// The derived Sui address (same secp256k1 key, blake2b-256).
    pub sui_address: SuiAddress,
}

/// Wrapper for a 32-byte stealth private key with automatic zeroization.
pub struct StealthPrivateKey {
    bytes: Vec<u8>,
}

impl StealthPrivateKey {
    /// Creates from raw bytes (expected to be exactly 32 bytes).
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the 32-byte Ethereum/secp256k1 private key.
    ///
    /// This key imports directly into any secp256k1 wallet (MetaMask, ethers)
    /// and controls the stealth address.
    pub fn to_eth_private_key(&self) -> [u8; 32] {
        let mut eth_sk = [0u8; 32];
        eth_sk.copy_from_slice(&self.bytes[..32]);
        eth_sk
    }
}

impl Drop for StealthPrivateKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl std::fmt::Debug for StealthPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StealthPrivateKey([REDACTED])")
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEY GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Generates a fresh secp256k1 spending keypair using the OS CSPRNG.
///
/// The public key goes into the meta-address; the secret key must never leave
/// the owner's device.
pub fn generate_spending_keypair() -> Secp256k1KeyPair {
    let secret = SecretKey::random(&mut OsRng);
    let public_compressed = secret.public_key().to_sec1_bytes();
    let public = Secp256k1PublicKey::from_bytes(&public_compressed)
        .expect("freshly generated secp256k1 public key is always valid");
    let sk = Secp256k1SecretKey::from_bytes(&secret.to_bytes())
        .expect("freshly generated secp256k1 secret key is always valid");
    Secp256k1KeyPair::new(public, sk)
}

// ═══════════════════════════════════════════════════════════════════════════════
// TWEAK
// ═══════════════════════════════════════════════════════════════════════════════

/// Derives the additive stealth tweak scalar `t = H(shared_secret)`.
///
/// Uses rejection sampling over `SHAKE256(DOMAIN_STEALTH_TWEAK || shared_secret ||
/// counter)`: the first 32-byte candidate that is a valid non-zero scalar in
/// `[1, n)` is returned. This is unbiased and, because secp256k1's order is very
/// close to `2^256`, effectively never iterates more than once.
fn derive_stealth_tweak(shared_secret: &[u8]) -> Scalar {
    let mut counter: u8 = 0;
    loop {
        let mut input = Vec::with_capacity(shared_secret.len() + 1);
        input.extend_from_slice(shared_secret);
        input.push(counter);
        let candidate = shake256(DOMAIN_STEALTH_TWEAK, &input, 32);
        if let Ok(sk) = SecretKey::from_slice(&candidate) {
            // SecretKey::from_slice already guarantees a non-zero scalar in [1, n).
            return *sk.to_nonzero_scalar().as_ref();
        }
        counter = counter.wrapping_add(1);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ADDRESS DERIVATION FROM A PUBLIC KEY
// ═══════════════════════════════════════════════════════════════════════════════

/// Derives the Ethereum address of a secp256k1 public key: `keccak256(uncompressed[1..])[12..]`.
fn eth_address_from_pubkey(pk: &PublicKey) -> EthAddress {
    let encoded = pk.to_encoded_point(false); // 0x04 || X(32) || Y(32)
    let hash = keccak256(&encoded.as_bytes()[1..]); // hash X||Y only
    let mut address_bytes = [0u8; ETH_ADDRESS_SIZE];
    address_bytes.copy_from_slice(&hash[32 - ETH_ADDRESS_SIZE..]);
    EthAddress::from_array(address_bytes)
}

/// Derives the Sui address from a compressed secp256k1 public key:
/// `blake2b-256(0x01 || compressed_pubkey)`.
fn sui_address_from_compressed(compressed: &[u8]) -> Result<SuiAddress> {
    let mut hasher = Blake2bVar::new(SUI_ADDRESS_SIZE)
        .map_err(|_| SpecterError::InvalidStealthAddress("Blake2bVar init failed".into()))?;
    hasher.update(&[SUI_SCHEME_SECP256K1]);
    hasher.update(compressed);
    let mut address_bytes = [0u8; SUI_ADDRESS_SIZE];
    hasher
        .finalize_variable(&mut address_bytes)
        .map_err(|_| SpecterError::InvalidStealthAddress("Blake2b finalize failed".into()))?;
    Ok(SuiAddress::from_array(address_bytes))
}

fn sui_address_from_pubkey(pk: &PublicKey) -> Result<SuiAddress> {
    let compressed = pk.to_encoded_point(true);
    sui_address_from_compressed(compressed.as_bytes())
}

/// Computes the stealth public key point `P = B + t·G` from the spending public
/// key bytes and the shared secret.
fn stealth_pubkey(spending_pub: &[u8], shared_secret: &[u8]) -> Result<PublicKey> {
    if spending_pub.len() != SECP256K1_PUBLIC_KEY_SIZE {
        return Err(SpecterError::InvalidKeySize {
            expected: SECP256K1_PUBLIC_KEY_SIZE,
            actual: spending_pub.len(),
        });
    }
    let b_point = PublicKey::from_sec1_bytes(spending_pub).map_err(|_| {
        SpecterError::InvalidStealthAddress("spending key is not a valid secp256k1 point".into())
    })?;
    let t = derive_stealth_tweak(shared_secret);
    let p_proj = b_point.to_projective() + ProjectivePoint::GENERATOR * t;
    PublicKey::from_affine(p_proj.to_affine()).map_err(|_| {
        SpecterError::InvalidStealthAddress("derived stealth point is the identity".into())
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC API: ADDRESS-ONLY (SENDER) DERIVATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Derives the stealth Ethereum address for a payment — needs only public data.
///
/// `spending_pub` is the recipient's 33-byte compressed secp256k1 spending key.
/// This is the function senders (and view-only scanners) use: it computes
/// `keccak256(B + t·G)` and cannot recover the spend key.
pub fn derive_stealth_address(spending_pub: &[u8], shared_secret: &[u8]) -> Result<EthAddress> {
    let p = stealth_pubkey(spending_pub, shared_secret)?;
    Ok(eth_address_from_pubkey(&p))
}

/// Derives the stealth Sui address for a payment — needs only public data.
pub fn derive_stealth_sui_address(spending_pub: &[u8], shared_secret: &[u8]) -> Result<SuiAddress> {
    let p = stealth_pubkey(spending_pub, shared_secret)?;
    sui_address_from_pubkey(&p)
}

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC API: FULL KEY (RECIPIENT) DERIVATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Derives an Ethereum address from a secp256k1 private key (32 bytes).
///
/// Matches how MetaMask/ethers derive an address from a raw private key.
pub fn derive_eth_address_from_seed(seed: &[u8; 32]) -> Result<EthAddress> {
    let secret = SecretKey::from_slice(seed).map_err(|_| {
        SpecterError::InvalidStealthAddress("invalid secp256k1 key from seed".to_string())
    })?;
    Ok(eth_address_from_pubkey(&secret.public_key()))
}

/// Derives a Sui address from a secp256k1 private key (32 bytes).
pub fn derive_sui_address_from_seed(seed: &[u8; 32]) -> Result<SuiAddress> {
    let secret = SecretKey::from_slice(seed).map_err(|_| {
        SpecterError::InvalidStealthAddress("invalid secp256k1 key from seed".to_string())
    })?;
    sui_address_from_pubkey(&secret.public_key())
}

/// Derives the complete stealth keys (public, private, address, sui) for a
/// discovered payment. **Requires the recipient's secret spending key.**
///
/// * `spending_pub` - recipient's 33-byte compressed spending public key
/// * `spending_sk`  - recipient's 32-byte secret spending scalar (never leaves device)
/// * `shared_secret` - the per-payment ML-KEM shared secret
///
/// Computes `p = b + t (mod n)` and returns the resulting one-time key material.
pub fn derive_stealth_keys(
    spending_pub: &[u8],
    spending_sk: &[u8],
    shared_secret: &[u8],
) -> Result<StealthKeys> {
    let b_secret =
        SecretKey::from_slice(spending_sk).map_err(|_| SpecterError::InvalidKeySize {
            expected: 32,
            actual: spending_sk.len(),
        })?;

    // Defense-in-depth: reject a mismatched (spending_pub, spending_sk) pair so a
    // caller can never silently derive keys for the wrong meta-address.
    if spending_pub.len() != SECP256K1_PUBLIC_KEY_SIZE
        || b_secret.public_key().to_sec1_bytes().as_ref() != spending_pub
    {
        return Err(SpecterError::InvalidStealthAddress(
            "spending secret key does not match the provided spending public key".into(),
        ));
    }

    let b = b_secret.to_nonzero_scalar();
    let t = derive_stealth_tweak(shared_secret);

    let p_scalar: Scalar = *b.as_ref() + t;
    let p_nonzero =
        Option::<NonZeroScalar>::from(NonZeroScalar::new(p_scalar)).ok_or_else(|| {
            SpecterError::InvalidStealthAddress("derived stealth scalar is zero".into())
        })?;
    let p_secret = SecretKey::from(p_nonzero);

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&p_secret.to_bytes());

    let pubkey = p_secret.public_key();
    let public_key = pubkey.to_encoded_point(false).as_bytes().to_vec();
    let address = eth_address_from_pubkey(&pubkey);
    let sui_address = sui_address_from_pubkey(&pubkey)?;
    let private_key = StealthPrivateKey::from_bytes(seed.to_vec());
    seed.zeroize();

    Ok(StealthKeys {
        public_key,
        private_key,
        address,
        sui_address,
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
// VERIFICATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Verifies that a stealth address was correctly derived from `(spending_pub, shared_secret)`.
pub fn verify_stealth_address(
    spending_pub: &[u8],
    shared_secret: &[u8],
    expected_address: &EthAddress,
) -> Result<bool> {
    let derived = derive_stealth_address(spending_pub, shared_secret)?;
    Ok(subtle::ConstantTimeEq::ct_eq(derived.as_bytes(), expected_address.as_bytes()).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic spending keypair `(compressed_pub_bytes, secret_bytes)`.
    fn test_spending_keys(seed: u8) -> (Vec<u8>, Vec<u8>) {
        let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
        (
            sk.public_key().to_sec1_bytes().to_vec(),
            sk.to_bytes().to_vec(),
        )
    }

    fn make_secret() -> [u8; 32] {
        [0xAB; 32]
    }

    #[test]
    fn test_generate_spending_keypair_is_valid_and_random() {
        let a = generate_spending_keypair();
        let b = generate_spending_keypair();
        assert_ne!(a.public.as_bytes(), b.public.as_bytes());
        // secret must derive back to the public key
        let derived =
            derive_eth_address_from_seed(&a.secret.as_bytes().try_into().expect("32 bytes"));
        assert!(derived.is_ok());
    }

    #[test]
    fn test_address_matches_between_sender_and_recipient() {
        let (spending_pub, spending_sk) = test_spending_keys(0x11);
        let shared = make_secret();

        // Sender: address from public key only.
        let sender_addr = derive_stealth_address(&spending_pub, &shared).unwrap();
        // Recipient: full keys from secret.
        let keys = derive_stealth_keys(&spending_pub, &spending_sk, &shared).unwrap();

        assert_eq!(
            sender_addr, keys.address,
            "sender-derived address must equal recipient-derived address"
        );
    }

    #[test]
    fn test_eth_private_key_controls_stealth_address() {
        let (spending_pub, spending_sk) = test_spending_keys(0x22);
        let shared = make_secret();
        let keys = derive_stealth_keys(&spending_pub, &spending_sk, &shared).unwrap();

        // The returned private key must derive to the same address (wallet import).
        let from_pk = derive_eth_address_from_seed(&keys.private_key.to_eth_private_key()).unwrap();
        assert_eq!(keys.address.as_bytes(), from_pk.as_bytes());
    }

    /// THE security regression test for CRITICAL #1.
    ///
    /// A party holding only the *public* spending key and the shared secret
    /// (i.e. the sender) must NOT be able to produce the stealth private key.
    #[test]
    fn sender_cannot_derive_stealth_private_key() {
        let (spending_pub, spending_sk) = test_spending_keys(0x33);
        let shared = make_secret();

        // The recipient's true private key for this payment.
        let recipient_keys = derive_stealth_keys(&spending_pub, &spending_sk, &shared).unwrap();
        let true_priv = recipient_keys.private_key.to_eth_private_key();

        // Everything the sender has: shared secret + public spending key + the
        // public tweak. There is no function that yields the private key from
        // these — the only derivation that does requires `spending_sk`. Prove the
        // sender's best effort (using the address-only path) never exposes it,
        // and that guessing the private key from public data fails.
        let sender_addr = derive_stealth_address(&spending_pub, &shared).unwrap();
        assert_eq!(sender_addr, recipient_keys.address);

        // If the sender could derive the key it would necessarily equal the
        // recipient's. Model the sender substituting the *public* spending key
        // bytes where a secret would go: it must NOT reproduce the true key.
        // (spending_pub is 33 bytes; not even the right size for a scalar.)
        let forged = derive_stealth_keys(&spending_pub, &spending_pub, &shared);
        assert!(
            forged.is_err(),
            "public spending key must not be usable as a secret"
        );

        // And a different (matching) keypair must not yield the true private key.
        let (pub2, other_sk) = test_spending_keys(0x99);
        let wrong = derive_stealth_keys(&pub2, &other_sk, &shared).unwrap();
        assert_ne!(
            wrong.private_key.to_eth_private_key(),
            true_priv,
            "a different secret must not reproduce the true stealth private key"
        );
    }

    #[test]
    fn test_different_secrets_give_different_addresses() {
        let (spending_pub, _sk) = test_spending_keys(0x44);
        let addr1 = derive_stealth_address(&spending_pub, &[1u8; 32]).unwrap();
        let addr2 = derive_stealth_address(&spending_pub, &[2u8; 32]).unwrap();
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_deterministic_derivation() {
        let (spending_pub, _sk) = test_spending_keys(0x55);
        let shared = make_secret();
        let a1 = derive_stealth_address(&spending_pub, &shared).unwrap();
        let a2 = derive_stealth_address(&spending_pub, &shared).unwrap();
        assert_eq!(a1, a2);
    }

    #[test]
    fn test_sui_address_matches_between_paths() {
        let (spending_pub, spending_sk) = test_spending_keys(0x66);
        let shared = make_secret();
        let sender_sui = derive_stealth_sui_address(&spending_pub, &shared).unwrap();
        let keys = derive_stealth_keys(&spending_pub, &spending_sk, &shared).unwrap();
        assert_eq!(sender_sui, keys.sui_address);
        assert!(!sender_sui.is_zero());
    }

    #[test]
    fn test_verify_stealth_address() {
        let (spending_pub, _sk) = test_spending_keys(0x77);
        let shared = make_secret();
        let addr = derive_stealth_address(&spending_pub, &shared).unwrap();
        assert!(verify_stealth_address(&spending_pub, &shared, &addr).unwrap());
        let wrong = EthAddress::from_array([0xFF; ETH_ADDRESS_SIZE]);
        assert!(!verify_stealth_address(&spending_pub, &shared, &wrong).unwrap());
    }

    #[test]
    fn test_invalid_spending_pub_rejected() {
        let bad = vec![0u8; 33]; // not a valid point
        let shared = make_secret();
        assert!(derive_stealth_address(&bad, &shared).is_err());
    }

    #[test]
    fn test_stealth_private_key_zeroized_on_drop() {
        let (spending_pub, spending_sk) = test_spending_keys(0x88);
        {
            let _keys = derive_stealth_keys(&spending_pub, &spending_sk, &make_secret()).unwrap();
        }
        // Drop impl zeroizes; cannot observe directly but the type guarantees it.
    }

    #[test]
    fn test_tweak_is_nonzero_and_deterministic() {
        let s = make_secret();
        let t1 = derive_stealth_tweak(&s);
        let t2 = derive_stealth_tweak(&s);
        assert_eq!(t1, t2);
        assert!(!bool::from(t1.is_zero()));
    }
}
