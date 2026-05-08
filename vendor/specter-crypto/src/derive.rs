//! Stealth key and address derivation.
//!
//! This module implements the core cryptographic operations for deriving
//! stealth public/private keys and Ethereum addresses.
//!
//! ## Derivation Flow
//!
//! ```text
//! shared_secret
//!       ↓
//! SHAKE256(DOMAIN_STEALTH_PK || shared_secret) → stealth_factor (1184 bytes)
//!       ↓
//! stealth_pk = spending_pk ⊕ stealth_factor
//!       ↓
//! eth_address = keccak256(stealth_pk)[12..32]
//! ```
//!
//! ## Private Key Derivation
//!
//! The recipient can derive the stealth private key:
//!
//! ```text
//! stealth_sk = spending_sk ⊕ stealth_factor
//! ```

use zeroize::Zeroize;

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use k256::ecdsa::SigningKey;
use specter_core::constants::{
    DOMAIN_ETH_KEY, DOMAIN_STEALTH_PK, DOMAIN_STEALTH_SK, ETH_ADDRESS_SIZE, KYBER_PUBLIC_KEY_SIZE,
    KYBER_SECRET_KEY_SIZE, SUI_ADDRESS_SIZE,
};
use specter_core::error::{Result, SpecterError};
use specter_core::types::{EthAddress, SuiAddress};

use crate::hash::{keccak256, shake256};

/// Sui signature scheme flag for ECDSA secp256k1.
const SUI_SCHEME_SECP256K1: u8 = 0x01;

/// Result of stealth key derivation.
#[derive(Debug)]
pub struct StealthKeys {
    /// The secp256k1 uncompressed public key (65 bytes); hashes to the Ethereum address.
    pub public_key: Vec<u8>,
    /// The stealth private key (2400 bytes, zeroized on drop)
    pub private_key: StealthPrivateKey,
    /// The derived Ethereum address
    pub address: EthAddress,
    /// The derived Sui address (same secp256k1 key, blake2b-256)
    pub sui_address: SuiAddress,
}

/// Wrapper for stealth private key with automatic zeroization.
pub struct StealthPrivateKey {
    bytes: Vec<u8>,
}

impl StealthPrivateKey {
    /// Creates from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Extracts the 32-byte seed for Ethereum signing.
    ///
    /// For Ethereum compatibility, we derive a 32-byte private key
    /// from the Kyber secret key material.
    pub fn to_eth_private_key(&self) -> [u8; 32] {
        // Use first 32 bytes of stealth SK as Ethereum private key
        // In production, this should use proper key derivation
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

/// stealth_factor = SHAKE256(DOMAIN_STEALTH_PK || shared_secret, 1184); stealth_pk = spending_pk ⊕ stealth_factor
pub fn derive_stealth_public_key(spending_pk: &[u8], shared_secret: &[u8]) -> Result<Vec<u8>> {
    if spending_pk.len() != KYBER_PUBLIC_KEY_SIZE {
        return Err(SpecterError::InvalidKeySize {
            expected: KYBER_PUBLIC_KEY_SIZE,
            actual: spending_pk.len(),
        });
    }

    let stealth_factor = shake256(DOMAIN_STEALTH_PK, shared_secret, KYBER_PUBLIC_KEY_SIZE);

    // XOR with spending public key
    let stealth_pk: Vec<u8> = spending_pk
        .iter()
        .zip(stealth_factor.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    Ok(stealth_pk)
}

/// stealth_factor = SHAKE256(DOMAIN_STEALTH_SK || shared_secret, 2400); stealth_sk = spending_sk ⊕ stealth_factor. Output is zeroized on drop.
pub fn derive_stealth_private_key(
    spending_sk: &[u8],
    shared_secret: &[u8],
) -> Result<StealthPrivateKey> {
    if spending_sk.len() != KYBER_SECRET_KEY_SIZE {
        return Err(SpecterError::InvalidKeySize {
            expected: KYBER_SECRET_KEY_SIZE,
            actual: spending_sk.len(),
        });
    }

    let stealth_factor = shake256(DOMAIN_STEALTH_SK, shared_secret, KYBER_SECRET_KEY_SIZE);

    // XOR with spending secret key
    let stealth_sk: Vec<u8> = spending_sk
        .iter()
        .zip(stealth_factor.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    Ok(StealthPrivateKey::from_bytes(stealth_sk))
}

// ═══════════════════════════════════════════════════════════════════════════════
// ETHEREUM ADDRESS DERIVATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Derives a 32-byte secp256k1 key seed from (shared_secret, spending_pk).
/// Both sender and recipient can compute this; used for stealth address and eth_private_key.
/// Retries with re-hashed seed if the first candidate is not a valid secp256k1 scalar.
fn derive_eth_key_seed(shared_secret: &[u8], spending_pk: &[u8]) -> Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    let mut raw = shake256(DOMAIN_ETH_KEY, &[shared_secret, spending_pk].concat(), 32);
    seed.copy_from_slice(&raw[..32]);
    loop {
        if SigningKey::from_slice(&seed).is_ok() {
            return Ok(seed);
        }
        raw = keccak256(&seed).to_vec();
        seed.copy_from_slice(&raw);
    }
}

/// Derives a Sui address from a secp256k1 private key (32 bytes).
/// Sui uses blake2b-256(scheme_flag || compressed_pubkey) where scheme_flag is 0x01 for secp256k1.
pub fn derive_sui_address_from_seed(seed: &[u8; 32]) -> Result<SuiAddress> {
    let signing_key = SigningKey::from_slice(seed).map_err(|_| {
        SpecterError::InvalidStealthAddress("invalid secp256k1 key from seed".to_string())
    })?;
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(true); // compressed (33 bytes)
    let compressed = encoded.as_bytes();

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

/// Derives an Ethereum address from a secp256k1 private key (32 bytes).
/// This matches how MetaMask/wallets derive address from private key.
pub fn derive_eth_address_from_seed(seed: &[u8; 32]) -> Result<EthAddress> {
    let signing_key = SigningKey::from_slice(seed).map_err(|_| {
        SpecterError::InvalidStealthAddress("invalid secp256k1 key from seed".to_string())
    })?;
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    // Skip the 0x04 prefix - Ethereum only hashes the 64-byte public key (x, y)
    let pubkey_bytes = &encoded.as_bytes()[1..];
    let hash = keccak256(pubkey_bytes);
    let mut address_bytes = [0u8; ETH_ADDRESS_SIZE];
    address_bytes.copy_from_slice(&hash[32 - ETH_ADDRESS_SIZE..]);
    Ok(EthAddress::from_array(address_bytes))
}

/// Derives an Ethereum address from a stealth public key (legacy Kyber-based; 1184 bytes).
/// Prefer the secp256k1 path via derive_stealth_address / derive_stealth_keys for wallet compatibility.
pub fn derive_eth_address(stealth_pk: &[u8]) -> Result<EthAddress> {
    if stealth_pk.len() != KYBER_PUBLIC_KEY_SIZE {
        return Err(SpecterError::InvalidKeySize {
            expected: KYBER_PUBLIC_KEY_SIZE,
            actual: stealth_pk.len(),
        });
    }

    let hash = keccak256(stealth_pk);

    // Take last 20 bytes as Ethereum address
    let mut address_bytes = [0u8; ETH_ADDRESS_SIZE];
    address_bytes.copy_from_slice(&hash[32 - ETH_ADDRESS_SIZE..]);

    Ok(EthAddress::from_array(address_bytes))
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMBINED DERIVATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Derives complete stealth keys (public, private, and address).
/// Uses secp256k1 so address and eth_private_key match (import key in wallet to spend).
///
/// * `spending_pk` - The recipient's spending public key
/// * `spending_sk` - Unused for secp256k1 path; kept for API compatibility
/// * `shared_secret` - The shared secret from Kyber decapsulation
pub fn derive_stealth_keys(
    spending_pk: &[u8],
    _spending_sk: &[u8],
    shared_secret: &[u8],
) -> Result<StealthKeys> {
    let seed = derive_eth_key_seed(shared_secret, spending_pk)?;
    let address = derive_eth_address_from_seed(&seed)?;
    let sui_address = derive_sui_address_from_seed(&seed)?;
    let signing_key = SigningKey::from_slice(&seed)
        .map_err(|_| SpecterError::InvalidStealthAddress("invalid secp256k1 key".to_string()))?;
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_encoded_point(false).as_bytes().to_vec();
    let private_key = StealthPrivateKey::from_bytes(seed.to_vec());

    Ok(StealthKeys {
        public_key,
        private_key,
        address,
        sui_address,
    })
}

/// Derives only the Ethereum address (for senders who don't need the private key).
/// Uses secp256k1 so the address matches the eth_private_key when imported in a wallet.
pub fn derive_stealth_address(spending_pk: &[u8], shared_secret: &[u8]) -> Result<EthAddress> {
    let seed = derive_eth_key_seed(shared_secret, spending_pk)?;
    derive_eth_address_from_seed(&seed)
}

/// Derives only the Sui address (for senders who don't need the private key).
/// Uses the same secp256k1 key as the Ethereum address.
pub fn derive_stealth_sui_address(spending_pk: &[u8], shared_secret: &[u8]) -> Result<SuiAddress> {
    let seed = derive_eth_key_seed(shared_secret, spending_pk)?;
    derive_sui_address_from_seed(&seed)
}

// ═══════════════════════════════════════════════════════════════════════════════
// VERIFICATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Verifies that a stealth address was correctly derived.
///
/// Used to confirm a discovered payment is actually for this recipient.
pub fn verify_stealth_address(
    spending_pk: &[u8],
    shared_secret: &[u8],
    expected_address: &EthAddress,
) -> Result<bool> {
    let derived = derive_stealth_address(spending_pk, shared_secret)?;
    Ok(subtle::ConstantTimeEq::ct_eq(derived.as_bytes(), expected_address.as_bytes()).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_pk() -> Vec<u8> {
        vec![0x42u8; KYBER_PUBLIC_KEY_SIZE]
    }

    fn make_test_sk() -> Vec<u8> {
        vec![0x99u8; KYBER_SECRET_KEY_SIZE]
    }

    fn make_test_secret() -> [u8; 32] {
        [0xAB; 32]
    }

    #[test]
    fn test_derive_stealth_public_key() {
        let spending_pk = make_test_pk();
        let shared_secret = make_test_secret();

        let stealth_pk = derive_stealth_public_key(&spending_pk, &shared_secret).unwrap();

        assert_eq!(stealth_pk.len(), KYBER_PUBLIC_KEY_SIZE);
        // Stealth PK should be different from spending PK
        assert_ne!(stealth_pk, spending_pk);
    }

    #[test]
    fn test_derive_stealth_public_key_deterministic() {
        let spending_pk = make_test_pk();
        let shared_secret = make_test_secret();

        let pk1 = derive_stealth_public_key(&spending_pk, &shared_secret).unwrap();
        let pk2 = derive_stealth_public_key(&spending_pk, &shared_secret).unwrap();

        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_derive_stealth_public_key_different_secrets() {
        let spending_pk = make_test_pk();
        let secret1 = [1u8; 32];
        let secret2 = [2u8; 32];

        let pk1 = derive_stealth_public_key(&spending_pk, &secret1).unwrap();
        let pk2 = derive_stealth_public_key(&spending_pk, &secret2).unwrap();

        // Different secrets should produce different stealth PKs
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn test_derive_stealth_private_key() {
        let spending_sk = make_test_sk();
        let shared_secret = make_test_secret();

        let stealth_sk = derive_stealth_private_key(&spending_sk, &shared_secret).unwrap();

        assert_eq!(stealth_sk.as_bytes().len(), KYBER_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_derive_eth_address() {
        let stealth_pk = make_test_pk();
        let address = derive_eth_address(&stealth_pk).unwrap();

        assert_eq!(address.as_bytes().len(), ETH_ADDRESS_SIZE);
    }

    #[test]
    fn test_derive_stealth_keys() {
        let spending_pk = make_test_pk();
        let spending_sk = make_test_sk();
        let shared_secret = make_test_secret();

        let keys = derive_stealth_keys(&spending_pk, &spending_sk, &shared_secret).unwrap();

        // secp256k1 path: 65-byte uncompressed pubkey, 32-byte eth private key
        assert_eq!(keys.public_key.len(), 65);
        assert_eq!(keys.private_key.as_bytes().len(), 32);
        assert_eq!(keys.address.as_bytes().len(), ETH_ADDRESS_SIZE);
        assert_eq!(keys.sui_address.as_bytes().len(), SUI_ADDRESS_SIZE);
        // eth_private_key must derive to the same address (wallet compatibility)
        let addr_from_pk =
            derive_eth_address_from_seed(&keys.private_key.to_eth_private_key()).unwrap();
        assert_eq!(keys.address.as_bytes(), addr_from_pk.as_bytes());
        // sui_address must derive from same seed
        let sui_from_seed =
            derive_sui_address_from_seed(&keys.private_key.to_eth_private_key()).unwrap();
        assert_eq!(keys.sui_address.as_bytes(), sui_from_seed.as_bytes());
    }

    #[test]
    fn test_derive_stealth_address() {
        let spending_pk = make_test_pk();
        let shared_secret = make_test_secret();

        let address = derive_stealth_address(&spending_pk, &shared_secret).unwrap();

        // Should match the address from full key derivation
        let keys = derive_stealth_keys(&spending_pk, &make_test_sk(), &shared_secret).unwrap();
        assert_eq!(address, keys.address);
    }

    #[test]
    fn test_verify_stealth_address() {
        let spending_pk = make_test_pk();
        let shared_secret = make_test_secret();

        let address = derive_stealth_address(&spending_pk, &shared_secret).unwrap();

        assert!(verify_stealth_address(&spending_pk, &shared_secret, &address).unwrap());

        // Wrong address should fail
        let wrong_address = EthAddress::from_array([0xFF; ETH_ADDRESS_SIZE]);
        assert!(!verify_stealth_address(&spending_pk, &shared_secret, &wrong_address).unwrap());
    }

    #[test]
    fn test_xor_reversibility() {
        // XOR is its own inverse: (A ⊕ B) ⊕ B = A
        let original = make_test_pk();
        let shared_secret = make_test_secret();

        let stealth = derive_stealth_public_key(&original, &shared_secret).unwrap();

        // Apply the same operation to recover original
        let factor = shake256(DOMAIN_STEALTH_PK, &shared_secret, KYBER_PUBLIC_KEY_SIZE);
        let recovered: Vec<u8> = stealth
            .iter()
            .zip(factor.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_stealth_private_key_zeroized_on_drop() {
        let spending_sk = make_test_sk();
        let shared_secret = make_test_secret();

        // Create and immediately drop
        {
            let _stealth_sk = derive_stealth_private_key(&spending_sk, &shared_secret).unwrap();
            // Key is zeroized when _stealth_sk goes out of scope
        }

        // Can't directly verify zeroization, but the Drop impl ensures it
    }

    #[test]
    fn test_derive_sui_address() {
        let spending_pk = make_test_pk();
        let shared_secret = make_test_secret();

        let sui_addr = derive_stealth_sui_address(&spending_pk, &shared_secret).unwrap();
        assert_eq!(sui_addr.as_bytes().len(), SUI_ADDRESS_SIZE);
        assert!(!sui_addr.is_zero());

        // Must match the sui_address from full key derivation
        let keys = derive_stealth_keys(&spending_pk, &make_test_sk(), &shared_secret).unwrap();
        assert_eq!(sui_addr, keys.sui_address);
    }

    #[test]
    fn test_invalid_key_sizes() {
        let too_short = vec![0u8; 100];
        let shared_secret = make_test_secret();

        assert!(derive_stealth_public_key(&too_short, &shared_secret).is_err());
        assert!(derive_stealth_private_key(&too_short, &shared_secret).is_err());
        assert!(derive_eth_address(&too_short).is_err());
    }
}
