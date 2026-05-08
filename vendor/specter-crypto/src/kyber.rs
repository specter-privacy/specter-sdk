//! ML-KEM-768 (Kyber) key encapsulation mechanism.
//!
//! This module uses the `ml-kem` crate from RustCrypto to provide ML-KEM-768
//! key encapsulation for SPECTER's post-quantum stealth address protocol.
//!
//! ## Implementation
//!
//! - **Pure Rust**: No C dependencies, compiles to WASM natively
//! - **FIPS 203 compliant**: Implements the finalized ML-KEM standard
//! - **Production ready**: Maintained by RustCrypto with constant-time operations
//!
//! ## Security Level
//!
//! ML-KEM-768 provides approximately 192 bits of classical security and
//! 128+ bits of quantum security, equivalent to AES-192.
//!
//! ## Key Sizes
//!
//! - Public key (encapsulation key): 1184 bytes
//! - Secret key (decapsulation key): 2400 bytes
//! - Ciphertext: 1088 bytes
//! - Shared secret: 32 bytes
//!
//! ## References
//!
//! - NIST FIPS 203: ML-KEM specification
//! - ml-kem: https://crates.io/crates/ml-kem
//! - RustCrypto KEMs: https://github.com/RustCrypto/KEMs

use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};

#[allow(unused_imports)]
use specter_core::constants::{
    KYBER_CIPHERTEXT_SIZE, KYBER_PUBLIC_KEY_SIZE, KYBER_SECRET_KEY_SIZE, KYBER_SHARED_SECRET_SIZE,
};
use specter_core::error::{Result, SpecterError};
use specter_core::types::{KeyPair, KyberPublicKey, KyberSecretKey};

// ═══════════════════════════════════════════════════════════════════════════════
// CIPHERTEXT TYPE
// ═══════════════════════════════════════════════════════════════════════════════

/// ML-KEM-768 ciphertext containing an encapsulated shared secret.
///
/// This type represents the encrypted ephemeral key that gets published in
/// SPECTER announcements. Recipients use their secret key to decapsulate
/// the ciphertext and recover the shared secret used for stealth address derivation.
///
/// # Size
///
/// The ciphertext is exactly [`KYBER_CIPHERTEXT_SIZE`] bytes (1088 bytes).
///
/// # Security
///
/// The ciphertext does not reveal any information about the shared secret
/// without the corresponding secret key. It is safe to publish on-chain.
#[derive(Clone)]
pub struct KyberCiphertext {
    /// Raw ciphertext bytes.
    bytes: Vec<u8>,
}

impl KyberCiphertext {
    /// Creates a ciphertext from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw ciphertext bytes. Must be exactly [`KYBER_CIPHERTEXT_SIZE`] bytes.
    ///
    /// # Returns
    ///
    /// Returns `Ok(KyberCiphertext)` if the byte slice has the correct length,
    /// otherwise returns [`SpecterError::InvalidCiphertextSize`].
    ///
    /// # Errors
    ///
    /// Returns [`SpecterError::InvalidCiphertextSize`] if the byte slice length
    /// does not match [`KYBER_CIPHERTEXT_SIZE`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KYBER_CIPHERTEXT_SIZE {
            return Err(SpecterError::InvalidCiphertextSize {
                expected: KYBER_CIPHERTEXT_SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Returns a reference to the raw ciphertext bytes.
    ///
    /// # Returns
    ///
    /// A byte slice containing the ciphertext data.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the ciphertext and returns the underlying byte vector.
    ///
    /// # Returns
    ///
    /// The raw ciphertext bytes as a `Vec<u8>`.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Returns a hex-encoded string representation of the ciphertext.
    ///
    /// # Returns
    ///
    /// A hexadecimal string encoding of the ciphertext bytes.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let ciphertext = KyberCiphertext::from_bytes(&[0u8; 1088])?;
    /// let hex = ciphertext.to_hex();
    /// ```
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Creates a ciphertext from a hex-encoded string.
    ///
    /// # Arguments
    ///
    /// * `s` - A hexadecimal string encoding of the ciphertext bytes.
    ///
    /// # Returns
    ///
    /// Returns `Ok(KyberCiphertext)` if the hex string decodes to a valid
    /// ciphertext, otherwise returns an error.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The hex string is invalid
    /// - The decoded bytes do not have the correct length (see [`from_bytes`])
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let hex_str = "deadbeef...";
    /// let ciphertext = KyberCiphertext::from_hex(hex_str)?;
    /// ```
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        Self::from_bytes(&bytes)
    }
}

impl std::fmt::Debug for KyberCiphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "KyberCiphertext({}...{})",
            hex::encode(&self.bytes[..8]),
            hex::encode(&self.bytes[KYBER_CIPHERTEXT_SIZE - 8..])
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEY GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Generates a new ML-KEM-768 key pair using cryptographically secure randomness.
///
/// This function creates a new key pair suitable for the SPECTER protocol.
/// The public key can be shared publicly and used for encapsulation, while
/// the secret key must be kept private and is used for decapsulation.
///
/// # Returns
///
/// A [`KeyPair`] containing:
/// - `public`: The public key (encapsulation key) - [`KYBER_PUBLIC_KEY_SIZE`] bytes
/// - `secret`: The secret key (decapsulation key) - [`KYBER_SECRET_KEY_SIZE`] bytes
///
/// # Security
///
/// Uses the system's cryptographically secure random number generator
/// (`rand::thread_rng()`). For production use, ensure your system's RNG
/// is properly seeded and secure.
///
/// # Example
///
/// ```rust,ignore
/// use specter_crypto::generate_keypair;
///
/// let keypair = generate_keypair();
/// assert_eq!(keypair.public.as_bytes().len(), KYBER_PUBLIC_KEY_SIZE);
/// assert_eq!(keypair.secret.as_bytes().len(), KYBER_SECRET_KEY_SIZE);
/// ```
pub fn generate_keypair() -> KeyPair {
    let mut rng = rand::thread_rng();
    let (dk, ek) = MlKem768::generate(&mut rng);

    // Convert to byte arrays
    // These expect calls are safe because ml-kem guarantees fixed sizes
    let public = KyberPublicKey::from_array(ek.as_bytes().into());

    let secret = KyberSecretKey::from_array(dk.as_bytes().into());

    KeyPair::new(public, secret)
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENCAPSULATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Encapsulates a shared secret to a recipient's public key.
///
/// This function is used by senders to create the ephemeral key material
/// for SPECTER announcements. It generates a random shared secret and
/// encrypts it to the recipient's public key.
///
/// # Arguments
///
/// * `public_key` - The recipient's Kyber public key (encapsulation key).
///   Must be a valid ML-KEM-768 public key of [`KYBER_PUBLIC_KEY_SIZE`] bytes.
///
/// # Returns
///
/// Returns `Ok((ciphertext, shared_secret))` where:
/// - `ciphertext`: A [`KyberCiphertext`] (1088 bytes) to include in the announcement
/// - `shared_secret`: A 32-byte array used for stealth address derivation
///
/// # Errors
///
/// Returns [`SpecterError::EncapsulationError`] if:
/// - The public key is invalid or has incorrect size
/// - The encapsulation operation fails
///
/// # Security
///
/// The shared secret is only computable by:
/// - This function (sender) - via encapsulation
/// - The holder of the corresponding secret key (recipient) - via decapsulation
///
/// The encapsulation uses cryptographically secure randomness, so each call
/// produces a different ciphertext and shared secret, even for the same public key.
///
/// # Example
///
/// ```rust,ignore
/// use specter_crypto::{generate_keypair, encapsulate};
///
/// let keypair = generate_keypair();
/// let (ciphertext, shared_secret) = encapsulate(&keypair.public)?;
/// // Use ciphertext in announcement, shared_secret for address derivation
/// ```
pub fn encapsulate(
    public_key: &KyberPublicKey,
) -> Result<(KyberCiphertext, [u8; KYBER_SHARED_SECRET_SIZE])> {
    // Convert public key bytes to the encoded form using the Encoded type alias
    type EkType = <MlKem768 as KemCore>::EncapsulationKey;

    let ek_array = Encoded::<EkType>::try_from(public_key.as_bytes())
        .map_err(|_| SpecterError::EncapsulationError("Invalid public key size".to_string()))?;

    // Create encapsulation key from the encoded bytes
    let ek = EkType::from_bytes(&ek_array);

    // Perform encapsulation with secure randomness
    let mut rng = rand::thread_rng();
    let (ct, ss) = ek
        .encapsulate(&mut rng)
        .map_err(|e| SpecterError::EncapsulationError(format!("Encapsulation failed: {:?}", e)))?;

    // Extract ciphertext - ct is a Ciphertext (Array), convert to bytes
    let ciphertext = KyberCiphertext::from_bytes(&ct[..])?;

    // Extract shared secret - ss is a SharedSecret (Array), convert to bytes
    let mut shared_secret = [0u8; KYBER_SHARED_SECRET_SIZE];
    shared_secret.copy_from_slice(&ss[..]);

    Ok((ciphertext, shared_secret))
}

// ═══════════════════════════════════════════════════════════════════════════════
// DECAPSULATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Decapsulates a ciphertext to recover the shared secret.
///
/// This function is used by recipients to recover the shared secret from
/// SPECTER announcements. The shared secret can then be used to derive
/// the stealth address for scanning.
///
/// # Arguments
///
/// * `ciphertext` - The [`KyberCiphertext`] from the announcement.
///   Must be exactly [`KYBER_CIPHERTEXT_SIZE`] bytes.
/// * `secret_key` - The recipient's Kyber secret key (decapsulation key).
///   Must be a valid ML-KEM-768 secret key of [`KYBER_SECRET_KEY_SIZE`] bytes.
///
/// # Returns
///
/// Returns `Ok([u8; 32])` containing the 32-byte shared secret, which can
/// be used for stealth address derivation.
///
/// # Errors
///
/// Returns [`SpecterError::DecapsulationError`] if:
/// - The ciphertext is invalid or has incorrect size
/// - The secret key is invalid or has incorrect size
/// - The decapsulation operation fails
///
/// # Security
///
/// The decapsulation is implicitly verified - if the ciphertext was not
/// created for the public key corresponding to this secret key, the result
/// will be a pseudo-random value (not an error). This is the standard KEM
/// security property that prevents timing attacks.
///
/// # Example
///
/// ```rust,ignore
/// use specter_crypto::{generate_keypair, encapsulate, decapsulate};
///
/// let keypair = generate_keypair();
/// let (ciphertext, _) = encapsulate(&keypair.public)?;
/// let shared_secret = decapsulate(&ciphertext, &keypair.secret)?;
/// ```
pub fn decapsulate(
    ciphertext: &KyberCiphertext,
    secret_key: &KyberSecretKey,
) -> Result<[u8; KYBER_SHARED_SECRET_SIZE]> {
    // Convert ciphertext bytes to ml-kem Ciphertext type (Array)
    let ct = ml_kem::Ciphertext::<MlKem768>::try_from(ciphertext.as_bytes())
        .map_err(|e| SpecterError::DecapsulationError(format!("Invalid ciphertext: {:?}", e)))?;

    // Convert secret key bytes to the encoded form using the Encoded type alias
    type DkType = <MlKem768 as KemCore>::DecapsulationKey;

    let dk_array = Encoded::<DkType>::try_from(secret_key.as_bytes())
        .map_err(|_| SpecterError::DecapsulationError("Invalid secret key size".to_string()))?;

    // Create decapsulation key from the encoded bytes
    let dk = DkType::from_bytes(&dk_array);

    // Perform decapsulation (constant-time operation)
    let ss = dk
        .decapsulate(&ct)
        .map_err(|e| SpecterError::DecapsulationError(format!("Decapsulation failed: {:?}", e)))?;

    // Extract shared secret - ss is a SharedSecret (Array), convert to bytes
    let mut shared_secret = [0u8; KYBER_SHARED_SECRET_SIZE];
    shared_secret.copy_from_slice(&ss[..]);

    Ok(shared_secret)
}

// ═══════════════════════════════════════════════════════════════════════════════
// VERIFICATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Verifies that encapsulation and decapsulation produce the same shared secret.
///
/// This function performs a round-trip test: it encapsulates a shared secret
/// to the public key, then decapsulates it with the secret key, and verifies
/// that both operations produce the same shared secret.
///
/// # Arguments
///
/// * `public_key` - The public key to use for encapsulation
/// * `secret_key` - The secret key to use for decapsulation
///
/// # Returns
///
/// Returns `Ok(true)` if the round-trip succeeds (keys are a valid pair),
/// `Ok(false)` if decapsulation produces a different secret (keys don't match),
/// or an error if either operation fails.
///
/// # Errors
///
/// Returns an error if encapsulation or decapsulation fails.
///
/// # Security
///
/// Uses constant-time comparison to prevent timing attacks.
///
/// # Example
///
/// ```rust,ignore
/// use specter_crypto::{generate_keypair, verify_roundtrip};
///
/// let keypair = generate_keypair();
/// assert!(verify_roundtrip(&keypair.public, &keypair.secret)?);
/// ```
pub fn verify_roundtrip(public_key: &KyberPublicKey, secret_key: &KyberSecretKey) -> Result<bool> {
    let (ciphertext, sender_secret) = encapsulate(public_key)?;
    let receiver_secret = decapsulate(&ciphertext, secret_key)?;

    // Constant-time comparison to prevent timing attacks
    Ok(subtle::ConstantTimeEq::ct_eq(&sender_secret[..], &receiver_secret[..]).into())
}

/// Verifies that a key pair is consistent.
///
/// This is a convenience function that verifies the public and secret keys
/// in a [`KeyPair`] form a valid ML-KEM-768 key pair.
///
/// # Arguments
///
/// * `keypair` - The key pair to verify
///
/// # Returns
///
/// Returns `Ok(true)` if the keys form a valid pair, `Ok(false)` otherwise,
/// or an error if verification fails.
///
/// # Example
///
/// ```rust,ignore
/// use specter_crypto::{generate_keypair, verify_keypair};
///
/// let keypair = generate_keypair();
/// assert!(verify_keypair(&keypair)?);
/// ```
pub fn verify_keypair(keypair: &KeyPair) -> Result<bool> {
    verify_roundtrip(&keypair.public, &keypair.secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = generate_keypair();

        assert_eq!(keypair.public.as_bytes().len(), KYBER_PUBLIC_KEY_SIZE);
        assert_eq!(keypair.secret.as_bytes().len(), KYBER_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_encapsulation_decapsulation_roundtrip() {
        let keypair = generate_keypair();

        // Encapsulate
        let (ciphertext, sender_secret) = encapsulate(&keypair.public).unwrap();

        // Verify ciphertext size
        assert_eq!(ciphertext.as_bytes().len(), KYBER_CIPHERTEXT_SIZE);

        // Decapsulate
        let receiver_secret = decapsulate(&ciphertext, &keypair.secret).unwrap();

        // Shared secrets must match
        assert_eq!(sender_secret, receiver_secret);
    }

    #[test]
    fn test_multiple_encapsulations_produce_different_secrets() {
        let keypair = generate_keypair();

        let (_, secret1) = encapsulate(&keypair.public).unwrap();
        let (_, secret2) = encapsulate(&keypair.public).unwrap();

        // Each encapsulation should produce a different shared secret
        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_different_keypairs_produce_different_secrets() {
        let keypair1 = generate_keypair();
        let keypair2 = generate_keypair();

        let (ct1, secret1) = encapsulate(&keypair1.public).unwrap();
        let (ct2, secret2) = encapsulate(&keypair2.public).unwrap();

        // Different public keys should produce different ciphertexts and secrets
        assert_ne!(ct1.as_bytes(), ct2.as_bytes());
        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_verify_roundtrip() {
        let keypair = generate_keypair();
        assert!(verify_roundtrip(&keypair.public, &keypair.secret).unwrap());
    }

    #[test]
    fn test_verify_keypair() {
        let keypair = generate_keypair();
        assert!(verify_keypair(&keypair).unwrap());
    }

    #[test]
    fn test_ciphertext_hex_roundtrip() {
        let keypair = generate_keypair();
        let (ciphertext, _) = encapsulate(&keypair.public).unwrap();

        let hex = ciphertext.to_hex();
        let recovered = KyberCiphertext::from_hex(&hex).unwrap();

        assert_eq!(ciphertext.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn test_invalid_public_key_size() {
        let bad_key = KyberPublicKey::from_bytes(&[0u8; 100]);
        assert!(bad_key.is_err());
    }

    #[test]
    fn test_invalid_ciphertext_size() {
        let bad_ct = KyberCiphertext::from_bytes(&[0u8; 100]);
        assert!(bad_ct.is_err());
    }

    #[test]
    fn test_wrong_key_decapsulation() {
        let keypair1 = generate_keypair();
        let keypair2 = generate_keypair();

        // Encapsulate with keypair1's public key
        let (ciphertext, sender_secret) = encapsulate(&keypair1.public).unwrap();

        // Decapsulate with keypair2's secret key (wrong key!)
        let wrong_secret = decapsulate(&ciphertext, &keypair2.secret).unwrap();

        // Should produce a different (pseudo-random) secret, not the original
        assert_ne!(sender_secret, wrong_secret);
    }
}
