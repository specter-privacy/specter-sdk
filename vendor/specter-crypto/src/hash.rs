//! Hashing utilities with domain separation.
//!
//! This module provides SHAKE256 (extendable-output function) with domain
//! separation to ensure different protocol components never produce
//! colliding outputs.
//!
//! ## Domain Separation
//!
//! Each use of SHAKE256 in the protocol includes a unique domain separator:
//!
//! ```text
//! output = SHAKE256(domain || input, output_length)
//! ```
//!
//! This prevents cross-protocol attacks where the same input might be
//! used in different contexts.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

// ═══════════════════════════════════════════════════════════════════════════════
// SHAKE256 FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/// Computes SHAKE256 hash with domain separation.
///
/// # Arguments
///
/// * `domain` - Domain separator bytes (unique per use case)
/// * `input` - Input data to hash
/// * `output_len` - Desired output length in bytes
///
/// # Example
///
/// ```rust,ignore
/// use specter_crypto::shake256;
/// use specter_core::constants::DOMAIN_VIEW_TAG;
///
/// let shared_secret = [0u8; 32];
/// let view_tag_hash = shake256(DOMAIN_VIEW_TAG, &shared_secret, 32);
/// let view_tag = view_tag_hash[0]; // First byte as view tag
/// ```
pub fn shake256(domain: &[u8], input: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();

    // Domain separation: prepend domain with length prefix
    hasher.update(&(domain.len() as u32).to_le_bytes());
    hasher.update(domain);

    // Add input
    hasher.update(input);

    // Read output
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; output_len];
    reader.read(&mut output);

    output
}

/// Computes SHAKE256 hash with multiple inputs.
///
/// Useful when the input consists of multiple parts that should be
/// processed in order.
///
/// # Arguments
///
/// * `domain` - Domain separator bytes
/// * `inputs` - Slice of input byte slices
/// * `output_len` - Desired output length
pub fn shake256_multi(domain: &[u8], inputs: &[&[u8]], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();

    // Domain separation
    hasher.update(&(domain.len() as u32).to_le_bytes());
    hasher.update(domain);

    // Add each input with length prefix (for unambiguous parsing)
    for input in inputs {
        hasher.update(&(input.len() as u64).to_le_bytes());
        hasher.update(input);
    }

    // Read output
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; output_len];
    reader.read(&mut output);

    output
}

/// Returns a SHAKE256 XOF reader for streaming output.
///
/// Use this when you need to generate a large amount of output
/// incrementally.
pub fn shake256_xof(domain: &[u8], input: &[u8]) -> Shake256XofReader {
    let mut hasher = Shake256::default();

    // Domain separation
    hasher.update(&(domain.len() as u32).to_le_bytes());
    hasher.update(domain);
    hasher.update(input);

    Shake256XofReader {
        reader: hasher.finalize_xof(),
    }
}

/// Streaming reader for SHAKE256 output.
pub struct Shake256XofReader {
    reader: sha3::digest::core_api::XofReaderCoreWrapper<sha3::Shake256ReaderCore>,
}

impl Shake256XofReader {
    /// Reads bytes into the provided buffer.
    pub fn read(&mut self, output: &mut [u8]) {
        self.reader.read(output);
    }

    /// Reads and returns a fixed-size array.
    pub fn read_array<const N: usize>(&mut self) -> [u8; N] {
        let mut output = [0u8; N];
        self.reader.read(&mut output);
        output
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// KECCAK256 (for Ethereum addresses)
// ═══════════════════════════════════════════════════════════════════════════════

/// Computes Keccak256 hash (used for Ethereum addresses).
///
/// Note: Keccak256 is NOT SHA3-256. They use different padding.
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};

    let mut hasher = Keccak256::new();
    Digest::update(&mut hasher, input);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use specter_core::constants::*;

    #[test]
    fn test_shake256_basic() {
        let output = shake256(b"test_domain", b"input", 32);
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_shake256_variable_output() {
        let short = shake256(b"domain", b"input", 16);
        let long = shake256(b"domain", b"input", 64);

        assert_eq!(short.len(), 16);
        assert_eq!(long.len(), 64);

        // First 16 bytes should match
        assert_eq!(&short[..], &long[..16]);
    }

    #[test]
    fn test_shake256_domain_separation() {
        let domain1 = shake256(b"domain1", b"input", 32);
        let domain2 = shake256(b"domain2", b"input", 32);

        // Different domains should produce different outputs
        assert_ne!(domain1, domain2);
    }

    #[test]
    fn test_shake256_deterministic() {
        let output1 = shake256(b"domain", b"input", 32);
        let output2 = shake256(b"domain", b"input", 32);

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_shake256_multi() {
        let multi = shake256_multi(b"domain", &[b"part1", b"part2"], 32);

        // Should be different from concatenated input
        let single = shake256(b"domain", b"part1part2", 32);
        assert_ne!(multi, single);
    }

    #[test]
    fn test_shake256_xof() {
        let mut reader = shake256_xof(b"domain", b"input");

        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        reader.read(&mut output1);
        reader.read(&mut output2);

        // Sequential reads should produce different data
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_shake256_xof_read_array() {
        let mut reader = shake256_xof(b"domain", b"input");
        let output: [u8; 32] = reader.read_array();

        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_keccak256() {
        let hash = keccak256(b"hello");
        assert_eq!(hash.len(), 32);

        // Known test vector
        let expected =
            hex::decode("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8")
                .unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_specter_domains_produce_different_outputs() {
        let input = [0u8; 32];

        let view_tag_hash = shake256(DOMAIN_VIEW_TAG, &input, 32);
        let stealth_pk_hash = shake256(DOMAIN_STEALTH_PK, &input, 32);
        let stealth_sk_hash = shake256(DOMAIN_STEALTH_SK, &input, 32);

        // All domain separators should produce different outputs
        assert_ne!(view_tag_hash, stealth_pk_hash);
        assert_ne!(view_tag_hash, stealth_sk_hash);
        assert_ne!(stealth_pk_hash, stealth_sk_hash);
    }

    #[test]
    fn test_shake256_large_output() {
        // Test generating 1184 bytes (Kyber public key size)
        let output = shake256(DOMAIN_STEALTH_PK, b"shared_secret", KYBER_PUBLIC_KEY_SIZE);
        assert_eq!(output.len(), KYBER_PUBLIC_KEY_SIZE);
    }
}
