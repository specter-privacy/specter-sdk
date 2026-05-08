//! # SPECTER Cryptography
//!
//! Post-quantum cryptographic primitives for the SPECTER protocol.
//!
//! This crate provides:
//!
//! - **Kyber**: ML-KEM-768 key generation, encapsulation, decapsulation
//! - **Hash**: SHAKE256 with domain separation
//! - **View Tags**: Efficient computation for scanning optimization
//! - **Derivation**: Stealth key derivation functions
//!
//! ## Security Properties
//!
//! - All secret key operations use constant-time implementations
//! - Secret keys are zeroized on drop
//! - Domain separators prevent cross-protocol attacks
//!
//! ## Example
//!
//! ```rust,ignore
//! use specter_crypto::{generate_keypair, encapsulate, decapsulate, compute_view_tag};
//!
//! // Generate Kyber keypair
//! let keypair = generate_keypair();
//!
//! // Sender encapsulates to create shared secret
//! let (ciphertext, shared_secret) = encapsulate(&keypair.public)?;
//!
//! // Receiver decapsulates to recover shared secret
//! let recovered = decapsulate(&ciphertext, &keypair.secret)?;
//!
//! // Compute view tag for efficient scanning
//! let view_tag = compute_view_tag(&shared_secret);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod derive;
pub mod hash;
pub mod kyber;
pub mod view_tag;

// Re-export main functions at crate root
pub use derive::{
    derive_eth_address, derive_eth_address_from_seed, derive_stealth_keys,
    derive_stealth_sui_address, derive_sui_address_from_seed,
};
pub use hash::{shake256, shake256_xof};
pub use kyber::{decapsulate, encapsulate, generate_keypair, KyberCiphertext};
pub use view_tag::compute_view_tag;
