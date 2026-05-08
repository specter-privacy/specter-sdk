//! # SPECTER Core
//!
//! Core types, errors, and traits for the SPECTER post-quantum stealth address protocol.
//!
//! This crate provides the foundational building blocks used by all other SPECTER crates:
//!
//! - **Types**: Domain models for keys, addresses, announcements, and metadata
//! - **Errors**: Comprehensive error types with context
//! - **Constants**: Protocol constants and sizes
//! - **Traits**: Common interfaces for extensibility
//!
//! ## Example
//!
//! ```rust
//! use specter_core::{MetaAddress, Announcement, SpecterError};
//!
//! // Types are serializable and well-documented
//! let meta = MetaAddress::default();
//! let json = serde_json::to_string(&meta).unwrap();
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, clippy::all)]

pub mod constants;
pub mod error;
pub mod traits;
pub mod types;

// Re-export commonly used items at crate root
pub use constants::*;
pub use error::{Result, SpecterError};
pub use traits::*;
pub use types::*;
