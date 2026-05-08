//! Domain types for SPECTER.
//!
//! This module provides all the core data structures used throughout the protocol:
//!
//! - [`KeyPair`]: Kyber public/secret key pair
//! - [`MetaAddress`]: Published address for receiving private payments
//! - [`StealthAddress`]: One-time address for a specific payment
//! - [`Announcement`]: Published ephemeral key + view tag

mod address;
mod announcement;
mod keys;

pub use address::*;
pub use announcement::*;
pub use keys::*;
