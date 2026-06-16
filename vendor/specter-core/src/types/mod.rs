//! Domain types for SPECTER.
//!
//! This module provides all the core data structures used throughout the protocol:
//!
//! - [`KeyPair`]: Kyber public/secret key pair
//! - [`MetaAddress`]: Published address for receiving private payments
//! - [`StealthAddress`]: One-time address for a specific payment
//! - [`Announcement`]: Published ephemeral key + view tag
//! - [`AnnouncementMetadata`]: 77-byte fixed metadata for on-chain events

mod address;
mod announcement;
mod keys;
mod metadata;

pub use address::*;
pub use announcement::*;
pub use keys::*;
pub use metadata::*;
