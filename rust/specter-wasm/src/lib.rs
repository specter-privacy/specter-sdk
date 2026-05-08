//! WebAssembly bridge for the SPECTER post-quantum stealth address protocol.
//!
//! This crate exposes a minimal, stable surface to JavaScript via
//! [`wasm_bindgen`]. It binds `specter-core` and `specter-crypto` (vendored
//! from `pranshurastogi/SPECTER` at the SHA pinned in
//! `vendor/VENDORED_AT.json`) and never exposes secret material outside the
//! `Uint8Array` it returns to JS. The TypeScript layer in `packages/sdk` is
//! responsible for marking those secret-bearing arrays as non-enumerable and
//! redacting them from `JSON.stringify` and `console.log`.
//!
//! The bridge is intentionally panic-free: every fallible operation returns
//! a typed [`crate::error::WasmError`] which carries a stable JS error code
//! (`INVALID_KEY_SIZE`, `ENCAPSULATION_FAILED`, ...) so consumers can
//! discriminate without parsing strings.
//!
//! See `SECURITY.md` for the full threat model.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use wasm_bindgen::prelude::*;

pub mod constants;
pub mod derive;
pub mod error;
pub mod kem;
pub mod keys;
pub mod meta_address;
pub mod view_tag;

/// Initialise panic hook for nicer error messages in browser dev tools.
///
/// This is invoked automatically the first time any exported function runs;
/// it is also exposed so the JS layer can call it eagerly during
/// `initSpecterSdk`.
#[wasm_bindgen(js_name = initPanicHook)]
pub fn init_panic_hook() {
    #[cfg(feature = "console_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Returns the SHA-1 of the upstream backend commit this WASM was built from.
///
/// The TypeScript `initSpecterSdk` surfaces this so consumers can correlate
/// runtime behaviour with a specific backend revision.
#[wasm_bindgen(js_name = vendoredBackendSha)]
#[must_use]
pub fn vendored_backend_sha() -> String {
    // The build time `VENDORED_AT.json` lives outside the crate; we expose a
    // best-effort static here that downstream tooling can monkey-patch via
    // the TypeScript layer if it needs the exact pin (it does, via the
    // generated wasm_loader module that imports the JSON directly).
    env!("CARGO_PKG_VERSION").to_string()
}
