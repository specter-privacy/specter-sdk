//! Resolves the full ML-KEM ciphertext for a chain-indexed announcement.
//!
//! The new contract emits only keccak256(ciphertext); the ciphertext lives in
//! the `announce()` calldata. Implementors (e.g. an RPC-backed resolver in
//! specter-chain) fetch that calldata and MUST verify keccak256 before
//! returning. Kept here as a trait so the scanner has no chain/RPC dependency.

use crate::error::Result;
use async_trait::async_trait;

/// Resolves the full ML-KEM ciphertext from on-chain calldata for a given announcement.
#[async_trait]
pub trait EphemeralKeyResolver: Send + Sync {
    /// Fetches and verifies the 1088-byte ciphertext for the given announce tx.
    ///
    /// * `announce_tx_hash` – the Monad tx that called `announce()`.
    /// * `expected_hash` – the 32-byte keccak256 from the event.
    ///
    /// Implementations MUST assert `keccak256(ciphertext) == expected_hash`.
    async fn resolve(&self, announce_tx_hash: &str, expected_hash: &[u8]) -> Result<Vec<u8>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubResolver;
    #[async_trait]
    impl EphemeralKeyResolver for StubResolver {
        async fn resolve(&self, _tx: &str, _h: &[u8]) -> Result<Vec<u8>> {
            Ok(vec![0x42u8; 1088])
        }
    }

    #[tokio::test]
    async fn stub_resolver_returns_ciphertext() {
        let r = StubResolver;
        let ct = r.resolve("0xabc", &[0u8; 32]).await.unwrap();
        assert_eq!(ct.len(), 1088);
    }
}
