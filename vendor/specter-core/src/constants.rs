//! Protocol constants for SPECTER.
//!
//! All cryptographic sizes are derived from ML-KEM-768 (NIST FIPS 203).
//! These constants are verified at compile time and match the reference implementation.

// ═══════════════════════════════════════════════════════════════════════════════
// ML-KEM-768 SIZES (NIST FIPS 203)
// ═══════════════════════════════════════════════════════════════════════════════

/// Size of ML-KEM-768 public key (encapsulation key) in bytes.
/// This is what recipients publish for others to send to them.
pub const KYBER_PUBLIC_KEY_SIZE: usize = 1184;

/// Size of ML-KEM-768 secret key (decapsulation key) in bytes.
/// This must be kept private and secure.
pub const KYBER_SECRET_KEY_SIZE: usize = 2400;

/// Size of ML-KEM-768 ciphertext in bytes.
/// This is the ephemeral key published in announcements.
pub const KYBER_CIPHERTEXT_SIZE: usize = 1088;

/// Size of the shared secret derived from Kyber encapsulation/decapsulation.
pub const KYBER_SHARED_SECRET_SIZE: usize = 32;

// ═══════════════════════════════════════════════════════════════════════════════
// VIEW TAG CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Size of view tag in bytes.
/// Using 1 byte gives 99.6% filtering efficiency (1/256 false positive rate).
/// This is the optimal balance between efficiency and storage.
pub const VIEW_TAG_SIZE: usize = 1;

/// Number of possible view tag values (2^8 = 256).
pub const VIEW_TAG_SPACE: usize = 256;

/// Expected filtering efficiency as a percentage.
/// With 1-byte view tags, we skip ~99.6% of announcements.
pub const VIEW_TAG_EFFICIENCY: f64 = 99.609375; // (255/256) * 100

// ═══════════════════════════════════════════════════════════════════════════════
// HASH OUTPUT SIZES
// ═══════════════════════════════════════════════════════════════════════════════

/// Size of SHAKE256 output for stealth key derivation.
/// Must match KYBER_PUBLIC_KEY_SIZE for XOR operation.
pub const SHAKE256_STEALTH_OUTPUT_SIZE: usize = KYBER_PUBLIC_KEY_SIZE;

/// Size of SHAKE256 output for view tag computation.
/// We only need 1 byte but compute 32 for future extensibility.
pub const SHAKE256_VIEW_TAG_OUTPUT_SIZE: usize = 32;

// ═══════════════════════════════════════════════════════════════════════════════
// DOMAIN SEPARATORS
// ═══════════════════════════════════════════════════════════════════════════════
// Each SHAKE256 invocation uses a unique domain separator to ensure
// outputs from different operations never collide, even with same inputs.

/// Domain separator for view tag derivation.
pub const DOMAIN_VIEW_TAG: &[u8] = b"SPECTER_VIEW_TAG_V1";

/// Domain separator for stealth public key derivation.
pub const DOMAIN_STEALTH_PK: &[u8] = b"SPECTER_STEALTH_PK_V1";

/// Domain separator for stealth secret key derivation.
pub const DOMAIN_STEALTH_SK: &[u8] = b"SPECTER_STEALTH_SK_V1";

/// Domain separator for spending seed generation.
pub const DOMAIN_SPENDING_SEED: &[u8] = b"SPECTER_SPENDING_SEED_V1";

/// Domain separator for Ethereum address derivation.
pub const DOMAIN_ETH_ADDRESS: &[u8] = b"SPECTER_ETH_ADDRESS_V1";

/// Domain separator for Ethereum secp256k1 key derivation (stealth address = eth address).
pub const DOMAIN_ETH_KEY: &[u8] = b"SPECTER_ETH_KEY_V1";

// ═══════════════════════════════════════════════════════════════════════════════
// PROTOCOL VERSIONING
// ═══════════════════════════════════════════════════════════════════════════════

/// Current protocol version.
/// Increment when making breaking changes to serialization formats.
pub const PROTOCOL_VERSION: u8 = 1;

/// Minimum supported protocol version for backward compatibility.
pub const MIN_PROTOCOL_VERSION: u8 = 1;

// ═══════════════════════════════════════════════════════════════════════════════
// ETHEREUM CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Size of Ethereum address in bytes (20 bytes = 160 bits).
pub const ETH_ADDRESS_SIZE: usize = 20;

/// Size of Sui address in bytes (32 bytes = 256 bits).
pub const SUI_ADDRESS_SIZE: usize = 32;

/// Size of Ethereum private key in bytes (32 bytes = 256 bits).
pub const ETH_PRIVATE_KEY_SIZE: usize = 32;

/// Size of keccak256 hash output.
pub const KECCAK256_SIZE: usize = 32;

// ═══════════════════════════════════════════════════════════════════════════════
// ENS CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// ENS text record key for SPECTER meta-addresses.
pub const ENS_TEXT_KEY: &str = "specter";

// ═══════════════════════════════════════════════════════════════════════════════
// SUINS CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// SuiNS registry table ID (mainnet).
/// This is the Table object that holds all name records as dynamic fields.
pub const SUINS_REGISTRY_TABLE_ID_MAINNET: &str =
    "0xe64cd9db9f829c6cc405d9790bd71567ae07259855f4fba6f02c84f52298c106";

/// SuiNS registry table ID (testnet).
pub const SUINS_REGISTRY_TABLE_ID_TESTNET: &str =
    "0xb120c0d55432630fce61f7854795a3463deb6e3b443cc4ae72e1282073ff56e4";

/// SuiNS v1 package ID (mainnet). Used to build the Domain type for dynamic field queries.
pub const SUINS_PACKAGE_ID_MAINNET: &str =
    "0xd22b24490e0bae52676651b4f56660a5ff8022a2576e0089f79b3c88d44e08f0";

/// SuiNS v1 package ID (testnet).
pub const SUINS_PACKAGE_ID_TESTNET: &str =
    "0x22fa05f21b1ad71442491220bb9338f7b7095fe35000ef88d5400d28523bdd93";

/// Default Sui mainnet RPC URL.
pub const SUI_MAINNET_RPC_URL: &str = "https://fullnode.mainnet.sui.io:443";

/// Default Sui testnet RPC URL.
pub const SUI_TESTNET_RPC_URL: &str = "https://fullnode.testnet.sui.io:443";

// ═══════════════════════════════════════════════════════════════════════════════
// SERIALIZATION CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Size of serialized MetaAddress (version + spending_pk + viewing_pk).
/// 1 + 1184 + 1184 = 2369 bytes
pub const META_ADDRESS_SERIALIZED_SIZE: usize = 1 + KYBER_PUBLIC_KEY_SIZE + KYBER_PUBLIC_KEY_SIZE;

/// Size of serialized Announcement (ephemeral_key + view_tag + timestamp).
/// 1088 + 1 + 8 = 1097 bytes (plus optional fields)
pub const ANNOUNCEMENT_MIN_SIZE: usize = KYBER_CIPHERTEXT_SIZE + VIEW_TAG_SIZE + 8;

// ═══════════════════════════════════════════════════════════════════════════════
// PERFORMANCE TUNING
// ═══════════════════════════════════════════════════════════════════════════════

/// Default batch size for scanning announcements.
pub const DEFAULT_SCAN_BATCH_SIZE: usize = 1000;

/// Maximum announcements to scan in a single request.
pub const MAX_SCAN_BATCH_SIZE: usize = 10_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber_sizes_match_specification() {
        // These sizes are defined by NIST FIPS 203 for ML-KEM-768
        assert_eq!(KYBER_PUBLIC_KEY_SIZE, 1184);
        assert_eq!(KYBER_SECRET_KEY_SIZE, 2400);
        assert_eq!(KYBER_CIPHERTEXT_SIZE, 1088);
        assert_eq!(KYBER_SHARED_SECRET_SIZE, 32);
    }

    #[test]
    fn test_view_tag_efficiency_calculation() {
        // With 1 byte (256 values), false positive rate is 1/256
        let expected_efficiency = (255.0 / 256.0) * 100.0;
        assert!((VIEW_TAG_EFFICIENCY - expected_efficiency).abs() < 0.0001);
    }

    #[test]
    fn test_meta_address_size() {
        // version (1) + spending_pk (1184) + viewing_pk (1184)
        assert_eq!(META_ADDRESS_SERIALIZED_SIZE, 2369);
    }

    #[test]
    fn test_domain_separators_unique() {
        // Ensure all domain separators are unique
        let domains = [
            DOMAIN_VIEW_TAG,
            DOMAIN_STEALTH_PK,
            DOMAIN_STEALTH_SK,
            DOMAIN_SPENDING_SEED,
            DOMAIN_ETH_ADDRESS,
            DOMAIN_ETH_KEY,
        ];

        for (i, a) in domains.iter().enumerate() {
            for (j, b) in domains.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "Domain separators must be unique");
                }
            }
        }
    }
}
