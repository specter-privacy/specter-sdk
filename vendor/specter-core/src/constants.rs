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
// SECP256K1 SIZES (SPENDING KEY, PROTOCOL v2)
// ═══════════════════════════════════════════════════════════════════════════════
//
// As of protocol v2 the *spending* key is a secp256k1 keypair (not ML-KEM). This
// is what makes stealth addresses genuinely one-way: the sender can derive the
// stealth *address* from the public spending key, but only the holder of the
// secret spending scalar can derive the spend key. See `specter-crypto::derive`.
//
// The *viewing* key remains ML-KEM-768 so payment discovery stays post-quantum.

/// Size of a compressed secp256k1 public key in bytes (0x02/0x03 prefix + X).
pub const SECP256K1_PUBLIC_KEY_SIZE: usize = 33;

/// Size of a secp256k1 secret scalar in bytes.
pub const SECP256K1_SECRET_KEY_SIZE: usize = 32;

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

/// Domain separator for the v2 stealth tweak scalar `t = H(shared_secret)`.
///
/// The tweak is the additive secp256k1 scalar that shifts the recipient's
/// spending key to a one-time stealth key: `P = B + t·G`, `p = b + t (mod n)`.
pub const DOMAIN_STEALTH_TWEAK: &[u8] = b"SPECTER_STEALTH_TWEAK_V2";

/// Domain separator for metadata encryption key derivation (AES-256-GCM key).
pub const DOMAIN_META_ENC_KEY: &[u8] = b"SPECTER_META_ENC_KEY_V1";

/// Domain separator for metadata encryption nonce derivation (AES-256-GCM nonce).
pub const DOMAIN_META_ENC_NONCE: &[u8] = b"SPECTER_META_ENC_NONCE_V1";

/// Domain separator: derive the dedup-MAC subkey from the DB master key.
pub const DOMAIN_DB_HMAC_KEY: &[u8] = b"SPECTER_DB_HMAC_V1";
/// Domain separator: derive the pending-secret AEAD-wrap subkey.
pub const DOMAIN_DB_PENDING_WRAP: &[u8] = b"SPECTER_DB_PENDING_V1";
/// Domain separator: derive the telemetry IP-hash salt from the DB master key.
pub const DOMAIN_DB_TELEMETRY_SALT: &[u8] = b"SPECTER_DB_TELEMETRY_V1";
/// Domain separator: keyed MAC over a normalized payment tx hash (dedup key).
pub const DOMAIN_DB_PAYMENT_MAC: &[u8] = b"SPECTER_DB_PAYMENT_MAC_V1";
/// Domain separator: telemetry IP hash (salt + day + ip).
pub const DOMAIN_DB_IP_HASH: &[u8] = b"SPECTER_DB_IP_HASH_V1";

// ═══════════════════════════════════════════════════════════════════════════════
// PROTOCOL VERSIONING
// ═══════════════════════════════════════════════════════════════════════════════

/// Current protocol version.
///
/// v2 (breaking): the spending key is secp256k1 and stealth keys use additive
/// tweak derivation (`P = B + t·G`). v1 meta-addresses and v1 stealth payments
/// are NOT compatible and are rejected — v1 stealth keys were derivable by the
/// sender and must be treated as compromised.
pub const PROTOCOL_VERSION: u8 = 2;

/// Minimum supported protocol version. v1 is rejected everywhere.
pub const MIN_PROTOCOL_VERSION: u8 = 2;

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
///
/// Note: `fullnode.mainnet.sui.io` is deliberately *not* the default. Sui
/// disabled JSON-RPC on the public fullnodes ("JSON-RPC on public fullnodes
/// has been deprecated. Please migrate to gRPC or GraphQL"), so the SuiNS
/// methods this crate calls — `suix_resolveNameServiceAddress` and
/// `suix_getDynamicFieldObject` — now answer `-32601 Method not found` there.
pub const SUI_MAINNET_RPC_URL: &str = "https://sui-rpc.publicnode.com";

/// Default Sui testnet RPC URL. See [`SUI_MAINNET_RPC_URL`] for why the
/// official public fullnode is not used.
pub const SUI_TESTNET_RPC_URL: &str = "https://sui-testnet-rpc.publicnode.com";

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC RPC FALLBACKS
// ═══════════════════════════════════════════════════════════════════════════════
//
// Key-free public endpoints tried in order when the configured primary RPC
// fails (transport error, HTTP 401/403/429/5xx, or a JSON-RPC error that is
// not a contract revert). A paid provider going down, hitting its rate limit,
// or having its key revoked should degrade name resolution to "slower", never
// to "broken" — and never to a false "this name has no SPECTER record".
//
// Every endpoint below was verified to answer the exact call this codebase
// makes: `eth_call` against the ENS registry for the Ethereum lists,
// `eth_getTransactionReceipt` for the source-chain verification lists, and
// `suix_resolveNameServiceAddress` for the Sui lists.
//
// Verify with the real method, never `eth_chainId`. Several free endpoints
// answer `eth_chainId` happily and then refuse the calls that matter —
// `1rpc.io/sepolia` returns "chain is not available on free plan" for
// `eth_getTransactionReceipt`, and some publicnode endpoints reject receipt
// lookups as "archive requests". An endpoint that passes a liveness ping but
// fails the real workload is worse than no fallback: it burns a retry and
// surfaces its error as the reason the whole operation failed.

/// Public Ethereum **mainnet** RPC fallbacks (ENS resolution).
pub const ETH_MAINNET_RPC_FALLBACKS: &[&str] =
    &["https://ethereum.publicnode.com", "https://eth.drpc.org"];

/// Public Ethereum **Sepolia** RPC fallbacks.
pub const ETH_SEPOLIA_RPC_FALLBACKS: &[&str] = &[
    "https://ethereum-sepolia-rpc.publicnode.com",
    "https://sepolia.gateway.tenderly.co",
];

/// Public Sui **mainnet** RPC fallbacks (JSON-RPC still enabled).
pub const SUI_MAINNET_RPC_FALLBACKS: &[&str] = &[
    "https://sui-rpc.publicnode.com",
    "https://mainnet.sui.rpcpool.com",
    "https://rpc-mainnet.suiscan.xyz",
    "https://sui-mainnet.nodeinfra.com",
];

/// Public RPC fallbacks for a source chain used in payment verification,
/// keyed by the chain name used in `CHAIN_RPC_*` env vars and announcements.
///
/// Returns an empty slice for an unknown chain, which simply means "no public
/// safety net" — the operator-configured endpoints are then the only ones.
pub fn chain_public_fallbacks(chain: &str) -> &'static [&'static str] {
    match chain {
        "ethereum" => ETH_MAINNET_RPC_FALLBACKS,
        "sepolia" => ETH_SEPOLIA_RPC_FALLBACKS,
        "arbitrum" => &[
            "https://sepolia-rollup.arbitrum.io/rpc",
            "https://arbitrum-sepolia-rpc.publicnode.com",
            "https://arbitrum-sepolia.drpc.org",
        ],
        "monad-testnet" => &[
            "https://testnet-rpc.monad.xyz",
            "https://rpc-testnet.monadinfra.com",
            "https://monad-testnet.drpc.org",
        ],
        "base" => &["https://mainnet.base.org", "https://base.drpc.org"],
        "polygon" => &["https://polygon-bor-rpc.publicnode.com"],
        _ => &[],
    }
}

/// Public Sui **testnet** RPC fallbacks (JSON-RPC still enabled).
pub const SUI_TESTNET_RPC_FALLBACKS: &[&str] = &[
    "https://sui-testnet-rpc.publicnode.com",
    "https://testnet.sui.rpcpool.com",
    "https://sui-testnet-endpoint.blockvision.org",
];

// ═══════════════════════════════════════════════════════════════════════════════
// SERIALIZATION CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Size of serialized MetaAddress v2 (version + secp256k1 spending_pub + ML-KEM viewing_pk).
/// 1 + 33 + 1184 = 1218 bytes
pub const META_ADDRESS_SERIALIZED_SIZE: usize =
    1 + SECP256K1_PUBLIC_KEY_SIZE + KYBER_PUBLIC_KEY_SIZE;

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
        // v2: version (1) + secp256k1 spending_pub (33) + ML-KEM viewing_pk (1184)
        assert_eq!(META_ADDRESS_SERIALIZED_SIZE, 1218);
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
            DOMAIN_STEALTH_TWEAK,
            DOMAIN_META_ENC_KEY,
            DOMAIN_META_ENC_NONCE,
            DOMAIN_DB_HMAC_KEY,
            DOMAIN_DB_PENDING_WRAP,
            DOMAIN_DB_TELEMETRY_SALT,
            DOMAIN_DB_PAYMENT_MAC,
            DOMAIN_DB_IP_HASH,
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
