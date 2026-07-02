/**
 * Protocol constants mirrored from the WASM bridge.
 *
 * These values are asserted at runtime in `tests/contract/sizes.test.ts`
 * against the WASM `*Size()` functions, so any drift between the TS layer
 * and the upstream `specter-core::constants` module fails CI.
 */

/** ML-KEM-768 public key size in bytes. */
export const KYBER_PUBLIC_KEY_SIZE = 1184 as const;

/** ML-KEM-768 secret key size in bytes. */
export const KYBER_SECRET_KEY_SIZE = 2400 as const;

/** ML-KEM-768 ciphertext size in bytes. */
export const KYBER_CIPHERTEXT_SIZE = 1088 as const;

/** ML-KEM-768 shared-secret size in bytes. */
export const KYBER_SHARED_SECRET_SIZE = 32 as const;

/** View-tag size in bytes. */
export const VIEW_TAG_SIZE = 1 as const;

/** Ethereum address size in bytes. */
export const ETH_ADDRESS_SIZE = 20 as const;

/** Sui address size in bytes. */
export const SUI_ADDRESS_SIZE = 32 as const;

/** Compressed secp256k1 spending public key size in bytes (`0x02|0x03 || X`). */
export const SPEND_PUBLIC_KEY_SIZE = 33 as const;

/** secp256k1 spending secret key size in bytes. */
export const SPEND_SECRET_KEY_SIZE = 32 as const;

/** Serialised meta-address size in bytes (1 + 33 + 1184 = hybrid v2 layout). */
export const META_ADDRESS_SIZE = 1218 as const;

/**
 * Meta-address wire-format version — the first byte of a serialised
 * meta-address (currently `2`, the hybrid secp256k1-spend + ML-KEM-view
 * layout). This is independent of {@link PROTOCOL_VERSION}: it tracks only the
 * meta-address binary format, not the overall SPECTER protocol revision.
 */
export const META_ADDRESS_VERSION = 2 as const;

/** Uncompressed secp256k1 public key size in bytes (`0x04 || X || Y`). */
export const STEALTH_SECP256K1_PUBLIC_SIZE = 65 as const;

/** secp256k1 private key size in bytes. */
export const STEALTH_ETH_PRIVATE_KEY_SIZE = 32 as const;

/**
 * Overall SPECTER protocol version (currently `1`). Do not confuse this with
 * {@link META_ADDRESS_VERSION} (`2`), which is the meta-address *binary format*
 * version and is bumped independently of the protocol revision.
 */
export const PROTOCOL_VERSION = 1 as const;

/** Plaintext announcement-metadata block size in bytes (1 + 32 + 32 + 8 + 4). */
export const PLAINTEXT_METADATA_SIZE = 77 as const;

/** Encrypted announcement-metadata block size in bytes (1 + 76 + 16). */
export const ENCRYPTED_METADATA_SIZE = 93 as const;

/** Source-chain transaction-hash field size within the metadata block (bytes). */
export const METADATA_TX_HASH_SIZE = 32 as const;

/** Amount (uint256) field size within the metadata block (bytes). */
export const METADATA_AMOUNT_SIZE = 32 as const;

/** Source-chain-id (big-endian u64) field size within the metadata block (bytes). */
export const METADATA_SOURCE_CHAIN_ID_SIZE = 8 as const;
