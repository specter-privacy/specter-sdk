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

/** Serialised meta-address size in bytes (1 + 1184 + 1184). */
export const META_ADDRESS_SIZE = 2369 as const;

/** Uncompressed secp256k1 public key size in bytes (`0x04 || X || Y`). */
export const STEALTH_SECP256K1_PUBLIC_SIZE = 65 as const;

/** secp256k1 private key size in bytes. */
export const STEALTH_ETH_PRIVATE_KEY_SIZE = 32 as const;

/** SPECTER protocol version. */
export const PROTOCOL_VERSION = 1 as const;
