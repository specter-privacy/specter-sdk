/**
 * Shared TypeScript types for `@specterpq/sdk`.
 *
 * All cryptographic byte strings are represented as branded `Hex<T>` strings.
 * The brand is purely structural (TypeScript-only, no runtime cost) but
 * prevents accidentally passing a `KyberPublicKeyHex` where a
 * `KyberCiphertextHex` is expected.
 */

/** Phantom-typed lowercase hex string with `0x` prefix. */
export type Hex<Brand extends string = string> = `0x${string}` & {
  readonly __specterBrand: Brand;
};

/** ML-KEM-768 public key (1184 bytes = 2370 hex chars after the `0x`). */
export type KyberPublicKeyHex = Hex<'KyberPublicKey'>;
/** ML-KEM-768 secret key (2400 bytes = 4802 hex chars after the `0x`). */
export type KyberSecretKeyHex = Hex<'KyberSecretKey'>;
/** Compressed secp256k1 spending public key (33 bytes = 66 hex chars). */
export type Secp256k1SpendPublicHex = Hex<'Secp256k1SpendPublic'>;
/** secp256k1 spending secret key (32 bytes = 64 hex chars). */
export type Secp256k1SpendSecretHex = Hex<'Secp256k1SpendSecret'>;
/** ML-KEM-768 ciphertext (1088 bytes = 2178 hex chars after the `0x`). */
export type KyberCiphertextHex = Hex<'KyberCiphertext'>;
/** 32-byte shared secret (64 hex chars after the `0x`). */
export type SharedSecretHex = Hex<'SharedSecret'>;
/** 20-byte Ethereum address (40 hex chars after the `0x`). */
export type EthAddressHex = Hex<'EthAddress'>;
/** 32-byte Sui address (64 hex chars after the `0x`). */
export type SuiAddressHex = Hex<'SuiAddress'>;
/** 65-byte uncompressed secp256k1 public key (`0x04 || X || Y`). */
export type StealthSecp256k1PublicHex = Hex<'StealthSecp256k1Public'>;
/** 32-byte secp256k1 private key. */
export type StealthEthPrivateHex = Hex<'StealthEthPrivate'>;
/** 1218-byte serialised meta-address. */
export type MetaAddressHex = Hex<'MetaAddress'>;
/** 93-byte encrypted announcement-metadata block. */
export type EncryptedMetadataHex = Hex<'EncryptedMetadata'>;
/** 77-byte plaintext announcement-metadata block. */
export type MetadataPlaintextHex = Hex<'MetadataPlaintext'>;
/** 32-byte source-chain transaction hash. */
export type TxHashHex = Hex<'TxHash'>;
/** 32-byte uint256 payment amount (big-endian). */
export type AmountHex = Hex<'Amount'>;

/** A SPECTER ML-KEM-768 keypair. The TS layer marks `secretKey` non-enumerable. */
export interface KyberKeyPair {
  /** Public key (safe to share). */
  readonly publicKey: KyberPublicKeyHex;
  /** Secret key (never log this). Non-enumerable in the runtime object. */
  readonly secretKey: KyberSecretKeyHex;
}

/**
 * A secp256k1 spending keypair. It controls funds on Ethereum/Sui and is the
 * base point for the stealth address tweak. The TS layer marks `secretKey`
 * non-enumerable.
 */
export interface Secp256k1KeyPair {
  /** 33-byte compressed public key (safe to publish in a meta-address). */
  readonly publicKey: Secp256k1SpendPublicHex;
  /** 32-byte secret key (never log this). Non-enumerable in the runtime object. */
  readonly secretKey: Secp256k1SpendSecretHex;
}

/**
 * A SPECTER recipient identity: a secp256k1 spending keypair plus an ML-KEM-768
 * viewing keypair.
 *
 * - `spending` controls funds and is the tweak base point. Only the holder of
 *   `spending.secretKey` can compute a stealth private key.
 * - `viewing` provides post-quantum scanning: detection needs only
 *   `viewing.secretKey` and the *public* `spending.publicKey`, so scanning can
 *   run on a device that never sees the spending secret.
 */
export interface SpecterKeys {
  /** secp256k1 spending keypair (controls funds; stealth tweak base point). */
  readonly spending: Secp256k1KeyPair;
  /** ML-KEM-768 viewing keypair (used to scan announcements). */
  readonly viewing: KyberKeyPair;
}

/** Optional metadata attached to a meta-address. */
export interface MetaAddressMetadata {
  /** Free-form description, e.g. an alias. */
  readonly description?: string;
  /** Avatar URL or IPFS CID. */
  readonly avatar?: string;
  /** Creation timestamp in Unix seconds. */
  readonly createdAt?: number;
}

/** Domain shape of a SPECTER meta-address (the publishable recipient identity). */
export interface MetaAddress {
  /** Wire-format version (currently `2` — hybrid secp256k1 + ML-KEM). */
  readonly version: number;
  /** 33-byte compressed secp256k1 spending public key. */
  readonly spendingPk: Secp256k1SpendPublicHex;
  /** 1184-byte ML-KEM-768 viewing public key. */
  readonly viewingPk: KyberPublicKeyHex;
  /** Optional metadata (description / avatar / createdAt). */
  readonly metadata?: MetaAddressMetadata;
}

/** Result of `metaAddressFromPublicKeys` and `parseMetaAddress`. */
export interface MetaAddressBundle {
  /** Domain shape suitable for inspection / serialisation. */
  readonly address: MetaAddress;
  /** Canonical 1218-byte serialised payload as a `Uint8Array`. */
  readonly bytes: Uint8Array;
  /** Same payload as a `0x`-prefixed hex string for ENS / SuiNS text records. */
  readonly hex: MetaAddressHex;
}

/** Output of `encapsulate`. The `sharedSecret` is non-enumerable at runtime. */
export interface EncapsulationResult {
  /** Ephemeral 1088-byte ciphertext to publish in the announcement. */
  readonly ciphertext: KyberCiphertextHex;
  /** 32-byte shared secret to use for stealth derivation locally. */
  readonly sharedSecret: SharedSecretHex;
}

/** The pair of stealth addresses for a single payment. */
export interface StealthAddresses {
  /** 20-byte Ethereum address. */
  readonly ethAddress: EthAddressHex;
  /** 32-byte Sui address. */
  readonly suiAddress: SuiAddressHex;
}

/**
 * Detection-only stealth data: the addresses plus the stealth public key,
 * computable from the recipient's *public* spend key. Contains no secret and
 * is what a watch-only scanner (viewing secret + spending public) receives.
 */
export interface DetectedStealth extends StealthAddresses {
  /** 65-byte uncompressed secp256k1 stealth public key. */
  readonly publicKey: StealthSecp256k1PublicHex;
}

/** Recipient-side stealth keys: detection data + spendable secp256k1 private key. */
export interface StealthKeys extends DetectedStealth {
  /**
   * 32-byte secp256k1 private key that controls funds at `ethAddress` (and,
   * with the Sui secp256k1 scheme, `suiAddress`). Only derivable from the
   * spending *secret* key. Non-enumerable at runtime.
   */
  readonly ethPrivateKey: StealthEthPrivateHex;
}

/** Output of the high-level `createStealthPayment` helper (sender side). */
export interface StealthPayment extends StealthAddresses {
  /** Ephemeral 1088-byte ciphertext for the announcement. */
  readonly ephemeralCiphertext: KyberCiphertextHex;
  /** 1-byte view-tag (0..255) for fast recipient filtering. */
  readonly viewTag: number;
}

/** Announcement DTO returned by the SPECTER API. */
export interface AnnouncementDto {
  readonly id?: number;
  readonly ephemeralCiphertext: KyberCiphertextHex;
  readonly viewTag: number;
  readonly timestamp?: number;
  readonly channelId?: Hex<'ChannelId'>;
  readonly blockNumber?: number;
  readonly txHash?: string;
  readonly amount?: string;
  readonly chain?: string;
}

/** API-backed payment creation response. */
export interface RemoteStealthPayment extends StealthPayment {
  /** Server-side pending payment identifier used for authoritative publish. */
  readonly paymentId: string;
  /** Full announcement backup returned by the API, when available. */
  readonly announcement?: AnnouncementDto;
}

/** Input for the server-authoritative registry publish path. */
export interface PublishAnnouncementInput {
  readonly paymentId: string;
  readonly txHash?: string;
  readonly blockNumber?: number;
  readonly amount?: string;
  readonly chain?: string;
}

/** Registry publish response from the SPECTER API. */
export interface PublishAnnouncementResponse {
  readonly announcementId?: number;
  readonly announcement?: AnnouncementDto;
}

/**
 * Decoded announcement metadata (the 77-byte on-chain block, parsed).
 *
 * Optional fields are `undefined` when the corresponding wire bytes are all
 * zero (the upstream "absent" encoding).
 */
export interface AnnouncementMetadata {
  /** 1-byte view tag (0..255). Byte 0 of the block; never encrypted. */
  readonly viewTag: number;
  /** 32-byte source-chain transaction hash, if present. */
  readonly txHash?: TxHashHex;
  /** 32-byte uint256 payment amount (big-endian hex), if present. */
  readonly amount?: AmountHex;
  /** EIP-155 source chain id (e.g. 42161 = Arbitrum), if present. */
  readonly sourceChainId?: number;
}

/**
 * Fields a sender can attach to an announcement. The `viewTag` is derived
 * automatically from the shared secret by `sealAnnouncementMetadata`, so it
 * is not part of this input.
 *
 * - `txHash` / `amount` accept a 32-byte `Uint8Array` or `0x` hex string.
 * - `amount` additionally accepts a non-negative `bigint` (encoded as a
 *   32-byte big-endian uint256).
 */
export interface AnnouncementMetadataInput {
  /** Source-chain transaction hash: a 32-byte `0x` hex string or `Uint8Array`. */
  readonly txHash?: `0x${string}` | Uint8Array;
  /**
   * Payment amount: a 32-byte uint256 as a `0x` hex string / `Uint8Array`, or a
   * non-negative `bigint`.
   */
  readonly amount?: `0x${string}` | Uint8Array | bigint;
  /** EIP-155 source chain id (non-negative safe integer). */
  readonly sourceChainId?: number;
}

/** Single announcement input shape used by `scanAnnouncement`. */
export interface AnnouncementInput {
  /** Ephemeral ML-KEM-768 ciphertext (1088 bytes). */
  readonly ephemeralCiphertext: KyberCiphertextHex;
  /** 1-byte view-tag (0..255). */
  readonly viewTag: number;
}

/** Result of `scanAnnouncement`. Match is `false` after a view-tag-fail or address mismatch. */
export type ScanResult =
  | {
      readonly isMatch: false;
      /**
       * Reason a non-match was returned, useful for diagnostics. The shape is
       * stable; new variants will only ever be added.
       */
      readonly reason: 'view_tag_mismatch' | 'address_mismatch';
    }
  | {
      readonly isMatch: true;
      /**
       * Detection data (addresses + stealth public key). Always present on a
       * match; derived from the *public* spend key, so it contains no secret.
       */
      readonly detected: DetectedStealth;
      /**
       * Full spendable keys, including the secp256k1 private key. Present only
       * when a spending *secret* key was supplied to `scanAnnouncement`; a
       * watch-only scan (viewing secret + spending public only) leaves this
       * `undefined`.
       */
      readonly stealthKeys?: StealthKeys;
    };
