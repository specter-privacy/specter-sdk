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
/** 2369-byte serialised meta-address. */
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

/** Spending + viewing keypairs that together make up a SPECTER recipient identity. */
export interface SpecterKeys {
  /** Used to derive stealth addresses and stealth private keys. */
  readonly spending: KyberKeyPair;
  /** Used to scan announcements for incoming payments. */
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
  /** Protocol version (currently `1`). */
  readonly version: number;
  /** 1184-byte spending public key. */
  readonly spendingPk: KyberPublicKeyHex;
  /** 1184-byte viewing public key. */
  readonly viewingPk: KyberPublicKeyHex;
  /** Optional metadata (description / avatar / createdAt). */
  readonly metadata?: MetaAddressMetadata;
}

/** Result of `metaAddressFromPublicKeys` and `parseMetaAddress`. */
export interface MetaAddressBundle {
  /** Domain shape suitable for inspection / serialisation. */
  readonly address: MetaAddress;
  /** Canonical 2369-byte serialised payload as a `Uint8Array`. */
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

/** Recipient-side stealth keys: addresses + spendable secp256k1 private key. */
export interface StealthKeys extends StealthAddresses {
  /** 65-byte uncompressed secp256k1 public key. */
  readonly publicKey: StealthSecp256k1PublicHex;
  /**
   * 32-byte secp256k1 private key that controls funds at `ethAddress` (and,
   * with the Sui secp256k1 scheme, `suiAddress`). Non-enumerable at runtime.
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

/** API-backed key generation response mapped into SDK-safe camelCase fields. */
export interface RemoteGeneratedKeys {
  /** Spending + viewing keypairs returned by the trusted SPECTER API. */
  readonly keys: SpecterKeys;
  /** Canonical 2369-byte meta-address from the API. */
  readonly metaAddress: MetaAddressHex;
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

/** Request body for trusted remote scanning. Prefer local scanning when possible. */
export interface RemoteScanRequest {
  readonly announcements?: readonly AnnouncementInput[];
  readonly viewingSk?: KyberSecretKeyHex;
  readonly spendingPk?: KyberPublicKeyHex;
  readonly spendingSk?: KyberSecretKeyHex;
  readonly viewTags?: readonly number[];
  readonly fromTimestamp?: number;
  readonly toTimestamp?: number;
}

/** Discovery DTO returned by the SPECTER API scan endpoint. */
export interface RemoteDiscovery {
  readonly ethAddress?: EthAddressHex;
  readonly suiAddress?: SuiAddressHex;
  readonly ethPrivateKey: StealthEthPrivateHex;
  readonly stealthSk: StealthEthPrivateHex;
  readonly announcementId?: number;
  readonly paymentId?: string;
  readonly timestamp?: number;
}

/** Remote scan response from the SPECTER API. */
export interface RemoteScanResponse {
  readonly discoveries: readonly RemoteDiscovery[];
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
  /** Source-chain transaction hash (32 bytes). */
  readonly txHash?: TxHashHex | Uint8Array;
  /** Payment amount as a 32-byte uint256, or a non-negative bigint. */
  readonly amount?: AmountHex | Uint8Array | bigint;
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
      /** Recipient-side stealth keys for the matching announcement. */
      readonly stealthKeys: StealthKeys;
    };
