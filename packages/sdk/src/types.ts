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
