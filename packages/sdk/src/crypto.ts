/**
 * Public crypto API of `@specterpq/sdk`.
 *
 * Each function mirrors a single `wasm-bindgen` export under a friendlier
 * name, with three wrappers:
 *
 *   - **Input validation** via the zod schemas in `./validation.ts`.
 *   - **Defensive output validation** via `expectByteLength` so a future
 *     drift between WASM and TS sizes fails closed.
 *   - **Secret redaction** via `defineSecretField` on every secret-bearing
 *     return value (`KyberKeyPair.secretKey`, `EncapsulationResult.sharedSecret`,
 *     `StealthKeys.ethPrivateKey`).
 */

import {
  ENCRYPTED_METADATA_SIZE,
  ETH_ADDRESS_SIZE,
  KYBER_CIPHERTEXT_SIZE,
  KYBER_PUBLIC_KEY_SIZE,
  KYBER_SECRET_KEY_SIZE,
  KYBER_SHARED_SECRET_SIZE,
  META_ADDRESS_SIZE,
  PLAINTEXT_METADATA_SIZE,
  SPEND_PUBLIC_KEY_SIZE,
  SPEND_SECRET_KEY_SIZE,
  STEALTH_ETH_PRIVATE_KEY_SIZE,
  STEALTH_SECP256K1_PUBLIC_SIZE,
  SUI_ADDRESS_SIZE,
} from './constants.js';
import { normalizeError, SpecterSdkError } from './errors.js';
import { asBytes, bytesToHex } from './internal/encoding.js';
import { getWasmSync } from './loader.js';
import { attachRedactingSerializers, defineSecretField } from './internal/redact.js';
import {
  KyberCiphertextInput,
  KyberPublicKeyInput,
  KyberSecretKeyInput,
  MetaAddressBytesInput,
  MetaAddressMetadataInput,
  MetadataPlaintextInput,
  parseHexOrBytes,
  SharedSecretInput,
  SpendPublicKeyInput,
  SpendSecretKeyInput,
  ViewTagInput,
  expectByteLength,
  trySchemaParse,
  type ValidatedMetaAddressMetadata,
} from './validation.js';

import type {
  DetectedStealth,
  EncapsulationResult,
  EncryptedMetadataHex,
  EthAddressHex,
  KyberCiphertextHex,
  KyberKeyPair,
  KyberPublicKeyHex,
  KyberSecretKeyHex,
  MetaAddress,
  MetaAddressBundle,
  MetaAddressHex,
  MetaAddressMetadata,
  MetadataPlaintextHex,
  Secp256k1KeyPair,
  Secp256k1SpendPublicHex,
  Secp256k1SpendSecretHex,
  SharedSecretHex,
  SpecterKeys,
  StealthEthPrivateHex,
  StealthKeys,
  StealthSecp256k1PublicHex,
  SuiAddressHex,
} from './types.js';

/* ----------------------------- Wire shapes ----------------------------- */

// `serde-wasm-bindgen` (with default settings) serialises `Vec<u8>` as a
// plain JS `Array<number>`, not a `Uint8Array`. We coerce on the way in via
// `toBytes` so downstream code can rely on a `Uint8Array`.
type ByteArrayWire = Uint8Array | readonly number[];

interface WireKeyPair {
  public_key: ByteArrayWire;
  secret_key: ByteArrayWire;
}
interface WireSpecterKeys {
  spending: WireKeyPair;
  viewing: WireKeyPair;
}
interface WireEncapsulation {
  ciphertext: ByteArrayWire;
  shared_secret: ByteArrayWire;
}
interface WireDecapsulation {
  shared_secret: ByteArrayWire;
}
interface WireStealthPublic {
  eth_address: ByteArrayWire;
  sui_address: ByteArrayWire;
  public_key: ByteArrayWire;
}
interface WireStealthKeys {
  eth_address: ByteArrayWire;
  sui_address: ByteArrayWire;
  public_key: ByteArrayWire;
  eth_private_key: ByteArrayWire;
}
interface WireMetaAddress {
  version: number;
  spending_pk: ByteArrayWire;
  viewing_pk: ByteArrayWire;
  metadata?: {
    description?: string;
    avatar?: string;
    created_at?: number;
  } | null;
  bytes: ByteArrayWire;
}

/* ----------------------------- Helpers ----------------------------- */

function bridgeCall<T>(fn: () => T): T {
  try {
    return fn();
  } catch (err) {
    throw normalizeError(err);
  }
}

/** Coerce a `Uint8Array` or `Array<number>` from the WASM bridge to `Uint8Array`. */
function toBytes(value: ByteArrayWire): Uint8Array {
  if (value instanceof Uint8Array) return value;
  return Uint8Array.from(value);
}

function buildKeyPair(wire: WireKeyPair): KyberKeyPair {
  const pkBytes = expectByteLength(toBytes(wire.public_key), KYBER_PUBLIC_KEY_SIZE, 'public_key');
  const skBytes = expectByteLength(toBytes(wire.secret_key), KYBER_SECRET_KEY_SIZE, 'secret_key');
  const publicKey = bytesToHex<'KyberPublicKey'>(pkBytes);
  const secretKey = bytesToHex<'KyberSecretKey'>(skBytes);
  const out = { publicKey } as { publicKey: KyberPublicKeyHex; secretKey: KyberSecretKeyHex };
  defineSecretField(out, 'secretKey', secretKey);
  attachRedactingSerializers(out, ['secretKey']);
  return out;
}

function buildSpendKeyPair(wire: WireKeyPair): Secp256k1KeyPair {
  const pkBytes = expectByteLength(
    toBytes(wire.public_key),
    SPEND_PUBLIC_KEY_SIZE,
    'spending_pk',
  );
  const skBytes = expectByteLength(
    toBytes(wire.secret_key),
    SPEND_SECRET_KEY_SIZE,
    'spending_sk',
  );
  const publicKey = bytesToHex<'Secp256k1SpendPublic'>(pkBytes);
  const secretKey = bytesToHex<'Secp256k1SpendSecret'>(skBytes);
  const out = { publicKey } as {
    publicKey: Secp256k1SpendPublicHex;
    secretKey: Secp256k1SpendSecretHex;
  };
  defineSecretField(out, 'secretKey', secretKey);
  attachRedactingSerializers(out, ['secretKey']);
  return out;
}

/* ----------------------------- Keygen ----------------------------- */

/** Generate a single ML-KEM-768 keypair (used for the viewing role). */
export function generateKeysLocal(): KyberKeyPair {
  const wasm = getWasmSync();
  const wire = bridgeCall<WireKeyPair>(() => wasm.generateKeys() as WireKeyPair);
  return buildKeyPair(wire);
}

/** Generate a single secp256k1 spending keypair. */
export function generateSpendKey(): Secp256k1KeyPair {
  const wasm = getWasmSync();
  const wire = bridgeCall<WireKeyPair>(() => wasm.generateSpendKey() as WireKeyPair);
  return buildSpendKeyPair(wire);
}

/** Generate a complete SPECTER recipient identity (secp256k1 spending + ML-KEM viewing). */
export function generateSpecterKeys(): SpecterKeys {
  const wasm = getWasmSync();
  const wire = bridgeCall<WireSpecterKeys>(() => wasm.generateSpecterKeys() as WireSpecterKeys);
  return {
    spending: buildSpendKeyPair(wire.spending),
    viewing: buildKeyPair(wire.viewing),
  };
}

/* ----------------------------- KEM ----------------------------- */

/** Encapsulate a fresh shared secret to a recipient's ML-KEM-768 public key. */
export function encapsulate(publicKey: KyberPublicKeyHex | Uint8Array): EncapsulationResult {
  const wasm = getWasmSync();
  const pkBytes = parseHexOrBytes(
    KyberPublicKeyInput,
    publicKey,
    'public_key',
    KYBER_PUBLIC_KEY_SIZE,
  );
  const wire = bridgeCall<WireEncapsulation>(
    () => wasm.encapsulate(pkBytes) as WireEncapsulation,
  );
  const ctBytes = expectByteLength(
    toBytes(wire.ciphertext),
    KYBER_CIPHERTEXT_SIZE,
    'ciphertext',
  );
  const ssBytes = expectByteLength(
    toBytes(wire.shared_secret),
    KYBER_SHARED_SECRET_SIZE,
    'shared_secret',
  );
  const out = { ciphertext: bytesToHex<'KyberCiphertext'>(ctBytes) } as {
    ciphertext: KyberCiphertextHex;
    sharedSecret: SharedSecretHex;
  };
  defineSecretField(out, 'sharedSecret', bytesToHex<'SharedSecret'>(ssBytes));
  attachRedactingSerializers(out, ['sharedSecret']);
  return out;
}

/** Recover the shared secret from a ciphertext using the matching secret key. */
export function decapsulate(
  ciphertext: KyberCiphertextHex | Uint8Array,
  secretKey: KyberSecretKeyHex | Uint8Array,
): SharedSecretHex {
  const wasm = getWasmSync();
  const ctBytes = parseHexOrBytes(
    KyberCiphertextInput,
    ciphertext,
    'ciphertext',
    KYBER_CIPHERTEXT_SIZE,
  );
  const skBytes = parseHexOrBytes(
    KyberSecretKeyInput,
    secretKey,
    'secret_key',
    KYBER_SECRET_KEY_SIZE,
  );
  const wire = bridgeCall<WireDecapsulation>(
    () => wasm.decapsulate(ctBytes, skBytes) as WireDecapsulation,
  );
  const ssBytes = expectByteLength(
    toBytes(wire.shared_secret),
    KYBER_SHARED_SECRET_SIZE,
    'shared_secret',
  );
  return bytesToHex<'SharedSecret'>(ssBytes);
}

/* ----------------------------- View tag ----------------------------- */

/** Compute the 1-byte view tag for a 32-byte shared secret. */
export function computeViewTag(sharedSecret: SharedSecretHex | Uint8Array): number {
  const wasm = getWasmSync();
  const ssBytes = parseHexOrBytes(
    SharedSecretInput,
    sharedSecret,
    'shared_secret',
    KYBER_SHARED_SECRET_SIZE,
  );
  return bridgeCall<number>(() => wasm.computeViewTag(ssBytes));
}

/** Constant-time compare an expected view tag against the one derived from `sharedSecret`. */
export function verifyViewTag(
  sharedSecret: SharedSecretHex | Uint8Array,
  expectedTag: number,
): boolean {
  const wasm = getWasmSync();
  const ssBytes = parseHexOrBytes(
    SharedSecretInput,
    sharedSecret,
    'shared_secret',
    KYBER_SHARED_SECRET_SIZE,
  );
  const tag = trySchemaParse(ViewTagInput, expectedTag, 'expected_tag') as number;
  return bridgeCall<boolean>(() => wasm.verifyViewTag(ssBytes, tag));
}

/* ----------------------------- Derivation ----------------------------- */

/**
 * Derive only the stealth Ethereum address from the recipient's **public**
 * spending key. This is the sender path and the watch-only detection path; it
 * yields the address but never the private key.
 */
export function deriveStealthAddress(
  spendingPk: Secp256k1SpendPublicHex | Uint8Array,
  sharedSecret: SharedSecretHex | Uint8Array,
): EthAddressHex {
  const wasm = getWasmSync();
  const pkBytes = parseHexOrBytes(
    SpendPublicKeyInput,
    spendingPk,
    'spending_pk',
    SPEND_PUBLIC_KEY_SIZE,
  );
  const ssBytes = parseHexOrBytes(
    SharedSecretInput,
    sharedSecret,
    'shared_secret',
    KYBER_SHARED_SECRET_SIZE,
  );
  const out = bridgeCall<ByteArrayWire>(
    () => wasm.deriveStealthAddress(pkBytes, ssBytes) as ByteArrayWire,
  );
  const ethBytes = expectByteLength(toBytes(out), ETH_ADDRESS_SIZE, 'eth_address');
  return bytesToHex<'EthAddress'>(ethBytes);
}

/** Derive only the stealth Sui address from the recipient's **public** spending key. */
export function deriveStealthSuiAddress(
  spendingPk: Secp256k1SpendPublicHex | Uint8Array,
  sharedSecret: SharedSecretHex | Uint8Array,
): SuiAddressHex {
  const wasm = getWasmSync();
  const pkBytes = parseHexOrBytes(
    SpendPublicKeyInput,
    spendingPk,
    'spending_pk',
    SPEND_PUBLIC_KEY_SIZE,
  );
  const ssBytes = parseHexOrBytes(
    SharedSecretInput,
    sharedSecret,
    'shared_secret',
    KYBER_SHARED_SECRET_SIZE,
  );
  const out = bridgeCall<ByteArrayWire>(
    () => wasm.deriveStealthSuiAddress(pkBytes, ssBytes) as ByteArrayWire,
  );
  const suiBytes = expectByteLength(toBytes(out), SUI_ADDRESS_SIZE, 'sui_address');
  return bytesToHex<'SuiAddress'>(suiBytes);
}

/**
 * Derive both stealth addresses **and** the stealth public key from the
 * recipient's **public** spending key. Contains no secret material — this is
 * the sender path and the watch-only detection path.
 */
export function deriveStealthPublic(
  spendingPk: Secp256k1SpendPublicHex | Uint8Array,
  sharedSecret: SharedSecretHex | Uint8Array,
): DetectedStealth {
  const wasm = getWasmSync();
  const pkBytes = parseHexOrBytes(
    SpendPublicKeyInput,
    spendingPk,
    'spending_pk',
    SPEND_PUBLIC_KEY_SIZE,
  );
  const ssBytes = parseHexOrBytes(
    SharedSecretInput,
    sharedSecret,
    'shared_secret',
    KYBER_SHARED_SECRET_SIZE,
  );
  const wire = bridgeCall<WireStealthPublic>(
    () => wasm.deriveStealthPublic(pkBytes, ssBytes) as WireStealthPublic,
  );
  const ethBytes = expectByteLength(toBytes(wire.eth_address), ETH_ADDRESS_SIZE, 'eth_address');
  const suiBytes = expectByteLength(toBytes(wire.sui_address), SUI_ADDRESS_SIZE, 'sui_address');
  const pubBytes = expectByteLength(
    toBytes(wire.public_key),
    STEALTH_SECP256K1_PUBLIC_SIZE,
    'public_key',
  );
  return {
    ethAddress: bytesToHex<'EthAddress'>(ethBytes),
    suiAddress: bytesToHex<'SuiAddress'>(suiBytes),
    publicKey: bytesToHex<'StealthSecp256k1Public'>(pubBytes),
  };
}

/**
 * Derive the stealth addresses **and** the spendable secp256k1 private key from
 * the recipient's **secret** spending key. Only the holder of the spending
 * secret can call this — passing a public key throws `INVALID_KEY_SIZE`.
 */
export function deriveStealthKeys(
  spendingSk: Secp256k1SpendSecretHex | Uint8Array,
  sharedSecret: SharedSecretHex | Uint8Array,
): StealthKeys {
  const wasm = getWasmSync();
  const skBytes = parseHexOrBytes(
    SpendSecretKeyInput,
    spendingSk,
    'spending_sk',
    SPEND_SECRET_KEY_SIZE,
  );
  const ssBytes = parseHexOrBytes(
    SharedSecretInput,
    sharedSecret,
    'shared_secret',
    KYBER_SHARED_SECRET_SIZE,
  );
  const wire = bridgeCall<WireStealthKeys>(
    () => wasm.deriveStealthKeys(skBytes, ssBytes) as WireStealthKeys,
  );
  const ethBytes = expectByteLength(toBytes(wire.eth_address), ETH_ADDRESS_SIZE, 'eth_address');
  const suiBytes = expectByteLength(toBytes(wire.sui_address), SUI_ADDRESS_SIZE, 'sui_address');
  const pubBytes = expectByteLength(
    toBytes(wire.public_key),
    STEALTH_SECP256K1_PUBLIC_SIZE,
    'public_key',
  );
  const privBytes = expectByteLength(
    toBytes(wire.eth_private_key),
    STEALTH_ETH_PRIVATE_KEY_SIZE,
    'eth_private_key',
  );

  const out = {
    ethAddress: bytesToHex<'EthAddress'>(ethBytes),
    suiAddress: bytesToHex<'SuiAddress'>(suiBytes),
    publicKey: bytesToHex<'StealthSecp256k1Public'>(pubBytes),
  } as {
    ethAddress: EthAddressHex;
    suiAddress: SuiAddressHex;
    publicKey: StealthSecp256k1PublicHex;
    ethPrivateKey: StealthEthPrivateHex;
  };
  defineSecretField(out, 'ethPrivateKey', bytesToHex<'StealthEthPrivate'>(privBytes));
  attachRedactingSerializers(out, ['ethPrivateKey']);
  return out;
}

/* ----------------------------- Meta-address ----------------------------- */

/**
 * Build a meta-address from a secp256k1 spending public key (33 bytes), an
 * ML-KEM-768 viewing public key (1184 bytes), and optional metadata.
 */
export function metaAddressFromPublicKeys(
  spendingPk: Secp256k1SpendPublicHex | Uint8Array,
  viewingPk: KyberPublicKeyHex | Uint8Array,
  metadata?: MetaAddressMetadata,
): MetaAddressBundle {
  const wasm = getWasmSync();
  const spending = parseHexOrBytes(
    SpendPublicKeyInput,
    spendingPk,
    'spending_pk',
    SPEND_PUBLIC_KEY_SIZE,
  );
  const viewing = parseHexOrBytes(
    KyberPublicKeyInput,
    viewingPk,
    'viewing_pk',
    KYBER_PUBLIC_KEY_SIZE,
  );

  let metadataJson: string | undefined;
  if (metadata !== undefined) {
    const validated = trySchemaParse(
      MetaAddressMetadataInput,
      metadata,
      'metadata',
    ) as ValidatedMetaAddressMetadata;
    // The Rust side uses snake_case `created_at`.
    const wire = {
      ...(validated.description !== undefined ? { description: validated.description } : {}),
      ...(validated.avatar !== undefined ? { avatar: validated.avatar } : {}),
      ...(validated.createdAt !== undefined ? { created_at: validated.createdAt } : {}),
    };
    metadataJson = JSON.stringify(wire);
  }

  const wire = bridgeCall<WireMetaAddress>(
    () =>
      wasm.metaAddressFromPublicKeys(spending, viewing, metadataJson) as WireMetaAddress,
  );
  return wireMetaToBundle(wire);
}

/** Parse a 2369-byte serialised meta-address. */
export function parseMetaAddress(input: MetaAddressHex | Uint8Array): MetaAddressBundle {
  const wasm = getWasmSync();
  let bytes: Uint8Array;
  if (input instanceof Uint8Array) {
    bytes = expectByteLength(
      asBytes(input, { lengthBytes: META_ADDRESS_SIZE, field: 'meta_address' }),
      META_ADDRESS_SIZE,
      'meta_address',
    );
  } else {
    bytes = parseHexOrBytes(MetaAddressBytesInput, input, 'meta_address', META_ADDRESS_SIZE);
  }

  const wire = bridgeCall<WireMetaAddress>(
    () => wasm.parseMetaAddress(bytes) as WireMetaAddress,
  );
  return wireMetaToBundle(wire);
}

function wireMetaToBundle(wire: WireMetaAddress): MetaAddressBundle {
  const spendingBytes = expectByteLength(
    toBytes(wire.spending_pk),
    SPEND_PUBLIC_KEY_SIZE,
    'spending_pk',
  );
  const viewingBytes = expectByteLength(
    toBytes(wire.viewing_pk),
    KYBER_PUBLIC_KEY_SIZE,
    'viewing_pk',
  );
  const metaBytes = expectByteLength(
    toBytes(wire.bytes),
    META_ADDRESS_SIZE,
    'meta_address bytes',
  );

  if (typeof wire.version !== 'number' || wire.version < 0 || wire.version > 255) {
    throw new SpecterSdkError(
      'INVALID_META_ADDRESS',
      `meta-address version out of range: ${String(wire.version)}`,
    );
  }

  const metadata: MetaAddressMetadata | undefined = wire.metadata
    ? {
        ...(wire.metadata.description !== undefined
          ? { description: wire.metadata.description }
          : {}),
        ...(wire.metadata.avatar !== undefined ? { avatar: wire.metadata.avatar } : {}),
        ...(wire.metadata.created_at !== undefined
          ? { createdAt: wire.metadata.created_at }
          : {}),
      }
    : undefined;

  const address: MetaAddress = {
    version: wire.version,
    spendingPk: bytesToHex<'Secp256k1SpendPublic'>(spendingBytes),
    viewingPk: bytesToHex<'KyberPublicKey'>(viewingBytes),
    ...(metadata !== undefined ? { metadata } : {}),
  };

  return {
    address,
    bytes: metaBytes,
    hex: bytesToHex<'MetaAddress'>(metaBytes),
  };
}

/* ----------------------- Announcement metadata ----------------------- */

/**
 * Encrypt a 77-byte plaintext metadata block with AES-256-GCM, keyed from the
 * ML-KEM shared secret. Returns the 93-byte encrypted block as hex.
 *
 * This is the low-level primitive; most callers should use
 * `sealAnnouncementMetadata`, which builds the plaintext for you and derives
 * the correct view-tag from the shared secret.
 */
export function encryptAnnouncementMetadata(
  plaintext: MetadataPlaintextHex | Uint8Array,
  sharedSecret: SharedSecretHex | Uint8Array,
): EncryptedMetadataHex {
  const wasm = getWasmSync();
  const ptBytes = parseHexOrBytes(
    MetadataPlaintextInput,
    plaintext,
    'metadata_plaintext',
    PLAINTEXT_METADATA_SIZE,
  );
  const ssBytes = parseHexOrBytes(
    SharedSecretInput,
    sharedSecret,
    'shared_secret',
    KYBER_SHARED_SECRET_SIZE,
  );
  const out = bridgeCall<ByteArrayWire>(
    () => wasm.encryptAnnouncementMetadata(ptBytes, ssBytes) as ByteArrayWire,
  );
  const encBytes = expectByteLength(toBytes(out), ENCRYPTED_METADATA_SIZE, 'encrypted_metadata');
  return bytesToHex<'EncryptedMetadata'>(encBytes);
}

/**
 * Decrypt a 93-byte (or longer) encrypted metadata block, returning the
 * recovered 77-byte plaintext. Throws `METADATA_DECRYPTION_FAILED` when the
 * authentication tag does not verify — the expected outcome for ~255/256
 * non-matching announcements.
 *
 * This is the low-level primitive; most callers should use
 * `openAnnouncementMetadata`, which also decodes the structured fields.
 */
export function decryptAnnouncementMetadata(
  encrypted: EncryptedMetadataHex | Uint8Array,
  sharedSecret: SharedSecretHex | Uint8Array,
): Uint8Array {
  const wasm = getWasmSync();
  const encBytes = asBytes(encrypted, { field: 'encrypted_metadata' });
  if (encBytes.length < ENCRYPTED_METADATA_SIZE) {
    throw new SpecterSdkError(
      'INVALID_METADATA_SIZE',
      `encrypted_metadata: expected at least ${ENCRYPTED_METADATA_SIZE} bytes, got ${encBytes.length}`,
    );
  }
  const ssBytes = parseHexOrBytes(
    SharedSecretInput,
    sharedSecret,
    'shared_secret',
    KYBER_SHARED_SECRET_SIZE,
  );
  const out = bridgeCall<ByteArrayWire>(
    () => wasm.decryptAnnouncementMetadata(encBytes, ssBytes) as ByteArrayWire,
  );
  return expectByteLength(toBytes(out), PLAINTEXT_METADATA_SIZE, 'metadata_plaintext');
}
