/**
 * Announcement-metadata helpers.
 *
 * SPECTER announcements can carry a fixed 77-byte metadata block describing
 * the payment. The block layout (matching the SPECTERAnnouncer contract) is:
 *
 * ```text
 * [0]      view_tag        1B   (kept in the clear for scanner filtering)
 * [1..33]  tx_hash         32B  (all-zero = absent)
 * [33..65] amount          32B  uint256 big-endian (all-zero = absent)
 * [65..73] source_chain_id 8B   big-endian u64 (0 = absent)
 * [73..77] reserved        4B   (always zero)
 * ```
 *
 * The encode/decode of this layout is pure byte manipulation and lives here in
 * TypeScript. The AES-256-GCM encryption of bytes `[1..77]` lives in the WASM
 * bridge (`crypto.ts`), keyed from the ML-KEM shared secret.
 *
 * The high-level pair — `sealAnnouncementMetadata` / `openAnnouncementMetadata`
 * — is what most integrations want: build + encrypt on the sender side, and
 * decrypt + decode on the recipient side.
 */

import {
  KYBER_SHARED_SECRET_SIZE,
  METADATA_AMOUNT_SIZE,
  METADATA_TX_HASH_SIZE,
  PLAINTEXT_METADATA_SIZE,
} from './constants.js';
import {
  computeViewTag,
  decryptAnnouncementMetadata,
  encryptAnnouncementMetadata,
} from './crypto.js';
import { SpecterSdkError } from './errors.js';
import { asBytes, bytesToHex } from './internal/encoding.js';
import {
  AmountBytesInput,
  parseHexOrBytes,
  SharedSecretInput,
  SourceChainIdInput,
  TxHashInput,
  trySchemaParse,
  ViewTagInput,
} from './validation.js';

import type {
  AmountHex,
  AnnouncementMetadata,
  AnnouncementMetadataInput,
  EncryptedMetadataHex,
  MetadataPlaintextHex,
  SharedSecretHex,
} from './types.js';

/* Field offsets within the 77-byte block. */
const VIEW_TAG_OFFSET = 0;
const TX_HASH_OFFSET = 1;
const AMOUNT_OFFSET = TX_HASH_OFFSET + METADATA_TX_HASH_SIZE; // 33
const CHAIN_ID_OFFSET = AMOUNT_OFFSET + METADATA_AMOUNT_SIZE; // 65
// Bytes [73..77] are the reserved field and stay zero.

const MAX_UINT256 = (1n << 256n) - 1n;

/** Input accepted by `encodeAnnouncementMetadata`: the fields plus an explicit view tag. */
export interface EncodeMetadataInput extends AnnouncementMetadataInput {
  /** 1-byte view tag (0..255). Use `computeViewTag` to derive it. */
  readonly viewTag: number;
}

/** Convert a uint256 amount (bytes / hex / bigint) into a 32-byte big-endian buffer. */
function amountToBytes(amount: AmountHex | Uint8Array | bigint): Uint8Array {
  if (typeof amount === 'bigint') {
    if (amount < 0n || amount > MAX_UINT256) {
      throw new SpecterSdkError(
        'INVALID_METADATA_FIELD',
        `amount: must be between 0 and 2^256-1, got ${amount.toString()}`,
      );
    }
    const out = new Uint8Array(METADATA_AMOUNT_SIZE);
    let v = amount;
    for (let i = METADATA_AMOUNT_SIZE - 1; i >= 0; i -= 1) {
      out[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    return out;
  }
  return parseHexOrBytes(AmountBytesInput, amount, 'amount', METADATA_AMOUNT_SIZE);
}

function isAllZero(bytes: Uint8Array): boolean {
  for (const b of bytes) {
    if (b !== 0) return false;
  }
  return true;
}

/**
 * Encode structured metadata fields into the canonical 77-byte block.
 *
 * Absent optional fields are encoded as all-zero, matching the upstream wire
 * format. The returned buffer is ready to pass to `encryptAnnouncementMetadata`.
 */
export function encodeAnnouncementMetadata(input: EncodeMetadataInput): Uint8Array {
  const viewTag = trySchemaParse(ViewTagInput, input.viewTag, 'view_tag') as number;

  const buf = new Uint8Array(PLAINTEXT_METADATA_SIZE);
  buf[VIEW_TAG_OFFSET] = viewTag;

  if (input.txHash !== undefined) {
    const txHash = parseHexOrBytes(TxHashInput, input.txHash, 'tx_hash', METADATA_TX_HASH_SIZE);
    buf.set(txHash, TX_HASH_OFFSET);
  }

  if (input.amount !== undefined) {
    buf.set(amountToBytes(input.amount), AMOUNT_OFFSET);
  }

  if (input.sourceChainId !== undefined) {
    const chainId = trySchemaParse(
      SourceChainIdInput,
      input.sourceChainId,
      'source_chain_id',
    ) as number;
    const view = new DataView(buf.buffer, buf.byteOffset, PLAINTEXT_METADATA_SIZE);
    view.setBigUint64(CHAIN_ID_OFFSET, BigInt(chainId), false);
  }

  // Bytes [73..77] (the reserved field) stay zero.

  return buf;
}

/**
 * Decode a 77-byte (or longer) metadata block into structured fields.
 *
 * Optional fields whose bytes are all-zero are returned as `undefined`. Only
 * the first 77 bytes are read; trailing bytes are ignored.
 */
export function decodeAnnouncementMetadata(
  raw: MetadataPlaintextHex | Uint8Array,
): AnnouncementMetadata {
  const bytes = asBytes(raw, { field: 'metadata_plaintext' });
  if (bytes.length < PLAINTEXT_METADATA_SIZE) {
    throw new SpecterSdkError(
      'INVALID_METADATA_SIZE',
      `metadata_plaintext: expected at least ${PLAINTEXT_METADATA_SIZE} bytes, got ${bytes.length}`,
    );
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, PLAINTEXT_METADATA_SIZE);
  const viewTag = view.getUint8(VIEW_TAG_OFFSET);

  const txHashBytes = bytes.subarray(TX_HASH_OFFSET, AMOUNT_OFFSET);
  const amountBytes = bytes.subarray(AMOUNT_OFFSET, CHAIN_ID_OFFSET);
  const chainIdBig = view.getBigUint64(CHAIN_ID_OFFSET, false);

  if (chainIdBig > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new SpecterSdkError(
      'INVALID_METADATA_FIELD',
      `source_chain_id: ${chainIdBig.toString()} exceeds the safe-integer range`,
    );
  }

  return {
    viewTag,
    ...(isAllZero(txHashBytes) ? {} : { txHash: bytesToHex<'TxHash'>(txHashBytes) }),
    ...(isAllZero(amountBytes) ? {} : { amount: bytesToHex<'Amount'>(amountBytes) }),
    ...(chainIdBig === 0n ? {} : { sourceChainId: Number(chainIdBig) }),
  };
}

/**
 * Sender-side: build the metadata block for `input`, derive the correct view
 * tag from `sharedSecret`, and encrypt it. Returns the 93-byte block as hex,
 * ready to embed in an on-chain announcement.
 *
 * The view tag is always derived from the shared secret (never caller-supplied)
 * so scanners can filter on it without decrypting.
 */
export function sealAnnouncementMetadata(
  input: AnnouncementMetadataInput,
  sharedSecret: SharedSecretHex | Uint8Array,
): EncryptedMetadataHex {
  const ssBytes = parseHexOrBytes(
    SharedSecretInput,
    sharedSecret,
    'shared_secret',
    KYBER_SHARED_SECRET_SIZE,
  );
  const viewTag = computeViewTag(ssBytes);
  const plaintext = encodeAnnouncementMetadata({ ...input, viewTag });
  return encryptAnnouncementMetadata(plaintext, ssBytes);
}

/**
 * Recipient-side: decrypt a 93-byte (or longer) encrypted block with
 * `sharedSecret` and decode the structured fields.
 *
 * Throws `METADATA_DECRYPTION_FAILED` if the authentication tag does not
 * verify (wrong recipient or tampered data) — the expected outcome for
 * non-matching announcements.
 */
export function openAnnouncementMetadata(
  encrypted: EncryptedMetadataHex | Uint8Array,
  sharedSecret: SharedSecretHex | Uint8Array,
): AnnouncementMetadata {
  const plaintext = decryptAnnouncementMetadata(encrypted, sharedSecret);
  return decodeAnnouncementMetadata(plaintext);
}
