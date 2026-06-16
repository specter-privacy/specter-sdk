import { describe, expect, it } from 'vitest';

import {
  computeViewTag,
  decodeAnnouncementMetadata,
  decryptAnnouncementMetadata,
  encapsulate,
  encodeAnnouncementMetadata,
  encryptAnnouncementMetadata,
  ENCRYPTED_METADATA_SIZE,
  generateSpecterKeys,
  openAnnouncementMetadata,
  PLAINTEXT_METADATA_SIZE,
  sealAnnouncementMetadata,
  SpecterSdkError,
} from '../../src/index.js';
import { hexToBytes } from '../../src/internal/encoding.js';

/**
 * Contract tests for announcement-metadata encryption.
 *
 * The 77-byte plaintext layout (view_tag + tx_hash + amount + source_chain_id
 * + reserved) is encoded/decoded in TypeScript; the AES-256-GCM seal/open is
 * performed in the WASM bridge keyed from the ML-KEM shared secret. These
 * tests exercise both layers and their composition.
 */

/** A deterministic 32-byte shared secret for layout/round-trip tests. */
function secret(byte = 0x42): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

const TX_HASH: `0x${string}` = `0x${'11'.repeat(32)}`;

describe('announcement metadata: encode/decode', () => {
  it('encodes to exactly 77 bytes with the view tag in the clear at byte 0', () => {
    const block = encodeAnnouncementMetadata({ viewTag: 0xab });
    expect(block).toBeInstanceOf(Uint8Array);
    expect(block.length).toBe(PLAINTEXT_METADATA_SIZE);
    expect(block[0]).toBe(0xab);
    // No optional fields → bytes [1..77] are all zero.
    expect(block.subarray(1).every((b) => b === 0)).toBe(true);
  });

  it('round-trips all structured fields', () => {
    const block = encodeAnnouncementMetadata({
      viewTag: 7,
      txHash: TX_HASH,
      amount: 1_000_000_000_000_000_000n, // 1e18 wei
      sourceChainId: 42161,
    });
    const decoded = decodeAnnouncementMetadata(block);
    expect(decoded.viewTag).toBe(7);
    expect(decoded.txHash).toBe(TX_HASH);
    expect(decoded.sourceChainId).toBe(42161);
    // 1e18 as a 32-byte big-endian uint256.
    expect(decoded.amount).toBe(`0x${(10n ** 18n).toString(16).padStart(64, '0')}`);
  });

  it('omits optional fields whose bytes are all zero', () => {
    const decoded = decodeAnnouncementMetadata(encodeAnnouncementMetadata({ viewTag: 1 }));
    expect(decoded.viewTag).toBe(1);
    expect(decoded.txHash).toBeUndefined();
    expect(decoded.amount).toBeUndefined();
    expect(decoded.sourceChainId).toBeUndefined();
  });

  it('accepts amount as a 32-byte hex string equivalently to a bigint', () => {
    const fromBig = encodeAnnouncementMetadata({ viewTag: 0, amount: 255n });
    const fromHex = encodeAnnouncementMetadata({
      viewTag: 0,
      amount: `0x${(255n).toString(16).padStart(64, '0')}`,
    });
    expect(Array.from(fromBig)).toStrictEqual(Array.from(fromHex));
  });

  it('rejects a negative bigint amount', () => {
    expect(() => encodeAnnouncementMetadata({ viewTag: 0, amount: -1n })).toThrow(SpecterSdkError);
    try {
      encodeAnnouncementMetadata({ viewTag: 0, amount: -1n });
    } catch (err) {
      expect((err as SpecterSdkError).code).toBe('INVALID_METADATA_FIELD');
    }
  });

  it('rejects an out-of-range view tag', () => {
    expect(() => encodeAnnouncementMetadata({ viewTag: 256 })).toThrow(SpecterSdkError);
  });

  it('rejects a too-short block on decode', () => {
    try {
      decodeAnnouncementMetadata(new Uint8Array(10));
      throw new Error('expected throw');
    } catch (err) {
      expect((err as SpecterSdkError).code).toBe('INVALID_METADATA_SIZE');
    }
  });

  it('rejects a source_chain_id beyond the JS safe-integer range', () => {
    // Hand-craft a block whose chain-id bytes [65..73] are all 0xff
    // (≈1.8e19, well above 2^53). Decode must fail closed rather than
    // silently return a lossy number.
    const block = new Uint8Array(PLAINTEXT_METADATA_SIZE);
    block.fill(0xff, 65, 73);
    try {
      decodeAnnouncementMetadata(block);
      throw new Error('expected throw');
    } catch (err) {
      expect((err as SpecterSdkError).code).toBe('INVALID_METADATA_FIELD');
    }
  });
});

describe('announcement metadata: encrypt/decrypt (WASM)', () => {
  it('matches the bridge size constants', async () => {
    const { getWasmSync } = await import('../../src/loader.js');
    const wasm = getWasmSync();
    expect(PLAINTEXT_METADATA_SIZE).toBe(wasm.plaintextMetadataSize());
    expect(ENCRYPTED_METADATA_SIZE).toBe(wasm.encryptedMetadataSize());
  });

  it('encrypts to 93 bytes and keeps the view tag in the clear', () => {
    const block = encodeAnnouncementMetadata({ viewTag: 0xcd, sourceChainId: 1 });
    const encrypted = encryptAnnouncementMetadata(block, secret());
    const encBytes = hexToBytes(encrypted);
    expect(encBytes.length).toBe(ENCRYPTED_METADATA_SIZE);
    expect(encBytes[0]).toBe(0xcd);
    // The payload [1..77] must differ from the plaintext payload.
    expect(Array.from(encBytes.subarray(1, 77))).not.toStrictEqual(
      Array.from(block.subarray(1, 77)),
    );
  });

  it('low-level encrypt → decrypt recovers the exact plaintext', () => {
    const block = encodeAnnouncementMetadata({ viewTag: 9, txHash: TX_HASH, sourceChainId: 10143 });
    const encrypted = encryptAnnouncementMetadata(block, secret());
    const plaintext = decryptAnnouncementMetadata(encrypted, secret());
    expect(Array.from(plaintext)).toStrictEqual(Array.from(block));
  });

  it('fails decryption with the wrong shared secret', () => {
    const block = encodeAnnouncementMetadata({ viewTag: 9, sourceChainId: 1 });
    const encrypted = encryptAnnouncementMetadata(block, secret(0x11));
    try {
      decryptAnnouncementMetadata(encrypted, secret(0x22));
      throw new Error('expected throw');
    } catch (err) {
      expect((err as SpecterSdkError).code).toBe('METADATA_DECRYPTION_FAILED');
      expect((err as SpecterSdkError).category).toBe('crypto');
    }
  });

  it('rejects a too-short encrypted block', () => {
    try {
      decryptAnnouncementMetadata(new Uint8Array(50), secret());
      throw new Error('expected throw');
    } catch (err) {
      expect((err as SpecterSdkError).code).toBe('INVALID_METADATA_SIZE');
    }
  });
});

describe('announcement metadata: seal/open over a real shared secret', () => {
  it('seals on the sender side and opens on the recipient side', () => {
    // Sender encapsulates to the recipient's viewing key.
    const recipient = generateSpecterKeys();
    const enc = encapsulate(recipient.viewing.publicKey);
    const sharedSecret = enc.sharedSecret;

    const sealed = sealAnnouncementMetadata(
      { txHash: TX_HASH, amount: 12345n, sourceChainId: 42161 },
      sharedSecret,
    );
    expect(hexToBytes(sealed).length).toBe(ENCRYPTED_METADATA_SIZE);

    const opened = openAnnouncementMetadata(sealed, sharedSecret);
    expect(opened.txHash).toBe(TX_HASH);
    expect(opened.amount).toBe(`0x${(12345n).toString(16).padStart(64, '0')}`);
    expect(opened.sourceChainId).toBe(42161);
  });

  it('derives the view tag from the shared secret (scanner-filterable)', () => {
    const sharedSecret = secret(0x5a);
    const sealed = sealAnnouncementMetadata({ sourceChainId: 1 }, sharedSecret);
    const opened = openAnnouncementMetadata(sealed, sharedSecret);
    expect(opened.viewTag).toBe(computeViewTag(sharedSecret));
    // The view tag is also readable from byte 0 without decrypting.
    expect(hexToBytes(sealed)[0]).toBe(computeViewTag(sharedSecret));
  });
});
