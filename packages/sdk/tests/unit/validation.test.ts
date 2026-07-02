import { describe, expect, it } from 'vitest';

import {
  computeViewTag,
  decapsulate,
  deriveStealthAddress,
  encapsulate,
  generateKeysLocal,
  generateSpendKey,
  META_ADDRESS_VERSION,
  metaAddressFromPublicKeys,
  parseMetaAddress,
  SpecterSdkError,
  verifyViewTag,
} from '../../src/index.js';

const FAKE_HEX_PK = `0x${'aa'.repeat(1184)}`;
const FAKE_HEX_SK = `0x${'bb'.repeat(2400)}`;
const FAKE_HEX_CT = `0x${'cc'.repeat(1088)}`;
const FAKE_HEX_SS = `0x${'dd'.repeat(32)}`;

// Branded-hex types intentionally reject arbitrary strings at compile time.
// These tests *deliberately* feed bad inputs into the runtime validators, so
// we cast through `never`/`unknown` to bypass the branding while still
// exercising the runtime error paths we ship to consumers.
const bad = <T,>(value: unknown): T => value as T;

describe('input validation: SpecterSdkError codes', () => {
  it('encapsulate rejects undersized public key', () => {
    expect.assertions(2);
    try {
      encapsulate(bad('0xdeadbeef'));
    } catch (err) {
      expect(err).toBeInstanceOf(SpecterSdkError);
      expect((err as SpecterSdkError).code).toBe('INVALID_KEY_SIZE');
    }
  });

  it('encapsulate rejects oversized public key', () => {
    expect.assertions(1);
    const oversized = `0x${'aa'.repeat(2000)}`;
    try {
      encapsulate(bad(oversized));
    } catch (err) {
      expect((err as SpecterSdkError).code).toBe('INVALID_KEY_SIZE');
    }
  });

  it('encapsulate rejects non-hex strings', () => {
    expect.assertions(1);
    try {
      encapsulate(bad('not-hex'));
    } catch (err) {
      expect(['INVALID_HEX', 'INVALID_KEY_SIZE']).toContain(
        (err as SpecterSdkError).code,
      );
    }
  });

  it('decapsulate rejects undersized ciphertext', () => {
    expect.assertions(1);
    try {
      decapsulate(bad('0xdead'), bad(FAKE_HEX_SK));
    } catch (err) {
      expect((err as SpecterSdkError).code).toBe('INVALID_KEY_SIZE');
    }
  });

  it('decapsulate rejects undersized secret key', () => {
    expect.assertions(1);
    try {
      decapsulate(bad(FAKE_HEX_CT), bad('0xdead'));
    } catch (err) {
      expect((err as SpecterSdkError).code).toBe('INVALID_KEY_SIZE');
    }
  });

  it('computeViewTag rejects undersized shared secret', () => {
    expect.assertions(1);
    try {
      computeViewTag(bad('0xdead'));
    } catch (err) {
      expect((err as SpecterSdkError).code).toBe('INVALID_KEY_SIZE');
    }
  });

  it('verifyViewTag rejects out-of-range tags', () => {
    expect.assertions(2);
    try {
      verifyViewTag(bad(FAKE_HEX_SS), -1);
    } catch (err) {
      expect((err as SpecterSdkError).code).toBe('INVALID_VIEW_TAG');
    }
    try {
      verifyViewTag(bad(FAKE_HEX_SS), 256);
    } catch (err) {
      expect((err as SpecterSdkError).code).toBe('INVALID_VIEW_TAG');
    }
  });

  it('deriveStealthAddress rejects bad spending pk', () => {
    expect.assertions(1);
    try {
      deriveStealthAddress(bad('0xab'), bad(FAKE_HEX_SS));
    } catch (err) {
      expect((err as SpecterSdkError).code).toBe('INVALID_KEY_SIZE');
    }
  });

  it('metaAddressFromPublicKeys rejects mis-sized spending key', () => {
    expect.assertions(1);
    try {
      metaAddressFromPublicKeys(bad('0xab'), bad(FAKE_HEX_PK));
    } catch (err) {
      expect((err as SpecterSdkError).code).toBe('INVALID_KEY_SIZE');
    }
  });

  it('metaAddressFromPublicKeys propagates an INVALID_META_ADDRESS for an invalid spend point', () => {
    expect.assertions(1);
    // Right size (33 bytes) but not a valid compressed secp256k1 point.
    const zeroSpend = `0x${'00'.repeat(33)}`;
    const zeroView = `0x${'00'.repeat(1184)}`;
    try {
      metaAddressFromPublicKeys(bad(zeroSpend), bad(zeroView));
    } catch (err) {
      expect((err as SpecterSdkError).code).toBe('INVALID_META_ADDRESS');
    }
  });

  it('parseMetaAddress rejects under-sized payload', () => {
    expect.assertions(1);
    try {
      parseMetaAddress(new Uint8Array(100));
    } catch (err) {
      expect(['INVALID_KEY_SIZE', 'INVALID_META_ADDRESS']).toContain(
        (err as SpecterSdkError).code,
      );
    }
  });

  it('parseMetaAddress accepts hex string', () => {
    const spend = generateSpendKey();
    const view = generateKeysLocal();
    const meta = metaAddressFromPublicKeys(spend.publicKey, view.publicKey);
    const reparsed = parseMetaAddress(meta.hex);
    expect(reparsed.address.spendingPk).toBe(spend.publicKey);
    expect(reparsed.address.viewingPk).toBe(view.publicKey);
    expect(reparsed.address.version).toBe(META_ADDRESS_VERSION);
  });

  it('parseMetaAddress accepts Uint8Array', () => {
    const spend = generateSpendKey();
    const view = generateKeysLocal();
    const meta = metaAddressFromPublicKeys(spend.publicKey, view.publicKey);
    const reparsed = parseMetaAddress(meta.bytes);
    expect(reparsed.hex).toBe(meta.hex);
  });

  it('SpecterSdkError carries category + recoverable', () => {
    const err = new SpecterSdkError('INVALID_KEY_SIZE', 'msg');
    expect(err.name).toBe('SpecterSdkError');
    expect(err.code).toBe('INVALID_KEY_SIZE');
    expect(err.category).toBe('validation');
    expect(err.recoverable).toBe(false);
    expect(err instanceof Error).toBe(true);
  });

  it('metaAddressFromPublicKeys validates metadata and accepts Unicode description', () => {
    const spend = generateSpendKey();
    const view = generateKeysLocal();
    const meta = metaAddressFromPublicKeys(spend.publicKey, view.publicKey, {
      description: 'alice ✨',
      avatar: 'ipfs://Qmfoo',
      createdAt: 1700000000,
    });
    expect(meta.address.metadata?.description).toBe('alice ✨');
    expect(meta.address.metadata?.avatar).toBe('ipfs://Qmfoo');
    expect(meta.address.metadata?.createdAt).toBe(1700000000);
  });
});
