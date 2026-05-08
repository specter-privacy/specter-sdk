import { describe, expect, it } from 'vitest';

import { type SpecterSdkError } from '../../src/index.js';
import { asBytes, bytesToHex, hexToBytes } from '../../src/internal/encoding.js';

describe('hex encoding helpers', () => {
  it('bytesToHex round-trips through hexToBytes', () => {
    const original = new Uint8Array([0x00, 0x01, 0xff, 0x10, 0xab]);
    const hex = bytesToHex(original);
    expect(hex).toBe('0x0001ff10ab');
    const back = hexToBytes(hex);
    expect(Array.from(back)).toEqual(Array.from(original));
  });

  it('bytesToHex emits 0x lower-case', () => {
    const bytes = new Uint8Array([0xab, 0xcd, 0xef]);
    expect(bytesToHex(bytes)).toBe('0xabcdef');
  });

  it('hexToBytes accepts upper-case', () => {
    const result = hexToBytes('0xDEADBEEF');
    expect(result).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });

  it('hexToBytes accepts strings without 0x prefix', () => {
    const result = hexToBytes('abcd');
    expect(result).toEqual(new Uint8Array([0xab, 0xcd]));
  });

  it('hexToBytes rejects odd-length hex', () => {
    expect.assertions(1);
    try {
      hexToBytes('0xabc');
    } catch (err) {
      expect((err as SpecterSdkError).code).toBe('INVALID_HEX');
    }
  });

  it('hexToBytes rejects non-hex characters', () => {
    expect.assertions(1);
    try {
      hexToBytes('0xZZ00');
    } catch (err) {
      expect((err as SpecterSdkError).code).toBe('INVALID_HEX');
    }
  });

  it('hexToBytes enforces lengthBytes', () => {
    expect.assertions(1);
    try {
      hexToBytes('0xabcd', { lengthBytes: 4, field: 'test' });
    } catch (err) {
      expect((err as SpecterSdkError).code).toBe('INVALID_KEY_SIZE');
    }
  });

  it('hexToBytes rejects empty hex when length required', () => {
    expect.assertions(1);
    try {
      hexToBytes('', { lengthBytes: 4 });
    } catch (err) {
      expect((err as SpecterSdkError).code).toBe('INVALID_KEY_SIZE');
    }
  });

  it('hexToBytes returns empty array when no length required', () => {
    expect(hexToBytes('').length).toBe(0);
    expect(hexToBytes('0x').length).toBe(0);
  });

  it('hexToBytes rejects non-string inputs', () => {
    expect.assertions(1);
    try {
      hexToBytes(undefined as unknown as string);
    } catch (err) {
      expect((err as SpecterSdkError).code).toBe('INVALID_HEX');
    }
  });

  it('asBytes passes Uint8Array through with size check', () => {
    const bytes = new Uint8Array([1, 2, 3]);
    expect(asBytes(bytes)).toBe(bytes);
    expect(asBytes(bytes, { lengthBytes: 3 })).toBe(bytes);
  });

  it('asBytes rejects mis-sized Uint8Array', () => {
    expect.assertions(1);
    try {
      asBytes(new Uint8Array(2), { lengthBytes: 4 });
    } catch (err) {
      expect((err as SpecterSdkError).code).toBe('INVALID_KEY_SIZE');
    }
  });
});
