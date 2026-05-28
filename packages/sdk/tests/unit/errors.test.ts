import { describe, expect, it } from 'vitest';

import { SpecterSdkError } from '../../src/index.js';
import { normalizeError } from '../../src/errors.js';

describe('normalizeError', () => {
  it('passes through SpecterSdkError unchanged', () => {
    const err = new SpecterSdkError('INVALID_HEX', 'foo');
    expect(normalizeError(err)).toBe(err);
  });

  it('wraps a wire-shaped error from WASM', () => {
    const wire = {
      code: 'INVALID_KEY_SIZE',
      message: 'expected 1184 got 100',
      recoverable: false,
      category: 'validation',
    };
    const err = normalizeError(wire);
    expect(err).toBeInstanceOf(SpecterSdkError);
    expect(err.code).toBe('INVALID_KEY_SIZE');
    expect(err.message).toBe('expected 1184 got 100');
    expect(err.category).toBe('validation');
  });

  it('falls back to INTERNAL_ERROR for unknown codes', () => {
    const wire = {
      code: 'TOTALLY_NEW_CODE',
      message: 'help',
      recoverable: false,
      category: 'validation',
    };
    const err = normalizeError(wire);
    expect(err.code).toBe('INTERNAL_ERROR');
    expect(err.message).toBe('help');
  });

  it('wraps a plain Error', () => {
    const err = normalizeError(new Error('oh no'));
    expect(err.code).toBe('INTERNAL_ERROR');
    expect(err.message).toBe('oh no');
  });

  it('wraps an unknown thrown value', () => {
    const err = normalizeError('weird string');
    expect(err.code).toBe('INTERNAL_ERROR');
    expect(err.message).toBe('unknown error');
  });
});

describe('SpecterSdkError category inference', () => {
  it.each([
    ['INVALID_KEY_SIZE', 'validation'],
    ['INVALID_CIPHERTEXT_SIZE', 'validation'],
    ['INVALID_SHARED_SECRET_SIZE', 'validation'],
    ['INVALID_META_ADDRESS', 'validation'],
    ['INVALID_METADATA_JSON', 'validation'],
    ['INVALID_VIEW_TAG', 'validation'],
    ['INVALID_API_RESPONSE', 'validation'],
    ['INVALID_HEX', 'encoding'],
    ['HTTP_ERROR', 'internal'],
    ['ENCAPSULATION_FAILED', 'crypto'],
    ['DECAPSULATION_FAILED', 'crypto'],
    ['STEALTH_DERIVATION_FAILED', 'crypto'],
    ['NOT_INITIALIZED', 'internal'],
    ['WASM_LOAD_FAILED', 'internal'],
    ['INTERNAL_ERROR', 'internal'],
  ] as const)('maps %s → %s', (code, category) => {
    const err = new SpecterSdkError(code, 'msg');
    expect(err.category).toBe(category);
  });
});
