import { describe, expect, it } from 'vitest';

import {
  computeViewTag,
  decapsulate,
  deriveStealthAddress,
  deriveStealthKeys,
  deriveStealthSuiAddress,
  encapsulate,
  generateKeysLocal,
  generateSpecterKeys,
  verifyViewTag,
} from '../../src/index.js';

describe('determinism', () => {
  it('view tag depends only on the shared secret', () => {
    const kp = generateKeysLocal();
    const enc = encapsulate(kp.publicKey);
    const a = computeViewTag(enc.sharedSecret);
    const b = computeViewTag(enc.sharedSecret);
    expect(a).toBe(b);
    expect(a).toBeGreaterThanOrEqual(0);
    expect(a).toBeLessThanOrEqual(255);
  });

  it('verify_view_tag agrees with compute_view_tag', () => {
    const kp = generateKeysLocal();
    const enc = encapsulate(kp.publicKey);
    const tag = computeViewTag(enc.sharedSecret);
    expect(verifyViewTag(enc.sharedSecret, tag)).toBe(true);
    expect(verifyViewTag(enc.sharedSecret, (tag + 1) & 0xff)).toBe(false);
  });

  it('stealth eth address depends only on (spending_pk, shared_secret)', () => {
    const { spending, viewing } = generateSpecterKeys();
    const enc = encapsulate(viewing.publicKey);
    const a = deriveStealthAddress(spending.publicKey, enc.sharedSecret);
    const b = deriveStealthAddress(spending.publicKey, enc.sharedSecret);
    expect(a).toBe(b);
    expect(a).toMatch(/^0x[0-9a-f]{40}$/u);
  });

  it('stealth sui address is deterministic for the same inputs', () => {
    const { spending, viewing } = generateSpecterKeys();
    const enc = encapsulate(viewing.publicKey);
    const a = deriveStealthSuiAddress(spending.publicKey, enc.sharedSecret);
    const b = deriveStealthSuiAddress(spending.publicKey, enc.sharedSecret);
    expect(a).toBe(b);
    expect(a).toMatch(/^0x[0-9a-f]{64}$/u);
  });

  it('addresses from the public spend key match those from the secret spend key', () => {
    // The sender path (public spend key) and the recipient path (secret spend
    // key) must derive the same stealth address — this is the EC-tweak
    // agreement P = B + t*G == (b + t)*G.
    const { spending, viewing } = generateSpecterKeys();
    const enc = encapsulate(viewing.publicKey);
    const eth = deriveStealthAddress(spending.publicKey, enc.sharedSecret);
    const sui = deriveStealthSuiAddress(spending.publicKey, enc.sharedSecret);
    const keys = deriveStealthKeys(spending.secretKey, enc.sharedSecret);
    expect(keys.ethAddress).toBe(eth);
    expect(keys.suiAddress).toBe(sui);
  });

  it('different shared secrets produce different stealth addresses', () => {
    const { spending, viewing } = generateSpecterKeys();
    const e1 = encapsulate(viewing.publicKey);
    const e2 = encapsulate(viewing.publicKey);
    const a1 = deriveStealthAddress(spending.publicKey, e1.sharedSecret);
    const a2 = deriveStealthAddress(spending.publicKey, e2.sharedSecret);
    expect(a1).not.toBe(a2);
  });

  it('decapsulate is deterministic for the same (ciphertext, secret_key)', () => {
    const kp = generateKeysLocal();
    const enc = encapsulate(kp.publicKey);
    const a = decapsulate(enc.ciphertext, kp.secretKey);
    const b = decapsulate(enc.ciphertext, kp.secretKey);
    expect(a).toBe(b);
    expect(a).toBe(enc.sharedSecret);
  });
});
