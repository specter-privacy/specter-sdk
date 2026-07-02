import { inspect } from 'node:util';

import { describe, expect, it } from 'vitest';

import {
  createStealthPayment,
  decapsulate,
  deriveStealthKeys,
  encapsulate,
  generateKeysLocal,
  generateSpecterKeys,
  metaAddressFromPublicKeys,
} from '../../src/index.js';

/**
 * Secret-safety contract tests.
 *
 * Every secret-bearing object in the public API must:
 *   1. Hide the secret from `JSON.stringify` (returns `[REDACTED]`).
 *   2. Hide the secret from `Object.keys` / `for..in` iteration.
 *   3. Hide the secret from Node's `util.inspect` (which `console.log` uses).
 *   4. Still expose the secret via direct property access (signing needs it).
 */
describe('secret-safety: KyberKeyPair', () => {
  it('JSON.stringify of a generated keypair does not contain the secret hex', () => {
    const kp = generateKeysLocal();
    const json = JSON.stringify(kp);
    expect(json).not.toContain(kp.secretKey);
    expect(json).toContain('[REDACTED]');
    expect(json).toContain(kp.publicKey);
  });

  it('Object.keys does not include secretKey', () => {
    const kp = generateKeysLocal();
    expect(Object.keys(kp)).toEqual(['publicKey']);
  });

  it('util.inspect does not leak the secret hex', () => {
    const kp = generateKeysLocal();
    const dump = inspect(kp, { depth: 5 });
    expect(dump).not.toContain(kp.secretKey);
    expect(dump).toContain('[REDACTED]');
  });

  it('property access still returns the secret hex', () => {
    const kp = generateKeysLocal();
    expect(typeof kp.secretKey).toBe('string');
    expect(kp.secretKey.startsWith('0x')).toBe(true);
    expect(kp.secretKey.length).toBe(2 + 2400 * 2);
  });
});

describe('secret-safety: SpecterKeys', () => {
  it('redacts both spending and viewing secret keys', () => {
    const keys = generateSpecterKeys();
    const json = JSON.stringify(keys);
    expect(json).not.toContain(keys.spending.secretKey);
    expect(json).not.toContain(keys.viewing.secretKey);
    expect(json.match(/\[REDACTED\]/gu)?.length).toBe(2);
  });
});

describe('secret-safety: EncapsulationResult', () => {
  it('JSON.stringify does not leak the shared secret', () => {
    const kp = generateKeysLocal();
    const enc = encapsulate(kp.publicKey);
    const json = JSON.stringify(enc);
    expect(json).not.toContain(enc.sharedSecret);
    expect(json).toContain('[REDACTED]');
    expect(json).toContain(enc.ciphertext);
  });

  it('Object.keys does not include sharedSecret', () => {
    const kp = generateKeysLocal();
    const enc = encapsulate(kp.publicKey);
    expect(Object.keys(enc)).toEqual(['ciphertext']);
  });

  it('util.inspect redacts the shared secret', () => {
    const kp = generateKeysLocal();
    const enc = encapsulate(kp.publicKey);
    const dump = inspect(enc);
    expect(dump).not.toContain(enc.sharedSecret);
    expect(dump).toContain('[REDACTED]');
  });

  it('decapsulate does NOT leak by design (returns a plain hex string the consumer must keep safe)', () => {
    // The SharedSecretHex returned by `decapsulate` is a primitive string;
    // the SDK's job ends at that point. Document the contract here so it
    // doesn't silently regress.
    const kp = generateKeysLocal();
    const enc = encapsulate(kp.publicKey);
    const ss = decapsulate(enc.ciphertext, kp.secretKey);
    expect(typeof ss).toBe('string');
    // It IS the same as enc.sharedSecret; the consumer is responsible for
    // not logging this primitive — see SECURITY.md.
    expect(ss).toBe(enc.sharedSecret);
  });
});

describe('secret-safety: StealthKeys', () => {
  it('redacts the eth private key in JSON.stringify', () => {
    const { spending, viewing } = generateSpecterKeys();
    const enc = encapsulate(viewing.publicKey);
    const stealth = deriveStealthKeys(spending.secretKey, enc.sharedSecret);
    const json = JSON.stringify(stealth);
    expect(json).not.toContain(stealth.ethPrivateKey);
    expect(json).toContain('[REDACTED]');
    expect(json).toContain(stealth.ethAddress);
    expect(json).toContain(stealth.suiAddress);
    expect(json).toContain(stealth.publicKey);
  });

  it('Object.keys excludes ethPrivateKey', () => {
    const { spending, viewing } = generateSpecterKeys();
    const enc = encapsulate(viewing.publicKey);
    const stealth = deriveStealthKeys(spending.secretKey, enc.sharedSecret);
    expect(Object.keys(stealth).sort()).toEqual([
      'ethAddress',
      'publicKey',
      'suiAddress',
    ]);
  });

  it('util.inspect redacts the eth private key', () => {
    const { spending, viewing } = generateSpecterKeys();
    const enc = encapsulate(viewing.publicKey);
    const stealth = deriveStealthKeys(spending.secretKey, enc.sharedSecret);
    const dump = inspect(stealth);
    expect(dump).not.toContain(stealth.ethPrivateKey);
  });

  it('property access still returns the eth private key', () => {
    const { spending, viewing } = generateSpecterKeys();
    const enc = encapsulate(viewing.publicKey);
    const stealth = deriveStealthKeys(spending.secretKey, enc.sharedSecret);
    expect(stealth.ethPrivateKey.startsWith('0x')).toBe(true);
    expect(stealth.ethPrivateKey.length).toBe(2 + 32 * 2);
  });
});

describe('secret-safety: meta-address never carries any secret material', () => {
  it('meta-address bytes contain only public information', () => {
    const recipient = generateSpecterKeys();
    const meta = metaAddressFromPublicKeys(
      recipient.spending.publicKey,
      recipient.viewing.publicKey,
    );
    // Sanity: the bytes must not contain either secret key (incredibly
    // unlikely by chance, but a regression to-stringifying secrets would
    // surface here immediately).
    expect(meta.hex).not.toContain(recipient.spending.secretKey.slice(2));
    expect(meta.hex).not.toContain(recipient.viewing.secretKey.slice(2));
  });
});

describe('secret-safety: createStealthPayment never returns the shared secret', () => {
  it('the StealthPayment object does not expose the shared secret', () => {
    const recipient = generateSpecterKeys();
    const meta = metaAddressFromPublicKeys(
      recipient.spending.publicKey,
      recipient.viewing.publicKey,
    );
    const payment = createStealthPayment(meta.hex);
    expect(Object.keys(payment).sort()).toEqual([
      'ephemeralCiphertext',
      'ethAddress',
      'suiAddress',
      'viewTag',
    ]);
    // No `sharedSecret` field, hidden or otherwise.
    expect((payment as unknown as { sharedSecret?: unknown }).sharedSecret).toBeUndefined();
  });
});
