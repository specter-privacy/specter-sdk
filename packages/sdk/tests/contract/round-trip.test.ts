import { describe, expect, it } from 'vitest';

import {
  decapsulate,
  encapsulate,
  generateKeysLocal,
  KYBER_CIPHERTEXT_SIZE,
  KYBER_PUBLIC_KEY_SIZE,
  KYBER_SECRET_KEY_SIZE,
  KYBER_SHARED_SECRET_SIZE,
} from '../../src/index.js';
import { hexToBytes } from '../../src/internal/encoding.js';

const ITERATIONS = 50;

describe('encapsulate / decapsulate round-trip', () => {
  it('produces matching shared secrets across many iterations', () => {
    for (let i = 0; i < ITERATIONS; i += 1) {
      const kp = generateKeysLocal();
      const enc = encapsulate(kp.publicKey);
      const ss = decapsulate(enc.ciphertext, kp.secretKey);
      expect(ss).toBe(enc.sharedSecret);
    }
  });

  it('keypair byte sizes match the protocol constants', () => {
    const kp = generateKeysLocal();
    expect(hexToBytes(kp.publicKey).length).toBe(KYBER_PUBLIC_KEY_SIZE);
    expect(hexToBytes(kp.secretKey).length).toBe(KYBER_SECRET_KEY_SIZE);
  });

  it('ciphertext + shared secret byte sizes match the protocol constants', () => {
    const kp = generateKeysLocal();
    const enc = encapsulate(kp.publicKey);
    expect(hexToBytes(enc.ciphertext).length).toBe(KYBER_CIPHERTEXT_SIZE);
    expect(hexToBytes(enc.sharedSecret).length).toBe(KYBER_SHARED_SECRET_SIZE);
  });

  it('two encapsulations to the same pk produce different ciphertexts', () => {
    const kp = generateKeysLocal();
    const a = encapsulate(kp.publicKey);
    const b = encapsulate(kp.publicKey);
    expect(a.ciphertext).not.toBe(b.ciphertext);
    expect(a.sharedSecret).not.toBe(b.sharedSecret);
  });

  it('decapsulate accepts hex strings and Uint8Array equivalently', () => {
    const kp = generateKeysLocal();
    const enc = encapsulate(kp.publicKey);

    const fromHex = decapsulate(enc.ciphertext, kp.secretKey);
    const fromBytes = decapsulate(
      hexToBytes(enc.ciphertext),
      hexToBytes(kp.secretKey),
    );
    expect(fromHex).toBe(fromBytes);
  });
});
