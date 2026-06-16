import { describe, expect, it } from 'vitest';

import {
  ENCRYPTED_METADATA_SIZE,
  ETH_ADDRESS_SIZE,
  KYBER_CIPHERTEXT_SIZE,
  KYBER_PUBLIC_KEY_SIZE,
  KYBER_SECRET_KEY_SIZE,
  KYBER_SHARED_SECRET_SIZE,
  META_ADDRESS_SIZE,
  PLAINTEXT_METADATA_SIZE,
  PROTOCOL_VERSION,
  STEALTH_ETH_PRIVATE_KEY_SIZE,
  STEALTH_SECP256K1_PUBLIC_SIZE,
  SUI_ADDRESS_SIZE,
  VIEW_TAG_SIZE,
} from '../../src/index.js';
import { getWasmSync } from '../../src/loader.js';

/**
 * Contract test: every TS-side constant must equal the value the WASM bridge
 * reports. If the upstream protocol bumps a size in
 * `vendor/specter-core/src/constants.rs`, the bridge starts returning a new
 * value here and this test fails until the TS layer (and any downstream
 * consumers) catches up.
 */
describe('protocol constants', () => {
  it('matches the WASM bridge', () => {
    const wasm = getWasmSync();
    expect(KYBER_PUBLIC_KEY_SIZE).toBe(wasm.kyberPublicKeySize());
    expect(KYBER_SECRET_KEY_SIZE).toBe(wasm.kyberSecretKeySize());
    expect(KYBER_CIPHERTEXT_SIZE).toBe(wasm.kyberCiphertextSize());
    expect(KYBER_SHARED_SECRET_SIZE).toBe(wasm.kyberSharedSecretSize());
    expect(VIEW_TAG_SIZE).toBe(wasm.viewTagSize());
    expect(ETH_ADDRESS_SIZE).toBe(wasm.ethAddressSize());
    expect(SUI_ADDRESS_SIZE).toBe(wasm.suiAddressSize());
    expect(META_ADDRESS_SIZE).toBe(wasm.metaAddressSize());
    expect(PROTOCOL_VERSION).toBe(wasm.protocolVersion());
    expect(PLAINTEXT_METADATA_SIZE).toBe(wasm.plaintextMetadataSize());
    expect(ENCRYPTED_METADATA_SIZE).toBe(wasm.encryptedMetadataSize());
  });

  it('matches the published FIPS 203 ML-KEM-768 sizes', () => {
    expect(KYBER_PUBLIC_KEY_SIZE).toBe(1184);
    expect(KYBER_SECRET_KEY_SIZE).toBe(2400);
    expect(KYBER_CIPHERTEXT_SIZE).toBe(1088);
    expect(KYBER_SHARED_SECRET_SIZE).toBe(32);
  });

  it('matches the SPECTER protocol layout', () => {
    expect(VIEW_TAG_SIZE).toBe(1);
    expect(ETH_ADDRESS_SIZE).toBe(20);
    expect(SUI_ADDRESS_SIZE).toBe(32);
    expect(META_ADDRESS_SIZE).toBe(1 + KYBER_PUBLIC_KEY_SIZE + KYBER_PUBLIC_KEY_SIZE);
    expect(PROTOCOL_VERSION).toBe(1);
    expect(STEALTH_ETH_PRIVATE_KEY_SIZE).toBe(32);
    expect(STEALTH_SECP256K1_PUBLIC_SIZE).toBe(65);
  });
});
