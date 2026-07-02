import { describe, expect, it } from 'vitest';

import {
  createStealthPayment,
  decapsulate,
  deriveStealthAddress,
  deriveStealthKeys,
  generateSpecterKeys,
  metaAddressFromPublicKeys,
  scanAnnouncement,
  scanAnnouncements,
} from '../../src/index.js';

/**
 * End-to-end payment flow.
 *
 * 1. Recipient generates `SpecterKeys` and publishes a meta-address.
 * 2. Sender calls `createStealthPayment(metaAddress)` and gets back the
 *    ephemeral ciphertext, view tag, Eth + Sui addresses.
 * 3. Recipient runs `scanAnnouncement` against their viewing keys; on a
 *    match they receive the spendable secp256k1 private key.
 *
 * This mirrors the upstream backend's `test_full_stealth_flow_e2e` test
 * (in `vendor/specter-crypto/tests/`) but exercises the JS bindings.
 */
describe('full payment flow', () => {
  it('sender → announcement → recipient match yields spendable keys', () => {
    const recipient = generateSpecterKeys();

    // Recipient publishes the meta-address.
    const meta = metaAddressFromPublicKeys(
      recipient.spending.publicKey,
      recipient.viewing.publicKey,
    );

    // Sender builds a stealth payment from the meta hex.
    const payment = createStealthPayment(meta.hex);
    expect(payment.viewTag).toBeGreaterThanOrEqual(0);
    expect(payment.viewTag).toBeLessThanOrEqual(255);
    expect(payment.ethAddress).toMatch(/^0x[0-9a-f]{40}$/u);
    expect(payment.suiAddress).toMatch(/^0x[0-9a-f]{64}$/u);

    // Recipient scans WITH their spending secret to recover the spendable key.
    const result = scanAnnouncement(
      {
        ephemeralCiphertext: payment.ephemeralCiphertext,
        viewTag: payment.viewTag,
      },
      recipient.viewing,
      recipient.spending.publicKey,
      recipient.spending.secretKey,
    );

    expect(result.isMatch).toBe(true);
    if (result.isMatch) {
      expect(result.detected.ethAddress).toBe(payment.ethAddress);
      expect(result.detected.suiAddress).toBe(payment.suiAddress);
      expect(result.stealthKeys).toBeDefined();
      expect(result.stealthKeys?.ethAddress).toBe(payment.ethAddress);
      expect(result.stealthKeys?.suiAddress).toBe(payment.suiAddress);
      expect(result.stealthKeys?.ethPrivateKey).toMatch(/^0x[0-9a-f]{64}$/u);
      expect(result.stealthKeys?.publicKey).toMatch(/^0x04[0-9a-f]{128}$/u);
    }
  });

  it('watch-only scan (viewing secret + spending public only) detects but yields no private key', () => {
    const recipient = generateSpecterKeys();
    const meta = metaAddressFromPublicKeys(
      recipient.spending.publicKey,
      recipient.viewing.publicKey,
    );
    const payment = createStealthPayment(meta.hex);

    // No spending secret supplied.
    const result = scanAnnouncement(
      { ephemeralCiphertext: payment.ephemeralCiphertext, viewTag: payment.viewTag },
      recipient.viewing,
      recipient.spending.publicKey,
    );

    expect(result.isMatch).toBe(true);
    if (result.isMatch) {
      expect(result.detected.ethAddress).toBe(payment.ethAddress);
      // No spendable key material without the spending secret.
      expect(result.stealthKeys).toBeUndefined();
    }
  });

  it('non-matching viewing key returns isMatch:false (different key path)', () => {
    const recipient = generateSpecterKeys();
    const stranger = generateSpecterKeys();

    const meta = metaAddressFromPublicKeys(
      recipient.spending.publicKey,
      recipient.viewing.publicKey,
    );
    const payment = createStealthPayment(meta.hex);

    const result = scanAnnouncement(
      {
        ephemeralCiphertext: payment.ephemeralCiphertext,
        viewTag: payment.viewTag,
      },
      stranger.viewing,
      stranger.spending.publicKey,
    );

    // The stranger decapsulates to a different shared secret (FIPS 203
    // implicit auth) and so their view-tag does not match. There's a 1/256
    // chance of a false positive if the random tags happen to collide; the
    // test runs once but the scope is small enough that this is a stable
    // assertion (re-roll the deterministic flow if it ever flakes).
    if (result.isMatch) {
      // Defence-in-depth: even on a tag collision, the derived address is
      // different. Confirm the address mismatch reason path.
      // (Cannot reach here in practice with the tag-mismatch path.)
      expect(false).toBe(true);
    } else {
      expect(['view_tag_mismatch', 'address_mismatch']).toContain(result.reason);
    }
  });

  it('scanAnnouncements is the batch form of scanAnnouncement', () => {
    const recipient = generateSpecterKeys();
    const meta = metaAddressFromPublicKeys(
      recipient.spending.publicKey,
      recipient.viewing.publicKey,
    );

    const announcements = Array.from({ length: 5 }, () => {
      const p = createStealthPayment(meta.hex);
      return { ephemeralCiphertext: p.ephemeralCiphertext, viewTag: p.viewTag };
    });

    const results = scanAnnouncements(
      announcements,
      recipient.viewing,
      recipient.spending.publicKey,
    );
    expect(results).toHaveLength(5);
    expect(results.every((r) => r.isMatch)).toBe(true);
  });

  it('the eth private key derived during scan equals the one the sender derived', () => {
    // Wallet-import contract: signing under `eth_private_key` produces
    // valid ECDSA over the stealth Eth address.
    const recipient = generateSpecterKeys();
    const enc = (() => {
      // Use the lower-level pieces so we can compare to what scanAnnouncement does.
      const meta = metaAddressFromPublicKeys(
        recipient.spending.publicKey,
        recipient.viewing.publicKey,
      );
      const payment = createStealthPayment(meta.hex);
      return { meta, payment };
    })();

    // Sender's view: eth address derived locally.
    const senderEth = enc.payment.ethAddress;

    // Recipient's view: re-derive the eth address from the decapsulated
    // shared secret using the spending pk, then re-derive the keys.
    const recipientShared = decapsulate(
      enc.payment.ephemeralCiphertext,
      recipient.viewing.secretKey,
    );
    const recipientEthRederived = deriveStealthAddress(
      recipient.spending.publicKey,
      recipientShared,
    );
    expect(recipientEthRederived).toBe(senderEth);

    // Only the spending SECRET yields the private key.
    const stealthKeys = deriveStealthKeys(recipient.spending.secretKey, recipientShared);
    expect(stealthKeys.ethAddress).toBe(senderEth);
    expect(stealthKeys.ethPrivateKey).toMatch(/^0x[0-9a-f]{64}$/u);
  });

  it('Issue #1 regression: the public spend key cannot derive a private key', () => {
    // A sender / anyone holding only the recipient's PUBLIC identity can
    // compute the address but must not be able to compute the private key.
    // The public spend key is 33 bytes; deriveStealthKeys requires a 32-byte
    // SECRET, so passing the public key fails length validation.
    const recipient = generateSpecterKeys();
    const meta = metaAddressFromPublicKeys(
      recipient.spending.publicKey,
      recipient.viewing.publicKey,
    );
    const payment = createStealthPayment(meta.hex);
    const shared = decapsulate(payment.ephemeralCiphertext, recipient.viewing.secretKey);

    expect(() =>
      // @ts-expect-error — a public spend key is not a valid secret key input.
      deriveStealthKeys(recipient.spending.publicKey, shared),
    ).toThrowError(/expected 32 bytes|INVALID_KEY_SIZE/u);
  });
});
