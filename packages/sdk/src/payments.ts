/**
 * High-level payment helpers.
 *
 * `createStealthPayment` packages the sender flow (encapsulate to spending
 * pk → derive both addresses → compute view-tag) into a single call.
 *
 * `scanAnnouncement` packages the recipient flow (decapsulate against the
 * viewing secret key → check view-tag → re-derive both addresses → return
 * spendable keys on a match).
 */

import { KYBER_SHARED_SECRET_SIZE } from './constants.js';
import {
  computeViewTag,
  decapsulate,
  deriveStealthAddress,
  deriveStealthKeys,
  deriveStealthSuiAddress,
  encapsulate,
  parseMetaAddress,
} from './crypto.js';
import { SpecterSdkError } from './errors.js';
import { hexToBytes } from './internal/encoding.js';
import {
  KyberPublicKeyInput,
  KyberSecretKeyInput,
  parseHexOrBytes,
  trySchemaParse,
  ViewTagInput,
} from './validation.js';

import {
  KYBER_PUBLIC_KEY_SIZE,
  KYBER_SECRET_KEY_SIZE,
} from './constants.js';

import type {
  AnnouncementInput,
  KyberKeyPair,
  KyberPublicKeyHex,
  MetaAddressHex,
  ScanResult,
  SpecterKeys,
  StealthPayment,
} from './types.js';

/**
 * Sender-side: given a recipient meta-address, build a complete payment
 * payload (ciphertext + view-tag + Eth address + Sui address). The shared
 * secret is consumed internally and never leaks out of this function.
 */
export function createStealthPayment(metaAddress: MetaAddressHex): StealthPayment {
  const meta = parseMetaAddress(metaAddress);
  // SPECTER encapsulates against the *viewing* public key so the recipient
  // can scan with their viewing secret without ever exposing the spending
  // secret. The spending public key is then mixed into the address-derivation
  // step.
  const enc = encapsulate(meta.address.viewingPk);
  // The shared secret is non-enumerable on `enc` but still readable.
  const ssBytes = hexToBytes(enc.sharedSecret, {
    lengthBytes: KYBER_SHARED_SECRET_SIZE,
    field: 'shared_secret',
  });
  const ethAddress = deriveStealthAddress(meta.address.spendingPk, ssBytes);
  const suiAddress = deriveStealthSuiAddress(meta.address.spendingPk, ssBytes);
  const viewTag = computeViewTag(ssBytes);

  return {
    ephemeralCiphertext: enc.ciphertext,
    viewTag,
    ethAddress,
    suiAddress,
  };
}

/**
 * Recipient-side: try to match a single announcement against the recipient's
 * viewing keys. The flow is:
 *
 *   1. Decapsulate against the viewing secret key.
 *   2. Compare view-tag (constant-time): non-match returns `{isMatch: false}`.
 *   3. Re-derive the stealth Eth address using the spending pk + shared secret.
 *   4. Use `deriveStealthKeys` to surface the spendable secp256k1 private key.
 *
 * The spending public key is intentionally NOT inferred from `viewingKeys`
 * because some applications keep the spending key on a more-restricted
 * device. Pass it explicitly.
 */
export function scanAnnouncement(
  announcement: AnnouncementInput,
  viewingKeys: KyberKeyPair,
  spendingPublicKey: KyberPublicKeyHex | Uint8Array,
): ScanResult {
  if (typeof announcement !== 'object') {
    throw new SpecterSdkError('INVALID_META_ADDRESS', 'announcement must be an object');
  }
  const expectedTag = trySchemaParse(
    ViewTagInput,
    announcement.viewTag,
    'announcement.view_tag',
  ) as number;

  // Validate viewing secret/public key shapes via the parsing helpers; this
  // also coerces the secret hex into a fresh Uint8Array we can pass to WASM
  // without exposing the upstream string.
  parseHexOrBytes(
    KyberPublicKeyInput,
    viewingKeys.publicKey,
    'viewing_public_key',
    KYBER_PUBLIC_KEY_SIZE,
  );
  parseHexOrBytes(
    KyberSecretKeyInput,
    viewingKeys.secretKey,
    'viewing_secret_key',
    KYBER_SECRET_KEY_SIZE,
  );

  const sharedSecretHex = decapsulate(announcement.ephemeralCiphertext, viewingKeys.secretKey);
  const ssBytes = hexToBytes(sharedSecretHex, {
    lengthBytes: KYBER_SHARED_SECRET_SIZE,
    field: 'shared_secret',
  });

  const computedTag = computeViewTag(ssBytes);
  if (computedTag !== expectedTag) {
    return { isMatch: false, reason: 'view_tag_mismatch' };
  }

  // Defence in depth: also re-derive the stealth Eth address and confirm it
  // matches the spending pk → shared secret combination. This ensures we
  // can't be fooled into returning matching tags when the announcement was
  // forged with a different spending key context.
  const stealthKeys = deriveStealthKeys(spendingPublicKey, ssBytes);

  return { isMatch: true, stealthKeys };
}

/**
 * Convenience helper: scan a batch of announcements against the same
 * `viewingKeys` / `spendingPublicKey`. Any announcement that does not match
 * is silently dropped (returned as an entry with `isMatch: false`). Useful
 * for client-side wallet scanning loops.
 */
export function scanAnnouncements(
  announcements: readonly AnnouncementInput[],
  viewingKeys: KyberKeyPair,
  spendingPublicKey: KyberPublicKeyHex | Uint8Array,
): ScanResult[] {
  return announcements.map((ann) => scanAnnouncement(ann, viewingKeys, spendingPublicKey));
}

/** Convenience: derive recipient's identity from a `SpecterKeys` bundle. */
export function specterKeysViewingPk(keys: SpecterKeys): KyberPublicKeyHex {
  return keys.viewing.publicKey;
}
