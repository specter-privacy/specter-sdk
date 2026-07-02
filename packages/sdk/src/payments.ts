/**
 * High-level payment helpers.
 *
 * `createStealthPayment` packages the sender flow (encapsulate to the viewing
 * pk → derive both stealth addresses from the *public* spend key → compute
 * view-tag) into a single call. The sender never learns a private key.
 *
 * `scanAnnouncement` packages the recipient flow:
 *
 *   - **Detection** needs only the viewing secret key and the *public* spend
 *     key: decapsulate → check view-tag → re-derive the stealth address. This
 *     is safe to run on a watch-only device that never sees the spend secret.
 *   - **Spending** additionally needs the spend *secret* key. Pass it as the
 *     optional fourth argument to also receive the spendable secp256k1 private
 *     key (`result.stealthKeys.ethPrivateKey`).
 */

import { KYBER_SHARED_SECRET_SIZE } from './constants.js';
import {
  computeViewTag,
  decapsulate,
  deriveStealthKeys,
  deriveStealthPublic,
  encapsulate,
  parseMetaAddress,
} from './crypto.js';
import { SpecterSdkError } from './errors.js';
import { hexToBytes } from './internal/encoding.js';
import {
  KyberPublicKeyInput,
  KyberSecretKeyInput,
  parseHexOrBytes,
  SpendPublicKeyInput,
  SpendSecretKeyInput,
  trySchemaParse,
  ViewTagInput,
} from './validation.js';

import {
  KYBER_PUBLIC_KEY_SIZE,
  KYBER_SECRET_KEY_SIZE,
  SPEND_PUBLIC_KEY_SIZE,
  SPEND_SECRET_KEY_SIZE,
} from './constants.js';

import type {
  AnnouncementInput,
  KyberKeyPair,
  KyberPublicKeyHex,
  MetaAddressHex,
  ScanResult,
  Secp256k1SpendPublicHex,
  Secp256k1SpendSecretHex,
  SpecterKeys,
  StealthPayment,
} from './types.js';

/**
 * Sender-side: given a recipient meta-address, build a complete payment
 * payload (ciphertext + view-tag + Eth address + Sui address). The shared
 * secret is consumed internally and never leaks out of this function, and no
 * private key is ever computed on the sender side.
 */
export function createStealthPayment(metaAddress: MetaAddressHex): StealthPayment {
  const meta = parseMetaAddress(metaAddress);
  // SPECTER encapsulates against the *viewing* public key so the recipient can
  // scan with their viewing secret without exposing the spending secret. The
  // spending public key is the base point for the stealth address tweak.
  const enc = encapsulate(meta.address.viewingPk);
  // The shared secret is non-enumerable on `enc` but still readable here.
  const ssBytes = hexToBytes(enc.sharedSecret, {
    lengthBytes: KYBER_SHARED_SECRET_SIZE,
    field: 'shared_secret',
  });
  const detected = deriveStealthPublic(meta.address.spendingPk, ssBytes);
  const viewTag = computeViewTag(ssBytes);

  return {
    ephemeralCiphertext: enc.ciphertext,
    viewTag,
    ethAddress: detected.ethAddress,
    suiAddress: detected.suiAddress,
  };
}

/**
 * Recipient-side: try to match a single announcement against the recipient's
 * viewing keys.
 *
 *   1. Decapsulate against the viewing secret key.
 *   2. Compare the view-tag: a non-match returns `{ isMatch: false }`.
 *   3. Re-derive the stealth addresses from the *public* spend key (detection).
 *   4. If `spendingSecretKey` is supplied, also derive the spendable
 *      secp256k1 private key and return it as `result.stealthKeys`.
 *
 * The spending public key is passed explicitly (rather than inferred) because
 * some applications keep the spending key on a more-restricted device. When
 * `spendingSecretKey` is omitted the scan is watch-only and never computes a
 * private key.
 */
export function scanAnnouncement(
  announcement: AnnouncementInput,
  viewingKeys: KyberKeyPair,
  spendingPublicKey: Secp256k1SpendPublicHex | Uint8Array,
  spendingSecretKey?: Secp256k1SpendSecretHex | Uint8Array,
): ScanResult {
  if (typeof announcement !== 'object') {
    throw new SpecterSdkError('INVALID_META_ADDRESS', 'announcement must be an object');
  }
  const expectedTag = trySchemaParse(
    ViewTagInput,
    announcement.viewTag,
    'announcement.view_tag',
  ) as number;

  // Validate the viewing keypair shape and the spend public key up front.
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
  parseHexOrBytes(
    SpendPublicKeyInput,
    spendingPublicKey,
    'spending_public_key',
    SPEND_PUBLIC_KEY_SIZE,
  );
  if (spendingSecretKey !== undefined) {
    parseHexOrBytes(
      SpendSecretKeyInput,
      spendingSecretKey,
      'spending_secret_key',
      SPEND_SECRET_KEY_SIZE,
    );
  }

  const sharedSecretHex = decapsulate(announcement.ephemeralCiphertext, viewingKeys.secretKey);
  const ssBytes = hexToBytes(sharedSecretHex, {
    lengthBytes: KYBER_SHARED_SECRET_SIZE,
    field: 'shared_secret',
  });

  const computedTag = computeViewTag(ssBytes);
  if (computedTag !== expectedTag) {
    return { isMatch: false, reason: 'view_tag_mismatch' };
  }

  // Detection: re-derive the stealth addresses from the public spend key.
  const detected = deriveStealthPublic(spendingPublicKey, ssBytes);

  if (spendingSecretKey === undefined) {
    return { isMatch: true, detected };
  }

  // Spending: derive the private key and defensively confirm it matches the
  // detected address (guards against a spend secret / public key mismatch).
  const stealthKeys = deriveStealthKeys(spendingSecretKey, ssBytes);
  if (stealthKeys.ethAddress !== detected.ethAddress) {
    throw new SpecterSdkError(
      'STEALTH_DERIVATION_FAILED',
      'spending secret key does not correspond to the supplied spending public key',
    );
  }
  return { isMatch: true, detected, stealthKeys };
}

/**
 * Convenience helper: scan a batch of announcements against the same viewing
 * keys / spend key material. Announcements that do not match are returned as
 * `{ isMatch: false }` entries. Useful for client-side wallet scanning loops.
 */
export function scanAnnouncements(
  announcements: readonly AnnouncementInput[],
  viewingKeys: KyberKeyPair,
  spendingPublicKey: Secp256k1SpendPublicHex | Uint8Array,
  spendingSecretKey?: Secp256k1SpendSecretHex | Uint8Array,
): ScanResult[] {
  return announcements.map((ann) =>
    scanAnnouncement(ann, viewingKeys, spendingPublicKey, spendingSecretKey),
  );
}

/** Convenience: read the viewing public key from a `SpecterKeys` bundle. */
export function specterKeysViewingPk(keys: SpecterKeys): KyberPublicKeyHex {
  return keys.viewing.publicKey;
}
