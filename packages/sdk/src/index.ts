/**
 * @specterpq/sdk public entry point.
 *
 * Browser-first SDK for the SPECTER post-quantum stealth address protocol.
 * Generates ML-KEM-768 keys, builds meta-addresses, encapsulates and
 * decapsulates ephemeral secrets, computes view-tags, and derives stealth
 * Ethereum + Sui addresses entirely in the user's browser via Rust compiled
 * to WebAssembly. No secret keys ever leave the device.
 *
 * **Usage:**
 *
 * ```ts
 * import { initSpecterSdk, generateSpecterKeys, createStealthPayment } from '@specterpq/sdk';
 *
 * await initSpecterSdk();
 * const recipient = generateSpecterKeys();
 * // ...publish recipient.viewing.publicKey + spending.publicKey via meta-address
 * ```
 *
 * Read SECURITY.md before integrating in production.
 */

export { initSpecterSdk, type LoadOptions } from './init.js';

export {
  computeViewTag,
  decapsulate,
  deriveStealthAddress,
  deriveStealthKeys,
  deriveStealthSuiAddress,
  encapsulate,
  generateKeysLocal,
  generateSpecterKeys,
  metaAddressFromPublicKeys,
  parseMetaAddress,
  verifyViewTag,
} from './crypto.js';

export {
  createStealthPayment,
  scanAnnouncement,
  scanAnnouncements,
  specterKeysViewingPk,
} from './payments.js';

export {
  ETH_ADDRESS_SIZE,
  KYBER_CIPHERTEXT_SIZE,
  KYBER_PUBLIC_KEY_SIZE,
  KYBER_SECRET_KEY_SIZE,
  KYBER_SHARED_SECRET_SIZE,
  META_ADDRESS_SIZE,
  PROTOCOL_VERSION,
  STEALTH_ETH_PRIVATE_KEY_SIZE,
  STEALTH_SECP256K1_PUBLIC_SIZE,
  SUI_ADDRESS_SIZE,
  VIEW_TAG_SIZE,
} from './constants.js';

export {
  SpecterSdkError,
  type SpecterErrorCategory,
  type SpecterErrorCode,
} from './errors.js';

export type {
  AnnouncementInput,
  EncapsulationResult,
  EthAddressHex,
  Hex,
  KyberCiphertextHex,
  KyberKeyPair,
  KyberPublicKeyHex,
  KyberSecretKeyHex,
  MetaAddress,
  MetaAddressBundle,
  MetaAddressHex,
  MetaAddressMetadata,
  ScanResult,
  SharedSecretHex,
  SpecterKeys,
  StealthAddresses,
  StealthEthPrivateHex,
  StealthKeys,
  StealthPayment,
  StealthSecp256k1PublicHex,
  SuiAddressHex,
} from './types.js';
