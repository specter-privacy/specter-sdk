# `@specterpq/sdk`

Production-grade TypeScript SDK for **SPECTER**, a post-quantum stealth
address protocol powered by ML-KEM-768 (Kyber). Cryptographic operations run
locally through Rust compiled to WebAssembly, with a separate opt-in HTTP client
for trusted SPECTER API deployments.

Local crypto helpers do not send secrets over the network. Remote helpers are
explicit and should only target infrastructure you trust.

---

## Table of contents

- [Why teams use this](#why-teams-use-this)
- [Install](#install)
- [Requirements](#requirements)
- [Quick start (end-to-end flow)](#quick-start-end-to-end-flow)
- [Public API reference](#public-api-reference)
  - [Initialization](#initialization)
  - [Key generation](#key-generation)
  - [Meta-address APIs](#meta-address-apis)
  - [KEM APIs](#kem-apis)
  - [View-tag APIs](#view-tag-apis)
  - [Stealth derivation APIs](#stealth-derivation-apis)
  - [High-level payment flow APIs](#high-level-payment-flow-apis)
  - [Announcement metadata APIs](#announcement-metadata-apis)
  - [Trusted HTTP API client](#trusted-http-api-client)
  - [Constants](#constants)
  - [Errors](#errors)
- [Type notes](#type-notes)
- [Security model](#security-model)
- [Integration patterns](#integration-patterns)
- [What this package does not do](#what-this-package-does-not-do)
- [Support and disclosure](#support-and-disclosure)
- [License](#license)

---

## Why teams use this

- **Post-quantum primitives now**: ML-KEM-768 encapsulation/decapsulation for
  stealth payment workflows.
- **Stealth-by-default addressing**: derive unique destination addresses per
  payment.
- **Client-side trust model**: key generation and shared-secret handling happen
  locally in WASM.
- **Production ergonomics**: strict runtime validation, structured errors,
  stable top-level API, and redaction for secret-bearing fields.
- **Supply-chain posture**: artifacts are built from pinned vendored crypto
  crates with CI verification of the vendor pin on every build and release.

---

## Install

```bash
pnpm add @specterpq/sdk
# or
npm install @specterpq/sdk
# or
yarn add @specterpq/sdk
```

---

## Requirements

- Node.js `>=20` (for server-side usage/tests)
- Modern browser with WebAssembly support (for frontend usage)

The package ships both web and node WASM artifacts and selects the proper
loader at runtime.

---

## Quick start (end-to-end flow)

```ts
import {
  initSpecterSdk,
  generateSpecterKeys,
  metaAddressFromPublicKeys,
  createStealthPayment,
  scanAnnouncement,
} from '@specterpq/sdk';

await initSpecterSdk();

// Recipient setup
const recipient = generateSpecterKeys();
const meta = metaAddressFromPublicKeys(
  recipient.spending.publicKey,
  recipient.viewing.publicKey,
  { description: 'Alice main receive profile' },
);
// publish meta.hex to your transport layer / profile registry

// Sender flow
const payment = createStealthPayment(meta.hex);
// payment: { ephemeralCiphertext, viewTag, ethAddress, suiAddress }
// viewTag is per-payment: SHAKE256(DOMAIN_VIEW_TAG, shared_secret, 32)[0]

// Recipient scan flow
const scan = scanAnnouncement(
  {
    ephemeralCiphertext: payment.ephemeralCiphertext,
    viewTag: payment.viewTag,
  },
  recipient.viewing,
  recipient.spending.publicKey,
);

if (scan.isMatch) {
  // import private key into wallet stack (ethers/viem/etc.)
  const spendable = scan.stealthKeys.ethPrivateKey;
  console.log('recipient stealth ETH', scan.stealthKeys.ethAddress);
}
```

---

## Public API reference

All exports are available at top level:

```ts
import * as Specter from '@specterpq/sdk';
```

### Initialization

#### `initSpecterSdk(opts?)`

Initializes and caches the underlying WASM module. Safe to call multiple times.

```ts
import { initSpecterSdk } from '@specterpq/sdk';

await initSpecterSdk();
// Optional browser override when hosting wasm files yourself:
await initSpecterSdk({ wasmUrl: 'https://cdn.example.com/specter_wasm_bg.wasm' });
```

---

### Key generation

#### `generateKeysLocal()`

Generates one ML-KEM-768 keypair.

```ts
import { generateKeysLocal } from '@specterpq/sdk';

const kp = generateKeysLocal();
console.log(kp.publicKey); // safe to log
// kp.secretKey exists but is secret-bearing and redacted from JSON/inspect
```

#### `generateSpecterKeys()`

Generates recipient identity: `{ spending, viewing }`.

```ts
import { generateSpecterKeys } from '@specterpq/sdk';

const keys = generateSpecterKeys();
console.log(keys.spending.publicKey);
console.log(keys.viewing.publicKey);
```

#### `specterKeysViewingPk(keys)`

Convenience helper to read viewing public key from a full identity object.

```ts
import { generateSpecterKeys, specterKeysViewingPk } from '@specterpq/sdk';

const keys = generateSpecterKeys();
const viewingPk = specterKeysViewingPk(keys);
```

---

### Meta-address APIs

#### `metaAddressFromPublicKeys(spendingPk, viewingPk, metadata?)`

Builds canonical recipient meta-address bundle.

```ts
import {
  generateSpecterKeys,
  metaAddressFromPublicKeys,
} from '@specterpq/sdk';

const { spending, viewing } = generateSpecterKeys();
const meta = metaAddressFromPublicKeys(
  spending.publicKey,
  viewing.publicKey,
  {
    description: 'Alice',
    avatar: 'ipfs://Qm...',
    createdAt: Math.floor(Date.now() / 1000),
  },
);

console.log(meta.hex);           // publishable
console.log(meta.bytes.length);  // 2369
console.log(meta.address.version); // 1
```

#### `parseMetaAddress(input)`

Parses a serialized meta-address from `MetaAddressHex` or `Uint8Array`.

```ts
import { parseMetaAddress } from '@specterpq/sdk';

const parsed = parseMetaAddress(meta.hex);
console.log(parsed.address.spendingPk);
console.log(parsed.address.viewingPk);
```

---

### KEM APIs

#### `encapsulate(publicKey)`

Sender-side KEM operation against recipient viewing public key.

```ts
import { encapsulate } from '@specterpq/sdk';

const enc = encapsulate(recipient.viewing.publicKey);
console.log(enc.ciphertext); // announce publicly
// enc.sharedSecret is secret-bearing and redacted in JSON/inspect
```

#### `decapsulate(ciphertext, secretKey)`

Recipient-side KEM operation against viewing secret key.

```ts
import { decapsulate } from '@specterpq/sdk';

const sharedSecret = decapsulate(enc.ciphertext, recipient.viewing.secretKey);
```

---

### View-tag APIs

#### `computeViewTag(sharedSecret)`

Computes 1-byte view-tag (`0..255`) from shared secret.

```ts
import { computeViewTag } from '@specterpq/sdk';

const tag = computeViewTag(sharedSecret);
console.log(tag); // number 0..255
```

#### `verifyViewTag(sharedSecret, expectedTag)`

Boolean check for view-tag match.

```ts
import { verifyViewTag } from '@specterpq/sdk';

if (verifyViewTag(sharedSecret, incomingTag)) {
  // candidate payment match
}
```

---

### Stealth derivation APIs

#### `deriveStealthAddress(spendingPk, sharedSecret)`

Derives stealth Ethereum address (`0x` + 20 bytes).

```ts
import { deriveStealthAddress } from '@specterpq/sdk';

const ethAddress = deriveStealthAddress(recipient.spending.publicKey, sharedSecret);
```

#### `deriveStealthSuiAddress(spendingPk, sharedSecret)`

Derives stealth Sui address (`0x` + 32 bytes).

```ts
import { deriveStealthSuiAddress } from '@specterpq/sdk';

const suiAddress = deriveStealthSuiAddress(recipient.spending.publicKey, sharedSecret);
```

#### `deriveStealthKeys(spendingPk, sharedSecret)`

Derives full spendable key material for recipient-side wallet import.

```ts
import { deriveStealthKeys } from '@specterpq/sdk';

const keys = deriveStealthKeys(recipient.spending.publicKey, sharedSecret);
console.log(keys.ethAddress);
console.log(keys.suiAddress);
console.log(keys.publicKey); // secp256k1 uncompressed pubkey
// keys.ethPrivateKey exists but is redacted from JSON/inspect
```

---

### High-level payment flow APIs

#### `createStealthPayment(metaAddress)`

High-level sender helper:
- parse meta-address
- encapsulate to viewing public key
- derive stealth ETH/Sui addresses
- compute view-tag

```ts
import { createStealthPayment } from '@specterpq/sdk';

const payment = createStealthPayment(meta.hex);
// {
//   ephemeralCiphertext,
//   viewTag,
//   ethAddress,
//   suiAddress
// }
```

#### `scanAnnouncement(announcement, viewingKeys, spendingPublicKey)`

High-level recipient helper for a single announcement.

```ts
import { scanAnnouncement } from '@specterpq/sdk';

const result = scanAnnouncement(
  {
    ephemeralCiphertext: payment.ephemeralCiphertext,
    viewTag: payment.viewTag,
  },
  recipient.viewing,
  recipient.spending.publicKey,
);

if (!result.isMatch) {
  // result.reason: 'view_tag_mismatch' | 'address_mismatch'
} else {
  console.log(result.stealthKeys.ethAddress);
}
```

#### `scanAnnouncements(announcements, viewingKeys, spendingPublicKey)`

Batch scanning helper.

```ts
import { scanAnnouncements } from '@specterpq/sdk';

const results = scanAnnouncements(batch, recipient.viewing, recipient.spending.publicKey);
const matches = results.filter((r) => r.isMatch);
```

---

### Announcement metadata APIs

Each on-chain announcement can carry a fixed **77-byte metadata block**
(source-chain tx hash, payment amount, source chain id). The payload is
encrypted with **AES-256-GCM** under a key + nonce derived from the ML-KEM
shared secret, producing a **93-byte block**. The 1-byte view tag stays in the
clear at byte 0 so scanners can filter ~255/256 events without decrypting.

The high-level pair is `sealAnnouncementMetadata` (sender) and
`openAnnouncementMetadata` (recipient):

```ts
import {
  sealAnnouncementMetadata,
  openAnnouncementMetadata,
  encapsulate,
  decapsulate,
} from '@specterpq/sdk';

// Sender: encapsulate to the recipient, then seal payment metadata.
const enc = encapsulate(recipient.viewing.publicKey);
const sealed = sealAnnouncementMetadata(
  {
    txHash: '0x' + 'ab'.repeat(32), // 32-byte source-chain tx hash
    amount: 1_000_000_000_000_000_000n, // 1e18 wei, as a bigint
    sourceChainId: 42161, // Arbitrum One
  },
  enc.sharedSecret,
);
// publish `sealed` (93-byte hex) alongside `enc.ciphertext` in the announcement.
// The view tag is derived from the shared secret automatically.

// Recipient: decapsulate, then open the metadata.
const sharedSecret = decapsulate(enc.ciphertext, recipient.viewing.secretKey);
const meta = openAnnouncementMetadata(sealed, sharedSecret);
// meta: { viewTag, txHash?, amount?, sourceChainId? }
```

`openAnnouncementMetadata` throws `SpecterSdkError` with code
`METADATA_DECRYPTION_FAILED` when the authentication tag does not verify — the
expected outcome for announcements addressed to someone else.

Lower-level building blocks are also exported for advanced flows:

- `encodeAnnouncementMetadata({ viewTag, txHash?, amount?, sourceChainId? })` →
  77-byte `Uint8Array`.
- `decodeAnnouncementMetadata(block)` → structured `AnnouncementMetadata`.
- `encryptAnnouncementMetadata(plaintext77, sharedSecret)` → 93-byte hex.
- `decryptAnnouncementMetadata(encrypted, sharedSecret)` → 77-byte `Uint8Array`.

---

### Trusted HTTP API client

The default crypto API is local-first. Use `createSpecterApiClient` only when
your app intentionally trusts a SPECTER API deployment to orchestrate payments,
publish server-held announcements, or scan remotely.

```ts
import { createSpecterApiClient } from '@specterpq/sdk';

const api = createSpecterApiClient({
  baseUrl: 'https://api.example.com',
  headers: { authorization: `Bearer ${token}` },
});
```

#### `generateKeysRemote()`

Calls `POST /api/v1/keys/generate` and maps the response into
`{ keys, metaAddress }`. Secret fields are still redacted in JSON/inspect, but
remote key generation means the server sees the generated secret keys. Prefer
`generateSpecterKeys()` for wallets unless you have a strong operational reason.

#### `createStealthPaymentRemote(metaAddress)`

Calls `POST /api/v1/stealth/create` with `{ meta_address }`. The returned
`paymentId` is the server-authoritative handle that binds the announcement and
view-tag to this payment.

```ts
const payment = await api.createStealthPaymentRemote(meta.hex);
// payment: { paymentId, ethAddress, suiAddress, ephemeralCiphertext, viewTag, announcement? }
```

#### `publishAnnouncement(input)`

Calls `POST /api/v1/registry/announcements`. Prefer the `paymentId` path so the
server publishes its stored announcement instead of trusting client-supplied
view-tags.

```ts
await api.publishAnnouncement({
  paymentId: payment.paymentId,
  txHash: '0x...',
  chain: 'ethereum',
});
```

#### `scanRemote(input)`

Calls `POST /api/v1/stealth/scan` and validates discovery DTOs. Remote scanning
may send `viewingSk` and other sensitive material to your backend; local
`scanAnnouncement` / `scanAnnouncements` remains the safer default.

```ts
const remoteScan = await api.scanRemote({
  announcements,
  viewingSk: recipient.viewing.secretKey,
  spendingPk: recipient.spending.publicKey,
});
```

---

### Constants

Use constants for runtime checks and schema alignment:

```ts
import {
  KYBER_PUBLIC_KEY_SIZE,
  KYBER_SECRET_KEY_SIZE,
  KYBER_CIPHERTEXT_SIZE,
  KYBER_SHARED_SECRET_SIZE,
  META_ADDRESS_SIZE,
  VIEW_TAG_SIZE,
  ETH_ADDRESS_SIZE,
  SUI_ADDRESS_SIZE,
  STEALTH_SECP256K1_PUBLIC_SIZE,
  STEALTH_ETH_PRIVATE_KEY_SIZE,
  PROTOCOL_VERSION,
  PLAINTEXT_METADATA_SIZE,
  ENCRYPTED_METADATA_SIZE,
} from '@specterpq/sdk';
```

---

### Errors

All thrown SDK errors are instances of `SpecterSdkError`.

```ts
import { SpecterSdkError, encapsulate } from '@specterpq/sdk';

try {
  encapsulate('0xdeadbeef' as never);
} catch (err) {
  if (err instanceof SpecterSdkError) {
    console.error(err.code, err.category, err.recoverable, err.message);
  } else {
    throw err;
  }
}
```

Typical error codes:
- `NOT_INITIALIZED`
- `INVALID_KEY_SIZE`
- `INVALID_CIPHERTEXT_SIZE`
- `INVALID_SHARED_SECRET_SIZE`
- `INVALID_METADATA_SIZE`
- `INVALID_METADATA_FIELD`
- `INVALID_HEX`
- `INVALID_META_ADDRESS`
- `INVALID_METADATA_JSON`
- `INVALID_VIEW_TAG`
- `INVALID_API_RESPONSE`
- `HTTP_ERROR`
- `ENCAPSULATION_FAILED`
- `DECAPSULATION_FAILED`
- `STEALTH_DERIVATION_FAILED`
- `METADATA_DECRYPTION_FAILED`
- `WASM_LOAD_FAILED`
- `INTERNAL_ERROR`

---

## Type notes

- Cryptographic strings use branded hex aliases (`KyberPublicKeyHex`, etc.).
- You can pass either branded hex or `Uint8Array` to most low-level functions.
- High-level APIs (`createStealthPayment`, `scanAnnouncement`) are recommended
  for app integration unless you need custom flow control.

---

## Security model

- WASM cryptography runs client-side.
- Secret-bearing fields (`secretKey`, `sharedSecret`, `ethPrivateKey`) are:
  - non-enumerable
  - redacted in JSON serialization
  - redacted in Node inspect/logging hooks
- Inputs are validated and outputs are length-checked.
- Local crypto helpers are offline-by-default. Network calls only happen through
  `createSpecterApiClient`.
- `generateKeysRemote` and `scanRemote` can expose secret material to your
  backend. Use them only with a trusted API, TLS, and an application-level
  authorization boundary.

Full policy: `SECURITY.md` in repo root.

---

## Integration patterns

### Pattern A: Wallet receive profile

1. Generate recipient keys (`generateSpecterKeys`)
2. Publish `metaAddressFromPublicKeys(...).hex` to your profile registry
3. Keep secret keys in secure local storage/HSM boundary

### Pattern B: Sender payment composer

1. Resolve recipient meta hex from your registry
2. Call `createStealthPayment(metaHex)`
3. Use `ethAddress`/`suiAddress` as destination
4. Publish announcement (`ephemeralCiphertext`, `viewTag`) to your transport

### Pattern B2: Server-authoritative sender flow

1. Create an API client with a trusted base URL
2. Call `createStealthPaymentRemote(metaHex)`
3. Send funds to the returned stealth address
4. Call `publishAnnouncement({ paymentId, txHash, chain })`

### Pattern C: Recipient scanner

1. Pull announcements from your transport
2. `scanAnnouncements(batch, viewingKeys, spendingPk)`
3. Import `ethPrivateKey` from matching results into signing path

---

## What this package does not do

- It does not sign transactions for you.
- It does not provide chain indexers or RPC abstraction.
- It does not resolve ENS/SuiNS/IPFS by itself.
- It does not make network calls unless you explicitly use `createSpecterApiClient`.

---

## Support and disclosure

- Project docs: <https://github.com/specter-privacy/specter-sdk>
- Security disclosure: **hello@specterpq.com**
- Please report vulnerabilities privately (not via public issues).

---

## License

Apache-2.0. See `LICENSE`.
