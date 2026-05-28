# @specterpq/sdk

Browser-first SDK for the [SPECTER](https://specterpq.com) post-quantum stealth address protocol. Generates ML-KEM-768 keys, builds meta-addresses, encapsulates and decapsulates ephemeral secrets, computes per-payment view-tags, and derives stealth Ethereum + Sui addresses **entirely in the user's browser** via Rust compiled to WebAssembly. No secret keys leave the device unless you explicitly opt into the trusted HTTP API helpers.

## Status

`0.x` — pre-1.0. The public surface listed below is stable across `0.x.y` patch and `0.y.x` minor bumps; breaking changes ship as a minor bump until 1.0.

## Why this matters (and why it is secure)

SPECTER gives wallets and apps a practical way to move from "one public address forever" to "fresh stealth destination per payment" without giving up UX.

- **What enables it**: ML-KEM-768 (post-quantum KEM), deterministic stealth derivation, and a compact view-tag filter are exposed through Rust->WASM bindings.
- **Secure key generation**: recipient spending/viewing keys are generated locally inside the WASM crypto layer; no backend round-trip is required.
- **Flow in one line**: recipient publishes a meta-address -> sender encapsulates to viewing key and derives stealth destinations -> recipient scans announcements and recovers spendable stealth keys only for matches.
- **Why this is safer than static addresses**: each payment can target a unique stealth address, making trivial address reuse tracking much harder.
- **Defense-in-depth in SDK design**: strict input/output length checks, typed errors, redaction of secret-bearing fields in JSON/inspect/logging paths, and offline-by-default behavior.
- **Server flow support**: an opt-in HTTP client covers `payment_id`-bound API flows while keeping network behavior separate from local crypto helpers.
- **Supply-chain confidence**: vendored Rust crates are pinned to an upstream SHA, verified in CI, and npm releases are configured with provenance.

In short, this SDK is built for teams that want strong cryptographic privacy defaults without building custom crypto infrastructure.

## What this SDK is

- A wasm-bindgen wrapper over [`pranshurastogi/SPECTER`](https://github.com/pranshurastogi/SPECTER)'s `specter-core` and `specter-crypto` crates. Vendored sources live in `vendor/` pinned to a specific upstream SHA recorded in `vendor/VENDORED_AT.json`.
- A strict TypeScript layer with branded `Hex` types, runtime validation via [Zod](https://zod.dev), redacted serialization for secret-bearing fields, and exhaustive contract tests against the protocol constants (`KYBER_PUBLIC_KEY_SIZE = 1184`, etc.).
- Offline-by-default. The crypto helpers make no network calls, load no remote code, and emit no telemetry. The separate HTTP client only runs when you create it with a trusted API `baseUrl`. See [`SECURITY.md`](./SECURITY.md).

## What this SDK is NOT

- It is **not** a transaction signer. Pass `ethPrivateKey` to `viem` / `ethers` / `@mysten/sui` to sign.
- It does **not** resolve ENS / SuiNS or fetch IPFS content. Wire those to your backend or do them yourself.
- It does **not** sign or broadcast transactions. It can call a trusted SPECTER API for payment creation, registry publish, and remote scan, but transaction submission remains yours.

## Public API (top-level, semver-stable)

```ts
import {
  initSpecterSdk,
  generateKeysLocal,
  generateSpecterKeys,
  metaAddressFromPublicKeys,
  parseMetaAddress,
  encapsulate,
  decapsulate,
  computeViewTag,
  verifyViewTag,
  deriveStealthAddress,
  deriveStealthSuiAddress,
  deriveStealthKeys,
  createStealthPayment,
  createSpecterApiClient,
  scanAnnouncement,
  SpecterSdkError,
  KYBER_PUBLIC_KEY_SIZE,
  KYBER_SECRET_KEY_SIZE,
  KYBER_CIPHERTEXT_SIZE,
  KYBER_SHARED_SECRET_SIZE,
  VIEW_TAG_SIZE,
  ETH_ADDRESS_SIZE,
  SUI_ADDRESS_SIZE,
  PROTOCOL_VERSION,
} from '@specterpq/sdk';

await initSpecterSdk();

// Recipient setup
const { spending, viewing } = generateSpecterKeys();
const meta = metaAddressFromPublicKeys(spending.publicKey, viewing.publicKey);
// publish meta.hex to your name service

// Sender (knows recipient's meta-address hex)
const payment = createStealthPayment(meta.hex);
// submit payment.ethAddress as the recipient, payment.ephemeralCiphertext + payment.viewTag as the announcement

// Recipient scan
const result = scanAnnouncement(
  { ephemeralCiphertext: payment.ephemeralCiphertext, viewTag: payment.viewTag },
  viewing,
  spending.publicKey,
);
if (result.isMatch) {
  // result.stealthKeys.ethPrivateKey is the spendable secp256k1 key for result.stealthKeys.ethAddress
}

// Optional trusted API flow: server creates and later publishes the authoritative announcement.
const api = createSpecterApiClient({ baseUrl: 'https://api.example.com' });
const remotePayment = await api.createStealthPaymentRemote(meta.hex);
await api.publishAnnouncement({
  paymentId: remotePayment.paymentId,
  txHash: '0x...',
  chain: 'ethereum',
});
```

See [`packages/sdk/README.md`](./packages/sdk/README.md) for the full reference.

## Repo layout

```
rust/specter-wasm/    wasm-bindgen bridge crate
vendor/specter-core/  pinned mirror of pranshurastogi/SPECTER:specter/specter-core
vendor/specter-crypto/ pinned mirror of pranshurastogi/SPECTER:specter/specter-crypto
packages/sdk/         the @specterpq/sdk npm package
scripts/              sync-backend.sh, verify-vendor.sh
.github/workflows/    ci.yml, release.yml, sync-backend.yml
```

## Development

See [`CONTRIBUTING.md`](./CONTRIBUTING.md). TL;DR:

```bash
pnpm install
pnpm vendor:verify
pnpm build:wasm && pnpm build
pnpm test
pnpm test:browser
```

## Docs index

- [`README.md`](./README.md) - project overview and architecture snapshot
- [`packages/sdk/README.md`](./packages/sdk/README.md) - full npm package API docs with examples
- [`cheatsheet.md`](./cheatsheet.md) - operator runbook (what to run when)
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) - contributor workflow and PR checklist
- [`SECURITY.md`](./SECURITY.md) - threat model and vulnerability disclosure process

## Security

Vulnerability reports go to **hello@specterpq.com**, not GitHub Issues. Read [`SECURITY.md`](./SECURITY.md) before filing.

## License

Apache-2.0. See [`LICENSE`](./LICENSE).
