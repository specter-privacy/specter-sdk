/**
 * Explicit HTTP client for trusted SPECTER API deployments.
 *
 * The local crypto helpers remain the default security boundary. This module
 * is opt-in for applications that intentionally delegate payment orchestration
 * or scanning to a backend.
 */

import type { z } from 'zod';

import {
  ETH_ADDRESS_SIZE,
  KYBER_CIPHERTEXT_SIZE,
  KYBER_PUBLIC_KEY_SIZE,
  KYBER_SECRET_KEY_SIZE,
  META_ADDRESS_SIZE,
  STEALTH_ETH_PRIVATE_KEY_SIZE,
  SUI_ADDRESS_SIZE,
} from './constants.js';
import { SpecterSdkError } from './errors.js';
import { bytesToHex } from './internal/encoding.js';
import { attachRedactingSerializers, defineSecretField } from './internal/redact.js';
import {
  ApiAnnouncementDto,
  ApiCreateStealthResponse,
  ApiDiscoveryDto,
  ApiGenerateKeysResponse,
  ApiPaymentId,
  ApiPublishAnnouncementResponse,
  ApiScanResponse,
  ChannelIdInput,
  EthAddressInput,
  KyberCiphertextInput,
  KyberPublicKeyInput,
  KyberSecretKeyInput,
  MetaAddressBytesInput,
  parseHexOrBytes,
  StealthEthPrivateInput,
  SuiAddressInput,
  trySchemaParse,
  ViewTagInput,
} from './validation.js';

import type {
  AnnouncementDto,
  AnnouncementInput,
  EthAddressHex,
  Hex,
  KyberCiphertextHex,
  KyberKeyPair,
  KyberPublicKeyHex,
  KyberSecretKeyHex,
  MetaAddressHex,
  PublishAnnouncementInput,
  PublishAnnouncementResponse,
  RemoteDiscovery,
  RemoteGeneratedKeys,
  RemoteScanRequest,
  RemoteScanResponse,
  RemoteStealthPayment,
  SpecterKeys,
  StealthEthPrivateHex,
  SuiAddressHex,
} from './types.js';

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface SpecterApiClientOptions {
  /** Base URL of your trusted SPECTER API, e.g. `https://api.example.com`. */
  readonly baseUrl: string;
  /** Optional fetch implementation for tests, Node runtimes, or custom auth. */
  readonly fetch?: FetchLike;
  /** Extra headers sent with every request, e.g. authorization. */
  readonly headers?: HeadersInit;
}

export interface SpecterApiClient {
  readonly generateKeysRemote: () => Promise<RemoteGeneratedKeys>;
  readonly createStealthPaymentRemote: (
    metaAddress: MetaAddressHex | Uint8Array,
  ) => Promise<RemoteStealthPayment>;
  readonly publishAnnouncement: (
    input: PublishAnnouncementInput,
  ) => Promise<PublishAnnouncementResponse>;
  readonly scanRemote: (input: RemoteScanRequest) => Promise<RemoteScanResponse>;
}

interface ApiAnnouncementWire {
  readonly id?: number;
  readonly ephemeral_key?: string;
  readonly ephemeral_ciphertext?: string;
  readonly view_tag: number;
  readonly timestamp?: number;
  readonly channel_id?: string | null;
  readonly block_number?: number | null;
  readonly tx_hash?: string | null;
  readonly amount?: string | null;
  readonly chain?: string | null;
}

interface ApiDiscoveryWire {
  readonly eth_address?: string;
  readonly stealth_address?: string;
  readonly sui_address?: string;
  readonly stealth_sui_address?: string;
  readonly eth_private_key: string;
  readonly stealth_sk: string;
  readonly announcement_id?: number;
  readonly payment_id?: string;
  readonly timestamp?: number;
}

type ApiGenerateKeysWire = z.infer<typeof ApiGenerateKeysResponse>;
type ApiCreateStealthWire = z.infer<typeof ApiCreateStealthResponse>;
type ApiPublishAnnouncementWire = z.infer<typeof ApiPublishAnnouncementResponse>;
type ApiScanWire = z.infer<typeof ApiScanResponse>;

export function createSpecterApiClient(options: SpecterApiClientOptions): SpecterApiClient {
  const baseUrl = normalizeBaseUrl(options.baseUrl);
  const fetchImpl = resolveFetch(options.fetch);

  async function post(path: string, body: unknown): Promise<unknown> {
    const headers = new Headers(options.headers);
    headers.set('content-type', 'application/json');
    const response = await fetchImpl(`${baseUrl}${path}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });

    const text = await response.text();
    let json: unknown = undefined;
    if (text.length > 0) {
      try {
        json = JSON.parse(text) as unknown;
      } catch (cause) {
        throw new SpecterSdkError('INVALID_API_RESPONSE', 'API returned invalid JSON', {
          cause,
        });
      }
    }

    if (!response.ok) {
      throw new SpecterSdkError(
        'HTTP_ERROR',
        apiErrorMessage(response.status, json),
        { recoverable: response.status >= 500, cause: json },
      );
    }
    return json;
  }

  return {
    async generateKeysRemote() {
      const raw = await post('/api/v1/keys/generate', {});
      const parsed = tryApiParse(ApiGenerateKeysResponse, raw) as ApiGenerateKeysWire;
      const spending = buildRemoteKeyPair(parsed.spending_pk, parsed.spending_sk);
      const viewing = buildRemoteKeyPair(parsed.viewing_pk, parsed.viewing_sk);
      const keys: SpecterKeys = { spending, viewing };
      return {
        keys,
        metaAddress: asMetaAddressHex(parsed.meta_address),
      };
    },

    async createStealthPaymentRemote(metaAddress) {
      const metaHex = asMetaAddressHex(metaAddress);
      const raw = await post('/api/v1/stealth/create', {
        meta_address: metaHex,
      });
      const parsed = tryApiParse(ApiCreateStealthResponse, raw) as ApiCreateStealthWire;
      return {
        paymentId: parsed.payment_id,
        ethAddress: asEthAddressHex(parsed.stealth_address),
        suiAddress: asSuiAddressHex(parsed.stealth_sui_address),
        ephemeralCiphertext: asCiphertextHex(parsed.ephemeral_ciphertext),
        viewTag: asViewTag(parsed.view_tag),
        ...(parsed.announcement !== undefined
          ? { announcement: mapAnnouncement(parsed.announcement) }
          : {}),
      };
    },

    async publishAnnouncement(input) {
      const paymentId = trySchemaParse(ApiPaymentId, input.paymentId, 'payment_id') as string;
      const raw = await post('/api/v1/registry/announcements', {
        payment_id: paymentId,
        ...(input.txHash !== undefined ? { tx_hash: input.txHash } : {}),
        ...(input.blockNumber !== undefined ? { block_number: input.blockNumber } : {}),
        ...(input.amount !== undefined ? { amount: input.amount } : {}),
        ...(input.chain !== undefined ? { chain: input.chain } : {}),
      });
      const parsed = tryApiParse(ApiPublishAnnouncementResponse, raw) as ApiPublishAnnouncementWire;
      return {
        ...(parsed.announcement_id !== undefined
          ? { announcementId: parsed.announcement_id }
          : parsed.id !== undefined
            ? { announcementId: parsed.id }
            : {}),
        ...(parsed.announcement !== undefined
          ? { announcement: mapAnnouncement(parsed.announcement) }
          : {}),
      };
    },

    async scanRemote(input) {
      const raw = await post('/api/v1/stealth/scan', buildScanBody(input));
      const parsed = tryApiParse(ApiScanResponse, raw) as ApiScanWire;
      const discoveries = parsed.discoveries ?? parsed.results ?? [];
      return {
        discoveries: discoveries.map((discovery) => mapDiscovery(discovery)),
      };
    },
  };
}

function resolveFetch(provided: FetchLike | undefined): FetchLike {
  if (provided !== undefined) return provided;
  const globalFetch = (globalThis as unknown as { fetch?: FetchLike }).fetch;
  if (globalFetch === undefined) {
    throw new SpecterSdkError(
      'HTTP_ERROR',
      'no fetch implementation available; pass options.fetch',
      { recoverable: true },
    );
  }
  return globalFetch.bind(globalThis);
}

function normalizeBaseUrl(baseUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(baseUrl);
  } catch (cause) {
    throw new SpecterSdkError('HTTP_ERROR', `invalid API base URL: ${baseUrl}`, { cause });
  }
  if (parsed.protocol !== 'https:' && parsed.hostname !== 'localhost') {
    throw new SpecterSdkError(
      'HTTP_ERROR',
      'SPECTER API base URL must use https, except localhost during development',
    );
  }
  return parsed.toString().replace(/\/$/u, '');
}

function apiErrorMessage(status: number, json: unknown): string {
  if (typeof json === 'object' && json !== null) {
    const record = json as Record<string, unknown>;
    if (typeof record['message'] === 'string') return `SPECTER API ${status}: ${record['message']}`;
    if (typeof record['error'] === 'string') return `SPECTER API ${status}: ${record['error']}`;
  }
  return `SPECTER API request failed with status ${status}`;
}

function tryApiParse(
  schema: { safeParse: (raw: unknown) => { success: true; data: unknown } | { success: false } },
  raw: unknown,
): unknown {
  const result = schema.safeParse(raw);
  if (result.success) return result.data;
  throw new SpecterSdkError('INVALID_API_RESPONSE', 'API response did not match SDK schema', {
    cause: raw,
  });
}

function buildRemoteKeyPair(publicKey: string, secretKey: string): KyberKeyPair {
  const pk = asPublicKeyHex(publicKey);
  const sk = asSecretKeyHex(secretKey);
  const out = { publicKey: pk } as { publicKey: KyberPublicKeyHex; secretKey: KyberSecretKeyHex };
  defineSecretField(out, 'secretKey', sk);
  attachRedactingSerializers(out, ['secretKey']);
  return out;
}

function asPublicKeyHex(value: string): KyberPublicKeyHex {
  return bytesToHex<'KyberPublicKey'>(
    parseHexOrBytes(KyberPublicKeyInput, value, 'kyber_public_key', KYBER_PUBLIC_KEY_SIZE),
  );
}

function asSecretKeyHex(value: string): KyberSecretKeyHex {
  return bytesToHex<'KyberSecretKey'>(
    parseHexOrBytes(KyberSecretKeyInput, value, 'kyber_secret_key', KYBER_SECRET_KEY_SIZE),
  );
}

function asCiphertextHex(value: string): KyberCiphertextHex {
  return bytesToHex<'KyberCiphertext'>(
    parseHexOrBytes(KyberCiphertextInput, value, 'kyber_ciphertext', KYBER_CIPHERTEXT_SIZE),
  );
}

function asMetaAddressHex(value: MetaAddressHex | Uint8Array | string): MetaAddressHex {
  return bytesToHex<'MetaAddress'>(
    parseHexOrBytes(MetaAddressBytesInput, value, 'meta_address', META_ADDRESS_SIZE),
  );
}

function asEthAddressHex(value: string): EthAddressHex {
  return bytesToHex<'EthAddress'>(
    parseHexOrBytes(EthAddressInput, value, 'eth_address', ETH_ADDRESS_SIZE),
  );
}

function asSuiAddressHex(value: string): SuiAddressHex {
  return bytesToHex<'SuiAddress'>(
    parseHexOrBytes(SuiAddressInput, value, 'sui_address', SUI_ADDRESS_SIZE),
  );
}

function asStealthPrivateHex(value: string, field: string): StealthEthPrivateHex {
  return bytesToHex<'StealthEthPrivate'>(
    parseHexOrBytes(StealthEthPrivateInput, value, field, STEALTH_ETH_PRIVATE_KEY_SIZE),
  );
}

function asChannelIdHex(value: string): Hex<'ChannelId'> {
  return bytesToHex<'ChannelId'>(
    parseHexOrBytes(ChannelIdInput, value, 'channel_id', 32),
  );
}

function asViewTag(value: number): number {
  return trySchemaParse(ViewTagInput, value, 'view_tag') as number;
}

function mapAnnouncement(raw: unknown): AnnouncementDto {
  const parsed = tryApiParse(ApiAnnouncementDto, raw) as ApiAnnouncementWire;
  const ciphertext = parsed.ephemeral_ciphertext ?? parsed.ephemeral_key;
  if (ciphertext === undefined) {
    throw new SpecterSdkError(
      'INVALID_API_RESPONSE',
      'announcement is missing ephemeral ciphertext',
    );
  }
  return {
    ...(parsed.id !== undefined ? { id: parsed.id } : {}),
    ephemeralCiphertext: asCiphertextHex(ciphertext),
    viewTag: asViewTag(parsed.view_tag),
    ...(parsed.timestamp !== undefined ? { timestamp: parsed.timestamp } : {}),
    ...(parsed.channel_id != null ? { channelId: asChannelIdHex(parsed.channel_id) } : {}),
    ...(parsed.block_number != null ? { blockNumber: parsed.block_number } : {}),
    ...(parsed.tx_hash != null ? { txHash: parsed.tx_hash } : {}),
    ...(parsed.amount != null ? { amount: parsed.amount } : {}),
    ...(parsed.chain != null ? { chain: parsed.chain } : {}),
  };
}

function buildScanBody(input: RemoteScanRequest): Record<string, unknown> {
  return {
    ...(input.announcements !== undefined
      ? { announcements: input.announcements.map((announcement) => mapAnnouncementInput(announcement)) }
      : {}),
    ...(input.viewingSk !== undefined
      ? { viewing_sk: asSecretKeyHex(input.viewingSk) }
      : {}),
    ...(input.spendingPk !== undefined
      ? { spending_pk: asPublicKeyHex(input.spendingPk) }
      : {}),
    ...(input.spendingSk !== undefined
      ? { spending_sk: asSecretKeyHex(input.spendingSk) }
      : {}),
    ...(input.viewTags !== undefined
      ? { view_tags: input.viewTags.map((tag) => asViewTag(tag)) }
      : {}),
    ...(input.fromTimestamp !== undefined ? { from_timestamp: input.fromTimestamp } : {}),
    ...(input.toTimestamp !== undefined ? { to_timestamp: input.toTimestamp } : {}),
  };
}

function mapAnnouncementInput(input: AnnouncementInput): Record<string, unknown> {
  return {
    ephemeral_ciphertext: asCiphertextHex(input.ephemeralCiphertext),
    view_tag: asViewTag(input.viewTag),
  };
}

function mapDiscovery(raw: unknown): RemoteDiscovery {
  const parsed = tryApiParse(ApiDiscoveryDto, raw) as ApiDiscoveryWire;
  const ethAddress = parsed.eth_address ?? parsed.stealth_address;
  const suiAddress = parsed.sui_address ?? parsed.stealth_sui_address;
  const ethPrivateKey = asStealthPrivateHex(parsed.eth_private_key, 'eth_private_key');
  const stealthSk = asStealthPrivateHex(parsed.stealth_sk, 'stealth_sk');
  const out = {
    ...(ethAddress !== undefined ? { ethAddress: asEthAddressHex(ethAddress) } : {}),
    ...(suiAddress !== undefined ? { suiAddress: asSuiAddressHex(suiAddress) } : {}),
    stealthSk,
    ...(parsed.announcement_id !== undefined ? { announcementId: parsed.announcement_id } : {}),
    ...(parsed.payment_id !== undefined ? { paymentId: parsed.payment_id } : {}),
    ...(parsed.timestamp !== undefined ? { timestamp: parsed.timestamp } : {}),
  } as {
    ethAddress?: EthAddressHex;
    suiAddress?: SuiAddressHex;
    ethPrivateKey: StealthEthPrivateHex;
    stealthSk: StealthEthPrivateHex;
    announcementId?: number;
    paymentId?: string;
    timestamp?: number;
  };
  defineSecretField(out, 'ethPrivateKey', ethPrivateKey);
  attachRedactingSerializers(out, ['ethPrivateKey', 'stealthSk']);
  return out;
}
