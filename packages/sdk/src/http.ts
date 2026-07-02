/**
 * Explicit HTTP client for trusted SPECTER API deployments.
 *
 * ## Security boundary
 *
 * The local, in-browser crypto helpers (`generateSpecterKeys`,
 * `createStealthPayment`, `scanAnnouncement`) are the default and only path
 * that touches secret keys. This HTTP client is **public-data only**:
 *
 *   - `createStealthPaymentRemote` sends a *public* meta-address and receives
 *     an ephemeral ciphertext + stealth addresses.
 *   - `publishAnnouncement` sends a server-side payment id and public
 *     on-chain references.
 *
 * There is deliberately **no** remote key-generation or remote scanning: those
 * require secret keys, and a SPECTER SDK must never transmit a spending or
 * viewing secret over the network. Generate keys locally with
 * `generateSpecterKeys` and scan locally with `scanAnnouncement`.
 */

import type { z } from 'zod';

import {
  KYBER_CIPHERTEXT_SIZE,
  META_ADDRESS_SIZE,
} from './constants.js';
import { SpecterSdkError } from './errors.js';
import { bytesToHex } from './internal/encoding.js';
import {
  ApiAnnouncementDto,
  ApiCreateStealthResponse,
  ApiPaymentId,
  ApiPublishAnnouncementResponse,
  ChannelIdInput,
  EthAddressInput,
  KyberCiphertextInput,
  MetaAddressBytesInput,
  parseHexOrBytes,
  SuiAddressInput,
  trySchemaParse,
  ViewTagInput,
} from './validation.js';

import {
  ETH_ADDRESS_SIZE,
  SUI_ADDRESS_SIZE,
} from './constants.js';

import type {
  AnnouncementDto,
  EthAddressHex,
  Hex,
  KyberCiphertextHex,
  MetaAddressHex,
  PublishAnnouncementInput,
  PublishAnnouncementResponse,
  RemoteStealthPayment,
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
  /**
   * Ask the API to build a stealth payment for a *public* meta-address. Only
   * public data crosses the wire; no secret key is involved.
   */
  readonly createStealthPaymentRemote: (
    metaAddress: MetaAddressHex | Uint8Array,
  ) => Promise<RemoteStealthPayment>;
  /** Publish an announcement's on-chain references (public data only). */
  readonly publishAnnouncement: (
    input: PublishAnnouncementInput,
  ) => Promise<PublishAnnouncementResponse>;
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

type ApiCreateStealthWire = z.infer<typeof ApiCreateStealthResponse>;
type ApiPublishAnnouncementWire = z.infer<typeof ApiPublishAnnouncementResponse>;

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
