import { describe, expect, it } from 'vitest';

import {
  createSpecterApiClient,
  createStealthPayment,
  generateSpecterKeys,
  metaAddressFromPublicKeys,
  SpecterSdkError,
} from '../../src/index.js';

interface CapturedRequest {
  readonly url: string;
  readonly init: RequestInit | undefined;
}

function jsonResponse(body: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
    ...init,
  });
}

function readBody(init: RequestInit | undefined): unknown {
  if (typeof init?.body !== 'string') return undefined;
  return JSON.parse(init.body) as unknown;
}

describe('createSpecterApiClient', () => {
  it('exposes only public-data methods (no remote key-gen or scanning)', () => {
    const client = createSpecterApiClient({
      baseUrl: 'https://api.example.test',
      fetch: () => Promise.resolve(jsonResponse({})),
    });
    // Issue #2: the SDK must never transmit secret keys. These methods are
    // deliberately absent.
    const asRecord = client as unknown as Record<string, unknown>;
    expect(asRecord['generateKeysRemote']).toBeUndefined();
    expect(asRecord['scanRemote']).toBeUndefined();
    expect(typeof client.createStealthPaymentRemote).toBe('function');
    expect(typeof client.publishAnnouncement).toBe('function');
  });

  it('uses server-authoritative payment_id when creating and publishing payments', async () => {
    const recipient = generateSpecterKeys();
    const meta = metaAddressFromPublicKeys(
      recipient.spending.publicKey,
      recipient.viewing.publicKey,
    );
    const localPayment = createStealthPayment(meta.hex);
    const calls: CapturedRequest[] = [];
    const fetchImpl = (url: string, init?: RequestInit): Promise<Response> => {
      calls.push({ url, init });
      if (url.endsWith('/api/v1/stealth/create')) {
        return Promise.resolve(jsonResponse({
          payment_id: 'pay_123',
          stealth_address: localPayment.ethAddress,
          stealth_sui_address: localPayment.suiAddress,
          ephemeral_ciphertext: localPayment.ephemeralCiphertext,
          view_tag: localPayment.viewTag,
          announcement: {
            ephemeral_key: localPayment.ephemeralCiphertext,
            view_tag: localPayment.viewTag,
          },
        }));
      }
      return Promise.resolve(jsonResponse({
        announcement_id: 42,
        announcement: {
          ephemeral_key: localPayment.ephemeralCiphertext,
          view_tag: localPayment.viewTag,
        },
      }));
    };

    const client = createSpecterApiClient({
      baseUrl: 'https://api.example.test',
      fetch: fetchImpl,
    });

    const payment = await client.createStealthPaymentRemote(meta.hex);
    const published = await client.publishAnnouncement({
      paymentId: payment.paymentId,
      txHash: '0xabc',
      chain: 'ethereum',
    });

    expect(payment.paymentId).toBe('pay_123');
    expect(payment.ethAddress).toBe(localPayment.ethAddress);
    expect(payment.announcement?.ephemeralCiphertext).toBe(localPayment.ephemeralCiphertext);
    expect(readBody(calls[0]?.init)).toEqual({ meta_address: meta.hex });
    expect(calls[1]?.url).toBe('https://api.example.test/api/v1/registry/announcements');
    expect(readBody(calls[1]?.init)).toEqual({
      payment_id: 'pay_123',
      tx_hash: '0xabc',
      chain: 'ethereum',
    });
    expect(published.announcementId).toBe(42);
  });

  it('covers optional API response aliases (bytes meta-address, id alias, full announcement)', async () => {
    const recipient = generateSpecterKeys();
    const meta = metaAddressFromPublicKeys(
      recipient.spending.publicKey,
      recipient.viewing.publicKey,
    );
    const payment = createStealthPayment(meta.hex);

    const channelId = `0x${'11'.repeat(32)}`;
    const calls: CapturedRequest[] = [];
    const fetchImpl = (url: string, init?: RequestInit): Promise<Response> => {
      calls.push({ url, init });
      if (url.endsWith('/api/v1/stealth/create')) {
        return Promise.resolve(jsonResponse({
          payment_id: 'pay_alias',
          stealth_address: payment.ethAddress,
          stealth_sui_address: payment.suiAddress,
          ephemeral_ciphertext: payment.ephemeralCiphertext,
          view_tag: payment.viewTag,
        }));
      }
      return Promise.resolve(jsonResponse({
        id: 99,
        announcement: {
          id: 99,
          ephemeral_ciphertext: payment.ephemeralCiphertext,
          view_tag: payment.viewTag,
          timestamp: 123,
          channel_id: channelId,
          block_number: 456,
          tx_hash: '0xabc',
          amount: '1',
          chain: 'ethereum',
        },
      }));
    };

    const client = createSpecterApiClient({
      baseUrl: 'http://localhost:8787',
      headers: { authorization: 'Bearer test' },
      fetch: fetchImpl,
    });
    // meta-address supplied as raw bytes exercises the Uint8Array path.
    const remotePayment = await client.createStealthPaymentRemote(meta.bytes);
    const published = await client.publishAnnouncement({ paymentId: 'pay_alias' });

    expect(remotePayment.announcement).toBeUndefined();
    expect(published.announcementId).toBe(99);
    expect(published.announcement?.channelId).toBe(channelId);
    expect(published.announcement?.blockNumber).toBe(456);
  });

  it('rejects invalid API responses and failed HTTP status codes', async () => {
    const recipient = generateSpecterKeys();
    const meta = metaAddressFromPublicKeys(
      recipient.spending.publicKey,
      recipient.viewing.publicKey,
    );

    const invalidClient = createSpecterApiClient({
      baseUrl: 'https://api.example.test',
      fetch: () => Promise.resolve(jsonResponse({ nope: true })),
    });
    await expect(invalidClient.createStealthPaymentRemote(meta.hex)).rejects.toMatchObject({
      code: 'INVALID_API_RESPONSE',
    });

    const failedClient = createSpecterApiClient({
      baseUrl: 'https://api.example.test',
      fetch: () => Promise.resolve(jsonResponse({ message: 'bad request' }, { status: 400 })),
    });
    await expect(failedClient.createStealthPaymentRemote(meta.hex)).rejects.toMatchObject({
      code: 'HTTP_ERROR',
      message: 'SPECTER API 400: bad request',
    });

    expect(() =>
      createSpecterApiClient({
        baseUrl: 'http://api.example.test',
        fetch: () => Promise.resolve(jsonResponse({})),
      }),
    ).toThrow(SpecterSdkError);
  });

  it('reports invalid JSON, generic API failures, and malformed announcements', async () => {
    const recipient = generateSpecterKeys();
    const meta = metaAddressFromPublicKeys(
      recipient.spending.publicKey,
      recipient.viewing.publicKey,
    );
    const payment = createStealthPayment(meta.hex);

    const invalidJsonClient = createSpecterApiClient({
      baseUrl: 'https://api.example.test',
      fetch: () => Promise.resolve(new Response('{', { status: 200 })),
    });
    await expect(invalidJsonClient.createStealthPaymentRemote(meta.hex)).rejects.toMatchObject({
      code: 'INVALID_API_RESPONSE',
      message: 'API returned invalid JSON',
    });

    const genericFailureClient = createSpecterApiClient({
      baseUrl: 'https://api.example.test',
      fetch: () => Promise.resolve(jsonResponse({}, { status: 503 })),
    });
    await expect(genericFailureClient.createStealthPaymentRemote(meta.hex)).rejects.toMatchObject({
      code: 'HTTP_ERROR',
      recoverable: true,
      message: 'SPECTER API request failed with status 503',
    });

    const malformedAnnouncementClient = createSpecterApiClient({
      baseUrl: 'https://api.example.test',
      fetch: () => Promise.resolve(jsonResponse({
        payment_id: 'pay_bad',
        stealth_address: payment.ethAddress,
        stealth_sui_address: payment.suiAddress,
        ephemeral_ciphertext: payment.ephemeralCiphertext,
        view_tag: payment.viewTag,
        announcement: {
          view_tag: payment.viewTag,
        },
      })),
    });
    await expect(malformedAnnouncementClient.createStealthPaymentRemote(meta.hex)).rejects.toMatchObject({
      code: 'INVALID_API_RESPONSE',
      message: 'announcement is missing ephemeral ciphertext',
    });
  });
});
