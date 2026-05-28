import { describe, expect, it } from 'vitest';

import {
  createSpecterApiClient,
  createStealthPayment,
  generateSpecterKeys,
  metaAddressFromPublicKeys,
  scanAnnouncement,
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
  it('maps remote key generation and keeps returned secrets redacted', async () => {
    const generated = generateSpecterKeys();
    const meta = metaAddressFromPublicKeys(
      generated.spending.publicKey,
      generated.viewing.publicKey,
    );
    const calls: CapturedRequest[] = [];
    const fetchImpl = (url: string, init?: RequestInit): Promise<Response> => {
      calls.push({ url, init });
      return Promise.resolve(jsonResponse({
        spending_pk: generated.spending.publicKey,
        spending_sk: generated.spending.secretKey,
        viewing_pk: generated.viewing.publicKey,
        viewing_sk: generated.viewing.secretKey,
        meta_address: meta.hex,
      }));
    };

    const client = createSpecterApiClient({
      baseUrl: 'https://api.example.test/',
      fetch: fetchImpl,
    });

    const remote = await client.generateKeysRemote();

    expect(calls[0]?.url).toBe('https://api.example.test/api/v1/keys/generate');
    expect(readBody(calls[0]?.init)).toEqual({});
    expect(remote.metaAddress).toBe(meta.hex);
    expect(remote.keys.spending.publicKey).toBe(generated.spending.publicKey);
    expect(remote.keys.viewing.publicKey).toBe(generated.viewing.publicKey);
    expect(remote.keys).not.toHaveProperty('viewTag');
    expect(JSON.stringify(remote.keys.spending)).toContain('[REDACTED]');
    expect(JSON.stringify(remote.keys.spending)).not.toContain(generated.spending.secretKey);
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

  it('validates remote scan responses and redacts discovered private keys', async () => {
    const recipient = generateSpecterKeys();
    const meta = metaAddressFromPublicKeys(
      recipient.spending.publicKey,
      recipient.viewing.publicKey,
    );
    const payment = createStealthPayment(meta.hex);
    const scan = scanAnnouncement(
      {
        ephemeralCiphertext: payment.ephemeralCiphertext,
        viewTag: payment.viewTag,
      },
      recipient.viewing,
      recipient.spending.publicKey,
    );
    expect(scan.isMatch).toBe(true);
    if (!scan.isMatch) return;

    const calls: CapturedRequest[] = [];
    const fetchImpl = (url: string, init?: RequestInit): Promise<Response> => {
      calls.push({ url, init });
      return Promise.resolve(jsonResponse({
        discoveries: [
          {
            eth_address: scan.stealthKeys.ethAddress,
            sui_address: scan.stealthKeys.suiAddress,
            eth_private_key: scan.stealthKeys.ethPrivateKey,
            stealth_sk: scan.stealthKeys.ethPrivateKey,
            announcement_id: 7,
          },
        ],
      }));
    };

    const client = createSpecterApiClient({
      baseUrl: 'https://api.example.test',
      fetch: fetchImpl,
    });
    const response = await client.scanRemote({
      announcements: [
        {
          ephemeralCiphertext: payment.ephemeralCiphertext,
          viewTag: payment.viewTag,
        },
      ],
      viewingSk: recipient.viewing.secretKey,
      spendingPk: recipient.spending.publicKey,
    });

    expect(calls[0]?.url).toBe('https://api.example.test/api/v1/stealth/scan');
    expect(readBody(calls[0]?.init)).toEqual({
      announcements: [
        {
          ephemeral_ciphertext: payment.ephemeralCiphertext,
          view_tag: payment.viewTag,
        },
      ],
      viewing_sk: recipient.viewing.secretKey,
      spending_pk: recipient.spending.publicKey,
    });
    expect(response.discoveries[0]?.announcementId).toBe(7);
    expect(JSON.stringify(response.discoveries[0])).toContain('[REDACTED]');
    expect(JSON.stringify(response.discoveries[0])).not.toContain(scan.stealthKeys.ethPrivateKey);
  });

  it('rejects invalid API responses and failed HTTP status codes', async () => {
    const invalidClient = createSpecterApiClient({
      baseUrl: 'https://api.example.test',
      fetch: () => Promise.resolve(jsonResponse({ nope: true })),
    });
    await expect(invalidClient.generateKeysRemote()).rejects.toMatchObject({
      code: 'INVALID_API_RESPONSE',
    });

    const failedClient = createSpecterApiClient({
      baseUrl: 'https://api.example.test',
      fetch: () => Promise.resolve(jsonResponse({ message: 'bad request' }, { status: 400 })),
    });
    await expect(failedClient.generateKeysRemote()).rejects.toMatchObject({
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
});
