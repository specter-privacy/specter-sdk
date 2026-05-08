/**
 * Zod schemas + JS-side guards used at every public API boundary.
 *
 * The flow for every SDK function is:
 *   1. Validate inputs with the schemas in this file (cheap rejection).
 *   2. Convert hex inputs to `Uint8Array` with strict length-checking.
 *   3. Call the WASM bridge.
 *   4. Validate WASM outputs against the protocol constants (defence in depth).
 *
 * Failures at any stage throw `SpecterSdkError` with a stable code so
 * downstream consumers can `error.code === 'INVALID_KEY_SIZE'`-style branch.
 */

import { z, type ZodIssue } from 'zod';

import {
  ETH_ADDRESS_SIZE,
  KYBER_CIPHERTEXT_SIZE,
  KYBER_PUBLIC_KEY_SIZE,
  KYBER_SECRET_KEY_SIZE,
  KYBER_SHARED_SECRET_SIZE,
  META_ADDRESS_SIZE,
  STEALTH_ETH_PRIVATE_KEY_SIZE,
  STEALTH_SECP256K1_PUBLIC_SIZE,
  SUI_ADDRESS_SIZE,
  VIEW_TAG_SIZE,
} from './constants.js';
import { SpecterSdkError } from './errors.js';
import { hexToBytes } from './internal/encoding.js';

/**
 * Allow either a `0x`-prefixed hex string or a `Uint8Array`. We keep the
 * raw shape and let the SDK internals handle the conversion.
 */
const hexOrBytesSchema = z.union([
  z.string().regex(/^0x[0-9a-fA-F]*$/u, { message: 'invalid hex encoding' }),
  z.instanceof(Uint8Array),
]);

/** Validate that a hex / bytes input has exactly `lengthBytes` after decoding. */
function fixedSizeHexOrBytes(lengthBytes: number, field: string) {
  return hexOrBytesSchema.superRefine((value, ctx) => {
    let actualLength: number;
    if (value instanceof Uint8Array) {
      actualLength = value.length;
    } else {
      // hex chars after 0x = 2 * bytes
      const stripped = value.startsWith('0x') ? value.slice(2) : value;
      if (stripped.length % 2 !== 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${field}: invalid hex encoding (odd length)`,
        });
        return;
      }
      actualLength = stripped.length / 2;
    }
    if (actualLength !== lengthBytes) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `${field}: expected ${lengthBytes} bytes, got ${actualLength}`,
      });
    }
  });
}

export const KyberPublicKeyInput = fixedSizeHexOrBytes(
  KYBER_PUBLIC_KEY_SIZE,
  'kyber_public_key',
);
export const KyberSecretKeyInput = fixedSizeHexOrBytes(
  KYBER_SECRET_KEY_SIZE,
  'kyber_secret_key',
);
export const KyberCiphertextInput = fixedSizeHexOrBytes(
  KYBER_CIPHERTEXT_SIZE,
  'kyber_ciphertext',
);
export const SharedSecretInput = fixedSizeHexOrBytes(
  KYBER_SHARED_SECRET_SIZE,
  'shared_secret',
);
export const EthAddressInput = fixedSizeHexOrBytes(ETH_ADDRESS_SIZE, 'eth_address');
export const SuiAddressInput = fixedSizeHexOrBytes(SUI_ADDRESS_SIZE, 'sui_address');
export const StealthSecp256k1PublicInput = fixedSizeHexOrBytes(
  STEALTH_SECP256K1_PUBLIC_SIZE,
  'stealth_public_key',
);
export const StealthEthPrivateInput = fixedSizeHexOrBytes(
  STEALTH_ETH_PRIVATE_KEY_SIZE,
  'eth_private_key',
);
export const MetaAddressBytesInput = fixedSizeHexOrBytes(META_ADDRESS_SIZE, 'meta_address');
export const ViewTagInput = z
  .number()
  .int()
  .min(0)
  .max(255)
  .describe(`a single byte view tag (${VIEW_TAG_SIZE} byte)`);

/** Optional metadata payload accepted by `metaAddressFromPublicKeys`. */
export const MetaAddressMetadataInput = z
  .object({
    description: z.string().max(1024).optional(),
    avatar: z.string().max(2048).optional(),
    createdAt: z.number().int().nonnegative().max(2 ** 53 - 1).optional(),
  })
  .strict();

export type ValidatedMetaAddressMetadata = z.infer<typeof MetaAddressMetadataInput>;

/**
 * Decode a validated hex-or-bytes input to a `Uint8Array`. Combines schema
 * parsing with `hexToBytes` length-checking so the call site stays small.
 */
export function parseHexOrBytes(
  schema: z.ZodTypeAny,
  raw: unknown,
  field: string,
  lengthBytes: number,
): Uint8Array {
  const parsed: unknown = trySchemaParse(schema, raw, field);
  if (parsed instanceof Uint8Array) {
    if (parsed.length !== lengthBytes) {
      throw new SpecterSdkError(
        'INVALID_KEY_SIZE',
        `${field}: expected ${lengthBytes} bytes, got ${parsed.length}`,
      );
    }
    return parsed;
  }
  return hexToBytes(parsed as string, { lengthBytes, field });
}

/** Run a schema and translate Zod failures into `SpecterSdkError`. */
export function trySchemaParse(schema: z.ZodTypeAny, raw: unknown, field: string): unknown {
  const result = schema.safeParse(raw);
  if (result.success) return result.data as unknown;
  const message = formatZodError(result.error.issues, field);
  throw new SpecterSdkError(classifyValidation(message), message);
}

function classifyValidation(message: string): 'INVALID_KEY_SIZE' | 'INVALID_HEX' | 'INVALID_VIEW_TAG' {
  if (message.includes('expected') && message.includes('bytes')) return 'INVALID_KEY_SIZE';
  if (message.includes('hex')) return 'INVALID_HEX';
  return 'INVALID_VIEW_TAG';
}

function formatZodError(issues: readonly ZodIssue[], field: string): string {
  if (issues.length === 0) return `${field}: invalid input`;
  return issues.map((i) => i.message).join('; ');
}

/** Defensive output validator: assert a returned byte buffer has the expected size. */
export function expectByteLength(
  bytes: Uint8Array,
  expected: number,
  field: string,
): Uint8Array {
  if (bytes.length !== expected) {
    throw new SpecterSdkError(
      'INTERNAL_ERROR',
      `${field}: WASM returned ${bytes.length} bytes, expected ${expected}`,
    );
  }
  return bytes;
}
