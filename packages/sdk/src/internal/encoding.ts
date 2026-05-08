/**
 * Hex encoding / decoding utilities used across the SDK.
 *
 * - All hex output uses the `0x`-prefixed lowercase form.
 * - Decoding accepts either prefixed or unprefixed hex but always rejects
 *   odd-length input and any non-hex characters.
 * - The `lengthBytes` argument lets callers enforce a fixed-byte-size at
 *   the boundary, mirroring the upstream Rust code's `from_bytes` checks.
 */

import { SpecterSdkError } from '../errors.js';
import type { Hex } from '../types.js';

const HEX_RE = /^[0-9a-fA-F]+$/;

/**
 * Convert raw bytes to a `0x`-prefixed lowercase hex string with a
 * structural brand applied at compile time only.
 */
export function bytesToHex<Brand extends string>(bytes: Uint8Array): Hex<Brand> {
  let out = '0x';
  for (const v of bytes) {
    out += v.toString(16).padStart(2, '0');
  }
  return out as Hex<Brand>;
}

/**
 * Decode a hex string (with or without `0x` prefix) into a `Uint8Array`.
 *
 * Throws `SpecterSdkError(INVALID_HEX)` for malformed input and
 * `SpecterSdkError(INVALID_KEY_SIZE)` if a `lengthBytes` is provided and the
 * decoded payload doesn't match it.
 */
export function hexToBytes(input: string, opts: { lengthBytes?: number; field?: string } = {}): Uint8Array {
  if (typeof input !== 'string') {
    throw new SpecterSdkError('INVALID_HEX', 'expected hex string');
  }
  const stripped = input.startsWith('0x') || input.startsWith('0X') ? input.slice(2) : input;

  if (stripped.length === 0) {
    if (opts.lengthBytes && opts.lengthBytes > 0) {
      throw new SpecterSdkError(
        'INVALID_KEY_SIZE',
        `${opts.field ?? 'hex'}: expected ${opts.lengthBytes} bytes, got 0`,
      );
    }
    return new Uint8Array(0);
  }

  if (stripped.length % 2 !== 0 || !HEX_RE.test(stripped)) {
    throw new SpecterSdkError('INVALID_HEX', 'invalid hex encoding');
  }

  const out = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const hi = stripped.charCodeAt(i * 2);
    const lo = stripped.charCodeAt(i * 2 + 1);
    out[i] = (hexNibble(hi) << 4) | hexNibble(lo);
  }

  if (opts.lengthBytes !== undefined && out.length !== opts.lengthBytes) {
    throw new SpecterSdkError(
      'INVALID_KEY_SIZE',
      `${opts.field ?? 'hex'}: expected ${opts.lengthBytes} bytes, got ${out.length}`,
    );
  }
  return out;
}

function hexNibble(charCode: number): number {
  if (charCode >= 48 && charCode <= 57) return charCode - 48;
  if (charCode >= 97 && charCode <= 102) return charCode - 87;
  if (charCode >= 65 && charCode <= 70) return charCode - 55;
  // Validation regex above already rejected non-hex chars; this is a defence.
  throw new SpecterSdkError('INVALID_HEX', 'invalid hex encoding');
}

/**
 * Coerce a `Hex<T> | Uint8Array` input into a `Uint8Array` with optional
 * length checking. Used as the gateway for every byte-shaped argument.
 */
export function asBytes(
  input: string | Uint8Array,
  opts: { lengthBytes?: number; field?: string } = {},
): Uint8Array {
  if (input instanceof Uint8Array) {
    if (opts.lengthBytes !== undefined && input.length !== opts.lengthBytes) {
      throw new SpecterSdkError(
        'INVALID_KEY_SIZE',
        `${opts.field ?? 'bytes'}: expected ${opts.lengthBytes} bytes, got ${input.length}`,
      );
    }
    return input;
  }
  return hexToBytes(input, opts);
}
