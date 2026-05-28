/**
 * Public error class and error-code union for `@specterpq/sdk`.
 *
 * Every fallible function in the SDK throws `SpecterSdkError` on failure.
 * The `code` field is the source of truth for programmatic discrimination:
 * the human-readable `message` may change between releases, but `code` is
 * stable across `0.x` and `1.x`.
 */

/** Stable, machine-readable error codes. */
export type SpecterErrorCode =
  | 'NOT_INITIALIZED'
  | 'INVALID_KEY_SIZE'
  | 'INVALID_CIPHERTEXT_SIZE'
  | 'INVALID_SHARED_SECRET_SIZE'
  | 'INVALID_HEX'
  | 'INVALID_META_ADDRESS'
  | 'INVALID_METADATA_JSON'
  | 'INVALID_VIEW_TAG'
  | 'INVALID_API_RESPONSE'
  | 'HTTP_ERROR'
  | 'ENCAPSULATION_FAILED'
  | 'DECAPSULATION_FAILED'
  | 'STEALTH_DERIVATION_FAILED'
  | 'WASM_LOAD_FAILED'
  | 'INTERNAL_ERROR';

/** Coarse-grained category for grouping errors. */
export type SpecterErrorCategory = 'validation' | 'crypto' | 'encoding' | 'internal';

/**
 * Wire shape returned by the WASM bridge when a Rust function fails. We
 * keep the shape narrow on purpose so the JS-side classification stays
 * simple.
 */
interface WireError {
  code: string;
  message: string;
  recoverable: boolean;
  category: string;
}

/** Default error class thrown by every public function in this SDK. */
export class SpecterSdkError extends Error {
  /** Stable error code, see [`SpecterErrorCode`]. */
  public readonly code: SpecterErrorCode;
  /** Whether retrying with the same input could plausibly succeed. */
  public readonly recoverable: boolean;
  /** Coarse-grained category. */
  public readonly category: SpecterErrorCategory;

  public constructor(
    code: SpecterErrorCode,
    message: string,
    options: { recoverable?: boolean; category?: SpecterErrorCategory; cause?: unknown } = {},
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'SpecterSdkError';
    this.code = code;
    this.recoverable = options.recoverable ?? false;
    this.category = options.category ?? categoryFor(code);
    // Restore prototype chain across transpiled targets.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Best-effort category inference for a raw error code that came in without
 * one (e.g. JS-side validation failures).
 */
function categoryFor(code: SpecterErrorCode): SpecterErrorCategory {
  switch (code) {
    case 'INVALID_KEY_SIZE':
    case 'INVALID_CIPHERTEXT_SIZE':
    case 'INVALID_SHARED_SECRET_SIZE':
    case 'INVALID_META_ADDRESS':
    case 'INVALID_METADATA_JSON':
    case 'INVALID_VIEW_TAG':
    case 'INVALID_API_RESPONSE':
      return 'validation';
    case 'HTTP_ERROR':
      return 'internal';
    case 'INVALID_HEX':
      return 'encoding';
    case 'ENCAPSULATION_FAILED':
    case 'DECAPSULATION_FAILED':
    case 'STEALTH_DERIVATION_FAILED':
      return 'crypto';
    case 'NOT_INITIALIZED':
    case 'WASM_LOAD_FAILED':
    case 'INTERNAL_ERROR':
      return 'internal';
  }
}

const KNOWN_CODES = new Set<SpecterErrorCode>([
  'NOT_INITIALIZED',
  'INVALID_KEY_SIZE',
  'INVALID_CIPHERTEXT_SIZE',
  'INVALID_SHARED_SECRET_SIZE',
  'INVALID_HEX',
  'INVALID_META_ADDRESS',
  'INVALID_METADATA_JSON',
  'INVALID_VIEW_TAG',
  'INVALID_API_RESPONSE',
  'HTTP_ERROR',
  'ENCAPSULATION_FAILED',
  'DECAPSULATION_FAILED',
  'STEALTH_DERIVATION_FAILED',
  'WASM_LOAD_FAILED',
  'INTERNAL_ERROR',
]);

const KNOWN_CATEGORIES = new Set<SpecterErrorCategory>([
  'validation',
  'crypto',
  'encoding',
  'internal',
]);

/**
 * Convert any unknown caught value into a `SpecterSdkError`.
 *
 * The WASM bridge throws either:
 *   - a `SpecterSdkError` (if the call originated from JS-side validation),
 *   - the wire shape produced by `serde-wasm-bindgen` (`{ code, message, ... }`),
 *   - or a plain `Error` if `wasm-bindgen` itself failed (e.g. memory grow).
 *
 * This normaliser folds all three into a `SpecterSdkError` so consumers
 * always have `error.code` available.
 */
export function normalizeError(raw: unknown): SpecterSdkError {
  if (raw instanceof SpecterSdkError) return raw;

  if (isWireError(raw)) {
    const code = KNOWN_CODES.has(raw.code as SpecterErrorCode)
      ? (raw.code as SpecterErrorCode)
      : 'INTERNAL_ERROR';
    const category = KNOWN_CATEGORIES.has(raw.category as SpecterErrorCategory)
      ? (raw.category as SpecterErrorCategory)
      : categoryFor(code);
    return new SpecterSdkError(code, raw.message, {
      recoverable: raw.recoverable,
      category,
      cause: raw,
    });
  }

  if (raw instanceof Error) {
    return new SpecterSdkError('INTERNAL_ERROR', raw.message, { cause: raw });
  }

  return new SpecterSdkError('INTERNAL_ERROR', 'unknown error', { cause: raw });
}

function isWireError(value: unknown): value is WireError {
  if (typeof value !== 'object' || value === null) return false;
  const obj = value as Record<string, unknown>;
  return typeof obj['code'] === 'string' && typeof obj['message'] === 'string';
}
