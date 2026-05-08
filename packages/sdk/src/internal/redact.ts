/**
 * Helpers for redacting secret-bearing fields from runtime objects.
 *
 * The SDK never wants secret material to surface in `console.log`,
 * `JSON.stringify`, error.cause chains, or `util.inspect`. This module
 * provides a single primitive — `defineSecretField` — that adds a property
 * with three protections:
 *
 * 1. The property is **non-enumerable**, so it doesn't appear in default
 *    iteration (`for...in`, `Object.keys`, `JSON.stringify`).
 * 2. A custom `toJSON` (defined separately on the parent object) ensures
 *    `JSON.stringify` returns `[REDACTED]` instead of the secret.
 * 3. A `Symbol.for('nodejs.util.inspect.custom')` hook makes Node's
 *    `console.log` and `util.inspect` show `[REDACTED]` too.
 *
 * Importantly, the value is still **readable** via direct property access
 * (so consumers can sign with it). It just won't leak through the
 * accidental serialisation paths.
 */

const NODE_INSPECT_CUSTOM = Symbol.for('nodejs.util.inspect.custom');

/**
 * Mark `key` on `target` as a secret field.
 *
 * @param target - the object that will hold the secret
 * @param key - the property name (e.g. `secretKey`, `ethPrivateKey`)
 * @param value - the actual secret value (kept readable via `target[key]`)
 */
export function defineSecretField(
  target: object,
  key: string,
  value: unknown,
): void {
  Object.defineProperty(target, key, {
    value,
    writable: false,
    enumerable: false,
    configurable: false,
  });
}

/**
 * Produce a shallow clone of `obj` with all keys in `secretKeys` replaced by
 * the literal string `'[REDACTED]'`. Used by the `toJSON` shims and the
 * Node `util.inspect.custom` hook so that any serialisation surfaces a
 * safe placeholder.
 */
export function redactedClone(
  obj: Record<string, unknown>,
  secretKeys: readonly string[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(obj)) {
    out[key] = obj[key];
  }
  // Object.keys skips non-enumerable, so we explicitly include the secrets.
  for (const sk of secretKeys) {
    out[sk] = '[REDACTED]';
  }
  return out;
}

/**
 * Wire `toJSON` and the Node inspect hook onto `target` so that
 * accidental serialisation produces redacted output.
 */
export function attachRedactingSerializers(
  target: object,
  secretKeys: readonly string[],
): void {
  const redactedView = (): Record<string, unknown> =>
    redactedClone(target as unknown as Record<string, unknown>, secretKeys);

  Object.defineProperty(target, 'toJSON', {
    value: redactedView,
    writable: false,
    enumerable: false,
    configurable: false,
  });

  Object.defineProperty(target, NODE_INSPECT_CUSTOM, {
    value: redactedView,
    writable: false,
    enumerable: false,
    configurable: false,
  });

  Object.defineProperty(target, Symbol.toPrimitive, {
    value: (hint: string): string =>
      hint === 'number' ? Number.NaN.toString() : '[Object SpecterSecretContainer]',
    writable: false,
    enumerable: false,
    configurable: false,
  });
}
