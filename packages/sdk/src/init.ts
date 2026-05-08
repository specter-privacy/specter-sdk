/**
 * Public initialiser for the SDK.
 *
 * `initSpecterSdk()` must be awaited once before any other public function
 * is called. It is idempotent — calling it more than once returns the same
 * underlying promise — and accepts an optional `wasmUrl` for browsers that
 * want to host the `.wasm` file from a custom URL (e.g. their own CDN).
 */

import { loadWasm, markResolved, type LoadOptions } from './loader.js';

/** Initialise the SDK. Awaiting twice returns the same cached promise. */
export async function initSpecterSdk(opts: LoadOptions = {}): Promise<void> {
  const mod = await loadWasm(opts);
  markResolved(mod);
}

export type { LoadOptions };
