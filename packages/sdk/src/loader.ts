/**
 * Environment-aware WASM loader.
 *
 * The wasm-pack output ships in two flavours:
 *   - `dist/wasm/web/specter_wasm.js`   — ESM, loads `.wasm` via `URL`.
 *   - `dist/wasm/node/specter_wasm.js`  — CJS, loads `.wasm` via `fs`.
 *
 * `loadWasm` picks one at runtime (Node vs browser) and caches the loaded
 * module so consumers can call `initSpecterSdk` multiple times without
 * incurring the instantiation cost twice.
 *
 * In the browser the consumer can override the wasm URL via
 * `initSpecterSdk({ wasmUrl })` to host the `.wasm` file from their own CDN
 * or to use a custom integrity hash.
 *
 * **Why this file lives at `src/loader.ts` rather than `src/internal/load.ts`:**
 * tsup bundles every `src/**` file into a single `dist/index.js`. The
 * dynamic-import paths declared as `external` are preserved verbatim. The
 * resolved URL must be valid relative to the executing file. By keeping the
 * loader at `src/`, both `src/loader.ts` and `dist/index.js` see the wasm
 * shim at `./wasm/{web,node}/specter_wasm.js`, so a single literal works
 * for both vitest-on-source and bundled-on-dist execution.
 */

import { SpecterSdkError } from './errors.js';
import type * as WebShim from './wasm/web/specter_wasm.js';

// The web shim is the canonical source of types; the node shim has the
// same surface. Both flavours export the same set of named functions.
type WasmModule = typeof WebShim;

let cached: Promise<WasmModule> | null = null;
let resolved: WasmModule | null = null;

/** Options accepted by [`loadWasm`] / `initSpecterSdk`. */
export interface LoadOptions {
  /**
   * Optional URL or path to the `.wasm` file. Browser-only. If omitted the
   * loader resolves `specter_wasm_bg.wasm` next to the published JS shim,
   * which works for typical bundler setups (Vite, webpack 5, esbuild, Next.js).
   */
  readonly wasmUrl?: string | URL;
}

/**
 * Detects the runtime once at module load. We deliberately do not look for
 * `globalThis.process` alone because Vitest in jsdom mode exposes one; we
 * also require the absence of a DOM `document`.
 */
function detectRuntime(): 'node' | 'browser' {
  const proc =
    typeof globalThis !== 'undefined' && (globalThis as { process?: unknown }).process;
  const isNode =
    typeof proc === 'object' &&
    proc !== null &&
    typeof (proc as { versions?: { node?: string } }).versions?.node === 'string' &&
    typeof (globalThis as { document?: unknown }).document === 'undefined';
  return isNode ? 'node' : 'browser';
}

/** Lazily import + initialise the WASM module appropriate for this runtime. */
export function loadWasm(opts: LoadOptions = {}): Promise<WasmModule> {
  if (cached !== null) return cached;

  const runtime = detectRuntime();

  cached = (async (): Promise<WasmModule> => {
    try {
      if (runtime === 'node') {
        // Node target ships as CJS (.cjs). The build pipeline renames the
        // wasm-pack output and writes a `type: commonjs` sub-package.json so
        // Node treats the file as CJS even though our parent package.json
        // declares `type: module`.
        const nodeUrl = new URL('./wasm/node/specter_wasm.cjs', import.meta.url).href;
        const mod = (await import(/* @vite-ignore */ nodeUrl)) as unknown as WasmModule;
        if (typeof mod.initPanicHook === 'function') mod.initPanicHook();
        return mod;
      }

      const webUrl = new URL('./wasm/web/specter_wasm.js', import.meta.url).href;
      const mod = (await import(/* @vite-ignore */ webUrl)) as unknown as WasmModule & {
        default: (input?: { module_or_path?: string | URL }) => Promise<unknown>;
      };

      const wasmUrl =
        opts.wasmUrl ?? new URL('./wasm/web/specter_wasm_bg.wasm', import.meta.url);

      await mod.default({ module_or_path: wasmUrl });
      if (typeof mod.initPanicHook === 'function') mod.initPanicHook();
      return mod;
    } catch (err) {
      cached = null;
      throw new SpecterSdkError(
        'WASM_LOAD_FAILED',
        `failed to load specter-wasm: ${err instanceof Error ? err.message : String(err)}`,
        { cause: err },
      );
    }
  })();

  return cached;
}

/**
 * Returns the cached WASM module synchronously, or throws if `initSpecterSdk`
 * has not been awaited yet. Used internally by every public function so that
 * `await initSpecterSdk()` is required exactly once.
 */
export function getWasmSync(): WasmModule {
  if (resolved === null) {
    throw new SpecterSdkError(
      'NOT_INITIALIZED',
      'await initSpecterSdk() before calling other SDK functions',
    );
  }
  return resolved;
}

/** Internal: cache the resolved module synchronously after init completes. */
export function markResolved(mod: WasmModule): void {
  resolved = mod;
}

/** Internal: reset both caches. Test-only. */
export function __resetWasmCacheForTests(): void {
  cached = null;
  resolved = null;
}
