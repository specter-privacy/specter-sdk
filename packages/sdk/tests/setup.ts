/**
 * Vitest global setup: initialise the WASM module once per worker so each
 * test file starts with the SDK ready to use. `vitest.config.ts` references
 * this via `setupFiles` indirectly through the package script.
 */

import { beforeAll } from 'vitest';

import { initSpecterSdk } from '../src/init.js';

beforeAll(async () => {
  await initSpecterSdk();
});
