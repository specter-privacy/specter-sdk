import { describe, expect, it } from 'vitest';

import { initSpecterSdk, generateKeysLocal } from '../../src/index.js';

describe('initSpecterSdk', () => {
  it('is idempotent — calling twice does not error', async () => {
    await initSpecterSdk();
    await initSpecterSdk();
    const kp = generateKeysLocal();
    expect(kp.publicKey.startsWith('0x')).toBe(true);
  });
});
