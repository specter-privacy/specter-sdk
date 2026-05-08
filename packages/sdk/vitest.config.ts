import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    setupFiles: ['./tests/setup.ts'],
    testTimeout: 30000,
    coverage: {
      enabled: false,
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      include: ['src/**/*.ts'],
      exclude: ['src/wasm/**', 'src/loader.ts', 'src/index.ts'],
      thresholds: {
        lines: 85,
        functions: 90,
        branches: 80,
        statements: 85,
      },
    },
  },
});
