import { defineConfig } from 'tsup';

/**
 * tsup builds the TypeScript SDK into ESM + CJS and generates `.d.ts`.
 *
 * The wasm-pack output gets copied into `dist/wasm/{web,node}/` by the
 * separate `scripts/copy-wasm.mjs` step, run after this build via the
 * `build` package.json script.
 */
export default defineConfig({
  entry: ['src/index.ts'],
  outDir: 'dist',
  format: ['esm', 'cjs'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  target: 'es2022',
  platform: 'neutral',
  shims: false,
  treeshake: true,
  external: [
    // The wasm shim files use top-level URL() and dynamic imports that tsup
    // must not try to bundle. They get copied verbatim into dist/wasm/ by
    // the post-build copy step.
    /\.\/wasm\/web\/specter_wasm\.js/,
    /\.\/wasm\/node\/specter_wasm\.js/,
  ],
});
