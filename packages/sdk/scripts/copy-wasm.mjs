#!/usr/bin/env node
// copy-wasm.mjs
//
// Copy the wasm-pack output from `src/wasm/{web,node}/` into
// `dist/wasm/{web,node}/`. Run after `tsup` so that the published npm
// tarball is self-contained (the runtime loader resolves
// `./wasm/web/specter_wasm.js` next to `dist/index.js`).
//
// Why a separate script? `tsup`'s `onSuccess` hook fires once per output
// format (ESM, CJS, DTS) and a clean run after that interleaves with the
// type-declaration emit, which sometimes drops freshly-copied files. A
// dedicated post-build script avoids the race.

import { copyFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const sdkRoot = resolve(__dirname, '..');

const TARGETS = ['web', 'node'];

let copied = 0;

for (const target of TARGETS) {
  const srcDir = resolve(sdkRoot, 'src', 'wasm', target);
  const dstDir = resolve(sdkRoot, 'dist', 'wasm', target);

  if (!existsSync(srcDir)) {
    console.error(
      `[copy-wasm] missing source: ${srcDir}. Run \`pnpm build:wasm\` first.`,
    );
    process.exit(1);
  }

  mkdirSync(dstDir, { recursive: true });

  // The build-wasm script already wrote everything (including the renamed
  // .cjs file and the sub-package.json for the node target). We just mirror
  // every file in the source directory verbatim.
  for (const entry of readdirSync(srcDir)) {
    if (entry.startsWith('.')) continue;
    copyFileSync(resolve(srcDir, entry), resolve(dstDir, entry));
    copied += 1;
  }
}

console.warn(`[copy-wasm] copied ${copied} files`);
