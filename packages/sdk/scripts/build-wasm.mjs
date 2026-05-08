#!/usr/bin/env node
// build-wasm.mjs
//
// Build the rust/specter-wasm crate twice (once for `--target web`, once for
// `--target nodejs`) and place the artefacts inside packages/sdk/src/wasm/.
// Both bundles end up in the published npm tarball under dist/wasm/ via tsup
// `loader` config; src/wasm/ is git-ignored.
//
// Usage:
//   node scripts/build-wasm.mjs                  # release build, both targets
//   node scripts/build-wasm.mjs --debug          # dev build (faster, larger)
//   node scripts/build-wasm.mjs --skip-existing  # no-op if dirs already populated

import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const sdkRoot = resolve(__dirname, '..');
const repoRoot = resolve(sdkRoot, '..', '..');
const crateDir = resolve(repoRoot, 'rust', 'specter-wasm');

const args = new Set(process.argv.slice(2));
const debug = args.has('--debug');
const skipExisting = args.has('--skip-existing');

const targets = [
  { name: 'web', flag: '--target', value: 'web' },
  { name: 'node', flag: '--target', value: 'nodejs' },
];

function run(cmd, cmdArgs, cwd) {
  console.warn(`[build-wasm] $ ${cmd} ${cmdArgs.join(' ')}`);
  const result = spawnSync(cmd, cmdArgs, {
    cwd,
    stdio: 'inherit',
    env: process.env,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${cmd} ${cmdArgs.join(' ')} exited ${String(result.status)}`);
  }
}

function dirHasFiles(dir) {
  if (!existsSync(dir)) return false;
  if (!statSync(dir).isDirectory()) return false;
  const entries = readdirSync(dir).filter((e) => !e.startsWith('.'));
  return entries.length > 0;
}

for (const target of targets) {
  const outDir = join(sdkRoot, 'src', 'wasm', target.name);

  if (skipExisting && dirHasFiles(outDir)) {
    console.warn(`[build-wasm] ${target.name}: artefacts present, skipping`);
    continue;
  }

  if (existsSync(outDir)) {
    rmSync(outDir, { recursive: true, force: true });
  }
  mkdirSync(outDir, { recursive: true });

  const wasmPackArgs = [
    'build',
    crateDir,
    target.flag,
    target.value,
    '--out-dir',
    outDir,
    '--out-name',
    'specter_wasm',
    debug ? '--dev' : '--release',
    '--no-pack',
  ];

  run('wasm-pack', wasmPackArgs, repoRoot);

  // The Node target emits CJS (`exports.X = X`, `__dirname`, `require`). Our
  // SDK package.json sets `"type": "module"`, so without intervention Node
  // would refuse to load the .js file. Rename to .cjs so the loader's
  // dynamic import resolves it as CommonJS regardless of the parent
  // package.json `type` field, and drop a sub-package.json with
  // `"type": "commonjs"` for belt-and-suspenders.
  if (target.name === 'node') {
    const oldJs = join(outDir, 'specter_wasm.js');
    const newCjs = join(outDir, 'specter_wasm.cjs');
    if (existsSync(oldJs)) renameSync(oldJs, newCjs);

    writeFileSync(
      join(outDir, 'package.json'),
      JSON.stringify({ type: 'commonjs' }, null, 2) + '\n',
    );
  }
}

console.warn('[build-wasm] done');
