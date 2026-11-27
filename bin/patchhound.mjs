#!/usr/bin/env node
// Runs Patchhound's TypeScript source with tsx, always with Patchhound's own tsconfig: tsx would otherwise
// read tsconfig.json from the folder it runs in (the user's repo), whose `paths` could redirect
// Patchhound's own imports.
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const tsconfig = `${root}tsconfig.json`;
const tsx = createRequire(import.meta.url).resolve('tsx/cli');
const result = spawnSync(process.execPath, [tsx, '--tsconfig', tsconfig, `${root}src/cli.ts`, ...process.argv.slice(2)], {
  stdio: 'inherit',
  env: { ...process.env, TSX_TSCONFIG_PATH: tsconfig },
});
process.exit(result.status ?? 1);
