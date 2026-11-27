import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { applyBump, applyOverride, applyRemove, raisedRange } from '../../src/fix/manifest.js';
import type { FixStep } from '../../src/fix/plan.js';

type Bump = Extract<FixStep, { kind: 'bump' }>;
type Override = Extract<FixStep, { kind: 'override' }>;

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'patchhound-manifest-'));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const write = (file: string, text: string) => writeFile(join(dir, file), text);
const read = async (file: string) => readFile(join(dir, file), 'utf8');
const json = async (file: string) => JSON.parse(await read(file)) as Record<string, Record<string, unknown>>;

const bump = (extra: Partial<Bump> = {}): Bump => ({ kind: 'bump', package: 'zod', from: '3.25.76', to: '4.1.12', change: 'major', root: '.', spec: '^3.25.76', ...extra });
const override = (extra: Partial<Override> = {}): Override => ({
  kind: 'override',
  package: 'minimatch',
  from: '3.1.2',
  to: '3.1.5',
  change: 'patch',
  parents: [{ id: 'serve-handler@6.1.5', spec: '3.1.2' }],
  ...extra,
});

describe('raisedRange', () => {
  it('keeps the range operator and an npm alias', () => {
    expect(raisedRange('^3.25.76', '4.1.12')).toBe('^4.1.12');
    expect(raisedRange('~1.2.0', '1.2.9')).toBe('~1.2.9');
    expect(raisedRange('1.2.0', '1.2.9')).toBe('1.2.9');
    expect(raisedRange('npm:lodash@^3.10.1', '4.17.21')).toBe('npm:lodash@^4.17.21');
  });
});

describe('applyBump', () => {
  it('raises the range where package.json lists it, keeping the file\'s indentation and final newline', async () => {
    await write('package.json', '{\n    "name": "app",\n    "devDependencies": {\n        "zod": "^3.25.76"\n    }\n}\n');
    expect(await applyBump(dir, bump(), 'npm')).toBe('package.json: zod -> 4.1.12');
    expect(await read('package.json')).toBe('{\n    "name": "app",\n    "devDependencies": {\n        "zod": "^4.1.12"\n    }\n}\n');
  });

  it('edits a workspace package.json, adds a package that was only a peer, and edits a pnpm catalog', async () => {
    await mkdir(join(dir, 'packages', 'ui'), { recursive: true });
    await write('packages/ui/package.json', '{\n  "dependencies": { "zod": "3.25.76" }\n}\n');
    await applyBump(dir, bump({ root: 'packages/ui' }), 'npm');
    expect((await json('packages/ui/package.json')).dependencies).toEqual({ zod: '4.1.12' });
    await write('package.json', '{\n  "name": "app"\n}\n');
    await applyBump(dir, bump({ package: 'vite', to: '8.2.3', add: 'devDependencies', spec: '' }), 'pnpm');
    expect((await json('package.json')).devDependencies).toEqual({ vite: '^8.2.3' });
    await write('pnpm-workspace.yaml', 'packages:\n  - packages/*\n# shared versions\ncatalog:\n  zod: ^3.25.76\ncatalogs:\n  react19:\n    react: 19.0.0\n');
    await applyBump(dir, bump({ catalog: 'default' }), 'pnpm');
    await applyBump(dir, bump({ package: 'react', to: '19.0.1', catalog: 'react19' }), 'pnpm');
    expect(await read('pnpm-workspace.yaml')).toBe('packages:\n  - packages/*\n# shared versions\ncatalog:\n  zod: ^4.1.12\ncatalogs:\n  react19:\n    react: 19.0.1\n');
  });
});

describe('applyOverride', () => {
  beforeEach(async () => {
    await write('package.json', '{\n  "name": "app",\n  "dependencies": { "serve-handler": "6.1.5" }\n}\n');
  });

  it('npm: forces only the vulnerable version, by a name@version key', async () => {
    expect(await applyOverride(dir, override(), 'npm', null)).toBe('package.json overrides: "minimatch@3.1.2": "3.1.5"');
    expect((await json('package.json')).overrides).toEqual({ 'minimatch@3.1.2': '3.1.5' });
  });

  it('npm: a package the root also lists moves there too, and the override refers to it', async () => {
    await write('package.json', '{\n  "dependencies": { "serve-handler": "6.1.5", "minimatch": "^3.1.2" }\n}\n');
    await applyOverride(dir, override({ direct: [{ root: '.', spec: '^3.1.2' }] }), 'npm', null);
    const data = await json('package.json');
    expect(data.dependencies!.minimatch).toBe('^3.1.5');
    expect(data.overrides).toEqual({ 'minimatch@3.1.2': '$minimatch' });
  });

  it('pnpm 11 reads overrides only from pnpm-workspace.yaml, pnpm 10 from package.json, and existing overrides stay where they are', async () => {
    expect(await applyOverride(dir, override(), 'pnpm', 11)).toBe('pnpm-workspace.yaml overrides: minimatch@3.1.2: 3.1.5');
    expect(await read('pnpm-workspace.yaml')).toBe('overrides:\n  minimatch@3.1.2: 3.1.5\n');
    await rm(join(dir, 'pnpm-workspace.yaml'));
    expect(await applyOverride(dir, override(), 'pnpm', 10)).toBe('package.json pnpm.overrides: "minimatch@3.1.2": "3.1.5"');
    expect((await json('package.json')).pnpm).toEqual({ overrides: { 'minimatch@3.1.2': '3.1.5' } });
    // pnpm 11 ignores package.json's overrides, so even a project that still keeps some there gets the YAML.
    await applyOverride(dir, override({ package: 'glob', from: '7.1.6', to: '7.2.3' }), 'pnpm', 11);
    expect(await read('pnpm-workspace.yaml')).toBe('overrides:\n  glob@7.1.6: 7.2.3\n');
    // An older pnpm whose project already keeps overrides in the YAML keeps them there.
    await applyOverride(dir, override({ package: 'ms', from: '2.0.0', to: '2.1.3' }), 'pnpm', 10);
    expect(await read('pnpm-workspace.yaml')).toBe('overrides:\n  glob@7.1.6: 7.2.3\n  ms@2.0.0: 2.1.3\n');
  });

  it('yarn 1 keys a resolution by the parent, yarn 2+ by the range the parent asks for', async () => {
    expect(await applyOverride(dir, override(), 'yarn-classic', null)).toBe('package.json resolutions: "**/serve-handler/minimatch" -> 3.1.5');
    await write('package.json', '{\n  "name": "app"\n}\n');
    await applyOverride(dir, override({ parents: [{ id: 'a@1.0.0', spec: '^3.0.4' }, { id: 'b@2.0.0', spec: 'npm:3.1.2' }] }), 'yarn-berry', null);
    expect((await json('package.json')).resolutions).toEqual({ 'minimatch@npm:^3.0.4': '3.1.5', 'minimatch@npm:3.1.2': '3.1.5' });
  });
});

describe('applyRemove', () => {
  it('takes the package out of every section of its package.json', async () => {
    await write('package.json', '{\n  "dependencies": { "evil": "1.0.0", "ok": "1.0.0" },\n  "devDependencies": { "evil": "1.0.0" }\n}\n');
    expect(await applyRemove(dir, { kind: 'remove', package: 'evil', from: '1.0.0', root: '.' })).toBe('package.json: removed evil');
    expect(await json('package.json')).toEqual({ dependencies: { ok: '1.0.0' }, devDependencies: {} });
  });
});
