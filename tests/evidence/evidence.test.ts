import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildEvidence, mentionedNames } from '../../src/evidence/evidence.js';
import { projectContext, redactSecrets, snippetsFor } from '../../src/evidence/snippets.js';
import type { SourceIndex } from '../../src/evidence/source.js';
import { indexSource } from '../../src/evidence/source.js';
import { finding } from '../helpers/findings.js';

const FILES: Record<string, string> = {
  'package.json': JSON.stringify({ dependencies: { next: '16.0.0', lodash: '4.17.20', axios: '1.0.0' } }),
  'app/api/render/route.ts': ["import _ from 'lodash';", '', 'export async function POST(req: Request) {', '  return new Response(_.template(await req.text())());', '}'].join('\n'),
  'app/page.tsx': "import axios from 'axios';\nexport default function Page() { return null; }",
  'components/Chart.tsx': "'use client';\nimport { merge } from 'lodash';\nexport const opts = merge({}, {});",
  'scripts/seed.ts': "import yaml from 'js-yaml';\nyaml.load('a: 1');",
  'tests/render.test.ts': "import _ from 'lodash';\n_.template('x');",
  'lib/types.ts': "import type { AxiosInstance } from 'axios';\nexport type A = AxiosInstance;",
  'lib/broken.ts': 'export const = ;;; import',
  '.claude/worktrees/copy/app/api/render/route.ts': "import _ from 'lodash';",
  'next.config.mjs': 'export default { experimental: {} };',
  '.next/server/chunk.js': "require('lodash');",
  'node_modules/lodash/index.js': "module.exports = require('other');",
};

let dir: string;
let source: SourceIndex;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), 'patchhound-evidence-'));
  for (const [path, text] of Object.entries(FILES)) {
    await mkdir(dirname(join(dir, path)), { recursive: true });
    await writeFile(join(dir, path), text);
  }
  source = await indexSource(dir, { next: true, wanted: new Map([['lodash', new Set(['template'])]]) });
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('indexSource', () => {
  it('reads the app code, skips dependencies, build output and hidden folders, and classifies each file', () => {
    // next.config.mjs imports nothing, so it is not listed; the .claude copy is skipped.
    expect(source.files.map((f) => [f.path, f.runtime])).toEqual([
      ['app/page.tsx', 'server'],
      ['components/Chart.tsx', 'client'],
      ['lib/types.ts', 'app'],
      ['scripts/seed.ts', 'script'],
      ['tests/render.test.ts', 'test'],
      ['app/api/render/route.ts', 'server'],
    ]);
  });

  it('counts the files it could not parse', () => {
    expect(source.unread).toEqual(['lib/broken.ts']);
  });
});

describe('buildEvidence', () => {
  const context = () => ({ source, exposure: 'internet-facing' as const, framework: { next: true, appRouter: true }, mentioned: ['template'] });

  it('lists where the package is imported, production code first, and where the mentioned names are used', () => {
    const e = buildEvidence(finding(), context());
    expect(e.usage.sites.map((s) => `${s.file}:${s.line} ${s.runtime}`)).toEqual([
      'app/api/render/route.ts:1 server',
      'components/Chart.tsx:2 client',
      'tests/render.test.ts:1 test',
    ]);
    expect(e.usage.runtimes).toEqual(['server', 'client', 'test']);
    expect(e.usage.calls.map((c) => `${c.file}:${c.line} ${c.name}`)).toEqual(['app/api/render/route.ts:4 template', 'tests/render.test.ts:2 template']);
    expect(e.exposure).toBe('internet-facing');
  });

  it('follows a transitive package to the direct dependency that brings it in, and marks dev-only exposure', () => {
    const e = buildEvidence(finding({ package: 'follow-redirects', version: '1.0.0', direct: false, devOnly: true, via: ['axios'] }), context());
    expect(e.usage.sites.map((s) => [s.file, s.package, s.typeOnly])).toEqual([
      ['app/page.tsx', 'axios', false],
      ['lib/types.ts', 'axios', true],
    ]);
    // Type-only imports run nothing, so they do not count as a runtime.
    expect(e.usage.runtimes).toEqual(['server']);
    expect(e.exposure).toBe('build/dev-only');
  });

  it('hashes what bears on triage, so a moved line keeps the hash and a new import changes it', () => {
    const a = buildEvidence(finding(), context());
    const moved = { ...source, files: source.files.map((f) => ({ ...f, imports: f.imports.map((i) => ({ ...i, line: i.line + 5 })) })) };
    expect(buildEvidence(finding(), { ...context(), source: moved }).hash).toBe(a.hash);
    const added = { ...source, files: [...source.files, { path: 'app/api/new/route.ts', runtime: 'server' as const, imports: [{ package: 'lodash', specifier: 'lodash', kind: 'import' as const, typeOnly: false, line: 1 }], calls: [], uses: [] }] };
    expect(buildEvidence(finding(), { ...context(), source: added }).hash).not.toBe(a.hash);
  });
});

describe('mentionedNames', () => {
  it('takes function and property names from code spans, not globals, paths, versions or the package itself', () => {
    const text = 'Calling `_.template()` or `merge` with `__proto__`, see `lib/index.js`, `RegExp`, `4.17.21`, `lodash`, `options.sourceURL`.';
    expect(mentionedNames(text, 'lodash')).toEqual(['template', 'merge', 'sourceURL']);
  });
});

describe('snippetsFor', () => {
  it('returns the code around each use and import, merged per file', async () => {
    const e = buildEvidence(finding(), { source, exposure: 'internet-facing', framework: { next: true, appRouter: true }, mentioned: ['template'] });
    const snippets = await snippetsFor(dir, e);
    expect(snippets.map((s) => [s.file, s.from, s.to])).toEqual([
      ['app/api/render/route.ts', 1, 5],
      ['tests/render.test.ts', 1, 2],
      ['components/Chart.tsx', 1, 3],
    ]);
    expect(snippets[0]!.code).toContain('_.template(await req.text())');
  });
});

describe('redactSecrets', () => {
  it('blanks values assigned to secret-looking names and keys with known prefixes, and leaves the rest', () => {
    const code = [
      "const apiKey = 'abcd1234efgh5678';",
      'headers: { Authorization: token },',
      `const client = new Stripe("sk_live_${'a'.repeat(24)}");`,
      "const title = 'not a secret at all';",
    ].join('\n');
    expect(redactSecrets(code).split('\n')).toEqual([
      "const apiKey = '[redacted]';",
      'headers: { Authorization: token },',
      'const client = new Stripe("[redacted]");',
      "const title = 'not a secret at all';",
    ]);
  });
});

describe('projectContext', () => {
  it('collects the configuration files that decide many advisories', async () => {
    expect(await projectContext(dir, [])).toBe('--- next.config.mjs\nexport default { experimental: {} };');
  });
});
