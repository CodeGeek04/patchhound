import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { DepGraph } from '../../src/match/graph.js';
import { GraphIndex } from '../../src/match/graph.js';
import { matchGraph } from '../../src/match/match.js';
import { addNextBundles, buildDate, settleBundled } from '../../src/match/vendored.js';
import { DiskCache } from '../../src/util/cache.js';
import type { OsvVuln } from '../../src/watch/osv.js';
import { OsvClient } from '../../src/watch/osv.js';
import type { Handler } from '../helpers/fake-fetch.js';
import { fakeFetch } from '../helpers/fake-fetch.js';
import { osvRoutes } from '../helpers/osv-routes.js';

const CDN = 'https://cdn.jsdelivr.net/npm';
const bundleRoute = (version: string) => `GET ${CDN}/next@${version}/dist/compiled/react-server-dom-webpack/package.json`;
const builtWith = (react: string) => () => ({ name: 'react-server-dom-webpack-builtin', peerDependencies: { react } });

/** The project depends on the given next versions, each from its own workspace. */
function appWith(...nexts: string[]): DepGraph {
  const roots = nexts.map((_, i) => `root:${i === 0 ? '.' : `apps/${i}`}`);
  const nodes = new Map(roots.map((id) => [id, { id, name: id, version: '' }]));
  for (const version of nexts) nodes.set(`next@${version}`, { id: `next@${version}`, name: 'next', version });
  const edges = nexts.map((version, i) => ({ from: roots[i]!, to: `next@${version}`, name: 'next', spec: version, type: 'prod' as const }));
  return { manager: 'npm', roots, nodes, edges, warnings: [] };
}

describe('addNextBundles', () => {
  it("adds the server-component packages next bundles, at their build's release line, under next", async () => {
    const graph = appWith('15.2.2');
    const { fetch } = fakeFetch({ [bundleRoute('15.2.2')]: builtWith('19.1.0-canary-029e8bd6-20250306') });
    expect(await addNextBundles(graph, { fetch })).toEqual([]);
    expect(graph.nodes.get('react-server-dom-webpack@19.1.0')).toEqual({
      id: 'react-server-dom-webpack@19.1.0',
      name: 'react-server-dom-webpack',
      version: '19.1.0',
      build: '19.1.0-canary-029e8bd6-20250306',
      bundledBy: ['next@15.2.2'],
    });
    expect(graph.nodes.has('react-server-dom-turbopack@19.1.0')).toBe(true);
    expect(new GraphIndex(graph).pathsTo('react-server-dom-turbopack@19.1.0')).toEqual([['root:.', 'next@15.2.2', 'react-server-dom-turbopack@19.1.0']]);
  });

  it('adds nothing for a next that bundles none, and warns when its files cannot be read', async () => {
    const graph = appWith('12.3.4', '15.2.2');
    const { fetch } = fakeFetch({ [bundleRoute('15.2.2')]: () => new Response('down', { status: 503 }) });
    expect(await addNextBundles(graph, { fetch, retry: { retries: 0 } })).toEqual([
      `Could not read which React build next 15.2.2 bundles, so React's own advisories were not checked for it: jsDelivr GET next@15.2.2 bundled React failed with HTTP 503: down`,
    ]);
    expect([...graph.nodes.keys()].filter((id) => id.startsWith('react'))).toEqual([]);
  });

  it('leaves a copy the app installs itself alone, and keeps the older build when two nexts share a line', async () => {
    const graph = appWith('16.4.3', '16.4.9');
    graph.nodes.set('react-server-dom-turbopack@19.3.0', { id: 'react-server-dom-turbopack@19.3.0', name: 'react-server-dom-turbopack', version: '19.3.0' });
    const { fetch } = fakeFetch({
      [bundleRoute('16.4.3')]: builtWith('19.3.0-canary-278794d7-20261002'),
      [bundleRoute('16.4.9')]: builtWith('19.3.0-canary-0f1e2d3c-20261120'),
    });
    await addNextBundles(graph, { fetch });
    expect(graph.nodes.get('react-server-dom-turbopack@19.3.0')).toEqual({ id: 'react-server-dom-turbopack@19.3.0', name: 'react-server-dom-turbopack', version: '19.3.0' });
    expect(graph.nodes.get('react-server-dom-webpack@19.3.0')).toMatchObject({ build: '19.3.0-canary-278794d7-20261002', bundledBy: ['next@16.4.3', 'next@16.4.9'] });
  });
});

describe('addNextBundles with a cache', () => {
  it("keeps what a next version bundles for good, but asks again about one jsDelivr did not have", async () => {
    const cache = new DiskCache(await mkdtemp(join(tmpdir(), 'bulwark-cache-')));
    const fake = fakeFetch({
      'GET https://cdn.jsdelivr.net/npm/next@15.2.2/dist/compiled/react-server-dom-webpack/package.json': () => ({
        peerDependencies: { react: '19.1.0-canary-029e8bd6-20250306' },
      }),
    });
    const graph = (): DepGraph => ({
      manager: 'npm',
      roots: ['root:.'],
      nodes: new Map([
        ['root:.', { id: 'root:.', name: 'app', version: '' }],
        ['next@15.2.2', { id: 'next@15.2.2', name: 'next', version: '15.2.2' }],
        ['next@12.3.4', { id: 'next@12.3.4', name: 'next', version: '12.3.4' }],
      ]),
      edges: [],
      warnings: [],
    });
    await addNextBundles(graph(), { fetch: fake.fetch, cache });
    const again = graph();
    await addNextBundles(again, { fetch: fake.fetch, cache });
    expect(again.nodes.get('react-server-dom-webpack@19.1.0')?.build).toBe('19.1.0-canary-029e8bd6-20250306');
    // 15.2.2 once; 12.3.4 (a 404) on both runs.
    expect(fake.calls).toHaveLength(3);
  });
});

describe('settleBundled', () => {
  const reactRce = (id: string, published: string, references: string[] = []): OsvVuln => ({
    id,
    modified: published,
    published,
    aliases: [`CVE-${id.slice(5)}`],
    references: references.map((url) => ({ type: 'WEB', url })),
    database_specific: { severity: 'CRITICAL' },
    affected: ['react-server-dom-webpack', 'react-server-dom-turbopack'].map((name) => ({
      package: { ecosystem: 'npm', name },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '19.3.0' }, { fixed: '19.3.1' }] }],
    })),
  });
  const before = reactRce('GHSA-0000-before', '2026-09-01T00:00:00Z');
  const after = reactRce('GHSA-0000-after', '2026-11-10T00:00:00Z');
  const answered = reactRce('GHSA-0000-answered', '2026-11-11T00:00:00Z');

  async function settle(nextRoutes: Record<string, Handler>) {
    const graph = appWith('16.4.3');
    const records = [before, after, answered];
    const affecting = Object.fromEntries(
      ['react-server-dom-webpack@19.3.0', 'react-server-dom-turbopack@19.3.0'].map((id) => [id, records.map((r) => r.id)]),
    );
    const { fetch } = fakeFetch({ ...osvRoutes(affecting, records), [bundleRoute('16.4.3')]: builtWith('19.3.0-canary-278794d7-20261002'), ...nextRoutes });
    await addNextBundles(graph, { fetch });
    const osv = new OsvClient({ fetch, retry: { retries: 0 } });
    const findings = await matchGraph(new GraphIndex(graph), osv);
    return settleBundled(findings, graph, osv);
  }

  it('keeps advisories newer than the build, unless Next.js references them in an advisory of its own', async () => {
    const nextAdvisory: OsvVuln = {
      id: 'GHSA-next',
      modified: '2026-11-11T00:00:00Z',
      references: [{ type: 'WEB', url: 'https://github.com/facebook/react/security/advisories/GHSA-0000-answered' }],
    };
    const { findings, warnings } = await settle({ 'POST https://api.osv.dev/v1/query': () => ({ vulns: [nextAdvisory] }) });
    // `before` was published before the build was made, so the build carries its fix.
    expect(findings.map((f) => `${f.advisory.id} ${f.package}`).sort()).toEqual([
      'GHSA-0000-after react-server-dom-turbopack',
      'GHSA-0000-after react-server-dom-webpack',
    ]);
    expect(warnings).toEqual([
      "next 16.4.3 bundles React build 19.3.0-canary-278794d7-20261002 (checked as 19.3.0); React's advisories reach it through react-server-dom-* until Next.js publishes its own.",
    ]);
  });

  it("keeps them, with a warning, when Next.js's advisories cannot be read", async () => {
    const { findings, warnings } = await settle({ 'POST https://api.osv.dev/v1/query': () => new Response('down', { status: 503 }) });
    expect(new Set(findings.map((f) => f.advisory.id))).toEqual(new Set(['GHSA-0000-after', 'GHSA-0000-answered']));
    expect(warnings[0]).toMatch(/^Could not read Next.js's own advisories/);
  });

  it('reads the date at the end of a build', () => {
    expect(buildDate('19.1.0-canary-029e8bd6-20250306')).toBe('2025-03-06');
    expect(buildDate('19.0.0-rc-66855b96-20241106')).toBe('2024-11-06');
    expect(buildDate('19.2.0')).toBeUndefined();
  });
});
