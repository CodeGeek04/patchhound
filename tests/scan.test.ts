import { access, copyFile, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeEach, describe, expect, it } from 'vitest';
import { scan } from '../src/scan.js';
import type { Fetch } from '../src/util/http.js';
import type { OsvVuln } from '../src/watch/osv.js';
import type { Handler } from './helpers/fake-fetch.js';
import { fakeFetch } from './helpers/fake-fetch.js';
import { lodashInjection, osvRoutes } from './helpers/osv-routes.js';
import { doc, REGISTRY, registryRoutes } from './helpers/registry-routes.js';

const KEV = 'GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS = 'GET https://api.first.org/data/v1/epss';
const NOW = new Date('2026-11-19T10:00:00Z');
/** Retries without waiting, so a feed that is down does not slow the tests. */
const NO_WAIT = { sleep: async () => {} };
const LODASH = doc('lodash', { '4.17.19': {}, '4.17.20': {}, '4.17.21': {} });
/** npm-app pins lodash 4.17.20 in package.json, so the plan bumps it there. */
const LODASH_BUMP = { kind: 'bump', package: 'lodash', from: '4.17.20', to: '4.17.21', change: 'patch', root: '.', spec: '4.17.20' };

let dir: string;
beforeEach(async () => {
  // A temp copy, so state files never land in the fixtures.
  dir = await mkdtemp(join(tmpdir(), 'bulwark-scan-'));
  await copyFile(fileURLToPath(new URL('./fixtures/npm-app/package-lock.json', import.meta.url)), join(dir, 'package-lock.json'));
});

function routes(overrides: Record<string, Handler> = {}) {
  return fakeFetch({
    ...osvRoutes({ 'lodash@4.17.20': ['GHSA-35jh-r3h4-6jhm'] }, [lodashInjection]),
    [KEV]: () => ({ vulnerabilities: [{ cveID: 'CVE-2021-23337' }] }),
    [EPSS]: () => ({ data: [{ cve: 'CVE-2021-23337', epss: '0.0123' }] }),
    ...registryRoutes([LODASH]),
    ...overrides,
  });
}

describe('scan', () => {
  it('reports enriched findings and remembers them', async () => {
    const { fetch } = routes();
    const first = await scan({ dir, fetch, now: NOW });
    expect(first).toMatchObject({
      schemaVersion: 1,
      scannedAt: NOW.toISOString(),
      manager: 'npm',
      packageCount: 4,
      warnings: [],
      enrichment: { kev: 'ok', epss: 'ok' },
    });
    expect(first.lockfile).toBe(join(dir, 'package-lock.json'));
    expect(first.findings).toHaveLength(1);
    expect(first.findings[0]).toMatchObject({ package: 'lodash', status: 'new', changed: [], kev: ['CVE-2021-23337'], epss: 0.0123 });
    expect(first.findings[0]!.key).toBe('GHSA-35jh-r3h4-6jhm|lodash@4.17.20');
    expect(first.fixPlan).toEqual({
      status: 'ok',
      actions: [
        {
          id: 'bump:.:lodash',
          kind: 'bump',
          steps: [LODASH_BUMP],
          packages: ['lodash@4.17.20'],
          findings: ['GHSA-35jh-r3h4-6jhm|lodash@4.17.20'],
          partial: [],
          devOnly: false,
        },
      ],
      brokenPeers: [],
      plans: [{ id: 'lodash@4.17.20', package: 'lodash', version: '4.17.20', kind: 'bump', target: expect.any(String), steps: [LODASH_BUMP] }],
    });
    expect(first.findings[0]!.fix).toEqual({ kind: 'bump', actions: ['bump:.:lodash'] });

    const second = await scan({ dir, fetch, now: NOW });
    expect(second.findings[0]).toMatchObject({ status: 'seen', changed: [] });
  });

  it('calls a finding updated when KEV lists its CVE later, and names the change', async () => {
    await scan({ dir, fetch: routes({ [KEV]: () => ({ vulnerabilities: [] }) }).fetch, now: NOW });
    const later = await scan({ dir, fetch: routes().fetch, now: NOW });
    expect(later.findings[0]).toMatchObject({ status: 'updated', changed: ['kev'], kev: ['CVE-2021-23337'] });
  });

  it('does not call a finding updated when OSV only re-stamps the advisory', async () => {
    await scan({ dir, fetch: routes().fetch, now: NOW });
    const restamped: OsvVuln = { ...lodashInjection, modified: '2026-11-19T09:00:00Z' };
    const { fetch } = routes(osvRoutes({ 'lodash@4.17.20': ['GHSA-35jh-r3h4-6jhm'] }, [restamped]));
    expect((await scan({ dir, fetch, now: NOW })).findings[0]).toMatchObject({ status: 'seen', changed: [] });
  });

  it('does not write state on a dry run', async () => {
    const { fetch } = routes();
    await scan({ dir, fetch, now: NOW, dryRun: true });
    await expect(access(join(dir, '.bulwark', 'state.json'))).rejects.toThrow();
    const again = await scan({ dir, fetch, now: NOW, dryRun: true });
    expect(again.findings[0]?.status).toBe('new');
  });

  it('keeps going when KEV is down, says so, and keeps the last KEV status', async () => {
    await scan({ dir, fetch: routes().fetch, now: NOW });
    const { fetch } = routes({ [KEV]: () => new Response('down', { status: 503 }) });
    const result = await scan({ dir, fetch, now: NOW, retry: NO_WAIT });
    expect(result.findings[0]).toMatchObject({ kev: null, status: 'seen', changed: [] });
    expect(result.warnings).toEqual(['KEV unavailable: KEV download failed with HTTP 503 after 4 attempts: down']);
    expect(result.enrichment).toEqual({ kev: 'unavailable', epss: 'ok' });
  });

  it('keeps going when EPSS is down and says so, with KEV still filled in', async () => {
    const { fetch } = routes({ [EPSS]: () => new Response('down', { status: 503 }) });
    const result = await scan({ dir, fetch, now: NOW, retry: NO_WAIT, dryRun: true });
    expect(result.findings[0]).toMatchObject({ kev: ['CVE-2021-23337'], epss: null });
    expect(result.warnings).toEqual([expect.stringMatching(/^EPSS unavailable: /)]);
    expect(result.enrichment).toEqual({ kev: 'ok', epss: 'unavailable' });
  });

  it('looks up linked CVEs only for an advisory with no CVE of its own', async () => {
    const nvd = (cve: string) => ({ type: 'WEB', url: `https://nvd.nist.gov/vuln/detail/${cve}` });
    const linkedOnly: OsvVuln = { ...lodashInjection, aliases: [], references: [nvd('CVE-2025-55182')] };
    const ownAndLinked: OsvVuln = {
      id: 'GHSA-ms',
      modified: '2026-01-01T00:00:00Z',
      aliases: ['CVE-2026-0001'],
      references: [nvd('CVE-2021-44228')],
      affected: [{ package: { ecosystem: 'npm', name: 'ms' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.1.3' }] }] }],
    };
    const asked: string[] = [];
    const { fetch } = fakeFetch({
      ...osvRoutes({ 'lodash@4.17.20': ['GHSA-35jh-r3h4-6jhm'], 'ms@2.1.2': ['GHSA-ms'] }, [linkedOnly, ownAndLinked]),
      [KEV]: () => ({ vulnerabilities: [{ cveID: 'CVE-2025-55182' }, { cveID: 'CVE-2021-44228' }] }),
      [EPSS]: (url) => {
        asked.push(...url.searchParams.get('cve')!.split(','));
        return { data: [] };
      },
    });
    const result = await scan({ dir, fetch, now: NOW, dryRun: true });
    const kevOf = (name: string) => result.findings.find((f) => f.package === name)?.kev;
    expect(kevOf('lodash')).toEqual(['CVE-2025-55182']);
    expect(kevOf('ms')).toEqual([]);
    expect(asked.sort()).toEqual(['CVE-2025-55182', 'CVE-2026-0001']);
  });

  it('skips KEV and EPSS when nothing matched', async () => {
    const fake = fakeFetch(osvRoutes({}, []));
    const result = await scan({ dir, fetch: fake.fetch, now: NOW, dryRun: true });
    expect(result.findings).toEqual([]);
    expect(result.enrichment).toEqual({ kev: 'skipped', epss: 'skipped' });
    expect(fake.calls).toEqual(['POST https://api.osv.dev/v1/querybatch']);
  });

  it('stops before asking OSV when the state file cannot be read', async () => {
    await mkdir(join(dir, '.bulwark'));
    await writeFile(join(dir, '.bulwark', 'state.json'), JSON.stringify({ version: 1, findings: {} }));
    const fake = routes();
    await expect(scan({ dir, fetch: fake.fetch, now: NOW })).rejects.toThrow(/state\.json has version 1/);
    expect(fake.calls).toEqual([]);
  });

  it('fails before any request when the state location cannot be created', async () => {
    await writeFile(join(dir, 'afile'), 'x');
    const statePath = join(dir, 'afile', 'state.json');
    const fake = routes();
    const failure = scan({ dir, fetch: fake.fetch, now: NOW, statePath });
    await expect(failure).rejects.toThrow('Could not save state file');
    await expect(failure).rejects.toThrow(statePath);
    expect(fake.calls).toEqual([]);
  });

  it('names a state path that is a directory', async () => {
    const statePath = join(dir, 'statedir');
    await mkdir(statePath);
    const fake = routes();
    const failure = scan({ dir, fetch: fake.fetch, now: NOW, statePath });
    await expect(failure).rejects.toThrow('Could not read state file');
    await expect(failure).rejects.toThrow(statePath);
    expect(fake.calls).toEqual([]);
  });

  it('makes the default state folder ignore itself, but only the default one', async () => {
    await scan({ dir, fetch: routes().fetch, now: NOW });
    expect(await readFile(join(dir, '.bulwark', '.gitignore'), 'utf8')).toBe('*\n');

    const other = join(dir, 'custom');
    await scan({ dir, fetch: routes().fetch, now: NOW, statePath: join(other, 'state.json') });
    await access(join(other, 'state.json'));
    await expect(access(join(other, '.gitignore'))).rejects.toThrow();
  });

  it('creates nothing on a dry run', async () => {
    await scan({ dir, fetch: routes().fetch, now: NOW, dryRun: true });
    await expect(access(join(dir, '.bulwark'))).rejects.toThrow();
  });

  it('reports the alias key when the state already has the finding under one', async () => {
    await scan({ dir, fetch: routes().fetch, now: NOW });
    const statePath = join(dir, '.bulwark', 'state.json');
    const saved = JSON.parse(await readFile(statePath, 'utf8'));
    const alias = 'CVE-2021-23337|lodash@4.17.20';
    saved.findings = { [alias]: saved.findings['GHSA-35jh-r3h4-6jhm|lodash@4.17.20'] };
    await writeFile(statePath, JSON.stringify(saved));
    const result = await scan({ dir, fetch: routes().fetch, now: NOW });
    expect(result.findings[0]).toMatchObject({ key: alias, status: 'seen' });
  });

  it('passes on what the lockfile parser could not check', async () => {
    const pnpmDir = await mkdtemp(join(tmpdir(), 'bulwark-scan-'));
    await copyFile(fileURLToPath(new URL('./fixtures/next-app-pnpm/pnpm-lock.yaml', import.meta.url)), join(pnpmDir, 'pnpm-lock.yaml'));
    const { fetch } = fakeFetch(osvRoutes({}, []));
    const result = await scan({ dir: pnpmDir, fetch, now: NOW, dryRun: true });
    expect(result.warnings).toEqual([expect.stringMatching(/^1 package bundles dependencies that pnpm-lock.yaml does not list/)]);
  });

  it('keeps the state key when a GHSA joins a MAL-only group', async () => {
    const mal: OsvVuln = {
      id: 'MAL-2026-9',
      modified: '2026-11-18T00:00:00Z',
      summary: 'Malicious code in lodash',
      affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '4.17.20' }, { fixed: '4.17.21' }] }] }],
    };
    const ghsa: OsvVuln = { ...lodashInjection, aliases: ['MAL-2026-9'] };
    const onlyMal = fakeFetch({ ...osvRoutes({ 'lodash@4.17.20': ['MAL-2026-9'] }, [mal]), [KEV]: () => ({ vulnerabilities: [] }), [EPSS]: () => ({ data: [] }) });
    await scan({ dir, fetch: onlyMal.fetch, now: NOW });
    const both = fakeFetch({
      ...osvRoutes({ 'lodash@4.17.20': ['MAL-2026-9', 'GHSA-35jh-r3h4-6jhm'] }, [mal, ghsa]),
      [KEV]: () => ({ vulnerabilities: [] }),
      [EPSS]: () => ({ data: [] }),
    });
    const later = await scan({ dir, fetch: both.fetch, now: NOW });
    expect(later.findings).toHaveLength(1);
    expect(later.findings[0]).toMatchObject({ status: 'updated' });
    expect(later.findings[0]!.advisory.id).toBe('GHSA-35jh-r3h4-6jhm');
    expect(later.findings[0]!.changed).toContain('advisory');
  });
});

describe('scan fix plan', () => {
  const registryCalls = (calls: string[]) => calls.filter((call) => call.startsWith(`GET ${REGISTRY}/`));

  it('says the plan is unavailable when the npm registry is down, and leaves every fix unknown', async () => {
    const fake = routes();
    const registryDown: Fetch = async (input, init) =>
      String(input).startsWith(`${REGISTRY}/`) ? new Response('down', { status: 503 }) : fake.fetch(input, init);
    const result = await scan({ dir, fetch: registryDown, now: NOW, retry: NO_WAIT, dryRun: true });
    expect(result.fixPlan).toEqual({ status: 'unavailable', actions: [], brokenPeers: [] });
    expect(result.warnings).toEqual(['Fix plan unavailable: npm registry GET lodash failed with HTTP 503 after 4 attempts: down']);
    expect(result.findings[0]!.fix).toBeNull();
    // KEV and EPSS still came through.
    expect(result.enrichment).toEqual({ kev: 'ok', epss: 'ok' });
  });

  it('says the plan is incomplete when only some lookups fail, and plans the rest', async () => {
    const msBug: OsvVuln = {
      id: 'GHSA-ms',
      modified: '2026-01-01T00:00:00Z',
      affected: [{ package: { ecosystem: 'npm', name: 'ms' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.1.3' }] }] }],
    };
    // The registry has no document for ms.
    const { fetch } = routes(osvRoutes({ 'lodash@4.17.20': ['GHSA-35jh-r3h4-6jhm'], 'ms@2.1.2': ['GHSA-ms'] }, [lodashInjection, msBug]));
    const result = await scan({ dir, fetch, now: NOW, dryRun: true });
    expect(result.fixPlan.status).toBe('ok');
    expect(result.warnings).toEqual([
      'Fix plan incomplete: 1 npm registry lookup failed: npm registry GET ms failed with HTTP 404: no route for GET https://registry.npmjs.org/ms',
    ]);
    const fixOf = (name: string) => result.findings.find((f) => f.package === name)?.fix;
    expect(fixOf('lodash')).toEqual({ kind: 'bump', actions: ['bump:.:lodash'] });
    expect(fixOf('ms')).toEqual({ kind: 'unknown', actions: ['unknown:ms@2.1.2'] });
  });

  it('calls the plan incomplete, not unavailable, when its only package is one the registry does not have', async () => {
    // A private package: the registry answers, with a 404.
    const { fetch } = routes({ [`GET ${REGISTRY}/lodash`]: () => new Response('{"error":"Not found"}', { status: 404 }) });
    const result = await scan({ dir, fetch, now: NOW, dryRun: true });
    expect(result.fixPlan.status).toBe('ok');
    expect(result.warnings).toEqual([
      'Fix plan incomplete: 1 npm registry lookup failed: npm registry GET lodash failed with HTTP 404: {"error":"Not found"}',
    ]);
    expect(result.findings[0]!.fix).toEqual({ kind: 'unknown', actions: ['unknown:lodash@4.17.20'] });
  });

  it('records the workspace folders besides the root', async () => {
    const workspace = await mkdtemp(join(tmpdir(), 'bulwark-scan-'));
    await copyFile(fileURLToPath(new URL('./fixtures/pnpm-workspace/pnpm-lock.yaml', import.meta.url)), join(workspace, 'pnpm-lock.yaml'));
    const result = await scan({ dir: workspace, fetch: fakeFetch(osvRoutes({}, [])).fetch, now: NOW, dryRun: true });
    expect(result.workspaces).toEqual(['apps/web', 'packages/ui']);
    expect((await scan({ dir, fetch: routes().fetch, now: NOW, dryRun: true })).workspaces).toEqual([]);
  });

  it('scans the lockfile it is told to', async () => {
    await copyFile(fileURLToPath(new URL('./fixtures/pnpm-app/pnpm-lock.yaml', import.meta.url)), join(dir, 'pnpm-lock.yaml'));
    expect((await scan({ dir, fetch: routes().fetch, now: NOW, dryRun: true, fixPlan: false })).manager).toBe('pnpm');
    const chosen = await scan({ dir, fetch: routes().fetch, now: NOW, dryRun: true, fixPlan: false, lockfile: 'package-lock.json' });
    expect(chosen.manager).toBe('npm');
    expect(chosen.warnings).toEqual([]);
  });

  it("checks the React build next bundles, and says which one it checked", async () => {
    const nextApp = await mkdtemp(join(tmpdir(), 'bulwark-scan-'));
    await copyFile(fileURLToPath(new URL('./fixtures/next-app-npm/package-lock.json', import.meta.url)), join(nextApp, 'package-lock.json'));
    const rsc: OsvVuln = {
      id: 'GHSA-rsc',
      modified: '2026-11-10T00:00:00Z',
      published: '2026-11-10T00:00:00Z',
      affected: [{ package: { ecosystem: 'npm', name: 'react-server-dom-webpack' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '19.1.0' }, { fixed: '19.1.10' }] }] }],
    };
    const fake = fakeFetch({
      ...osvRoutes({ 'react-server-dom-webpack@19.1.0': ['GHSA-rsc'] }, [rsc]),
      'POST https://api.osv.dev/v1/query': () => ({ vulns: [] }),
      'GET https://cdn.jsdelivr.net/npm/next@15.2.2/dist/compiled/react-server-dom-webpack/package.json': () => ({
        peerDependencies: { react: '19.1.0-canary-029e8bd6-20250306' },
      }),
    });
    const result = await scan({ dir: nextApp, fetch: fake.fetch, now: NOW, dryRun: true, fixPlan: false, retry: NO_WAIT });
    expect(result.findings.map((f) => `${f.advisory.id} ${f.package}@${f.version} via ${f.paths[0]!.join(' > ')}`)).toEqual([
      'GHSA-rsc react-server-dom-webpack@19.1.0 via next-demo > next@15.2.2 > react-server-dom-webpack@19.1.0',
    ]);
    expect(result.warnings).toContain(
      "next 15.2.2 bundles React build 19.1.0-canary-029e8bd6-20250306 (checked as 19.1.0); React's advisories reach it through react-server-dom-* until Next.js publishes its own.",
    );
    const off = await scan({ dir: nextApp, fetch: fake.fetch, now: NOW, dryRun: true, fixPlan: false, nextBundles: false });
    expect(off.findings).toEqual([]);
  });

  it('skips the plan when it is turned off, without asking the registry', async () => {
    const fake = routes();
    const result = await scan({ dir, fetch: fake.fetch, now: NOW, dryRun: true, fixPlan: false });
    expect(result.fixPlan).toEqual({ status: 'skipped', actions: [], brokenPeers: [] });
    expect(result.findings[0]!.fix).toBeNull();
    expect(result.warnings).toEqual([]);
    expect(registryCalls(fake.calls)).toEqual([]);
  });

  it('skips the plan when nothing matched', async () => {
    const fake = fakeFetch(osvRoutes({}, []));
    const result = await scan({ dir, fetch: fake.fetch, now: NOW, dryRun: true });
    expect(result.fixPlan).toEqual({ status: 'skipped', actions: [], brokenPeers: [] });
    expect(fake.calls).toEqual(['POST https://api.osv.dev/v1/querybatch']);
  });

  it('asks the registry at registryUrl', async () => {
    const fake = routes(registryRoutes([LODASH], 'https://npm.example.test'));
    const result = await scan({ dir, fetch: fake.fetch, now: NOW, dryRun: true, registryUrl: 'https://npm.example.test' });
    expect(result.fixPlan.actions.map((a) => a.id)).toEqual(['bump:.:lodash']);
    expect(fake.calls).toContain('GET https://npm.example.test/lodash');
    expect(registryCalls(fake.calls)).toEqual([]);
  });
});
