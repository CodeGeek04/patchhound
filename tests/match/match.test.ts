import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import type { Edge, PkgNode } from '../../src/match/graph.js';
import { GraphIndex, pkgId, rootId } from '../../src/match/graph.js';
import { parsePackageLock } from '../../src/match/lockfiles/package-lock.js';
import { matchGraph } from '../../src/match/match.js';
import { advisoryFingerprint, combineFingerprints } from '../../src/watch/advisory.js';
import type { OsvVuln } from '../../src/watch/osv.js';
import { OsvClient } from '../../src/watch/osv.js';
import { fakeFetch } from '../helpers/fake-fetch.js';
import { lodashInjection, osvRoutes, withdrawnMs } from '../helpers/osv-routes.js';

/** A graph where the app depends directly on each package. */
function appWith(...packages: [name: string, version: string][]): GraphIndex {
  const root = rootId('');
  const nodes = new Map<string, PkgNode>([[root, { id: root, name: 'app', version: '' }]]);
  const edges: Edge[] = [];
  for (const [name, version] of packages) {
    const id = pkgId(name, version);
    nodes.set(id, { id, name, version });
    edges.push({ from: root, to: id, name, type: 'prod' });
  }
  return new GraphIndex({ manager: 'npm', roots: [root], nodes, edges, warnings: [] });
}

const npm = (name: string) => ({ ecosystem: 'npm', name });

// Real pair, trimmed: the September 2025 debug@4.4.2 compromise is in OSV twice.
const debugGhsa: OsvVuln = {
  id: 'GHSA-4x49-vf9v-38px',
  modified: '2025-09-16T06:44:36.384185Z',
  published: '2025-09-15T21:30:55Z',
  summary: 'debug@4.4.2 contains malware after npm account takeover',
  aliases: ['CVE-2025-59144', 'GHSA-8mgj-vmr8-frr6', 'MAL-2025-46974'],
  database_specific: { severity: 'HIGH', cwe_ids: ['CWE-506'] },
  affected: [{ package: npm('debug'), ranges: [{ type: 'SEMVER', events: [{ introduced: '4.4.2' }, { fixed: '4.4.3' }] }], versions: ['4.4.2'] }],
};
const debugMal: OsvVuln = {
  id: 'MAL-2025-46974',
  modified: '2025-09-16T06:44:36.384185Z',
  published: '2025-09-08T14:26:51Z',
  summary: 'Malicious code in debug (npm)',
  aliases: ['CVE-2025-59144', 'GHSA-4x49-vf9v-38px', 'GHSA-8mgj-vmr8-frr6'],
  affected: [{ package: npm('debug'), versions: ['4.4.2'] }],
};

const lockfile = readFileSync(new URL('../fixtures/npm-app/package-lock.json', import.meta.url), 'utf8');

describe('matchGraph', () => {
  it('turns OSV matches into findings with paths, dev status and fix version', async () => {
    const { fetch } = fakeFetch(
      osvRoutes({ 'lodash@4.17.20': ['GHSA-35jh-r3h4-6jhm'], 'ms@2.1.2': ['GHSA-gone'] }, [lodashInjection, withdrawnMs]),
    );
    const findings = await matchGraph(new GraphIndex(parsePackageLock(lockfile)), new OsvClient({ fetch }));

    // The withdrawn advisory for ms is dropped.
    expect(findings).toHaveLength(1);
    const [lodash] = findings;
    expect(lodash).toMatchObject({
      package: 'lodash',
      version: '4.17.20',
      direct: true,
      devOnly: false,
      fixedVersion: '4.17.21',
      advisory: { id: 'GHSA-35jh-r3h4-6jhm', cves: ['CVE-2021-23337'], severity: 'HIGH' },
    });
    expect(lodash?.paths).toEqual([
      ['demo-app', 'lodash@4.17.20'],
      ['demo-app', 'async@2.6.3', 'lodash@4.17.20'],
    ]);
  });

  it('fingerprints each finding from its record and package', async () => {
    const { fetch } = fakeFetch(osvRoutes({ 'lodash@4.17.20': ['GHSA-35jh-r3h4-6jhm'] }, [lodashInjection]));
    const [lodash] = await matchGraph(new GraphIndex(parsePackageLock(lockfile)), new OsvClient({ fetch }));
    expect(lodash?.advisoryFingerprint).toBe(advisoryFingerprint(lodashInjection, 'lodash'));
  });

  it('merges records that are aliases of each other into one finding', async () => {
    const { fetch } = fakeFetch(osvRoutes({ 'debug@4.4.2': ['MAL-2025-46974', 'GHSA-4x49-vf9v-38px'] }, [debugMal, debugGhsa]));
    const findings = await matchGraph(appWith(['debug', '4.4.2']), new OsvClient({ fetch }));
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      package: 'debug',
      version: '4.4.2',
      fixedVersion: '4.4.3',
      advisoryFingerprint: combineFingerprints([advisoryFingerprint(debugMal, 'debug'), advisoryFingerprint(debugGhsa, 'debug')]),
      advisory: {
        id: 'GHSA-4x49-vf9v-38px',
        kind: 'malicious',
        summary: 'debug@4.4.2 contains malware after npm account takeover',
        aliases: ['CVE-2025-59144', 'GHSA-8mgj-vmr8-frr6', 'MAL-2025-46974'],
        severity: 'HIGH',
      },
    });
  });

  it('merges records that only share an alias, and keeps unrelated ones apart', async () => {
    const shared = (id: string, fixed: string): OsvVuln => ({
      id,
      modified: 'm',
      aliases: ['CVE-2026-1'],
      affected: [{ package: npm('pkg'), ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed }] }] }],
    });
    const unrelated: OsvVuln = { ...shared('GHSA-cccc', '1.0.1'), aliases: ['CVE-2026-2'] };
    const { fetch } = fakeFetch(
      osvRoutes({ 'pkg@1.0.0': ['GHSA-bbbb', 'GHSA-cccc', 'GHSA-aaaa'] }, [shared('GHSA-bbbb', '1.2.0'), unrelated, shared('GHSA-aaaa', '1.1.0')]),
    );
    const findings = await matchGraph(appWith(['pkg', '1.0.0']), new OsvClient({ fetch }));
    expect(findings.map((f) => [f.advisory.id, f.advisory.aliases, f.fixedVersion])).toEqual([
      ['GHSA-aaaa', ['CVE-2026-1', 'GHSA-bbbb'], '1.2.0'],
      ['GHSA-cccc', ['CVE-2026-2'], '1.0.1'],
    ]);
  });

  it('works out paths once per package, not once per finding', async () => {
    const second: OsvVuln = { ...lodashInjection, id: 'GHSA-second', aliases: [] };
    const { fetch } = fakeFetch(osvRoutes({ 'lodash@4.17.20': ['GHSA-35jh-r3h4-6jhm', 'GHSA-second'] }, [lodashInjection, second]));
    const index = new GraphIndex(parsePackageLock(lockfile));
    const pathsTo = vi.spyOn(index, 'pathsTo');
    const findings = await matchGraph(index, new OsvClient({ fetch }));
    expect(findings).toHaveLength(2);
    expect(pathsTo).toHaveBeenCalledTimes(1);
  });

  it('does not ask OSV about local packages', async () => {
    let asked: string[] = [];
    const routes = osvRoutes({}, []);
    const batch = routes['POST https://api.osv.dev/v1/querybatch']!;
    routes['POST https://api.osv.dev/v1/querybatch'] = (url, init) => {
      asked = (JSON.parse(String(init?.body)) as { queries: { package: { name: string }; version: string }[] }).queries.map(
        (q) => `${q.package.name}@${q.version}`,
      );
      return batch(url, init);
    };
    const { fetch } = fakeFetch(routes);
    await matchGraph(appWith(['lodash', '4.17.20'], ['@demo/ui', 'file:packages/ui'], ['@demo/cli', 'link:../cli']), new OsvClient({ fetch }));
    expect(asked).toEqual(['lodash@4.17.20']);
  });

  it('fetches an advisory shared by two packages once', async () => {
    const both: OsvVuln = {
      ...lodashInjection,
      affected: [...lodashInjection.affected!, { package: npm('lodash-es'), ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }],
    };
    const fake = fakeFetch(osvRoutes({ 'lodash@4.17.20': ['GHSA-35jh-r3h4-6jhm'], 'lodash-es@4.17.20': ['GHSA-35jh-r3h4-6jhm'] }, [both]));
    const findings = await matchGraph(appWith(['lodash', '4.17.20'], ['lodash-es', '4.17.20']), new OsvClient({ fetch: fake.fetch }));
    expect(findings.map((f) => `${f.advisory.id} ${f.package}`)).toEqual(['GHSA-35jh-r3h4-6jhm lodash', 'GHSA-35jh-r3h4-6jhm lodash-es']);
    expect(fake.calls.filter((call) => call.startsWith('GET'))).toEqual(['GET https://api.osv.dev/v1/vulns/GHSA-35jh-r3h4-6jhm']);
  });

  it('returns nothing when OSV has no matches', async () => {
    const { fetch } = fakeFetch(osvRoutes({}, []));
    expect(await matchGraph(new GraphIndex(parsePackageLock(lockfile)), new OsvClient({ fetch }))).toEqual([]);
  });
});
