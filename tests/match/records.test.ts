import { describe, expect, it } from 'vitest';
import type { Edge, PkgNode } from '../../src/match/graph.js';
import { GraphIndex, pkgId, rootId } from '../../src/match/graph.js';
import { matchGraph } from '../../src/match/match.js';
import type { OsvVuln } from '../../src/watch/osv.js';
import { OsvClient } from '../../src/watch/osv.js';
import { fakeFetch } from '../helpers/fake-fetch.js';
import { lodashInjection, osvRoutes } from '../helpers/osv-routes.js';

/** A graph where the app depends directly on each package. */
function appWith(...packages: [name: string, version: string][]): GraphIndex {
  const root = rootId('.');
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

// The September 2025 debug@4.4.2 compromise, trimmed: a GHSA and its MAL- twin.
const debugGhsa: OsvVuln = {
  id: 'GHSA-4x49-vf9v-38px',
  modified: '2025-09-16T06:44:36.384185Z',
  aliases: ['CVE-2025-59144', 'GHSA-8mgj-vmr8-frr6', 'MAL-2025-46974'],
  database_specific: { severity: 'HIGH', cwe_ids: ['CWE-506'] },
  affected: [{ package: npm('debug'), versions: ['4.4.2'] }],
};
const debugMal: OsvVuln = {
  id: 'MAL-2025-46974',
  modified: '2025-09-16T06:44:36.384185Z',
  aliases: ['CVE-2025-59144', 'GHSA-4x49-vf9v-38px', 'GHSA-8mgj-vmr8-frr6'],
  affected: [{ package: npm('debug'), versions: ['4.4.2'] }],
};

/** Findings for the given packages, with OSV answering `affecting` from `records`. */
async function match(affecting: Record<string, string[]>, records: OsvVuln[], ...packages: [string, string][]) {
  const { fetch } = fakeFetch(osvRoutes(affecting, records));
  return matchGraph(appWith(...packages), new OsvClient({ fetch }));
}

describe('Finding.records', () => {
  it('lists the merged OSV ids with the primary first, whatever order OSV answers in', async () => {
    const findings = await match({ 'debug@4.4.2': ['MAL-2025-46974', 'GHSA-4x49-vf9v-38px'] }, [debugMal, debugGhsa], ['debug', '4.4.2']);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.advisory.id).toBe('GHSA-4x49-vf9v-38px');
    expect(findings[0]?.records).toEqual(['GHSA-4x49-vf9v-38px', 'MAL-2025-46974']);
  });

  it('puts the rest after the primary in id order', async () => {
    const twin: OsvVuln = { ...debugGhsa, id: 'GHSA-zzzz-zzzz-zzzz', aliases: ['MAL-2025-46974'] };
    const findings = await match(
      { 'debug@4.4.2': ['MAL-2025-46974', 'GHSA-zzzz-zzzz-zzzz', 'GHSA-4x49-vf9v-38px'] },
      [debugMal, twin, debugGhsa],
      ['debug', '4.4.2'],
    );
    expect(findings.map((f) => f.records)).toEqual([['GHSA-4x49-vf9v-38px', 'GHSA-zzzz-zzzz-zzzz', 'MAL-2025-46974']]);
  });

  it('holds the one id of a finding that merged nothing', async () => {
    const findings = await match({ 'lodash@4.17.20': ['GHSA-35jh-r3h4-6jhm'] }, [lodashInjection], ['lodash', '4.17.20']);
    expect(findings.map((f) => f.records)).toEqual([['GHSA-35jh-r3h4-6jhm']]);
  });
});
