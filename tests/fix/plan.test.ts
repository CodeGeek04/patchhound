import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { PlanResult } from '../../src/fix/plan.js';
import { brokenPeers, planFixes } from '../../src/fix/plan.js';
import type { Packument } from '../../src/fix/registry.js';
import { RegistryClient } from '../../src/fix/registry.js';
import type { DepType, Edge, Manager, PkgNode } from '../../src/match/graph.js';
import { GraphIndex } from '../../src/match/graph.js';
import { parsePackageLock } from '../../src/match/lockfiles/package-lock.js';
import { parsePnpmLock } from '../../src/match/lockfiles/pnpm-lock.js';
import { matchGraph } from '../../src/match/match.js';
import type { OsvVuln } from '../../src/watch/osv.js';
import { OsvClient } from '../../src/watch/osv.js';
import { fakeFetch } from '../helpers/fake-fetch.js';
import { lodashInjection, osvRoutes } from '../helpers/osv-routes.js';
import { doc, REGISTRY, registryRoutes } from '../helpers/registry-routes.js';

const ROOT = 'root:.';

interface EdgeOptions {
  type?: DepType;
  /** The name the parent asks for, when it differs from the target's (an npm alias). */
  name?: string;
  catalog?: string;
}

/** Parent id, child id, the declared range (left out when the lockfile does not record one), options. */
type EdgeSpec = [from: string, to: string, spec?: string, options?: EdgeOptions];

const nameOf = (id: string) => id.slice(0, id.lastIndexOf('@'));

/**
 * A graph from its edges. Ids that start with `root:` are the project and its workspaces, the rest
 * are `name@version`. `bundledBy` marks npm `inBundle` packages.
 */
function graphOf(edges: EdgeSpec[], bundledBy: Record<string, string[]> = {}, manager: Manager = 'npm'): GraphIndex {
  const nodes = new Map<string, PkgNode>();
  const add = (id: string) => {
    if (nodes.has(id)) return;
    if (id.startsWith('root:')) {
      nodes.set(id, { id, name: id === ROOT ? 'app' : id.slice('root:'.length), version: '' });
    } else {
      const by = bundledBy[id];
      nodes.set(id, { id, name: nameOf(id), version: id.slice(id.lastIndexOf('@') + 1), ...(by ? { bundledBy: by } : {}) });
    }
  };
  add(ROOT);
  const list = edges.map(([from, to, spec, options = {}]): Edge => {
    add(from);
    add(to);
    return {
      from,
      to,
      name: options.name ?? nameOf(to),
      ...(spec === undefined ? {} : { spec }),
      ...(options.catalog === undefined ? {} : { catalog: options.catalog }),
      type: options.type ?? 'prod',
    };
  });
  const roots = [...nodes.keys()].filter((id) => id.startsWith('root:'));
  return new GraphIndex({ manager, roots, nodes, edges: list, warnings: [] });
}

const npm = (name: string) => ({ ecosystem: 'npm', name });

/** A vulnerability in `name` from `introduced` up to `fixed` (no fix when left out). */
function vuln(id: string, name: string, introduced: string, fixed?: string): OsvVuln {
  return {
    id,
    modified: '2026-11-01T00:00:00Z',
    database_specific: { severity: 'HIGH' },
    affected: [{ package: npm(name), ranges: [{ type: 'SEMVER', events: [{ introduced }, ...(fixed ? [{ fixed }] : [])] }] }],
  };
}

/** Malware in the listed versions of `name`. */
function malware(id: string, name: string, versions: string[]): OsvVuln {
  return { id, modified: '2026-11-01T00:00:00Z', affected: [{ package: npm(name), versions }] };
}

interface Case {
  index: GraphIndex;
  docs: Packument[];
  /** `name@version` -> the records OSV answers for it. */
  vulnerable: Record<string, OsvVuln[]>;
}

/** Matches the graph against the records, as a scan does, then plans. Also returns the packages asked of the registry. */
async function planCase({ index, docs, vulnerable }: Case): Promise<PlanResult & { asked: string[] }> {
  const records = [...new Set(Object.values(vulnerable).flat())];
  const affecting = Object.fromEntries(Object.entries(vulnerable).map(([id, list]) => [id, list.map((r) => r.id)]));
  const fake = fakeFetch({ ...osvRoutes(affecting, records), ...registryRoutes(docs) });
  const osv = new OsvClient({ fetch: fake.fetch });
  const findings = await matchGraph(index, osv);
  const result = await planFixes(index, findings, { osv, registry: new RegistryClient({ fetch: fake.fetch }) });
  const prefix = `GET ${REGISTRY}/`;
  return { ...result, asked: fake.calls.filter((call) => call.startsWith(prefix)).map((call) => call.slice(prefix.length)) };
}

const fixture = (name: string, file: string) => readFileSync(new URL(`../fixtures/${name}/${file}`, import.meta.url), 'utf8');

const lodashDoc = doc('lodash', { '3.10.1': {}, '4.17.19': {}, '4.17.20': {}, '4.17.21': {} });

describe('planFixes: refresh', () => {
  const formDataBug = vuln('GHSA-fd', 'form-data', '4.0.0', '4.0.5');
  const formData = doc('form-data', { '3.0.4': {}, '4.0.4': {}, '4.0.5': {} });

  it('refreshes a transitive package whose parent range already allows a clean version', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'axios@1.12.2', '1.12.2'],
        ['axios@1.12.2', 'form-data@4.0.4', '^4.0.4'],
      ]),
      docs: [formData],
      vulnerable: { 'form-data@4.0.4': [formDataBug] },
    });
    expect(result).toEqual({
      plans: [
        {
          id: 'form-data@4.0.4',
          package: 'form-data',
          version: '4.0.4',
          kind: 'refresh',
          target: '4.0.5',
          steps: [{ kind: 'refresh', package: 'form-data', from: '4.0.4', to: '4.0.5', direct: false }],
        },
      ],
      brokenPeers: [],
      problems: [],
      outage: null,
      // The lockfile records axios's range, so the registry is asked about form-data only.
      asked: ['form-data'],
    });
  });

  it("reads the parent's range from the registry when the lockfile does not record it (pnpm)", async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'axios@1.12.2', '1.12.2'],
        ['axios@1.12.2', 'form-data@4.0.4'],
      ]),
      docs: [formData, doc('axios', { '1.12.2': { dependencies: { 'form-data': '^4.0.4' } } })],
      vulnerable: { 'form-data@4.0.4': [formDataBug] },
    });
    expect(result.plans[0]?.steps).toEqual([{ kind: 'refresh', package: 'form-data', from: '4.0.4', to: '4.0.5', direct: false }]);
    expect(result.asked.sort()).toEqual(['axios', 'form-data']);
  });

  it('marks a refresh of a package that package.json lists as direct', async () => {
    const result = await planCase({
      index: graphOf([[ROOT, 'axios@1.12.2', '^1.12.2']]),
      docs: [doc('axios', { '1.12.2': {}, '1.13.0': {}, '1.13.1': {} })],
      vulnerable: { 'axios@1.12.2': [vuln('GHSA-axios', 'axios', '0', '1.13.0')] },
    });
    expect(result.plans[0]?.steps).toEqual([{ kind: 'refresh', package: 'axios', from: '1.12.2', to: '1.13.1', direct: true }]);
  });

  it('adds a package that only peer ranges point at to package.json, at the highest clean version they all allow', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'plugin-a@1.0.0', '^1.0.0'],
        [ROOT, 'plugin-b@1.0.0', '^1.0.0'],
        ['plugin-a@1.0.0', 'host@2.0.0', '^2.0.0', { type: 'peer' }],
        ['plugin-b@1.0.0', 'host@2.0.0', '>=2.0.0 <2.2.0', { type: 'peerOptional' }],
      ]),
      docs: [doc('host', { '2.0.0': {}, '2.0.1': {}, '2.1.0': {}, '2.2.0': {}, '3.0.0': {} })],
      vulnerable: { 'host@2.0.0': [vuln('GHSA-host', 'host', '0', '2.0.1')] },
    });
    // pnpm keeps such a peer where it is even on a fresh resolve, so a refresh would not move it.
    expect(result.plans).toEqual([
      {
        id: 'host@2.0.0',
        package: 'host',
        version: '2.0.0',
        kind: 'bump',
        target: '2.0.1',
        steps: [{ kind: 'bump', package: 'host', from: '2.0.0', to: '2.1.0', change: 'minor', root: '.', spec: '', add: 'dependencies' }],
      },
    ]);
  });

  it('adds it to devDependencies when only dev dependencies reach it', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'vitest@4.1.11', '^4.1.6', { type: 'dev' }],
        ['vitest@4.1.11', 'vite@8.2.2', '^6.0.0 || ^7.0.0 || ^8.0.0', { type: 'peer' }],
      ]),
      docs: [doc('vite', { '8.2.2': {}, '8.2.4': {}, '8.3.8': {} })],
      vulnerable: { 'vite@8.2.2': [vuln('GHSA-vite', 'vite', '8.0.0', '8.2.4')] },
    });
    expect(result.plans[0]?.steps).toEqual([
      { kind: 'bump', package: 'vite', from: '8.2.2', to: '8.3.8', change: 'minor', root: '.', spec: '', add: 'devDependencies' },
    ]);
  });
});

describe('planFixes: bump', () => {
  it('bumps a pinned direct dependency to the lowest clean release', async () => {
    const result = await planCase({
      index: graphOf([[ROOT, 'lodash@4.17.20', '4.17.20']]),
      docs: [doc('lodash', { '4.17.20': {}, '4.17.21': {}, '4.17.22': {}, '5.0.0': {} })],
      vulnerable: { 'lodash@4.17.20': [lodashInjection] },
    });
    expect(result.plans).toEqual([
      {
        id: 'lodash@4.17.20',
        package: 'lodash',
        version: '4.17.20',
        kind: 'bump',
        target: '4.17.21',
        steps: [{ kind: 'bump', package: 'lodash', from: '4.17.20', to: '4.17.21', change: 'patch', root: '.', spec: '4.17.20' }],
      },
    ]);
  });

  it('names a major move', async () => {
    const result = await planCase({
      index: graphOf([[ROOT, 'lodash@3.10.1', '^3.10.0']]),
      docs: [lodashDoc],
      vulnerable: { 'lodash@3.10.1': [lodashInjection] },
    });
    expect(result.plans[0]?.steps).toEqual([
      { kind: 'bump', package: 'lodash', from: '3.10.1', to: '4.17.21', change: 'major', root: '.', spec: '^3.10.0' },
    ]);
  });

  it('drops the refresh of a package that also has a bump (npm-app: lodash direct and under async)', async () => {
    const result = await planCase({
      index: new GraphIndex(parsePackageLock(fixture('npm-app', 'package-lock.json'))),
      docs: [lodashDoc],
      vulnerable: { 'lodash@4.17.20': [lodashInjection] },
    });
    // async's ^4.17.14 alone would only need a refresh; the root pins 4.17.20, so it has to be bumped.
    expect(result.plans[0]).toMatchObject({
      kind: 'bump',
      steps: [{ kind: 'bump', package: 'lodash', from: '4.17.20', to: '4.17.21', change: 'patch', root: '.', spec: '4.17.20' }],
    });
    expect(result.asked).toEqual(['lodash']);
  });

  it('asks pnpm to dedupe after the bump, since pnpm 11 keeps the other copies where they are', async () => {
    const result = await planCase({
      index: graphOf(
        [
          [ROOT, 'lodash@4.17.20', '4.17.20'],
          [ROOT, 'async@3.2.6', '^3.2.0'],
          ['async@3.2.6', 'lodash@4.17.20'],
        ],
        {},
        'pnpm',
      ),
      docs: [lodashDoc, doc('async', { '3.2.6': { dependencies: { lodash: '^4.17.14' } } })],
      vulnerable: { 'lodash@4.17.20': [lodashInjection] },
    });
    expect(result.plans[0]?.steps).toEqual([
      { kind: 'bump', package: 'lodash', from: '4.17.20', to: '4.17.21', change: 'patch', root: '.', spec: '4.17.20', dedupe: true },
    ]);
  });

  it('bumps the direct parent when it pins the vulnerable version and a newer parent accepts a clean one', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'wrapper@1.0.0', '1.0.0'],
        ['wrapper@1.0.0', 'lodash@4.17.20', '4.17.20'],
      ]),
      docs: [
        lodashDoc,
        doc('wrapper', {
          '1.0.0': { dependencies: { lodash: '4.17.20' } },
          '1.0.1': { dependencies: { lodash: '4.17.20' } },
          '1.1.0': { dependencies: { lodash: '^4.17.21' } },
          '2.0.0': { dependencies: { lodash: '^4.17.21' } },
        }),
      ],
      vulnerable: { 'lodash@4.17.20': [lodashInjection] },
    });
    expect(result.plans).toEqual([
      {
        id: 'lodash@4.17.20',
        package: 'lodash',
        version: '4.17.20',
        kind: 'bump',
        target: '4.17.21',
        steps: [{ kind: 'bump', package: 'wrapper', from: '1.0.0', to: '1.1.0', change: 'minor', root: '.', spec: '1.0.0' }],
      },
    ]);
  });

  it('bumps a parent whose newer version no longer depends on the package', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'tool@1.0.0', '^1.0.0'],
        ['tool@1.0.0', 'leftpad@1.0.0', '^1.0.0'],
      ]),
      docs: [
        doc('leftpad', { '1.0.0': {}, '1.1.0': {} }),
        doc('tool', { '1.0.0': { dependencies: { leftpad: '^1.0.0' } }, '1.1.0': { dependencies: { leftpad: '^1.0.0' } }, '2.0.0': {} }),
      ],
      vulnerable: { 'leftpad@1.0.0': [vuln('GHSA-lp', 'leftpad', '0')] },
    });
    expect(result.plans).toEqual([
      {
        id: 'leftpad@1.0.0',
        package: 'leftpad',
        version: '1.0.0',
        kind: 'bump',
        target: null,
        steps: [{ kind: 'bump', package: 'tool', from: '1.0.0', to: '2.0.0', change: 'major', root: '.', spec: '^1.0.0' }],
      },
    ]);
  });

  it('keeps the alias package.json uses, in the workspace that lists it', async () => {
    const result = await planCase({
      index: graphOf([['root:packages/ui', 'lodash@3.10.1', 'npm:lodash@3.10.1', { name: 'old-lodash' }]]),
      docs: [lodashDoc],
      vulnerable: { 'lodash@3.10.1': [lodashInjection] },
    });
    expect(result.plans[0]?.steps).toEqual([
      {
        kind: 'bump',
        package: 'lodash',
        alias: 'old-lodash',
        from: '3.10.1',
        to: '4.17.21',
        change: 'major',
        root: 'packages/ui',
        spec: 'npm:lodash@3.10.1',
      },
    ]);
  });

  it('names the pnpm catalog that holds the range', async () => {
    // pnpm-catalog: ms comes from `catalog:old` (~2.0.0), lodash from the default catalog.
    const result = await planCase({
      index: new GraphIndex(parsePnpmLock(fixture('pnpm-catalog', 'pnpm-lock.yaml'))),
      docs: [doc('ms', { '2.0.0': {}, '2.1.1': {} })],
      vulnerable: { 'ms@2.0.0': [vuln('GHSA-ms', 'ms', '0', '2.1.1')] },
    });
    expect(result.plans[0]?.steps).toEqual([
      { kind: 'bump', package: 'ms', from: '2.0.0', to: '2.1.1', change: 'minor', root: '.', spec: '~2.0.0', catalog: 'old' },
    ]);
  });
});

describe('planFixes: override', () => {
  it('names the range a parent asks for from the registry when the lockfile does not record it (pnpm)', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'a@1.0.0', '^1.0.0'],
        ['a@1.0.0', 'lodash@4.17.20'],
      ]),
      docs: [lodashDoc, doc('a', { '1.0.0': { dependencies: { lodash: '4.17.20' } } })],
      vulnerable: { 'lodash@4.17.20': [lodashInjection] },
    });
    expect(result.plans[0]?.steps).toEqual([
      { kind: 'override', package: 'lodash', from: '4.17.20', to: '4.17.21', change: 'patch', parents: [{ id: 'a@1.0.0', spec: '4.17.20' }] },
    ]);
  });

  it('overrides when no version of any parent accepts a clean one, listing every blocking parent', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'a@1.0.0', '^1.0.0'],
        [ROOT, 'b@2.0.0', '^2.0.0'],
        ['a@1.0.0', 'lodash@4.17.20', '4.17.20'],
        ['b@2.0.0', 'lodash@4.17.20', '>=4.17.0 <4.17.21'],
      ]),
      docs: [
        lodashDoc,
        doc('a', { '1.0.0': { dependencies: { lodash: '4.17.20' } }, '1.0.1': { dependencies: { lodash: '4.17.20' } } }),
        doc('b', { '2.0.0': { dependencies: { lodash: '>=4.17.0 <4.17.21' } } }),
      ],
      vulnerable: { 'lodash@4.17.20': [lodashInjection] },
    });
    expect(result.plans).toEqual([
      {
        id: 'lodash@4.17.20',
        package: 'lodash',
        version: '4.17.20',
        kind: 'override',
        target: '4.17.21',
        steps: [
          {
            kind: 'override',
            package: 'lodash',
            from: '4.17.20',
            to: '4.17.21',
            change: 'patch',
            parents: [
              { id: 'a@1.0.0', spec: '4.17.20' },
              { id: 'b@2.0.0', spec: '>=4.17.0 <4.17.21' },
            ],
          },
        ],
      },
    ]);
  });

  const postcssCase = (installed: string, fixed: string): Case => ({
    index: graphOf([
      [ROOT, 'next@15.0.0', '^15.0.0'],
      ['next@15.0.0', `postcss@${installed}`, installed],
    ]),
    docs: [
      doc('postcss', { [installed]: {}, [fixed]: {} }),
      doc('next', {
        '15.0.0': { dependencies: { postcss: installed } },
        '15.1.0': { dependencies: { postcss: installed } },
        '16.0.0': { dependencies: { postcss: `^${fixed}` } },
      }),
    ],
    vulnerable: { [`postcss@${installed}`]: [vuln('GHSA-pc', 'postcss', '0', fixed)] },
  });

  it('prefers an override to a major upgrade of another package, keeping that as the alternative', async () => {
    const result = await planCase(postcssCase('8.4.31', '8.4.32'));
    expect(result.plans[0]).toEqual({
      id: 'postcss@8.4.31',
      package: 'postcss',
      version: '8.4.31',
      kind: 'override',
      target: '8.4.32',
      steps: [
        {
          kind: 'override',
          package: 'postcss',
          from: '8.4.31',
          to: '8.4.32',
          change: 'patch',
          parents: [{ id: 'next@15.0.0', spec: '8.4.31' }],
          alternative: [{ kind: 'bump', package: 'next', from: '15.0.0', to: '16.0.0', change: 'major', root: '.', spec: '^15.0.0' }],
        },
      ],
    });
  });

  it('keeps the major upgrade of the parent when the override would be major too', async () => {
    const result = await planCase(postcssCase('7.0.39', '8.4.32'));
    expect(result.plans[0]).toMatchObject({
      kind: 'bump',
      steps: [{ kind: 'bump', package: 'next', from: '15.0.0', to: '16.0.0', change: 'major', root: '.', spec: '^15.0.0' }],
    });
  });
});

describe('planFixes: malware', () => {
  it('removes a malicious direct dependency that has no clean release', async () => {
    const result = await planCase({
      index: graphOf([[ROOT, 'evil-pkg@1.0.1', '^1.0.0']]),
      docs: [doc('evil-pkg', { '1.0.0': {}, '1.0.1': {} })],
      vulnerable: { 'evil-pkg@1.0.1': [malware('MAL-2026-1', 'evil-pkg', ['1.0.0', '1.0.1'])] },
    });
    expect(result.plans).toEqual([
      { id: 'evil-pkg@1.0.1', package: 'evil-pkg', version: '1.0.1', kind: 'remove', target: null, steps: [{ kind: 'remove', package: 'evil-pkg', from: '1.0.1', root: '.' }] },
    ]);
  });

  it('pins malware back to the highest clean release below when none above is clean', async () => {
    const result = await planCase({
      index: graphOf([[ROOT, 'debug@4.4.2', '^4.4.0']]),
      docs: [doc('debug', { '4.4.0': {}, '4.4.1': {}, '4.4.2': {} })],
      vulnerable: { 'debug@4.4.2': [malware('MAL-2025-46974', 'debug', ['4.4.2'])] },
    });
    expect(result.plans).toEqual([
      {
        id: 'debug@4.4.2',
        package: 'debug',
        version: '4.4.2',
        kind: 'bump',
        target: '4.4.1',
        steps: [{ kind: 'bump', package: 'debug', from: '4.4.2', to: '4.4.1', change: 'downgrade', root: '.', spec: '^4.4.0' }],
      },
    ]);
  });
});

describe('planFixes: no fix, bundled, unknown', () => {
  it('says there is no fix for a transitive package with no clean release that every parent version keeps', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'tool@1.0.0', '^1.0.0'],
        ['tool@1.0.0', 'leftpad@1.0.0', '^1.0.0'],
      ]),
      docs: [doc('leftpad', { '1.0.0': {}, '1.1.0': {} }), doc('tool', { '1.0.0': { dependencies: { leftpad: '^1.0.0' } }, '1.1.0': { dependencies: { leftpad: '^1.0.0' } } })],
      vulnerable: { 'leftpad@1.0.0': [vuln('GHSA-lp', 'leftpad', '0')] },
    });
    expect(result.plans).toEqual([
      { id: 'leftpad@1.0.0', package: 'leftpad', version: '1.0.0', kind: 'no-fix', target: null, steps: [{ kind: 'no-fix', package: 'leftpad', from: '1.0.0', parent: 'tool@1.0.0' }] },
    ]);
  });

  it('points a bundled package at the package that ships it, without asking the registry', async () => {
    const result = await planCase({
      index: graphOf(
        [
          [ROOT, 'npm@10.9.2', '10.9.2', { type: 'dev' }],
          ['npm@10.9.2', 'tar@6.2.1', '^6.2.1'],
        ],
        { 'tar@6.2.1': ['npm@10.9.2'] },
      ),
      docs: [],
      vulnerable: { 'tar@6.2.1': [vuln('GHSA-tar', 'tar', '0', '6.2.2')] },
    });
    expect(result.plans).toEqual([
      { id: 'tar@6.2.1', package: 'tar', version: '6.2.1', kind: 'bundled', target: null, steps: [{ kind: 'bundled', package: 'tar', from: '6.2.1', bundler: 'npm@10.9.2' }] },
    ]);
    expect(result.asked).toEqual([]);
  });

  it('gives an unknown plan and a problem when the registry lookup fails, and plans the other packages', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'ghost@1.0.0', '1.0.0'],
        [ROOT, 'lodash@4.17.20', '4.17.20'],
      ]),
      docs: [lodashDoc],
      vulnerable: { 'ghost@1.0.0': [vuln('GHSA-gh', 'ghost', '0', '1.0.1')], 'lodash@4.17.20': [lodashInjection] },
    });
    const message = 'npm registry GET ghost failed with HTTP 404: no route for GET https://registry.npmjs.org/ghost';
    expect(result.problems).toEqual([message]);
    expect(result.plans).toEqual([
      { id: 'ghost@1.0.0', package: 'ghost', version: '1.0.0', kind: 'unknown', target: null, steps: [{ kind: 'unknown', package: 'ghost', from: '1.0.0', reason: message }] },
      expect.objectContaining({ id: 'lodash@4.17.20', kind: 'bump' }),
    ]);
  });

  it('gives an unknown plan, without asking the registry, for a package nothing installs', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'axios@1.12.2', '^1.12.2'],
        ['orphan@1.0.0', 'lodash@4.17.20', '^4.17.0'],
      ]),
      docs: [lodashDoc, doc('axios', { '1.12.2': {} })],
      vulnerable: { 'orphan@1.0.0': [vuln('GHSA-or', 'orphan', '0', '1.0.1')] },
    });
    expect(result.plans).toEqual([
      {
        id: 'orphan@1.0.0',
        package: 'orphan',
        version: '1.0.0',
        kind: 'unknown',
        target: null,
        steps: [{ kind: 'unknown', package: 'orphan', from: '1.0.0', reason: 'nothing in the lockfile installs it' }],
      },
    ]);
    expect(result.asked).toEqual([]);
  });

  it('gives an unknown step when package.json does not name a registry range', async () => {
    const result = await planCase({
      index: graphOf([[ROOT, 'lib@1.0.0', 'github:demo/lib#v1.0.0']]),
      docs: [doc('lib', { '1.0.0': {}, '1.0.1': {} })],
      vulnerable: { 'lib@1.0.0': [vuln('GHSA-lib', 'lib', '0', '1.0.1')] },
    });
    expect(result.plans[0]).toMatchObject({
      kind: 'unknown',
      target: '1.0.1',
      steps: [{ kind: 'unknown', package: 'lib', from: '1.0.0', reason: 'package.json asks for "github:demo/lib#v1.0.0", which is not a version range' }],
    });
  });
});

describe('planFixes: peers and cycles', () => {
  it('adds no step for a peer range that already allows a clean version', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'host@2.0.0', '2.0.0'],
        [ROOT, 'plugin@1.0.0', '^1.0.0'],
        ['plugin@1.0.0', 'host@2.0.0', '^2.0.0', { type: 'peer' }],
      ]),
      docs: [doc('host', { '2.0.0': {}, '2.0.1': {} })],
      vulnerable: { 'host@2.0.0': [vuln('GHSA-host', 'host', '0', '2.0.1')] },
    });
    expect(result.plans[0]?.steps).toEqual([{ kind: 'bump', package: 'host', from: '2.0.0', to: '2.0.1', change: 'patch', root: '.', spec: '2.0.0' }]);
    expect(result.asked).toEqual(['host']);
  });

  // a depends on b, and b needs exactly its a as a peer: moving a moves b, which must not block a.
  const cycleDocs = [
    doc('a', { '1.0.0': { dependencies: { b: '1.0.0' } }, '1.0.1': { dependencies: { b: '1.0.1' } } }),
    doc('b', { '1.0.0': { peerDependencies: { a: '1.0.0' } }, '1.0.1': { peerDependencies: { a: '1.0.1' } } }),
  ];
  const cycleBug = { 'a@1.0.0': [vuln('GHSA-a', 'a', '0', '1.0.1')] };

  it('does not fall back to an override for a cycle through a peer', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'a@1.0.0', '1.0.0'],
        ['a@1.0.0', 'b@1.0.0', '1.0.0'],
        ['b@1.0.0', 'a@1.0.0', '1.0.0', { type: 'peer' }],
      ]),
      docs: cycleDocs,
      vulnerable: cycleBug,
    });
    // b moves with a, so it gets no step of its own.
    expect(result.plans[0]).toMatchObject({
      kind: 'bump',
      steps: [{ kind: 'bump', package: 'a', from: '1.0.0', to: '1.0.1', change: 'patch', root: '.', spec: '1.0.0' }],
    });
  });

  it('bumps both packages of a cycle that package.json lists (vitest and @vitest/ui)', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'a@1.0.0', '1.0.0', { type: 'dev' }],
        [ROOT, 'b@1.0.0', '1.0.0', { type: 'dev' }],
        ['a@1.0.0', 'b@1.0.0', '1.0.0'],
        ['b@1.0.0', 'a@1.0.0', '1.0.0', { type: 'peer' }],
      ]),
      docs: cycleDocs,
      vulnerable: cycleBug,
    });
    expect(result.plans[0]?.steps).toEqual([
      { kind: 'bump', package: 'a', from: '1.0.0', to: '1.0.1', change: 'patch', root: '.', spec: '1.0.0' },
      { kind: 'bump', package: 'b', from: '1.0.0', to: '1.0.1', change: 'patch', root: '.', spec: '1.0.0' },
    ]);
  });
});

describe('planFixes: a parent that moves keeps the old child where it can', () => {
  // a 1.0.0 pins lodash 4.17.20 and a 1.0.1 allows ^4.17.0: npm and pnpm move a to 1.0.1 and keep lodash 4.17.20.
  const aDoc = doc('a', { '1.0.0': { dependencies: { lodash: '4.17.20' } }, '1.0.1': { dependencies: { lodash: '^4.17.0' } } });

  it('refreshes the child after a parent that a refresh moves', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'a@1.0.0', '^1.0.0'],
        ['a@1.0.0', 'lodash@4.17.20', '4.17.20'],
      ]),
      docs: [lodashDoc, aDoc],
      vulnerable: { 'lodash@4.17.20': [lodashInjection] },
    });
    expect(result.plans[0]).toMatchObject({
      kind: 'refresh',
      steps: [
        { kind: 'refresh', package: 'a', from: '1.0.0', to: '1.0.1', direct: true },
        { kind: 'refresh', package: 'lodash', from: '4.17.20', to: '4.17.21', direct: false },
      ],
    });
  });

  it('refreshes the child after a parent that a bump moves', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'a@1.0.0', '1.0.0'],
        ['a@1.0.0', 'lodash@4.17.20', '4.17.20'],
      ]),
      docs: [lodashDoc, aDoc],
      vulnerable: { 'lodash@4.17.20': [lodashInjection] },
    });
    expect(result.plans[0]).toMatchObject({
      kind: 'bump',
      steps: [
        { kind: 'refresh', package: 'lodash', from: '4.17.20', to: '4.17.21', direct: false },
        { kind: 'bump', package: 'a', from: '1.0.0', to: '1.0.1', change: 'patch', root: '.', spec: '1.0.0' },
      ],
    });
  });

  // g 1.0.0 pins p 1.0.0, which pins lodash 4.17.20; p 1.1.0 allows ^4.17.0.
  const chain = graphOf([
    [ROOT, 'g@1.0.0', '1.0.0'],
    ['g@1.0.0', 'p@1.0.0', '1.0.0'],
    ['p@1.0.0', 'lodash@4.17.20', '4.17.20'],
  ]);
  const pDoc = doc('p', { '1.0.0': { dependencies: { lodash: '4.17.20' } }, '1.1.0': { dependencies: { lodash: '^4.17.0' } } });

  it('adds no refresh for a child whose parent the move takes out (vitest 4 no longer uses vite-node)', async () => {
    const result = await planCase({
      index: chain,
      docs: [lodashDoc, pDoc, doc('g', { '1.0.0': { dependencies: { p: '1.0.0' } }, '1.1.0': {} })],
      vulnerable: { 'lodash@4.17.20': [lodashInjection] },
    });
    expect(result.plans[0]?.steps).toEqual([{ kind: 'bump', package: 'g', from: '1.0.0', to: '1.1.0', change: 'minor', root: '.', spec: '1.0.0' }]);
  });

  it('refreshes every level that the new range above it still allows', async () => {
    const result = await planCase({
      index: chain,
      docs: [lodashDoc, pDoc, doc('g', { '1.0.0': { dependencies: { p: '1.0.0' } }, '1.1.0': { dependencies: { p: '^1.0.0' } } })],
      vulnerable: { 'lodash@4.17.20': [lodashInjection] },
    });
    expect(result.plans[0]?.steps).toEqual([
      { kind: 'refresh', package: 'p', from: '1.0.0', to: '1.1.0', direct: false },
      // lodash can move only once p has: a round later.
      { kind: 'refresh', package: 'lodash', from: '4.17.20', to: '4.17.21', direct: false, round: 1 },
      { kind: 'bump', package: 'g', from: '1.0.0', to: '1.1.0', change: 'minor', root: '.', spec: '1.0.0' },
    ]);
  });

  it('refreshes a listed child a round after the transitive parent it waits for', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'lodash@4.17.20', '^4.17.0'],
        [ROOT, 'q@1.0.0', '^1.0.0'],
        ['q@1.0.0', 'a@1.0.0', '^1.0.0'],
        ['a@1.0.0', 'lodash@4.17.20', '4.17.20'],
      ]),
      docs: [lodashDoc, aDoc],
      vulnerable: { 'lodash@4.17.20': [lodashInjection] },
    });
    // The root's range alone would give a round-0 refresh of lodash; the copy under a has to wait for a.
    expect(result.plans[0]?.steps).toEqual([
      { kind: 'refresh', package: 'lodash', from: '4.17.20', to: '4.17.21', direct: true, round: 1 },
      { kind: 'refresh', package: 'a', from: '1.0.0', to: '1.0.1', direct: false },
    ]);
  });

  it('keeps the refresh of an aliased copy when the package itself is bumped (npm keeps the alias)', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'string-width@4.2.0', '4.2.0'],
        [ROOT, '@isaacs/cliui@8.0.2', '^8.0.2'],
        ['@isaacs/cliui@8.0.2', 'string-width@4.2.0', 'npm:string-width@^4.2.0', { name: 'string-width-cjs' }],
      ]),
      docs: [doc('string-width', { '4.2.0': {}, '4.2.3': {} })],
      vulnerable: { 'string-width@4.2.0': [vuln('GHSA-sw', 'string-width', '0', '4.2.3')] },
    });
    expect(result.plans[0]?.steps).toEqual([
      { kind: 'refresh', package: 'string-width', alias: 'string-width-cjs', from: '4.2.0', to: '4.2.3', direct: true },
      { kind: 'bump', package: 'string-width', from: '4.2.0', to: '4.2.3', change: 'patch', root: '.', spec: '4.2.0' },
    ]);
  });

  it("does not walk an ancestor onto a version that the ancestor's own advisory affects", async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'x@1.0.0', '1.0.0'],
        ['x@1.0.0', 'y@1.0.0', '1.0.0'],
      ]),
      docs: [
        doc('y', { '1.0.0': {}, '2.0.0': {} }),
        doc('x', {
          '1.0.0': { dependencies: { y: '1.0.0' } },
          '1.0.1': { dependencies: { y: '1.0.0' } },
          '2.0.0': { dependencies: { y: '^2.0.0' } },
          '2.0.1': { dependencies: { y: '^2.0.0' } },
        }),
      ],
      vulnerable: {
        'x@1.0.0': [
          {
            id: 'GHSA-x',
            modified: '2026-11-01T00:00:00Z',
            database_specific: { severity: 'HIGH' },
            affected: [
              {
                package: npm('x'),
                ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.1' }, { introduced: '2.0.0' }, { fixed: '2.0.1' }] }],
              },
            ],
          },
        ],
        'y@1.0.0': [vuln('GHSA-y', 'y', '0', '2.0.0')],
      },
    });
    // x 2.0.0 is the first to take y 2, but GHSA-x affects it, so both plans land on 2.0.1.
    const x = { kind: 'bump', package: 'x', from: '1.0.0', to: '2.0.1', change: 'major', root: '.', spec: '1.0.0' };
    expect(result.plans.map((plan) => [plan.id, plan.steps])).toEqual([
      ['x@1.0.0', [x]],
      ['y@1.0.0', [x]],
    ]);
  });

  it('keeps walking to a major bump that another plan already needs, rather than overriding', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'p@1.0.0', '1.0.0'],
        ['p@1.0.0', 'c@1.0.0', '1.0.0'],
      ]),
      docs: [
        doc('c', { '1.0.0': {}, '1.0.1': {} }),
        doc('p', { '1.0.0': { dependencies: { c: '1.0.0' } }, '1.1.0': { dependencies: { c: '^1.0.1' } }, '2.0.0': { dependencies: { c: '^1.0.1' } } }),
      ],
      vulnerable: { 'p@1.0.0': [vuln('GHSA-p', 'p', '0', '2.0.0')], 'c@1.0.0': [vuln('GHSA-c', 'c', '0', '1.0.1')] },
    });
    const p2 = { kind: 'bump', package: 'p', from: '1.0.0', to: '2.0.0', change: 'major', root: '.', spec: '1.0.0' };
    expect(result.plans.map((plan) => [plan.id, plan.steps])).toEqual([
      ['p@1.0.0', [p2]],
      ['c@1.0.0', [p2]],
    ]);
  });

  it('decides the refreshes after a bump at the highest version any plan bumps it to', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'g@1.0.0', '1.0.0'],
        ['g@1.0.0', 'p@1.0.0', '1.0.0'],
        ['g@1.0.0', 'ms@2.0.0', '2.0.0'],
        ['p@1.0.0', 'lodash@4.17.20', '4.17.20'],
      ]),
      docs: [
        lodashDoc,
        pDoc,
        doc('ms', { '2.0.0': {}, '2.1.1': {} }),
        doc('g', {
          '1.0.0': { dependencies: { p: '1.0.0', ms: '2.0.0' } },
          '1.1.0': { dependencies: { p: '^1.0.0', ms: '2.0.0' } },
          '1.2.0': { dependencies: { ms: '^2.1.1' } },
        }),
      ],
      vulnerable: { 'lodash@4.17.20': [lodashInjection], 'ms@2.0.0': [vuln('GHSA-ms', 'ms', '0', '2.1.1')] },
    });
    // On its own, lodash would need g 1.1.0, which keeps p 1.0.0 and so needs p and lodash refreshed.
    // ms needs g 1.2.0, which drops p, so the lodash plan is made again for g 1.2.0 and needs nothing more.
    const g = { kind: 'bump', package: 'g', from: '1.0.0', to: '1.2.0', change: 'minor', root: '.', spec: '1.0.0' };
    expect(result.plans.map((plan) => [plan.id, plan.steps])).toEqual([
      ['ms@2.0.0', [g]],
      ['lodash@4.17.20', [g]],
    ]);
  });

  it('lists a package that only peer ranges point at once the parent with the blocking range moves', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'plugin-a@1.0.0', '^1.0.0'],
        [ROOT, 'plugin-b@1.0.0', '1.0.0'],
        ['plugin-a@1.0.0', 'host@2.0.0', '^2.0.0', { type: 'peer' }],
        ['plugin-b@1.0.0', 'host@2.0.0', '~2.0.0', { type: 'peer' }],
      ]),
      docs: [
        doc('host', { '2.0.0': {}, '2.1.0': {}, '2.2.0': {} }),
        doc('plugin-b', { '1.0.0': { peerDependencies: { host: '~2.0.0' } }, '1.1.0': { peerDependencies: { host: '>=2.0.0 <2.2.0' } } }),
      ],
      vulnerable: { 'host@2.0.0': [vuln('GHSA-host', 'host', '0', '2.1.0')] },
    });
    // plugin-b 1.1.0 allows host up to 2.1.x, so host goes to 2.1.0, not 2.2.0.
    expect(result.plans[0]?.steps).toEqual([
      { kind: 'bump', package: 'plugin-b', from: '1.0.0', to: '1.1.0', change: 'minor', root: '.', spec: '1.0.0' },
      { kind: 'bump', package: 'host', from: '2.0.0', to: '2.1.0', change: 'minor', root: '.', spec: '', add: 'dependencies' },
    ]);
  });

  it('refreshes an aliased copy by the name its parent uses, which is the one npm updates', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, '@isaacs/cliui@8.0.2', '^8.0.2'],
        ['@isaacs/cliui@8.0.2', 'string-width@4.2.0', 'npm:string-width@^4.2.0', { name: 'string-width-cjs' }],
      ]),
      docs: [doc('string-width', { '4.2.0': {}, '4.2.3': {} })],
      vulnerable: { 'string-width@4.2.0': [vuln('GHSA-sw', 'string-width', '0', '4.2.3')] },
    });
    expect(result.plans[0]?.steps).toEqual([
      { kind: 'refresh', package: 'string-width', alias: 'string-width-cjs', from: '4.2.0', to: '4.2.3', direct: false },
    ]);
  });
});

describe('planFixes: yarn', () => {
  it('keeps the refresh of the other ranges after a bump, since yarn locks each range apart', async () => {
    const result = await planCase({
      index: graphOf(
        [
          [ROOT, 'lodash@4.17.20', '4.17.20'],
          [ROOT, 'async@3.2.6', '^3.2.0'],
          ['async@3.2.6', 'lodash@4.17.20', '^4.17.14'],
        ],
        {},
        'yarn-classic',
      ),
      docs: [lodashDoc],
      vulnerable: { 'lodash@4.17.20': [lodashInjection] },
    });
    expect(result.plans[0]?.steps).toEqual([
      { kind: 'refresh', package: 'lodash', from: '4.17.20', to: '4.17.21', direct: true },
      { kind: 'bump', package: 'lodash', from: '4.17.20', to: '4.17.21', change: 'patch', root: '.', spec: '4.17.20' },
    ]);
  });

  const aDoc = doc('a', { '1.0.0': { dependencies: { lodash: '4.17.20' } }, '1.0.1': { dependencies: { lodash: '^4.17.0' } } });

  it('needs no refresh after a parent moves when yarn has not locked the range it moves to', async () => {
    const result = await planCase({
      index: graphOf(
        [
          [ROOT, 'a@1.0.0', '^1.0.0'],
          ['a@1.0.0', 'lodash@4.17.20', '4.17.20'],
        ],
        {},
        'yarn-berry',
      ),
      docs: [lodashDoc, aDoc],
      vulnerable: { 'lodash@4.17.20': [lodashInjection] },
    });
    expect(result.plans[0]?.steps).toEqual([{ kind: 'refresh', package: 'a', from: '1.0.0', to: '1.0.1', direct: true }]);
  });

  it('refreshes the child too when another parent already locked that range at the old version', async () => {
    const result = await planCase({
      index: graphOf(
        [
          [ROOT, 'a@1.0.0', '^1.0.0'],
          [ROOT, 'b@1.0.0', '^1.0.0'],
          ['a@1.0.0', 'lodash@4.17.20', '4.17.20'],
          ['b@1.0.0', 'lodash@4.17.20', '^4.17.0'],
        ],
        {},
        'yarn-berry',
      ),
      docs: [lodashDoc, aDoc],
      vulnerable: { 'lodash@4.17.20': [lodashInjection] },
    });
    expect(result.plans[0]?.steps).toEqual([
      { kind: 'refresh', package: 'a', from: '1.0.0', to: '1.0.1', direct: true },
      { kind: 'refresh', package: 'lodash', from: '4.17.20', to: '4.17.21', direct: false, round: 1 },
    ]);
  });
});

describe('planFixes: parents the registry cannot show', () => {
  it('overrides past a parent the registry refuses (a private package), and plans the other parents', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, '@corp/lib@1.0.0', '^1.0.0'],
        [ROOT, 'async@3.2.6', '^3.2.0'],
        ['@corp/lib@1.0.0', 'lodash@4.17.20', '4.17.20'],
        ['async@3.2.6', 'lodash@4.17.20', '^4.17.14'],
      ]),
      docs: [lodashDoc],
      vulnerable: { 'lodash@4.17.20': [lodashInjection] },
    });
    expect(result.problems).toEqual([]);
    expect(result.plans[0]).toMatchObject({
      kind: 'override',
      steps: [{ kind: 'override', package: 'lodash', from: '4.17.20', to: '4.17.21', parents: [{ id: '@corp/lib@1.0.0', spec: '4.17.20' }] }],
    });
  });

  it('never asks the registry about a folder dependency', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'shared@file:shared', 'file:shared'],
        ['shared@file:shared', 'lodash@4.17.20', '4.17.20'],
      ]),
      docs: [lodashDoc],
      vulnerable: { 'lodash@4.17.20': [lodashInjection] },
    });
    expect(result.plans[0]).toMatchObject({ kind: 'override', steps: [{ kind: 'override', parents: [{ id: 'shared@file:shared', spec: '4.17.20' }] }] });
    expect(result.asked).toEqual(['lodash']);
  });
});

describe('planFixes: an override of a package that package.json also lists', () => {
  it('names the direct listings, which npm needs moved along with the override', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'lodash@4.17.20', '4.17.20'],
        [ROOT, 'a@1.0.0', '^1.0.0'],
        ['a@1.0.0', 'lodash@4.17.20', '4.17.20'],
      ]),
      docs: [lodashDoc, doc('a', { '1.0.0': { dependencies: { lodash: '4.17.20' } } })],
      vulnerable: { 'lodash@4.17.20': [lodashInjection] },
    });
    expect(result.plans[0]?.steps).toEqual([
      {
        kind: 'override',
        package: 'lodash',
        from: '4.17.20',
        to: '4.17.21',
        change: 'patch',
        parents: [{ id: 'a@1.0.0', spec: '4.17.20' }],
        direct: [{ root: '.', spec: '4.17.20' }],
      },
    ]);
  });
});

describe('brokenPeers', () => {
  it('lists peer edges whose installed version breaks the declared range, sorted by parent', () => {
    const index = graphOf([
      [ROOT, 'react@17.0.2', '17.0.2'],
      [ROOT, 'react-dom@19.1.0-canary-1', '19.1.0-canary-1'],
      ['z-plugin@1.0.0', 'react@17.0.2', '^18.0.0', { type: 'peer' }],
      ['a-plugin@1.0.0', 'react@17.0.2', '^18.0.0 || ^19.0.0', { type: 'peerOptional' }],
      ['old-plugin@1.0.0', 'react@17.0.2', '^17.0.0', { type: 'peer' }],
      ['meta-only@1.0.0', 'react@17.0.2', undefined, { type: 'peerOptional' }],
      ['plain@1.0.0', 'react@17.0.2', '^18.0.0'],
      // A prerelease counts as in range.
      ['next@15.2.2', 'react-dom@19.1.0-canary-1', '^19.0.0', { type: 'peer' }],
    ]);
    expect(brokenPeers(index)).toEqual([
      { parent: 'a-plugin@1.0.0', name: 'react', spec: '^18.0.0 || ^19.0.0', installed: '17.0.2' },
      { parent: 'z-plugin@1.0.0', name: 'react', spec: '^18.0.0', installed: '17.0.2' },
    ]);
  });

  it('comes back from planFixes', async () => {
    const result = await planCase({
      index: graphOf([
        [ROOT, 'lodash@4.17.20', '4.17.20'],
        ['plugin@1.0.0', 'lodash@4.17.20', '^3.0.0', { type: 'peer' }],
      ]),
      docs: [lodashDoc],
      vulnerable: { 'lodash@4.17.20': [lodashInjection] },
    });
    expect(result.brokenPeers).toEqual([{ parent: 'plugin@1.0.0', name: 'lodash', spec: '^3.0.0', installed: '4.17.20' }]);
  });
});
