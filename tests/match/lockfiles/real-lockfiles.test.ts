import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { DepGraph } from '../../../src/match/graph.js';
import { GraphIndex } from '../../../src/match/graph.js';
import { parsePackageLock } from '../../../src/match/lockfiles/package-lock.js';
import { parsePnpmLock } from '../../../src/match/lockfiles/pnpm-lock.js';

// Real lockfiles that npm 11 and pnpm 11 wrote for the same package.json (kept next to each for
// the Next.js apps), with the same release cutoff (npm --before, pnpm minimumReleaseAge), so both
// resolved the same versions. next-app has npm itself as a devDependency; next-babel has
// @babel/core, sass and @playwright/test as devDependencies, which next can also use as optional
// peers. lib-monorepo has one workspace, packages/ui, with react as a peer and a devDependency.
const read = (path: string) => readFileSync(new URL(`../../fixtures/${path}`, import.meta.url), 'utf8');

const ids = (index: GraphIndex, keep: (id: string) => boolean = () => true) =>
  index
    .packages()
    .map((p) => p.id)
    .filter(keep)
    .sort();

interface NpmEntry {
  name?: string;
  version?: string;
  link?: boolean;
  dev?: boolean;
  devOptional?: boolean;
  inBundle?: boolean;
}

/** Each installed copy in an npm lockfile, as [name@version, entry]. */
function npmCopies(text: string): [string, NpmEntry][] {
  const packages = (JSON.parse(text) as { packages: Record<string, NpmEntry> }).packages;
  return Object.entries(packages)
    .filter(([location, entry]) => location.includes('node_modules/') && !entry.link)
    .map(([location, entry]) => {
      const name = entry.name ?? location.slice(location.lastIndexOf('node_modules/') + 'node_modules/'.length);
      return [`${name}@${entry.version}`, entry];
    });
}

type NpmFlag = 'dev' | 'devOptional' | 'prod';

/** npm's own verdict per name@version: the least dev-like flag of any copy. */
function npmFlags(text: string): Map<string, NpmFlag> {
  const rank: Record<NpmFlag, number> = { dev: 0, devOptional: 1, prod: 2 };
  const flags = new Map<string, NpmFlag>();
  for (const [id, entry] of npmCopies(text)) {
    const flag: NpmFlag = entry.dev ? 'dev' : entry.devOptional ? 'devOptional' : 'prod';
    const seen = flags.get(id);
    if (!seen || rank[flag] > rank[seen]) flags.set(id, flag);
  }
  return flags;
}

/** Packages that npm installs only inside another package's bundle. */
function bundledOnly(text: string): Set<string> {
  const copies = npmCopies(text);
  const unbundled = new Set(copies.filter(([, entry]) => !entry.inBundle).map(([id]) => id));
  return new Set(copies.map(([id]) => id).filter((id) => !unbundled.has(id)));
}

const LOCKFILES: [string, (text: string) => DepGraph][] = [
  ['next-app-npm/package-lock.json', parsePackageLock],
  ['next-app-pnpm/pnpm-lock.yaml', parsePnpmLock],
  ['next-babel-npm/package-lock.json', parsePackageLock],
  ['next-babel-pnpm/pnpm-lock.yaml', parsePnpmLock],
  ['lib-monorepo-npm/package-lock.json', parsePackageLock],
  ['lib-monorepo-pnpm/pnpm-lock.yaml', parsePnpmLock],
];

describe.each(LOCKFILES)('%s', (path, parse) => {
  const graph = parse(read(path));
  const index = new GraphIndex(graph);

  it('reaches every package from a root', () => {
    expect(index.packages().filter((p) => index.pathsTo(p.id, 1).length === 0).map((p) => p.id)).toEqual([]);
  });

  it('has a node at both ends of every edge', () => {
    expect(graph.edges.filter((e) => !graph.nodes.has(e.from) || !graph.nodes.has(e.to))).toEqual([]);
  });
});

describe.each([
  ['next-app-npm', []],
  ['lib-monorepo-npm', []],
  [
    'next-babel-npm',
    [
      '@playwright/test@1.50.0',
      'chokidar@4.0.3',
      'immutable@5.2.1',
      'playwright-core@1.50.0',
      'playwright@1.50.0',
      'readdirp@4.1.2',
      'sass@1.83.0',
    ],
  ],
])("dev-only on %s matches npm's own flags", (dir, devOptional) => {
  const text = read(`${dir}/package-lock.json`);
  const index = new GraphIndex(parsePackageLock(text));
  const flags = npmFlags(text);
  const flagged = (flag: NpmFlag) => [...flags].filter(([, f]) => f === flag).map(([id]) => id).sort();

  it('calls exactly the packages npm flags dev: true dev-only', () => {
    expect(ids(index, (id) => index.isDevOnly(id) && flags.get(id) !== 'devOptional')).toEqual(flagged('dev'));
  });

  it('calls devOptional packages dev-only', () => {
    // npm flags `devOptional` a devDependency that a production package can also use as an
    // optional peer (sass for next, and what sass needs). Only the devDependency installs it, so
    // it is dev-only here, though `npm ci --omit=dev` alone would still install it.
    expect(flagged('devOptional')).toEqual(devOptional);
    expect(devOptional.filter((id) => !index.isDevOnly(id))).toEqual([]);
  });
});

describe.each([
  ['a Next.js app with npm as a devDependency', 'next-app'],
  ['a Next.js app with @babel/core, sass and @playwright/test as devDependencies', 'next-babel'],
  ['a library workspace with react as both a peer and a devDependency', 'lib-monorepo'],
])('npm and pnpm agree on %s', (_, app) => {
  const npmText = read(`${app}-npm/package-lock.json`);
  const npm = new GraphIndex(parsePackageLock(npmText));
  const pnpm = new GraphIndex(parsePnpmLock(read(`${app}-pnpm/pnpm-lock.yaml`)));
  // pnpm does not list what a package bundles (parsePnpmLock warns about it), npm does.
  const bundled = bundledOnly(npmText);
  const listed = (id: string) => !bundled.has(id);

  it('finds the same packages, apart from bundled ones', () => {
    expect(ids(npm, listed)).toEqual(ids(pnpm));
  });

  it('finds the same dev-only packages', () => {
    expect(ids(npm, (id) => listed(id) && npm.isDevOnly(id))).toEqual(ids(pnpm, (id) => pnpm.isDevOnly(id)));
  });

  it('finds the same direct dependencies', () => {
    expect(ids(npm, (id) => npm.isDirect(id))).toEqual(ids(pnpm, (id) => pnpm.isDirect(id)));
  });
});

describe('the Next.js app with optional peers provided by devDependencies', () => {
  it('keeps @babel/core and sass dev-only under both parsers', () => {
    const npm = new GraphIndex(parsePackageLock(read('next-babel-npm/package-lock.json')));
    const pnpm = new GraphIndex(parsePnpmLock(read('next-babel-pnpm/pnpm-lock.yaml')));
    for (const index of [npm, pnpm]) {
      expect(index.isDevOnly('@babel/core@7.26.0')).toBe(true);
      expect(index.isDevOnly('sass@1.83.0')).toBe(true);
      expect(index.isDevOnly('next@15.2.2')).toBe(false);
      expect(ids(index, (id) => id.startsWith('@babel/') && !index.isDevOnly(id))).toEqual([]);
    }
  });
});
