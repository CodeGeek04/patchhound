import { posix } from 'node:path';
import { parseAllDocuments } from 'yaml';
import type { DepGraph, DepType, Edge, PkgNode } from '../graph.js';
import { dedupeEdges, pkgId, rootId } from '../graph.js';

interface ImporterDep {
  specifier: string;
  version: string;
}

interface Importer {
  dependencies?: Record<string, ImporterDep>;
  devDependencies?: Record<string, ImporterDep>;
  optionalDependencies?: Record<string, ImporterDep>;
  /** Only in pnpm 11's first document, which locks what pnpm itself runs. */
  configDependencies?: Record<string, ImporterDep>;
  packageManagerDependencies?: Record<string, ImporterDep>;
}

interface Snapshot {
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

interface PackageInfo {
  /** Set for git and tarball packages, whose key holds a URL instead of a version. */
  version?: string;
  /** Names only; pnpm does not lock what a package ships in its own node_modules. */
  bundledDependencies?: string[] | boolean;
  peerDependencies?: Record<string, string>;
  peerDependenciesMeta?: Record<string, { optional?: boolean }>;
}

interface PnpmLock {
  lockfileVersion?: string | number;
  /** Named version ranges that `catalog:` specifiers point at (pnpm-workspace.yaml `catalog` and `catalogs`). */
  catalogs?: Record<string, Record<string, { specifier: string; version: string }>>;
  importers?: Record<string, Importer>;
  packages?: Record<string, PackageInfo>;
  snapshots?: Record<string, Snapshot>;
}

/** Parses pnpm-lock.yaml (lockfile format 9, written by pnpm 9 and later) into a dependency graph. */
export function parsePnpmLock(text: string): DepGraph {
  const [lock, ...skipped] = readDocuments(text);
  if (Number.parseInt(String(lock.lockfileVersion), 10) !== 9) {
    throw new Error(`pnpm lockfile version ${String(lock.lockfileVersion)} is not supported. Use pnpm 9 or later.`);
  }
  const nodes = new Map<string, PkgNode>();
  const roots: string[] = [];
  const edges: Edge[] = [];

  // A semver filter later would drop a URL, so use the version the package entry records.
  const versionOf = (name: string, ref: string): string =>
    ref.includes(':') ? (lock.packages?.[pkgId(name, ref)]?.version ?? ref) : ref;
  const addNode = (name: string, ref: string): string => {
    const version = versionOf(name, ref);
    const id = pkgId(name, version);
    if (!nodes.has(id)) nodes.set(id, { id, name, version });
    return id;
  };

  const importers = lock.importers ?? {};
  // A link to another importer is a workspace dependency. A link anywhere else is a folder that
  // pnpm does not lock; keep it as a package whose `link:` version no advisory range matches.
  const linkTo = (name: string, importer: string, ref: string): string => {
    const target = posix.normalize(posix.join(importer, ref.slice('link:'.length)));
    return Object.hasOwn(importers, target) ? rootId(target) : addNode(name, `link:${target}`);
  };
  for (const path of Object.keys(importers)) {
    const id = rootId(path);
    roots.push(id);
    nodes.set(id, { id, name: path, version: '' });
  }

  for (const [path, importer] of Object.entries(importers)) {
    const from = rootId(path);
    const sections: [Record<string, ImporterDep> | undefined, DepType][] = [
      [importer.dependencies, 'prod'],
      [importer.devDependencies, 'dev'],
      [importer.optionalDependencies, 'optional'],
    ];
    for (const [deps, type] of sections) {
      for (const [name, dep] of Object.entries(deps ?? {})) {
        const to = dep.version.startsWith('link:')
          ? linkTo(name, path, dep.version)
          : addNode(...refToPackage(name, dep.version));
        // `catalog:` and `catalog:<name>` point at a range in pnpm-workspace.yaml, which the lockfile copies.
        const catalog = dep.specifier.startsWith('catalog:') ? dep.specifier.slice('catalog:'.length) || 'default' : undefined;
        const spec = catalog === undefined ? dep.specifier : (lock.catalogs?.[catalog]?.[name]?.specifier ?? dep.specifier);
        edges.push(catalog === undefined ? { from, to, name, spec, type } : { from, to, name, spec, catalog, type });
      }
    }
  }

  for (const [key, snapshot] of Object.entries(lock.snapshots ?? {})) {
    const from = addNode(...splitKey(key));
    const info = lock.packages?.[stripPeers(key)] ?? {};
    const sections: [Record<string, string> | undefined, 'prod' | 'optional'][] = [
      [snapshot.dependencies, 'prod'],
      [snapshot.optionalDependencies, 'optional'],
    ];
    for (const [deps, type] of sections) {
      for (const [name, ref] of Object.entries(deps ?? {})) {
        if (ref.startsWith('link:')) continue;
        // Snapshots record only resolved versions, so `spec` is unknown here, except for a peer:
        // the package entry keeps its declared peer ranges.
        const to = addNode(...refToPackage(name, ref));
        const edgeKind = edgeType(info, name, type);
        const peerSpec = edgeKind === 'peer' || edgeKind === 'peerOptional' ? info.peerDependencies?.[name] : undefined;
        edges.push(peerSpec === undefined ? { from, to, name, type: edgeKind } : { from, to, name, spec: peerSpec, type: edgeKind });
      }
    }
  }
  const bundles: [string, number | 'all'][] = [];
  for (const [key, info] of Object.entries(lock.packages ?? {})) {
    const bundled = info.bundledDependencies;
    if (!bundled || (Array.isArray(bundled) && bundled.length === 0)) continue;
    const [name, ref] = splitKey(key);
    bundles.push([pkgId(name, versionOf(name, ref)), Array.isArray(bundled) ? bundled.length : 'all']);
  }
  const warnings = [...skippedWarnings(skipped), ...bundleWarnings(bundles)];
  return { manager: 'pnpm', roots, nodes, edges: dedupeEdges(edges), warnings };
}

/** Names what the skipped documents lock: pnpm's config dependencies and pnpm itself. */
function skippedWarnings(skipped: PnpmLock[]): string[] {
  const names: string[] = [];
  let total = 0;
  for (const doc of skipped) {
    total += Object.keys(doc.packages ?? {}).length;
    for (const importer of Object.values(doc.importers ?? {})) {
      for (const deps of [importer.configDependencies, importer.packageManagerDependencies]) {
        for (const [name, dep] of Object.entries(deps ?? {})) names.push(pkgId(name, stripPeers(dep.version)));
      }
    }
  }
  if (names.length === 0) return [];
  const rest = total > names.length ? ` (${total} packages with their dependencies)` : '';
  return [
    'pnpm-lock.yaml also locks packages that pnpm itself runs when it installs (config dependencies and the ' +
      `package manager), and those were not checked: ${names.sort().join(', ')}${rest}`,
  ];
}

/**
 * One warning that names each package with bundled dependencies, the largest bundles first.
 * pnpm records only the top-level bundled names, and what those depend on is bundled too.
 */
function bundleWarnings(bundles: [string, number | 'all'][]): string[] {
  if (bundles.length === 0) return [];
  const size = (count: number | 'all') => (count === 'all' ? Infinity : count);
  const describe = (count: number | 'all') =>
    count === 'all' ? 'all its dependencies' : `${count} top-level name${count === 1 ? '' : 's'}`;
  const list = bundles
    .sort(([a, x], [b, y]) => size(y) - size(x) || a.localeCompare(b))
    .map(([id, count]) => `${id} (${describe(count)})`)
    .join(', ');
  const subject = bundles.length === 1 ? '1 package bundles' : `${bundles.length} packages bundle`;
  return [
    `${subject} dependencies that pnpm-lock.yaml does not list, so they were not checked, and neither ` +
      `were their own dependencies: ${list}`,
  ];
}

/**
 * Snapshots list resolved peers among their dependencies, so only the package entry tells a
 * peer from a plain dependency. pnpm 11 puts a resolved optional peer under
 * `optionalDependencies`; under `dependencies` the name was installed as a plain dependency,
 * and calling it an optional peer there could make a runtime package look dev-only.
 */
function edgeType(info: PackageInfo, name: string, section: 'prod' | 'optional'): DepType {
  const optionalPeer = info.peerDependenciesMeta?.[name]?.optional === true;
  if (optionalPeer) return section === 'optional' ? 'peerOptional' : section;
  return Object.hasOwn(info.peerDependencies ?? {}, name) ? 'peer' : section;
}

/**
 * Returns the project lockfile first, then the other documents. pnpm 11 puts its own config and
 * package manager dependencies in a first YAML document when a repo has `configDependencies` or
 * `devEngines.packageManager`. That document has `importers` too, and pnpm itself reads the
 * project lockfile from the last one.
 */
function readDocuments(text: string): [PnpmLock, ...PnpmLock[]] {
  const docs = parseAllDocuments(text);
  docs.forEach((doc, i) => {
    const [error] = doc.errors;
    if (error) throw new Error(`pnpm-lock.yaml is not valid YAML (document ${i + 1}): ${error.message}`);
  });
  const locks = docs.map((doc) => (doc.toJS() ?? {}) as PnpmLock).reverse();
  const project = locks.find((lock) => lock.importers !== undefined) ?? locks[0] ?? {};
  return [project, ...locks.filter((lock) => lock !== project)];
}

/**
 * `4.17.20` and `15.2.2(react@19.0.0)` are versions of the requested package, and so are URLs
 * and `file:` refs. `string-width@4.2.3`, `7zip-bin@5.2.0` and `is-number@https://...` are
 * aliases: a version never contains `@`, so an `@` after the first character that no `:` comes
 * before (as in `https://user@host`) separates another package's name from its version.
 */
function refToPackage(requested: string, ref: string): [string, string] {
  const base = stripPeers(ref);
  const at = base.indexOf('@', 1);
  if (at === -1 || base.slice(0, at).includes(':')) return [requested, base];
  return splitKey(base);
}

/** `@next/env@15.2.2` → [`@next/env`, `15.2.2`]; peer suffixes in parentheses are dropped. */
function splitKey(key: string): [string, string] {
  const base = stripPeers(key);
  const at = base.indexOf('@', 1);
  return [base.slice(0, at), base.slice(at + 1)];
}

function stripPeers(ref: string): string {
  const paren = ref.indexOf('(');
  return paren === -1 ? ref : ref.slice(0, paren);
}
