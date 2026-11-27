import { posix } from 'node:path';
import type { DepGraph, DepType, Edge, PkgNode } from '../graph.js';
import { dedupeEdges, pkgId, rootId } from '../graph.js';

interface LockEntry {
  name?: string;
  version?: string;
  resolved?: string;
  link?: boolean;
  /** Shipped inside another package's tarball (its `bundleDependencies`), not installed from the registry. */
  inBundle?: boolean;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  peerDependenciesMeta?: Record<string, { optional?: boolean }>;
}

interface PackageLock {
  lockfileVersion?: number;
  packages?: Record<string, LockEntry>;
}

const NM = 'node_modules/';

/** Parses package-lock.json or npm-shrinkwrap.json (lockfile v2 or v3) into a dependency graph. */
export function parsePackageLock(text: string): DepGraph {
  const lock = JSON.parse(text) as PackageLock;
  if (!lock.packages || (lock.lockfileVersion ?? 1) < 2) {
    throw new Error('package-lock.json v1 is not supported. Regenerate it with npm 7 or later.');
  }
  const entries = lock.packages;
  const nodes = new Map<string, PkgNode>();
  const roots: string[] = [];
  const idAt = new Map<string, string>();

  const linked = fileTargets(entries);
  // node id -> locations of the packages that bundle a copy of it; ids with a copy that is not bundled
  const bundlers = new Map<string, Set<string>>();
  const unbundled = new Set<string>();
  for (const [location, entry] of Object.entries(entries)) {
    if (entry.link) continue;
    // npm writes `name` only when it differs from the folder name: for aliases
    // ("old-lodash": "npm:lodash@3.10.1") and for folders like "packages/ui" named "@demo/ui".
    const installed = inNodeModules(location);
    // Outside node_modules npm records the project, its workspaces, and the folders that file:
    // dependencies point at. The specs name the last group, so every other folder is a workspace,
    // whatever glob syntax the workspaces field uses.
    if (location === '' || (!installed && !linked.has(location))) {
      const path = location === '' ? '.' : location;
      const id = rootId(path);
      roots.push(id);
      nodes.set(id, { id, name: entry.name ?? posix.basename(path), version: entry.version ?? '' });
      idAt.set(location, id);
      continue;
    }
    const name = entry.name ?? (installed ? location.slice(location.lastIndexOf(NM) + NM.length) : posix.basename(location));
    // A file: target has no registry version, so `file:<location>` keeps it apart from the
    // registry package of the same name.
    const version = installed ? (entry.version ?? '') : `file:${location}`;
    const id = pkgId(name, version);
    if (!nodes.has(id)) nodes.set(id, { id, name, version });
    idAt.set(location, id);
    const bundler = entry.inBundle ? bundlerOf(location, entries) : undefined;
    if (bundler) (bundlers.get(id) ?? bundlers.set(id, new Set()).get(id)!).add(bundler);
    else unbundled.add(id);
  }
  for (const [id, places] of bundlers) {
    if (unbundled.has(id)) continue;
    // The project or a workspace that bundles its own dependencies changes them like any other.
    const shippers = [...places].map((place) => idAt.get(place)).filter((by): by is string => by !== undefined && !roots.includes(by));
    if (shippers.length > 0) nodes.get(id)!.bundledBy = [...new Set(shippers)].sort();
  }

  // Node's lookup: the package's own node_modules first, then each parent directory's.
  const resolve = (from: string, depName: string): string | undefined => {
    const parts = from === '' ? [] : from.split('/');
    for (let i = parts.length; i >= 0; i--) {
      const prefix = parts.slice(0, i).join('/');
      const candidate = `${prefix === '' ? '' : `${prefix}/`}${NM}${depName}`;
      const entry = entries[candidate];
      if (!entry) continue;
      return entry.link ? idAt.get(entry.resolved ?? '') : idAt.get(candidate);
    }
    return undefined;
  };

  const edges: Edge[] = [];
  for (const [location, entry] of Object.entries(entries)) {
    const from = idAt.get(location);
    if (entry.link || !from) continue;
    const [peers, optionalPeers] = splitPeers(entry);
    // The first section that lists a name decides the edge type (dedupeEdges keeps the first).
    // npm installs devDependencies only for the project, its workspaces and linked folders. A
    // devDependency beats a peer of the same name, as in npm: a library workspace that lists
    // react as both installs it only for its own development.
    const sections: [Record<string, string | undefined> | undefined, DepType][] = [
      [entry.dependencies, 'prod'],
      [entry.optionalDependencies, 'optional'],
      [inNodeModules(location) ? undefined : entry.devDependencies, 'dev'],
      [peers, 'peer'],
      [optionalPeers, 'peerOptional'],
    ];
    for (const [deps, type] of sections) {
      for (const [name, spec] of Object.entries(deps ?? {})) {
        const to = resolve(location, name);
        // An optional or peer dependency that was not installed has no entry.
        if (to) edges.push(spec === undefined ? { from, to, name, type } : { from, to, name, spec, type });
      }
    }
  }
  // npm lists bundled dependencies (`inBundle`) like any other, so they are all checked.
  return { manager: 'npm', roots, nodes, edges: dedupeEdges(edges), warnings: [] };
}

/**
 * Splits peers into required and optional ones. A name that only `peerDependenciesMeta` lists
 * (styled-jsx lists `@babel/core` that way) is an optional peer with no declared range.
 */
function splitPeers(entry: LockEntry): [Record<string, string>, Record<string, string | undefined>] {
  const meta = entry.peerDependenciesMeta ?? {};
  const required: Record<string, string> = {};
  const optional: Record<string, string | undefined> = {};
  for (const [name, spec] of Object.entries(entry.peerDependencies ?? {})) {
    if (meta[name]?.optional) optional[name] = spec;
    else required[name] = spec;
  }
  for (const name of Object.keys(meta)) {
    if (!Object.hasOwn(entry.peerDependencies ?? {}, name)) optional[name] = undefined;
  }
  return [required, optional];
}

/**
 * The location of the package whose tarball holds a bundled entry: the nearest enclosing folder
 * that is not bundled itself (`node_modules/npm` for `node_modules/npm/node_modules/tar`).
 */
function bundlerOf(location: string, entries: Record<string, LockEntry>): string | undefined {
  let at = location;
  while (entries[at]?.inBundle) {
    const cut = at.lastIndexOf(`/${NM}`);
    if (cut === -1) return '';
    at = at.slice(0, cut);
  }
  return at;
}

function inNodeModules(location: string): boolean {
  return location.startsWith(NM) || location.includes(`/${NM}`);
}

/** Folders, relative to the lockfile, that some entry's `file:` dependency points at. */
function fileTargets(entries: Record<string, LockEntry>): Set<string> {
  const targets = new Set<string>();
  for (const [location, entry] of Object.entries(entries)) {
    for (const deps of [entry.dependencies, entry.devDependencies, entry.optionalDependencies, entry.peerDependencies]) {
      for (const spec of Object.values(deps ?? {})) {
        if (!spec.startsWith('file:')) continue;
        targets.add(posix.normalize(posix.join(location, spec.slice('file:'.length))).replace(/\/+$/, ''));
      }
    }
  }
  return targets;
}
