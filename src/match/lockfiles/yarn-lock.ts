import { parse } from 'yaml';
import type { DepGraph, DepType, Edge, PkgNode } from '../graph.js';
import { dedupeEdges, pkgId, rootId } from '../graph.js';

/** The fields of a package.json that the graph needs. */
export interface Manifest {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  /** The root's forced ranges (`"lodash": "4.17.21"`, `"lodash@^4.17.0": "4.17.21"`, `"**\/lodash": ...`). */
  resolutions?: Record<string, string>;
}

/** yarn 4's named ranges, from .yarnrc.yml: `catalog` (used as `catalog:`) and `catalogs` (`catalog:<name>`). */
export interface YarnCatalogs {
  default?: Record<string, string>;
  named?: Record<string, Record<string, string>>;
}

/** One resolved package in yarn.lock, under every descriptor (`name@range`) that resolved to it. */
interface Entry {
  descriptors: string[];
  /** The real package name: an alias entry (`old-lodash@npm:lodash@3.10.1`) installs another package. */
  name: string;
  version: string;
  /** What yarn resolved it to (`lodash@npm:4.17.20`); yarn 2+ only. A dependency's `::locator=` names it. */
  locator?: string;
  /** Set for a berry workspace (`@workspace:packages/ui`): the folder, `.` for the project. */
  workspace?: string;
  dependencies: Record<string, string>;
  optional: Set<string>;
}

/** Ranges that point at a folder or a file instead of the registry: such a package has no registry version. */
const LOCAL = /^(link|portal|file):/;

/**
 * Parses yarn.lock into a dependency graph: yarn 1 ("classic", its own text format) and yarn 2 and
 * later ("berry", YAML with `__metadata`). `manifests` holds the package.json of the project (`.`)
 * and of each workspace, by folder: a classic lockfile does not list workspaces at all, and neither
 * format tells devDependencies apart. A package from a folder or a file (`link:`, `portal:`, `file:`)
 * keeps that reference as its version, so no registry advisory matches it. The graph has no peer
 * edges: yarn 1 records no peer ranges, and yarn 2+ records ranges without what met them.
 */
export function parseYarnLock(text: string, manifests: ReadonlyMap<string, Manifest>, catalogs: YarnCatalogs = {}): DepGraph {
  const berry = /^__metadata:/m.test(text);
  const entries = berry ? berryEntries(text) : classicEntries(text);
  const nodes = new Map<string, PkgNode>();
  const roots: string[] = [];
  const byDescriptor = new Map<string, string>();
  const workspaceByName = new Map<string, string>();
  const byName = new Map<string, Set<string>>();

  for (const [path, manifest] of manifests) {
    const id = rootId(path);
    roots.push(id);
    nodes.set(id, { id, name: manifest.name ?? path, version: manifest.version ?? '' });
    if (manifest.name) workspaceByName.set(manifest.name, id);
  }
  for (const entry of entries) {
    let id: string;
    if (entry.workspace !== undefined) {
      id = rootId(entry.workspace);
      if (!nodes.has(id)) {
        roots.push(id);
        nodes.set(id, { id, name: entry.name, version: '' });
      }
    } else {
      id = pkgId(entry.name, entry.version);
      if (!nodes.has(id)) nodes.set(id, { id, name: entry.name, version: entry.version });
      (byName.get(entry.name) ?? byName.set(entry.name, new Set()).get(entry.name)!).add(id);
    }
    for (const descriptor of entry.descriptors) byDescriptor.set(descriptor, id);
  }

  const edges: Edge[] = [];
  const resolutions = manifests.get('.')?.resolutions ?? {};
  const unresolved: string[] = [];
  /**
   * The node a dependency resolves to. yarn keys an entry by the descriptor it resolved, which is not
   * always what the parent asked for: yarn 2+ adds `npm:` to a registry range (yarn 2 and 3 left it out
   * of dependency ranges), keys a range that `resolutions` or a `catalog:` replaced by its replacement,
   * and adds `::locator=<parent>` to a folder or file range. yarn 1 leaves workspaces out. Last, a
   * name that only one entry has links to that entry.
   */
  const resolve = (name: string, range: string, parent: string | undefined): string | undefined => {
    const ranges = [range, catalogRange(name, range, catalogs), forcedRange(resolutions, name, range)].filter(
      (r): r is string => r !== undefined,
    );
    for (const r of ranges) {
      const keys = [`${name}@${r}`];
      if (berry && !/^[a-z]+:/.test(r)) keys.push(`${name}@npm:${r}`);
      if (berry && parent) keys.push(`${name}@${r}::locator=${encodeURIComponent(parent)}`);
      for (const key of keys) {
        const id = byDescriptor.get(key);
        if (id) return id;
      }
    }
    const workspace = workspaceByName.get(name);
    if (workspace) return workspace;
    const only = byName.get(name);
    if (only?.size === 1) return [...only][0];
    unresolved.push(`${name}@${range}`);
    return undefined;
  };

  // What each workspace's package.json asks for, with the dev and optional sections told apart.
  for (const [path, manifest] of manifests) {
    const from = rootId(path);
    const locator = manifest.name ? `${manifest.name}@workspace:${path}` : undefined;
    const sections: [Record<string, string> | undefined, DepType][] = [
      [manifest.dependencies, 'prod'],
      [manifest.optionalDependencies, 'optional'],
      [manifest.devDependencies, 'dev'],
    ];
    for (const [deps, type] of sections) {
      for (const [name, range] of Object.entries(deps ?? {})) {
        const to = resolve(name, range, locator);
        if (!to || to === from) continue;
        // A catalog range lives in .yarnrc.yml, so a bump edits it there.
        const catalog = range.startsWith('catalog:') ? range.slice('catalog:'.length) || 'default' : undefined;
        const spec = catalogRange(name, range, catalogs) ?? range;
        edges.push(catalog === undefined ? { from, to, name, spec, type } : { from, to, name, spec, catalog, type });
      }
    }
  }
  for (const entry of entries) {
    const from = entry.workspace !== undefined ? rootId(entry.workspace) : pkgId(entry.name, entry.version);
    // A workspace's own dependencies come from its package.json above, which knows dev from prod.
    if (entry.workspace !== undefined && manifests.has(entry.workspace)) continue;
    for (const [name, range] of Object.entries(entry.dependencies)) {
      const to = resolve(name, range, entry.locator);
      if (!to) continue;
      const type: DepType = entry.optional.has(name) ? 'optional' : 'prod';
      edges.push({ from, to, name, spec: specOf(range), type });
    }
  }
  const warnings =
    unresolved.length === 0
      ? []
      : [
          `yarn.lock has no entry for ${unresolved.length} ${unresolved.length === 1 ? 'dependency' : 'dependencies'}, so the paths ` +
            `and dev-only status of what they install may be off: ${[...new Set(unresolved)].slice(0, 5).join(', ')}` +
            (new Set(unresolved).size > 5 ? ', ...' : ''),
        ];
  return { manager: berry ? 'yarn-berry' : 'yarn-classic', roots, nodes, edges: dedupeEdges(edges), warnings };
}

/** The range a `catalog:` or `catalog:<name>` range stands for, from .yarnrc.yml. */
function catalogRange(name: string, range: string, catalogs: YarnCatalogs): string | undefined {
  if (!range.startsWith('catalog:')) return undefined;
  const catalog = range.slice('catalog:'.length);
  return catalog === '' ? catalogs.default?.[name] : catalogs.named?.[catalog]?.[name];
}

/** The range the root's `resolutions` force on this dependency: keyed by the name, `name@range`, or a path ending in the name. */
function forcedRange(resolutions: Record<string, string>, name: string, range: string): string | undefined {
  return (
    resolutions[`${name}@${range}`] ??
    resolutions[name] ??
    Object.entries(resolutions).find(([key]) => key.endsWith(`/${name}`) || key.endsWith(`/${name}@${range}`))?.[1]
  );
}

/**
 * The range a dependency asks for, the way the fix planner reads specs: berry's `npm:^4.17.0` is
 * `^4.17.0`, and a patched one (`patch:typescript@npm%3A^5.4.5#...`) asks for the range it patches.
 * An alias (`npm:lodash@^3.0.0`) stays as it is.
 */
function specOf(range: string): string {
  const patched = /^patch:(?:@[^@/]+\/)?[^@]+@([^#]+)#/.exec(range);
  const inner = patched ? decodeURIComponent(patched[1]!) : range;
  return /^npm:[^@]*$/.test(inner) ? inner.slice('npm:'.length) : inner;
}

/** `name@range` -> [name, range]; the name may be scoped (`@demo/ui@^1.0.0`). */
function splitDescriptor(descriptor: string): [string, string] {
  const at = descriptor.indexOf('@', 1);
  return [descriptor.slice(0, at), descriptor.slice(at + 1)];
}

/** The package an `npm:` alias installs: `npm:lodash@^3.0.0` and `npm:lodash` -> `lodash`; undefined for a plain range. */
function aliasTarget(range: string): string | undefined {
  if (!range.startsWith('npm:')) return undefined;
  const rest = range.slice('npm:'.length);
  const at = rest.indexOf('@', 1);
  return at === -1 ? rest : rest.slice(0, at);
}

/**
 * Entries of a yarn 2+ lockfile. Read with YAML's failsafe schema, which keeps every value a string:
 * yarn 2 and 3 wrote ranges such as `1.0` unquoted, and the core schema would read them as numbers.
 */
function berryEntries(text: string): Entry[] {
  const lock = (parse(text, { schema: 'failsafe' }) ?? {}) as Record<string, BerryEntry>;
  const entries: Entry[] = [];
  for (const [key, value] of Object.entries(lock)) {
    if (key === '__metadata' || typeof value !== 'object' || value === null) continue;
    const descriptors = key.split(',').map((d) => d.trim());
    const resolution = value.resolution ?? descriptors[0]!;
    const [name, reference] = splitDescriptor(resolution);
    const optional = new Set(
      Object.entries(value.dependenciesMeta ?? {}).flatMap(([dep, meta]) => (meta?.optional === true || meta?.optional === 'true' ? [dep] : [])),
    );
    entries.push({
      descriptors,
      name,
      version: LOCAL.test(reference) ? reference : String(value.version ?? ''),
      locator: resolution,
      ...(reference.startsWith('workspace:') ? { workspace: reference.slice('workspace:'.length) } : {}),
      dependencies: Object.fromEntries(Object.entries(value.dependencies ?? {}).map(([dep, range]) => [dep, String(range)])),
      optional,
    });
  }
  return entries;
}

interface BerryEntry {
  version?: string;
  resolution?: string;
  dependencies?: Record<string, string>;
  dependenciesMeta?: Record<string, { optional?: boolean | string }>;
}

/**
 * Entries of a yarn 1 lockfile. Its format is close to YAML but is not YAML: a header line lists
 * every descriptor (`"@babel/core@^7.0.0", "@babel/core@^7.12.3":`), then indented `key value`
 * lines and `dependencies:` sections whose lines are `name range`.
 */
function classicEntries(text: string): Entry[] {
  const entries: Entry[] = [];
  let entry: { descriptors: string[]; fields: Record<string, string>; sections: Record<string, Record<string, string>> } | undefined;
  let section: string | undefined;
  const finish = () => {
    if (!entry) return;
    const [requested, range] = splitDescriptor(entry.descriptors[0]!);
    entries.push({
      descriptors: entry.descriptors,
      name: aliasTarget(range) ?? requested,
      version: LOCAL.test(range) ? range : (entry.fields.version ?? ''),
      dependencies: { ...entry.sections.dependencies, ...entry.sections.optionalDependencies },
      optional: new Set(Object.keys(entry.sections.optionalDependencies ?? {})),
    });
  };
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+$/, '');
    if (line === '' || line.startsWith('#')) continue;
    const indent = line.length - line.trimStart().length;
    if (indent === 0) {
      finish();
      entry = { descriptors: splitList(line.slice(0, -1)), fields: {}, sections: {} };
      section = undefined;
    } else if (entry && indent === 2 && line.endsWith(':')) {
      section = unquote(line.trim().slice(0, -1));
      entry.sections[section] = {};
    } else if (entry && indent === 2) {
      const [key, value] = keyValue(line.trim());
      entry.fields[key] = value;
      section = undefined;
    } else if (entry && section && indent >= 4) {
      const [key, value] = keyValue(line.trim());
      entry.sections[section]![key] = value;
    }
  }
  finish();
  return entries;
}

/** `"a@^1", b@^2` -> [`a@^1`, `b@^2`]. */
function splitList(header: string): string[] {
  return header.split(/,\s*/).map((part) => unquote(part.trim()));
}

/** `name "range"`, `"@scope/name" "^1.0.0"` or `version 1.2.3` -> [key, value]. */
function keyValue(text: string): [string, string] {
  const match = /^("(?:[^"\\]|\\.)*"|\S+)\s+(.*)$/.exec(text);
  return match ? [unquote(match[1]!), unquote(match[2]!)] : [unquote(text), ''];
}

function unquote(text: string): string {
  return text.length >= 2 && text.startsWith('"') && text.endsWith('"') ? JSON.parse(text) : text;
}
