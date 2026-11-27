import { access, readdir, readFile, stat } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, posix } from 'node:path';
import { parse } from 'yaml';
import type { DepGraph } from '../graph.js';
import { parsePackageLock } from './package-lock.js';
import { parsePnpmLock } from './pnpm-lock.js';
import type { Manifest, YarnCatalogs } from './yarn-lock.js';
import { parseYarnLock } from './yarn-lock.js';

/** The lockfiles this reads, in the order a project with several prefers when its package.json names no package manager. */
export const LOCKFILES = ['pnpm-lock.yaml', 'npm-shrinkwrap.json', 'package-lock.json', 'yarn.lock'] as const;

/** Which lockfiles each package manager writes, for package.json's `packageManager` field (`pnpm@10.4.1`). */
const WRITTEN_BY: Record<string, readonly string[]> = {
  pnpm: ['pnpm-lock.yaml'],
  npm: ['npm-shrinkwrap.json', 'package-lock.json'],
  yarn: ['yarn.lock'],
};

export interface LoadedGraph {
  lockfile: string;
  graph: DepGraph;
}

export interface LoadOptions {
  /** The lockfile to read, as a name in the project folder or a path, instead of choosing one. */
  lockfile?: string;
}

interface PackageJson extends Manifest {
  packageManager?: string;
  workspaces?: string[] | { packages?: string[] };
}

/**
 * Finds the project's lockfile and parses it. When there are several, the one written by the package
 * manager that package.json's `packageManager` names wins, else the first in LOCKFILES, and a warning
 * names the others: a stale lockfile that a CI job still installs from is worth knowing about.
 */
export async function loadGraph(dir: string, options: LoadOptions = {}): Promise<LoadedGraph> {
  const present: string[] = [];
  for (const file of LOCKFILES) if (await exists(join(dir, file))) present.push(file);
  let lockfile: string;
  if (options.lockfile !== undefined) {
    lockfile = isAbsolute(options.lockfile) ? options.lockfile : join(dir, options.lockfile);
    if (!(LOCKFILES as readonly string[]).includes(basename(lockfile))) {
      throw new Error(`${lockfile} is not a lockfile this reads. Supported: ${LOCKFILES.join(', ')}.`);
    }
    if (!(await exists(lockfile))) throw new Error(`No such lockfile: ${lockfile}`);
  } else {
    if (present.length === 0) throw new Error(`No lockfile in ${dir}. Supported: ${LOCKFILES.join(', ')}.`);
    const root = await readManifest(join(dir, 'package.json'));
    const named = WRITTEN_BY[root?.packageManager?.split('@')[0] ?? ''] ?? [];
    lockfile = join(dir, present.find((file) => named.includes(file)) ?? present[0]!);
  }
  const text = await readFile(lockfile, 'utf8');
  let graph: DepGraph;
  try {
    const project = dirname(lockfile);
    graph =
      basename(lockfile) === 'yarn.lock'
        ? parseYarnLock(text, await readManifests(project), await readYarnCatalogs(project))
        : PARSERS[basename(lockfile)]!(text);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`Could not read ${lockfile}: ${reason}`, { cause: error });
  }
  const others = options.lockfile === undefined ? present.filter((file) => file !== basename(lockfile)) : [];
  if (others.length > 0) {
    const names = others.join(' and ');
    graph.warnings.push(
      `${basename(dir)} also has ${names}, which ${others.length === 1 ? 'was' : 'were'} not scanned. ` +
        `If anything still installs from ${others.length === 1 ? 'it' : 'them'}, scan with --lockfile ${others[0]}.`,
    );
  }
  return { lockfile, graph };
}

const PARSERS: Record<string, (text: string) => DepGraph> = {
  'pnpm-lock.yaml': parsePnpmLock,
  'npm-shrinkwrap.json': parsePackageLock,
  'package-lock.json': parsePackageLock,
};

/** yarn 4's catalogs from .yarnrc.yml (`catalog` and `catalogs`); empty when there are none. */
export async function readYarnCatalogs(dir: string): Promise<YarnCatalogs> {
  try {
    const yarnrc = parse(await readFile(join(dir, '.yarnrc.yml'), 'utf8'), { schema: 'failsafe' }) as {
      catalog?: Record<string, string>;
      catalogs?: Record<string, Record<string, string>>;
    } | null;
    return { ...(yarnrc?.catalog ? { default: yarnrc.catalog } : {}), ...(yarnrc?.catalogs ? { named: yarnrc.catalogs } : {}) };
  } catch {
    return {};
  }
}

/**
 * The package.json of the project (`.`, empty when there is none) and of every workspace its
 * `workspaces` globs match, by folder. Globs support `*` within a segment, `**`, `{a,b}`, and `!` to
 * exclude; a symlinked folder counts like any other.
 */
export async function readManifests(dir: string): Promise<Map<string, Manifest>> {
  const root = (await readManifest(join(dir, 'package.json'))) ?? {};
  const manifests = new Map<string, Manifest>([['.', root]]);
  const patterns = Array.isArray(root.workspaces) ? root.workspaces : (root.workspaces?.packages ?? []);
  const excluded = new Set<string>();
  for (const pattern of patterns.filter((p) => p.startsWith('!'))) {
    for (const path of await expand(dir, pattern.slice(1))) excluded.add(path);
  }
  for (const pattern of patterns.filter((p) => !p.startsWith('!'))) {
    for (const path of await expand(dir, pattern)) {
      if (excluded.has(path) || manifests.has(path)) continue;
      const manifest = await readManifest(join(dir, path, 'package.json'));
      if (manifest) manifests.set(path, manifest);
    }
  }
  return manifests;
}

/** Folders under `dir` that a workspace glob matches, as posix paths relative to `dir`. */
async function expand(dir: string, pattern: string): Promise<string[]> {
  const found = await Promise.all(braces(pattern).map((one) => expandOne(dir, one)));
  return [...new Set(found.flat())];
}

/** `{apps,libs}/*` -> [`apps/*`, `libs/*`]; nested and several groups expand too. */
function braces(pattern: string): string[] {
  const match = /\{([^{}]*)\}/.exec(pattern);
  if (!match) return [pattern];
  return match[1]!.split(',').flatMap((option) => braces(pattern.slice(0, match.index) + option + pattern.slice(match.index + match[0].length)));
}

async function expandOne(dir: string, pattern: string): Promise<string[]> {
  let paths = [''];
  for (const segment of posix.normalize(pattern.replace(/\/+$/, '')).split('/')) {
    const next: string[] = [];
    for (const path of paths) {
      if (segment === '**') next.push(path, ...(await descendants(dir, path)));
      else if (segment.includes('*')) {
        const match = new RegExp(`^${segment.split('*').map(escapeRegExp).join('[^/]*')}$`);
        next.push(...(await subfolders(dir, path)).filter((name) => match.test(name)).map((name) => posix.join(path, name)));
      } else next.push(posix.join(path, segment));
    }
    paths = next;
  }
  return [...new Set(paths.filter((path) => path !== '' && path !== '.'))];
}

async function subfolders(dir: string, path: string): Promise<string[]> {
  try {
    const entries = await readdir(join(dir, path), { withFileTypes: true });
    const folders: string[] = [];
    for (const e of entries) {
      if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
      const linkedFolder = e.isSymbolicLink() && (await stat(join(dir, path, e.name)).then((s) => s.isDirectory(), () => false));
      if (e.isDirectory() || linkedFolder) folders.push(e.name);
    }
    return folders;
  } catch {
    return [];
  }
}

async function descendants(dir: string, path: string): Promise<string[]> {
  const found: string[] = [];
  for (const name of await subfolders(dir, path)) {
    const child = posix.join(path, name);
    found.push(child, ...(await descendants(dir, child)));
  }
  return found;
}

function escapeRegExp(text: string): string {
  return text.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
}

async function readManifest(path: string): Promise<PackageJson | undefined> {
  try {
    return JSON.parse(await readFile(path, 'utf8')) as PackageJson;
  } catch {
    return undefined;
  }
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}
