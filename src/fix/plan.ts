import semver from 'semver';
import type { Edge, GraphIndex, Manager, PkgNode } from '../match/graph.js';
import { pkgId } from '../match/graph.js';
import type { Finding } from '../match/match.js';
import { mapLimit } from '../util/pool.js';
import { isAffected } from '../watch/advisory.js';
import type { OsvClient, OsvVuln } from '../watch/osv.js';
import type { Packument, PackumentVersion, RegistryClient } from './registry.js';
import { isRefused } from './registry.js';
import type { Change } from './versions.js';
import { allowsAny, changeOf, dependencySpec, pick, rangeOf, releases } from './versions.js';

/** The fix cases, cheapest first. */
export type FixKind = 'refresh' | 'bump' | 'override' | 'remove' | 'no-fix' | 'bundled' | 'unknown';

export const FIX_KINDS: readonly FixKind[] = ['refresh', 'bump', 'override', 'remove', 'no-fix', 'bundled', 'unknown'];

/** One change in a fix. Every step a package's plan lists must happen before its findings close. */
export type FixStep =
  /**
   * Lockfile only (spec case B): the ranges that ask for `package` already allow `to`, so re-resolving
   * it is enough. `alias` is the name the dependency uses when it differs (`string-width-cjs` for
   * string-width), and npm updates such a copy only by that name. `direct` is true when a
   * package.json lists it: given one such name, `pnpm update` updates only listed packages and skips
   * the others, so the two kinds need separate runs. In a plan that also moves a parent of the
   * package, the refresh comes after that move: npm and pnpm keep an installed version that the
   * parent's new range still allows. `round` orders such refreshes: one that has to wait for
   * another refresh to move its parent comes a round later (pnpm runs them in that order). Left out
   * for round 0.
   */
  | { kind: 'refresh'; package: string; alias?: string; from: string; to: string; direct: boolean; round?: number }
  /**
   * Raise a direct dependency in a package.json (spec cases A and C): the vulnerable package itself, or the
   * dependency of the app whose newer version accepts a fixed one. `alias` is the name package.json uses
   * when it differs (`"old-lodash": "npm:lodash@3.10.1"`). `catalog` names the pnpm catalog that holds the range.
   */
  | {
      kind: 'bump';
      package: string;
      alias?: string;
      from: string;
      to: string;
      change: Change;
      /** The project folder whose package.json lists it: `.` or a workspace path. */
      root: string;
      /** The range it has today; empty when it is not listed yet (see `add`). */
      spec: string;
      catalog?: string;
      /**
       * Set when package.json does not list it yet: it was installed only to satisfy peer ranges, and
       * pnpm keeps such a peer where it is even on a fresh resolve (vite 8.2.2 under vitest), so it
       * has to be listed in this section at `to`.
       */
      add?: 'dependencies' | 'devDependencies';
      /**
       * pnpm only: other copies of the package sit at `from` under parents whose ranges allow `to`.
       * pnpm 11 keeps them there after the bump (pnpm 10 moves them on install), and `pnpm update`
       * skips them because package.json lists the name, so `pnpm dedupe` has to run after it.
       */
      dedupe?: boolean;
    }
  /**
   * Force the version with npm or pnpm `overrides` (spec case D): no version of `parent` accepts a fixed
   * one, or the only parent fix is a major upgrade of another package (kept in `alternative`) while the
   * override itself is not major.
   */
  | {
      kind: 'override';
      package: string;
      from: string;
      to: string;
      change: Change;
      /** The parents whose ranges keep it at `from`, with the range each asks for. */
      parents: { id: string; spec: string }[];
      /**
       * Where a package.json also lists the package under its own name, with the range it gives.
       * npm refuses an override of a direct dependency that differs from that range, so the range
       * moves to `to` there and the override refers to it as `$<package>`.
       */
      direct?: { root: string; spec: string }[];
      alternative?: FixStep[];
    }
  /** Take a malicious direct dependency out: no clean version exists. */
  | { kind: 'remove'; package: string; alias?: string; from: string; root: string }
  /** No release is clean and no version of `parent` drops the package. */
  | { kind: 'no-fix'; package: string; from: string; parent: string }
  /** It ships inside `bundler`'s tarball, so only a new version of `bundler` changes it. */
  | { kind: 'bundled'; package: string; from: string; bundler: string }
  | { kind: 'unknown'; package: string; from: string; reason: string };

/** How to fix one vulnerable package version. */
export interface PackagePlan {
  /** `name@version` of the vulnerable package. */
  id: string;
  package: string;
  version: string;
  /** The costliest step's kind. */
  kind: FixKind;
  /**
   * The release the fix moves it to: the lowest clean one above it, or for malware with none above,
   * the highest clean one below (a pin-back). Null when no release is clean.
   */
  target: string | null;
  steps: FixStep[];
}

/** A peer range the lockfile already breaks. npm refuses to update such a lockfile without --legacy-peer-deps. */
export interface BrokenPeer {
  /** `name@version` of the package that declares the peer range. */
  parent: string;
  name: string;
  spec: string;
  installed: string;
}

export interface PlanResult {
  plans: PackagePlan[];
  brokenPeers: BrokenPeer[];
  /** Registry lookups that failed, one message each. Their packages have an `unknown` plan. */
  problems: string[];
  /** Set when the registry itself failed (no answer, a timeout, 429 or 5xx), not only some packages in it. */
  outage: string | null;
}

export interface PlanOptions {
  registry: RegistryClient;
  /** The client that matched the findings: its cache already holds their records. */
  osv: OsvClient;
  /** Packages planned at the same time. Default 8. */
  concurrency?: number;
}

/** How far up the dependency chain a fix is looked for before falling back to an override. */
const MAX_DEPTH = 6;

/**
 * The steps that move a package through one dependency edge (or through all of them, for an
 * ancestor), and the version it ends up at: null when it is no longer installed there, undefined
 * when that is not known (the edge is a peer range, or a cycle moves it).
 */
interface Move {
  steps: FixStep[];
  to?: string | null;
  /** The refresh round that gets it to `to`; -1 when a package.json edit does, before any refresh. */
  round?: number;
}

/**
 * Works out the cheapest fix for every vulnerable package version, from the lockfile's graph, the
 * advisories' ranges and the npm registry's version lists. It reads only: nothing is installed or run.
 */
export async function planFixes(index: GraphIndex, findings: readonly Finding[], options: PlanOptions): Promise<PlanResult> {
  const byPackage = new Map<string, Finding[]>();
  for (const f of findings) {
    const id = pkgId(f.package, f.version);
    byPackage.set(id, [...(byPackage.get(id) ?? []), f]);
  }
  const planner = new Planner(index, options.registry);
  // A walk must not move an ancestor onto a version that the ancestor's own advisories affect.
  const recordsByName = new Map<string, Set<string>>();
  for (const f of findings) for (const record of f.records) (recordsByName.get(f.package) ?? recordsByName.set(f.package, new Set()).get(f.package)!).add(record);
  for (const [name, records] of recordsByName) {
    const settled = await Promise.allSettled([...records].map((record) => options.osv.getVuln(record)));
    planner.known.set(name, settled.flatMap((r) => (r.status === 'fulfilled' ? [r.value] : [])));
  }
  const problems = new Set<string>();
  const planOne = async ([id, group]: [string, Finding[]]): Promise<PackagePlan> => {
    const node = index.graph.nodes.get(id);
    if (!node) return unknownPlan(id, group[0]!.package, group[0]!.version, 'not in the dependency graph');
    try {
      const recordIds = [...new Set(group.flatMap((f) => f.records))];
      const vulns = await Promise.all(recordIds.map((recordId) => options.osv.getVuln(recordId)));
      const malicious = group.some((f) => f.advisory.kind === 'malicious');
      return await planner.plan(node, vulns, malicious);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      problems.add(message);
      return unknownPlan(id, node.name, node.version, message);
    }
  };
  const entries = [...byPackage];
  const plans = await mapLimit(entries, options.concurrency ?? 8, planOne);
  // Bumps of one dependency merge into the highest version any plan asks for (see groupActions). The
  // plans that asked for less are made again at that version, so the refreshes that follow a bump
  // are decided for the version it gets: vitest 3 still uses vite-node and would keep its vite 5,
  // while vitest 4 drops vite-node. So is a plan whose override beat a bump that another plan needs
  // anyway, since that bump now costs nothing more.
  const pins = highestBumps(plans);
  planner.pins = pins;
  const stale = entries.flatMap((_, i) =>
    plans[i]!.steps.some(
      (step) =>
        (step.kind === 'bump' && pins.get(bumpKey(step)) !== step.to) ||
        (step.kind === 'override' && (step.alternative ?? []).some((alt) => alt.kind === 'bump' && pins.has(bumpKey(alt)))),
    )
      ? [i]
      : [],
  );
  const again = await mapLimit(
    stale.map((i) => entries[i]!),
    options.concurrency ?? 8,
    planOne,
  );
  stale.forEach((i, n) => {
    plans[i] = again[n]!;
  });
  return { plans, brokenPeers: brokenPeers(index), problems: [...problems], outage: options.registry.failure ?? null };
}

/** Where a bump's range lives: `<root>:<name in package.json>`, or `catalog:<catalog>:<name>` for a pnpm catalog entry. */
export function bumpKey(step: { root: string; package: string; alias?: string; catalog?: string }): string {
  return `${step.catalog === undefined ? step.root : `catalog:${step.catalog}`}:${step.alias ?? step.package}`;
}

/** The highest version that the plans bump each dependency to, by bumpKey. */
function highestBumps(plans: readonly PackagePlan[]): Map<string, string> {
  const pins = new Map<string, string>();
  for (const step of plans.flatMap((plan) => plan.steps)) {
    if (step.kind !== 'bump') continue;
    const key = bumpKey(step);
    const pinned = pins.get(key);
    if (pinned === undefined || semver.gt(step.to, pinned)) pins.set(key, step.to);
  }
  return pins;
}

/** Peer ranges that the installed version of the peer does not satisfy. */
export function brokenPeers(index: GraphIndex): BrokenPeer[] {
  const broken: BrokenPeer[] = [];
  for (const edge of index.graph.edges) {
    if ((edge.type !== 'peer' && edge.type !== 'peerOptional') || edge.spec === undefined) continue;
    const installed = index.graph.nodes.get(edge.to)?.version ?? '';
    const range = rangeOf(edge.spec);
    if (range === null || !semver.valid(installed) || semver.satisfies(installed, range, { includePrerelease: true })) continue;
    broken.push({ parent: edge.from, name: edge.name, spec: edge.spec, installed });
  }
  return broken.sort((a, b) => a.parent.localeCompare(b.parent) || a.name.localeCompare(b.name));
}

class Planner {
  /** Versions to bump dependencies to (by bumpKey) when the edge accepts them: the highest that any plan asked for. */
  pins = new Map<string, string>();
  /** The advisories the scan found for each package name. */
  readonly known = new Map<string, OsvVuln[]>();

  constructor(
    private readonly index: GraphIndex,
    private readonly registry: RegistryClient,
  ) {
    this.manager = index.graph.manager;
  }

  private readonly manager: Manager;

  async plan(node: PkgNode, vulns: readonly OsvVuln[], malicious: boolean): Promise<PackagePlan> {
    if (node.bundledBy) {
      const steps = node.bundledBy.map((bundler): FixStep => ({ kind: 'bundled', package: node.name, from: node.version, bundler }));
      return finish(node, null, steps, this.manager);
    }
    const edges = this.index.parents(node.id);
    if (edges.length === 0) {
      return finish(node, null, [{ kind: 'unknown', package: node.name, from: node.version, reason: 'nothing in the lockfile installs it' }], this.manager);
    }
    const doc = await this.registry.packument(node.name);
    const clean = releases(doc).filter((v) => !vulns.some((vuln) => isAffected(vuln, node.name, v)));
    const above = clean.filter((v) => semver.gt(v, node.version));
    // Malware with no clean release above it can still be pinned back to a clean release below.
    const accept = new Set(above.length > 0 ? above : malicious ? clean : []);
    const target = above[0] ?? (malicious ? (clean.at(-1) ?? null) : null);

    const steps: FixStep[] = [];
    for (const edge of edges) {
      const found = await this.viaEdge(edge, node, doc, accept, [node.id]);
      const parent = this.index.graph.nodes.get(edge.from);
      const spec = edge.spec ?? (parent && !this.index.isRoot(edge.from) ? await this.specInRegistry(parent, edge.name) : undefined);
      const fallback = this.fallback(edge, node, target, malicious, spec);
      steps.push(...(found === null ? [fallback] : this.preferOverride(found.steps, fallback, node)));
    }
    // Only peer ranges point at it, and they all allow a fixed version: list it at that version.
    if (steps.length === 0) steps.push(this.addOrUnknown(node, accept));
    const direct = edges
      .filter((edge) => this.index.isRoot(edge.from) && !isPeer(edge) && edge.name === node.name)
      .map((edge) => ({ root: rootPath(edge.from), spec: edge.spec ?? '' }));
    return finish(node, target, steps, this.manager, direct);
  }

  /**
   * The steps that make the dependency `edge` (parent -> child) take a version in `accept`, or null
   * when there is none within MAX_DEPTH levels. A parent that cannot move is asked of its own parents
   * in turn: the versions of the parent that accept a fixed child become what its parents must allow.
   * `chain` holds the packages this fix already moves, the vulnerable one first.
   */
  private async viaEdge(
    edge: Edge,
    child: PkgNode,
    childDoc: Packument,
    accept: ReadonlySet<string>,
    chain: readonly string[],
  ): Promise<Move | null> {
    // The parent is already being moved by this fix (a cycle, such as vitest and @vitest/ui), so its current range stops mattering.
    if (chain.includes(edge.from)) return { steps: [] };
    const parentIsRoot = this.index.isRoot(edge.from);
    const parent = this.index.graph.nodes.get(edge.from);
    if (!parent) return null;
    const spec = edge.spec ?? (parentIsRoot ? undefined : await this.specInRegistry(parent, edge.name));

    if (isPeer(edge)) {
      // A peer range installs nothing; it only has to allow a fixed version.
      if (spec === undefined || allowsAny(spec, accept)) return { steps: [] };
    } else {
      if (spec === undefined) return null;
      const picked = pick(childDoc, spec, this.manager);
      if (picked !== null && accept.has(picked)) return { steps: [this.refreshStep(edge, child, picked, 0)], to: picked, round: 0 };
    }

    if (parentIsRoot) {
      if (accept.size === 0 || spec === undefined || rangeOf(spec) === null) return null;
      const name = edge.name === child.name ? {} : { alias: edge.name };
      const where = { root: rootPath(edge.from), ...(edge.catalog === undefined ? {} : { catalog: edge.catalog }) };
      const pinned = this.pins.get(bumpKey({ package: child.name, ...name, ...where }));
      const lowest = [...accept].find((v) => semver.gt(v, child.version)) ?? [...accept].at(-1)!;
      const to = pinned !== undefined && accept.has(pinned) ? pinned : lowest;
      const bump: FixStep = { kind: 'bump', package: child.name, ...name, from: child.version, to, change: changeOf(child.version, to), ...where, spec };
      return { steps: [bump], to, round: -1 };
    }

    if (chain.length >= MAX_DEPTH) return null;
    const parentDoc = await this.docOf(parent);
    if (parentDoc === null) return null;
    const parentAccept = new Set(
      releases(parentDoc).filter(
        (v) =>
          semver.gt(v, parent.version) &&
          !this.affected(parent.name, v) &&
          accepts(parentDoc.versions[v]!, edge.name, childDoc, accept, this.manager),
      ),
    );
    if (parentAccept.size === 0) return null;
    const moved = await this.moveAncestor(parent, parentDoc, parentAccept, [...chain, parent.id]);
    if (moved === null) return null;
    return this.follow(edge, child, childDoc, accept, parentDoc, parentAccept, moved);
  }

  /**
   * Where `child` ends up once the parent of `edge` has moved. Gone, when the parent is no longer
   * installed or its new version does not depend on the child. Kept, when the parent's new range
   * still allows the installed version (npm and pnpm keep it), so the child needs a refresh of its
   * own after the move. Otherwise it is resolved again from the new range. A child that only peer
   * ranges point at is listed in package.json instead; one with other parents is moved by the
   * steps for those parents.
   */
  private follow(
    edge: Edge,
    child: PkgNode,
    childDoc: Packument,
    accept: ReadonlySet<string>,
    parentDoc: Packument,
    parentAccept: ReadonlySet<string>,
    moved: Move,
  ): Move {
    if (moved.to === null) return { steps: moved.steps, to: null };
    // A parent moved by another package of its cycle has no known version: assume the lowest that works.
    const meta = parentDoc.versions[moved.to ?? [...parentAccept][0]!];
    const dep = meta ? dependencySpec(meta, edge.name) : undefined;
    if (!dep) return { steps: moved.steps, to: null };
    const parentRound = moved.round ?? -1;
    if (dep.peer) {
      if (this.index.parents(child.id).some((e) => !isPeer(e))) return { steps: moved.steps };
      const add = this.addOrUnknown(child, accept, { from: edge.from, spec: dep.spec });
      return { steps: [...moved.steps, add], ...(add.kind === 'bump' ? { to: add.to, round: -1 } : {}) };
    }
    const to = pick(childDoc, dep.spec, this.manager) ?? [...accept][0]!;
    // Not allowed any more, so the parent's move resolves it again in the same round.
    if (!allowsAny(dep.spec, [child.version])) return { steps: moved.steps, to, round: parentRound };
    // yarn locks each range (`lodash@^4.17.0`) apart and resolves a range it has not locked from the
    // registry, so the child stays only when another parent already asks for that same range.
    const locked = this.index.parents(child.id).some((e) => !isPeer(e) && e.name === edge.name && e.spec === dep.spec);
    if (isYarn(this.manager) && !locked) return { steps: moved.steps, to, round: parentRound };
    const round = parentRound + 1;
    return { steps: [...moved.steps, this.refreshStep(edge, child, to, round)], to, round };
  }

  private refreshStep(edge: Edge, child: PkgNode, to: string, round: number): FixStep {
    const alias = edge.name === child.name ? {} : { alias: edge.name };
    return {
      kind: 'refresh',
      package: child.name,
      ...alias,
      from: child.version,
      to,
      direct: this.index.isDirect(child.id),
      ...(round > 0 ? { round } : {}),
    };
  }

  /** True when an advisory the scan found for this package affects that version of it. */
  private affected(name: string, version: string): boolean {
    return (this.known.get(name) ?? []).some((vuln) => isAffected(vuln, name, version));
  }

  /**
   * Picks between walking up the chain and an override for one parent edge. A walk that ends in a
   * major upgrade of another package (next 15 to 16 to fix the postcss it pins) loses to an override
   * that is not major for the vulnerable package; the walk is kept as the alternative. A major bump
   * that another plan already needs (pinned at that version) costs nothing more, so it does not count.
   */
  private preferOverride(found: FixStep[], fallback: FixStep, node: PkgNode): FixStep[] {
    if (fallback.kind !== 'override' || fallback.change === 'major') return found;
    const majorElsewhere = found.filter(
      (step) => step.kind === 'bump' && step.package !== node.name && step.change === 'major' && this.pins.get(bumpKey(step)) !== step.to,
    );
    return majorElsewhere.length === 0 ? found : [{ ...fallback, alternative: found }];
  }

  /** The steps that move an ancestor to a version in `accept`: every one of its own parents must allow it. */
  private async moveAncestor(node: PkgNode, doc: Packument, accept: ReadonlySet<string>, chain: readonly string[]): Promise<Move | null> {
    const edges = this.index.parents(node.id);
    if (edges.length === 0) return null;
    const steps: FixStep[] = [];
    const ends: (string | null | undefined)[] = [];
    const rounds: number[] = [];
    for (const edge of edges) {
      const found = await this.viaEdge(edge, node, doc, accept, chain);
      if (!found) return null;
      steps.push(...found.steps);
      ends.push(found.to);
      if (found.round !== undefined) rounds.push(found.round);
    }
    // Still installed where any edge keeps it; gone only when every edge says so.
    const to = ends.find((end): end is string => typeof end === 'string') ?? (ends.every((end) => end === null) ? null : undefined);
    // It is in place once the last of its moves is done.
    const round = rounds.length > 0 ? { round: Math.max(...rounds) } : {};
    if (steps.length > 0) return { steps, to, ...round };
    // A parent this fix already moves brings the package along (vitest brings its @vitest/ui), so it needs no step of its own.
    if (edges.some((edge) => chain.includes(edge.from))) return { steps: [], to, ...round };
    // Otherwise only peer ranges point at it, and they all allow a version in `accept`: list it at that version.
    const add = this.peerPick(node, accept);
    return add === null ? null : { steps: [this.addStep(node, add)], to: add, round: -1 };
  }

  /** The add step for a package that only peer ranges point at, or an unknown step when no clean version fits them all. */
  private addOrUnknown(node: PkgNode, accept: ReadonlySet<string>, moved?: { from: string; spec: string }): FixStep {
    const to = this.peerPick(node, accept, moved);
    if (to !== null) return this.addStep(node, to);
    return { kind: 'unknown', package: node.name, from: node.version, reason: 'no clean version fits every peer range on it' };
  }

  /** Lists a package that was installed only for peer ranges in the package.json of the project that reaches it first. */
  private addStep(node: PkgNode, to: string): FixStep {
    const root = this.index.pathsTo(node.id, 1)[0]?.[0] ?? 'root:.';
    return {
      kind: 'bump',
      package: node.name,
      from: node.version,
      to,
      change: changeOf(node.version, to),
      root: rootPath(root),
      spec: '',
      add: this.index.isDevOnly(node.id) ? 'devDependencies' : 'dependencies',
    };
  }

  /**
   * The highest version in `accept` that every known peer range on the package allows. `moved` gives
   * the range of a parent the fix moves, at its new version. A range that allows nothing in `accept`
   * belongs to a parent that the fix moves as well, so it is left out.
   */
  private peerPick(node: PkgNode, accept: ReadonlySet<string>, moved?: { from: string; spec: string }): string | null {
    const specs = this.index
      .parents(node.id)
      .filter(isPeer)
      .flatMap((edge) => {
        if (moved && edge.from === moved.from) return [moved.spec];
        return edge.spec === undefined || !allowsAny(edge.spec, accept) ? [] : [edge.spec];
      });
    return [...accept].filter((v) => specs.every((spec) => allowsAny(spec, [v]))).at(-1) ?? null;
  }

  /** What to do for a parent edge of the vulnerable package that no parent version can fix. */
  private fallback(edge: Edge, node: PkgNode, target: string | null, malicious: boolean, spec: string | undefined): FixStep {
    const parentIsRoot = this.index.isRoot(edge.from);
    const alias = edge.name === node.name ? {} : { alias: edge.name };
    if (target !== null && !parentIsRoot) {
      return {
        kind: 'override',
        package: node.name,
        from: node.version,
        to: target,
        change: changeOf(node.version, target),
        parents: [{ id: edge.from, spec: spec ?? '' }],
      };
    }
    if (target !== null) {
      const reason =
        spec === undefined ? 'the lockfile does not record the range package.json asks for' : `package.json asks for "${spec}", which is not a version range`;
      return { kind: 'unknown', package: node.name, from: node.version, reason };
    }
    if (parentIsRoot && malicious) {
      return { kind: 'remove', package: node.name, ...alias, from: node.version, root: rootPath(edge.from) };
    }
    return { kind: 'no-fix', package: node.name, from: node.version, parent: edge.from };
  }

  /** The range the installed version of `parent` gives dependency `name`, from the registry. */
  private async specInRegistry(parent: PkgNode, name: string): Promise<string | undefined> {
    const doc = await this.docOf(parent);
    const meta = doc?.versions[parent.version];
    return meta ? dependencySpec(meta, name)?.spec : undefined;
  }

  /**
   * The registry document of a package the fix may move, or null when it has none to read: a folder
   * or git dependency, or a package the registry refuses to show (a private one). Such a parent
   * cannot move, so its edge falls back to an override. Any other registry failure is thrown.
   */
  private async docOf(node: PkgNode): Promise<Packument | null> {
    if (semver.valid(node.version) === null) return null;
    try {
      return await this.registry.packument(node.name);
    } catch (error) {
      if (isRefused(error)) return null;
      throw error;
    }
  }
}

function isPeer(edge: Edge): boolean {
  return edge.type === 'peer' || edge.type === 'peerOptional';
}

export function isYarn(manager: string): boolean {
  return manager === 'yarn-classic' || manager === 'yarn-berry';
}

/** True when this version of a parent would get a version of `name` from `accept`, or no longer depends on it. */
function accepts(meta: PackumentVersion, name: string, childDoc: Packument, accept: ReadonlySet<string>, manager: Manager): boolean {
  const dep = dependencySpec(meta, name);
  if (!dep) return true;
  if (dep.peer) return allowsAny(dep.spec, accept);
  const picked = pick(childDoc, dep.spec, manager);
  return picked !== null && accept.has(picked);
}

/** `root:apps/web` -> `apps/web`. */
function rootPath(id: string): string {
  return id.startsWith('root:') ? id.slice('root:'.length) : id;
}

/**
 * Tidies a package's steps. An override scoped to this package version forces every copy, so it
 * replaces the other steps (one override, every blocking parent and direct listing named). A bump
 * of a package makes re-resolving that same package redundant: npm shares the one copy, and pnpm 10
 * moves the others on install. For pnpm the bump asks for a dedupe instead (see `dedupe`). yarn
 * keeps the other ranges' copies where they are, so for yarn the refresh stays and runs after the
 * bump. Repeats are dropped, and the cheapest steps come first.
 */
function finish(
  node: PkgNode,
  target: string | null,
  steps: FixStep[],
  manager: Manager,
  direct: { root: string; spec: string }[] = [],
): PackagePlan {
  const overrides = steps.filter((step): step is Extract<FixStep, { kind: 'override' }> => step.kind === 'override');
  let kept = steps;
  if (overrides.length > 0) {
    const { package: name, from, to, change } = overrides[0]!;
    const parents = [...new Map(overrides.flatMap((o) => o.parents).map((p) => [p.id, p])).values()];
    const alternative = dedupe(overrides.flatMap((o) => o.alternative ?? []));
    kept = [
      {
        kind: 'override',
        package: name,
        from,
        to,
        change,
        parents,
        ...(direct.length > 0 ? { direct } : {}),
        ...(alternative.length > 0 ? { alternative } : {}),
      },
    ];
  } else {
    const id = (step: { package: string; from: string }) => pkgId(step.package, step.from);
    const bumped = new Set(steps.flatMap((step) => (step.kind === 'bump' ? [id(step)] : [])));
    // An aliased copy (string-width-cjs) is not the one the bump names: npm keeps it, so its refresh stays.
    const redundant = (step: FixStep) => !isYarn(manager) && step.kind === 'refresh' && step.alias === undefined && bumped.has(id(step));
    const refreshed = new Set(steps.flatMap((step) => (redundant(step) ? [id(step as { package: string; from: string })] : [])));
    kept = steps.flatMap((step): FixStep[] => {
      if (redundant(step)) return [];
      if (step.kind === 'bump' && manager === 'pnpm' && refreshed.has(id(step))) return [{ ...step, dedupe: true }];
      return [step];
    });
  }
  const unique = dedupe(mergeRefreshes(kept));
  unique.sort((a, b) => FIX_KINDS.indexOf(a.kind) - FIX_KINDS.indexOf(b.kind));
  const kind = unique.reduce<FixKind>((worst, step) => (FIX_KINDS.indexOf(step.kind) > FIX_KINDS.indexOf(worst) ? step.kind : worst), 'refresh');
  return { id: node.id, package: node.name, version: node.version, kind, target, steps: unique };
}

/**
 * One refresh per copy (package version under one name): two parents can each call for one, and a
 * copy that has to wait for a parent keeps the later round.
 */
function mergeRefreshes(steps: readonly FixStep[]): FixStep[] {
  const merged = new Map<string, Extract<FixStep, { kind: 'refresh' }>>();
  const out: FixStep[] = [];
  for (const step of steps) {
    if (step.kind !== 'refresh') {
      out.push(step);
      continue;
    }
    const key = `${step.alias ?? step.package}=${pkgId(step.package, step.from)}`;
    const seen = merged.get(key);
    if (!seen) {
      merged.set(key, step);
      out.push(step);
      continue;
    }
    const round = Math.max(seen.round ?? 0, step.round ?? 0);
    const combined = { ...seen, to: semver.gt(step.to, seen.to) ? step.to : seen.to, ...(round > 0 ? { round } : {}) };
    merged.set(key, combined);
    out[out.indexOf(seen)] = combined;
  }
  return out;
}

function dedupe(steps: readonly FixStep[]): FixStep[] {
  return [...new Map(steps.map((step) => [JSON.stringify(step), step])).values()];
}

function unknownPlan(id: string, name: string, version: string, reason: string): PackagePlan {
  return { id, package: name, version, kind: 'unknown', target: null, steps: [{ kind: 'unknown', package: name, from: version, reason }] };
}
