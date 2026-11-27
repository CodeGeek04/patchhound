import semver from 'semver';
import type { Manager } from '../match/graph.js';
import type { Packument, PackumentVersion } from './registry.js';

/** How big a move between two versions is, the way a caret range sees it. */
export type Change = 'patch' | 'minor' | 'major' | 'downgrade';

const releaseCache = new WeakMap<Packument, string[]>();
const pickCache = new WeakMap<Packument, Map<string, string | null>>();

/** Published versions that are not prereleases, oldest first. The array is shared: do not change it. */
export function releases(doc: Packument): readonly string[] {
  let list = releaseCache.get(doc);
  if (!list) {
    list = Object.keys(doc.versions)
      .filter((v) => semver.valid(v) !== null && semver.prerelease(v) === null)
      .sort(semver.compare);
    releaseCache.set(doc, list);
  }
  return list;
}

/**
 * The semver range inside a dependency spec, or null when the spec does not name registry versions
 * (git, file:, link:, workspace:, a URL). `npm:lodash@^4` gives `^4`, and an empty spec means any version.
 */
export function rangeOf(spec: string): string | null {
  let range = spec.trim();
  if (range.startsWith('npm:')) {
    const at = range.lastIndexOf('@');
    range = at > 'npm:'.length ? range.slice(at + 1) : '';
  }
  if (range === '') return '*';
  return semver.validRange(range) === null ? null : range;
}

/**
 * The version an install would pick for `spec` today: a dist-tag's version, or else for a range:
 * - npm: the `latest` tag's version when the range allows it and it is not deprecated, even with
 *   newer releases published; otherwise the highest release, passing over deprecated ones while
 *   another fits.
 * - pnpm: the same, but it takes a deprecated `latest` too.
 * - yarn 1: the `latest` tag's version when the range allows it; otherwise the highest release,
 *   deprecated or not.
 * - yarn 2 and later: the highest release, passing over deprecated ones; the `latest` tag plays no part.
 * Null when nothing fits or the spec names no registry versions.
 */
export function pick(doc: Packument, spec: string, manager: Manager = 'npm'): string | null {
  let picks = pickCache.get(doc);
  if (!picks) pickCache.set(doc, (picks = new Map()));
  const key = `${manager} ${spec}`;
  if (picks.has(key)) return picks.get(key)!;
  const picked = pickUncached(doc, spec, manager);
  picks.set(key, picked);
  return picked;
}

function pickUncached(doc: Packument, spec: string, manager: Manager): string | null {
  const tagged = doc['dist-tags']?.[spec.trim()];
  if (tagged && doc.versions[tagged]) return tagged;
  const range = rangeOf(spec);
  if (range === null) return null;
  const latest = doc['dist-tags']?.latest;
  const latestMeta = latest === undefined ? undefined : doc.versions[latest];
  const takesLatest = manager === 'pnpm' || manager === 'yarn-classic' || (manager === 'npm' && !latestMeta?.deprecated);
  if (latest && latestMeta && takesLatest && semver.satisfies(latest, range)) return latest;
  const fitting = releases(doc).filter((v) => semver.satisfies(v, range));
  const live = manager === 'yarn-classic' ? fitting : fitting.filter((v) => !doc.versions[v]?.deprecated);
  return (live.length > 0 ? live : fitting).at(-1) ?? null;
}

/** True when some version in `versions` satisfies the spec's range. */
export function allowsAny(spec: string, versions: Iterable<string>): boolean {
  const range = rangeOf(spec);
  if (range === null) return false;
  for (const v of versions) if (semver.satisfies(v, range)) return true;
  return false;
}

/**
 * The spec a published version gives one of its dependencies, from `dependencies`,
 * `optionalDependencies` or `peerDependencies`, with whether it is a peer. Undefined when the
 * version does not depend on that name.
 */
export function dependencySpec(meta: PackumentVersion, name: string): { spec: string; peer: boolean } | undefined {
  const plain = meta.dependencies?.[name] ?? meta.optionalDependencies?.[name];
  if (plain !== undefined) return { spec: plain, peer: false };
  const peer = meta.peerDependencies?.[name];
  return peer === undefined ? undefined : { spec: peer, peer: true };
}

/** Patch, minor or major as a caret range sees it: in 0.x a minor bump is major, and in 0.0.x a patch is. */
export function changeOf(from: string, to: string): Change {
  const a = semver.parse(from);
  const b = semver.parse(to);
  if (!a || !b) return 'major';
  if (semver.lt(b, a)) return 'downgrade';
  if (a.major !== b.major) return 'major';
  if (a.major === 0 && a.minor !== b.minor) return 'major';
  if (a.major === 0 && a.minor === 0 && a.patch !== b.patch) return 'major';
  return a.minor !== b.minor ? 'minor' : 'patch';
}
