import { createHash } from 'node:crypto';
import semver from 'semver';
import type { OsvEvent, OsvVuln } from './osv.js';

export type Severity = 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW' | 'UNKNOWN';

export interface Advisory {
  id: string;
  /**
   * `malicious` for malware: an OSV `MAL-` record, a record with a `MAL-` alias, or a GitHub advisory
   * for embedded malicious code (CWE-506). The remedy is removal or a clean version; most have no
   * fixed version, though some (27 MAL records on npm) name one.
   */
  kind: 'vulnerability' | 'malicious';
  summary: string;
  aliases: string[];
  /** CVE ids this advisory is (its id or aliases). */
  cves: string[];
  /**
   * CVE ids named by NVD links in its references, other than its own. Next.js's RCE advisory
   * GHSA-9qr9-h5gf-34mp has no CVE alias and links CVE-2025-55182 (in KEV) only this way.
   * Use them for KEV and EPSS only when `cves` is empty.
   */
  linkedCves: string[];
  /**
   * OSV `related` ids, for display only. They are not the same problem: CVE-2025-54073 belongs to
   * mcp-package-docs but is `related` on three other packages' advisories.
   */
  related: string[];
  severity: Severity;
  cvssVector?: string;
  published?: string;
  modified: string;
}

const LABELS: Record<string, Severity> = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MODERATE: 'MODERATE',
  MEDIUM: 'MODERATE',
  LOW: 'LOW',
};

const NVD_LINK = /^https?:\/\/nvd\.nist\.gov\/vuln\/detail\/(cve-\d{4}-\d+)\/?$/i;

export function toAdvisory(vuln: OsvVuln): Advisory {
  const aliases = vuln.aliases ?? [];
  const cves = [vuln.id, ...aliases].filter((id) => id.startsWith('CVE-'));
  const linked = (vuln.references ?? []).flatMap((ref) => NVD_LINK.exec(ref.url)?.[1]?.toUpperCase() ?? []);
  return {
    id: vuln.id,
    kind: isMalicious(vuln) ? 'malicious' : 'vulnerability',
    summary: vuln.summary ?? '',
    aliases,
    cves,
    linkedCves: [...new Set(linked)].filter((id) => !cves.includes(id)),
    related: vuln.related ?? [],
    severity: LABELS[vuln.database_specific?.severity?.toUpperCase() ?? ''] ?? 'UNKNOWN',
    cvssVector: cvssVectorOf(vuln),
    published: vuln.published,
    modified: vuln.modified,
  };
}

/**
 * A sha256 of what triage reads in the record for package `name`: summary, details, severity label,
 * CVSS vector, aliases, whether it marks malware, and this package's affected ranges and versions.
 * It leaves out `modified`, because OSV re-stamps records without changing them, and other packages.
 */
export function advisoryFingerprint(vuln: OsvVuln, name: string): string {
  const affected = (vuln.affected ?? [])
    .filter((entry) => entry.package?.ecosystem === 'npm' && entry.package.name === name)
    .map((entry) =>
      JSON.stringify({
        ranges: (entry.ranges ?? [])
          .map((range) => JSON.stringify({ type: range.type, events: range.events.map(eventText).sort() }))
          .sort(),
        versions: [...(entry.versions ?? [])].sort(),
      }),
    )
    .sort();
  const content = {
    summary: vuln.summary ?? '',
    details: vuln.details ?? '',
    severity: vuln.database_specific?.severity ?? '',
    cvssVector: cvssVectorOf(vuln) ?? '',
    aliases: [...(vuln.aliases ?? [])].sort(),
    malicious: isMalicious(vuln),
    affected,
  };
  return createHash('sha256').update(JSON.stringify(content)).digest('hex');
}

/** One fingerprint for a group of merged records. A lone fingerprint is kept as it is. */
export function combineFingerprints(fingerprints: readonly string[]): string {
  if (fingerprints.length === 1) return fingerprints[0]!;
  return createHash('sha256').update([...fingerprints].sort().join('\n')).digest('hex');
}

const SEVERITY_ORDER: readonly Severity[] = ['UNKNOWN', 'LOW', 'MODERATE', 'HIGH', 'CRITICAL'];

/**
 * One advisory for records that describe the same problem, such as a GHSA and its MAL- twin.
 * The lowest GHSA id (else the lowest id) is the primary and gives the id and summary. The
 * other ids join the aliases, lists are unioned, the severity is the highest, the advisory is
 * malicious if any record is, `published` is the earliest and `modified` the latest.
 */
export function mergeAdvisories(members: readonly Advisory[]): Advisory {
  if (members.length === 0) throw new RangeError('mergeAdvisories needs at least one advisory');
  if (members.length === 1) return members[0]!;
  const sorted = [...members].sort((a, b) => primaryRank(a.id) - primaryRank(b.id) || compareText(a.id, b.id));
  const primary = sorted[0]!;
  const aliases = unique(sorted.flatMap((m) => [m.id, ...m.aliases])).filter((id) => id !== primary.id);
  const cves = unique(sorted.flatMap((m) => m.cves));
  const sameProblem = new Set([primary.id, ...aliases]);
  const times = (field: 'published' | 'modified') =>
    sorted.flatMap((m) => m[field] ?? []).sort((a, b) => Date.parse(a) - Date.parse(b));
  return {
    id: primary.id,
    kind: sorted.some((m) => m.kind === 'malicious') ? 'malicious' : 'vulnerability',
    summary: primary.summary || (sorted.find((m) => m.summary)?.summary ?? ''),
    aliases,
    cves,
    linkedCves: unique(sorted.flatMap((m) => m.linkedCves)).filter((id) => !cves.includes(id)),
    related: unique(sorted.flatMap((m) => m.related)).filter((id) => !sameProblem.has(id)),
    severity: sorted.map((m) => m.severity).reduce((a, b) => (SEVERITY_ORDER.indexOf(b) > SEVERITY_ORDER.indexOf(a) ? b : a)),
    cvssVector: primary.cvssVector ?? sorted.find((m) => m.cvssVector)?.cvssVector,
    published: times('published')[0],
    modified: times('modified').at(-1)!,
  };
}

const primaryRank = (id: string) => (id.startsWith('GHSA-') ? 0 : 1);
const compareText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const unique = (items: readonly string[]) => [...new Set(items)];

function eventText(event: OsvEvent): string {
  return JSON.stringify(Object.entries(event).sort(([a], [b]) => a.localeCompare(b)));
}

function cvssVectorOf(vuln: OsvVuln): string | undefined {
  return (vuln.severity?.find((s) => s.type === 'CVSS_V3') ?? vuln.severity?.find((s) => s.type === 'CVSS_V4'))?.score;
}

function isMalicious(vuln: OsvVuln): boolean {
  return (
    [vuln.id, ...(vuln.aliases ?? [])].some((id) => id.startsWith('MAL-')) ||
    (vuln.database_specific?.cwe_ids ?? []).includes('CWE-506')
  );
}

/**
 * The lowest version that fixes `installed` of package `name`, or null when there is no fix yet.
 * Every range that covers the installed version must be left, so this jumps to the highest of
 * their fixes and repeats until no range covers the version. If any covering range has no fix
 * above it, there is no fixed version.
 */
export function fixedVersionFor(vuln: OsvVuln, name: string, installed: string): string | null {
  if (!semver.valid(installed)) return null;
  const { ranges, listed } = rangesFor(vuln, name);
  let candidate = installed;
  for (let step = 0; step < 100; step++) {
    const covering = ranges.filter((points) => covers(points, candidate));
    if (covering.length === 0) return candidate === installed || listed.has(candidate) ? null : candidate;
    const fixes = covering.map((points) => points.find((p) => p.kind === 'fixed' && semver.gt(p.at, candidate))?.at);
    if (fixes.some((fix) => fix === undefined)) return null;
    candidate = (fixes as string[]).sort(semver.compare).at(-1)!;
  }
  return null;
}

/**
 * True when the record says `version` of package `name` is affected: the version is listed, or a
 * range covers it. A version that is not strict semver is never affected.
 */
export function isAffected(vuln: OsvVuln, name: string, version: string): boolean {
  if (!semver.valid(version)) return false;
  const { ranges, listed } = rangesFor(vuln, name);
  return listed.has(version) || ranges.some((points) => covers(points, version));
}

/** The record's SEMVER and ECOSYSTEM ranges for package `name`, as sorted points, and its listed versions. */
function rangesFor(vuln: OsvVuln, name: string): { ranges: Point[][]; listed: Set<string> } {
  const ranges: Point[][] = [];
  const listed = new Set<string>();
  for (const affected of vuln.affected ?? []) {
    if (affected.package?.ecosystem !== 'npm' || affected.package.name !== name) continue;
    for (const version of affected.versions ?? []) listed.add(version);
    for (const range of affected.ranges ?? []) {
      if (range.type === 'SEMVER' || range.type === 'ECOSYSTEM') ranges.push(pointsOf(range.events));
    }
  }
  return { ranges, listed };
}

type EventKind = 'introduced' | 'fixed' | 'last_affected' | 'limit';

interface Point {
  kind: EventKind;
  /** The event's version as strict semver. */
  at: string;
}

const KINDS: readonly EventKind[] = ['introduced', 'fixed', 'last_affected', 'limit'];

/**
 * At one version, a range closes (`fixed`, `limit`) before the next one opens, and
 * `last_affected` comes after `introduced` because it still includes that version.
 */
const TIE_ORDER: Record<EventKind, number> = { fixed: 0, limit: 0, introduced: 1, last_affected: 2 };

/** A range's events as sorted points. Events whose version cannot be read are dropped. */
function pointsOf(events: readonly OsvEvent[]): Point[] {
  const points: Point[] = [];
  for (const event of events) {
    for (const kind of KINDS) {
      const raw = event[kind];
      const at = raw === undefined ? null : normalise(raw);
      if (at) points.push({ kind, at });
    }
  }
  return points.sort((a, b) => semver.compare(a.at, b.at) || TIE_ORDER[a.kind] - TIE_ORDER[b.kind]);
}

/**
 * OSV event versions are not always strict semver ("13.0", "1.90"). "0" means "every version",
 * prereleases of 0.0.0 included.
 */
function normalise(version: string): string | null {
  if (version === '0') return '0.0.0-0';
  return semver.valid(version) ?? semver.valid(version, { loose: true }) ?? semver.coerce(version)?.version ?? null;
}

/** The OSV schema's evaluation of one range: https://ossf.github.io/osv-schema/#evaluation */
function covers(points: readonly Point[], version: string): boolean {
  let affected = false;
  for (const { kind, at } of points) {
    const order = semver.compare(version, at);
    if (kind === 'introduced' && order >= 0) affected = true;
    else if ((kind === 'fixed' || kind === 'limit') && order >= 0) affected = false;
    else if (kind === 'last_affected' && order > 0) affected = false;
  }
  return affected;
}
