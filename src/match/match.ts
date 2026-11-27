import semver from 'semver';
import { mapLimit } from '../util/pool.js';
import type { Advisory } from '../watch/advisory.js';
import { advisoryFingerprint, combineFingerprints, fixedVersionFor, mergeAdvisories, toAdvisory } from '../watch/advisory.js';
import type { OsvClient, OsvVuln } from '../watch/osv.js';
import type { GraphIndex } from './graph.js';

export interface Finding {
  /** One advisory, or several OSV records for the same problem merged into one (see mergeAdvisories). */
  advisory: Advisory;
  /**
   * What the advisory says about this package, as a hash that ignores `modified` (combined over
   * merged records). It changes only when the content does.
   */
  advisoryFingerprint: string;
  package: string;
  version: string;
  direct: boolean;
  devOnly: boolean;
  /** Up to three chains from the app (or workspace) to the package. */
  paths: string[][];
  /** The names the app's package.json files declare that lead to the package (see GraphIndex.declaredBy). */
  via: string[];
  /** The highest fix among the merged records that name one. */
  fixedVersion: string | null;
  /** OSV ids of the records merged into this finding, the primary first. */
  records: string[];
}

/**
 * Asks OSV about every installed package. One finding per (advisory, package version), where
 * records that are aliases of each other (a GHSA and its MAL- twin) count as one advisory.
 */
export async function matchGraph(index: GraphIndex, osv: OsvClient): Promise<Finding[]> {
  const packages = index.packages().filter((pkg) => semver.valid(pkg.version));
  const idsPerPackage = await osv.queryBatch(packages.map(({ name, version }) => ({ name, version })));
  const ids = [...new Set(idsPerPackage.flat())];
  const records = await mapLimit(ids, 8, (id) => osv.getVuln(id));
  const byId = new Map(ids.map((id, i) => [id, records[i]!]));
  const advisories = new Map(records.map((record) => [record, toAdvisory(record)]));
  const label = (id: string) => (index.isRoot(id) ? (index.graph.nodes.get(id)?.name ?? id) : id);

  const findings: Finding[] = [];
  packages.forEach((pkg, i) => {
    const matched = [...new Set(idsPerPackage[i] ?? [])]
      .map((id) => byId.get(id))
      .filter((vuln): vuln is OsvVuln => vuln !== undefined && !vuln.withdrawn);
    if (matched.length === 0) return;
    const paths = index.pathsTo(pkg.id).map((chain) => chain.map(label));
    const direct = index.isDirect(pkg.id);
    const devOnly = index.isDevOnly(pkg.id);
    const via = index.declaredBy(pkg.id);
    for (const group of aliasGroups(matched)) {
      const advisory = mergeAdvisories(group.map((vuln) => advisories.get(vuln)!));
      findings.push({
        advisory,
        advisoryFingerprint: combineFingerprints(group.map((vuln) => advisoryFingerprint(vuln, pkg.name))),
        package: pkg.name,
        version: pkg.version,
        direct,
        devOnly,
        paths,
        via,
        fixedVersion: highest(group.map((vuln) => fixedVersionFor(vuln, pkg.name, pkg.version))),
        records: group.map((vuln) => vuln.id).sort((a, b) => (a === advisory.id ? -1 : b === advisory.id ? 1 : a < b ? -1 : a > b ? 1 : 0)),
      });
    }
  });
  return findings;
}

/** Splits records into sets connected by ids and aliases, in the order each set first appears. */
function aliasGroups(records: readonly OsvVuln[]): OsvVuln[][] {
  const parent = new Map<string, string>();
  const root = (id: string): string => {
    const up = parent.get(id);
    if (up === undefined || up === id) return id;
    const top = root(up);
    parent.set(id, top);
    return top;
  };
  for (const record of records) {
    for (const alias of record.aliases ?? []) parent.set(root(alias), root(record.id));
  }
  const groups = new Map<string, OsvVuln[]>();
  for (const record of records) {
    const key = root(record.id);
    const group = groups.get(key);
    if (group) group.push(record);
    else groups.set(key, [record]);
  }
  return [...groups.values()];
}

function highest(versions: readonly (string | null)[]): string | null {
  return versions.filter((v): v is string => v !== null).sort(semver.compare).at(-1) ?? null;
}
