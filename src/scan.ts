import { basename, join, resolve } from 'node:path';
import type { FixAction } from './fix/actions.js';
import { groupActions } from './fix/actions.js';
import type { BrokenPeer, FixKind, PackagePlan, PlanResult } from './fix/plan.js';
import { planFixes } from './fix/plan.js';
import { RegistryClient } from './fix/registry.js';
import { GraphIndex } from './match/graph.js';
import { loadGraph } from './match/lockfiles/load.js';
import { addNextBundles, settleBundled } from './match/vendored.js';
import { DiskCache } from './util/cache.js';
import type { Finding } from './match/match.js';
import { matchGraph } from './match/match.js';
import type { RetryOptions } from './util/http.js';
import type { Advisory, Severity } from './watch/advisory.js';
import { fetchEpss, fetchKev } from './watch/enrich.js';
import type { Fetch } from './watch/osv.js';
import { OsvClient } from './watch/osv.js';
import type { Facts, FindingStatus } from './watch/state.js';
import { loadState, observe, prepareStateDir, saveState } from './watch/state.js';

export interface ScanOptions {
  dir: string;
  /** Default: <dir>/.bulwark/state.json */
  statePath?: string;
  /** Report only: do not save which advisories were seen. */
  dryRun?: boolean;
  fetch?: Fetch;
  /** Retry settings for OSV, KEV, EPSS and npm registry requests. Tests pass a sleep that returns at once. */
  retry?: RetryOptions;
  /** Work out how to fix each finding, from npm registry metadata. Default true. */
  fixPlan?: boolean;
  /** Default https://registry.npmjs.org */
  registryUrl?: string;
  /** The lockfile to scan, by name or path, when the project has several. Default: see loadGraph. */
  lockfile?: string;
  /** Check the React builds that next bundles (see addNextBundles). Default true. */
  nextBundles?: boolean;
  /** Where addNextBundles reads next's published files. Default https://cdn.jsdelivr.net/npm */
  cdnUrl?: string;
  /** Keep OSV records, npm registry documents, the KEV catalog and next's bundled builds here between runs. Default: no cache. */
  cacheDir?: string;
  now?: Date;
}

export interface ScanFinding extends Finding {
  /**
   * The key the state file uses for this finding (it may be an alias key kept from an earlier scan).
   * The stable id consumers should use to track a finding across runs.
   */
  key: string;
  status: FindingStatus;
  /** For an updated finding, the facts that changed since the last scan: advisory, kev, fixedVersion, devOnly, direct. */
  changed: string[];
  /**
   * KEV-listed CVEs among the advisory's own CVEs, or among its linked CVEs when it has none.
   * Null when the KEV feed could not be read.
   */
  kev: string[] | null;
  /** The fix plan's verdict for this finding's package: its costliest kind, and the ids of the actions it needs. Null without a plan. */
  fix: { kind: FixKind; actions: string[] } | null;
  /**
   * Highest EPSS score among those CVEs. Null when none of its CVEs has a score,
   * or when the EPSS feed was unavailable (see `enrichment.epss`).
   */
  epss: number | null;
}

/** 'skipped' when there were no CVEs to look up, 'unavailable' when the feed request failed. */
export type EnrichmentStatus = 'ok' | 'unavailable' | 'skipped';

export interface ScanResult {
  /** Version of this output's shape. */
  schemaVersion: 1;
  /** ISO timestamp of the scan. */
  scannedAt: string;
  project: string;
  lockfile: string;
  manager: string;
  /** Workspace folders besides the project root, as the lockfile records them (`packages/ui`). */
  workspaces: string[];
  packageCount: number;
  findings: ScanFinding[];
  /** Whether each enrichment feed was read. A feed that is not 'ok' leaves its per-finding values unknown. */
  enrichment: { kev: EnrichmentStatus; epss: EnrichmentStatus };
  /**
   * What to do about the findings, most urgent and cheapest first. 'skipped' with no findings or when
   * turned off, 'unavailable' when the npm registry could not be read.
   */
  /** `plans` is each vulnerable package's own plan, before `actions` merges them. */
  fixPlan: { status: EnrichmentStatus; actions: FixAction[]; brokenPeers: BrokenPeer[]; plans?: PackagePlan[] };
  warnings: string[];
}

/** One full pass over a project: parse the lockfile, match against OSV, enrich, compare with last time. */
export async function scan(options: ScanOptions): Promise<ScanResult> {
  const dir = resolve(options.dir);
  const now = options.now ?? new Date();
  const fetchFn = options.fetch ?? globalThis.fetch.bind(globalThis);
  const statePath = options.statePath ?? join(dir, '.bulwark', 'state.json');

  const { lockfile, graph } = await loadGraph(dir, options.lockfile === undefined ? {} : { lockfile: options.lockfile });
  // Read the state before any request, so a bad state file costs no API calls.
  const state = await loadState(statePath);
  // Likewise a state location that cannot be written. Only the default folder ignores itself in git.
  if (!options.dryRun) await prepareStateDir(statePath, { gitignore: options.statePath === undefined });
  // Parser warnings (such as bundled packages pnpm-lock.yaml does not list) lead the report's warnings.
  const warnings = [...graph.warnings];
  const cache = options.cacheDir === undefined ? undefined : new DiskCache(options.cacheDir);
  if (options.nextBundles !== false) {
    const cdn = options.cdnUrl === undefined ? {} : { cdnUrl: options.cdnUrl };
    warnings.push(...(await addNextBundles(graph, { fetch: fetchFn, retry: options.retry, ...cdn, ...(cache ? { cache } : {}) })));
  }
  const index = new GraphIndex(graph);
  const osv = new OsvClient({ fetch: fetchFn, retry: options.retry, ...(cache ? { cache } : {}) });
  const answered = await settleBundled(await matchGraph(index, osv), graph, osv);
  const findings = answered.findings;
  warnings.push(...answered.warnings);

  const cves = findings.flatMap((f) => lookupCves(f.advisory));
  const planning: Promise<PlanResult | { failed: string } | null> =
    options.fixPlan === false || findings.length === 0
      ? Promise.resolve(null)
      : planFixes(index, findings, {
          osv,
          registry: new RegistryClient({ fetch: fetchFn, retry: options.retry, baseUrl: options.registryUrl, ...(cache ? { cache } : {}) }),
        }).catch((error: unknown) => ({ failed: `Fix plan unavailable: ${messageOf(error)}` }));
  // KEV, EPSS and the registry are independent: ask them together so a slow one does not delay the others.
  const [kev, epss, planned] = await Promise.all([
    cves.length === 0
      ? new Set<string>()
      : fetchKev(fetchFn, options.retry, cache).catch((error: unknown) => ({ failed: `KEV unavailable: ${messageOf(error)}` })),
    cves.length === 0
      ? new Map<string, number>()
      : fetchEpss(cves, fetchFn, options.retry).catch((error: unknown) => ({ failed: `EPSS unavailable: ${messageOf(error)}` })),
    planning,
  ]);
  const enrichment: ScanResult['enrichment'] =
    cves.length === 0
      ? { kev: 'skipped', epss: 'skipped' }
      : { kev: 'failed' in kev ? 'unavailable' : 'ok', epss: 'failed' in epss ? 'unavailable' : 'ok' };
  const kevSet = 'failed' in kev ? null : kev;
  const epssScores = 'failed' in epss ? null : epss;
  // Warnings in a fixed order: KEV, EPSS, then the fix plan.
  if ('failed' in kev) warnings.push(kev.failed);
  if ('failed' in epss) warnings.push(epss.failed);
  let plan: PlanResult | null = null;
  let planStatus: EnrichmentStatus = 'skipped';
  if (planned !== null && 'failed' in planned) {
    warnings.push(planned.failed);
    planStatus = 'unavailable';
  } else if (planned !== null && planned.outage !== null && planned.plans.every((p) => p.kind === 'unknown')) {
    // The registry itself failed and nothing could be planned. A package the registry does not have
    // (a private one) only makes the plan incomplete.
    warnings.push(`Fix plan unavailable: ${planned.outage}`);
    planStatus = 'unavailable';
  } else if (planned !== null) {
    if (planned.problems.length > 0) {
      const count = planned.problems.length;
      warnings.push(`Fix plan incomplete: ${count} npm registry ${count === 1 ? 'lookup' : 'lookups'} failed: ${planned.problems[0]}`);
    }
    plan = planned;
    planStatus = 'ok';
  }

  const enriched = findings.map((f) => {
    const lookup = lookupCves(f.advisory);
    return {
      finding: f,
      kev: kevSet ? lookup.filter((cve) => kevSet.has(cve)) : null,
      epss: epssScores ? highestScore(lookup, epssScores) : null,
    };
  });

  // A merged group's primary id can change (a GHSA later joins a MAL-only group), so reuse any key the state already has.
  const keyFor = (id: string, f: Finding) => `${id}|${f.package}@${f.version}`;
  const keyOf = (f: Finding) =>
    [f.advisory.id, ...f.advisory.aliases].map((id) => keyFor(id, f)).find((key) => key in state.findings) ??
    keyFor(f.advisory.id, f);
  const observations = enriched.map(({ finding: f, kev: listed }) => {
    const facts: Facts = {
      advisory: f.advisoryFingerprint,
      // Unknown while the KEV feed is down; the state then keeps the last known value.
      kev: listed === null ? undefined : listed.length > 0,
      fixedVersion: f.fixedVersion,
      devOnly: f.devOnly,
      direct: f.direct,
    };
    return { key: keyOf(f), facts };
  });
  const { results, next } = observe(state, observations, now);
  if (!options.dryRun) await saveState(statePath, next);

  const scanned = enriched.map(({ finding: f, kev: listed, epss: score }) => {
    const key = keyOf(f);
    const { status, changed } = results.get(key) ?? { status: 'new', changed: [] };
    return { ...f, key, status, changed, kev: listed, epss: score };
  });
  const actions = plan ? groupActions(plan.plans, scanned) : [];
  const planOf = new Map(plan?.plans.map((p) => [p.id, p]) ?? []);

  return {
    schemaVersion: 1,
    scannedAt: now.toISOString(),
    project: basename(dir),
    lockfile,
    manager: graph.manager,
    workspaces: graph.roots.map((id) => id.slice('root:'.length)).filter((path) => path !== '.'),
    packageCount: index.packages().length,
    findings: scanned
      .map((f): ScanFinding => {
        const id = `${f.package}@${f.version}`;
        const packagePlan = planOf.get(id);
        const needs = actions.filter((action) => action.packages.includes(id)).map((action) => action.id);
        return { ...f, fix: packagePlan ? { kind: packagePlan.kind, actions: needs } : null };
      })
      .sort(byPriority),
    enrichment,
    fixPlan: { status: planStatus, actions, brokenPeers: plan?.brokenPeers ?? [], ...(plan ? { plans: plan.plans } : {}) },
    warnings,
  };
}

const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MODERATE: 2, LOW: 3, UNKNOWN: 4 };

/** New first, then malicious packages, then KEV-listed, then severity, then EPSS. */
function byPriority(a: ScanFinding, b: ScanFinding): number {
  const key = (f: ScanFinding) => [
    f.status === 'seen' ? 1 : 0,
    f.advisory.kind === 'malicious' ? 0 : 1,
    f.kev && f.kev.length > 0 ? 0 : 1,
    SEVERITY_RANK[f.advisory.severity],
    -(f.epss ?? 0),
  ];
  const ka = key(a);
  const kb = key(b);
  for (let i = 0; i < ka.length; i++) {
    if (ka[i] !== kb[i]) return ka[i]! - kb[i]!;
  }
  return a.advisory.id.localeCompare(b.advisory.id);
}

/**
 * The CVEs to look up in KEV and EPSS: the advisory's own, or the ones its NVD references name
 * when it has none (GHSA-9qr9-h5gf-34mp reaches CVE-2025-55182 only that way).
 */
function lookupCves(advisory: Advisory): string[] {
  return advisory.cves.length > 0 ? advisory.cves : advisory.linkedCves;
}

function highestScore(cves: readonly string[], scores: Map<string, number>): number | null {
  const known = cves.map((cve) => scores.get(cve)).filter((s): s is number => s !== undefined);
  return known.length > 0 ? Math.max(...known) : null;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
