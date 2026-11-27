import { createHash } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';
import { loadGraph } from '../match/lockfiles/load.js';
import { NEXT_BUNDLES } from '../match/vendored.js';
import type { ScanOptions, ScanResult } from '../scan.js';
import { scan as runScan } from '../scan.js';
import { DiskCache } from '../util/cache.js';
import type { Fetch, RetryOptions } from '../util/http.js';
import { HttpError } from '../util/http.js';
import { mapLimit } from '../util/pool.js';
import { fetchKev } from './enrich.js';
import type { Change } from './feed.js';
import { changesSince } from './feed.js';
import type { OsvVuln } from './osv.js';
import { OsvClient } from './osv.js';

/** What watch remembers between polls. */
export interface WatchState {
  /** The newest OSV change time already looked at. */
  cursor?: string;
  /** A hash of the KEV catalog's CVE list at the last poll. */
  kev?: string;
  /** Changed records that could not be read yet; each poll asks for them again. */
  unread?: Change[];
  /**
   * Per project directory: the lockfile scanned, its hash, when it was last scanned, and why it still
   * needs a scan when the last one failed or the project could not be read.
   */
  repos: Record<string, { lockfile: string; hash: string; scannedAt: string; pending?: string[] }>;
}

export interface WatchOptions {
  dirs: readonly string[];
  /** Where the watch state lives. */
  statePath: string;
  fetch?: Fetch;
  retry?: RetryOptions;
  cacheDir?: string;
  /** How often a project is scanned in full when nothing else asks for it. Default 24 hours. */
  fullRescanMs?: number;
  now?: () => Date;
  /** Settings for every scan (dryRun, fixPlan, lockfile...). */
  scanOptions?: Omit<ScanOptions, 'dir'>;
  /** Runs one scan. Tests pass their own. */
  scan?: (options: ScanOptions) => Promise<ScanResult>;
  /** Where to read OSV's change list. Default CHANGES_URL. */
  changesUrl?: string;
}

export interface RepoScan {
  dir: string;
  /** Why it was scanned: first scan, a lockfile change, an advisory, the KEV catalog, the daily rescan. */
  reasons: string[];
  result?: ScanResult;
  error?: string;
}

export interface Poll {
  scans: RepoScan[];
  /** How many OSV records changed since the last poll. */
  changes: number;
  warnings: string[];
}

const DAY_MS = 24 * 60 * 60 * 1000;
/** Advisory ids named per project before the rest are counted. */
const NAMED = 3;

/**
 * One poll. A project is scanned when it has not been scanned yet, when its lockfile changed, when
 * OSV changed a record that names a package it installs, when the KEV catalog changed, when its
 * last full scan is a day old, or when a scan it needed failed before. OSV's change list is read from
 * where the last poll stopped, so only new changes cost requests, and only changed records are
 * fetched. A reason to scan is never dropped: when the scan fails, or the project cannot be read,
 * the reason stays with the project until a scan succeeds. Scans update each project's own state, as
 * `scan` does, so findings show as new or updated against what was seen before.
 */
export async function pollOnce(options: WatchOptions): Promise<Poll> {
  const now = options.now?.() ?? new Date();
  const fetchFn = options.fetch ?? globalThis.fetch.bind(globalThis);
  const cache = options.cacheDir === undefined ? undefined : new DiskCache(options.cacheDir);
  const state = await loadWatchState(options.statePath);
  const repos = { ...state.repos };
  const warnings: string[] = [];
  const scans: RepoScan[] = [];
  const reasons = new Map<string, string[]>();
  const want = (dir: string, ...why: string[]) => reasons.set(dir, [...new Set([...(reasons.get(dir) ?? []), ...why])]);
  const lockfiles = new Map<string, { lockfile: string; hash: string }>();
  const installs = new Map<string, Set<string>>();
  const dirs = options.dirs.map((d) => resolve(d));

  for (const dir of dirs) {
    const seen = repos[dir];
    if (seen?.pending) want(dir, ...seen.pending);
    try {
      const lockfileOption = options.scanOptions?.lockfile;
      const { lockfile, graph } = await loadGraph(dir, lockfileOption === undefined ? {} : { lockfile: lockfileOption });
      const hash = sha256(await readFile(lockfile));
      lockfiles.set(dir, { lockfile, hash });
      const names = new Set([...graph.nodes.values()].map((node) => node.name));
      // next bundles React's server-component packages (see addNextBundles).
      if (names.has('next')) for (const name of NEXT_BUNDLES) names.add(name);
      installs.set(dir, names);
      if (!seen) want(dir, 'first scan');
      else if (seen.lockfile !== lockfile || seen.hash !== hash) want(dir, `${basename(lockfile)} changed`);
      else if (now.getTime() - Date.parse(seen.scannedAt) >= (options.fullRescanMs ?? DAY_MS)) want(dir, 'daily rescan');
    } catch (error) {
      scans.push({ dir, reasons: [], error: messageOf(error) });
      // This poll cannot tell which changes touch it, so it gets a full scan once it can be read.
      if (seen) repos[dir] = { ...seen, pending: [...new Set([...(seen.pending ?? []), 'could not be read on an earlier poll'])] };
      reasons.delete(dir);
    }
  }

  let cursor = state.cursor;
  let unread: Change[] = state.unread ?? [];
  let changed = 0;
  try {
    const { changes, newest } = await changesSince(fetchFn, state.cursor, options.changesUrl);
    changed = changes.length;
    const asked = [...new Map([...changes, ...unread].map((change) => [change.id, change])).values()];
    const osv = new OsvClient({ fetch: fetchFn, retry: options.retry, ...(cache ? { cache } : {}) });
    for (const change of asked) osv.noteModified(change.id, change.modified);
    const records = await mapLimit(asked, 8, (change) =>
      osv.getVuln(change.id).then(
        (record): OsvVuln | 'gone' | undefined => record,
        // A record OSV no longer has is gone; any other failure is asked again next poll.
        (error: unknown) => (error instanceof HttpError && error.status === 404 ? 'gone' : undefined),
      ),
    );
    unread = asked.filter((_, i) => records[i] === undefined);
    const hits = new Map<string, string[]>();
    for (const record of records) {
      if (record === undefined || record === 'gone') continue;
      const names = new Set((record.affected ?? []).filter((a) => a.package?.ecosystem === 'npm').map((a) => a.package!.name));
      for (const [dir, installed] of installs) {
        const touched = [...names].filter((name) => installed.has(name));
        if (touched.length > 0) hits.set(dir, [...(hits.get(dir) ?? []), `${record.id} (${touched.join(', ')})`]);
      }
    }
    for (const [dir, ids] of hits) {
      const more = ids.length > NAMED ? ` and ${ids.length - NAMED} more` : '';
      want(dir, `${ids.length === 1 ? 'advisory' : 'advisories'} ${ids.slice(0, NAMED).join(', ')}${more}`);
    }
    if (unread.length > 0) {
      warnings.push(`${unread.length} changed OSV ${unread.length === 1 ? 'record' : 'records'} could not be read; the next poll asks again`);
    }
    cursor = newest ?? cursor;
  } catch (error) {
    warnings.push(`OSV change list unavailable: ${messageOf(error)}`);
  }

  let kev = state.kev;
  try {
    const catalog = await fetchKev(fetchFn, options.retry, cache);
    kev = sha256([...catalog].sort().join('\n'));
    if (state.kev !== undefined && state.kev !== kev) for (const dir of installs.keys()) want(dir, 'KEV catalog changed');
  } catch (error) {
    warnings.push(`KEV unavailable: ${messageOf(error)}`);
  }

  const scan = options.scan ?? runScan;
  for (const [dir, why] of reasons) {
    try {
      const result = await scan({
        ...options.scanOptions,
        dir,
        ...(options.fetch ? { fetch: options.fetch } : {}),
        ...(options.retry ? { retry: options.retry } : {}),
        ...(options.cacheDir === undefined ? {} : { cacheDir: options.cacheDir }),
      });
      const { lockfile, hash } = lockfiles.get(dir)!;
      repos[dir] = { lockfile, hash, scannedAt: now.toISOString() };
      scans.push({ dir, reasons: why, result });
    } catch (error) {
      // Keep the reasons, so the next poll scans it again.
      const seen = repos[dir];
      if (seen) repos[dir] = { ...seen, pending: why };
      scans.push({ dir, reasons: why, error: messageOf(error) });
    }
  }
  await saveWatchState(options.statePath, {
    ...(cursor === undefined ? {} : { cursor }),
    ...(kev === undefined ? {} : { kev }),
    ...(unread.length > 0 ? { unread } : {}),
    repos,
  });
  return { scans, changes: changed, warnings };
}

export async function loadWatchState(path: string): Promise<WatchState> {
  try {
    const state = JSON.parse(await readFile(path, 'utf8')) as WatchState;
    return { ...state, repos: state.repos ?? {} };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { repos: {} };
    throw new Error(`Could not read the watch state ${path}: ${messageOf(error)}`, { cause: error });
  }
}

async function saveWatchState(path: string, state: WatchState): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temp = `${path}.${process.pid}.tmp`;
  await writeFile(temp, `${JSON.stringify(state, null, 2)}\n`);
  await rename(temp, path);
}

function sha256(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
