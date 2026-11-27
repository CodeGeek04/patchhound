import type { Fetch, RetryOptions } from '../util/http.js';
import type { DiskCache } from '../util/cache.js';
import type { Tagged } from '../util/http.js';
import { requestJson, requestJsonConditional } from '../util/http.js';

export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
export const EPSS_URL = 'https://api.first.org/data/v1/epss';

/** The KEV catalog is about 2 MB, so it gets longer than the usual 30 s. */
const KEV_TIMEOUT_MS = 60_000;

/** CVE ids in CISA's Known Exploited Vulnerabilities catalog. */
export async function fetchKev(fetchFn: Fetch, retry: RetryOptions = {}, cache?: DiskCache): Promise<Set<string>> {
  // With a cache, the catalog is asked for with its ETag and reused when it has not changed.
  const stored = await cache?.get<Tagged<{ vulnerabilities?: unknown }>>('kev');
  // A cached body that does not read as a catalog is asked for again, in full.
  const cached = stored && isCatalog(stored.body) ? stored : undefined;
  const answer = await requestJsonConditional<{ vulnerabilities?: unknown }>(
    fetchFn,
    { label: 'KEV download', url: KEV_URL, timeoutMs: KEV_TIMEOUT_MS },
    retry,
    cached,
  );
  if (!isCatalog(answer.body)) {
    throw new Error('KEV download returned an unexpected body: no "vulnerabilities" list with a cveID in each entry');
  }
  if (cache && answer !== cached) await cache.set('kev', answer);
  return new Set(answer.body.vulnerabilities.map((v) => v.cveID));
}

function isCatalog(body: unknown): body is { vulnerabilities: { cveID: string }[] } {
  const entries = (body as { vulnerabilities?: unknown } | null | undefined)?.vulnerabilities;
  return Array.isArray(entries) && entries.every((v) => typeof v?.cveID === 'string');
}

/** EPSS exploit probability (0 to 1) per CVE. CVEs without a score are left out. */
export async function fetchEpss(cves: readonly string[], fetchFn: Fetch, retry: RetryOptions = {}): Promise<Map<string, number>> {
  const scores = new Map<string, number>();
  const unique = [...new Set(cves)];
  for (let start = 0; start < unique.length; start += 50) {
    const batch = unique.slice(start, start + 50);
    const body = await requestJson<{ total?: number; data?: { cve: string; epss: string }[] }>(
      fetchFn,
      { label: 'EPSS lookup', url: `${EPSS_URL}?cve=${batch.join(',')}` },
      retry,
    );
    if (!Array.isArray(body?.data)) throw new Error('EPSS lookup returned an unexpected body: no "data" list');
    // EPSS pages its answer (100 rows by default). A partial page would leave scores out without saying so.
    if (typeof body.total === 'number' && body.total > body.data.length) {
      throw new Error(`EPSS lookup returned ${body.data.length} of ${body.total} rows`);
    }
    for (const row of body.data) scores.set(row.cve, Number.parseFloat(row.epss));
  }
  return scores;
}
