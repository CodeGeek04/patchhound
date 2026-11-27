import type { DiskCache } from '../util/cache.js';
import type { Fetch, RetryOptions } from '../util/http.js';
import { requestJson } from '../util/http.js';

import { isAfter } from './feed.js';

export type { Fetch } from '../util/http.js';

export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

export interface OsvRange {
  type: string;
  events: OsvEvent[];
}

export interface OsvAffected {
  package?: { ecosystem: string; name: string };
  ranges?: OsvRange[];
  versions?: string[];
}

/** The parts of an OSV record (https://ossf.github.io/osv-schema/) this project reads. */
export interface OsvVuln {
  id: string;
  modified: string;
  published?: string;
  withdrawn?: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  related?: string[];
  references?: { type: string; url: string }[];
  severity?: { type: string; score: string }[];
  affected?: OsvAffected[];
  /** GitHub's fields. `cwe_ids` holds CWE-506 (embedded malicious code) for malware GHSAs. */
  database_specific?: { severity?: string; cwe_ids?: string[] };
}

export interface PackageVersion {
  name: string;
  version: string;
}

interface QueryResult {
  vulns?: { id: string; modified?: string }[];
  next_page_token?: string;
}

interface PackageQueryResult {
  vulns?: OsvVuln[];
  next_page_token?: string;
}

const BATCH_SIZE = 1000;

/** Client for the OSV.dev API (https://google.github.io/osv.dev/api/), npm ecosystem only. */
export class OsvClient {
  private readonly fetch: Fetch;
  private readonly baseUrl: string;
  private readonly retry: RetryOptions;
  private readonly records = new Map<string, Promise<OsvVuln>>();
  private readonly byPackage = new Map<string, Promise<OsvVuln[]>>();
  /** When each record last changed, as a query or the change list reported it. */
  private readonly modified = new Map<string, string>();
  private readonly cache: DiskCache | undefined;

  /**
   * `retry` tunes the retries of every request (see requestJson); tests pass a sleep that returns at
   * once. With a `cache`, a record is read from it while its `modified` time is the one OSV reports.
   */
  constructor(options: { fetch?: Fetch; baseUrl?: string; retry?: RetryOptions; cache?: DiskCache } = {}) {
    this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.baseUrl = options.baseUrl ?? 'https://api.osv.dev';
    this.retry = options.retry ?? {};
    this.cache = options.cache;
  }

  /** Records when a record last changed (from OSV's change list), so getVuln can trust a cached copy that is as new. */
  noteModified(id: string, modified: string): void {
    this.modified.set(id, modified);
  }

  /** Advisory ids affecting each package version, in input order. */
  async queryBatch(packages: readonly PackageVersion[]): Promise<string[][]> {
    const results: string[][] = [];
    for (let start = 0; start < packages.length; start += BATCH_SIZE) {
      const chunk = packages.slice(start, start + BATCH_SIZE);
      const response = await this.post<{ results?: unknown }>('/v1/querybatch', { queries: chunk.map(toQuery) });
      const answers = checkedResults(response.results, chunk.length);
      for (const [i, pkg] of chunk.entries()) {
        const first = answers[i]!;
        const ids = this.noted(first.vulns);
        let token = first.next_page_token;
        while (token) {
          const page = await this.post<QueryResult>('/v1/query', { ...toQuery(pkg), page_token: token });
          ids.push(...this.noted(page.vulns));
          token = page.next_page_token;
        }
        results.push(ids);
      }
    }
    return results;
  }

  /** The full advisory record. Each id is fetched once per client; a failed fetch is not kept. */
  getVuln(id: string): Promise<OsvVuln> {
    let record = this.records.get(id);
    if (!record) {
      const pending = this.load(id);
      pending.catch(() => {
        if (this.records.get(id) === pending) this.records.delete(id);
      });
      this.records.set(id, pending);
      record = pending;
    }
    return record;
  }

  private async load(id: string): Promise<OsvVuln> {
    const known = this.modified.get(id);
    if (this.cache && known) {
      const hit = await this.cache.get<OsvVuln>(`osv/${id}`);
      // Compared to the nanosecond: Date.parse keeps only milliseconds.
      if (hit && !isAfter(hit.modified, known) && !isAfter(known, hit.modified)) return hit;
    }
    const record = await this.request<OsvVuln>('GET', `/v1/vulns/${encodeURIComponent(id)}`);
    await this.cache?.set(`osv/${id}`, record);
    return record;
  }

  private noted(vulns: QueryResult['vulns']): string[] {
    for (const vuln of vulns ?? []) if (vuln.modified) this.modified.set(vuln.id, vuln.modified);
    return (vulns ?? []).map((vuln) => vuln.id);
  }

  /** Every advisory OSV has for a package, whatever the version, as full records. Asked once per client. */
  packageVulns(name: string): Promise<OsvVuln[]> {
    let pending = this.byPackage.get(name);
    if (!pending) {
      pending = (async () => {
        const vulns: OsvVuln[] = [];
        let token: string | undefined;
        do {
          const page = await this.post<PackageQueryResult>('/v1/query', {
            package: { name, ecosystem: 'npm' },
            ...(token === undefined ? {} : { page_token: token }),
          });
          vulns.push(...(page.vulns ?? []));
          token = page.next_page_token;
        } while (token);
        return vulns;
      })();
      pending.catch(() => this.byPackage.delete(name));
      this.byPackage.set(name, pending);
    }
    return pending;
  }

  private post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>('POST', path, body);
  }

  private request<T>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<T> {
    return requestJson<T>(this.fetch, { label: `OSV ${method} ${path}`, url: `${this.baseUrl}${path}`, method, body }, this.retry);
  }
}

/** querybatch answers one result per query, in order. Anything else would hide advisories, so it is an error. */
function checkedResults(results: unknown, asked: number): QueryResult[] {
  if (!Array.isArray(results)) throw new Error(`OSV querybatch returned no results list for ${asked} queries`);
  if (results.length !== asked) throw new Error(`OSV querybatch returned ${results.length} results for ${asked} queries`);
  if (results.some((r) => typeof r !== 'object' || r === null)) throw new Error('OSV querybatch returned a result that is not an object');
  return results as QueryResult[];
}

function toQuery(pkg: PackageVersion) {
  return { package: { name: pkg.name, ecosystem: 'npm' }, version: pkg.version };
}
