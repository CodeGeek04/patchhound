import type { DiskCache } from '../util/cache.js';
import type { Fetch, RetryOptions, Tagged } from '../util/http.js';
import { HttpError, requestJsonConditional } from '../util/http.js';

/** One version in the registry's abbreviated metadata: what an installer needs to resolve it. */
export interface PackumentVersion {
  version: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  /** The deprecation message, on deprecated versions. */
  deprecated?: string;
}

/** A package's abbreviated metadata ("corgi" document): every published version with its dependency ranges. */
export interface Packument {
  name: string;
  'dist-tags'?: Record<string, string>;
  versions: Record<string, PackumentVersion>;
}

/**
 * Client for the npm registry's abbreviated package metadata, one cached request per package. Once
 * the registry itself fails (no answer, a timeout, HTTP 429 or 5xx after the retries), every later
 * call fails at once with that error: a scan where the registry is blocked would otherwise wait out
 * the timeouts and retries once per package.
 */
export class RegistryClient {
  private readonly fetch: Fetch;
  private readonly baseUrl: string;
  private readonly retry: RetryOptions;
  private readonly documents = new Map<string, Promise<Packument>>();
  private outage: HttpError | undefined;
  private readonly cache: DiskCache | undefined;

  /** With a `cache`, a document read before is asked for again with its ETag and reused on 304 Not Modified. */
  constructor(options: { fetch?: Fetch; baseUrl?: string; retry?: RetryOptions; cache?: DiskCache } = {}) {
    this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.baseUrl = (options.baseUrl ?? 'https://registry.npmjs.org').replace(/\/+$/, '');
    this.retry = options.retry ?? {};
    this.cache = options.cache;
  }

  /**
   * The package's metadata. A request the registry refused for this package alone (such as a 404
   * for a private package) is not cached, so a later call tries again.
   */
  packument(name: string): Promise<Packument> {
    if (this.outage) {
      return Promise.reject(new HttpError(`npm registry GET ${name} not sent: the registry failed earlier (${this.outage.message})`, this.outage.status));
    }
    const cached = this.documents.get(name);
    if (cached) return cached;
    const request = this.load(name);
    this.documents.set(name, request);
    request.catch((error: unknown) => {
      this.documents.delete(name);
      if (isOutage(error)) this.outage ??= error;
    });
    return request;
  }

  /** The error that stopped this client, when the registry itself failed. */
  get failure(): string | undefined {
    return this.outage?.message;
  }

  private async load(name: string): Promise<Packument> {
    // A scoped name keeps its @ and encodes the slash: @sentry/nextjs -> @sentry%2fnextjs.
    const url = `${this.baseUrl}/${name.replace('/', '%2f')}`;
    const key = `npm/${new URL(this.baseUrl).host}/${name}`;
    const stored = await this.cache?.get<Tagged<Packument>>(key);
    const cached = stored && hasVersions(stored.body) ? stored : undefined;
    const answer = await requestJsonConditional<Packument>(
      this.fetch,
      // Full documents of big packages run to hundreds of MB; the abbreviated one has what resolving needs.
      { label: `npm registry GET ${name}`, url, headers: { accept: 'application/vnd.npm.install-v1+json' }, timeoutMs: 60_000 },
      this.retry,
      cached,
    );
    if (!hasVersions(answer.body)) throw new Error(`npm registry GET ${name} returned no versions`);
    if (this.cache && answer !== cached) await this.cache.set(key, answer);
    return answer.body;
  }
}

function hasVersions(doc: unknown): doc is Packument {
  return typeof doc === 'object' && doc !== null && typeof (doc as Packument).versions === 'object' && (doc as Packument).versions !== null;
}

/** True when the registry itself failed, rather than refusing one package (HTTP 4xx other than 429). */
function isOutage(error: unknown): error is HttpError {
  return error instanceof HttpError && (error.status === undefined || error.status === 429 || error.status >= 500);
}

/** True when the registry answered that it has no such package, or will not show it (HTTP 4xx other than 429). */
export function isRefused(error: unknown): boolean {
  return error instanceof HttpError && error.status !== undefined && error.status >= 400 && error.status < 500 && error.status !== 429;
}
