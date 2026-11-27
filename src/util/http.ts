/** JSON over HTTP for the OSV, KEV and EPSS clients: a time limit per attempt, retries, readable errors. */

export type Fetch = typeof fetch;

export interface RetryOptions {
  /** Attempts after the first, on HTTP 429 and 5xx, network errors and timeouts. Default 3. */
  retries?: number;
  /** Wait before the first retry; each later wait doubles. Default 1 s. */
  baseDelayMs?: number;
  /** Longest single wait, which also caps a server's Retry-After. Default 30 s. */
  maxDelayMs?: number;
  /** Tests pass one that returns at once. */
  sleep?: (ms: number) => Promise<void>;
}

export interface JsonRequest {
  /** Names the request in errors, such as "OSV POST /v1/querybatch". */
  label: string;
  url: string;
  method?: 'GET' | 'POST';
  /** Sent as JSON. */
  body?: unknown;
  /** Extra request headers, such as `accept`. */
  headers?: Record<string, string>;
  /** Time limit for each attempt, reading the body included. Default 30 s. */
  timeoutMs?: number;
}

/** A request that failed for good. `status` is the last HTTP status, or undefined when no answer came (a network error or a timeout). */
export class HttpError extends Error {
  constructor(
    message: string,
    readonly status: number | undefined,
  ) {
    super(message);
    this.name = 'HttpError';
  }
}

const DEFAULT_TIMEOUT_MS = 30_000;
/** How much of a failed response's body an error message quotes. */
const SNIPPET_CHARS = 200;

const wait = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

type Attempt =
  | { ok: true; text: string; etag?: string; notModified: boolean }
  | { ok: false; status?: number; reason: string; retryable: boolean; retryAfterMs?: number };

/** Sends the request and parses the JSON answer, retrying what may pass (429, 5xx, network errors, timeouts). */
export async function requestJson<T>(fetchFn: Fetch, request: JsonRequest, retry: RetryOptions = {}): Promise<T> {
  const result = await send(fetchFn, request, retry);
  return parseJson<T>(request.label, result.text);
}

/** requestJson for an answer that is not JSON (a Slack webhook's `ok`, a web page): the body as text. */
export async function requestText(fetchFn: Fetch, request: JsonRequest, retry: RetryOptions = {}): Promise<string> {
  return (await send(fetchFn, request, retry)).text;
}

/** A response body kept with its ETag, so the next request can ask whether it changed. */
export interface Tagged<T> {
  etag?: string;
  body: T;
}

/**
 * requestJson for a resource fetched before: sends `cached`'s ETag as If-None-Match and, when the
 * server answers 304 Not Modified, returns `cached` as it is. Otherwise the new body and ETag.
 */
export async function requestJsonConditional<T>(
  fetchFn: Fetch,
  request: JsonRequest,
  retry: RetryOptions = {},
  cached?: Tagged<T>,
): Promise<Tagged<T>> {
  const conditional = cached?.etag ? { ...request, headers: { ...request.headers, 'if-none-match': cached.etag } } : request;
  const result = await send(fetchFn, conditional, retry);
  if (result.notModified && cached) return cached;
  const body = parseJson<T>(request.label, result.text);
  return result.etag ? { etag: result.etag, body } : { body };
}

async function send(fetchFn: Fetch, request: JsonRequest, retry: RetryOptions): Promise<Extract<Attempt, { ok: true }>> {
  const { retries = 3, baseDelayMs = 1000, maxDelayMs = 30_000, sleep = wait } = retry;
  const init: RequestInit = { method: request.method ?? 'GET' };
  const headers: Record<string, string> = { ...request.headers };
  if (request.body !== undefined) {
    headers['content-type'] = 'application/json';
    init.body = JSON.stringify(request.body);
  }
  if (Object.keys(headers).length > 0) init.headers = headers;
  for (let attempts = 1; ; attempts++) {
    const result = await attemptOnce(fetchFn, request.url, init, request.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    if (result.ok) return result;
    if (!result.retryable || attempts > retries) throw new HttpError(failureMessage(request.label, result, attempts), result.status);
    await sleep(Math.min(maxDelayMs, result.retryAfterMs ?? baseDelayMs * 2 ** (attempts - 1)));
  }
}

async function attemptOnce(fetchFn: Fetch, url: string, init: RequestInit, timeoutMs: number): Promise<Attempt> {
  try {
    const response = await fetchFn(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    const text = await response.text();
    const etag = response.headers.get('etag') ?? undefined;
    if (response.status === 304) return { ok: true, text, notModified: true, ...(etag ? { etag } : {}) };
    if (response.ok) return { ok: true, text, notModified: false, ...(etag ? { etag } : {}) };
    return {
      ok: false,
      status: response.status,
      reason: snippet(text),
      retryable: response.status === 429 || response.status >= 500,
      retryAfterMs: retryAfterMs(response.headers.get('retry-after')),
    };
  } catch (error) {
    return { ok: false, reason: describeError(error, timeoutMs), retryable: true };
  }
}

function failureMessage(label: string, failure: Extract<Attempt, { ok: false }>, attempts: number): string {
  const after = attempts > 1 ? ` after ${attempts} attempts` : '';
  if (failure.status === undefined) return `${label} failed${after}: ${failure.reason}`;
  return `${label} failed with HTTP ${failure.status}${after}${failure.reason ? `: ${failure.reason}` : ''}`;
}

function parseJson<T>(label: string, text: string): T {
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error(`${label} returned a body that is not JSON: ${snippet(text)}`);
  }
}

/** Retry-After in seconds or as an HTTP date, in milliseconds from now. */
function retryAfterMs(header: string | null): number | undefined {
  if (header === null) return undefined;
  const value = header.trim();
  if (/^\d+$/.test(value)) return Number(value) * 1000;
  const at = Date.parse(value);
  return Number.isNaN(at) ? undefined : Math.max(0, at - Date.now());
}

function describeError(error: unknown, timeoutMs: number): string {
  if (error instanceof Error && (error.name === 'TimeoutError' || error.name === 'AbortError')) {
    return `timed out after ${timeoutMs % 1000 === 0 ? `${timeoutMs / 1000} s` : `${timeoutMs} ms`}`;
  }
  if (!(error instanceof Error)) return String(error);
  const cause = error.cause instanceof Error ? ` (${error.cause.message})` : '';
  return `${error.message}${cause}`;
}

function snippet(text: string): string {
  return text.replace(/\s+/g, ' ').trim().slice(0, SNIPPET_CHARS);
}
