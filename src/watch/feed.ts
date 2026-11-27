import type { Fetch } from '../util/http.js';
import { HttpError } from '../util/http.js';

/** OSV's list of every npm record and when it last changed: `<modified>,<id>` lines, newest first. */
export const CHANGES_URL = 'https://osv-vulnerabilities.storage.googleapis.com/npm/modified_id.csv';

export interface Change {
  id: string;
  modified: string;
}

export interface Changes {
  /** Records changed after `since`, newest first. Empty on a first poll. */
  changes: Change[];
  /** The newest change time in the list: the cursor for the next poll. Undefined for an empty list. */
  newest: string | undefined;
}

/**
 * The npm records OSV changed after `since`. The list holds every record ever (over 8 MB), newest
 * first, so it is read as a stream and dropped at the first line no newer than `since`: a poll reads
 * only the lines that are new. Without `since` (a first poll) nothing counts as changed, and only
 * the newest time is read, as the cursor to start from.
 */
export async function changesSince(fetchFn: Fetch, since: string | undefined, url = CHANGES_URL, timeoutMs = 60_000): Promise<Changes> {
  const response = await fetchFn(url, { signal: AbortSignal.timeout(timeoutMs) });
  if (!response.ok || !response.body) {
    throw new HttpError(`OSV change list GET failed with HTTP ${response.status}`, response.status);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const changes: Change[] = [];
  let newest: string | undefined;
  let rest = '';
  try {
    for (;;) {
      const { done, value } = await reader.read();
      rest += done ? decoder.decode() : decoder.decode(value, { stream: true });
      const lines = rest.split('\n');
      rest = done ? '' : lines.pop()!;
      for (const line of lines) {
        const comma = line.indexOf(',');
        if (comma === -1) continue;
        const modified = line.slice(0, comma).trim();
        const id = line.slice(comma + 1).trim();
        newest ??= modified;
        if (since === undefined || !isAfter(modified, since)) return { changes, newest };
        changes.push({ id, modified });
      }
      if (done) return { changes, newest };
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
}

/**
 * True when timestamp `a` is later than `b`. The list writes up to nine digits of fractional seconds
 * and drops trailing zeros (`37.65093584Z`), so both are padded before they are compared as text.
 */
export function isAfter(a: string, b: string): boolean {
  return normalize(a) > normalize(b);
}

function normalize(timestamp: string): string {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$/.exec(timestamp.trim());
  if (!match) return timestamp;
  return `${match[1]}.${(match[2] ?? '').padEnd(9, '0').slice(0, 9)}Z`;
}
