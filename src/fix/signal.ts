import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';

/**
 * Whether the GitHub Action's fix job has anything to do. A run is three jobs, and GitHub bills each
 * at least a minute, so a scan that finds nothing new tells the workflow to skip the fix and publish
 * jobs. The scan job decides from what it saw itself: it never reads what the fix job saved (that job
 * runs the project's code; see action.yml).
 *
 * The fix job runs when:
 * - a malicious package is in the lockfile (it makes the malware PR, and fails the run until it is out);
 * - the findings a fix would take on, or the dependency files, differ from the last time the fix job
 *   was sent;
 * - a day has passed since then (a fix that failed, or a PR a person closed, gets another try).
 * It is skipped when there is nothing a fix PR would cover.
 */

export const SIGNAL_FILE = 'fix-signal.json';
const RETRY_MS = 24 * 60 * 60 * 1000;

const signalSchema = z.object({ fingerprint: z.string(), at: z.string() });
export type FixSignal = z.infer<typeof signalSchema>;

export interface FixDecision {
  fix: boolean;
  reason: string;
  /** What to save for the next scan; null clears it. */
  next: FixSignal | null;
}

export function decideFix(work: { keys: readonly string[]; malicious: boolean }, dependencies: string, previous: FixSignal | null, now = new Date()): FixDecision {
  if (work.malicious) return { fix: true, reason: 'a malicious package is in the lockfile', next: previous };
  if (work.keys.length === 0) return { fix: false, reason: 'nothing a fix PR would cover', next: null };
  const fingerprint = createHash('sha256').update(JSON.stringify([...work.keys].sort())).update('\n').update(dependencies).digest('hex');
  const sent = previous?.fingerprint === fingerprint ? Date.parse(previous.at) : NaN;
  if (now.getTime() - sent < RETRY_MS) {
    return { fix: false, reason: `the same ${work.keys.length === 1 ? 'finding' : `${work.keys.length} findings`} and dependency files as when the fix job last ran (${previous!.at}); it runs again a day after that, or when they change`, next: previous };
  }
  return { fix: true, reason: previous?.fingerprint === fingerprint ? 'a day since the fix job last ran for these findings' : `${work.keys.length === 1 ? 'a finding' : `${work.keys.length} findings`} for a fix PR, new or changed since the fix job last ran`, next: { fingerprint, at: now.toISOString() } };
}

/** The dependency files a fix works from: the lockfile and the root manifest, as they are now. */
export async function dependencyFiles(dir: string, lockfile: string): Promise<string> {
  const read = (path: string) => readFile(path, 'utf8').catch(() => '');
  return `${await read(join(dir, 'package.json'))}\n${await read(lockfile.startsWith('/') ? lockfile : join(dir, lockfile))}`;
}

/** The last time the fix job was sent; null when never, or when the file does not read (the fix job then runs). */
export async function readSignal(stateDir: string): Promise<FixSignal | null> {
  try {
    const parsed = signalSchema.safeParse(JSON.parse(await readFile(join(stateDir, SIGNAL_FILE), 'utf8')));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

export async function saveSignal(stateDir: string, signal: FixSignal | null): Promise<void> {
  await writeFile(join(stateDir, SIGNAL_FILE), `${JSON.stringify(signal)}\n`);
}
