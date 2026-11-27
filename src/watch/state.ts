import { randomBytes } from 'node:crypto';
import { access, constants, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';

export type FindingStatus = 'new' | 'updated' | 'seen';

/** What triage cares about for one finding. A change to any of them makes the finding `updated`. */
export interface Facts {
  /** The advisory's content fingerprint (see advisoryFingerprint), which ignores OSV's `modified`. */
  advisory: string;
  /** Whether a CVE of the advisory is in KEV. Undefined when the KEV feed could not be read. */
  kev: boolean | undefined;
  fixedVersion: string | null;
  devOnly: boolean;
  direct: boolean;
}

export type FactName = keyof Facts;

const FACT_NAMES: readonly FactName[] = ['advisory', 'kev', 'fixedVersion', 'devOnly', 'direct'];

export interface Observation {
  key: string;
  facts: Facts;
}

export interface Comparison {
  status: FindingStatus;
  /** The facts that differ from last time, for an `updated` finding. Empty otherwise. */
  changed: FactName[];
}

/** As saved: `kev` is left out while it has never been known for this finding. */
export type SavedFacts = Omit<Facts, 'kev'> & { kev?: boolean };

export interface SeenEntry {
  firstSeen: string;
  lastSeen: string;
  facts: SavedFacts;
}

export interface SeenState {
  version: 2;
  findings: Record<string, SeenEntry>;
}

/** How long a finding that is no longer observed is remembered, so a run where OSV misses it does not make it new again. */
export const RETAIN_MS = 7 * 24 * 60 * 60 * 1000;

export const emptyState = (): SeenState => ({ version: 2, findings: {} });

export async function loadState(path: string): Promise<SeenState> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (error) {
    // ENOTDIR: a parent of the path is a file, so there is no state to read (saving will say so).
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') return emptyState();
    throw new Error(`Could not read state file ${path}: ${messageOf(error)}`);
  }
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch (error) {
    throw new Error(`State file ${path} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (isRecord(data) && data.version !== 2) {
    throw new Error(`State file ${path} has version ${JSON.stringify(data.version)}; this bulwark reads version 2`);
  }
  const problem = stateProblem(data);
  if (problem) throw new Error(`State file ${path} is malformed: ${problem}`);
  return data as SeenState;
}

/**
 * Makes sure the folder for the state file exists and can be written, so a bad location fails
 * before any network request. With `gitignore`, a new folder ignores itself, so state is never committed by accident.
 */
export async function prepareStateDir(path: string, options: { gitignore: boolean }): Promise<void> {
  const dir = dirname(path);
  try {
    await mkdir(dir, { recursive: true });
    await access(dir, constants.W_OK);
    if (options.gitignore) {
      // 'wx' leaves an existing .gitignore alone.
      await writeFile(join(dir, '.gitignore'), '*\n', { flag: 'wx' }).catch((error: unknown) => {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      });
    }
  } catch (error) {
    throw new Error(`Could not save state file ${path}: ${messageOf(error)}`);
  }
}

/** Writes a temp file next to `path`, then renames it over `path`, so a crash never leaves half a file. */
export async function saveState(path: string, state: SeenState): Promise<void> {
  const dir = dirname(path);
  const temp = join(dir, `.${basename(path)}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`);
  try {
    await mkdir(dir, { recursive: true });
    await writeFile(temp, `${JSON.stringify(state, null, 2)}\n`);
    await rename(temp, path);
  } catch (error) {
    await rm(temp, { force: true });
    throw new Error(`Could not save state file ${path}: ${messageOf(error)}`);
  }
}

/**
 * Labels each observation new, updated (naming the facts that changed) or seen, and returns the
 * state to save next. A fact that is unknown this time (undefined) keeps its last value and is
 * not a change. Keys not observed this time are kept until they have gone unseen for RETAIN_MS.
 */
export function observe(
  state: SeenState,
  observations: readonly Observation[],
  now: Date,
): { results: Map<string, Comparison>; next: SeenState } {
  const results = new Map<string, Comparison>();
  const next = emptyState();
  const stamp = now.toISOString();
  for (const { key, facts } of observations) {
    const before = state.findings[key];
    const saved: SavedFacts = { ...facts, kev: facts.kev ?? before?.facts.kev };
    if (saved.kev === undefined) delete saved.kev;
    if (!before) {
      results.set(key, { status: 'new', changed: [] });
    } else {
      const changed = FACT_NAMES.filter((name) => {
        if (facts[name] === undefined || facts[name] === before.facts[name]) return false;
        // A KEV status that was never known turning out to be "not listed" is not news.
        return !(name === 'kev' && before.facts.kev === undefined && facts.kev === false);
      });
      results.set(key, { status: changed.length > 0 ? 'updated' : 'seen', changed });
    }
    next.findings[key] = { firstSeen: before?.firstSeen ?? stamp, lastSeen: stamp, facts: saved };
  }
  for (const [key, entry] of Object.entries(state.findings)) {
    if (key in next.findings) continue;
    if (now.getTime() - Date.parse(entry.lastSeen) < RETAIN_MS) next.findings[key] = entry;
  }
  return { results, next };
}

function stateProblem(data: unknown): string | undefined {
  if (!isRecord(data)) return 'not an object';
  if (!isRecord(data.findings)) return '"findings" is not an object';
  for (const [key, entry] of Object.entries(data.findings)) {
    const problem = entryProblem(entry);
    if (problem) return `findings[${JSON.stringify(key)}]${problem}`;
  }
  return undefined;
}

function entryProblem(entry: unknown): string | undefined {
  if (!isRecord(entry)) return ' is not an object';
  if (typeof entry.firstSeen !== 'string') return '.firstSeen is not a string';
  if (typeof entry.lastSeen !== 'string' || Number.isNaN(Date.parse(entry.lastSeen))) return '.lastSeen is not a date';
  const facts = entry.facts;
  if (!isRecord(facts)) return '.facts is not an object';
  if (typeof facts.advisory !== 'string') return '.facts.advisory is not a string';
  if (facts.kev !== undefined && typeof facts.kev !== 'boolean') return '.facts.kev is not a boolean';
  if (facts.fixedVersion !== null && typeof facts.fixedVersion !== 'string') return '.facts.fixedVersion is not a string or null';
  if (typeof facts.devOnly !== 'boolean') return '.facts.devOnly is not a boolean';
  if (typeof facts.direct !== 'boolean') return '.facts.direct is not a boolean';
  return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
