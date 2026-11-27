import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { ScanResult } from '../scan.js';
import type { FixAction } from './actions.js';
import type { RefreshRun } from './commands.js';
import { refreshRuns, unlockYarnEntries } from './commands.js';
import { applyBump, applyOverride, applyRemove } from './manifest.js';
import type { FixStep } from './plan.js';
import { lockfileUpdate, managerCommand, managerEnv, pnpmMajor, QUIET, runTool, tail } from './pm.js';
import { changeOf } from './versions.js';

type Refresh = Extract<FixStep, { kind: 'refresh' }>;

/** The kinds of action plain code can apply. The rest (no fix yet, a bundled copy, unknown) need a person or a new release. */
export const APPLICABLE = new Set(['refresh', 'bump', 'override', 'remove']);

export interface ApplyLog {
  /** Manifest edits, one line each: `package.json: zod -> 4.1.12`. */
  edits: string[];
  /** Package manager commands run, in order. */
  commands: string[];
  /** Refresh passes run (a refresh can leave a package behind when others move with it, so it repeats). */
  passes: number;
}

export interface ApplyOptions {
  manager: string;
  workspaces: boolean;
  /** npm refuses a lockfile whose peer ranges are already broken without this (milestone 1 reports them). */
  legacyPeerDeps: boolean;
  /** Scans the folder again; used to repeat refreshes until the packages they claim to fix are gone. */
  rescan: () => Promise<ScanResult>;
  timeoutMs?: number;
}

/** A package manager command failed; `output` is the end of what it printed. */
export class ApplyError extends Error {
  constructor(
    message: string,
    readonly output: string,
  ) {
    super(message);
    this.name = 'ApplyError';
  }
}

/**
 * Applies the fix plan's actions to a checkout: package.json and catalog edits for bumps, overrides
 * and removals, then a lockfile update, then the refreshes (repeated up to three times while a
 * package they claim to fix is still installed), then `pnpm dedupe` when a bump asked for it.
 */
export async function applyActions(dir: string, actions: readonly FixAction[], options: ApplyOptions): Promise<ApplyLog> {
  const log: ApplyLog = { edits: [], commands: [], passes: 0 };
  const steps = actions.filter((a) => APPLICABLE.has(a.kind)).flatMap((a) => a.steps);
  const pnpmVersion = options.manager === 'pnpm' && steps.some((s) => s.kind === 'override') ? await pnpmMajor(dir) : null;
  for (const step of steps) {
    if (step.kind === 'bump') log.edits.push(await applyBump(dir, step, options.manager));
    else if (step.kind === 'override') log.edits.push(await applyOverride(dir, step, options.manager, pnpmVersion));
    else if (step.kind === 'remove') log.edits.push(await applyRemove(dir, step));
  }
  const pm = await managerCommand(options.manager, dir);
  const legacy = options.manager === 'npm' && options.legacyPeerDeps ? ['--legacy-peer-deps'] : [];
  const run = async (args: readonly string[]) => {
    const argv = [...pm, ...args, ...legacy];
    log.commands.push(argv.join(' '));
    const result = await runTool(argv, { cwd: dir, env: managerEnv(), timeoutMs: options.timeoutMs ?? 15 * 60_000 });
    if (result.code !== 0) throw new ApplyError(`${argv.join(' ')} failed${result.timedOut ? ' (timed out)' : ''}`, tail(result.output));
  };
  if (log.edits.length > 0) await run(lockfileUpdate(options.manager));

  const refreshes = steps.filter((s): s is Refresh => s.kind === 'refresh');
  const runs = refreshRuns(refreshes, options.manager, options.workspaces);
  const claimed = new Set(refreshes.map((s) => `${s.package}@${s.from}`));
  let left = claimed;
  for (let pass = 0; runs.length > 0 && pass < 3; pass++) {
    for (const r of runs) await applyRun(r, dir, run, options.manager);
    log.passes = pass + 1;
    const after = await options.rescan();
    const still = new Set(after.findings.map((f) => `${f.package}@${f.version}`).filter((id) => claimed.has(id)));
    // Another pass helps when the first moved some (a package that moved with others); not when it moved none.
    const stuck = still.size >= left.size;
    left = still;
    if (still.size === 0 || stuck) break;
  }
  // pnpm update moves the copy a package.json lists and keeps the copies under other parents at the
  // old version (lodash in shadcn/ui). An override scoped to that version moves just those copies.
  if (options.manager === 'pnpm' && left.size > 0) {
    const major = await pnpmMajor(dir);
    const behind = refreshes.filter((s, i, all) => left.has(`${s.package}@${s.from}`) && all.findIndex((t) => t.package === s.package && t.from === s.from) === i);
    for (const s of behind) {
      log.edits.push(`${await applyOverride(dir, { kind: 'override', package: s.package, from: s.from, to: s.to, change: changeOf(s.from, s.to), parents: [] }, 'pnpm', major)} (pnpm update left this copy behind)`);
    }
    await run(lockfileUpdate('pnpm'));
  }
  if (options.manager === 'pnpm' && steps.some((s) => s.kind === 'bump' && s.dedupe)) await run(['dedupe', ...QUIET.pnpm!]);
  return log;
}

async function applyRun(r: RefreshRun, dir: string, run: (args: readonly string[]) => Promise<void>, manager: string): Promise<void> {
  if (r.kind === 'unlock') {
    const lockfile = join(dir, 'yarn.lock');
    await writeFile(lockfile, unlockYarnEntries(await readFile(lockfile, 'utf8'), r.packages));
    return;
  }
  // The program is the project's package manager, which `run` puts in front (with yarn's own path).
  await run([...r.argv.slice(1), ...(QUIET[manager] ?? []).filter((flag) => !r.argv.includes(flag))]);
}
