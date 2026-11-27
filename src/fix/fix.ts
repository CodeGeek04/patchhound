import { rm } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import type { AssessedFinding, Assessment } from '../assess.js';
import { assess, onPath } from '../assess.js';
import type { AuditRecord, FixRecord } from '../audit.js';
import { appendAudit, FIX_LOG, readAllAudit } from '../audit.js';
import type { Config } from '../config.js';
import type { ScanResult } from '../scan.js';
import { scan } from '../scan.js';
import { DiskCache } from '../util/cache.js';
import { OsvClient } from '../watch/osv.js';
import type { FixAction } from './actions.js';
import type { FixStep } from './plan.js';
import { groupActions } from './actions.js';
import type { AgentFinding, AgentRun } from './agent.js';
import { PROTECTED, runFixAgent } from './agent.js';
import type { ApplyLog } from './apply.js';
import { APPLICABLE, ApplyError, applyActions } from './apply.js';
import type { CheckResult } from './checks.js';
import { detectChecks, detectSetup, runChecks } from './checks.js';
import type { PullRequest, RepoInfo } from './git.js';
import { addWorktree, baseCommit as resolveBaseCommit, BranchTaken, changedSince, cleanUntracked, commitAll, commitAuthor, git, isDirty, openPullRequest, othersOnBranch, publishPullRequest, pullRequestState, removeWorktree, repoInfo } from './git.js';
import { writeHandoff } from './handoff.js';
import type { PrContent } from './pr-body.js';
import { noDashes, prBody, prTitle } from './pr-body.js';
import { cleanInstall, managerCommand, runTool, tail } from './pm.js';

export interface FixOptions {
  /** A git checkout of the project. */
  dir: string;
  config: Config;
  /** Push the branch and open or update the PR. Without it the work stays in a local worktree to look at. */
  pr: boolean;
  /** Work in `dir` itself, as the GitHub Action does, instead of a fresh worktree beside it. */
  inPlace?: boolean;
  /** Let Claude Code finish what plain code cannot. Default true. */
  agent?: boolean;
  cacheDir?: string;
  env?: Record<string, string | undefined>;
  /** Progress lines for the terminal. */
  log?: (line: string) => void;
  /** Redo the fix even when the open PR already covers the same findings. */
  force?: boolean;
  /**
   * Instead of pushing, hand each PR's work (a git bundle and its text) to this folder for a publish
   * job that holds the write token (see handoff.ts). Implies the bookkeeping of --pr.
   */
  handoff?: string;
  /** Tests replace these. */
  runAgent?: typeof runFixAgent;
  publish?: typeof publishPullRequest;
  prState?: typeof pullRequestState;
}

export interface FixRun {
  kind: 'fixes' | 'malware';
  branch: string;
  /** The worktree the work is in (kept when not publishing, so it can be looked at). */
  worktree: string;
  /** Findings this run set out to fix. */
  selected: string[];
  actions: string[];
  applied: ApplyLog | null;
  baseline: CheckResult[];
  after: CheckResult[];
  /** What each Claude Code session did, for the PR (a session whose work was rolled back says so). */
  agentNotes: string[];
  /** What the sessions cost, as far as known (a session stopped at the time limit reports nothing). */
  agentCostUsd: number | null;
  fixed: string[];
  remaining: string[];
  /** Findings that were not there before the changes. */
  appeared: string[];
  committed: boolean;
  pr: PullRequest | null;
  /** Why nothing was published, when nothing was. */
  note?: string;
  /** The safe updates, then the major upgrades, and what became of each. */
  phases: PhaseRecord[];
  /** Why a finding the run set out to fix was left: the major upgrade that would fix it breaks a check. */
  leftBecause: Record<string, string>;
  /** Claude Code's edits are in the branch (every check passed with them), whether or not it answered. */
  agentKept: boolean;
  /** Set when the run needs a person and the command should fail: a malicious package is left, or the project does not install. */
  attention?: string;
}

export interface PhaseRecord {
  name: 'safe' | 'major';
  actions: string[];
  /** Actions whose changes are in the branch (every check passes with them). */
  kept: string[];
  /** Actions left out because they break a check even after Claude Code, or could not be applied. */
  rolledBack: string[];
  /** Claude Code ran for this phase. */
  agent?: boolean;
}

/** Why an attempt failed: the checks it broke, or the plan that would not apply. */
interface Failure {
  ok: false;
  failing: CheckResult[];
  applyError?: string;
  /** Claude Code tried and still left it failing. */
  agent?: boolean;
}

/**
 * Tier 1: fixes a repo's findings in one branch and one PR. Plain code applies the fix plan, the
 * project's own checks (those that passed before) decide whether it worked, and Claude Code, once for
 * the whole repo, finishes what plain code could not. Malicious packages get a PR of their own first.
 */
export async function fixRepo(options: FixOptions): Promise<FixRun[]> {
  const log = options.log ?? (() => {});
  const info = await repoInfo(options.dir);
  const branches = { malware: `${options.config.fix.branch}-malware`, fixes: options.config.fix.branch } as const;
  if (Object.values(branches).includes(info.base)) throw new Error(`fix.branch must not name ${info.base}, the branch PRs go to`);
  // Both runs start from one commit (a push during triage must not move the second), so one scan and
  // one triage serve both.
  let start: string;
  let original = '';
  if (options.inPlace) {
    if (await isDirty(info.top)) throw new Error(`${info.top} has uncommitted changes; commit or stash them first`);
    original = await git(info.top, ['rev-parse', '--abbrev-ref', 'HEAD']);
    // A fix of another branch would carry that branch's commits into a PR against the base.
    if (original !== info.base && original !== 'HEAD') throw new Error(`--in-place works on ${info.base}, the branch PRs go to; this checkout is on ${original}`);
    start = await git(info.top, ['rev-parse', 'HEAD']);
    if (original === 'HEAD') {
      const tip = await git(info.top, ['rev-parse', '--verify', '--quiet', `origin/${info.base}^{commit}`]).catch(() => '');
      if (tip !== start) throw new Error(`--in-place works on ${info.base}, the branch PRs go to; this checkout is detached at another commit`);
      original = start;
    }
  } else start = await resolveBaseCommit(info.top, info.base);
  const runs: FixRun[] = [];
  let prepared: Prepared | undefined;
  for (const kind of ['malware', 'fixes'] as const) {
    let worktree = info.top;
    try {
      if (options.inPlace) await git(info.top, ['checkout', '--quiet', '--detach', start]);
      else worktree = await addWorktree(info.top, start);
      const { run, base } = await fixOne(kind, branches[kind], worktree, info, options, log, prepared);
      prepared = base;
      runs.push(run);
      // Kept only when there is work to look at and nowhere it was published.
      if (!options.inPlace && (run.pr || !run.committed)) await removeWorktree(info.top, worktree);
    } catch (error) {
      if (worktree !== info.top) await removeWorktree(info.top, worktree);
      throw error;
    } finally {
      if (options.inPlace) await git(info.top, ['checkout', '--quiet', original]).catch(() => '');
    }
  }
  return runs.filter((r) => r.selected.length > 0 || r.kind === 'fixes');
}

/** The base commit's scan and triage. */
interface Prepared {
  before: ScanResult;
  assessment: Assessment;
  baseCommit: string;
}

async function fixOne(
  kind: FixRun['kind'],
  branch: string,
  dir: string,
  info: RepoInfo,
  options: FixOptions,
  log: (line: string) => void,
  prepared?: Prepared,
): Promise<{ run: FixRun; base: Prepared }> {
  const base = prepared ?? (await prepare(dir, info, options, log));
  return { run: await (kind === 'malware' ? fixMalware : fixFrom)(kind, branch, dir, info, options, log, base), base };
}

async function prepare(dir: string, info: RepoInfo, options: FixOptions, log: (line: string) => void): Promise<Prepared> {
  const scope = info.github ? `github:${info.github.owner}/${info.github.name}` : info.top;
  const cache = options.cacheDir === undefined ? undefined : new DiskCache(options.cacheDir);
  log(`scanning and triaging ${info.base}`);
  const before = await scan({ dir, dryRun: true, ...(options.cacheDir === undefined ? {} : { cacheDir: options.cacheDir }) });
  const assessment = await assess({ dir, result: before, config: options.config, osv: new OsvClient(cache ? { cache } : {}), ...(cache ? { cache } : {}), write: false, scope, ...(options.env ? { env: options.env } : {}) });
  return { before, assessment, baseCommit: await git(dir, ['rev-parse', 'HEAD']) };
}

/** A step that moves a package across a major version, which is where checks break. */
function isMajorStep(step: FixStep): boolean {
  return (step.kind === 'bump' || step.kind === 'override') && step.change === 'major';
}

function isMajor(action: FixAction): boolean {
  return action.steps.some(isMajorStep);
}

async function fixFrom(kind: FixRun['kind'], branch: string, dir: string, info: RepoInfo, options: FixOptions, log: (line: string) => void, prepared: Prepared): Promise<FixRun> {
  const { config } = options;
  const { before, assessment } = prepared;
  const scanDir = (fixPlan: boolean) => scan({ dir, dryRun: true, fixPlan, ...(options.cacheDir === undefined ? {} : { cacheDir: options.cacheDir }) });
  const { actions, selected } = select(kind, before, assessment);
  const run = newRun(kind, branch, dir, selected, actions);
  // The repository's name, not the folder's: a worktree's folder is always called "repo".
  const project = info.github?.name ?? basename(info.top);
  // Installing, building or testing this commit would run the malicious package.
  if (before.findings.some((f) => f.advisory.kind === 'malicious')) {
    run.note = 'waits for the malware PR: installing or building this commit would run the malicious package';
    return run;
  }
  if (actions.length === 0) {
    run.note = kind === 'malware' ? 'no malicious package to remove' : 'nothing to fix: no finding that triage would open a PR for has a fix plain code can apply';
    return run;
  }
  if (await alreadyCovered(run, info, options, prepared.baseCommit)) return run;
  log(`${kind}: ${selected.size} ${selected.size === 1 ? 'finding' : 'findings'}, ${actions.length} ${actions.length === 1 ? 'action' : 'actions'}`);

  const timeoutMs = config.fix.timeLimitMinutes * 60_000;
  const pm = await managerCommand(before.manager, dir);
  const installArgv = [...pm, ...cleanInstall(before.manager, config.fix.installScripts, before.fixPlan.brokenPeers.length > 0)];
  const setup = await detectSetup(dir, config.fix.setup);
  // An install counts once its setup (code generation) ran too.
  const install = async () => {
    const installed = await runTool(installArgv, { cwd: dir, timeoutMs });
    if (installed.code !== 0) return installed;
    for (const step of setup) {
      const ran = await runTool(step.argv, { cwd: dir, timeoutMs });
      if (ran.code !== 0) return { ...ran, output: `${step.name} failed after the install:\n${ran.output}` };
    }
    return installed;
  };
  log(`${kind}: installing and running the checks on the code as it is`);
  const baseInstall = await install();
  if (baseInstall.code !== 0) {
    run.note = `the project does not install as it is, so a fix could not be checked:\n${tail(baseInstall.output, 15)}`;
    run.attention = 'the project does not install as it is';
    return run;
  }
  const checks = await detectChecks(dir, before.manager, config.fix.checks);
  run.baseline = await runChecks(dir, checks, { timeoutMs });
  for (const b of run.baseline.filter((r) => !r.passed)) {
    log(`${kind}: ${b.command} ${b.timedOut ? 'times out' : 'fails'} on the code as it is, so it does not count (the report shows why)`);
  }
  const gating = checks.filter((c) => run.baseline.find((b) => b.name === c.name)?.passed);
  // What the checks write (a build that regenerates sources, output that is not ignored) is theirs,
  // not part of a fix: undone now, and new files of that kind are dropped after the agent too.
  const generated = await changedSince(dir, 'HEAD');
  await git(dir, ['reset', '--quiet', '--hard', 'HEAD']);
  await cleanUntracked(dir);
  const verify = async (): Promise<CheckResult[]> => {
    // A new version that is a known malicious package is never installed, whatever brought it in.
    const malicious = [...new Set((await scanDir(false)).findings.filter((f) => f.advisory.kind === 'malicious').map((f) => `${f.package}@${f.version}`))];
    if (malicious.length > 0) {
      return [{ name: 'malware', command: 'the malware check', passed: false, timedOut: false, output: `not installed: ${malicious.join(', ')} is a known malicious package`, seconds: 0 }];
    }
    const installed = await install();
    if (installed.code !== 0) return [{ name: 'install', command: installArgv.join(' '), passed: false, timedOut: installed.timedOut, output: tail(installed.output, 60), seconds: 0 }];
    return runChecks(dir, gating, { timeoutMs });
  };
  const applyOptions = {
    manager: before.manager,
    workspaces: before.workspaces.length > 0,
    legacyPeerDeps: before.fixPlan.brokenPeers.length > 0,
    rescan: () => scanDir(false),
    timeoutMs,
  };
  run.applied = { edits: [], commands: [], passes: 0 };
  const agentReady = options.agent !== false && config.fix.budgetUsd > 0 && (options.runAgent !== undefined || (await onPath('claude', options.env ?? process.env)));
  if (!agentReady && options.agent !== false) log(`${kind}: Claude Code is not set up, so plain-code fixes only`);
  let spent = 0;
  let checked: CheckResult[] = run.baseline.filter((b) => b.passed);

  // Phase 1 is what the ranges and minor releases allow; phase 2 the major upgrades, which is where
  // checks break. Each phase is tried whole. When a check fails, a bisection (plain code, no model)
  // keeps the actions that pass on their own and finds the ones that break a check; one Claude Code
  // session adapts the code to those; what still fails is rolled back, and the PR says why. The branch
  // only ever holds changes that pass every check that passed before.
  const phases = (['safe', 'major'] as const).map((name) => ({ name, actions: actionsFor(before, selected, name) })).filter((phase) => phase.actions.length > 0);
  // With no check that passed on the base, nothing shows a major upgrade still works: they stay out.
  if (gating.length === 0 && phases.some((p) => p.name === 'major')) {
    const major = phases.pop()!;
    log(`${kind}: no check passed on the base commit, so the ${major.actions.length} major ${major.actions.length === 1 ? 'upgrade stays' : 'upgrades stay'} out`);
    for (const action of major.actions) {
      for (const key of action.findings) {
        if (selected.has(key)) run.leftBecause[key] = `needs ${describeAction(action)}, and no check passed on the base commit to show the project still works after it`;
      }
    }
  }
  for (const phase of phases) {
    const record: PhaseRecord = { name: phase.name, actions: phase.actions.map((a) => a.id), kept: [], rolledBack: [] };
    run.phases.push(record);
    const what = phase.name === 'safe' ? 'refreshes and minor updates' : 'major upgrades';
    log(`${kind}: applying the ${what} (${phase.actions.length} ${phase.actions.length === 1 ? 'action' : 'actions'})`);
    const whole = await attempt(phase.name, phase.actions);
    if (whole.ok) {
      record.kept = phase.actions.map((a) => a.id);
      continue;
    }
    // Which actions break a check: each action that fails on its own, with why.
    const why = new Map<FixAction, Failure>();
    let breaking = phase.actions;
    if (phase.actions.length === 1) why.set(phase.actions[0]!, whole);
    else {
      log(`${kind}: ${failed(whole)} after the ${what}; trying them in smaller groups to keep those that pass`);
      const until = Date.now() + timeoutMs;
      breaking = await findBreaking(phase.actions, (part) => attempt(phase.name, part), () => Date.now() > until, why);
    }
    record.kept = phase.actions.filter((a) => !breaking.includes(a)).map((a) => a.id);
    // A plan that cannot be applied has nothing for the agent to adapt to, and one that brings in a
    // malicious version must never reach an agent that installs.
    const adaptable = breaking.filter((a) => why.get(a)?.applyError === undefined && !bringsMalware(why.get(a)));
    const left = config.fix.budgetUsd - spent;
    if (adaptable.length > 0 && agentReady && left >= 1) {
      const start = await git(dir, ['rev-parse', 'HEAD']);
      const marks = { edits: run.applied.edits.length, commands: run.applied.commands.length };
      const together = await attempt(phase.name, adaptable, true);
      if (together.ok) {
        record.kept.push(...adaptable.map((a) => a.id));
      } else if (bringsMalware(together)) {
        for (const action of adaptable) if (!why.has(action)) why.set(action, together);
      } else if (together.applyError === undefined) {
        const mechanical = await git(dir, ['rev-parse', 'HEAD']);
        log(`${kind}: ${failed(together)} with ${adaptable.length === 1 ? describeAction(adaptable[0]!) : `${adaptable.length} of the ${what}`}; Claude Code takes over (budget left $${left.toFixed(2)})`);
        const agent = await (options.runAgent ?? runFixAgent)(
          dir,
          {
            project,
            manager: before.manager,
            command: pm.join(' '),
            findings: agentFindings(assessment, adaptable, await scanDir(false), before),
            checks: gating.map((c) => ({ name: c.name, command: c.argv[0] === 'sh' ? c.argv[2]! : c.argv.join(' ') })),
            failing: together.failing,
            applied: [...run.applied.edits.slice(marks.edits), ...run.applied.commands.slice(marks.commands).map((c) => `ran ${c}`)],
            since: start,
            limits: { minutes: config.fix.timeLimitMinutes, budgetUsd: left },
          },
          { model: config.fix.model, effort: config.fix.effort, budgetUsd: left, timeoutMs },
        );
        spent += agent.costUsd ?? left;
        if (agent.costUsd !== null) run.agentCostUsd = (run.agentCostUsd ?? 0) + agent.costUsd;
        record.agent = true;
        // Protected paths go back (the agent does not commit, so this compares the working tree), and
        // new files the checks make on their own are dropped.
        const touched = await changedSince(dir, mechanical);
        for (const file of touched.tracked) {
          if (PROTECTED.some((pattern) => pattern.test(file))) await git(dir, ['checkout', mechanical, '--', file]).catch(() => '');
        }
        for (const file of touched.untracked) {
          if (PROTECTED.some((pattern) => pattern.test(file)) || generated.untracked.includes(file)) await rm(join(dir, file), { force: true });
        }
        const committed = await commitAll(dir, noDashes(`fix: adapt the code to the ${what}\n\n${agent.answer?.summary ?? ''}\n\nMade by Claude Code for patchhound.`), commitAuthor(config.fix.commitAs));
        const result = await checkCommitted();
        if (result.every((c) => c.passed)) {
          checked = result;
          run.agentKept = committed || run.agentKept;
          record.kept.push(...adaptable.map((a) => a.id));
          run.agentNotes.push(
            agent.answer
              ? `**Claude Code** (${what}): ${agent.answer.summary}`
              : `**Claude Code** (${what}) stopped before it answered (${agent.error ?? 'no answer'}); its changes are kept because every check passes with them.`,
          );
          // What the agent undid stays out of the PR; say so, and why, for each finding it leaves.
          for (const undone of agent.answer?.undone ?? []) {
            run.agentNotes.push(`Claude Code undid the change to ${undone.package}: ${undone.reason}`);
            const named = (edit: string) => [`: ${undone.package} -> `, `"${undone.package}@`, `/${undone.package}"`, `"$${undone.package}"`].some((mark) => edit.includes(mark));
            run.applied.edits = run.applied.edits.filter((edit, i) => i < marks.edits || !named(edit));
            for (const action of adaptable) {
              const step = action.steps.find((s) => (s.kind === 'bump' || s.kind === 'override') && s.package === undone.package);
              if (!step || !('to' in step)) continue;
              for (const key of action.findings) if (selected.has(key)) run.leftBecause[key] = `needs ${step.package} ${step.to}, which Claude Code undid: ${undone.reason}`;
            }
          }
        } else {
          run.agentNotes.push(`**Claude Code** (${what}) could not get every check to pass${agent.error ? ` (${agent.error})` : ''}, so its changes are not here and those upgrades are left out (below).`);
          for (const action of adaptable) why.set(action, { ok: false, failing: result.filter((c) => !c.passed), agent: true });
        }
      }
      if (!record.kept.includes(adaptable[0]!.id)) {
        await git(dir, ['reset', '--quiet', '--hard', start]);
        await cleanUntracked(dir);
        run.applied.edits.splice(marks.edits);
        run.applied.commands.splice(marks.commands);
      }
    }
    // What is still breaking stays out, with the reason.
    for (const action of breaking.filter((a) => !record.kept.includes(a.id))) {
      record.rolledBack.push(action.id);
      const failure = why.get(action);
      const reason = !failure
        ? 'not tried on its own: the time limit ran out while looking for the upgrades that break a check'
        : bringsMalware(failure)
          ? `${describeAction(action)} would bring in a known malicious package (${failure.failing.find((c) => c.name === 'malware')!.output.replace(/^not installed: /, '')})`
          : failure.applyError !== undefined
          ? `the plan could not be applied: ${failure.applyError.split('\n')[0]}`
          : `needs ${describeAction(action)}, which breaks ${failure.failing.map((c) => c.command).join(' and ')}${failure.agent ? ' (Claude Code could not adapt the code)' : ''}`;
      for (const key of action.findings) if (selected.has(key)) run.leftBecause[key] ??= reason;
    }
  }
  run.after = checked;
  const latest = await scanDir(false);
  await tally(run, before, latest);
  run.committed = (await git(dir, ['rev-parse', 'HEAD'])) !== prepared.baseCommit;
  if (!run.committed) {
    run.note = run.phases.every((p) => p.kept.length === 0) ? 'every change broke a check, so nothing is left to propose' : 'the changes left nothing to commit';
    // So that the next scheduled run does not redo (and pay for) the same attempt on the same commit.
    await recordRun(run, info, options, project, prepared.baseCommit);
    return run;
  }
  return publishRun(run, {
    project,
    kind,
    findings: assessment.findings.filter((f) => selected.has(f.key)),
    fixed: run.fixed,
    remaining: run.remaining,
    leftBecause: run.leftBecause,
    appeared: appearedOf(run, latest),
    applied: run.applied,
    baseline: run.baseline,
    after: run.after,
    agentNotes: run.agentNotes,
    agentCostUsd: run.agentCostUsd,
  }, info, options, log, prepared.baseCommit);

  /**
   * Applies `list` (and the plan for advisories its new versions bring) on top of HEAD and runs the
   * checks: committed when they pass; otherwise undone, unless `keep` (the agent then works on top).
   */
  async function attempt(phase: 'safe' | 'major', list: readonly FixAction[], keep = false): Promise<{ ok: true } | Failure> {
    const from = await git(dir, ['rev-parse', 'HEAD']);
    const marks = { edits: run.applied!.edits.length, commands: run.applied!.commands.length };
    const undo = async () => {
      await git(dir, ['reset', '--quiet', '--hard', from]);
      await cleanUntracked(dir);
      run.applied!.edits.splice(marks.edits);
      run.applied!.commands.splice(marks.commands);
    };
    try {
      const done = await applyActions(dir, list, applyOptions);
      run.applied!.edits.push(...done.edits);
      run.applied!.commands.push(...done.commands);
      await chase(phase, list, done);
    } catch (error) {
      await undo();
      const applyError = error instanceof ApplyError ? `${error.message}\n${error.output}` : error instanceof Error ? error.message : String(error);
      return { ok: false, applyError, failing: [{ name: 'apply', command: 'apply the fix plan', passed: false, timedOut: false, output: applyError, seconds: 0 }] };
    }
    // Committed before the checks run, so a build that rewrites tracked files (shadcn/ui regenerates
    // its registry) does not put its output in the commit.
    const now = new Set((await scanDir(false)).findings.map((f) => f.key));
    const fixedHere = list.flatMap((a) => a.findings).filter((key) => selected.has(key) && !now.has(key));
    await commitAll(dir, commitMessage(kind, phase, fixedHere, assessment), commitAuthor(config.fix.commitAs));
    const result = await checkCommitted();
    if (result.every((c) => c.passed)) {
      checked = result;
      return { ok: true };
    }
    if (!keep) await undo();
    return { ok: false, failing: result.filter((c) => !c.passed) };
  }

  /** Runs the checks on HEAD, then drops whatever they wrote, so the tree is HEAD again. */
  async function checkCommitted(): Promise<CheckResult[]> {
    const result = await verify();
    await git(dir, ['reset', '--quiet', '--hard', 'HEAD']);
    await cleanUntracked(dir);
    return result;
  }

  /**
   * A fixed version can carry advisories of its own (axios 0.33.0 fixes 0.21.1's but has newer ones):
   * plan again for those and for this attempt's own findings still there, up to two more rounds,
   * stopping when a round would repeat what is already done. The safe phase chases with safe actions only.
   */
  async function chase(phase: 'safe' | 'major', list: readonly FixAction[], first: ApplyLog): Promise<void> {
    const done = new Set(first.edits);
    const own = new Set(list.flatMap((a) => a.findings).filter((key) => selected.has(key)));
    for (let round = 0; round < 2; round++) {
      const now = await scanDir(true);
      const was = new Set(before.findings.map((f) => f.key));
      const target = new Set([...own, ...now.findings.map((f) => f.key).filter((key) => !was.has(key))]);
      const more = actionsFor(now, target, phase === 'safe' ? 'safe' : undefined);
      if (more.length === 0) return;
      log(`${kind}: the new versions have advisories of their own; planning again (round ${round + 2})`);
      const again = await applyActions(dir, more, applyOptions);
      const fresh = again.edits.filter((edit) => !done.has(edit));
      for (const edit of fresh) done.add(edit);
      run.applied!.edits.push(...fresh);
      run.applied!.commands.push(...again.commands);
      if (fresh.length === 0) return;
    }
  }
}

/**
 * `list` fails as a whole. Tries each half on its own (on top of what passed so far), keeping a half
 * that passes and splitting one that fails, down to single items. Returns the items that fail on their
 * own (each with its failure in `why`) and those left untried once `expired()`. A whole list whose
 * halves each pass (an interaction) leaves nothing failing: both halves stay, each one checked.
 */
export async function findBreaking<T, F>(list: readonly T[], attempt: (part: readonly T[]) => Promise<{ ok: true } | F>, expired: () => boolean, why: Map<T, F>): Promise<T[]> {
  const mid = Math.ceil(list.length / 2);
  const breaking: T[] = [];
  for (const half of [list.slice(0, mid), list.slice(mid)]) {
    if (half.length === 0) continue;
    if (expired()) {
      breaking.push(...half);
      continue;
    }
    const result = await attempt(half);
    if ((result as { ok?: boolean }).ok === true) continue;
    if (half.length === 1) {
      why.set(half[0]!, result as F);
      breaking.push(half[0]!);
    } else breaking.push(...(await findBreaking(half, attempt, expired, why)));
  }
  return breaking;
}

/** The checks stopped at the malware check: the change would install a known malicious package. */
function bringsMalware(failure: Failure | undefined): boolean {
  return failure?.failing.some((c) => c.name === 'malware') ?? false;
}

/** "pnpm run build and pnpm run typecheck failed" */
function failed(failure: Failure): string {
  return failure.applyError !== undefined ? 'the plan could not be applied' : `${failure.failing.map((c) => c.command).join(' and ')} failed`;
}

const DAY_MS = 24 * 60 * 60_000;

/**
 * Why a run on `branch` would only repeat the last one, or null when it would not: the last run set
 * out to fix exactly these findings, and its PR is still open, or it kept nothing on this same base
 * commit. New findings, a closed or merged PR, a new commit, or no record: null.
 */
export async function coveringPullRequest(
  auditPath: string,
  branch: string,
  selected: ReadonlySet<string>,
  prState: (url: string) => Promise<string | null>,
  base: string,
  now = Date.now(),
  openPr: () => Promise<string | null> = async () => null,
): Promise<string | null> {
  // The fix log beside it too: fix records go there now, and an older cache kept them in this one.
  const records: AuditRecord[] = await readAllAudit(dirname(auditPath)).catch(() => []);
  const last = records.filter((r): r is FixRecord => r.type === 'fix' && r.branch === branch).at(-1);
  if (!last) return null;
  const covered = new Set([...last.fixed, ...last.remaining]);
  if (covered.size !== selected.size || [...selected].some((key) => !covered.has(key))) return null;
  const these = selected.size === 1 ? 'this finding' : `these ${selected.size} findings`;
  if (last.pr === null && last.committed !== true) {
    if (last.base === base) return `the last run tried ${these} on this same commit and every change broke a check (run with --force to try again)`;
    // A repo with a commit every hour would otherwise pay every hour for the same failing attempt.
    if (now - Date.parse(last.at) < DAY_MS) return `the last run tried ${these} less than a day ago and every change broke a check (run with --force to try again)`;
    return null;
  }
  // Handed off to a publish job: that job opened the PR, so GitHub knows it by its branch.
  const url = last.pr ?? (await openPr());
  if (!url) return null;
  return (await prState(url)) === 'OPEN' ? `the open PR ${url} already covers ${these} (run with --force to redo it)` : null;
}

/** "a major upgrade of nanoid (4.0.2 -> 5.1.16)", "an update of lodash (4.17.21 -> 4.18.1)" */
function describeAction(action: FixAction): string {
  const step = action.steps.find(isMajorStep) ?? action.steps.find((s) => s.kind === 'bump' || s.kind === 'override') ?? action.steps[0];
  if (!step || !('to' in step)) return `the ${action.kind} of ${action.packages.join(', ')}`;
  return `${isMajorStep(step) ? 'a major upgrade' : 'an update'} of ${step.package} (${step.from} -> ${step.to})`;
}


function newRun(kind: FixRun['kind'], branch: string, dir: string, selected: ReadonlySet<string>, actions: readonly FixAction[]): FixRun {
  return {
    kind,
    branch,
    worktree: dir,
    selected: [...selected],
    actions: actions.map((a) => a.id),
    applied: null,
    baseline: [],
    after: [],
    agentNotes: [],
    agentCostUsd: null,
    fixed: [],
    remaining: [],
    appeared: [],
    committed: false,
    pr: null,
    phases: [],
    leftBecause: {},
    agentKept: false,
  };
}

/**
 * Whether to stop before any work: the open PR already holds these findings, the last attempt on
 * this same commit set out to fix exactly these and kept nothing (a scheduled run must not redo and
 * pay for either), or someone else pushed to the PR branch (it is left alone).
 */
async function alreadyCovered(run: FixRun, info: RepoInfo, options: FixOptions, base: string): Promise<boolean> {
  // `base` is the commit this run starts from; the PR branch is compared with the base branch.
  if (!publishing(options)) return false;
  if (info.github && (await othersOnBranch(info.github, run.branch, info.base).catch(() => false))) {
    run.note = `${run.branch} on GitHub has commits patchhound did not make, so it was left alone; merge or close its PR, or delete the branch, and the next run opens a fresh one`;
    // A malicious package left in place needs a person.
    if (run.kind === 'malware') run.attention = run.note;
    return true;
  }
  if (options.force) return false;
  const github = info.github;
  const covered = await coveringPullRequest(
    join(info.top, '.patchhound', 'audit.jsonl'),
    run.branch,
    new Set(run.selected),
    options.prState ?? pullRequestState,
    base,
    Date.now(),
    async () => (github ? openPullRequest(github, run.branch) : null),
  );
  if (covered) run.note = covered;
  // Until its PR is merged, the malicious package is still in the lockfile.
  if (covered && run.kind === 'malware') run.attention = `a malicious package is still in the lockfile: ${covered}`;
  return covered !== null;
}

/** Pushing, or handing off to the job that pushes. */
function publishing(options: FixOptions): boolean {
  return options.pr || options.handoff !== undefined;
}

/** Records a run that tried something, published or not (see coveringPullRequest). */
async function recordRun(run: FixRun, info: RepoInfo, options: FixOptions, project: string, base: string): Promise<void> {
  if (!publishing(options) || run.applied === null) return;
  await appendAudit(join(info.top, '.patchhound', FIX_LOG), [
    {
      type: 'fix',
      at: new Date().toISOString(),
      project,
      kind: run.kind,
      branch: run.branch,
      base,
      pr: run.pr?.url ?? null,
      committed: run.committed,
      fixed: run.fixed,
      remaining: run.remaining,
      checks: run.after.map((c) => ({ command: c.command, passed: c.passed })),
      agentCostUsd: run.agentCostUsd,
    },
  ]).catch(() => undefined);
}

function appearedOf(run: FixRun, latest: ScanResult): PrContent['appeared'] {
  return latest.findings
    .filter((f) => run.appeared.includes(f.key))
    .map((f) => ({ key: f.key, advisory: f.advisory.id, severity: f.advisory.severity, package: `${f.package}@${f.version}`, summary: f.advisory.summary }));
}

/**
 * A malicious package's PR. Nothing is installed or run while it is in the lockfile: the plan removes it
 * or pins it back with lockfile-only commands (scripts off), and only when a scan of the result shows no
 * malicious package left does the project install and run its checks. Those checks cannot gate the PR
 * (there is no clean "before" to compare with), so they are reported, and the PR opens either way.
 */
async function fixMalware(kind: FixRun['kind'], branch: string, dir: string, info: RepoInfo, options: FixOptions, log: (line: string) => void, prepared: Prepared): Promise<FixRun> {
  const { config } = options;
  const { before, assessment } = prepared;
  const scanDir = () => scan({ dir, dryRun: true, fixPlan: false, ...(options.cacheDir === undefined ? {} : { cacheDir: options.cacheDir }) });
  const { actions, selected } = select(kind, before, assessment);
  const run = newRun(kind, branch, dir, selected, actions);
  if (actions.length === 0) {
    run.note = selected.size === 0 ? 'no malicious package to remove' : 'a malicious package is in the lockfile, but the plan has no change that takes it out';
    if (selected.size > 0) run.attention = run.note;
    return run;
  }
  if (await alreadyCovered(run, info, options, prepared.baseCommit)) return run;
  const project = info.github?.name ?? basename(info.top);
  const timeoutMs = config.fix.timeLimitMinutes * 60_000;
  const versions = new Set(before.findings.filter((f) => selected.has(f.key)).map((f) => `${f.package}@${f.version}`));
  log(`${kind}: taking out ${[...versions].join(', ')} with lockfile changes only; nothing is installed or run first`);
  try {
    run.applied = await applyActions(dir, actions, {
      manager: before.manager,
      workspaces: before.workspaces.length > 0,
      legacyPeerDeps: before.fixPlan.brokenPeers.length > 0,
      rescan: scanDir,
      timeoutMs,
    });
  } catch (error) {
    await git(dir, ['reset', '--quiet', '--hard', 'HEAD']);
    await cleanUntracked(dir);
    run.note = `the plan to take it out could not be applied: ${(error instanceof Error ? error.message : String(error)).split('\n')[0]}`;
    run.attention = run.note;
    return run;
  }
  const latest = await scanDir();
  await tally(run, before, latest);
  run.committed = await commitAll(dir, commitMessage(kind, 'safe', run.fixed, assessment), commitAuthor(config.fix.commitAs));
  if (!run.committed) {
    run.note = 'the plan changed nothing';
    run.attention = 'a malicious package is still in the lockfile';
    return run;
  }
  if (latest.findings.some((f) => f.advisory.kind === 'malicious')) {
    run.attention = 'a malicious package is still in the lockfile';
    log(`${kind}: ${run.attention}, so nothing was installed or run`);
  } else {
    const pm = await managerCommand(before.manager, dir);
    const installArgv = [...pm, ...cleanInstall(before.manager, config.fix.installScripts, before.fixPlan.brokenPeers.length > 0)];
    let installed = await runTool(installArgv, { cwd: dir, timeoutMs });
    for (const step of installed.code === 0 ? await detectSetup(dir, config.fix.setup) : []) {
      const ran = await runTool(step.argv, { cwd: dir, timeoutMs });
      if (ran.code !== 0) {
        installed = { ...ran, output: `${step.name} failed after the install:\n${ran.output}` };
        break;
      }
    }
    run.after =
      installed.code === 0
        ? await runChecks(dir, await detectChecks(dir, before.manager, config.fix.checks), { timeoutMs })
        : [{ name: 'install', command: installArgv.join(' '), passed: false, timedOut: installed.timedOut, output: tail(installed.output, 60), seconds: 0 }];
    await git(dir, ['reset', '--quiet', '--hard', 'HEAD']);
    await cleanUntracked(dir);
  }
  return publishRun(
    run,
    {
      project,
      kind,
      findings: assessment.findings.filter((f) => selected.has(f.key)),
      fixed: run.fixed,
      remaining: run.remaining,
      appeared: appearedOf(run, latest),
      applied: run.applied,
      baseline: [],
      after: run.after,
      agentNotes: [],
      agentCostUsd: null,
      noBaseline: 'not run before the change: installing or building with a malicious package would run it',
    },
    info,
    options,
    log,
    prepared.baseCommit,
  );
}

/** Pushes the branch and opens or updates the PR (with --pr and a GitHub origin), and records it. */
async function publishRun(run: FixRun, content: PrContent, info: RepoInfo, options: FixOptions, log: (line: string) => void, base: string): Promise<FixRun> {
  if (options.handoff !== undefined) {
    await writeHandoff(run.worktree, options.handoff, {
      kind: run.kind,
      base,
      head: await git(run.worktree, ['rev-parse', 'HEAD']),
      title: prTitle(content),
      body: prBody(content),
      needsReview: run.agentKept,
    });
    run.note = `handed off to the publish job (${options.handoff})`;
    await recordRun(run, info, options, content.project, base);
    return run;
  }
  if (!options.pr) {
    run.note = `not published (run with --pr to push ${run.branch} and open the PR); the work is in ${run.worktree}`;
    return run;
  }
  if (!info.github) {
    run.note = 'not published: origin is not a GitHub repository';
    return run;
  }
  log(`${run.kind}: pushing ${run.branch} to ${info.github.owner}/${info.github.name}`);
  const publish = options.publish ?? publishPullRequest;
  try {
    run.pr = await publish(run.worktree, info.github, {
      branch: run.branch,
      base: info.base,
      title: prTitle(content),
      body: prBody(content),
      labels: run.kind === 'malware' ? ['security', 'malware'] : run.agentKept ? ['security', 'needs-review'] : ['security'],
    });
  } catch (error) {
    if (!(error instanceof BranchTaken)) throw error;
    run.note = `${error.message}; this run's work is in ${run.worktree}`;
    if (run.kind === 'malware') run.attention = error.message;
    return run;
  }
  await recordRun(run, info, options, content.project, base);
  return run;
}

/**
 * The findings this run takes on and the actions that fix them: for `malware`, every malicious
 * finding's action; for `fixes`, the findings the policy marks "would open a fix PR" (tier 1, when the
 * config turns it on), with the actions plain code can apply.
 */
function select(kind: FixRun['kind'], result: ScanResult, assessment: Assessment): { actions: FixAction[]; selected: Set<string> } {
  const wanted = new Set(
    assessment.findings
      .filter((f) => (kind === 'malware' ? f.evidence.advisory.kind === 'malicious' : f.evidence.advisory.kind !== 'malicious' && f.decision.wouldDo.some((w) => w.tier === 'fix-pr' && w.enabled)))
      .map((f) => f.key),
  );
  const actions = actionsFor(result, wanted);
  const selected = new Set(actions.flatMap((a) => a.findings).filter((key) => wanted.has(key)));
  return { actions, selected };
}

/**
 * The applicable actions for these findings only. The scan merges every package's refresh into one
 * action (in Excalidraw, 44 packages); regrouping just these findings' packages' plans keeps a PR to
 * what it fixes, instead of moving everything a refresh could.
 */
// With `phase`, only the packages whose plan does (major) or does not (safe) cross a major version,
// split per package before grouping: in shadcn/ui a minor next bump that fixes a critical advisory
// is grouped with major bumps elsewhere in the monorepo, and must not be rolled back with them.
export function actionsFor(result: ScanResult, keys: ReadonlySet<string>, phase?: 'safe' | 'major'): FixAction[] {
  const inPhase = (major: boolean) => phase === undefined || (phase === 'major') === major;
  const plans = result.fixPlan.plans;
  if (!plans) return result.fixPlan.actions.filter((a) => APPLICABLE.has(a.kind) && a.findings.some((key) => keys.has(key)) && inPhase(isMajor(a)));
  const ids = new Set(result.findings.filter((f) => keys.has(f.key)).map((f) => `${f.package}@${f.version}`));
  const picked = plans.filter((p) => ids.has(p.id) && inPhase(p.steps.some(isMajorStep)));
  const pickedIds = new Set(picked.map((p) => p.id));
  return groupActions(
    picked,
    result.findings.filter((f) => pickedIds.has(`${f.package}@${f.version}`)),
  ).filter((a) => APPLICABLE.has(a.kind));
}

/** Which selected findings are gone, which are still there, and which are new. */
async function tally(run: FixRun, before: ScanResult, after: ScanResult): Promise<void> {
  const now = new Set(after.findings.map((f) => f.key));
  const was = new Set(before.findings.map((f) => f.key));
  run.fixed = run.selected.filter((key) => !now.has(key));
  run.remaining = run.selected.filter((key) => now.has(key));
  run.appeared = [...now].filter((key) => !was.has(key));
}

function agentFindings(assessment: Assessment, actions: readonly FixAction[], latest: ScanResult, before: ScanResult): AgentFinding[] {
  const byKey = new Map<string, AssessedFinding>(assessment.findings.map((f) => [f.key, f]));
  const was = new Set(before.findings.map((f) => f.key));
  const still = new Set(latest.findings.map((f) => f.key));
  const keys = [...new Set(actions.flatMap((a) => a.findings))].filter((key) => byKey.has(key));
  const left = keys.flatMap((key) => {
    const f = byKey.get(key)!;
    const action = actions.find((a) => a.findings.includes(key))!;
    return [
      {
        key,
        advisory: f.evidence.advisory.id,
        severity: f.evidence.advisory.severity,
        package: f.evidence.package,
        version: f.evidence.version,
        summary: f.evidence.advisory.summary,
        reason: f.triage.reason,
        plan: `${action.kind}: ${action.steps.map((s) => `${s.kind} ${s.package}${'to' in s ? ` -> ${s.to}` : ''}`).join('; ')}${still.has(key) ? ' (applied, but the finding is still there)' : ' (applied)'}`,
      },
    ];
  });
  // Findings the new versions brought: the scan knows them, triage has not seen them.
  const appeared = latest.findings
    .filter((f) => !was.has(f.key))
    .map((n) => ({ key: n.key, advisory: n.advisory.id, severity: n.advisory.severity, package: n.package, version: n.version, summary: n.advisory.summary, reason: 'appeared with the updated version', plan: n.fix ? `${n.fix.kind} (the plan for it did not finish the job)` : 'no plan' }));
  return [...left, ...appeared];
}

function commitMessage(kind: FixRun['kind'], phase: 'safe' | 'major', fixed: readonly string[], assessment: Assessment): string {
  const ids = [...new Set(assessment.findings.filter((f) => fixed.includes(f.key)).map((f) => f.evidence.advisory.id))];
  const what = phase === 'safe' ? 'security updates' : 'major upgrades';
  const title = kind === 'malware' ? 'fix(deps): remove a malicious package' : `fix(deps): ${what} for ${ids.length} ${ids.length === 1 ? 'advisory' : 'advisories'}`;
  return `${title}\n\nFixes: ${ids.join(', ') || 'none on their own (the checks needed this)'}\n\nApplied by patchhound from its fix plan.`;
}
