#!/usr/bin/env node
import { exec } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { appendFile, mkdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { Command } from 'commander';
import type { Assessment } from './assess.js';
import { assess, openClaude } from './assess.js';
import { formatExplain, readAllAudit } from './audit.js';
import { check } from './check.js';
import type { CentralConfig } from './config.js';
import { centralRepos, defaultCentralPath, initConfig, loadCentral, loadConfig } from './config.js';
import { defaultAction } from './setup/action-ref.js';
import { init } from './setup/init.js';
import { DEFAULT_SCHEDULE } from './setup/workflow.js';
import type { FixRun } from './fix/fix.js';
import { fixRepo, fixWork } from './fix/fix.js';
import { decideFix, dependencyFiles, readSignal, saveSignal } from './fix/signal.js';
import { failureExcerpt } from './fix/checks.js';
import { publishHandoff } from './fix/handoff.js';
import { formatReport } from './report.js';
import { formatAssessment } from './report-triage.js';
import type { ScanResult } from './scan.js';
import { scan } from './scan.js';
import { DiskCache, defaultCacheDir } from './util/cache.js';
import { OsvClient } from './watch/osv.js';
import { pollOnce } from './watch/watcher.js';

// tsx has read it by now (the Action points it at patchhound's own tsconfig). What the fix runs,
// the project's installs and tests, must find the project's own tsconfig, as it would without us.
delete process.env.TSX_TSCONFIG_PATH;

const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };

const program = new Command()
  .name('patchhound')
  .version(version)
  .description('Checks whether new advisories affect your app, and fixes them.');

interface ScanFlags {
  dryRun?: boolean;
  json?: boolean;
  state?: string;
  details?: boolean;
  fixPlan: boolean;
  lockfile?: string;
  cache: boolean;
  cacheDir?: string;
  triage: boolean;
  config?: string;
  githubOutput?: boolean;
}

/** The central config file: the one named, else the default location when it exists. */
async function central(path: string | undefined): Promise<CentralConfig | null> {
  const found = await loadCentral(path ?? defaultCentralPath());
  if (path !== undefined && found === null) throw new Error(`${path}: no such config file`);
  return found;
}

/** Triage, policy, notifications and the audit log for one scan's findings (milestone 2). */
async function triageScan(
  dir: string,
  result: ScanResult,
  options: { centralPath?: string; cacheDir?: string; write: boolean },
): Promise<Assessment> {
  const config = await loadConfig(dir, { central: await central(options.centralPath) });
  const cache = options.cacheDir === undefined ? undefined : new DiskCache(options.cacheDir);
  return assess({ dir, result, config, osv: new OsvClient(cache ? { cache } : {}), ...(cache ? { cache } : {}), write: options.write });
}

program
  .command('scan')
  .description('One full pass: find advisories that affect the project in [dir]')
  .argument('[dir]', 'project directory', '.')
  .option('--dry-run', 'report only; do not save which advisories were seen')
  .option('--json', 'print JSON instead of the text report')
  .option('--state <path>', 'state file (default: <dir>/.patchhound/state.json)')
  .option('--details', 'list every advisory under the fix plan')
  .option('--no-fix-plan', 'skip the fix plan (no npm registry requests)')
  .option('--lockfile <file>', 'the lockfile to scan, when the project has several')
  .option('--cache-dir <dir>', 'keep advisories and registry metadata here between runs (default: ~/.cache/patchhound)')
  .option('--no-cache', 'ask the network for everything, and keep nothing')
  .option('--no-triage', 'skip triage, notifications and the audit log (milestone 1 output only)')
  .option('--config <file>', 'central config file (default: ~/.config/patchhound/config.yml when it exists)')
  .option('--github-output', "in GitHub Actions: tell the workflow whether the fix job has anything new to do (fix=true or false in $GITHUB_OUTPUT)")
  .action(async (dir: string, options: ScanFlags) => {
    const cacheDir = options.cache ? (options.cacheDir ?? defaultCacheDir()) : undefined;
    // A config that does not read fails here, before the scan saves which findings it has seen.
    if (options.triage) await loadConfig(dir, { central: await central(options.config) });
    const result = await scan({
      dir,
      dryRun: options.dryRun,
      statePath: options.state,
      fixPlan: options.fixPlan,
      ...(options.lockfile === undefined ? {} : { lockfile: options.lockfile }),
      ...(cacheDir === undefined ? {} : { cacheDir }),
    });
    let assessment: Assessment | null = null;
    let triageError: string | null = null;
    if (options.triage) {
      try {
        assessment = await triageScan(dir, result, { ...(options.config === undefined ? {} : { centralPath: options.config }), ...(cacheDir === undefined ? {} : { cacheDir }), write: !options.dryRun });
      } catch (error) {
        // The scan itself worked and saved its state: print its report, then the failure.
        triageError = error instanceof Error ? error.message : String(error);
        process.exitCode = 1;
      }
    }
    if (options.json) {
      process.stdout.write(`${JSON.stringify(assessment ? { ...result, triage: triageJson(assessment) } : result, null, 2)}\n`);
    } else {
      process.stdout.write(`${formatReport(result, { details: options.details })}\n`);
      if (assessment) process.stdout.write(`\n${formatAssessment(assessment)}\n`);
    }
    // The text report already lists warnings; JSON output would otherwise hide them from a person watching.
    if (options.json) for (const warning of [...result.warnings, ...(assessment?.warnings ?? [])]) process.stderr.write(`patchhound: warning: ${warning}\n`);
    if (triageError !== null) process.stderr.write(`patchhound: triage failed: ${triageError}\n`);
    if (options.githubOutput) await signalFixJob(dir, result, assessment, options.dryRun ?? false);
  });

/**
 * The Action's scan job tells the workflow whether to run the fix job (see fix/signal.ts). Without a
 * triage to go by, it runs: the fix job works out for itself whether there is anything to do.
 */
async function signalFixJob(dir: string, result: ScanResult, assessment: Assessment | null, dryRun: boolean): Promise<void> {
  const stateDir = join(dir, '.patchhound');
  const decision = assessment
    ? decideFix(fixWork(result, assessment), await dependencyFiles(dir, result.lockfile), await readSignal(stateDir))
    : { fix: true, reason: 'triage did not finish', next: undefined };
  if (!dryRun && decision.next !== undefined) {
    await mkdir(stateDir, { recursive: true });
    await saveSignal(stateDir, decision.next);
  }
  if (process.env.GITHUB_OUTPUT) await appendFile(process.env.GITHUB_OUTPUT, `fix=${decision.fix}\n`);
  process.stdout.write(`\nFix job: ${decision.fix ? 'runs' : 'skipped'}, ${decision.reason}.\n`);
}

/** The assessment in --json output: per finding, its triage and decision; and the messages. */
function triageJson(a: Assessment) {
  return {
    scan: a.scan,
    models: a.models,
    stats: a.stats,
    dryRun: a.dryRun,
    findings: a.findings.map((f) => ({ key: f.key, evidence: f.evidence, triage: f.triage, decision: f.decision, alert: f.alert })),
    messages: a.messages.map((m) => ({ kind: m.message.kind, channel: m.channel, sent: m.sent, text: m.message.text, ...(m.error ? { error: m.error } : {}) })),
    warnings: a.warnings,
  };
}

interface WatchFlags {
  interval: string;
  once?: boolean;
  state?: string;
  cache: boolean;
  cacheDir?: string;
  exec?: string;
  details?: boolean;
  triage: boolean;
  config?: string;
}

program
  .command('watch')
  .description("Poll OSV's npm change list and the KEV catalog, and scan each project that a change touches")
  .argument('[dirs...]', 'project directories (default: the repos the central config lists, else .)')
  .option('--interval <minutes>', 'minutes between polls', '5')
  .option('--once', 'poll once and exit, for cron or CI')
  .option('--state <path>', 'watch state (default: <cache dir>/watch.json)')
  .option('--cache-dir <dir>', 'keep advisories and registry metadata here between runs (default: ~/.cache/patchhound)')
  .option('--no-cache', 'ask the network for everything, and keep nothing')
  .option('--exec <command>', 'run this shell command for each project with new or updated findings (PATCHHOUND_PROJECT names it)')
  .option('--details', 'list every advisory under the fix plan')
  .option('--no-triage', 'skip triage, notifications and the audit log')
  .option('--config <file>', 'central config file (default: ~/.config/patchhound/config.yml when it exists)')
  .action(async (given: string[], options: WatchFlags) => {
    const centralConfig = await central(options.config);
    const dirs = given.length > 0 ? given : centralConfig && centralRepos(centralConfig).length > 0 ? centralRepos(centralConfig) : ['.'];
    const minutes = Number(options.interval);
    // setTimeout takes at most about 24.8 days; a longer wait would fire at once, in a tight loop.
    if (!(minutes > 0 && minutes <= 35_000)) throw new Error(`--interval needs a number of minutes from above 0 to 35000, got ${options.interval}`);
    const cacheDir = options.cacheDir ?? defaultCacheDir();
    const statePath = options.state ?? join(cacheDir, 'watch.json');
    for (;;) {
      const poll = await pollOnce({ dirs, statePath, ...(options.cache ? { cacheDir } : {}) });
      const stamp = `${new Date().toISOString().slice(0, 19).replace('T', ' ')} UTC`;
      for (const warning of poll.warnings) process.stderr.write(`patchhound: warning: ${warning}\n`);
      for (const { dir, reasons, result, error } of poll.scans) {
        if (error !== undefined) {
          process.stderr.write(`${stamp} ${dir}: ${error}\n`);
          continue;
        }
        const fresh = result!.findings.filter((f) => f.status !== 'seen').length;
        process.stdout.write(`${stamp} ${dir}: ${fresh === 0 ? 'no' : fresh} new or updated ${fresh === 1 ? 'finding' : 'findings'} (${reasons.join('; ')})\n`);
        // Triage runs after every scan: a finding can need an alert without being new (newly KEV-listed, newly reachable).
        if (options.triage) {
          try {
            const assessment = await triageScan(dir, result!, { ...(options.config === undefined ? {} : { centralPath: options.config }), ...(options.cache ? { cacheDir } : {}), write: true });
            if (fresh > 0 || assessment.messages.length > 0) process.stdout.write(`${formatAssessment(assessment)}\n`);
          } catch (error) {
            process.stderr.write(`${stamp} ${dir}: triage failed: ${error instanceof Error ? error.message : String(error)}\n`);
          }
        }
        if (fresh === 0) continue;
        process.stdout.write(`${formatReport(result!, { details: options.details })}\n`);
        if (options.exec) await runHook(options.exec, dir, fresh);
      }
      if (poll.scans.length === 0) process.stdout.write(`${stamp} ${poll.changes} changed OSV records; none touch the watched projects\n`);
      if (options.once) {
        // So cron or CI can tell that a project could not be scanned.
        if (poll.scans.some((s) => s.error !== undefined)) process.exitCode = 1;
        return;
      }
      await new Promise((done) => setTimeout(done, minutes * 60_000));
    }
  });

program
  .command('explain')
  .description('The decision trail for one advisory, from the audit log')
  .argument('<id>', 'advisory id: GHSA, CVE or MAL')
  .argument('[dir]', 'project directory', '.')
  .action(async (id: string, dir: string) => {
    process.stdout.write(`${formatExplain(await readAllAudit(join(dir, '.patchhound')), id)}\n`);
  });

program
  .command('check')
  .description('Does this advisory, or the vulnerability a link describes, affect the project? Saves nothing.')
  .argument('<target>', 'advisory id (GHSA, CVE, MAL) or a link to a post, advisory or issue')
  .argument('[dir]', 'project directory', '.')
  .option('--config <file>', 'central config file (default: ~/.config/patchhound/config.yml when it exists)')
  .option('--no-cache', 'ask the network for everything, and keep nothing')
  .action(async (target: string, dir: string, options: { config?: string; cache: boolean }) => {
    const cacheDir = options.cache ? defaultCacheDir() : undefined;
    const cache = cacheDir === undefined ? undefined : new DiskCache(cacheDir);
    const config = await loadConfig(dir, { central: await central(options.config) });
    const warnings: string[] = [];
    let ran: Promise<{ result: ScanResult; assessment: Assessment }> | undefined;
    const output = await check(target, {
      dir,
      osv: new OsvClient(cache ? { cache } : {}),
      claude: await openClaude(config, process.env, warnings),
      scanAndAssess: () =>
        (ran ??= (async () => {
          const result = await scan({ dir, dryRun: true, ...(cacheDir === undefined ? {} : { cacheDir }) });
          return { result, assessment: await triageScan(dir, result, { ...(options.config === undefined ? {} : { centralPath: options.config }), ...(cacheDir === undefined ? {} : { cacheDir }), write: false }) };
        })()),
    });
    process.stdout.write(`${output}\n`);
    for (const warning of warnings) process.stderr.write(`patchhound: warning: ${warning}\n`);
  });

program
  .command('fix')
  .description('Fix what triage would open a PR for: apply the fix plan in a fresh worktree, run the project\'s checks, let Claude Code finish, and with --pr push the branch and open the PR')
  .argument('[dir]', 'a git checkout of the project', '.')
  .option('--pr', 'push the branch and open or update the pull request (otherwise the work stays in a local worktree)')
  .option('--in-place', 'work in the checkout itself, as in CI, instead of a temporary worktree')
  .option('--no-agent', 'plain code only: no Claude Code')
  .option('--force', 'redo the fix even when the open PR already covers the same findings')
  .option('--handoff <dir>', 'instead of pushing, write each PR as a git bundle and its text to <dir>, for `patchhound publish` in a job that holds the write token')
  .option('--budget <usd>', 'most Claude Code may spend in this run (overrides fix.budget_usd)')
  .option('--time-limit <minutes>', 'longest one Claude Code session, install or check may run (overrides fix.time_limit_minutes)')
  .option('--config <file>', 'central config file (default: ~/.config/patchhound/config.yml when it exists)')
  .option('--no-cache', 'ask the network for everything, and keep nothing')
  .action(async (dir: string, options: { pr?: boolean; inPlace?: boolean; agent: boolean; force?: boolean; handoff?: string; budget?: string; timeLimit?: string; config?: string; cache: boolean }) => {
    const config = await loadConfig(dir, { central: await central(options.config) });
    if (options.budget !== undefined) {
      const usd = Number(options.budget);
      if (!(usd >= 0 && usd <= 500)) throw new Error(`--budget needs dollars from 0 to 500, got ${options.budget}`);
      config.fix.budgetUsd = usd;
    }
    if (options.timeLimit !== undefined) {
      const minutes = Number(options.timeLimit);
      if (!(Number.isInteger(minutes) && minutes >= 1 && minutes <= 360)) throw new Error(`--time-limit needs whole minutes from 1 to 360, got ${options.timeLimit}`);
      config.fix.timeLimitMinutes = minutes;
    }
    const runs = await fixRepo({
      dir,
      config,
      pr: options.pr === true,
      inPlace: options.inPlace === true,
      agent: options.agent,
      force: options.force === true,
      ...(options.handoff ? { handoff: resolve(options.handoff) } : {}),
      ...(options.cache ? { cacheDir: defaultCacheDir() } : {}),
      log: (line) => process.stderr.write(`patchhound: ${line}\n`),
    });
    process.stdout.write(`${runs.map(formatFixRun).join('\n\n')}\n`);
    // Tried, and every change broke a check: worth a red step in CI.
    // A run that needs a person fails the command (and the Action's step); one that kept nothing does not.
    for (const run of runs) if (run.attention) process.stderr.write(`patchhound: ${run.kind}: needs a person: ${run.attention}\n`);
    if (runs.some((r) => r.attention)) process.exitCode = 1;
  });

program
  .command('publish')
  .description('Check the PRs `fix --handoff` wrote (their base, that every commit is patchhound\'s, the files they touch) and push them; runs nothing from the repository')
  .argument('<handoff>', 'the folder `fix --handoff` wrote')
  .argument('[dir]', 'a checkout of the repository the PRs go to', '.')
  .option('--config <file>', 'central config file (default: ~/.config/patchhound/config.yml when it exists)')
  .action(async (handoff: string, dir: string, options: { config?: string }) => {
    const config = await loadConfig(dir, { central: await central(options.config) });
    const results = await publishHandoff(dir, resolve(handoff), config, { log: (line) => process.stderr.write(`patchhound: ${line}\n`) });
    for (const r of results) process.stdout.write(`${r.kind}: ${r.pr ? `${r.pr.url}${r.pr.created ? '' : ' (updated)'}` : `not published: ${r.refused}`}\n`);
    if (results.length === 0) process.stdout.write('nothing to publish\n');
    if (results.some((r) => r.refused)) process.exitCode = 1;
  });

/** One fix run for the terminal: what it fixed, the checks, the agent, and the PR or why there is none. */
function formatFixRun(run: FixRun): string {
  const what = run.kind === 'malware' ? 'Malicious packages' : 'Fixes';
  if (run.applied === null) return `${what}: ${run.note ?? 'nothing done'}`;
  const lines = [`${what}: ${run.fixed.length} of ${run.selected.length} ${run.selected.length === 1 ? 'finding' : 'findings'} fixed on ${run.branch}`];
  for (const edit of run.applied?.edits ?? []) lines.push(`  edit: ${edit}`);
  for (const command of run.applied?.commands ?? []) lines.push(`  ran: ${command}`);
  for (const b of run.baseline) {
    const a = run.after.find((x) => x.name === b.name);
    lines.push(`  check ${b.command}: before ${b.passed ? 'pass' : 'fail'}, after ${b.passed ? (a?.passed ? 'pass' : 'FAIL') : 'not required'}`);
    if (!b.passed) for (const line of failureExcerpt(b.output, 12).split('\n').filter(Boolean)) lines.push(`    | ${line}`);
  }
  const install = run.after.find((a) => a.name === 'install');
  if (install) lines.push(`  install after the changes: FAIL`);
  for (const note of run.agentNotes) lines.push(`  ${note.replace(/\*\*/g, '')}`);
  if (run.agentNotes.length > 0) lines.push(`  Claude Code cost: ${run.agentCostUsd === null ? 'unknown' : `$${run.agentCostUsd.toFixed(2)}`}`);
  if (run.remaining.length > 0) lines.push(`  still there: ${run.remaining.join(', ')}`);
  if (run.appeared.length > 0) lines.push(`  new after the change: ${run.appeared.join(', ')}`);
  lines.push(run.pr ? `  PR: ${run.pr.url}${run.pr.created ? '' : ' (updated)'}` : `  ${run.note ?? 'no PR'}`);
  return lines.join('\n');
}

program
  .command('init')
  .description('Set a GitHub repo up for Patchhound: the workflow, the Claude token secret, and a setup PR to merge')
  .argument('[dir]', 'a checkout of the repo', '.')
  .option('--vercel', 'the repo deploys on Vercel: fix commits are authored by the person who started the run, so Vercel builds the preview')
  .option('--no-vercel', 'the repo does not deploy on Vercel (do not ask)')
  .option('--api-key', 'use an Anthropic API key (secret ANTHROPIC_API_KEY) instead of a Claude token')
  .option('--schedule <cron>', 'when scheduled runs start (cron, UTC)', DEFAULT_SCHEDULE)
  .option('--no-pr', 'write the files into [dir] instead of opening a setup PR')
  .option('--force', 'replace a Patchhound workflow already there')
  .option('--action <ref>', 'the Action the workflow runs, owner/repo@ref (default: this copy of Patchhound)')
  .option('--config-only', 'only write a starter .patchhound.yml, with every setting')
  .action(async (dir: string, options: { vercel?: boolean; apiKey?: boolean; schedule: string; pr: boolean; force?: boolean; action?: string; configOnly?: boolean }) => {
    if (options.configOnly) {
      process.stdout.write(`Wrote ${await initConfig(dir)}. Notifications stay in dry run until you set dry_run: false.\n`);
      return;
    }
    const action = options.action ?? (await defaultAction());
    const result = await init({
      dir,
      action,
      ...(options.vercel !== undefined ? { vercel: options.vercel } : {}),
      apiKey: options.apiKey ?? false,
      schedule: options.schedule,
      pr: options.pr,
      force: options.force ?? false,
    });
    const secret = (state: string) => ({ present: 'already set', set: 'stored', 'not set': 'NOT set (see above)', skipped: 'skipped (see above)' })[state];
    const setting = (state: string) => ({ on: 'already on', 'turned on': 'turned on', 'not on': 'NOT on (see above)' })[state];
    const next = result.merged
      ? 'The first run has started: Actions tab, patchhound.'
      : result.pr
        ? `Merge ${result.pr} and the first run starts (Actions tab, patchhound).`
        : result.files.length > 0
          ? 'Commit the files to the default branch and the first run starts.'
          : 'Start a run any time: Actions tab, patchhound, Run workflow.';
    process.stdout.write(
      [
        '',
        `Patchhound is set up for ${result.repo}:`,
        result.files.length > 0 ? `  files: ${result.files.join(', ')}${result.pr ? ` in ${result.pr}${result.merged ? ' (merged)' : ''}` : ''}` : '  files: already in the repo',
        `  Action: ${action}`,
        `  Claude secret: ${secret(result.secrets.claude)}`,
        `  Jev key: ${secret(result.secrets.jev)}`,
        `  Slack alerts: ${secret(result.secrets.slack)}`,
        `  GitHub Actions: ${setting(result.actions)}`,
        `  Actions may open pull requests: ${setting(result.pullRequests)}`,
        next,
        '',
      ].join('\n'),
    );
  });

/** Runs the --exec command for one project; a failing command is reported, not fatal. */
async function runHook(command: string, dir: string, fresh: number): Promise<void> {
  try {
    const { stdout, stderr } = await promisify(exec)(command, {
      env: { ...process.env, PATCHHOUND_PROJECT: dir, PATCHHOUND_NEW: String(fresh) },
    });
    process.stdout.write(stdout);
    process.stderr.write(stderr);
  } catch (error) {
    process.stderr.write(`patchhound: --exec failed for ${dir}: ${error instanceof Error ? error.message : String(error)}\n`);
  }
}

program.parseAsync().catch((error: unknown) => {
  process.stderr.write(`patchhound: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
