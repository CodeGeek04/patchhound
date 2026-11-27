// Checks the fix plan's refresh claims with the package manager itself. It copies the project's
// manifests and lockfile to a temp folder, runs `npm update` or `pnpm update` there for the packages
// the plan says to refresh, and scans the result. Nothing in <project-dir> changes.
// One update can leave a package behind when others move in the same run (npm kept
// brace-expansion 1.1.12 under the new minimatch 3.1.5; pnpm kept fast-xml-parser 5.7.1 when
// @aws-sdk/xml-builder was one of 22 names), so while a claim fails the whole list runs again,
// up to three passes. The runs are the ones the report prints (see refreshRuns): pnpm goes round
// by round, listed packages first, with -r in a workspace, and an aliased copy is updated by its alias.
// yarn runs as the project would run it: its yarnPath, else `yarn` on PATH, else through npx.
// Usage: npm run verify-plan -- <project-dir> [extra npm, pnpm or yarn args, such as --legacy-peer-deps]
import { execFile } from 'node:child_process';
import { access, copyFile, cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { promisify } from 'node:util';
import type { RefreshRun } from '../src/fix/commands.js';
import { refreshRuns, unlockYarnEntries } from '../src/fix/commands.js';
import type { FixStep } from '../src/fix/plan.js';
import { loadGraph } from '../src/match/lockfiles/load.js';
import { scan } from '../src/scan.js';

const run = promisify(execFile);

/** Flags that keep each run to the lockfile, or at least away from install scripts. */
const QUIET: Record<string, string[]> = {
  npm: ['--ignore-scripts', '--no-audit', '--no-fund'],
  pnpm: ['--ignore-scripts'],
  'yarn-berry': ['--mode=update-lockfile'],
  'yarn-classic': ['--ignore-scripts', '--non-interactive'],
};

const [dir, ...extra] = process.argv.slice(2);
if (!dir) {
  console.error('usage: npm run verify-plan -- <project-dir> [extra npm or pnpm args]');
  process.exit(2);
}

const before = await scan({ dir, dryRun: true });
if (before.fixPlan.status !== 'ok') {
  console.error(`${before.project}: no fix plan (${before.warnings.join('; ') || before.fixPlan.status})`);
  process.exit(1);
}
const refresh = before.fixPlan.actions.find((action) => action.kind === 'refresh');
const steps = (refresh?.steps ?? []).filter((step): step is Extract<FixStep, { kind: 'refresh' }> => step.kind === 'refresh');
const runs = refreshRuns(steps, before.manager, before.workspaces.length > 0);
const names = [...new Set(steps.map((step) => step.alias ?? step.package))];
if (runs.length === 0) {
  console.log(`${before.project}: the plan has no refresh action, so there is nothing to verify`);
  process.exit(0);
}

const work = await mkdtemp(join(tmpdir(), 'patchhound-verify-'));
try {
  await copyProject(dir, work, basename(before.lockfile));
  const id = (f: { package: string; version: string }) => `${f.package}@${f.version}`;
  const planned = (kind: (k: string) => boolean) =>
    [...new Set(before.findings.filter((f) => f.fix !== null && kind(f.fix.kind)).map(id))].sort();
  const claimed = planned((k) => k === 'refresh');
  let after = before;
  let remaining = new Set<string>();
  let wrong: string[] = [];
  let passes = 0;
  do {
    for (const step of runs) await apply(step, work);
    passes++;
    after = await scan({ dir: work, dryRun: true, fixPlan: false });
    remaining = new Set(after.findings.map(id));
    wrong = claimed.filter((pkg) => remaining.has(pkg));
  } while (wrong.length > 0 && passes < 3);
  const known = new Set(before.findings.map((f) => f.key));
  const appeared = after.findings.filter((f) => !known.has(f.key));
  // A package planned for a bump or an override that the refresh moved to another vulnerable version is not fixed.
  const stillNamed = new Set(after.findings.map((f) => f.package));
  const gone = planned((k) => k !== 'refresh').filter((pkg) => !remaining.has(pkg));
  const bonus = gone.filter((pkg) => !stillNamed.has(pkg.slice(0, pkg.lastIndexOf('@'))));
  const moved = gone.filter((pkg) => !bonus.includes(pkg));
  const count = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;
  console.log(
    `${before.project}: ${before.manager} update of ${count(names.length, 'package', 'packages')} in ${count(passes, 'pass', 'passes')}. ` +
      `${count(claimed.length, 'package', 'packages')} planned as refresh, ` +
      `${wrong.length} still vulnerable; ${count(bonus.length, 'package', 'packages')} planned otherwise fixed too, ` +
      `${moved.length} moved to another vulnerable version; ` +
      `${count(appeared.length, 'finding', 'findings')} appeared; findings ${before.findings.length} -> ${after.findings.length}`,
  );
  for (const pkg of wrong) console.log(`  still vulnerable  ${pkg}`);
  for (const pkg of bonus) console.log(`  also fixed        ${pkg}`);
  for (const pkg of moved) console.log(`  moved, still vulnerable  ${pkg}`);
  for (const f of appeared) console.log(`  appeared          ${f.advisory.id} ${id(f)}`);
  process.exitCode = wrong.length > 0 ? 1 : 0;
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
} finally {
  await rm(work, { recursive: true, force: true });
}

async function apply(step: RefreshRun, cwd: string): Promise<void> {
  if (step.kind === 'unlock') {
    const lockfile = join(cwd, 'yarn.lock');
    await writeFile(lockfile, unlockYarnEntries(await readFile(lockfile, 'utf8'), step.packages));
    return;
  }
  const [program, ...args] = step.argv as [string, ...string[]];
  const [command, ...prefix] = program === 'yarn' ? await yarnCommand(cwd) : [program];
  try {
    // `npm run --silent` hands its log level down; reset it so the package manager's errors show.
    await run(command!, [...prefix, ...args, ...(QUIET[before.manager] ?? []), ...extra], {
      cwd,
      maxBuffer: 64 * 1024 * 1024,
      env: { ...process.env, npm_config_loglevel: 'warn', YARN_ENABLE_TELEMETRY: '0' },
    });
  } catch (error) {
    const { stdout = '', stderr = '' } = error as { stdout?: string; stderr?: string };
    const output = `${stderr}\n${stdout}`.trim().split('\n').slice(0, 12).join('\n') || String(error);
    throw new Error(`${before.project}: ${step.argv.join(' ')} failed, so the refresh could not be checked:\n${output}`, { cause: error });
  }
}

/** How to run the project's yarn: its yarnPath, else `yarn` on PATH, else the version package.json names through npx. */
async function yarnCommand(cwd: string): Promise<string[]> {
  const yarnrc = await readFile(join(cwd, '.yarnrc.yml'), 'utf8').catch(() => '');
  const yarnPath = /^yarnPath:\s*["']?([^"'\n]+)/m.exec(yarnrc)?.[1];
  if (yarnPath) return ['node', join(cwd, yarnPath.trim())];
  if (await run('yarn', ['--version'], { cwd }).then(() => true, () => false)) return ['yarn'];
  const named = /^yarn@(\d[^+]*)/.exec(JSON.parse(await readFile(join(cwd, 'package.json'), 'utf8')).packageManager ?? '')?.[1];
  if (before.manager === 'yarn-berry') return ['npx', '-y', '-p', `@yarnpkg/cli-dist@${named ?? '4'}`, 'yarn'];
  return ['npx', '-y', `yarn@${named ?? '1'}`];
}

/**
 * The lockfile, pnpm-workspace.yaml and the package.json of the project and every workspace, plus
 * what the package manager reads beside them: .npmrc (settings such as legacy-peer-deps),
 * .pnpmfile.cjs, the patches folder that pnpm's patchedDependencies point into, and yarn's
 * settings with its releases, plugins and patches.
 */
async function copyProject(from: string, to: string, lockfile: string): Promise<void> {
  const { graph } = await loadGraph(from);
  const roots = graph.roots.map((root) => root.slice('root:'.length));
  const files = [
    lockfile,
    'pnpm-workspace.yaml',
    '.npmrc',
    '.pnpmfile.cjs',
    '.yarnrc',
    '.yarnrc.yml',
    ...roots.map((root) => join(root, 'package.json')),
  ];
  for (const file of new Set(files)) {
    const source = join(from, file);
    if (!(await exists(source))) continue;
    await mkdir(dirname(join(to, file)), { recursive: true });
    await copyFile(source, join(to, file));
  }
  for (const folder of ['patches', '.yarn/releases', '.yarn/plugins', '.yarn/patches']) {
    if (await exists(join(from, folder))) await cp(join(from, folder), join(to, folder), { recursive: true });
  }
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}
