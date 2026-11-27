import { chmod, mkdir, mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { AssessedFinding } from '../../src/assess.js';
import { FIX_LOG } from '../../src/audit.js';
import { DEFAULT_CONFIG } from '../../src/config.js';
import { actionsFor, coveringPullRequest, findBreaking, fixRepo } from '../../src/fix/fix.js';
import type { PackagePlan } from '../../src/fix/plan.js';
import { addWorktree, changedSince, cleanUntracked, commitAll, commitAuthor, git, isDirty, othersOnBranch, removeWorktree, SELF } from '../../src/fix/git.js';
import { safeEnv } from '../../src/fix/pm.js';
import type { PrContent } from '../../src/fix/pr-body.js';
import { prBody, prTitle } from '../../src/fix/pr-body.js';
import { evidence, finding as scanFinding, scanResult } from '../helpers/findings.js';

const finding = (key: string, extra: Partial<AssessedFinding> = {}): AssessedFinding => ({
  key,
  evidence: evidence({ key }),
  triage: { reachable: 'yes', reachableP: 0.9, exposure: 'internet-facing', dropIn: 'yes', urgency: 4, reason: 'app/api/render/route.ts:4 renders request text | with _.template', source: 'claude', jev: null, claude: null },
  decision: { outcome: 'notify', rule: 'reachable', wouldDo: [{ tier: 'fix-pr', enabled: true }] },
  alert: 'new',
  ...extra,
});

const content = (extra: Partial<PrContent> = {}): PrContent => ({
  project: 'demo-app',
  kind: 'fixes',
  findings: [finding('a'), finding('b')],
  fixed: ['a'],
  remaining: ['b'],
  applied: { edits: ['package.json: lodash -> 4.17.21'], commands: ['npm install --package-lock-only --ignore-scripts'], passes: 0 },
  baseline: [
    { name: 'test', command: 'npm run test', passed: true, timedOut: false, output: '', seconds: 3 },
    { name: 'build', command: 'npm run build', passed: false, timedOut: false, output: 'needs DATABASE_URL', seconds: 2 },
  ],
  after: [{ name: 'test', command: 'npm run test', passed: true, timedOut: false, output: '', seconds: 3 }],
  agentNotes: [],
  agentCostUsd: null,
  ...extra,
});

describe('the PR', () => {
  it('names what it fixes, why each matters, what changed, the checks before and after, and what is left', () => {
    const c = content();
    expect(prTitle(c)).toBe('Security fixes for 1 advisory');
    const body = prBody(c);
    expect(body).toContain('Patchhound fixes 1 finding in demo-app, and every check that passed before still passes.');
    expect(body).toContain('| [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) | HIGH | lodash@4.17.20 | yes | Command Injection in lodash |');
    expect(body).toContain('renders request text \\| with _.template');
    expect(body).toContain('- package.json: lodash -> 4.17.21');
    expect(body).toContain('| `npm run test` | pass | pass |');
    expect(body).toContain('| `npm run build` | fail | skipped (failed before) |');
    expect(body).toContain('### Not fixed here');
  });

  it('says why each finding left out waits, and when Claude Code did not finish', () => {
    const c = content({
      leftBecause: { b: 'needs a major upgrade of lodash (3.10.1 -> 4.17.21), which breaks npm run test (Claude Code could not adapt the code)' },
      agentNotes: ['**Claude Code** (major upgrades) could not get every check to pass, so its changes are not here and those upgrades are left out (below).'],
      agentCostUsd: 4.2,
    });
    const body = prBody(c);
    expect(body).toContain('| Advisory | Severity | Package | Reachable | Why not |');
    expect(body).toContain('| needs a major upgrade of lodash (3.10.1 -> 4.17.21), which breaks npm run test (Claude Code could not adapt the code) |');
    expect(body).toContain('**Claude Code** (major upgrades) could not get every check to pass, so its changes are not here and those upgrades are left out (below).');
    expect(body).toContain('(Claude Code cost $4.20)');
  });

  it('for a malicious package, says to merge it first and shows the checks after only', () => {
    const c = content({
      kind: 'malware',
      fixed: ['a'],
      remaining: [],
      findings: [finding('a')],
      baseline: [],
      after: [{ name: 'test', command: 'npm run test', passed: true, timedOut: false, output: '', seconds: 2 }],
      noBaseline: 'not run before the change: installing or building with a malicious package would run it',
    });
    expect(prTitle(c)).toBe('Remove a malicious package');
    const body = prBody(c);
    expect(body).toContain('Patchhound takes a malicious package (lodash@4.17.20) out of demo-app. Merge it before anything installs this project again.');
    expect(body).toContain('Checks were not run before the change: installing or building with a malicious package would run it.');
    expect(body).toContain('| `npm run test` | pass |');
  });

  it('says so when no check passed before the change, so only a new scan confirms the fixes', () => {
    const body = prBody(content({ baseline: [{ name: 'build', command: 'npm run build', passed: false, timedOut: false, output: 'no DATABASE_URL', seconds: 2 }], after: [] }));
    expect(body).toContain("None of the project's checks passed before the change (below), so only a new scan confirms these fixes: review them with care.");
    expect(body).not.toContain('every check that passed before still passes');
  });

  it('shows why a check failed before any change', () => {
    const output = ['> next build', '', 'Error occurred prerendering page "/editions"', "Can't reach database server at `localhost:5432`", '    at _n.request (library.js:121:6741)', '\u001b[31m ELIFECYCLE\u001b[39m Command failed with exit code 1.'].join('\n');
    const body = prBody(content({ baseline: [{ name: 'build', command: 'pnpm run build', passed: false, timedOut: false, output, seconds: 2 }], after: [] }));
    expect(body).toContain('<details><summary>Why <code>pnpm run build</code> failed before any change</summary>');
    expect(body).toContain("Can't reach database server at `localhost:5432`\n ELIFECYCLE Command failed with exit code 1.");
    expect(body).not.toContain('at _n.request');
  });

  it('writes no em dashes, not even in the advisory titles and agent notes it quotes', () => {
    const dashed = finding('a');
    dashed.evidence.advisory.summary = 'PostCSS: incomplete fix \u2014 reads .map files';
    const c = content({ findings: [dashed, finding('b')], agentNotes: ['**Claude Code** (major upgrades): moved to zod 4 \u2014 two call sites'] });
    const body = prBody(c);
    expect(body).toContain('PostCSS: incomplete fix, reads .map files');
    expect(body).toContain('moved to zod 4, two call sites');
    expect(body).not.toContain('\u2014');
  });
});

describe('fixRepo', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'patchhound-fixrepo-'));
    await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'empty-app', version: '1.0.0' }, null, 2));
    await writeFile(join(dir, 'package-lock.json'), JSON.stringify({ name: 'empty-app', version: '1.0.0', lockfileVersion: 3, requires: true, packages: { '': { name: 'empty-app', version: '1.0.0' } } }, null, 2));
    await git(dir, ['init', '-q', '-b', 'main']);
    await git(dir, ['add', '-A']);
    await git(dir, ['-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-qm', 'init']);
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('says there is nothing to fix, opens nothing, and leaves no worktree behind', async () => {
    const config = { ...DEFAULT_CONFIG, triage: { ...DEFAULT_CONFIG.triage, llm: { ...DEFAULT_CONFIG.triage.llm, via: 'off' as const } } };
    const runs = await fixRepo({ dir, config, pr: true, env: {}, publish: async () => { throw new Error('must not publish'); } });
    expect(runs.map((r) => [r.kind, r.selected.length, r.pr, r.note])).toEqual([
      ['fixes', 0, null, 'nothing to fix: no finding that triage would open a PR for has a fix plain code can apply'],
    ]);
    expect((await git(dir, ['worktree', 'list'])).split('\n')).toHaveLength(1);
  });

  it('leaves its own state folder out of the dirty check, the commits and the clean-up', async () => {
    await mkdir(join(dir, '.patchhound'));
    await writeFile(join(dir, '.patchhound', 'state.json'), '{}');
    expect(await isDirty(dir)).toBe(false);
    await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'empty-app', version: '1.0.1' }));
    await writeFile(join(dir, 'leftover.log'), 'x');
    expect(await commitAll(dir, 'fix')).toBe(true);
    expect((await git(dir, ['show', '--name-only', '--format=', 'HEAD'])).split('\n').sort()).toEqual(['leftover.log', 'package.json']);
    await writeFile(join(dir, 'agent-scratch.txt'), 'x');
    await cleanUntracked(dir);
    expect(await git(dir, ['status', '--porcelain', '--untracked-files=all'])).toBe('?? .patchhound/state.json');
  });

  it('works in place only on the branch PRs go to', async () => {
    const remote = await mkdtemp(join(tmpdir(), 'patchhound-remote-'));
    try {
      await git(remote, ['init', '-q', '--bare']);
      await git(dir, ['remote', 'add', 'origin', remote]);
      await git(dir, ['push', '-q', 'origin', 'main']);
      await git(dir, ['remote', 'set-head', 'origin', 'main']);
      await git(dir, ['checkout', '-q', '-b', 'feature']);
      await expect(fixRepo({ dir, config: DEFAULT_CONFIG, pr: false, inPlace: true, env: {} })).rejects.toThrow(/--in-place works on main, the branch PRs go to; this checkout is on feature/);
    } finally {
      await rm(remote, { recursive: true, force: true });
    }
  });

  it('refuses a fix branch that names the base branch', async () => {
    const config = { ...DEFAULT_CONFIG, fix: { ...DEFAULT_CONFIG.fix, branch: 'main' } };
    await expect(fixRepo({ dir, config, pr: false, env: {} })).rejects.toThrow(/fix.branch must not name main/);
  });

  it('refuses to work in place in a checkout with uncommitted changes', async () => {
    await writeFile(join(dir, 'notes.txt'), 'wip');
    await expect(fixRepo({ dir, config: DEFAULT_CONFIG, pr: false, inPlace: true, env: {} })).rejects.toThrow(/uncommitted changes/);
  });
});

describe('actionsFor', () => {
  // A monorepo like shadcn/ui: next in apps/v4 needs a minor bump (a critical advisory), next in
  // apps/www a major one, and both share a vulnerable postcss, so the scan groups the bumps together.
  const findings = [
    scanFinding({ id: 'GHSA-crit', package: 'next', version: '15.2.0', severity: 'CRITICAL' }),
    scanFinding({ id: 'GHSA-old', package: 'next', version: '14.3.0' }),
    scanFinding({ id: 'GHSA-ms', package: 'ms', version: '2.0.0' }),
    scanFinding({ id: 'GHSA-qs', package: 'qs', version: '6.14.0', devOnly: true }),
  ];
  const bump = (root: string, from: string, change: 'minor' | 'major') => ({ kind: 'bump' as const, package: 'next', from, to: '15.5.29', change, root, spec: from });
  const refresh = (pkg: string, from: string, to: string) => ({ kind: 'refresh' as const, package: pkg, from, to, direct: false });
  const plans: PackagePlan[] = [
    { id: 'next@15.2.0', package: 'next', version: '15.2.0', kind: 'bump', target: '15.5.29', steps: [bump('apps/v4', '15.2.0', 'minor')] },
    { id: 'next@14.3.0', package: 'next', version: '14.3.0', kind: 'bump', target: '15.5.29', steps: [bump('apps/www', '14.3.0', 'major'), bump('apps/v4', '15.2.0', 'minor')] },
    { id: 'ms@2.0.0', package: 'ms', version: '2.0.0', kind: 'refresh', target: '2.1.3', steps: [refresh('ms', '2.0.0', '2.1.3')] },
    { id: 'qs@6.14.0', package: 'qs', version: '6.14.0', kind: 'refresh', target: '6.17.1', steps: [refresh('qs', '6.14.0', '6.17.1')] },
  ];
  const result = scanResult(findings, { fixPlan: { status: 'ok', actions: [], brokenPeers: [], plans } });
  const keys = (...ids: string[]) => new Set(findings.filter((f) => ids.includes(f.advisory.id)).map((f) => f.key));
  const summary = (actions: ReturnType<typeof actionsFor>) => actions.map((a) => [a.id, a.steps.map((s) => `${s.kind} ${s.package}@${s.from}`)]).sort((a, b) => String(a[0]).localeCompare(String(b[0])));

  it('keeps only the steps of the chosen findings, so a merged refresh does not move every package', () => {
    expect(summary(actionsFor(result, keys('GHSA-ms')))).toEqual([['refresh', ['refresh ms@2.0.0']]]);
  });

  it('splits by package before grouping, so a minor fix grouped with a major one still lands in the safe phase', () => {
    const chosen = keys('GHSA-crit', 'GHSA-old', 'GHSA-ms');
    expect(summary(actionsFor(result, chosen, 'safe'))).toEqual([
      ['bump:apps/v4:next', ['bump next@15.2.0']],
      ['refresh', ['refresh ms@2.0.0']],
    ]);
    expect(summary(actionsFor(result, chosen, 'major'))).toEqual([['bump:apps/v4:next+apps/www:next', ['bump next@14.3.0', 'bump next@15.2.0']]]);
  });

  it('falls back to whole actions when the scan has no per-package plans', () => {
    const action = { id: 'refresh', kind: 'refresh' as const, steps: [refresh('ms', '2.0.0', '2.1.3'), refresh('qs', '6.14.0', '6.17.1')], packages: ['ms@2.0.0', 'qs@6.14.0'], findings: [findings[2]!.key, findings[3]!.key], partial: [], devOnly: false };
    const old = scanResult(findings, { fixPlan: { status: 'ok', actions: [action], brokenPeers: [] } });
    expect(actionsFor(old, keys('GHSA-ms'), 'safe')).toEqual([action]);
    expect(actionsFor(old, keys('GHSA-ms'), 'major')).toEqual([]);
  });
});

describe('coveringPullRequest', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'patchhound-covered-'));
    await mkdir(join(dir, '.patchhound'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  const record = (pr: string | null, fixed: string[], remaining: string[], base = 'c1') =>
    JSON.stringify({ type: 'fix', at: '2026-11-22T10:00:00.000Z', project: 'app', kind: 'fixes', branch: 'patchhound/fixes', base, pr, fixed, remaining, checks: [], agentCostUsd: null });
  const path = () => join(dir, '.patchhound', 'audit.jsonl');

  it('names the open PR whose last run set out to fix exactly these findings, and nothing otherwise', async () => {
    await writeFile(path(), `${record('https://github.com/o/r/pull/1', ['a'], [])}\n${record('https://github.com/o/r/pull/2', ['a'], ['b'])}\n`);
    const open = async () => 'OPEN';
    expect(await coveringPullRequest(path(), 'patchhound/fixes', new Set(['a', 'b']), open, 'c2')).toBe('the open PR https://github.com/o/r/pull/2 already covers these 2 findings (run with --force to redo it)');
    // A new finding, a closed PR, another branch or no record: run again.
    expect(await coveringPullRequest(path(), 'patchhound/fixes', new Set(['a', 'b', 'c']), open, 'c2')).toBeNull();
    expect(await coveringPullRequest(path(), 'patchhound/fixes', new Set(['a', 'b']), async () => 'MERGED', 'c2')).toBeNull();
    expect(await coveringPullRequest(path(), 'patchhound/fixes-malware', new Set(['a', 'b']), open, 'c2')).toBeNull();
    expect(await coveringPullRequest(join(dir, 'missing.jsonl'), 'patchhound/fixes', new Set(['a']), open, 'c2')).toBeNull();
  });

  it('finds the PR a publish job opened by its branch, when the work was handed off', async () => {
    await writeFile(path(), `${JSON.stringify({ type: 'fix', at: '2026-11-22T10:00:00.000Z', project: 'app', kind: 'fixes', branch: 'patchhound/fixes', base: 'c1', pr: null, committed: true, fixed: ['a'], remaining: [], checks: [], agentCostUsd: null })}\n`);
    const open = async (url: string) => (url === 'https://github.com/o/r/pull/7' ? 'OPEN' : null);
    expect(await coveringPullRequest(path(), 'patchhound/fixes', new Set(['a']), open, 'c2', Date.now(), async () => 'https://github.com/o/r/pull/7')).toBe(
      'the open PR https://github.com/o/r/pull/7 already covers this finding (run with --force to redo it)',
    );
    expect(await coveringPullRequest(path(), 'patchhound/fixes', new Set(['a']), open, 'c2', Date.now(), async () => null)).toBeNull();
  });

  it('reads the fix log, and the fix records an older cache kept in the audit log', async () => {
    await writeFile(path(), `${record('https://github.com/o/r/pull/1', ['a'], [])}\n`);
    // The newer run, in the fix log, is the one that counts.
    await writeFile(join(dir, '.patchhound', FIX_LOG), `${record('https://github.com/o/r/pull/2', ['a'], ['b']).replace('2026-11-22T10', '2026-11-23T10')}\n`);
    const open = async () => 'OPEN';
    expect(await coveringPullRequest(path(), 'patchhound/fixes', new Set(['a', 'b']), open, 'c2')).toBe('the open PR https://github.com/o/r/pull/2 already covers these 2 findings (run with --force to redo it)');
    expect(await coveringPullRequest(path(), 'patchhound/fixes', new Set(['a']), open, 'c2')).toBeNull();
  });

  it('skips the same attempt on the same commit when it kept nothing, and tries again on a new commit a day later', async () => {
    await writeFile(path(), `${record(null, [], ['a', 'b'], 'c1')}\n`);
    const never = async () => {
      throw new Error('no PR to ask about');
    };
    const at = Date.parse('2026-11-22T10:00:00.000Z');
    expect(await coveringPullRequest(path(), 'patchhound/fixes', new Set(['a', 'b']), never, 'c1', at + 3 * 86_400_000)).toMatch(/^the last run tried these 2 findings on this same commit/);
    // On a new commit, at most once a day.
    expect(await coveringPullRequest(path(), 'patchhound/fixes', new Set(['a', 'b']), never, 'c2', at + 3_600_000)).toMatch(/less than a day ago/);
    expect(await coveringPullRequest(path(), 'patchhound/fixes', new Set(['a', 'b']), never, 'c2', at + 86_400_001)).toBeNull();
  });
});

describe('findBreaking', () => {
  // Each attempt applies a part on top of what passed so far; a part fails when it holds a bad item.
  const run = (bad: string[], items: string[], expireAfter = Infinity) => {
    const kept: string[] = [];
    const tries: string[][] = [];
    const why = new Map<string, { ok: false; item: string }>();
    const attempt = async (part: readonly string[]) => {
      tries.push([...part]);
      const culprit = part.find((item) => bad.includes(item));
      if (culprit) return { ok: false as const, item: culprit };
      kept.push(...part);
      return { ok: true as const };
    };
    return findBreaking(items, attempt, () => tries.length >= expireAfter, why).then((breaking) => ({ breaking, kept, tries, why }));
  };

  it('keeps every item that passes and names each one that fails on its own', async () => {
    const { breaking, kept, tries, why } = await run(['c', 'f'], ['a', 'b', 'c', 'd', 'e', 'f', 'g']);
    expect(breaking).toEqual(['c', 'f']);
    expect(kept.sort()).toEqual(['a', 'b', 'd', 'e', 'g']);
    expect([...why.keys()]).toEqual(['c', 'f']);
    expect(tries.length).toBeLessThan(2 * 7);
  });

  it('keeps both halves of a list that only failed as a whole', async () => {
    expect((await run([], ['a', 'b'])).breaking).toEqual([]);
  });

  it('counts what it had no time to try as breaking, without a reason', async () => {
    const { breaking, why } = await run(['a'], ['a', 'b', 'c', 'd'], 1);
    expect(breaking).toEqual(['a', 'b', 'c', 'd']);
    expect(why.size).toBe(0);
  });
});

describe('git safety', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'patchhound-git-'));
    await git(dir, ['init', '-q', '-b', 'main']);
    await writeFile(join(dir, 'a.txt'), 'a');
    await git(dir, ['add', '-A']);
    await git(dir, ['-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-qm', 'init']);
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('never runs the hooks of the repository, and makes worktrees without branches', async () => {
    // A post-checkout hook that installs would run a malicious package before anything is checked.
    await writeFile(join(dir, '.git', 'hooks', 'post-checkout'), `#!/bin/sh\ntouch "${join(dir, 'hook-ran')}"\n`);
    await chmod(join(dir, '.git', 'hooks', 'post-checkout'), 0o755);
    const worktree = await addWorktree(dir, await git(dir, ['rev-parse', 'HEAD']));
    await expect(stat(join(dir, 'hook-ran'))).rejects.toThrow();
    expect(await git(worktree, ['rev-parse', '--abbrev-ref', 'HEAD'])).toBe('HEAD');
    expect(await git(dir, ['branch', '--format=%(refname:short)'])).toBe('main');
    await removeWorktree(dir, worktree);
  });

  it('sees what changed in the working tree, tracked or new', async () => {
    const head = await git(dir, ['rev-parse', 'HEAD']);
    await writeFile(join(dir, 'a.txt'), 'changed');
    await mkdir(join(dir, '.github'));
    await writeFile(join(dir, '.github', 'ci.yml'), 'x');
    await mkdir(join(dir, '.patchhound'));
    await writeFile(join(dir, '.patchhound', 'audit.jsonl'), '{}');
    // patchhound's own state is never a change (so never cleaned away with the agent's files).
    expect(await changedSince(dir, head)).toEqual({ tracked: ['a.txt'], untracked: ['.github/ci.yml'] });
  });

  it('asks GitHub whether someone else pushed to the PR branch (a shallow checkout cannot tell)', async () => {
    const repo = { owner: 'o', name: 'r' };
    const asked: string[] = [];
    const api = (commits: string[] | null) => async (path: string) => {
      asked.push(path);
      return commits;
    };
    expect(await othersOnBranch(repo, 'patchhound/fixes', 'main', api(null))).toBe(false);
    expect(asked).toEqual(['repos/o/r/compare/main...patchhound%2Ffixes']);
    expect(await othersOnBranch(repo, 'patchhound/fixes', 'main', api([SELF.email, SELF.email]))).toBe(false);
    expect(await othersOnBranch(repo, 'patchhound/fixes', 'main', api([SELF.email, 'someone@example.com']))).toBe(true);
  });

  it('reads an open PR\'s commits from the identity it used before as its own', async () => {
    const repo = { owner: 'o', name: 'r' };
    const api = (committers: string[]) => async () => committers;
    expect(await othersOnBranch(repo, 'patchhound/fixes', 'main', api(['security-agent@users.noreply.github.com', SELF.email]))).toBe(false);
    // A person's edit in GitHub's web editor has GitHub as its committer.
    expect(await othersOnBranch(repo, 'patchhound/fixes', 'main', api([SELF.email, 'noreply@github.com']))).toBe(true);
  });

  it('commits as github-actions[bot], or with the person who started the run as the author', async () => {
    expect(SELF).toEqual({ name: 'github-actions[bot]', email: '41898282+github-actions[bot]@users.noreply.github.com' });
    const run = { GITHUB_ACTOR: 'octocat', GITHUB_ACTOR_ID: '583231' };
    expect(commitAuthor('bot', run)).toEqual(SELF);
    expect(commitAuthor('actor', run)).toEqual({ name: 'octocat', email: '583231+octocat@users.noreply.github.com' });
    // Outside a run, or when a bot started it, the bot.
    expect(commitAuthor('actor', {})).toEqual(SELF);
    expect(commitAuthor('actor', { GITHUB_ACTOR: 'dependabot[bot]', GITHUB_ACTOR_ID: '49699333' })).toEqual(SELF);

    await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'empty-app', version: '1.0.2' }));
    expect(await commitAll(dir, 'fix', commitAuthor('actor', run))).toBe(true);
    expect(await git(dir, ['log', '-1', '--format=%an <%ae> | %cn <%ce>'])).toBe(
      'octocat <583231+octocat@users.noreply.github.com> | github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>',
    );
  });

  it('keeps its own secrets out of what it runs', () => {
    const saved = { GH_TOKEN: process.env.GH_TOKEN, CLAUDE_CODE_OAUTH_TOKEN: process.env.CLAUDE_CODE_OAUTH_TOKEN };
    process.env.GH_TOKEN = 'gh-secret';
    process.env.CLAUDE_CODE_OAUTH_TOKEN = 'claude-secret';
    try {
      expect(safeEnv().GH_TOKEN).toBeUndefined();
      expect(safeEnv().CLAUDE_CODE_OAUTH_TOKEN).toBeUndefined();
      expect(safeEnv(['CLAUDE_CODE_OAUTH_TOKEN']).CLAUDE_CODE_OAUTH_TOKEN).toBe('claude-secret');
      expect(safeEnv().PATH).toBe(process.env.PATH);
    } finally {
      for (const [name, value] of Object.entries(saved)) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  });
});
