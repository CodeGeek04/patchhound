import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config.js';
import { git } from '../../src/fix/git.js';
import type { ToolResult } from '../../src/fix/pm.js';
import type { InitIO } from '../../src/setup/init.js';
import { editConfig, init } from '../../src/setup/init.js';
import { WORKFLOW_PATH, workflowFile } from '../../src/setup/workflow.js';

const ok = (output = ''): ToolResult => ({ code: 0, timedOut: false, output });
const fail = (output: string): ToolResult => ({ code: 1, timedOut: false, output });
const ACTION = 'acme/patchhound@main';
const repo = { owner: 'o', name: 'r' };

/** What a .patchhound.yml text means, read the way a run reads it. */
async function settings(text: string) {
  const dir = await mkdtemp(join(tmpdir(), 'patchhound-settings-'));
  try {
    await writeFile(join(dir, '.patchhound.yml'), text);
    return await loadConfig(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

describe('patchhound init', () => {
  let root: string;
  let origin: string;
  let checkout: string;
  let calls: string[][];
  let questions: string[];
  let logs: string[];
  let secrets: string;
  let actionsSettings: ToolResult;
  let selected: ToolResult;
  let workflowSettings: ToolResult;
  let putResult: ToolResult;
  let openPr: string;
  let mergeResult: ToolResult;
  let answer: (question: string) => boolean;

  const io = (overrides: Partial<InitIO> = {}): InitIO => ({
    gh: async (args) => {
      calls.push(['gh', ...args]);
      const [a, b, c, d] = args;
      if (a === 'api' && b === 'repos/o/r') return ok('{"default_branch":"main","allow_merge_commit":true}');
      if (a === 'secret' && b === 'list') return ok(secrets);
      if (a === 'api' && b === 'repos/o/r/actions/permissions') return actionsSettings;
      if (a === 'api' && b === 'repos/o/r/actions/permissions/selected-actions') return selected;
      if (a === 'api' && b === '-X' && d === 'repos/o/r/actions/permissions') return ok();
      if (a === 'api' && b === 'repos/o/r/actions/permissions/workflow') return workflowSettings;
      if (a === 'api' && b === '-X' && c === 'PUT' && d === 'repos/o/r/actions/permissions/workflow') return putResult;
      if (a === 'pr' && b === 'list') return ok(openPr);
      if (a === 'pr' && b === 'edit') return ok();
      if (a === 'pr' && b === 'create') return ok('Creating pull request\nhttps://github.com/o/r/pull/7\n');
      if (a === 'pr' && b === 'merge') return mergeResult;
      throw new Error(`unexpected gh ${args.join(' ')}`);
    },
    interactive: async (argv) => {
      calls.push(['interactive', ...argv]);
      return 0;
    },
    ask: async (question) => {
      questions.push(question);
      return answer(question);
    },
    tty: true,
    onPath: async () => true,
    log: (line) => logs.push(line),
    ...overrides,
  });

  const show = (path: string) => git(origin, ['show', `patchhound/setup:${path}`]).then((text) => `${text}\n`);
  const commitToMain = async (files: Record<string, string>) => {
    for (const [path, text] of Object.entries(files)) {
      await mkdir(join(checkout, path, '..'), { recursive: true });
      await writeFile(join(checkout, path), text);
    }
    await git(checkout, ['add', '-A']);
    await git(checkout, ['commit', '-qm', 'setup']);
    await git(checkout, ['push', '-q', 'origin', 'main']);
  };

  beforeEach(async () => {
    calls = [];
    questions = [];
    logs = [];
    secrets = '';
    actionsSettings = ok('{"enabled":true,"allowed_actions":"all"}');
    selected = ok('{}');
    workflowSettings = ok('{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}');
    putResult = ok();
    openPr = '';
    mergeResult = ok();
    answer = () => true;
    root = await mkdtemp(join(tmpdir(), 'patchhound-init-'));
    origin = join(root, 'origin.git');
    checkout = join(root, 'app');
    await git(root, ['init', '-q', '--bare', '-b', 'main', origin]);
    await git(root, ['clone', '-q', origin, checkout]);
    await git(checkout, ['checkout', '-q', '-b', 'main']);
    await git(checkout, ['config', 'user.email', 'dev@example.com']);
    await git(checkout, ['config', 'user.name', 'dev']);
    await commitToMain({ 'package.json': '{"name":"app"}\n', 'package-lock.json': '{"lockfileVersion":3,"packages":{}}\n' });
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it('does everything a new repo needs: files, the three secrets, both settings, the PR and its merge', async () => {
    await writeFile(join(checkout, 'work-in-progress.txt'), 'not committed\n');
    const head = await git(checkout, ['rev-parse', 'HEAD']);
    const result = await init({ dir: checkout, action: ACTION, repo }, io());

    expect(result).toEqual({
      repo: 'o/r',
      pr: 'https://github.com/o/r/pull/7',
      merged: true,
      files: [WORKFLOW_PATH, '.patchhound.yml'],
      secrets: { claude: 'set', jev: 'set', slack: 'set' },
      actions: 'on',
      pullRequests: 'turned on',
    });
    expect(await show(WORKFLOW_PATH)).toBe(workflowFile({ action: ACTION, base: 'main' }));
    // Alerts only go out with a channel and dry_run off; Vercel needs the person as the author.
    const config = await settings(await show('.patchhound.yml'));
    expect(config.dryRun).toBe(false);
    expect(config.notify.channels).toEqual([{ type: 'slack', webhookEnv: 'SLACK_WEBHOOK_URL' }]);
    expect(config.fix.commitAs).toBe('actor');
    expect(await git(origin, ['log', '-1', '--format=%s|%ae', 'patchhound/setup'])).toBe('Add Patchhound|dev@example.com');

    for (const name of ['CLAUDE_CODE_OAUTH_TOKEN', 'TYPESAFE_API_KEY', 'SLACK_WEBHOOK_URL']) expect(calls).toContainEqual(['interactive', 'gh', 'secret', 'set', name, '--repo', 'o/r']);
    expect(calls).toContainEqual(['interactive', 'claude', 'setup-token']);
    expect(calls).toContainEqual(['gh', 'api', '-X', 'PUT', 'repos/o/r/actions/permissions/workflow', '-f', 'default_workflow_permissions=read', '-F', 'can_approve_pull_request_reviews=true']);
    expect(calls).toContainEqual(['gh', 'pr', 'merge', 'https://github.com/o/r/pull/7', '--merge', '--delete-branch']);
    expect(questions.map((q) => q.split('?')[0])).toEqual(['Does this repo deploy on Vercel', 'Make a Claude token now (claude setup-token)', 'Add your Jev (TypeSafe) API key', 'Send alerts to Slack', 'Merge the setup PR now']);

    // The person's own checkout: same commit, same files, nothing added.
    expect(await git(checkout, ['rev-parse', 'HEAD'])).toBe(head);
    expect(await git(checkout, ['status', '--porcelain'])).toBe('?? work-in-progress.txt');
    expect((await git(checkout, ['worktree', 'list'])).split('\n')).toHaveLength(1);
  });

  it('run again once set up, does nothing and asks nothing but what is missing', async () => {
    await commitToMain({ [WORKFLOW_PATH]: 'name: patchhound\n', '.patchhound.yml': 'dry_run: false\nnotify:\n  channels:\n    - type: slack\n' });
    secrets = 'CLAUDE_CODE_OAUTH_TOKEN\nTYPESAFE_API_KEY\nSLACK_WEBHOOK_URL\n';
    workflowSettings = ok('{"default_workflow_permissions":"write","can_approve_pull_request_reviews":true}');
    const result = await init({ dir: checkout, action: ACTION, repo, vercel: false }, io());
    expect(result).toEqual({ repo: 'o/r', pr: null, merged: false, files: [], secrets: { claude: 'present', jev: 'present', slack: 'present' }, actions: 'on', pullRequests: 'on' });
    expect(questions).toEqual([]);
    expect(calls.filter((c) => c[0] === 'interactive' || c[1] === 'pr' || c[2] === '-X')).toEqual([]);
  });

  it('run again with its setup PR still open, updates that PR', async () => {
    answer = (q) => !q.startsWith('Merge');
    await init({ dir: checkout, action: ACTION, repo, vercel: false }, io());
    openPr = 'https://github.com/o/r/pull/7\n';
    secrets = 'CLAUDE_CODE_OAUTH_TOKEN\n';
    calls = [];
    const result = await init({ dir: checkout, action: ACTION, repo, vercel: true }, io());
    expect(result.pr).toBe('https://github.com/o/r/pull/7');
    expect(calls.some((c) => c[1] === 'pr' && c[2] === 'create')).toBe(false);
    expect(calls.some((c) => c[1] === 'pr' && c[2] === 'edit')).toBe(true);
    expect((await settings(await show('.patchhound.yml'))).fix.commitAs).toBe('actor');
  });

  it('adds what is missing to a .patchhound.yml already there, keeping its comments and settings', async () => {
    const current = '# ours\nnotify:\n  threshold: critical # only the worst\nfix:\n  budget_usd: 3\n';
    const next = editConfig(current, { alerts: true, vercel: true })!;
    expect(next).toContain('# ours');
    expect(next).toContain('threshold: critical # only the worst');
    const config = await settings(next);
    expect(config).toMatchObject({ dryRun: false, notify: { threshold: 'critical', channels: [{ type: 'slack', webhookEnv: 'SLACK_WEBHOOK_URL' }] }, fix: { budgetUsd: 3, commitAs: 'actor' } });
    expect(editConfig(next, { alerts: true, vercel: true })).toBeNull();
    expect(editConfig(null, { alerts: false, vercel: false })).toBeNull();
    expect((await settings(editConfig(null, { alerts: true, vercel: false })!)).fix.commitAs).toBe('bot');
  });

  it('keeps a workflow already there unless --force, and stops on a repo without a lockfile', async () => {
    await commitToMain({ [WORKFLOW_PATH]: 'name: old\n' });
    secrets = 'CLAUDE_CODE_OAUTH_TOKEN\nTYPESAFE_API_KEY\n';
    answer = (q) => !q.startsWith('Send alerts');
    expect((await init({ dir: checkout, action: ACTION, repo, vercel: false }, io())).files).toEqual([]);
    expect(logs).toContain(`${WORKFLOW_PATH} is already on main: kept (--force writes it again).`);
    expect((await init({ dir: checkout, action: ACTION, repo, vercel: false, force: true }, io())).files).toEqual([WORKFLOW_PATH]);

    await git(checkout, ['rm', '-q', 'package-lock.json']);
    await git(checkout, ['commit', '-qm', 'no lockfile']);
    await git(checkout, ['push', '-q', 'origin', 'main']);
    calls = [];
    await expect(init({ dir: checkout, action: ACTION, repo, vercel: false }, io())).rejects.toThrow(/has none on main/);
    expect(calls.filter((c) => c[1] === 'secret' || c[0] === 'interactive')).toEqual([]);
  });

  it('says what to do when nobody can answer, and what to allow when GitHub refuses', async () => {
    putResult = fail('gh: Conflict (HTTP 409)');
    actionsSettings = ok('{"enabled":true,"allowed_actions":"selected"}');
    selected = ok('{"github_owned_allowed":true,"patterns_allowed":[]}');
    const result = await init({ dir: checkout, action: ACTION, repo, vercel: false }, io({ tty: false }));
    expect(result).toMatchObject({ merged: false, secrets: { claude: 'not set', jev: 'skipped', slack: 'skipped' }, actions: 'not on', pullRequests: 'not on' });
    expect(logs).toContain('The CLAUDE_CODE_OAUTH_TOKEN secret is not set: run gh secret set CLAUDE_CODE_OAUTH_TOKEN --repo o/r and paste it.');
    expect(logs.some((line) => line.startsWith('Without Jev, Claude judges every finding') && line.includes('gh secret set TYPESAFE_API_KEY --repo o/r'))).toBe(true);
    expect(logs).toContain('o/r allows only some actions; add these at https://github.com/o/r/settings/actions: acme/patchhound@*.');
    expect(logs.some((line) => line.includes('Allow GitHub Actions to create and approve pull requests'))).toBe(true);
  });

  it('turns Actions on when it is off, and says where to merge when GitHub will not merge from here', async () => {
    actionsSettings = ok('{"enabled":false}');
    mergeResult = fail('GraphQL: Pull request is not mergeable: review required');
    const result = await init({ dir: checkout, action: ACTION, repo, vercel: false }, io());
    expect(result).toMatchObject({ actions: 'turned on', merged: false });
    expect(calls).toContainEqual(['gh', 'api', '-X', 'PUT', 'repos/o/r/actions/permissions', '-F', 'enabled=true']);
    expect(logs).toContain('It could not be merged from here (GraphQL: Pull request is not mergeable: review required): merge it at https://github.com/o/r/pull/7.');
  });

  it('with --no-pr, writes the files into the checkout instead', async () => {
    const result = await init({ dir: checkout, action: ACTION, repo, vercel: true, pr: false }, io());
    expect(result).toMatchObject({ pr: null, merged: false });
    expect(await readFile(join(checkout, WORKFLOW_PATH), 'utf8')).toBe(workflowFile({ action: ACTION, base: 'main' }));
    expect((await settings(await readFile(join(checkout, '.patchhound.yml'), 'utf8'))).fix.commitAs).toBe('actor');
    expect(calls.some((c) => c[1] === 'pr')).toBe(false);
  });
});

describe('the workflow file', () => {
  it('runs the given Action in all three jobs, and starts once it lands on the default branch', () => {
    const text = workflowFile({ action: 'acme/patchhound@v1', base: 'trunk' });
    expect(text.match(/uses: acme\/patchhound@v1/g)).toHaveLength(3);
    expect(text).toContain('    branches: [trunk]\n    paths: [.github/workflows/patchhound.yml]');
    expect(text).toContain('cron: "17 */4 * * *"   # every 4 hours');
    expect(workflowFile({ action: 'a/b@v1', base: 'main', schedule: '0 3 * * *' })).toContain('cron: "0 3 * * *"\n');
  });

  it('is the one the docs show', async () => {
    const docs = await readFile(join(import.meta.dirname, '..', '..', 'docs', 'github-action.md'), 'utf8');
    const shown = /`\.github\/workflows\/patchhound\.yml`:\n\n```yaml\n([\s\S]*?)```/.exec(docs)?.[1];
    expect(shown).toBe(workflowFile({ action: 'CodeGeek04/patchhound@v0', base: 'main' }));
  });
});
