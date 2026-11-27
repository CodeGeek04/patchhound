import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { git } from '../../src/fix/git.js';
import type { ToolResult } from '../../src/fix/pm.js';
import type { InitIO } from '../../src/setup/init.js';
import { init } from '../../src/setup/init.js';
import { WORKFLOW_PATH, workflowFile } from '../../src/setup/workflow.js';

const ok = (output = ''): ToolResult => ({ code: 0, timedOut: false, output });
const fail = (output: string): ToolResult => ({ code: 1, timedOut: false, output });
const ACTION = 'acme/bulwark@main';
const repo = { owner: 'o', name: 'r' };

describe('bulwark init', () => {
  let root: string;
  let origin: string;
  let checkout: string;
  let calls: string[][];
  let answers: { question: string; fallback: boolean }[];
  let logs: string[];
  let secrets: string;
  let workflowSettings: ToolResult;
  let putResult: ToolResult;

  const io = (overrides: Partial<InitIO> = {}): InitIO => ({
    gh: async (args) => {
      calls.push(['gh', ...args]);
      if (args[0] === 'api' && args[1] === 'repos/o/r') return ok('main\n');
      if (args[0] === 'secret' && args[1] === 'list') return ok(secrets);
      if (args[0] === 'api' && args[1] === 'repos/o/r/actions/permissions/workflow') return workflowSettings;
      if (args[0] === 'api' && args[1] === '-X') return putResult;
      if (args[0] === 'pr' && args[1] === 'create') return ok('Creating pull request\nhttps://github.com/o/r/pull/7\n');
      throw new Error(`unexpected gh ${args.join(' ')}`);
    },
    interactive: async (argv) => {
      calls.push(['interactive', ...argv]);
      return 0;
    },
    ask: async (question, fallback) => {
      answers.push({ question, fallback });
      return true;
    },
    tty: true,
    onPath: async () => true,
    log: (line) => logs.push(line),
    ...overrides,
  });

  const show = (path: string) => git(origin, ['show', `bulwark/setup:${path}`]);

  beforeEach(async () => {
    calls = [];
    answers = [];
    logs = [];
    secrets = '';
    workflowSettings = ok('{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}');
    putResult = ok();
    root = await mkdtemp(join(tmpdir(), 'bulwark-init-'));
    origin = join(root, 'origin.git');
    checkout = join(root, 'app');
    await git(root, ['init', '-q', '--bare', '-b', 'main', origin]);
    await git(root, ['clone', '-q', origin, checkout]);
    await git(checkout, ['checkout', '-q', '-b', 'main']);
    await writeFile(join(checkout, 'package.json'), '{"name":"app"}\n');
    await writeFile(join(checkout, 'package-lock.json'), '{"lockfileVersion":3,"packages":{}}\n');
    await git(checkout, ['add', '-A']);
    await git(checkout, ['-c', 'user.email=dev@example.com', '-c', 'user.name=dev', 'commit', '-qm', 'app']);
    await git(checkout, ['push', '-q', 'origin', 'main']);
    await git(checkout, ['config', 'user.email', 'dev@example.com']);
    await git(checkout, ['config', 'user.name', 'dev']);
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it('opens a setup PR with the workflow, stores the token, and lets Actions open PRs, leaving the checkout alone', async () => {
    await writeFile(join(checkout, 'work-in-progress.txt'), 'not committed\n');
    const head = await git(checkout, ['rev-parse', 'HEAD']);
    const result = await init({ dir: checkout, action: ACTION, repo }, io());

    expect(result).toEqual({ repo: 'o/r', pr: 'https://github.com/o/r/pull/7', files: [WORKFLOW_PATH, '.bulwark.yml'], secret: 'set', pullRequests: 'turned on' });
    expect(await show(WORKFLOW_PATH)).toBe(workflowFile({ action: ACTION, base: 'main' }).trimEnd());
    expect(await show('.bulwark.yml')).toContain('commit_as: actor');
    expect(await git(origin, ['log', '-1', '--format=%s|%ae', 'bulwark/setup'])).toBe('Add Bulwark|dev@example.com');
    // The person's own checkout: same commit, same files, nothing added.
    expect(await git(checkout, ['rev-parse', 'HEAD'])).toBe(head);
    expect(await git(checkout, ['status', '--porcelain'])).toBe('?? work-in-progress.txt');
    expect((await git(checkout, ['worktree', 'list'])).split('\n')).toHaveLength(1);

    expect(calls).toContainEqual(['interactive', 'claude', 'setup-token']);
    expect(calls).toContainEqual(['interactive', 'gh', 'secret', 'set', 'CLAUDE_CODE_OAUTH_TOKEN', '--repo', 'o/r']);
    // The default workflow permissions stay as they were.
    expect(calls).toContainEqual(['gh', 'api', '-X', 'PUT', 'repos/o/r/actions/permissions/workflow', '-f', 'default_workflow_permissions=read', '-F', 'can_approve_pull_request_reviews=true']);
    const create = calls.find((c) => c[1] === 'pr')!;
    expect(create.slice(0, 10)).toEqual(['gh', 'pr', 'create', '--repo', 'o/r', '--base', 'main', '--head', 'bulwark/setup', '--title']);
    expect(create.at(-1)).toContain('Vercel builds the PR');
  });

  it('skips what is already done: the secret, the setting, and no .bulwark.yml off Vercel', async () => {
    secrets = 'OTHER\nCLAUDE_CODE_OAUTH_TOKEN\n';
    workflowSettings = ok('{"default_workflow_permissions":"write","can_approve_pull_request_reviews":true}');
    const result = await init({ dir: checkout, action: ACTION, repo, vercel: false }, io());
    expect(result).toMatchObject({ files: [WORKFLOW_PATH], secret: 'present', pullRequests: 'on' });
    expect(calls.filter((c) => c[0] === 'interactive' || c[2] === '-X')).toEqual([]);
    expect(answers).toEqual([]);
  });

  it('uses an API key secret and its Action input with --api-key', async () => {
    await init({ dir: checkout, action: ACTION, repo, vercel: false, apiKey: true }, io());
    expect(await show(WORKFLOW_PATH)).toContain('anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}');
    expect(calls).toContainEqual(['interactive', 'gh', 'secret', 'set', 'ANTHROPIC_API_KEY', '--repo', 'o/r']);
    expect(calls.some((c) => c.includes('setup-token'))).toBe(false);
  });

  it('stops before changing anything when the repo already has the workflow, or has no lockfile', async () => {
    await mkdir(join(checkout, '.github', 'workflows'), { recursive: true });
    await writeFile(join(checkout, WORKFLOW_PATH), 'name: old\n');
    await git(checkout, ['add', WORKFLOW_PATH]);
    await git(checkout, ['commit', '-qm', 'old workflow']);
    await git(checkout, ['push', '-q', 'origin', 'main']);
    await expect(init({ dir: checkout, action: ACTION, repo, vercel: false }, io())).rejects.toThrow(`o/r already has ${WORKFLOW_PATH}: --force replaces it`);
    expect(calls.filter((c) => c[1] === 'secret' || c[1] === 'pr' || c[0] === 'interactive')).toEqual([]);

    await git(checkout, ['rm', '-q', 'package-lock.json']);
    await git(checkout, ['commit', '-qm', 'no lockfile']);
    await git(checkout, ['push', '-q', 'origin', 'main']);
    await expect(init({ dir: checkout, action: ACTION, repo, vercel: false, force: true }, io())).rejects.toThrow(/has none on main/);
  });

  it('says where to tick the setting when GitHub refuses it, and what to run when nobody can paste the token', async () => {
    putResult = fail('gh: Conflict (HTTP 409)');
    const result = await init({ dir: checkout, action: ACTION, repo, vercel: false }, io({ tty: false }));
    expect(result).toMatchObject({ secret: 'not set', pullRequests: 'not on' });
    expect(logs).toContain('The CLAUDE_CODE_OAUTH_TOKEN secret is not set: run gh secret set CLAUDE_CODE_OAUTH_TOKEN --repo o/r and paste it.');
    expect(logs.some((line) => line.includes('https://github.com/o/r/settings/actions'))).toBe(true);
  });

  it('with --no-pr, writes the files into the checkout instead', async () => {
    const result = await init({ dir: checkout, action: ACTION, repo, vercel: true, pr: false }, io());
    expect(result.pr).toBeNull();
    expect(await readFile(join(checkout, WORKFLOW_PATH), 'utf8')).toBe(workflowFile({ action: ACTION, base: 'main' }));
    expect(await readFile(join(checkout, '.bulwark.yml'), 'utf8')).toContain('commit_as: actor');
    expect(calls.some((c) => c[1] === 'pr')).toBe(false);
  });
});

describe('the workflow file', () => {
  it('runs the given Action in all three jobs, and starts once it lands on the default branch', () => {
    const text = workflowFile({ action: 'acme/bulwark@v1', base: 'trunk' });
    expect(text.match(/uses: acme\/bulwark@v1/g)).toHaveLength(3);
    expect(text).toContain('    branches: [trunk]\n    paths: [.github/workflows/bulwark.yml]');
    expect(text).toContain('cron: "17 */4 * * *"   # every 4 hours');
    expect(workflowFile({ action: 'a/b@v1', base: 'main', schedule: '0 3 * * *' })).toContain('cron: "0 3 * * *"\n');
  });

  it('is the one the docs show', async () => {
    const docs = await readFile(join(import.meta.dirname, '..', '..', 'docs', 'github-action.md'), 'utf8');
    const shown = /`\.github\/workflows\/bulwark\.yml`:\n\n```yaml\n([\s\S]*?)```/.exec(docs)?.[1];
    expect(shown).toBe(workflowFile({ action: 'CodeGeek04/bulwark@v0', base: 'main' }));
  });
});
