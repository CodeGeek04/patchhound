import { spawn } from 'node:child_process';
import { access, mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { REPO_FILE } from '../config.js';
import type { GitHubRepo } from '../fix/git.js';
import { addWorktree, git, removeWorktree, repoInfo } from '../fix/git.js';
import type { ToolResult } from '../fix/pm.js';
import { runTool } from '../fix/pm.js';
import { noDashes } from '../fix/pr-body.js';
import { DEFAULT_SCHEDULE, WORKFLOW_PATH, workflowFile } from './workflow.js';

/**
 * `patchhound init`: sets a repo up for the GitHub Action in one go. It writes the workflow (and a
 * .patchhound.yml when a setting differs from the default), stores the Claude token as a repo secret
 * through gh's own hidden prompt, lets Actions open pull requests, and opens a setup PR. The person's
 * checkout is never touched: the PR is made from a worktree of the default branch.
 */

export const SETUP_BRANCH = 'patchhound/setup';

/** How init reaches GitHub and the person; the CLI's are real, tests pass fakes. */
export interface InitIO {
  /** gh with its output captured. */
  gh: (args: readonly string[]) => Promise<ToolResult>;
  /** A command the person answers in their own terminal (gh's hidden secret prompt, claude setup-token). */
  interactive: (argv: readonly string[]) => Promise<number | null>;
  /** A yes/no question; `fallback` when nobody can answer (no terminal). */
  ask: (question: string, fallback: boolean) => Promise<boolean>;
  /** Whether someone is at a terminal to answer. */
  tty: boolean;
  /** Whether a program is on the PATH. */
  onPath: (program: string) => Promise<boolean>;
  log: (line: string) => void;
}

export interface InitOptions {
  dir: string;
  /** The Action the workflow runs: `owner/repo@ref`. */
  action: string;
  /** Does the repo deploy on Vercel; asked (or read from vercel.json / .vercel) when undefined. */
  vercel?: boolean;
  /** An Anthropic API key (ANTHROPIC_API_KEY) instead of a Claude token. */
  apiKey?: boolean;
  schedule?: string;
  /** false: write the files into `dir` and open no PR. */
  pr?: boolean;
  /** Replace a workflow already there. */
  force?: boolean;
  /** The GitHub repository; origin's by default. */
  repo?: GitHubRepo;
}

export interface InitResult {
  repo: string;
  pr: string | null;
  files: string[];
  secret: 'present' | 'set' | 'not set';
  pullRequests: 'on' | 'turned on' | 'not on';
}

const LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'];

export async function init(options: InitOptions, io: InitIO = realIO()): Promise<InitResult> {
  const info = await repoInfo(options.dir);
  const repo = options.repo ?? info.github;
  if (!repo) throw new Error('origin is not a GitHub repository; Patchhound runs as a GitHub Action');
  const slug = `${repo.owner}/${repo.name}`;

  const about = await io.gh(['api', `repos/${slug}`, '--jq', '.default_branch']);
  if (about.code !== 0) throw new Error(`gh cannot read ${slug}: ${lastLine(about.output)} (gh auth login signs in)`);
  const base = about.output.trim();

  // What the files go on top of: the default branch as GitHub has it (a PR), or this checkout.
  const pr = options.pr !== false;
  let commit: string | null = null;
  if (pr) {
    await ghGit(info.top, ['fetch', '--quiet', 'origin', base]);
    commit = await git(info.top, ['rev-parse', 'FETCH_HEAD']);
  }
  const present = async (paths: readonly string[]) => {
    if (commit === null) return anyExists(info.top, paths);
    for (const path of paths) if (await git(info.top, ['cat-file', '-e', `${commit}:${path}`]).then(() => true, () => false)) return true;
    return false;
  };

  if (!(await present(LOCKFILES))) throw new Error(`Patchhound reads ${LOCKFILES.join(', ')} at the repo root, and ${slug} has none on ${pr ? base : 'this checkout'}`);
  // Before anything changes on GitHub.
  if (!options.force && (await present([WORKFLOW_PATH]))) throw new Error(`${slug} already has ${WORKFLOW_PATH}: --force replaces it`);

  const vercel = options.vercel ?? ((await present(['vercel.json'])) || (await anyExists(info.top, ['.vercel/project.json'])) || (await io.ask('Does this repo deploy on Vercel?', false)));
  const files = new Map<string, string>([[WORKFLOW_PATH, workflowFile({ action: options.action, base, apiKey: options.apiKey ?? false, ...(options.schedule ? { schedule: options.schedule } : {}) })]]);
  if (vercel) {
    if (await present([REPO_FILE])) io.log(`${REPO_FILE} is already there: add fix.commit_as: actor to it, so Vercel builds the fix PR's preview.`);
    else files.set(REPO_FILE, VERCEL_CONFIG);
  }

  const secret = await storeSecret(slug, options.apiKey ? 'ANTHROPIC_API_KEY' : 'CLAUDE_CODE_OAUTH_TOKEN', io);
  const pullRequests = await allowPullRequests(slug, io);

  let url: string | null = null;
  if (commit === null) {
    for (const [path, text] of files) await writeFiles(info.top, path, text);
    io.log(`Wrote ${[...files.keys()].join(' and ')}. Commit them to ${base} and the first run starts.`);
  } else {
    url = await openSetupPr(info.top, commit, slug, base, files, options.schedule ?? DEFAULT_SCHEDULE, io);
  }
  return { repo: slug, pr: url, files: [...files.keys()], secret, pullRequests };
}

const VERCEL_CONFIG = `# Patchhound's settings for this repo (every setting: patchhound init --config-only).
fix:
  # Vercel builds a private repo's previews only for its team members' commits, so the fix commits
  # are authored by the person who started the run (github-actions[bot] stays the committer).
  commit_as: actor
`;

/** Stores the Claude token (or API key) as a repo secret, unless it is there; gh asks for it, hidden. */
async function storeSecret(slug: string, name: string, io: InitIO): Promise<InitResult['secret']> {
  const list = await io.gh(['secret', 'list', '--repo', slug, '--json', 'name', '--jq', '.[].name']);
  if (list.code === 0 && list.output.split('\n').map((line) => line.trim()).includes(name)) return 'present';
  const command = `gh secret set ${name} --repo ${slug}`;
  if (!io.tty) {
    io.log(`The ${name} secret is not set: run ${command} and paste it.`);
    return 'not set';
  }
  if (name === 'CLAUDE_CODE_OAUTH_TOKEN' && (await io.onPath('claude')) && (await io.ask('Make a Claude token now (claude setup-token)?', true))) {
    io.log('Sign in in the browser; the token it prints goes in the next prompt.');
    await io.interactive(['claude', 'setup-token']);
  }
  io.log(`Paste the ${name === 'ANTHROPIC_API_KEY' ? 'API key' : 'Claude token'} (it is not shown); it is stored as the ${name} secret of ${slug}.`);
  if ((await io.interactive(['gh', 'secret', 'set', name, '--repo', slug])) === 0) return 'set';
  io.log(`The secret was not stored: run ${command} later.`);
  return 'not set';
}

/** Lets GitHub Actions open pull requests (off by default); an organization may forbid it. */
async function allowPullRequests(slug: string, io: InitIO): Promise<InitResult['pullRequests']> {
  const path = `repos/${slug}/actions/permissions/workflow`;
  const now = await io.gh(['api', path]);
  const settings = now.code === 0 ? (JSON.parse(now.output) as { default_workflow_permissions?: string; can_approve_pull_request_reviews?: boolean }) : null;
  if (settings?.can_approve_pull_request_reviews) return 'on';
  const set = await io.gh(['api', '-X', 'PUT', path, '-f', `default_workflow_permissions=${settings?.default_workflow_permissions ?? 'read'}`, '-F', 'can_approve_pull_request_reviews=true']);
  if (set.code === 0) return 'turned on';
  io.log(
    `Could not let GitHub Actions open pull requests (${lastLine(set.output)}). Tick "Allow GitHub Actions to create and approve pull requests" at https://github.com/${slug}/settings/actions (in an organization, an owner may have to allow it first).`,
  );
  return 'not on';
}

/** Commits the files on top of the default branch, in a worktree of its own, and opens the PR. */
async function openSetupPr(top: string, commit: string, slug: string, base: string, files: Map<string, string>, schedule: string, io: InitIO): Promise<string> {
  const worktree = await addWorktree(top, commit);
  try {
    for (const [path, text] of files) await writeFiles(worktree, path, text);
    await git(worktree, ['add', '--', ...files.keys()]);
    await git(worktree, ['commit', '--quiet', '--no-verify', '-m', 'Add Patchhound']);
    try {
      await ghGit(worktree, ['push', '--quiet', 'origin', `HEAD:refs/heads/${SETUP_BRANCH}`]);
    } catch {
      throw new Error(`${SETUP_BRANCH} is already on GitHub: merge or close its PR, or delete the branch, and run init again`);
    }
  } finally {
    await removeWorktree(top, worktree);
  }
  const created = await io.gh(['pr', 'create', '--repo', slug, '--base', base, '--head', SETUP_BRANCH, '--title', 'Add Patchhound', '--body', setupBody(files, schedule)]);
  if (created.code !== 0) throw new Error(`the branch ${SETUP_BRANCH} is pushed, but the PR could not be opened: ${lastLine(created.output)}`);
  return lastLine(created.output);
}

function setupBody(files: Map<string, string>, schedule: string): string {
  const when = schedule === DEFAULT_SCHEDULE ? 'Every 4 hours' : `On the schedule \`${schedule}\` (UTC)`;
  const lines = [
    `Adds Patchhound. ${when} it checks the dependencies for advisories, alerts on the ones the code exposes, and keeps one pull request open that fixes what it can.`,
    '',
    `- \`${WORKFLOW_PATH}\`: the scan, fix and publish jobs. The job that runs this project's code has no write access.`,
  ];
  if (files.has(REPO_FILE)) lines.push(`- \`${REPO_FILE}\`: the fix commits are authored by the person who started the run, so Vercel builds the PR's preview.`);
  lines.push('', "Merging starts the first run. Its report is on the run's Summary page in the Actions tab, and the fix PR, when there is one, shows up under Pull requests.");
  return noDashes(lines.join('\n'));
}

/**
 * git against GitHub with gh's sign-in, whatever credentials git itself has saved: GitHub refuses a
 * push that adds a workflow from a token without the workflow scope, which older saved tokens lack
 * and gh's sign-in has. An SSH remote uses its key, as before.
 */
async function ghGit(dir: string, args: readonly string[]): Promise<string> {
  return git(dir, ['-c', 'credential.https://github.com.helper=', '-c', 'credential.https://github.com.helper=!gh auth git-credential', ...args]);
}

/** Writes one file (init checked before that it may: see `present`). */
async function writeFiles(root: string, path: string, text: string): Promise<void> {
  await mkdir(dirname(join(root, path)), { recursive: true });
  await writeFile(join(root, path), text);
}

async function anyExists(top: string, paths: readonly string[]): Promise<boolean> {
  for (const path of paths) if (await access(join(top, path)).then(() => true, () => false)) return true;
  return false;
}

function lastLine(output: string): string {
  return output.trim().split('\n').at(-1) ?? '';
}

/** The terminal and gh of the person running init. gh keeps its own sign-in; it needs no token from us. */
export function realIO(): InitIO {
  return {
    gh: (args) => runTool(['gh', ...args], { cwd: process.cwd(), env: process.env, timeoutMs: 120_000 }),
    interactive: (argv) =>
      new Promise((resolve) => {
        const [command, ...args] = argv as [string, ...string[]];
        const child = spawn(command, args, { stdio: 'inherit' });
        child.on('error', () => resolve(127));
        child.on('close', (code) => resolve(code));
      }),
    ask: async (question, fallback) => {
      if (!process.stdin.isTTY) return fallback;
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      try {
        const answer = (await rl.question(`${question} ${fallback ? '[Y/n]' : '[y/N]'} `)).trim().toLowerCase();
        return answer === '' ? fallback : answer.startsWith('y');
      } finally {
        rl.close();
      }
    },
    tty: Boolean(process.stdin.isTTY),
    onPath: async (program) => (await runTool(['sh', '-c', `command -v ${program}`], { cwd: process.cwd(), timeoutMs: 10_000 })).code === 0,
    log: (line) => process.stdout.write(`${line}\n`),
  };
}
