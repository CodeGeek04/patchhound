import { spawn } from 'node:child_process';
import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import { delimiter, dirname, join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { isMap, isSeq, parseDocument } from 'yaml';
import { REPO_FILE } from '../config.js';
import type { GitHubRepo } from '../fix/git.js';
import { addWorktree, BRANCH_NAME, git, removeWorktree, repoInfo } from '../fix/git.js';
import type { ToolResult } from '../fix/pm.js';
import { runTool, safeEnv } from '../fix/pm.js';
import { noDashes } from '../fix/pr-body.js';
import { DEFAULT_SCHEDULE, WORKFLOW_PATH, workflowFile } from './workflow.js';

/**
 * `patchhound init`: everything a repo needs for the GitHub Action, in one command. It
 * - writes the workflow, and the .patchhound.yml settings the answers call for (Slack alerts on,
 *   Vercel's commit author), editing a .patchhound.yml already there;
 * - stores the secrets through gh's own hidden prompt: the Claude token, the Jev key (which makes
 *   triage faster and cheaper) and the Slack webhook;
 * - makes sure Actions is on and may run the actions the workflow uses, and may open pull requests;
 * - opens a setup PR (or updates its own from an earlier run) and offers to merge it, which starts
 *   the first run.
 * The person's checkout is never touched: the PR is made from a worktree of the default branch. Run it
 * again at any time: it does only what is still missing.
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
  /** The branch fix PRs go to (staging, say); the default branch when unset, or asked when the repo has a staging or develop branch. */
  branch?: string;
  /** The GitHub repository; origin's by default. */
  repo?: GitHubRepo;
}

export type SecretState = 'present' | 'set' | 'not set' | 'skipped';
export type SettingState = 'on' | 'turned on' | 'not on';

export interface InitResult {
  repo: string;
  /** The branch fix PRs go to. */
  branch: string;
  /** The setup PR, when there was anything to add to the repo. */
  pr: string | null;
  merged: boolean;
  /** What the PR adds or changes (or, with pr: false, what was written). */
  files: string[];
  secrets: { claude: SecretState; jev: SecretState; slack: SecretState };
  actions: SettingState;
  pullRequests: SettingState;
}

const LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'];
/** The actions the workflow and the Patchhound Action use, besides Patchhound itself. */
const GITHUB_ACTIONS = ['actions/checkout', 'actions/setup-node', 'actions/cache', 'actions/upload-artifact', 'actions/download-artifact'];

interface RepoAbout {
  default_branch: string;
  allow_merge_commit?: boolean;
  allow_squash_merge?: boolean;
  allow_rebase_merge?: boolean;
}

export async function init(options: InitOptions, io: InitIO = realIO()): Promise<InitResult> {
  const info = await repoInfo(options.dir);
  const repo = options.repo ?? info.github;
  if (!repo) throw new Error('origin is not a GitHub repository; Patchhound runs as a GitHub Action');
  const slug = `${repo.owner}/${repo.name}`;

  const read = await io.gh(['api', `repos/${slug}`]);
  if (read.code !== 0) throw new Error(`gh cannot read ${slug}: ${lastLine(read.output)} (gh auth login signs in)`);
  const about = JSON.parse(read.output) as RepoAbout;
  const base = await fixBranch(slug, about.default_branch, options.branch, io);

  // What the files go on top of: the default branch as GitHub has it (a PR), or this checkout.
  let commit: string | null = null;
  if (options.pr !== false) {
    await ghGit(info.top, ['fetch', '--quiet', 'origin', base]);
    commit = await git(info.top, ['rev-parse', 'FETCH_HEAD']);
  }
  const readAt = async (path: string): Promise<string | null> =>
    commit === null ? readFile(join(info.top, path), 'utf8').catch(() => null) : git(info.top, ['show', `${commit}:${path}`]).then((text) => `${text}\n`, () => null);
  const present = async (paths: readonly string[]) => {
    if (commit === null) return anyExists(info.top, paths);
    for (const path of paths) if (await git(info.top, ['cat-file', '-e', `${commit}:${path}`]).then(() => true, () => false)) return true;
    return false;
  };

  if (!(await present(LOCKFILES))) throw new Error(`Patchhound reads ${LOCKFILES.join(', ')} at the repo root, and ${slug} has none on ${commit ? base : 'this checkout'}`);

  const files = new Map<string, string>();
  if (options.force || !(await present([WORKFLOW_PATH]))) {
    files.set(WORKFLOW_PATH, workflowFile({ action: options.action, base, defaultBranch: about.default_branch, apiKey: options.apiKey ?? false, ...(options.schedule ? { schedule: options.schedule } : {}) }));
  } else {
    io.log(`${WORKFLOW_PATH} is already on ${base}: kept (--force writes it again).`);
  }

  const vercel = options.vercel ?? ((await present(['vercel.json'])) || (await anyExists(info.top, ['.vercel/project.json'])) || (await io.ask('Does this repo deploy on Vercel?', false)));

  const secretNames = await listSecrets(slug, io);
  const claude = await claudeSecret(slug, options.apiKey ? 'ANTHROPIC_API_KEY' : 'CLAUDE_CODE_OAUTH_TOKEN', secretNames, io);
  const jev = await extraSecret(slug, 'TYPESAFE_API_KEY', secretNames, io, {
    question: 'Add your Jev (TypeSafe) API key? Jev answers most triage questions faster and cheaper than Claude, which then judges only what Jev is unsure of. Keys: console.typesafe.ai',
    paste: 'Paste the TypeSafe API key',
    without: 'Without Jev, Claude judges every finding: slower, and more of your Claude usage.',
  });
  const slack = await extraSecret(slug, 'SLACK_WEBHOOK_URL', secretNames, io, {
    question: 'Send alerts to Slack? It takes a Slack incoming webhook URL (api.slack.com/messaging/webhooks).',
    paste: 'Paste the Slack webhook URL',
    without: "Without a channel, alerts only show on each run's Summary page in the Actions tab.",
  });

  const current = await readAt(REPO_FILE);
  // Slack just stored: alerts on. Stored before: on too, unless the file already says how alerts go
  // (a dry_run: true or a channel list someone set on purpose stays as it is).
  const alerts = slack === 'set' || (slack === 'present' && !choosesAlerts(current));
  if (slack === 'present' && !alerts && current !== null && parseDocument(current).get('dry_run') === true) io.log(`${REPO_FILE} sets dry_run: true, so alerts are only printed in the run's log; set it to false to send them to Slack.`);
  const config = editConfig(current, { alerts, vercel });
  if (config !== null) files.set(REPO_FILE, config);

  const actions = await enableActions(slug, options.action, io);
  const pullRequests = await allowPullRequests(slug, io);

  let url: string | null = null;
  let merged = false;
  if (files.size === 0) {
    io.log(`Nothing to add to the repo: the workflow and settings are already on ${base}.`);
  } else if (commit === null) {
    for (const [path, text] of files) await writeFiles(info.top, path, text);
    io.log(`Wrote ${[...files.keys()].join(' and ')}. Commit them to ${base} and the first run starts.`);
  } else {
    const pr = await setupPr(info.top, commit, slug, base, files, options.schedule ?? DEFAULT_SCHEDULE, io);
    url = pr.url;
    merged = await offerMerge(pr.url, pr.head, files, about, io);
  }
  return { repo: slug, branch: base, pr: url, merged, files: [...files.keys()], secrets: { claude, jev, slack }, actions, pullRequests };
}

/** Branches a team may send work to before it reaches the default branch, in the order init offers them. */
const INTEGRATION_BRANCHES = ['staging', 'develop'];

/**
 * The branch fix PRs go to: the one asked for; else the one an earlier init set up (the workflow's
 * PATCHHOUND_BASE, on the default branch or on a staging branch it has not reached main from yet);
 * else, when the repo has a staging or develop branch, that one if the person says so; else the
 * default branch.
 */
async function fixBranch(slug: string, defaultBranch: string, asked: string | undefined, io: InitIO): Promise<string> {
  const exists = async (branch: string) => (await io.gh(['api', `repos/${slug}/branches/${encodeURIComponent(branch)}`, '--jq', '.name'])).code === 0;
  let branch = asked;
  if (branch === undefined) {
    for (const candidate of [defaultBranch, ...INTEGRATION_BRANCHES.filter((b) => b !== defaultBranch)]) {
      const read = await io.gh(['api', `repos/${slug}/contents/${WORKFLOW_PATH}?ref=${encodeURIComponent(candidate)}`, '--jq', '.content']);
      if (read.code !== 0) continue;
      const text = Buffer.from(read.output.replace(/\s/g, ''), 'base64').toString('utf8');
      branch = /^\s*PATCHHOUND_BASE:\s*["']?([\w./-]+)/m.exec(text)?.[1] ?? (candidate === defaultBranch ? defaultBranch : undefined);
      if (branch) break;
    }
  }
  if (branch === undefined) {
    branch = defaultBranch;
    for (const candidate of INTEGRATION_BRANCHES.filter((b) => b !== defaultBranch)) {
      if (!(await exists(candidate))) continue;
      if (await io.ask(`Fix PRs go to ${defaultBranch}, the default branch. This repo also has ${candidate}: send them to ${candidate} instead?`, false)) branch = candidate;
      break;
    }
  }
  if (!BRANCH_NAME.test(branch)) throw new Error(`not a branch name: ${branch}`);
  if (branch !== defaultBranch) {
    if (!(await exists(branch))) throw new Error(`${slug} has no branch ${branch}`);
    io.log(
      `Fix PRs go to ${branch}, and the setup PR does too. Merging it into ${branch} starts the first run; scheduled runs start once the workflow reaches ${defaultBranch}, with your next release (GitHub runs schedules only from the default branch).`,
    );
  }
  return branch;
}

/** Whether a .patchhound.yml already says how alerts go: dry_run, or a list of channels. */
function choosesAlerts(current: string | null): boolean {
  if (current === null) return false;
  const doc = parseDocument(current);
  return doc.has('dry_run') || doc.hasIn(['notify', 'channels']);
}

/**
 * The .patchhound.yml the answers call for, from the one on the default branch (comments and other
 * settings kept); null when it needs no change. `alerts`: Slack on, and dry_run off, which is what
 * lets alerts go out. `vercel`: the fix commits are authored by the person who started the run.
 */
export function editConfig(current: string | null, want: { alerts: boolean; vercel: boolean }): string | null {
  if (current === null) {
    if (!want.alerts && !want.vercel) return null;
    const parts = ["# Patchhound's settings for this repo. Every setting: https://github.com/CodeGeek04/patchhound/blob/main/docs/github-action.md#3-settings"];
    if (want.alerts) {
      parts.push(
        '',
        '# Send alerts to the channels below (dry_run: true only prints them in the run\'s log).',
        'dry_run: false',
        'notify:',
        '  channels:',
        '    # The webhook URL is the repo secret SLACK_WEBHOOK_URL.',
        '    - type: slack',
      );
    }
    if (want.vercel) {
      parts.push(
        '',
        'fix:',
        "  # Vercel builds a private repo's previews only for its team members' commits, so the fix commits",
        '  # are authored by the person who started the run (github-actions[bot] stays the committer).',
        '  commit_as: actor',
      );
    }
    return `${parts.join('\n')}\n`;
  }
  const doc = parseDocument(current);
  let changed = false;
  if (want.alerts) {
    if (doc.get('dry_run') !== false) {
      doc.set('dry_run', false);
      changed = true;
    }
    const channels = doc.getIn(['notify', 'channels']);
    const slack = isSeq(channels) && channels.items.some((item) => isMap(item) && item.get('type') === 'slack');
    if (!slack) {
      if (isSeq(channels)) channels.add(doc.createNode({ type: 'slack' }));
      else doc.setIn(['notify', 'channels'], doc.createNode([{ type: 'slack' }]));
      changed = true;
    }
  }
  if (want.vercel && doc.getIn(['fix', 'commit_as']) !== 'actor') {
    doc.setIn(['fix', 'commit_as'], 'actor');
    changed = true;
  }
  return changed ? doc.toString() : null;
}

async function listSecrets(slug: string, io: InitIO): Promise<Set<string>> {
  const list = await io.gh(['secret', 'list', '--repo', slug, '--json', 'name', '--jq', '.[].name']);
  return new Set(list.code === 0 ? list.output.split('\n').map((line) => line.trim()).filter(Boolean) : []);
}

/** Stores a secret through gh's hidden prompt. */
async function setSecret(slug: string, name: string, paste: string, io: InitIO): Promise<boolean> {
  io.log(`${paste} (it is not shown); it is stored as the ${name} secret of ${slug}.`);
  if ((await io.interactive(['gh', 'secret', 'set', name, '--repo', slug])) === 0) return true;
  io.log(`${name} was not stored: run gh secret set ${name} --repo ${slug} later.`);
  return false;
}

/** The Claude token (or API key): the one secret a run cannot do without. */
async function claudeSecret(slug: string, name: string, have: ReadonlySet<string>, io: InitIO): Promise<SecretState> {
  if (have.has(name)) return 'present';
  if (!io.tty) {
    io.log(`The ${name} secret is not set: run gh secret set ${name} --repo ${slug} and paste it.`);
    return 'not set';
  }
  if (name === 'CLAUDE_CODE_OAUTH_TOKEN' && (await io.onPath('claude')) && (await io.ask('Make a Claude token now (claude setup-token)?', true))) {
    io.log('Sign in in the browser; the token it prints goes in the next prompt.');
    await io.interactive(['claude', 'setup-token']);
  }
  return (await setSecret(slug, name, name === 'ANTHROPIC_API_KEY' ? 'Paste the Anthropic API key' : 'Paste the Claude token', io)) ? 'set' : 'not set';
}

/** The Jev key or the Slack webhook: asked for, unless already there. */
async function extraSecret(slug: string, name: string, have: ReadonlySet<string>, io: InitIO, text: { question: string; paste: string; without: string }): Promise<SecretState> {
  if (have.has(name)) return 'present';
  const later = `Add it later: gh secret set ${name} --repo ${slug} (and run npx patchhound init again).`;
  if (!io.tty || !(await io.ask(text.question, true))) {
    io.log(`${text.without} ${later}`);
    return 'skipped';
  }
  return (await setSecret(slug, name, text.paste, io)) ? 'set' : 'not set';
}

/**
 * Actions must be on, and allowed to run GitHub's own actions and Patchhound's. It is turned on when
 * off; a narrower list of allowed actions is the owner's choice, so init says what to add to it.
 */
async function enableActions(slug: string, action: string, io: InitIO): Promise<SettingState> {
  const path = `repos/${slug}/actions/permissions`;
  const now = await io.gh(['api', path]);
  if (now.code !== 0) return 'on'; // Not readable with this sign-in: the first run will tell.
  const settings = JSON.parse(now.output) as { enabled?: boolean; allowed_actions?: string };
  let state: SettingState = 'on';
  if (settings.enabled === false) {
    if ((await io.gh(['api', '-X', 'PUT', path, '-F', 'enabled=true'])).code !== 0) {
      io.log(`GitHub Actions is off for ${slug}, and it could not be turned on: turn it on at https://github.com/${slug}/settings/actions.`);
      return 'not on';
    }
    state = 'turned on';
  }
  const own = action.split('@')[0]!;
  const needed = [...GITHUB_ACTIONS, own];
  let missing: string[] = [];
  if (settings.allowed_actions === 'local_only') missing = needed;
  else if (settings.allowed_actions === 'selected') {
    const selected = await io.gh(['api', `${path}/selected-actions`]);
    const allowed = selected.code === 0 ? (JSON.parse(selected.output) as { github_owned_allowed?: boolean; patterns_allowed?: string[] }) : {};
    const patterns = allowed.patterns_allowed ?? [];
    const allows = (name: string) => patterns.some((p) => p === name || p === `${name}@*` || p.startsWith(`${name}@`) || p === `${name.split('/')[0]}/*`);
    missing = needed.filter((name) => !(name.startsWith('actions/') && allowed.github_owned_allowed) && !allows(name));
  }
  if (missing.length === 0) return state;
  io.log(`${slug} allows only some actions; add these at https://github.com/${slug}/settings/actions: ${missing.map((name) => `${name}@*`).join(', ')}.`);
  return 'not on';
}

/** Lets GitHub Actions open pull requests (off by default); an organization may forbid it. */
async function allowPullRequests(slug: string, io: InitIO): Promise<SettingState> {
  const path = `repos/${slug}/actions/permissions/workflow`;
  const now = await io.gh(['api', path]);
  const tick = `Tick "Allow GitHub Actions to create and approve pull requests" at https://github.com/${slug}/settings/actions (in an organization, an owner may have to allow it first).`;
  if (now.code !== 0) {
    // Written back without reading, the default token permissions could change: leave it to the person.
    io.log(`Could not read whether GitHub Actions may open pull requests (${lastLine(now.output)}). ${tick}`);
    return 'not on';
  }
  const settings = JSON.parse(now.output) as { default_workflow_permissions?: string; can_approve_pull_request_reviews?: boolean };
  if (settings.can_approve_pull_request_reviews) return 'on';
  const set = await io.gh(['api', '-X', 'PUT', path, '-f', `default_workflow_permissions=${settings.default_workflow_permissions ?? 'read'}`, '-F', 'can_approve_pull_request_reviews=true']);
  if (set.code === 0) {
    io.log('Turned on "Allow GitHub Actions to create and approve pull requests". It is one GitHub setting: it also lets workflows approve pull requests.');
    return 'turned on';
  }
  io.log(`Could not let GitHub Actions open pull requests (${lastLine(set.output)}). ${tick}`);
  return 'not on';
}

/**
 * Commits the files on top of the default branch, in a worktree of its own, and opens the setup PR,
 * or updates the one an earlier run opened (the branch is init's own, so it is replaced).
 */
async function setupPr(top: string, commit: string, slug: string, base: string, files: Map<string, string>, schedule: string, io: InitIO): Promise<{ url: string; head: string }> {
  // The branch from an earlier run is replaced only when it holds init's own commit and nothing else.
  const earlier = (await ghGit(top, ['ls-remote', 'origin', `refs/heads/${SETUP_BRANCH}`])).split(/\s/)[0] ?? '';
  if (earlier) {
    await ghGit(top, ['fetch', '--quiet', 'origin', earlier]);
    const extra = (await git(top, ['log', '--format=%s', earlier, '--not', commit])).split('\n').filter(Boolean);
    if (extra.length > 1 || (extra.length === 1 && extra[0] !== 'Add Patchhound')) {
      throw new Error(`${SETUP_BRANCH} on GitHub has commits init did not make: merge or close its PR (or delete the branch), then run init again`);
    }
  }
  const worktree = await addWorktree(top, commit);
  let head: string;
  try {
    for (const [path, text] of files) await writeFiles(worktree, path, text);
    await git(worktree, ['add', '--', ...files.keys()]);
    await git(worktree, ['commit', '--quiet', '--no-verify', '-m', 'Add Patchhound']);
    head = await git(worktree, ['rev-parse', 'HEAD']);
    await ghGit(worktree, ['push', '--quiet', `--force-with-lease=refs/heads/${SETUP_BRANCH}:${earlier}`, 'origin', `HEAD:refs/heads/${SETUP_BRANCH}`]);
  } finally {
    await removeWorktree(top, worktree);
  }
  const body = setupBody(files, schedule);
  // gh matches --head by branch name alone, so a fork's PR from a branch of the same name would match
  // too: only a PR from this repository's own branch is init's.
  const open = await io.gh(['pr', 'list', '--repo', slug, '--head', SETUP_BRANCH, '--state', 'open', '--json', 'url,isCrossRepository', '--jq', '[.[] | select(.isCrossRepository | not)][0].url // ""']);
  const existing = open.code === 0 ? open.output.trim() : '';
  if (existing) {
    await io.gh(['pr', 'edit', existing, '--body', body]);
    return { url: existing, head };
  }
  const created = await io.gh(['pr', 'create', '--repo', slug, '--base', base, '--head', SETUP_BRANCH, '--title', 'Add Patchhound', '--body', body]);
  if (created.code !== 0) throw new Error(`the branch ${SETUP_BRANCH} is pushed, but the PR could not be opened: ${lastLine(created.output)}`);
  return { url: lastLine(created.output), head };
}

/**
 * Merges the setup PR when the person says so (which starts the first run, when it adds the
 * workflow), and only at the commit init pushed.
 */
async function offerMerge(url: string, head: string, files: ReadonlyMap<string, string>, about: RepoAbout, io: InitIO): Promise<boolean> {
  const startsRun = files.has(WORKFLOW_PATH);
  if (!io.tty || !(await io.ask(`Merge the setup PR now (${[...files.keys()].join(', ')})?${startsRun ? ' That starts the first run.' : ''}`, true))) return false;
  const method = about.allow_merge_commit !== false ? '--merge' : about.allow_squash_merge !== false ? '--squash' : '--rebase';
  const result = await io.gh(['pr', 'merge', url, method, '--match-head-commit', head, '--delete-branch']);
  if (result.code === 0) return true;
  io.log(`It could not be merged from here (${lastLine(result.output)}): merge it at ${url}.`);
  return false;
}

function setupBody(files: Map<string, string>, schedule: string): string {
  const when = schedule === DEFAULT_SCHEDULE ? 'Every 4 hours' : `On the schedule \`${schedule}\` (UTC)`;
  const lines = [`Adds Patchhound. ${when} it checks the dependencies for advisories, alerts on the ones the code exposes, and keeps one pull request open that fixes what it can.`, ''];
  if (files.has(WORKFLOW_PATH)) lines.push(`- \`${WORKFLOW_PATH}\`: the scan, fix and publish jobs. The job that runs this project's code has no write access.`);
  if (files.has(REPO_FILE)) lines.push(`- \`${REPO_FILE}\`: this repo's settings (alerts to Slack, and the fix commits' author for Vercel previews, as chosen).`);
  if (files.has(WORKFLOW_PATH)) lines.push('', "Merging starts the first run. Its report is on the run's Summary page in the Actions tab, and the fix PR, when there is one, shows up under Pull requests.");
  else lines.push('', 'The next run uses these settings (Run workflow in the Actions tab starts one now).');
  return noDashes(lines.join('\n'));
}

/**
 * git against GitHub with gh's sign-in, whatever credentials git itself has saved: GitHub refuses a
 * push that adds a workflow from a token without the workflow scope, which older saved tokens lack
 * and gh's sign-in has. An SSH remote uses its key, as before.
 */
async function ghGit(dir: string, args: readonly string[]): Promise<string> {
  // gh's sign-in may be only GH_TOKEN in the environment, which git commands do not get by default.
  return git(dir, ['-c', 'credential.https://github.com.helper=', '-c', 'credential.https://github.com.helper=!gh auth git-credential', ...args], safeEnv(['GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN']));
}

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
    onPath: async (program) => {
      const extensions = process.platform === 'win32' ? (process.env.PATHEXT ?? '.EXE;.CMD;.BAT').split(';') : [''];
      for (const folder of (process.env.PATH ?? '').split(delimiter).filter(Boolean)) {
        for (const extension of extensions) if (await access(join(folder, `${program}${extension}`)).then(() => true, () => false)) return true;
      }
      return false;
    },
    log: (line) => process.stdout.write(`${line}\n`),
  };
}
