import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runTool, safeEnv, tail } from './pm.js';

/**
 * Runs git in `dir`; throws with git's own message when it fails. The user's hooks never run (a
 * post-checkout hook that installs would run a malicious package before anything is checked).
 */
export async function git(dir: string, args: readonly string[], env?: NodeJS.ProcessEnv): Promise<string> {
  const result = await runTool(['git', '-c', 'core.hooksPath=/dev/null', ...args], { cwd: dir, timeoutMs: 10 * 60_000, ...(env ? { env } : {}) });
  if (result.code !== 0) throw new Error(`git ${args.join(' ')} failed: ${tail(result.output, 8)}`);
  return result.output.trim();
}

/** gh gets the GitHub token; nothing else patchhound runs does. */
const ghEnv = () => safeEnv(['GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN']);

/** Who a commit is from. */
export interface Identity {
  name: string;
  email: string;
}

/**
 * GitHub Actions' own bot: the committer of every commit patchhound makes, and by default its
 * author too. GitHub shows it as github-actions[bot].
 */
export const SELF: Identity = { name: 'github-actions[bot]', email: '41898282+github-actions[bot]@users.noreply.github.com' };

/**
 * The address earlier versions committed with. GitHub links it to an unrelated account, so it is
 * never written again; it is still read, so a PR opened before the change stays patchhound's.
 */
const FORMER_EMAIL = 'security-agent@users.noreply.github.com';

/** Whether patchhound made a commit: it is the committer (whoever the author is, see commitAuthor). */
export function isOwnCommit(committerEmail: string): boolean {
  return committerEmail === SELF.email || committerEmail === FORMER_EMAIL;
}

/**
 * The author of patchhound's commits. `bot`: SELF. `actor`: the person who started the workflow
 * run, from GitHub's GITHUB_ACTOR and GITHUB_ACTOR_ID: a host that builds previews only for its own
 * members' commits (Vercel, for a private repo) then builds the PR. Outside a run, or when a bot
 * started it, SELF.
 */
export function commitAuthor(commitAs: 'bot' | 'actor', env: NodeJS.ProcessEnv = process.env): Identity {
  const login = env.GITHUB_ACTOR ?? '';
  const id = env.GITHUB_ACTOR_ID ?? '';
  if (commitAs === 'bot' || !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(login) || !/^\d+$/.test(id)) return SELF;
  return { name: login, email: `${id}+${login}@users.noreply.github.com` };
}

/**
 * git against the GitHub remote. With GH_TOKEN (the Action's token) set, gh answers git's credential
 * requests, so the checkout need not keep a token in .git/config where installs and tests can read it.
 */
export async function remoteGit(dir: string, args: readonly string[]): Promise<string> {
  const token = process.env.GH_TOKEN ?? process.env.GITHUB_TOKEN;
  if (!token) return git(dir, args);
  // An empty extraheader drops the one actions/checkout saves, so the push uses this token (the
  // Action's github-token input), not the job's own.
  return git(dir, ['-c', 'http.https://github.com/.extraheader=', '-c', 'credential.helper=', '-c', 'credential.helper=!gh auth git-credential', ...args], {
    ...safeEnv(),
    GH_TOKEN: token,
  });
}

export interface GitHubRepo {
  owner: string;
  name: string;
}

/** `owner/name` of a GitHub remote URL (https or ssh), or null for any other host. */
export function parseGitHubRemote(url: string): GitHubRepo | null {
  const match = /^(?:https:\/\/(?:[^@/]+@)?github\.com\/|git@github\.com:|ssh:\/\/git@github\.com\/)([^/]+)\/([^/]+?)(?:\.git)?\/?$/.exec(url.trim());
  return match ? { owner: match[1]!, name: match[2]! } : null;
}

export interface RepoInfo {
  top: string;
  /** The branch fixes start from: origin's default branch, else the current one. */
  base: string;
  /** The GitHub repository `origin` points at; PRs go there and nowhere else. Null without one. */
  github: GitHubRepo | null;
}

export async function repoInfo(dir: string): Promise<RepoInfo> {
  const top = await git(dir, ['rev-parse', '--show-toplevel']);
  const url = await git(top, ['remote', 'get-url', 'origin']).catch(() => '');
  const head = await git(top, ['symbolic-ref', '--short', 'refs/remotes/origin/HEAD']).catch(() => '');
  const base = head.startsWith('origin/') ? head.slice('origin/'.length) : await git(top, ['rev-parse', '--abbrev-ref', 'HEAD']);
  return { top, base, github: url ? parseGitHubRemote(url) : null };
}

/**
 * patchhound's own state folder: never part of a fix. In CI the Action restores it into the
 * checkout from its cache, so it must not count as a change, be committed, or be cleaned away.
 */
export const OWN_STATE = '.patchhound';

/** True when the checkout has changes git would commit. */
export async function isDirty(dir: string): Promise<boolean> {
  return (await git(dir, ['status', '--porcelain', '--', '.', `:(exclude)${OWN_STATE}`])) !== '';
}

/** Throws away untracked files (what a rolled-back install or agent left), keeping patchhound's state. */
export async function cleanUntracked(dir: string): Promise<void> {
  await git(dir, ['clean', '-fdq', '-e', OWN_STATE]);
}

/** The commit fixes start from: origin's `base` as it is now (fetched), else the local `base`. */
export async function baseCommit(top: string, base: string): Promise<string> {
  await remoteGit(top, ['fetch', '--quiet', 'origin', base]).catch(() => '');
  const remote = await git(top, ['rev-parse', '--verify', '--quiet', `origin/${base}^{commit}`]).catch(() => '');
  return remote || git(top, ['rev-parse', '--verify', `${base}^{commit}`]);
}

/**
 * A fresh worktree at `commit`, detached, in the system temp folder: the user's own checkout and
 * branches are never touched (the PR branch exists only on GitHub).
 */
export async function addWorktree(top: string, commit: string): Promise<string> {
  const parent = await mkdtemp(join(tmpdir(), 'patchhound-fix-'));
  const path = join(parent, 'repo');
  try {
    await git(top, ['worktree', 'add', '--force', '--detach', path, commit]);
  } catch (error) {
    await rm(parent, { recursive: true, force: true });
    throw error;
  }
  return path;
}

export async function removeWorktree(top: string, path: string): Promise<void> {
  await git(top, ['worktree', 'remove', '--force', path]).catch(() => undefined);
  await rm(join(path, '..'), { recursive: true, force: true });
}

/**
 * Commits everything changed (respecting .gitignore); returns false when there was nothing to commit.
 * The committer is always SELF; the author is `author` (see commitAuthor).
 */
export async function commitAll(dir: string, message: string, author: Identity = SELF): Promise<boolean> {
  await git(dir, ['add', '--all', '--', '.', `:(exclude)${OWN_STATE}`]);
  if ((await git(dir, ['diff', '--cached', '--name-only'])) === '') return false;
  // Never the identity in the user's git config (a global one often holds a work email), and no
  // signing with the user's key.
  const identity = ['-c', `user.name=${SELF.name}`, '-c', `user.email=${SELF.email}`, '-c', 'commit.gpgsign=false'];
  await git(dir, [...identity, 'commit', '--quiet', '--no-verify', `--author=${author.name} <${author.email}>`, '-m', message]);
  return true;
}

/** Files that differ from `from` in the working tree (changed, deleted, or new and not ignored). */
export async function changedSince(dir: string, from: string): Promise<{ tracked: string[]; untracked: string[] }> {
  const lines = (out: string) => (out === '' ? [] : out.split('\n'));
  return {
    tracked: lines(await git(dir, ['diff', '--name-only', from, '--', '.', `:(exclude)${OWN_STATE}`])),
    untracked: lines(await git(dir, ['ls-files', '--others', '--exclude-standard', '--', '.', `:(exclude)${OWN_STATE}`])),
  };
}

export interface PullRequest {
  number: number;
  url: string;
  created: boolean;
}


/** The URL of the open PR from `branch` in `repo` itself (not from a fork), or null. */
export async function openPullRequest(repo: GitHubRepo, branch: string): Promise<string | null> {
  const result = await runTool(['gh', 'pr', 'list', '--repo', `${repo.owner}/${repo.name}`, '--head', branch, '--state', 'open', '--json', 'url,isCrossRepository'], {
    cwd: process.cwd(),
    timeoutMs: 60_000,
    env: ghEnv(),
  });
  if (result.code !== 0) return null;
  const open = JSON.parse(result.output) as { url: string; isCrossRepository: boolean }[];
  return open.find((pr) => !pr.isCrossRepository)?.url ?? null;
}

/** A pull request's state (OPEN, CLOSED or MERGED), or null when gh cannot tell. */
export async function pullRequestState(url: string): Promise<string | null> {
  const result = await runTool(['gh', 'pr', 'view', url, '--json', 'state', '--jq', '.state'], { cwd: process.cwd(), timeoutMs: 60_000, env: ghEnv() });
  return result.code === 0 ? result.output.trim() || null : null;
}

/** Runs gh, throwing with its message when it fails. */
async function gh(args: readonly string[], cwd: string): Promise<string> {
  const result = await runTool(['gh', ...args], { cwd, timeoutMs: 2 * 60_000, env: ghEnv() });
  if (result.code !== 0) throw new Error(`gh ${args.slice(0, 2).join(' ')} failed: ${tail(result.output, 6)}`);
  return result.output.trim();
}

/** The PR branch has commits patchhound did not make; it is left alone. */
export class BranchTaken extends Error {}

/** GitHub's REST API through gh, filtered by `jq` (answers can be large): the parsed result, or null for a 404. */
export type GitHubApi = (path: string, jq: string) => Promise<unknown>;

export const githubApi: GitHubApi = async (path, jq) => {
  const result = await runTool(['gh', 'api', path, '--jq', jq], { cwd: process.cwd(), timeoutMs: 60_000, env: ghEnv() });
  if (result.code === 0) return JSON.parse(result.output) as unknown;
  if (/HTTP 404|Not Found/.test(result.output)) return null;
  throw new Error(`gh api ${path} failed: ${tail(result.output, 4)}`);
};

/**
 * Whether `branch` in `repo` has a commit beyond `base` (the branch PRs go to) that patchhound
 * did not make. GitHub answers it (compare base...branch): a shallow checkout, as in the Action,
 * does not have the history to.
 */
export async function othersOnBranch(repo: GitHubRepo, branch: string, base: string, api: GitHubApi = githubApi): Promise<boolean> {
  const committers = (await api(`repos/${repo.owner}/${repo.name}/compare/${encodeURIComponent(base)}...${encodeURIComponent(branch)}`, '[.commits[]?.commit.committer.email]')) as string[] | null;
  return (committers ?? []).some((email) => !isOwnCommit(email));
}

/**
 * Pushes HEAD to `branch` on origin and opens a PR in `repo` (origin's own repository, named
 * explicitly so gh never picks an upstream fork parent), or updates the one already open from that
 * branch in that repository. The push replaces the branch only when every commit on it beyond `base`
 * is patchhound's own, and only if it has not moved since it was checked (--force-with-lease).
 */
export async function publishPullRequest(
  dir: string,
  repo: GitHubRepo,
  options: { branch: string; base: string; title: string; body: string; labels: readonly string[] },
): Promise<PullRequest> {
  const slug = `${repo.owner}/${repo.name}`;
  const ref = `refs/heads/${options.branch}`;
  const there = (await remoteGit(dir, ['ls-remote', 'origin', ref])).split(/\s/)[0] ?? '';
  if (there && (await othersOnBranch(repo, options.branch, options.base))) {
    throw new BranchTaken(`${options.branch} on GitHub has commits patchhound did not make, so it was left alone; merge or close its PR, or delete the branch, and the next run opens a fresh one`);
  }
  await remoteGit(dir, ['push', '--quiet', `--force-with-lease=${ref}:${there}`, 'origin', `HEAD:${ref}`]);
  const bodyDir = await mkdtemp(join(tmpdir(), 'patchhound-pr-'));
  const bodyFile = join(bodyDir, 'body.md');
  await writeFile(bodyFile, options.body);
  try {
    // --head matches the branch name in forks too: only a PR from this repository's own branch is ours.
    const open = JSON.parse(await gh(['pr', 'list', '--repo', slug, '--head', options.branch, '--state', 'open', '--json', 'number,url,isCrossRepository'], dir)) as {
      number: number;
      url: string;
      isCrossRepository: boolean;
    }[];
    const existing = open.find((pr) => !pr.isCrossRepository);
    let pr: PullRequest;
    if (existing) {
      await gh(['pr', 'edit', String(existing.number), '--repo', slug, '--title', options.title, '--body-file', bodyFile], dir);
      pr = { number: existing.number, url: existing.url, created: false };
    } else {
      const out = await gh(
        ['pr', 'create', '--repo', slug, '--base', options.base, '--head', options.branch, '--title', options.title, '--body-file', bodyFile],
        dir,
      );
      const url = out.split('\n').pop()!;
      pr = { number: Number(/\/pull\/(\d+)/.exec(url)?.[1] ?? 0), url, created: true };
    }
    // Labels are a courtesy: a token that may not create them still gets its PR.
    for (const label of options.labels) {
      await gh(['label', 'create', label, '--repo', slug, '--color', label === 'security' ? 'B60205' : 'FBCA04', '--force'], dir).catch(() => '');
      await gh(['pr', 'edit', String(pr.number), '--repo', slug, '--add-label', label], dir).catch(() => '');
    }
    return pr;
  } finally {
    await rm(bodyDir, { recursive: true, force: true });
  }
}
