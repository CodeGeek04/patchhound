import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';
import type { Config } from '../config.js';
import { PROTECTED } from './agent.js';
import type { GitHubRepo, PullRequest } from './git.js';
import { BranchTaken, commitAuthor, git, publishPullRequest, remoteGit, repoInfo, SELF } from './git.js';
import { noDashes } from './pr-body.js';

/**
 * The GitHub Action runs the fix in a job with a read-only token and no write access, as the spec
 * asks: that job runs the project's installs, scripts and tests, and the coding agent. It hands off a
 * git bundle per PR and the PR's text. A second job, which runs nothing from the repository, checks
 * each bundle (its base, its authors, the files it touches) and only then pushes and opens the PR.
 */

const entrySchema = z.strictObject({
  kind: z.enum(['fixes', 'malware']),
  /** The commit the work starts from, and the commit it ends at. */
  base: z.string().regex(/^[0-9a-f]{40}$/),
  head: z.string().regex(/^[0-9a-f]{40}$/),
  bundle: z.string().regex(/^[\w.-]+\.bundle$/),
  title: z.string().max(256),
  body: z.string().max(60_000),
  needsReview: z.boolean(),
});

const handoffSchema = z.strictObject({ version: z.literal(1), runs: z.array(entrySchema).max(2) });

export type HandoffEntry = z.infer<typeof entrySchema>;

/** Adds one PR's work to the handoff folder: a bundle of base..head, and its text. */
export async function writeHandoff(dir: string, folder: string, entry: Omit<HandoffEntry, 'bundle'>): Promise<void> {
  await mkdir(folder, { recursive: true });
  const bundle = `${entry.kind}.bundle`;
  await git(dir, ['bundle', 'create', '--quiet', join(folder, bundle), 'HEAD', `^${entry.base}`]);
  const path = join(folder, 'handoff.json');
  const current = handoffSchema.safeParse(JSON.parse(await readFile(path, 'utf8').catch(() => '{"version":1,"runs":[]}')));
  const runs = (current.success ? current.data.runs : []).filter((r) => r.kind !== entry.kind);
  await writeFile(path, `${JSON.stringify({ version: 1, runs: [...runs, { ...entry, bundle }] }, null, 2)}\n`);
}

/** Files a malware PR may touch: manifests and lockfiles only (it is made with lockfile-only commands). */
const MALWARE_FILES = /(^|\/)(package\.json|package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|pnpm-workspace\.yaml|yarn\.lock|\.yarnrc\.yml)$/;

export interface PublishResult {
  kind: HandoffEntry['kind'];
  pr: PullRequest | null;
  /** Why nothing was published. */
  refused?: string;
}

/**
 * The publish job: for each handed-off PR, checks the bundle and pushes it. Refuses a bundle whose
 * commits do not start at the declared base, that has a commit patchhound did not make, or that
 * touches .github/ or patchhound's config (a malware PR: anything but manifests and lockfiles).
 * Branch names and labels come from this job's own config, not from the handoff.
 */
export async function publishHandoff(
  dir: string,
  folder: string,
  config: Config,
  options: { publish?: typeof publishPullRequest; repo?: GitHubRepo; log?: (line: string) => void } = {},
): Promise<PublishResult[]> {
  const log = options.log ?? (() => {});
  const handoff = handoffSchema.parse(JSON.parse(await readFile(join(folder, 'handoff.json'), 'utf8')));
  const info = await repoInfo(dir);
  const repo = options.repo ?? info.github;
  if (!repo) throw new Error('origin is not a GitHub repository');
  const results: PublishResult[] = [];
  for (const entry of handoff.runs) {
    const refuse = (refused: string) => {
      log(`${entry.kind}: not published: ${refused}`);
      results.push({ kind: entry.kind, pr: null, refused });
    };
    const branch = entry.kind === 'malware' ? `${config.fix.branch}-malware` : config.fix.branch;
    // The push replaces the branch: never the one PRs go to.
    if (branch === info.base) {
      refuse(`fix.branch must not name ${info.base}, the branch PRs go to`);
      continue;
    }
    // The base must be here to read the bundle against (the checkout is shallow; GitHub serves a commit by its id).
    if (!(await git(dir, ['cat-file', '-e', `${entry.base}^{commit}`]).then(() => true, () => false))) {
      await remoteGit(dir, ['fetch', '--quiet', '--depth=1', 'origin', entry.base]).catch(() => '');
    }
    const fetched = await git(dir, ['fetch', '--quiet', join(folder, entry.bundle), 'HEAD']).then(
      async () => git(dir, ['rev-parse', 'FETCH_HEAD']),
      (error: unknown) => `failed: ${error instanceof Error ? error.message.split('\n')[0] : String(error)}`,
    );
    if (fetched !== entry.head) {
      refuse(fetched.startsWith('failed') ? `the bundle could not be read (${fetched})` : 'the bundle does not hold the declared commit');
      continue;
    }
    const commits = (await git(dir, ['log', '--format=%H %ae %ce', `${entry.base}..${entry.head}`])).split('\n').filter(Boolean);
    const first = (await git(dir, ['rev-list', '--reverse', `${entry.base}..${entry.head}`])).split('\n')[0];
    const parent = first ? await git(dir, ['rev-parse', `${first}^`]).catch(() => '') : '';
    if (commits.length === 0 || parent !== entry.base) {
      refuse('its commits do not start at the declared base');
      continue;
    }
    // The fix job commits as commitAuthor says, with SELF as the committer; this job works out the
    // same author from its own config and run.
    const author = commitAuthor(config.fix.commitAs).email;
    if (commits.some((line) => line.split(' ')[1] !== author || line.split(' ')[2] !== SELF.email)) {
      refuse('it has a commit patchhound did not make');
      continue;
    }
    const files = (await git(dir, ['diff', '--name-only', entry.base, entry.head])).split('\n').filter(Boolean);
    const forbidden = files.filter((file) => PROTECTED.some((pattern) => pattern.test(file)) || (entry.kind === 'malware' && !MALWARE_FILES.test(file)));
    if (forbidden.length > 0) {
      refuse(`it changes files it may not: ${forbidden.join(', ')}`);
      continue;
    }
    await git(dir, ['checkout', '--quiet', '--detach', entry.head]);
    log(`${entry.kind}: pushing ${branch} to ${repo.owner}/${repo.name}`);
    try {
      const pr = await (options.publish ?? publishPullRequest)(dir, repo, {
        branch,
        base: info.base,
        title: noDashes(entry.title),
        body: noDashes(entry.body),
        labels: entry.kind === 'malware' ? ['security', 'malware'] : entry.needsReview ? ['security', 'needs-review'] : ['security'],
      });
      results.push({ kind: entry.kind, pr });
    } catch (error) {
      if (!(error instanceof BranchTaken)) throw error;
      refuse(error.message);
    }
  }
  return results;
}
