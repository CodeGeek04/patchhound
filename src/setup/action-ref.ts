import { readFile, realpath } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { git, parseGitHubRemote } from '../fix/git.js';

/** Patchhound's own folder (this file is in src/setup/). */
const ROOT = fileURLToPath(new URL('../..', import.meta.url));

/**
 * The Action the workflow `init` writes runs: PATCHHOUND_ACTION when set; else, run from a clone of
 * Patchhound, that clone's GitHub repository at main; else the package's repository at its major
 * version's tag (v0 for 0.x), which moves with each release of that major.
 */
export async function defaultAction(env: NodeJS.ProcessEnv = process.env, root = ROOT): Promise<string> {
  if (env.PATCHHOUND_ACTION) return env.PATCHHOUND_ACTION;
  // A clone of Patchhound, not a folder that happens to sit inside some other repo (npx's cache in a
  // home directory kept in git, say).
  const top = await git(root, ['rev-parse', '--show-toplevel']).catch(() => '');
  const remote = top && (await realpath(top)) === (await realpath(root)) ? parseGitHubRemote(await git(root, ['remote', 'get-url', 'origin']).catch(() => '')) : null;
  if (remote) return `${remote.owner}/${remote.name}@main`;
  const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')) as { version?: string; repository?: string | { url?: string } };
  const url = typeof manifest.repository === 'string' ? manifest.repository : manifest.repository?.url ?? '';
  const repo = /github(?:\.com[/:]|:)([^/]+)\/([^/.#]+)/.exec(url);
  if (!repo) throw new Error('cannot tell which repository the Action is in: pass --action owner/repo@ref');
  return `${repo[1]}/${repo[2]}@v${(manifest.version ?? '0').split('.')[0]}`;
}
