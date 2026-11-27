import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DEFAULT_CONFIG } from '../../src/config.js';
import { commitAll, commitAuthor, git } from '../../src/fix/git.js';
import { publishHandoff, writeHandoff } from '../../src/fix/handoff.js';

describe('the handoff from the fix job to the publish job', () => {
  let root: string;
  let fixSide: string;
  let publishSide: string;
  let folder: string;
  let base: string;
  const repo = { owner: 'o', name: 'r' };
  const published: { branch: string; labels: readonly string[]; title: string; head: string }[] = [];
  const publish = async (dir: string, _repo: unknown, options: { branch: string; labels: readonly string[]; title: string }) => {
    published.push({ branch: options.branch, labels: options.labels, title: options.title, head: await git(dir, ['rev-parse', 'HEAD']) });
    return { number: 1, url: 'https://github.com/o/r/pull/1', created: true };
  };

  beforeEach(async () => {
    published.length = 0;
    root = await mkdtemp(join(tmpdir(), 'patchhound-handoff-'));
    const origin = join(root, 'origin.git');
    fixSide = join(root, 'fix');
    publishSide = join(root, 'publish');
    folder = join(root, 'handoff');
    await git(root, ['init', '-q', '--bare', origin]);
    await mkdir(fixSide);
    await git(fixSide, ['init', '-q', '-b', 'main']);
    await writeFile(join(fixSide, 'package.json'), '{"dependencies":{"lodash":"4.17.20"}}\n');
    await writeFile(join(fixSide, 'index.js'), 'module.exports = 1;\n');
    await git(fixSide, ['add', '-A']);
    await git(fixSide, ['-c', 'user.email=dev@example.com', '-c', 'user.name=dev', 'commit', '-qm', 'app']);
    await git(fixSide, ['remote', 'add', 'origin', origin]);
    await git(fixSide, ['push', '-q', 'origin', 'main']);
    base = await git(fixSide, ['rev-parse', 'HEAD']);
    await git(root, ['clone', '-q', origin, publishSide]);
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  const handOff = async (kind: 'fixes' | 'malware') =>
    writeHandoff(fixSide, folder, { kind, base, head: await git(fixSide, ['rev-parse', 'HEAD']), title: 'Security fixes for 1 advisory', body: 'body', needsReview: true });

  it('publishes patchhound\'s own commits on the declared base, to the branch its own config names', async () => {
    await writeFile(join(fixSide, 'package.json'), '{"dependencies":{"lodash":"4.17.21"}}\n');
    await commitAll(fixSide, 'fix(deps): security updates for 1 advisory');
    await handOff('fixes');
    const head = await git(fixSide, ['rev-parse', 'HEAD']);
    expect(JSON.parse(await readFile(join(folder, 'handoff.json'), 'utf8')).runs).toHaveLength(1);
    const results = await publishHandoff(publishSide, folder, DEFAULT_CONFIG, { publish, repo });
    expect(results).toEqual([{ kind: 'fixes', pr: { number: 1, url: 'https://github.com/o/r/pull/1', created: true } }]);
    expect(published).toEqual([{ branch: 'patchhound/fixes', labels: ['security', 'needs-review'], title: 'Security fixes for 1 advisory', head }]);
  });

  it('refuses a branch from its config that names the base, the branch PRs go to', async () => {
    await writeFile(join(fixSide, 'package.json'), '{"dependencies":{"lodash":"4.17.21"}}\n');
    await commitAll(fixSide, 'fix(deps): security updates for 1 advisory');
    await handOff('fixes');
    const config = { ...DEFAULT_CONFIG, fix: { ...DEFAULT_CONFIG.fix, branch: 'main' } };
    expect(await publishHandoff(publishSide, folder, config, { publish, repo })).toEqual([{ kind: 'fixes', pr: null, refused: 'fix.branch must not name main, the branch PRs go to' }]);
    expect(published).toEqual([]);
  });

  it('refuses a commit someone else made, a change to .github/, and a malware PR that touches code', async () => {
    await writeFile(join(fixSide, 'index.js'), 'module.exports = 2;\n');
    await git(fixSide, ['-c', 'user.email=dev@example.com', '-c', 'user.name=dev', 'commit', '-qam', 'not ours']);
    await handOff('fixes');
    expect((await publishHandoff(publishSide, folder, DEFAULT_CONFIG, { publish, repo }))[0]!.refused).toBe('it has a commit patchhound did not make');

    await git(fixSide, ['reset', '-q', '--hard', base]);
    await mkdir(join(fixSide, '.github'));
    await writeFile(join(fixSide, '.github', 'ci.yml'), 'on: push\n');
    await commitAll(fixSide, 'fix: adapt the code');
    await handOff('fixes');
    expect((await publishHandoff(publishSide, folder, DEFAULT_CONFIG, { publish, repo }))[0]!.refused).toBe('it changes files it may not: .github/ci.yml');

    await git(fixSide, ['reset', '-q', '--hard', base]);
    await writeFile(join(fixSide, 'index.js'), 'module.exports = 3;\n');
    await commitAll(fixSide, 'fix(deps): remove a malicious package');
    await handOff('malware');
    const results = await publishHandoff(publishSide, folder, DEFAULT_CONFIG, { publish, repo });
    expect(results.find((r) => r.kind === 'malware')!.refused).toBe('it changes files it may not: index.js');
    expect(published).toEqual([]);
  });

  it('expects the author its own config names: the bot, or the person who started the run', async () => {
    const saved = { GITHUB_ACTOR: process.env.GITHUB_ACTOR, GITHUB_ACTOR_ID: process.env.GITHUB_ACTOR_ID };
    process.env.GITHUB_ACTOR = 'octocat';
    process.env.GITHUB_ACTOR_ID = '583231';
    try {
      const actor = { ...DEFAULT_CONFIG, fix: { ...DEFAULT_CONFIG.fix, commitAs: 'actor' as const } };
      await writeFile(join(fixSide, 'package.json'), '{"dependencies":{"lodash":"4.17.21"}}\n');
      await commitAll(fixSide, 'fix(deps): security updates for 1 advisory', commitAuthor('actor'));
      await handOff('fixes');
      expect((await publishHandoff(publishSide, folder, DEFAULT_CONFIG, { publish, repo }))[0]!.refused).toBe('it has a commit patchhound did not make');
      expect((await publishHandoff(publishSide, folder, actor, { publish, repo }))[0]!.refused).toBeUndefined();
    } finally {
      for (const [name, value] of Object.entries(saved)) if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });

  it('refuses a bundle that does not hold the commit it declares', async () => {
    await writeFile(join(fixSide, 'package.json'), '{"dependencies":{"lodash":"4.17.21"}}\n');
    await commitAll(fixSide, 'fix(deps): security updates for 1 advisory');
    await handOff('fixes');
    const path = join(folder, 'handoff.json');
    const handoff = JSON.parse(await readFile(path, 'utf8'));
    handoff.runs[0].head = base;
    await writeFile(path, JSON.stringify(handoff));
    expect((await publishHandoff(publishSide, folder, DEFAULT_CONFIG, { publish, repo }))[0]!.refused).toBe('the bundle does not hold the declared commit');
  });
});
