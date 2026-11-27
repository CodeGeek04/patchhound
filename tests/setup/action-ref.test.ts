import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { git, repoInfo } from '../../src/fix/git.js';
import { defaultAction } from '../../src/setup/action-ref.js';

describe('the Action init writes into the workflow', () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'patchhound-action-ref-'));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it('is PATCHHOUND_ACTION when set', async () => {
    expect(await defaultAction({ PATCHHOUND_ACTION: 'me/fork@test' }, root)).toBe('me/fork@test');
  });

  it("is a clone's own repository at main", async () => {
    await git(root, ['init', '-q']);
    await git(root, ['remote', 'add', 'origin', 'https://github.com/acme/patchhound.git']);
    expect(await defaultAction({}, root)).toBe('acme/patchhound@main');
  });

  it("is the package's repository at its major version's tag, even inside some other git repo", async () => {
    await git(root, ['init', '-q']);
    await git(root, ['remote', 'add', 'origin', 'https://github.com/someone/dotfiles.git']);
    const pkg = join(root, '.npm', '_npx', 'x', 'node_modules', 'patchhound');
    await mkdir(pkg, { recursive: true });
    await writeFile(join(pkg, 'package.json'), JSON.stringify({ version: '0.1.0', repository: { type: 'git', url: 'git+https://github.com/acme/patchhound.git' } }));
    expect(await defaultAction({}, pkg)).toBe('acme/patchhound@v0');
    await writeFile(join(pkg, 'package.json'), JSON.stringify({ version: '1.4.2', repository: 'github:acme/patchhound' }));
    expect(await defaultAction({}, pkg)).toBe('acme/patchhound@v1');
  });
});

describe('the branch fixes go to', () => {
  it('is PATCHHOUND_BASE when the workflow sets it, else the default branch', async () => {
    const root = await mkdtemp(join(tmpdir(), 'patchhound-base-'));
    try {
      await git(root, ['init', '-q', '-b', 'main']);
      await git(root, ['-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '--allow-empty', '-m', 'init']);
      expect((await repoInfo(root, {})).base).toBe('main');
      expect((await repoInfo(root, { PATCHHOUND_BASE: 'staging' })).base).toBe('staging');
      await expect(repoInfo(root, { PATCHHOUND_BASE: 'staging; rm -rf ~' })).rejects.toThrow('PATCHHOUND_BASE is not a branch name');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
