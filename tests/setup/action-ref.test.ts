import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { git } from '../../src/fix/git.js';
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
