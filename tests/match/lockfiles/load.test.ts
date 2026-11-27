import { copyFile, mkdir, mkdtemp, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { loadGraph, readManifests, readYarnCatalogs } from '../../../src/match/lockfiles/load.js';

const fixtureDir = (name: string) => fileURLToPath(new URL(`../../fixtures/${name}`, import.meta.url));

describe('loadGraph', () => {
  it('picks the npm parser for package-lock.json', async () => {
    const { lockfile, graph } = await loadGraph(fixtureDir('npm-app'));
    expect(lockfile).toBe(join(fixtureDir('npm-app'), 'package-lock.json'));
    expect(graph.manager).toBe('npm');
  });

  it('picks the pnpm parser for pnpm-lock.yaml', async () => {
    const { graph } = await loadGraph(fixtureDir('pnpm-app'));
    expect(graph.manager).toBe('pnpm');
  });

  it('picks the yarn parser for yarn.lock, classic or berry', async () => {
    expect((await loadGraph(fixtureDir('yarn-classic-app'))).graph.manager).toBe('yarn-classic');
    expect((await loadGraph(fixtureDir('yarn-berry-app'))).graph.manager).toBe('yarn-berry');
  });

  /** A project with a current pnpm-lock.yaml and a stale package-lock.json, as one real app had. */
  async function twoLockfiles(packageManager?: string): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), 'bulwark-'));
    await copyFile(join(fixtureDir('pnpm-app'), 'pnpm-lock.yaml'), join(dir, 'pnpm-lock.yaml'));
    await copyFile(join(fixtureDir('npm-app'), 'package-lock.json'), join(dir, 'package-lock.json'));
    await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'two', ...(packageManager ? { packageManager } : {}) }));
    return dir;
  }

  it('picks the lockfile of the package manager package.json names, and warns about the other', async () => {
    const dir = await twoLockfiles('npm@11.6.2');
    const { lockfile, graph } = await loadGraph(dir);
    expect(lockfile).toBe(join(dir, 'package-lock.json'));
    expect(graph.warnings).toEqual([
      `${basename(dir)} also has pnpm-lock.yaml, which was not scanned. If anything still installs from it, scan with --lockfile pnpm-lock.yaml.`,
    ]);
  });

  it('picks pnpm-lock.yaml first when package.json names no package manager', async () => {
    const { lockfile, graph } = await loadGraph(await twoLockfiles());
    expect(basename(lockfile)).toBe('pnpm-lock.yaml');
    expect(graph.warnings.at(-1)).toMatch(/also has package-lock.json, which was not scanned/);
  });

  it('reads the lockfile it is given, without a warning about the other', async () => {
    const dir = await twoLockfiles('pnpm@10.4.1');
    const { lockfile, graph } = await loadGraph(dir, { lockfile: 'package-lock.json' });
    expect(lockfile).toBe(join(dir, 'package-lock.json'));
    expect(graph.manager).toBe('npm');
    expect(graph.warnings).toEqual([]);
    await expect(loadGraph(dir, { lockfile: 'bun.lockb' })).rejects.toThrow(/is not a lockfile this reads/);
    await expect(loadGraph(dir, { lockfile: 'yarn.lock' })).rejects.toThrow(`No such lockfile: ${join(dir, 'yarn.lock')}`);
  });

  it('finds the workspaces that package.json globs name', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'bulwark-'));
    const write = async (path: string, name: string) => {
      await mkdir(join(dir, path), { recursive: true });
      await writeFile(join(dir, path, 'package.json'), JSON.stringify({ name }));
    };
    await write('packages/ui', 'ui');
    await write('packages/skip', 'skip');
    await write('apps/web/site', 'site');
    await write('libs/util', 'util');
    await write('elsewhere/linked', 'linked');
    await symlink(join(dir, 'elsewhere/linked'), join(dir, 'packages/linked'));
    await mkdir(join(dir, 'packages/no-manifest'), { recursive: true });
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'root', workspaces: { packages: ['packages/*', '{apps,libs}/**', '!packages/skip'] } }),
    );
    const manifests = await readManifests(dir);
    expect([...manifests.keys()].sort()).toEqual(['.', 'apps/web/site', 'libs/util', 'packages/linked', 'packages/ui']);
    expect(manifests.get('packages/ui')).toEqual({ name: 'ui' });
  });

  it('names the lockfile it could not parse', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'bulwark-'));
    await writeFile(join(dir, 'package-lock.json'), '{ "lockfileVersion": 3,');
    await expect(loadGraph(dir)).rejects.toThrow(`Could not read ${join(dir, 'package-lock.json')}: `);
  });

  it("reads yarn 4's catalogs from .yarnrc.yml", async () => {
    const dir = await mkdtemp(join(tmpdir(), 'bulwark-'));
    await writeFile(join(dir, '.yarnrc.yml'), 'catalog:\n  react: ^18.3.1\ncatalogs:\n  old:\n    react: 1.0\n');
    expect(await readYarnCatalogs(dir)).toEqual({ default: { react: '^18.3.1' }, named: { old: { react: '1.0' } } });
    expect(await readYarnCatalogs(await mkdtemp(join(tmpdir(), 'bulwark-')))).toEqual({});
  });

  it('says when there is no lockfile', async () => {
    const empty = await mkdtemp(join(tmpdir(), 'bulwark-'));
    await expect(loadGraph(empty)).rejects.toThrow(/No lockfile/);
  });
});
