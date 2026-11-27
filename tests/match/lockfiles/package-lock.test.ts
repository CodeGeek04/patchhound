import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parsePackageLock } from '../../../src/match/lockfiles/package-lock.js';

const fixture = (name: string) => readFileSync(new URL(`../../fixtures/${name}/package-lock.json`, import.meta.url), 'utf8');

describe('parsePackageLock', () => {
  it('reads a single-app lockfile written by npm 11', () => {
    const graph = parsePackageLock(fixture('npm-app'));
    expect(graph.manager).toBe('npm');
    expect(graph.roots).toEqual(['root:.']);
    expect(graph.nodes.get('root:.')?.name).toBe('demo-app');
    expect([...graph.nodes.keys()].sort()).toEqual(
      ['async@2.6.3', 'debug@4.3.4', 'lodash@4.17.20', 'ms@2.1.2', 'root:.'].sort(),
    );
    expect(graph.edges).toContainEqual({ from: 'root:.', to: 'async@2.6.3', name: 'async', spec: '2.6.3', type: 'dev' });
    expect(graph.edges).toContainEqual({ from: 'async@2.6.3', to: 'lodash@4.17.20', name: 'lodash', spec: '^4.17.14', type: 'prod' });
    expect(graph.edges).toContainEqual({ from: 'debug@4.3.4', to: 'ms@2.1.2', name: 'ms', spec: '2.1.2', type: 'prod' });
    expect(graph.edges).toHaveLength(5);
    expect(graph.warnings).toEqual([]);
  });

  it('handles workspaces, nested copies, links and aliases', () => {
    const graph = parsePackageLock(fixture('npm-workspace'));
    expect(graph.roots.sort()).toEqual(['root:.', 'root:apps/web']);
    // npm 11 leaves `name` out when it equals the folder name.
    expect(graph.nodes.get('root:apps/web')?.name).toBe('web');
    // Two copies of lodash@3.10.1 on disk are one node.
    expect([...graph.nodes.keys()].sort()).toEqual([
      '@demo/dev-tool@2.0.0',
      '@demo/wrapper@1.0.0',
      'lodash@3.10.1',
      'lodash@4.17.20',
      'next@15.2.2',
      'root:.',
      'root:apps/web',
    ]);
    expect(graph.edges).toHaveLength(7);
    expect(graph.edges).toContainEqual({ from: 'root:.', to: '@demo/dev-tool@2.0.0', name: '@demo/dev-tool', spec: '^2.0.0', type: 'dev' });
    expect(graph.edges).toContainEqual({ from: 'root:apps/web', to: '@demo/wrapper@1.0.0', name: '@demo/wrapper', spec: '^1.0.0', type: 'prod' });
    expect(graph.edges).toContainEqual({ from: '@demo/wrapper@1.0.0', to: 'lodash@4.17.20', name: 'lodash', spec: '^4.17.0', type: 'prod' });
    // The nested copy wins over the hoisted one.
    expect(graph.edges).toContainEqual({ from: '@demo/dev-tool@2.0.0', to: 'lodash@3.10.1', name: 'lodash', spec: '^3.0.0', type: 'prod' });
    // A link points at the workspace root.
    expect(graph.edges).toContainEqual({ from: '@demo/dev-tool@2.0.0', to: 'root:apps/web', name: 'web', spec: '*', type: 'prod' });
    // An alias keeps the requested name on the edge and the real name on the node.
    expect(graph.edges).toContainEqual({
      from: 'root:apps/web',
      to: 'lodash@3.10.1',
      name: 'old-lodash',
      spec: 'npm:lodash@3.10.1',
      type: 'prod',
    });
    expect(graph.edges).toContainEqual({ from: 'root:apps/web', to: 'next@15.2.2', name: 'next', spec: '15.2.2', type: 'prod' });
  });

  it('types peer edges by peerDependenciesMeta', () => {
    const graph = parsePackageLock(fixture('next-babel-npm'));
    const fromNext = (name: string) => graph.edges.find((e) => e.from === 'next@15.2.2' && e.name === name);
    expect(fromNext('react')).toEqual({
      from: 'next@15.2.2',
      to: 'react@19.0.0',
      name: 'react',
      spec: '^18.2.0 || 19.0.0-rc-de68d2f4-20241204 || ^19.0.0',
      type: 'peer',
    });
    expect(fromNext('sass')).toEqual({ from: 'next@15.2.2', to: 'sass@1.83.0', name: 'sass', spec: '^1.3.0', type: 'peerOptional' });
    expect(fromNext('@playwright/test')?.type).toBe('peerOptional');
    // Optional peers that are not installed have no edge.
    expect(fromNext('@opentelemetry/api')).toBeUndefined();
  });

  it('gives a name that only peerDependenciesMeta lists an optional peer edge', () => {
    // styled-jsx lists @babel/core in peerDependenciesMeta but not in peerDependencies.
    const graph = parsePackageLock(fixture('next-babel-npm'));
    expect(graph.edges.filter((e) => e.from === 'styled-jsx@5.1.6' && e.name === '@babel/core')).toEqual([
      { from: 'styled-jsx@5.1.6', to: '@babel/core@7.26.0', name: '@babel/core', type: 'peerOptional' },
    ]);
  });

  it('treats only the project and its workspace folders as roots', () => {
    // Real npm 11 lockfile: workspaces ["apps/*", "packages/*"], and apps/web depends on
    // "local-lib": "file:../../libs/local-lib", which npm links like a workspace.
    const graph = parsePackageLock(fixture('npm-monorepo'));
    expect(graph.roots.sort()).toEqual(['root:.', 'root:apps/admin', 'root:apps/web', 'root:packages/test-utils', 'root:packages/ui']);
    expect(graph.roots.map((id) => graph.nodes.get(id)?.name).sort()).toEqual(['@demo/test-utils', '@demo/ui', 'admin', 'mono', 'web']);
    // A file: dependency is a package with a version that no advisory range matches.
    expect(graph.nodes.get('local-lib@file:libs/local-lib')).toEqual({
      id: 'local-lib@file:libs/local-lib',
      name: 'local-lib',
      version: 'file:libs/local-lib',
    });
    expect(graph.edges).toContainEqual({
      from: 'root:apps/web',
      to: 'local-lib@file:libs/local-lib',
      name: 'local-lib',
      spec: 'file:../../libs/local-lib',
      type: 'prod',
    });
    expect(graph.edges).toContainEqual({ from: 'local-lib@file:libs/local-lib', to: 'debug@2.6.8', name: 'debug', spec: '2.6.8', type: 'prod' });
    // npm installs a linked folder's devDependencies too.
    expect(graph.edges).toContainEqual({ from: 'local-lib@file:libs/local-lib', to: 'ms@0.7.0', name: 'ms', spec: '0.7.0', type: 'dev' });
    // 5 roots, 83 installed packages and the linked folder.
    expect(graph.nodes.size).toBe(89);
    expect(graph.edges).toHaveLength(114);
  });

  it('reads a file: dependency outside the project as a package', () => {
    const graph = parsePackageLock(fixture('npm-alias'));
    expect(graph.roots).toEqual(['root:.']);
    expect([...graph.nodes.keys()].sort()).toEqual(['7zip-bin@5.2.0', 'is-number@7.0.0', 'ms@2.0.0', 'root:.', 'shared@file:outside']);
    expect(graph.edges).toEqual([
      {
        from: 'root:.',
        to: 'is-number@7.0.0',
        name: 'is-number',
        spec: 'github:jonschlinkert/is-number#98e8ff1da1a89f93d1397a24d7413ed15421c139',
        type: 'prod',
      },
      { from: 'root:.', to: '7zip-bin@5.2.0', name: 'seven', spec: 'npm:7zip-bin@5.2.0', type: 'prod' },
      { from: 'root:.', to: 'shared@file:outside', name: 'shared', spec: 'file:./outside', type: 'prod' },
      { from: 'shared@file:outside', to: 'ms@2.0.0', name: 'ms', spec: '2.0.0', type: 'prod' },
    ]);
  });

  it("lets a workspace's devDependency win over a peer of the same name", () => {
    // Real npm 11 lockfile: packages/ui has react as a peer (>=18) and a devDependency (19.0.0),
    // and npm flags the installed react dev: true.
    const graph = parsePackageLock(fixture('lib-monorepo-npm'));
    expect(graph.edges.filter((e) => e.from === 'root:packages/ui')).toEqual([
      { from: 'root:packages/ui', to: 'clsx@2.1.1', name: 'clsx', spec: '2.1.1', type: 'prod' },
      { from: 'root:packages/ui', to: 'react@19.0.0', name: 'react', spec: '19.0.0', type: 'dev' },
    ]);
  });

  it('reads workspaces that a brace pattern names', () => {
    // Real npm 11 lockfile for "workspaces": ["{apps,packages}/*"].
    const graph = parsePackageLock(fixture('npm-brace'));
    expect(graph.roots.sort()).toEqual(['root:.', 'root:apps/web', 'root:packages/ui']);
    expect(graph.roots.map((id) => graph.nodes.get(id)?.name).sort()).toEqual(['@demo/ui', 'brace', 'web']);
    expect([...graph.nodes.keys()].sort()).toEqual([
      'lodash@4.17.20',
      'minimist@1.2.5',
      'ms@2.0.0',
      'root:.',
      'root:apps/web',
      'root:packages/ui',
    ]);
    expect(graph.edges.map((e) => `${e.from} -${e.name}-> ${e.to} ${e.type}`).sort()).toEqual([
      'root:apps/web -@demo/ui-> root:packages/ui prod',
      'root:apps/web -minimist-> minimist@1.2.5 dev',
      'root:apps/web -ms-> ms@2.0.0 prod',
      'root:packages/ui -lodash-> lodash@4.17.20 prod',
    ]);
  });

  it('makes a folder a file: package only when a file: dependency points at it', () => {
    // npm records the project, its workspaces and file: targets outside node_modules. The specs
    // tell them apart, whatever form the workspace patterns take.
    const folder = (deps: Record<string, string> = {}) => ({ version: '1.0.0', dependencies: deps });
    const lock = {
      lockfileVersion: 3,
      packages: {
        '': { name: 'mono', workspaces: ['{apps,tools}/*', 'packages/**'], dependencies: { vendored: 'file:vendor/x/' } },
        'apps/web': folder({ shared: 'file:../../libs/shared', e2e: 'file:./e2e' }),
        'apps/web/e2e': folder(),
        'libs/shared': folder(),
        'packages/group/a': folder({ lodash: '^4.17.0' }),
        'packages/group/a/node_modules/lodash': { version: '4.17.20' },
        'tools/cli': folder(),
        'vendor/x': { name: 'vendored', version: '1.0.0' },
      },
    };
    const graph = parsePackageLock(JSON.stringify(lock));
    expect(graph.roots.sort()).toEqual(['root:.', 'root:apps/web', 'root:packages/group/a', 'root:tools/cli']);
    expect([...graph.nodes.keys()].filter((id) => !id.startsWith('root:')).sort()).toEqual([
      'e2e@file:apps/web/e2e',
      'lodash@4.17.20',
      'shared@file:libs/shared',
      'vendored@file:vendor/x',
    ]);
  });

  it('rejects lockfile v1', () => {
    expect(() => parsePackageLock(JSON.stringify({ lockfileVersion: 1, dependencies: {} }))).toThrow(/v1 is not supported/);
  });
});
