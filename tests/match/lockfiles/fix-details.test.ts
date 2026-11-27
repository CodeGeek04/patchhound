import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parsePackageLock } from '../../../src/match/lockfiles/package-lock.js';
import { parsePnpmLock } from '../../../src/match/lockfiles/pnpm-lock.js';

const fixture = (name: string, file: string) => readFileSync(new URL(`../../fixtures/${name}/${file}`, import.meta.url), 'utf8');

/** A package-lock.json v3 from its `packages` section. */
const npmLock = (packages: Record<string, unknown>) => JSON.stringify({ name: 'app', lockfileVersion: 3, requires: true, packages });

/** `bundledBy` of each listed node, undefined when it has none. */
const bundledBy = (text: string, ...ids: string[]) => {
  const graph = parsePackageLock(text);
  return Object.fromEntries(ids.map((id) => [id, graph.nodes.get(id)?.bundledBy]));
};

describe('package-lock bundledBy', () => {
  it('names the package whose tarball ships every copy, past bundled folders in between', () => {
    // npm@10.9.2 is a devDependency that bundles its own dependencies; tar 7.4.3 sits under its
    // bundled cacache and node-gyp, which are not the bundlers.
    const text = fixture('next-app-npm', 'package-lock.json');
    expect(bundledBy(text, 'tar@7.4.3', 'tar@6.2.1', 'npm@10.9.2', 'next@15.2.2')).toEqual({
      'tar@7.4.3': ['npm@10.9.2'],
      'tar@6.2.1': ['npm@10.9.2'],
      'npm@10.9.2': undefined,
      'next@15.2.2': undefined,
    });
  });

  it('leaves out a version that also has a copy installed from the registry', () => {
    // cross-spawn 7.0.6 is inside npm's tarball and also installed for eslint.
    expect(bundledBy(fixture('next-app-npm', 'package-lock.json'), 'cross-spawn@7.0.6')).toEqual({ 'cross-spawn@7.0.6': undefined });

    const text = npmLock({
      '': { name: 'app', dependencies: { tool: '1.0.0', helper: '2.0.0' } },
      'node_modules/tool': { version: '1.0.0', dependencies: { helper: '2.0.0' }, bundleDependencies: ['helper'] },
      'node_modules/tool/node_modules/helper': { version: '2.0.0', inBundle: true },
      'node_modules/helper': { version: '2.0.0' },
    });
    expect(bundledBy(text, 'helper@2.0.0')).toEqual({ 'helper@2.0.0': undefined });
  });

  it('lists every package that bundles a copy, sorted', () => {
    const text = npmLock({
      '': { name: 'app', dependencies: { 'tool-b': '1.0.0', 'tool-a': '1.0.0' } },
      'node_modules/tool-b': { version: '1.0.0', dependencies: { helper: '2.0.0' }, bundleDependencies: ['helper'] },
      'node_modules/tool-b/node_modules/helper': { version: '2.0.0', inBundle: true },
      'node_modules/tool-a': { version: '1.0.0', dependencies: { helper: '2.0.0' }, bundleDependencies: ['helper'] },
      'node_modules/tool-a/node_modules/helper': { version: '2.0.0', inBundle: true },
    });
    expect(bundledBy(text, 'helper@2.0.0', 'tool-a@1.0.0')).toEqual({ 'helper@2.0.0': ['tool-a@1.0.0', 'tool-b@1.0.0'], 'tool-a@1.0.0': undefined });
  });

  it('does not count a copy that the project or a workspace bundles itself', () => {
    const text = npmLock({
      '': { name: 'app', dependencies: { helper: '2.0.0' }, bundleDependencies: ['helper'], workspaces: ['packages/lib'] },
      'node_modules/helper': { version: '2.0.0', inBundle: true },
      'node_modules/lib': { resolved: 'packages/lib', link: true },
      'packages/lib': { name: 'lib', version: '1.0.0', dependencies: { other: '3.0.0' }, bundleDependencies: ['other'] },
      'packages/lib/node_modules/other': { version: '3.0.0', inBundle: true },
    });
    expect(bundledBy(text, 'helper@2.0.0', 'other@3.0.0')).toEqual({ 'helper@2.0.0': undefined, 'other@3.0.0': undefined });
  });
});

describe('pnpm-lock catalogs', () => {
  it('replaces catalog: specifiers with the catalog range and names the catalog', () => {
    const graph = parsePnpmLock(fixture('pnpm-catalog', 'pnpm-lock.yaml'));
    expect(graph.edges).toEqual([
      { from: 'root:.', to: 'lodash@4.18.1', name: 'lodash', spec: '^4.17.20', catalog: 'default', type: 'prod' },
      { from: 'root:.', to: 'ms@2.0.0', name: 'ms', spec: '~2.0.0', catalog: 'old', type: 'prod' },
    ]);
  });

  it('keeps the catalog: specifier when the lockfile has no such catalog entry, and leaves plain specifiers alone', () => {
    const graph = parsePnpmLock(`lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      lodash: {specifier: 'catalog:missing', version: 4.17.21}
      ms: {specifier: ^2.1.0, version: 2.1.3}
packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-placeholder}
  ms@2.1.3:
    resolution: {integrity: sha512-placeholder}
snapshots:
  lodash@4.17.21: {}
  ms@2.1.3: {}
`);
    expect(graph.edges).toEqual([
      { from: 'root:.', to: 'lodash@4.17.21', name: 'lodash', spec: 'catalog:missing', catalog: 'missing', type: 'prod' },
      { from: 'root:.', to: 'ms@2.1.3', name: 'ms', spec: '^2.1.0', type: 'prod' },
    ]);
  });
});

describe('pnpm-lock peer ranges', () => {
  // plugin needs host as a peer and theme as an optional peer; it also depends on util.
  const PEERS = `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      host: {specifier: ^2.0.0, version: 2.1.0}
      plugin: {specifier: 1.0.0, version: 1.0.0(host@2.1.0)(theme@3.0.0)}
      theme: {specifier: 3.0.0, version: 3.0.0}
packages:
  host@2.1.0:
    resolution: {integrity: sha512-placeholder}
  plugin@1.0.0:
    resolution: {integrity: sha512-placeholder}
    peerDependencies:
      host: ^2.0.0
      theme: '>=3'
    peerDependenciesMeta:
      theme: {optional: true}
  theme@3.0.0:
    resolution: {integrity: sha512-placeholder}
  util@1.2.3:
    resolution: {integrity: sha512-placeholder}
snapshots:
  host@2.1.0: {}
  plugin@1.0.0(host@2.1.0)(theme@3.0.0):
    dependencies:
      host: 2.1.0
      util: 1.2.3
    optionalDependencies:
      theme: 3.0.0
  theme@3.0.0: {}
  util@1.2.3: {}
`;

  it('gives a peer edge the range the package entry declares, and a plain one none', () => {
    const graph = parsePnpmLock(PEERS);
    expect(graph.edges.filter((e) => e.from === 'plugin@1.0.0')).toEqual([
      { from: 'plugin@1.0.0', to: 'host@2.1.0', name: 'host', spec: '^2.0.0', type: 'peer' },
      { from: 'plugin@1.0.0', to: 'util@1.2.3', name: 'util', type: 'prod' },
      { from: 'plugin@1.0.0', to: 'theme@3.0.0', name: 'theme', spec: '>=3', type: 'peerOptional' },
    ]);
  });
});
