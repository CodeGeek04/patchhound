import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { GraphIndex } from '../../../src/match/graph.js';
import { parsePnpmLock } from '../../../src/match/lockfiles/pnpm-lock.js';

const IS_NUMBER_TARBALL = 'https://codeload.github.com/jonschlinkert/is-number/tar.gz/98e8ff1';

const GIT_ALIAS = `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      foo:
        specifier: github:jonschlinkert/is-number#98e8ff1
        version: is-number@${IS_NUMBER_TARBALL}
packages:
  is-number@${IS_NUMBER_TARBALL}:
    resolution: {gitHosted: true, tarball: ${IS_NUMBER_TARBALL}}
    version: 7.0.0
snapshots:
  is-number@${IS_NUMBER_TARBALL}: {}
`;

const BUNDLES = `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      big: {specifier: 2.0.0, version: 2.0.0}
      everything: {specifier: 1.0.0, version: 1.0.0}
      is-number: {specifier: 'github:jonschlinkert/is-number#98e8ff1', version: '${IS_NUMBER_TARBALL}'}
packages:
  big@2.0.0:
    resolution: {integrity: sha512-placeholder}
    bundledDependencies: [a, b, c]
  everything@1.0.0:
    resolution: {integrity: sha512-placeholder}
    bundledDependencies: true
  is-number@${IS_NUMBER_TARBALL}:
    resolution: {tarball: ${IS_NUMBER_TARBALL}}
    version: 7.0.0
    bundledDependencies: [a]
snapshots:
  big@2.0.0: {}
  everything@1.0.0: {}
  is-number@${IS_NUMBER_TARBALL}: {}
`;

// ui-kit lists helper as a dependency and as an optional peer, and the snapshot puts helper
// under `dependencies`: it is installed as a plain dependency.
const DEP_AND_OPTIONAL_PEER = `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      ui-kit: {specifier: 1.0.0, version: 1.0.0}
    devDependencies:
      tool: {specifier: 1.0.0, version: 1.0.0}
packages:
  ui-kit@1.0.0:
    resolution: {integrity: sha512-placeholder}
    peerDependencies:
      helper: '*'
    peerDependenciesMeta:
      helper: {optional: true}
  helper@2.0.0:
    resolution: {integrity: sha512-placeholder}
  tool@1.0.0:
    resolution: {integrity: sha512-placeholder}
snapshots:
  ui-kit@1.0.0:
    dependencies:
      helper: 2.0.0
  helper@2.0.0: {}
  tool@1.0.0:
    dependencies:
      helper: 2.0.0
`;

const fixture = (name: string) => readFileSync(new URL(`../../fixtures/${name}/pnpm-lock.yaml`, import.meta.url), 'utf8');

describe('parsePnpmLock', () => {
  it('reads a single-app lockfile written by pnpm 11', () => {
    const graph = parsePnpmLock(fixture('pnpm-app'));
    expect(graph.manager).toBe('pnpm');
    expect(graph.roots).toEqual(['root:.']);
    expect([...graph.nodes.keys()].sort()).toEqual(
      ['async@2.6.3', 'debug@4.3.4', 'lodash@4.17.20', 'ms@2.1.2', 'root:.'].sort(),
    );
    expect(graph.edges).toContainEqual({ from: 'root:.', to: 'async@2.6.3', name: 'async', spec: '2.6.3', type: 'dev' });
    expect(graph.edges).toContainEqual({ from: 'async@2.6.3', to: 'lodash@4.17.20', name: 'lodash', type: 'prod' });
    expect(graph.edges).toContainEqual({ from: 'debug@4.3.4', to: 'ms@2.1.2', name: 'ms', type: 'prod' });
    expect(graph.edges).toHaveLength(5);
  });

  it('handles workspaces, peer suffixes, links and aliases', () => {
    const graph = parsePnpmLock(fixture('pnpm-workspace'));
    expect(graph.roots).toEqual(['root:.', 'root:apps/web', 'root:packages/ui']);
    // Peer suffixes are stripped, so next has one node.
    expect([...graph.nodes.keys()].sort()).toEqual([
      '@next/env@15.2.2',
      'lodash@3.10.1',
      'next@15.2.2',
      'react-dom@19.0.0',
      'react@19.0.0',
      'root:.',
      'root:apps/web',
      'root:packages/ui',
      'scheduler@0.25.0',
      'typescript@5.4.5',
    ]);
    expect(graph.edges).toHaveLength(11);
    expect(graph.edges).toContainEqual({ from: 'root:.', to: 'typescript@5.4.5', name: 'typescript', spec: '^5.4.0', type: 'dev' });
    expect(graph.edges).toContainEqual({ from: 'root:apps/web', to: 'react@19.0.0', name: 'react', spec: '19.0.0', type: 'prod' });
    expect(graph.edges).toContainEqual({ from: 'root:apps/web', to: 'react-dom@19.0.0', name: 'react-dom', spec: '19.0.0', type: 'prod' });
    expect(graph.edges).toContainEqual({ from: 'next@15.2.2', to: 'react@19.0.0', name: 'react', spec: '^18.2.0 || 19.0.0-rc-de68d2f4-20241204 || ^19.0.0', type: 'peer' });
    expect(graph.edges).toContainEqual({ from: 'next@15.2.2', to: 'react-dom@19.0.0', name: 'react-dom', spec: '^18.2.0 || 19.0.0-rc-de68d2f4-20241204 || ^19.0.0', type: 'peer' });
    expect(graph.edges).toContainEqual({ from: 'react-dom@19.0.0', to: 'react@19.0.0', name: 'react', spec: '^19.0.0', type: 'peer' });
    expect(graph.edges).toContainEqual({ from: 'root:apps/web', to: 'next@15.2.2', name: 'next', spec: '15.2.2', type: 'prod' });
    expect(graph.edges).toContainEqual({
      from: 'root:apps/web',
      to: 'root:packages/ui',
      name: '@demo/ui',
      spec: 'workspace:*',
      type: 'prod',
    });
    expect(graph.edges).toContainEqual({
      from: 'root:packages/ui',
      to: 'lodash@3.10.1',
      name: 'old-lodash',
      spec: 'npm:lodash@3.10.1',
      type: 'prod',
    });
    expect(graph.edges).toContainEqual({ from: 'next@15.2.2', to: '@next/env@15.2.2', name: '@next/env', type: 'prod' });
    expect(graph.edges).toContainEqual({ from: 'react-dom@19.0.0', to: 'scheduler@0.25.0', name: 'scheduler', type: 'prod' });
  });

  it('reads the project document of a pnpm 11 lockfile that also holds config dependencies', () => {
    // pnpm 11 writes its own config dependencies as a first YAML document. That document has
    // `importers` too, so the project lockfile is the last document that has them.
    const graph = parsePnpmLock(fixture('pnpm-config-deps'));
    expect(graph.roots).toEqual(['root:.']);
    expect([...graph.nodes.keys()].sort()).toEqual(['lodash@4.17.20', 'root:.']);
    expect(graph.edges).toEqual([{ from: 'root:.', to: 'lodash@4.17.20', name: 'lodash', spec: '4.17.20', type: 'prod' }]);
  });

  it('warns that it did not check the packages pnpm itself runs', () => {
    expect(parsePnpmLock(fixture('pnpm-config-deps')).warnings).toEqual([
      'pnpm-lock.yaml also locks packages that pnpm itself runs when it installs (config dependencies ' +
        'and the package manager), and those were not checked: is-positive@3.1.0',
    ]);
    // devEngines.packageManager: pnpm and its own dependencies.
    const graph = parsePnpmLock(fixture('pnpm-package-manager'));
    expect([...graph.nodes.keys()].sort()).toEqual(['lodash@4.17.20', 'root:.']);
    expect(graph.warnings).toEqual([
      'pnpm-lock.yaml also locks packages that pnpm itself runs when it installs (config dependencies ' +
        'and the package manager), and those were not checked: @pnpm/exe@11.28.13, pnpm@11.28.13 ' +
        '(18 packages with their dependencies)',
    ]);
  });

  it('says which document is not valid YAML', () => {
    const broken = "---\nlockfileVersion: '9.0'\n---\nlockfileVersion: '9.0'\nimporters: [\n";
    expect(() => parsePnpmLock(broken)).toThrow(/pnpm-lock.yaml is not valid YAML \(document 2\)/);
  });

  it('reads an alias whose target name starts with a digit', () => {
    // "seven": "npm:7zip-bin@5.2.0" is locked as `7zip-bin@5.2.0`, which is not a version.
    const graph = parsePnpmLock(fixture('pnpm-alias'));
    expect(graph.edges).toContainEqual({
      from: 'root:.',
      to: '7zip-bin@5.2.0',
      name: 'seven',
      spec: 'npm:7zip-bin@5.2.0',
      type: 'prod',
    });
    expect([...graph.nodes.keys()].filter((id) => id.startsWith('seven@'))).toEqual([]);
  });

  it('reads an alias of a git dependency', () => {
    // pnpm 11 output for "foo": "github:jonschlinkert/is-number#98e8ff1".
    const graph = parsePnpmLock(GIT_ALIAS);
    expect(graph.edges).toEqual([
      { from: 'root:.', to: 'is-number@7.0.0', name: 'foo', spec: 'github:jonschlinkert/is-number#98e8ff1', type: 'prod' },
    ]);
  });

  it('uses the version that a git dependency holds, as npm does', () => {
    // pnpm keys git and tarball packages by URL; the package entry records the version.
    const graph = parsePnpmLock(fixture('pnpm-alias'));
    expect(graph.nodes.get('is-number@7.0.0')).toEqual({ id: 'is-number@7.0.0', name: 'is-number', version: '7.0.0' });
    expect(graph.edges).toContainEqual({
      from: 'root:.',
      to: 'is-number@7.0.0',
      name: 'is-number',
      spec: 'github:jonschlinkert/is-number#98e8ff1da1a89f93d1397a24d7413ed15421c139',
      type: 'prod',
    });
    expect([...graph.nodes.keys()].filter((id) => id.includes('codeload'))).toEqual([]);
  });

  it('types resolved peers by the package entry', () => {
    const graph = parsePnpmLock(fixture('next-babel-pnpm'));
    const from = (parent: string, name: string) => graph.edges.filter((e) => e.from === parent && e.name === name);
    expect(from('next@15.2.2', 'react')).toEqual([
      { from: 'next@15.2.2', to: 'react@19.0.0', name: 'react', spec: '^18.2.0 || 19.0.0-rc-de68d2f4-20241204 || ^19.0.0', type: 'peer' },
    ]);
    expect(from('next@15.2.2', 'sass')).toEqual([{ from: 'next@15.2.2', to: 'sass@1.83.0', name: 'sass', spec: '^1.3.0', type: 'peerOptional' }]);
    expect(from('next@15.2.2', '@playwright/test')).toEqual([
      { from: 'next@15.2.2', to: '@playwright/test@1.50.0', name: '@playwright/test', spec: '^1.41.2', type: 'peerOptional' },
    ]);
    expect(from('styled-jsx@5.1.6', '@babel/core')).toEqual([
      { from: 'styled-jsx@5.1.6', to: '@babel/core@7.26.0', name: '@babel/core', spec: '*', type: 'peerOptional' },
    ]);
    // A plain dependency keeps its type.
    expect(from('next@15.2.2', 'styled-jsx')).toEqual([{ from: 'next@15.2.2', to: 'styled-jsx@5.1.6', name: 'styled-jsx', type: 'prod' }]);
  });

  it('reads a real lockfile with an alias, a git dependency and a link exactly', () => {
    const graph = parsePnpmLock(fixture('pnpm-alias'));
    expect([...graph.nodes.keys()].sort()).toEqual(['7zip-bin@5.2.0', 'is-number@7.0.0', 'root:.', 'shared@link:outside']);
    expect(graph.edges.map((e) => `${e.from} -${e.name}-> ${e.to}`).sort()).toEqual([
      'root:. -is-number-> is-number@7.0.0',
      'root:. -seven-> 7zip-bin@5.2.0',
      'root:. -shared-> shared@link:outside',
    ]);
  });

  it('makes a link to a folder that is not an importer a package', () => {
    // "shared": "link:./outside" points outside the workspace, so no importer describes it.
    const graph = parsePnpmLock(fixture('pnpm-alias'));
    expect(graph.nodes.get('shared@link:outside')).toEqual({ id: 'shared@link:outside', name: 'shared', version: 'link:outside' });
    expect(graph.edges).toContainEqual({ from: 'root:.', to: 'shared@link:outside', name: 'shared', spec: 'link:./outside', type: 'prod' });
    expect(graph.edges.filter((e) => !graph.nodes.has(e.to))).toEqual([]);
  });

  it('warns that it cannot check dependencies a package bundles', () => {
    // pnpm records only the top-level names of bundled dependencies. npm's lockfile for the same
    // app lists 197 distinct bundled packages under npm@10.9.2, so 68 must not read as the total.
    expect(parsePnpmLock(fixture('next-app-pnpm')).warnings).toEqual([
      '1 package bundles dependencies that pnpm-lock.yaml does not list, so they were not checked, and ' +
        'neither were their own dependencies: npm@10.9.2 (68 top-level names)',
    ]);
    expect(parsePnpmLock(BUNDLES).warnings).toEqual([
      '3 packages bundle dependencies that pnpm-lock.yaml does not list, so they were not checked, and ' +
        'neither were their own dependencies: everything@1.0.0 (all its dependencies), ' +
        'big@2.0.0 (3 top-level names), is-number@7.0.0 (1 top-level name)',
    ]);
  });

  it('has no warnings when it could check everything', () => {
    expect(parsePnpmLock(fixture('pnpm-app')).warnings).toEqual([]);
  });

  it('keeps an optional peer that the snapshot lists as a plain dependency a dependency', () => {
    const graph = parsePnpmLock(DEP_AND_OPTIONAL_PEER);
    expect(graph.edges.filter((e) => e.to === 'helper@2.0.0')).toEqual([
      { from: 'ui-kit@1.0.0', to: 'helper@2.0.0', name: 'helper', type: 'prod' },
      { from: 'tool@1.0.0', to: 'helper@2.0.0', name: 'helper', type: 'prod' },
    ]);
    expect(new GraphIndex(graph).isDevOnly('helper@2.0.0')).toBe(false);
  });

  it('rejects lockfile formats before 9', () => {
    expect(() => parsePnpmLock("lockfileVersion: '6.0'\n")).toThrow(/not supported/);
  });
});
