import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { GraphIndex } from '../../../src/match/graph.js';
import { readManifests } from '../../../src/match/lockfiles/load.js';
import type { Manifest } from '../../../src/match/lockfiles/yarn-lock.js';
import { parseYarnLock } from '../../../src/match/lockfiles/yarn-lock.js';

const fixtureDir = (name: string) => fileURLToPath(new URL(`../../fixtures/${name}`, import.meta.url));

async function load(name: string) {
  const dir = fixtureDir(name);
  return new GraphIndex(parseYarnLock(readFileSync(`${dir}/yarn.lock`, 'utf8'), await readManifests(dir)));
}

const parentsOf = (index: GraphIndex, id: string) => index.parents(id).map((e) => ({ from: e.from, name: e.name, spec: e.spec, type: e.type }));

// Both fixtures: lodash 4.17.20 and old-lodash (npm:lodash@3.10.1) and axios in the root, typescript
// as a devDependency, and two workspaces: packages/ui needs ms 2.0.0 and @demo/core 1.0.0 (the
// workspace), and packages/core needs debug ^4.3.0.
describe.each(['classic', 'berry'])('parseYarnLock: yarn %s', (flavor) => {
  it('makes the project and each workspace a root, and names the manager', async () => {
    const index = await load(`yarn-${flavor}-app`);
    expect(index.graph.manager).toBe(`yarn-${flavor}`);
    expect(index.graph.roots.sort()).toEqual(['root:.', 'root:packages/core', 'root:packages/ui']);
    expect(index.graph.nodes.get('root:packages/ui')).toEqual({ id: 'root:packages/ui', name: '@demo/ui', version: '1.0.0' });
  });

  it('takes the ranges and the dev section from package.json, and resolves an alias to the real package', async () => {
    const index = await load(`yarn-${flavor}-app`);
    expect(parentsOf(index, 'lodash@4.17.20')).toEqual([{ from: 'root:.', name: 'lodash', spec: '4.17.20', type: 'prod' }]);
    expect(parentsOf(index, 'lodash@3.10.1')).toEqual([{ from: 'root:.', name: 'old-lodash', spec: 'npm:lodash@3.10.1', type: 'prod' }]);
    expect(index.isDevOnly('typescript@5.4.5')).toBe(true);
    expect(index.isDevOnly('lodash@4.17.20')).toBe(false);
  });

  it('links a dependency on a workspace to that workspace, and follows package to package ranges', async () => {
    const index = await load(`yarn-${flavor}-app`);
    expect(parentsOf(index, 'root:packages/core')).toEqual([{ from: 'root:packages/ui', name: '@demo/core', spec: '1.0.0', type: 'prod' }]);
    expect(parentsOf(index, 'ms@2.1.3')).toEqual([{ from: 'debug@4.4.3', name: 'ms', spec: '^2.1.3', type: 'prod' }]);
    expect(index.pathsTo('ms@2.1.3', 1)).toEqual([['root:packages/core', 'debug@4.4.3', 'ms@2.1.3']]);
  });

  it('leaves no installed package without a parent', async () => {
    const index = await load(`yarn-${flavor}-app`);
    expect(index.packages().filter((node) => index.parents(node.id).length === 0)).toEqual([]);
  });
});

describe('parseYarnLock: details', () => {
  const app: Map<string, Manifest> = new Map([['.', { name: 'app', dependencies: { a: '^1.0.0' } }]]);

  it('reads optional dependencies in yarn 1 and in yarn 2+ (dependenciesMeta)', () => {
    const classic = [
      '# yarn lockfile v1',
      '',
      'a@^1.0.0:',
      '  version "1.0.0"',
      '  dependencies:',
      '    b "^2.0.0"',
      '  optionalDependencies:',
      '    "@scope/c" "^3.0.0"',
      '',
      'b@^2.0.0:',
      '  version "2.0.0"',
      '',
      '"@scope/c@^3.0.0":',
      '  version "3.0.0"',
      '',
    ].join('\n');
    const berry = [
      '__metadata:',
      '  version: 8',
      '',
      '"a@npm:^1.0.0":',
      '  version: 1.0.0',
      '  resolution: "a@npm:1.0.0"',
      '  dependencies:',
      '    "@scope/c": "npm:^3.0.0"',
      '    b: "npm:^2.0.0"',
      '  dependenciesMeta:',
      '    "@scope/c":',
      '      optional: true',
      '',
      '"b@npm:^2.0.0":',
      '  version: 2.0.0',
      '  resolution: "b@npm:2.0.0"',
      '',
      '"@scope/c@npm:^3.0.0":',
      '  version: 3.0.0',
      '  resolution: "@scope/c@npm:3.0.0"',
      '',
    ].join('\n');
    for (const text of [classic, berry]) {
      const edges = parseYarnLock(text, app).edges.filter((e) => e.from === 'a@1.0.0');
      expect(edges.map((e) => [e.to, e.spec, e.type]).sort()).toEqual([
        ['@scope/c@3.0.0', '^3.0.0', 'optional'],
        ['b@2.0.0', '^2.0.0', 'prod'],
      ]);
    }
  });

  it('reads the range a patched dependency asks for, and yarn 2 and 3 ranges with no npm: prefix', () => {
    const berry = [
      '__metadata:',
      '  version: 4',
      '',
      '"a@npm:^1.0.0":',
      '  version: 1.0.0',
      '  resolution: "a@npm:1.0.0"',
      '  dependencies:',
      '    resolve: "patch:resolve@npm%3A^1.22.0#~builtin<compat/resolve>"',
      '    ms: ^2.1.0',
      '',
      '"resolve@patch:resolve@npm%3A^1.22.0#~builtin<compat/resolve>":',
      '  version: 1.22.8',
      '  resolution: "resolve@patch:resolve@npm%3A1.22.8#~builtin<compat/resolve>::version=1.22.8&hash=c3c19d"',
      '',
      '"ms@npm:^2.1.0":',
      '  version: 2.1.3',
      '  resolution: "ms@npm:2.1.3"',
      '',
    ].join('\n');
    const edges = parseYarnLock(berry, app).edges.filter((e) => e.from === 'a@1.0.0');
    expect(edges.map((e) => [e.to, e.spec]).sort()).toEqual([
      ['ms@2.1.3', '^2.1.0'],
      ['resolve@1.22.8', '^1.22.0'],
    ]);
  });

  it('gives a package from a folder or a file its reference as version, so no registry advisory matches it', () => {
    const classic = ['# yarn lockfile v1', '', '"example-typescript@link:./example-typescript":', '  version "0.0.0"', ''].join('\n');
    const berry = [
      '__metadata:',
      '  version: 8',
      '',
      '"example-typescript@link:./example-typescript::locator=app%40workspace%3A.":',
      '  version: 0.0.0-use.local',
      '  resolution: "example-typescript@link:./example-typescript::locator=app%40workspace%3A."',
      '',
    ].join('\n');
    const manifests: Map<string, Manifest> = new Map([['.', { name: 'app', dependencies: { 'example-typescript': 'link:./example-typescript' } }]]);
    expect([...parseYarnLock(classic, manifests).nodes.keys()]).toContain('example-typescript@link:./example-typescript');
    const graph = parseYarnLock(berry, manifests);
    // The ::locator= key is found from the workspace that asks for it.
    expect(graph.edges).toEqual([
      {
        from: 'root:.',
        to: 'example-typescript@link:./example-typescript::locator=app%40workspace%3A.',
        name: 'example-typescript',
        spec: 'link:./example-typescript',
        type: 'prod',
      },
    ]);
  });

  it("links a range that resolutions or a catalog replaced, through the replacement yarn keyed", () => {
    const berry = [
      '__metadata:',
      '  version: 8',
      '',
      '"b@npm:^1.0.0":',
      '  version: 1.0.0',
      '  resolution: "b@npm:1.0.0"',
      '  dependencies:',
      '    lodash: "npm:^4.17.0"',
      '',
      '"lodash@npm:4.17.20":',
      '  version: 4.17.20',
      '  resolution: "lodash@npm:4.17.20"',
      '',
      '"react@npm:^18.3.1":',
      '  version: 18.3.1',
      '  resolution: "react@npm:18.3.1"',
      '',
    ].join('\n');
    const manifests: Map<string, Manifest> = new Map([
      ['.', { name: 'app', dependencies: { b: '^1.0.0', react: 'catalog:' }, resolutions: { lodash: '4.17.20' } }],
    ]);
    const graph = parseYarnLock(berry, manifests, { default: { react: '^18.3.1' } });
    const edge = (to: string) => graph.edges.find((e) => e.to === to);
    expect(edge('lodash@4.17.20')).toMatchObject({ from: 'b@1.0.0', spec: '^4.17.0' });
    expect(edge('react@18.3.1')).toEqual({ from: 'root:.', to: 'react@18.3.1', name: 'react', spec: '^18.3.1', catalog: 'default', type: 'prod' });
    expect(graph.warnings).toEqual([]);
  });

  it('keeps yarn 2 and 3 ranges as text (1.0 is not the number 1), and reads a yarn 1 alias with no version', () => {
    const berry = [
      '__metadata:',
      '  version: 4',
      '',
      '"a@npm:1.0.0":',
      '  version: 1.0.0',
      '  resolution: "a@npm:1.0.0"',
      '  dependencies:',
      '    b: 1.0',
      '',
      '"b@npm:1.0":',
      '  version: 1.0.0',
      '  resolution: "b@npm:1.0.0"',
      '',
    ].join('\n');
    const one: Map<string, Manifest> = new Map([['.', { name: 'app', dependencies: { a: '1.0.0' } }]]);
    expect(parseYarnLock(berry, one).edges.find((e) => e.from === 'a@1.0.0')).toMatchObject({ to: 'b@1.0.0', spec: '1.0' });
    const classic = ['# yarn lockfile v1', '', '"al@npm:lodash":', '  version "4.17.21"', ''].join('\n');
    expect([...parseYarnLock(classic, new Map([['.', { dependencies: { al: 'npm:lodash' } }]])).nodes.keys()]).toContain('lodash@4.17.21');
  });

  it('warns about dependencies it cannot find an entry for', () => {
    const graph = parseYarnLock('# yarn lockfile v1\n', new Map([['.', { dependencies: { gone: '^1.0.0' } }]]));
    expect(graph.warnings).toEqual([
      'yarn.lock has no entry for 1 dependency, so the paths and dev-only status of what they install may be off: gone@^1.0.0',
    ]);
  });

  it('reads escaped quotes in a yarn 1 entry, and treats a project with no package.json as one root', () => {
    const text = ['# yarn lockfile v1', '', '"we\\"ird@^1.0.0":', '  version "1.0.0"', ''].join('\n');
    const graph = parseYarnLock(text, new Map([['.', {}]]));
    expect(graph.roots).toEqual(['root:.']);
    expect([...graph.nodes.keys()]).toEqual(['root:.', 'we"ird@1.0.0']);
  });
});
