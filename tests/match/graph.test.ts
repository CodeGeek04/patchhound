import { describe, expect, it } from 'vitest';
import type { DepGraph, Edge } from '../../src/match/graph.js';
import { dedupeEdges, GraphIndex, pkgId, rootId } from '../../src/match/graph.js';

// app ── next ── @next/env
//  ├── @demo/wrapper ── lodash@4.17.20
//  └── (dev) @demo/dev-tool ── @demo/wrapper
//                         └── lodash@3.10.1
const ROOT = rootId('.');
const NEXT = pkgId('next', '15.2.2');
const ENV = pkgId('@next/env', '15.2.2');
const WRAPPER = pkgId('@demo/wrapper', '1.0.0');
const LODASH4 = pkgId('lodash', '4.17.20');
const DEVTOOL = pkgId('@demo/dev-tool', '2.0.0');
const LODASH3 = pkgId('lodash', '3.10.1');

function node(id: string) {
  const at = id.indexOf('@', 1);
  return { id, name: id.slice(0, at), version: id.slice(at + 1) };
}

const edges: Edge[] = [
  { from: ROOT, to: NEXT, name: 'next', spec: '15.2.2', type: 'prod' },
  { from: NEXT, to: ENV, name: '@next/env', type: 'prod' },
  { from: ROOT, to: WRAPPER, name: '@demo/wrapper', spec: '^1.0.0', type: 'prod' },
  { from: WRAPPER, to: LODASH4, name: 'lodash', spec: '^4.17.0', type: 'prod' },
  { from: ROOT, to: DEVTOOL, name: '@demo/dev-tool', spec: '^2.0.0', type: 'dev' },
  { from: DEVTOOL, to: WRAPPER, name: '@demo/wrapper', type: 'prod' },
  { from: DEVTOOL, to: LODASH3, name: 'lodash', type: 'prod' },
];

const graph: DepGraph = {
  manager: 'npm',
  roots: [ROOT],
  nodes: new Map([
    [ROOT, { id: ROOT, name: 'demo-app', version: '1.0.0' }],
    ...[NEXT, ENV, WRAPPER, LODASH4, DEVTOOL, LODASH3].map((id) => [id, node(id)] as const),
  ]),
  edges,
  warnings: [],
};

describe('GraphIndex', () => {
  const index = new GraphIndex(graph);

  it('lists packages without roots', () => {
    expect(index.packages().map((p) => p.id).sort()).toEqual([DEVTOOL, WRAPPER, ENV, LODASH3, LODASH4, NEXT].sort());
  });

  it('knows which packages the app declares itself', () => {
    expect(index.isDirect(NEXT)).toBe(true);
    expect(index.isDirect(LODASH4)).toBe(false);
  });

  it('marks packages reachable only through devDependencies as dev-only', () => {
    expect(index.isDevOnly(LODASH3)).toBe(true);
    expect(index.isDevOnly(DEVTOOL)).toBe(true);
    expect(index.isDevOnly(LODASH4)).toBe(false);
    expect(index.isDevOnly(ENV)).toBe(false);
  });

  it('does not call a package dev-only when no root reaches it', () => {
    const orphan = pkgId('orphan', '1.0.0');
    const withOrphan = new GraphIndex({ ...graph, nodes: new Map([...graph.nodes, [orphan, node(orphan)]]) });
    expect(withOrphan.isDevOnly(orphan)).toBe(false);
  });

  it('never calls a root dev-only', () => {
    expect(index.isDevOnly(ROOT)).toBe(false);
  });

  it('returns the shortest paths first, root included', () => {
    expect(index.pathsTo(LODASH4)).toEqual([
      [ROOT, WRAPPER, LODASH4],
      [ROOT, DEVTOOL, WRAPPER, LODASH4],
    ]);
    expect(index.pathsTo(LODASH4, 1)).toEqual([[ROOT, WRAPPER, LODASH4]]);
  });
});

describe('GraphIndex with peer dependencies', () => {
  // app ── next ┄┄(optional peer)┄┄ sass ── chokidar
  //  ├── ui ┄┄(peer)┄┄ react
  //  ├── (dev) sass
  //  └── (dev) react
  const NEXT_ = pkgId('next', '15.2.2');
  const SASS = pkgId('sass', '1.83.0');
  const CHOKIDAR = pkgId('chokidar', '4.0.3');
  const UI = pkgId('ui', '1.0.0');
  const REACT = pkgId('react', '19.0.0');
  const peerGraph: DepGraph = {
    manager: 'npm',
    roots: [ROOT],
    nodes: new Map([
      [ROOT, { id: ROOT, name: 'app', version: '' }],
      ...[NEXT_, SASS, CHOKIDAR, UI, REACT].map((id) => [id, node(id)] as const),
    ]),
    edges: [
      { from: ROOT, to: NEXT_, name: 'next', type: 'prod' },
      { from: NEXT_, to: SASS, name: 'sass', type: 'peerOptional' },
      { from: SASS, to: CHOKIDAR, name: 'chokidar', type: 'prod' },
      { from: ROOT, to: UI, name: 'ui', type: 'prod' },
      { from: UI, to: REACT, name: 'react', type: 'peer' },
      { from: ROOT, to: SASS, name: 'sass', type: 'dev' },
      { from: ROOT, to: REACT, name: 'react', type: 'dev' },
    ],
    warnings: [],
  };
  const index = new GraphIndex(peerGraph);

  it('keeps an optional peer that only a devDependency installs dev-only', () => {
    expect(index.isDevOnly(SASS)).toBe(true);
    expect(index.isDevOnly(CHOKIDAR)).toBe(true);
  });

  it('counts a required peer as production code', () => {
    expect(index.isDevOnly(REACT)).toBe(false);
  });

  it('still shows paths through an optional peer', () => {
    expect(index.pathsTo(CHOKIDAR)).toEqual([
      [ROOT, SASS, CHOKIDAR],
      [ROOT, NEXT_, SASS, CHOKIDAR],
    ]);
  });
});

describe('dedupeEdges', () => {
  it('drops repeats of the same parent, child and name', () => {
    const edge: Edge = { from: ROOT, to: NEXT, name: 'next', type: 'prod' };
    expect(dedupeEdges([edge, { ...edge }, { ...edge, name: 'alias' }])).toHaveLength(2);
  });
});
