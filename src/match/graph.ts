export type DepType = 'prod' | 'dev' | 'optional' | 'peer' | 'peerOptional';
export type Manager = 'npm' | 'pnpm' | 'yarn-classic' | 'yarn-berry';

export interface PkgNode {
  /** `name@version` for packages, `root:<path>` for the project and each workspace. */
  id: string;
  name: string;
  version: string;
  /**
   * npm only: ids of the packages that ship this one inside their own tarball (`inBundle`), set when
   * every installed copy is bundled. Such a copy changes only when the package that ships it does.
   */
  bundledBy?: string[];
  /**
   * For a copy that next bundles (see addNextBundles): the exact build next ships, such as
   * `19.1.0-canary-029e8bd6-20250306`. `version` then holds its release line, which OSV's ranges name.
   */
  build?: string;
}

export interface Edge {
  from: string;
  to: string;
  /** The name the parent asks for. Differs from the target's name for npm aliases. */
  name: string;
  /** Declared range, when the lockfile records it. A pnpm `catalog:` spec is replaced by the catalog's range. */
  spec?: string;
  /** pnpm: the catalog that holds the range (`default` for a bare `catalog:`), so a bump edits pnpm-workspace.yaml. */
  catalog?: string;
  type: DepType;
}

export interface DepGraph {
  manager: Manager;
  roots: string[];
  nodes: Map<string, PkgNode>;
  edges: Edge[];
  /** What the parser could not check, as sentences to show the user. */
  warnings: string[];
}

/**
 * Edges that make their target production code. An optional peer is not one: the parent only
 * uses it when something else installs it, so a devDependency that provides it stays dev-only.
 * A required peer is, since the parent cannot run without it.
 */
const RUNTIME_EDGES: ReadonlySet<DepType> = new Set(['prod', 'optional', 'peer']);

export const rootId = (path: string): string => `root:${path}`;
export const pkgId = (name: string, version: string): string => `${name}@${version}`;

/** Drops repeated edges (same parent, child and requested name). */
export function dedupeEdges(edges: readonly Edge[]): Edge[] {
  const seen = new Set<string>();
  return edges.filter((e) => {
    const key = `${e.from}>${e.to}>${e.name}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Lookups over a dependency graph: parents, children, direct and dev-only status, paths. */
export class GraphIndex {
  private readonly rootSet: Set<string>;
  private readonly incoming = new Map<string, Edge[]>();
  private readonly outgoing = new Map<string, Edge[]>();
  /** Reached from a root over runtime edges only. Includes the roots. */
  private readonly prodReachable: Set<string>;
  /** Reached from a root through at least one devDependency. */
  private readonly devReachable: Set<string>;

  constructor(readonly graph: DepGraph) {
    this.rootSet = new Set(graph.roots);
    for (const edge of graph.edges) {
      push(this.outgoing, edge.from, edge);
      push(this.incoming, edge.to, edge);
    }
    this.prodReachable = this.reach(graph.roots, (edge) => RUNTIME_EDGES.has(edge.type));
    const reachable = this.reach(graph.roots, () => true);
    const devTargets = graph.edges
      .filter((edge) => edge.type === 'dev' && reachable.has(edge.from))
      .map((edge) => edge.to);
    this.devReachable = this.reach(devTargets, () => true);
  }

  isRoot(id: string): boolean {
    return this.rootSet.has(id);
  }

  /** Every installed package, roots excluded. */
  packages(): PkgNode[] {
    return [...this.graph.nodes.values()].filter((node) => !this.rootSet.has(node.id));
  }

  parents(id: string): Edge[] {
    return this.incoming.get(id) ?? [];
  }

  children(id: string): Edge[] {
    return this.outgoing.get(id) ?? [];
  }

  /** True when the app or a workspace declares the package itself. */
  isDirect(id: string): boolean {
    return this.parents(id).some((edge) => this.rootSet.has(edge.from));
  }

  /**
   * True when a root reaches the package through a devDependency and no production path reaches
   * it. A package that nothing reaches is not dev-only: calling it dev-only would hide it.
   */
  isDevOnly(id: string): boolean {
    return this.devReachable.has(id) && !this.prodReachable.has(id);
  }

  /** Up to `max` shortest chains from a root to the package, as node ids, root first. */
  pathsTo(id: string, max = 3): string[][] {
    const found: string[][] = [];
    const expansions = new Map<string, number>();
    const queue: string[][] = [[id]];
    while (queue.length > 0 && found.length < max) {
      const chain = queue.shift()!;
      const head = chain[0]!;
      if (this.rootSet.has(head)) {
        found.push(chain);
        continue;
      }
      const times = expansions.get(head) ?? 0;
      if (times >= max) continue;
      expansions.set(head, times + 1);
      for (const edge of this.parents(head)) {
        if (!chain.includes(edge.from)) queue.push([edge.from, ...chain]);
      }
    }
    return found;
  }

  /**
   * The names the app and its workspaces declare that lead to the package: itself when direct, else
   * the direct dependencies that pull it in. These are the names the app's code imports. For a package
   * that runs in production, only production paths count (a devDependency that also pulls it in is not
   * how it reaches production).
   */
  declaredBy(id: string): string[] {
    const follow = this.isDevOnly(id) ? () => true : (edge: Edge) => RUNTIME_EDGES.has(edge.type);
    const names = new Set<string>();
    const seen = new Set([id]);
    const queue = [id];
    for (let i = 0; i < queue.length; i++) {
      for (const edge of this.parents(queue[i]!)) {
        if (!follow(edge)) continue;
        if (this.rootSet.has(edge.from)) names.add(edge.name);
        else if (!seen.has(edge.from)) {
          seen.add(edge.from);
          queue.push(edge.from);
        }
      }
    }
    return [...names].sort();
  }

  /** Every node reachable from `starts` (included) over the edges that `follow` accepts. */
  private reach(starts: readonly string[], follow: (edge: Edge) => boolean): Set<string> {
    const seen = new Set(starts);
    const queue = [...seen];
    for (let i = 0; i < queue.length; i++) {
      for (const edge of this.children(queue[i]!)) {
        if (!follow(edge) || seen.has(edge.to)) continue;
        seen.add(edge.to);
        queue.push(edge.to);
      }
    }
    return seen;
  }
}

function push<K, V>(map: Map<K, V[]>, key: K, value: V): void {
  const list = map.get(key);
  if (list) list.push(value);
  else map.set(key, [value]);
}
