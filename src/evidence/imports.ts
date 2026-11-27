import { parse } from '@babel/parser';

/** Where a file's code runs, judged from its path and directives. `app` is app code that could run on either side. */
export type Runtime = 'server' | 'client' | 'app' | 'build' | 'test' | 'script';

export interface ImportSite {
  /** The package the specifier names (`lodash` for `lodash/template`). */
  package: string;
  specifier: string;
  kind: 'import' | 'export' | 'require' | 'dynamic';
  /** `import type`: erased at build time, so no code from the package runs. */
  typeOnly: boolean;
  line: number;
}

export interface CallSite {
  package: string;
  /** The property or function name used (`template` in `_.template(...)`). */
  name: string;
  line: number;
}

/** Where the file uses something it imported from a package: `_.template(...)`, `new Agent(...)`, `sanitizeHtml(...)`. */
export interface UseSite {
  package: string;
  /** As the code writes it: `cheerio.load`, `Agent`, `sanitizeHtml`. */
  expression: string;
  line: number;
}

export interface FileFacts {
  imports: ImportSite[];
  /** Uses of a property or named import of an imported package, for the names `wanted` lists per package. */
  calls: CallSite[];
  /** Uses of anything imported from a package, at most MAX_USES_PER_PACKAGE per package. */
  uses: UseSite[];
  directives: string[];
}

const MAX_USES_PER_PACKAGE = 8;

const SKIP_SPECIFIER = /^(\.|\/|#|node:|[a-z]+:\/\/|data:)/;

/** `lodash/template` -> `lodash`, `@scope/pkg/sub` -> `@scope/pkg`; null for relative, absolute and built-in specifiers. */
export function packageOf(specifier: string): string | null {
  if (SKIP_SPECIFIER.test(specifier) || specifier === '') return null;
  const parts = specifier.split('/');
  if (specifier.startsWith('@')) return parts.length >= 2 && parts[1] ? `${parts[0]}/${parts[1]}` : null;
  return parts[0]!;
}

type Node = { type: string; loc?: { start: { line: number } } | null; [key: string]: unknown };

/**
 * The imports of one source file, and the uses of `wanted` names on what it imports. A file the
 * parser cannot read gives null (the caller counts it, so a gap in the evidence is visible).
 */
export function readFile(code: string, fileName: string, wanted: ReadonlyMap<string, ReadonlySet<string>> = new Map()): FileFacts | null {
  const typescript = /\.[cm]?tsx?$/.test(fileName);
  // In a .ts file `<T>x` is a type assertion, so JSX is only on for .tsx and for JavaScript.
  const jsx = !/\.[cm]?ts$/.test(fileName);
  let ast: { program: Node & { body: Node[]; directives?: { value: { value: string } }[] } };
  try {
    ast = parse(code, {
      sourceType: 'unambiguous',
      allowReturnOutsideFunction: true,
      allowImportExportEverywhere: true,
      errorRecovery: true,
      plugins: [...(typescript ? (['typescript'] as const) : []), ...(jsx ? (['jsx'] as const) : []), 'decorators-legacy'],
    }) as unknown as typeof ast;
  } catch {
    return null;
  }
  const imports: ImportSite[] = [];
  const calls: CallSite[] = [];
  const uses: UseSite[] = [];
  const useCounts = new Map<string, number>();
  const use = (pkg: string, expression: string, node: Node) => {
    const n = useCounts.get(pkg) ?? 0;
    if (n >= MAX_USES_PER_PACKAGE || uses.some((u) => u.package === pkg && u.expression === expression && u.line === lineOf(node))) return;
    useCounts.set(pkg, n + 1);
    uses.push({ package: pkg, expression, line: lineOf(node) });
  };
  // Local names bound to a whole package (`import _ from 'lodash'`, `const _ = require('lodash')`).
  const namespaces = new Map<string, string>();
  // Local names bound to one export (`import { template } from 'lodash'`): local -> [package, exported name].
  const named = new Map<string, [string, string]>();
  const lineOf = (node: Node) => node.loc?.start.line ?? 0;
  const add = (specifier: string, kind: ImportSite['kind'], typeOnly: boolean, node: Node) => {
    const pkg = packageOf(specifier);
    if (pkg !== null) imports.push({ package: pkg, specifier, kind, typeOnly, line: lineOf(node) });
    return pkg;
  };
  const noteSubpath = (pkg: string, specifier: string, node: Node) => {
    // `import template from 'lodash/template'` names the function in the path.
    const rest = specifier.slice(pkg.length + 1).split('/').pop() ?? '';
    if (rest !== '' && wanted.get(pkg)?.has(rest)) calls.push({ package: pkg, name: rest, line: lineOf(node) });
  };

  walk(ast.program, (node, parent) => {
    switch (node.type) {
      case 'ImportDeclaration': {
        const source = (node.source as { value: string }).value;
        const declType = node.importKind === 'type';
        const specifiers = (node.specifiers as Node[]) ?? [];
        const allTypes = declType || (specifiers.length > 0 && specifiers.every((s) => s.importKind === 'type'));
        const pkg = add(source, 'import', allTypes, node);
        if (pkg === null || allTypes) return;
        noteSubpath(pkg, source, node);
        for (const s of specifiers) {
          const local = (s.local as { name: string }).name;
          if (s.type === 'ImportSpecifier') {
            if (s.importKind === 'type') continue;
            const imported = s.imported as { name?: string; value?: string };
            named.set(local, [pkg, imported.name ?? imported.value ?? local]);
          } else {
            namespaces.set(local, pkg);
          }
        }
        return;
      }
      case 'ExportNamedDeclaration':
      case 'ExportAllDeclaration': {
        const source = node.source as { value: string } | null;
        if (source) add(source.value, 'export', node.exportKind === 'type', node);
        return;
      }
      case 'ImportExpression': {
        const source = node.source as Node;
        if (source.type === 'StringLiteral') add(source.value as string, 'dynamic', false, node);
        return;
      }
      case 'CallExpression': {
        const callee = node.callee as Node;
        const [first] = (node.arguments as Node[]) ?? [];
        if (first?.type === 'StringLiteral') {
          const specifier = first.value as string;
          if (callee.type === 'Import') {
            add(specifier, 'dynamic', false, node);
            return;
          }
          if (callee.type === 'Identifier' && callee.name === 'require') {
            const pkg = add(specifier, 'require', false, node);
            if (pkg !== null) {
              noteSubpath(pkg, specifier, node);
              bindRequire(parent, pkg, namespaces, named);
            }
            return;
          }
        }
        if (callee.type === 'Identifier') {
          const local = callee.name as string;
          const hit = named.get(local);
          if (hit) {
            use(hit[0], local, node);
            if (wanted.get(hit[0])?.has(hit[1])) calls.push({ package: hit[0], name: hit[1], line: lineOf(node) });
          }
          // A default or namespace import called as a function: `sanitizeHtml(html, options)`.
          const pkg = namespaces.get(local);
          if (pkg !== undefined) use(pkg, local, node);
        }
        return;
      }
      case 'NewExpression': {
        const callee = node.callee as Node;
        if (callee.type !== 'Identifier') return;
        const local = callee.name as string;
        const pkg = named.get(local)?.[0] ?? namespaces.get(local);
        if (pkg !== undefined) use(pkg, `new ${local}`, node);
        return;
      }
      case 'MemberExpression':
      case 'OptionalMemberExpression': {
        const object = node.object as Node;
        const property = node.property as Node;
        if (object.type !== 'Identifier' || node.computed) return;
        const pkg = namespaces.get(object.name as string);
        const name = property.type === 'Identifier' ? (property.name as string) : null;
        if (pkg !== undefined && name !== null) use(pkg, `${object.name as string}.${name}`, node);
        if (pkg !== undefined && name !== null && wanted.get(pkg)?.has(name)) calls.push({ package: pkg, name, line: lineOf(node) });
        return;
      }
    }
  });
  const directives = (ast.program.directives ?? []).map((d) => d.value.value);
  return { imports, calls: dedupeCalls(calls), uses, directives };
}

/** `const x = require('p')` and `const { a, b: c } = require('p')`. */
function bindRequire(parent: Node | null, pkg: string, namespaces: Map<string, string>, named: Map<string, [string, string]>): void {
  if (parent?.type !== 'VariableDeclarator') return;
  const id = parent.id as Node;
  if (id.type === 'Identifier') namespaces.set(id.name as string, pkg);
  if (id.type === 'ObjectPattern') {
    for (const prop of id.properties as Node[]) {
      if (prop.type !== 'ObjectProperty') continue;
      const key = prop.key as Node;
      const value = prop.value as Node;
      const exported = key.type === 'Identifier' ? (key.name as string) : key.type === 'StringLiteral' ? (key.value as string) : null;
      if (exported !== null && value.type === 'Identifier') named.set(value.name as string, [pkg, exported]);
    }
  }
}

function dedupeCalls(calls: CallSite[]): CallSite[] {
  const seen = new Set<string>();
  return calls.filter((c) => {
    const key = `${c.package}|${c.name}|${c.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Visits every AST node once, parents before children, with each node's parent. */
function walk(root: Node, visit: (node: Node, parent: Node | null) => void): void {
  const stack: [Node, Node | null][] = [[root, null]];
  while (stack.length > 0) {
    const [node, parent] = stack.pop()!;
    visit(node, parent);
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'start' || key === 'end' || key === 'leadingComments' || key === 'trailingComments' || key === 'extra') continue;
      const value = node[key];
      if (Array.isArray(value)) {
        for (let i = value.length - 1; i >= 0; i--) if (isNode(value[i])) stack.push([value[i] as Node, node]);
      } else if (isNode(value)) {
        stack.push([value, node]);
      }
    }
  }
}

function isNode(value: unknown): value is Node {
  return typeof value === 'object' && value !== null && typeof (value as { type?: unknown }).type === 'string';
}

const TEST = /(^|\/)(__tests__|__mocks__|tests?|e2e|cypress|playwright|\.storybook)\/|\.(test|spec|stories|cy)\.[cm]?[jt]sx?$/;
const SCRIPT = /(^|\/)scripts?\//;
// Build tools' own config files; `sentry.server.config.ts` or `auth.config.ts` run with the app.
const BUILD =
  /(^|\/)(next|vite|vitest|webpack|rollup|rolldown|tailwind|postcss|babel|eslint|prettier|stylelint|jest|playwright|cypress|tsup|esbuild|svelte|astro|nuxt|remix|metro|turbo|commitlint|drizzle|lint-staged|electron-builder|electron\.vite)\.config\.[cm]?[jt]s$|(^|\/)\.eslintrc\.[cm]?js$|(^|\/)(gulpfile|Gruntfile)\.[cm]?js$/;
const SERVER_PATH = /(^|\/)pages\/api\/|(^|\/)(middleware|instrumentation)\.[jt]s$|(^|\/)(server|api|backend|lambdas?|functions|workers?)\/|\.server\.[cm]?[jt]sx?$|(^|\/)route\.[jt]sx?$/;
const NEXT_SERVER_FILE = /(^|\/)app\/(.*\/)?(page|layout|template|loading|error|not-found|default|head|opengraph-image|sitemap|robots)\.[jt]sx?$/;
const CLIENT_PATH = /\.client\.[cm]?[jt]sx?$/;

/**
 * Where a file's code runs. `next` says the project uses Next.js, whose app-router files are server
 * components unless they say 'use client'.
 */
export function classify(relativePath: string, directives: readonly string[], next: boolean): Runtime {
  if (TEST.test(relativePath)) return 'test';
  if (BUILD.test(relativePath)) return 'build';
  if (SCRIPT.test(relativePath)) return 'script';
  if (directives.includes('use client') || CLIENT_PATH.test(relativePath)) return 'client';
  if (directives.includes('use server') || SERVER_PATH.test(relativePath)) return 'server';
  if (next && NEXT_SERVER_FILE.test(relativePath)) return 'server';
  return 'app';
}
