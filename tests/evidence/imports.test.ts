import { describe, expect, it } from 'vitest';
import { classify, packageOf, readFile } from '../../src/evidence/imports.js';

describe('packageOf', () => {
  it('names the package a specifier imports, and skips relative, absolute, built-in and URL specifiers', () => {
    expect(packageOf('lodash/template')).toBe('lodash');
    expect(packageOf('@aws-sdk/client-s3/dist')).toBe('@aws-sdk/client-s3');
    expect(packageOf('next')).toBe('next');
    for (const skip of ['./a', '../b', '/abs', 'node:fs', '#internal', 'https://x.dev/m.js', '@scope']) expect(packageOf(skip)).toBeNull();
  });
});

describe('readFile', () => {
  const wanted = new Map([['lodash', new Set(['template', 'merge'])]]);

  it('finds imports, exports, require() and dynamic import(), with lines', () => {
    const code = [
      "import _ from 'lodash';",
      "import type { Foo } from 'types-only';",
      "import { type Bar } from 'types-too';",
      "export { x } from 'reexported';",
      "const yaml = require('js-yaml');",
      "const later = () => import('lazy-pkg');",
      "import './styles.css';",
    ].join('\n');
    const facts = readFile(code, 'src/a.ts', wanted)!;
    expect(facts.imports.map((i) => [i.package, i.kind, i.typeOnly, i.line])).toEqual([
      ['lodash', 'import', false, 1],
      ['types-only', 'import', true, 2],
      ['types-too', 'import', true, 3],
      ['reexported', 'export', false, 4],
      ['js-yaml', 'require', false, 5],
      ['lazy-pkg', 'dynamic', false, 6],
    ]);
  });

  it('records uses of the wanted names: on a namespace, a named import, a destructured require and a subpath', () => {
    const code = [
      "import _ from 'lodash';",
      "import { merge as deepMerge } from 'lodash';",
      "const { template } = require('lodash');",
      "import tpl from 'lodash/template';",
      '_.template(userInput);',
      'deepMerge(a, b);',
      'template(x);',
      '_.map(list, f);',
    ].join('\n');
    const facts = readFile(code, 'src/b.js', wanted)!;
    expect(facts.calls.map((c) => [c.name, c.line])).toEqual([
      ['template', 4],
      ['template', 5],
      ['merge', 6],
      ['template', 7],
    ]);
  });

  it('records how the file uses what it imports: calls, members and constructors', () => {
    const code = [
      "import sanitizeHtml from 'sanitize-html';",
      "import * as cheerio from 'cheerio';",
      "import { Agent } from 'undici';",
      'sanitizeHtml(text, { allowedTags: ["a"] });',
      'const $ = cheerio.load(html);',
      'const agent = new Agent({ connect: {} });',
    ].join('\n');
    expect(readFile(code, 'src/e.ts')!.uses.map((u) => [u.package, u.expression, u.line])).toEqual([
      ['sanitize-html', 'sanitizeHtml', 4],
      ['cheerio', 'cheerio.load', 5],
      ['undici', 'new Agent', 6],
    ]);
  });

  it('ignores imports in comments and strings, reads JSX, and reports directives', () => {
    const code = ["'use client';", "// import x from 'commented';", "const s = \"require('in-a-string')\";", 'export const A = () => <div />;'].join('\n');
    const facts = readFile(code, 'app/c.tsx')!;
    expect(facts.imports).toEqual([]);
    expect(facts.directives).toEqual(['use client']);
  });

  it('reads `<T>x` in a .ts file as a type assertion, not JSX', () => {
    expect(readFile("import a from 'a';\nconst n = <number>value;", 'src/d.ts')!.imports.map((i) => i.package)).toEqual(['a']);
  });
});

describe('classify', () => {
  it('tells where a file runs from its path and directives', () => {
    expect(classify('src/__tests__/a.ts', [], false)).toBe('test');
    expect(classify('src/a.test.tsx', [], false)).toBe('test');
    expect(classify('next.config.mjs', [], true)).toBe('build');
    expect(classify('scripts/seed.ts', [], false)).toBe('script');
    expect(classify('components/Button.tsx', ['use client'], true)).toBe('client');
    expect(classify('lib/actions.ts', ['use server'], true)).toBe('server');
    expect(classify('app/api/users/route.ts', [], true)).toBe('server');
    expect(classify('pages/api/hello.ts', [], false)).toBe('server');
    expect(classify('src/middleware.ts', [], true)).toBe('server');
    expect(classify('app/dashboard/page.tsx', [], true)).toBe('server');
    expect(classify('app/dashboard/page.tsx', [], false)).toBe('app');
    expect(classify('lib/util.ts', [], true)).toBe('app');
    // Config files that run with the app, and Next routes named like test folders, are not build or test code.
    expect(classify('sentry.server.config.ts', [], true)).toBe('app');
    expect(classify('src/config/database.config.ts', [], false)).toBe('app');
    expect(classify('app/stories/page.tsx', [], true)).toBe('server');
    expect(classify('vite.config.ts', [], false)).toBe('build');
  });
});
