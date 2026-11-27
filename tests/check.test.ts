import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { Assessment } from '../src/assess.js';
import type { CheckOptions } from '../src/check.js';
import { check, pageText } from '../src/check.js';
import type { ScanResult } from '../src/scan.js';
import type { ClaudeTransport } from '../src/triage/claude.js';
import { OsvClient } from '../src/watch/osv.js';
import { fakeFetch } from './helpers/fake-fetch.js';
import { scanResult } from './helpers/findings.js';
import { lodashInjection, osvRoutes } from './helpers/osv-routes.js';

// npm-app installs lodash 4.17.20 (among others).
const dir = fileURLToPath(new URL('./fixtures/npm-app', import.meta.url));

const nothingFound = async (): Promise<{ result: ScanResult; assessment: Assessment }> => ({
  result: scanResult([], { lockfile: 'package-lock.json' }),
  assessment: { findings: [] } as unknown as Assessment,
});

const options = (overrides: Partial<CheckOptions> = {}): CheckOptions => ({
  dir,
  osv: new OsvClient({
    fetch: fakeFetch(
      osvRoutes({}, [
        { ...lodashInjection, id: 'GHSA-29mw-wpgm-hmr9', affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.16' }] }] }] },
        // OSV's own CVE records name no npm package; the GitHub advisory they alias does.
        { id: 'CVE-2020-28500', modified: '2026-01-01T00:00:00Z', aliases: ['GHSA-29mw-wpgm-hmr9'] },
      ]),
    ).fetch,
  }),
  scanAndAssess: nothingFound,
  claude: null,
  ...overrides,
});

describe('check', () => {
  it('explains why an advisory does not affect the project', async () => {
    expect(await check('ghsa-29mw-wpgm-hmr9', options())).toBe(['GHSA-29mw-wpgm-hmr9: demo-app is not affected.', '  lodash@4.17.20: installed, outside the affected range'].join('\n'));
    expect(await check('CVE-2099-0001', options())).toBe('CVE-2099-0001: OSV has no record of it, and nothing installed in demo-app matches it.');
    expect(await check('cve-2020-28500', options())).toBe(
      ["CVE-2020-28500 (OSV's GHSA-29mw-wpgm-hmr9): demo-app is not affected.", '  lodash@4.17.20: installed, outside the affected range'].join('\n'),
    );
  });

  it('reads a link with Claude, then checks the ids and packages it names; a link only ever reports', async () => {
    const page = '<html><script>var x = "CVE-1999-1";</script><h1>lodash &amp; friends</h1><p>See GHSA-29MW-WPGM-HMR9.</p></html>';
    const fetch = fakeFetch({ 'GET https://blog.test/post': () => new Response(page, { headers: { 'content-type': 'text/html' } }) }).fetch;
    const prompts: string[] = [];
    const claude: ClaudeTransport = {
      name: 'api',
      async ask({ prompt }) {
        prompts.push(prompt);
        return {
          output: { advisories: [], packages: [{ name: 'lodash', ecosystem: 'npm', affected: '<4.17.21', fixed: '4.17.21' }], summary: 'Template injection in lodash.' },
          model: 'claude-opus-5-5',
          costUsd: 0,
          inputTokens: 1,
          outputTokens: 1,
        };
      },
    };
    const out = await check('https://blog.test/post', options({ fetch, claude }));
    expect(prompts[0]).toContain('<page>\nlodash & friends See GHSA-29MW-WPGM-HMR9.\n</page>');
    expect(out).toContain('Template injection in lodash.');
    expect(out).toContain('GHSA-29mw-wpgm-hmr9: demo-app is not affected.');
    expect(out).toContain('lodash@4.17.20: in the range the page gives (<4.17.21); fixed in 4.17.21. Only a link says so: this can notify or propose a fix, never act on its own.');
  });
});

describe('check, a link without a range', () => {
  it('does not read an empty range as every version', async () => {
    const fetch = fakeFetch({ 'GET https://blog.test/post': () => new Response('<p>lodash is affected</p>') }).fetch;
    const claude: ClaudeTransport = {
      name: 'api',
      async ask() {
        return { output: { advisories: [], packages: [{ name: 'lodash', ecosystem: 'npm', affected: '', fixed: '' }], summary: '' }, model: 'm', costUsd: 0, inputTokens: 1, outputTokens: 1 };
      },
    };
    const out = await check('https://blog.test/post', options({ fetch, claude }));
    expect(out).toContain('lodash@4.17.20: the page\'s range "" does not read as semver; check by hand');
  });
});

describe('pageText', () => {
  it('drops scripts, styles and tags, and decodes entities', () => {
    expect(pageText('<style>p{}</style><p>a &lt;b&gt; &quot;c&quot;</p>\n\n<b>d</b>')).toBe('a <b> "c" d');
  });
});
