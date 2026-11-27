import { copyFile, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { ScanOptions, ScanResult } from '../../src/scan.js';
import { KEV_URL } from '../../src/watch/enrich.js';
import { CHANGES_URL, changesSince, isAfter } from '../../src/watch/feed.js';
import type { OsvVuln } from '../../src/watch/osv.js';
import { loadWatchState, pollOnce } from '../../src/watch/watcher.js';
import { fakeFetch } from '../helpers/fake-fetch.js';

const csv = (...lines: [string, string][]) => () => new Response(lines.map(([modified, id]) => `${modified},${id}`).join('\n'));

describe('changesSince', () => {
  const list = csv(
    ['2026-11-20T17:30:38.125612443Z', 'MAL-3'],
    ['2026-11-20T17:30:37.65093584Z', 'MAL-2'],
    ['2026-11-20T16:12:35Z', 'GHSA-1'],
  );

  it('returns the records changed after the cursor, newest first, and the newest time', async () => {
    const { fetch } = fakeFetch({ [`GET ${CHANGES_URL}`]: list });
    expect(await changesSince(fetch, '2026-11-20T16:12:35Z')).toEqual({
      changes: [
        { id: 'MAL-3', modified: '2026-11-20T17:30:38.125612443Z' },
        { id: 'MAL-2', modified: '2026-11-20T17:30:37.65093584Z' },
      ],
      newest: '2026-11-20T17:30:38.125612443Z',
    });
  });

  it('counts nothing as changed on a first poll, and only reads where to start', async () => {
    const { fetch } = fakeFetch({ [`GET ${CHANGES_URL}`]: list });
    expect(await changesSince(fetch, undefined)).toEqual({ changes: [], newest: '2026-11-20T17:30:38.125612443Z' });
  });

  it('fails on an HTTP error', async () => {
    const { fetch } = fakeFetch({ [`GET ${CHANGES_URL}`]: () => new Response('gone', { status: 503 }) });
    await expect(changesSince(fetch, undefined)).rejects.toThrow('OSV change list GET failed with HTTP 503');
  });

  it('compares times with any number of fractional digits', () => {
    expect(isAfter('2026-11-20T17:30:37.65093584Z', '2026-11-20T17:30:37.650935839Z')).toBe(true);
    expect(isAfter('2026-11-20T17:30:37Z', '2026-11-20T17:30:37.000000001Z')).toBe(false);
    expect(isAfter('2026-11-20T17:30:38Z', '2026-11-20T17:30:37.999999999Z')).toBe(true);
  });
});

describe('pollOnce', () => {
  const fixture = (name: string, file: string) => fileURLToPath(new URL(`../fixtures/${name}/${file}`, import.meta.url));
  const lodashBug: OsvVuln = {
    id: 'GHSA-lodash',
    modified: '2026-11-21T01:00:00Z',
    affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] }],
  };
  const unrelated: OsvVuln = { id: 'MAL-elsewhere', modified: '2026-11-21T01:00:01Z', affected: [{ package: { ecosystem: 'npm', name: 'evil' } }] };

  /** Two projects (npm-app has lodash; pnpm-refresh does not), a fake network, and a scan that records its calls. */
  async function setup() {
    const root = await mkdtemp(join(tmpdir(), 'bulwark-watch-'));
    const npmApp = join(root, 'npm-app');
    const pnpmApp = join(root, 'pnpm-app');
    await mkdir(npmApp);
    await mkdir(pnpmApp);
    await copyFile(fixture('npm-app', 'package-lock.json'), join(npmApp, 'package-lock.json'));
    await copyFile(fixture('pnpm-refresh', 'pnpm-lock.yaml'), join(pnpmApp, 'pnpm-lock.yaml'));
    const net = {
      changes: [['2026-11-21T00:00:00Z', 'GHSA-old']] as [string, string][],
      kev: ['CVE-2021-23337'],
      records: new Map([lodashBug, unrelated].map((r) => [r.id, r])),
      lodashStatus: 503,
    };
    const { fetch } = fakeFetch({
      [`GET ${CHANGES_URL}`]: () => csv(...net.changes)(),
      [`GET ${KEV_URL}`]: () => ({ vulnerabilities: net.kev.map((cveID) => ({ cveID })) }),
      'GET https://api.osv.dev/v1/vulns/GHSA-lodash': () => net.records.get('GHSA-lodash') ?? new Response('busy', { status: net.lodashStatus }),
      'GET https://api.osv.dev/v1/vulns/MAL-elsewhere': () => unrelated,
    });
    const scanned: string[] = [];
    const scan = async (options: ScanOptions) => {
      scanned.push(options.dir);
      return { findings: [] } as unknown as ScanResult;
    };
    let clock = new Date('2026-11-21T02:00:00Z');
    let failing = false;
    const flaky = async (options: ScanOptions) => {
      if (failing) throw new Error('scan failed');
      return scan(options);
    };
    const poll = () =>
      pollOnce({ dirs: [npmApp, pnpmApp], statePath: join(root, 'watch.json'), fetch, scan: flaky, now: () => clock, retry: { retries: 0 } });
    const reasons = (result: Awaited<ReturnType<typeof poll>>) => Object.fromEntries(result.scans.map((s) => [s.dir.slice(root.length + 1), s.reasons]));
    return {
      root,
      npmApp,
      net,
      poll,
      reasons,
      scanned,
      tick: (ms: number) => (clock = new Date(clock.getTime() + ms)),
      fail: (on: boolean) => (failing = on),
    };
  }

  it('scans every project first, then only what a change touches', async () => {
    const w = await setup();
    expect(w.reasons(await w.poll())).toEqual({ 'npm-app': ['first scan'], 'pnpm-app': ['first scan'] });
    expect((await loadWatchState(join(w.root, 'watch.json'))).cursor).toBe('2026-11-21T00:00:00Z');

    // Nothing changed.
    expect((await w.poll()).scans).toEqual([]);

    // An advisory for lodash, which only npm-app installs, and one for a package nobody installs.
    w.net.changes.unshift(['2026-11-21T01:00:01Z', 'MAL-elsewhere'], ['2026-11-21T01:00:00Z', 'GHSA-lodash']);
    const poll = await w.poll();
    expect(poll.changes).toBe(2);
    expect(w.reasons(poll)).toEqual({ 'npm-app': ['advisory GHSA-lodash (lodash)'] });

    // A lockfile edit, then a KEV catalog change, then a quiet day.
    await writeFile(join(w.npmApp, 'package-lock.json'), `${await readFile(join(w.npmApp, 'package-lock.json'), 'utf8')}\n`);
    expect(w.reasons(await w.poll())).toEqual({ 'npm-app': ['package-lock.json changed'] });
    w.net.kev.push('CVE-2026-1');
    expect(w.reasons(await w.poll())).toEqual({ 'npm-app': ['KEV catalog changed'], 'pnpm-app': ['KEV catalog changed'] });
    w.tick(24 * 60 * 60 * 1000);
    expect(w.reasons(await w.poll())).toEqual({ 'npm-app': ['daily rescan'], 'pnpm-app': ['daily rescan'] });
  });

  it('moves on past a record it cannot read, and asks for that record again on the next poll', async () => {
    const w = await setup();
    await w.poll();
    w.net.records.delete('GHSA-lodash');
    w.net.changes.unshift(['2026-11-21T01:00:00Z', 'GHSA-lodash']);
    const poll = await w.poll();
    expect(poll.warnings).toEqual(['1 changed OSV record could not be read; the next poll asks again']);
    const state = await loadWatchState(join(w.root, 'watch.json'));
    expect(state.cursor).toBe('2026-11-21T01:00:00Z');
    expect(state.unread).toEqual([{ id: 'GHSA-lodash', modified: '2026-11-21T01:00:00Z' }]);
    w.net.records.set('GHSA-lodash', lodashBug);
    expect(w.reasons(await w.poll())).toEqual({ 'npm-app': ['advisory GHSA-lodash (lodash)'] });
    expect((await loadWatchState(join(w.root, 'watch.json'))).unread).toBeUndefined();
  });

  it('drops a changed record that OSV no longer has', async () => {
    const w = await setup();
    await w.poll();
    w.net.records.delete('GHSA-lodash');
    w.net.lodashStatus = 404;
    w.net.changes.unshift(['2026-11-21T01:00:00Z', 'GHSA-lodash']);
    expect((await w.poll()).warnings).toEqual([]);
    expect((await loadWatchState(join(w.root, 'watch.json'))).unread).toBeUndefined();
  });

  it('keeps the reasons of a scan that failed, and scans again on every poll until one succeeds', async () => {
    const w = await setup();
    await w.poll();
    w.net.changes.unshift(['2026-11-21T01:00:00Z', 'GHSA-lodash']);
    w.fail(true);
    expect((await w.poll()).scans.map((s) => s.error)).toEqual(['scan failed']);
    expect(w.reasons(await w.poll())).toEqual({ 'npm-app': ['advisory GHSA-lodash (lodash)'] });
    w.fail(false);
    expect(w.reasons(await w.poll())).toEqual({ 'npm-app': ['advisory GHSA-lodash (lodash)'] });
    expect((await w.poll()).scans).toEqual([]);
  });

  it('reports a project it cannot read, still polls the others, and scans it in full once it can be read', async () => {
    const w = await setup();
    await w.poll();
    const lockfile = join(w.npmApp, 'package-lock.json');
    const good = await readFile(lockfile, 'utf8');
    await writeFile(lockfile, '{ broken');
    const poll = await w.poll();
    expect(poll.scans.find((s) => s.dir === w.npmApp)?.error).toMatch(/^Could not read /);
    await writeFile(lockfile, good);
    expect(w.reasons(await w.poll())).toEqual({ 'npm-app': ['could not be read on an earlier poll'] });
  });
});
