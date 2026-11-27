import { mkdtemp, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { Facts } from '../../src/watch/state.js';
import { emptyState, loadState, observe, saveState } from '../../src/watch/state.js';

const T1 = new Date('2026-11-19T10:00:00Z');
const T2 = new Date('2026-11-19T10:30:00Z');
const T3 = new Date('2026-11-19T11:00:00Z');
const DAY = 24 * 60 * 60 * 1000;
const KEY = 'GHSA-9qr9-h5gf-34mp|next@15.2.2';

const facts = (overrides: Partial<Facts> = {}): Facts => ({
  advisory: 'fingerprint-1',
  kev: false,
  fixedVersion: '15.2.6',
  devOnly: false,
  direct: true,
  ...overrides,
});

describe('observe', () => {
  it('labels a finding new, then seen while its facts stay the same', () => {
    const first = observe(emptyState(), [{ key: KEY, facts: facts() }], T1);
    expect(first.results.get(KEY)).toEqual({ status: 'new', changed: [] });

    const second = observe(first.next, [{ key: KEY, facts: facts() }], T2);
    expect(second.results.get(KEY)).toEqual({ status: 'seen', changed: [] });
    expect(second.next.findings[KEY]).toMatchObject({ firstSeen: T1.toISOString(), lastSeen: T2.toISOString() });
  });

  it('labels a finding updated when KEV adds its CVE, though the advisory did not change', () => {
    // CVE-2025-55182 joined KEV two days after GHSA-9qr9-h5gf-34mp was published; OSV's record stayed the same.
    const first = observe(emptyState(), [{ key: KEY, facts: facts({ kev: false }) }], T1);
    const second = observe(first.next, [{ key: KEY, facts: facts({ kev: true }) }], T2);
    expect(second.results.get(KEY)).toEqual({ status: 'updated', changed: ['kev'] });
  });

  it('labels a finding updated when its package moves from dev-only to runtime', () => {
    const first = observe(emptyState(), [{ key: KEY, facts: facts({ devOnly: true, direct: false }) }], T1);
    const second = observe(first.next, [{ key: KEY, facts: facts({ devOnly: false, direct: true }) }], T2);
    expect(second.results.get(KEY)).toEqual({ status: 'updated', changed: ['devOnly', 'direct'] });
  });

  it('names advisory and fixed-version changes', () => {
    const first = observe(emptyState(), [{ key: KEY, facts: facts() }], T1);
    const second = observe(first.next, [{ key: KEY, facts: facts({ advisory: 'fingerprint-2', fixedVersion: null }) }], T2);
    expect(second.results.get(KEY)).toEqual({ status: 'updated', changed: ['advisory', 'fixedVersion'] });
  });

  it('does not call a never-known KEV value turning false a change, but true is news', () => {
    const first = observe(emptyState(), [{ key: KEY, facts: facts({ kev: undefined }) }], T1);
    const cleared = observe(first.next, [{ key: KEY, facts: facts({ kev: false }) }], T2);
    expect(cleared.results.get(KEY)).toEqual({ status: 'seen', changed: [] });
    expect(cleared.next.findings[KEY]?.facts.kev).toBe(false);

    const listed = observe(first.next, [{ key: KEY, facts: facts({ kev: true }) }], T2);
    expect(listed.results.get(KEY)).toEqual({ status: 'updated', changed: ['kev'] });
  });

  it('keeps the last KEV status while the feed is down, without calling it a change', () => {
    const first = observe(emptyState(), [{ key: KEY, facts: facts({ kev: true }) }], T1);
    const down = observe(first.next, [{ key: KEY, facts: facts({ kev: undefined }) }], T2);
    expect(down.results.get(KEY)).toEqual({ status: 'seen', changed: [] });
    expect(down.next.findings[KEY]?.facts.kev).toBe(true);

    const back = observe(down.next, [{ key: KEY, facts: facts({ kev: true }) }], T3);
    expect(back.results.get(KEY)).toEqual({ status: 'seen', changed: [] });
  });

  it('counts a KEV status that becomes known after the feed was down at first sight', () => {
    const first = observe(emptyState(), [{ key: KEY, facts: facts({ kev: undefined }) }], T1);
    expect(first.next.findings[KEY]?.facts).not.toHaveProperty('kev');
    const second = observe(first.next, [{ key: KEY, facts: facts({ kev: true }) }], T2);
    expect(second.results.get(KEY)).toEqual({ status: 'updated', changed: ['kev'] });
  });

  it('keeps a finding OSV missed for one run, so it does not come back new', () => {
    const first = observe(emptyState(), [{ key: KEY, facts: facts() }], T1);
    const missed = observe(first.next, [], T2);
    expect(missed.next.findings[KEY]).toEqual(first.next.findings[KEY]);
    const back = observe(missed.next, [{ key: KEY, facts: facts() }], T3);
    expect(back.results.get(KEY)).toEqual({ status: 'seen', changed: [] });
    expect(back.next.findings[KEY]?.firstSeen).toBe(T1.toISOString());
  });

  it('drops a finding once it has not been seen for 7 days', () => {
    const first = observe(emptyState(), [{ key: KEY, facts: facts() }], T1);
    const almost = observe(first.next, [], new Date(T1.getTime() + 7 * DAY - 1));
    expect(almost.next.findings[KEY]).toBeDefined();
    expect(observe(almost.next, [], new Date(T1.getTime() + 7 * DAY)).next.findings).toEqual({});
  });
});

describe('loadState and saveState', () => {
  const tempDir = () => mkdtemp(join(tmpdir(), 'patchhound-'));

  it('starts empty when there is no file, and round-trips', async () => {
    const path = join(await tempDir(), 'nested', 'state.json');
    expect(await loadState(path)).toEqual(emptyState());
    const { next } = observe(emptyState(), [{ key: 'a', facts: facts() }, { key: 'b', facts: facts({ kev: undefined }) }], T1);
    await saveState(path, next);
    expect(await loadState(path)).toEqual(next);
    expect(JSON.parse(await readFile(path, 'utf8'))).toMatchObject({ version: 2 });
  });

  it('replaces the file in one step and leaves no temp file behind', async () => {
    const dir = await tempDir();
    const path = join(dir, 'state.json');
    await saveState(path, emptyState());
    const before = await stat(path);
    await saveState(path, observe(emptyState(), [{ key: 'a', facts: facts() }], T1).next);
    // A new inode: the old file was renamed over, not truncated and rewritten in place.
    expect((await stat(path)).ino).not.toBe(before.ino);
    expect(await readdir(dir)).toEqual(['state.json']);
  });

  it('rejects a state file of another version, naming the file', async () => {
    const path = join(await tempDir(), 'state.json');
    await writeFile(path, JSON.stringify({ version: 1, findings: { a: { firstSeen: 'x', modified: 'm' } } }));
    await expect(loadState(path)).rejects.toThrow(`State file ${path} has version 1; this patchhound reads version 2`);
  });

  it('rejects a state file it cannot read, naming the file and the problem', async () => {
    const path = join(await tempDir(), 'state.json');
    await writeFile(path, '{"version": 2, "findings": {');
    await expect(loadState(path)).rejects.toThrow(`State file ${path} is not valid JSON`);

    const entry = { firstSeen: T1.toISOString(), lastSeen: T1.toISOString(), facts: { ...facts(), devOnly: 'no' } };
    await writeFile(path, JSON.stringify({ version: 2, findings: { [KEY]: entry } }));
    await expect(loadState(path)).rejects.toThrow(`State file ${path} is malformed: findings["${KEY}"].facts.devOnly is not a boolean`);

    await writeFile(path, JSON.stringify([]));
    await expect(loadState(path)).rejects.toThrow(`State file ${path} is malformed: not an object`);
  });
});
