import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { decideFix, readSignal, saveSignal, SIGNAL_FILE } from '../../src/fix/signal.js';

const at = (iso: string) => new Date(iso);
const work = (keys: string[], malicious = false) => ({ keys, malicious });

describe('whether the fix job runs', () => {
  it('runs the first time there is something to fix, and not again for the same findings and files within a day', () => {
    const first = decideFix(work(['A|x@1', 'B|y@2']), 'lock v1', null, at('2026-11-27T10:00:00Z'));
    expect(first).toMatchObject({ fix: true, reason: '2 findings for a fix PR, new or changed since the fix job last ran' });
    const again = decideFix(work(['B|y@2', 'A|x@1']), 'lock v1', first.next, at('2026-11-27T14:00:00Z'));
    expect(again.fix).toBe(false);
    expect(again.reason).toContain('the same 2 findings and dependency files as when the fix job last ran (2026-11-27T10:00:00.000Z)');
    expect(again.next).toEqual(first.next);
  });

  it('runs again when the findings or the dependency files change, or a day later', () => {
    const first = decideFix(work(['A|x@1']), 'lock v1', null, at('2026-11-27T10:00:00Z'));
    expect(decideFix(work(['A|x@1', 'C|z@3']), 'lock v1', first.next, at('2026-11-27T11:00:00Z')).fix).toBe(true);
    expect(decideFix(work(['A|x@1']), 'lock v2', first.next, at('2026-11-27T11:00:00Z')).fix).toBe(true);
    const later = decideFix(work(['A|x@1']), 'lock v1', first.next, at('2026-11-28T10:00:01Z'));
    expect(later).toMatchObject({ fix: true, reason: 'a day since the fix job last ran for these findings', next: { at: '2026-11-28T10:00:01.000Z' } });
  });

  it('always runs for a malicious package, and never when there is nothing a fix PR would cover', () => {
    const first = decideFix(work(['A|x@1']), 'lock', null, at('2026-11-27T10:00:00Z'));
    expect(decideFix(work(['A|x@1'], true), 'lock', first.next, at('2026-11-27T11:00:00Z'))).toMatchObject({ fix: true, next: first.next });
    expect(decideFix(work([]), 'lock', first.next)).toEqual({ fix: false, reason: 'nothing a fix PR would cover', next: null });
  });

  it('keeps its record in the state folder, and reads a broken one as none', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'patchhound-signal-'));
    try {
      expect(await readSignal(dir)).toBeNull();
      await saveSignal(dir, { fingerprint: 'f', at: '2026-11-27T10:00:00.000Z' });
      expect(await readSignal(dir)).toEqual({ fingerprint: 'f', at: '2026-11-27T10:00:00.000Z' });
      await writeFile(join(dir, SIGNAL_FILE), '{not json');
      expect(await readSignal(dir)).toBeNull();
      await saveSignal(dir, null);
      expect(await readSignal(dir)).toBeNull();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
