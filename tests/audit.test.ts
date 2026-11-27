import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { AuditRecord, FixRecord } from '../src/audit.js';
import { decisionRecord, FIX_LOG, formatExplain, readAllAudit } from '../src/audit.js';
import { evidence } from './helpers/findings.js';

describe('the audit log and the fix log', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'bulwark-audit-'));
    await mkdir(join(dir, '.bulwark'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  const KEY = 'GHSA-35jh-r3h4-6jhm|lodash@4.17.20';
  const decision = decisionRecord({
    at: '2026-11-26T09:00:00.000Z',
    scan: 's1',
    project: 'app',
    evidence: evidence(),
    triage: { reachable: 'yes', reachableP: 0.9, exposure: 'internet-facing', dropIn: 'yes', urgency: 4, reason: 'renders request text', source: 'claude', jev: null, claude: null },
    decision: { outcome: 'notify', rule: 'reachable', wouldDo: [{ tier: 'fix-pr', enabled: true }] },
    dryRun: false,
  });
  const fix = (at: string, pr: string): FixRecord => ({ type: 'fix', at, project: 'app', kind: 'fixes', branch: 'bulwark/fixes', base: 'c1', pr, fixed: [KEY], remaining: [], checks: [], agentCostUsd: null });
  const lines = (records: readonly AuditRecord[]) => records.map((r) => `${JSON.stringify(r)}\n`).join('');
  const state = () => join(dir, '.bulwark');

  it('reads both, oldest first, so explain shows the fix PR the fix job logged on its own', async () => {
    // A cache from before the fix log kept its fix records in the audit log; they still count.
    await writeFile(join(state(), 'audit.jsonl'), lines([decision, fix('2026-11-26T10:00:00.000Z', 'https://github.com/o/r/pull/1')]));
    await writeFile(join(state(), FIX_LOG), lines([fix('2026-11-26T09:30:00.000Z', 'https://github.com/o/r/pull/0'), fix('2026-11-26T11:00:00.000Z', 'https://github.com/o/r/pull/2')]));
    const records = await readAllAudit(state());
    expect(records.map((r) => `${r.type} ${r.at.slice(11, 16)}`)).toEqual(['decision 09:00', 'fix 09:30', 'fix 10:00', 'fix 11:00']);
    const text = formatExplain(records, 'CVE-2021-23337');
    expect(text).toContain('2026-11-26 11:00 fix PR https://github.com/o/r/pull/2: fixed there');
    expect(text.indexOf('pull/0')).toBeLessThan(text.indexOf('pull/1'));
  });

  it('reads either log alone, and neither as nothing', async () => {
    expect(await readAllAudit(state())).toEqual([]);
    await writeFile(join(state(), FIX_LOG), lines([fix('2026-11-26T11:00:00.000Z', 'https://github.com/o/r/pull/2')]));
    expect((await readAllAudit(state())).map((r) => r.type)).toEqual(['fix']);
  });
});
