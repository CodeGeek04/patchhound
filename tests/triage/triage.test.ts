import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { Evidence } from '../../src/evidence/evidence.js';
import type { ClaudeTransport } from '../../src/triage/claude.js';
import type { JevAnswers, JevClient } from '../../src/triage/jev.js';
import type { TriageItem, TriageOptions } from '../../src/triage/triage.js';
import { fromRules, needsJudgment, triage } from '../../src/triage/triage.js';
import { DiskCache } from '../../src/util/cache.js';
import { evidence } from '../helpers/findings.js';

const jevAnswer = (reachable: number, exposureConfidence = 0.95): JevAnswers => ({
  model: 'jev-1.14.0',
  reachable,
  exposure: { choice: 'internet-facing', confidence: exposureConfidence, probabilities: {} },
  dropIn: 0.9,
  urgency: { score: 3, confidence: 0.8 },
  inputTokens: 1000,
});

/** A Jev that answers from a table by finding key, and counts its calls. */
function fakeJev(table: Record<string, JevAnswers | Error>): JevClient & { calls: number } {
  const jev = {
    calls: 0,
    async ask(e: Evidence) {
      jev.calls += 1;
      const answer = table[e.key];
      if (!answer || answer instanceof Error) throw answer ?? new Error(`no answer for ${e.key}`);
      return answer;
    },
  };
  return jev as unknown as JevClient & { calls: number };
}

function fakeClaude(reachable: 'yes' | 'no' | 'unknown' = 'no'): ClaudeTransport & { asked: string[][] } {
  const claude = {
    name: 'claude-code' as const,
    asked: [] as string[][],
    async ask({ prompt }: { prompt: string }) {
      const keys = [...prompt.matchAll(/<finding key="([^"]+)">/g)].map((m) => m[1]!);
      claude.asked.push(keys);
      return {
        output: { findings: keys.map((key) => ({ key, reachable, confidence: 0.85, exposure: 'internet-facing', drop_in: 'unknown', urgency: 2, reason: `judged ${key}` })) },
        model: 'claude-opus-5-5',
        costUsd: 0.05,
        inputTokens: 1,
        outputTokens: 1,
      };
    },
  };
  return claude;
}

const item = (key: string, extra: Partial<Evidence> & { severity?: Evidence['advisory']['severity']; kev?: boolean; kind?: Evidence['advisory']['kind'] } = {}, decisive = true): TriageItem => ({
  evidence: evidence({ key, ...extra }),
  details: '',
  references: [],
  decisive,
});

const options = (overrides: Partial<TriageOptions>): TriageOptions => ({
  jev: null,
  jevModel: 'jev-latest',
  claude: null,
  claudeModel: 'claude-opus-5-5',
  threshold: 0.7,
  snippets: async () => [],
  ...overrides,
});

const dirs: string[] = [];
afterEach(async () => {
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe('triage', () => {
  it('settles dev-only and malicious findings by plain rules, asking no model', async () => {
    const jev = fakeJev({});
    const run = await triage([item('dev', { devOnly: true, exposure: 'build/dev-only' }), item('mal', { kind: 'malicious' })], options({ jev, claude: fakeClaude() }));
    expect(jev.calls).toBe(0);
    expect(run.results.get('dev')).toMatchObject({ source: 'rules', reachable: 'no', exposure: 'build/dev-only' });
    expect(run.results.get('mal')).toMatchObject({ source: 'rules', reachable: 'yes' });
  });

  it("keeps Jev's sure answers, and sends the unsure ones whose answer counts to Claude in one request", async () => {
    const jev = fakeJev({ sure: jevAnswer(0.9), unsure: jevAnswer(0.55), unsureExposure: jevAnswer(0.95, 0.5), minor: jevAnswer(0.5) });
    const claude = fakeClaude('no');
    const run = await triage([item('sure'), item('unsure'), item('unsureExposure'), item('minor', {}, false)], options({ jev, claude }));
    expect(run.results.get('sure')).toMatchObject({ source: 'jev', reachable: 'yes', reachableP: 0.9 });
    expect(claude.asked).toEqual([['unsure', 'unsureExposure']]);
    expect(run.results.get('unsure')).toMatchObject({ source: 'claude', reachable: 'no', reason: 'judged unsure', reachableP: expect.closeTo(0.15) });
    // Not decisive: Jev's unsure answer stands, as unknown.
    expect(run.results.get('minor')).toMatchObject({ source: 'jev', reachable: 'unknown' });
    expect(run.stats).toMatchObject({ jev: 4, escalated: 2, claude: 2, claudeRequests: 1, claudeCostUsd: 0.05 });
  });

  it('with escalate unless-unreachable, Claude checks every "yes"; with always, everything whose answer counts', async () => {
    const jev = fakeJev({ yes: jevAnswer(0.9), no: jevAnswer(0.1), minor: jevAnswer(0.9) });
    const items = [item('yes'), item('no'), item('minor', {}, false)];
    const unless = fakeClaude('no');
    await triage(items, options({ jev, claude: unless, escalate: 'unless-unreachable' }));
    expect(unless.asked).toEqual([['yes']]);
    const always = fakeClaude('no');
    await triage(items, options({ jev, claude: always, escalate: 'always' }));
    expect(always.asked).toEqual([['yes', 'no']]);
  });

  it('counts a yes or no that Claude is less than 50% sure of as unknown', async () => {
    const unsure: ClaudeTransport = {
      name: 'api',
      async ask({ prompt }) {
        const keys = [...prompt.matchAll(/<finding key="([^"]+)">/g)].map((m) => m[1]!);
        return {
          output: { findings: keys.map((key) => ({ key, reachable: 'no', confidence: 0.3, exposure: 'internet-facing', drop_in: 'yes', urgency: 3, reason: 'r' })) },
          model: 'claude-opus-5-5',
          costUsd: 0,
          inputTokens: 1,
          outputTokens: 1,
        };
      },
    };
    expect((await triage([item('a')], options({ claude: unsure }))).results.get('a')).toMatchObject({ source: 'claude', reachable: 'unknown', reachableP: expect.closeTo(0.7) });
  });

  it('goes straight to Claude without Jev, and falls back to plain rules without either', async () => {
    const claude = fakeClaude('yes');
    expect((await triage([item('a')], options({ claude }))).results.get('a')).toMatchObject({ source: 'claude', reachable: 'yes' });
    expect((await triage([item('a')], options({}))).results.get('a')).toMatchObject({ source: 'rules', reachable: 'unknown' });
  });

  it('caches answers by the evidence, so a second run asks nothing until the evidence changes', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'patchhound-triage-'));
    dirs.push(dir);
    const cache = new DiskCache(dir);
    const jev = fakeJev({ a: jevAnswer(0.5) });
    const claude = fakeClaude('no');
    await triage([item('a')], options({ jev, claude, cache }));
    const second = await triage([item('a')], options({ jev, claude, cache }));
    expect(jev.calls).toBe(1);
    expect(claude.asked).toHaveLength(1);
    expect(second.stats).toMatchObject({ jevCached: 1, claudeCached: 1, jev: 0, claude: 0 });
    expect(second.results.get('a')).toMatchObject({ source: 'claude', reachable: 'no' });
    await triage([item('a', { hash: 'hash-2' })], options({ jev, claude, cache }));
    expect(jev.calls).toBe(2);
  });

  it('warns when Claude leaves findings out of its answer, and keeps Jev\'s answer for them', async () => {
    const silent: ClaudeTransport = {
      name: 'api',
      async ask() {
        return { output: { findings: [] }, model: 'claude-opus-5-5', costUsd: 0, inputTokens: 1, outputTokens: 1 };
      },
    };
    const run = await triage([item('a')], options({ jev: fakeJev({ a: jevAnswer(0.5) }), claude: silent }));
    expect(run.results.get('a')).toMatchObject({ source: 'jev', reachable: 'unknown' });
    expect(run.warnings).toEqual(["Claude gave no answer for 1 finding; Jev's answer, or plain rules, stands for it."]);
    expect(run.stats.claudeRequests).toBe(2);
  });

  it('asks Claude again when the code around a use changes, and never shares an answer between projects', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'patchhound-triage-'));
    dirs.push(dir);
    const cache = new DiskCache(dir);
    const claude = fakeClaude('no');
    const code = (text: string) => async () => [{ file: 'src/a.ts', from: 1, to: 1, code: text }];
    await triage([item('a')], options({ claude, cache, scope: '/app', snippets: code('_.template(HEADER)') }));
    await triage([item('a')], options({ claude, cache, scope: '/app', snippets: code('_.template(HEADER)') }));
    expect(claude.asked).toHaveLength(1);
    await triage([item('a')], options({ claude, cache, scope: '/app', snippets: code('_.template(req.body.tpl)') }));
    expect(claude.asked).toHaveLength(2);
    await triage([item('a')], options({ claude, cache, scope: '/other-app', snippets: code('_.template(HEADER)') }));
    expect(claude.asked).toHaveLength(3);
  });

  it('carries on when Jev fails, with a warning', async () => {
    const run = await triage([item('a')], options({ jev: fakeJev({ a: new Error('Jev POST /v1/systemone failed with HTTP 401') }) }));
    expect(run.results.get('a')).toMatchObject({ source: 'rules' });
    expect(run.warnings).toEqual(['Jev failed for 1 finding: Jev POST /v1/systemone failed with HTTP 401']);
  });
});

describe('needsJudgment', () => {
  it('is true only where reachability can change what happens', () => {
    expect(needsJudgment(evidence(), true)).toBe(true);
    expect(needsJudgment(evidence(), false)).toBe(false);
    expect(needsJudgment(evidence({ severity: 'CRITICAL' }), false)).toBe(true);
    expect(needsJudgment(evidence({ kev: true }), false)).toBe(true);
    expect(needsJudgment(evidence({ devOnly: true }), true)).toBe(false);
    expect(needsJudgment(evidence({ kind: 'malicious' }), true)).toBe(false);
  });
});

describe('fromRules', () => {
  it('calls a direct dependency that only tests, scripts and build config import unreachable', () => {
    const usage = { sites: [], siteCount: 2, fileCount: 2, runtimes: ['test' as const, 'script' as const], calls: [], uses: [], unreadFiles: 0, truncated: false };
    expect(fromRules(evidence({ usage }))).toMatchObject({ reachable: 'no', exposure: 'build/dev-only' });
    expect(fromRules(evidence({ usage, direct: false }))).toMatchObject({ reachable: 'unknown' });
  });
});
