import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { AssessOptions } from '../src/assess.js';
import { assess } from '../src/assess.js';
import type { AuditRecord } from '../src/audit.js';
import { formatExplain, readAudit } from '../src/audit.js';
import { DEFAULT_CONFIG } from '../src/config.js';
import type { Channel } from '../src/notify/channels.js';
import type { Message } from '../src/notify/message.js';
import { formatAssessment } from '../src/report-triage.js';
import type { ClaudeTransport } from '../src/triage/claude.js';
import { OsvClient } from '../src/watch/osv.js';
import { fakeFetch } from './helpers/fake-fetch.js';
import { finding, scanResult } from './helpers/findings.js';
import { lodashInjection, osvRoutes } from './helpers/osv-routes.js';

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'bulwark-assess-'));
  await writeFile(join(dir, 'package.json'), JSON.stringify({ dependencies: { lodash: '4.17.20', minimist: '1.0.0' } }));
  await mkdir(join(dir, 'src'));
  await writeFile(join(dir, 'src', 'server.ts'), "import _ from 'lodash';\nexport const render = (s: string) => _.template(s)();\n");
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const minimistRecord = { ...lodashInjection, id: 'GHSA-xvch-5gv4-984h', summary: 'Prototype Pollution in minimist', aliases: ['CVE-2021-44906'] };
const osv = () => new OsvClient({ fetch: fakeFetch(osvRoutes({}, [{ ...lodashInjection, details: 'Use of `template` with untrusted input.' }, minimistRecord])).fetch });

const lodash = finding();
const minimist = finding({ id: 'GHSA-xvch-5gv4-984h', package: 'minimist', version: '1.0.0', devOnly: true, severity: 'CRITICAL', key: 'GHSA-xvch-5gv4-984h|minimist@1.0.0' });

/** Claude judges every finding it is asked about reachable. */
const claude: ClaudeTransport = {
  name: 'claude-code',
  async ask({ prompt }) {
    const keys = [...prompt.matchAll(/<finding key="([^"]+)">/g)].map((m) => m[1]!);
    return {
      output: { findings: keys.map((key) => ({ key, reachable: 'yes', confidence: 0.9, exposure: 'internet-facing', drop_in: 'yes', urgency: 4, reason: 'src/server.ts:2 renders request text with template.' })) },
      model: 'claude-opus-5-5',
      costUsd: 0.02,
      inputTokens: 1,
      outputTokens: 1,
    };
  },
};

function recorder(fail = false): Channel & { sent: Message[] } {
  const channel = {
    name: 'slack',
    sent: [] as Message[],
    async send(message: Message) {
      if (fail) throw new Error('HTTP 500');
      channel.sent.push(message);
    },
  };
  return channel;
}

const run = (overrides: Partial<AssessOptions>) =>
  assess({
    dir,
    result: scanResult([lodash, minimist]),
    config: { ...DEFAULT_CONFIG, dryRun: false },
    osv: osv(),
    env: {},
    write: true,
    jev: null,
    claude,
    channels: [],
    now: new Date('2026-11-21T10:00:00Z'),
    ...overrides,
  });

describe('assess', () => {
  it('judges, decides, sends one alert and the first digest, and logs each decision', async () => {
    const slack = recorder();
    const a = await run({ channels: [slack] });
    expect(a.findings.map((f) => [f.key, f.triage.source, f.decision.outcome, f.decision.rule, f.alert])).toEqual([
      ['GHSA-35jh-r3h4-6jhm|lodash@4.17.20', 'claude', 'notify', 'reachable', 'new'],
      ['GHSA-xvch-5gv4-984h|minimist@1.0.0', 'rules', 'digest', 'dev-only', null],
    ]);
    // Evidence found the import and the use of the name the advisory's text mentions.
    expect(a.findings[0]!.evidence.usage.calls).toEqual([{ file: 'src/server.ts', line: 2, runtime: 'app', name: 'template' }]);
    expect(slack.sent.map((m) => [m.kind, m.items.map((i) => i.package)])).toEqual([
      ['alert', ['lodash']],
      ['digest', ['minimist']],
    ]);
    const audit = await readAudit(join(dir, '.bulwark', 'audit.jsonl'));
    expect(audit.map((r) => (r.type === 'decision' ? `decision ${r.package} ${r.decision.rule}` : r.type === 'message' ? `message ${r.kind} ${r.sent}` : r.type))).toEqual([
      'decision lodash reachable',
      'decision minimist dev-only',
      'message alert true',
      'message digest true',
    ]);
    expect(formatAssessment(a)).toContain('Notify: 1 (1 at or above the threshold and reachable). Weekly digest: 1 (1 dev-only in the lockfile).');
  });

  it('sends nothing again until a finding gets worse, and logs only what changed', async () => {
    const slack = recorder();
    await run({ channels: [slack] });
    const again = await run({ channels: [slack], now: new Date('2026-11-22T10:00:00Z') });
    expect(again.messages).toEqual([]);
    const worse = finding({ kev: ['CVE-2021-23337'] });
    const third = await run({ channels: [slack], result: scanResult([worse, minimist]), now: new Date('2026-11-23T10:00:00Z') });
    expect(third.findings[0]).toMatchObject({ alert: 'worse', decision: { rule: 'kev' } });
    expect(slack.sent.map((m) => m.kind)).toEqual(['alert', 'digest', 'alert']);
    const audit = await readAudit(join(dir, '.bulwark', 'audit.jsonl'));
    expect(audit.filter((r): r is Extract<AuditRecord, { type: 'decision' }> => r.type === 'decision').map((r) => r.decision.rule)).toEqual(['reachable', 'dev-only', 'kev']);
    expect(formatExplain(audit, 'cve-2021-23337')).toContain('notify (kev): KEV-listed');
  });

  it('sends the digest again a week later, with only what has not been in one', async () => {
    const slack = recorder();
    await run({ channels: [slack] });
    const later = await run({ channels: [slack], now: new Date('2026-11-28T10:00:00Z') });
    expect(later.messages).toEqual([]);
  });

  it('in dry run prints instead of sending; without write it saves nothing', async () => {
    const slack = recorder();
    const dry = await run({ channels: [slack], config: DEFAULT_CONFIG });
    expect(slack.sent).toEqual([]);
    expect(dry.messages.map((m) => [m.channel, m.sent])).toEqual([
      ['terminal', false],
      ['terminal', false],
    ]);
    await rm(join(dir, '.bulwark'), { recursive: true, force: true });
    await run({ channels: [slack], write: false });
    await expect(readFile(join(dir, '.bulwark', 'decisions.json'), 'utf8')).rejects.toThrow(/ENOENT/);
  });

  it('an alert only printed in dry run is still sent once a channel is set up', async () => {
    await run({ config: DEFAULT_CONFIG });
    const again = await run({ config: DEFAULT_CONFIG, now: new Date('2026-11-21T11:00:00Z') });
    // Printed once: the next dry run does not print it again.
    expect(again.messages).toEqual([]);
    const slack = recorder();
    await run({ channels: [slack], now: new Date('2026-11-22T10:00:00Z') });
    expect(slack.sent.map((m) => [m.kind, m.items.map((i) => i.package)])).toEqual([
      ['alert', ['lodash']],
      ['digest', ['minimist']],
    ]);
  });

  it('with a missing webhook variable, messages are printed and sent once the variable is set', async () => {
    const config = { ...DEFAULT_CONFIG, dryRun: false, notify: { ...DEFAULT_CONFIG.notify, channels: [{ type: 'slack' as const, webhookEnv: 'SLACK_WEBHOOK_URL' }] } };
    const first = await run({ config, channels: undefined, env: {} });
    expect(first.messages.map((m) => m.channel)).toEqual(['terminal', 'terminal']);
    expect(first.warnings).toContain('slack channel: SLACK_WEBHOOK_URL is not set, so its messages are only printed');
    const slack = recorder();
    await run({ config, channels: [slack], now: new Date('2026-11-21T11:00:00Z') });
    expect(slack.sent.map((m) => m.kind)).toEqual(['alert', 'digest']);
  });

  it('a channel that fails does not make the one that works send again', async () => {
    const slack = recorder();
    const broken = { ...recorder(true), name: 'webhook' };
    await run({ channels: [slack, broken] });
    await run({ channels: [slack, broken], now: new Date('2026-11-21T11:00:00Z') });
    expect(slack.sent.map((m) => m.kind)).toEqual(['alert', 'digest']);
  });

  it('remembers a finding that drops out of one scan, so it does not alert again as new', async () => {
    const slack = recorder();
    await run({ channels: [slack] });
    await run({ channels: [slack], result: scanResult([minimist]), now: new Date('2026-11-21T11:00:00Z') });
    const back = await run({ channels: [slack], now: new Date('2026-11-21T12:00:00Z') });
    expect(back.findings[0]!.alert).toBeNull();
    expect(slack.sent.map((m) => m.kind)).toEqual(['alert', 'digest']);
  });

  it('keeps the last known KEV status while the KEV feed is down', async () => {
    const slack = recorder();
    await run({ channels: [slack], result: scanResult([finding({ kev: ['CVE-2021-23337'] }), minimist]) });
    const down = await run({ channels: [slack], result: scanResult([finding({ kev: null }), minimist]), now: new Date('2026-11-21T11:00:00Z') });
    expect(down.findings[0]).toMatchObject({ decision: { rule: 'kev' }, alert: null });
  });

  it('tries a message that could not be sent again on the next scan', async () => {
    const failing = recorder(true);
    const first = await run({ channels: [failing] });
    expect(first.warnings).toContain('Could not send the alert to slack: HTTP 500');
    const slack = recorder();
    await run({ channels: [slack], now: new Date('2026-11-21T11:00:00Z') });
    expect(slack.sent.map((m) => m.kind)).toEqual(['alert', 'digest']);
  });
});
