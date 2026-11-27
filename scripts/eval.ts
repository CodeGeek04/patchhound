/**
 * The milestone 2 gate: triage and the policy against labeled findings from real apps.
 *
 *   npm run eval -- [labels.json] [--only-labeled] [--draft candidates.json]
 *
 * Labels are per advisory and app, the way an alert lists them. Every finding whose answer counts
 * goes to Jev and to Claude once (answers are cached), so four strategies are compared on the same
 * answers: Jev first and Claude when Jev is unsure; Jev first, but Claude checks every "reachable"
 * (a "yes" alerts, so it is worth a second look); Claude for every such finding; and Jev alone. Each
 * is scored with the critical floor (every critical finding alerts) and without it (the default).
 * `--only-labeled` asks Claude about labeled findings only, which is all the scores need.
 *
 * A label may carry a `weight`: a random sample of N out of M alerts gets M/N each, so precision
 * estimates all alerts. The labels file stays out of git (eval/local/): which advisories affect which
 * private app is not for publishing. See eval/README.md.
 */
import { readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import type { AssessedFinding } from '../src/assess.js';
import { assess } from '../src/assess.js';
import { loadConfig } from '../src/config.js';
import type { Decision } from '../src/policy.js';
import { decide } from '../src/policy.js';
import { scan } from '../src/scan.js';
import type { Triage, YesNo } from '../src/triage/triage.js';
import { fromClaude, fromJev, fromRules, isSure } from '../src/triage/triage.js';
import { DiskCache, defaultCacheDir } from '../src/util/cache.js';
import { OsvClient } from '../src/watch/osv.js';

interface Label {
  app: string;
  advisory: string;
  reachable: YesNo;
  notify: boolean;
  /** How many alerts this label stands for (sampling). Default 1. */
  weight?: number;
  /** `critical`: every critical or KEV-listed finding in production code is labeled, for recall. */
  stratum?: string;
  confirmed?: boolean;
  note?: string;
}

interface LabelFile {
  apps: Record<string, string>;
  items: Label[];
}

const STRATEGIES = ['jev+claude', 'jev-no+claude', 'claude', 'jev'] as const;
type Strategy = (typeof STRATEGIES)[number];
const VARIANTS = STRATEGIES.flatMap((s) => [s, `${s}/no-floor`]);
const JEV_PRICE_PER_TOKEN = 0.042 / 1e6;
const REACH_ORDER: YesNo[] = ['yes', 'unknown', 'no'];

function strategyTriage(f: AssessedFinding, strategy: Strategy, threshold: number): Triage {
  const t = f.triage;
  if (t.source === 'rules' && !t.jev && !t.claude) return t;
  const jev = t.jev ? fromJev(f.evidence, t.jev, threshold) : null;
  const claude = t.claude ? fromClaude(f.evidence, t.claude, t.jev) : null;
  if (strategy === 'jev') return jev ?? fromRules(f.evidence);
  if (strategy === 'claude') return claude ?? jev ?? fromRules(f.evidence);
  // jev-no+claude trusts Jev only when it is sure the code is not reachable: a "yes" alerts, so Claude checks it.
  if (strategy === 'jev-no+claude' && t.jev && isSure(t.jev, threshold) && t.jev.reachable <= 1 - threshold) return jev!;
  if (strategy === 'jev-no+claude') return claude ?? jev ?? fromRules(f.evidence);
  if (t.jev && isSure(t.jev, threshold)) return jev!;
  return claude ?? jev ?? fromRules(f.evidence);
}

/** One advisory in one app, as an alert line shows it. */
interface Group {
  app: string;
  advisory: string;
  severity: string;
  kev: boolean;
  production: boolean;
  findings: { f: AssessedFinding; triage: Record<Strategy, Triage>; decisions: Record<string, Decision> }[];
}

const expand = (path: string) => resolve(path.startsWith('~/') ? join(homedir(), path.slice(2)) : path);
const pct = (n: number, d: number) => (d === 0 ? 'n/a' : `${((100 * n) / d).toFixed(0)}%`);
const groupKey = (app: string, advisory: string) => `${app}|${advisory.toUpperCase()}`;

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const draftAt = args.indexOf('--draft');
  const draftPath = draftAt >= 0 ? args[draftAt + 1] : undefined;
  const onlyLabeled = args.includes('--only-labeled');
  const labelsPath = args.find((a, i) => !a.startsWith('--') && (draftAt < 0 || i !== draftAt + 1)) ?? 'eval/local/labels.json';
  const labels = JSON.parse(await readFile(labelsPath, 'utf8')) as LabelFile;
  const byGroup = new Map(labels.items.map((l) => [groupKey(l.app, l.advisory), l]));
  const cacheDir = defaultCacheDir();
  const cache = new DiskCache(cacheDir);

  const groups = new Map<string, Group>();
  let jevTokens = 0;
  let claudeCost = 0;
  let asked = 0;
  let unsure = 0;
  for (const [app, path] of Object.entries(labels.apps)) {
    const dir = expand(path);
    process.stderr.write(`${app}: scanning\n`);
    const result = await scan({ dir, dryRun: true, cacheDir });
    const config = await loadConfig(dir);
    const a = await assess({
      dir,
      result,
      config,
      osv: new OsvClient({ cache }),
      cache,
      write: false,
      escalate: 'always',
      ...(onlyLabeled ? { decisive: (e) => byGroup.has(groupKey(app, e.advisory.id)) && !e.devOnly && e.advisory.kind !== 'malicious' } : {}),
    });
    for (const warning of a.warnings) process.stderr.write(`${app}: warning: ${warning}\n`);
    jevTokens += a.stats.jevTokens;
    claudeCost += a.stats.claudeCostUsd ?? 0;
    const threshold = config.triage.jev.threshold;
    for (const f of a.findings) {
      if (f.triage.claude) {
        asked += 1;
        if (!f.triage.jev || !isSure(f.triage.jev, threshold)) unsure += 1;
      }
      const triage = Object.fromEntries(STRATEGIES.map((s) => [s, strategyTriage(f, s, threshold)])) as Record<Strategy, Triage>;
      const decisions: Record<string, Decision> = {};
      // The policy with and without the critical floor (notify.always), whatever the config says.
      const withFloor = { ...config, notify: { ...config.notify, always: ['kev', 'critical'] as ('kev' | 'critical')[] } };
      const withoutFloor = { ...config, notify: { ...config.notify, always: ['kev'] as ('kev' | 'critical')[] } };
      for (const s of STRATEGIES) {
        decisions[s] = decide(f.evidence, triage[s], withFloor);
        decisions[`${s}/no-floor`] = decide(f.evidence, triage[s], withoutFloor);
      }
      const key = groupKey(app, f.evidence.advisory.id);
      const group = groups.get(key) ?? {
        app,
        advisory: f.evidence.advisory.id,
        severity: f.evidence.advisory.severity,
        kev: f.evidence.advisory.kev,
        production: false,
        findings: [],
      };
      group.production ||= !f.evidence.devOnly;
      group.findings.push({ f, triage, decisions });
      groups.set(key, group);
    }
  }

  const notifies = (g: Group, variant: string) => g.findings.some((x) => x.decisions[variant]!.outcome === 'notify');
  const reachableOf = (g: Group, s: Strategy): YesNo =>
    REACH_ORDER.find((r) => g.findings.some((x) => x.triage[s].reachable === r)) ?? 'unknown';

  if (draftPath) {
    const candidates = [...groups.values()].filter((g) => VARIANTS.some((v) => notifies(g, v)));
    await writeFile(
      draftPath,
      `${JSON.stringify(
        candidates.map((g) => ({
          app: g.app,
          advisory: g.advisory,
          severity: g.severity,
          kev: g.kev,
          findings: g.findings.map((x) => ({ key: x.f.key, evidence: x.f.evidence, jev: x.f.triage.jev, claude: x.f.triage.claude, outcomes: Object.fromEntries(Object.entries(x.decisions).map(([k, d]) => [k, `${d.outcome}/${d.rule}`])) })),
        })),
        null,
        2,
      )}\n`,
    );
    process.stderr.write(`${candidates.length} advisory groups written to ${draftPath}\n`);
  }

  const confirmed = labels.items.filter((l) => l.confirmed).length;
  const lines = [
    `Labels: ${labels.items.length} advisories (${confirmed} confirmed by you, ${labels.items.length - confirmed} drafts)`,
    `Findings Claude was asked about: ${asked}; Jev was unsure of ${unsure} (${pct(unsure, asked)} of them)`,
    `Cost of this run: Jev $${(jevTokens * JEV_PRICE_PER_TOKEN).toFixed(3)}, Claude $${claudeCost.toFixed(2)} (cached answers cost nothing)`,
    '',
    ...(onlyLabeled ? ['With --only-labeled, only labeled findings got an answer from Claude, so the alert counts below are not what a scan sends; precision and recall are.', ''] : []),
    '| Strategy | Policy | Alerts (advisories) | Labeled | Precision (weighted) | Criticals worth an alert, alerted | Reachability right |',
    '| --- | --- | --- | --- | --- | --- | --- |',
  ];
  const wrong: Record<string, string[]> = {};
  for (const variant of VARIANTS) {
    const strategy = variant.split('/')[0] as Strategy;
    const alerted = [...groups.values()].filter((g) => notifies(g, variant));
    const labeled = alerted.filter((g) => byGroup.has(groupKey(g.app, g.advisory)));
    const weight = (g: Group) => byGroup.get(groupKey(g.app, g.advisory))!.weight ?? 1;
    const total = labeled.reduce((sum, g) => sum + weight(g), 0);
    const relevant = labeled.filter((g) => byGroup.get(groupKey(g.app, g.advisory))!.notify).reduce((sum, g) => sum + weight(g), 0);
    const criticals = [...groups.values()].filter((g) => {
      const l = byGroup.get(groupKey(g.app, g.advisory));
      // Critical or KEV-listed, and labeled worth an alert or reachable: the gate allows no miss here.
      return l !== undefined && (l.notify || l.reachable === 'yes') && (g.severity === 'CRITICAL' || g.kev) && g.production;
    });
    const caught = criticals.filter((g) => notifies(g, variant));
    const judged = [...groups.values()].filter((g) => {
      const l = byGroup.get(groupKey(g.app, g.advisory));
      return l && l.reachable !== 'unknown' && reachableOf(g, strategy) !== 'unknown';
    });
    const right = judged.filter((g) => byGroup.get(groupKey(g.app, g.advisory))!.reachable === reachableOf(g, strategy));
    lines.push(
      `| ${strategy} | ${variant.endsWith('no-floor') ? 'KEV floor (default)' : 'KEV and critical floor'} | ${alerted.length} | ${labeled.length} | ${pct(relevant, total)} | ${caught.length} of ${criticals.length} | ${right.length} of ${judged.length} |`,
    );
    wrong[variant] = [
      ...labeled.filter((g) => !byGroup.get(groupKey(g.app, g.advisory))!.notify).map((g) => `  irrelevant alert: ${g.app} ${g.advisory} (${g.findings.map((x) => x.decisions[variant]!.rule).filter((r, i, all) => all.indexOf(r) === i).join(', ')})`),
      ...criticals.filter((g) => !notifies(g, variant)).map((g) => `  missed critical: ${g.app} ${g.advisory}`),
    ];
  }
  lines.push('', 'Gate: precision at least 80%, and every critical worth an alert alerted.');
  for (const variant of ['jev-no+claude/no-floor', 'jev+claude']) {
    const name = variant === 'jev-no+claude/no-floor' ? 'The default (jev-no+claude, KEV floor)' : variant;
    lines.push('', `${name} got these wrong:`, ...(wrong[variant]!.length > 0 ? wrong[variant]! : ['  nothing']));
  }
  process.stdout.write(`${lines.join('\n')}\n`);
}

main().catch((error: unknown) => {
  process.stderr.write(`eval: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
