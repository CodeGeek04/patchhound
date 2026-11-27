import { appendFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { Evidence, Exposure } from './evidence/evidence.js';
import type { Decision, Outcome, Rule } from './policy.js';
import { RULE_TEXT } from './policy.js';
import type { Triage, YesNo } from './triage/triage.js';
import type { Severity } from './watch/advisory.js';

/** One finding's decision, logged when it is first made and again whenever it or its inputs change. */
export interface DecisionRecord {
  type: 'decision';
  at: string;
  scan: string;
  project: string;
  key: string;
  advisory: string;
  aliases: string[];
  package: string;
  version: string;
  severity: Severity;
  kev: boolean;
  evidence: {
    hash: string;
    direct: boolean;
    devOnly: boolean;
    via: string[];
    exposure: Exposure;
    files: number;
    runtimes: string[];
    sites: string[];
    calls: string[];
    fix: string | null;
  };
  triage: {
    source: Triage['source'];
    reachable: YesNo;
    reachableP: number | null;
    exposure: Exposure;
    dropIn: YesNo;
    urgency: number | null;
    reason: string;
    jev: { model: string; reachable: number; exposure: string; exposureConfidence: number; dropIn: number; urgency: number } | null;
    claude: { reachable: YesNo; confidence: number; exposure: string; dropIn: YesNo; urgency: number } | null;
  };
  decision: Decision;
  dryRun: boolean;
}

/** One message, sent or (in dry run, or when sending failed) not. */
export interface MessageRecord {
  type: 'message';
  at: string;
  scan: string;
  project: string;
  kind: 'alert' | 'digest';
  channel: string;
  keys: string[];
  sent: boolean;
  dryRun: boolean;
  error?: string;
}

/** A fix PR opened or updated (milestone 3). */
export interface FixRecord {
  type: 'fix';
  at: string;
  project: string;
  kind: 'fixes' | 'malware';
  branch: string;
  /** The commit the run started from. */
  base?: string;
  /** Null when this process published nothing: every change broke a check, or the work was handed off. */
  pr: string | null;
  /** The run produced commits (published here, or handed off to the publish job). */
  committed?: boolean;
  fixed: string[];
  remaining: string[];
  checks: { command: string; passed: boolean }[];
  agentCostUsd: number | null;
}

export type AuditRecord = DecisionRecord | MessageRecord | FixRecord;

export function decisionRecord(input: {
  at: string;
  scan: string;
  project: string;
  evidence: Evidence;
  triage: Triage;
  decision: Decision;
  dryRun: boolean;
}): DecisionRecord {
  const { evidence: e, triage: t } = input;
  return {
    type: 'decision',
    at: input.at,
    scan: input.scan,
    project: input.project,
    key: e.key,
    advisory: e.advisory.id,
    aliases: e.advisory.aliases,
    package: e.package,
    version: e.version,
    severity: e.advisory.severity,
    kev: e.advisory.kev,
    evidence: {
      hash: e.hash,
      direct: e.direct,
      devOnly: e.devOnly,
      via: e.via,
      exposure: e.exposure,
      files: e.usage.fileCount,
      runtimes: e.usage.runtimes,
      sites: e.usage.sites.map((s) => `${s.file}:${s.line} ${s.runtime} ${s.package}${s.typeOnly ? ' (types)' : ''}`),
      calls: e.usage.calls.map((c) => `${c.file}:${c.line} ${c.name}`),
      fix: e.fix.kind,
    },
    triage: {
      source: t.source,
      reachable: t.reachable,
      reachableP: t.reachableP,
      exposure: t.exposure,
      dropIn: t.dropIn,
      urgency: t.urgency,
      reason: t.reason,
      jev: t.jev
        ? {
            model: t.jev.model,
            reachable: t.jev.reachable,
            exposure: t.jev.exposure.choice,
            exposureConfidence: t.jev.exposure.confidence,
            dropIn: t.jev.dropIn,
            urgency: t.jev.urgency.score,
          }
        : null,
      claude: t.claude
        ? { reachable: t.claude.reachable, confidence: t.claude.confidence, exposure: t.claude.exposure, dropIn: t.claude.drop_in, urgency: t.claude.urgency }
        : null,
    },
    decision: input.decision,
    dryRun: input.dryRun,
  };
}

/** Appends records to the log, one JSON object per line. */
export async function appendAudit(path: string, records: readonly AuditRecord[]): Promise<void> {
  if (records.length === 0) return;
  await mkdir(dirname(path), { recursive: true });
  await appendFile(path, records.map((r) => `${JSON.stringify(r)}\n`).join(''));
}

/** Every record in the log; a missing log is empty, and an unreadable line is skipped. */
export async function readAudit(path: string): Promise<AuditRecord[]> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
  const records: AuditRecord[] = [];
  for (const line of text.split('\n')) {
    if (line.trim() === '') continue;
    try {
      records.push(JSON.parse(line) as AuditRecord);
    } catch {
      // A line cut short by a crash; the rest of the log still reads.
    }
  }
  return records;
}

/**
 * Fix records (FixRecord) have a log of their own beside the audit log. In the Action the fix job
 * keeps it in a cache of its own, and restores the scan job's cache over its state: the scan job must
 * never read what the fix job saved, which ran the project's code (see action.yml).
 */
export const FIX_LOG = 'fix-audit.jsonl';

/**
 * Every record in a state folder's audit log and fix log, oldest first. Fix records an older version
 * kept in the audit log still count.
 */
export async function readAllAudit(stateDir: string): Promise<AuditRecord[]> {
  const records = [...(await readAudit(join(stateDir, 'audit.jsonl'))), ...(await readAudit(join(stateDir, FIX_LOG)))];
  // ISO times sort as text; the sort is stable, so records of the same moment keep their order.
  return records.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0));
}

/** The records about one advisory (by its id or any alias, any case), in order. */
export function recordsFor(records: readonly AuditRecord[], id: string): AuditRecord[] {
  const wanted = id.toUpperCase();
  const decisions = records.filter(
    (r): r is DecisionRecord => r.type === 'decision' && [r.advisory, ...r.aliases].some((a) => a.toUpperCase() === wanted),
  );
  const keys = new Set(decisions.map((d) => d.key));
  return records.filter((r) =>
    r.type === 'decision' ? decisions.includes(r) : r.type === 'message' ? r.keys.some((key) => keys.has(key)) : [...r.fixed, ...r.remaining].some((key) => keys.has(key)),
  );
}

/** The decision trail for one advisory, for `patchhound explain`. */
export function formatExplain(records: readonly AuditRecord[], id: string): string {
  const trail = recordsFor(records, id);
  if (trail.length === 0) return `${id}: no decision about it in the audit log. Run patchhound check ${id} to look it up now.`;
  const first = trail.find((r): r is DecisionRecord => r.type === 'decision')!;
  const lines = [`${first.advisory}${first.aliases.length > 0 ? ` (${first.aliases.join(', ')})` : ''} in ${first.project}`];
  const byKey = new Map<string, AuditRecord[]>();
  for (const r of trail) {
    const keys = r.type === 'decision' ? [r.key] : r.type === 'message' ? r.keys : [...r.fixed, ...r.remaining];
    for (const key of r.type === 'decision' ? keys : keys.filter((k) => trail.some((d) => d.type === 'decision' && d.key === k))) {
      byKey.set(key, [...(byKey.get(key) ?? []), r]);
    }
  }
  for (const [key, list] of byKey) {
    lines.push('', key.split('|')[1] ?? key);
    for (const r of list) {
      const when = r.at.slice(0, 16).replace('T', ' ');
      if (r.type === 'message') {
        lines.push(`  ${when} ${r.kind} to ${r.channel}: ${r.sent ? 'sent' : r.dryRun ? 'printed (dry run)' : `not sent${r.error ? ` (${r.error})` : ''}`}`);
        continue;
      }
      if (r.type === 'fix') {
        lines.push(r.pr ? `  ${when} fix PR ${r.pr}: ${r.fixed.includes(key) ? 'fixed there' : 'not fixed yet'}` : `  ${when} fix tried; every change broke a check, so no PR`);
        continue;
      }
      const e = r.evidence;
      const t = r.triage;
      lines.push(
        `  ${when} ${r.decision.outcome} (${r.decision.rule}): ${RULE_TEXT[r.decision.rule as Rule]}${r.dryRun ? '; dry run' : ''}`,
        `    evidence ${e.hash}: ${e.devOnly ? 'dev-only' : 'production'}, ${e.direct ? 'direct' : `via ${e.via.join(', ') || 'nothing declared'}`}, imported by ${e.files} ${e.files === 1 ? 'file' : 'files'}${e.runtimes.length > 0 ? ` (${e.runtimes.join(', ')})` : ''}, fix: ${e.fix ?? 'none'}`,
        ...e.sites.slice(0, 5).map((s) => `      ${s}`),
        `    triage (${t.source}): reachable ${t.reachable}${t.reachableP === null ? '' : ` (${t.reachableP.toFixed(2)})`}, ${t.exposure}, drop-in ${t.dropIn}${t.urgency === null ? '' : `, urgency ${t.urgency} of 5`}`,
        `      ${t.reason}`,
        ...(t.jev
          ? [`    jev ${t.jev.model}: reachable ${t.jev.reachable.toFixed(2)}, ${t.jev.exposure} (${t.jev.exposureConfidence.toFixed(2)}), drop-in ${t.jev.dropIn.toFixed(2)}`]
          : []),
        ...(r.decision.wouldDo.length > 0
          ? [`    would do: ${r.decision.wouldDo.map((w) => `${w.tier} (${w.enabled ? 'on' : 'off'})`).join(', ')}`]
          : []),
      );
    }
  }
  return lines.join('\n');
}

/** What a finding looked like when an alert about it went out (or was printed). */
export interface AlertFacts {
  at: string;
  reachable: YesNo;
  severity: Severity;
  kev: boolean;
}

/** What was last decided and sent per finding, so a notification goes out once and again only when worse. */
export interface DecisionEntry {
  outcome: Outcome;
  rule: Rule;
  evidenceHash: string;
  reachable: YesNo;
  severity: Severity;
  kev: boolean;
  decidedAt: string;
  /** The last scan that found it. A finding that drops out is remembered for a while, so it does not alert again as new. */
  seenAt: string;
  /** The last alert a channel took. */
  notified?: AlertFacts;
  /** The last alert only printed (dry run, or no channel): it does not count as sent. */
  previewed?: AlertFacts;
  /** When a channel took a digest that listed it. */
  digestedAt?: string;
}

export interface DecisionState {
  version: 1;
  /** The last digest a channel took. */
  lastDigestAt: string | null;
  /** The last digest only printed, so dry run prints one a week too. */
  lastDigestPreviewAt?: string | null;
  findings: Record<string, DecisionEntry>;
}

export async function loadDecisions(path: string): Promise<DecisionState> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { version: 1, lastDigestAt: null, findings: {} };
    throw error;
  }
  const data = JSON.parse(text) as DecisionState;
  if (data.version !== 1 || typeof data.findings !== 'object') throw new Error(`${path}: not a decisions file this version reads`);
  return data;
}

export async function saveDecisions(path: string, state: DecisionState): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temp = `${path}.${process.pid}.tmp`;
  await writeFile(temp, `${JSON.stringify(state, null, 2)}\n`);
  await rename(temp, path);
}

const REACH_RANK: Record<YesNo, number> = { no: 0, unknown: 1, yes: 2 };
const SEVERITY_RANK: Record<Severity, number> = { UNKNOWN: 0, LOW: 1, MODERATE: 2, HIGH: 3, CRITICAL: 4 };

/** Worse than when last sent: newly KEV-listed, more reachable, or more severe. */
export function isWorse(before: AlertFacts, now: { reachable: YesNo; severity: Severity; kev: boolean }): boolean {
  return (now.kev && !before.kev) || REACH_RANK[now.reachable] > REACH_RANK[before.reachable] || SEVERITY_RANK[now.severity] > SEVERITY_RANK[before.severity];
}
