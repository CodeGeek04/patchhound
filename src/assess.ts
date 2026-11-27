import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { access, readFile } from 'node:fs/promises';
import { delimiter, join } from 'node:path';
import type { AuditRecord, DecisionEntry, DecisionState } from './audit.js';
import { appendAudit, decisionRecord, isWorse, loadDecisions, saveDecisions } from './audit.js';
import type { Config } from './config.js';
import type { Evidence } from './evidence/evidence.js';
import { buildEvidence, mentionedNames } from './evidence/evidence.js';
import { projectContext, snippetsFor } from './evidence/snippets.js';
import { indexSource } from './evidence/source.js';
import type { Channel } from './notify/channels.js';
import { openChannels } from './notify/channels.js';
import type { Message, MessageItem } from './notify/message.js';
import { alertMessage, digestMessage } from './notify/message.js';
import type { Decision } from './policy.js';
import { atOrAbove, decide } from './policy.js';
import type { ScanFinding, ScanResult } from './scan.js';
import type { ClaudeTransport } from './triage/claude.js';
import { ApiTransport, ClaudeCodeTransport } from './triage/claude.js';
import { JevClient } from './triage/jev.js';
import type { Escalate, Triage, TriageStats } from './triage/triage.js';
import { needsJudgment, triage } from './triage/triage.js';
import type { DiskCache } from './util/cache.js';
import type { Fetch, RetryOptions } from './util/http.js';
import { mapLimit } from './util/pool.js';
import type { OsvClient, OsvVuln } from './watch/osv.js';

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;
/** How long a finding that dropped out of the scans is remembered, so it does not alert again as new. */
export const RETAIN_MS = 30 * 24 * 60 * 60 * 1000;

export interface AssessOptions {
  dir: string;
  result: ScanResult;
  config: Config;
  /** Reads the advisories' full text (cached like the scan's). */
  osv: OsvClient;
  /** Where API keys and channel secrets come from. Default process.env. */
  env?: Record<string, string | undefined>;
  fetch?: Fetch;
  retry?: RetryOptions;
  cache?: DiskCache;
  /** Save decisions and the audit log under <dir>/.bulwark, and send messages unless the config's dry_run. False for `scan --dry-run`. */
  write: boolean;
  now?: Date;
  /** Names the project in the triage cache (default: `dir`). The fix step works in a temporary worktree of the same repo. */
  scope?: string;
  /** Overrides the config's triage.escalate (the eval sends everything to Claude to compare). */
  escalate?: Escalate;
  /** Which findings' answers count (default: needsJudgment). The eval narrows it to labeled findings. */
  decisive?: (evidence: Evidence) => boolean;
  /** Tests replace the clients; null turns one off. */
  jev?: JevClient | null;
  claude?: ClaudeTransport | null;
  channels?: Channel[];
}

export interface AssessedFinding {
  key: string;
  evidence: Evidence;
  triage: Triage;
  decision: Decision;
  /** Why it goes in this scan's alert: first time, or worse than when last sent. Null when it does not. */
  alert: 'new' | 'worse' | null;
}

export interface Assessment {
  scan: string;
  findings: AssessedFinding[];
  messages: { message: Message; channel: string; sent: boolean; error?: string }[];
  /** Which models were used: the Jev model, and how Claude was reached. */
  models: { jev: string | null; claude: string | null };
  stats: TriageStats;
  dryRun: boolean;
  warnings: string[];
}

/**
 * Milestone 2's pipeline after a scan: evidence from the app's code, triage (Jev, then Claude for what
 * Jev is unsure of), the policy's decision, one alert for what is new or worse, the weekly digest, and
 * the audit log.
 */
export async function assess(options: AssessOptions): Promise<Assessment> {
  const { dir, result, config } = options;
  const env = options.env ?? process.env;
  const now = options.now ?? new Date();
  const scanId = randomUUID().slice(0, 8);
  const warnings: string[] = [];
  const findings = result.findings;

  // The advisories' own text: for the names they mention, and for the models.
  const texts = new Map<string, { details: string; references: string[] }>();
  await mapLimit(findings, 8, async (f) => {
    // The scan has just read (and cached) these records, so the cache usually answers.
    const records = await Promise.all(
      f.records.map(async (id) => (await options.cache?.get<OsvVuln>(`osv/${id}`)) ?? options.osv.getVuln(id).catch(() => null)),
    );
    const present = records.filter((r) => r !== null);
    texts.set(f.key, {
      details: [...new Set(present.map((r) => r.details ?? '').filter(Boolean))].join('\n\n'),
      references: [...new Set(present.flatMap((r) => (r.references ?? []).map((ref) => ref.url)))],
    });
  });
  const mentioned = new Map(findings.map((f) => [f.key, mentionedNames(`${f.advisory.summary}\n${texts.get(f.key)?.details ?? ''}`, f.package)]));
  const wanted = new Map<string, Set<string>>();
  for (const f of findings) for (const name of mentioned.get(f.key)!) wanted.set(f.package, new Set([...(wanted.get(f.package) ?? []), name]));

  // The state first: a bad decisions file fails before any model is asked.
  const statePath = join(dir, '.bulwark', 'decisions.json');
  const previous = await loadDecisions(statePath);

  const next = await usesNext(dir, result.workspaces);
  const source = await indexSource(dir, { next, wanted });
  if (source.truncated) warnings.push('Evidence: the project has over 20,000 source files; only the first were read.');
  const appRouter = next && source.files.some((file) => /(^|\/)app\/(.*\/)?(page|layout|route)\.[jt]sx?$/.test(file.path));
  const evidence = findings.map((f) =>
    buildEvidence(f, {
      source,
      exposure: config.exposure,
      framework: { next, appRouter },
      mentioned: mentioned.get(f.key)!,
      ...(previous.findings[f.key] ? { lastKnownKev: previous.findings[f.key]!.kev } : {}),
    }),
  );

  // Triage.
  const jev = options.jev !== undefined ? options.jev : env.TYPESAFE_API_KEY ? new JevClient({ apiKey: env.TYPESAFE_API_KEY, model: config.triage.jev.model, fetch: options.fetch, retry: options.retry }) : null;
  const claude = options.claude !== undefined ? options.claude : await openClaude(config, env, warnings);
  const run = await triage(
    evidence.map((e) => ({
      evidence: e,
      details: texts.get(e.key)?.details ?? '',
      references: texts.get(e.key)?.references ?? [],
      decisive: options.decisive ? options.decisive(e) : needsJudgment(e, atOrAbove(e.advisory.severity, config.notify.threshold)),
    })),
    {
      jev,
      jevModel: config.triage.jev.model,
      claude,
      claudeModel: `${claude?.name ?? 'none'}|${config.triage.llm.model}|${config.triage.llm.effort}`,
      threshold: config.triage.jev.threshold,
      escalate: options.escalate ?? config.triage.escalate,
      snippets: (e) => snippetsFor(dir, e),
      project: await projectContext(dir, result.workspaces),
      scope: options.scope ?? dir,
      ...(options.cache ? { cache: options.cache } : {}),
    },
  );
  warnings.push(...run.warnings);

  // Decisions, compared with what was decided and sent before.
  const dryRun = config.dryRun || !options.write;
  const opened = options.channels ? { channels: options.channels, warnings: [] } : openChannels(config.notify.channels, env, { fetch: options.fetch, retry: options.retry });
  if (!dryRun) warnings.push(...opened.warnings);
  // Delivering: a channel will take the messages. Otherwise they are only printed, which counts as a preview, not as sent.
  const delivering = !dryRun && opened.channels.length > 0;
  const at = now.toISOString();
  const next_: DecisionState = {
    version: 1,
    lastDigestAt: previous.lastDigestAt,
    lastDigestPreviewAt: previous.lastDigestPreviewAt ?? null,
    findings: {},
  };
  // Findings this scan did not see keep their record for a while (a branch switched back, a feed down for a day).
  for (const [key, entry] of Object.entries(previous.findings)) {
    if (now.getTime() - Date.parse(entry.seenAt ?? entry.decidedAt) < RETAIN_MS) next_.findings[key] = entry;
  }
  const audit: AuditRecord[] = [];
  const assessed: AssessedFinding[] = evidence.map((e, i) => {
    const t = run.results.get(e.key)!;
    const decision = decide(e, t, config);
    const before = previous.findings[e.key];
    const facts = { reachable: t.reachable, severity: e.advisory.severity, kev: e.advisory.kev };
    let alert: AssessedFinding['alert'] = null;
    if (decision.outcome === 'notify') {
      // A preview stands in for the last alert only while nothing has been sent; once sent, sending decides.
      const last = delivering ? before?.notified : (before?.notified ?? before?.previewed);
      alert = !last ? 'new' : isWorse(last, facts) ? 'worse' : null;
    }
    const entry: DecisionEntry = {
      outcome: decision.outcome,
      rule: decision.rule,
      evidenceHash: e.hash,
      ...facts,
      decidedAt: before && sameDecision(before, decision, e, t) ? before.decidedAt : at,
      seenAt: at,
      ...(before?.notified ? { notified: before.notified } : {}),
      ...(before?.previewed ? { previewed: before.previewed } : {}),
      ...(before?.digestedAt ? { digestedAt: before.digestedAt } : {}),
    };
    next_.findings[e.key] = entry;
    if (!before || !sameDecision(before, decision, e, t)) {
      audit.push(decisionRecord({ at, scan: scanId, project: result.project, evidence: e, triage: t, decision, dryRun }));
    }
    return { key: findings[i]!.key, evidence: e, triage: t, decision, alert };
  });

  // Messages: one alert for what is new or worse, and the digest once a week.
  const outgoing: Message[] = [];
  const alerts = assessed.filter((a) => a.alert !== null);
  if (alerts.length > 0) outgoing.push(alertMessage(result.project, alerts.map((a) => item(a, findings))));
  const lastDigest = delivering ? previous.lastDigestAt : (previous.lastDigestPreviewAt ?? previous.lastDigestAt);
  const digestDue = config.notify.digest === 'weekly' && (lastDigest == null || now.getTime() - Date.parse(lastDigest) >= WEEK_MS);
  const pending = assessed.filter((a) => a.decision.outcome === 'digest' && !next_.findings[a.key]!.digestedAt);
  if (digestDue && pending.length > 0) {
    outgoing.push(digestMessage(result.project, pending.map((a) => ({ ...item(a, findings), change: 'digest' as const }))));
  }

  const messages: Assessment['messages'] = [];
  for (const message of outgoing) {
    if (!delivering) {
      messages.push({ message, channel: 'terminal', sent: false });
      continue;
    }
    for (const channel of opened.channels) {
      try {
        await channel.send(message);
        messages.push({ message, channel: channel.name, sent: true });
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        messages.push({ message, channel: channel.name, sent: false, error: reason });
        warnings.push(`Could not send the ${message.kind} to ${channel.name}: ${reason}`);
      }
    }
  }
  for (const m of messages) {
    audit.push({
      type: 'message',
      at,
      scan: scanId,
      project: result.project,
      kind: m.message.kind,
      channel: m.channel,
      keys: m.message.items.map((i) => i.key),
      sent: m.sent,
      dryRun,
      ...(m.error ? { error: m.error } : {}),
    });
  }
  // A message counts as sent when at least one channel took it; when none did, it is tried again next scan.
  for (const message of outgoing) {
    const took = messages.some((m) => m.message === message && m.sent);
    const printed = !delivering;
    if (!took && !printed) continue;
    if (message.kind === 'alert') {
      for (const i of message.items) {
        const entry = next_.findings[i.key]!;
        const shown = { at, reachable: entry.reachable, severity: entry.severity, kev: entry.kev };
        if (took) entry.notified = shown;
        else entry.previewed = shown;
      }
    } else if (took) {
      next_.lastDigestAt = at;
      for (const i of message.items) next_.findings[i.key]!.digestedAt = at;
    } else {
      next_.lastDigestPreviewAt = at;
    }
  }
  if (options.write) {
    await saveDecisions(statePath, next_);
    await appendAudit(join(dir, '.bulwark', 'audit.jsonl'), audit);
  }
  return {
    scan: scanId,
    findings: assessed,
    messages,
    models: { jev: jev ? config.triage.jev.model : null, claude: claude ? `${config.triage.llm.model} via ${claude.name}` : null },
    stats: run.stats,
    dryRun,
    warnings,
  };
}

function sameDecision(before: DecisionEntry, decision: Decision, e: Evidence, t: Triage): boolean {
  return (
    before.outcome === decision.outcome &&
    before.rule === decision.rule &&
    before.evidenceHash === e.hash &&
    before.reachable === t.reachable &&
    before.severity === e.advisory.severity &&
    before.kev === e.advisory.kev
  );
}

function item(a: AssessedFinding, findings: readonly ScanFinding[]): MessageItem {
  const f = findings.find((x) => x.key === a.key)!;
  const judge = a.triage.source === 'rules' ? '' : `${a.triage.source === 'claude' ? 'Claude' : 'Jev'}: `;
  return {
    key: a.key,
    package: f.package,
    version: f.version,
    advisory: f.advisory.id,
    severity: f.advisory.severity,
    summary: f.advisory.summary,
    kev: a.evidence.advisory.kev,
    rule: a.decision.rule,
    reachable: a.triage.reachable,
    reason: a.triage.reason.startsWith('Jev:') ? a.triage.reason : `${judge}${a.triage.reason}`,
    fix: a.evidence.fix.kind,
    change: a.alert ?? 'new',
  };
}

/** Claude, the way the config says to reach it. A transport that cannot work is a warning, and triage goes on without it. */
export async function openClaude(config: Config, env: Record<string, string | undefined>, warnings: string[]): Promise<ClaudeTransport | null> {
  const { via, model, effort } = config.triage.llm;
  if (via === 'off') return null;
  const apiKey = env.ANTHROPIC_API_KEY;
  if (via === 'api' || (via === 'auto' && apiKey)) {
    if (apiKey) return new ApiTransport({ apiKey, model, effort });
    warnings.push('triage.llm.via is api, but ANTHROPIC_API_KEY is not set: Claude was not asked.');
    return null;
  }
  if (await onPath('claude', env)) return new ClaudeCodeTransport({ model, effort });
  if (via === 'claude-code') warnings.push('triage.llm.via is claude-code, but the claude command was not found: Claude was not asked.');
  return null;
}

/** True when `command` is an executable file in one of PATH's folders. */
export async function onPath(command: string, env: Record<string, string | undefined>): Promise<boolean> {
  for (const folder of (env.PATH ?? '').split(delimiter).filter(Boolean)) {
    try {
      await access(join(folder, command), constants.X_OK);
      return true;
    } catch {
      // Not in this folder.
    }
  }
  return false;
}

/** True when the project or a workspace depends on next. */
async function usesNext(dir: string, workspaces: readonly string[]): Promise<boolean> {
  for (const folder of ['.', ...workspaces]) {
    try {
      const manifest = JSON.parse(await readFile(join(dir, folder, 'package.json'), 'utf8')) as Record<string, Record<string, string> | undefined>;
      if (['dependencies', 'devDependencies', 'peerDependencies'].some((section) => manifest[section]?.next !== undefined)) return true;
    } catch {
      // No package.json here, or one that does not read: the scan already reported it.
    }
  }
  return false;
}
