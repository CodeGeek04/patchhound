import { createHash } from 'node:crypto';
import type { Evidence, Exposure } from '../evidence/evidence.js';
import type { DiskCache } from '../util/cache.js';
import { mapLimit } from '../util/pool.js';
import type { Snippet } from '../evidence/snippets.js';
import type { ClaudeItem, ClaudeTransport, ClaudeVerdict } from './claude.js';
import { askClaude, SYSTEM_PROMPT } from './claude.js';
import type { JevAnswers, JevClient } from './jev.js';
import { JEV_QUESTIONS, noulConfidence } from './jev.js';

/** The prompt and the questions are part of every cache key: a change to either asks again. */
const CLAUDE_PROMPT_HASH = createHash('sha256').update(SYSTEM_PROMPT).digest('hex').slice(0, 12);
const JEV_QUESTIONS_HASH = createHash('sha256').update(JSON.stringify(JEV_QUESTIONS)).digest('hex').slice(0, 12);

export type YesNo = 'yes' | 'no' | 'unknown';

/**
 * Which findings whose answer counts go to Claude: `unsure` those Jev is unsure of; `unless-unreachable`
 * all but those Jev is sure are unreachable (a "yes" alerts, so Claude checks it); `always` all of them.
 */
export type Escalate = 'unsure' | 'unless-unreachable' | 'always';

/** The answer the policy reads for one finding. */
export interface Triage {
  reachable: YesNo;
  /** Probability that production code reaches the vulnerable part, when a model gave one. */
  reachableP: number | null;
  exposure: Exposure;
  dropIn: YesNo;
  /** 1 (no realistic path) to 5 (exploited, or trivial and severe), when a model gave one. */
  urgency: number | null;
  reason: string;
  /** Who decided: plain rules (dev-only, malware, or no model), Jev, or Claude. */
  source: 'rules' | 'jev' | 'claude';
  jev: JevAnswers | null;
  claude: ClaudeVerdict | null;
}

export interface TriageItem {
  evidence: Evidence;
  /** The advisory's full text and links, for the models. */
  details: string;
  references: string[];
  /** True when the answer can change what happens (see needsJudgment); only then is Claude asked. */
  decisive: boolean;
}

export interface TriageOptions {
  jev: JevClient | null;
  /** Names the Jev model in cache keys. */
  jevModel: string;
  claude: ClaudeTransport | null;
  /** Names the Claude model and effort in cache keys. */
  claudeModel: string;
  /** Jev answers with a confidence below this go to Claude. */
  threshold: number;
  /** Which of the findings whose answer counts Claude sees (see Escalate). Default `unsure`. */
  escalate?: Escalate;
  /** The code around each import and call, for Claude. */
  snippets: (evidence: Evidence) => Promise<Snippet[]>;
  /** The project's configuration files, shared by every finding Claude sees (see projectContext). */
  project?: string;
  /**
   * Names the project in cache keys (its folder). The evidence hash leaves out line numbers and the code
   * around a use, so two projects with the same file names could otherwise share an answer.
   */
  scope?: string;
  cache?: DiskCache;
}

export interface TriageStats {
  findings: number;
  rules: number;
  jev: number;
  jevCached: number;
  jevTokens: number;
  /** Findings Jev was unsure of whose answer could change what happens. */
  escalated: number;
  claude: number;
  claudeCached: number;
  claudeRequests: number;
  claudeCostUsd: number | null;
  claudeModels: string[];
}

export interface TriageRun {
  results: Map<string, Triage>;
  stats: TriageStats;
  warnings: string[];
}

/**
 * Triage for each finding. Dev-only and malicious findings are settled by plain rules. The rest go to
 * Jev; when Jev is unsure (or there is no Jev) and the answer can change what happens, to Claude, all
 * together. Answers are cached by the evidence's hash, so a finding is asked about once until its
 * evidence or the advisory changes.
 */
export async function triage(items: readonly TriageItem[], options: TriageOptions): Promise<TriageRun> {
  const results = new Map<string, Triage>();
  const warnings: string[] = [];
  const stats: TriageStats = {
    findings: items.length,
    rules: 0,
    jev: 0,
    jevCached: 0,
    jevTokens: 0,
    escalated: 0,
    claude: 0,
    claudeCached: 0,
    claudeRequests: 0,
    claudeCostUsd: null,
    claudeModels: [],
  };
  const judged = items.filter((item) => {
    const settled = plainAnswer(item.evidence);
    if (settled) results.set(item.evidence.key, settled);
    return !settled;
  });

  // Jev first, eight at a time.
  const jevAnswers = new Map<string, JevAnswers>();
  const jevErrors: string[] = [];
  if (options.jev) {
    const jev = options.jev;
    await mapLimit(judged, 8, async (item) => {
      const cacheKey = `triage/jev/${digest(options.scope ?? '', item.evidence.key, item.evidence.hash, options.jevModel, JEV_QUESTIONS_HASH)}`;
      const cached = await options.cache?.get<JevAnswers>(cacheKey);
      if (cached) {
        stats.jevCached += 1;
        jevAnswers.set(item.evidence.key, cached);
        return;
      }
      try {
        const answer = await jev.ask(item.evidence, item.details);
        stats.jev += 1;
        stats.jevTokens += answer.inputTokens;
        jevAnswers.set(item.evidence.key, answer);
        await options.cache?.set(cacheKey, answer);
      } catch (error) {
        jevErrors.push(error instanceof Error ? error.message : String(error));
      }
    });
    if (jevErrors.length > 0) warnings.push(`Jev failed for ${jevErrors.length} ${jevErrors.length === 1 ? 'finding' : 'findings'}: ${jevErrors[0]}`);
  }

  // Claude for the unsure ones whose answer counts, all in one run.
  const toClaude: TriageItem[] = [];
  for (const item of judged) {
    const jev = jevAnswers.get(item.evidence.key) ?? null;
    const escalate = options.escalate ?? 'unsure';
    const trusted =
      jev !== null &&
      isSure(jev, options.threshold) &&
      (escalate === 'unsure' || (escalate === 'unless-unreachable' && jev.reachable <= 1 - options.threshold));
    const sure = jev !== null && (trusted || !item.decisive || !options.claude);
    if (sure) {
      results.set(item.evidence.key, fromJev(item.evidence, jev, options.threshold));
      continue;
    }
    if (item.decisive && options.claude) toClaude.push(item);
    else results.set(item.evidence.key, jev ? fromJev(item.evidence, jev, options.threshold) : fromRules(item.evidence));
  }
  stats.escalated = toClaude.length;

  // The key holds the code Claude reads: a change around a use (`_.template(HEADER)` to `_.template(req.body)`)
  // keeps the evidence hash, but must be judged again.
  const claudeKey = (item: TriageItem, snippets: readonly Snippet[]) =>
    `triage/claude/${digest(
      options.scope ?? '',
      item.evidence.key,
      item.evidence.hash,
      options.claudeModel,
      CLAUDE_PROMPT_HASH,
      JSON.stringify(jevAnswers.get(item.evidence.key) ?? null),
      options.project ?? '',
      JSON.stringify(snippets),
    )}`;
  const ask: ClaudeItem[] = [];
  const keys = new Map<string, string>();
  for (const item of toClaude) {
    const snippets = await options.snippets(item.evidence);
    const key = claudeKey(item, snippets);
    keys.set(item.evidence.key, key);
    const cached = await options.cache?.get<ClaudeVerdict>(key);
    const jev = jevAnswers.get(item.evidence.key) ?? null;
    if (cached) {
      stats.claudeCached += 1;
      results.set(item.evidence.key, fromClaude(item.evidence, cached, jev));
    } else {
      ask.push({ evidence: item.evidence, details: item.details, references: item.references, snippets, jev });
    }
  }
  if (ask.length > 0 && options.claude) {
    const run = await askClaude(ask, options.claude, options.project ?? '');
    stats.claudeRequests = run.requests;
    stats.claudeCostUsd = run.costUsd;
    stats.claudeModels = run.models;
    warnings.push(...run.errors);
    if (run.missing.length > 0) {
      const n = run.missing.length;
      warnings.push(`Claude gave no answer for ${n} ${n === 1 ? 'finding' : 'findings'}; Jev's answer, or plain rules, stands for ${n === 1 ? 'it' : 'them'}.`);
    }
    for (const item of ask) {
      const key = item.evidence.key;
      const verdict = run.verdicts.get(key);
      if (verdict) {
        stats.claude += 1;
        results.set(key, fromClaude(item.evidence, verdict, item.jev));
        await options.cache?.set(keys.get(key)!, verdict);
      } else {
        results.set(key, item.jev ? fromJev(item.evidence, item.jev, options.threshold) : fromRules(item.evidence));
      }
    }
  }
  stats.rules = [...results.values()].filter((t) => t.source === 'rules').length;
  return { results, stats, warnings };
}

/**
 * Whether triage can change what happens to a finding: it runs in production, and it notifies only if
 * reachable (at or above the threshold), or it notifies anyway but tiers 1 to 3 depend on reachability.
 */
export function needsJudgment(evidence: Evidence, atOrAboveThreshold: boolean): boolean {
  if (evidence.devOnly || evidence.advisory.kind === 'malicious') return false;
  return atOrAboveThreshold || evidence.advisory.kev || evidence.advisory.severity === 'CRITICAL';
}

/** Dev-only and malicious findings need no model: the lockfile and the advisory settle them. */
function plainAnswer(e: Evidence): Triage | null {
  if (e.advisory.kind === 'malicious') {
    return base(e, { reachable: 'yes', reason: 'A malicious package runs its code when installed, whatever the app imports.' });
  }
  if (e.devOnly) {
    return base(e, { reachable: 'no', reason: 'Dev-only: the lockfile shows no production dependency path to it.' });
  }
  return null;
}

function base(e: Evidence, answer: { reachable: YesNo; reason: string }): Triage {
  return {
    reachable: answer.reachable,
    reachableP: null,
    exposure: e.exposure,
    dropIn: 'unknown',
    urgency: null,
    reason: answer.reason,
    source: 'rules',
    jev: null,
    claude: null,
  };
}

/** Without a model, only what plain code can tell: imports only from tests, scripts and build config. */
export function fromRules(e: Evidence): Triage {
  const nonProduction = !e.usage.truncated && e.usage.siteCount > 0 && e.usage.runtimes.every((r) => r === 'test' || r === 'script' || r === 'build');
  if (e.direct && nonProduction) {
    return {
      ...base(e, { reachable: 'no', reason: `Only ${e.usage.runtimes.join(', ')} files import it.` }),
      exposure: 'build/dev-only',
    };
  }
  return base(e, { reachable: 'unknown', reason: 'No model was available to judge reachability.' });
}

/** Both answers the policy reads are at least `threshold` confident. */
export function isSure(jev: JevAnswers, threshold: number): boolean {
  return noulConfidence(jev.reachable) >= threshold && jev.exposure.confidence >= threshold;
}

function yesNo(p: number, threshold: number): YesNo {
  return p >= threshold ? 'yes' : p <= 1 - threshold ? 'no' : 'unknown';
}

export function fromJev(e: Evidence, jev: JevAnswers, threshold: number): Triage {
  const exposure = (['internet-facing', 'internal', 'build/dev-only'] as const).find((x) => x === jev.exposure.choice) ?? e.exposure;
  const reachable = yesNo(jev.reachable, threshold);
  return {
    reachable,
    reachableP: jev.reachable,
    exposure: jev.exposure.confidence >= threshold ? exposure : e.exposure,
    dropIn: yesNo(jev.dropIn, threshold),
    urgency: Math.round((jev.urgency.score + 1) * 10) / 10,
    reason: `Jev: ${(jev.reachable * 100).toFixed(0)}% likely reachable, ${exposure} (${(jev.exposure.confidence * 100).toFixed(0)}% confident).`,
    source: 'jev',
    jev,
    claude: null,
  };
}

/** Below this, Claude thinks its own yes or no is more likely wrong than right, so it counts as unknown. */
const CLAUDE_MIN_CONFIDENCE = 0.5;

export function fromClaude(e: Evidence, verdict: ClaudeVerdict, jev: JevAnswers | null): Triage {
  const p = verdict.reachable === 'yes' ? verdict.confidence : verdict.reachable === 'no' ? 1 - verdict.confidence : null;
  // A "no" Claude gives 30% confidence is a "probably yes": the policy must not file it as unreachable.
  const reachable = verdict.reachable !== 'unknown' && verdict.confidence < CLAUDE_MIN_CONFIDENCE ? 'unknown' : verdict.reachable;
  return {
    reachable,
    reachableP: p,
    exposure: e.devOnly ? 'build/dev-only' : verdict.exposure,
    dropIn: verdict.drop_in,
    urgency: verdict.urgency,
    reason: verdict.reason,
    source: 'claude',
    jev,
    claude: verdict,
  };
}

function digest(...parts: string[]): string {
  return createHash('sha256').update(parts.join('\n')).digest('hex').slice(0, 32);
}
