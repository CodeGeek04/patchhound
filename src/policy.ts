import type { Config, Threshold } from './config.js';
import type { Evidence } from './evidence/evidence.js';
import type { Triage } from './triage/triage.js';
import type { Severity } from './watch/advisory.js';

export type Outcome = 'notify' | 'digest';
export type Tier = 'fix-pr' | 'auto-merge' | 'containment';

export interface Decision {
  /** Tier 0: tell someone now, or put it in the weekly digest. */
  outcome: Outcome;
  /** The rule that decided, a stable name for the audit log and `explain`. */
  rule: Rule;
  /** The tiers above 0 whose conditions hold. Milestone 2 only logs them; `enabled` says which the config turns on. */
  wouldDo: { tier: Tier; enabled: boolean }[];
}

export type Rule =
  | 'malware'
  | 'kev'
  | 'critical'
  | 'dev-only'
  | 'below-threshold'
  | 'not-reachable'
  | 'build-only-use'
  | 'reachable'
  | 'reachability-unknown';

const RANK: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MODERATE: 2, LOW: 1, UNKNOWN: 2 };
const THRESHOLD_RANK: Record<Threshold, number> = { critical: 4, high: 3, moderate: 2, low: 1 };

/** True when the severity notifies at once under the threshold. An advisory with no severity counts as moderate. */
export function atOrAbove(severity: Severity, threshold: Threshold): boolean {
  return RANK[severity] >= THRESHOLD_RANK[threshold];
}

/** Rule explanations, for reports and `explain`. */
export const RULE_TEXT: Record<Rule, string> = {
  malware: 'a malicious package always notifies',
  kev: 'KEV-listed (known to be exploited): always notifies, whatever triage says',
  critical: 'critical (CVSS 9 or more) in production code: always notifies, whatever triage says',
  'dev-only': 'dev-only in the lockfile: weekly digest',
  'below-threshold': "below the repo's severity threshold: weekly digest",
  'not-reachable': 'triage found the vulnerable code unreachable: weekly digest',
  'build-only-use': 'triage found it used only in builds, tests or scripts: weekly digest',
  reachable: 'at or above the threshold and reachable: notifies',
  'reachability-unknown': 'at or above the threshold, reachability unknown: notifies to be safe',
};

/**
 * The deterministic rules that turn evidence and triage into an action (spec, "Action tiers"). Models
 * never choose: a "not reachable" answer cannot silence a KEV-listed advisory (`notify.always`), nor a
 * critical one in production code when the config adds `critical`. Dev-only status comes from the
 * lockfile, not a model, so it can.
 */
export function decide(e: Evidence, t: Triage, config: Config): Decision {
  const rule = pickRule(e, t, config);
  const outcome: Outcome = ['malware', 'kev', 'critical', 'reachable', 'reachability-unknown'].includes(rule) ? 'notify' : 'digest';
  return { outcome, rule, wouldDo: config.paused ? [] : tiers(e, t, config) };
}

function pickRule(e: Evidence, t: Triage, config: Config): Rule {
  if (e.advisory.kind === 'malicious') return 'malware';
  if (e.advisory.kev && config.notify.always.includes('kev')) return 'kev';
  if (e.devOnly) return 'dev-only';
  if (e.advisory.severity === 'CRITICAL' && config.notify.always.includes('critical')) return 'critical';
  if (!atOrAbove(e.advisory.severity, config.notify.threshold)) return 'below-threshold';
  if (t.reachable === 'no') return 'not-reachable';
  if (t.exposure === 'build/dev-only') return 'build-only-use';
  return t.reachable === 'yes' ? 'reachable' : 'reachability-unknown';
}

const FIXABLE = new Set(['refresh', 'bump', 'override', 'remove']);

function tiers(e: Evidence, t: Triage, config: Config): Decision['wouldDo'] {
  const out: Decision['wouldDo'] = [];
  const fixable = e.fix.kind !== null && FIXABLE.has(e.fix.kind);
  const severe = e.advisory.kev || e.advisory.severity === 'CRITICAL';
  if (t.reachable !== 'no' && fixable) {
    out.push({ tier: 'fix-pr', enabled: config.tiers.fixPr });
    const small = e.fix.kind === 'refresh' || t.dropIn === 'yes';
    if (severe && t.reachable === 'yes' && small) out.push({ tier: 'auto-merge', enabled: config.tiers.autoMerge });
  }
  if (e.advisory.kev && t.reachable === 'yes' && t.exposure === 'internet-facing' && !fixable) {
    out.push({ tier: 'containment', enabled: config.tiers.containment });
  }
  return out;
}
