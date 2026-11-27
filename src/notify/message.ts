import type { Rule } from '../policy.js';
import { RULE_TEXT } from '../policy.js';
import type { YesNo } from '../triage/triage.js';
import type { Severity } from '../watch/advisory.js';

export interface MessageItem {
  key: string;
  package: string;
  version: string;
  advisory: string;
  severity: Severity;
  summary: string;
  kev: boolean;
  rule: Rule;
  reachable: YesNo;
  /** Who judged reachability, and why. */
  reason: string;
  fix: string | null;
  /** Why it is in this message: first seen, or worse than when it was last sent. */
  change: 'new' | 'worse' | 'digest';
}

export interface Message {
  kind: 'alert' | 'digest';
  project: string;
  title: string;
  items: MessageItem[];
  /** Plain text, for the terminal and generic webhooks. */
  text: string;
  /** Slack mrkdwn. */
  slack: string;
}

const SEVERITY_ORDER: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MODERATE: 2, LOW: 3, UNKNOWN: 4 };
const DIGEST_LINES = 15;

const FIX_TEXT: Record<string, string> = {
  refresh: 'refresh the lockfile',
  bump: 'bump a dependency',
  override: 'override the version',
  remove: 'remove the package',
  'no-fix': 'no fixed version yet',
  bundled: 'wait for a new version of the package that bundles it',
  unknown: 'fix unknown',
};

/**
 * One advisory: its packages (an advisory often hits several, like React's in two bundled copies),
 * the most reachable verdict among them, and why it is here.
 */
function line(group: readonly MessageItem[], slack: boolean): string {
  const item = group.find((i) => i.reachable === 'yes') ?? group.find((i) => i.reachable === 'unknown') ?? group[0]!;
  const id = slack ? `<https://osv.dev/vulnerability/${item.advisory}|${item.advisory}>` : item.advisory;
  const severity = slack ? `*${item.severity}*` : item.severity;
  const tags = [item.kev ? 'KEV' : '', group.some((i) => i.change === 'worse') ? 'worse since last time' : ''].filter(Boolean).join(', ');
  const fix = item.fix ? (FIX_TEXT[item.fix] ?? item.fix) : 'no fix plan';
  const esc = slack ? escapeSlack : (text: string) => text;
  const packages = group.map((i) => `${i.package}@${i.version}`).join(', ');
  return (
    `${severity} ${id}${tags ? ` (${tags})` : ''} in ${esc(packages)}: ${esc(item.summary)}\n` +
    `    reachable: ${item.reachable}; ${esc(item.reason)}\n` +
    `    why: ${RULE_TEXT[item.rule]}; fix: ${fix}`
  );
}

function sorted(items: readonly MessageItem[]): MessageItem[] {
  return [...items].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || Number(b.kev) - Number(a.kev) || a.key.localeCompare(b.key));
}

/** Items grouped by advisory, in the order of each advisory's first item. */
function byAdvisory(items: readonly MessageItem[]): MessageItem[][] {
  const groups = new Map<string, MessageItem[]>();
  for (const item of items) groups.set(item.advisory, [...(groups.get(item.advisory) ?? []), item]);
  return [...groups.values()];
}

/** One message for everything that needs attention after a scan, not one per finding. */
export function alertMessage(project: string, items: readonly MessageItem[]): Message {
  const ordered = sorted(items);
  const groups = byAdvisory(ordered);
  const title = `Bulwark: ${groups.length} ${groups.length === 1 ? 'advisory needs' : 'advisories need'} attention in ${project}`;
  return {
    kind: 'alert',
    project,
    title,
    items: ordered,
    text: [title, ...groups.map((group) => line(group, false))].join('\n'),
    slack: [`*${escapeSlack(title)}*`, ...groups.map((group) => line(group, true))].join('\n'),
  };
}

/** Judged findings before the ones the threshold or the lockfile settled. */
const DIGEST_ORDER: Partial<Record<Rule, number>> = { 'not-reachable': 0, 'build-only-use': 1, 'below-threshold': 2, 'dev-only': 3 };

/** The weekly digest: counts by rule, then the findings below the bar, judged ones and the most severe first. */
export function digestMessage(project: string, items: readonly MessageItem[]): Message {
  const ordered = sorted(items).sort((a, b) => (DIGEST_ORDER[a.rule] ?? 9) - (DIGEST_ORDER[b.rule] ?? 9));
  const title = `Bulwark weekly digest for ${project}: ${ordered.length} ${ordered.length === 1 ? 'finding' : 'findings'} below the bar for an alert`;
  const counts = new Map<Rule, number>();
  for (const item of ordered) counts.set(item.rule, (counts.get(item.rule) ?? 0) + 1);
  const summary = [...counts].map(([rule, n]) => `${n} ${RULE_TEXT[rule].split(':')[0]}`).join('; ');
  const groups = byAdvisory(ordered);
  const shown = groups.slice(0, DIGEST_LINES);
  const more = groups.length - shown.length;
  const tail = more > 0 ? [`and ${more} more ${more === 1 ? 'advisory' : 'advisories'}: run bulwark scan --details for all of them`] : [];
  return {
    kind: 'digest',
    project,
    title,
    items: ordered,
    text: [title, summary, ...shown.map((group) => line(group, false)), ...tail].join('\n'),
    slack: [`*${escapeSlack(title)}*`, escapeSlack(summary), ...shown.map((group) => line(group, true)), ...tail.map(escapeSlack)].join('\n'),
  };
}

/** Slack reads &, < and > as markup. */
function escapeSlack(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
