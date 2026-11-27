import type { Assessment } from './assess.js';
import type { Rule } from './policy.js';
import { RULE_TEXT } from './policy.js';

const count = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** The triage section of the terminal report: how findings were judged, what notifies, what waits for the digest. */
export function formatAssessment(a: Assessment): string {
  const s = a.stats;
  const lines: string[] = [];
  const parts = [`${count(s.findings, 'finding', 'findings')}`];
  const settled = a.findings.filter((f) => f.triage.source === 'rules').length;
  if (settled > 0) parts.push(`${settled} settled by plain rules (dev-only, malware, or no model)`);
  if (a.models.jev) parts.push(`${s.jev + s.jevCached} judged by Jev${s.jevCached > 0 ? ` (${s.jevCached} cached)` : ''}`);
  else parts.push('no Jev (TYPESAFE_API_KEY is not set)');
  if (a.models.claude) {
    const cost = s.claudeCostUsd !== null && s.claudeRequests > 0 ? `, $${s.claudeCostUsd.toFixed(2)}` : '';
    const cached = s.claudeCached > 0 ? `, ${s.claudeCached} cached` : '';
    const requests = s.claudeRequests > 0 ? `, ${count(s.claudeRequests, 'request', 'requests')}` : '';
    parts.push(`${s.escalated} checked by Claude (${a.models.claude}${cached}${requests}${cost})`);
  } else {
    parts.push('no Claude (set ANTHROPIC_API_KEY, or install Claude Code)');
  }
  lines.push(`Triage: ${parts.join('; ')}.`);

  const notify = a.findings.filter((f) => f.decision.outcome === 'notify');
  const digest = a.findings.filter((f) => f.decision.outcome === 'digest');
  const byRule = (list: typeof a.findings) => {
    const counts = new Map<Rule, number>();
    for (const f of list) counts.set(f.decision.rule, (counts.get(f.decision.rule) ?? 0) + 1);
    return [...counts].map(([rule, n]) => `${n} ${RULE_TEXT[rule].split(':')[0]}`).join('; ');
  };
  lines.push(`Notify: ${notify.length}${notify.length > 0 ? ` (${byRule(notify)})` : ''}. Weekly digest: ${digest.length}${digest.length > 0 ? ` (${byRule(digest)})` : ''}.`);
  const fixPr = a.findings.filter((f) => f.decision.wouldDo.some((w) => w.tier === 'fix-pr')).length;
  if (fixPr > 0) lines.push(`Tier 1: one fix PR would cover ${count(fixPr, 'finding', 'findings')} (patchhound fix makes it).`);
  for (const tier of ['auto-merge', 'containment'] as const) {
    const n = a.findings.filter((f) => f.decision.wouldDo.some((w) => w.tier === tier)).length;
    if (n > 0) lines.push(`Tier ${tier === 'auto-merge' ? 2 : 3} (${tier}) conditions hold for ${count(n, 'finding', 'findings')} (logged only).`);
  }
  if (a.messages.length === 0) {
    lines.push(
      notify.length > 0 ? `No new alert: everything that alerts was ${a.dryRun ? 'printed' : 'sent'} before and is not worse.` : 'No alert.',
    );
  }
  for (const m of a.messages) {
    const how = m.sent ? `sent to ${m.channel}` : m.channel === 'terminal' ? (a.dryRun ? 'dry run, not sent' : 'no channel set up, not sent') : `could not be sent to ${m.channel}`;
    lines.push('', `${m.message.kind === 'alert' ? 'Alert' : 'Digest'} (${how}):`, ...m.message.text.split('\n').map((l) => `  ${l}`));
  }
  for (const warning of a.warnings) lines.push('', `warning: ${warning}`);
  return lines.join('\n');
}
