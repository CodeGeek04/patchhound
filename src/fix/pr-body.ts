import type { AssessedFinding } from '../assess.js';
import type { ApplyLog } from './apply.js';
import type { CheckResult } from './checks.js';
import { failureExcerpt } from './checks.js';

export interface PrContent {
  project: string;
  kind: 'fixes' | 'malware';
  /** Findings the PR set out to fix, with their triage. */
  findings: AssessedFinding[];
  fixed: readonly string[];
  remaining: readonly string[];
  /** Why a finding was left: the major upgrade that would fix it breaks a check. */
  leftBecause?: Readonly<Record<string, string>>;
  /** Advisories that come with the new versions (a newer release line can carry its own). */
  appeared?: readonly { key: string; advisory: string; severity: string; package: string; summary: string }[];
  applied: ApplyLog | null;
  baseline: readonly CheckResult[];
  after: readonly CheckResult[];
  /** What each Claude Code session did, including a session whose work was left out. */
  agentNotes: readonly string[];
  /** What the sessions cost, as far as known. */
  agentCostUsd: number | null;
  /** Why the checks did not run before the change (a malicious package); they are then shown after it only. */
  noBaseline?: string;
}

/** The user's rule for every text patchhound writes: no em dashes, even in advisory titles it quotes. */
export function noDashes(text: string): string {
  return text.replace(/\s*\u2014\s*/g, ', ');
}

const cell = (text: string) => text.replace(/\|/g, '\\|').replace(/\n/g, ' ');

/** "a malicious package (ua-parser-js@0.7.29)", "3 malicious package versions (a@1, b@2, c@3)" */
function malicious(findings: readonly AssessedFinding[]): string {
  const versions = [...new Set(findings.map((f) => `${f.evidence.package}@${f.evidence.version}`))];
  return `${versions.length === 1 ? 'a malicious package' : `${versions.length} malicious package versions`} (${versions.join(', ')})`;
}

/** The PR's title: what it fixes. */
export function prTitle(c: PrContent): string {
  const advisories = new Set(c.findings.filter((f) => c.fixed.includes(f.key)).map((f) => f.evidence.advisory.id)).size;
  const what = c.kind === 'malware' ? 'Remove a malicious package' : `Security fixes for ${advisories} ${advisories === 1 ? 'advisory' : 'advisories'}`;
  return noDashes(what);
}

/** The PR's body: each advisory and why it matters, what changed, the checks before and after, and what is left. */
export function prBody(c: PrContent): string {
  const fixed = c.findings.filter((f) => c.fixed.includes(f.key));
  const left = c.findings.filter((f) => c.remaining.includes(f.key));
  const row = (f: AssessedFinding) =>
    `| [${f.evidence.advisory.id}](https://osv.dev/vulnerability/${f.evidence.advisory.id}) | ${f.evidence.advisory.severity}${f.evidence.advisory.kev ? ', KEV' : ''} | ${cell(`${f.evidence.package}@${f.evidence.version}`)} | ${f.triage.reachable} | ${cell(f.evidence.advisory.summary)} |`;
  const lines = [
    c.kind === 'malware'
      ? `Patchhound takes ${malicious(fixed)} out of ${c.project}. Merge it before anything installs this project again.`
      : c.baseline.length > 0 && !c.baseline.some((b) => b.passed)
        ? `Patchhound fixes ${fixed.length} ${fixed.length === 1 ? 'finding' : 'findings'} in ${c.project}. None of the project's checks passed before the change (below), so only a new scan confirms these fixes: review them with care.`
        : `Patchhound fixes ${fixed.length} ${fixed.length === 1 ? 'finding' : 'findings'} in ${c.project}, and every check that passed before still passes.`,
    '',
  ];
  if (fixed.length > 0) {
    lines.push('### Fixed', '', '| Advisory | Severity | Package | Reachable | Summary |', '| --- | --- | --- | --- | --- |', ...fixed.map(row), '');
    const reasons = fixed.filter((f) => f.triage.source !== 'rules');
    if (reasons.length > 0) {
      lines.push('<details><summary>Why each one matters (triage)</summary>', '');
      for (const f of reasons) lines.push(`- **${f.evidence.advisory.id}** (${f.evidence.package}): ${cell(f.triage.reason)}`);
      lines.push('', '</details>', '');
    }
  }
  lines.push('### What changed', '');
  for (const edit of c.applied?.edits ?? []) lines.push(`- ${edit}`);
  for (const command of c.applied?.commands ?? []) lines.push(`- ran \`${command}\``);
  for (const note of c.agentNotes) lines.push('', note);
  if (c.agentNotes.length > 0 && c.agentCostUsd !== null) lines.push(`(Claude Code cost $${c.agentCostUsd.toFixed(2)})`);
  lines.push('', '### Checks', '');
  if (c.noBaseline) {
    lines.push(`Checks were ${c.noBaseline}.`, '');
    if (c.after.length === 0) lines.push('None ran after it either: a malicious package is still in the lockfile.');
    else {
      lines.push('| Check | After |', '| --- | --- |');
      for (const a of c.after) lines.push(`| \`${cell(a.command)}\` | ${a.passed ? 'pass' : a.timedOut ? 'timed out' : 'fail'} |`);
    }
  } else if (c.baseline.length === 0) {
    lines.push('No typecheck, test or build script was found; the fixes were checked by scanning the lockfile again.');
  } else {
    lines.push('| Check | Before | After |', '| --- | --- | --- |');
    for (const b of c.baseline) {
      const a = c.after.find((x) => x.name === b.name);
      const status = (r?: CheckResult) => (!r ? 'not run' : r.passed ? 'pass' : r.timedOut ? 'timed out' : 'fail');
      lines.push(`| \`${cell(b.command)}\` | ${status(b)} | ${b.passed ? status(a) : 'skipped (failed before)'} |`);
    }
    for (const b of c.baseline.filter((r) => !r.passed)) {
      const excerpt = failureExcerpt(b.output);
      if (!excerpt) continue;
      lines.push('', `<details><summary>Why <code>${escapeHtml(b.command)}</code> failed before any change</summary>`, '', '~~~text', excerpt.replace(/~~~/g, '~ ~ ~'), '~~~', '', '</details>');
    }
  }
  if (left.length > 0) {
    lines.push('', '### Not fixed here', '', '| Advisory | Severity | Package | Reachable | Why not |', '| --- | --- | --- | --- | --- |');
    for (const f of left) {
      const why = c.leftBecause?.[f.key] ?? 'the planned change did not remove it';
      lines.push(`| [${f.evidence.advisory.id}](https://osv.dev/vulnerability/${f.evidence.advisory.id}) | ${f.evidence.advisory.severity} | ${cell(`${f.evidence.package}@${f.evidence.version}`)} | ${f.triage.reachable} | ${cell(why)} |`);
    }
  }
  if ((c.appeared ?? []).length > 0) {
    lines.push('', '### Advisories that come with the new versions', '', 'A newer release can carry advisories of its own, with no fixed version yet:', '');
    for (const a of c.appeared!) lines.push(`- [${a.advisory}](https://osv.dev/vulnerability/${a.advisory}) ${a.severity} in ${cell(a.package)}: ${cell(a.summary)}`);
  }
  lines.push('', '---', 'Opened by Patchhound. `patchhound explain <advisory>` shows how each finding was judged.');
  return noDashes(lines.join('\n'));
}

function escapeHtml(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
