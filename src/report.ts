import { basename } from 'node:path';
import type { FixAction } from './fix/actions.js';
import type { RefreshRun } from './fix/commands.js';
import { refreshRuns } from './fix/commands.js';
import type { FixStep } from './fix/plan.js';
import type { ScanFinding, ScanResult } from './scan.js';
import type { Severity } from './watch/advisory.js';

const INDENT = '    ';

export interface ReportOptions {
  /** Also list every finding under the fix plan. Without a plan, findings are always listed. */
  details?: boolean;
}

/**
 * Human-readable scan output for the terminal. With a fix plan, it leads with the actions to take,
 * each with the findings it closes; otherwise, and with `details`, every finding gets its own block.
 */
export function formatReport(result: ScanResult, options: ReportOptions = {}): string {
  const fresh = result.findings.filter((f) => f.status !== 'seen').length;
  const packages = new Set(result.findings.map((f) => `${f.package}@${f.version}`)).size;
  const count = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;
  const lines = [
    `${result.project}: ${basename(result.lockfile)}, ${count(result.packageCount, 'package', 'packages')}, ` +
      `${count(result.findings.length, 'finding', 'findings')}` +
      `${result.findings.length > 0 ? ` in ${count(packages, 'package', 'packages')}` : ''} (${fresh} new or updated)`,
  ];
  const actions = result.fixPlan.status === 'ok' ? result.fixPlan.actions : [];
  const epssUnavailable = result.enrichment.epss === 'unavailable';
  if (actions.length > 0) {
    lines.push('', `Fix plan: ${count(actions.length, 'action', 'actions')}, most urgent and cheapest first`);
    const byKey = new Map(result.findings.map((f) => [f.key, f]));
    // On a first scan everything is new, so counting new findings per action says nothing.
    const showFresh = result.findings.some((f) => f.status === 'seen');
    actions.forEach((action, i) => {
      lines.push('', ...formatAction(action, i + 1, byKey, showFresh, result.manager), ...followUp(action, result));
    });
    if (options.details) {
      lines.push('', 'Findings');
      const number = new Map(actions.map((action, i) => [action.id, i + 1]));
      for (const f of result.findings) lines.push('', ...formatFinding(f, epssUnavailable, number));
    } else {
      lines.push('', 'Run with --details to list every advisory.');
    }
  } else {
    for (const f of result.findings) lines.push('', ...formatFinding(f, epssUnavailable));
  }
  for (const warning of result.warnings) lines.push('', `warning: ${warning}`);
  return lines.join('\n');
}

const SEVERITIES: readonly Severity[] = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'UNKNOWN'];

type Refresh = Extract<FixStep, { kind: 'refresh' }>;
type Bump = Extract<FixStep, { kind: 'bump' }>;

/**
 * What finishes an action: the refresh command, or for a bump, the refreshes and the pnpm dedupe that
 * run after it. npm and pnpm keep a version that the bumped package's range still allows, and pnpm 11
 * keeps other copies of a bumped package where they are.
 */
function followUp(action: FixAction, result: ScanResult): string[] {
  const refreshes = action.steps.filter((step): step is Refresh => step.kind === 'refresh');
  if (action.kind === 'refresh') {
    const listed = result.manager === 'pnpm' && refreshes.some((step) => step.direct);
    return [
      ...refreshCommand(refreshes, result, 'run'),
      ...(listed ? [`${INDENT}pnpm also raises the package.json range of each listed package it updates`] : []),
    ];
  }
  if (action.kind !== 'bump') return [];
  const lines: string[] = [];
  if (refreshes.length > 0) {
    lines.push(
      `${INDENT}then refresh these, which the bump leaves at the old version:`,
      ...refreshes.map((step) => `${INDENT}  ${refreshName(step)} ${step.from} -> ${step.to}`),
      ...refreshCommand(refreshes, result, 'then'),
    );
  }
  const deduped = action.steps.filter((step): step is Bump => step.kind === 'bump' && step.dedupe === true);
  if (result.manager === 'pnpm' && deduped.length > 0) {
    const copies = deduped.map((step) => `${step.package} ${step.from}`).join(', ');
    lines.push(`${INDENT}then: pnpm dedupe --lockfile-only (pnpm 11 keeps the other copies of ${copies})`);
  }
  return lines;
}

/** The commands that refresh those packages (see refreshRuns for their order), and what npm will refuse first. */
function refreshCommand(steps: readonly Refresh[], result: ScanResult, label: 'run' | 'then'): string[] {
  const runs = refreshRuns(steps, result.manager, result.workspaces.length > 0);
  const lines = runs.map((run, i) => `${INDENT}${i === 0 ? (run.kind === 'unlock' && label === 'run' ? 'edit' : label) : 'then'}: ${describeRun(run)}`);
  const broken = result.fixPlan.brokenPeers;
  if (result.manager === 'npm' && broken.length > 0) {
    const first = broken[0]!;
    const more = broken.length > 1 ? ` (and ${broken.length - 1} more)` : '';
    lines.push(
      `${INDENT}npm refuses it without --legacy-peer-deps, because the lockfile already breaks a peer range:`,
      `${INDENT}  ${spaced(first.parent)} wants ${first.name} ${first.spec} and gets ${first.installed}${more}`,
    );
  }
  return lines;
}

function describeRun(run: RefreshRun): string {
  return run.kind === 'command' ? run.argv.join(' ') : `delete the yarn.lock entries of ${run.packages.join(', ')}`;
}

function formatAction(action: FixAction, n: number, byKey: Map<string, ScanFinding>, showFresh: boolean, manager: string): string[] {
  const findings = action.findings.map((key) => byKey.get(key)).filter((f): f is ScanFinding => f !== undefined);
  const lines = [`${n}. ${title(action, manager)}`, `${INDENT}${tally(action, findings, showFresh)}`];
  if (action.kind === 'refresh') {
    for (const step of action.steps) {
      if (step.kind === 'refresh') lines.push(`${INDENT}  ${refreshName(step)} ${step.from} -> ${step.to}`);
    }
  }
  // Name the vulnerable packages when the steps change something else (a parent, the bundling package).
  const named = new Set(action.steps.map((step) => `${step.package}@${step.from}`));
  const others = action.packages.filter((id) => !named.has(id));
  if (others.length > 0) lines.push(...wrap('fixes', others.map(spaced)));
  if (action.partial.length > 0) {
    lines.push(...wrap(`also ${action.partial.length === 1 ? 'needs' : 'need'} another action:`, action.partial.map(spaced)));
  }
  for (const step of action.steps) {
    const listed = step.kind === 'override' ? step.direct?.find((d) => d.root === '.') : undefined;
    if (step.kind === 'override' && listed && manager === 'npm') {
      lines.push(
        `${INDENT}package.json lists ${step.package} too, and npm refuses an override of a direct dependency:`,
        `${INDENT}  set it there to ${raised(listed.spec, step.to)} and the override to "$${step.package}"`,
      );
    }
    if (step.kind === 'override' && (manager === 'yarn-classic' || manager === 'yarn-berry')) {
      lines.push(`${INDENT}yarn calls this a resolution: "resolutions" in package.json`);
    }
    if (step.kind === 'override' && step.alternative) {
      lines.push(`${INDENT}or instead: ${step.alternative.map((alt) => describe(alt, manager)).join('; ')}`);
    }
    if (step.kind === 'no-fix') {
      const via = findings.find((f) => f.package === step.package && f.version === step.from)?.paths[0];
      if (via) lines.push(`${INDENT}pulled in via ${via.join(' > ')}`);
    }
  }
  return lines;
}

/** `string-width-cjs (string-width)` for an aliased copy, otherwise the package name. */
function refreshName(step: Refresh): string {
  return step.alias ? `${step.alias} (${step.package})` : step.package;
}

/** The range package.json should give a direct dependency so that it allows `to`, keeping a ^ or ~ it had. */
function raised(spec: string, to: string): string {
  const prefix = /^\s*([~^])\d/.exec(spec)?.[1] ?? '';
  return `${prefix}${to}`;
}

/** The action as one instruction. */
function title(action: FixAction, manager: string): string {
  const first = action.steps.find((step) => step.kind === action.kind) ?? action.steps[0]!;
  switch (first.kind) {
    case 'refresh':
      return 'Refresh the lockfile: the version ranges already allow the fixes';
    case 'bump': {
      const bumps = action.steps.filter((step): step is Extract<FixStep, { kind: 'bump' }> => step.kind === 'bump');
      const places = new Set(bumps.map((step) => place(step, manager)));
      const what = (step: Extract<FixStep, { kind: 'bump' }>) =>
        `${step.alias ? `${step.alias} (${step.package})` : step.package} ${step.from} -> ${step.to} ` +
        `(${step.change}${step.add ? `, add it to ${step.add}` : ''})`;
      return places.size === 1
        ? `Bump ${bumps.map(what).join(' and ')} in ${place(first, manager)}`
        : `Bump ${bumps.map((step) => `${what(step)} in ${place(step, manager)}`).join('; ')}`;
    }
    case 'override': {
      const asks = first.parents.map((p) => `${spaced(p.id)} asks for ${p.spec || 'it'}`).join(', ');
      return `Override ${first.package} ${first.from} -> ${first.to} (${first.change}): ${asks}`;
    }
    case 'remove':
      return `Remove ${first.alias ?? first.package} ${first.from} from ${where(first.root)}: malicious, and no release is clean`;
    case 'no-fix':
      return `No fixed version of ${first.package} ${first.from} yet`;
    case 'bundled':
      return `Upgrade ${spaced(first.bundler)}: it ships its own copies, so only a newer release of it changes them`;
    case 'unknown':
      return `Could not plan ${first.package} ${first.from}: ${first.reason}`;
  }
}

function describe(step: FixStep, manager: string): string {
  if (step.kind !== 'bump') return `${step.kind} ${step.package}`;
  const name = step.alias ? `${step.alias} (${step.package})` : step.package;
  return `bump ${name} ${step.from} -> ${step.to} (${step.change}${step.add ? `, add it to ${step.add}` : ''}) in ${place(step, manager)}`;
}

/** The file a bump edits: a package.json, or the catalog in pnpm-workspace.yaml (pnpm) or .yarnrc.yml (yarn 4). */
function place(step: Extract<FixStep, { kind: 'bump' }>, manager: string): string {
  if (step.catalog === undefined) return where(step.root);
  const file = manager === 'yarn-berry' ? '.yarnrc.yml' : 'pnpm-workspace.yaml';
  return `the ${step.catalog === 'default' ? 'default catalog' : `"${step.catalog}" catalog`} in ${file}`;
}

/** `label item, item, ...` over indented lines of at most about 100 characters, breaking only between items. */
function wrap(label: string, items: readonly string[]): string[] {
  const lines: string[] = [];
  let line = label;
  items.forEach((item, i) => {
    const piece = `${item}${i < items.length - 1 ? ',' : ''}`;
    if (line.trim() && line.length + piece.length + 1 > 96) {
      lines.push(line);
      line = `  ${piece}`;
    } else {
      line = `${line} ${piece}`;
    }
  });
  lines.push(line);
  return lines.map((l) => `${INDENT}${l}`);
}

function where(root: string): string {
  return root === '.' ? 'package.json' : `${root}/package.json`;
}

/** "3 findings: 1 critical, 2 high, KEV-listed, dev-only, 3 new or updated" */
function tally(action: FixAction, findings: readonly ScanFinding[], showFresh: boolean): string {
  const parts = SEVERITIES.flatMap((severity) => {
    const n = findings.filter((f) => f.advisory.kind !== 'malicious' && f.advisory.severity === severity).length;
    return n > 0 ? [`${n} ${severity.toLowerCase()}`] : [];
  });
  const malicious = findings.filter((f) => f.advisory.kind === 'malicious').length;
  if (malicious > 0) parts.unshift(`${malicious} malicious`);
  if (findings.some((f) => (f.kev?.length ?? 0) > 0)) parts.push('KEV-listed');
  if (action.devOnly) parts.push('dev-only');
  const fresh = findings.filter((f) => f.status !== 'seen').length;
  if (showFresh && fresh > 0) parts.push(`${fresh} new or updated`);
  return `${findings.length} ${findings.length === 1 ? 'finding' : 'findings'}: ${parts.join(', ')}`;
}

/** `lodash@4.17.20` -> `lodash 4.17.20` (the @ of a scope stays). */
function spaced(id: string): string {
  const at = id.lastIndexOf('@');
  return at > 0 ? `${id.slice(0, at)} ${id.slice(at + 1)}` : id;
}

function formatFinding(f: ScanFinding, epssUnavailable: boolean, actionNumbers?: Map<string, number>): string[] {
  const malicious = f.advisory.kind === 'malicious';
  const { cves, linkedCves } = f.advisory;
  const cve = cves[0] ?? (linkedCves.length > 0 ? `linked ${linkedCves.join(', ')}` : undefined);
  const head = [
    f.status.toUpperCase().padEnd(7),
    (malicious ? 'MALICIOUS' : f.advisory.severity).padEnd(9),
    cve ? `${f.advisory.id} (${cve})` : f.advisory.id,
    `${f.package}@${f.version}`,
  ].join('  ');
  const fix = malicious
    ? f.fixedVersion
      ? `${f.fixedVersion} (or remove it)`
      : 'remove it or pin a clean version'
    : (f.fixedVersion ?? 'none yet');
  const facts = [
    f.direct ? 'direct' : 'transitive',
    f.devOnly ? 'dev-only' : 'runtime',
    `fix: ${fix}`,
    `KEV: ${f.kev === null ? 'unknown' : f.kev.length > 0 ? `yes (${f.kev.join(', ')})` : 'no'}`,
    `EPSS: ${epssUnavailable ? 'unknown' : f.epss === null ? 'none' : f.epss.toFixed(2)}`,
  ].join(', ');
  const numbers = actionNumbers && f.fix ? f.fix.actions.map((id) => actionNumbers.get(id)).filter((n) => n !== undefined) : [];
  return [
    head,
    ...(f.advisory.summary ? [`${INDENT}${f.advisory.summary}`] : []),
    `${INDENT}${facts}`,
    ...(f.status === 'updated' && f.changed.length > 0 ? [`${INDENT}changed: ${f.changed.join(', ')}`] : []),
    ...f.paths.map((chain) => `${INDENT}via ${chain.join(' > ')}`),
    ...(numbers.length > 0 ? [`${INDENT}plan: action ${numbers.join(' and ')}`] : []),
  ];
}
