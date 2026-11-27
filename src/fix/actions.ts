import semver from 'semver';
import type { Severity } from '../watch/advisory.js';
import type { FixKind, FixStep, PackagePlan } from './plan.js';
import { bumpKey, FIX_KINDS } from './plan.js';
import { changeOf } from './versions.js';

/** What grouping needs to know about a finding. */
export interface PlannedFinding {
  key: string;
  package: string;
  version: string;
  devOnly: boolean;
  advisory: { severity: Severity; kind: 'vulnerability' | 'malicious' };
  /** KEV-listed CVEs, or null when unknown. */
  kev: string[] | null;
}

/** One thing to do, such as "refresh the lockfile" or "bump vitest and @vitest/ui to 4.1.12", with the findings it works on. */
export interface FixAction {
  /**
   * Stable id: `refresh`, `bump:<root>:<name>[+<root>:<name>...]`, `override:<package>@<from>`,
   * `remove:<root>:<name>`, `no-fix:<id>`, `bundled:<bundler>`, `unknown:<id>`.
   */
  id: string;
  kind: FixKind;
  /**
   * The changes, merged: one per package to refresh, otherwise one, at the highest version any finding
   * needs. A bump action also holds the refreshes that have to run after it: those of a package whose
   * new parent still allows the old version.
   */
  steps: FixStep[];
  /** Vulnerable package versions (`name@version`) this action works on. */
  packages: string[];
  /** Keys of their findings. */
  findings: string[];
  /** Those of `packages` that also need another action before their findings close. */
  partial: string[];
  /** True when every finding is in a dev-only package. */
  devOnly: boolean;
}

const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MODERATE: 2, LOW: 3, UNKNOWN: 4 };

/**
 * Turns per-package plans into actions. Steps that change the same thing merge (two packages that
 * need vitest bumped to 3.0.0 and 4.1.12 get one bump to 4.1.12), and bumps that one plan needs
 * together form one action (vitest with @vitest/ui, zod with the openai that pins zod 3). Order:
 * actions with malware, then KEV-listed findings, then the cheapest kind, runtime before dev-only,
 * the worst severity, and the most findings.
 */
export function groupActions(plans: readonly PackagePlan[], findings: readonly PlannedFinding[]): FixAction[] {
  const findingsOf = new Map<string, PlannedFinding[]>();
  for (const f of findings) {
    const id = `${f.package}@${f.version}`;
    findingsOf.set(id, [...(findingsOf.get(id) ?? []), f]);
  }
  const bumpGroups = coupledBumps(plans);
  const actions = new Map<string, { kind: FixKind; steps: FixStep[]; packages: Set<string> }>();
  const actionsOf = new Map<string, Set<string>>();
  for (const plan of plans) {
    const bump = plan.steps.find((step): step is Extract<FixStep, { kind: 'bump' }> => step.kind === 'bump');
    for (const step of plan.steps) {
      // In a plan with a bump, a refresh re-resolves what the bump leaves behind, so it belongs to the bump's action.
      const owner = step.kind === 'refresh' && bump ? bump : step;
      const id = owner.kind === 'bump' ? `bump:${bumpGroups(bumpKey(owner))}` : actionId(owner, plan.id);
      const action = actions.get(id) ?? actions.set(id, { kind: owner.kind, steps: [], packages: new Set() }).get(id)!;
      action.steps.push(step);
      action.packages.add(plan.id);
      (actionsOf.get(plan.id) ?? actionsOf.set(plan.id, new Set()).get(plan.id)!).add(id);
    }
  }
  const result = [...actions].map(([id, action]): FixAction => {
    const packages = [...action.packages].sort();
    const covered = packages.flatMap((pkg) => findingsOf.get(pkg) ?? []);
    return {
      id,
      kind: action.kind,
      steps: mergeSteps(action.steps),
      packages,
      findings: covered.map((f) => f.key),
      partial: packages.filter((pkg) => (actionsOf.get(pkg)?.size ?? 0) > 1),
      devOnly: covered.length > 0 && covered.every((f) => f.devOnly),
    };
  });
  const byKey = new Map(findings.map((f) => [f.key, f]));
  const rank = (action: FixAction) => {
    const list = action.findings.map((key) => byKey.get(key)!).filter(Boolean);
    return [
      list.some((f) => f.advisory.kind === 'malicious') ? 0 : 1,
      list.some((f) => (f.kev?.length ?? 0) > 0) ? 0 : 1,
      FIX_KINDS.indexOf(action.kind),
      action.devOnly ? 1 : 0,
      Math.min(...list.map((f) => SEVERITY_RANK[f.advisory.severity]), 4),
      -list.length,
    ];
  };
  return result.sort((a, b) => {
    const ra = rank(a);
    const rb = rank(b);
    for (let i = 0; i < ra.length; i++) if (ra[i] !== rb[i]) return ra[i]! - rb[i]!;
    return a.id.localeCompare(b.id);
  });
}

/**
 * Bumps that some plan needs together, joined with union-find. Returns the group name for a bump
 * key: its members, sorted and joined by `+`.
 */
function coupledBumps(plans: readonly PackagePlan[]): (key: string) => string {
  const parent = new Map<string, string>();
  const find = (key: string): string => {
    const up = parent.get(key) ?? key;
    if (up === key) return key;
    const top = find(up);
    parent.set(key, top);
    return top;
  };
  for (const plan of plans) {
    const keys = plan.steps.flatMap((step) => (step.kind === 'bump' ? [bumpKey(step)] : []));
    for (const key of keys) if (!parent.has(key)) parent.set(key, key);
    for (const key of keys.slice(1)) parent.set(find(key), find(keys[0]!));
  }
  const members = new Map<string, string[]>();
  for (const key of parent.keys()) members.set(find(key), [...(members.get(find(key)) ?? []), key]);
  return (key) => (members.get(find(key)) ?? [key]).sort().join('+');
}

function actionId(step: FixStep, planId: string): string {
  switch (step.kind) {
    case 'refresh':
      return 'refresh';
    case 'bump':
      return `bump:${bumpKey(step)}`;
    case 'override':
      return `override:${step.package}@${step.from}`;
    case 'remove':
      return `remove:${step.root}:${step.alias ?? step.package}`;
    case 'bundled':
      return `bundled:${step.bundler}`;
    case 'no-fix':
    case 'unknown':
      return `${step.kind}:${planId}`;
  }
}

/** Merges steps that change the same package under the same name: the highest target wins, and a dedupe any of them asks for stays. */
function mergeSteps(steps: readonly FixStep[]): FixStep[] {
  const merged = new Map<string, FixStep>();
  for (const step of steps) {
    const key =
      step.kind === 'refresh'
        ? `${step.alias ?? step.package}=${step.package}@${step.from}`
        : step.kind === 'bump'
          ? `${bumpKey(step)}@${step.from}`
          : JSON.stringify(step);
    const seen = merged.get(key);
    if (!seen) {
      merged.set(key, step);
      continue;
    }
    if (seen.kind === 'refresh' && step.kind === 'refresh') {
      // The later round wins: the copy has to wait for every parent that one of the plans moves.
      const round = Math.max(seen.round ?? 0, step.round ?? 0);
      merged.set(key, { ...seen, to: semver.gt(step.to, seen.to) ? step.to : seen.to, ...(round > 0 ? { round } : {}) });
    }
    if (seen.kind === 'bump' && step.kind === 'bump') {
      const to = semver.gt(step.to, seen.to) ? step.to : seen.to;
      merged.set(key, { ...seen, to, change: changeOf(seen.from, to), ...(seen.dedupe || step.dedupe ? { dedupe: true } : {}) });
    }
  }
  const list = [...merged.values()];
  // An override for the same package version from two plans cannot happen (one plan per version), so only refresh and bump merge.
  return list.sort((a, b) => a.package.localeCompare(b.package));
}
