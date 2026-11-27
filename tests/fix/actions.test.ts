import { describe, expect, it } from 'vitest';
import type { PlannedFinding } from '../../src/fix/actions.js';
import { groupActions } from '../../src/fix/actions.js';
import type { FixKind, FixStep, PackagePlan } from '../../src/fix/plan.js';
import { FIX_KINDS } from '../../src/fix/plan.js';
import { changeOf } from '../../src/fix/versions.js';

type Bump = Extract<FixStep, { kind: 'bump' }>;

const refresh = (pkg: string, from: string, to: string): FixStep => ({ kind: 'refresh', package: pkg, from, to, direct: false });

/** A bump in the app's package.json from a pinned version, unless `extra` says otherwise. */
const bump = (pkg: string, from: string, to: string, extra: Partial<Bump> = {}): Bump => ({
  kind: 'bump',
  package: pkg,
  from,
  to,
  change: changeOf(from, to),
  root: '.',
  spec: from,
  ...extra,
});

/** The plan for `id` (`name@version`), its kind the costliest step's. */
function plan(id: string, ...steps: FixStep[]): PackagePlan {
  const at = id.lastIndexOf('@');
  const kind = steps.reduce<FixKind>((worst, s) => (FIX_KINDS.indexOf(s.kind) > FIX_KINDS.indexOf(worst) ? s.kind : worst), 'refresh');
  return { id, package: id.slice(0, at), version: id.slice(at + 1), kind, target: null, steps };
}

/** A high-severity, runtime, not KEV-listed finding for `id`, keyed `<advisory>|<id>`. */
function finding(id: string, extra: Partial<PlannedFinding> & { advisoryId?: string } = {}): PlannedFinding {
  const at = id.lastIndexOf('@');
  const { advisoryId = 'GHSA-test', ...rest } = extra;
  return {
    key: `${advisoryId}|${id}`,
    package: id.slice(0, at),
    version: id.slice(at + 1),
    devOnly: false,
    advisory: { severity: 'HIGH', kind: 'vulnerability' },
    kev: [],
    ...rest,
  };
}

describe('groupActions', () => {
  it('merges the refresh steps of several plans into one action, keeping the highest target per package', () => {
    const plans = [
      plan('form-data@4.0.4', refresh('form-data', '4.0.4', '4.0.5')),
      plan('brace-expansion@1.1.11', refresh('brace-expansion', '1.1.11', '1.1.12')),
      // Fixing minimatch takes brace-expansion further than its own advisory needs.
      plan('minimatch@3.0.4', refresh('minimatch', '3.0.4', '3.1.2'), refresh('brace-expansion', '1.1.11', '2.0.2')),
    ];
    const findings = plans.map((p) => finding(p.id));
    expect(groupActions(plans, findings)).toEqual([
      {
        id: 'refresh',
        kind: 'refresh',
        steps: [refresh('brace-expansion', '1.1.11', '2.0.2'), refresh('form-data', '4.0.4', '4.0.5'), refresh('minimatch', '3.0.4', '3.1.2')],
        packages: ['brace-expansion@1.1.11', 'form-data@4.0.4', 'minimatch@3.0.4'],
        findings: ['GHSA-test|brace-expansion@1.1.11', 'GHSA-test|form-data@4.0.4', 'GHSA-test|minimatch@3.0.4'],
        partial: [],
        devOnly: false,
      },
    ]);
  });

  it('couples the bumps one plan needs together into one action, which other bumps of those packages join', () => {
    const plans = [
      // zod 4 needs an openai that accepts it.
      plan('zod@3.23.8', bump('zod', '3.23.8', '4.0.0'), bump('openai', '4.0.0', '5.0.0')),
      plan('openai@4.0.0', bump('openai', '4.0.0', '4.2.0')),
      plan('lodash@4.17.20', bump('lodash', '4.17.20', '4.17.21')),
    ];
    const actions = groupActions(plans, plans.map((p) => finding(p.id)));
    expect(actions.map((a) => a.id)).toEqual(['bump:.:openai+.:zod', 'bump:.:lodash']);
    expect(actions[0]).toEqual({
      id: 'bump:.:openai+.:zod',
      kind: 'bump',
      steps: [bump('openai', '4.0.0', '5.0.0'), bump('zod', '3.23.8', '4.0.0')],
      packages: ['openai@4.0.0', 'zod@3.23.8'],
      findings: ['GHSA-test|openai@4.0.0', 'GHSA-test|zod@3.23.8'],
      partial: [],
      devOnly: false,
    });
  });

  it('merges two plans that need the same bump to different versions into the higher one', () => {
    const plans = [plan('vitest@3.0.0', bump('vitest', '3.0.0', '3.0.5')), plan('vite@6.0.0', bump('vitest', '3.0.0', '4.1.12'))];
    const actions = groupActions(plans, plans.map((p) => finding(p.id)));
    expect(actions).toHaveLength(1);
    expect(actions[0]).toMatchObject({ id: 'bump:.:vitest', packages: ['vite@6.0.0', 'vitest@3.0.0'] });
    expect(actions[0]?.steps).toEqual([{ ...bump('vitest', '3.0.0', '4.1.12'), change: 'major' }]);
  });

  it('keys a bump by where its range lives: the workspace, the alias, or the pnpm catalog', () => {
    const plans = [
      plan('lodash@4.17.20', bump('lodash', '4.17.20', '4.17.21'), bump('lodash', '4.17.20', '4.17.21', { root: 'apps/web' })),
      plan('lodash@3.10.1', bump('lodash', '3.10.1', '4.17.21', { alias: 'old-lodash', root: 'packages/ui' })),
      plan('ms@2.0.0', bump('ms', '2.0.0', '2.1.1', { catalog: 'old' })),
    ];
    expect(groupActions(plans, []).map((a) => a.id)).toEqual([
      'bump:.:lodash+apps/web:lodash',
      'bump:catalog:old:ms',
      'bump:packages/ui:old-lodash',
    ]);
  });

  it('names every other kind of action', () => {
    const plans = [
      plan('postcss@8.4.31', { kind: 'override', package: 'postcss', from: '8.4.31', to: '8.4.32', change: 'patch', parents: [{ id: 'next@15.0.0', spec: '8.4.31' }] }),
      plan('evil@1.0.0', { kind: 'remove', package: 'evil', alias: 'nice', from: '1.0.0', root: '.' }),
      plan('leftpad@1.0.0', { kind: 'no-fix', package: 'leftpad', from: '1.0.0', parent: 'tool@1.0.0' }),
      plan('tar@6.2.1', { kind: 'bundled', package: 'tar', from: '6.2.1', bundler: 'npm@10.9.2' }),
      plan('cross-spawn@7.0.3', { kind: 'bundled', package: 'cross-spawn', from: '7.0.3', bundler: 'npm@10.9.2' }),
      plan('ghost@1.0.0', { kind: 'unknown', package: 'ghost', from: '1.0.0', reason: 'npm registry GET ghost failed' }),
    ];
    const actions = groupActions(plans, []);
    expect(actions.map((a) => [a.id, a.kind])).toEqual([
      ['override:postcss@8.4.31', 'override'],
      ['remove:.:nice', 'remove'],
      ['no-fix:leftpad@1.0.0', 'no-fix'],
      ['bundled:npm@10.9.2', 'bundled'],
      ['unknown:ghost@1.0.0', 'unknown'],
    ]);
    // Both packages that npm ships move with npm, in one action.
    expect(actions[3]).toMatchObject({ packages: ['cross-spawn@7.0.3', 'tar@6.2.1'] });
    expect(actions[3]?.steps.map((s) => s.package)).toEqual(['cross-spawn', 'tar']);
  });

  it('marks the packages that also need another action as partial', () => {
    const plans = [
      plan('lib@1.0.0', refresh('lib', '1.0.0', '1.0.1'), { kind: 'unknown', package: 'lib', from: '1.0.0', reason: 'git' }),
      plan('form-data@4.0.4', refresh('form-data', '4.0.4', '4.0.5')),
    ];
    const actions = groupActions(plans, plans.map((p) => finding(p.id)));
    expect(actions.map((a) => [a.id, a.packages, a.partial])).toEqual([
      ['refresh', ['form-data@4.0.4', 'lib@1.0.0'], ['lib@1.0.0']],
      ['unknown:lib@1.0.0', ['lib@1.0.0'], ['lib@1.0.0']],
    ]);
  });

  it("puts the refreshes of a plan with a bump into the bump's action, since they run after it", () => {
    const plans = [
      plan('postcss@8.4.31', refresh('postcss', '8.4.31', '8.4.32'), bump('next', '15.0.0', '15.2.3')),
      plan('form-data@4.0.4', refresh('form-data', '4.0.4', '4.0.5')),
    ];
    const actions = groupActions(plans, plans.map((p) => finding(p.id)));
    expect(actions.map((a) => [a.id, a.kind, a.steps, a.packages, a.partial])).toEqual([
      ['refresh', 'refresh', [refresh('form-data', '4.0.4', '4.0.5')], ['form-data@4.0.4'], []],
      ['bump:.:next', 'bump', [bump('next', '15.0.0', '15.2.3'), refresh('postcss', '8.4.31', '8.4.32')], ['postcss@8.4.31'], []],
    ]);
  });

  it('keeps a refresh by an alias apart from one by the real name, and keeps a dedupe that any merged bump asks for', () => {
    const viaAlias: FixStep = { kind: 'refresh', package: 'string-width', alias: 'string-width-cjs', from: '4.2.0', to: '4.2.3', direct: false };
    const plans = [
      plan('string-width@4.2.0', refresh('string-width', '4.2.0', '4.2.3'), viaAlias),
      plan('lodash@4.17.20', bump('lodash', '4.17.20', '4.17.21', { dedupe: true })),
      plan('lodash@4.17.20-other', bump('lodash', '4.17.20', '4.17.22')),
    ];
    const actions = groupActions(plans, plans.map((p) => finding(p.id)));
    expect(actions.find((a) => a.id === 'refresh')?.steps).toEqual([refresh('string-width', '4.2.0', '4.2.3'), viaAlias]);
    expect(actions.find((a) => a.id === 'bump:.:lodash')?.steps).toEqual([bump('lodash', '4.17.20', '4.17.22', { dedupe: true })]);
  });

  it('calls an action dev-only only when every finding it works on is', () => {
    const plans = [
      plan('vitest@3.0.0', bump('vitest', '3.0.0', '3.0.5')),
      plan('esbuild@0.24.0', refresh('esbuild', '0.24.0', '0.25.0')),
      plan('axios@1.12.2', refresh('axios', '1.12.2', '1.12.3')),
      plan('lonely@1.0.0', bump('lonely', '1.0.0', '1.0.1')),
    ];
    const findings = [
      finding('vitest@3.0.0', { devOnly: true }),
      finding('vitest@3.0.0', { devOnly: true, advisoryId: 'GHSA-other' }),
      finding('esbuild@0.24.0', { devOnly: true }),
      finding('axios@1.12.2'),
    ];
    const devOnly = Object.fromEntries(groupActions(plans, findings).map((a) => [a.id, a.devOnly]));
    // No finding at all is not dev-only.
    expect(devOnly).toEqual({ refresh: false, 'bump:.:vitest': true, 'bump:.:lonely': false });
  });

  it('orders malware first, then KEV, then the cheapest kind, runtime before dev-only, the worst severity and the most findings', () => {
    const plans = [
      plan('dev-crit@1.0.0', bump('dev-crit', '1.0.0', '1.0.1')),
      plan('low-one@1.0.0', bump('low-one', '1.0.0', '1.0.1')),
      plan('low-many@1.0.0', bump('low-many', '1.0.0', '1.0.1')),
      plan('crit@1.0.0', bump('crit', '1.0.0', '1.0.1')),
      plan('esbuild@0.24.0', refresh('esbuild', '0.24.0', '0.25.0')),
      plan('kev@1.0.0', { kind: 'override', package: 'kev', from: '1.0.0', to: '1.0.1', change: 'patch', parents: [{ id: 'p@1.0.0', spec: '1.0.0' }] }),
      plan('evil@1.0.0', { kind: 'remove', package: 'evil', from: '1.0.0', root: '.' }),
    ];
    const low = { severity: 'LOW', kind: 'vulnerability' } as const;
    const findings = [
      finding('dev-crit@1.0.0', { devOnly: true, advisory: { severity: 'CRITICAL', kind: 'vulnerability' } }),
      finding('low-one@1.0.0', { advisory: low }),
      finding('low-many@1.0.0', { advisory: low }),
      finding('low-many@1.0.0', { advisory: low, advisoryId: 'GHSA-second' }),
      finding('crit@1.0.0', { advisory: { severity: 'CRITICAL', kind: 'vulnerability' } }),
      finding('esbuild@0.24.0', { devOnly: true, advisory: low }),
      finding('kev@1.0.0', { kev: ['CVE-2026-1'], advisory: { severity: 'MODERATE', kind: 'vulnerability' } }),
      finding('evil@1.0.0', { kev: null, advisory: { severity: 'UNKNOWN', kind: 'malicious' } }),
    ];
    expect(groupActions(plans, findings).map((a) => a.id)).toEqual([
      'remove:.:evil',
      'override:kev@1.0.0',
      'refresh',
      'bump:.:crit',
      'bump:.:low-many',
      'bump:.:low-one',
      'bump:.:dev-crit',
    ]);
  });
});
