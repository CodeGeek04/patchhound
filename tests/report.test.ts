import { describe, expect, it } from 'vitest';
import type { FixAction } from '../src/fix/actions.js';
import type { BrokenPeer, FixKind, FixStep } from '../src/fix/plan.js';
import { formatReport } from '../src/report.js';
import type { ScanFinding, ScanResult } from '../src/scan.js';

const lodash: ScanFinding = {
  advisory: {
    id: 'GHSA-35jh-r3h4-6jhm',
    kind: 'vulnerability',
    summary: 'Command Injection in lodash',
    aliases: ['CVE-2021-23337'],
    cves: ['CVE-2021-23337'],
    linkedCves: [],
    related: [],
    severity: 'HIGH',
    modified: '2026-10-17T02:55:38Z',
  },
  advisoryFingerprint: 'fingerprint-lodash',
  package: 'lodash',
  version: '4.17.20',
  direct: false,
  devOnly: false,
  paths: [['demo-app', '@demo/wrapper@1.0.0', 'lodash@4.17.20']],
  via: ['@demo/wrapper'],
  fixedVersion: '4.17.21',
  records: ['GHSA-35jh-r3h4-6jhm'],
  key: 'GHSA-35jh-r3h4-6jhm|lodash@4.17.20',
  status: 'new',
  changed: [],
  kev: [],
  fix: null,
  epss: 0.0123,
};

const malware: ScanFinding = {
  ...lodash,
  advisory: {
    id: 'MAL-2026-1',
    kind: 'malicious',
    summary: '',
    aliases: [],
    cves: [],
    linkedCves: [],
    related: [],
    severity: 'UNKNOWN',
    modified: 'm',
  },
  advisoryFingerprint: 'fingerprint-malware',
  records: ['MAL-2026-1'],
  key: 'MAL-2026-1|evil-pkg@1.0.1',
  package: 'evil-pkg',
  version: '1.0.1',
  direct: true,
  paths: [['demo-app', 'evil-pkg@1.0.1']],
  fixedVersion: null,
  status: 'seen',
  kev: null,
  epss: null,
};

const nextRce: ScanFinding = {
  ...lodash,
  advisory: {
    id: 'GHSA-9qr9-h5gf-34mp',
    kind: 'vulnerability',
    summary: 'Next.js is vulnerable to RCE in React flight protocol',
    aliases: [],
    cves: [],
    linkedCves: ['CVE-2025-55182'],
    related: ['CVE-2025-71389'],
    severity: 'CRITICAL',
    modified: 'm',
  },
  advisoryFingerprint: 'fingerprint-next',
  records: ['GHSA-9qr9-h5gf-34mp'],
  key: 'GHSA-9qr9-h5gf-34mp|next@15.2.2',
  package: 'next',
  version: '15.2.2',
  direct: true,
  paths: [['web', 'next@15.2.2']],
  fixedVersion: '15.2.6',
  status: 'new',
  kev: ['CVE-2025-55182'],
  epss: 0.9973,
};

const result: ScanResult = {
  schemaVersion: 1,
  scannedAt: '2026-11-19T10:00:00.000Z',
  project: 'demo-app',
  lockfile: '/work/demo-app/package-lock.json',
  manager: 'npm',
  workspaces: [],
  packageCount: 4,
  findings: [lodash, malware],
  enrichment: { kev: 'ok', epss: 'ok' },
  fixPlan: { status: 'skipped', actions: [], brokenPeers: [] },
  warnings: ['EPSS unavailable: EPSS lookup failed with HTTP 500'],
};

describe('formatReport', () => {
  it('prints a summary line, each finding, and warnings', () => {
    expect(formatReport(result)).toBe(
      [
        'demo-app: package-lock.json, 4 packages, 2 findings in 2 packages (1 new or updated)',
        '',
        'NEW      HIGH       GHSA-35jh-r3h4-6jhm (CVE-2021-23337)  lodash@4.17.20',
        '    Command Injection in lodash',
        '    transitive, runtime, fix: 4.17.21, KEV: no, EPSS: 0.01',
        '    via demo-app > @demo/wrapper@1.0.0 > lodash@4.17.20',
        '',
        'SEEN     MALICIOUS  MAL-2026-1  evil-pkg@1.0.1',
        '    direct, runtime, fix: remove it or pin a clean version, KEV: unknown, EPSS: none',
        '    via demo-app > evil-pkg@1.0.1',
        '',
        'warning: EPSS unavailable: EPSS lookup failed with HTTP 500',
      ].join('\n'),
    );
  });

  it('shows a linked CVE and the KEV entry it came from', () => {
    const text = formatReport({ ...result, findings: [nextRce], warnings: [] });
    expect(text).toContain('NEW      CRITICAL   GHSA-9qr9-h5gf-34mp (linked CVE-2025-55182)  next@15.2.2');
    expect(text).toContain('    direct, runtime, fix: 15.2.6, KEV: yes (CVE-2025-55182), EPSS: 1.00');
  });

  it('names what changed for an updated finding', () => {
    const updated: ScanFinding = { ...nextRce, status: 'updated', changed: ['kev', 'devOnly'] };
    expect(formatReport({ ...result, findings: [updated], warnings: [] }).split('\n').slice(2)).toEqual([
      'UPDATED  CRITICAL   GHSA-9qr9-h5gf-34mp (linked CVE-2025-55182)  next@15.2.2',
      '    Next.js is vulnerable to RCE in React flight protocol',
      '    direct, runtime, fix: 15.2.6, KEV: yes (CVE-2025-55182), EPSS: 1.00',
      '    changed: kev, devOnly',
      '    via web > next@15.2.2',
    ]);
  });

  it('says when there is nothing to report', () => {
    expect(formatReport({ ...result, findings: [], warnings: [] })).toBe(
      'demo-app: package-lock.json, 4 packages, 0 findings (0 new or updated)',
    );
  });

  it('shows a known clean version for a malicious package', () => {
    const pinned: ScanFinding = { ...malware, fixedVersion: '4.4.3' };
    expect(formatReport({ ...result, findings: [pinned], warnings: [] })).toContain(
      '    direct, runtime, fix: 4.4.3 (or remove it), KEV: unknown, EPSS: none',
    );
  });

  it('says EPSS is unknown for every finding when the feed was unavailable', () => {
    const text = formatReport({ ...result, findings: [lodash, nextRce], enrichment: { kev: 'ok', epss: 'unavailable' }, warnings: [] });
    expect(text).toContain('KEV: no, EPSS: unknown');
    expect(text).toContain('KEV: yes (CVE-2025-55182), EPSS: unknown');
    expect(text).not.toContain('EPSS: 0.');
  });

  it('writes "1 package" for a single package', () => {
    expect(formatReport({ ...result, packageCount: 1, findings: [], warnings: [] })).toBe(
      'demo-app: package-lock.json, 1 package, 0 findings (0 new or updated)',
    );
  });
});

describe('formatReport summary', () => {
  it('counts the packages the findings are in', () => {
    const second: ScanFinding = { ...lodash, advisory: { ...lodash.advisory, id: 'GHSA-second' }, key: 'GHSA-second|lodash@4.17.20' };
    expect(formatReport({ ...result, findings: [lodash, second], warnings: [] }).split('\n')[0]).toBe(
      'demo-app: package-lock.json, 4 packages, 2 findings in 1 package (2 new or updated)',
    );
  });

  it('lists findings the old way when the plan is unavailable', () => {
    const text = formatReport({ ...result, fixPlan: { status: 'unavailable', actions: [], brokenPeers: [] }, warnings: ['Fix plan unavailable: down'] });
    expect(text).not.toContain('Fix plan:');
    expect(text.split('\n').slice(2, 3)).toEqual(['NEW      HIGH       GHSA-35jh-r3h4-6jhm (CVE-2021-23337)  lodash@4.17.20']);
    expect(text.endsWith('warning: Fix plan unavailable: down')).toBe(true);
  });
});

/** A finding like lodash's for another package version. */
function findingOf(id: string, extra: Partial<ScanFinding> = {}): ScanFinding {
  const at = id.lastIndexOf('@');
  return { ...lodash, package: id.slice(0, at), version: id.slice(at + 1), key: `GHSA-test|${id}`, paths: [['demo-app', id]], ...extra };
}

const severity = (level: ScanFinding['advisory']['severity']): Partial<ScanFinding> => ({ advisory: { ...lodash.advisory, severity: level } });

/** An action over the findings' packages; nothing partial, not dev-only unless `extra` says so. */
function action(id: string, kind: FixKind, steps: FixStep[], findings: ScanFinding[], extra: Partial<FixAction> = {}): FixAction {
  return {
    id,
    kind,
    steps,
    packages: [...new Set(findings.map((f) => `${f.package}@${f.version}`))].sort(),
    findings: findings.map((f) => f.key),
    partial: [],
    devOnly: false,
    ...extra,
  };
}

type BumpExtra = Partial<Extract<FixStep, { kind: 'bump' }>>;
const bump = (pkg: string, from: string, to: string, change: 'patch' | 'minor' | 'major' | 'downgrade', extra: BumpExtra = {}): FixStep => ({
  kind: 'bump',
  package: pkg,
  from,
  to,
  change,
  root: '.',
  spec: from,
  ...extra,
});

/** A result with a fix plan. */
function planned(findings: ScanFinding[], actions: FixAction[], extra: Partial<ScanResult> = {}, brokenPeers: BrokenPeer[] = []): ScanResult {
  return { ...result, findings, fixPlan: { status: 'ok', actions, brokenPeers }, warnings: [], ...extra };
}

/** The numbered action titles of a report. */
const titles = (text: string) => text.split('\n').filter((line) => /^\d+\. /.test(line));

describe('formatReport with a fix plan', () => {
  const brace = findingOf('brace-expansion@1.1.11', severity('LOW'));
  const formData = findingOf('form-data@4.0.4');
  const refresh = action(
    'refresh',
    'refresh',
    [
      { kind: 'refresh', package: 'brace-expansion', from: '1.1.11', to: '1.1.12', direct: false },
      { kind: 'refresh', package: 'form-data', from: '4.0.4', to: '4.0.5', direct: true },
    ],
    [brace, formData],
  );
  const broken: BrokenPeer[] = [
    { parent: '@testing-library/react@16.0.0', name: 'react-dom', spec: '^18.0.0', installed: '17.0.2' },
    { parent: 'next@15.2.2', name: 'react', spec: '^18.2.0 || ^19.0.0', installed: '17.0.2' },
  ];

  it('leads with a refresh action, the npm command, and the peer range npm will trip on', () => {
    expect(formatReport(planned([brace, formData], [refresh], {}, broken))).toBe(
      [
        'demo-app: package-lock.json, 4 packages, 2 findings in 2 packages (2 new or updated)',
        '',
        'Fix plan: 1 action, most urgent and cheapest first',
        '',
        '1. Refresh the lockfile: the version ranges already allow the fixes',
        '    2 findings: 1 high, 1 low',
        '      brace-expansion 1.1.11 -> 1.1.12',
        '      form-data 4.0.4 -> 4.0.5',
        '    run: npm update brace-expansion form-data --package-lock-only',
        '    npm refuses it without --legacy-peer-deps, because the lockfile already breaks a peer range:',
        '      @testing-library/react 16.0.0 wants react-dom ^18.0.0 and gets 17.0.2 (and 1 more)',
        '',
        'Run with --details to list every advisory.',
      ].join('\n'),
    );
  });

  it('leaves the peer note out when no peer range is broken', () => {
    const text = formatReport(planned([brace, formData], [refresh]));
    expect(text).toContain('    run: npm update brace-expansion form-data --package-lock-only');
    expect(text).not.toContain('--legacy-peer-deps');
  });

  it('gives pnpm two runs, listed packages first, with no npm peer note', () => {
    const pnpm = planned([brace, formData], [refresh], { manager: 'pnpm', lockfile: '/work/demo-app/pnpm-lock.yaml' }, broken);
    expect(formatReport(pnpm)).toBe(
      [
        'demo-app: pnpm-lock.yaml, 4 packages, 2 findings in 2 packages (2 new or updated)',
        '',
        'Fix plan: 1 action, most urgent and cheapest first',
        '',
        '1. Refresh the lockfile: the version ranges already allow the fixes',
        '    2 findings: 1 high, 1 low',
        '      brace-expansion 1.1.11 -> 1.1.12',
        '      form-data 4.0.4 -> 4.0.5',
        '    run: pnpm update form-data --lockfile-only',
        '    then: pnpm update brace-expansion --lockfile-only',
        '    pnpm also raises the package.json range of each listed package it updates',
        '',
        'Run with --details to list every advisory.',
      ].join('\n'),
    );
  });

  it('runs pnpm with -r in a workspace, and a child refresh after the parent it waits for', () => {
    const steps: FixStep[] = [
      { kind: 'refresh', package: 'lodash', from: '4.17.20', to: '4.17.21', direct: true, round: 1 },
      { kind: 'refresh', package: 'a', from: '1.0.0', to: '1.0.1', direct: false },
    ];
    const lodashOld = findingOf('lodash@4.17.20');
    const workspace = planned([lodashOld], [action('refresh', 'refresh', steps, [lodashOld])], {
      manager: 'pnpm',
      lockfile: '/work/demo-app/pnpm-lock.yaml',
      workspaces: ['packages/app'],
    });
    expect(formatReport(workspace).split('\n').filter((line) => /^ {4}(run|then):/.test(line))).toEqual([
      '    run: pnpm update -r a --lockfile-only',
      '    then: pnpm update -r lodash --lockfile-only',
    ]);
  });

  it('refreshes with yarn up -R in yarn 2+, and by deleting yarn.lock entries then installing in yarn 1', () => {
    const lodashOld = findingOf('lodash@4.17.20');
    const steps: FixStep[] = [{ kind: 'refresh', package: 'lodash', from: '4.17.20', to: '4.17.21', direct: false }];
    const commands = (manager: string) =>
      formatReport(planned([lodashOld], [action('refresh', 'refresh', steps, [lodashOld])], { manager, lockfile: '/work/demo-app/yarn.lock' }))
        .split('\n')
        .filter((line) => /^ {4}(run|then|edit):/.test(line));
    expect(commands('yarn-berry')).toEqual(['    run: yarn up -R lodash']);
    expect(commands('yarn-classic')).toEqual(['    edit: delete the yarn.lock entries of lodash', '    then: yarn install']);
  });

  it('calls an override a resolution for yarn', () => {
    const postcss = findingOf('postcss@8.4.31');
    const step: FixStep = { kind: 'override', package: 'postcss', from: '8.4.31', to: '8.4.32', change: 'patch', parents: [{ id: 'next@15.0.0', spec: '8.4.31' }] };
    const text = formatReport(planned([postcss], [action('override:postcss@8.4.31', 'override', [step], [postcss])], { manager: 'yarn-berry' }));
    expect(text).toContain('    yarn calls this a resolution: "resolutions" in package.json');
  });

  it('shows coupled bumps as one action, naming a vulnerable package the steps do not', () => {
    const zod = findingOf('zod@3.23.8');
    const undici = findingOf('undici@5.0.0', severity('CRITICAL'));
    const coupled = action('bump:.:openai+.:zod', 'bump', [bump('openai', '4.0.0', '5.0.0', 'major'), bump('zod', '3.23.8', '4.0.0', 'major')], [undici, zod]);
    expect(formatReport(planned([undici, zod], [coupled]))).toBe(
      [
        'demo-app: package-lock.json, 4 packages, 2 findings in 2 packages (2 new or updated)',
        '',
        'Fix plan: 1 action, most urgent and cheapest first',
        '',
        '1. Bump openai 4.0.0 -> 5.0.0 (major) and zod 3.23.8 -> 4.0.0 (major) in package.json',
        '    2 findings: 1 critical, 1 high',
        '    fixes undici 5.0.0',
        '',
        'Run with --details to list every advisory.',
      ].join('\n'),
    );
  });

  it('says to add a package that only peer ranges pulled in', () => {
    const vite = findingOf('vite@8.2.2');
    const add = action('bump:.:vite', 'bump', [bump('vite', '8.2.2', '8.3.8', 'minor', { spec: '', add: 'devDependencies' })], [vite]);
    expect(titles(formatReport(planned([vite], [add])))).toEqual([
      '1. Bump vite 8.2.2 -> 8.3.8 (minor, add it to devDependencies) in package.json',
    ]);
  });

  it('names the file each bump edits: a workspace package.json, an alias, a pnpm catalog', () => {
    const old = findingOf('lodash@3.10.1');
    const ms = findingOf('ms@2.0.0');
    const twoPlaces = action(
      'bump:catalog:old:ms+packages/ui:old-lodash',
      'bump',
      [
        bump('lodash', '3.10.1', '4.17.21', 'major', { alias: 'old-lodash', root: 'packages/ui', spec: 'npm:lodash@3.10.1' }),
        bump('ms', '2.0.0', '2.1.1', 'minor', { spec: '~2.0.0', catalog: 'old' }),
      ],
      [old, ms],
    );
    const catalog = findingOf('lodash@4.18.0');
    const inDefault = action('bump:catalog:default:lodash', 'bump', [bump('lodash', '4.18.0', '4.18.1', 'patch', { spec: '^4.18.0', catalog: 'default' })], [catalog]);
    expect(titles(formatReport(planned([old, ms, catalog], [twoPlaces, inDefault])))).toEqual([
      '1. Bump old-lodash (lodash) 3.10.1 -> 4.17.21 (major) in packages/ui/package.json; ms 2.0.0 -> 2.1.1 (minor) in the "old" catalog in pnpm-workspace.yaml',
      '2. Bump lodash 4.18.0 -> 4.18.1 (patch) in the default catalog in pnpm-workspace.yaml',
    ]);
  });

  it('shows an override with each blocking parent and the alternative it beat', () => {
    const postcss = findingOf('postcss@8.4.31', severity('MODERATE'));
    const override = action(
      'override:postcss@8.4.31',
      'override',
      [
        {
          kind: 'override',
          package: 'postcss',
          from: '8.4.31',
          to: '8.4.32',
          change: 'patch',
          parents: [
            { id: 'next@15.0.0', spec: '8.4.31' },
            { id: '@vercel/og@0.6.0', spec: '' },
          ],
          alternative: [bump('next', '15.0.0', '16.0.0', 'major', { spec: '^15.0.0' })],
        },
      ],
      [postcss],
    );
    expect(formatReport(planned([postcss], [override])).split('\n').slice(4, -2)).toEqual([
      '1. Override postcss 8.4.31 -> 8.4.32 (patch): next 15.0.0 asks for 8.4.31, @vercel/og 0.6.0 asks for it',
      '    1 finding: 1 moderate',
      '    or instead: bump next 15.0.0 -> 16.0.0 (major) in package.json',
    ]);
  });

  it('tells npm what an override of a package that package.json lists needs, and pnpm nothing more', () => {
    const postcss = findingOf('postcss@8.4.31', severity('MODERATE'));
    const step: FixStep = {
      kind: 'override',
      package: 'postcss',
      from: '8.4.31',
      to: '8.4.32',
      change: 'patch',
      parents: [{ id: 'next@15.0.0', spec: '8.4.31' }],
      direct: [{ root: '.', spec: '^8.4.31' }],
    };
    const override = action('override:postcss@8.4.31', 'override', [step], [postcss]);
    expect(formatReport(planned([postcss], [override])).split('\n').slice(4, -2)).toEqual([
      '1. Override postcss 8.4.31 -> 8.4.32 (patch): next 15.0.0 asks for 8.4.31',
      '    1 finding: 1 moderate',
      '    package.json lists postcss too, and npm refuses an override of a direct dependency:',
      '      set it there to ^8.4.32 and the override to "$postcss"',
    ]);
    const pnpm = formatReport(planned([postcss], [override], { manager: 'pnpm', lockfile: '/work/demo-app/pnpm-lock.yaml' }));
    expect(pnpm).not.toContain('$postcss');
  });

  it('runs the refreshes a bump leaves behind after it', () => {
    const lodashOld = findingOf('lodash@4.17.20');
    const steps: FixStep[] = [
      { kind: 'refresh', package: 'lodash', from: '4.17.20', to: '4.17.21', direct: false },
      bump('a', '1.0.0', '1.0.1', 'patch'),
    ];
    const lines = (manager: string) =>
      formatReport(planned([lodashOld], [action('bump:.:a', 'bump', steps, [lodashOld])], { manager })).split('\n').slice(4, -2);
    expect(lines('npm')).toEqual([
      '1. Bump a 1.0.0 -> 1.0.1 (patch) in package.json',
      '    1 finding: 1 high',
      '    then refresh these, which the bump leaves at the old version:',
      '      lodash 4.17.20 -> 4.17.21',
      '    then: npm update lodash --package-lock-only',
    ]);
    expect(lines('pnpm').at(-1)).toBe('    then: pnpm update lodash --lockfile-only');
  });

  it('asks pnpm, not npm, to dedupe after a bump that leaves other copies behind', () => {
    const lodashOld = findingOf('lodash@4.17.20');
    const bumped = action('bump:.:lodash', 'bump', [bump('lodash', '4.17.20', '4.17.21', 'patch', { dedupe: true })], [lodashOld]);
    const pnpm = formatReport(planned([lodashOld], [bumped], { manager: 'pnpm', lockfile: '/work/demo-app/pnpm-lock.yaml' }));
    expect(pnpm.split('\n').slice(4, -2)).toEqual([
      '1. Bump lodash 4.17.20 -> 4.17.21 (patch) in package.json',
      '    1 finding: 1 high',
      '    then: pnpm dedupe --lockfile-only (pnpm 11 keeps the other copies of lodash 4.17.20)',
    ]);
    expect(formatReport(planned([lodashOld], [bumped]))).not.toContain('dedupe');
  });

  it('refreshes an aliased copy by its alias', () => {
    const width = findingOf('string-width@4.2.0');
    const viaAlias = action(
      'refresh',
      'refresh',
      [{ kind: 'refresh', package: 'string-width', alias: 'string-width-cjs', from: '4.2.0', to: '4.2.3', direct: false }],
      [width],
    );
    expect(formatReport(planned([width], [viaAlias])).split('\n').slice(6, 9)).toEqual([
      '      string-width-cjs (string-width) 4.2.0 -> 4.2.3',
      '    run: npm update string-width-cjs --package-lock-only',
      '',
    ]);
  });

  it('says where a package with no fix comes from', () => {
    const leftpad = findingOf('leftpad@1.0.0', { fixedVersion: null, paths: [['demo-app', 'tool@1.0.0', 'leftpad@1.0.0']] });
    const noFix = action('no-fix:leftpad@1.0.0', 'no-fix', [{ kind: 'no-fix', package: 'leftpad', from: '1.0.0', parent: 'tool@1.0.0' }], [leftpad]);
    expect(formatReport(planned([leftpad], [noFix])).split('\n').slice(4, -2)).toEqual([
      '1. No fixed version of leftpad 1.0.0 yet',
      '    1 finding: 1 high',
      '    pulled in via demo-app > tool@1.0.0 > leftpad@1.0.0',
    ]);
  });

  it('points bundled packages at the package that ships them', () => {
    const tar = findingOf('tar@6.2.1', { devOnly: true });
    const crossSpawn = findingOf('cross-spawn@7.0.3', { ...severity('LOW'), devOnly: true });
    const bundled = action(
      'bundled:npm@10.9.2',
      'bundled',
      [
        { kind: 'bundled', package: 'cross-spawn', from: '7.0.3', bundler: 'npm@10.9.2' },
        { kind: 'bundled', package: 'tar', from: '6.2.1', bundler: 'npm@10.9.2' },
      ],
      [crossSpawn, tar],
      { devOnly: true },
    );
    expect(formatReport(planned([crossSpawn, tar], [bundled])).split('\n').slice(4, -2)).toEqual([
      '1. Upgrade npm 10.9.2: it ships its own copies, so only a newer release of it changes them',
      '    2 findings: 1 high, 1 low, dev-only',
    ]);
  });

  it('names a removal in a workspace and a package it could not plan', () => {
    const evil = findingOf('evil@1.0.0', { advisory: malware.advisory });
    const ghost = findingOf('ghost@1.0.0');
    const actions = [
      action('remove:apps/web:nice', 'remove', [{ kind: 'remove', package: 'evil', alias: 'nice', from: '1.0.0', root: 'apps/web' }], [evil]),
      action('unknown:ghost@1.0.0', 'unknown', [{ kind: 'unknown', package: 'ghost', from: '1.0.0', reason: 'npm registry GET ghost failed with HTTP 404' }], [ghost]),
    ];
    const text = formatReport(planned([evil, ghost], actions));
    expect(titles(text)).toEqual([
      '1. Remove nice 1.0.0 from apps/web/package.json: malicious, and no release is clean',
      '2. Could not plan ghost 1.0.0: npm registry GET ghost failed with HTTP 404',
    ]);
    expect(text).toContain('    1 finding: 1 malicious');
  });

  // The wrapper bump fixes lodash; evil-pkg has to go. malware was seen on an earlier scan.
  const withFix = (f: ScanFinding, kind: FixKind, actions: string[]): ScanFinding => ({ ...f, fix: { kind, actions } });
  const removeEvil = action('remove:.:evil-pkg', 'remove', [{ kind: 'remove', package: 'evil-pkg', from: '1.0.1', root: '.' }], [malware]);
  const bumpWrapper = action('bump:.:@demo/wrapper', 'bump', [bump('@demo/wrapper', '1.0.0', '1.1.0', 'minor')], [lodash]);
  const details = planned(
    [withFix(lodash, 'bump', ['bump:.:@demo/wrapper']), withFix(malware, 'remove', ['remove:.:evil-pkg'])],
    [removeEvil, bumpWrapper],
    { warnings: ['EPSS unavailable: EPSS lookup failed with HTTP 500'] },
  );

  it('lists every finding under the plan with details, each naming its actions', () => {
    expect(formatReport(details, { details: true })).toBe(
      [
        'demo-app: package-lock.json, 4 packages, 2 findings in 2 packages (1 new or updated)',
        '',
        'Fix plan: 2 actions, most urgent and cheapest first',
        '',
        '1. Remove evil-pkg 1.0.1 from package.json: malicious, and no release is clean',
        '    1 finding: 1 malicious',
        '',
        '2. Bump @demo/wrapper 1.0.0 -> 1.1.0 (minor) in package.json',
        '    1 finding: 1 high, 1 new or updated',
        '    fixes lodash 4.17.20',
        '',
        'Findings',
        '',
        'NEW      HIGH       GHSA-35jh-r3h4-6jhm (CVE-2021-23337)  lodash@4.17.20',
        '    Command Injection in lodash',
        '    transitive, runtime, fix: 4.17.21, KEV: no, EPSS: 0.01',
        '    via demo-app > @demo/wrapper@1.0.0 > lodash@4.17.20',
        '    plan: action 2',
        '',
        'SEEN     MALICIOUS  MAL-2026-1  evil-pkg@1.0.1',
        '    direct, runtime, fix: remove it or pin a clean version, KEV: unknown, EPSS: none',
        '    via demo-app > evil-pkg@1.0.1',
        '    plan: action 1',
        '',
        'warning: EPSS unavailable: EPSS lookup failed with HTTP 500',
      ].join('\n'),
    );
  });

  it('names every action a finding needs, and marks a package that needs more than one', () => {
    const next = findingOf('next@15.0.0', { fix: { kind: 'bump', actions: ['refresh', 'bump:.:next'] } });
    const actions = [
      action('refresh', 'refresh', [{ kind: 'refresh', package: 'postcss', from: '8.4.31', to: '8.4.32', direct: false }], [next], { partial: ['next@15.0.0'] }),
      action('bump:.:next', 'bump', [bump('next', '15.0.0', '15.2.3', 'minor')], [next], { partial: ['next@15.0.0'] }),
    ];
    const lines = formatReport(planned([next], actions), { details: true }).split('\n');
    expect(lines.filter((line) => line.includes('another action') || line.startsWith('    plan:') || line.startsWith('    fixes'))).toEqual([
      '    fixes next 15.0.0',
      '    also needs another action: next 15.0.0',
      '    also needs another action: next 15.0.0',
      '    plan: action 1 and 2',
    ]);
  });

  it('counts new or updated findings per action only when some finding was seen before', () => {
    const tallies = (r: ScanResult) => formatReport(r).split('\n').filter((line) => line.startsWith('    1 finding'));
    expect(tallies(details)).toEqual(['    1 finding: 1 malicious', '    1 finding: 1 high, 1 new or updated']);
    const allNew = planned(details.findings.map((f) => ({ ...f, status: 'new' as const })), details.fixPlan.actions);
    expect(tallies(allNew)).toEqual(['    1 finding: 1 malicious', '    1 finding: 1 high']);
  });
});
