import type { Evidence } from '../../src/evidence/evidence.js';
import type { ScanFinding, ScanResult } from '../../src/scan.js';

/** A scan finding with every field set; `overrides` replaces any of them. */
export function finding(overrides: Partial<ScanFinding> & { severity?: ScanFinding['advisory']['severity']; id?: string } = {}): ScanFinding {
  const { severity = 'HIGH', id = 'GHSA-35jh-r3h4-6jhm', ...rest } = overrides;
  const pkg = rest.package ?? 'lodash';
  const version = rest.version ?? '4.17.20';
  return {
    advisory: {
      id,
      kind: 'vulnerability',
      summary: 'Command Injection in lodash',
      aliases: ['CVE-2021-23337'],
      cves: ['CVE-2021-23337'],
      linkedCves: [],
      related: [],
      severity,
      modified: '2026-10-17T02:55:38Z',
    },
    advisoryFingerprint: 'fingerprint',
    package: pkg,
    version,
    direct: true,
    devOnly: false,
    paths: [['demo-app', `${pkg}@${version}`]],
    via: [pkg],
    fixedVersion: '4.17.21',
    records: [id],
    key: `${id}|${pkg}@${version}`,
    status: 'new',
    changed: [],
    kev: [],
    fix: { kind: 'refresh', actions: ['a1'] },
    epss: 0.01,
    ...rest,
  };
}

/** An evidence record with every field set. */
export function evidence(overrides: Partial<Evidence> & { severity?: Evidence['advisory']['severity']; kev?: boolean; kind?: Evidence['advisory']['kind'] } = {}): Evidence {
  const { severity = 'HIGH', kev = false, kind = 'vulnerability', ...rest } = overrides;
  return {
    key: 'GHSA-35jh-r3h4-6jhm|lodash@4.17.20',
    package: 'lodash',
    version: '4.17.20',
    advisory: {
      id: 'GHSA-35jh-r3h4-6jhm',
      aliases: ['CVE-2021-23337'],
      kind,
      severity,
      cvssVector: null,
      kev,
      epss: null,
      summary: 'Command Injection in lodash',
      fixedVersion: '4.17.21',
    },
    direct: true,
    devOnly: false,
    via: ['lodash'],
    paths: ['demo-app > lodash@4.17.20'],
    exposure: 'internet-facing',
    framework: { next: false, appRouter: false },
    usage: { sites: [], siteCount: 0, fileCount: 0, runtimes: [], calls: [], uses: [], unreadFiles: 0, truncated: false },
    mentioned: ['template'],
    fix: { kind: 'refresh', actions: ['a1'] },
    hash: 'hash-1',
    ...rest,
  };
}

/** A scan result around the given findings. */
export function scanResult(findings: ScanFinding[], overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    schemaVersion: 1,
    scannedAt: '2026-11-21T10:00:00.000Z',
    project: 'demo-app',
    lockfile: 'package-lock.json',
    manager: 'npm',
    workspaces: [],
    packageCount: 10,
    findings,
    enrichment: { kev: 'ok', epss: 'ok' },
    fixPlan: { status: 'ok', actions: [], brokenPeers: [] },
    warnings: [],
    ...overrides,
  };
}
