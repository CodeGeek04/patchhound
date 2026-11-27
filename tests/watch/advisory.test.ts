import { describe, expect, it } from 'vitest';
import type { Advisory } from '../../src/watch/advisory.js';
import { advisoryFingerprint, combineFingerprints, fixedVersionFor, mergeAdvisories, toAdvisory } from '../../src/watch/advisory.js';
import type { OsvVuln } from '../../src/watch/osv.js';

// Shape of the real record for CVE-2025-29927 (Next.js middleware bypass), trimmed.
const nextBypass: OsvVuln = {
  id: 'GHSA-f82v-jwr5-mffw',
  modified: '2025-09-10T00:00:00Z',
  published: '2025-03-21T15:20:12Z',
  summary: 'Authorization Bypass in Next.js Middleware',
  aliases: ['CVE-2025-29927'],
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N' }],
  database_specific: { severity: 'CRITICAL' },
  affected: [
    { package: { ecosystem: 'npm', name: 'next' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '13.0.0' }, { fixed: '13.5.9' }] }] },
    { package: { ecosystem: 'npm', name: 'next' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '14.0.0' }, { fixed: '14.2.25' }] }] },
    // Events out of order on purpose: OSV does not promise sorted events.
    { package: { ecosystem: 'npm', name: 'next' }, ranges: [{ type: 'SEMVER', events: [{ fixed: '15.2.3' }, { introduced: '15.0.0' }] }] },
    { package: { ecosystem: 'npm', name: 'next' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '11.1.4' }, { fixed: '12.3.5' }] }] },
  ],
};

describe('fixedVersionFor', () => {
  it('picks the fix on the installed release line', () => {
    expect(fixedVersionFor(nextBypass, 'next', '15.2.2')).toBe('15.2.3');
    expect(fixedVersionFor(nextBypass, 'next', '14.1.0')).toBe('14.2.25');
    expect(fixedVersionFor(nextBypass, 'next', '12.0.0')).toBe('12.3.5');
  });

  it('returns null when the installed version is not affected', () => {
    expect(fixedVersionFor(nextBypass, 'next', '15.2.3')).toBeNull();
  });

  it('ignores other packages', () => {
    expect(fixedVersionFor(nextBypass, 'react', '15.2.2')).toBeNull();
  });

  it('returns null when the range has no fix yet', () => {
    const unfixed: OsvVuln = {
      id: 'GHSA-x',
      modified: '2026-01-01T00:00:00Z',
      affected: [{ package: { ecosystem: 'npm', name: 'pkg' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { last_affected: '2.0.0' }] }] }],
    };
    expect(fixedVersionFor(unfixed, 'pkg', '1.5.0')).toBeNull();
  });
});

const npm = (name: string) => ({ ecosystem: 'npm', name });

describe('fixedVersionFor with overlapping ranges', () => {
  it('returns null when another range covering the version has no fix (GHSA-96x6-fvhx-49hg)', () => {
    // Real record, trimmed: nuxt 4.0.0 is in [4.0.0, 4.6.4) and in an open-ended range from 3.0.0.
    const nuxt: OsvVuln = {
      id: 'GHSA-96x6-fvhx-49hg',
      modified: '2026-11-16T15:15:03.553381168Z',
      affected: [
        { package: npm('nuxt'), ranges: [{ type: 'SEMVER', events: [{ introduced: '4.0.0' }, { fixed: '4.6.4' }] }] },
        { package: npm('nuxt'), ranges: [{ type: 'SEMVER', events: [{ introduced: '3.0.0' }] }] },
      ],
    };
    expect(fixedVersionFor(nuxt, 'nuxt', '4.0.0')).toBeNull();
  });

  it('jumps past a fix that another range still covers', () => {
    const chained: OsvVuln = {
      id: 'GHSA-x',
      modified: 'm',
      affected: [
        { package: npm('pkg'), ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }] }] },
        { package: npm('pkg'), ranges: [{ type: 'SEMVER', events: [{ introduced: '1.5.0' }, { fixed: '2.5.0' }] }] },
        { package: npm('pkg'), ranges: [{ type: 'SEMVER', events: [{ introduced: '2.5.0' }, { fixed: '3.0.0' }] }] },
      ],
    };
    // 2.0.0 is still in [1.5.0, 2.5.0), and 2.5.0 opens the next range.
    expect(fixedVersionFor(chained, 'pkg', '1.2.0')).toBe('3.0.0');
    expect(fixedVersionFor(chained, 'pkg', '1.6.0')).toBe('3.0.0');
    expect(fixedVersionFor(chained, 'pkg', '2.6.0')).toBe('3.0.0');
  });
});

describe('fixedVersionFor with versions that are not strict semver', () => {
  it('reads "13.0" as 13.0.0 (GHSA-3h52-269p-cp9r)', () => {
    const nextRecord: OsvVuln = {
      id: 'GHSA-3h52-269p-cp9r',
      modified: '2026-09-10T03:49:36.489791181Z',
      affected: [
        { package: npm('next'), ranges: [{ type: 'SEMVER', events: [{ introduced: '15.0.0' }, { fixed: '15.2.2' }] }] },
        { package: npm('next'), ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '13.0' }, { fixed: '14.2.30' }] }] },
      ],
    };
    expect(fixedVersionFor(nextRecord, 'next', '14.2.29')).toBe('14.2.30');
    expect(fixedVersionFor(nextRecord, 'next', '13.0.0')).toBe('14.2.30');
    expect(fixedVersionFor(nextRecord, 'next', '15.1.0')).toBe('15.2.2');
  });

  it('reads "1.90" as 1.90.0 (GHSA-8m45-2rjm-j347)', () => {
    const solana: OsvVuln = {
      id: 'GHSA-8m45-2rjm-j347',
      modified: '2026-09-10T03:50:12.722446210Z',
      affected: [
        { package: npm('@solana/web3.js'), ranges: [{ type: 'SEMVER', events: [{ introduced: '1.91.0' }, { fixed: '1.91.3' }] }] },
        { package: npm('@solana/web3.js'), ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '1.90' }, { fixed: '1.90.2' }] }] },
        { package: npm('@solana/web3.js'), ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '1.89' }, { fixed: '1.89.2' }] }] },
      ],
    };
    expect(fixedVersionFor(solana, '@solana/web3.js', '1.90.0')).toBe('1.90.2');
    expect(fixedVersionFor(solana, '@solana/web3.js', '1.89.1')).toBe('1.89.2');
  });

  it('reads "9.11" as 9.11.0 (GHSA-jgf4-vwc3-r46v)', () => {
    const directus: OsvVuln = {
      id: 'GHSA-jgf4-vwc3-r46v',
      modified: '2026-09-10T03:50:16.747407652Z',
      affected: [{ package: npm('directus'), ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '9.11' }, { fixed: '10.13.0' }] }] }],
    };
    expect(fixedVersionFor(directus, 'directus', '10.0.0')).toBe('10.13.0');
  });
});

describe('fixedVersionFor with two introduced events before one fix', () => {
  it('finds the fix for the earlier introduced version (MAL-2026-3463)', () => {
    const tanstack: OsvVuln = {
      id: 'MAL-2026-3463',
      modified: '2026-05-13T00:48:31.813014Z',
      affected: [
        {
          package: npm('@tanstack/history'),
          ranges: [{ type: 'SEMVER', events: [{ introduced: '1.161.12' }, { fixed: '1.161.13' }, { introduced: '1.161.9' }, { fixed: '1.161.13' }] }],
          versions: ['1.161.12', '1.161.9'],
        },
      ],
    };
    expect(fixedVersionFor(tanstack, '@tanstack/history', '1.161.9')).toBe('1.161.13');
    expect(fixedVersionFor(tanstack, '@tanstack/history', '1.161.10')).toBe('1.161.13');
    expect(fixedVersionFor(tanstack, '@tanstack/history', '1.161.12')).toBe('1.161.13');
  });
});

describe('fixedVersionFor edge cases', () => {
  it('treats a version where one range is fixed and the next introduced as affected, in any event order', () => {
    const adjacent = (events: OsvVuln['affected']) => ({ id: 'GHSA-x', modified: 'm', affected: events }) as OsvVuln;
    const inOrder = adjacent([
      { package: npm('pkg'), ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }, { introduced: '2.0.0' }, { fixed: '3.0.0' }] }] },
    ]);
    const shuffled = adjacent([
      { package: npm('pkg'), ranges: [{ type: 'SEMVER', events: [{ introduced: '2.0.0' }, { fixed: '3.0.0' }, { introduced: '1.0.0' }, { fixed: '2.0.0' }] }] },
    ]);
    for (const record of [inOrder, shuffled]) {
      expect(fixedVersionFor(record, 'pkg', '1.5.0')).toBe('3.0.0');
      expect(fixedVersionFor(record, 'pkg', '2.0.0')).toBe('3.0.0');
    }
  });

  it('reads introduced and last_affected at the same version as that version only', () => {
    // Real shape: MAL-2025-47143 for @ctrl/transmission is [{introduced: 7.3.1}, {last_affected: 7.3.1}].
    const single: OsvVuln = {
      id: 'MAL-x',
      modified: 'm',
      affected: [
        { package: npm('pkg'), ranges: [{ type: 'SEMVER', events: [{ introduced: '7.3.1' }, { last_affected: '7.3.1' }] }] },
        { package: npm('pkg'), ranges: [{ type: 'SEMVER', events: [{ introduced: '7.3.2' }, { fixed: '7.3.5' }] }] },
      ],
    };
    // A last_affected range names no fix.
    expect(fixedVersionFor(single, 'pkg', '7.3.1')).toBeNull();
    // 7.3.2 is past the single-version range, so only the second range applies.
    expect(fixedVersionFor(single, 'pkg', '7.3.2')).toBe('7.3.5');
  });

  it('handles prerelease installed versions', () => {
    // Real shape: GHSA-9qr9-h5gf-34mp has ranges that start at canaries.
    const canary: OsvVuln = {
      id: 'GHSA-9qr9-h5gf-34mp',
      modified: 'm',
      affected: [
        { package: npm('next'), ranges: [{ type: 'SEMVER', events: [{ introduced: '14.3.0-canary.77' }, { fixed: '15.0.5' }] }] },
        { package: npm('next'), ranges: [{ type: 'SEMVER', events: [{ introduced: '15.2.0-canary.0' }, { fixed: '15.2.6' }] }] },
      ],
    };
    expect(fixedVersionFor(canary, 'next', '15.0.0-canary.100')).toBe('15.0.5');
    expect(fixedVersionFor(canary, 'next', '15.2.0-canary.10')).toBe('15.2.6');
    expect(fixedVersionFor(canary, 'next', '15.2.6-canary.1')).toBe('15.2.6');
    expect(fixedVersionFor(canary, 'next', '14.3.0-canary.76')).toBeNull();

    const fromZero: OsvVuln = {
      id: 'GHSA-y',
      modified: 'm',
      affected: [{ package: npm('pkg'), ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.0' }] }] }],
    };
    expect(fixedVersionFor(fromZero, 'pkg', '0.0.0-alpha.1')).toBe('1.0.0');
  });

  it('returns null for a package listed only by version', () => {
    // Real shape: MAL-2025-46974 lists debug 4.4.2 with no ranges.
    const listedOnly: OsvVuln = { id: 'MAL-2025-46974', modified: 'm', affected: [{ package: npm('debug'), versions: ['4.4.2'] }] };
    expect(fixedVersionFor(listedOnly, 'debug', '4.4.2')).toBeNull();
  });

  it('returns null when the fix a range names is itself listed as affected', () => {
    const relisted: OsvVuln = {
      id: 'GHSA-z',
      modified: 'm',
      affected: [{ package: npm('pkg'), ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.0.1' }] }], versions: ['1.0.0', '1.0.1'] }],
    };
    expect(fixedVersionFor(relisted, 'pkg', '1.0.0')).toBeNull();
  });
});

describe('toAdvisory', () => {
  it('keeps what triage and reports need', () => {
    expect(toAdvisory(nextBypass)).toEqual({
      id: 'GHSA-f82v-jwr5-mffw',
      kind: 'vulnerability',
      summary: 'Authorization Bypass in Next.js Middleware',
      aliases: ['CVE-2025-29927'],
      cves: ['CVE-2025-29927'],
      linkedCves: [],
      related: [],
      severity: 'CRITICAL',
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
      published: '2025-03-21T15:20:12Z',
      modified: '2025-09-10T00:00:00Z',
    });
  });

  it('collects CVEs the advisory only links to', () => {
    // Real shape: Next.js's React flight RCE has no CVE alias; its NVD reference names CVE-2025-55182.
    const advisory = toAdvisory({
      id: 'GHSA-9qr9-h5gf-34mp',
      modified: '2026-01-01T00:00:00Z',
      related: ['CVE-2025-71389'],
      references: [
        { type: 'ADVISORY', url: 'https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp' },
        { type: 'WEB', url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-55182' },
      ],
    });
    expect(advisory.cves).toEqual([]);
    expect(advisory.linkedCves).toEqual(['CVE-2025-55182']);
  });

  it('keeps related ids for display but does not treat them as linked CVEs', () => {
    // CVE-2025-54073 belongs to mcp-package-docs but sits in `related` for other packages' advisories.
    const advisory = toAdvisory({ id: 'GHSA-r', modified: 'm', related: ['CVE-2025-54073', 'GHSA-other'] });
    expect(advisory.linkedCves).toEqual([]);
    expect(advisory.related).toEqual(['CVE-2025-54073', 'GHSA-other']);
  });

  it('reads NVD links in any case and upper-cases the CVE', () => {
    const advisory = toAdvisory({
      id: 'GHSA-l',
      modified: 'm',
      references: [
        { type: 'WEB', url: 'https://nvd.nist.gov/vuln/detail/cve-2024-1234' },
        { type: 'WEB', url: 'HTTPS://NVD.NIST.GOV/vuln/detail/CVE-2024-1234' },
      ],
    });
    expect(advisory.linkedCves).toEqual(['CVE-2024-1234']);
  });

  it('does not link an NVD reference to the advisory\'s own CVE', () => {
    const advisory = toAdvisory({
      id: 'GHSA-own',
      modified: 'm',
      aliases: ['CVE-2021-23337'],
      references: [{ type: 'ADVISORY', url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337' }],
    });
    expect(advisory.cves).toEqual(['CVE-2021-23337']);
    expect(advisory.linkedCves).toEqual([]);
  });

  it('marks GHSAs for embedded malicious code (CWE-506) as malicious packages', () => {
    // Real record, trimmed: the 2018 event-stream compromise.
    const eventStream = toAdvisory({
      id: 'GHSA-mh6f-8j2x-4483',
      modified: '2021-09-15T20:08:26Z',
      summary: 'Critical severity vulnerability that affects event-stream and flatmap-stream',
      database_specific: { severity: 'CRITICAL', cwe_ids: ['CWE-506'] },
    });
    expect(eventStream.kind).toBe('malicious');
    // ua-parser-js 0.7.29 (GHSA-pjwm-rvh2-c87w) lists CWE-506 with another CWE.
    const uaParser = toAdvisory({ id: 'GHSA-pjwm-rvh2-c87w', modified: 'm', database_specific: { cwe_ids: ['CWE-506', 'CWE-912'] } });
    expect(uaParser.kind).toBe('malicious');
  });

  it('marks a record with a MAL- alias as malicious', () => {
    const advisory = toAdvisory({ id: 'GHSA-4x49-vf9v-38px', modified: 'm', aliases: ['CVE-2025-59144', 'MAL-2025-46974'] });
    expect(advisory.kind).toBe('malicious');
  });

  it('keeps other CWEs as vulnerabilities', () => {
    expect(toAdvisory({ id: 'GHSA-v', modified: 'm', database_specific: { cwe_ids: ['CWE-79'] } }).kind).toBe('vulnerability');
  });

  it('marks MAL- records as malicious packages', () => {
    const advisory = toAdvisory({ id: 'MAL-2026-20205', modified: '2026-11-19T07:30:05Z', summary: 'Malicious code in some-pkg (npm)' });
    expect(advisory.kind).toBe('malicious');
    expect(advisory.severity).toBe('UNKNOWN');
  });
});

describe('advisoryFingerprint', () => {
  const base: OsvVuln = {
    id: 'GHSA-35jh-r3h4-6jhm',
    modified: '2026-10-17T02:55:38Z',
    summary: 'Command Injection in lodash',
    details: '`template` is vulnerable to command injection.',
    aliases: ['CVE-2021-23337', 'SNYK-JS-LODASH-1040724'],
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' }],
    database_specific: { severity: 'HIGH' },
    affected: [
      { package: npm('lodash'), ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] },
      { package: npm('lodash-es'), ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] },
    ],
  };
  const fingerprint = advisoryFingerprint(base, 'lodash');

  it('is a sha256 hex digest', () => {
    expect(fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it('ignores a new modified time when nothing else changed', () => {
    // OSV re-stamped 14% of npm GHSA records within one hour without changing their content.
    expect(advisoryFingerprint({ ...base, modified: '2026-11-19T09:00:00Z' }, 'lodash')).toBe(fingerprint);
  });

  it('ignores the order of aliases, ranges and events', () => {
    const shuffled: OsvVuln = {
      ...base,
      aliases: ['SNYK-JS-LODASH-1040724', 'CVE-2021-23337'],
      affected: [
        base.affected![1]!,
        { package: npm('lodash'), ranges: [{ type: 'SEMVER', events: [{ fixed: '4.17.21' }, { introduced: '0' }] }] },
      ],
    };
    expect(advisoryFingerprint(shuffled, 'lodash')).toBe(fingerprint);
  });

  it('ignores other packages in the record', () => {
    const otherPackageChanged: OsvVuln = {
      ...base,
      affected: [base.affected![0]!, { package: npm('lodash-es'), versions: ['4.17.20'] }],
    };
    expect(advisoryFingerprint(otherPackageChanged, 'lodash')).toBe(fingerprint);
  });

  it('changes with what triage reads', () => {
    const changes: OsvVuln[] = [
      { ...base, summary: 'Command injection in lodash template' },
      { ...base, details: 'More details.' },
      { ...base, database_specific: { severity: 'CRITICAL' } },
      { ...base, severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] },
      { ...base, aliases: [...base.aliases!, 'MAL-2026-1'] },
      { ...base, affected: [{ package: npm('lodash'), ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.22' }] }] }] },
      { ...base, affected: [{ ...base.affected![0]!, versions: ['4.17.20'] }] },
      { ...base, database_specific: { severity: 'HIGH', cwe_ids: ['CWE-506'] } },
    ];
    const prints = changes.map((record) => advisoryFingerprint(record, 'lodash'));
    for (const print of prints) expect(print).not.toBe(fingerprint);
    expect(new Set(prints).size).toBe(changes.length);
  });
});

describe('mergeAdvisories', () => {
  const advisory = (fields: Partial<Advisory> & { id: string }): Advisory => ({
    kind: 'vulnerability',
    summary: '',
    aliases: [],
    cves: [],
    linkedCves: [],
    related: [],
    severity: 'UNKNOWN',
    modified: '2026-01-01T00:00:00Z',
    ...fields,
  });

  it('returns a lone advisory unchanged', () => {
    const only = advisory({ id: 'GHSA-1', summary: 'one' });
    expect(mergeAdvisories([only])).toBe(only);
  });

  it('merges a GHSA and its MAL- twin under the GHSA id', () => {
    // Real pair, trimmed: debug@4.4.2 matches both GHSA-4x49-vf9v-38px and MAL-2025-46974.
    const mal = advisory({
      id: 'MAL-2025-46974',
      kind: 'malicious',
      summary: 'Malicious code in debug (npm)',
      aliases: ['CVE-2025-59144', 'GHSA-4x49-vf9v-38px', 'GHSA-8mgj-vmr8-frr6'],
      cves: ['CVE-2025-59144'],
      published: '2025-09-08T14:26:51Z',
      modified: '2025-09-16T06:44:36.384185Z',
    });
    const ghsa = advisory({
      id: 'GHSA-4x49-vf9v-38px',
      summary: 'debug@4.4.2 contains malware after npm account takeover',
      aliases: ['CVE-2025-59144', 'GHSA-8mgj-vmr8-frr6'],
      cves: ['CVE-2025-59144'],
      linkedCves: [],
      related: ['GHSA-other'],
      severity: 'HIGH',
      cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N/E:A/U:Red',
      published: '2025-09-15T21:30:55Z',
      modified: '2025-09-16T06:44:36Z',
    });
    expect(mergeAdvisories([mal, ghsa])).toEqual({
      id: 'GHSA-4x49-vf9v-38px',
      kind: 'malicious',
      summary: 'debug@4.4.2 contains malware after npm account takeover',
      aliases: ['CVE-2025-59144', 'GHSA-8mgj-vmr8-frr6', 'MAL-2025-46974'],
      cves: ['CVE-2025-59144'],
      linkedCves: [],
      related: ['GHSA-other'],
      severity: 'HIGH',
      cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N/E:A/U:Red',
      published: '2025-09-08T14:26:51Z',
      modified: '2025-09-16T06:44:36.384185Z',
    });
  });

  it('picks the lowest GHSA id, else the lowest id, and the highest severity', () => {
    const a = advisory({ id: 'GHSA-b', severity: 'LOW', summary: 'b' });
    const b = advisory({ id: 'GHSA-a', severity: 'MODERATE', summary: 'a' });
    const c = advisory({ id: 'EEF-CVE-2026-1', severity: 'CRITICAL', summary: 'eef' });
    expect(mergeAdvisories([a, c, b])).toMatchObject({ id: 'GHSA-a', summary: 'a', severity: 'CRITICAL' });
    expect(mergeAdvisories([advisory({ id: 'MAL-2' }), advisory({ id: 'MAL-1' })]).id).toBe('MAL-1');
  });

  it('keeps linked CVEs that are not a member\'s own CVE', () => {
    const own = advisory({ id: 'GHSA-a', cves: ['CVE-1'], linkedCves: ['CVE-3'] });
    const other = advisory({ id: 'GHSA-b', aliases: ['GHSA-a'], linkedCves: ['CVE-1', 'CVE-2'] });
    expect(mergeAdvisories([own, other])).toMatchObject({ cves: ['CVE-1'], linkedCves: ['CVE-3', 'CVE-2'] });
  });

  it('refuses an empty group', () => {
    expect(() => mergeAdvisories([])).toThrow(RangeError);
  });
});

describe('combineFingerprints', () => {
  it('keeps a lone fingerprint and combines several in any order', () => {
    expect(combineFingerprints(['aa'])).toBe('aa');
    const both = combineFingerprints(['aa', 'bb']);
    expect(both).toMatch(/^[0-9a-f]{64}$/);
    expect(combineFingerprints(['bb', 'aa'])).toBe(both);
    expect(combineFingerprints(['aa', 'cc'])).not.toBe(both);
  });
});
