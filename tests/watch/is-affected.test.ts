import { describe, expect, it } from 'vitest';
import { isAffected } from '../../src/watch/advisory.js';
import type { OsvAffected, OsvEvent, OsvVuln } from '../../src/watch/osv.js';

const npm = (name: string) => ({ ecosystem: 'npm', name });

const record = (...affected: OsvAffected[]): OsvVuln => ({ id: 'GHSA-test', modified: '2026-11-01T00:00:00Z', affected });

/** One SEMVER range for npm package `name`. */
const semverRange = (name: string, ...events: OsvEvent[]): OsvAffected => ({ package: npm(name), ranges: [{ type: 'SEMVER', events }] });

/** The versions of `pkg` among `versions` that the record calls affected. */
const affectedOf = (vuln: OsvVuln, versions: string[], pkg = 'pkg') => versions.filter((v) => isAffected(vuln, pkg, v));

describe('isAffected', () => {
  it('matches listed versions exactly', () => {
    const vuln = record({ package: npm('pkg'), versions: ['1.0.1', '1.0.3'] });
    expect(affectedOf(vuln, ['1.0.0', '1.0.1', '1.0.2', '1.0.3'])).toEqual(['1.0.1', '1.0.3']);
  });

  it('covers a range from introduced up to, not including, fixed', () => {
    const vuln = record(semverRange('pkg', { introduced: '1.0.0' }, { fixed: '1.2.0' }));
    expect(affectedOf(vuln, ['0.9.9', '1.0.0', '1.1.9', '1.2.0', '2.0.0'])).toEqual(['1.0.0', '1.1.9']);
  });

  it('includes last_affected itself', () => {
    const vuln = record(semverRange('pkg', { introduced: '2.0.0' }, { last_affected: '2.3.0' }));
    expect(affectedOf(vuln, ['1.9.0', '2.0.0', '2.3.0', '2.3.1'])).toEqual(['2.0.0', '2.3.0']);
  });

  it('reads introduced "0" as every version, prereleases of 0.0.0 included', () => {
    const vuln = record(semverRange('pkg', { introduced: '0' }, { fixed: '4.17.21' }));
    expect(affectedOf(vuln, ['0.0.0-beta', '0.0.1', '4.17.20', '4.17.21', '5.0.0'])).toEqual(['0.0.0-beta', '0.0.1', '4.17.20']);
  });

  it('keeps a range with no fix open', () => {
    const vuln = record(semverRange('pkg', { introduced: '3.0.0' }));
    expect(affectedOf(vuln, ['2.9.9', '3.0.0', '99.0.0'])).toEqual(['3.0.0', '99.0.0']);
  });

  it('counts every range and every affected entry for the package', () => {
    const vuln = record(
      semverRange('pkg', { introduced: '1.0.0' }, { fixed: '1.0.5' }),
      { package: npm('pkg'), ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '2.0.0' }, { fixed: '2.0.2' }] }] },
    );
    expect(affectedOf(vuln, ['1.0.4', '1.0.5', '2.0.1', '2.0.2'])).toEqual(['1.0.4', '2.0.1']);
  });

  it('ignores GIT ranges', () => {
    const vuln = record({ package: npm('pkg'), ranges: [{ type: 'GIT', events: [{ introduced: '0' }] }] });
    expect(affectedOf(vuln, ['1.0.0'])).toEqual([]);
  });

  it('ignores other packages and other ecosystems in the record', () => {
    const vuln = record(
      semverRange('other', { introduced: '0' }),
      { package: { ecosystem: 'PyPI', name: 'pkg' }, versions: ['1.0.0'], ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }] }] },
      semverRange('pkg', { introduced: '5.0.0' }, { fixed: '5.0.1' }),
    );
    expect(affectedOf(vuln, ['1.0.0', '5.0.0'])).toEqual(['5.0.0']);
    expect(affectedOf(vuln, ['1.0.0'], 'other')).toEqual(['1.0.0']);
  });

  it('calls a version that is not strict semver unaffected', () => {
    const vuln = record({ ...semverRange('pkg', { introduced: '0' }), versions: ['1.0'] });
    expect(affectedOf(vuln, ['1.0', 'file:packages/ui', 'link:../cli', 'latest', ''])).toEqual([]);
  });

  it('is false for a record with no affected list', () => {
    expect(isAffected({ id: 'GHSA-empty', modified: 'm' }, 'pkg', '1.0.0')).toBe(false);
  });
});
