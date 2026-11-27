import { describe, expect, it } from 'vitest';
import type { Config } from '../src/config.js';
import { DEFAULT_CONFIG } from '../src/config.js';
import { atOrAbove, decide } from '../src/policy.js';
import type { Triage } from '../src/triage/triage.js';
import { evidence } from './helpers/findings.js';

const triaged = (overrides: Partial<Triage> = {}): Triage => ({
  reachable: 'unknown',
  reachableP: null,
  exposure: 'internet-facing',
  dropIn: 'unknown',
  urgency: null,
  reason: '',
  source: 'jev',
  jev: null,
  claude: null,
  ...overrides,
});

const config = (overrides: Partial<Config> = {}): Config => ({ ...DEFAULT_CONFIG, ...overrides });

describe('decide', () => {
  it('always notifies for malware and KEV, whatever triage says', () => {
    const no = triaged({ reachable: 'no' });
    expect(decide(evidence({ kind: 'malicious' }), no, config())).toMatchObject({ outcome: 'notify', rule: 'malware' });
    expect(decide(evidence({ kev: true, severity: 'LOW', devOnly: true }), no, config())).toMatchObject({ outcome: 'notify', rule: 'kev' });
  });

  it('judges a critical finding like any other, unless notify.always adds critical', () => {
    const critical = evidence({ severity: 'CRITICAL' });
    expect(decide(critical, triaged({ reachable: 'no' }), config())).toMatchObject({ outcome: 'digest', rule: 'not-reachable' });
    expect(decide(critical, triaged(), config())).toMatchObject({ outcome: 'notify', rule: 'reachability-unknown' });
    const floor = config({ notify: { ...DEFAULT_CONFIG.notify, always: ['kev', 'critical'] } });
    expect(decide(critical, triaged({ reachable: 'no' }), floor)).toMatchObject({ outcome: 'notify', rule: 'critical' });
    expect(decide(evidence({ severity: 'CRITICAL', devOnly: true }), triaged({ reachable: 'no' }), floor)).toMatchObject({ outcome: 'digest', rule: 'dev-only' });
  });

  it('puts dev-only (from the lockfile), below-threshold and unreachable findings in the digest', () => {
    expect(decide(evidence({ devOnly: true }), triaged({ reachable: 'no' }), config())).toMatchObject({ outcome: 'digest', rule: 'dev-only' });
    expect(decide(evidence({ severity: 'MODERATE' }), triaged({ reachable: 'yes' }), config())).toMatchObject({ outcome: 'digest', rule: 'below-threshold' });
    expect(decide(evidence(), triaged({ reachable: 'no' }), config())).toMatchObject({ outcome: 'digest', rule: 'not-reachable' });
    expect(decide(evidence(), triaged({ exposure: 'build/dev-only' }), config())).toMatchObject({ outcome: 'digest', rule: 'build-only-use' });
  });

  it('notifies at or above the threshold when reachable or unknown', () => {
    expect(decide(evidence(), triaged({ reachable: 'yes' }), config())).toMatchObject({ outcome: 'notify', rule: 'reachable' });
    expect(decide(evidence(), triaged(), config())).toMatchObject({ outcome: 'notify', rule: 'reachability-unknown' });
    const low = config({ notify: { ...DEFAULT_CONFIG.notify, threshold: 'moderate' } });
    expect(decide(evidence({ severity: 'MODERATE' }), triaged({ reachable: 'yes' }), low)).toMatchObject({ outcome: 'notify' });
  });

  it('lists the tiers whose conditions hold, with whether the config turns each on, and none when paused', () => {
    const yes = triaged({ reachable: 'yes', dropIn: 'yes' });
    expect(decide(evidence({ kev: true }), yes, config()).wouldDo).toEqual([
      { tier: 'fix-pr', enabled: true },
      { tier: 'auto-merge', enabled: false },
    ]);
    expect(decide(evidence({ kev: true, fix: { kind: 'no-fix', actions: [] } }), yes, config()).wouldDo).toEqual([{ tier: 'containment', enabled: false }]);
    expect(decide(evidence(), triaged({ reachable: 'no' }), config()).wouldDo).toEqual([]);
    expect(decide(evidence({ kev: true }), yes, config({ paused: true })).wouldDo).toEqual([]);
  });
});

describe('atOrAbove', () => {
  it('compares a severity with the threshold, counting an unknown severity as moderate', () => {
    expect(atOrAbove('HIGH', 'high')).toBe(true);
    expect(atOrAbove('MODERATE', 'high')).toBe(false);
    expect(atOrAbove('UNKNOWN', 'moderate')).toBe(true);
    expect(atOrAbove('LOW', 'critical')).toBe(false);
  });
});
