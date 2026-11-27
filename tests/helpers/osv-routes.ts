import type { OsvVuln } from '../../src/watch/osv.js';
import type { Handler } from './fake-fetch.js';

/** Real lodash advisory, trimmed: CVE-2021-23337, command injection, fixed in 4.17.21. */
export const lodashInjection: OsvVuln = {
  id: 'GHSA-35jh-r3h4-6jhm',
  modified: '2026-10-17T02:55:38Z',
  summary: 'Command Injection in lodash',
  aliases: ['CVE-2021-23337'],
  database_specific: { severity: 'HIGH' },
  affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }],
};

export const withdrawnMs: OsvVuln = {
  id: 'GHSA-gone',
  modified: '2026-01-01T00:00:00Z',
  withdrawn: '2026-01-02T00:00:00Z',
  affected: [{ package: { ecosystem: 'npm', name: 'ms' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] }],
};

/**
 * OSV routes for a fake fetch: `affecting` maps "name@version" to advisory ids,
 * and every record in `records` can be fetched by id.
 */
export function osvRoutes(affecting: Record<string, string[]>, records: OsvVuln[]): Record<string, Handler> {
  const routes: Record<string, Handler> = {
    'POST https://api.osv.dev/v1/querybatch': (_url, init) => {
      const { queries } = JSON.parse(String(init?.body)) as { queries: { package: { name: string }; version: string }[] };
      return {
        results: queries.map((q) => {
          const ids = affecting[`${q.package.name}@${q.version}`] ?? [];
          return ids.length > 0 ? { vulns: ids.map((id) => ({ id })) } : {};
        }),
      };
    },
  };
  for (const record of records) routes[`GET https://api.osv.dev/v1/vulns/${record.id}`] = () => record;
  return routes;
}
