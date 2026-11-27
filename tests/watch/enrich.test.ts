import { describe, expect, it } from 'vitest';
import { fetchEpss, fetchKev } from '../../src/watch/enrich.js';
import { fakeFetch } from '../helpers/fake-fetch.js';

const KEV = 'GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS = 'GET https://api.first.org/data/v1/epss';
const NO_WAIT = { sleep: async () => {} };

describe('fetchKev', () => {
  it('returns the CVE ids in the catalog', async () => {
    const { fetch } = fakeFetch({
      [KEV]: () => ({ count: 2, vulnerabilities: [{ cveID: 'CVE-2025-55182' }, { cveID: 'CVE-2021-44228' }] }),
    });
    expect(await fetchKev(fetch)).toEqual(new Set(['CVE-2025-55182', 'CVE-2021-44228']));
  });

  it('throws when the feed is down, after retrying', async () => {
    const fake = fakeFetch({ [KEV]: () => new Response('down', { status: 503 }) });
    await expect(fetchKev(fake.fetch, NO_WAIT)).rejects.toThrow('KEV download failed with HTTP 503 after 4 attempts: down');
    expect(fake.calls).toHaveLength(4);
  });

  it('says so when the feed is not the catalog', async () => {
    for (const body of [{}, { vulnerabilities: 'none' }, { vulnerabilities: [{ cve: 'CVE-2025-55182' }] }]) {
      const { fetch } = fakeFetch({ [KEV]: () => body });
      await expect(fetchKev(fetch, NO_WAIT)).rejects.toThrow('KEV download returned an unexpected body: no "vulnerabilities" list with a cveID in each entry');
    }
  });

  it('retries a feed that fails once', async () => {
    let calls = 0;
    const { fetch } = fakeFetch({
      [KEV]: () => (++calls === 1 ? new Response('busy', { status: 502 }) : { vulnerabilities: [{ cveID: 'CVE-2025-55182' }] }),
    });
    expect(await fetchKev(fetch, NO_WAIT)).toEqual(new Set(['CVE-2025-55182']));
  });
});

describe('fetchEpss', () => {
  it('throws when EPSS holds back rows', async () => {
    // EPSS pages its answer; a page that is not the whole answer would drop scores silently.
    const { fetch } = fakeFetch({
      [EPSS]: () => ({ status: 'OK', total: 2, offset: 0, limit: 1, data: [{ cve: 'CVE-2021-23337', epss: '0.01' }] }),
    });
    await expect(fetchEpss(['CVE-2021-23337', 'CVE-2025-55182'], fetch, NO_WAIT)).rejects.toThrow('EPSS lookup returned 1 of 2 rows');
  });

  it('says so when the answer has no data list', async () => {
    const { fetch } = fakeFetch({ [EPSS]: () => ({ status: 'OK' }) });
    await expect(fetchEpss(['CVE-2021-23337'], fetch, NO_WAIT)).rejects.toThrow('EPSS lookup returned an unexpected body: no "data" list');
  });

  it('makes no request for no CVEs', async () => {
    const fake = fakeFetch({});
    expect(await fetchEpss([], fake.fetch)).toEqual(new Map());
    expect(fake.calls).toEqual([]);
  });
  it('throws on an HTTP error, after retrying', async () => {
    const fake = fakeFetch({ [EPSS]: () => new Response('{"status":"error"}', { status: 500 }) });
    await expect(fetchEpss(['CVE-2021-23337'], fake.fetch, NO_WAIT)).rejects.toThrow(
      'EPSS lookup failed with HTTP 500 after 4 attempts: {"status":"error"}',
    );
    expect(fake.calls).toHaveLength(4);
  });

  it('parses scores and batches 50 CVEs per request', async () => {
    const asked: string[][] = [];
    const fake = fakeFetch({
      [EPSS]: (url) => {
        const cves = url.searchParams.get('cve')!.split(',');
        asked.push(cves);
        return { status: 'OK', data: cves.map((cve) => ({ cve, epss: '0.5', percentile: '0.9' })) };
      },
    });
    const cves = Array.from({ length: 51 }, (_, i) => `CVE-2025-${1000 + i}`);
    const scores = await fetchEpss([...cves, cves[0]!], fake.fetch);
    expect(asked.map((batch) => batch.length)).toEqual([50, 1]);
    expect(scores.get('CVE-2025-1000')).toBe(0.5);
    expect(scores.size).toBe(51);
  });
});
