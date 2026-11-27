import { describe, expect, it } from 'vitest';
import { OsvClient } from '../../src/watch/osv.js';
import { fakeFetch } from '../helpers/fake-fetch.js';

const BATCH = 'POST https://api.osv.dev/v1/querybatch';
const NO_WAIT = { sleep: async () => {} };
const QUERY = 'POST https://api.osv.dev/v1/query';

type Query = { package: { name: string }; version: string; page_token?: string };
const queriesOf = (init: RequestInit | undefined) => (JSON.parse(String(init?.body)) as { queries: Query[] }).queries;

describe('OsvClient.queryBatch', () => {
  it('returns advisory ids per package, in input order', async () => {
    const { fetch } = fakeFetch({
      [BATCH]: () => ({ results: [{ vulns: [{ id: 'GHSA-1' }, { id: 'GHSA-2' }] }, {}] }),
    });
    const ids = await new OsvClient({ fetch }).queryBatch([
      { name: 'lodash', version: '4.17.20' },
      { name: 'ms', version: '2.1.2' },
    ]);
    expect(ids).toEqual([['GHSA-1', 'GHSA-2'], []]);
  });

  it('sends at most 1000 queries per request', async () => {
    const sizes: number[] = [];
    const { fetch } = fakeFetch({
      [BATCH]: (_url, init) => {
        const queries = queriesOf(init);
        sizes.push(queries.length);
        return { results: queries.map(() => ({})) };
      },
    });
    const packages = Array.from({ length: 1001 }, (_, i) => ({ name: `pkg-${i}`, version: '1.0.0' }));
    const ids = await new OsvClient({ fetch }).queryBatch(packages);
    expect(sizes).toEqual([1000, 1]);
    expect(ids).toHaveLength(1001);
  });

  it('throws when OSV answers fewer results than it was asked', async () => {
    // A short answer used to read as "no advisories" for the packages at the end.
    const { fetch } = fakeFetch({ [BATCH]: () => ({ results: [{ vulns: [{ id: 'GHSA-1' }] }] }) });
    await expect(
      new OsvClient({ fetch }).queryBatch([
        { name: 'lodash', version: '4.17.20' },
        { name: 'ms', version: '2.1.2' },
      ]),
    ).rejects.toThrow('OSV querybatch returned 1 results for 2 queries');
  });

  it('throws when querybatch has no results list', async () => {
    const { fetch } = fakeFetch({ [BATCH]: () => ({}) });
    await expect(new OsvClient({ fetch }).queryBatch([{ name: 'ms', version: '2.1.2' }])).rejects.toThrow(
      'OSV querybatch returned no results list for 1 queries',
    );
  });

  it('follows next_page_token for a package with many advisories', async () => {
    const { fetch } = fakeFetch({
      [BATCH]: () => ({ results: [{ vulns: [{ id: 'GHSA-1' }], next_page_token: 'page-2' }] }),
      [QUERY]: (_url, init) => {
        const body = JSON.parse(String(init?.body)) as Query;
        expect(body).toMatchObject({ package: { name: 'next' }, version: '13.0.0', page_token: 'page-2' });
        return { vulns: [{ id: 'GHSA-2' }] };
      },
    });
    const ids = await new OsvClient({ fetch }).queryBatch([{ name: 'next', version: '13.0.0' }]);
    expect(ids).toEqual([['GHSA-1', 'GHSA-2']]);
  });
});

describe('OsvClient.queryBatch paging past the first chunk', () => {
  it('pages for the right package in a later chunk', async () => {
    const packages = Array.from({ length: 1003 }, (_, i) => ({ name: `pkg-${i}`, version: '1.0.0' }));
    const { fetch } = fakeFetch({
      [BATCH]: (_url, init) => ({
        results: queriesOf(init).map((q) => (q.package.name === 'pkg-1001' ? { vulns: [{ id: 'GHSA-1' }], next_page_token: 't' } : {})),
      }),
      [QUERY]: (_url, init) => {
        expect(JSON.parse(String(init?.body))).toMatchObject({ package: { name: 'pkg-1001' }, page_token: 't' });
        return { vulns: [{ id: 'GHSA-2' }] };
      },
    });
    const ids = await new OsvClient({ fetch }).queryBatch(packages);
    expect(ids[1001]).toEqual(['GHSA-1', 'GHSA-2']);
    expect(ids.filter((list) => list.length > 0)).toHaveLength(1);
  });
});

describe('OsvClient retries', () => {
  it('fails after the retries when querybatch keeps failing', async () => {
    const fake = fakeFetch({ [BATCH]: () => new Response('overloaded', { status: 503 }) });
    await expect(new OsvClient({ fetch: fake.fetch, retry: NO_WAIT }).queryBatch([{ name: 'x', version: '1.0.0' }])).rejects.toThrow(
      'OSV POST /v1/querybatch failed with HTTP 503 after 4 attempts: overloaded',
    );
    expect(fake.calls).toHaveLength(4);
  });

  it('retries a querybatch that fails once with 503', async () => {
    let calls = 0;
    const { fetch } = fakeFetch({
      [BATCH]: () => (++calls === 1 ? new Response('busy', { status: 503 }) : { results: [{ vulns: [{ id: 'GHSA-1' }] }] }),
    });
    expect(await new OsvClient({ fetch, retry: NO_WAIT }).queryBatch([{ name: 'lodash', version: '4.17.20' }])).toEqual([['GHSA-1']]);
    expect(calls).toBe(2);
  });

  it('retries a record fetch that fails once with 429', async () => {
    let calls = 0;
    const { fetch } = fakeFetch({
      'GET https://api.osv.dev/v1/vulns/GHSA-1': () =>
        ++calls === 1 ? new Response('', { status: 429, headers: { 'retry-after': '1' } }) : { id: 'GHSA-1', modified: 'm' },
    });
    expect((await new OsvClient({ fetch, retry: NO_WAIT }).getVuln('GHSA-1')).id).toBe('GHSA-1');
  });

  it('quotes what OSV said when querybatch fails', async () => {
    const fake = fakeFetch({ [BATCH]: () => new Response('{"code":3,"message":"Invalid query."}', { status: 400 }) });
    await expect(new OsvClient({ fetch: fake.fetch, retry: NO_WAIT }).queryBatch([{ name: 'x', version: '1.0.0' }])).rejects.toThrow(
      'OSV POST /v1/querybatch failed with HTTP 400: {"code":3,"message":"Invalid query."}',
    );
    expect(fake.calls).toHaveLength(1);
  });
});

describe('OsvClient.getVuln', () => {
  it('fetches each record once', async () => {
    const fake = fakeFetch({
      'GET https://api.osv.dev/v1/vulns/GHSA-1': () => ({ id: 'GHSA-1', modified: '2026-01-01T00:00:00Z' }),
    });
    const client = new OsvClient({ fetch: fake.fetch });
    await client.getVuln('GHSA-1');
    const record = await client.getVuln('GHSA-1');
    expect(record.id).toBe('GHSA-1');
    expect(fake.calls).toHaveLength(1);
  });

  it('asks again after a failed fetch instead of keeping the failure', async () => {
    let calls = 0;
    const { fetch } = fakeFetch({
      'GET https://api.osv.dev/v1/vulns/GHSA-1': () =>
        ++calls === 1 ? new Response('not yet', { status: 404 }) : { id: 'GHSA-1', modified: '2026-01-01T00:00:00Z' },
    });
    const client = new OsvClient({ fetch });
    await expect(client.getVuln('GHSA-1')).rejects.toThrow(/HTTP 404/);
    expect((await client.getVuln('GHSA-1')).id).toBe('GHSA-1');
    expect(calls).toBe(2);
  });

  it('throws on an HTTP error', async () => {
    const { fetch } = fakeFetch({});
    await expect(new OsvClient({ fetch }).getVuln('GHSA-404')).rejects.toThrow(/HTTP 404/);
  });
});
