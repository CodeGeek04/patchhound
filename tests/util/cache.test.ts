import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { RegistryClient } from '../../src/fix/registry.js';
import { DiskCache, defaultCacheDir } from '../../src/util/cache.js';
import { requestJsonConditional } from '../../src/util/http.js';
import { fetchKev, KEV_URL } from '../../src/watch/enrich.js';
import type { OsvVuln } from '../../src/watch/osv.js';
import { OsvClient } from '../../src/watch/osv.js';
import { fakeFetch } from '../helpers/fake-fetch.js';
import { doc } from '../helpers/registry-routes.js';

const tempCache = async () => new DiskCache(await mkdtemp(join(tmpdir(), 'bulwark-cache-')));

/** A route that answers 304 when asked with `etag`, else the body with that ETag, and counts both. */
function etagRoute(etag: string, body: unknown) {
  const seen = { full: 0, notModified: 0 };
  const handler = (_url: URL, init: RequestInit | undefined) => {
    if (new Headers(init?.headers).get('if-none-match') === etag) {
      seen.notModified++;
      return new Response(null, { status: 304, headers: { etag } });
    }
    seen.full++;
    return new Response(JSON.stringify(body), { headers: { etag, 'content-type': 'application/json' } });
  };
  return { handler, seen };
}

describe('DiskCache', () => {
  it('keeps JSON by key, in folders, and reads a missing or corrupt entry as undefined', async () => {
    const cache = await tempCache();
    await cache.set('osv/GHSA-1', { id: 'GHSA-1' });
    expect(await cache.get('osv/GHSA-1')).toEqual({ id: 'GHSA-1' });
    expect(await cache.get('osv/GHSA-2')).toBeUndefined();
    await writeFile(join(cache.dir, 'osv', 'GHSA-3.json'), '{ not json');
    expect(await cache.get('osv/GHSA-3')).toBeUndefined();
    // A scoped package name stays one file.
    await cache.set('npm/registry.npmjs.org/@sentry/nextjs', 1);
    expect(await cache.get('npm/registry.npmjs.org/@sentry/nextjs')).toBe(1);
  });

  it('defaults to $XDG_CACHE_HOME/bulwark', () => {
    const before = process.env.XDG_CACHE_HOME;
    process.env.XDG_CACHE_HOME = '/x/cache';
    try {
      expect(defaultCacheDir()).toBe('/x/cache/bulwark');
    } finally {
      if (before === undefined) delete process.env.XDG_CACHE_HOME;
      else process.env.XDG_CACHE_HOME = before;
    }
  });
});

describe('requestJsonConditional', () => {
  it('asks with the ETag and reuses the cached body on 304', async () => {
    const { handler, seen } = etagRoute('"v1"', { n: 1 });
    const { fetch } = fakeFetch({ 'GET https://x.test/doc': handler });
    const first = await requestJsonConditional(fetch, { label: 'doc', url: 'https://x.test/doc' });
    expect(first).toEqual({ etag: '"v1"', body: { n: 1 } });
    expect(await requestJsonConditional(fetch, { label: 'doc', url: 'https://x.test/doc' }, {}, first)).toBe(first);
    expect(seen).toEqual({ full: 1, notModified: 1 });
  });
});

describe('caches in the clients', () => {
  it('reuses an OSV record while OSV reports the same modified time, and fetches it again when it changed', async () => {
    const cache = await tempCache();
    const record = (modified: string): OsvVuln => ({ id: 'GHSA-1', modified });
    let served = record('2026-11-01T00:00:00.000000Z');
    const fake = fakeFetch({ 'GET https://api.osv.dev/v1/vulns/GHSA-1': () => served });
    const client = () => new OsvClient({ fetch: fake.fetch, cache });
    const first = client();
    first.noteModified('GHSA-1', '2026-11-01T00:00:00Z');
    await first.getVuln('GHSA-1');
    const second = client();
    second.noteModified('GHSA-1', '2026-11-01T00:00:00Z');
    expect(await second.getVuln('GHSA-1')).toEqual(record('2026-11-01T00:00:00.000000Z'));
    served = record('2026-11-02T00:00:00Z');
    const third = client();
    third.noteModified('GHSA-1', '2026-11-02T00:00:00Z');
    expect((await third.getVuln('GHSA-1')).modified).toBe('2026-11-02T00:00:00Z');
    expect(fake.calls).toEqual(['GET https://api.osv.dev/v1/vulns/GHSA-1', 'GET https://api.osv.dev/v1/vulns/GHSA-1']);
  });

  it('asks the registry again with the ETag and reuses the document on 304', async () => {
    const cache = await tempCache();
    const lodash = doc('lodash', { '4.17.21': {} });
    const { handler, seen } = etagRoute('"abc"', lodash);
    const { fetch } = fakeFetch({ 'GET https://registry.npmjs.org/lodash': handler });
    expect(await new RegistryClient({ fetch, cache }).packument('lodash')).toEqual(lodash);
    expect(await new RegistryClient({ fetch, cache }).packument('lodash')).toEqual(lodash);
    expect(seen).toEqual({ full: 1, notModified: 1 });
  });

  it('asks for the KEV catalog in full when the cached copy does not read as one', async () => {
    const cache = await tempCache();
    await cache.set('kev', { etag: '"k1"', body: { nope: true } });
    const { handler, seen } = etagRoute('"k1"', { vulnerabilities: [{ cveID: 'CVE-2021-23337' }] });
    const { fetch } = fakeFetch({ [`GET ${KEV_URL}`]: handler });
    expect(await fetchKev(fetch, {}, cache)).toEqual(new Set(['CVE-2021-23337']));
    expect(seen).toEqual({ full: 1, notModified: 0 });
  });

  it('compares OSV modified times to the nanosecond', async () => {
    const cache = await tempCache();
    await cache.set('osv/GHSA-1', { id: 'GHSA-1', modified: '2026-11-21T03:30:06.653763533Z' });
    const fake = fakeFetch({ 'GET https://api.osv.dev/v1/vulns/GHSA-1': () => ({ id: 'GHSA-1', modified: '2026-11-21T03:30:06.653999999Z' }) });
    const client = new OsvClient({ fetch: fake.fetch, cache });
    client.noteModified('GHSA-1', '2026-11-21T03:30:06.653999999Z');
    expect((await client.getVuln('GHSA-1')).modified).toBe('2026-11-21T03:30:06.653999999Z');
    expect(fake.calls).toHaveLength(1);
  });

  it('reuses the KEV catalog on 304', async () => {
    const cache = await tempCache();
    const { handler, seen } = etagRoute('"k1"', { vulnerabilities: [{ cveID: 'CVE-2021-23337' }] });
    const { fetch } = fakeFetch({ [`GET ${KEV_URL}`]: handler });
    await fetchKev(fetch, {}, cache);
    expect(await fetchKev(fetch, {}, cache)).toEqual(new Set(['CVE-2021-23337']));
    expect(seen).toEqual({ full: 1, notModified: 1 });
  });

});
