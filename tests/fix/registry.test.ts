import { describe, expect, it } from 'vitest';
import { isRefused, RegistryClient } from '../../src/fix/registry.js';
import { HttpError } from '../../src/util/http.js';
import { fakeFetch } from '../helpers/fake-fetch.js';
import { doc, registryRoutes } from '../helpers/registry-routes.js';

const lodash = doc('lodash', { '4.17.20': {}, '4.17.21': {} }, { latest: '4.17.21' });
const nextjs = doc('@sentry/nextjs', { '8.0.0': { dependencies: { '@sentry/core': '8.0.0' } } });

describe('RegistryClient', () => {
  it('asks for the abbreviated document, with a scoped name keeping its @ and encoding the slash', async () => {
    const accepts: (string | null)[] = [];
    const fake = fakeFetch({
      'GET https://registry.npmjs.org/@sentry%2fnextjs': (_url, init) => {
        accepts.push(new Headers(init?.headers).get('accept'));
        return nextjs;
      },
    });
    expect(await new RegistryClient({ fetch: fake.fetch }).packument('@sentry/nextjs')).toEqual(nextjs);
    expect(fake.calls).toEqual(['GET https://registry.npmjs.org/@sentry%2fnextjs']);
    expect(accepts).toEqual(['application/vnd.npm.install-v1+json']);
  });

  it('makes one request for a package however often it is asked', async () => {
    const fake = fakeFetch(registryRoutes([lodash]));
    const client = new RegistryClient({ fetch: fake.fetch });
    const [a, b] = await Promise.all([client.packument('lodash'), client.packument('lodash')]);
    const c = await client.packument('lodash');
    expect(a).toEqual(lodash);
    expect(b).toBe(a);
    expect(c).toBe(a);
    expect(fake.calls).toEqual(['GET https://registry.npmjs.org/lodash']);
  });

  it('does not count a refused package as a registry failure', async () => {
    const { fetch } = fakeFetch({ 'GET https://registry.npmjs.org/ghost': () => new Response('{}', { status: 404 }), ...registryRoutes([lodash]) });
    const client = new RegistryClient({ fetch });
    await expect(client.packument('ghost')).rejects.toThrow('HTTP 404');
    expect(client.failure).toBeUndefined();
    expect(await client.packument('lodash')).toEqual(lodash);
  });

  it('does not keep a request the registry refused, so the next call tries again', async () => {
    let attempt = 0;
    const fake = fakeFetch({
      'GET https://registry.npmjs.org/lodash': () => (++attempt === 1 ? new Response('not yet', { status: 404 }) : lodash),
    });
    const client = new RegistryClient({ fetch: fake.fetch });
    await expect(client.packument('lodash')).rejects.toThrow('npm registry GET lodash failed with HTTP 404: not yet');
    expect(await client.packument('lodash')).toEqual(lodash);
    expect(fake.calls).toHaveLength(2);
  });

  it('names the package when the registry has no such package, and calls that refused', async () => {
    const { fetch } = fakeFetch({ 'GET https://registry.npmjs.org/ghost': () => new Response('{"error":"Not found"}', { status: 404 }) });
    const error = await new RegistryClient({ fetch }).packument('ghost').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(HttpError);
    expect((error as HttpError).message).toBe('npm registry GET ghost failed with HTTP 404: {"error":"Not found"}');
    expect((error as HttpError).status).toBe(404);
    expect(isRefused(error)).toBe(true);
    expect(isRefused(new HttpError('busy', 503))).toBe(false);
    expect(isRefused(new HttpError('timed out', undefined))).toBe(false);
  });

  it('after the registry itself fails, fails every later call at once with that error', async () => {
    const fake = fakeFetch({
      'GET https://registry.npmjs.org/lodash': () => new Response('busy', { status: 503 }),
      ...registryRoutes([nextjs]),
    });
    const client = new RegistryClient({ fetch: fake.fetch, retry: { retries: 0 } });
    expect(client.failure).toBeUndefined();
    await expect(client.packument('lodash')).rejects.toThrow('npm registry GET lodash failed with HTTP 503: busy');
    const later = (await client.packument('@sentry/nextjs').catch((e: unknown) => e)) as Error;
    expect(later.message).toBe('npm registry GET @sentry/nextjs not sent: the registry failed earlier (npm registry GET lodash failed with HTTP 503: busy)');
    expect(client.failure).toBe('npm registry GET lodash failed with HTTP 503: busy');
    expect(fake.calls).toEqual(['GET https://registry.npmjs.org/lodash']);
  });

  it('counts a request that got no answer as the registry failing', async () => {
    let calls = 0;
    const fetch = (async () => {
      calls++;
      throw new TypeError('fetch failed');
    }) as typeof globalThis.fetch;
    const client = new RegistryClient({ fetch, retry: { retries: 0 } });
    await expect(client.packument('lodash')).rejects.toThrow('npm registry GET lodash failed: fetch failed');
    await expect(client.packument('react')).rejects.toThrow('npm registry GET react not sent: the registry failed earlier');
    expect(calls).toBe(1);
  });

  it('throws a clear error for a body without versions', async () => {
    const { fetch } = fakeFetch(registryRoutes({ empty: { name: 'empty' }, nulled: { name: 'nulled', versions: null }, text: 'Not found' }));
    const client = new RegistryClient({ fetch });
    await expect(client.packument('empty')).rejects.toThrow('npm registry GET empty returned no versions');
    await expect(client.packument('nulled')).rejects.toThrow('npm registry GET nulled returned no versions');
    await expect(client.packument('text')).rejects.toThrow('npm registry GET text returned no versions');
  });

  it('uses a custom base URL, without a trailing slash', async () => {
    const fake = fakeFetch(registryRoutes([lodash], 'https://npm.example.test/registry'));
    const client = new RegistryClient({ fetch: fake.fetch, baseUrl: 'https://npm.example.test/registry/' });
    expect(await client.packument('lodash')).toEqual(lodash);
    expect(fake.calls).toEqual(['GET https://npm.example.test/registry/lodash']);
  });
});
