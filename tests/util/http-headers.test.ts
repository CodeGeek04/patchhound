import { describe, expect, it } from 'vitest';
import { requestJson } from '../../src/util/http.js';
import { fakeFetch } from '../helpers/fake-fetch.js';

const URL_ = 'https://api.example.test/v1/thing';

/** A fake fetch that answers every method on URL_ and remembers the headers of each request. */
function capturing() {
  const seen: Headers[] = [];
  const handler = (_url: URL, init: RequestInit | undefined) => {
    seen.push(new Headers(init?.headers));
    return { ok: 1 };
  };
  return { seen, ...fakeFetch({ [`GET ${URL_}`]: handler, [`POST ${URL_}`]: handler }) };
}

describe('requestJson headers', () => {
  it('sends the extra headers it is given', async () => {
    const { fetch, seen } = capturing();
    await requestJson(fetch, { label: 'Thing', url: URL_, headers: { accept: 'application/vnd.npm.install-v1+json' } });
    expect(seen[0]?.get('accept')).toBe('application/vnd.npm.install-v1+json');
    expect(seen[0]?.has('content-type')).toBe(false);
  });

  it('still sets content-type when there is a body', async () => {
    const { fetch, seen } = capturing();
    const headers = { accept: 'application/json' };
    await requestJson(fetch, { label: 'Thing', url: URL_, method: 'POST', body: { a: 1 }, headers });
    expect(seen[0]?.get('accept')).toBe('application/json');
    expect(seen[0]?.get('content-type')).toBe('application/json');
    // The caller's object is not changed.
    expect(headers).toEqual({ accept: 'application/json' });
  });

  it('sends the headers again on a retry', async () => {
    let attempt = 0;
    const seen: (string | null)[] = [];
    const { fetch } = fakeFetch({
      [`GET ${URL_}`]: (_url, init) => {
        seen.push(new Headers(init?.headers).get('accept'));
        return ++attempt === 1 ? new Response('busy', { status: 503 }) : { ok: 1 };
      },
    });
    await requestJson(fetch, { label: 'Thing', url: URL_, headers: { accept: 'text/x-test' } }, { sleep: async () => {} });
    expect(seen).toEqual(['text/x-test', 'text/x-test']);
  });
});
