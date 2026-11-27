import { describe, expect, it } from 'vitest';
import type { Fetch } from '../../src/util/http.js';
import { requestJson } from '../../src/util/http.js';
import { fakeFetch } from '../helpers/fake-fetch.js';

const URL_ = 'https://api.example.test/v1/thing';
const ROUTE = `GET ${URL_}`;

/** A sleep that returns at once and remembers how long it was asked to wait. */
function recordingSleep() {
  const waits: number[] = [];
  return { waits, sleep: async (ms: number) => void waits.push(ms) };
}

/** Answers with each response in turn, then repeats the last. */
function sequence(...responses: (() => unknown)[]) {
  let i = 0;
  return () => responses[Math.min(i++, responses.length - 1)]!();
}

describe('requestJson', () => {
  it('parses a JSON response, and sends a JSON body', async () => {
    const { fetch } = fakeFetch({
      [ROUTE]: () => ({ ok: 1 }),
      [`POST ${URL_}`]: (_url, init) => {
        expect(new Headers(init?.headers).get('content-type')).toBe('application/json');
        return { echo: JSON.parse(String(init?.body)) };
      },
    });
    expect(await requestJson(fetch, { label: 'Thing', url: URL_ })).toEqual({ ok: 1 });
    expect(await requestJson(fetch, { label: 'Thing', url: URL_, method: 'POST', body: { a: 1 } })).toEqual({ echo: { a: 1 } });
  });

  it('retries 429 and 5xx with doubling waits, then succeeds', async () => {
    const fake = fakeFetch({
      [ROUTE]: sequence(
        () => new Response('busy', { status: 503 }),
        () => new Response('slow down', { status: 429 }),
        () => new Response('oops', { status: 500 }),
        () => ({ ok: 1 }),
      ),
    });
    const { waits, sleep } = recordingSleep();
    expect(await requestJson(fake.fetch, { label: 'Thing', url: URL_ }, { sleep })).toEqual({ ok: 1 });
    expect(fake.calls).toHaveLength(4);
    expect(waits).toEqual([1000, 2000, 4000]);
  });

  it('waits as long as Retry-After asks, up to the cap', async () => {
    const later = new Date(Date.now() + 5000).toUTCString();
    const { fetch } = fakeFetch({
      [ROUTE]: sequence(
        () => new Response('', { status: 429, headers: { 'retry-after': '7' } }),
        () => new Response('', { status: 429, headers: { 'retry-after': '3600' } }),
        () => new Response('', { status: 503, headers: { 'retry-after': later } }),
        () => ({ ok: 1 }),
      ),
    });
    const { waits, sleep } = recordingSleep();
    await requestJson(fetch, { label: 'Thing', url: URL_ }, { sleep, maxDelayMs: 30_000 });
    expect(waits.slice(0, 2)).toEqual([7000, 30_000]);
    expect(waits[2]).toBeGreaterThan(3000);
    expect(waits[2]).toBeLessThanOrEqual(5000);
  });

  it('gives up after 3 retries, with the status and the start of the body', async () => {
    const body = `<html>${'x'.repeat(300)}</html>`;
    const fake = fakeFetch({ [ROUTE]: () => new Response(body, { status: 503 }) });
    const { sleep } = recordingSleep();
    const error = await requestJson(fake.fetch, { label: 'Thing lookup', url: URL_ }, { sleep }).catch((e: Error) => e);
    expect(fake.calls).toHaveLength(4);
    expect((error as Error).message).toBe(`Thing lookup failed with HTTP 503 after 4 attempts: ${body.slice(0, 200)}`);
  });

  it('does not retry other client errors', async () => {
    const fake = fakeFetch({ [ROUTE]: () => new Response('{"code":3,"message":"Bug not found."}', { status: 404 }) });
    const { sleep, waits } = recordingSleep();
    await expect(requestJson(fake.fetch, { label: 'Thing', url: URL_ }, { sleep })).rejects.toThrow(
      'Thing failed with HTTP 404: {"code":3,"message":"Bug not found."}',
    );
    expect(fake.calls).toHaveLength(1);
    expect(waits).toEqual([]);
  });

  it('retries network errors', async () => {
    let calls = 0;
    const flaky: Fetch = async () => {
      if (++calls < 3) throw new TypeError('fetch failed', { cause: new Error('read ECONNRESET') });
      return new Response('{"ok":1}');
    };
    const { sleep } = recordingSleep();
    expect(await requestJson(flaky, { label: 'Thing', url: URL_ }, { sleep })).toEqual({ ok: 1 });
    expect(calls).toBe(3);

    const down: Fetch = async () => {
      throw new TypeError('fetch failed', { cause: new Error('getaddrinfo ENOTFOUND api.example.test') });
    };
    await expect(requestJson(down, { label: 'Thing', url: URL_ }, { sleep, retries: 1 })).rejects.toThrow(
      'Thing failed after 2 attempts: fetch failed (getaddrinfo ENOTFOUND api.example.test)',
    );
  });

  it('times out a request that hangs, and retries it', async () => {
    let calls = 0;
    const hang: Fetch = (_input, init) => {
      calls++;
      return new Promise((_resolve, reject) => init?.signal?.addEventListener('abort', () => reject(init.signal!.reason)));
    };
    const { sleep } = recordingSleep();
    await expect(requestJson(hang, { label: 'Thing', url: URL_, timeoutMs: 5 }, { sleep, retries: 1 })).rejects.toThrow(
      'Thing failed after 2 attempts: timed out after 5 ms',
    );
    expect(calls).toBe(2);
  });

  it('says when a response is not JSON', async () => {
    const { fetch } = fakeFetch({ [ROUTE]: () => new Response('<html>maintenance</html>') });
    await expect(requestJson(fetch, { label: 'Thing', url: URL_ })).rejects.toThrow(
      'Thing returned a body that is not JSON: <html>maintenance</html>',
    );
  });
});
