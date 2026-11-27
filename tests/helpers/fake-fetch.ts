export type Handler = (url: URL, init: RequestInit | undefined) => unknown;

export interface FakeFetch {
  fetch: typeof fetch;
  /** Every request made, as "METHOD origin+path". */
  calls: string[];
}

/**
 * A stand-in for fetch. Routes are keyed by "METHOD origin+path" (query string ignored).
 * A handler returns a JSON body, or a Response for errors. Unknown routes get a 404.
 */
export function fakeFetch(routes: Record<string, Handler>): FakeFetch {
  const calls: string[] = [];
  const fn = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(input instanceof Request ? input.url : input.toString());
    const key = `${init?.method ?? 'GET'} ${url.origin}${url.pathname}`;
    calls.push(key);
    const handler = routes[key];
    if (!handler) return new Response(`no route for ${key}`, { status: 404 });
    const body = await handler(url, init);
    if (body instanceof Response) return body;
    return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
  };
  return { fetch: fn as typeof fetch, calls };
}
