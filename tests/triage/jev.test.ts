import { describe, expect, it } from 'vitest';
import { buildJevRequest, JEV_URL, JevClient, noulConfidence, parseJevResponse } from '../../src/triage/jev.js';
import { fakeFetch } from '../helpers/fake-fetch.js';
import { evidence } from '../helpers/findings.js';

const ANSWER = {
  model: 'jev-1.14.0',
  answers: {
    reachable: { type: 'noul', noul: 0.82 },
    exposure: { type: 'choice', choice: 'internet-facing', confidence: 0.9, probabilities: { 'internet-facing': 0.93, internal: 0.05, 'build/dev-only': 0.02 } },
    drop_in: { type: 'noul', noul: 0.4 },
    urgency: { type: 'score', score: 2.6, confidence: 0.7, probabilities: { '2': 0.4, '3': 0.6 } },
  },
  usage: { input_tokens: 1200, output_tokens: 5 },
};

describe('buildJevRequest', () => {
  it('asks four questions about one state, with the advisory marked untrusted and its text cut to size', () => {
    const body = buildJevRequest(evidence(), 'x'.repeat(5000), 'jev-latest') as { model: string; state: Record<string, unknown>; questions: Record<string, { type: string }> };
    expect(body.model).toBe('jev-latest');
    expect(Object.fromEntries(Object.entries(body.questions).map(([k, q]) => [k, q.type]))).toEqual({
      reachable: 'noul',
      exposure: 'choice',
      drop_in: 'noul',
      urgency: 'score',
    });
    const advisory = body.state.advisory_untrusted as { details: string };
    expect(advisory.details).toHaveLength(4000 + ' [cut]'.length);
  });
});

describe('parseJevResponse', () => {
  it('reads the answers, and rejects a body in another shape', () => {
    expect(parseJevResponse(ANSWER)).toMatchObject({ model: 'jev-1.14.0', reachable: 0.82, dropIn: 0.4, urgency: { score: 2.6 }, inputTokens: 1200 });
    expect(() => parseJevResponse({ model: 'x', answers: {} })).toThrow(/unexpected shape/);
  });
});

describe('JevClient', () => {
  it('posts to System One with the key as a bearer token', async () => {
    let auth: string | null = null;
    const fake = fakeFetch({
      [`POST ${JEV_URL}`]: (_url, init) => {
        auth = new Headers(init?.headers).get('authorization');
        return ANSWER;
      },
    });
    const answer = await new JevClient({ apiKey: 'k', model: 'jev-latest', fetch: fake.fetch }).ask(evidence(), 'details');
    expect(answer.reachable).toBe(0.82);
    expect(auth).toBe('Bearer k');
  });
});

describe('noulConfidence', () => {
  it('is how far a probability is from a coin toss, either way', () => {
    expect(noulConfidence(0.9)).toBe(0.9);
    expect(noulConfidence(0.2)).toBe(0.8);
    expect(noulConfidence(0.5)).toBe(0.5);
  });
});
