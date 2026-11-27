import { describe, expect, it } from 'vitest';
import { openChannels, SlackChannel, WebhookChannel } from '../src/notify/channels.js';
import type { MessageItem } from '../src/notify/message.js';
import { alertMessage, digestMessage } from '../src/notify/message.js';
import { fakeFetch } from './helpers/fake-fetch.js';

const item = (overrides: Partial<MessageItem> = {}): MessageItem => ({
  key: 'GHSA-xqc2-xf4c-x3h3|react-server-dom-webpack@19.3.0',
  package: 'react-server-dom-webpack',
  version: '19.3.0',
  advisory: 'GHSA-xqc2-xf4c-x3h3',
  severity: 'CRITICAL',
  summary: 'Remote Code Execution in React Server Components <script>',
  kev: false,
  rule: 'critical',
  reachable: 'yes',
  reason: 'Claude: the app router renders server components.',
  fix: 'bundled',
  change: 'new',
  ...overrides,
});

describe('alertMessage', () => {
  it('lists each advisory once with all its packages, most severe first', () => {
    const message = alertMessage('demo-app', [
      item({ key: 'b|zod@4.0.0', advisory: 'GHSA-mrhx-c7xc-m3w5', package: 'zod', version: '4.0.0', severity: 'HIGH', rule: 'reachable', summary: 'Zod memory', fix: 'refresh' }),
      item(),
      item({ key: 'a|react-server-dom-turbopack@19.3.0', package: 'react-server-dom-turbopack', change: 'worse' }),
    ]);
    expect(message.title).toBe('Patchhound: 2 advisories need attention in demo-app');
    expect(message.text.split('\n')).toEqual([
      'Patchhound: 2 advisories need attention in demo-app',
      'CRITICAL GHSA-xqc2-xf4c-x3h3 (worse since last time) in react-server-dom-turbopack@19.3.0, react-server-dom-webpack@19.3.0: Remote Code Execution in React Server Components <script>',
      '    reachable: yes; Claude: the app router renders server components.',
      '    why: critical (CVSS 9 or more) in production code: always notifies, whatever triage says; fix: wait for a new version of the package that bundles it',
      'HIGH GHSA-mrhx-c7xc-m3w5 in zod@4.0.0: Zod memory',
      '    reachable: yes; Claude: the app router renders server components.',
      '    why: at or above the threshold and reachable: notifies; fix: refresh the lockfile',
    ]);
    expect(message.slack).toContain('*CRITICAL* <https://osv.dev/vulnerability/GHSA-xqc2-xf4c-x3h3|GHSA-xqc2-xf4c-x3h3>');
    expect(message.slack).toContain('Server Components &lt;script&gt;');
  });
});

describe('digestMessage', () => {
  it('counts by rule and lists judged findings before the ones the threshold or lockfile settled', () => {
    const message = digestMessage('demo-app', [
      item({ advisory: 'A', rule: 'dev-only', severity: 'CRITICAL', change: 'digest' }),
      item({ advisory: 'B', rule: 'not-reachable', severity: 'HIGH', change: 'digest' }),
    ]);
    expect(message.text.split('\n').slice(0, 3)).toEqual([
      'Patchhound weekly digest for demo-app: 2 findings below the bar for an alert',
      '1 triage found the vulnerable code unreachable; 1 dev-only in the lockfile',
      'HIGH B in react-server-dom-webpack@19.3.0: Remote Code Execution in React Server Components <script>',
    ]);
  });
});

describe('channels', () => {
  it('posts Slack mrkdwn as {text}, and the whole message to a generic webhook', async () => {
    const bodies: unknown[] = [];
    const fake = fakeFetch({
      'POST https://hooks.slack.test/services/x': (_url, init) => {
        bodies.push(JSON.parse(String(init?.body)));
        return new Response('ok');
      },
      'POST https://relay.test/hook': (_url, init) => {
        bodies.push(JSON.parse(String(init?.body)));
        return new Response('');
      },
    });
    const message = alertMessage('demo-app', [item()]);
    await new SlackChannel({ url: 'https://hooks.slack.test/services/x', fetch: fake.fetch }).send(message);
    await new WebhookChannel({ url: 'https://relay.test/hook', fetch: fake.fetch }).send(message);
    expect(bodies[0]).toEqual({ text: message.slack });
    expect(bodies[1]).toMatchObject({ kind: 'alert', project: 'demo-app', title: message.title, items: [{ advisory: 'GHSA-xqc2-xf4c-x3h3' }] });
  });

  it('never quotes a webhook URL: a value that is not a URL is refused, and errors name the host only', async () => {
    const quoted = '"https://hooks.slack.test/services/T000/B000/secret-token"';
    const { channels, warnings } = openChannels([{ type: 'slack', webhookEnv: 'SLACK_WEBHOOK_URL' }], { SLACK_WEBHOOK_URL: quoted });
    expect(channels).toEqual([]);
    expect(warnings).toEqual(['slack channel: SLACK_WEBHOOK_URL does not hold a URL (quotes around it?), so its messages are only printed']);
    expect(warnings.join(' ')).not.toContain('secret-token');
    const url = 'https://hooks.slack.test/services/T000/B000/secret-token';
    const failing = fakeFetch({}).fetch;
    const error = await new SlackChannel({ url, fetch: (() => Promise.reject(new TypeError(`Failed to parse URL from ${url}`))) as typeof failing, retry: { retries: 0 } })
      .send(alertMessage('demo-app', [item()]))
      .catch((e: Error) => e);
    expect(String(error)).toContain('https://hooks.slack.test/...');
    expect(String(error)).not.toContain('secret-token');
  });

  it('opens the channels whose secret is set, and warns about the rest', () => {
    const { channels, warnings } = openChannels(
      [
        { type: 'slack', webhookEnv: 'SLACK_WEBHOOK_URL' },
        { type: 'webhook', urlEnv: 'RELAY_URL' },
      ],
      { SLACK_WEBHOOK_URL: 'https://hooks.slack.test/x' },
    );
    expect(channels.map((c) => c.name)).toEqual(['slack']);
    expect(warnings).toEqual(['webhook channel: RELAY_URL is not set, so its messages are only printed']);
  });
});
