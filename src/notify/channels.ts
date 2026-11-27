import type { ChannelConfig } from '../config.js';
import type { Fetch, RetryOptions } from '../util/http.js';
import { requestText } from '../util/http.js';
import type { Message } from './message.js';

/** Somewhere a message can go. Add a channel by implementing this and naming it in ChannelConfig. */
export interface Channel {
  readonly name: string;
  send(message: Message): Promise<void>;
}

/** A Slack incoming webhook (api.slack.com/messaging/webhooks). */
export class SlackChannel implements Channel {
  readonly name = 'slack';

  constructor(private readonly options: { url: string; fetch?: Fetch; retry?: RetryOptions }) {}

  async send(message: Message): Promise<void> {
    await post(this.options, 'Slack webhook', { text: message.slack });
  }
}

/** Any URL that takes JSON: the message's title, text and items. For Discord, Teams or a relay of your own. */
export class WebhookChannel implements Channel {
  readonly name = 'webhook';

  constructor(private readonly options: { url: string; fetch?: Fetch; retry?: RetryOptions }) {}

  async send(message: Message): Promise<void> {
    await post(this.options, 'webhook', { kind: message.kind, project: message.project, title: message.title, text: message.text, items: message.items });
  }
}

async function post(options: { url: string; fetch?: Fetch; retry?: RetryOptions }, label: string, body: unknown): Promise<void> {
  const fetchFn = options.fetch ?? globalThis.fetch.bind(globalThis);
  try {
    // Slack answers `ok` as plain text, so the answer is read as text and not used.
    await requestText(fetchFn, { label: `${label} POST`, url: options.url, method: 'POST', body }, options.retry);
  } catch (error) {
    // The URL is the secret (Slack's carries a token): an error names only its host.
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(message.split(options.url).join(redacted(options.url)));
  }
}

/** A webhook URL as errors may show it: its host only. */
function redacted(url: string): string {
  try {
    const { protocol, host } = new URL(url);
    return `${protocol}//${host}/...`;
  } catch {
    return '(the webhook URL)';
  }
}

/** The channels the config names whose secret is set; a missing secret is a warning, not an error. */
export function openChannels(
  configs: readonly ChannelConfig[],
  env: Record<string, string | undefined>,
  options: { fetch?: Fetch; retry?: RetryOptions } = {},
): { channels: Channel[]; warnings: string[] } {
  const channels: Channel[] = [];
  const warnings: string[] = [];
  for (const config of configs) {
    const variable = config.type === 'slack' ? config.webhookEnv : config.urlEnv;
    const url = env[variable]?.trim();
    if (!url) {
      warnings.push(`${config.type} channel: ${variable} is not set, so its messages are only printed`);
      continue;
    }
    // Never quote the value: it is a secret, and the variable might even hold some other key by mistake.
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      warnings.push(`${config.type} channel: ${variable} does not hold a URL (quotes around it?), so its messages are only printed`);
      continue;
    }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      warnings.push(`${config.type} channel: ${variable} is not an http(s) URL, so its messages are only printed`);
      continue;
    }
    channels.push(config.type === 'slack' ? new SlackChannel({ url, ...options }) : new WebhookChannel({ url, ...options }));
  }
  return { channels, warnings };
}
