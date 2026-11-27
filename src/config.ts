import { readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { parse } from 'yaml';
import { z } from 'zod';

/** Where a repo's code runs, as the repo's owner describes it. Dev-only packages are build/dev-only whatever this says. */
export type Exposure = 'internet-facing' | 'internal';
export type Threshold = 'critical' | 'high' | 'moderate' | 'low';
export type LlmVia = 'auto' | 'api' | 'claude-code' | 'off';

export type ChannelConfig = { type: 'slack'; webhookEnv: string } | { type: 'webhook'; urlEnv: string };

export interface Config {
  exposure: Exposure;
  /** Print and log what would be sent or done, without sending or doing it. */
  dryRun: boolean;
  /** Stop everything above tier 0 (milestone 3 on). */
  paused: boolean;
  notify: {
    /** The lowest severity that notifies at once (when reachable or unknown). */
    threshold: Threshold;
    /**
     * What alerts whatever triage says. Malware always does. `kev` (default): known to be exploited.
     * `critical`: CVSS 9 or more in production code too, as the spec first had it; on the owner's apps
     * 23 of 26 such alerts were for code nothing could reach, so it is off by default.
     */
    always: ('kev' | 'critical')[];
    digest: 'weekly' | 'off';
    channels: ChannelConfig[];
  };
  triage: {
    jev: { model: string; threshold: number };
    /** Which of the findings whose answer counts Claude checks (see Escalate in triage.ts). */
    escalate: 'unsure' | 'unless-unreachable' | 'always';
    llm: { via: LlmVia; model: string; effort: 'low' | 'medium' | 'high' | 'xhigh' | 'max' };
  };
  tiers: { fixPr: boolean; autoMerge: boolean; containment: boolean };
  fix: {
    /** Commands that must keep passing; empty to detect them (typecheck, test, build). */
    checks: string[];
    /** Commands that run after each install, before the checks (code generation); empty to detect them (prisma generate). */
    setup: string[];
    /** Let installs run the packages' install scripts (prisma generate and the like); tests often need them. */
    installScripts: boolean;
    /** Most Claude Code may spend on one repo in one run, in dollars. */
    budgetUsd: number;
    /** Longest the coding agent may run, and each check, in minutes. */
    timeLimitMinutes: number;
    model: string;
    effort: 'low' | 'medium' | 'high' | 'xhigh' | 'max';
    /** The branch the fix PR comes from. */
    branch: string;
    /** Who the fix commits are from: GitHub Actions' bot, or the person who started the run (see commitAuthor). */
    commitAs: 'bot' | 'actor';
  };
}

export const DEFAULT_CONFIG: Config = {
  exposure: 'internet-facing',
  dryRun: true,
  paused: false,
  notify: { threshold: 'high', always: ['kev'], digest: 'weekly', channels: [] },
  triage: {
    jev: { model: 'jev-latest', threshold: 0.7 },
    escalate: 'unless-unreachable',
    llm: { via: 'auto', model: 'claude-opus-5-5', effort: 'medium' },
  },
  tiers: { fixPr: true, autoMerge: false, containment: false },
  fix: {
    checks: [],
    setup: [],
    installScripts: true,
    budgetUsd: 10,
    timeLimitMinutes: 30,
    model: 'claude-opus-5-5',
    effort: 'high',
    branch: 'bulwark/fixes',
    commitAs: 'bot',
  },
};

/** A secret never goes in a config file that may be committed: the file names the environment variable that holds it. */
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

const channel = z.discriminatedUnion('type', [
  z.strictObject({ type: z.literal('slack'), webhook_env: z.string().regex(ENV_NAME).default('SLACK_WEBHOOK_URL') }),
  z.strictObject({ type: z.literal('webhook'), url_env: z.string().regex(ENV_NAME) }),
]);

/** The settings a repo file, the central file's `defaults`, or one of its `repos` entries may set. Every key is optional. */
const settings = {
  exposure: z.enum(['internet-facing', 'internal']).optional(),
  dry_run: z.boolean().optional(),
  paused: z.boolean().optional(),
  notify: z
    .strictObject({
      threshold: z.enum(['critical', 'high', 'moderate', 'low']).optional(),
      always: z.array(z.enum(['kev', 'critical'])).optional(),
      digest: z.enum(['weekly', 'off']).optional(),
      channels: z.array(channel).optional(),
    })
    .optional(),
  triage: z
    .strictObject({
      jev: z.strictObject({ model: z.string().min(1).optional(), threshold: z.number().gt(0.5).lt(1).optional() }).optional(),
      escalate: z.enum(['unsure', 'unless-unreachable', 'always']).optional(),
      llm: z
        .strictObject({
          via: z.enum(['auto', 'api', 'claude-code', 'off']).optional(),
          model: z.string().min(1).optional(),
          effort: z.enum(['low', 'medium', 'high', 'xhigh', 'max']).optional(),
        })
        .optional(),
    })
    .optional(),
  tiers: z
    .strictObject({ fix_pr: z.boolean().optional(), auto_merge: z.boolean().optional(), containment: z.boolean().optional() })
    .optional(),
  fix: z
    .strictObject({
      checks: z.array(z.string().min(1)).optional(),
      setup: z.array(z.string().min(1)).optional(),
      install_scripts: z.boolean().optional(),
      budget_usd: z.number().positive().max(500).optional(),
      time_limit_minutes: z.number().positive().max(360).optional(),
      model: z.string().min(1).optional(),
      effort: z.enum(['low', 'medium', 'high', 'xhigh', 'max']).optional(),
      branch: z.string().regex(/^[\w./-]+$/).optional(),
      commit_as: z.enum(['bot', 'actor']).optional(),
    })
    .optional(),
};

const repoFile = z.strictObject(settings);
const centralFile = z.strictObject({
  defaults: z.strictObject(settings).optional(),
  repos: z.array(z.strictObject({ path: z.string().min(1), name: z.string().optional(), ...settings })).optional(),
});

type Settings = z.infer<typeof repoFile>;
export type CentralConfig = z.infer<typeof centralFile>;

/** `$XDG_CONFIG_HOME/bulwark/config.yml`, else `~/.config/bulwark/config.yml`. */
export function defaultCentralPath(): string {
  const base = process.env.XDG_CONFIG_HOME || join(homedir(), '.config');
  return join(base, 'bulwark', 'config.yml');
}

export const REPO_FILE = '.bulwark.yml';

/** The central file, or null when there is none. A file that exists but does not read is an error. */
export async function loadCentral(path: string): Promise<CentralConfig | null> {
  const text = await readOptional(path);
  return text === null ? null : validate(centralFile, text, path);
}

/**
 * The settings for the repo in `dir`: the built-in defaults, then the central file's `defaults`, then
 * its entry for this repo, then the repo's own `.bulwark.yml`. Containment can only be turned
 * on by the central file (spec, "Config").
 */
export async function loadConfig(dir: string, options: { central?: CentralConfig | null } = {}): Promise<Config> {
  const path = join(dir, REPO_FILE);
  const text = await readOptional(path);
  const own = text === null ? {} : validate(repoFile, text, path);
  if (own.tiers?.containment === true) {
    throw new Error(`${path}: tiers.containment can only be turned on in the central config file`);
  }
  const central = options.central ?? null;
  const entry = central?.repos?.find((repo) => expandHome(repo.path) === resolve(dir));
  const { path: _path, name: _name, ...entrySettings } = entry ?? { path: '' };
  return [central?.defaults ?? {}, entrySettings, own].reduce(apply, DEFAULT_CONFIG);
}

/** The repo folders a central file lists, resolved. */
export function centralRepos(central: CentralConfig): string[] {
  return (central.repos ?? []).map((repo) => expandHome(repo.path));
}

function apply(config: Config, s: Settings): Config {
  return {
    exposure: s.exposure ?? config.exposure,
    dryRun: s.dry_run ?? config.dryRun,
    paused: s.paused ?? config.paused,
    notify: {
      threshold: s.notify?.threshold ?? config.notify.threshold,
      always: s.notify?.always ?? config.notify.always,
      digest: s.notify?.digest ?? config.notify.digest,
      channels:
        s.notify?.channels?.map((c): ChannelConfig =>
          c.type === 'slack' ? { type: 'slack', webhookEnv: c.webhook_env } : { type: 'webhook', urlEnv: c.url_env },
        ) ?? config.notify.channels,
    },
    triage: {
      jev: {
        model: s.triage?.jev?.model ?? config.triage.jev.model,
        threshold: s.triage?.jev?.threshold ?? config.triage.jev.threshold,
      },
      escalate: s.triage?.escalate ?? config.triage.escalate,
      llm: {
        via: s.triage?.llm?.via ?? config.triage.llm.via,
        model: s.triage?.llm?.model ?? config.triage.llm.model,
        effort: s.triage?.llm?.effort ?? config.triage.llm.effort,
      },
    },
    tiers: {
      fixPr: s.tiers?.fix_pr ?? config.tiers.fixPr,
      autoMerge: s.tiers?.auto_merge ?? config.tiers.autoMerge,
      containment: s.tiers?.containment ?? config.tiers.containment,
    },
    fix: {
      checks: s.fix?.checks ?? config.fix.checks,
      setup: s.fix?.setup ?? config.fix.setup,
      installScripts: s.fix?.install_scripts ?? config.fix.installScripts,
      budgetUsd: s.fix?.budget_usd ?? config.fix.budgetUsd,
      timeLimitMinutes: s.fix?.time_limit_minutes ?? config.fix.timeLimitMinutes,
      model: s.fix?.model ?? config.fix.model,
      effort: s.fix?.effort ?? config.fix.effort,
      branch: s.fix?.branch ?? config.fix.branch,
      commitAs: s.fix?.commit_as ?? config.fix.commitAs,
    },
  };
}

function validate<T>(schema: z.ZodType<T>, text: string, path: string): T {
  let data: unknown;
  try {
    data = parse(text) ?? {};
  } catch (error) {
    throw new Error(`${path}: not valid YAML: ${error instanceof Error ? error.message : String(error)}`);
  }
  const result = schema.safeParse(data);
  if (!result.success) {
    const problems = result.error.issues.map((issue) => {
      const where = issue.path.join('.');
      // "exposre: unknown key" reads better than zod's "(top): Unrecognized key".
      if (issue.code === 'unrecognized_keys') return issue.keys.map((key) => `${where ? `${where}.` : ''}${key}: unknown key`).join('; ');
      return `${where || '(top)'}: ${issue.message}`;
    });
    throw new Error(`${path}: ${problems.join('; ')}`);
  }
  return result.data;
}

async function readOptional(path: string): Promise<string | null> {
  try {
    return await readFile(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
}

function expandHome(path: string): string {
  return resolve(path === '~' || path.startsWith('~/') ? join(homedir(), path.slice(1)) : path);
}

export const STARTER_CONFIG = `# bulwark settings for this repo. Every key is optional; these are the defaults.

# Where the deployed app runs: internet-facing (the default, also for apps behind a login) or internal.
exposure: internet-facing

# Print and log notifications instead of sending them. Turn off once the messages look right.
dry_run: true

notify:
  # The lowest severity that notifies at once, when triage finds it reachable or cannot tell:
  # critical, high, moderate or low. The rest goes to the weekly digest.
  threshold: high
  # Alert whatever triage says: kev (known to be exploited), and critical (CVSS 9+) if you add it.
  # Malicious packages always alert.
  always: [kev]
  digest: weekly
  channels:
    # A Slack incoming webhook. The URL is a secret, so it comes from this environment variable.
    - type: slack
      webhook_env: SLACK_WEBHOOK_URL

triage:
  # Jev (TypeSafe) answers first when TYPESAFE_API_KEY is set; Claude gets what it is unsure of.
  jev:
    threshold: 0.7
  # Which findings Claude checks, among those whose answer decides an alert:
  # unless-unreachable (all but what Jev is sure is unreachable: a "reachable" alerts, so Claude checks it),
  # unsure (only what Jev is unsure of), or always.
  escalate: unless-unreachable
  llm:
    # auto: the Anthropic API when ANTHROPIC_API_KEY is set, else Claude Code when it is installed.
    via: auto
    model: claude-opus-5-5
    effort: medium

# Fix PRs (bulwark fix --pr, or the GitHub Action).
fix:
  # Commands that must keep passing. Empty: the build, typecheck and test scripts, those that pass before any change.
  checks: []
  # Commands to run after each install, before the checks (code generation your CI runs). Empty: prisma generate when the project uses Prisma.
  setup: []
  # Most Claude Code may spend on one repo in one run, and how long it and each check may take.
  budget_usd: 10
  time_limit_minutes: 30
  model: claude-opus-5-5
  effort: high
  # Who the fix commits are from: bot (github-actions[bot]) or actor (the person who started the run).
  # Vercel builds a private repo's previews only for its team members' commits: use actor there.
  commit_as: bot
`;

/** Writes a starter `.bulwark.yml`; refuses to replace one. */
export async function initConfig(dir: string): Promise<string> {
  const path = join(dir, REPO_FILE);
  try {
    await writeFile(path, STARTER_CONFIG, { flag: 'wx' });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new Error(`${path} already exists`);
    throw error;
  }
  return path;
}
