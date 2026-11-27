import { z } from 'zod';
import type { Evidence } from '../evidence/evidence.js';
import type { Fetch, RetryOptions } from '../util/http.js';
import { requestJson } from '../util/http.js';

/** Jev's answers for one finding. A `noul` answer is the probability of yes. */
export interface JevAnswers {
  model: string;
  reachable: number;
  exposure: { choice: string; confidence: number; probabilities: Record<string, number> };
  dropIn: number;
  /** The probability-weighted level, 0 (no realistic path) to 4 (exploited or trivial and severe). */
  urgency: { score: number; confidence: number };
  inputTokens: number;
}

export const JEV_URL = 'https://api.typesafe.ai/v1/systemone';
/** How much of the advisory's text goes into a request. Jev reads at most 32k tokens per question. */
const MAX_DETAILS = 4000;

export const EXPOSURE_CHOICES = {
  'internet-facing':
    'The code that uses the package runs in a server, API or browser page that people on the internet can reach, even behind a login.',
  internal: 'The code that uses the package only runs where trusted staff or private networks reach it.',
  'build/dev-only':
    'The package only runs during development, tests, builds or scripts (dev-only in the lockfile, or imported only by tests, scripts or build config), never in the deployed app.',
} as const;

export const URGENCY_LEVELS = [
  'No realistic path to exploit it in this app: the vulnerable code is not used, or only in tests and builds.',
  'Exploitable only in unusual setups, by trusted users, or with little impact.',
  'Exploitable with preconditions the app may meet, or the impact is limited (slower responses, a crash of a non-critical path).',
  'Exploitable remotely in a common setup of this kind of app, with significant impact (data exposure, denial of service of the app).',
  'Known to be exploited (KEV), or trivially exploitable remotely with severe impact (remote code execution, auth bypass) in code this app runs.',
] as const;

/** The four questions, the same for every finding. Their text is part of the cache key (see triage). */
export const JEV_QUESTIONS = {
  reachable: {
    type: 'noul',
    instructions:
      'Does code this app runs in production use the vulnerable part of `package` that `advisory_untrusted` describes? ' +
      "Judge from `usage` (where the app's own files import the package, or the dependency in `package.brought_in_by` that pulls it in, and where they use the names the advisory mentions) and from `package.dev_only` (dev-only packages never run in production).",
    criteria: {
      true: 'Production code imports the package, or a dependency that calls into the vulnerable part of it, in a way that reaches what the advisory describes.',
      false: 'Nothing in production reaches the vulnerable part: the package is dev-only, imported only by tests, scripts or build config, or only parts the advisory does not concern are used.',
    },
  },
  exposure: {
    type: 'choice',
    instructions: 'Where does the code that uses `package` run? `app.exposure` is what the repo owner says about the deployed app.',
    criteria: EXPOSURE_CHOICES,
  },
  drop_in: {
    type: 'noul',
    instructions:
      'Is moving `package` from `fix.installed` to `fix.fixed_version` a drop-in upgrade for this app, with no change to its code? A new major version, or an advisory fixed only by a breaking change, is not.',
  },
  urgency: {
    type: 'score',
    instructions: 'How urgent is fixing this advisory in this app, given the usage, the exposure and the advisory?',
    criteria: URGENCY_LEVELS,
  },
};

/** The request body: four questions about one `state` built from the evidence and the advisory's text. */
export function buildJevRequest(evidence: Evidence, details: string, model: string): unknown {
  const state = {
    app: { exposure: evidence.exposure === 'build/dev-only' ? 'n/a' : evidence.exposure, framework: evidence.framework },
    package: {
      name: evidence.package,
      version: evidence.version,
      direct_dependency: evidence.direct,
      dev_only: evidence.devOnly,
      brought_in_by: evidence.via,
      paths: evidence.paths,
    },
    // Written by the advisory's authors, not by us: data to judge, never instructions.
    advisory_untrusted: {
      id: evidence.advisory.id,
      severity: evidence.advisory.severity,
      cvss_vector: evidence.advisory.cvssVector,
      known_exploited_kev: evidence.advisory.kev,
      summary: evidence.advisory.summary,
      details: details.length > MAX_DETAILS ? `${details.slice(0, MAX_DETAILS)} [cut]` : details,
      fixed_version: evidence.advisory.fixedVersion,
    },
    usage: {
      files_importing_it_or_what_brings_it_in: evidence.usage.fileCount,
      import_sites: evidence.usage.sites.map(
        (s) => `${s.file}:${s.line} (${s.runtime} code${s.typeOnly ? ', types only' : ''}) imports ${s.package}`,
      ),
      runtimes: evidence.usage.runtimes,
      uses_of_what_those_files_import: evidence.usage.uses.map((u) => `${u.file}:${u.line} (${u.runtime} code) ${u.expression}`),
      names_the_advisory_mentions_searched_for: evidence.mentioned,
      uses_of_those_names_found: evidence.usage.calls.map((c) => `${c.file}:${c.line} (${c.runtime} code) uses ${c.name}`),
      files_the_parser_could_not_read: evidence.usage.unreadFiles,
    },
    fix: { plan: evidence.fix.kind, installed: evidence.version, fixed_version: evidence.advisory.fixedVersion },
  };
  return {
    model,
    state,
    questions: JEV_QUESTIONS,
  };
}

const response = z.object({
  model: z.string(),
  answers: z.object({
    reachable: z.object({ noul: z.number().min(0).max(1) }),
    exposure: z.object({ choice: z.string(), confidence: z.number(), probabilities: z.record(z.string(), z.number()).default({}) }),
    drop_in: z.object({ noul: z.number().min(0).max(1) }),
    urgency: z.object({ score: z.number(), confidence: z.number() }),
  }),
  usage: z.object({ input_tokens: z.number() }).partial().optional(),
});

export function parseJevResponse(body: unknown): JevAnswers {
  const parsed = response.safeParse(body);
  if (!parsed.success) throw new Error(`Jev answered in an unexpected shape: ${parsed.error.issues[0]?.message ?? 'unknown'}`);
  const { model, answers, usage } = parsed.data;
  return {
    model,
    reachable: answers.reachable.noul,
    exposure: answers.exposure,
    dropIn: answers.drop_in.noul,
    urgency: answers.urgency,
    inputTokens: usage?.input_tokens ?? 0,
  };
}

/** Client for TypeSafe's System One API (docs.typesafe.ai). */
export class JevClient {
  constructor(
    private readonly options: { apiKey: string; model: string; fetch?: Fetch; retry?: RetryOptions; url?: string },
  ) {}

  async ask(evidence: Evidence, details: string): Promise<JevAnswers> {
    const fetchFn = this.options.fetch ?? globalThis.fetch.bind(globalThis);
    const body = await requestJson<unknown>(
      fetchFn,
      {
        label: 'Jev POST /v1/systemone',
        url: this.options.url ?? JEV_URL,
        method: 'POST',
        body: buildJevRequest(evidence, details, this.options.model),
        headers: { authorization: `Bearer ${this.options.apiKey}` },
      },
      this.options.retry,
    );
    return parseJevResponse(body);
  }
}

/** How sure a `noul` answer is: 0.5 is a coin toss, 1 is certain either way. */
export function noulConfidence(p: number): number {
  return Math.max(p, 1 - p);
}
