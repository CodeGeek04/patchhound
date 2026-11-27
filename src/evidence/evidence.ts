import { createHash } from 'node:crypto';
import type { Exposure as RepoExposure } from '../config.js';
import type { ScanFinding } from '../scan.js';
import type { Severity } from '../watch/advisory.js';
import type { ImportSite, Runtime } from './imports.js';
import type { SourceIndex } from './source.js';

export type Exposure = RepoExposure | 'build/dev-only';

export interface UsageSite {
  file: string;
  line: number;
  runtime: Runtime;
  /** The package the file imports: the vulnerable one, or a direct dependency that brings it in. */
  package: string;
  kind: ImportSite['kind'];
  typeOnly: boolean;
}

export interface Evidence {
  /** The scan's finding key (`advisory|package@version`). */
  key: string;
  package: string;
  version: string;
  advisory: {
    id: string;
    aliases: string[];
    kind: 'vulnerability' | 'malicious';
    severity: Severity;
    cvssVector: string | null;
    kev: boolean;
    epss: number | null;
    summary: string;
    fixedVersion: string | null;
  };
  direct: boolean;
  devOnly: boolean;
  /** The names the app declares that bring the package in (itself when direct). */
  via: string[];
  paths: string[];
  /** build/dev-only for a dev-only package, else what the repo's config says. */
  exposure: Exposure;
  framework: { next: boolean; appRouter: boolean };
  usage: {
    /** Where the app's own files import the package or what brings it in, server code first. At most 12. */
    sites: UsageSite[];
    /** All such imports, and the files they are in. */
    siteCount: number;
    fileCount: number;
    /** Where the importing files run, each once. */
    runtimes: Runtime[];
    /** Uses of names the advisory mentions, on the vulnerable package. At most 12. */
    calls: { file: string; line: number; runtime: Runtime; name: string }[];
    /** Uses of anything the app imports from the package or what brings it in, production code first. At most 12. */
    uses: { file: string; line: number; runtime: Runtime; package: string; expression: string }[];
    /** Files the parser could not read. Usage may be missing from them. */
    unreadFiles: number;
    /** True when the project had more source files than were read. */
    truncated: boolean;
  };
  /** Function and property names in the advisory's code spans. */
  mentioned: string[];
  fix: { kind: string | null; actions: string[] };
  /** Hash of everything above that bears on triage (not line numbers, KEV or EPSS, which the policy reads itself). */
  hash: string;
}

const RUNTIME_ORDER: readonly Runtime[] = ['server', 'app', 'client', 'build', 'script', 'test'];
const MAX_SITES = 12;

/** The evidence record for one finding. `mentioned` holds the names the advisory mentions (see mentionedNames). */
export function buildEvidence(
  finding: ScanFinding,
  context: {
    source: SourceIndex;
    exposure: RepoExposure;
    framework: Evidence['framework'];
    mentioned: readonly string[];
    /** KEV status from the last scan, for when the KEV feed is down (`finding.kev` is null). */
    lastKnownKev?: boolean;
  },
): Evidence {
  const names = new Set([finding.package, ...finding.via]);
  const sites: UsageSite[] = [];
  const calls: Evidence['usage']['calls'] = [];
  const uses: Evidence['usage']['uses'] = [];
  const files = new Set<string>();
  for (const file of context.source.files) {
    for (const site of file.imports) {
      if (!names.has(site.package)) continue;
      sites.push({ file: file.path, line: site.line, runtime: file.runtime, package: site.package, kind: site.kind, typeOnly: site.typeOnly });
      files.add(file.path);
    }
    for (const u of file.uses) {
      if (names.has(u.package)) uses.push({ file: file.path, line: u.line, runtime: file.runtime, package: u.package, expression: u.expression });
    }
    for (const call of file.calls) {
      if (call.package === finding.package && context.mentioned.includes(call.name)) {
        calls.push({ file: file.path, line: call.line, runtime: file.runtime, name: call.name });
      }
    }
  }
  const rank = (runtime: Runtime) => RUNTIME_ORDER.indexOf(runtime);
  const ordered = [...sites].sort(
    (a, b) => Number(a.typeOnly) - Number(b.typeOnly) || rank(a.runtime) - rank(b.runtime) || a.file.localeCompare(b.file) || a.line - b.line,
  );
  calls.sort((a, b) => rank(a.runtime) - rank(b.runtime) || a.file.localeCompare(b.file) || a.line - b.line);
  // One use per file and expression first, so twelve lines show twelve different places.
  uses.sort((a, b) => rank(a.runtime) - rank(b.runtime) || a.file.localeCompare(b.file) || a.line - b.line);
  const seenUse = new Set<string>();
  const distinctUses = uses.filter((u) => {
    const key = `${u.file}|${u.expression}`;
    if (seenUse.has(key)) return false;
    seenUse.add(key);
    return true;
  });
  const runtimes = RUNTIME_ORDER.filter((r) => sites.some((s) => s.runtime === r && !s.typeOnly));
  const evidence: Omit<Evidence, 'hash'> = {
    key: finding.key,
    package: finding.package,
    version: finding.version,
    advisory: {
      id: finding.advisory.id,
      aliases: finding.advisory.aliases,
      kind: finding.advisory.kind,
      severity: finding.advisory.severity,
      cvssVector: finding.advisory.cvssVector ?? null,
      kev: finding.kev === null ? (context.lastKnownKev ?? false) : finding.kev.length > 0,
      epss: finding.epss,
      summary: finding.advisory.summary,
      fixedVersion: finding.fixedVersion,
    },
    direct: finding.direct,
    devOnly: finding.devOnly,
    via: finding.via,
    paths: finding.paths.map((chain) => chain.join(' > ')),
    exposure: finding.devOnly ? 'build/dev-only' : context.exposure,
    framework: context.framework,
    usage: {
      sites: ordered.slice(0, MAX_SITES),
      siteCount: sites.length,
      fileCount: files.size,
      runtimes,
      calls: calls.slice(0, MAX_SITES),
      uses: distinctUses.slice(0, MAX_SITES),
      unreadFiles: context.source.unread.length,
      truncated: context.source.truncated,
    },
    mentioned: [...context.mentioned],
    fix: { kind: finding.fix?.kind ?? null, actions: finding.fix?.actions ?? [] },
  };
  return { ...evidence, hash: evidenceHash(evidence, finding.advisoryFingerprint) };
}

function evidenceHash(e: Omit<Evidence, 'hash'>, fingerprint: string): string {
  const stable = {
    package: e.package,
    version: e.version,
    fingerprint,
    direct: e.direct,
    devOnly: e.devOnly,
    via: e.via,
    exposure: e.exposure,
    framework: e.framework,
    fixedVersion: e.advisory.fixedVersion,
    fix: e.fix.kind,
    // Lines move with every edit above them; the file, where it runs and what it imports are what count.
    sites: [...new Set(e.usage.sites.map((s) => `${s.file}|${s.runtime}|${s.package}|${s.kind}|${s.typeOnly}`))],
    siteCount: e.usage.siteCount,
    calls: [...new Set(e.usage.calls.map((c) => `${c.file}|${c.name}`))],
    uses: [...new Set(e.usage.uses.map((u) => `${u.file}|${u.expression}`))],
    mentioned: e.mentioned,
  };
  return createHash('sha256').update(JSON.stringify(stable)).digest('hex').slice(0, 16);
}

const NOT_NAMES = new Set([
  'true',
  'false',
  'null',
  'undefined',
  'function',
  'object',
  'string',
  'number',
  'boolean',
  'require',
  'import',
  'export',
  'default',
  'module',
  'exports',
  'constructor',
  'prototype',
  '__proto__',
  'this',
  'new',
  'return',
  'async',
  'await',
  'const',
  'let',
  'var',
  'npm',
  'node',
  'http',
  'https',
  // JavaScript's own globals: an advisory names them, but the app's uses of them say nothing about the package.
  'Array',
  'AsyncLocalStorage',
  'Buffer',
  'Date',
  'Error',
  'JSON',
  'Map',
  'Math',
  'Number',
  'Object',
  'Promise',
  'Proxy',
  'RangeError',
  'RegExp',
  'Set',
  'String',
  'Symbol',
  'TypeError',
  'URL',
  'URLSearchParams',
  'eval',
]);

/**
 * Function and property names the advisory puts in code spans: `template`, `merge()`, `_.set` (the last
 * part). Version numbers, paths and the package's own name are left out.
 */
export function mentionedNames(text: string, packageName: string): string[] {
  const names = new Set<string>();
  for (const match of text.matchAll(/`([^`\n]{1,80})`/g)) {
    const span = match[1]!.trim().replace(/\(.*\)$/s, '');
    if (/[\s/<>=]/.test(span) || span === packageName) continue;
    const last = span.split('.').pop() ?? '';
    if (/^[A-Za-z_$][\w$]{2,}$/.test(last) && !NOT_NAMES.has(last) && last !== packageName) names.add(last);
    if (names.size >= 10) break;
  }
  return [...names];
}
