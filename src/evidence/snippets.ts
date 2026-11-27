import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Evidence } from './evidence.js';

/** Lines `from` to `to` (1-based, inclusive) of one of the app's files. */
export interface Snippet {
  file: string;
  from: number;
  to: number;
  code: string;
}

/** Values that look like secrets: assigned to a name like key, secret, token or password, or with a known key prefix. */
const SECRET_ASSIGNMENT = /\b([A-Za-z0-9_]*(?:key|secret|token|passw(?:or)?d|credential|private)[A-Za-z0-9_]*)(\s*[:=]\s*)(['"`])([^'"`\n]{8,})\3/gi;
const SECRET_PREFIX = /\b(sk-[A-Za-z0-9_-]{16,}|sk_live_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|gh[ousr]_[A-Za-z0-9]{20,}|xox[abposr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,})\b/g;

/** Blanks values that look like secrets, so code sent to a model carries none it should not. */
export function redactSecrets(code: string): string {
  return code
    .replace(SECRET_ASSIGNMENT, (_m, name: string, sep: string, quote: string) => `${name}${sep}${quote}[redacted]${quote}`)
    .replace(SECRET_PREFIX, '[redacted]');
}

const RADIUS = 6;
const MAX_FILES = 4;
const MAX_LINES_PER_FILE = 40;

/**
 * The code around a finding's imports and uses: up to four files (uses of mentioned names first, then
 * other uses, then production imports), a few lines either side of each place, at most 40 lines a file.
 */
export async function snippetsFor(dir: string, evidence: Evidence): Promise<Snippet[]> {
  const places = new Map<string, number[]>();
  const add = (file: string, line: number) => {
    if (!places.has(file) && places.size >= MAX_FILES) return;
    places.set(file, [...(places.get(file) ?? []), line]);
  };
  for (const call of evidence.usage.calls) add(call.file, call.line);
  // How the app uses what it imports says more than the import line.
  for (const u of evidence.usage.uses) add(u.file, u.line);
  for (const site of evidence.usage.sites) if (!site.typeOnly) add(site.file, site.line);
  const snippets: Snippet[] = [];
  for (const [file, lines] of places) {
    let text: string;
    try {
      text = await readFile(join(dir, file), 'utf8');
    } catch {
      continue;
    }
    const all = text.split(/\r?\n/);
    for (const [from, to] of ranges(lines, all.length)) {
      snippets.push({ file, from, to, code: redactSecrets(all.slice(from - 1, to).join('\n')) });
    }
  }
  return snippets;
}

/** Windows around each line, merged where they touch, cut to MAX_LINES_PER_FILE in total. */
function ranges(lines: readonly number[], length: number): [number, number][] {
  const merged: [number, number][] = [];
  for (const line of [...new Set(lines)].sort((a, b) => a - b)) {
    const from = Math.max(1, line - RADIUS);
    const to = Math.min(length, line + RADIUS);
    const last = merged.at(-1);
    if (last && from <= last[1] + 1) last[1] = Math.max(last[1], to);
    else merged.push([from, to]);
  }
  const out: [number, number][] = [];
  let budget = MAX_LINES_PER_FILE;
  for (const [from, to] of merged) {
    if (budget <= 0) break;
    const end = Math.min(to, from + budget - 1);
    out.push([from, end]);
    budget -= end - from + 1;
  }
  return out;
}

/** Configuration that decides whether many advisories apply: framework config and middleware. */
const PROJECT_FILES = [
  'next.config.js',
  'next.config.mjs',
  'next.config.cjs',
  'next.config.ts',
  'middleware.ts',
  'middleware.js',
  'src/middleware.ts',
  'src/middleware.js',
  'vite.config.ts',
  'vite.config.js',
];
const MAX_PROJECT_LINES = 80;

/**
 * The project's configuration files (root and workspaces), at most 80 lines each, as one text block
 * that every finding of a Claude request shares. Empty when there are none.
 */
export async function projectContext(dir: string, workspaces: readonly string[]): Promise<string> {
  const parts: string[] = [];
  for (const folder of ['.', ...workspaces]) {
    for (const name of PROJECT_FILES) {
      const rel = folder === '.' ? name : `${folder}/${name}`;
      let text: string;
      try {
        text = await readFile(join(dir, rel), 'utf8');
      } catch {
        continue;
      }
      const lines = text.split(/\r?\n/);
      const cut = lines.length > MAX_PROJECT_LINES ? `\n[${lines.length - MAX_PROJECT_LINES} more lines]` : '';
      parts.push(`--- ${rel}\n${redactSecrets(lines.slice(0, MAX_PROJECT_LINES).join('\n'))}${cut}`);
    }
  }
  return parts.join('\n\n');
}
