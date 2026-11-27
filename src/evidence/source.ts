import { readdir, readFile as readText, stat } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import type { CallSite, ImportSite, Runtime, UseSite } from './imports.js';
import { classify, readFile } from './imports.js';

/** Folders that hold no source the app's authors wrote, or build output. Hidden folders are skipped too. */
const SKIP_DIRS = new Set([
  'node_modules',
  'dist',
  'build',
  'out',
  'coverage',
  'public',
  'static',
  'vendor',
  'storybook-static',
  'tmp',
]);
const SOURCE = /\.(?:[cm]?[jt]s|[jt]sx)$/;
const MAX_FILE_BYTES = 512 * 1024;
const MAX_FILES = 20_000;

export interface SourceFile {
  /** Relative to the project, with forward slashes. */
  path: string;
  runtime: Runtime;
  imports: ImportSite[];
  calls: CallSite[];
  uses: UseSite[];
}

export interface SourceIndex {
  files: SourceFile[];
  /** Files that could not be parsed, or were skipped for size. Evidence from them is missing. */
  unread: string[];
  /** True when the file limit cut the walk short. */
  truncated: boolean;
}

/**
 * Reads every JavaScript and TypeScript file in the project (workspaces included), skipping build
 * output and dependencies. `wanted` lists, per package, the names whose uses to record.
 */
export async function indexSource(dir: string, options: { next: boolean; wanted?: ReadonlyMap<string, ReadonlySet<string>> }): Promise<SourceIndex> {
  const files: SourceFile[] = [];
  const unread: string[] = [];
  const paths = await listSource(dir);
  for (const path of paths.files) {
    const rel = relative(dir, path).split(sep).join('/');
    let code: string;
    try {
      if ((await stat(path)).size > MAX_FILE_BYTES) {
        unread.push(rel);
        continue;
      }
      code = await readText(path, 'utf8');
    } catch {
      unread.push(rel);
      continue;
    }
    const facts = readFile(code, rel, options.wanted);
    if (facts === null) {
      unread.push(rel);
      continue;
    }
    if (facts.imports.length === 0) continue;
    files.push({ path: rel, runtime: classify(rel, facts.directives, options.next), imports: facts.imports, calls: facts.calls, uses: facts.uses });
  }
  return { files, unread, truncated: paths.truncated };
}

async function listSource(root: string): Promise<{ files: string[]; truncated: boolean }> {
  const files: string[] = [];
  const queue = [root];
  while (queue.length > 0) {
    const dir = queue.shift()!;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (entry.isDirectory()) {
        // Hidden folders hold tools' copies and caches (.claude/worktrees, .next, .git), not the app.
        if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.')) queue.push(join(dir, entry.name));
      } else if (entry.isFile() && SOURCE.test(entry.name) && !entry.name.endsWith('.d.ts') && !/\.min\.[cm]?js$/.test(entry.name)) {
        if (files.length >= MAX_FILES) return { files, truncated: true };
        files.push(join(dir, entry.name));
      }
    }
  }
  return { files, truncated: false };
}
