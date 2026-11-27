import type { FixStep } from './plan.js';

type Refresh = Extract<FixStep, { kind: 'refresh' }>;

/**
 * One thing a refresh needs done: run a command (`argv`, the program first), or, for yarn 1, delete
 * the yarn.lock entries of some packages so that the next `yarn install` resolves their ranges again.
 */
export type RefreshRun = { kind: 'command'; argv: string[] } | { kind: 'unlock'; packages: string[] };

/**
 * What carries out refresh steps, in order:
 * - npm takes every name in one run: it re-resolves them together, parents and children alike.
 * - pnpm goes round by round (a parent's refresh before the refresh of a child that waits for it),
 *   and within a round the names a package.json lists go before the others: given one listed name,
 *   `pnpm update` updates only listed packages (pnpm 10.4.1 left @xmldom/xmldom alone in
 *   `pnpm update zod @xmldom/xmldom`). In a pnpm workspace every run needs `-r`, or the packages
 *   that only workspace packages use stay where they are.
 * - yarn 2 and later: `yarn up -R` resolves every range of those packages again, in one run.
 * - yarn 1 has no command for it (`yarn upgrade` skips a package no package.json lists), but
 *   deleting a package's yarn.lock entries makes `yarn install` resolve its ranges again.
 * An aliased copy is updated by its alias.
 */
export function refreshRuns(steps: readonly Refresh[], manager: string, workspaces: boolean): RefreshRun[] {
  if (steps.length === 0) return [];
  const names = (list: readonly Refresh[]) => [...new Set(list.map((step) => step.alias ?? step.package))].sort();
  const run = (...argv: string[]): RefreshRun => ({ kind: 'command', argv });
  if (manager === 'npm') return [run('npm', 'update', ...names(steps), '--package-lock-only')];
  if (manager === 'yarn-berry') return [run('yarn', 'up', '-R', ...names(steps))];
  if (manager === 'yarn-classic') return [{ kind: 'unlock', packages: names(steps) }, run('yarn', 'install')];
  const rounds = [...new Set(steps.map((step) => step.round ?? 0))].sort((a, b) => a - b);
  return rounds.flatMap((round) => {
    const inRound = steps.filter((step) => (step.round ?? 0) === round);
    return [names(inRound.filter((step) => step.direct)), names(inRound.filter((step) => !step.direct))]
      .filter((group) => group.length > 0)
      .map((group) => run('pnpm', 'update', ...(workspaces ? ['-r'] : []), ...group, '--lockfile-only'));
  });
}

/**
 * A yarn 1 lockfile without the entries of these packages (by the name each entry is asked for, so
 * an alias by its alias), everything else unchanged. Entries are separated by a blank line; the
 * file's own line endings (LF or CRLF) are kept.
 */
export function unlockYarnEntries(text: string, packages: readonly string[]): string {
  const drop = new Set(packages);
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  const blocks = text.split(new RegExp(`${eol}${eol}(?=\\S)`));
  const kept = blocks.filter((block) => {
    const header = block.split(eol)[0]!;
    if (header.startsWith('#') || !header.endsWith(':')) return true;
    const names = header
      .slice(0, -1)
      .split(/,\s*/)
      .map((part) => {
        const descriptor = part.trim().replace(/^"|"$/g, '');
        return descriptor.slice(0, descriptor.indexOf('@', 1));
      });
    return !names.some((name) => drop.has(name));
  });
  const result = kept.join(eol + eol);
  return text.endsWith(eol) && !result.endsWith(eol) ? `${result}${eol}` : result;
}
