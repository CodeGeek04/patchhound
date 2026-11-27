import { access, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { managerCommand, runTool, safeEnv, tail } from './pm.js';

/** A command that tells whether the project still works: a typecheck, its tests, its build. */
export interface Check {
  name: string;
  argv: string[];
}

export interface CheckResult {
  name: string;
  command: string;
  passed: boolean;
  timedOut: boolean;
  /** The end of its output, for the PR and for the coding agent. */
  output: string;
  seconds: number;
}

/** The last lines of a check's output that say something: colours, blank lines and stack frames dropped. */
export function failureExcerpt(output: string, n = 20): string {
  // eslint-disable-next-line no-control-regex
  const plain = output.replace(/\u001b\[[0-9;]*[A-Za-z]/g, '');
  return plain
    .split('\n')
    .map((line) => line.trimEnd())
    .filter((line) => line.trim() !== '' && !/^\s*at\s/.test(line))
    .slice(-n)
    .join('\n');
}

const TYPECHECK_SCRIPTS = ['typecheck', 'type-check', 'check-types', 'types', 'tsc'];

/** Where a Prisma project keeps its schema or config. */
const PRISMA_FILES = ['prisma/schema.prisma', 'schema.prisma', 'prisma.config.ts', 'prisma/schema'];

/**
 * What has to run after an install for the checks to see what CI sees: `configured` (the `fix.setup`
 * setting), else `prisma generate` when the project uses Prisma (a client generated into the source
 * tree, which no build script makes, fails every check without it).
 */
export async function detectSetup(dir: string, configured?: readonly string[]): Promise<Check[]> {
  if (configured && configured.length > 0) return configured.map((command) => ({ name: command, argv: ['sh', '-c', command] }));
  const manifest = JSON.parse(await readFile(join(dir, 'package.json'), 'utf8').catch(() => '{}')) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  const deps = { ...manifest.dependencies, ...manifest.devDependencies };
  if (!('prisma' in deps || '@prisma/client' in deps)) return [];
  const found = await Promise.all(PRISMA_FILES.map((file) => exists(join(dir, file))));
  return found.some(Boolean) ? [{ name: 'prisma generate', argv: ['npx', '--no-install', 'prisma', 'generate'] }] : [];
}
const NO_TESTS = /no test specified/i;

/**
 * The project's checks, in the order they fail fastest: a typecheck (its script, else `tsc --noEmit`
 * when there is a tsconfig and TypeScript is installed), its `test` script, its `build` script.
 * `configured` (the `fix.checks` setting) replaces the detection; each entry runs through the shell.
 */
export async function detectChecks(dir: string, manager: string, configured?: readonly string[]): Promise<Check[]> {
  if (configured && configured.length > 0) return configured.map((command) => ({ name: command, argv: ['sh', '-c', command] }));
  const manifest = JSON.parse(await readFile(join(dir, 'package.json'), 'utf8').catch(() => '{}')) as {
    scripts?: Record<string, string>;
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  const scripts = manifest.scripts ?? {};
  const pm = await managerCommand(manager, dir);
  const script = (name: string): Check => ({ name, argv: [...pm, 'run', name] });
  // The build goes first: in a monorepo the type check and the tests often import other workspace
  // packages from their built output (shadcn/ui's typecheck needs packages/shadcn's dist).
  const checks: Check[] = [];
  if (scripts.build) checks.push(script('build'));
  const typecheck = TYPECHECK_SCRIPTS.find((name) => scripts[name]);
  if (typecheck) checks.push(script(typecheck));
  else if ((await exists(join(dir, 'tsconfig.json'))) && ('typescript' in { ...manifest.dependencies, ...manifest.devDependencies })) {
    checks.push({ name: 'tsc --noEmit', argv: ['npx', '--no-install', 'tsc', '--noEmit'] });
  }
  if (scripts.test && !NO_TESTS.test(scripts.test)) checks.push(script('test'));
  return checks;
}

/**
 * Runs each check with CI set (so test runners run once instead of watching). A check that runs past
 * `timeoutMs` counts as failed.
 */
export async function runChecks(dir: string, checks: readonly Check[], options: { timeoutMs: number; env?: NodeJS.ProcessEnv }): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  for (const check of checks) {
    const started = Date.now();
    const result = await runTool(check.argv, { cwd: dir, env: { ...(options.env ?? safeEnv()), CI: '1', FORCE_COLOR: '0' }, timeoutMs: options.timeoutMs });
    results.push({
      name: check.name,
      command: check.argv[0] === 'sh' ? check.argv[2]! : check.argv.join(' '),
      passed: result.code === 0,
      timedOut: result.timedOut,
      output: tail(result.output, 60),
      seconds: Math.round((Date.now() - started) / 1000),
    });
  }
  return results;
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}
