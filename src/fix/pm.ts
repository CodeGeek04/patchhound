import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

/** What a command printed and how it ended. */
export interface ToolResult {
  code: number | null;
  /** Set when the time limit stopped it. */
  timedOut: boolean;
  /** The output's last lines, stdout and stderr together, as a person would see it. */
  output: string;
}

const MAX_OUTPUT = 64 * 1024;

/**
 * Runs a command without a shell and collects its output (the last 64 KB). It never throws for a
 * failing command: `code` says how it ended. An argv that cannot start (no such program) gives code 127.
 */
/**
 * Credentials patchhound itself uses, and the ones GitHub Actions hands every step. Installs,
 * install scripts, checks and the coding agent's tools run without them: a dependency or a prompt
 * injection must not be able to read them.
 */
export const SECRET_NAMES = [
  'GH_TOKEN',
  'GITHUB_TOKEN',
  'GH_ENTERPRISE_TOKEN',
  'CLAUDE_CODE_OAUTH_TOKEN',
  'ANTHROPIC_API_KEY',
  'TYPESAFE_API_KEY',
  'SLACK_WEBHOOK_URL',
  'ACTIONS_RUNTIME_TOKEN',
  'ACTIONS_RUNTIME_URL',
  'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
  'ACTIONS_ID_TOKEN_REQUEST_URL',
  'ACTIONS_CACHE_URL',
  'ACTIONS_RESULTS_URL',
];

/** This process's environment without SECRET_NAMES, except those in `keep`. */
export function safeEnv(keep: readonly string[] = []): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const name of SECRET_NAMES) if (!keep.includes(name)) delete env[name];
  return env;
}

/** Runs a program; its environment is `env`, else this process's without the secrets (see safeEnv). */
export function runTool(argv: readonly string[], options: { cwd: string; env?: NodeJS.ProcessEnv; timeoutMs?: number; input?: string }): Promise<ToolResult> {
  return new Promise((resolve) => {
    const [command, ...args] = argv as [string, ...string[]];
    const child = spawn(command, args, { cwd: options.cwd, env: options.env ?? safeEnv(), stdio: [options.input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'] });
    let output = '';
    let timedOut = false;
    const keep = (chunk: Buffer) => {
      output += chunk.toString();
      if (output.length > MAX_OUTPUT * 2) output = output.slice(-MAX_OUTPUT);
    };
    child.stdout?.on('data', keep);
    child.stderr?.on('data', keep);
    const timer = options.timeoutMs
      ? setTimeout(() => {
          timedOut = true;
          child.kill('SIGTERM');
          setTimeout(() => child.kill('SIGKILL'), 5000).unref();
        }, options.timeoutMs)
      : undefined;
    child.on('error', (error) => {
      if (timer) clearTimeout(timer);
      // Node reports a folder that does not exist as the program not existing (spawn git ENOENT).
      const why = (error as NodeJS.ErrnoException).code === 'ENOENT' && !existsSync(options.cwd) ? `no such folder: ${options.cwd}` : String(error);
      resolve({ code: 127, timedOut, output: `${output}${why}`.slice(-MAX_OUTPUT) });
    });
    child.on('close', (code) => {
      if (timer) clearTimeout(timer);
      resolve({ code, timedOut, output: output.slice(-MAX_OUTPUT) });
    });
    if (options.input !== undefined && child.stdin) {
      // A command that exits before reading its input must not crash us with EPIPE; 'close' reports it.
      child.stdin.on('error', () => {});
      child.stdin.end(options.input);
    }
  });
}

/** The last `n` lines of some output, for messages and the agent's prompt. */
export function tail(output: string, n = 40): string {
  const lines = output.trimEnd().split('\n');
  return lines.slice(-n).join('\n');
}

/**
 * How to run the project's package manager. npm and pnpm by name; yarn as the project runs it: its
 * yarnPath, else `yarn` on PATH, else the version package.json names through npx.
 */
export async function managerCommand(manager: string, cwd: string): Promise<string[]> {
  if (manager === 'npm') return ['npm'];
  if (manager === 'pnpm') {
    // The pnpm the project pins (packageManager) when the installed one is another major: a pnpm 9
    // project run with pnpm 11 would change its lockfile format and refuse the pin.
    const pinned = await pinnedVersion(cwd, 'pnpm');
    const installed = await installedMajor(cwd);
    return pinned && installed !== Number(pinned.split('.')[0]) ? ['npx', '-y', `pnpm@${pinned}`] : ['pnpm'];
  }
  const yarnrc = await readFile(join(cwd, '.yarnrc.yml'), 'utf8').catch(() => '');
  const yarnPath = /^yarnPath:\s*["']?([^"'\n]+)/m.exec(yarnrc)?.[1];
  if (yarnPath) return ['node', join(cwd, yarnPath.trim())];
  if ((await runTool(['yarn', '--version'], { cwd, timeoutMs: 30_000 })).code === 0) return ['yarn'];
  const manifest = JSON.parse(await readFile(join(cwd, 'package.json'), 'utf8').catch(() => '{}')) as { packageManager?: string };
  const named = /^yarn@(\d[^+]*)/.exec(manifest.packageManager ?? '')?.[1];
  if (manager === 'yarn-berry') return ['npx', '-y', '-p', `@yarnpkg/cli-dist@${named ?? '4'}`, 'yarn'];
  return ['npx', '-y', `yarn@${named ?? '1'}`];
}

/**
 * Environment for lockfile updates: quieter, no telemetry, and yarn 2+ allowed to change its lockfile.
 * CI is cleared: in CI, pnpm and yarn 2+ refuse to change a lockfile, which is the point here.
 */
export function managerEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...safeEnv(), npm_config_loglevel: 'warn', YARN_ENABLE_TELEMETRY: '0', YARN_ENABLE_IMMUTABLE_INSTALLS: '0' };
  delete env.CI;
  return env;
}

/** The flags that keep a lockfile update away from install scripts (yarn 2+ only touches the lockfile). */
export const QUIET: Record<string, string[]> = {
  npm: ['--ignore-scripts', '--no-audit', '--no-fund'],
  pnpm: ['--ignore-scripts'],
  'yarn-berry': ['--mode=update-lockfile'],
  'yarn-classic': ['--ignore-scripts', '--non-interactive'],
};

/** Resolves package.json changes into the lockfile without installing (yarn 1 has no such mode, so it installs). */
export function lockfileUpdate(manager: string): string[] {
  switch (manager) {
    case 'npm':
      return ['install', '--package-lock-only', ...QUIET.npm!];
    case 'pnpm':
      return ['install', '--lockfile-only', ...QUIET.pnpm!];
    case 'yarn-berry':
      return ['install', ...QUIET['yarn-berry']!];
    default:
      return ['install', ...QUIET['yarn-classic']!];
  }
}

/** Installs exactly what the lockfile says, for running the project's checks. */
/**
 * The install that checks run on: the lockfile as it is. `legacyPeerDeps`: npm refuses a lockfile that
 * already breaks a peer range (as its lockfile updates do, see BrokenPeer) unless told to accept it.
 */
export function cleanInstall(manager: string, scripts: boolean, legacyPeerDeps = false): string[] {
  const noScripts = scripts ? [] : ['--ignore-scripts'];
  switch (manager) {
    case 'npm':
      return ['ci', '--no-audit', '--no-fund', ...noScripts, ...(legacyPeerDeps ? ['--legacy-peer-deps'] : [])];
    case 'pnpm':
      // pnpm 11 and later fail the install when a dependency has build scripts the project never
      // approved; pnpm 9 and 10 skip them with a warning. Skipping is what the project gets
      // elsewhere, so keep that (approved scripts still run; code generation is `fix.setup`).
      return ['install', '--frozen-lockfile', '--config.strict-dep-builds=false', ...noScripts];
    case 'yarn-berry':
      return ['install', '--immutable', ...(scripts ? [] : ['--mode=skip-build'])];
    default:
      return ['install', '--frozen-lockfile', '--non-interactive', ...noScripts];
  }
}

/** The version package.json's `packageManager` pins for `name`, if any. */
export async function pinnedVersion(cwd: string, name: string): Promise<string | null> {
  const manifest = JSON.parse(await readFile(join(cwd, 'package.json'), 'utf8').catch(() => '{}')) as { packageManager?: string };
  return new RegExp(`^${name}@(\\d[^+]*)`).exec(manifest.packageManager ?? '')?.[1] ?? null;
}

async function installedMajor(cwd: string): Promise<number | null> {
  const result = await runTool(['pnpm', '--version'], { cwd, timeoutMs: 60_000 });
  const major = Number(/^(\d+)\./.exec(result.output.trim().split('\n').pop() ?? '')?.[1]);
  return result.code === 0 && Number.isFinite(major) ? major : null;
}

/** The major version of the pnpm the project runs with: the one it pins, else the installed one; null when neither is known. */
export async function pnpmMajor(cwd: string): Promise<number | null> {
  const pinned = await pinnedVersion(cwd, 'pnpm');
  return pinned ? Number(pinned.split('.')[0]) : installedMajor(cwd);
}
