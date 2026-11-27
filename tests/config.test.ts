import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { centralRepos, DEFAULT_CONFIG, initConfig, loadCentral, loadConfig, STARTER_CONFIG } from '../src/config.js';

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'bulwark-config-'));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('loadConfig', () => {
  it('uses the defaults when there is no file: internet-facing, dry run, high threshold, Jev at 0.7, Claude', async () => {
    expect(await loadConfig(dir)).toEqual(DEFAULT_CONFIG);
    expect(DEFAULT_CONFIG).toMatchObject({ exposure: 'internet-facing', dryRun: true, notify: { threshold: 'high' }, triage: { jev: { threshold: 0.7 }, llm: { via: 'auto', model: 'claude-opus-5-5' } } });
  });

  it('layers the central defaults, its entry for the repo, then the repo file', async () => {
    await writeFile(join(dir, '.bulwark.yml'), 'notify:\n  threshold: critical\n');
    const central = {
      defaults: { exposure: 'internal' as const, dry_run: false },
      repos: [{ path: dir, notify: { threshold: 'moderate' as const, channels: [{ type: 'slack' as const, webhook_env: 'TEAM_HOOK' }] } }],
    };
    const config = await loadConfig(dir, { central });
    expect(config).toMatchObject({ exposure: 'internal', dryRun: false, notify: { threshold: 'critical', channels: [{ type: 'slack', webhookEnv: 'TEAM_HOOK' }] } });
  });

  it('rejects unknown keys and bad values with the file and the path in the message', async () => {
    await writeFile(join(dir, '.bulwark.yml'), 'exposre: internal\ntriage:\n  jev:\n    threshold: 2\n');
    const error = await loadConfig(dir).catch((e: Error) => e);
    expect(String(error)).toMatch(/\.bulwark\.yml: /);
    expect(String(error)).toContain('exposre: unknown key');
    expect(String(error)).toContain('triage.jev.threshold: Too big');
  });

  it('refuses containment from a repo file: only the central file can turn it on', async () => {
    await writeFile(join(dir, '.bulwark.yml'), 'tiers:\n  containment: true\n');
    await expect(loadConfig(dir)).rejects.toThrow(/only be turned on in the central config file/);
    await writeFile(join(dir, '.bulwark.yml'), '');
    expect((await loadConfig(dir, { central: { repos: [{ path: dir, tiers: { containment: true } }] } })).tiers.containment).toBe(true);
  });
});

describe('the central file', () => {
  it('reads repos, expanding ~, and is null when absent', async () => {
    const path = join(dir, 'config.yml');
    expect(await loadCentral(path)).toBeNull();
    await writeFile(path, 'repos:\n  - path: ~/code/app\n  - path: /srv/api\n');
    const central = (await loadCentral(path))!;
    expect(centralRepos(central)).toEqual([join(process.env.HOME ?? '', 'code/app'), '/srv/api']);
  });
});

describe('initConfig', () => {
  it('writes a starter file that reads back as the defaults, and never replaces one', async () => {
    const path = await initConfig(dir);
    expect(await readFile(path, 'utf8')).toBe(STARTER_CONFIG);
    expect(parse(STARTER_CONFIG)).toBeTruthy();
    expect(await loadConfig(dir)).toEqual({ ...DEFAULT_CONFIG, notify: { ...DEFAULT_CONFIG.notify, channels: [{ type: 'slack', webhookEnv: 'SLACK_WEBHOOK_URL' }] } });
    await expect(initConfig(dir)).rejects.toThrow(/already exists/);
  });
});
