import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

interface Step {
  name?: string;
  uses?: string;
  if?: string;
  run?: string;
  env?: Record<string, string>;
  with?: Record<string, string>;
}

const steps = async (): Promise<Step[]> => (parse(await readFile(fileURLToPath(new URL('../action.yml', import.meta.url)), 'utf8')) as { runs: { steps: Step[] } }).runs.steps;

describe('action.yml', () => {
  it("runs every bulwark command with bulwark's own tsconfig, never the checkout's", async () => {
    const tsx = (await steps()).filter((step) => step.run?.includes('node_modules/.bin/tsx'));
    expect(tsx.map((step) => step.name)).toHaveLength(3);
    for (const step of tsx) {
      for (const line of step.run!.split('\n').filter((l) => l.includes('node_modules/.bin/tsx'))) {
        expect(line).toContain('/node_modules/.bin/tsx" --tsconfig "$GITHUB_ACTION_PATH/tsconfig.json" "$GITHUB_ACTION_PATH/src/cli.ts"');
      }
      expect(step.env?.TSX_TSCONFIG_PATH).toBe('${{ github.action_path }}/tsconfig.json');
    }
  });

  it('keeps the scan job off every cache the fix job saved, and the fix job on the scan job\'s data', async () => {
    const os = '${{ runner.os }}';
    const run = '${{ github.run_id }}';
    const state = ['~/.cache/bulwark', '.bulwark'];
    const caches = (await steps())
      .filter((step) => step.uses?.startsWith('actions/cache/'))
      .map((step) => [step.uses!.split('@')[0], step.if, step.with!.key, step.with!['restore-keys'] ?? null, step.with!.path!.trim().split('\n').map((p) => p.trim())]);
    expect(caches).toEqual([
      ['actions/cache/restore', "inputs.mode == 'scan'", `bulwark-${os}-scan-${run}`, `bulwark-${os}-scan-`, state],
      // The fix history first, then this run's scan cache over it, by its exact key.
      ['actions/cache/restore', "inputs.mode == 'fix'", `bulwark-${os}-fix-${run}`, `bulwark-${os}-fix-`, ['.bulwark/fix-audit.jsonl']],
      ['actions/cache/restore', "inputs.mode == 'fix'", `bulwark-${os}-scan-${run}`, null, state],
      ['actions/cache/save', "always() && inputs.mode == 'scan'", `bulwark-${os}-scan-${run}`, null, state],
      ['actions/cache/save', "always() && inputs.mode == 'fix'", `bulwark-${os}-fix-${run}`, null, ['.bulwark/fix-audit.jsonl']],
    ]);
  });
});
