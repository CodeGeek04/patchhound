import { describe, expect, it } from 'vitest';
import { mapLimit } from '../../src/util/pool.js';

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe('mapLimit', () => {
  it('keeps input order even when later items finish first', async () => {
    const out = await mapLimit([30, 10, 20], 2, async (ms) => {
      await sleep(ms);
      return ms * 2;
    });
    expect(out).toEqual([60, 20, 40]);
  });

  it('never runs more than the limit at once', async () => {
    let running = 0;
    let peak = 0;
    await mapLimit([1, 2, 3, 4, 5, 6], 2, async () => {
      running++;
      peak = Math.max(peak, running);
      await sleep(5);
      running--;
    });
    expect(peak).toBe(2);
  });

  it('rejects a limit that would run nothing', async () => {
    for (const limit of [0, -1, Number.NaN]) {
      await expect(mapLimit([1, 2], limit, async (x) => x)).rejects.toThrow(RangeError);
    }
  });

  it('starts no new items after one fails', async () => {
    // After one OSV record fetch failed, the other workers used to fetch every remaining record.
    const started: number[] = [];
    const run = mapLimit([0, 1, 2, 3, 4, 5, 6, 7], 2, async (item) => {
      started.push(item);
      if (item === 0) throw new Error('HTTP 429');
      await sleep(5);
      return item;
    });
    await expect(run).rejects.toThrow('HTTP 429');
    await sleep(30);
    expect(started).toEqual([0, 1]);
  });

  it('returns an empty list for no items', async () => {
    expect(await mapLimit([], 4, async () => 1)).toEqual([]);
  });
});
