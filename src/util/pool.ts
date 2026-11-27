/**
 * Runs `fn` over `items` with at most `limit` calls in flight. Results keep the input order.
 * After the first rejection no new item starts, and the returned promise rejects with it.
 */
export async function mapLimit<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  // Fewer than one worker would return without calling `fn`, leaving every slot empty.
  if (!(limit >= 1)) throw new RangeError(`mapLimit needs a limit of at least 1, got ${limit}`);
  const results = new Array<R>(items.length);
  let next = 0;
  let failed = false;
  const worker = async (): Promise<void> => {
    while (!failed && next < items.length) {
      const i = next++;
      try {
        results[i] = await fn(items[i] as T, i);
      } catch (error) {
        failed = true;
        throw error;
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}
