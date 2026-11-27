import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

/**
 * JSON files in a folder, one per key (`osv/GHSA-35jh-r3h4-6jhm` -> `osv/GHSA-35jh-r3h4-6jhm.json`).
 * A cache only saves requests: a missing or unreadable entry reads as undefined, and a write that
 * fails is ignored, so the caller asks the network instead.
 */
export class DiskCache {
  constructor(readonly dir: string) {}

  async get<T>(key: string): Promise<T | undefined> {
    try {
      return JSON.parse(await readFile(this.path(key), 'utf8')) as T;
    } catch {
      return undefined;
    }
  }

  async set(key: string, value: unknown): Promise<void> {
    const path = this.path(key);
    try {
      await mkdir(dirname(path), { recursive: true });
      // Write then rename, so a reader never sees half a file.
      const temp = `${path}.${process.pid}.${Date.now()}.tmp`;
      await writeFile(temp, JSON.stringify(value));
      await rename(temp, path);
    } catch {
      // Best effort: the next run asks the network again.
    }
  }

  private path(key: string): string {
    return `${join(this.dir, ...key.split('/').map((part) => encodeURIComponent(part)))}.json`;
  }
}

/** `$XDG_CACHE_HOME/patchhound`, else `~/.cache/patchhound`. */
export function defaultCacheDir(): string {
  const base = process.env.XDG_CACHE_HOME || join(homedir(), '.cache');
  return join(base, 'patchhound');
}
