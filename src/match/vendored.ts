import semver from 'semver';
import type { DiskCache } from '../util/cache.js';
import type { Fetch, RetryOptions } from '../util/http.js';
import { HttpError, requestJson } from '../util/http.js';
import type { OsvClient } from '../watch/osv.js';
import type { DepGraph, PkgNode } from './graph.js';
import { pkgId } from './graph.js';
import type { Finding } from './match.js';

/**
 * React's server-component packages, which next ships inside itself (`dist/compiled`) instead of
 * installing them. React's advisories name only these packages (CVE-2025-55182 did), so without this
 * list they would never reach a Next.js app before Next.js publishes an advisory of its own.
 */
export const NEXT_BUNDLES = ['react-server-dom-webpack', 'react-server-dom-turbopack'] as const;

export interface BundleOptions {
  fetch?: Fetch;
  retry?: RetryOptions;
  /** Where to read next's published files. Default https://cdn.jsdelivr.net/npm */
  cdnUrl?: string;
  /** A published version never changes, so what it bundles is kept for good (but not a 404, which can be jsDelivr catching up). */
  cache?: DiskCache;
}

/**
 * Adds, under each next in the graph, the NEXT_BUNDLES copies it ships, as packages that next
 * bundles (`bundledBy`), so matching asks OSV about them and the fix plan says to upgrade next. The
 * build is read from next's published files: the bundled package's `react` peer range names the
 * exact React build (`19.1.0-canary-029e8bd6-20250306`; a patched next ships a newer build of the
 * same line). OSV's ranges name releases, so the copy is checked as its release line (19.1.0).
 * Returns warnings for next versions whose files could not be read; a next that bundles none
 * (before the App Router) adds nothing.
 */
export async function addNextBundles(graph: DepGraph, options: BundleOptions = {}): Promise<string[]> {
  const fetchFn = options.fetch ?? globalThis.fetch.bind(globalThis);
  const cdn = (options.cdnUrl ?? 'https://cdn.jsdelivr.net/npm').replace(/\/+$/, '');
  const nexts = [...graph.nodes.values()].filter((node) => node.name === 'next' && semver.valid(node.version) && !node.id.startsWith('root:'));
  const warnings: string[] = [];
  for (const next of nexts) {
    const key = `next-bundles/${new URL(cdn).host}/${next.version}`;
    let build = (await options.cache?.get<{ build: string | null }>(key))?.build;
    if (build === undefined) {
      try {
        const manifest = await requestJson<{ version?: string; peerDependencies?: Record<string, string> }>(
          fetchFn,
          { label: `jsDelivr GET next@${next.version} bundled React`, url: `${cdn}/next@${next.version}/dist/compiled/${NEXT_BUNDLES[0]}/package.json` },
          options.retry ?? {},
        );
        build = manifest.peerDependencies?.react ?? manifest.version ?? null;
      } catch (error) {
        if (!(error instanceof HttpError && error.status === 404)) {
          warnings.push(`Could not read which React build next ${next.version} bundles, so React's own advisories were not checked for it: ${messageOf(error)}`);
        }
        continue;
      }
      await options.cache?.set(key, { build });
    }
    const parsed = build === null ? null : semver.parse(build);
    if (!parsed || build === null) continue;
    const release = `${parsed.major}.${parsed.minor}.${parsed.patch}`;
    for (const name of NEXT_BUNDLES) {
      const id = pkgId(name, release);
      const existing = graph.nodes.get(id);
      // The app installs this version itself: that copy is matched already.
      if (existing && existing.build === undefined) continue;
      const node: PkgNode = existing ?? { id, name, version: release, build: build!, bundledBy: [] };
      node.bundledBy = [...new Set([...(node.bundledBy ?? []), next.id])].sort();
      // Two nexts that bundle builds of the same line share the copy; the older build speaks for both.
      if ((buildDate(build!) ?? '') < (buildDate(node.build!) ?? '')) node.build = build!;
      graph.nodes.set(id, node);
      graph.edges.push({ from: next.id, to: id, name, type: 'prod' });
    }
  }
  return warnings;
}

/**
 * Settles the findings on bundled copies, which are checked as their release line and so would
 * outlive the fix. A finding is dropped when:
 * - the build is newer than the advisory: canary and rc builds end in their build date, and one
 *   made after the advisory was published comes from React's main branch with the fix in it;
 * - Next.js has answered the advisory with one of its own, whose references name it (its GHSA or one
 *   of its CVEs, as GHSA-9qr9-h5gf-34mp names GHSA-fv66-9v8q-g76r and CVE-2025-55182). Next's
 *   advisory then decides, by its own ranges, since a patched next can ship a build of the same
 *   line from before the advisory went public.
 * The findings that stay get a warning naming the build. When Next's advisories cannot be read,
 * every finding stays, with a warning.
 */
export async function settleBundled(
  findings: readonly Finding[],
  graph: DepGraph,
  osv: OsvClient,
): Promise<{ findings: Finding[]; warnings: string[] }> {
  const nodeOf = (f: Finding) => graph.nodes.get(pkgId(f.package, f.version));
  const bundled = (f: Finding) => nodeOf(f)?.build !== undefined;
  if (!findings.some(bundled)) return { findings: [...findings], warnings: [] };
  const published = new Map<string, string | undefined>();
  for (const f of findings.filter(bundled)) {
    const records = await Promise.all(f.records.map((id) => osv.getVuln(id)));
    published.set(f.advisory.id, records.map((r) => r.published).filter((d): d is string => d !== undefined).sort()[0]);
  }
  const fixedInBuild = (f: Finding) => {
    const date = buildDate(nodeOf(f)!.build!);
    const advisory = published.get(f.advisory.id);
    return date !== undefined && advisory !== undefined && date > advisory.slice(0, 10);
  };
  let urls: string[] = [];
  const warnings: string[] = [];
  try {
    urls = (await osv.packageVulns('next')).flatMap((vuln) => (vuln.references ?? []).map((ref) => ref.url));
  } catch (error) {
    warnings.push(`Could not read Next.js's own advisories, so a bundled React finding may repeat one of them: ${messageOf(error)}`);
  }
  // A whole id: CVE-2025-5518 must not match a URL that names CVE-2025-55182.
  const names = (url: string, id: string) => new RegExp(`${id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![0-9a-z])`, 'i').test(url);
  const answered = (f: Finding) => [f.advisory.id, ...f.advisory.aliases, ...f.records].some((id) => urls.some((url) => names(url, id)));
  const kept = findings.filter((f) => !bundled(f) || (!fixedInBuild(f) && !answered(f)));
  const builds = new Map<string, string>();
  for (const f of kept.filter(bundled)) {
    const node = nodeOf(f)!;
    for (const by of node.bundledBy ?? []) builds.set(by.slice(by.lastIndexOf('@') + 1), `${node.build} (checked as ${node.version})`);
  }
  for (const [version, build] of builds) {
    warnings.push(`next ${version} bundles React build ${build}; React's advisories reach it through react-server-dom-* until Next.js publishes its own.`);
  }
  return { findings: kept, warnings };
}

/** `19.1.0-canary-029e8bd6-20250306` -> `2025-03-06`; undefined for a build with no date. */
export function buildDate(build: string): string | undefined {
  const match = /-(\d{4})(\d{2})(\d{2})$/.exec(build);
  return match ? `${match[1]}-${match[2]}-${match[3]}` : undefined;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
