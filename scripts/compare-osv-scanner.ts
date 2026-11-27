// Milestone 1 gate: our matches must include everything osv-scanner finds for the same lockfile.
// Usage: npm run compare -- <project-dir>     (needs osv-scanner v2 on PATH)
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { NEXT_BUNDLES } from '../src/match/vendored.js';
import { scan } from '../src/scan.js';

const run = promisify(execFile);

interface ScannerReport {
  results?: {
    packages?: { package: { name: string; version: string }; vulnerabilities?: { id: string }[] }[];
  }[];
}

async function osvScannerKeys(lockfile: string): Promise<Set<string>> {
  let stdout: string;
  try {
    ({ stdout } = await run('osv-scanner', ['scan', 'source', '--lockfile', lockfile, '--format', 'json'], {
      maxBuffer: 64 * 1024 * 1024,
    }));
  } catch (error) {
    // osv-scanner exits with code 1 when it finds vulnerabilities; the report is still on stdout.
    const out = (error as { stdout?: string }).stdout;
    if (!out) throw error;
    stdout = out;
  }
  const report = JSON.parse(stdout) as ScannerReport;
  const keys = new Set<string>();
  for (const result of report.results ?? []) {
    for (const pkg of result.packages ?? []) {
      for (const vuln of pkg.vulnerabilities ?? []) keys.add(`${vuln.id} ${pkg.package.name}@${pkg.package.version}`);
    }
  }
  return keys;
}

const dir = process.argv[2];
if (!dir) {
  console.error('usage: npm run compare -- <project-dir>');
  process.exit(2);
}

const ours = await scan({ dir, dryRun: true });
// osv-scanner reads only the lockfile, so it cannot see the React builds that next bundles.
const bundled = ours.findings.filter(
  (f) => (NEXT_BUNDLES as readonly string[]).includes(f.package) && f.paths.every((chain) => chain.at(-2)?.startsWith('next@')),
);
const bundledKeys = bundled.map((f) => `${f.advisory.id} ${f.package}@${f.version}`);
const ourKeys = new Set(ours.findings.map((f) => `${f.advisory.id} ${f.package}@${f.version}`).filter((key) => !bundledKeys.includes(key)));
// A finding merges alias records (such as a GHSA and its MAL- twin); osv-scanner lists each of them.
const covered = new Set(
  ours.findings.flatMap((f) => [f.advisory.id, ...f.advisory.aliases].map((id) => `${id} ${f.package}@${f.version}`)),
);
const reported = await osvScannerKeys(ours.lockfile);
// yarn 2+ records each workspace at version 0.0.0-use.local. osv-scanner matches advisories against
// it by name (jest's `example-typescript` workspace against the malicious npm package of that name),
// but a workspace is the project's own source, linked, never installed from the registry.
const workspaceKeys = [...reported].filter((key) => key.endsWith('@0.0.0-use.local'));
const theirKeys = new Set([...reported].filter((key) => !workspaceKeys.includes(key)));
const missed = [...theirKeys].filter((key) => !covered.has(key)).sort();
const extra = [...ourKeys].filter((key) => !theirKeys.has(key)).sort();

console.log(
  `${ours.project}: osv-scanner ${theirKeys.size}, bulwark ${ourKeys.size}, missed ${missed.length}, extra ${extra.length}` +
    (workspaceKeys.length > 0 ? ` (${workspaceKeys.length} osv-scanner matches on yarn workspaces left out)` : '') +
    (bundledKeys.length > 0 ? `; ${bundledKeys.length} more inside next, which osv-scanner cannot see` : ''),
);
for (const key of missed) console.log(`  missed  ${key}`);
for (const key of extra) console.log(`  extra   ${key}`);
for (const key of workspaceKeys.sort()) console.log(`  workspace, left out  ${key}`);
for (const key of bundledKeys.sort()) console.log(`  inside next  ${key}`);
process.exitCode = missed.length > 0 ? 1 : 0;
