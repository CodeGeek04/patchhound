import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parseDocument } from 'yaml';
import type { FixStep } from './plan.js';

type Bump = Extract<FixStep, { kind: 'bump' }>;
type Override = Extract<FixStep, { kind: 'override' }>;
type Remove = Extract<FixStep, { kind: 'remove' }>;
type Manifest = Record<string, unknown> & { [section: string]: unknown };

const SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] as const;

/** The range a manifest should give so that it allows `to`, keeping a ^ or ~ (and an `npm:` alias) it had. */
export function raisedRange(spec: string, to: string): string {
  const alias = /^(npm:(?:@[^/]+\/)?[^@]+@)(.*)$/.exec(spec);
  if (alias) return `${alias[1]}${raisedRange(alias[2]!, to)}`;
  const prefix = /^\s*([~^])/.exec(spec)?.[1] ?? '';
  return `${prefix}${to}`;
}

/** Edits a JSON file in place, keeping its indentation and its final newline. */
async function editJson(path: string, edit: (data: Manifest) => void): Promise<void> {
  const text = await readFile(path, 'utf8');
  const indent = /^\{\r?\n([ \t]+)"/.exec(text)?.[1] ?? '  ';
  const data = JSON.parse(text) as Manifest;
  edit(data);
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  const out = JSON.stringify(data, null, indent).replace(/\n/g, eol);
  await writeFile(path, text.endsWith('\n') ? `${out}${eol}` : out);
}

/** Edits a YAML file in place with its comments and layout kept; a missing file starts empty. */
async function editYaml(path: string, edit: (doc: ReturnType<typeof parseDocument>) => void): Promise<void> {
  const text = await readFile(path, 'utf8').catch(() => '');
  const doc = parseDocument(text);
  edit(doc);
  await writeFile(path, doc.toString());
}

const manifestPath = (dir: string, root: string) => join(dir, root === '.' ? '' : root, 'package.json');

function section(data: Manifest, name: string): Record<string, string> | undefined {
  for (const key of SECTIONS) {
    const deps = data[key] as Record<string, string> | undefined;
    if (deps && typeof deps === 'object' && name in deps) return deps;
  }
  return undefined;
}

/** Raises a direct dependency's range in its package.json, or in the pnpm or yarn catalog that holds it. */
export async function applyBump(dir: string, step: Bump, manager: string): Promise<string> {
  const name = step.alias ?? step.package;
  if (step.catalog !== undefined) {
    const file = manager === 'yarn-berry' ? '.yarnrc.yml' : 'pnpm-workspace.yaml';
    const path = step.catalog === 'default' ? ['catalog', name] : ['catalogs', step.catalog, name];
    await editYaml(join(dir, file), (doc) => {
      const current = doc.getIn(path);
      doc.setIn(path, raisedRange(typeof current === 'string' ? current : '', step.to));
    });
    return `${file}: ${path.join('.')} -> ${step.to}`;
  }
  const file = manifestPath(dir, step.root);
  await editJson(file, (data) => {
    if (step.add) {
      const deps = ((data[step.add] as Record<string, string> | undefined) ?? {}) as Record<string, string>;
      deps[name] = `^${step.to}`;
      data[step.add] = deps;
      return;
    }
    const deps = section(data, name);
    if (!deps) throw new Error(`${step.root}/package.json does not list ${name}`);
    deps[name] = raisedRange(deps[name]!, step.to);
  });
  return `${step.root === '.' ? '' : `${step.root}/`}package.json: ${name} -> ${step.to}`;
}

/** Takes a malicious package out of the package.json that lists it. */
export async function applyRemove(dir: string, step: Remove): Promise<string> {
  const name = step.alias ?? step.package;
  await editJson(manifestPath(dir, step.root), (data) => {
    for (const key of SECTIONS) {
      const deps = data[key] as Record<string, string> | undefined;
      if (deps && name in deps) delete deps[name];
    }
  });
  return `${step.root === '.' ? '' : `${step.root}/`}package.json: removed ${name}`;
}

/**
 * Forces the vulnerable copy to the fixed version, and only that copy (verified with npm 11, pnpm
 * 10.4 and 11, yarn 1.22 and 4.5): npm and pnpm by a `name@version` key, yarn 1 by the parent's
 * name (`parent/name`), yarn 2+ by the range the parent asks for (`name@npm:<range>`). pnpm 11 reads
 * overrides only from pnpm-workspace.yaml and pnpm 10.4 only from package.json, so pnpm 11 gets the
 * YAML, older pnpm package.json unless the YAML already holds overrides.
 */
export async function applyOverride(dir: string, step: Override, manager: string, pnpmMajor: number | null): Promise<string> {
  const scoped = `${step.package}@${step.from}`;
  const root = manifestPath(dir, '.');
  // A direct listing moves with the override: npm refuses an override that contradicts it.
  for (const listed of step.direct ?? []) {
    await editJson(manifestPath(dir, listed.root), (data) => {
      const deps = section(data, step.package);
      if (deps) deps[step.package] = raisedRange(deps[step.package]!, step.to);
    });
  }
  const listedAtRoot = (step.direct ?? []).some((d) => d.root === '.');
  if (manager === 'npm') {
    await editJson(root, (data) => {
      const overrides = ((data.overrides as Record<string, unknown> | undefined) ?? {}) as Record<string, unknown>;
      overrides[scoped] = listedAtRoot ? `$${step.package}` : step.to;
      data.overrides = overrides;
    });
    return `package.json overrides: "${scoped}": "${listedAtRoot ? `$${step.package}` : step.to}"`;
  }
  if (manager === 'pnpm') {
    const yamlPath = join(dir, 'pnpm-workspace.yaml');
    const yamlText = await readFile(yamlPath, 'utf8').catch(() => '');
    const manifest = JSON.parse(await readFile(root, 'utf8')) as Manifest;
    const inPackageJson = typeof (manifest.pnpm as { overrides?: unknown } | undefined)?.overrides === 'object';
    const inYaml = /^overrides:/m.test(yamlText);
    // pnpm 11 ignores package.json's "pnpm" field; pnpm 10.4 ignores the YAML's overrides.
    const useYaml = pnpmMajor !== null ? pnpmMajor >= 11 || inYaml : inYaml || !inPackageJson;
    if (useYaml) {
      await editYaml(yamlPath, (doc) => doc.setIn(['overrides', scoped], step.to));
      return `pnpm-workspace.yaml overrides: ${scoped}: ${step.to}`;
    }
    await editJson(root, (data) => {
      const pnpm = ((data.pnpm as Record<string, unknown> | undefined) ?? {}) as Record<string, unknown>;
      const overrides = ((pnpm.overrides as Record<string, string> | undefined) ?? {}) as Record<string, string>;
      overrides[scoped] = step.to;
      pnpm.overrides = overrides;
      data.pnpm = pnpm;
    });
    return `package.json pnpm.overrides: "${scoped}": "${step.to}"`;
  }
  // yarn 1 matches `parent/child` only when the parent is a root dependency; `**/parent/child` matches it at any depth.
  const keys = [
    ...new Set(
      manager === 'yarn-classic'
        ? step.parents.filter((p) => !p.id.startsWith('root:')).map((p) => `**/${p.id.slice(0, p.id.lastIndexOf('@'))}/${step.package}`)
        : step.parents.filter((p) => !p.id.startsWith('root:') && p.spec).map((p) => `${step.package}@${p.spec.startsWith('npm:') ? p.spec : `npm:${p.spec}`}`),
    ),
  ];
  await editJson(root, (data) => {
    const resolutions = ((data.resolutions as Record<string, string> | undefined) ?? {}) as Record<string, string>;
    for (const key of keys) resolutions[key] = step.to;
    data.resolutions = resolutions;
  });
  return `package.json resolutions: ${keys.map((k) => `"${k}"`).join(', ')} -> ${step.to}`;
}
