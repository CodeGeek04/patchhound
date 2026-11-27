import type { Packument, PackumentVersion } from '../../src/fix/registry.js';
import type { Handler } from './fake-fetch.js';

export const REGISTRY = 'https://registry.npmjs.org';

/** The fake-fetch route of a package's document: a scoped name keeps its @ and encodes the slash. */
export const registryRoute = (name: string, baseUrl = REGISTRY): string => `GET ${baseUrl}/${name.replace('/', '%2f')}`;

/** Routes that serve each document (name -> body, or a list of documents) at its package's URL. */
export function registryRoutes(docs: Record<string, unknown> | readonly Packument[], baseUrl = REGISTRY): Record<string, Handler> {
  const entries = Array.isArray(docs) ? docs.map((d: Packument) => [d.name, d] as const) : Object.entries(docs);
  return Object.fromEntries(entries.map(([name, body]) => [registryRoute(name, baseUrl), () => body]));
}

/** A package document from version -> metadata, with each version's `version` filled in. */
export function doc(
  name: string,
  versions: Record<string, Omit<PackumentVersion, 'version'>>,
  distTags?: Record<string, string>,
): Packument {
  return {
    name,
    ...(distTags ? { 'dist-tags': distTags } : {}),
    versions: Object.fromEntries(Object.entries(versions).map(([version, meta]) => [version, { version, ...meta }])),
  };
}
