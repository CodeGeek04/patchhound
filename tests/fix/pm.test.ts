import { describe, expect, it } from 'vitest';
import { cleanInstall } from '../../src/fix/pm.js';

describe('cleanInstall', () => {
  it('keeps pnpm 11+ from failing on build scripts the project never approved', () => {
    expect(cleanInstall('pnpm', true)).toEqual(['install', '--frozen-lockfile', '--config.strict-dep-builds=false']);
    expect(cleanInstall('pnpm', false)).toEqual(['install', '--frozen-lockfile', '--config.strict-dep-builds=false', '--ignore-scripts']);
  });

  it('installs exactly the lockfile for the other managers', () => {
    expect(cleanInstall('npm', true, true)).toEqual(['ci', '--no-audit', '--no-fund', '--legacy-peer-deps']);
    expect(cleanInstall('yarn-berry', false)).toEqual(['install', '--immutable', '--mode=skip-build']);
    expect(cleanInstall('yarn-classic', true)).toEqual(['install', '--frozen-lockfile', '--non-interactive']);
  });
});
