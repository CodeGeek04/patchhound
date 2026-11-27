import { describe, expect, it } from 'vitest';
import { allowsAny, changeOf, dependencySpec, pick, rangeOf, releases } from '../../src/fix/versions.js';
import { doc } from '../helpers/registry-routes.js';

describe('releases', () => {
  it('lists published versions oldest first, leaving out prereleases', () => {
    const pkg = doc('pkg', { '1.10.0': {}, '1.2.0': {}, '2.0.0-beta.1': {}, '1.9.0': {}, '0.1.0': {} });
    expect(releases(pkg)).toEqual(['0.1.0', '1.2.0', '1.9.0', '1.10.0']);
    // Worked out once per document.
    expect(releases(pkg)).toBe(releases(pkg));
  });
});

describe('rangeOf', () => {
  it('keeps a semver range as it is', () => {
    expect(rangeOf('^4.17.0')).toBe('^4.17.0');
    expect(rangeOf('1.x || >=2.5.0')).toBe('1.x || >=2.5.0');
    expect(rangeOf('4.17.20')).toBe('4.17.20');
  });

  it('takes the range out of an npm: alias', () => {
    expect(rangeOf('npm:lodash@^4')).toBe('^4');
    expect(rangeOf('npm:@scope/pkg@1.2.3')).toBe('1.2.3');
    expect(rangeOf('npm:lodash')).toBe('*');
    expect(rangeOf('npm:@scope/pkg')).toBe('*');
  });

  it('reads an empty spec as any version', () => {
    expect(rangeOf('')).toBe('*');
    expect(rangeOf('  ')).toBe('*');
  });

  it('gives null for specs that name no registry versions', () => {
    for (const spec of ['github:user/repo', 'git+https://github.com/user/repo.git', 'file:../lib', 'link:../lib', 'workspace:*', 'https://example.test/pkg.tgz', 'latest']) {
      expect(rangeOf(spec), spec).toBeNull();
    }
  });
});

describe('pick', () => {
  const pkg = doc(
    'pkg',
    { '1.0.0': {}, '1.1.0': {}, '1.2.0': { deprecated: 'broken' }, '2.0.0': {}, '2.1.0-beta.0': {} },
    { latest: '2.0.0', next: '2.1.0-beta.0', gone: '9.9.9' },
  );

  it('picks the highest release the range allows', () => {
    expect(pick(pkg, '*')).toBe('2.0.0');
    expect(pick(pkg, '~1.0.0')).toBe('1.0.0');
    expect(pick(pkg, 'npm:pkg@^1.0.0')).toBe('1.1.0');
  });

  it('passes over a deprecated release while another one fits, but not when it is the only one', () => {
    expect(pick(pkg, '^1.0.0')).toBe('1.1.0');
    expect(pick(pkg, '1.2.0')).toBe('1.2.0');
  });

  it("follows a dist-tag to its version, a prerelease included, but not to one that is not published", () => {
    expect(pick(pkg, 'latest')).toBe('2.0.0');
    expect(pick(pkg, 'next')).toBe('2.1.0-beta.0');
    expect(pick(pkg, 'gone')).toBeNull();
  });

  it('gives null when nothing fits or the spec names no registry versions', () => {
    expect(pick(pkg, '^3.0.0')).toBeNull();
    expect(pick(pkg, 'github:user/pkg')).toBeNull();
  });

  it("prefers the latest tag's version when the range allows it, even with newer releases (a rolled-back latest)", () => {
    const rolledBack = doc('pkg', { '1.0.0': {}, '1.1.0': {}, '2.0.0': {} }, { latest: '1.0.0' });
    expect(pick(rolledBack, '^1.0.0')).toBe('1.0.0');
    expect(pick(rolledBack, '^1.0.0', 'pnpm')).toBe('1.0.0');
    expect(pick(rolledBack, '^2.0.0')).toBe('2.0.0');
  });

  it('takes the latest tag in yarn 1 and never passes over a deprecated release; yarn 2+ ignores the tag and passes over them', () => {
    const rolledBack = doc('pkg', { '1.0.0': {}, '1.1.0': {}, '1.2.0': { deprecated: 'oops' } }, { latest: '1.0.0' });
    expect(pick(rolledBack, '^1.0.0', 'yarn-classic')).toBe('1.0.0');
    expect(pick(rolledBack, '~1.2.0', 'yarn-classic')).toBe('1.2.0');
    expect(pick(rolledBack, '^1.0.0', 'yarn-berry')).toBe('1.1.0');
    const noTag = doc('pkg', { '1.0.0': {}, '1.1.0': { deprecated: 'oops' } });
    expect(pick(noTag, '^1.0.0', 'yarn-classic')).toBe('1.1.0');
    expect(pick(noTag, '^1.0.0', 'yarn-berry')).toBe('1.0.0');
  });

  it('passes over a deprecated latest for npm but not for pnpm', () => {
    const deprecatedLatest = doc('pkg', { '1.0.0': {}, '1.0.1': {}, '1.0.2': { deprecated: 'oops' } }, { latest: '1.0.2' });
    expect(pick(deprecatedLatest, '^1.0.0')).toBe('1.0.1');
    expect(pick(deprecatedLatest, '^1.0.0', 'npm')).toBe('1.0.1');
    expect(pick(deprecatedLatest, '^1.0.0', 'pnpm')).toBe('1.0.2');
  });
});

describe('allowsAny', () => {
  it('is true when some version satisfies the range', () => {
    expect(allowsAny('^1.0.0', ['0.9.0', '1.2.0'])).toBe(true);
    expect(allowsAny('npm:pkg@^1.0.0', new Set(['1.0.1']))).toBe(true);
    expect(allowsAny('', ['0.0.1'])).toBe(true);
  });

  it('is false when none does, when there are none, or when the spec names no registry versions', () => {
    expect(allowsAny('^2.0.0', ['1.0.0', '3.0.0'])).toBe(false);
    expect(allowsAny('^1.0.0', [])).toBe(false);
    expect(allowsAny('file:../lib', ['1.0.0'])).toBe(false);
  });
});

describe('dependencySpec', () => {
  const meta = {
    version: '1.0.0',
    dependencies: { a: '^1.0.0' },
    optionalDependencies: { a: '^2.0.0', b: '^3.0.0' },
    peerDependencies: { a: '^4.0.0', b: '^5.0.0', c: '^6.0.0' },
  };

  it('looks in dependencies, then optionalDependencies, then peerDependencies', () => {
    expect(dependencySpec(meta, 'a')).toEqual({ spec: '^1.0.0', peer: false });
    expect(dependencySpec(meta, 'b')).toEqual({ spec: '^3.0.0', peer: false });
    expect(dependencySpec(meta, 'c')).toEqual({ spec: '^6.0.0', peer: true });
  });

  it('is undefined for a name the version does not depend on', () => {
    expect(dependencySpec(meta, 'd')).toBeUndefined();
    expect(dependencySpec({ version: '1.0.0' }, 'a')).toBeUndefined();
  });
});

describe('changeOf', () => {
  it('names the move the way a caret range sees it', () => {
    expect(changeOf('1.2.3', '1.2.4')).toBe('patch');
    expect(changeOf('1.2.3', '1.2.3')).toBe('patch');
    expect(changeOf('1.2.3', '1.3.0')).toBe('minor');
    expect(changeOf('1.2.3', '2.0.0')).toBe('major');
  });

  it('calls a minor move in 0.x major, and a patch move in 0.0.x major', () => {
    expect(changeOf('0.2.3', '0.2.4')).toBe('patch');
    expect(changeOf('0.2.3', '0.3.0')).toBe('major');
    expect(changeOf('0.0.3', '0.0.4')).toBe('major');
  });

  it('calls a lower version a downgrade', () => {
    expect(changeOf('4.4.2', '4.4.1')).toBe('downgrade');
    expect(changeOf('2.0.0', '1.9.9')).toBe('downgrade');
  });

  it('calls a move from a version it cannot read major', () => {
    expect(changeOf('file:packages/ui', '1.0.0')).toBe('major');
  });
});
