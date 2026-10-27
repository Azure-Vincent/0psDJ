import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
const debScript = readFileSync('build/deb-after-install.sh', 'utf8');

describe('packaging names', () => {
  it('the .deb post-install script uses the install folder and command electron-builder creates', () => {
    expect(debScript).toContain(`APP_DIR='/opt/${pkg.build.productName}'`);
    const exe = pkg.build.linux.executableName;
    expect(debScript).toContain(`"$APP_DIR/${exe}"`);
    expect(debScript).toContain(`update-alternatives --install '/usr/bin/${exe}' '${exe}'`);
  });

  it('keeps the identifiers existing installs depend on (user data, apt package, Windows install, update manifests)', () => {
    expect(pkg.name).toBe('infrastructure-lab');
    expect(pkg.build.appId).toBe('lab.infrastructure.desktop');
  });

  it('release file names match what the update signer recognises', async () => {
    const { createRequire } = await import('node:module');
    const { classify } = createRequire(import.meta.url)('../scripts/sign-update-manifest.cjs');
    const v = '9.9.9';
    const fill = (s: string, os: string, arch: string, ext: string) => s.replace('${version}', v).replace('${os}', os).replace('${arch}', arch).replace('${ext}', ext);
    expect(classify(fill(pkg.build.nsis.artifactName, '', '', 'exe'))?.kind).toBe('nsis');
    expect(classify(fill(pkg.build.portable.artifactName, '', '', 'exe'))?.kind).toBe('portable');
    expect(classify(fill(pkg.build.artifactName, 'win', 'x64', 'zip'))?.kind).toBe('zip');
    expect(classify(fill(pkg.build.artifactName, 'linux', 'x86_64', 'AppImage'))?.kind).toBe('appimage');
    expect(classify(fill(pkg.build.artifactName, 'linux', 'amd64', 'deb'))?.kind).toBe('deb');
    expect(classify(fill(pkg.build.artifactName, 'linux', 'x64', 'tar.gz'))?.kind).toBe('targz');
    expect(classify(fill(pkg.build.artifactName, 'mac', 'arm64', 'dmg'))?.kind).toBe('dmg');
  });
});
