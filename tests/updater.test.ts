import { createRequire } from 'node:module';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';

const require = createRequire(import.meta.url);
const U = require('../electron/updater.cjs');
const { classify } = require('../scripts/sign-update-manifest.cjs');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const PUB = publicKey.export({ type: 'spki', format: 'pem' }) as string;
const other = crypto.generateKeyPairSync('ed25519');

const ARTIFACT = Buffer.from('new installer bytes '.repeat(1000));
const SHA = crypto.createHash('sha256').update(ARTIFACT).digest('hex');
const SETUP = 'InfrastructureLab-Setup-1.3.0-win-x64.exe';

function manifest(over: Record<string, unknown> = {}) {
  return Buffer.from(JSON.stringify({
    schema: 1, product: U.PRODUCT, version: '1.3.0', tag: 'v1.3.0',
    files: [{ name: SETUP, platform: 'win32', arch: 'x64', kind: 'nsis', size: ARTIFACT.length, sha256: SHA }], ...over,
  }));
}
const sign = (b: Buffer, key = privateKey) => crypto.sign(null, b, key).toString('base64');

/** A fake GitHub: the API answer, the release assets, optional redirects. */
function github(files: Record<string, Buffer>, opts: { redirect?: string; assetSize?: Record<string, number> } = {}) {
  const base = 'https://github.com/Azure-Vincent/0psDJ/releases/download/v1.3.0/';
  const release = { tag_name: 'v1.3.0', assets: Object.keys(files).map((name) => ({ name, size: opts.assetSize?.[name] ?? files[name].length, browser_download_url: base + name })) };
  const seen: string[] = [];
  const respond = (status: number, body: Buffer, headers: Record<string, string> = {}) => ({
    status,
    headers: { get: (h: string) => headers[h.toLowerCase()] ?? (h.toLowerCase() === 'content-length' ? String(body.length) : null) },
    body: new Blob([body]).stream(),
  });
  const fetchFn = async (url: string, init: { redirect: string }) => {
    expect(init.redirect).toBe('manual');
    seen.push(url);
    if (url === 'https://api.github.com/repos/Azure-Vincent/0psDJ/releases/latest') return respond(200, Buffer.from(JSON.stringify(release)));
    if (url.startsWith(base)) {
      const name = url.slice(base.length);
      if (opts.redirect) return respond(302, Buffer.alloc(0), { location: opts.redirect + name });
      return respond(200, files[name]);
    }
    if (url.startsWith('https://objects.githubusercontent.com/')) return respond(200, files[url.split('/').pop()!]);
    return respond(404, Buffer.alloc(0));
  };
  return { fetchFn, seen };
}

const WIN = { platform: 'win32', arch: 'x64', hasUninstaller: true, execPath: 'C:\\Users\\a\\AppData\\Local\\Programs\\infrastructure-lab\\Infrastructure Lab.exe' };

describe('updater: manifest verification', () => {
  it('accepts a manifest signed by an embedded key', () => {
    const m = manifest();
    expect(U.verifyManifest(m, sign(m), [PUB]).version).toBe('1.3.0');
  });

  it('rejects a wrong key, a tampered manifest, and a malformed signature', () => {
    const m = manifest();
    expect(() => U.verifyManifest(m, sign(m, other.privateKey), [PUB])).toThrow(/not signed by the project key/);
    const tampered = Buffer.from(m.toString().replace(SHA, 'f'.repeat(64)));
    expect(() => U.verifyManifest(tampered, sign(m), [PUB])).toThrow(/not signed/);
    expect(() => U.verifyManifest(m, 'AAAA', [PUB])).toThrow(/malformed/);
    expect(() => U.verifyManifest(m, sign(m), [])).toThrow(/no update signing key/);
  });

  it('rejects signed manifests with bad content (product, tag, names, hashes)', () => {
    const bad = (over: Record<string, unknown>) => { const m = manifest(over); return () => U.verifyManifest(m, sign(m), [PUB]); };
    expect(bad({ product: 'other.app' })).toThrow(/another product/);
    expect(bad({ tag: 'v9.9.9' })).toThrow(/tag does not match/);
    expect(bad({ version: '1.3.0-beta' })).toThrow(/invalid version/);
    for (const name of ['../../evil.exe', '..', 'a/b.exe', 'C:\\x.exe', '.hidden']) {
      expect(bad({ files: [{ name, platform: 'win32', arch: 'x64', kind: 'nsis', size: 1, sha256: SHA }] })).toThrow(/invalid file entry/);
    }
    expect(bad({ files: [{ name: SETUP, platform: 'win32', arch: 'x64', kind: 'nsis', size: 1, sha256: 'abc' }] })).toThrow(/invalid file entry/);
    expect(bad({ files: [{ name: SETUP, platform: 'win32', arch: 'x64', kind: 'script', size: 1, sha256: SHA }] })).toThrow(/invalid file entry/);
  });

  it('compares versions strictly', () => {
    expect(U.compareVersions('1.10.0', '1.9.9')).toBeGreaterThan(0);
    expect(U.compareVersions('1.2.4', '1.2.4')).toBe(0);
    expect(() => U.compareVersions('v1.2.4', '1.2.4')).toThrow();
    expect(U.parseVersion('01.2.3')).toBeNull();
  });

  it('lets a prerelease build update to its stable release and later', () => {
    expect(U.isNewer('1.3.0', '1.3.0-rc.1')).toBe(true);
    expect(U.isNewer('1.3.0', '1.3.0')).toBe(false);
    expect(U.isNewer('1.2.9', '1.3.0-rc.1')).toBe(false);
    expect(() => U.isNewer('1.3.0', 'garbage')).toThrow(/invalid running version/);
  });
});

describe('updater: where it may connect', () => {
  it('allows only https to GitHub hosts, without credentials or ports', () => {
    expect(U.safeUrl('https://objects.githubusercontent.com/x')).toBe('https://objects.githubusercontent.com/x');
    for (const u of ['http://github.com/x', 'https://evil.example/x', 'https://github.com.evil.example/x', 'https://user:pw@github.com/x', 'https://github.com:8443/x', 'file:///etc/passwd', 'javascript:alert(1)']) {
      expect(() => U.safeUrl(u), u).toThrow();
    }
  });

  it('checks each redirect the Electron adapter is about to follow, and their number', () => {
    expect(U.checkRedirect(1, 'https://release-assets.githubusercontent.com/a')).toBe('https://release-assets.githubusercontent.com/a');
    expect(() => U.checkRedirect(1, 'https://evil.example/a')).toThrow(/refusing/);
    expect(() => U.checkRedirect(U.MAX_REDIRECTS + 1, 'https://github.com/a')).toThrow(/too many redirects/);
  });

  it('re-checks every redirect target', async () => {
    const m = manifest();
    const files = { 'update-manifest.json': m, 'update-manifest.json.sig': Buffer.from(sign(m)), [SETUP]: ARTIFACT };
    const ok = github(files, { redirect: 'https://objects.githubusercontent.com/' });
    expect((await U.checkForUpdate({ fetchFn: ok.fetchFn, currentVersion: '1.2.4', publicKeys: [PUB], env: WIN })).state).toBe('available');
    const evil = github(files, { redirect: 'https://evil.example/' });
    await expect(U.checkForUpdate({ fetchFn: evil.fetchFn, currentVersion: '1.2.4', publicKeys: [PUB], env: WIN })).rejects.toThrow(/refusing to download from https:\/\/evil\.example/);
  });
});

describe('updater: checking the latest release', () => {
  const m = manifest();
  const files = { 'update-manifest.json': m, 'update-manifest.json.sig': Buffer.from(sign(m)), [SETUP]: ARTIFACT };

  it('offers a newer, signed release with the file for this install', async () => {
    const r = await U.checkForUpdate({ fetchFn: github(files).fetchFn, currentVersion: '1.2.4', publicKeys: [PUB], env: WIN });
    expect(r).toMatchObject({ state: 'available', version: '1.3.0', mode: 'nsis', releaseUrl: 'https://github.com/Azure-Vincent/0psDJ/releases/tag/v1.3.0' });
    expect(r.file.name).toBe(SETUP);
  });

  it('never offers the same or an older version (no downgrade)', async () => {
    for (const current of ['1.3.0', '2.0.0']) {
      expect((await U.checkForUpdate({ fetchFn: github(files).fetchFn, currentVersion: current, publicKeys: [PUB], env: WIN })).state).toBe('current');
    }
  });

  it('offers nothing without a key, or for a release without a signed manifest', async () => {
    expect((await U.checkForUpdate({ fetchFn: github(files).fetchFn, currentVersion: '1.2.4', publicKeys: [], env: WIN })).state).toBe('not-configured');
    const unsigned = github({ [SETUP]: ARTIFACT });
    expect((await U.checkForUpdate({ fetchFn: unsigned.fetchFn, currentVersion: '1.2.4', publicKeys: [PUB], env: WIN })).state).toBe('unsigned');
    expect(unsigned.seen.some((u) => u.includes(SETUP))).toBe(false);
  });

  it('refuses a release whose asset differs in size from the signed manifest', async () => {
    const g = github(files, { assetSize: { [SETUP]: ARTIFACT.length + 1 } });
    await expect(U.checkForUpdate({ fetchFn: g.fetchFn, currentVersion: '1.2.4', publicKeys: [PUB], env: WIN })).rejects.toThrow(/differs from the signed manifest/);
  });

  it('reports a release without a build for this computer as such, not as an error', async () => {
    const r = await U.checkForUpdate({ fetchFn: github(files).fetchFn, currentVersion: '1.2.4', publicKeys: [PUB], env: { platform: 'darwin', arch: 'x64', execPath: '/Applications/x' } });
    expect(r).toEqual({ state: 'no-build', latest: '1.3.0', platform: 'darwin-x64', kind: 'dmg' });
  });

  it('picks the install mode from how the app was installed', () => {
    expect(U.installMode(WIN)).toEqual({ mode: 'nsis', kind: 'nsis' });
    expect(U.installMode({ ...WIN, portableDir: 'D:\\apps' })).toEqual({ mode: 'download', kind: 'portable' });
    expect(U.installMode({ ...WIN, hasUninstaller: false })).toEqual({ mode: 'download', kind: 'zip' });
    expect(U.installMode({ platform: 'linux', arch: 'x64', appImage: '/home/a/Lab.AppImage', appDir: '/tmp/.mount_LabX1', execPath: '/tmp/.mount_LabX1/infrastructure-lab' })).toEqual({ mode: 'appimage', kind: 'appimage' });
    // APPIMAGE inherited from another AppImage (a .deb install started from it): never replace that other file.
    expect(U.installMode({ platform: 'linux', arch: 'x64', appImage: '/home/a/Editor.AppImage', appDir: '/tmp/.mount_Edit99', execPath: '/opt/Infrastructure Lab/infrastructure-lab' })).toEqual({ mode: 'download', kind: 'deb' });
    expect(U.installMode({ platform: 'linux', arch: 'x64', appImage: '/home/a/Editor.AppImage', execPath: '/home/a/lab/infrastructure-lab' })).toEqual({ mode: 'download', kind: 'targz' });
    expect(U.installMode({ platform: 'linux', arch: 'x64', appImage: 'relative.AppImage', execPath: '/opt/Infrastructure Lab/x' })).toEqual({ mode: 'download', kind: 'deb' });
    expect(U.installMode({ platform: 'darwin', arch: 'arm64', execPath: '/Applications/x' })).toEqual({ mode: 'download', kind: 'dmg' });
    // An AppImage in a folder the user cannot write: the verified file is downloaded instead.
    expect(U.installMode({ platform: 'linux', arch: 'x64', appImage: '/opt/Lab.AppImage', appDir: '/tmp/.mount_Lab1', execPath: '/tmp/.mount_Lab1/x', appImageWritable: false })).toEqual({ mode: 'download', kind: 'appimage' });
  });
});

describe('updater: downloads', () => {
  const dir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'lab-upd-'));
  const fetchOf = (body: Buffer) => github({ [SETUP]: body }).fetchFn;
  const url = `https://github.com/Azure-Vincent/0psDJ/releases/download/v1.3.0/${SETUP}`;

  it('keeps a file only if size and SHA-256 match, created exclusively with mode 0600', async () => {
    const d = dir();
    const dest = path.join(d, SETUP);
    await U.downloadVerified({ fetchFn: fetchOf(ARTIFACT), url, dest, size: ARTIFACT.length, sha256: SHA });
    expect(fs.readFileSync(dest).equals(ARTIFACT)).toBe(true);
    if (process.platform !== 'win32') expect(fs.statSync(dest).mode & 0o777).toBe(0o600);
    await expect(U.downloadVerified({ fetchFn: fetchOf(ARTIFACT), url, dest, size: ARTIFACT.length, sha256: SHA })).rejects.toThrow(/already exists/);
    expect(await U.fileSha256(dest)).toBe(SHA);
    expect(fs.readdirSync(d)).toEqual([SETUP]);
  });

  it('deletes a file with the wrong content, size or length', async () => {
    const d = dir();
    const evil = Buffer.from(ARTIFACT); evil[10] ^= 1;
    await expect(U.downloadVerified({ fetchFn: fetchOf(evil), url, dest: path.join(d, 'a'), size: ARTIFACT.length, sha256: SHA })).rejects.toThrow(/does not match the signed SHA-256/);
    await expect(U.downloadVerified({ fetchFn: fetchOf(Buffer.concat([ARTIFACT, Buffer.from('x')])), url, dest: path.join(d, 'b'), size: ARTIFACT.length, sha256: SHA })).rejects.toThrow(/size differs/);
    expect(fs.readdirSync(d)).toEqual([]);
  });

  it('never replaces a file that appears at the destination during the download', async () => {
    const d = dir();
    const dest = path.join(d, SETUP);
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    // The body arrives only after someone else has created dest.
    const fetchFn = async () => ({ status: 200, headers: { get: () => String(ARTIFACT.length) }, body: new ReadableStream({ async start(c) { await gate; c.enqueue(new Uint8Array(ARTIFACT)); c.close(); } }) });
    const p = U.downloadVerified({ fetchFn, url, dest, size: ARTIFACT.length, sha256: SHA });
    await new Promise((r) => setTimeout(r, 20));
    fs.writeFileSync(dest, 'the user\'s own file');
    release();
    await expect(p).rejects.toThrow(/appeared during the download/);
    expect(fs.readFileSync(dest, 'utf8')).toBe('the user\'s own file');
    expect(fs.readdirSync(d)).toEqual([SETUP]);
  });

  it('never overwrites a file in the download folder', () => {
    const d = dir();
    fs.writeFileSync(path.join(d, 'a.exe'), 'x');
    expect(path.basename(U.freePath(d, 'a.exe'))).toBe('a (1).exe');
  });
});

describe('updater: the CI signer', () => {
  it('classifies the release artifacts by their real names', () => {
    expect(classify('InfrastructureLab-Setup-1.2.4-win-x64.exe')).toEqual({ platform: 'win32', arch: 'x64', kind: 'nsis' });
    expect(classify('InfrastructureLab-1.2.4-win-x64-portable.exe')).toEqual({ platform: 'win32', arch: 'x64', kind: 'portable' });
    expect(classify('InfrastructureLab-1.2.4-linux-x86_64.AppImage')).toEqual({ platform: 'linux', arch: 'x64', kind: 'appimage' });
    expect(classify('InfrastructureLab-1.2.4-mac-arm64.dmg')).toEqual({ platform: 'darwin', arch: 'arm64', kind: 'dmg' });
    expect(classify('InfrastructureLab-1.2.4-mac-arm64.zip')).toBeNull();
  });

  it('skips tags that are not vX.Y.Z (prereleases are not offered), without failing the release', () => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'lab-sign-'));
    fs.writeFileSync(path.join(d, 'InfrastructureLab-Setup-1.3.0-rc.1-win-x64.exe'), ARTIFACT);
    const out = execFileSync(process.execPath, ['scripts/sign-update-manifest.cjs', d, 'v1.3.0-rc.1'], { env: { ...process.env, UPDATE_SIGNING_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string } }).toString();
    expect(out).toContain('not a vX.Y.Z tag');
    expect(fs.existsSync(path.join(d, U.MANIFEST))).toBe(false);
  });

  it('writes a manifest and signature that the app accepts', () => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'lab-sign-'));
    fs.writeFileSync(path.join(d, 'InfrastructureLab-Setup-1.3.0-win-x64.exe'), ARTIFACT);
    fs.writeFileSync(path.join(d, 'notes.txt'), 'ignored');
    execFileSync(process.execPath, ['scripts/sign-update-manifest.cjs', d, 'v1.3.0'], { env: { ...process.env, UPDATE_SIGNING_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string } });
    const m = U.verifyManifest(fs.readFileSync(path.join(d, U.MANIFEST)), fs.readFileSync(path.join(d, U.SIGNATURE), 'utf8'), [PUB]);
    expect(m.files).toEqual([{ name: SETUP, platform: 'win32', arch: 'x64', kind: 'nsis', size: ARTIFACT.length, sha256: SHA }]);
  });
});
