// Self-update for the desktop app, designed so that neither the user nor the
// project can be attacked through it.
//
// Trust comes from one place: an Ed25519 signature made in CI with a private
// key that exists only as a GitHub Actions secret. Each release carries
// update-manifest.json (version, product id, and the SHA-256 and size of every
// artifact) and update-manifest.json.sig. The app embeds the public key(s)
// (update-public-keys.cjs) and accepts an update only if:
//   - the manifest's signature verifies with an embedded key;
//   - it names this product and a version strictly newer than the running one
//     (no downgrades, no replay of another product's manifest);
//   - the artifact it downloads has exactly the signed size and SHA-256.
// Everything runs in the main process. The renderer can only ask to check, to
// install the update the last check verified, or for the status: it never
// passes URLs, file names or paths. Downloads use HTTPS to GitHub hosts only
// (every redirect is re-checked), are size-limited, and are written with
// exclusive creation into a per-user folder before verification. With no key
// configured or no signed manifest on the release, no update is offered.

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const REPO = 'Azure-Vincent/0psDJ';
// The appId, kept from the app's first name so that installs and signed manifests stay compatible.
const PRODUCT = 'lab.infrastructure.desktop';
const MANIFEST = 'update-manifest.json';
const SIGNATURE = 'update-manifest.json.sig';
const ALLOWED_HOSTS = new Set(['api.github.com', 'github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com']);
const MAX_API_BYTES = 1024 * 1024;
const MAX_MANIFEST_BYTES = 64 * 1024;
const MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024;
const MAX_REDIRECTS = 5;
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/;
const KINDS = ['nsis', 'portable', 'zip', 'appimage', 'deb', 'targz', 'dmg'];

class UpdateError extends Error {}

/** "1.2.3" → [1, 2, 3]; anything else (prereleases, "v" prefix, leading zeros) → null. */
function parseVersion(v) {
  const m = /^(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})$/.exec(String(v));
  return m ? m.slice(1).map(Number) : null;
}

/** <0, 0, >0 like a comparator; both versions must parse. */
function compareVersions(a, b) {
  const x = parseVersion(a);
  const y = parseVersion(b);
  if (!x || !y) throw new UpdateError(`invalid version: ${!x ? a : b}`);
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
}

/**
 * Is `latest` (X.Y.Z) newer than the running version? The running version may
 * be a prerelease build (1.3.0-rc.1): then 1.3.0 itself counts as newer.
 */
function isNewer(latest, running) {
  const m = /^(\d+\.\d+\.\d+)(-[0-9A-Za-z.-]+)?$/.exec(String(running));
  if (!m || !parseVersion(m[1])) throw new UpdateError(`invalid running version: ${running}`);
  const c = compareVersions(latest, m[1]);
  return c > 0 || (c === 0 && !!m[2]);
}

/** A redirect the downloader may follow (the `n`th of this request), or throws. */
function checkRedirect(n, target) {
  if (n > MAX_REDIRECTS) throw new UpdateError('too many redirects');
  return safeUrl(target);
}

/** An https URL on an allowed GitHub host, with no credentials; otherwise throws. */
function safeUrl(u) {
  let url;
  try { url = new URL(u); } catch { throw new UpdateError('invalid download URL'); }
  if (url.protocol !== 'https:' || !ALLOWED_HOSTS.has(url.hostname) || url.username || url.password || url.port) {
    throw new UpdateError(`refusing to download from ${url.protocol}//${url.host}`);
  }
  return url.href;
}

/**
 * Verify a manifest's bytes against its detached signature and validate its
 * content. Returns the parsed manifest; throws UpdateError otherwise.
 */
function verifyManifest(bytes, signatureText, publicKeys) {
  if (!publicKeys.length) throw new UpdateError('no update signing key is built into this app');
  const sigText = String(signatureText).trim();
  if (!/^[A-Za-z0-9+/]{86}==$/.test(sigText)) throw new UpdateError('malformed manifest signature');
  const sig = Buffer.from(sigText, 'base64');
  const signedBy = publicKeys.some((pem) => {
    try { return crypto.verify(null, bytes, crypto.createPublicKey(pem), sig); } catch { return false; }
  });
  if (!signedBy) throw new UpdateError('the update manifest is not signed by the project key');
  let m;
  try { m = JSON.parse(bytes.toString('utf8')); } catch { throw new UpdateError('the update manifest is not valid JSON'); }
  if (!m || typeof m !== 'object' || m.schema !== 1) throw new UpdateError('unsupported manifest schema');
  if (m.product !== PRODUCT) throw new UpdateError('the manifest is for another product');
  if (!parseVersion(m.version)) throw new UpdateError('invalid version in manifest');
  if (m.tag !== `v${m.version}`) throw new UpdateError('manifest tag does not match its version');
  if (!Array.isArray(m.files) || m.files.length === 0 || m.files.length > 50) throw new UpdateError('invalid file list in manifest');
  const names = new Set();
  for (const f of m.files) {
    const ok = f && typeof f === 'object' && typeof f.name === 'string' && NAME_RE.test(f.name) && !names.has(f.name)
      && typeof f.sha256 === 'string' && /^[0-9a-f]{64}$/.test(f.sha256)
      && Number.isSafeInteger(f.size) && f.size > 0 && f.size <= MAX_ARTIFACT_BYTES
      && ['win32', 'linux', 'darwin'].includes(f.platform) && ['x64', 'arm64'].includes(f.arch) && KINDS.includes(f.kind);
    if (!ok) throw new UpdateError('invalid file entry in manifest');
    names.add(f.name);
  }
  return m;
}

/**
 * How this copy of the app can be updated:
 *  - "nsis": installed with the Windows installer (its uninstaller sits next to the exe): run the new installer;
 *  - "appimage": a Linux AppImage (APPIMAGE is set): replace the file;
 *  - "download": anything else (portable exe, zip, deb, tar.gz, macOS without code signing):
 *    save the verified file to Downloads for the user to install.
 */
function installMode(env) {
  if (env.platform === 'win32' && !env.portableDir && env.hasUninstaller) return { mode: 'nsis', kind: 'nsis' };
  // APPIMAGE is inherited by child processes: trust it only if this process runs from that AppImage's mount (APPDIR).
  const ownAppImage = env.appImage && path.isAbsolute(env.appImage) && env.appDir && path.isAbsolute(env.appDir) && env.execPath.startsWith(`${env.appDir.replace(/\/+$/, '')}/`);
  // An AppImage in a folder the user cannot write (e.g. /opt) cannot be replaced: offer the download instead.
  if (env.platform === 'linux' && ownAppImage && env.appImageWritable !== false) return { mode: 'appimage', kind: 'appimage' };
  if (env.platform === 'linux' && ownAppImage) return { mode: 'download', kind: 'appimage' };
  if (env.platform === 'win32') return { mode: 'download', kind: env.portableDir ? 'portable' : 'zip' };
  if (env.platform === 'linux') return { mode: 'download', kind: env.execPath.startsWith('/opt/') ? 'deb' : 'targz' };
  return { mode: 'download', kind: 'dmg' };
}

/** The manifest entry for this platform, architecture and kind of install (null: none). */
function chooseFile(manifest, env, kind) {
  return manifest.files.find((f) => f.platform === env.platform && f.arch === env.arch && f.kind === kind) ?? null;
}

/** fetch with manual redirects, each target re-checked against the host allow-list. */
async function safeFetch(fetchFn, url, accept) {
  let current = safeUrl(url);
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const res = await fetchFn(current, { redirect: 'manual', headers: { Accept: accept, 'User-Agent': 'CyberOwlLab-Updater' } });
    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const loc = res.headers.get('location');
      if (!loc) throw new UpdateError('redirect without a location');
      current = checkRedirect(i + 1, new URL(loc, current).href);
      continue;
    }
    if (res.status === 403 || res.status === 429) throw new UpdateError('GitHub refused the request (rate limit): try again later');
    if (res.status !== 200) throw new UpdateError(`download failed: HTTP ${res.status}`);
    return res;
  }
  throw new UpdateError('too many redirects');
}

/** Read a whole (small) response body, refusing more than `max` bytes. */
async function readLimited(res, max) {
  const declared = Number(res.headers.get('content-length'));
  if (declared > max) throw new UpdateError('response too large');
  const chunks = [];
  let total = 0;
  const reader = res.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) { await reader.cancel(); throw new UpdateError('response too large'); }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

/**
 * Find the latest release and verify its signed manifest. Returns
 * { state: 'not-configured' | 'unsigned' | 'current' | 'available', ... }.
 */
async function checkForUpdate({ fetchFn, currentVersion, publicKeys, env }) {
  if (!publicKeys.length) return { state: 'not-configured' };
  const apiRes = await safeFetch(fetchFn, `https://api.github.com/repos/${REPO}/releases/latest`, 'application/vnd.github+json');
  let release;
  try { release = JSON.parse((await readLimited(apiRes, MAX_API_BYTES)).toString('utf8')); } catch (e) { throw e instanceof UpdateError ? e : new UpdateError('unexpected answer from GitHub'); }
  const assets = new Map();
  for (const a of Array.isArray(release.assets) ? release.assets : []) {
    if (a && typeof a.name === 'string' && NAME_RE.test(a.name) && typeof a.browser_download_url === 'string') assets.set(a.name, a);
  }
  if (!assets.has(MANIFEST) || !assets.has(SIGNATURE)) return { state: 'unsigned', tag: typeof release.tag_name === 'string' ? release.tag_name.slice(0, 40) : '' };
  const manifestBytes = await readLimited(await safeFetch(fetchFn, assets.get(MANIFEST).browser_download_url, 'application/octet-stream'), MAX_MANIFEST_BYTES);
  const sigText = (await readLimited(await safeFetch(fetchFn, assets.get(SIGNATURE).browser_download_url, 'application/octet-stream'), 1024)).toString('utf8');
  const manifest = verifyManifest(manifestBytes, sigText, publicKeys);
  if (!isNewer(manifest.version, currentVersion)) return { state: 'current', latest: manifest.version };
  const { mode, kind } = installMode(env);
  const file = chooseFile(manifest, env, kind);
  if (!file) return { state: 'no-build', latest: manifest.version, platform: `${env.platform}-${env.arch}`, kind };
  const asset = assets.get(file.name);
  if (!asset || asset.size !== file.size) throw new UpdateError(`release asset ${file.name} is missing or differs from the signed manifest`);
  return {
    state: 'available',
    version: manifest.version,
    mode,
    file,
    url: safeUrl(asset.browser_download_url),
    releaseUrl: `https://github.com/${REPO}/releases/tag/v${manifest.version}`,
  };
}

/**
 * Download to `dest`, checking the size as it arrives and the SHA-256 at the
 * end. The bytes go to "<dest>.part" (created exclusively, mode 0600), which
 * is renamed to `dest` only once verified: `dest` never holds unverified data.
 * A mismatch deletes the partial file and throws.
 */
async function downloadVerified({ fetchFn, url, dest, size, sha256, onProgress }) {
  if (fs.existsSync(dest)) throw new UpdateError('the destination file already exists');
  const res = await safeFetch(fetchFn, url, 'application/octet-stream');
  const declared = Number(res.headers.get('content-length'));
  if (declared && declared !== size) throw new UpdateError('download size differs from the signed manifest');
  const part = `${dest}.part`;
  const fh = await fs.promises.open(part, 'wx', 0o600);
  const hash = crypto.createHash('sha256');
  let received = 0;
  let ok = false;
  try {
    const reader = res.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.length;
      if (received > size) { await reader.cancel(); throw new UpdateError('download is larger than the signed manifest says'); }
      hash.update(value);
      await fh.write(value);
      if (onProgress) onProgress(received, size);
    }
    if (received !== size) throw new UpdateError('download is incomplete');
    if (hash.digest('hex') !== sha256) throw new UpdateError('download does not match the signed SHA-256: discarded');
    await fh.sync();
    ok = true;
  } finally {
    await fh.close();
    if (!ok) await fs.promises.rm(part, { force: true });
  }
  await placeNoClobber(part, dest);
  return dest;
}

/** Move `from` to `to` without ever replacing an existing `to` (hard link, else exclusive copy). */
async function placeNoClobber(from, to) {
  try {
    await fs.promises.link(from, to);
  } catch (e) {
    if (e.code === 'EEXIST') { await fs.promises.rm(from, { force: true }); throw new UpdateError('the destination file appeared during the download'); }
    await fs.promises.copyFile(from, to, fs.constants.COPYFILE_EXCL);
  }
  await fs.promises.rm(from, { force: true });
}

/** SHA-256 of a file, streamed. */
function fileSha256(file) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    fs.createReadStream(file).on('data', (c) => hash.update(c)).on('error', reject).on('end', () => resolve(hash.digest('hex')));
  });
}

/** A path in `dir` for `name` that does not exist yet ("name (1).ext" ...). */
function freePath(dir, name) {
  const ext = path.extname(name);
  const base = name.slice(0, name.length - ext.length);
  for (let i = 0; i < 1000; i++) {
    const p = path.join(dir, i ? `${base} (${i})${ext}` : name);
    if (!fs.existsSync(p) && !fs.existsSync(`${p}.part`)) return p;
  }
  throw new UpdateError('no free file name in the download folder');
}

module.exports = {
  REPO, PRODUCT, MANIFEST, SIGNATURE, ALLOWED_HOSTS, NAME_RE, KINDS, UpdateError,
  parseVersion, compareVersions, isNewer, checkRedirect, safeUrl, verifyManifest, installMode, chooseFile, safeFetch, readLimited, checkForUpdate, downloadVerified, fileSha256, freePath, MAX_REDIRECTS,
};
