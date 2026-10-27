#!/usr/bin/env node
// Build and sign update-manifest.json for a release (run in CI).
//
//   UPDATE_SIGNING_KEY=<pkcs8 pem> node scripts/sign-update-manifest.cjs <artifact-dir> <tag>
//
// The manifest lists every artifact the app can update from, with its size and
// SHA-256, the version and the product id; update-manifest.json.sig is the
// Ed25519 signature of its exact bytes. The key is read from the environment
// only and never written to disk.

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { PRODUCT, MANIFEST, SIGNATURE, NAME_RE, parseVersion, verifyManifest } = require('../electron/updater.cjs');

/** Release file name → what it is (names come from the "build" section of package.json). */
function classify(name) {
  const rules = [
    [/^InfrastructureLab-Setup-.+-win-x64\.exe$/, 'win32', 'x64', 'nsis'],
    [/^InfrastructureLab-.+-win-x64-portable\.exe$/, 'win32', 'x64', 'portable'],
    [/^InfrastructureLab-.+-win-x64\.zip$/, 'win32', 'x64', 'zip'],
    [/^InfrastructureLab-.+-linux-x86_64\.AppImage$/, 'linux', 'x64', 'appimage'],
    [/^InfrastructureLab-.+-linux-amd64\.deb$/, 'linux', 'x64', 'deb'],
    [/^InfrastructureLab-.+-linux-x64\.tar\.gz$/, 'linux', 'x64', 'targz'],
    [/^InfrastructureLab-.+-mac-(x64|arm64)\.dmg$/, 'darwin', null, 'dmg'],
  ];
  for (const [re, platform, arch, kind] of rules) {
    const m = re.exec(name);
    if (m) return { platform, arch: arch ?? m[1], kind };
  }
  return null;
}

function main() {
  const [dir, tag] = process.argv.slice(2);
  const key = process.env.UPDATE_SIGNING_KEY;
  if (!dir || !tag || !key) {
    console.error('usage: UPDATE_SIGNING_KEY=<pem> sign-update-manifest.cjs <artifact-dir> <tag>');
    process.exit(2);
  }
  const version = tag.replace(/^v/, '');
  // Only X.Y.Z releases are offered as updates; others (v1.3.0-rc.1) are published unsigned.
  if (!/^v/.test(tag) || !parseVersion(version)) {
    console.log(`::warning::${tag} is not a vX.Y.Z tag: no update manifest (the app will not offer this release).`);
    return;
  }
  const files = [];
  for (const name of fs.readdirSync(dir).sort()) {
    const what = classify(name);
    if (!what || !NAME_RE.test(name)) continue;
    const data = fs.readFileSync(path.join(dir, name));
    files.push({ name, ...what, size: data.length, sha256: crypto.createHash('sha256').update(data).digest('hex') });
  }
  if (!files.length) throw new Error(`no release artifacts found in ${dir}`);
  const manifest = Buffer.from(`${JSON.stringify({ schema: 1, product: PRODUCT, version, tag: `v${version}`, created: new Date().toISOString(), files }, null, 2)}\n`);
  const privateKey = crypto.createPrivateKey(key);
  const sig = crypto.sign(null, manifest, privateKey).toString('base64');
  // Check with the public half before publishing, exactly as the app will.
  verifyManifest(manifest, sig, [crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'pem' })]);
  fs.writeFileSync(path.join(dir, MANIFEST), manifest);
  fs.writeFileSync(path.join(dir, SIGNATURE), `${sig}\n`);
  console.log(`Signed ${MANIFEST} for ${tag}: ${files.map((f) => f.name).join(', ')}`);
}

if (require.main === module) main();
module.exports = { classify };
