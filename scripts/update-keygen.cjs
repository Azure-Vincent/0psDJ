#!/usr/bin/env node
// Create the Ed25519 key pair that signs update manifests.
//
//   node scripts/update-keygen.cjs [private-key-file]
//
// Writes the private key to the given file (default: update-signing-key.pem,
// git-ignored, mode 0600) and adds the public key to
// electron/update-public-keys.cjs. Then:
//   1. GitHub → Settings → Secrets and variables → Actions → New secret
//      UPDATE_SIGNING_KEY = the whole content of the private key file;
//   2. commit electron/update-public-keys.cjs;
//   3. move the private key file offline (password manager) and delete it here.
// Anyone holding the private key can sign updates every user will install.

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const out = path.resolve(process.argv[2] || 'update-signing-key.pem');
if (fs.existsSync(out)) {
  console.error(`${out} already exists; refusing to overwrite a signing key.`);
  process.exit(1);
}
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
fs.writeFileSync(out, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });

const keysFile = path.join(__dirname, '..', 'electron', 'update-public-keys.cjs');
const pub = publicKey.export({ type: 'spki', format: 'pem' }).trim();
const keys = require(keysFile);
if (keys.includes(pub)) process.exit(0);
const list = [...keys, pub].map((k) => `  ${JSON.stringify(k)},`).join('\n');
const src = fs.readFileSync(keysFile, 'utf8').replace(/module\.exports = \[[\s\S]*\];\s*$/, `module.exports = [\n${list}\n];\n`);
fs.writeFileSync(keysFile, src);
console.log(`Private key: ${out} (keep it secret; store it as the UPDATE_SIGNING_KEY secret, then move it offline).`);
console.log(`Public key added to ${path.relative(process.cwd(), keysFile)}.`);
