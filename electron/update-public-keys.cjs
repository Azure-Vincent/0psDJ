// Public keys that may sign update manifests (Ed25519, PEM). The matching
// private key lives only in the GitHub Actions secret UPDATE_SIGNING_KEY.
// Generate a pair with: node scripts/update-keygen.cjs
// To rotate, add the new key here, ship a release signed with the old key,
// then sign with the new key and remove the old one in a later release.
// While this list is empty the app never offers an update.
'use strict';

module.exports = [];
