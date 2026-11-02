# Release signing (maintainers)

Installed apps accept an update only if its `update-manifest.json` is signed
with the project key. Set this up once:

1. `node scripts/update-keygen.cjs` creates `update-signing-key.pem` (git-ignored)
   and adds the public key to `electron/update-public-keys.cjs`. Commit that file.
2. In GitHub, create the environment **release** (Settings → Environments) and
   store the whole private key file there as the secret **`UPDATE_SIGNING_KEY`**
   (not as a repository secret). Then protect it:
   - **Deployment branches and tags → Selected branches and tags**: add the tag
     pattern `v*` only (and `main` if you create releases with a manual run);
   - **Required reviewers**: yourself (and any co-maintainer);
   - a **tag ruleset** (Settings → Rules) so that only maintainers can create
     or move `v*` tags.

   Only the `release` job of `.github/workflows/build.yml` can read the key, only
   for a protected tag, and only after approval: a collaborator cannot change
   the signing script on a branch and run it with the key.
3. Move the private key file offline (a password manager) and delete it from
   the working copy.

Each release (a pushed `v*` tag, or a manual run with a release tag) then gets
`update-manifest.json` and `update-manifest.json.sig` next to the executables.
Without the secret, a release is published without them and apps do not offer
it. Builds made before step 1 contain no key and never self-update; users of
those builds install the first signed version by hand once.
To rotate the key, add the new public key to `update-public-keys.cjs`, release
that version with the old key, then switch the secret to the new key and remove
the old public key in a later release. If the private key leaks, remove its
public key in a release signed with another key you trust, and revoke the
secret.
