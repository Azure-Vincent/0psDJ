// Synthetic SSH keys. Public key blobs use the real RFC 4253 / RFC 8709 wire
// encoding and fingerprints are genuine SHA-256 digests of those blobs, so they
// are internally consistent with OpenSSH tooling. The key material itself is
// deterministic pseudo-random data: it is NOT a usable cryptographic key.

import { base64Decode, base64Encode, seededBytes, sha256, utf8 } from '../util/sha256';

export type KeyType = 'ed25519' | 'ecdsa' | 'rsa';

export const KEY_ALG: Record<KeyType, string> = {
  ed25519: 'ssh-ed25519',
  ecdsa: 'ecdsa-sha2-nistp256',
  rsa: 'ssh-rsa',
};

export const KEY_LABEL: Record<KeyType, string> = { ed25519: 'ED25519', ecdsa: 'ECDSA', rsa: 'RSA' };
const KEY_BITS: Record<KeyType, number> = { ed25519: 256, ecdsa: 256, rsa: 3072 };

function sshString(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + b.length);
  new DataView(out.buffer).setUint32(0, b.length);
  out.set(b, 4);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function publicBlob(type: KeyType, seed: string): Uint8Array {
  switch (type) {
    case 'ed25519':
      return concat(sshString(utf8('ssh-ed25519')), sshString(seededBytes(seed, 32)));
    case 'ecdsa': {
      const q = seededBytes(seed, 65);
      q[0] = 0x04;
      return concat(sshString(utf8('ecdsa-sha2-nistp256')), sshString(utf8('nistp256')), sshString(q));
    }
    case 'rsa': {
      const n = seededBytes(seed, 385);
      n[0] = 0x00;
      n[1] |= 0x80;
      return concat(sshString(utf8('ssh-rsa')), sshString(new Uint8Array([1, 0, 1])), sshString(n));
    }
  }
}

export function fingerprintOfBlob(blob: Uint8Array): string {
  return 'SHA256:' + base64Encode(sha256(blob), false);
}

export interface KeyPair {
  type: KeyType;
  publicLine: string;
  privateFile: string;
  fingerprint: string;
  blobB64: string;
}

export function makeKeyPair(type: KeyType, seed: string, comment: string): KeyPair {
  const blob = publicBlob(type, seed);
  const blobB64 = base64Encode(blob);
  return {
    type,
    blobB64,
    publicLine: `${KEY_ALG[type]} ${blobB64} ${comment}`,
    privateFile: [
      '-----BEGIN OPENSSH PRIVATE KEY-----',
      '(Infrastructure Lab simulated private key. No real key material is stored.)',
      `sim-public: ${KEY_ALG[type]} ${blobB64}`,
      '-----END OPENSSH PRIVATE KEY-----',
      '',
    ].join('\n'),
    fingerprint: fingerprintOfBlob(blob),
  };
}

export interface ParsedPublicKey {
  alg: string;
  type: KeyType;
  blobB64: string;
  comment: string;
  options: string;
  fingerprint: string;
  bits: number;
}

const ALG_TO_TYPE: Record<string, KeyType> = { 'ssh-ed25519': 'ed25519', 'ecdsa-sha2-nistp256': 'ecdsa', 'ssh-rsa': 'rsa' };

/** Parse an authorized_keys / .pub / known_hosts key portion. Returns null for malformed lines. */
export function parsePublicKey(text: string): ParsedPublicKey | null {
  const toks = text.trim().split(/\s+/);
  let i = 0;
  let options = '';
  if (toks.length > 0 && !ALG_TO_TYPE[toks[0]]) {
    options = toks[0];
    i = 1;
  }
  const alg = toks[i];
  const b64 = toks[i + 1];
  const type = ALG_TO_TYPE[alg];
  if (!type || !b64) return null;
  try {
    const blob = base64Decode(b64);
    return { alg, type, blobB64: b64, comment: toks.slice(i + 2).join(' '), options, fingerprint: fingerprintOfBlob(blob), bits: KEY_BITS[type] };
  } catch {
    return null;
  }
}

/** Extract the public key that a simulated private-key file belongs to. */
export function publicFromPrivate(content: string): ParsedPublicKey | null {
  const m = /sim-public: (\S+ \S+)/.exec(content);
  return m ? parsePublicKey(m[1]) : null;
}

export function hostKeyFiles(): { type: KeyType; path: string }[] {
  return [
    { type: 'rsa', path: '/etc/ssh/ssh_host_rsa_key' },
    { type: 'ecdsa', path: '/etc/ssh/ssh_host_ecdsa_key' },
    { type: 'ed25519', path: '/etc/ssh/ssh_host_ed25519_key' },
  ];
}
