// SSH binary packet construction (RFC 4253 §6) for the unencrypted part of the
// handshake, so exported PCAPs decode correctly in Wireshark. Encrypted packets
// are represented by deterministic pseudo-random bytes of a realistic length.

import { seededBytes, utf8 } from '../util/sha256';

function u32(n: number): number[] {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
}

function str(b: Uint8Array | string): number[] {
  const bytes = typeof b === 'string' ? utf8(b) : b;
  return [...u32(bytes.length), ...bytes];
}

export function binaryPacket(payload: number[], seed: string): Uint8Array {
  // padding: at least 4 bytes, total (4 + 1 + payload + padding) multiple of 8
  let pad = 8 - ((5 + payload.length) % 8);
  if (pad < 4) pad += 8;
  const padding = [...seededBytes(seed, pad)];
  return new Uint8Array([...u32(1 + payload.length + pad), pad, ...payload, ...padding]);
}

export interface KexInitLists {
  kex: string[];
  hostKey: string[];
  ciphers: string[];
  macs: string[];
  compression: string[];
}

export function kexInitPacket(l: KexInitLists, seed: string): Uint8Array {
  const payload = [
    20,
    ...seededBytes(seed + 'cookie', 16),
    ...str(l.kex.join(',')),
    ...str(l.hostKey.join(',')),
    ...str(l.ciphers.join(',')),
    ...str(l.ciphers.join(',')),
    ...str(l.macs.join(',')),
    ...str(l.macs.join(',')),
    ...str(l.compression.join(',')),
    ...str(l.compression.join(',')),
    ...str(''),
    ...str(''),
    0,
    ...u32(0),
  ];
  return binaryPacket(payload, seed);
}

export function kexEcdhInit(qcLen: number, seed: string): Uint8Array {
  return binaryPacket([30, ...str(seededBytes(seed + 'qc', qcLen))], seed);
}

export function kexEcdhReply(hostKeyBlob: Uint8Array, qsLen: number, sigAlg: string, seed: string): Uint8Array {
  const sig = [...str(sigAlg), ...str(seededBytes(seed + 'sig', sigAlg === 'ssh-ed25519' ? 64 : sigAlg.startsWith('rsa') ? 384 : 72))];
  return binaryPacket([31, ...str(hostKeyBlob), ...str(seededBytes(seed + 'qs', qsLen)), ...str(new Uint8Array(sig))], seed);
}

export function newKeysPacket(seed: string): Uint8Array {
  return binaryPacket([21], seed);
}

/** Size on the wire of an encrypted chacha20-poly1305 / AES-GCM packet with a given payload size. */
export function encryptedSize(payloadLen: number): number {
  let pad = 8 - ((1 + payloadLen) % 8);
  if (pad < 4) pad += 8;
  return 4 + 1 + payloadLen + pad + 16;
}

export function encryptedBytes(payloadLen: number, seed: string): Uint8Array {
  return seededBytes(seed, encryptedSize(payloadLen));
}

export const KEX_PUBLIC_SIZES: Record<string, { client: number; server: number }> = {
  'sntrup761x25519-sha512@openssh.com': { client: 1158 + 32, server: 1039 + 32 },
  'curve25519-sha256': { client: 32, server: 32 },
  'curve25519-sha256@libssh.org': { client: 32, server: 32 },
  'ecdh-sha2-nistp256': { client: 65, server: 65 },
  'ecdh-sha2-nistp384': { client: 97, server: 97 },
  'ecdh-sha2-nistp521': { client: 133, server: 133 },
  'diffie-hellman-group14-sha256': { client: 257, server: 257 },
  'diffie-hellman-group14-sha1': { client: 257, server: 257 },
  'diffie-hellman-group16-sha512': { client: 513, server: 513 },
  'diffie-hellman-group18-sha512': { client: 1025, server: 1025 },
  'diffie-hellman-group1-sha1': { client: 129, server: 129 },
  'diffie-hellman-group-exchange-sha256': { client: 385, server: 385 },
  'diffie-hellman-group-exchange-sha1': { client: 385, server: 385 },
};
