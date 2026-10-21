// X.509 / PKI model. Certificates, keys and CSRs are PEM files whose base64 body
// carries the certificate fields as JSON (plus a synthetic signature), so they
// look like real PEM, survive cp/cat/sed, and can be inspected with openssl.
// The cryptography is simulated: a "signature" is a hash of the to-be-signed
// fields and the signer's key id, so tampering, wrong issuers and key/cert
// mismatches are detected exactly where OpenSSL would detect them.
//
// Verification follows OpenSSL 3.0's X509_verify_cert: build the chain from the
// peer's certificates (untrusted) up to a self-signed anchor in the trust store,
// then check validity periods and CA flags. Error codes and texts are OpenSSL's.

import type { Host } from '../types';
import { readFile } from '../fs';
import { base64Decode, base64Encode, seededBytes, sha256, utf8 } from '../util/sha256';

export type DN = [string, string][];

export interface Cert {
  serial: string;
  subject: DN;
  issuer: DN;
  notBefore: number;
  notAfter: number;
  /** subjectAltName entries, e.g. "DNS:www.corp.lab", "IP:203.0.113.80". */
  san: string[];
  ca: boolean;
  pathlen?: number;
  /** Id of the subject's key pair (stands in for the public key). */
  keyId: string;
  /** Id of the key that signed this certificate. */
  signer: string;
  bits: number;
  sig: string;
}

export interface PrivKey { keyId: string; bits: number }
export interface Csr { subject: DN; san: string[]; keyId: string; bits: number }

const BEGIN = (t: string) => `-----BEGIN ${t}-----`;
const END = (t: string) => `-----END ${t}-----`;

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function wrap(b64: string): string {
  return b64.match(/.{1,64}/g)!.join('\n');
}

function pem(type: string, body: object): string {
  return `${BEGIN(type)}\n${wrap(base64Encode(utf8(JSON.stringify(body))))}\n${END(type)}\n`;
}

/** All PEM blocks of `type` in `text`, decoded (undefined entries for corrupt blocks). */
function blocks<T>(text: string, type: string): (T | undefined)[] {
  const re = new RegExp(`${BEGIN(type)}([\\s\\S]*?)${END(type)}`, 'g');
  const out: (T | undefined)[] = [];
  for (const m of text.matchAll(re)) {
    try {
      out.push(JSON.parse(new TextDecoder().decode(base64Decode(m[1].replace(/\s+/g, '')))) as T);
    } catch {
      out.push(undefined);
    }
  }
  return out;
}

function tbs(c: Omit<Cert, 'sig'>): string {
  return JSON.stringify([c.serial, c.subject, c.issuer, c.notBefore, c.notAfter, c.san, c.ca, c.pathlen, c.keyId, c.bits]);
}

function signature(c: Omit<Cert, 'sig'>): string {
  return hex(sha256(utf8(tbs(c) + '|' + c.signer)));
}

export function keyIdFor(seed: string): string {
  return hex(seededBytes('key:' + seed, 8));
}

export function makeCert(fields: Omit<Cert, 'sig' | 'serial' | 'bits'> & { serial?: string; bits?: number }): Cert {
  const base = { bits: 2048, serial: hex(seededBytes('serial:' + fields.keyId + fields.notBefore, 16)).toUpperCase(), ...fields };
  return { ...base, sig: signature(base) };
}

export const certPem = (c: Cert) => pem('CERTIFICATE', c);
export const keyPem = (k: PrivKey) => pem('PRIVATE KEY', { ...k, d: hex(seededBytes('priv:' + k.keyId, 96)) });
export const csrPem = (r: Csr) => pem('CERTIFICATE REQUEST', r);

export function parseCerts(text: string): (Cert | undefined)[] {
  return blocks<Cert>(text, 'CERTIFICATE');
}
export function parseKey(text: string): PrivKey | undefined {
  return [...blocks<PrivKey>(text, 'PRIVATE KEY'), ...blocks<PrivKey>(text, 'RSA PRIVATE KEY')][0];
}
export function parseCsr(text: string): Csr | undefined {
  return blocks<Csr>(text, 'CERTIFICATE REQUEST')[0];
}

export function signatureValid(c: Cert, signerKeyId: string): boolean {
  return c.signer === signerKeyId && c.sig === signature(c);
}

// ---------------------------------------------------------------------------
// Formatting (OpenSSL 3.0 / curl 7.88 styles)
// ---------------------------------------------------------------------------

export const dnOpenssl = (dn: DN) => dn.map(([k, v]) => `${k} = ${v}`).join(', ');
export const dnCurl = (dn: DN) => dn.map(([k, v]) => `${k}=${v}`).join('; ');
export const cn = (dn: DN) => dn.find(([k]) => k === 'CN')?.[1] ?? '';
const sameDn = (a: DN, b: DN) => JSON.stringify(a) === JSON.stringify(b);

/** "/C=US/O=Corp Lab/CN=www.corp.lab" -> DN. */
export function parseSubj(s: string): DN | null {
  if (!s.startsWith('/')) return null;
  const out: DN = [];
  for (const part of s.slice(1).split('/')) {
    if (!part) continue;
    const i = part.indexOf('=');
    if (i <= 0) return null;
    out.push([part.slice(0, i), part.slice(i + 1)]);
  }
  return out;
}

const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
/** "Jun  1 00:00:00 2026 GMT" (ASN1_TIME_print). */
export function asn1Time(ms: number): string {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${MON[d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2, ' ')} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} ${d.getUTCFullYear()} GMT`;
}

export function fingerprint(c: Cert, alg: 'sha1' | 'sha256' = 'sha256'): string {
  const h = sha256(utf8(c.sig + c.serial));
  return hex(alg === 'sha1' ? h.slice(0, 20) : h).toUpperCase().match(/../g)!.join(':');
}

/** RSA modulus stand-in derived from the key id: equal for a certificate and its private key. */
export function modulus(keyId: string, bits = 2048): string {
  return hex(seededBytes('modulus:' + keyId, bits / 8)).toUpperCase();
}

export function publicKeyPem(keyId: string, bits = 2048): string {
  const body = base64Encode(new Uint8Array([0x30, 0x82, 0x01, 0x22, ...seededBytes('pub:' + keyId, bits / 8 + 30)]));
  return `-----BEGIN PUBLIC KEY-----\n${wrap(body)}\n-----END PUBLIC KEY-----`;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

export const VERIFY_TEXT: Record<number, string> = {
  2: 'unable to get issuer certificate',
  7: 'certificate signature failure',
  9: 'certificate is not yet valid',
  10: 'certificate has expired',
  18: 'self-signed certificate',
  19: 'self-signed certificate in certificate chain',
  20: 'unable to get local issuer certificate',
  21: 'unable to verify the first certificate',
  24: 'invalid CA certificate',
};

export interface VerifyError { depth: number; code: number; cert: Cert }
export interface VerifyResult { ok: boolean; chain: Cert[]; errors: VerifyError[]; trustedAnchor: boolean }

const selfSigned = (c: Cert) => sameDn(c.subject, c.issuer) && c.signer === c.keyId;

/**
 * Verify `leaf` against `trusted` anchors, using `untrusted` certificates (the rest of the peer's
 * chain) to fill gaps. Returns every error in the order OpenSSL's verify callback reports them.
 */
export function verifyChain(leaf: Cert, untrusted: Cert[], trusted: Cert[], now: number): VerifyResult {
  const chain: Cert[] = [leaf];
  const errors: VerifyError[] = [];
  let anchored = false;
  let cur = leaf;
  const isTrusted = (c: Cert) => trusted.some((t) => t.keyId === c.keyId && sameDn(t.subject, c.subject));
  for (let guard = 0; guard < 10; guard++) {
    if (selfSigned(cur)) {
      if (isTrusted(cur)) anchored = true;
      else errors.push({ depth: chain.length - 1, code: chain.length === 1 ? 18 : 19, cert: cur });
      break;
    }
    const fromTrust = trusted.find((t) => sameDn(t.subject, cur.issuer) && t.keyId === cur.signer);
    const fromPeer = fromTrust ? undefined : untrusted.find((u) => sameDn(u.subject, cur.issuer) && u.keyId === cur.signer && !chain.includes(u));
    const next = fromTrust ?? fromPeer;
    if (!next) {
      const nameOnly = [...trusted, ...untrusted].find((t) => sameDn(t.subject, cur.issuer));
      if (nameOnly) errors.push({ depth: chain.length - 1, code: 7, cert: cur });
      else {
        const lastTrusted = isTrusted(cur);
        errors.push({ depth: chain.length - 1, code: lastTrusted ? 2 : 20, cert: cur });
        if (chain.length === 1) errors.push({ depth: 0, code: 21, cert: cur });
      }
      break;
    }
    if (!next.ca) errors.push({ depth: chain.length, code: 24, cert: next });
    chain.push(next);
    if (fromTrust && !selfSigned(next)) {
      // A trusted intermediate still needs its own issuer (no partial chains by default).
      cur = next;
      continue;
    }
    cur = next;
  }
  chain.forEach((c, depth) => {
    if (now < c.notBefore) errors.push({ depth, code: 9, cert: c });
    else if (now > c.notAfter) errors.push({ depth, code: 10, cert: c });
  });
  return { ok: errors.length === 0, chain, errors, trustedAnchor: anchored };
}

/** RFC 6125 host name check (as X509_check_host): SAN DNS/IP entries, CN only when there is no DNS SAN. */
export function matchesHost(c: Cert, host: string): string | null {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  const isIp = /^[\d.]+$/.test(h) || h.includes(':');
  if (isIp) return c.san.find((s) => s === `IP:${h}`) ?? null;
  const names = c.san.filter((s) => s.startsWith('DNS:')).map((s) => s.slice(4).toLowerCase());
  const candidates = names.length ? names : [cn(c.subject).toLowerCase()];
  for (const n of candidates) {
    if (n === h) return n;
    if (n.startsWith('*.') && h.split('.').length > 2 && h.slice(h.indexOf('.') + 1) === n.slice(2)) return n;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Trust store (Debian ca-certificates)
// ---------------------------------------------------------------------------

export const CA_BUNDLE = '/etc/ssl/certs/ca-certificates.crt';

export function trustStore(host: Host, file = CA_BUNDLE): Cert[] {
  return parseCerts(readFile(host, file) ?? '').filter((c): c is Cert => !!c);
}

// ---------------------------------------------------------------------------
// The lab's certificate authorities
// ---------------------------------------------------------------------------

const day = 86_400_000;
const at = (iso: string) => Date.parse(iso);
const addYears = (ms: number, n: number) => { const d = new Date(ms); d.setUTCFullYear(d.getUTCFullYear() + n); return d.getTime(); };

function ca(name: DN, seed: string, issuer: { dn: DN; keyId: string } | null, from: string, years: number, pathlen?: number): { cert: Cert; key: PrivKey } {
  const keyId = keyIdFor(seed);
  const cert = makeCert({
    subject: name, issuer: issuer?.dn ?? name, notBefore: at(from), notAfter: addYears(at(from), years),
    san: [], ca: true, pathlen, keyId, signer: issuer?.keyId ?? keyId, bits: issuer ? 2048 : 4096,
  });
  return { cert, key: { keyId, bits: cert.bits } };
}

export const CORP_ROOT = ca([['C', 'US'], ['O', 'Corp Lab'], ['CN', 'Corp Lab Root CA']], 'corp-root', null, '2024-01-15T00:00:00Z', 20);
export const CORP_ISSUING = ca([['C', 'US'], ['O', 'Corp Lab'], ['CN', 'Corp Lab Issuing CA 1']], 'corp-issuing-1',
  { dn: CORP_ROOT.cert.subject, keyId: CORP_ROOT.key.keyId }, '2024-01-15T00:00:00Z', 10, 0);

/** Fictitious public roots that stand in for the Mozilla bundle Debian ships. */
export const PUBLIC_ROOTS = [
  { file: 'mozilla/Example_Global_Root_R1.crt', ...ca([['C', 'US'], ['O', 'Example Trust Services'], ['CN', 'Example Global Root R1']], 'pub-r1', null, '2016-12-01T00:00:00Z', 20) },
  { file: 'mozilla/Sample_Public_Root_CA_2019.crt', ...ca([['C', 'GB'], ['O', 'Sample Certification Ltd'], ['CN', 'Sample Public Root CA 2019']], 'pub-2019', null, '2019-03-01T00:00:00Z', 25) },
  { file: 'mozilla/Demo_Root_Authority_G2.crt', ...ca([['C', 'DE'], ['O', 'Demo Trust GmbH'], ['CN', 'Demo Root Authority G2']], 'pub-g2', null, '2014-06-01T00:00:00Z', 24) },
];
export const PUBLIC_ISSUING = ca([['C', 'US'], ['O', 'Example Trust Services'], ['CN', 'Example TLS Issuing CA 3']], 'pub-issuing-3',
  { dn: PUBLIC_ROOTS[0].cert.subject, keyId: PUBLIC_ROOTS[0].key.keyId }, '2023-04-01T00:00:00Z', 8, 0);

/** Issue a server certificate (serverAuth) for `names` from `issuer`. */
export function issueServerCert(issuer: { cert: Cert; key: PrivKey }, names: string[], keySeed: string, from: string, days: number): { cert: Cert; key: PrivKey } {
  const keyId = keyIdFor(keySeed);
  const cert = makeCert({
    subject: [['CN', names[0]]], issuer: issuer.cert.subject, notBefore: at(from), notAfter: at(from) + days * day,
    san: names.map((n) => (/^[\d.]+$/.test(n) ? `IP:${n}` : `DNS:${n}`)), ca: false, keyId, signer: issuer.key.keyId,
  });
  return { cert, key: { keyId, bits: 2048 } };
}

/** Text of /etc/ca-certificates.conf as Debian writes it, listing the public roots. */
export function caCertificatesConf(): string {
  return '# This file lists certificates that you wish to use or to ignore to be\n# installed in /etc/ssl/certs.\n# update-ca-certificates(8) will update /etc/ssl/certs by reading this file.\n#\n# This is autogenerated by dpkg-reconfigure ca-certificates.\n# Certificates should be installed under /usr/share/ca-certificates\n# and files with extension \'.crt\' is recognized as available certificate.\n#\n# line begins with # is comment.\n# line begins with ! is certificate filename to be deselected.\n#\n' + PUBLIC_ROOTS.map((r) => r.file).join('\n') + '\n';
}
