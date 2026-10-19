// IPv6 helpers (RFC 4291 addressing, RFC 5952 text form). Addresses are
// handled as 128-bit bigints internally.

const MASK128 = (1n << 128n) - 1n;

export function parseIp6(s: string): bigint | null {
  let t = s.trim().toLowerCase();
  const pct = t.indexOf('%');
  if (pct >= 0) t = t.slice(0, pct);
  if (!t.includes(':') || !/^[0-9a-f:.]+$/.test(t)) return null;
  // Embedded IPv4 in the last 32 bits (::ffff:10.0.0.1)
  const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(t);
  if (v4) {
    const p = v4[1].split('.').map(Number);
    if (p.some((x) => x > 255)) return null;
    t = t.slice(0, -v4[1].length) + ((p[0] << 8) | p[1]).toString(16) + ':' + ((p[2] << 8) | p[3]).toString(16);
  }
  const halves = t.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  if (halves.length === 1 && head.length !== 8) return null;
  if (halves.length === 2 && head.length + tail.length > 7) return null;
  const groups = [...head, ...Array(8 - head.length - tail.length).fill('0'), ...tail];
  let n = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    n = (n << 16n) | BigInt(parseInt(g, 16));
  }
  return n;
}

/** RFC 5952 canonical text: lowercase, no leading zeros, longest run (≥2) of zero groups as "::". */
export function formatIp6(n: bigint): string {
  const g: number[] = [];
  for (let i = 7; i >= 0; i--) g.push(Number((n >> BigInt(i * 16)) & 0xffffn));
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (g[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen && j - i >= 2) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  const hex = g.map((x) => x.toString(16));
  if (bestStart < 0) return hex.join(':');
  return `${hex.slice(0, bestStart).join(':')}::${hex.slice(bestStart + bestLen).join(':')}`;
}

/** Fully expanded form (8 groups of 4 digits), used for teaching. */
export function expandIp6(n: bigint): string {
  const g: string[] = [];
  for (let i = 7; i >= 0; i--) g.push(((n >> BigInt(i * 16)) & 0xffffn).toString(16).padStart(4, '0'));
  return g.join(':');
}

export function canonicalIp6(s: string): string | null {
  const n = parseIp6(s);
  return n === null ? null : formatIp6(n);
}

export function prefixMask6(prefix: number): bigint {
  return prefix === 0 ? 0n : (MASK128 << BigInt(128 - prefix)) & MASK128;
}

export interface Cidr6 {
  network: bigint;
  prefix: number;
}

export function parseCidr6(s: string): Cidr6 | null {
  if (s === 'default' || s === '::/0') return { network: 0n, prefix: 0 };
  const [a, p] = s.split('/');
  const n = parseIp6(a);
  if (n === null) return null;
  const prefix = p === undefined ? 128 : Number(p);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) return null;
  return { network: n & prefixMask6(prefix), prefix };
}

export function inCidr6(ip: string | bigint, c: Cidr6): boolean {
  const n = typeof ip === 'string' ? parseIp6(ip) : ip;
  if (n === null) return false;
  return (n & prefixMask6(c.prefix)) === c.network;
}

export function networkOf6(ip: string, prefix: number): string {
  return `${formatIp6(parseIp6(ip)! & prefixMask6(prefix))}/${prefix}`;
}

/** Modified EUI-64 interface identifier from a MAC (RFC 4291 appendix A): flip the U/L bit, insert ff:fe. */
export function eui64(mac: string): bigint {
  const b = mac.split(':').map((x) => parseInt(x, 16));
  const bytes = [b[0] ^ 0x02, b[1], b[2], 0xff, 0xfe, b[3], b[4], b[5]];
  return bytes.reduce((acc, x) => (acc << 8n) | BigInt(x), 0n);
}

export function linkLocalFromMac(mac: string): string {
  return formatIp6((0xfe80n << 112n) | eui64(mac));
}

/** SLAAC address: /64 prefix + EUI-64 interface identifier. */
export function slaacAddress(prefix: string, mac: string): string {
  const c = parseCidr6(prefix)!;
  return formatIp6(c.network | eui64(mac));
}

/** Solicited-node multicast group ff02::1:ffXX:XXXX for an address (RFC 4291 2.7.1). */
export function solicitedNode(ip: string): string {
  const n = parseIp6(ip)!;
  return formatIp6((0xff02n << 112n) | (1n << 32n) | (0xffn << 24n) | (n & 0xffffffn));
}

/** Ethernet multicast MAC for an IPv6 multicast group: 33:33 + low 32 bits (RFC 2464). */
export function multicastMac(ip: string): string {
  const n = parseIp6(ip)!;
  const low = Number(n & 0xffffffffn);
  return ['33', '33', ...[24, 16, 8, 0].map((s) => ((low >>> s) & 255).toString(16).padStart(2, '0'))].join(':');
}

export type V6Kind = 'unspecified' | 'loopback' | 'link-local' | 'unique-local' | 'multicast' | 'documentation' | 'ipv4-mapped' | 'global';

export function classify6(ip: string): V6Kind {
  const n = parseIp6(ip);
  if (n === null) throw new Error(`bad IPv6 address ${ip}`);
  if (n === 0n) return 'unspecified';
  if (n === 1n) return 'loopback';
  const top16 = Number(n >> 112n);
  if ((top16 & 0xffc0) === 0xfe80) return 'link-local';
  if ((top16 & 0xfe00) === 0xfc00) return 'unique-local';
  if ((top16 & 0xff00) === 0xff00) return 'multicast';
  if (inCidr6(n, parseCidr6('2001:db8::/32')!)) return 'documentation';
  if (inCidr6(n, parseCidr6('::ffff:0:0/96')!)) return 'ipv4-mapped';
  return 'global';
}

export function isLinkLocal6(ip: string): boolean {
  return /^fe[89ab]/i.test(ip);
}

/** 16 bytes, network order. */
export function ip6Bytes(ip: string): number[] {
  const n = parseIp6(ip) ?? 0n;
  const out: number[] = [];
  for (let i = 15; i >= 0; i--) out.push(Number((n >> BigInt(i * 8)) & 0xffn));
  return out;
}
