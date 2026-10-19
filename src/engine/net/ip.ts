// IPv4 helpers. Addresses are handled as unsigned 32-bit integers internally.

export function parseIp(s: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s.trim());
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

export function formatIp(n: number): string {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

export function isIp(s: string): boolean {
  return parseIp(s) !== null;
}

export function prefixMask(prefix: number): number {
  return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
}

export interface Cidr {
  network: number;
  prefix: number;
}

/** Parses "10.0.0.0/24", "10.0.0.5" (as /32) or "default" (0.0.0.0/0). */
export function parseCidr(s: string): Cidr | null {
  if (s === 'default') return { network: 0, prefix: 0 };
  const [ip, p] = s.split('/');
  const addr = parseIp(ip);
  if (addr === null) return null;
  const prefix = p === undefined ? 32 : Number(p);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  return { network: (addr & prefixMask(prefix)) >>> 0, prefix };
}

export function formatCidr(c: Cidr): string {
  return `${formatIp(c.network)}/${c.prefix}`;
}

export function inCidr(ip: string | number, cidr: Cidr): boolean {
  const n = typeof ip === 'string' ? parseIp(ip) : ip;
  if (n === null) return false;
  return ((n & prefixMask(cidr.prefix)) >>> 0) === cidr.network;
}

export function networkOf(ip: string, prefix: number): string {
  const n = parseIp(ip);
  if (n === null) throw new Error(`bad ip ${ip}`);
  return `${formatIp((n & prefixMask(prefix)) >>> 0)}/${prefix}`;
}

export function broadcastOf(ip: string, prefix: number): string {
  const n = parseIp(ip)!;
  return formatIp(((n & prefixMask(prefix)) | (~prefixMask(prefix) >>> 0)) >>> 0);
}
