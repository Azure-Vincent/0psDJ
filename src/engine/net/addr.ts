// Family-independent address helpers used by the forwarding engine and tools.

import { inCidr, parseCidr, parseIp } from './ip';
import { canonicalIp6, inCidr6, parseCidr6, parseIp6 } from './ip6';

export type Family = 4 | 6;

export function familyOf(ip: string): Family {
  return ip.includes(':') ? 6 : 4;
}

export function isIpAddress(s: string): boolean {
  return s.includes(':') ? parseIp6(s) !== null : parseIp(s) !== null;
}

/** Normalise an address string (canonical IPv6 text; IPv4 unchanged). */
export function normAddr(s: string): string {
  return s.includes(':') ? canonicalIp6(s) ?? s : s;
}

export function validPrefix(cidr: string, family?: Family): boolean {
  const f = family ?? (cidr.includes(':') ? 6 : 4);
  return f === 6 ? parseCidr6(cidr) !== null : parseCidr(cidr) !== null;
}

/** True when `ip` lies in `cidr` (both of the same family; 'default' matches everything of that family). */
export function inPrefix(ip: string, cidr: string): boolean {
  if (ip.includes(':')) {
    if (cidr === 'default') return true;
    if (!cidr.includes(':')) return false;
    const c = parseCidr6(cidr);
    return !!c && inCidr6(ip, c);
  }
  if (cidr.includes(':')) return false;
  const c = parseCidr(cidr);
  return !!c && inCidr(ip, c);
}

export function prefixLength(cidr: string): number {
  if (cidr === 'default') return 0;
  const p = cidr.split('/')[1];
  return p === undefined ? (cidr.includes(':') ? 128 : 32) : Number(p);
}

/** "[2001:db8::1]:22" style for v6, "10.0.0.1:22" for v4. */
export function hostPort(ip: string, port: number): string {
  return ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`;
}
