// Network operations shared by the PowerShell cmdlets and the Windows console
// programs: one ICMP echo exchange, name resolution with Windows wording, and
// helpers for addresses and masks.

import { formatIp, prefixMask } from '../../net/ip';
import { resolve, type ResolveResult } from '../../sim/dns';
import { echoIcmp, icmpMeaning, nextId, sourceAddress, transmit } from '../../sim/network';
import type { Host, Packet, World } from '../../types';

export type EchoResult =
  | { kind: 'reply'; ms: number; ttl: number }
  | { kind: 'timeout' }
  | { kind: 'unreachable'; from: string; text: string }
  | { kind: 'local'; text: string };

/** Send one echo request and wait for the reply (Windows waits 4 s by default). */
export function echo(world: World, host: Host, dst: string, size = 32, seq = 1, ttl?: number, timeoutMs = 4000): EchoResult {
  const v6 = dst.includes(':');
  const start = world.clock;
  const src = sourceAddress(host, dst);
  const req: Packet = { id: nextId(world), src, dst, ttl: ttl ?? 64, proto: 'icmp', icmp: { ...echoIcmp(v6, false, 1, seq), size } };
  const d = transmit(world, host.id, req);
  if (d.status === 'local-error') {
    if (d.errno === 'ENETUNREACH') return { kind: 'local', text: 'PING: transmit failed. General failure.' };
    if (d.errno === 'EHOSTUNREACH') return { kind: 'unreachable', from: src, text: 'Destination host unreachable.' };
    return { kind: 'local', text: 'General failure.' };
  }
  if (d.status === 'delivered') {
    const target = world.hosts[d.host];
    const rep: Packet = { id: nextId(world), src: d.final.dst, dst: d.final.src, ttl: 64, proto: 'icmp', icmp: { ...echoIcmp(v6, true, 1, seq), size } };
    const back = transmit(world, target.id, rep);
    if (back.status === 'delivered') return { kind: 'reply', ms: Math.max(0, Math.round(world.clock - start)), ttl: back.final.ttl };
  } else if (d.error?.delivered) {
    const e = d.error.packet;
    const m = icmpMeaning(e);
    const text = m === 'ttl' ? 'TTL expired in transit.' : m === 'net' ? 'Destination net unreachable.' : m === 'port' ? 'Destination port unreachable.' : m === 'admin' ? 'Communication administratively prohibited.' : 'Destination host unreachable.';
    return { kind: 'unreachable', from: e.src, text };
  }
  world.clock = Math.max(world.clock, start + timeoutMs);
  return { kind: 'timeout' };
}

export function maskOf(prefix: number): string {
  return formatIp(prefixMask(prefix));
}

/** IPv4 resolution as Windows programs do it (hosts file, then the adapters' DNS servers). */
export function resolve4(world: World, host: Host, name: string): ResolveResult {
  return resolve(world, host, name, { family: 4 });
}

/** MAC address in Windows notation (00-15-5D-...). */
export function winMac(mac: string): string {
  return mac.toUpperCase().replace(/:/g, '-');
}
