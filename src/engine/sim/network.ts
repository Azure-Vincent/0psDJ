// Hop-by-hop IPv4/IPv6 forwarding model.
//
// For every packet the simulator performs, on each host it reaches:
//   ingress capture -> local delivery (nft input) | forwarding (TTL, route, nft forward)
//   -> route lookup (longest prefix) -> nft output (originating host only)
//   -> ARP (IPv4) or Neighbor Discovery (IPv6) on the egress segment -> egress capture -> next host
// ICMP errors (host/net unreachable, time exceeded, port unreachable,
// admin-prohibited) are generated where the real kernel would generate them and
// are themselves routed back, so asymmetric failures behave realistically.

import { evaluate, evaluateNat, renderRule, type EvalResult, type PacketContext, type RejectType } from '../config/nft';
import { familyOf, inPrefix, normAddr, prefixLength } from '../net/addr';
import { inCidr, parseCidr, parseIp } from '../net/ip';
import { isLinkLocal6, multicastMac, networkOf6, solicitedNode } from '../net/ip6';
import type { ArpPacket, ConntrackEntry, Host, Interface, NatEntry, NatTuple, Packet, Route, World } from '../types';
import { kernelLog } from './journal';
import { linkPeer, switchPath } from './l2';
import { activeRecorder } from './trace';

export const LOOPBACK = 'lo';

export function nextId(world: World): number {
  world.counter += 1;
  return world.counter;
}

/** Addresses configured on up interfaces (IPv4 by default; family 6 = IPv6 incl. link-local; 0 = both). */
export function hostAddresses(host: Host, family: 0 | 4 | 6 = 4): string[] {
  const v4 = family === 6 ? [] : host.ifaces.filter((i) => i.up && i.address).map((i) => i.address!);
  const v6 = family === 4 ? [] : host.ifaces.filter((i) => i.up).flatMap((i) => (i.addrs6 ?? []).map((a) => a.address));
  return [...v4, ...v6];
}

export function isLocalAddress(host: Host, ip: string): boolean {
  if (ip.startsWith('127.') || ip === '::1') return true;
  return hostAddresses(host, ip.includes(':') ? 6 : 4).includes(normAddr(ip));
}

export function findHostByIp(world: World, ip: string): Host | undefined {
  return Object.values(world.hosts).find((h) => h.ifaces.some((i) => i.address === ip || i.addrs6?.some((a) => a.address === ip)));
}

/** Global (non-link-local) IPv6 addresses of a host. */
export function globalAddrs6(host: Host): string[] {
  return host.ifaces.filter((i) => i.up && i.name !== LOOPBACK).flatMap((i) => (i.addrs6 ?? []).filter((a) => a.scope === 'global').map((a) => a.address));
}

/** IPv6 routing table: connected prefixes (from addresses), fe80::/64 per interface, configured and RA routes. */
export function routeTable6(host: Host): Route[] {
  const out: Route[] = [];
  for (const i of host.ifaces) {
    if (!i.up || i.name === LOOPBACK) continue;
    for (const a of i.addrs6 ?? []) {
      if (a.scope !== 'global') continue;
      const dest = networkOf6(a.address, a.prefix);
      if (!out.some((r) => r.dest === dest && r.dev === i.name)) out.push({ dest, dev: i.name, proto: a.origin === 'ra' ? 'ra' : 'kernel', src: a.address });
    }
    if ((i.addrs6 ?? []).some((a) => a.scope === 'link')) out.push({ dest: 'fe80::/64', dev: i.name, proto: 'kernel' });
  }
  return [...out, ...(host.routes6 ?? [])];
}

/** Connected routes derived from interface addresses plus configured routes. */
export function routeTable(host: Host): Route[] {
  const connected: Route[] = host.ifaces
    // A /32 address gets no prefix route: it covers no other host.
    .filter((i) => i.up && i.address && i.prefix !== null && i.prefix < 32 && i.name !== LOOPBACK)
    .map((i) => {
      const c = parseCidr(`${i.address}/${i.prefix}`)!;
      return { dest: `${formatNet(c.network)}/${c.prefix}`, dev: i.name, proto: 'kernel' as const, src: i.address! };
    });
  return [...host.routes.filter((r) => r.dest === 'default'), ...connected, ...host.routes.filter((r) => r.dest !== 'default')];
}

function formatNet(n: number): string {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

export interface RouteDecision {
  route: Route;
  dev: string;
  nextHop: string;
  src: string;
}

export function lookupRoute(host: Host, dst: string, oif?: string): RouteDecision | null {
  if (dst.includes(':')) return lookupRoute6(host, dst, oif);
  let best: { r: Route; prefix: number } | null = null;
  for (const r of routeTable(host)) {
    const c = parseCidr(r.dest);
    if (!c || !inCidr(dst, c)) continue;
    const iface = host.ifaces.find((i) => i.name === r.dev);
    if (!iface || !iface.up) continue;
    if (!best || c.prefix > best.prefix) best = { r, prefix: c.prefix };
  }
  if (!best) return null;
  const iface = host.ifaces.find((i) => i.name === best!.r.dev)!;
  return { route: best.r, dev: best.r.dev, nextHop: best.r.via ?? dst, src: best.r.src ?? iface.address ?? '0.0.0.0' };
}

function lookupRoute6(host: Host, dst: string, oif?: string): RouteDecision | null {
  let best: { r: Route; prefix: number } | null = null;
  for (const r of routeTable6(host)) {
    if (oif && r.dev !== oif) continue;
    if (!inPrefix(dst, r.dest)) continue;
    const iface = host.ifaces.find((i) => i.name === r.dev);
    if (!iface || !iface.up) continue;
    const len = prefixLength(r.dest);
    if (!best || len > best.prefix) best = { r, prefix: len };
  }
  if (!best) return null;
  const iface = host.ifaces.find((i) => i.name === best!.r.dev)!;
  return { route: best.r, dev: best.r.dev, nextHop: best.r.via ?? dst, src: source6(iface, dst) };
}

/** RFC 6724 source selection, simplified: same scope, prefer a global address on the outgoing interface. */
function source6(iface: Interface, dst: string): string {
  const addrs = iface.addrs6 ?? [];
  if (isLinkLocal6(dst)) return addrs.find((a) => a.scope === 'link')?.address ?? '::';
  return addrs.find((a) => a.scope === 'global' && inPrefix(dst, networkOf6(a.address, a.prefix)))?.address
    ?? addrs.find((a) => a.scope === 'global')?.address ?? '::';
}

/** Source address the kernel would pick for a packet to `dst`. */
export function sourceAddress(host: Host, dst: string): string {
  if (isLocalAddress(host, dst)) return dst.startsWith('127.') ? '127.0.0.1' : normAddr(dst);
  return lookupRoute(host, dst)?.src ?? (dst.includes(':') ? '::' : '0.0.0.0');
}

// ---------------------------------------------------------------------------
// Connection tracking
// ---------------------------------------------------------------------------

function ports(p: Packet): [number, number] {
  if (p.tcp) return [p.tcp.sport, p.tcp.dport];
  if (p.udp) return [p.udp.sport, p.udp.dport];
  if (p.icmp && p.icmp.id !== undefined) return [p.icmp.id, p.icmp.id];
  return [0, 0];
}

function ctFind(host: Host, p: Packet): { entry: ConntrackEntry; reply: boolean } | null {
  const [sp, dp] = ports(p);
  for (const e of host.conntrack) {
    if (e.proto !== p.proto) continue;
    if (e.src === p.src && e.dst === p.dst && e.sport === sp && e.dport === dp) return { entry: e, reply: false };
    if (e.src === p.dst && e.dst === p.src && e.sport === dp && e.dport === sp) return { entry: e, reply: true };
  }
  return null;
}

/** IPv6 Neighbor Discovery / MLD messages are never tracked by conntrack ("ct state untracked"). */
export function isNdp(p: Packet): boolean {
  return p.proto === 'icmp' && familyOf(p.src || p.dst) === 6 && !!p.icmp && p.icmp.type >= 130 && p.icmp.type <= 137;
}

export function ctState(host: Host, p: Packet): PacketContext['ctState'] {
  if (isNdp(p)) return 'untracked';
  if (p.icmp?.quoted) {
    const q = p.icmp.quoted;
    const related = host.conntrack.some(
      (e) => e.proto === q.proto && ((e.src === q.src && e.dst === q.dst) || (e.src === q.dst && e.dst === q.src)),
    );
    return related ? 'related' : 'new';
  }
  const f = ctFind(host, p);
  if (!f) return 'new';
  if (f.reply || f.entry.state !== 'UNREPLIED') return 'established';
  return 'new';
}

function ctConfirm(host: Host, p: Packet, time: number): void {
  if (p.icmp?.quoted || isNdp(p)) return;
  const f = ctFind(host, p);
  const [sp, dp] = ports(p);
  if (!f) {
    host.conntrack.push({
      proto: p.proto, src: p.src, dst: p.dst, sport: sp, dport: dp,
      state: p.proto === 'tcp' ? 'UNREPLIED' : 'UNREPLIED', time,
    });
    if (host.conntrack.length > 200) host.conntrack.shift();
    return;
  }
  f.entry.time = time;
  if (f.reply) {
    if (p.tcp?.flags.includes('RST')) f.entry.state = 'CLOSE';
    else if (p.tcp?.flags.includes('FIN')) f.entry.state = 'FIN_WAIT';
    else f.entry.state = p.proto === 'tcp' ? 'ESTABLISHED' : 'ASSURED';
  } else if (p.tcp?.flags.includes('FIN') && f.entry.state === 'ESTABLISHED') f.entry.state = 'FIN_WAIT';
}

// ---------------------------------------------------------------------------
// Packet helpers
// ---------------------------------------------------------------------------

export function packetLength(p: Packet): number {
  const ih = familyOf(p.src) === 6 ? 40 : 20;
  if (p.tcp) return ih + (p.tcp.flags.includes('SYN') ? 40 : 32) + p.tcp.len;
  if (p.udp) return ih + 8 + p.udp.len;
  if (p.icmp) {
    if (ih === 40 && p.icmp.nd) return ih + (p.icmp.type === 134 ? 56 : p.icmp.type === 133 ? 16 : 32);
    return p.icmp.quoted ? ih + 36 : ih + 64;
  }
  return ih;
}

export const ICMP4_TYPE_NAMES: Record<number, string> = { 0: 'echo-reply', 3: 'destination-unreachable', 8: 'echo-request', 11: 'time-exceeded' };
export const ICMP6_TYPE_NAMES: Record<number, string> = {
  1: 'destination-unreachable', 2: 'packet-too-big', 3: 'time-exceeded', 4: 'parameter-problem', 128: 'echo-request', 129: 'echo-reply',
  133: 'nd-router-solicit', 134: 'nd-router-advert', 135: 'nd-neighbor-solicit', 136: 'nd-neighbor-advert', 137: 'nd-redirect',
};

/** Meaning of an ICMP/ICMPv6 message independent of the family's type numbers. */
export type IcmpMeaning = 'echo-request' | 'echo-reply' | 'net' | 'host' | 'port' | 'admin' | 'ttl' | 'other';
export function icmpMeaning(p: Packet): IcmpMeaning {
  const i = p.icmp;
  if (!i) return 'other';
  if (familyOf(p.src) === 6) {
    if (i.type === 128) return 'echo-request';
    if (i.type === 129) return 'echo-reply';
    if (i.type === 3) return 'ttl';
    if (i.type === 1) return i.code === 0 ? 'net' : i.code === 1 ? 'admin' : i.code === 4 ? 'port' : 'host';
    return 'other';
  }
  if (i.type === 8) return 'echo-request';
  if (i.type === 0) return 'echo-reply';
  if (i.type === 11) return 'ttl';
  if (i.type === 3) return i.code === 0 ? 'net' : i.code === 3 ? 'port' : i.code === 13 ? 'admin' : 'host';
  return 'other';
}

/** Echo request/reply header for either family. */
export function echoIcmp(v6: boolean, reply: boolean, id: number, seq: number): NonNullable<Packet['icmp']> {
  return v6
    ? { type: reply ? 129 : 128, code: 0, description: reply ? 'Echo (ping) reply' : 'Echo (ping) request', id, seq }
    : { type: reply ? 0 : 8, code: 0, description: reply ? 'Echo (ping) reply' : 'Echo (ping) request', id, seq };
}

function toContext(p: Packet, host: Host, iif?: string, oif?: string): PacketContext {
  const v6 = familyOf(p.src) === 6;
  const icmpTypes = v6 ? ICMP6_TYPE_NAMES : ICMP4_TYPE_NAMES;
  return {
    family: v6 ? 6 : 4,
    src: p.src,
    dst: p.dst,
    proto: p.proto,
    sport: p.tcp?.sport ?? p.udp?.sport,
    dport: p.tcp?.dport ?? p.udp?.dport,
    icmpType: p.icmp ? icmpTypes[p.icmp.type] : undefined,
    iif,
    oif,
    ctState: ctState(host, p),
    len: packetLength(p),
    tcpFlags: p.tcp?.flags.map((f) => f.toLowerCase()),
  };
}

function pushFrame(host: Host, f: Host['capture'][number]) {
  host.capture.push(f);
  if (host.capture.length > 400) host.capture.splice(0, host.capture.length - 400);
}

/**
 * Record a frame as seen on host:iface. A frame on a VLAN sub-interface is also
 * seen, tagged, on its parent NIC; and the switch port at the other end of the
 * cable sees it too (with the tag as it is on that cable).
 */
export function capture(world: World, host: Host, iface: Interface, dir: 'in' | 'out', srcMac: string, dstMac: string, ip?: Packet, arp?: ArpPacket) {
  const base = { time: world.clock, host: host.id, dir, srcMac, dstMac, ip: ip ? clonePacket(ip) : undefined, arp };
  pushFrame(host, { ...base, iface: iface.name });
  const tag = iface.vlan?.id;
  if (iface.vlan) pushFrame(host, { ...base, iface: iface.vlan.parent, vlan: tag });
  const peer = linkPeer(world, host.id, iface.vlan ? iface.vlan.parent : iface.name);
  const sw = peer ? world.hosts[peer.host] : undefined;
  if (peer && sw?.bridge) {
    pushFrame(sw, { ...base, host: sw.id, iface: peer.iface, dir: dir === 'out' ? 'in' : 'out', vlan: tag });
    // MAC learning: the bridge records which port (and VLAN) each source MAC arrived on.
    const vid = tag ?? sw.bridge.ports[peer.iface]?.pvid ?? 1;
    if (dir === 'out' && srcMac === iface.mac) {
      const fdb = (sw.bridge.fdb = sw.bridge.fdb ?? []);
      const k = fdb.findIndex((e) => e.mac === srcMac && e.vlan === vid);
      if (k >= 0) fdb.splice(k, 1);
      fdb.push({ mac: srcMac, port: peer.iface, vlan: vid });
    }
  }
}

export function clonePacket(p: Packet): Packet {
  return {
    ...p,
    tcp: p.tcp ? { ...p.tcp, flags: [...p.tcp.flags] } : undefined,
    udp: p.udp ? { ...p.udp } : undefined,
    icmp: p.icmp ? { ...p.icmp, quoted: p.icmp.quoted ? { ...p.icmp.quoted } : undefined } : undefined,
    app: p.app,
  };
}

function quote(p: Packet): NonNullable<Packet['icmp']>['quoted'] {
  return { proto: p.proto, src: p.src, dst: p.dst, sport: p.tcp?.sport ?? p.udp?.sport, dport: p.tcp?.dport ?? p.udp?.dport };
}

function firewallLog(world: World, host: Host, prefix: string, p: Packet, iif: string | undefined, oif: string | undefined) {
  const flags = p.tcp ? p.tcp.flags.join(' ') : '';
  const l4 = p.tcp
    ? `PROTO=TCP SPT=${p.tcp.sport} DPT=${p.tcp.dport} WINDOW=${p.tcp.window} RES=0x00 ${flags} URGP=0`
    : p.udp
      ? `PROTO=UDP SPT=${p.udp.sport} DPT=${p.udp.dport} LEN=${p.udp.len + 8}`
      : `PROTO=ICMP TYPE=${p.icmp?.type} CODE=${p.icmp?.code}`;
  kernelLog(world, host, `${prefix}IN=${iif ?? ''} OUT=${oif ?? ''} SRC=${p.src} DST=${p.dst} LEN=${packetLength(p)} TOS=0x00 PREC=0x00 TTL=${p.ttl} ID=${p.id & 0xffff} DF ${l4}`);
}

// ---------------------------------------------------------------------------
// NAT (nftables "type nat" chains on prerouting/postrouting)
// ---------------------------------------------------------------------------

function tupleOf(p: Packet): NatTuple {
  const [sport, dport] = ports(p);
  return { src: p.src, sport, dst: p.dst, dport };
}

function setPorts(p: Packet, sport: number, dport: number): void {
  if (p.tcp) { p.tcp.sport = sport; p.tcp.dport = dport; }
  else if (p.udp) { p.udp.sport = sport; p.udp.dport = dport; }
}

const sameTuple = (a: NatTuple, b: NatTuple) => a.src === b.src && a.sport === b.sport && a.dst === b.dst && a.dport === b.dport;
const replyOf = (t: NatTuple): NatTuple => ({ src: t.dst, sport: t.dport, dst: t.src, dport: t.sport });

interface NatState {
  entry?: NatEntry;
  dir?: 'orig' | 'reply';
  /** Original tuple of a new flow whose destination was translated in prerouting. */
  pendingDnat?: { orig: NatTuple; rule: string };
  notes: string[];
}

function hasNatChains(host: Host): boolean {
  return host.nft.tables.some((t) => t.chains.some((c) => c.base?.type === 'nat'));
}

function natLookup(host: Host, p: Packet): NatState {
  for (const e of host.nat) {
    if (e.proto !== p.proto) continue;
    const t = tupleOf(p);
    if (sameTuple(t, e.orig)) return { entry: e, dir: 'orig', notes: [] };
    if (sameTuple(t, replyOf(e.trans))) return { entry: e, dir: 'reply', notes: [] };
  }
  return { notes: [] };
}

/** Prerouting: reverse-translate replies, translate later packets of known flows, or DNAT a new flow. */
function natPrerouting(host: Host, p: Packet, iif: string): NatState {
  if (host.nat.length === 0 && !hasNatChains(host)) return { notes: [] };
  const st = natLookup(host, p);
  if (st.entry && st.dir === 'orig' && (st.entry.trans.dst !== p.dst || st.entry.trans.dport !== ports(p)[1])) {
    st.notes.push(`prerouting NAT (known flow): destination ${p.dst}:${ports(p)[1]} → ${st.entry.trans.dst}:${st.entry.trans.dport}`);
    p.dst = st.entry.trans.dst;
    setPorts(p, ports(p)[0], st.entry.trans.dport);
  } else if (st.entry && st.dir === 'reply' && (st.entry.orig.src !== p.dst || st.entry.orig.sport !== ports(p)[1])) {
    st.notes.push(`prerouting NAT (reply of a translated flow): destination ${p.dst}:${ports(p)[1]} → ${st.entry.orig.src}:${st.entry.orig.sport}`);
    p.dst = st.entry.orig.src;
    setPorts(p, ports(p)[0], st.entry.orig.sport);
  } else if (!st.entry && ctState(host, p) === 'new' && !p.icmp?.quoted) {
    const r = evaluateNat(host.nft, 'prerouting', toContext(p, host, iif));
    if (r && r.nat.kind === 'dnat') {
      const orig = tupleOf(p);
      p.dst = r.nat.addr;
      if (r.nat.port) setPorts(p, ports(p)[0], r.nat.port);
      st.pendingDnat = { orig, rule: renderRule({ ...r.rule, counter: null }) };
      st.notes.push(`prerouting NAT: rule "${st.pendingDnat.rule}" → destination ${orig.dst}:${orig.dport} rewritten to ${p.dst}:${ports(p)[1]}`);
    }
  }
  return st;
}

/** Postrouting: apply source translation and record new NAT flows. */
function natPostrouting(world: World, host: Host, p: Packet, st: NatState, oif: string, egressAddr: string | null): void {
  if (st.entry) {
    const want = st.dir === 'orig' ? { a: st.entry.trans.src, port: st.entry.trans.sport } : { a: st.entry.orig.dst, port: st.entry.orig.dport };
    if (want.a !== p.src || want.port !== ports(p)[0]) {
      st.notes.push(`postrouting NAT (${st.dir === 'orig' ? 'known flow' : 'reply'}): source ${p.src}:${ports(p)[0]} → ${want.a}:${want.port}`);
      p.src = want.a;
      setPorts(p, want.port, ports(p)[1]);
    }
    return;
  }
  if (!hasNatChains(host) || p.icmp?.quoted) return;
  if (!st.pendingDnat && ctState(host, p) !== 'new') return;
  const before = tupleOf(p);
  const r = evaluateNat(host.nft, 'postrouting', toContext(p, host, undefined, oif));
  let kind = st.pendingDnat ? 'dnat' : '';
  let rule = st.pendingDnat?.rule ?? '';
  if (r && (r.nat.kind === 'masquerade' || r.nat.kind === 'snat')) {
    const newSrc = r.nat.kind === 'masquerade' ? egressAddr ?? p.src : r.nat.addr;
    const newPort = r.nat.kind === 'snat' && r.nat.port ? r.nat.port : ports(p)[0];
    st.notes.push(`postrouting NAT: rule "${renderRule({ ...r.rule, counter: null })}" → source ${p.src}:${ports(p)[0]} rewritten to ${newSrc}:${newPort}`);
    p.src = newSrc;
    setPorts(p, newPort, ports(p)[1]);
    kind = kind ? `${kind}+${r.nat.kind}` : r.nat.kind;
    rule = rule ? `${rule}; ${renderRule({ ...r.rule, counter: null })}` : renderRule({ ...r.rule, counter: null });
  }
  if (!kind) return;
  const orig = st.pendingDnat?.orig ?? before;
  host.nat.push({ proto: p.proto, orig, trans: tupleOf(p), kind, rule, time: world.clock });
  if (host.nat.length > 200) host.nat.shift();
}

/** Human-readable firewall decision for hop notes ("nft inet filter input: rule 7 'tcp dport 22 accept'"). */
export function describeDecision(hook: string, fw: EvalResult): string {
  const d = fw.decidedBy;
  if (!d) return `${hook}: no nftables base chain on this hook (accepted)`;
  if (d.policy) return `nft ${d.table} ${d.chain}: no rule matched, chain policy ${fw.verdict}`;
  return `nft ${d.table} ${d.chain}: rule handle ${d.rule!.handle} "${renderRule({ ...d.rule!, counter: null })}" → ${fw.verdict}`;
}

// ---------------------------------------------------------------------------
// Transmission
// ---------------------------------------------------------------------------

export interface HopRecord {
  host: string;
  ingress?: string;
  egress?: string;
  srcMac?: string;
  dstMac?: string;
  ttl: number;
  note: string;
}

export type Delivery =
  | { status: 'delivered'; host: string; hops: HopRecord[]; error?: undefined; /** The packet as received (after any NAT on the path). */ final: Packet }
  | { status: 'dropped'; host: string; hops: HopRecord[]; reason: string; error?: IcmpErrorReturn }
  | { status: 'rejected'; host: string; hops: HopRecord[]; reason: string; rejectWith: RejectType; error?: IcmpErrorReturn; rst?: { packet: Packet; delivered: boolean } }
  | { status: 'local-error'; host: string; hops: HopRecord[]; errno: 'ENETUNREACH' | 'EHOSTUNREACH' | 'EPERM' | 'EMSGSIZE'; reason: string; error?: undefined; mtu?: number };

export interface IcmpErrorReturn {
  packet: Packet;
  from: string;
  /** True when the ICMP error made it back to the original sender. */
  delivered: boolean;
}

const ICMP_DESC: Record<string, { type: number; code: number; description: string }> = {
  'net-unreachable': { type: 3, code: 0, description: 'Destination unreachable (Network unreachable)' },
  'host-unreachable': { type: 3, code: 1, description: 'Destination unreachable (Host unreachable)' },
  'port-unreachable': { type: 3, code: 3, description: 'Destination unreachable (Port unreachable)' },
  'admin-prohibited': { type: 3, code: 13, description: 'Destination unreachable (Communication administratively filtered)' },
  'ttl-exceeded': { type: 11, code: 0, description: 'Time-to-live exceeded (Time to live exceeded in transit)' },
  'frag-needed': { type: 3, code: 4, description: 'Destination unreachable (Fragmentation needed)' },
};

const ICMP6_DESC: Record<string, { type: number; code: number; description: string }> = {
  'net-unreachable': { type: 1, code: 0, description: 'Destination unreachable (No route to destination)' },
  'host-unreachable': { type: 1, code: 3, description: 'Destination unreachable (Address unreachable)' },
  'port-unreachable': { type: 1, code: 4, description: 'Destination unreachable (Port unreachable)' },
  'admin-prohibited': { type: 1, code: 1, description: 'Destination unreachable (Communication with destination administratively prohibited)' },
  'ttl-exceeded': { type: 3, code: 0, description: 'Time exceeded (Hop limit exceeded in transit)' },
  'frag-needed': { type: 2, code: 0, description: 'Packet too big' },
};

const ICMP_EXPLAIN: Record<string, (h: string, p: Packet) => string> = {
  'net-unreachable': (h) => `${h} has no route to the destination network and reports it to the sender. A TCP client in SYN_SENT fails with ENETUNREACH ("Network is unreachable").`,
  'host-unreachable': (h, p) => p.dst.includes(':')
    ? `${h} tried to deliver the packet on the final link but nobody answered its Neighbor Solicitation for ${p.dst} (3 tries, 1 s apart), so it reports ICMPv6 "address unreachable". The sender sees "No route to host" (EHOSTUNREACH). Common causes: the host is down, the address is wrong, or the target's firewall drops ICMPv6 neighbor solicitations.`
    : `${h} tried to deliver the packet on the final network but nobody answered its ARP request for ${p.dst} (about 3 s of retries). The sender receives "No route to host" (EHOSTUNREACH), although routing itself works.`,
  'port-unreachable': (h, p) => `${h} received a ${p.proto.toUpperCase()} datagram for a port with no listening socket (or a firewall rejected it with port-unreachable). For UDP this is how "connection refused" is signalled; resolvers move to the next server immediately.`,
  'admin-prohibited': (h) => `A firewall rule on ${h} rejected the packet with "communication administratively prohibited" (type 3 code 13). Clients report "No route to host", which misleadingly suggests a routing problem.`,
  'ttl-exceeded': (h, p) => `The ${p.dst.includes(':') ? 'hop limit' : 'TTL'} reached zero at ${h}, which discards the packet and reports "time exceeded". traceroute uses this deliberately to discover each router on the path.`,
  'frag-needed': (h, p) => p.dst.includes(':')
    ? `The packet (${packetSize(p)} bytes) is larger than the MTU of ${h}'s next link. IPv6 routers never fragment, so ${h} drops it and sends ICMPv6 "Packet Too Big" with the link MTU. The sender lowers its path MTU and resends smaller packets. If a firewall drops this message, large transfers hang: a path MTU black hole.`
    : `The packet (${packetSize(p)} bytes) is larger than the MTU of ${h}'s next link and has the Don't Fragment bit set (TCP always sets it for path MTU discovery). ${h} drops it and sends ICMP "fragmentation needed" with the next-hop MTU. The sender lowers its path MTU and resends smaller segments. If a firewall drops this message, small packets work but large transfers hang: a path MTU black hole.`,
};


// ---------------------------------------------------------------------------
// MTU and path MTU discovery
// ---------------------------------------------------------------------------

export const DEFAULT_MTU = 1500;

export function ifaceMtu(i: Interface): number {
  return i.mtu ?? (i.name === LOOPBACK ? 65536 : DEFAULT_MTU);
}

/** Size of the IP packet in bytes (IP header + transport header + payload). */
export function packetSize(p: Packet): number {
  const ip = p.dst.includes(':') ? 40 : 20;
  if (p.tcp) return ip + (p.tcp.flags.includes('SYN') ? 40 : 32) + p.tcp.len;
  if (p.udp) return ip + 8 + p.udp.len;
  if (p.icmp) return ip + 8 + (p.icmp.quoted ? 28 : p.icmp.nd ? 24 : p.icmp.size ?? 56);
  return ip;
}

/** IPv4 packets may be fragmented by routers unless DF is set; TCP sets DF. IPv6 is never fragmented in transit. */
function dontFragment(p: Packet): boolean {
  return p.dst.includes(':') || (p.df ?? p.proto === 'tcp');
}

/** Is this an ICMP "fragmentation needed" / ICMPv6 "packet too big" error? */
export function isFragNeeded(p: Packet): boolean {
  const i = p.icmp;
  if (!i || i.mtu === undefined) return false;
  return p.src.includes(':') ? i.type === 2 : i.type === 3 && i.code === 4;
}

/** Path MTU towards `dst` as known to `host` (learned PMTU, else the egress interface MTU). */
export function pathMtu(host: Host, dst: string): number {
  const rd = lookupRoute(host, dst);
  const egress = rd ? host.ifaces.find((i) => i.name === rd.dev) : undefined;
  const link = egress ? ifaceMtu(egress) : DEFAULT_MTU;
  return Math.min(link, host.pmtu?.[dst] ?? Infinity);
}

/**
 * MTU checks for a packet leaving `host` on `egress` towards `peer`.
 * Returns null when it fits; otherwise what happens to it.
 */
function mtuCheck(p: Packet, egress: Interface, peer: Interface): { fits: false; size: number; mtu: number; where: 'egress' | 'peer'; df: boolean } | null {
  const size = packetSize(p);
  const out = ifaceMtu(egress);
  if (size > out) return { fits: false, size, mtu: out, where: 'egress', df: dontFragment(p) };
  // A frame larger than the receiving NIC's MTU is discarded by that NIC (no ICMP: it is a layer-2 drop).
  if (size > ifaceMtu(peer)) return { fits: false, size, mtu: ifaceMtu(peer), where: 'peer', df: dontFragment(p) };
  return null;
}

/** Send an ICMP error from `host` about `offending`. Errors are never sent about ICMP errors. */
export function sendIcmpError(world: World, host: Host, offending: Packet, kind: keyof typeof ICMP_DESC, mtu?: number): IcmpErrorReturn | undefined {
  if (offending.icmp?.quoted || isNdp(offending)) return undefined;
  const v6 = offending.src.includes(':');
  const route = lookupRoute(host, offending.src);
  const src = isLocalAddress(host, offending.dst) ? offending.dst : route?.src ?? hostAddresses(host, v6 ? 6 : 4)[0];
  const d = (v6 ? ICMP6_DESC : ICMP_DESC)[kind];
  const pkt: Packet = {
    id: nextId(world), src, dst: offending.src, ttl: 64, proto: 'icmp',
    icmp: { type: d.type, code: d.code, description: d.description, quoted: quote(offending), ...(mtu ? { mtu } : {}) },
  };
  const res = transmit(world, host.id, pkt);
  activeRecorder()?.describe(pkt.id, `${v6 ? 'ICMPv6' : 'ICMP'} ${d.description}`, ICMP_EXPLAIN[kind](host.hostname, offending));
  return { packet: pkt, from: host.id, delivered: res.status === 'delivered' };
}

type NeighborHit = { mac: string; host: Host; iface: Interface } | null;

/** Link-layer address resolution: ARP for IPv4, Neighbor Discovery for IPv6. */
export function resolveNeighbor(world: World, host: Host, iface: Interface, ip: string): NeighborHit {
  return ip.includes(':') ? resolveNdp(world, host, iface, ip) : resolveArp(world, host, iface, ip);
}

function linkPeers(world: World, iface: Interface, match: (i: Interface) => boolean): { host: Host; iface: Interface }[] {
  return Object.values(world.hosts).flatMap((h) =>
    h.ifaces.filter((i) => i !== iface && i.up && i.segment && i.segment === iface.segment && match(i)).map((i) => ({ host: h, iface: i })),
  );
}

/**
 * IPv6 Neighbor Discovery (RFC 4861 §7.2): a Neighbor Solicitation to the
 * target's solicited-node multicast group, answered by a unicast Neighbor
 * Advertisement. Both messages are ICMPv6, so unlike ARP they pass through the
 * nftables input chains (as "ct state untracked") and can be dropped by a
 * firewall that forgets ICMPv6.
 */
function resolveNdp(world: World, host: Host, iface: Interface, ip: string): NeighborHit {
  const cached = host.neighbors.find((n) => n.ip === ip && n.dev === iface.name && n.mac);
  const peers = linkPeers(world, iface, (i) => !!i.addrs6?.some((a) => a.address === ip));
  if (cached) {
    const peer = peers.find((p) => p.iface.mac === cached.mac);
    if (peer) return { mac: cached.mac!, ...peer };
    host.neighbors = host.neighbors.filter((n) => n !== cached);
  }
  const rec = activeRecorder();
  const srcAddr = (iface.addrs6 ?? []).find((a) => a.scope === 'link')?.address ?? '::';
  const group = solicitedNode(ip);
  const fail = () => {
    // The caller accounts for the ~3 s (3 solicitations, RetransTimer 1 s).
    const existing = host.neighbors.find((n) => n.ip === ip && n.dev === iface.name);
    if (existing) existing.state = 'FAILED';
    else host.neighbors.push({ ip, dev: iface.name, mac: null, state: 'FAILED' });
    return null;
  };
  const ns: Packet = {
    id: nextId(world), src: srcAddr, dst: group, ttl: 255, proto: 'icmp',
    icmp: { type: 135, code: 0, description: 'Neighbor Solicitation', nd: { target: ip, lladdr: iface.mac } },
  };
  const ev = rec?.beginPacket(world.clock, host.id, clonePacket(ns), true);
  capture(world, host, iface, 'out', iface.mac, multicastMac(group), ns);
  for (const o of linkPeers(world, iface, () => true)) capture(world, o.host, o.iface, 'in', iface.mac, multicastMac(group), ns);
  const peer = peers[0];
  const nsVerdict = peer ? evaluate(peer.host.nft, 'input', toContext(ns, peer.host, peer.iface.name)) : null;
  const nsOk = !!nsVerdict && nsVerdict.verdict === 'accept';
  if (rec && ev) {
    rec.endPacket(ev, peer?.host.id ?? host.id, [], [{ host: host.id, egress: iface.name, srcMac: iface.mac, dstMac: multicastMac(group), ttl: 255, note: `multicast to the solicited-node group ${group} (Ethernet ${multicastMac(group)}) on ${iface.segment}${peer ? `; ${peer.host.hostname} owns ${ip}; its input hook: ${describeDecision('input', nsVerdict!)}` : '; no host on this link has that address'}` }], nsOk, nsOk ? `received by ${peer!.host.id}` : peer ? `dropped by ${peer.host.hostname}'s firewall` : 'no answer');
    rec.describe(ns.id, `ICMPv6 Neighbor Solicitation: who has ${ip}?`, `IPv6 has no ARP. To learn the MAC address of ${ip}, ${host.hostname} sends an ICMPv6 Neighbor Solicitation to the solicited-node multicast group ${group} (derived from the last 24 bits of the target address), so only hosts whose address ends the same way process it. It carries the sender's MAC (source link-layer address option). Hop limit 255 proves it was not routed.`);
  }
  if (!peer || !nsOk) return fail();
  const na: Packet = {
    id: nextId(world), src: ip, dst: srcAddr, ttl: 255, proto: 'icmp',
    icmp: { type: 136, code: 0, description: 'Neighbor Advertisement', nd: { target: ip, lladdr: peer.iface.mac, flags: `${peer.host.ip6Forward ? 'router, ' : ''}solicited, override` } },
  };
  world.clock += 0.2;
  const naVerdict = evaluate(host.nft, 'input', toContext(na, host, iface.name));
  const ev2 = rec?.beginPacket(world.clock, peer.host.id, clonePacket(na), true);
  capture(world, peer.host, peer.iface, 'out', peer.iface.mac, iface.mac, na);
  capture(world, host, iface, 'in', peer.iface.mac, iface.mac, na);
  const naOk = naVerdict.verdict === 'accept';
  if (rec && ev2) {
    rec.endPacket(ev2, host.id, [], [{ host: peer.host.id, egress: peer.iface.name, srcMac: peer.iface.mac, dstMac: iface.mac, ttl: 255, note: `unicast reply; ${host.hostname} input hook: ${describeDecision('input', naVerdict)}` }], naOk, naOk ? `delivered to ${host.id}` : `dropped by ${host.hostname}'s firewall`);
    rec.describe(na.id, `ICMPv6 Neighbor Advertisement: ${ip} is at ${peer.iface.mac}`, `${peer.host.hostname} answers with its MAC address in the target link-layer address option. Flags: S (solicited: answer to a solicitation)${peer.host.ip6Forward ? ', R (the sender is a router)' : ''}, O (override cached entries). It also created a neighbour entry for ${host.hostname} from the solicitation.`);
  }
  // The target learns the solicitor from the source link-layer address option (STALE entry).
  peer.host.neighbors = peer.host.neighbors.filter((n) => !(n.ip === srcAddr && n.dev === peer.iface.name));
  peer.host.neighbors.push({ ip: srcAddr, dev: peer.iface.name, mac: iface.mac, state: 'STALE' });
  if (!naOk) return fail();
  host.neighbors = host.neighbors.filter((n) => !(n.ip === ip && n.dev === iface.name));
  host.neighbors.push({ ip, dev: iface.name, mac: peer.iface.mac, state: 'REACHABLE' });
  return { mac: peer.iface.mac, ...peer };
}

function resolveArp(world: World, host: Host, iface: Interface, ip: string): NeighborHit {
  const cached = host.neighbors.find((n) => n.ip === ip && n.dev === iface.name && n.mac);
  const peers = Object.values(world.hosts).flatMap((h) =>
    h.ifaces.filter((i) => i.up && i.segment && i.segment === iface.segment && i.address === ip).map((i) => ({ host: h, iface: i })),
  );
  if (cached) {
    const peer = peers.find((p) => p.iface.mac === cached.mac);
    if (peer) return { mac: cached.mac!, ...peer };
    // stale cache entry: fall through and re-ARP
    host.neighbors = host.neighbors.filter((n) => n !== cached);
  }
  // ARP request (broadcast): every host on the segment sees it.
  const req: ArpPacket = { op: 'request', senderIp: iface.address ?? '0.0.0.0', senderMac: iface.mac, targetIp: ip, targetMac: '00:00:00:00:00:00' };
  capture(world, host, iface, 'out', iface.mac, 'ff:ff:ff:ff:ff:ff', undefined, req);
  const rec = activeRecorder();
  for (const h of Object.values(world.hosts)) {
    for (const i of h.ifaces) if (h !== host && i.up && i.segment === iface.segment) capture(world, h, i, 'in', iface.mac, 'ff:ff:ff:ff:ff:ff', undefined, req);
  }
  const peer = peers[0];
  const segHosts = Object.values(world.hosts).filter((h) => h !== host && h.ifaces.some((i) => i.up && i.segment === iface.segment));
  rec?.arp(world.clock, host.id, peer?.host.id ?? segHosts[0]?.id ?? host.id, req);
  if (!peer) {
    const existing = host.neighbors.find((n) => n.ip === ip && n.dev === iface.name);
    if (existing) existing.state = 'FAILED';
    else host.neighbors.push({ ip, dev: iface.name, mac: null, state: 'FAILED' });
    return null;
  }
  const rep: ArpPacket = { op: 'reply', senderIp: ip, senderMac: peer.iface.mac, targetIp: req.senderIp, targetMac: iface.mac };
  capture(world, peer.host, peer.iface, 'out', peer.iface.mac, iface.mac, undefined, rep);
  capture(world, host, iface, 'in', peer.iface.mac, iface.mac, undefined, rep);
  rec?.arp(world.clock, peer.host.id, host.id, rep);
  host.neighbors = host.neighbors.filter((n) => !(n.ip === ip && n.dev === iface.name));
  host.neighbors.push({ ip, dev: iface.name, mac: peer.iface.mac, state: 'REACHABLE' });
  // The target learns the requester from the request (RFC 826 merge).
  if (iface.address) {
    peer.host.neighbors = peer.host.neighbors.filter((n) => !(n.ip === iface.address && n.dev === peer.iface.name));
    peer.host.neighbors.push({ ip: iface.address, dev: peer.iface.name, mac: iface.mac, state: 'REACHABLE' });
  }
  return { mac: peer.iface.mac, ...peer };
}

function handleReject(world: World, host: Host, p: Packet, how: RejectType): { error?: IcmpErrorReturn; rst?: { packet: Packet; delivered: boolean } } {
  let kind = how;
  if (kind === 'default') kind = p.proto === 'tcp' ? 'tcp-reset' : 'port-unreachable';
  if (kind === 'tcp-reset' && p.tcp) {
    const rst = makeRst(world, p);
    const r = transmit(world, host.id, rst, { bypassOutputFilter: true });
    return { rst: { packet: rst, delivered: r.status === 'delivered' } };
  }
  return { error: sendIcmpError(world, host, p, kind === 'tcp-reset' ? 'port-unreachable' : kind) };
}

export function makeRst(world: World, p: Packet): Packet {
  const t = p.tcp!;
  return {
    id: nextId(world), src: p.dst, dst: p.src, ttl: 64, proto: 'tcp',
    tcp: { sport: t.dport, dport: t.sport, seq: 0, ack: (t.seq + (t.flags.includes('SYN') ? 1 : t.len)) >>> 0, flags: ['RST', 'ACK'], window: 0, len: 0 },
  };
}

export interface TransmitOptions {
  /** Skip the originating host's output chain (used for kernel-generated RSTs). */
  bypassOutputFilter?: boolean;
  /**
   * A packet (LPF) socket on these interfaces of this host receives the packet before netfilter
   * (dhcpd, dhclient and dhcrelay read DHCP this way), so the input chain cannot drop it.
   */
  rawSocket?: { host: string; ifaces: string[] };
}

/**
 * Deliver an IP packet from `fromHostId`. The packet is copied at every hop, so
 * the caller's object keeps its original TTL.
 */
export function transmit(world: World, fromHostId: string, original: Packet, opts: TransmitOptions = {}): Delivery {
  const rec = activeRecorder();
  const ev = rec?.beginPacket(world.clock, fromHostId, clonePacket(original));
  const d = transmitInner(world, fromHostId, original, opts);
  if (rec && ev) {
    const via = d.hops.map((h) => h.host).filter((h, i, a) => h !== fromHostId && h !== d.host && a.indexOf(h) === i);
    const outcome =
      d.status === 'delivered' ? `delivered to ${d.host}`
      : d.status === 'local-error' ? `not sent: ${d.errno} (${d.reason})`
      : `${d.status} at ${d.host}: ${d.reason}`;
    rec.endPacket(ev, d.host, via, d.hops, d.status === 'delivered', outcome);
  }
  return d;
}

function transmitInner(world: World, fromHostId: string, original: Packet, opts: TransmitOptions): Delivery {
  const hops: HopRecord[] = [];
  let p = clonePacket(original);
  let host = world.hosts[fromHostId];
  let ingress: Interface | null = null;

  for (let guard = 0; guard < 40; guard++) {
    world.clock += 0.2;
    if (ingress) {
      // ---- Arrived at `host` via `ingress` -------------------------------------
      const nat = natPrerouting(host, p, ingress.name);
      if (isLocalAddress(host, p.dst)) {
        const fw = evaluate(host.nft, 'input', toContext(p, host, ingress.name));
        fw.logs.forEach((pre) => firewallLog(world, host, pre, p, ingress!.name, undefined));
        const raw = opts.rawSocket?.host === host.id && opts.rawSocket.ifaces.includes(ingress.name);
        if (raw && fw.verdict !== 'accept') {
          hops.push({ host: host.id, ingress: ingress.name, ttl: p.ttl, note: `${nat.notes.map((n) => n + '; ').join('')}input hook: ${describeDecision('input', fw)}, but a packet socket (LPF) on ${ingress.name} already received a copy before netfilter: delivered to the application` });
          return { status: 'delivered', host: host.id, hops, final: clonePacket(p) };
        }
        if (fw.verdict === 'accept') {
          ctConfirm(host, p, world.clock);
          if (isFragNeeded(p) && p.icmp!.quoted) {
            // The kernel records the smaller path MTU for that destination (route exception, ~10 min).
            host.pmtu = { ...(host.pmtu ?? {}), [p.icmp!.quoted.dst]: p.icmp!.mtu! };
          }
          hops.push({ host: host.id, ingress: ingress.name, ttl: p.ttl, note: `${nat.notes.map((n) => n + '; ').join('')}input hook: ${describeDecision('input', fw)}; delivered to the local socket layer` });
          return { status: 'delivered', host: host.id, hops, final: clonePacket(p) };
        }
        const why = describeDecision('input', fw);
        hops.push({ host: host.id, ingress: ingress.name, ttl: p.ttl, note: `${nat.notes.map((n) => n + '; ').join('')}${why}` });
        if (fw.verdict === 'drop') return { status: 'dropped', host: host.id, hops, reason: why };
        const r = handleReject(world, host, p, fw.rejectWith!);
        return { status: 'rejected', host: host.id, hops, reason: why, rejectWith: fw.rejectWith!, ...r };
      }
      if (p.dst.includes(':') && !host.ip6Forward) {
        // IPv6 (ip6_input): a packet not addressed to a non-router is silently discarded.
        hops.push({ host: host.id, ingress: ingress.name, ttl: p.ttl, note: 'not addressed to this host and IPv6 forwarding is disabled (net.ipv6.conf.all.forwarding=0): silently discarded' });
        return { status: 'dropped', host: host.id, hops, reason: 'IPv6 forwarding disabled' };
      }
      if (!p.dst.includes(':') && !host.ipForward) {
        // Linux: the input route lookup fails with EHOSTUNREACH and ip_error() answers ICMP host unreachable.
        hops.push({ host: host.id, ingress: ingress.name, ttl: p.ttl, note: 'not addressed to this host and IP forwarding is disabled (net.ipv4.ip_forward=0): not routed' });
        const error = sendIcmpError(world, host, p, 'host-unreachable');
        return { status: 'dropped', host: host.id, hops, reason: 'ip_forward=0', error };
      }
      if (p.ttl <= 1) {
        hops.push({ host: host.id, ingress: ingress.name, ttl: p.ttl, note: p.dst.includes(':') ? 'hop limit expired in transit' : 'TTL expired in transit' });
        const error = sendIcmpError(world, host, p, 'ttl-exceeded');
        return { status: 'dropped', host: host.id, hops, reason: 'TTL exceeded', error };
      }
      p.ttl -= 1;
      const rd = lookupRoute(host, p.dst);
      if (!rd) {
        hops.push({ host: host.id, ingress: ingress.name, ttl: p.ttl, note: 'no route to destination' });
        const error = sendIcmpError(world, host, p, 'net-unreachable');
        return { status: 'dropped', host: host.id, hops, reason: 'no route', error };
      }
      const fctx = toContext(p, host, ingress.name, rd.dev);
      const fw = evaluate(host.nft, 'forward', fctx);
      fw.logs.forEach((pre) => firewallLog(world, host, pre, p, ingress!.name, rd.dev));
      if (fw.verdict !== 'accept') {
        const why = describeDecision('forward', fw);
        hops.push({ host: host.id, ingress: ingress.name, ttl: p.ttl, note: `${nat.notes.map((n) => n + '; ').join('')}${why}` });
        if (fw.verdict === 'drop') return { status: 'dropped', host: host.id, hops, reason: why };
        const r = handleReject(world, host, p, fw.rejectWith!);
        return { status: 'rejected', host: host.id, hops, reason: why, rejectWith: fw.rejectWith!, ...r };
      }
      ctConfirm(host, p, world.clock);
      const egress = host.ifaces.find((i) => i.name === rd.dev)!;
      let clampNote = '';
      if (fctx.setMss !== undefined && p.tcp?.flags.includes('SYN')) {
        // MSS clamping: lower the MSS option in SYNs crossing this router so neither end sends segments too big for the path.
        const limit = fctx.setMss === 'rt mtu' ? ifaceMtu(egress) - (p.dst.includes(':') ? 60 : 40) : fctx.setMss;
        const cur = Number(/MSS=(\d+)/.exec(p.tcp.options ?? '')?.[1] ?? 1460);
        if (cur > limit) {
          p.tcp = { ...p.tcp, options: (p.tcp.options ?? '').replace(/MSS=\d+/, `MSS=${limit}`) };
          clampNote = `; MSS option clamped ${cur}→${limit} (tcp option maxseg size set ${fctx.setMss})`;
        }
      }
      const nh = resolveNeighbor(world, host, egress, rd.nextHop);
      if (!nh) {
        world.clock += 3000; // ARP / ND resolution gives up after ~3 s (3 probes, 1 s apart)
        hops.push({ host: host.id, ingress: ingress.name, egress: egress.name, ttl: p.ttl, note: `${rd.nextHop.includes(':') ? 'Neighbor Discovery' : 'ARP'} for ${rd.nextHop} on ${egress.name} failed` });
        const error = sendIcmpError(world, host, p, 'host-unreachable');
        return { status: 'dropped', host: host.id, hops, reason: `no ${rd.nextHop.includes(':') ? 'neighbor advertisement' : 'ARP reply'} from ${rd.nextHop}`, error };
      }
      const big = mtuCheck(p, egress, nh.iface);
      if (big && big.where === 'egress' && big.df) {
        hops.push({ host: host.id, ingress: ingress.name, egress: egress.name, ttl: p.ttl, note: `packet of ${big.size} bytes exceeds the MTU ${big.mtu} of ${egress.name} and ${p.dst.includes(':') ? 'IPv6 is never fragmented by routers' : 'has DF (Don\'t Fragment) set'}: dropped, ICMP ${p.dst.includes(':') ? 'packet too big' : 'fragmentation needed'} (mtu ${big.mtu}) sent back` });
        const error = sendIcmpError(world, host, { ...p, ttl: p.ttl + 1 }, 'frag-needed', big.mtu);
        return { status: 'dropped', host: host.id, hops, reason: `packet too big for ${egress.name} (mtu ${big.mtu})`, error };
      }
      if (big && big.where === 'peer') {
        hops.push({ host: host.id, ingress: ingress.name, egress: egress.name, ttl: p.ttl, note: `frame of ${big.size} bytes is larger than the MTU (${big.mtu}) of ${nh.host.hostname} ${nh.iface.name}: the receiving NIC discards it (no ICMP error: a layer-2 drop)` });
        return { status: 'dropped', host: nh.host.id, hops, reason: `frame larger than ${nh.host.hostname} ${nh.iface.name} MTU ${big.mtu}` };
      }
      natPostrouting(world, host, p, nat, egress.name, egress.address);
      const sw = switchPath(world, host, egress, nh.host, nh.iface);
      hops.push({ host: host.id, ingress: ingress.name, egress: egress.name, srcMac: egress.mac, dstMac: nh.mac, ttl: p.ttl, note: `TTL ${p.ttl + 1}→${p.ttl}; forward hook: ${describeDecision('forward', fw)}; routed via ${rd.route.dest}${rd.route.via ? ' via ' + rd.route.via : ''} dev ${egress.name}${nat.notes.length ? '; ' + nat.notes.join('; ') : ''}${clampNote}${sw ? '; ' + sw : ''}${big ? `; fragmented into ${Math.ceil((big.size - 20) / (big.mtu - 20))} fragments for the ${big.mtu}-byte MTU of ${egress.name}` : ''}` });
      capture(world, host, egress, 'out', egress.mac, nh.mac, p);
      capture(world, nh.host, nh.iface, 'in', egress.mac, nh.mac, p);
      host = nh.host;
      ingress = nh.iface;
      continue;
    }

    // ---- Originating host ------------------------------------------------------
    if (isLocalAddress(host, p.dst)) {
      const lo = host.ifaces.find((i) => i.name === LOOPBACK)!;
      const out = opts.bypassOutputFilter ? { verdict: 'accept' as const } : evaluate(host.nft, 'output', toContext(p, host, undefined, LOOPBACK));
      if (out.verdict !== 'accept') return { status: 'local-error', host: host.id, hops, errno: 'EPERM', reason: 'blocked by nft output chain' };
      ctConfirm(host, p, world.clock);
      capture(world, host, lo, 'out', '00:00:00:00:00:00', '00:00:00:00:00:00', p);
      hops.push({ host: host.id, egress: LOOPBACK, ttl: p.ttl, note: 'local destination: looped back via lo' });
      ingress = lo;
      continue;
    }
    const rd = lookupRoute(host, p.dst);
    if (!rd) {
      hops.push({ host: host.id, ttl: p.ttl, note: `no route to ${p.dst} in the routing table` });
      return { status: 'local-error', host: host.id, hops, errno: 'ENETUNREACH', reason: 'no matching route' };
    }
    if (p.dst.includes(':') ? !p.src || p.src === '::' : !parseIp(p.src) || p.src === '0.0.0.0') p.src = rd.src;
    if (!opts.bypassOutputFilter) {
      const out = evaluate(host.nft, 'output', toContext(p, host, undefined, rd.dev));
      out.logs.forEach((pre) => firewallLog(world, host, pre, p, undefined, rd.dev));
      if (out.verdict !== 'accept') {
        hops.push({ host: host.id, ttl: p.ttl, note: 'blocked by local nft output chain' });
        return { status: 'local-error', host: host.id, hops, errno: 'EPERM', reason: 'blocked by nft output chain' };
      }
    }
    ctConfirm(host, p, world.clock);
    const egress = host.ifaces.find((i) => i.name === rd.dev)!;
    const nh = resolveNeighbor(world, host, egress, rd.nextHop);
    if (!nh) {
      world.clock += 3000;
      hops.push({ host: host.id, egress: egress.name, ttl: p.ttl, note: `${rd.nextHop.includes(':') ? 'Neighbor Discovery' : 'ARP'} for next hop ${rd.nextHop} failed (no answer on ${egress.name})` });
      return { status: 'local-error', host: host.id, hops, errno: 'EHOSTUNREACH', reason: `no ${rd.nextHop.includes(':') ? 'neighbor advertisement' : 'ARP reply'} from ${rd.nextHop}` };
    }
    const big = mtuCheck(p, egress, nh.iface);
    const learned = host.pmtu?.[p.dst];
    if ((big && big.where === 'egress' && big.df) || (learned !== undefined && dontFragment(p) && packetSize(p) > learned)) {
      const mtu = big?.where === 'egress' ? big.mtu : learned!;
      hops.push({ host: host.id, egress: egress.name, ttl: p.ttl, note: `packet of ${packetSize(p)} bytes is larger than the ${big?.where === 'egress' ? `MTU of ${egress.name}` : 'learned path MTU'} (${mtu}) and may not be fragmented` });
      return { status: 'local-error', host: host.id, hops, errno: 'EMSGSIZE', reason: `message too long, mtu=${mtu}`, mtu };
    }
    if (big && big.where === 'peer') {
      hops.push({ host: host.id, egress: egress.name, ttl: p.ttl, note: `frame of ${big.size} bytes is larger than the MTU (${big.mtu}) of ${nh.host.hostname} ${nh.iface.name}: the receiving NIC discards it (no ICMP error: a layer-2 drop)` });
      capture(world, host, egress, 'out', egress.mac, nh.mac, p);
      return { status: 'dropped', host: nh.host.id, hops, reason: `frame larger than ${nh.host.hostname} ${nh.iface.name} MTU ${big.mtu}` };
    }
    const onat = natLookup(host, p);
    natPostrouting(world, host, p, onat, egress.name, egress.address);
    const sw = switchPath(world, host, egress, nh.host, nh.iface);
    hops.push({ host: host.id, egress: egress.name, srcMac: egress.mac, dstMac: nh.mac, ttl: p.ttl, note: `route ${rd.route.dest}${rd.route.via ? ' via ' + rd.route.via : ''} dev ${egress.name}${onat.notes.length ? '; ' + onat.notes.join('; ') : ''}${sw ? '; ' + sw : ''}${big ? `; fragmented into ${Math.ceil((big.size - 20) / (big.mtu - 20))} fragments for the ${big.mtu}-byte MTU` : ''}` });
    capture(world, host, egress, 'out', egress.mac, nh.mac, p);
    capture(world, nh.host, nh.iface, 'in', egress.mac, nh.mac, p);
    host = nh.host;
    ingress = nh.iface;
  }
  return { status: 'dropped', host: host.id, hops, reason: 'routing loop' };
}
