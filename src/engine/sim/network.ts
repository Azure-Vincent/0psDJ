// Hop-by-hop IPv4 forwarding model.
//
// For every packet the simulator performs, on each host it reaches:
//   ingress capture -> local delivery (nft input) | forwarding (TTL, route, nft forward)
//   -> route lookup (longest prefix) -> nft output (originating host only)
//   -> ARP resolution on the egress segment -> egress capture -> next host
// ICMP errors (host/net unreachable, time exceeded, port unreachable,
// admin-prohibited) are generated where the real kernel would generate them and
// are themselves routed back, so asymmetric failures behave realistically.

import { evaluate, renderRule, type EvalResult, type PacketContext, type RejectType } from '../config/nft';
import { inCidr, parseCidr, parseIp } from '../net/ip';
import type { ArpPacket, ConntrackEntry, Host, Interface, Packet, Route, World } from '../types';
import { kernelLog } from './journal';
import { activeRecorder } from './trace';

export const LOOPBACK = 'lo';

export function nextId(world: World): number {
  world.counter += 1;
  return world.counter;
}

export function hostAddresses(host: Host): string[] {
  return host.ifaces.filter((i) => i.up && i.address).map((i) => i.address!);
}

export function isLocalAddress(host: Host, ip: string): boolean {
  if (ip.startsWith('127.')) return true;
  return hostAddresses(host).includes(ip);
}

export function findHostByIp(world: World, ip: string): Host | undefined {
  return Object.values(world.hosts).find((h) => h.ifaces.some((i) => i.address === ip));
}

/** Connected routes derived from interface addresses plus configured routes. */
export function routeTable(host: Host): Route[] {
  const connected: Route[] = host.ifaces
    .filter((i) => i.up && i.address && i.prefix !== null && i.name !== LOOPBACK)
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

export function lookupRoute(host: Host, dst: string): RouteDecision | null {
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

/** Source address the kernel would pick for a packet to `dst`. */
export function sourceAddress(host: Host, dst: string): string {
  if (isLocalAddress(host, dst)) return dst.startsWith('127.') ? '127.0.0.1' : dst;
  return lookupRoute(host, dst)?.src ?? '0.0.0.0';
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

export function ctState(host: Host, p: Packet): PacketContext['ctState'] {
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
  if (p.icmp?.quoted) return;
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
  if (p.tcp) return 20 + (p.tcp.flags.includes('SYN') ? 40 : 32) + p.tcp.len;
  if (p.udp) return 28 + p.udp.len;
  if (p.icmp) return p.icmp.quoted ? 56 : 84;
  return 20;
}

function toContext(p: Packet, host: Host, iif?: string, oif?: string): PacketContext {
  const icmpTypes: Record<number, string> = { 0: 'echo-reply', 3: 'destination-unreachable', 8: 'echo-request', 11: 'time-exceeded' };
  return {
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
  };
}

function capture(world: World, host: Host, iface: Interface, dir: 'in' | 'out', srcMac: string, dstMac: string, ip?: Packet, arp?: ArpPacket) {
  host.capture.push({ time: world.clock, host: host.id, iface: iface.name, dir, srcMac, dstMac, ip: ip ? clonePacket(ip) : undefined, arp });
  if (host.capture.length > 400) host.capture.splice(0, host.capture.length - 400);
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
  | { status: 'delivered'; host: string; hops: HopRecord[]; error?: undefined }
  | { status: 'dropped'; host: string; hops: HopRecord[]; reason: string; error?: IcmpErrorReturn }
  | { status: 'rejected'; host: string; hops: HopRecord[]; reason: string; rejectWith: RejectType; error?: IcmpErrorReturn; rst?: { packet: Packet; delivered: boolean } }
  | { status: 'local-error'; host: string; hops: HopRecord[]; errno: 'ENETUNREACH' | 'EHOSTUNREACH' | 'EPERM'; reason: string; error?: undefined };

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
};

const ICMP_EXPLAIN: Record<string, (h: string, p: Packet) => string> = {
  'net-unreachable': (h) => `${h} has no route to the destination network and reports it to the sender. A TCP client in SYN_SENT fails with ENETUNREACH ("Network is unreachable").`,
  'host-unreachable': (h, p) => `${h} tried to deliver the packet on the final network but nobody answered its ARP request for ${p.dst} (about 3 s of retries). The sender receives "No route to host" (EHOSTUNREACH), although routing itself works.`,
  'port-unreachable': (h, p) => `${h} received a ${p.proto.toUpperCase()} datagram for a port with no listening socket (or a firewall rejected it with port-unreachable). For UDP this is how "connection refused" is signalled; resolvers move to the next server immediately.`,
  'admin-prohibited': (h) => `A firewall rule on ${h} rejected the packet with "communication administratively prohibited" (type 3 code 13). Clients report "No route to host", which misleadingly suggests a routing problem.`,
  'ttl-exceeded': (h) => `The TTL reached zero at ${h}, which discards the packet and reports "time exceeded". traceroute uses this deliberately to discover each router on the path.`,
};

/** Send an ICMP error from `host` about `offending`. Errors are never sent about ICMP errors. */
export function sendIcmpError(world: World, host: Host, offending: Packet, kind: keyof typeof ICMP_DESC): IcmpErrorReturn | undefined {
  if (offending.icmp?.quoted) return undefined;
  const route = lookupRoute(host, offending.src);
  const src = isLocalAddress(host, offending.dst) ? offending.dst : route?.src ?? hostAddresses(host)[0];
  const d = ICMP_DESC[kind];
  const pkt: Packet = {
    id: nextId(world), src, dst: offending.src, ttl: 64, proto: 'icmp',
    icmp: { type: d.type, code: d.code, description: d.description, quoted: quote(offending) },
  };
  const res = transmit(world, host.id, pkt);
  activeRecorder()?.describe(pkt.id, `ICMP ${d.description}`, ICMP_EXPLAIN[kind](host.hostname, offending));
  return { packet: pkt, from: host.id, delivered: res.status === 'delivered' };
}

function resolveArp(world: World, host: Host, iface: Interface, ip: string): { mac: string; host: Host; iface: Interface } | null {
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
      if (isLocalAddress(host, p.dst)) {
        const fw = evaluate(host.nft, 'input', toContext(p, host, ingress.name));
        fw.logs.forEach((pre) => firewallLog(world, host, pre, p, ingress!.name, undefined));
        if (fw.verdict === 'accept') {
          ctConfirm(host, p, world.clock);
          hops.push({ host: host.id, ingress: ingress.name, ttl: p.ttl, note: `input hook: ${describeDecision('input', fw)}; delivered to the local socket layer` });
          return { status: 'delivered', host: host.id, hops };
        }
        const why = describeDecision('input', fw);
        hops.push({ host: host.id, ingress: ingress.name, ttl: p.ttl, note: why });
        if (fw.verdict === 'drop') return { status: 'dropped', host: host.id, hops, reason: why };
        const r = handleReject(world, host, p, fw.rejectWith!);
        return { status: 'rejected', host: host.id, hops, reason: why, rejectWith: fw.rejectWith!, ...r };
      }
      if (!host.ipForward) {
        hops.push({ host: host.id, ingress: ingress.name, ttl: p.ttl, note: 'not addressed to this host and IP forwarding is disabled: discarded' });
        return { status: 'dropped', host: host.id, hops, reason: 'ip_forward=0' };
      }
      if (p.ttl <= 1) {
        hops.push({ host: host.id, ingress: ingress.name, ttl: p.ttl, note: 'TTL expired in transit' });
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
      const fw = evaluate(host.nft, 'forward', toContext(p, host, ingress.name, rd.dev));
      fw.logs.forEach((pre) => firewallLog(world, host, pre, p, ingress!.name, rd.dev));
      if (fw.verdict !== 'accept') {
        const why = describeDecision('forward', fw);
        hops.push({ host: host.id, ingress: ingress.name, ttl: p.ttl, note: why });
        if (fw.verdict === 'drop') return { status: 'dropped', host: host.id, hops, reason: why };
        const r = handleReject(world, host, p, fw.rejectWith!);
        return { status: 'rejected', host: host.id, hops, reason: why, rejectWith: fw.rejectWith!, ...r };
      }
      ctConfirm(host, p, world.clock);
      const egress = host.ifaces.find((i) => i.name === rd.dev)!;
      const nh = resolveArp(world, host, egress, rd.nextHop);
      if (!nh) {
        world.clock += 3000; // ARP resolution gives up after ~3 s (3 probes, 1 s apart)
        hops.push({ host: host.id, ingress: ingress.name, egress: egress.name, ttl: p.ttl, note: `ARP for ${rd.nextHop} on ${egress.name} failed` });
        const error = sendIcmpError(world, host, p, 'host-unreachable');
        return { status: 'dropped', host: host.id, hops, reason: `no ARP reply from ${rd.nextHop}`, error };
      }
      hops.push({ host: host.id, ingress: ingress.name, egress: egress.name, srcMac: egress.mac, dstMac: nh.mac, ttl: p.ttl, note: `TTL ${p.ttl + 1}→${p.ttl}; forward hook: ${describeDecision('forward', fw)}; routed via ${rd.route.dest}${rd.route.via ? ' via ' + rd.route.via : ''} dev ${egress.name}` });
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
    if (!parseIp(p.src) || p.src === '0.0.0.0') p.src = rd.src;
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
    const nh = resolveArp(world, host, egress, rd.nextHop);
    if (!nh) {
      world.clock += 3000;
      hops.push({ host: host.id, egress: egress.name, ttl: p.ttl, note: `ARP for next hop ${rd.nextHop} failed (no host answered on ${egress.name})` });
      return { status: 'local-error', host: host.id, hops, errno: 'EHOSTUNREACH', reason: `no ARP reply from ${rd.nextHop}` };
    }
    hops.push({ host: host.id, egress: egress.name, srcMac: egress.mac, dstMac: nh.mac, ttl: p.ttl, note: `route ${rd.route.dest}${rd.route.via ? ' via ' + rd.route.via : ''} dev ${egress.name}` });
    capture(world, host, egress, 'out', egress.mac, nh.mac, p);
    capture(world, nh.host, nh.iface, 'in', egress.mac, nh.mac, p);
    host = nh.host;
    ingress = nh.iface;
  }
  return { status: 'dropped', host: host.id, hops, reason: 'routing loop' };
}
