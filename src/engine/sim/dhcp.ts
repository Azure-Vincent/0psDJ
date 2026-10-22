// DHCP (RFC 2131) between dhclient and ISC dhcpd, directly on one Ethernet
// segment or through a relay agent (isc-dhcp-relay) on the router.
//
// - DISCOVER and REQUEST are broadcast (every host on the segment sees them);
//   OFFER and ACK are unicast to the client's MAC (Linux dhclient does not set
//   the broadcast flag). dhcpd, dhclient and dhcrelay read DHCP with packet
//   (LPF) sockets on the interfaces they listen on, which receive frames before
//   netfilter: host input chains do not stop them. Only the relay's fallback
//   UDP socket (an interface it does not listen on) is subject to the firewall.
// - A relay on the client's segment turns the broadcast into a unicast to each
//   configured server, sets giaddr to its own address on that segment, and
//   relays the server's reply back to the client. dhcpd picks the subnet by
//   giaddr ("unknown network segment" when it has no matching declaration).
// - The client keeps a binding with RFC 2131 timers: at T1 (lease/2) it
//   renews by unicast with the server that granted the lease, at T2 (7/8) it
//   rebinds by broadcast to any server, and at expiry it drops the address.
//   maintainLeases() replays these events whenever simulated time has passed.
// - dhclient with a remembered lease starts in INIT-REBOOT: it broadcasts a
//   REQUEST for its old address; an authoritative server NAKs an address that
//   does not belong to the client's current network, and the client starts over.
// Leases persist in the server's /var/lib/dhcp/dhcpd.leases, so allocations
// survive reboots.

import { type DhcpdConfig, type DhcpSubnet, type Lease, formatLease, formatLeaseDate, parseLeases } from '../config/dhcpd';
import { readFile, writeFile } from '../fs';
import { formatIp, inCidr, parseCidr, parseIp, prefixMask } from '../net/ip';
import type { DhcpBinding, Host, Interface, Packet, World } from '../types';
import { seededInt } from '../util/sha256';
import { log } from './journal';
import { capture, nextId, sourceAddress, transmit } from './network';
import { activeRecorder, withRecorder } from './trace';

export interface DhcpdLoaded {
  config: DhcpdConfig;
  interfaces: string[];
}

export interface DhcpLease {
  address: string;
  prefix: number;
  routers: string[];
  dns: string[];
  domain?: string;
  server: string;
  leaseTime: number;
}

const BCAST_MAC = 'ff:ff:ff:ff:ff:ff';

function u32(n: number) { return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]; }
function ipb(s: string) { return u32(parseIp(s) ?? 0); }

interface BootpFields { yiaddr?: string; siaddr?: string; ciaddr?: string; giaddr?: string; hops?: number }

/** BOOTP/DHCP message bytes (RFC 2131 §2, RFC 2132 options) for PCAP export. */
export function encodeDhcp(op: 1 | 2, type: number, xid: number, mac: string, fields: BootpFields, opts: [number, number[]][]): Uint8Array {
  const b: number[] = [op, 1, 6, fields.hops ?? 0, ...u32(xid), 0, 0, 0, 0, ...ipb(fields.ciaddr ?? '0.0.0.0'), ...ipb(fields.yiaddr ?? '0.0.0.0'), ...ipb(fields.siaddr ?? '0.0.0.0'), ...ipb(fields.giaddr ?? '0.0.0.0')];
  const chaddr = mac.split(':').map((x) => parseInt(x, 16));
  b.push(...chaddr, ...new Array(10).fill(0), ...new Array(64).fill(0), ...new Array(128).fill(0));
  b.push(99, 130, 83, 99, 53, 1, type);
  for (const [code, val] of opts) b.push(code, val.length, ...val);
  b.push(255);
  while (b.length < 300) b.push(0);
  return new Uint8Array(b);
}

const TYPE_NAME: Record<number, string> = { 1: 'DHCPDISCOVER', 2: 'DHCPOFFER', 3: 'DHCPREQUEST', 5: 'DHCPACK', 6: 'DHCPNAK', 7: 'DHCPRELEASE' };

interface Msg { op: 1 | 2; type: number; xid: number; mac: string; fields: BootpFields; opts: [number, number[]][]; extra: { name: string; value: string }[] }

function dhcpPacket(world: World, src: string, dst: string, m: Msg, ports?: [number, number]): Packet {
  const bytes = encodeDhcp(m.op, m.type, m.xid, m.mac, m.fields, m.opts);
  const [sport, dport] = ports ?? (m.op === 1 ? [68, 67] : [67, 68]);
  const f = m.fields;
  return {
    id: nextId(world), src, dst, ttl: 64, proto: 'udp',
    udp: { sport, dport, len: bytes.length },
    app: {
      protocol: 'DHCP',
      info: `${TYPE_NAME[m.type]} - Transaction ID 0x${m.xid.toString(16).padStart(8, '0')}${f.yiaddr ? ` (${f.yiaddr})` : ''}${f.giaddr ? ` via relay ${f.giaddr}` : ''}`,
      fields: [
        { name: 'Message type', value: `${m.op === 1 ? 'Boot Request (1)' : 'Boot Reply (2)'}, option 53 = ${TYPE_NAME[m.type]}` },
        { name: 'Transaction ID', value: `0x${m.xid.toString(16).padStart(8, '0')}` },
        { name: 'Client MAC (chaddr)', value: m.mac },
        ...(f.hops ? [{ name: 'Hops', value: String(f.hops) }] : []),
        ...(f.ciaddr ? [{ name: 'Client IP (ciaddr)', value: f.ciaddr }] : []),
        ...(f.yiaddr ? [{ name: 'Your IP (yiaddr)', value: f.yiaddr }] : []),
        ...(f.giaddr ? [{ name: 'Relay agent IP (giaddr)', value: f.giaddr }] : []),
        ...m.extra,
      ],
      bytes,
    },
  };
}

/** A DHCP server that can answer this client, reached directly or through a relay agent. */
interface ServerCandidate {
  host: Host;
  /** The server interface the request arrived on. */
  iface: Interface;
  loaded: DhcpdLoaded;
  subnet: DhcpSubnet;
  relay?: { host: Host; iface: Interface; giaddr: string };
}

const via = (s: ServerCandidate) => s.relay?.giaddr ?? s.iface.name;

function serversOnSegment(world: World, segment: string): ServerCandidate[] {
  const out: ServerCandidate[] = [];
  for (const h of Object.values(world.hosts)) {
    const rt = h.services.dhcpd;
    if (!rt || rt.state !== 'active') continue;
    const loaded = rt.loaded as DhcpdLoaded;
    for (const ifname of loaded.interfaces) {
      const iface = h.ifaces.find((i) => i.name === ifname && i.up && i.segment === segment && i.address);
      if (!iface) continue;
      const subnet = loaded.config.subnets.find((s) => inCidr(iface.address!, parseCidr(`${s.network}/${s.prefix}`)!));
      if (subnet) out.push({ host: h, iface, loaded, subnet });
    }
  }
  return out;
}

interface RelayAgent { host: Host; iface: Interface; servers: string[] }

/** Relay agents (isc-dhcp-relay) listening on `segment` with an IPv4 address there. */
function relaysOnSegment(world: World, segment: string): RelayAgent[] {
  const out: RelayAgent[] = [];
  for (const h of Object.values(world.hosts)) {
    const rt = h.services.dhcrelay;
    if (!rt || rt.state !== 'active') continue;
    const loaded = rt.loaded as { servers: string[]; downstream: string[] };
    const candidates = h.ifaces.filter((i) => loaded.downstream.includes(i.name) && i.up && i.segment === segment && i.address);
    for (const iface of candidates) out.push({ host: h, iface, servers: loaded.servers });
  }
  return out;
}

const LEASES = '/var/lib/dhcp/dhcpd.leases';
/** dhclient's "retry" interval after a failed attempt (dhclient.conf default: 300 s). */
const RETRY_MS = 300_000;

/** Choose an address for `mac` the way dhcpd does: fixed host, existing lease, then first free in range. */
export function chooseAddress(config: DhcpdConfig, subnet: DhcpSubnet, leases: Lease[], mac: string, now: number): { ip: string; reason: 'fixed-address' | 'previous lease' | 'pool' } | null {
  const net = parseCidr(`${subnet.network}/${subnet.prefix}`)!;
  const fixed = config.hosts.find((h) => h.mac === mac && h.fixedAddress && inCidr(h.fixedAddress, net));
  if (fixed) return { ip: fixed.fixedAddress!, reason: 'fixed-address' };
  const mine = leases.find((l) => l.mac === mac && inCidr(l.ip, net));
  if (mine) return { ip: mine.ip, reason: 'previous lease' };
  if (!subnet.range) return null;
  const [a, b] = subnet.range.map((x) => parseIp(x)!);
  const taken = new Set([...leases.filter((l) => l.state === 'active' && l.ends > now).map((l) => l.ip), ...config.hosts.map((h) => h.fixedAddress).filter(Boolean)]);
  for (let n = a; n <= b; n++) if (!taken.has(formatIp(n))) return { ip: formatIp(n), reason: 'pool' };
  return null;
}

function allocate(world: World, s: ServerCandidate, mac: string): string | null {
  return chooseAddress(s.loaded.config, s.subnet, parseLeases(readFile(s.host, LEASES) ?? ''), mac, world.clock)?.ip ?? null;
}

function options(s: ServerCandidate, leaseTime: number): [number, number[]][] {
  const o = { ...s.loaded.config.options, ...s.subnet.options };
  const opts: [number, number[]][] = [[54, ipb(s.iface.address!)], [51, u32(leaseTime)], [58, u32(Math.floor(leaseTime / 2))], [59, u32(Math.floor(leaseTime * 7 / 8))], [1, u32(prefixMask(s.subnet.prefix))]];
  if (o.routers) opts.push([3, o.routers.flatMap(ipb)]);
  if (o.domainNameServers) opts.push([6, o.domainNameServers.flatMap(ipb)]);
  if (o.domainName) opts.push([15, [...new TextEncoder().encode(o.domainName)]]);
  return opts;
}

/** Packet-socket receive on a DHCP server: the dhcpd host owning `addr`, on its listening interfaces. */
function serverRaw(world: World, addr: string): { host: string; ifaces: string[] } | undefined {
  const h = Object.values(world.hosts).find((x) => x.ifaces.some((i) => i.address === addr));
  const loaded = h?.services.dhcpd?.state === 'active' ? (h.services.dhcpd.loaded as DhcpdLoaded) : undefined;
  return h && loaded ? { host: h.id, ifaces: loaded.interfaces } : undefined;
}

function serverLog(world: World, s: { host: Host }, m: string, prio: 'info' | 'err' = 'info') {
  log(world, s.host, 'dhcpd', m, { pid: s.host.services.dhcpd.pid, unit: 'isc-dhcp-server.service', priority: prio });
}

/** The relay forwards a client broadcast to each configured server. Returns the servers that will answer. */
function relayForward(world: World, r: RelayAgent, m: Msg): ServerCandidate[] {
  const out: ServerCandidate[] = [];
  const rec = activeRecorder();
  for (const server of r.servers) {
    const fwd = dhcpPacket(world, sourceAddress(r.host, server), server, { ...m, fields: { ...m.fields, giaddr: r.iface.address!, hops: (m.fields.hops ?? 0) + 1 } }, [67, 67]);
    const d = transmit(world, r.host.id, fwd, { rawSocket: serverRaw(world, server) });
    rec?.describe(fwd.id, `Relayed ${TYPE_NAME[m.type]} to ${server}`, `${r.host.hostname} (isc-dhcp-relay) received the client's broadcast on ${r.iface.name}. Broadcasts do not cross routers, so the relay sends a copy as a normal unicast UDP packet (port 67 → 67) to the DHCP server ${server}, with giaddr = ${r.iface.address} (its own address on the client's network) and hops incremented. The server uses giaddr to choose the subnet and sends its answer back to the relay.`);
    if (d.status !== 'delivered') continue;
    const host = world.hosts[d.host];
    const rt = host.services.dhcpd;
    if (!rt || rt.state !== 'active') continue;
    const loaded = rt.loaded as DhcpdLoaded;
    const iface = host.ifaces.find((i) => i.address === d.final.dst && loaded.interfaces.includes(i.name));
    if (!iface) continue;
    const giaddr = r.iface.address!;
    const subnet = loaded.config.subnets.find((s) => inCidr(giaddr, parseCidr(`${s.network}/${s.prefix}`)!));
    if (!subnet) {
      serverLog(world, { host }, `${TYPE_NAME[m.type]} from ${m.mac} via ${giaddr}: unknown network segment`, 'err');
      continue;
    }
    out.push({ host, iface, loaded, subnet, relay: { host: r.host, iface: r.iface, giaddr } });
  }
  return out;
}

/** Send a broadcast on the client's segment; returns the servers (direct or via relays) that accepted it. */
function broadcast(world: World, client: Host, iface: Interface, p: Packet, m: Msg, title: string, detail: string): ServerCandidate[] {
  const rec = activeRecorder();
  const ev = rec?.beginPacket(world.clock, client.id, p);
  capture(world, client, iface, 'out', iface.mac, BCAST_MAC, p);
  for (const h of Object.values(world.hosts)) {
    if (h === client) continue;
    for (const i of h.ifaces) if (i.up && i.segment === iface.segment) capture(world, h, i, 'in', iface.mac, BCAST_MAC, p);
  }
  // dhcpd reads with a packet socket: the server's input chain does not apply.
  const direct = serversOnSegment(world, iface.segment!);
  const relays = relaysOnSegment(world, iface.segment!);
  if (rec && ev) {
    const who = [...direct.map((r) => `${r.host.hostname} (DHCP server)`), ...relays.map((r) => `${r.host.hostname} (relay agent on ${r.iface.name})`)];
    rec.endPacket(ev, direct[0]?.host.id ?? relays[0]?.host.id ?? client.id, [], [{ host: client.id, egress: iface.name, srcMac: iface.mac, dstMac: BCAST_MAC, ttl: 64, note: `broadcast on ${iface.segment}: every host on the segment receives it${who.length ? `; answered by: ${who.join(', ')}` : '; no DHCP server or relay agent on this segment'}` }], who.length > 0, who.length ? `received by ${[...direct.map((r) => r.host.id), ...relays.map((r) => r.host.id)].join(', ')}` : 'no DHCP server answered');
    rec.describe(p.id, title, detail);
  }
  world.clock += 0.4;
  const viaRelay = relays.flatMap((r) => relayForward(world, r, m));
  return [...direct, ...viaRelay];
}

/** A server's reply to the client: straight on the segment, or to the relay which forwards it. */
function replyToClient(world: World, s: ServerCandidate, client: Host, iface: Interface, m: Msg, yiaddr: string, title: string, detail: string): boolean {
  const rec = activeRecorder();
  let from: { host: Host; iface: Interface; src: string } = { host: s.host, iface: s.iface, src: s.iface.address! };
  if (s.relay) {
    const toRelay = dhcpPacket(world, s.iface.address!, s.relay.giaddr, m, [67, 67]);
    // dhcrelay reads replies with LPF on the interfaces it listens on (bypassing nftables); on any other
    // interface the reply reaches its fallback UDP socket and the input chain applies.
    const upstream = (s.relay.host.services.dhcrelay?.loaded as { upstream: string[] } | undefined)?.upstream ?? [];
    const d = transmit(world, s.host.id, toRelay, { rawSocket: { host: s.relay.host.id, ifaces: upstream } });
    rec?.describe(toRelay.id, `${TYPE_NAME[m.type]} to the relay ${s.relay.giaddr}`, `The server cannot reach the client directly (it has no address yet and is on another network), so it sends the reply to giaddr ${s.relay.giaddr}, the relay agent, on UDP port 67.`);
    if (d.status !== 'delivered' || d.host !== s.relay.host.id || s.relay.host.services.dhcrelay?.state !== 'active') return false;
    from = { host: s.relay.host, iface: s.relay.iface, src: s.relay.giaddr };
  }
  const p = dhcpPacket(world, from.src, yiaddr, m);
  const ev = rec?.beginPacket(world.clock, from.host.id, p);
  capture(world, from.host, from.iface, 'out', from.iface.mac, iface.mac, p);
  capture(world, client, iface, 'in', from.iface.mac, iface.mac, p);
  const ok = iface.up;
  if (rec && ev) {
    rec.endPacket(ev, client.id, [], [{ host: from.host.id, egress: from.iface.name, srcMac: from.iface.mac, dstMac: iface.mac, ttl: 64, note: `unicast to the client MAC ${iface.mac} (the client has no IP address yet; ${s.relay ? 'the relay' : 'the server'} uses chaddr from the request). dhclient reads it with a packet socket, before the client's firewall.` }], ok, ok ? `delivered to ${client.id}` : `${client.hostname}'s interface is down`);
    rec.describe(p.id, title, s.relay ? `${detail} The relay forwards it onto ${s.relay.iface.name}, addressed to the client's MAC.` : detail);
  }
  world.clock += 0.4;
  return ok;
}

function clientLog(world: World, client: Host, pid: number) {
  return (m: string) => log(world, client, 'dhclient', m, { pid, unit: 'networking.service' });
}

function recordLease(world: World, s: ServerCandidate, ip: string, mac: string, hostname: string, leaseTime: number) {
  const prev = readFile(s.host, LEASES) ?? '';
  writeFile(s.host, LEASES, prev + formatLease({ ip, mac, hostname, starts: world.clock, ends: world.clock + leaseTime * 1000, state: 'active' }), world.clock);
}

function leaseFrom(s: ServerCandidate, ip: string, leaseTime: number): DhcpLease {
  const o = { ...s.loaded.config.options, ...s.subnet.options };
  return { address: ip, prefix: s.subnet.prefix, routers: o.routers ?? [], dns: o.domainNameServers ?? [], domain: o.domainName, server: s.iface.address!, leaseTime };
}

function msg(type: number, xid: number, mac: string, fields: BootpFields, opts: [number, number[]][], extra: { name: string; value: string }[], op: 1 | 2 = type === 2 || type === 5 || type === 6 ? 2 : 1): Msg {
  return { op, type, xid, mac, fields, opts, extra };
}

/** The address dhclient remembers from its lease file (used for INIT-REBOOT). */
function rememberedAddress(client: Host, iface: Interface): string | null {
  return /fixed-address ([\d.]+);/.exec(readFile(client, `/var/lib/dhcp/dhclient.${iface.name}.leases`) ?? '')?.[1] ?? null;
}

/**
 * INIT-REBOOT (RFC 2131 §3.2): broadcast a REQUEST for the remembered address. Returns the lease on
 * ACK, 'nak' when a server rejects it (wrong network, address taken), or null when nobody answered.
 */
function initReboot(world: World, client: Host, iface: Interface, old: string, dl: (m: string) => void): DhcpLease | 'nak' | null {
  const xid = seededInt(`xid:${client.id}:${world.counter}`, 1, 0x7fffffff) >>> 0;
  dl(`DHCPREQUEST for ${old} on ${iface.name} to 255.255.255.255 port 67`);
  const m = msg(3, xid, iface.mac, {}, [[50, ipb(old)]], [{ name: 'Requested IP (option 50)', value: old }]);
  const req = dhcpPacket(world, '0.0.0.0', '255.255.255.255', m);
  const servers = broadcast(world, client, iface, req, m, `DHCPREQUEST ${old} (INIT-REBOOT)`, 'The client remembers its previous lease (dhclient.eth0.leases) and asks to keep that address, without a DISCOVER and without naming a server. A server that knows the client and the network answers ACK; an authoritative server for a network the address does not belong to answers NAK so the client starts over.');
  for (const s of servers) {
    const inSubnet = inCidr(old, parseCidr(`${s.subnet.network}/${s.subnet.prefix}`)!);
    const choice = inSubnet ? chooseAddress(s.loaded.config, s.subnet, parseLeases(readFile(s.host, LEASES) ?? ''), iface.mac, world.clock) : null;
    if (inSubnet && choice?.ip === old) {
      const leaseTime = s.loaded.config.defaultLeaseTime;
      serverLog(world, s, `DHCPREQUEST for ${old} from ${iface.mac} (${client.hostname}) via ${via(s)}`);
      recordLease(world, s, old, iface.mac, client.hostname, leaseTime);
      serverLog(world, s, `DHCPACK on ${old} to ${iface.mac} (${client.hostname}) via ${via(s)}`);
      const ack = msg(5, xid, iface.mac, { yiaddr: old, siaddr: s.iface.address! }, options(s, leaseTime), [{ name: 'Options', value: describeOpts(s) }]);
      if (!replyToClient(world, s, client, iface, ack, old, `DHCPACK ${old}`, 'The server confirms the remembered address and renews the lease.')) continue;
      dl(`DHCPACK of ${old} from ${s.relay?.giaddr ?? s.iface.address}`);
      return leaseFrom(s, old, leaseTime);
    }
    if (!s.loaded.config.authoritative) continue;
    serverLog(world, s, `DHCPREQUEST for ${old} from ${iface.mac} (${client.hostname}) via ${via(s)}: ${inSubnet ? 'lease not available' : 'wrong network'}.`);
    serverLog(world, s, `DHCPNAK on ${old} to ${iface.mac} via ${via(s)}`);
    const nak = msg(6, xid, iface.mac, {}, [[54, ipb(s.iface.address!)]], [{ name: 'Message', value: inSubnet ? 'requested address not available' : 'wrong network' }]);
    if (replyToClient(world, s, client, iface, nak, '255.255.255.255', `DHCPNAK for ${old}`, `${s.host.hostname} is authoritative for ${s.subnet.network}/${s.subnet.prefix} and ${old} does not belong there (the laptop moved, or the address was given away). The NAK tells the client to forget it and start with DISCOVER.`)) {
      dl(`DHCPNAK from ${s.relay?.giaddr ?? s.iface.address}`);
      return 'nak';
    }
  }
  return null;
}

/** dhclient: obtain a lease on `iface` (INIT-REBOOT if a lease is remembered, else DISCOVER). Configures the interface on success. */
export function dhcpAcquire(world: World, client: Host, iface: Interface, opts: { retry?: boolean } = {}): DhcpLease | null {
  // A retry comes from the dhclient process that is already running (same PID, no banner), in
  // INIT state: its lease is gone, so it starts with DISCOVER instead of INIT-REBOOT.
  const pid = opts.retry ? client.nextPid : (client.nextPid += 5);
  const dl = clientLog(world, client, pid);
  const rec = activeRecorder();
  if (rec) rec.phase = 'DHCP';
  if (!opts.retry) {
    dl(`Internet Systems Consortium DHCP Client 4.4.3-P1`);
    dl(`Listening on LPF/${iface.name}/${iface.mac}`);
    dl(`Sending on   LPF/${iface.name}/${iface.mac}`);
  }
  const old = opts.retry ? null : rememberedAddress(client, iface);
  if (old) {
    const r = initReboot(world, client, iface, old, dl);
    if (r && r !== 'nak') {
      dl(`bound to ${r.address} -- renewal in ${Math.floor(r.leaseTime / 2)} seconds.`);
      applyLease(world, client, iface, r);
      return r;
    }
  }
  const xid = seededInt(`xid:${client.id}:${world.counter}`, 1, 0x7fffffff) >>> 0;
  let offer: { s: ServerCandidate; ip: string } | null = null;
  let interval = 3;
  for (let attempt = 0; attempt < 6 && !offer; attempt++) {
    dl(`DHCPDISCOVER on ${iface.name} to 255.255.255.255 port 67 interval ${interval}`);
    const dm = msg(1, xid, iface.mac, {}, [[55, [1, 3, 6, 15, 51, 54]], [12, [...new TextEncoder().encode(client.hostname)]]], [{ name: 'Parameter request list', value: 'subnet mask, router, DNS servers, domain name, lease time, server id' }]);
    const disc = dhcpPacket(world, '0.0.0.0', '255.255.255.255', dm);
    const servers = broadcast(world, client, iface, disc, dm, 'DHCPDISCOVER (broadcast)', 'The client has no address, so it sends from 0.0.0.0:68 to the broadcast address 255.255.255.255:67 in a frame to ff:ff:ff:ff:ff:ff. Every host on the segment receives it; only DHCP servers listening on that segment, or a relay agent that forwards it to a server elsewhere, answer. Broadcasts do not cross routers.');
    for (const s of servers) {
      serverLog(world, s, `DHCPDISCOVER from ${iface.mac} (${client.hostname}) via ${via(s)}`);
      const ip = allocate(world, s, iface.mac);
      if (!ip) {
        serverLog(world, s, `DHCPDISCOVER from ${iface.mac} (${client.hostname}) via ${via(s)}: network ${s.subnet.network}/${s.subnet.prefix}: no free leases`, 'err');
        continue;
      }
      serverLog(world, s, `DHCPOFFER on ${ip} to ${iface.mac} (${client.hostname}) via ${via(s)}`);
      const om = msg(2, xid, iface.mac, { yiaddr: ip, siaddr: s.iface.address!, giaddr: s.relay?.giaddr }, options(s, s.loaded.config.defaultLeaseTime), [{ name: 'Offered options', value: describeOpts(s) }]);
      if (replyToClient(world, s, client, iface, om, ip, `DHCPOFFER ${ip}`, `${s.host.hostname} picks an address for this MAC (a host reservation, the client's previous lease, or the first free address of the pool${s.relay ? ` in ${s.subnet.network}/${s.subnet.prefix}, the subnet that contains giaddr` : ''}) and offers it together with the subnet mask, router, DNS servers and lease time.`)) {
        offer = { s, ip };
        dl(`DHCPOFFER of ${ip} from ${s.relay?.giaddr ?? s.iface.address}`);
        break;
      }
    }
    if (!offer) {
      world.clock += interval * 1000;
      interval = Math.min(interval * 2 + 2, 20);
    }
  }
  if (!offer) {
    dl('No DHCPOFFERS received.');
    dl('No working leases in persistent database - sleeping.');
    iface.dhcpRetryAt = world.clock + RETRY_MS;
    return null;
  }
  const { s, ip } = offer;
  dl(`DHCPREQUEST for ${ip} on ${iface.name} to 255.255.255.255 port 67`);
  const rm = msg(3, xid, iface.mac, {}, [[50, ipb(ip)], [54, ipb(s.iface.address!)]], [{ name: 'Requested IP (option 50)', value: ip }, { name: 'Server identifier (option 54)', value: s.iface.address! }]);
  const req = dhcpPacket(world, '0.0.0.0', '255.255.255.255', rm);
  const got = broadcast(world, client, iface, req, rm, `DHCPREQUEST ${ip} (broadcast)`, 'The client accepts one offer by broadcasting a REQUEST naming the chosen server (option 54). Broadcasting it tells any other server that offered an address that its offer was declined.');
  const chosen = got.find((g) => g.host.id === s.host.id);
  if (!chosen) {
    dl('No DHCPOFFERS received.');
    iface.dhcpRetryAt = world.clock + RETRY_MS;
    return null;
  }
  serverLog(world, chosen, `DHCPREQUEST for ${ip} (${s.iface.address}) from ${iface.mac} (${client.hostname}) via ${via(chosen)}`);
  const leaseTime = s.loaded.config.defaultLeaseTime;
  recordLease(world, chosen, ip, iface.mac, client.hostname, leaseTime);
  serverLog(world, chosen, `DHCPACK on ${ip} to ${iface.mac} (${client.hostname}) via ${via(chosen)}`);
  const am = msg(5, xid, iface.mac, { yiaddr: ip, siaddr: s.iface.address!, giaddr: chosen.relay?.giaddr }, options(chosen, leaseTime), [{ name: 'Options', value: describeOpts(chosen) }]);
  if (!replyToClient(world, chosen, client, iface, am, ip, `DHCPACK ${ip}`, `The server records the lease in /var/lib/dhcp/dhcpd.leases and confirms it. The client now configures ${ip}/${s.subnet.prefix}, a default route via the offered router and the DNS servers (written to /etc/resolv.conf by dhclient-script). It will renew after half the lease time (T1).`)) {
    iface.dhcpRetryAt = world.clock + RETRY_MS;
    return null;
  }
  const lease = leaseFrom(chosen, ip, leaseTime);
  dl(`DHCPACK of ${ip} from ${chosen.relay?.giaddr ?? s.iface.address}`);
  dl(`bound to ${ip} -- renewal in ${Math.floor(leaseTime / 2)} seconds.`);
  applyLease(world, client, iface, lease);
  return lease;
}

function describeOpts(s: ServerCandidate): string {
  const o = { ...s.loaded.config.options, ...s.subnet.options };
  return [`mask /${s.subnet.prefix}`, o.routers ? `router ${o.routers.join(', ')}` : 'no router', o.domainNameServers ? `DNS ${o.domainNameServers.join(', ')}` : 'no DNS', o.domainName ? `domain ${o.domainName}` : ''].filter(Boolean).join('; ');
}

function binding(world: World, lease: DhcpLease): DhcpBinding {
  const t = world.clock;
  // A zero lease time would make every timer fire at once; keep at least one second.
  const secs = Math.max(1, lease.leaseTime);
  return { server: lease.server, leaseTime: secs, obtained: t, renewAt: t + secs * 500, rebindAt: t + secs * 875, expires: t + secs * 1000, state: 'bound' };
}

export function applyLease(world: World, host: Host, iface: Interface, lease: DhcpLease): void {
  iface.dhcpRetryAt = undefined;
  iface.address = lease.address;
  iface.prefix = lease.prefix;
  iface.dhcp = binding(world, lease);
  host.routes = host.routes.filter((r) => !(r.dest === 'default' && r.dev === iface.name));
  if (lease.routers[0]) host.routes.push({ dest: 'default', via: lease.routers[0], dev: iface.name, proto: 'boot' });
  const rc = [`domain ${lease.domain ?? ''}`.trim(), lease.domain ? `search ${lease.domain}` : '', ...lease.dns.map((d) => `nameserver ${d}`)].filter((l) => l && l !== 'domain').join('\n') + '\n';
  writeFile(host, '/etc/resolv.conf', rc, world.clock);
  const b = iface.dhcp;
  writeFile(host, `/var/lib/dhcp/dhclient.${iface.name}.leases`, `lease {\n  interface "${iface.name}";\n  fixed-address ${lease.address};\n  option subnet-mask ${formatIp(prefixMask(lease.prefix))};\n${lease.routers.length ? `  option routers ${lease.routers.join(',')};\n` : ''}${lease.dns.length ? `  option domain-name-servers ${lease.dns.join(',')};\n` : ''}  option dhcp-server-identifier ${lease.server};\n  option dhcp-lease-time ${lease.leaseTime};\n  renew ${formatLeaseDate(b.renewAt)};\n  rebind ${formatLeaseDate(b.rebindAt)};\n  expire ${formatLeaseDate(b.expires)};\n}\n`, world.clock);
}

function dropAddress(host: Host, iface: Interface): void {
  iface.address = null;
  iface.prefix = null;
  iface.dhcp = undefined;
  host.routes = host.routes.filter((r) => r.dev !== iface.name);
}

/**
 * RENEWING (unicast to the granting server) or REBINDING (broadcast to any server) for a bound
 * client. Returns true when the lease was extended.
 */
export function dhcpRenew(world: World, client: Host, iface: Interface, mode: 'renew' | 'rebind'): boolean {
  const b = iface.dhcp;
  const ip = iface.address;
  if (!b || !ip) return false;
  const dl = clientLog(world, client, client.nextPid);
  const xid = seededInt(`xid:${client.id}:${world.counter}`, 1, 0x7fffffff) >>> 0;
  const m = msg(3, xid, iface.mac, { ciaddr: ip }, [], [{ name: 'Phase', value: mode === 'renew' ? 'RENEWING (T1): unicast to the server that granted the lease' : 'REBINDING (T2): broadcast to any server' }]);
  let servers: ServerCandidate[] = [];
  if (mode === 'renew') {
    dl(`DHCPREQUEST for ${ip} on ${iface.name} to ${b.server} port 67`);
    const p = dhcpPacket(world, ip, b.server, m);
    const d = transmit(world, client.id, p, { rawSocket: serverRaw(world, b.server) });
    activeRecorder()?.describe(p.id, `DHCPREQUEST ${ip} (renewal, unicast)`, `Half the lease time (T1) has passed. The client still has its address and a route, so it asks the server that granted the lease (${b.server}) directly, by unicast through the router: no broadcast and no relay are involved.`);
    if (d.status === 'delivered') {
      const host = world.hosts[d.host];
      const rt = host.services.dhcpd;
      if (rt?.state === 'active') {
        const loaded = rt.loaded as DhcpdLoaded;
        const sIface = host.ifaces.find((i) => i.address === b.server && loaded.interfaces.includes(i.name));
        const subnet = loaded.config.subnets.find((s) => inCidr(ip, parseCidr(`${s.network}/${s.prefix}`)!));
        if (sIface && subnet) servers = [{ host, iface: sIface, loaded, subnet }];
      }
    }
  } else {
    dl(`DHCPREQUEST for ${ip} on ${iface.name} to 255.255.255.255 port 67`);
    const p = dhcpPacket(world, ip, '255.255.255.255', m);
    servers = broadcast(world, client, iface, p, m, `DHCPREQUEST ${ip} (rebinding, broadcast)`, 'The original server did not answer the renewals. At 7/8 of the lease time (T2) the client broadcasts its REQUEST so that any server responsible for this network (directly or through a relay) can extend the lease.');
  }
  for (const s of servers) {
    const choice = chooseAddress(s.loaded.config, s.subnet, parseLeases(readFile(s.host, LEASES) ?? ''), iface.mac, world.clock);
    if (choice?.ip !== ip) continue;
    const leaseTime = s.loaded.config.defaultLeaseTime;
    serverLog(world, s, `DHCPREQUEST for ${ip} from ${iface.mac} (${client.hostname}) via ${mode === 'renew' ? s.iface.name : via(s)}`);
    recordLease(world, s, ip, iface.mac, client.hostname, leaseTime);
    serverLog(world, s, `DHCPACK on ${ip} to ${iface.mac} (${client.hostname}) via ${mode === 'renew' ? s.iface.name : via(s)}`);
    const am = msg(5, xid, iface.mac, { ciaddr: ip, yiaddr: ip, siaddr: s.iface.address! }, options(s, leaseTime), [{ name: 'Options', value: describeOpts(s) }]);
    const ack = dhcpPacket(world, s.iface.address!, ip, am);
    const d = transmit(world, s.host.id, ack, { rawSocket: { host: client.id, ifaces: [iface.name] } });
    activeRecorder()?.describe(ack.id, `DHCPACK ${ip} (lease extended)`, 'The server extends the lease and answers by unicast to the client\'s address. Nothing changes on the client except the timers.');
    if (d.status !== 'delivered' || d.host !== client.id) continue;
    dl(`DHCPACK of ${ip} from ${s.iface.address}`);
    const lease = leaseFrom(s, ip, leaseTime);
    dl(`bound to ${ip} -- renewal in ${Math.floor(leaseTime / 2)} seconds.`);
    applyLease(world, client, iface, lease);
    return true;
  }
  return false;
}

/** dhclient keeps retransmitting while RENEWING/REBINDING; the simulator retries once a minute. */
const RETRANSMIT_MS = 60_000;

/** When the next timer of this interface fires, if it has one. */
function nextEvent(iface: Interface): number | undefined {
  const b = iface.dhcp;
  if (b) {
    if (b.state === 'bound') return b.renewAt;
    const until = b.state === 'renewing' ? b.rebindAt : b.expires;
    return Math.min(until, b.nextTry ?? until);
  }
  return iface.address ? undefined : iface.dhcpRetryAt;
}

/**
 * Replay the DHCP client timers of every host up to the current time: renew at T1 (retried until
 * T2), rebind at T2 (retried until expiry), drop the address at expiry, and retry every 5 minutes
 * without a lease. Events of all hosts are processed in time order, so the journals stay ordered.
 * A client that renews successfully over a long gap is assumed to have kept renewing with the same
 * server, so only the first and the latest exchange are simulated; long outages are summarised.
 */
export function maintainLeases(world: World, record = false): void {
  const now = world.clock;
  const retries = new Map<Interface, number>();
  withRecorder(record ? activeRecorder() : null, () => {
    for (let guard = 0; guard < 2000; guard++) {
      let next: { host: Host; iface: Interface; at: number } | null = null;
      for (const host of Object.values(world.hosts)) {
        for (const iface of host.ifaces) {
          const at = nextEvent(iface);
          if (at !== undefined && at <= now && (!next || at < next.at)) next = { host, iface, at };
        }
      }
      if (!next) break;
      const { host, iface, at } = next;
      world.clock = at;
      const b = iface.dhcp;
      if (!b) {
        // A sleeping dhclient tries again every 5 minutes; after two attempts, skip to the last one.
        const tries = retries.get(iface) ?? 0;
        retries.set(iface, tries + 1);
        if (tries >= 2) {
          iface.dhcpRetryAt = at + Math.ceil((now - at) / RETRY_MS) * RETRY_MS;
          if (iface.dhcpRetryAt <= now) iface.dhcpRetryAt += RETRY_MS;
          continue;
        }
        dhcpAcquire(world, host, iface, { retry: true });
        continue;
      }
      if (b.state === 'bound' || (b.state === 'renewing' && at < b.rebindAt)) {
        if (dhcpRenew(world, host, iface, 'renew')) {
          // Healthy server: skip ahead to the last renewal before now.
          const nb = iface.dhcp!;
          const half = nb.leaseTime * 500;
          const skips = Math.floor((now - nb.renewAt) / half) - 1;
          if (skips > 0) for (const k of ['obtained', 'renewAt', 'rebindAt', 'expires'] as const) nb[k] += skips * half;
          continue;
        }
        b.state = 'renewing';
        b.nextTry = at + RETRANSMIT_MS;
        continue;
      }
      if (at < b.expires) {
        b.state = 'rebinding';
        if (dhcpRenew(world, host, iface, 'rebind')) continue;
        b.nextTry = at + RETRANSMIT_MS;
        continue;
      }
      const dl = clientLog(world, host, host.nextPid);
      dl(`DHCPREQUEST for ${iface.address} on ${iface.name} to 255.255.255.255 port 67`);
      dl(`No DHCPOFFERS received.`);
      dl(`No working leases in persistent database - sleeping.`);
      dropAddress(host, iface);
      iface.dhcpRetryAt = at;
    }
  });
  world.clock = Math.max(world.clock, now);
}

/** dhclient -r: send DHCPRELEASE (unicast to the server) and deconfigure the interface. */
export function dhcpRelease(world: World, client: Host, iface: Interface): string | null {
  const leaseText = readFile(client, `/var/lib/dhcp/dhclient.${iface.name}.leases`) ?? '';
  const server = iface.dhcp?.server ?? /dhcp-server-identifier ([\d.]+);/.exec(leaseText)?.[1];
  if (!iface.address || !server) return null;
  const xid = seededInt(`xid:${client.id}:${world.counter}`, 1, 0x7fffffff) >>> 0;
  const p = dhcpPacket(world, iface.address, server, msg(7, xid, iface.mac, { ciaddr: iface.address }, [[54, ipb(server)]], []));
  const d = transmit(world, client.id, p, { rawSocket: serverRaw(world, server) });
  if (d.status === 'delivered') {
    const s = world.hosts[d.host];
    if (s.services.dhcpd?.state === 'active') {
      const leases = parseLeases(readFile(s, LEASES) ?? '');
      const l = leases.find((x) => x.ip === iface.address);
      if (l) writeFile(s, LEASES, (readFile(s, LEASES) ?? '') + formatLease({ ...l, state: 'free', ends: world.clock }), world.clock);
      const sIface = s.ifaces.find((i) => i.address === server);
      serverLog(world, { host: s }, `DHCPRELEASE of ${iface.address} from ${iface.mac} (${client.hostname}) via ${sIface?.name ?? 'eth0'} (${l ? 'found' : 'not found'})`);
    }
  }
  const released = iface.address;
  dropAddress(client, iface);
  iface.dhcpRetryAt = undefined; // dhclient -r also stops the running client
  return `DHCPRELEASE of ${released} on ${iface.name} to ${server} port 67`;
}
