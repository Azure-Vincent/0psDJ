// DHCPv6 (RFC 8415) between `dhclient -6` and ISC `dhcpd -6`, on one link.
//
// - The client sends from its link-local address, UDP 546, to the
//   All_DHCP_Relay_Agents_and_Servers multicast address ff02::1:2, UDP 547.
//   The server answers by unicast to the client's link-local address.
// - Unlike DHCPv4 (packet sockets), both programs use ordinary UDP sockets, so
//   nftables applies: the server needs "udp dport 547" accepted, and the client
//   needs "udp dport 546" accepted, because the reply comes from the server's
//   own address while the request went to a multicast group: conntrack does not
//   match them, the reply is ct state "new".
// - Stateful: SOLICIT → ADVERTISE → REQUEST → REPLY gives an IA_NA address
//   (installed as a /128 by dhclient-script) with preferred/valid lifetimes and
//   T1/T2. Stateless (dhclient -6 -S): INFORMATION-REQUEST → REPLY, options only.
// - DHCPv6 never carries a default route or a prefix length: those come from
//   router advertisements (radvd). The M/O flags in the RA tell hosts that
//   honour them (NetworkManager, systemd-networkd) to use DHCPv6; ifupdown's
//   "inet6 dhcp" runs dhclient -6 regardless.
// - Clients and servers identify each other by DUID; addresses belong to an
//   IA (identity association, IAID) of a client DUID.

import { type Dhcpd6Config, type Dhcp6Subnet, formatLease6, inPrefix6, parseLeases6 } from '../config/dhcpd6';
import { evaluate } from '../config/nft';
import { readFile, writeFile } from '../fs';
import { formatIp6, ip6Bytes, multicastMac, parseIp6 } from '../net/ip6';
import type { Dhcp6Binding, Host, Interface, Packet, World } from '../types';
import { seededInt } from '../util/sha256';
import { log } from './journal';
import { capture, clonePacket, describeDecision, nextId } from './network';
import { activeRecorder } from './trace';

export const ALL_DHCP_SERVERS = 'ff02::1:2';
export const LEASES6 = '/var/lib/dhcp/dhcpd6.leases';
/** RFC 3315 SOL_MAX_RT (ISC dhclient 4.4): a client without a lease solicits again every 120 s. */
const SOLICIT_RETRY_MS = 120_000;

export interface Dhcpd6Loaded {
  config: Dhcpd6Config;
  /** Interfaces dhcpd -6 listens on, each with the subnet6 that contains one of its addresses. */
  interfaces: { name: string; subnet: string }[];
  duid: string;
}

const TYPE: Record<number, string> = { 1: 'Solicit', 2: 'Advertise', 3: 'Request', 5: 'Renew', 6: 'Rebind', 7: 'Reply', 8: 'Release', 11: 'Information-request' };
/** tcpdump's short names. */
const TCPDUMP: Record<number, string> = { 1: 'solicit', 2: 'advertise', 3: 'request', 5: 'renew', 6: 'rebind', 7: 'reply', 8: 'release', 11: 'inf-req' };
export function dhcp6TcpdumpName(info: string): string {
  const t = Object.entries(TYPE).find(([, n]) => info.startsWith(n));
  return t ? TCPDUMP[Number(t[0])] : 'unknown';
}

const hex = (b: number[]) => b.map((x) => x.toString(16).padStart(2, '0')).join(':');
const bytesOf = (h: string) => h.split(':').filter(Boolean).map((x) => parseInt(x, 16));
const u16 = (n: number) => [(n >>> 8) & 255, n & 255];
const u32 = (n: number) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];

/** DUID-LLT (type 1, hardware type 1 = Ethernet, a time, the MAC), as dhclient and dhcpd create by default. */
export function duidLlt(mac: string): string {
  const time = seededInt(`duid-time:${mac}`, 0x2a000000, 0x2cffffff);
  return hex([0, 1, 0, 1, ...u32(time), ...bytesOf(mac)]);
}

/** dhclient uses the last four octets of the interface's hardware address as IAID. */
export function iaidOf(mac: string): string {
  return hex(bytesOf(mac).slice(2));
}

/** The MAC inside a DUID-LLT (type 1) or DUID-LL (type 3), as dhcpd does for "hardware ethernet" in dhcpd6.conf. */
function macOfDuid(duid: string): string | undefined {
  const b = bytesOf(duid);
  if (b[1] === 1 && b.length === 14) return hex(b.slice(8));
  if (b[1] === 3 && b.length === 10) return hex(b.slice(4));
  return undefined;
}

interface IaAddr { address: string; preferred: number; valid: number }
interface Dhcp6Msg {
  type: number;
  xid: number;
  clientDuid: string;
  serverDuid?: string;
  ia?: { iaid: string; t1: number; t2: number; addr?: IaAddr; status?: 'NoAddrsAvail' };
  dns?: string[];
  search?: string[];
}

function encodeOption(code: number, data: number[]): number[] {
  return [...u16(code), ...u16(data.length), ...data];
}

function encodeName(name: string): number[] {
  const out: number[] = [];
  for (const label of name.replace(/\.$/, '').split('.')) out.push(label.length, ...new TextEncoder().encode(label));
  return [...out, 0];
}

/** DHCPv6 message bytes (RFC 8415 §8, §21) for PCAP export. */
function encode(m: Dhcp6Msg): Uint8Array {
  const b: number[] = [m.type, (m.xid >>> 16) & 255, (m.xid >>> 8) & 255, m.xid & 255];
  b.push(...encodeOption(1, bytesOf(m.clientDuid)));
  if (m.serverDuid) b.push(...encodeOption(2, bytesOf(m.serverDuid)));
  if (m.ia) {
    const sub = m.ia.addr ? encodeOption(5, [...ip6Bytes(m.ia.addr.address), ...u32(m.ia.addr.preferred), ...u32(m.ia.addr.valid)]) : m.ia.status ? encodeOption(13, [0, 2, ...new TextEncoder().encode('No addresses available')]) : [];
    b.push(...encodeOption(3, [...bytesOf(m.ia.iaid), ...u32(m.ia.t1), ...u32(m.ia.t2), ...sub]));
  }
  if (m.type === 1 || m.type === 3 || m.type === 11) b.push(...encodeOption(6, [...u16(23), ...u16(24)]), ...encodeOption(8, [0, 0]));
  if (m.dns?.length) b.push(...encodeOption(23, m.dns.flatMap(ip6Bytes)));
  if (m.search?.length) b.push(...encodeOption(24, m.search.flatMap(encodeName)));
  return new Uint8Array(b);
}

function dhcp6Packet(world: World, src: string, dst: string, m: Dhcp6Msg): Packet {
  const bytes = encode(m);
  const fromClient = m.type !== 2 && m.type !== 7;
  const xid = `0x${m.xid.toString(16).padStart(6, '0')}`;
  return {
    id: nextId(world), src, dst, ttl: dst.startsWith('ff') ? 1 : 64, proto: 'udp',
    udp: { sport: fromClient ? 546 : 547, dport: fromClient ? 547 : 546, len: bytes.length },
    app: {
      protocol: 'DHCPv6',
      info: `${TYPE[m.type]} XID: ${xid}${m.ia?.addr ? ` IAA: ${m.ia.addr.address}` : ''}`,
      fields: [
        { name: 'Message type', value: `${TYPE[m.type]} (${m.type})` },
        { name: 'Transaction ID', value: xid },
        { name: 'Client Identifier (DUID)', value: m.clientDuid },
        ...(m.serverDuid ? [{ name: 'Server Identifier (DUID)', value: m.serverDuid }] : []),
        ...(m.ia ? [{ name: 'IA_NA', value: `IAID ${m.ia.iaid}, T1 ${m.ia.t1}, T2 ${m.ia.t2}${m.ia.addr ? `, IA Address ${m.ia.addr.address} (preferred ${m.ia.addr.preferred} s, valid ${m.ia.addr.valid} s)` : ''}${m.ia.status ? `, Status: ${m.ia.status}` : ''}` }] : []),
        ...(m.dns?.length ? [{ name: 'DNS recursive name servers (23)', value: m.dns.join(', ') }] : []),
        ...(m.search?.length ? [{ name: 'Domain search list (24)', value: m.search.join(', ') }] : []),
      ],
      bytes,
    },
  };
}

const linkLocal = (i: Interface) => (i.addrs6 ?? []).find((a) => a.scope === 'link')?.address;

interface Endpoint { host: Host; iface: Interface }

/** Firewall check of a DHCPv6 datagram on one host (UDP socket: nftables applies). */
function fw(h: Host, hook: 'input' | 'output', p: Packet, ifname: string) {
  return evaluate(h.nft, hook, { family: 6, src: p.src, dst: p.dst, proto: 'udp', sport: p.udp!.sport, dport: p.udp!.dport, ...(hook === 'input' ? { iif: ifname } : { oif: ifname }), ctState: 'new', len: p.udp!.len + 48 });
}

/** DHCPv6 servers on the client's link: dhcpd -6 running and listening on that interface. */
function serversOn(world: World, segment: string): (Endpoint & { loaded: Dhcpd6Loaded; subnet: Dhcp6Subnet })[] {
  const out: (Endpoint & { loaded: Dhcpd6Loaded; subnet: Dhcp6Subnet })[] = [];
  for (const h of Object.values(world.hosts)) {
    const rt = h.services.dhcpd;
    const loaded = rt?.state === 'active' ? (rt.loaded as { v6?: Dhcpd6Loaded } | null)?.v6 : undefined;
    if (!loaded) continue;
    for (const l of loaded.interfaces) {
      const iface = h.ifaces.find((i) => i.name === l.name && i.up && i.segment === segment && linkLocal(i));
      const subnet = loaded.config.subnets.find((s) => s.prefix === l.subnet);
      if (iface && subnet) out.push({ host: h, iface, loaded, subnet });
    }
  }
  return out;
}

/** Client → ff02::1:2. Returns the servers whose socket received it. */
function multicastToServers(world: World, client: Endpoint, p: Packet, title: string, detail: string) {
  const rec = activeRecorder();
  const ev = rec?.beginPacket(world.clock, client.host.id, clonePacket(p));
  const dstMac = multicastMac(ALL_DHCP_SERVERS);
  const notes: string[] = [];
  const out = fw(client.host, 'output', p, client.iface.name);
  const receivers: ReturnType<typeof serversOn> = [];
  if (out.verdict !== 'accept') notes.push(`dropped by ${client.host.hostname}'s own output chain (${describeDecision('output', out)})`);
  else {
    capture(world, client.host, client.iface, 'out', client.iface.mac, dstMac, p);
    for (const h of Object.values(world.hosts)) {
      if (h === client.host) continue;
      for (const i of h.ifaces) if (i.up && i.segment === client.iface.segment && linkLocal(i)) capture(world, h, i, 'in', client.iface.mac, dstMac, p);
    }
    for (const s of serversOn(world, client.iface.segment!)) {
      const inp = fw(s.host, 'input', p, s.iface.name);
      if (inp.verdict !== 'accept') { notes.push(`${s.host.hostname} runs dhcpd -6 on ${s.iface.name}, but its input chain dropped it (${describeDecision('input', inp)})`); continue; }
      receivers.push(s);
    }
  }
  if (rec && ev) {
    const ok = receivers.length > 0;
    rec.endPacket(ev, receivers[0]?.host.id ?? client.host.id, [], [{ host: client.host.id, egress: client.iface.name, srcMac: client.iface.mac, dstMac, ttl: p.ttl, note: `multicast to all DHCPv6 servers and relay agents (ff02::1:2) on ${client.iface.segment}${ok ? `; received by ${receivers.map((r) => `${r.host.hostname} (dhcpd -6)`).join(', ')}` : ''}${notes.length ? `; ${notes.join('; ')}` : ok ? '' : '; no DHCPv6 server listening on this link'}` }], ok, ok ? `received by ${receivers.map((r) => r.host.id).join(', ')}` : 'no DHCPv6 server received it');
    rec.describe(p.id, title, detail);
  }
  world.clock += 0.4;
  return receivers;
}

/** Server → client link-local, unicast on the link. True when the client's socket received it. */
function unicastToClient(world: World, server: Endpoint, client: Endpoint, p: Packet, title: string, detail: string): boolean {
  const rec = activeRecorder();
  const ev = rec?.beginPacket(world.clock, server.host.id, clonePacket(p));
  let note = '';
  let ok = false;
  const out = fw(server.host, 'output', p, server.iface.name);
  if (out.verdict !== 'accept') note = `dropped by ${server.host.hostname}'s output chain (${describeDecision('output', out)})`;
  else {
    capture(world, server.host, server.iface, 'out', server.iface.mac, client.iface.mac, p);
    capture(world, client.host, client.iface, 'in', server.iface.mac, client.iface.mac, p);
    const inp = fw(client.host, 'input', p, client.iface.name);
    if (inp.verdict !== 'accept') note = `arrived, but ${client.host.hostname}'s input chain dropped it: the request went to a multicast group, so conntrack does not see this reply as part of it (ct state new) and only an explicit "udp dport 546" rule lets it in (${describeDecision('input', inp)})`;
    else { ok = true; note = `unicast to the client's link-local address on ${server.iface.segment}; accepted by ${client.host.hostname}`; }
  }
  if (rec && ev) {
    rec.endPacket(ev, client.host.id, [], [{ host: server.host.id, egress: server.iface.name, srcMac: server.iface.mac, dstMac: client.iface.mac, ttl: p.ttl, note }], ok, ok ? `delivered to dhclient on ${client.host.id}` : `not received by dhclient on ${client.host.id}`);
    rec.describe(p.id, title, detail);
  }
  world.clock += 0.4;
  return ok;
}

function serverLog(world: World, h: Host, m: string, prio: 'info' | 'err' = 'info') {
  log(world, h, 'dhcpd', m, { pid: (h.services.dhcpd.loaded as { pid6?: number } | null)?.pid6 ?? h.services.dhcpd.pid, unit: 'isc-dhcp-server.service', priority: prio });
}

const xidHex = (xid: number) => `0x${xid.toString(16).toUpperCase().padStart(6, '0')}`;
const iaidDecimal = (iaid: string) => parseInt(iaid.replace(/:/g, ''), 16);

/** Lifetimes the server hands out: preferred defaults to 5/8 of valid; T1/T2 = 0.5/0.8 of preferred (RFC 8415 §21.4). */
function lifetimes(cfg: Dhcpd6Config) {
  const valid = cfg.defaultLeaseTime;
  const preferred = Math.min(valid, cfg.preferredLifetime ?? Math.floor(valid * 5 / 8));
  return { valid, preferred, t1: Math.floor(preferred / 2), t2: Math.floor(preferred * 4 / 5) };
}

/** Pick an address the way dhcpd -6 does: the client's current lease, a host reservation, else a pseudo-random pool address. */
function pickAddress(world: World, s: ReturnType<typeof serversOn>[number], duid: string, iaid: string): { address: string; reason: string } | null {
  const leases = parseLeases6(readFile(s.host, LEASES6) ?? '');
  const mine = leases.find((l) => l.duid === duid && l.iaid === iaid && l.state === 'active' && l.ends > world.clock && inPrefix6(l.address, s.subnet.prefix));
  if (mine) return { address: mine.address, reason: 'existing lease' };
  const mac = macOfDuid(duid);
  const host = s.loaded.config.hosts.find((h) => h.fixedAddress && ((h.duid && h.duid === duid) || (h.mac && h.mac === mac)));
  if (host && inPrefix6(host.fixedAddress!, s.subnet.prefix)) return { address: host.fixedAddress!, reason: `host ${host.name}` };
  if (!s.subnet.range) return null;
  const lo = parseIp6(s.subnet.range[0])!;
  const hi = parseIp6(s.subnet.range[1])!;
  const size = hi - lo + 1n;
  if (size <= 0n) return null;
  const taken = new Set([...leases.filter((l) => l.state === 'active' && l.ends > world.clock).map((l) => l.address), ...s.loaded.config.hosts.map((h) => h.fixedAddress).filter(Boolean)]);
  // dhcpd -6 hashes the client's identity into the pool instead of counting up from the start.
  let off = BigInt(seededInt(`dhcp6:${duid}:${iaid}`, 0, 0x7fffffff)) % size;
  for (let n = 0n; n < size && n < 4096n; n++, off = (off + 1n) % size) {
    const a = formatIp6(lo + off);
    if (!taken.has(a)) return { address: a, reason: 'pool' };
  }
  return null;
}

function recordLease(world: World, s: Endpoint, duid: string, iaid: string, a: IaAddr, state: 'active' | 'released') {
  const prev = readFile(s.host, LEASES6) ?? '';
  writeFile(s.host, LEASES6, prev + formatLease6({ iaid, duid, address: a.address, cltt: world.clock, ends: world.clock + (state === 'active' ? a.valid * 1000 : 0), preferred: a.preferred, valid: a.valid, state }), world.clock);
}

/** The server's answer to a client message (null = no answer). */
function serve(world: World, s: ReturnType<typeof serversOn>[number], from: string, m: Dhcp6Msg): Dhcp6Msg | null {
  const name = TYPE[m.type];
  serverLog(world, s.host, `${name} message from ${from} port 546, transaction ID ${xidHex(m.xid)}`);
  // Messages that name a different server are ignored by everyone else.
  if (m.serverDuid && m.serverDuid !== s.loaded.duid) return null;
  const o = { ...s.loaded.config.options, ...s.subnet.options };
  const reply: Dhcp6Msg = { type: m.type === 1 ? 2 : 7, xid: m.xid, clientDuid: m.clientDuid, serverDuid: s.loaded.duid, dns: o.nameServers, search: o.domainSearch };
  if (m.type === 11) {
    serverLog(world, s.host, `Sending Reply to ${from} port 546`);
    return reply;
  }
  if (!m.ia) return null;
  const lt = lifetimes(s.loaded.config);
  if (m.type === 8) {
    if (m.ia.addr) recordLease(world, s, m.clientDuid, m.ia.iaid, { ...m.ia.addr, preferred: 0, valid: 0 }, 'released');
    serverLog(world, s.host, `Sending Reply to ${from} port 546`);
    return { ...reply, dns: undefined, search: undefined };
  }
  // Renew/Rebind keep the client's address while it is still appropriate for the link.
  const keep = (m.type === 5 || m.type === 6) && m.ia.addr && inPrefix6(m.ia.addr.address, s.subnet.prefix) ? m.ia.addr.address : null;
  const pick = keep ? { address: keep, reason: 'renewal' } : pickAddress(world, s, m.clientDuid, m.ia.iaid);
  if (!pick) {
    reply.ia = { iaid: m.ia.iaid, t1: 0, t2: 0, status: 'NoAddrsAvail' };
    serverLog(world, s.host, `Sending ${TYPE[reply.type]} to ${from} port 546`);
    return reply;
  }
  if (pick.reason === 'pool' && m.type === 1) serverLog(world, s.host, `Picking pool address ${pick.address}`);
  const addr: IaAddr = { address: pick.address, preferred: lt.preferred, valid: lt.valid };
  reply.ia = { iaid: m.ia.iaid, t1: lt.t1, t2: lt.t2, addr };
  if (m.type !== 1) recordLease(world, s, m.clientDuid, m.ia.iaid, addr, 'active');
  serverLog(world, s.host, `${m.type === 1 ? 'Advertise' : 'Reply'} NA: address ${pick.address} to client with duid ${m.clientDuid} iaid = ${iaidDecimal(m.ia.iaid)} valid for ${lt.valid} seconds`);
  serverLog(world, s.host, `Sending ${TYPE[reply.type]} to ${from} port 546`);
  return reply;
}

function clientLog(world: World, client: Host, pid: number) {
  return (m: string) => log(world, client, 'dhclient', m, { pid, unit: 'networking.service' });
}

/** One exchange: send `m` to the servers and collect replies that reached the client. */
function exchange(world: World, client: Endpoint, m: Dhcp6Msg, title: string, detail: string, replyTitle: (r: Dhcp6Msg) => string, replyDetail: string): { reply: Dhcp6Msg; from: Endpoint & { linkLocal: string } }[] {
  const src = linkLocal(client.iface)!;
  const p = dhcp6Packet(world, src, ALL_DHCP_SERVERS, m);
  const servers = multicastToServers(world, client, p, title, detail);
  const out: { reply: Dhcp6Msg; from: Endpoint & { linkLocal: string } }[] = [];
  for (const s of servers) {
    const r = serve(world, s, src, m);
    if (!r) continue;
    const ll = linkLocal(s.iface)!;
    const rp = dhcp6Packet(world, ll, src, r);
    if (unicastToClient(world, s, client, rp, replyTitle(r), replyDetail)) out.push({ reply: r, from: { ...s, linkLocal: ll } });
  }
  return out;
}

const XMT_INTERVALS = [1040, 2120, 4310, 8650];

/** Write the address, lease file and resolv.conf the way dhclient-script does for BOUND6/RENEW6. */
function applyBinding(world: World, client: Host, iface: Interface, r: Dhcp6Msg, server: string) {
  const a = r.ia!.addr!;
  const t = world.clock;
  iface.addrs6 = (iface.addrs6 ?? []).filter((x) => !(x.origin === 'dhcp6' && x.address !== a.address));
  if (!iface.addrs6.some((x) => x.address === a.address)) iface.addrs6.unshift({ address: a.address, prefix: 128, scope: 'global', origin: 'dhcp6', validLft: a.valid });
  const b: Dhcp6Binding = {
    server, serverDuid: r.serverDuid!, address: a.address, iaid: r.ia!.iaid, preferred: a.preferred, valid: a.valid, obtained: t,
    renewAt: t + r.ia!.t1 * 1000, rebindAt: t + r.ia!.t2 * 1000, expires: t + a.valid * 1000, state: 'bound',
  };
  iface.dhcp6 = b;
  iface.dhcp6RetryAt = undefined;
  const duid = r.clientDuid;
  const escaped = duid.split(':').map((x) => { const n = parseInt(x, 16); return n >= 0x20 && n < 0x7f && n !== 0x22 && n !== 0x5c ? String.fromCharCode(n) : `\\${n.toString(8).padStart(3, '0')}`; }).join('');
  writeFile(client, `/var/lib/dhcp/dhclient6.${iface.name}.leases`, `default-duid "${escaped}";\nlease6 {\n  interface "${iface.name}";\n  ia-na ${b.iaid} {\n    starts ${Math.floor(t / 1000)};\n    renew ${r.ia!.t1};\n    rebind ${r.ia!.t2};\n    iaaddr ${a.address} {\n      starts ${Math.floor(t / 1000)};\n      preferred-life ${a.preferred};\n      max-life ${a.valid};\n    }\n  }\n  option dhcp6.client-id ${duid.split(':').map((x) => parseInt(x, 16).toString(16)).join(':')};\n  option dhcp6.server-id ${r.serverDuid!.split(':').map((x) => parseInt(x, 16).toString(16)).join(':')};\n${r.dns?.length ? `  option dhcp6.name-servers ${r.dns.join(',')};\n` : ''}${r.search?.length ? `  option dhcp6.domain-search ${r.search.map((d) => `"${d}."`).join(', ')};\n` : ''}}\n`, t);
  if (r.dns?.length || r.search?.length) writeResolvConf(world, client, r);
}

/** Debian's dhclient-script (DHCPv6 branch of make_resolv_conf) replaces /etc/resolv.conf with the DHCPv6 values. */
function writeResolvConf(world: World, client: Host, r: Dhcp6Msg) {
  const old = readFile(client, '/etc/resolv.conf') ?? '';
  const lines = [...(r.search?.length ? [`search ${r.search.map((d) => `${d}.`).join(' ')}`] : [])];
  if (r.dns?.length) lines.push(...r.dns.map((d) => `nameserver ${d}`));
  else lines.push(...old.split('\n').filter((l) => /^\s*nameserver\b/i.test(l)));
  writeFile(client, '/etc/resolv.conf', lines.join('\n') + '\n', world.clock);
}

/**
 * dhclient -6 on `iface`: stateful (SOLICIT/ADVERTISE/REQUEST/REPLY) or, with `stateless`, an
 * INFORMATION-REQUEST for options only. Returns true when the client is configured.
 */
export function dhcp6Acquire(world: World, client: Host, iface: Interface, opts: { retry?: boolean; stateless?: boolean } = {}): boolean {
  const ll = linkLocal(iface);
  const pid = opts.retry ? (iface.dhcp6Pid ?? client.nextPid) : (client.nextPid += 5);
  iface.dhcp6Pid = pid;
  const dl = clientLog(world, client, pid);
  const rec = activeRecorder();
  if (rec) rec.phase = 'DHCP';
  if (!opts.retry) {
    dl('Internet Systems Consortium DHCP Client 4.4.3-P1');
    dl(`Listening on Socket/${iface.name}`);
    dl(`Sending on   Socket/${iface.name}`);
  }
  if (!ll || !iface.up) {
    dl(`Unable to set up socket on ${iface.name}: no link-local address (is the interface up?)`);
    return false;
  }
  const duid = duidLlt(iface.mac);
  const iaid = iaidOf(iface.mac);
  const endpoint = { host: client, iface };
  const xidOf = () => seededInt(`xid6:${client.id}:${world.counter++}`, 1, 0xffffff);
  if (opts.stateless) {
    dl('PRC: Requesting information (INIT).');
    for (const interval of XMT_INTERVALS) {
      const xid = xidOf();
      dl('XMT: Forming Info-Request, 0 ms elapsed.');
      dl(`XMT: Info-Request on ${iface.name}, interval ${interval}ms.`);
      const got = exchange(world, endpoint, { type: 11, xid, clientDuid: duid }, 'DHCPv6 Information-request', 'Stateless DHCPv6: the client already has addresses (SLAAC or static) and only asks for configuration options such as DNS servers and the domain search list. This is what the O ("other configuration") flag in a router advertisement asks for.', () => 'DHCPv6 Reply (options)', 'The server answers with the options only: no IA_NA, no address.');
      if (got.length) {
        const { reply, from } = got[0];
        dl(`RCV: Reply message on ${iface.name} from ${from.linkLocal}.`);
        if (reply.dns?.length || reply.search?.length) writeResolvConf(world, client, reply);
        return true;
      }
      world.clock += interval;
    }
    return false;
  }
  dl('PRC: Soliciting for leases (INIT).');
  let adv: { reply: Dhcp6Msg; from: Endpoint & { linkLocal: string } } | null = null;
  let elapsed = 0;
  for (const interval of XMT_INTERVALS) {
    const xid = xidOf();
    dl(`XMT: Forming Solicit, ${elapsed} ms elapsed.`);
    dl(`XMT:  X-- IA_NA ${iaid}`);
    dl(`XMT: Solicit on ${iface.name}, interval ${interval}ms.`);
    const got = exchange(world, endpoint, { type: 1, xid, clientDuid: duid, ia: { iaid, t1: 3600, t2: 5400 } },
      'DHCPv6 Solicit (multicast)',
      `${client.hostname} sends from its link-local address ${ll} (UDP 546) to ff02::1:2 (UDP 547), the multicast group of all DHCPv6 servers and relay agents on the link. It identifies itself by its DUID (${duid}) and asks for an IA_NA (identity association for non-temporary addresses, IAID ${iaid}). Unlike DHCPv4 there is no broadcast and no MAC-based identity.`,
      (r) => (r.ia?.addr ? `DHCPv6 Advertise ${r.ia.addr.address}` : 'DHCPv6 Advertise (no addresses available)'),
      'The server offers an address for the IA by unicast to the client\'s link-local address, together with its own DUID (server identifier), the preferred and valid lifetimes, T1/T2 and options such as DNS servers. A DHCPv6 reply never contains a default route or a prefix length: those come from router advertisements.');
    if (got.length) { adv = got[0]; break; }
    world.clock += interval;
    elapsed += interval;
  }
  if (!adv) {
    iface.dhcp6RetryAt = world.clock + SOLICIT_RETRY_MS;
    return false;
  }
  dl(`RCV: Advertise message on ${iface.name} from ${adv.from.linkLocal}.`);
  if (!adv.reply.ia?.addr) {
    dl(`RCV:  X-- IA_NA ${iaid}`);
    dl('RCV:  | X-- Status code of NoAddrsAvail.');
    iface.dhcp6RetryAt = world.clock + SOLICIT_RETRY_MS;
    return false;
  }
  const a = adv.reply.ia.addr;
  dl(`RCV:  X-- IA_NA ${iaid}`);
  dl(`RCV:  | X-- t1 - renew  +${adv.reply.ia.t1}`);
  dl(`RCV:  | X-- t2 - rebind +${adv.reply.ia.t2}`);
  dl(`RCV:  | | X-- IAADDR ${a.address}`);
  dl(`RCV:  | | | X-- Preferred lifetime ${a.preferred}.`);
  dl(`RCV:  | | | X-- Max lifetime ${a.valid}.`);
  dl(`RCV:  X-- Server ID: ${adv.reply.serverDuid}`);
  dl('PRC: Selecting best advertised lease.');
  const xid = xidOf();
  dl('XMT: Forming Request, 0 ms elapsed.');
  dl(`XMT:  X-- IA_NA ${iaid}`);
  dl(`XMT:  | | X-- IAADDR ${a.address}`);
  dl(`XMT: Request on ${iface.name}, interval 1000ms.`);
  const got = exchange(world, endpoint, { type: 3, xid, clientDuid: duid, serverDuid: adv.reply.serverDuid, ia: { iaid, t1: 3600, t2: 5400, addr: a } },
    `DHCPv6 Request ${a.address}`,
    'The client asks the server it chose (by its server identifier) for the advertised address. It is still multicast to ff02::1:2; every other server ignores a message that names a different server DUID.',
    () => `DHCPv6 Reply ${a.address}`,
    'The server records the lease in /var/lib/dhcp/dhcpd6.leases and confirms it. dhclient-script installs the address as a /128 (the prefix length comes from the router advertisement\'s on-link prefix, not from DHCPv6) and rewrites /etc/resolv.conf with the DHCPv6 DNS servers.');
  const ack = got.find((g) => g.reply.ia?.addr);
  if (!ack) {
    iface.dhcp6RetryAt = world.clock + SOLICIT_RETRY_MS;
    return false;
  }
  dl(`RCV: Reply message on ${iface.name} from ${ack.from.linkLocal}.`);
  dl(`PRC: Bound to lease ${ack.reply.serverDuid}.`);
  applyBinding(world, client, iface, ack.reply, ack.from.linkLocal);
  dl(`PRC: Renewal event scheduled in ${ack.reply.ia!.t1} seconds, to run for ${ack.reply.ia!.t2 - ack.reply.ia!.t1} seconds.`);
  dl(`PRC: Depreference scheduled in ${a.preferred} seconds.`);
  dl(`PRC: Expiration scheduled in ${a.valid} seconds.`);
  return true;
}

/** RENEW (T1, to the granting server) or REBIND (T2, any server). True when the lease was extended. */
export function dhcp6Renew(world: World, client: Host, iface: Interface, mode: 'renew' | 'rebind'): boolean {
  const b = iface.dhcp6;
  if (!b || !linkLocal(iface)) return false;
  const dl = clientLog(world, client, iface.dhcp6Pid ?? client.nextPid);
  const xid = seededInt(`xid6:${client.id}:${world.counter++}`, 1, 0xffffff);
  const duid = duidLlt(iface.mac);
  const name = mode === 'renew' ? 'Renew' : 'Rebind';
  dl(`XMT: Forming ${name}, 0 ms elapsed.`);
  dl(`XMT: ${name} on ${iface.name}, interval 10240ms.`);
  const got = exchange(world, { host: client, iface }, { type: mode === 'renew' ? 5 : 6, xid, clientDuid: duid, serverDuid: mode === 'renew' ? b.serverDuid : undefined, ia: { iaid: b.iaid, t1: 0, t2: 0, addr: { address: b.address, preferred: b.preferred, valid: b.valid } } },
    `DHCPv6 ${name} ${b.address}`,
    mode === 'renew' ? 'T1 has passed: the client asks the server that granted the lease (named by its DUID) to extend it. The message still goes to ff02::1:2; there is no unicast unless the server sent the "server unicast" option.' : 'T2 has passed without an answer from the original server: the client asks any server on the link (no server identifier) to extend its lease before the valid lifetime runs out.',
    () => `DHCPv6 Reply ${b.address} (extended)`, 'The server extends the lifetimes; nothing else changes on the client.');
  const ok = got.find((g) => g.reply.ia?.addr);
  if (!ok) return false;
  dl(`RCV: Reply message on ${iface.name} from ${ok.from.linkLocal}.`);
  dl(`PRC: Bound to lease ${ok.reply.serverDuid}.`);
  applyBinding(world, client, iface, ok.reply, ok.from.linkLocal);
  return true;
}

/** Drop the DHCPv6 address (lease expired or released). */
export function dropDhcp6(client: Host, iface: Interface): void {
  iface.addrs6 = (iface.addrs6 ?? []).filter((a) => a.origin !== 'dhcp6');
  iface.dhcp6 = undefined;
  void client;
}

/** dhclient -6 -r: RELEASE to the server, then remove the address. */
export function dhcp6Release(world: World, client: Host, iface: Interface): string | null {
  const b = iface.dhcp6;
  if (!b) return null;
  const xid = seededInt(`xid6:${client.id}:${world.counter++}`, 1, 0xffffff);
  exchange(world, { host: client, iface }, { type: 8, xid, clientDuid: duidLlt(iface.mac), serverDuid: b.serverDuid, ia: { iaid: b.iaid, t1: 0, t2: 0, addr: { address: b.address, preferred: 0, valid: 0 } } },
    `DHCPv6 Release ${b.address}`, 'The client gives the address back so the server can mark the lease released.', () => 'DHCPv6 Reply (release confirmed)', 'The server confirms the release.');
  const released = b.address;
  dropDhcp6(client, iface);
  iface.dhcp6RetryAt = undefined;
  return `XMT: Release on ${iface.name}: ${released}`;
}

/** Timer of the next DHCPv6 client event on this interface, if any. */
export function nextEvent6(iface: Interface): number | undefined {
  const b = iface.dhcp6;
  if (b) {
    if (b.state === 'bound') return b.renewAt;
    const until = b.state === 'renewing' ? b.rebindAt : b.expires;
    return Math.min(until, b.nextTry ?? until);
  }
  return iface.dhcp6RetryAt;
}

/** dhclient -6 retransmits RENEW/REBIND with backoff; the simulator tries once a minute. */
const RETRANSMIT_MS = 60_000;

/** Process the DHCPv6 timer that is due at `at` (called by maintainLeases in time order). */
export function stepDhcp6(world: World, host: Host, iface: Interface, at: number, tries: number, now: number): void {
  const b = iface.dhcp6;
  if (!b) {
    if (tries >= 2) {
      // Long outages are summarised: skip to the last retry before now.
      iface.dhcp6RetryAt = at + Math.ceil((now - at) / SOLICIT_RETRY_MS) * SOLICIT_RETRY_MS;
      if (iface.dhcp6RetryAt <= now) iface.dhcp6RetryAt += SOLICIT_RETRY_MS;
      return;
    }
    if (!dhcp6Acquire(world, host, iface, { retry: true }) && (iface.dhcp6RetryAt ?? 0) <= at) iface.dhcp6RetryAt = at + SOLICIT_RETRY_MS;
    return;
  }
  if (b.state === 'bound' || (b.state === 'renewing' && at < b.rebindAt)) {
    if (dhcp6Renew(world, host, iface, 'renew')) {
      // Healthy server: skip ahead to the last renewal before now (as for DHCPv4).
      const nb = iface.dhcp6!;
      const period = nb.renewAt - nb.obtained;
      const skips = period > 0 ? Math.floor((now - nb.renewAt) / period) - 1 : 0;
      if (skips > 0) for (const k of ['obtained', 'renewAt', 'rebindAt', 'expires'] as const) nb[k] += skips * period;
      return;
    }
    b.state = 'renewing';
    b.nextTry = at + RETRANSMIT_MS;
    return;
  }
  if (at < b.expires) {
    b.state = 'rebinding';
    if (dhcp6Renew(world, host, iface, 'rebind')) return;
    b.nextTry = at + RETRANSMIT_MS;
    return;
  }
  log(world, host, 'dhclient', `PRC: Address ${b.address} depreferred.`, { pid: iface.dhcp6Pid ?? host.nextPid, unit: 'networking.service' });
  log(world, host, 'dhclient', `PRC: Discarding expired lease ${b.address}.`, { pid: iface.dhcp6Pid ?? host.nextPid, unit: 'networking.service' });
  dropDhcp6(host, iface);
  iface.dhcp6RetryAt = at;
}

/** Remaining lifetimes of a DHCPv6 address for `ip -6 addr` (valid, preferred in seconds). */
export function dhcp6Lifetimes(iface: Interface, now: number): { valid: number; preferred: number } | null {
  const b = iface.dhcp6;
  if (!b) return null;
  return { valid: Math.max(0, Math.floor((b.expires - now) / 1000)), preferred: Math.max(0, Math.floor((b.obtained + b.preferred * 1000 - now) / 1000)) };
}
