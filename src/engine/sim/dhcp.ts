// DHCP (RFC 2131) between dhclient and ISC dhcpd on the same Ethernet segment.
// DISCOVER and REQUEST are broadcast (every host on the segment sees them),
// OFFER and ACK are unicast to the client's MAC (Linux dhclient does not set
// the broadcast flag). Both firewalls are consulted. Leases persist in the
// server's /var/lib/dhcp/dhcpd.leases, so allocations survive reboots.

import { evaluate } from '../config/nft';
import { type DhcpdConfig, type DhcpSubnet, type Lease, formatLease, parseLeases } from '../config/dhcpd';
import { readFile, writeFile } from '../fs';
import { formatIp, inCidr, parseCidr, parseIp, prefixMask } from '../net/ip';
import type { Host, Interface, Packet, World } from '../types';
import { seededInt } from '../util/sha256';
import { log } from './journal';
import { capture, nextId } from './network';
import { activeRecorder } from './trace';

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

/** BOOTP/DHCP message bytes (RFC 2131 §2, RFC 2132 options) for PCAP export. */
export function encodeDhcp(op: 1 | 2, type: number, xid: number, mac: string, fields: { yiaddr?: string; siaddr?: string; ciaddr?: string }, opts: [number, number[]][]): Uint8Array {
  const b: number[] = [op, 1, 6, 0, ...u32(xid), 0, 0, 0, 0, ...ipb(fields.ciaddr ?? '0.0.0.0'), ...ipb(fields.yiaddr ?? '0.0.0.0'), ...ipb(fields.siaddr ?? '0.0.0.0'), 0, 0, 0, 0];
  const chaddr = mac.split(':').map((x) => parseInt(x, 16));
  b.push(...chaddr, ...new Array(10).fill(0), ...new Array(64).fill(0), ...new Array(128).fill(0));
  b.push(99, 130, 83, 99, 53, 1, type);
  for (const [code, val] of opts) b.push(code, val.length, ...val);
  b.push(255);
  while (b.length < 300) b.push(0);
  return new Uint8Array(b);
}

const TYPE_NAME: Record<number, string> = { 1: 'DHCPDISCOVER', 2: 'DHCPOFFER', 3: 'DHCPREQUEST', 5: 'DHCPACK', 6: 'DHCPNAK', 7: 'DHCPRELEASE' };

function dhcpPacket(world: World, src: string, dst: string, op: 1 | 2, type: number, xid: number, mac: string, fields: { yiaddr?: string; siaddr?: string; ciaddr?: string }, opts: [number, number[]][], extra: { name: string; value: string }[]): Packet {
  const bytes = encodeDhcp(op, type, xid, mac, fields, opts);
  return {
    id: nextId(world), src, dst, ttl: 64, proto: 'udp',
    udp: { sport: op === 1 ? 68 : 67, dport: op === 1 ? 67 : 68, len: bytes.length },
    app: {
      protocol: 'DHCP',
      info: `${TYPE_NAME[type]} - Transaction ID 0x${xid.toString(16).padStart(8, '0')}${fields.yiaddr ? ` (${fields.yiaddr})` : ''}`,
      fields: [
        { name: 'Message type', value: `${op === 1 ? 'Boot Request (1)' : 'Boot Reply (2)'}, option 53 = ${TYPE_NAME[type]}` },
        { name: 'Transaction ID', value: `0x${xid.toString(16).padStart(8, '0')}` },
        { name: 'Client MAC (chaddr)', value: mac },
        ...(fields.ciaddr ? [{ name: 'Client IP (ciaddr)', value: fields.ciaddr }] : []),
        ...(fields.yiaddr ? [{ name: 'Your IP (yiaddr)', value: fields.yiaddr }] : []),
        ...extra,
      ],
      bytes,
    },
  };
}

interface ServerCandidate { host: Host; iface: Interface; loaded: DhcpdLoaded; subnet: DhcpSubnet }

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

const LEASES = '/var/lib/dhcp/dhcpd.leases';

/** Choose an address for `mac` the way dhcpd does: fixed host, existing lease, then first free in range. */
export function chooseAddress(config: DhcpdConfig, subnet: DhcpSubnet, leases: Lease[], mac: string, now: number): { ip: string; reason: 'fixed-address' | 'previous lease' | 'pool' } | null {
  const fixed = config.hosts.find((h) => h.mac === mac && h.fixedAddress);
  if (fixed) return { ip: fixed.fixedAddress!, reason: 'fixed-address' };
  const mine = leases.find((l) => l.mac === mac && inCidr(l.ip, parseCidr(`${subnet.network}/${subnet.prefix}`)!));
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
  const opts: [number, number[]][] = [[54, ipb(s.iface.address!)], [51, u32(leaseTime)], [1, u32(prefixMask(s.subnet.prefix))]];
  if (o.routers) opts.push([3, o.routers.flatMap(ipb)]);
  if (o.domainNameServers) opts.push([6, o.domainNameServers.flatMap(ipb)]);
  if (o.domainName) opts.push([15, [...new TextEncoder().encode(o.domainName)]]);
  return opts;
}

function firewallAllows(world: World, h: Host, p: Packet, iif: string): boolean {
  const r = evaluate(h.nft, 'input', { src: p.src, dst: p.dst, proto: 'udp', sport: p.udp!.sport, dport: p.udp!.dport, iif, ctState: 'new', len: 328 });
  void world;
  return r.verdict === 'accept';
}

/** Send a broadcast on the client's segment; returns the servers that accepted it. */
function broadcast(world: World, client: Host, iface: Interface, p: Packet, title: string, detail: string): ServerCandidate[] {
  const rec = activeRecorder();
  const ev = rec?.beginPacket(world.clock, client.id, p);
  capture(world, client, iface, 'out', iface.mac, BCAST_MAC, p);
  const reached: ServerCandidate[] = [];
  for (const h of Object.values(world.hosts)) {
    if (h === client) continue;
    for (const i of h.ifaces) if (i.up && i.segment === iface.segment) capture(world, h, i, 'in', iface.mac, BCAST_MAC, p);
  }
  for (const s of serversOnSegment(world, iface.segment!)) if (firewallAllows(world, s.host, p, s.iface.name)) reached.push(s);
  if (rec && ev) {
    rec.endPacket(ev, reached[0]?.host.id ?? client.id, [], [{ host: client.id, egress: iface.name, srcMac: iface.mac, dstMac: BCAST_MAC, ttl: 64, note: `broadcast on ${iface.segment}: every host on the segment receives it${reached.length ? `; DHCP server(s) listening: ${reached.map((r) => r.host.hostname).join(', ')}` : '; no DHCP server accepted it'}` }], reached.length > 0, reached.length ? `received by ${reached.map((r) => r.host.id).join(', ')}` : 'no DHCP server answered');
    rec.describe(p.id, title, detail);
  }
  world.clock += 0.4;
  return reached;
}

function unicastReply(world: World, s: ServerCandidate, client: Host, iface: Interface, p: Packet, title: string, detail: string): boolean {
  const rec = activeRecorder();
  const ev = rec?.beginPacket(world.clock, s.host.id, p);
  capture(world, s.host, s.iface, 'out', s.iface.mac, iface.mac, p);
  capture(world, client, iface, 'in', s.iface.mac, iface.mac, p);
  const ok = firewallAllows(world, client, p, iface.name);
  if (rec && ev) {
    rec.endPacket(ev, client.id, [], [{ host: s.host.id, egress: s.iface.name, srcMac: s.iface.mac, dstMac: iface.mac, ttl: 64, note: `unicast to the client MAC ${iface.mac} (the client has no IP address yet; the server uses chaddr from the request)` }], ok, ok ? `delivered to ${client.id}` : `dropped by ${client.hostname}'s input chain`);
    rec.describe(p.id, title, detail);
  }
  world.clock += 0.4;
  return ok;
}

/** dhclient: obtain a lease on `iface`. Configures the interface on success. */
export function dhcpAcquire(world: World, client: Host, iface: Interface): DhcpLease | null {
  const pid = (client.nextPid += 5);
  const dl = (m: string) => log(world, client, 'dhclient', m, { pid, unit: 'networking.service' });
  const xid = seededInt(`xid:${client.id}:${world.counter}`, 1, 0x7fffffff) >>> 0;
  const rec = activeRecorder();
  if (rec) rec.phase = 'DHCP';
  dl(`Internet Systems Consortium DHCP Client 4.4.3-P1`);
  dl(`Listening on LPF/${iface.name}/${iface.mac}`);
  dl(`Sending on   LPF/${iface.name}/${iface.mac}`);
  let offer: { s: ServerCandidate; ip: string } | null = null;
  let interval = 3;
  for (let attempt = 0; attempt < 6 && !offer; attempt++) {
    dl(`DHCPDISCOVER on ${iface.name} to 255.255.255.255 port 67 interval ${interval}`);
    const disc = dhcpPacket(world, '0.0.0.0', '255.255.255.255', 1, 1, xid, iface.mac, {}, [[55, [1, 3, 6, 15, 51, 54]], [12, [...new TextEncoder().encode(client.hostname)]]], [{ name: 'Parameter request list', value: 'subnet mask, router, DNS servers, domain name, lease time, server id' }]);
    const servers = broadcast(world, client, iface, disc, 'DHCPDISCOVER (broadcast)', 'The client has no address, so it sends from 0.0.0.0:68 to the broadcast address 255.255.255.255:67 in a frame to ff:ff:ff:ff:ff:ff. Every host on the segment receives it; only DHCP servers listening on that segment answer. Broadcasts do not cross routers (a DHCP relay would be needed).');
    for (const s of servers) {
      const sp = s.host.services.dhcpd.pid;
      const slog = (m: string, prio: 'info' | 'err' = 'info') => log(world, s.host, 'dhcpd', m, { pid: sp, unit: 'isc-dhcp-server.service', priority: prio });
      slog(`DHCPDISCOVER from ${iface.mac} (${client.hostname}) via ${s.iface.name}`);
      const ip = allocate(world, s, iface.mac);
      if (!ip) {
        slog(`DHCPDISCOVER from ${iface.mac} (${client.hostname}) via ${s.iface.name}: network ${s.subnet.network}/${s.subnet.prefix}: no free leases`, 'err');
        continue;
      }
      slog(`DHCPOFFER on ${ip} to ${iface.mac} (${client.hostname}) via ${s.iface.name}`);
      const off = dhcpPacket(world, s.iface.address!, ip, 2, 2, xid, iface.mac, { yiaddr: ip, siaddr: s.iface.address! }, options(s, s.loaded.config.defaultLeaseTime), [{ name: 'Offered options', value: describeOpts(s) }]);
      if (unicastReply(world, s, client, iface, off, `DHCPOFFER ${ip}`, `${s.host.hostname} picks an address for this MAC (a host reservation, the client's previous lease, or the first free address of the pool) and offers it together with the subnet mask, router, DNS servers and lease time.`)) {
        offer = { s, ip };
        dl(`DHCPOFFER of ${ip} from ${s.iface.address}`);
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
    return null;
  }
  const { s, ip } = offer;
  dl(`DHCPREQUEST for ${ip} on ${iface.name} to 255.255.255.255 port 67`);
  const req = dhcpPacket(world, '0.0.0.0', '255.255.255.255', 1, 3, xid, iface.mac, {}, [[50, ipb(ip)], [54, ipb(s.iface.address!)]], [{ name: 'Requested IP (option 50)', value: ip }, { name: 'Server identifier (option 54)', value: s.iface.address! }]);
  const got = broadcast(world, client, iface, req, `DHCPREQUEST ${ip} (broadcast)`, 'The client accepts one offer by broadcasting a REQUEST naming the chosen server (option 54). Broadcasting it tells any other server that offered an address that its offer was declined.');
  if (!got.some((g) => g.host.id === s.host.id)) {
    dl('No DHCPOFFERS received.');
    return null;
  }
  const sp = s.host.services.dhcpd.pid;
  log(world, s.host, 'dhcpd', `DHCPREQUEST for ${ip} (${s.iface.address}) from ${iface.mac} (${client.hostname}) via ${s.iface.name}`, { pid: sp, unit: 'isc-dhcp-server.service' });
  const leaseTime = s.loaded.config.defaultLeaseTime;
  const leasesPath = LEASES;
  const prev = readFile(s.host, leasesPath) ?? '';
  writeFile(s.host, leasesPath, prev + formatLease({ ip, mac: iface.mac, hostname: client.hostname, starts: world.clock, ends: world.clock + leaseTime * 1000, state: 'active' }), world.clock);
  log(world, s.host, 'dhcpd', `DHCPACK on ${ip} to ${iface.mac} (${client.hostname}) via ${s.iface.name}`, { pid: sp, unit: 'isc-dhcp-server.service' });
  const ack = dhcpPacket(world, s.iface.address!, ip, 2, 5, xid, iface.mac, { yiaddr: ip, siaddr: s.iface.address! }, options(s, leaseTime), [{ name: 'Options', value: describeOpts(s) }]);
  if (!unicastReply(world, s, client, iface, ack, `DHCPACK ${ip}`, `The server records the lease in /var/lib/dhcp/dhcpd.leases and confirms it. The client now configures ${ip}/${s.subnet.prefix}, a default route via the offered router and the DNS servers (written to /etc/resolv.conf by dhclient-script).`)) return null;
  const o = { ...s.loaded.config.options, ...s.subnet.options };
  const lease: DhcpLease = { address: ip, prefix: s.subnet.prefix, routers: o.routers ?? [], dns: o.domainNameServers ?? [], domain: o.domainName, server: s.iface.address!, leaseTime };
  dl(`DHCPACK of ${ip} from ${s.iface.address}`);
  dl(`bound to ${ip} -- renewal in ${Math.floor(leaseTime / 2)} seconds.`);
  applyLease(world, client, iface, lease);
  return lease;
}

function describeOpts(s: ServerCandidate): string {
  const o = { ...s.loaded.config.options, ...s.subnet.options };
  return [`mask /${s.subnet.prefix}`, o.routers ? `router ${o.routers.join(', ')}` : 'no router', o.domainNameServers ? `DNS ${o.domainNameServers.join(', ')}` : 'no DNS', o.domainName ? `domain ${o.domainName}` : ''].filter(Boolean).join('; ');
}

export function applyLease(world: World, host: Host, iface: Interface, lease: DhcpLease): void {
  iface.address = lease.address;
  iface.prefix = lease.prefix;
  host.routes = host.routes.filter((r) => !(r.dest === 'default' && r.dev === iface.name));
  if (lease.routers[0]) host.routes.push({ dest: 'default', via: lease.routers[0], dev: iface.name, proto: 'boot' });
  const rc = [`domain ${lease.domain ?? ''}`.trim(), lease.domain ? `search ${lease.domain}` : '', ...lease.dns.map((d) => `nameserver ${d}`)].filter((l) => l && l !== 'domain').join('\n') + '\n';
  writeFile(host, '/etc/resolv.conf', rc, world.clock);
  writeFile(host, `/var/lib/dhcp/dhclient.${iface.name}.leases`, `lease {\n  interface "${iface.name}";\n  fixed-address ${lease.address};\n  option subnet-mask ${formatIp(prefixMask(lease.prefix))};\n${lease.routers.length ? `  option routers ${lease.routers.join(',')};\n` : ''}${lease.dns.length ? `  option domain-name-servers ${lease.dns.join(',')};\n` : ''}  option dhcp-server-identifier ${lease.server};\n  option dhcp-lease-time ${lease.leaseTime};\n}\n`, world.clock);
}

/** dhclient -r: send DHCPRELEASE and deconfigure the interface. */
export function dhcpRelease(world: World, client: Host, iface: Interface): string | null {
  const leaseText = readFile(client, `/var/lib/dhcp/dhclient.${iface.name}.leases`) ?? '';
  const server = /dhcp-server-identifier ([\d.]+);/.exec(leaseText)?.[1];
  if (!iface.address || !server) return null;
  const s = serversOnSegment(world, iface.segment!).find((c) => c.iface.address === server);
  if (s) {
    const leases = parseLeases(readFile(s.host, '/var/lib/dhcp/dhcpd.leases') ?? '');
    const l = leases.find((x) => x.ip === iface.address);
    if (l) writeFile(s.host, '/var/lib/dhcp/dhcpd.leases', (readFile(s.host, '/var/lib/dhcp/dhcpd.leases') ?? '') + formatLease({ ...l, state: 'free', ends: world.clock }), world.clock);
    log(world, s.host, 'dhcpd', `DHCPRELEASE of ${iface.address} from ${iface.mac} (${client.hostname}) via ${s.iface.name} (found)`, { pid: s.host.services.dhcpd.pid, unit: 'isc-dhcp-server.service' });
  }
  const released = iface.address;
  iface.address = null;
  iface.prefix = null;
  client.routes = client.routes.filter((r) => r.dev !== iface.name);
  return `DHCPRELEASE of ${released} on ${iface.name} to ${server} port 67`;
}
