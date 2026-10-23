// Stub-resolver + authoritative-server simulation.
// Follows glibc behaviour: /etc/hosts first (for NSS lookups), then each
// nameserver from /etc/resolv.conf with `timeout`/`attempts`, search-list
// expansion with ndots:1. Queries and responses are real UDP packets routed
// through the network model, so firewalls/routing affect DNS just like SSH.

import { parseHostsFile, parseResolvConf, type ResolvConf } from '../config/netconf';
import { isWindows, WIN_HOSTS_PATH, winResolver } from '../win/model';
import { answerQuery, type DnsAnswer, type ZoneRecord } from '../config/zone';
import { readFile } from '../fs';
import { familyOf, isIpAddress, normAddr } from '../net/addr';
import { ip6Bytes } from '../net/ip6';
import type { Host, Packet, World } from '../types';
import { utf8 } from '../util/sha256';
import { globalAddrs6, hostAddresses, icmpMeaning, nextId, sendIcmpError, sourceAddress, transmit } from './network';
import { activeRecorder } from './trace';
import { findListener, type NamedLoaded } from './services';

export interface DnsExchange {
  server: string;
  qname: string;
  outcome: 'answer' | 'nxdomain' | 'nodata' | 'servfail' | 'refused' | 'timeout' | 'port-unreachable' | 'unreachable';
  answer?: DnsAnswer;
  rttMs: number;
}

export type ResolveResult =
  | { ok: true; ip: string; /** All addresses in getaddrinfo() order (RFC 6724: IPv6 first when usable). */ addrs: string[]; source: 'literal' | 'hosts' | 'dns'; fqdn: string; exchanges: DnsExchange[]; cname?: string[] }
  | { ok: false; error: 'NXDOMAIN' | 'EAI_AGAIN' | 'EAI_NODATA'; exchanges: DnsExchange[]; message: string };

export type QType = 'A' | 'AAAA' | 'SRV' | 'TXT' | 'MX' | 'NS' | 'SOA' | 'CNAME' | 'PTR';
export const QTYPES: QType[] = ['A', 'AAAA', 'SRV', 'TXT', 'MX', 'NS', 'SOA', 'CNAME', 'PTR'];

// --- DNS wire format (RFC 1035) for PCAP export -----------------------------

function encodeName(name: string): number[] {
  const out: number[] = [];
  for (const label of name.replace(/\.$/, '').split('.')) {
    if (!label) continue;
    const b = utf8(label);
    out.push(b.length, ...b);
  }
  out.push(0);
  return out;
}

const QTYPE: Record<string, number> = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33 };

export function encodeDns(id: number, qname: string, response?: { rcode: number; aa: boolean; ra: boolean; answers: ZoneRecord[] }, qtype: QType = 'A'): Uint8Array {
  const b: number[] = [];
  const u16 = (n: number) => b.push((n >> 8) & 255, n & 255);
  const u32 = (n: number) => b.push((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
  u16(id);
  let flags = 0x0100; // RD
  if (response) flags = 0x8000 | 0x0100 | (response.aa ? 0x0400 : 0) | (response.ra ? 0x0080 : 0) | response.rcode;
  u16(flags);
  u16(1);
  u16(response ? response.answers.length : 0);
  u16(0);
  u16(0);
  b.push(...encodeName(qname));
  u16(QTYPE[qtype]);
  u16(1);
  for (const rr of response?.answers ?? []) {
    b.push(...encodeName(rr.name));
    u16(QTYPE[rr.type]);
    u16(1);
    u32(rr.ttl);
    const rdata = rdataBytes(rr);
    u16(rdata.length);
    b.push(...rdata);
  }
  return new Uint8Array(b);
}

function rdataBytes(rr: ZoneRecord): number[] {
  const u16 = (n: number) => [(n >> 8) & 255, n & 255];
  const f = rr.data.split(' ');
  switch (rr.type) {
    case 'A': return rr.data.split('.').map(Number);
    case 'AAAA': return ip6Bytes(rr.data);
    case 'SRV': return [...u16(Number(f[0])), ...u16(Number(f[1])), ...u16(Number(f[2])), ...encodeName(f[3])];
    case 'MX': return [...u16(Number(f[0])), ...encodeName(f[1])];
    case 'TXT': {
      const b = Array.from(utf8(rr.data.replace(/^"|"$/g, ''))).slice(0, 255);
      return [b.length, ...b];
    }
    case 'SOA': return [...encodeName(f[0]), ...encodeName(f[1]), ...f.slice(2, 7).flatMap((n) => { const v = Number(n) >>> 0; return [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255]; })];
    default: return encodeName(rr.data);
  }
}

const RCODE: Record<string, number> = { NOERROR: 0, SERVFAIL: 2, NXDOMAIN: 3, REFUSED: 5 };

let ephemeral = 0;
function ephemeralPort(world: World): number {
  ephemeral = (world.counter * 7919 + 32768) % 28000;
  return 32768 + ephemeral;
}

/** Send one DNS query from `host` to `server` and process the reply. */
export function dnsQuery(world: World, host: Host, server: string, qname: string, timeoutS = 5, qtype: QType = 'A'): DnsExchange {
  const id = (world.counter * 2654435761) & 0xffff;
  const sport = ephemeralPort(world);
  const qbytes = encodeDns(id, qname, undefined, qtype);
  const q: Packet = {
    id: nextId(world), src: sourceAddress(host, server), dst: server, ttl: 64, proto: 'udp',
    udp: { sport, dport: 53, len: qbytes.length },
    app: {
      protocol: 'DNS',
      info: `Standard query 0x${id.toString(16).padStart(4, '0')} ${qtype} ${qname.replace(/\.$/, '')}`,
      fields: [
        { name: 'Transaction ID', value: `0x${id.toString(16).padStart(4, '0')}` },
        { name: 'Flags', value: '0x0100 Standard query (recursion desired)' },
        { name: 'Questions', value: '1' },
        { name: 'Query', value: `${qname.replace(/\.$/, '')}: type ${qtype}, class IN` },
      ],
      bytes: qbytes,
    },
  };
  const start = world.clock;
  const rec = activeRecorder();
  const prevPhase = rec?.phase;
  if (rec) rec.phase = 'DNS';
  const d = transmit(world, host.id, q);
  rec?.describe(q.id, `DNS query: ${qtype} ${qname}`, `The stub resolver sends one UDP datagram from an ephemeral port to ${server}:53 asking for the ${qtype} record${qtype === 'AAAA' ? ' (IPv6 address)' : ''} of "${qname}" with "recursion desired" set. There is no handshake: if the datagram or its answer is lost, the resolver waits for its timeout (${timeoutS} s here) and retries.`);
  if (rec && prevPhase) rec.phase = prevPhase;
  if (d.status === 'local-error') return { server, qname, outcome: 'unreachable', rttMs: 0 };
  if (d.status !== 'delivered') {
    // An ICMP error (port unreachable, admin-prohibited, host unreachable) makes
    // the resolver give up on this server immediately; silence means a timeout.
    if (d.error?.delivered) {
      return { server, qname, outcome: icmpMeaning(d.error.packet) === 'port' ? 'port-unreachable' : 'unreachable', rttMs: world.clock - start };
    }
    world.clock += timeoutS * 1000;
    return { server, qname, outcome: 'timeout', rttMs: timeoutS * 1000 };
  }
  const srv = world.hosts[d.host];
  const fq = d.final;
  const listener = findListener(srv, 'udp', fq.dst, fq.udp!.dport);
  if (!listener) {
    const err = sendIcmpError(world, srv, fq, 'port-unreachable');
    if (err?.delivered) return { server, qname, outcome: 'port-unreachable', rttMs: world.clock - start };
    world.clock += timeoutS * 1000;
    return { server, qname, outcome: 'timeout', rttMs: timeoutS * 1000 };
  }
  let ans: DnsAnswer;
  const wds = isWindows(srv) ? srv.win!.dnsServer : undefined;
  if (wds) {
    // Windows DNS Server: its zones (AD-integrated), otherwise recursion through the forwarders.
    ans = answerQuery(wds.zones, qname, qtype);
    if (ans.rcode === 'REFUSED') {
      ans = { rcode: 'SERVFAIL', answers: [], authoritative: false };
      for (const f of wds.forwarders) {
        const ex = dnsQuery(world, srv, f, qname, 2, qtype);
        if (ex.outcome === 'answer' || ex.outcome === 'nodata') { ans = { rcode: 'NOERROR', answers: ex.answer!.answers as ZoneRecord[], authoritative: false }; break; }
        if (ex.outcome === 'nxdomain') { ans = { rcode: 'NXDOMAIN', answers: [], authoritative: false }; break; }
      }
    }
  } else {
    const loaded = srv.services.named?.loaded as NamedLoaded | undefined;
    ans = answerQuery(loaded?.zones ?? [], qname, qtype);
    const failed = loaded?.failedZones.some((z) => qname.toLowerCase().replace(/\.$/, '').endsWith(z));
    if (failed) ans = { rcode: 'SERVFAIL', answers: [], authoritative: false };
  }
  const rbytes = encodeDns(id, qname, { rcode: RCODE[ans.rcode], aa: ans.authoritative, ra: false, answers: ans.answers }, qtype);
  const r: Packet = {
    id: nextId(world), src: fq.dst, dst: fq.src, ttl: 64, proto: 'udp',
    udp: { sport: fq.udp!.dport, dport: fq.udp!.sport, len: rbytes.length },
    app: {
      protocol: 'DNS',
      info: `Standard query response 0x${id.toString(16).padStart(4, '0')} ${ans.rcode === 'NOERROR' ? '' : ans.rcode.toLowerCase() + ' '}${qtype} ${qname.replace(/\.$/, '')}${ans.answers.map((a) => ` ${a.type} ${a.data}`).join('')}`,
      fields: [
        { name: 'Transaction ID', value: `0x${id.toString(16).padStart(4, '0')}` },
        { name: 'Flags', value: `Standard query response, ${ans.rcode}${ans.authoritative ? ', authoritative' : ''}` },
        { name: 'Answer RRs', value: String(ans.answers.length) },
        ...ans.answers.map((a) => ({ name: 'Answer', value: `${a.name} ${a.ttl} IN ${a.type} ${a.data}` })),
      ],
      bytes: rbytes,
    },
  };
  world.clock += 0.4;
  if (rec) rec.phase = 'DNS';
  const back = transmit(world, srv.id, r);
  rec?.describe(r.id, `DNS response: ${ans.rcode}${ans.answers.length ? ' ' + ans.answers.map((a) => a.data).join(', ') : ''}`, ans.rcode === 'NOERROR'
    ? `${srv.hostname} is authoritative for the zone ("aa" flag) and answers from its loaded zone data. The transaction ID matches the query, which is how the client pairs them.`
    : ans.rcode === 'NXDOMAIN' ? 'The name does not exist in the zone. The resolver will try the next search-domain candidate, if any.'
      : ans.rcode === 'SERVFAIL' ? 'The server is responsible for this zone but could not load it, so it cannot answer. glibc reports this as "Temporary failure in name resolution".'
        : 'The server is not authoritative for this name and does not recurse, so it refuses.');
  if (rec && prevPhase) rec.phase = prevPhase;
  if (back.status !== 'delivered') {
    world.clock += timeoutS * 1000;
    return { server, qname, outcome: 'timeout', rttMs: timeoutS * 1000 };
  }
  const outcome: DnsExchange['outcome'] =
    ans.rcode === 'NXDOMAIN' ? 'nxdomain'
    : ans.rcode === 'SERVFAIL' ? 'servfail'
    : ans.rcode === 'REFUSED' ? 'refused'
    : ans.answers.some((a) => a.type === qtype) ? 'answer' : 'nodata';
  return { server, qname, outcome, answer: ans, rttMs: Math.max(1, world.clock - start) };
}

export function lookupHostsFile(host: Host, name: string): string | undefined {
  return lookupHostsFileAll(host, name)[0];
}

export function lookupHostsFileAll(host: Host, name: string): string[] {
  const n = name.toLowerCase().replace(/\.$/, '');
  return parseHostsFile(readFile(host, isWindows(host) ? WIN_HOSTS_PATH : '/etc/hosts')).filter((e) => e.names.some((x) => x.toLowerCase() === n)).map((e) => e.ip);
}

/** The stub resolver's servers and search list (/etc/resolv.conf, or a Windows host's adapter settings). */
export function resolverConf(host: Host): ResolvConf {
  if (isWindows(host)) return { ...winResolver(host), timeout: 2, attempts: 2 };
  return parseResolvConf(readFile(host, '/etc/resolv.conf'));
}

/**
 * getaddrinfo()-style resolution as used by ssh, ping, nc, curl.
 * family 0 = AF_UNSPEC with AI_ADDRCONFIG: AAAA is only asked for when the host
 * has a global IPv6 address, A only when it has a non-loopback IPv4 address.
 * IPv6 results are sorted first (RFC 6724 default policy).
 */
export function resolve(world: World, host: Host, name: string, opts: { useHostsFile?: boolean; family?: 0 | 4 | 6 } = {}): ResolveResult {
  const fam = opts.family ?? 0;
  const literal = name.replace(/^\[(.*)\]$/, '$1');
  if (isIpAddress(literal)) {
    const ip = normAddr(literal);
    if (fam && familyOf(ip) !== fam) return { ok: false, error: 'EAI_NODATA', exchanges: [], message: 'Address family for hostname not supported' };
    return { ok: true, ip, addrs: [ip], source: 'literal', fqdn: ip, exchanges: [] };
  }
  // Windows answers "localhost" itself (its hosts file entries are commented out).
  if (isWindows(host) && name.toLowerCase() === 'localhost') return { ok: true, ip: '127.0.0.1', addrs: ['127.0.0.1'], source: 'hosts', fqdn: 'localhost', exchanges: [] };
  const has6 = globalAddrs6(host).length > 0;
  const has4 = hostAddresses(host, 4).some((a) => !a.startsWith('127.'));
  const want6 = fam === 6 || (fam === 0 && has6);
  const want4 = fam === 4 || (fam === 0 && (has4 || !has6));
  const order = (addrs: string[]) => [...addrs.filter((a) => a.includes(':')), ...addrs.filter((a) => !a.includes(':'))].filter((a) => (a.includes(':') ? want6 : want4));
  if (opts.useHostsFile !== false) {
    const ips = order(lookupHostsFileAll(host, name));
    if (ips.length) return { ok: true, ip: ips[0], addrs: ips, source: 'hosts', fqdn: name, exchanges: [] };
  }
  const rc = resolverConf(host);
  const exchanges: DnsExchange[] = [];
  if (rc.nameservers.length === 0) rc.nameservers.push('127.0.0.1');
  const dots = (name.match(/\./g) ?? []).length;
  const absolute = name.endsWith('.');
  const candidates = absolute ? [name] : dots >= 1 ? [name + '.', ...rc.search.map((s) => `${name}.${s}.`)] : [...rc.search.map((s) => `${name}.${s}.`), name + '.'];
  const qtypes: QType[] = [...(want4 ? ['A' as const] : []), ...(want6 ? ['AAAA' as const] : [])];
  let sawTempFail = false;
  let sawNodata = false;
  for (const qname of candidates) {
    const found: DnsExchange[] = [];
    for (const qtype of qtypes) {
      let resolved: DnsExchange | null = null;
      outer: for (let attempt = 0; attempt < rc.attempts; attempt++) {
        for (const ns of rc.nameservers) {
          const ex = dnsQuery(world, host, ns, qname, rc.timeout, qtype);
          exchanges.push(ex);
          if (['answer', 'nxdomain', 'nodata'].includes(ex.outcome)) {
            resolved = ex;
            break outer;
          }
        }
      }
      if (!resolved) {
        sawTempFail = true;
        break;
      }
      found.push(resolved);
    }
    if (sawTempFail) break; // glibc stops on timeouts / server failures: EAI_AGAIN
    const answers = found.filter((e) => e.outcome === 'answer');
    if (answers.length) {
      const all = answers.flatMap((e) => e.answer!.answers);
      const addrs = order(all.filter((r) => r.type === 'A' || r.type === 'AAAA').map((r) => r.data));
      const cn = [...new Set(all.filter((r) => r.type === 'CNAME').map((r) => r.data))];
      return { ok: true, ip: addrs[0], addrs, source: 'dns', fqdn: qname.replace(/\.$/, ''), exchanges, cname: cn };
    }
    if (found.some((e) => e.outcome === 'nodata')) sawNodata = true;
  }
  if (sawTempFail) return { ok: false, error: 'EAI_AGAIN', exchanges, message: 'Temporary failure in name resolution' };
  if (sawNodata && fam) return { ok: false, error: 'EAI_NODATA', exchanges, message: 'No address associated with hostname' };
  return { ok: false, error: 'NXDOMAIN', exchanges, message: 'Name or service not known' };
}
