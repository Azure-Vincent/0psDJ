// Stub-resolver + authoritative-server simulation.
// Follows glibc behaviour: /etc/hosts first (for NSS lookups), then each
// nameserver from /etc/resolv.conf with `timeout`/`attempts`, search-list
// expansion with ndots:1. Queries and responses are real UDP packets routed
// through the network model, so firewalls/routing affect DNS just like SSH.

import { parseHostsFile, parseResolvConf } from '../config/netconf';
import { answerQuery, type DnsAnswer, type ZoneRecord } from '../config/zone';
import { readFile } from '../fs';
import { isIp } from '../net/ip';
import type { Host, Packet, World } from '../types';
import { utf8 } from '../util/sha256';
import { nextId, sendIcmpError, sourceAddress, transmit } from './network';
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
  | { ok: true; ip: string; source: 'literal' | 'hosts' | 'dns'; fqdn: string; exchanges: DnsExchange[]; cname?: string[] }
  | { ok: false; error: 'NXDOMAIN' | 'EAI_AGAIN'; exchanges: DnsExchange[]; message: string };

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

const QTYPE: Record<string, number> = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16 };

export function encodeDns(id: number, qname: string, response?: { rcode: number; aa: boolean; ra: boolean; answers: ZoneRecord[] }): Uint8Array {
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
  u16(1);
  u16(1);
  for (const rr of response?.answers ?? []) {
    b.push(...encodeName(rr.name));
    u16(QTYPE[rr.type]);
    u16(1);
    u32(rr.ttl);
    const rdata = rr.type === 'A' ? rr.data.split('.').map(Number) : encodeName(rr.data);
    u16(rdata.length);
    b.push(...rdata);
  }
  return new Uint8Array(b);
}

const RCODE: Record<string, number> = { NOERROR: 0, SERVFAIL: 2, NXDOMAIN: 3, REFUSED: 5 };

let ephemeral = 0;
function ephemeralPort(world: World): number {
  ephemeral = (world.counter * 7919 + 32768) % 28000;
  return 32768 + ephemeral;
}

/** Send one DNS query from `host` to `server` and process the reply. */
export function dnsQuery(world: World, host: Host, server: string, qname: string, timeoutS = 5): DnsExchange {
  const id = (world.counter * 2654435761) & 0xffff;
  const sport = ephemeralPort(world);
  const qbytes = encodeDns(id, qname);
  const q: Packet = {
    id: nextId(world), src: sourceAddress(host, server), dst: server, ttl: 64, proto: 'udp',
    udp: { sport, dport: 53, len: qbytes.length },
    app: {
      protocol: 'DNS',
      info: `Standard query 0x${id.toString(16).padStart(4, '0')} A ${qname.replace(/\.$/, '')}`,
      fields: [
        { name: 'Transaction ID', value: `0x${id.toString(16).padStart(4, '0')}` },
        { name: 'Flags', value: '0x0100 Standard query (recursion desired)' },
        { name: 'Questions', value: '1' },
        { name: 'Query', value: `${qname.replace(/\.$/, '')}: type A, class IN` },
      ],
      bytes: qbytes,
    },
  };
  const start = world.clock;
  const rec = activeRecorder();
  const prevPhase = rec?.phase;
  if (rec) rec.phase = 'DNS';
  const d = transmit(world, host.id, q);
  rec?.describe(q.id, `DNS query: A ${qname}`, `The stub resolver sends one UDP datagram from an ephemeral port to ${server}:53 asking for the A record of "${qname}" with "recursion desired" set. There is no handshake: if the datagram or its answer is lost, the resolver waits for its timeout (${timeoutS} s here) and retries.`);
  if (rec && prevPhase) rec.phase = prevPhase;
  if (d.status === 'local-error') return { server, qname, outcome: 'unreachable', rttMs: 0 };
  if (d.status !== 'delivered') {
    // An ICMP error (port unreachable, admin-prohibited, host unreachable) makes
    // the resolver give up on this server immediately; silence means a timeout.
    if (d.error?.delivered) {
      return { server, qname, outcome: d.error.packet.icmp?.code === 3 ? 'port-unreachable' : 'unreachable', rttMs: world.clock - start };
    }
    world.clock += timeoutS * 1000;
    return { server, qname, outcome: 'timeout', rttMs: timeoutS * 1000 };
  }
  const srv = world.hosts[d.host];
  const listener = findListener(srv, 'udp', server, 53);
  if (!listener) {
    const err = sendIcmpError(world, srv, q, 'port-unreachable');
    if (err?.delivered) return { server, qname, outcome: 'port-unreachable', rttMs: world.clock - start };
    world.clock += timeoutS * 1000;
    return { server, qname, outcome: 'timeout', rttMs: timeoutS * 1000 };
  }
  const loaded = srv.services.named?.loaded as NamedLoaded | undefined;
  let ans: DnsAnswer = answerQuery(loaded?.zones ?? [], qname);
  const failed = loaded?.failedZones.some((z) => qname.toLowerCase().replace(/\.$/, '').endsWith(z));
  if (failed) ans = { rcode: 'SERVFAIL', answers: [], authoritative: false };
  const rbytes = encodeDns(id, qname, { rcode: RCODE[ans.rcode], aa: ans.authoritative, ra: false, answers: ans.answers });
  const r: Packet = {
    id: nextId(world), src: server, dst: q.src, ttl: 64, proto: 'udp',
    udp: { sport: 53, dport: sport, len: rbytes.length },
    app: {
      protocol: 'DNS',
      info: `Standard query response 0x${id.toString(16).padStart(4, '0')} ${ans.rcode === 'NOERROR' ? '' : ans.rcode.toLowerCase() + ' '}A ${qname.replace(/\.$/, '')}${ans.answers.map((a) => ` ${a.type} ${a.data}`).join('')}`,
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
    : ans.answers.some((a) => a.type === 'A') ? 'answer' : 'nodata';
  return { server, qname, outcome, answer: ans, rttMs: Math.max(1, world.clock - start) };
}

export function lookupHostsFile(host: Host, name: string): string | undefined {
  const n = name.toLowerCase().replace(/\.$/, '');
  return parseHostsFile(readFile(host, '/etc/hosts')).find((e) => e.names.some((x) => x.toLowerCase() === n))?.ip;
}

/** getaddrinfo()-style resolution as used by ssh, ping, nc, curl. */
export function resolve(world: World, host: Host, name: string, opts: { useHostsFile?: boolean } = {}): ResolveResult {
  if (isIp(name)) return { ok: true, ip: name, source: 'literal', fqdn: name, exchanges: [] };
  if (opts.useHostsFile !== false) {
    const ip = lookupHostsFile(host, name);
    if (ip) return { ok: true, ip, source: 'hosts', fqdn: name, exchanges: [] };
  }
  const rc = parseResolvConf(readFile(host, '/etc/resolv.conf'));
  const exchanges: DnsExchange[] = [];
  if (rc.nameservers.length === 0) rc.nameservers.push('127.0.0.1');
  const dots = (name.match(/\./g) ?? []).length;
  const absolute = name.endsWith('.');
  const candidates = absolute ? [name] : dots >= 1 ? [name + '.', ...rc.search.map((s) => `${name}.${s}.`)] : [...rc.search.map((s) => `${name}.${s}.`), name + '.'];
  let sawAnswerless = false;
  let sawTempFail = false;
  for (const qname of candidates) {
    let resolved: DnsExchange | null = null;
    outer: for (let attempt = 0; attempt < rc.attempts; attempt++) {
      for (const ns of rc.nameservers) {
        const ex = dnsQuery(world, host, ns, qname, rc.timeout);
        exchanges.push(ex);
        if (['answer', 'nxdomain', 'nodata'].includes(ex.outcome)) {
          resolved = ex;
          break outer;
        }
      }
    }
    if (!resolved) {
      sawTempFail = true;
      break; // glibc stops on timeouts / server failures: EAI_AGAIN
    }
    if (resolved.outcome === 'answer') {
      const a = resolved.answer!.answers.filter((r) => r.type === 'A');
      const cn = resolved.answer!.answers.filter((r) => r.type === 'CNAME').map((r) => r.data);
      return { ok: true, ip: a[0].data, source: 'dns', fqdn: qname.replace(/\.$/, ''), exchanges, cname: cn };
    }
    sawAnswerless = true;
  }
  if (sawTempFail) return { ok: false, error: 'EAI_AGAIN', exchanges, message: 'Temporary failure in name resolution' };
  void sawAnswerless;
  return { ok: false, error: 'NXDOMAIN', exchanges, message: 'Name or service not known' };
}
