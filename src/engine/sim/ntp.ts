// NTP over the simulated network. A client sends one 48-byte NTPv4 request to
// UDP port 123 and reads the server's clock from the reply; routing, firewalls
// and NAT apply to both datagrams. Servers are chronyd (chrony.conf: server /
// pool upstreams, allow/deny, local stratum, refclock, makestep); clients are
// chronyd and systemd-timesyncd (timesyncd.conf NTP= / FallbackNTP=).
//
// Simplifications: one exchange per poll (no filtering of several samples, no
// frequency discipline), corrections are applied at once, and daemons poll at
// start and when ntpSettle() lets "a few minutes" pass (after boot, before a
// check). NTP never blocks a boot: exchanges leave the world clock unchanged.

import { readFile } from '../fs';
import { inCidr, parseCidr } from '../net/ip';
import { isIpAddress } from '../net/addr';
import type { Host, Packet, ServiceRuntime, World } from '../types';
import { resolve } from './dns';
import { log } from './journal';
import { icmpMeaning, nextId, sendIcmpError, sourceAddress, transmit } from './network';
import { findListener } from './services';
import { activeRecorder } from './trace';

export const CHRONY_VERSION = '4.3';
export const CHRONY_CONF = '/etc/chrony/chrony.conf';
export const TIMESYNCD_CONF_PATH = '/etc/systemd/timesyncd.conf';
const DEBIAN_POOL = ['0.debian.pool.ntp.org', '1.debian.pool.ntp.org', '2.debian.pool.ntp.org', '3.debian.pool.ntp.org'];

/** What a server's reply says about its clock. */
export interface NtpReply {
  /** 0 = normal, 3 = alarm (server not synchronized). */
  leap: 0 | 3;
  stratum: number;
  /** Reference ID as chronyc/timesyncd print it: 8 hex digits. */
  refId: string;
  /** For display: the upstream address, "LOCL" or a refclock name. */
  refName: string;
  /** The server's clock (ms since the epoch) when it answered. */
  serverTime: number;
  rootDelayMs: number;
  rootDispersionMs: number;
}

export type NtpOutcome =
  | { kind: 'reply'; reply: NtpReply; delayMs: number }
  | { kind: 'timeout' }
  | { kind: 'port-unreachable' }
  | { kind: 'unreachable' };

export const ntpSynced = (r: NtpReply) => r.leap !== 3 && r.stratum > 0 && r.stratum < 16;

export function hostClock(world: World, host: Host): number {
  return world.clock + (host.clockOffset ?? 0);
}

const NTP_EPOCH = 2_208_988_800; // seconds between 1900 and 1970

function ntpBytes(mode: 3 | 4, leap: number, stratum: number, refId: string, txMs: number): Uint8Array {
  const b = new Uint8Array(48);
  b[0] = (leap << 6) | (4 << 3) | mode;
  b[1] = stratum;
  b[2] = 6; // poll 2^6 s
  b[3] = 0xe9; // precision 2^-23 s
  const ref = parseInt(refId, 16) >>> 0;
  b[12] = ref >>> 24; b[13] = (ref >>> 16) & 0xff; b[14] = (ref >>> 8) & 0xff; b[15] = ref & 0xff;
  const sec = Math.floor(txMs / 1000) + NTP_EPOCH;
  const frac = Math.floor(((txMs % 1000) / 1000) * 2 ** 32);
  const dv = new DataView(b.buffer);
  dv.setUint32(40, sec >>> 0);
  dv.setUint32(44, frac >>> 0);
  return b;
}

const isoTime = (ms: number) => new Date(Math.floor(ms)).toISOString().replace('T', ' ').replace('Z', ' UTC');

/** Reference ID of an IPv4 upstream, as chronyc prints it (203.0.113.80 → CB007150). */
export function ipRefId(ip: string): string {
  return ip.split('.').map((o) => Number(o).toString(16).padStart(2, '0')).join('').toUpperCase();
}

/**
 * One NTP client/server exchange from `host` to `serverIp`. The world clock is
 * restored afterwards: daemons poll asynchronously, nobody waits for them.
 */
export function ntpExchange(world: World, host: Host, serverIp: string): NtpOutcome {
  const start = world.clock;
  const rec = activeRecorder();
  const prev = rec?.phase;
  if (rec) rec.phase = 'NTP';
  try {
    const sport = 32768 + ((world.counter * 7919) % 28000);
    const tx = hostClock(world, host);
    const q: Packet = {
      id: nextId(world), src: sourceAddress(host, serverIp), dst: serverIp, ttl: 64, proto: 'udp',
      udp: { sport, dport: 123, len: 48 },
      app: {
        protocol: 'NTP', info: 'NTP Version 4, client',
        fields: [{ name: 'Leap Indicator', value: 'unknown (clock unsynchronized)' }, { name: 'Version', value: '4' }, { name: 'Mode', value: 'client (3)' }, { name: 'Transmit Timestamp', value: isoTime(tx) }],
        bytes: ntpBytes(3, 3, 0, '00000000', tx),
      },
    };
    const d = transmit(world, host.id, q);
    rec?.describe(q.id, 'NTP request', `${host.hostname} asks ${serverIp} for the time: one UDP datagram to port 123 carrying its own transmit timestamp. The server copies it into the reply, so the client can compute the round-trip delay and its clock offset.`);
    if (d.status === 'local-error') return { kind: 'unreachable' };
    if (d.status !== 'delivered') {
      if (d.error?.delivered) return icmpMeaning(d.error.packet) === 'port' ? { kind: 'port-unreachable' } : { kind: 'unreachable' };
      return { kind: 'timeout' };
    }
    const srv = world.hosts[d.host];
    const fq = d.final;
    const listener = findListener(srv, 'udp', fq.dst, 123);
    if (!listener) {
      const e = sendIcmpError(world, srv, fq, 'port-unreachable');
      return e?.delivered ? { kind: 'port-unreachable' } : { kind: 'timeout' };
    }
    const reply = listener.process === 'chronyd' ? chronyServe(world, srv, fq.src) : null;
    if (!reply) return { kind: 'timeout' };
    world.clock += 0.2;
    const r: Packet = {
      id: nextId(world), src: fq.dst, dst: fq.src, ttl: 64, proto: 'udp',
      udp: { sport: 123, dport: fq.udp!.sport, len: 48 },
      app: {
        protocol: 'NTP', info: 'NTP Version 4, server',
        fields: [
          { name: 'Leap Indicator', value: reply.leap === 3 ? 'unknown (clock unsynchronized)' : 'no warning' },
          { name: 'Version', value: '4' }, { name: 'Mode', value: 'server (4)' },
          { name: 'Stratum', value: reply.stratum === 16 ? '16 (unsynchronized)' : String(reply.stratum) },
          { name: 'Reference ID', value: reply.refName },
          { name: 'Transmit Timestamp', value: isoTime(reply.serverTime) },
        ],
        bytes: ntpBytes(4, reply.leap, reply.stratum, reply.refId, reply.serverTime),
      },
    };
    const back = transmit(world, srv.id, r);
    rec?.describe(r.id, `NTP reply: stratum ${reply.stratum}${reply.leap === 3 ? ', not synchronized' : ''}`, ntpSynced(reply)
      ? `The server answers with its own clock (stratum ${reply.stratum}, reference ${reply.refName}). The client sets its clock from it.`
      : 'The server answers, but marks itself unsynchronized (leap indicator 3, stratum 16): clients must not use its time.');
    if (back.status !== 'delivered') return { kind: 'timeout' };
    return { kind: 'reply', reply, delayMs: Math.max(0.3, world.clock - start) };
  } finally {
    world.clock = start;
    if (rec && prev) rec.phase = prev;
  }
}

// ---------------------------------------------------------------------------
// chronyd
// ---------------------------------------------------------------------------

export interface ChronySource { name: string; ip?: string; state: '*' | '?' | 'x' | '-'; stratum: number; reach: number; lastRxMs?: number; lastPollMs?: number; offsetMs: number }

export interface ChronyLoaded {
  sources: ChronySource[];
  allow: { cidr: string; deny: boolean }[];
  localStratum?: number;
  refclock?: string;
  makestep?: { threshold: number; limit: number };
  synced: boolean;
  stratum: number;
  refId: string;
  refName: string;
  refTime: number;
  clients: Record<string, { ntp: number; drop: number; last: number }>;
  steps: number;
  /** "Can't synchronise" was logged for the current outage. */
  noSources?: boolean;
}

const CHRONY_KNOWN = new Set(['server', 'pool', 'peer', 'allow', 'deny', 'local', 'makestep', 'driftfile', 'keyfile', 'ntsdumpdir', 'logdir', 'log', 'maxupdateskew', 'rtcsync', 'leapsectz', 'refclock', 'confdir', 'sourcedir', 'include', 'cmdallow', 'bindcmdaddress', 'port', 'hwtimestamp', 'minsources', 'maxdistance']);

/** Parse chrony.conf; returns the loaded state or chronyd's fatal error. */
export function parseChronyConf(text: string, file = CHRONY_CONF): { loaded?: ChronyLoaded; error?: string } {
  const loaded: ChronyLoaded = { sources: [], allow: [], synced: false, stratum: 0, refId: '00000000', refName: '', refTime: 0, clients: {}, steps: 0 };
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].replace(/[#!;%].*$/, '').trim();
    if (!line) continue;
    const [d, ...a] = line.split(/\s+/);
    const at = `at line ${i + 1} in file ${file}`;
    if (!CHRONY_KNOWN.has(d)) return { error: `Fatal error : Invalid directive ${at}` };
    switch (d) {
      case 'server': case 'pool': case 'peer':
        if (!a[0]) return { error: `Fatal error : Could not parse ${d} directive ${at}` };
        loaded.sources.push({ name: a[0], state: '?', stratum: 0, reach: 0, offsetMs: 0 });
        break;
      case 'allow': case 'deny': {
        const cidr = a[0] === 'all' || !a[0] ? '0.0.0.0/0' : a[0].includes('/') ? a[0] : `${a[0]}/32`;
        if (!parseCidr(cidr)) return { error: `Fatal error : Could not parse ${d} directive ${at}` };
        loaded.allow.push({ cidr, deny: d === 'deny' });
        break;
      }
      case 'local': {
        const s = a.indexOf('stratum');
        loaded.localStratum = s >= 0 ? Number(a[s + 1]) : 10;
        break;
      }
      case 'refclock': if (!a.includes('noselect')) loaded.refclock = a.includes('refid') ? a[a.indexOf('refid') + 1] : a[0]; break;
      case 'makestep': loaded.makestep = { threshold: Number(a[0] ?? 1), limit: Number(a[1] ?? 3) }; break;
    }
  }
  return { loaded };
}

/** chrony's access rule: the last matching allow/deny wins; without a match, deny. */
export function chronyAllows(l: ChronyLoaded, ip: string): boolean {
  let ok = false;
  let best = -1;
  for (const r of l.allow) {
    const bits = Number(r.cidr.split('/')[1]);
    const c = parseCidr(r.cidr);
    if (c && inCidr(ip, c) && bits >= best) { best = bits; ok = !r.deny; }
  }
  return ok;
}

/** Answer one NTP request (null: dropped by the allow/deny rules, as chronyd does silently). */
function chronyServe(world: World, srv: Host, clientIp: string): NtpReply | null {
  const rt = srv.services.chrony;
  const l = rt?.loaded as ChronyLoaded | undefined;
  if (!l) return null;
  const c = (l.clients[clientIp] ??= { ntp: 0, drop: 0, last: 0 });
  c.last = world.clock;
  if (!chronyAllows(l, clientIp)) { c.drop++; return null; }
  c.ntp++;
  const local = !l.synced && l.localStratum !== undefined;
  if (!l.synced && !local) return { leap: 3, stratum: 16, refId: '00000000', refName: '(none)', serverTime: hostClock(world, srv), rootDelayMs: 0, rootDispersionMs: 0 };
  return local
    ? { leap: 0, stratum: l.localStratum!, refId: '7F7F0101', refName: 'LOCL', serverTime: hostClock(world, srv), rootDelayMs: 0, rootDispersionMs: 0.01 }
    : { leap: 0, stratum: l.stratum, refId: l.refId, refName: l.refName, serverTime: hostClock(world, srv), rootDelayMs: 1.2, rootDispersionMs: 0.4 };
}

/** Poll chronyd's sources and discipline the clock (start, settle, chronyc makestep). */
export function chronySync(world: World, host: Host, rt: ServiceRuntime, forceStep = false): void {
  const l = rt.loaded as ChronyLoaded | undefined;
  if (!l) return;
  const opts = { pid: rt.pid, unit: 'chrony.service' };
  const was = l.synced ? l.refName : null;
  if (l.refclock) {
    Object.assign(l, { synced: true, stratum: 1, refId: [...l.refclock.padEnd(4, '\0')].map((ch) => ch.charCodeAt(0).toString(16).padStart(2, '0')).join('').toUpperCase(), refName: l.refclock, refTime: hostClock(world, host) });
    if (was !== l.refName) log(world, host, 'chronyd', `Selected source ${l.refclock}`, opts);
    return;
  }
  let chosen: { s: ChronySource; reply: NtpReply } | null = null;
  for (const s of l.sources) {
    if (!s.ip) {
      if (isIpAddress(s.name)) s.ip = s.name;
      else {
        const r = resolve(world, host, s.name, { family: 4 });
        if (r.ok) s.ip = r.ip;
      }
    }
    if (!s.ip) { s.state = '?'; continue; }
    const out = ntpExchange(world, host, s.ip);
    s.lastPollMs = world.clock;
    s.reach = ((s.reach << 1) | (out.kind === 'reply' ? 1 : 0)) & 0xff;
    if (out.kind !== 'reply') { s.state = '?'; continue; }
    s.stratum = out.reply.stratum;
    s.lastRxMs = world.clock;
    s.offsetMs = out.reply.serverTime - hostClock(world, host);
    if (!ntpSynced(out.reply)) { s.state = 'x'; continue; }
    s.state = chosen ? '-' : '*';
    if (!chosen) chosen = { s, reply: out.reply };
  }
  if (!chosen) {
    if (!l.noSources && l.sources.length) log(world, host, 'chronyd', `Can't synchronise: no selectable sources`, opts);
    l.noSources = true;
    Object.assign(l, { synced: false, stratum: 0, refId: '00000000', refName: '', refTime: 0 });
    return;
  }
  const { s, reply } = chosen;
  l.noSources = false;
  const label = s.name === s.ip ? s.ip : `${s.ip} (${s.name})`;
  if (was !== s.ip) log(world, host, 'chronyd', `Selected source ${label}`, opts);
  const off = s.offsetMs;
  if (Math.abs(off) >= 1000) {
    log(world, host, 'chronyd', `System clock wrong by ${(off / 1000).toFixed(6)} seconds`, opts);
    if (forceStep || (l.makestep && (l.makestep.limit < 0 || l.steps < l.makestep.limit) && Math.abs(off) / 1000 > l.makestep.threshold)) {
      host.clockOffset = (host.clockOffset ?? 0) + off;
      l.steps++;
      log(world, host, 'chronyd', `System clock was stepped by ${(off / 1000).toFixed(6)} seconds`, opts);
      s.offsetMs = 0;
    }
    // Without makestep chronyd only slews (at most 83 ms per second): a large error stays for hours.
  } else {
    host.clockOffset = (host.clockOffset ?? 0) + off;
    s.offsetMs = 0;
  }
  Object.assign(l, { synced: true, stratum: Math.min(reply.stratum + 1, 15), refId: ipRefId(s.ip!), refName: s.ip!, refTime: hostClock(world, host) });
  l.steps = Math.max(l.steps, 1);
}

export function chronyLoad(world: World, host: Host, rt: ServiceRuntime, pid: number): boolean {
  const opts = { pid, unit: 'chrony.service' };
  log(world, host, 'chronyd', `chronyd version ${CHRONY_VERSION} starting (+CMDMON +NTP +REFCLOCK +RTC +PRIVDROP +SCFILTER +SIGND +ASYNCDNS +NTS +SECHASH +IPV6 -DEBUG)`, opts);
  const text = readFile(host, CHRONY_CONF);
  if (text === undefined) {
    log(world, host, 'chronyd', `Could not open configuration file ${CHRONY_CONF} : No such file or directory`, { ...opts, priority: 'err' });
    return false;
  }
  const p = parseChronyConf(text);
  if (p.error) {
    log(world, host, 'chronyd', p.error, { ...opts, priority: 'err' });
    return false;
  }
  rt.loaded = p.loaded;
  log(world, host, 'chronyd', 'Frequency -4.112 +/- 0.035 ppm read from /var/lib/chrony/chrony.drift', opts);
  log(world, host, 'chronyd', 'Using right/UTC timezone to obtain leap second data', opts);
  log(world, host, 'chronyd', 'Loaded seccomp filter (level 1)', opts);
  chronySync(world, host, rt);
  return true;
}

// ---------------------------------------------------------------------------
// systemd-timesyncd
// ---------------------------------------------------------------------------

export interface TimesyncLoaded {
  servers: string[];
  synced: boolean;
  /** The server timesyncd talks to (or last tried), for timedatectl timesync-status. */
  current?: { name: string; ip: string };
  last?: NtpReply & { delayMs: number; offsetMs: number };
  packets: number;
  /** A timeout was already logged for the current outage (timesyncd logs it once). */
  failing?: boolean;
}

export function timesyncServers(host: Host): string[] {
  const text = readFile(host, TIMESYNCD_CONF_PATH) ?? '';
  const val = (k: string) => new RegExp(`^${k}=(.*)$`, 'm').exec(text)?.[1].trim();
  const ntp = val('NTP');
  if (ntp) return ntp.split(/\s+/);
  const fb = val('FallbackNTP');
  return fb !== undefined ? fb.split(/\s+/).filter(Boolean) : DEBIAN_POOL;
}

/** One polling round of systemd-timesyncd: try the servers in order until one gives a usable reply. */
export function timesyncSync(world: World, host: Host, rt: ServiceRuntime): void {
  const l = rt.loaded as TimesyncLoaded;
  const opts = { pid: rt.pid, unit: 'systemd-timesyncd.service' };
  for (const name of l.servers) {
    let ip = isIpAddress(name) ? name : undefined;
    if (!ip) {
      const r = resolve(world, host, name, { family: 4 });
      if (!r.ok) continue;
      ip = r.ip;
    }
    l.current = { name, ip };
    const out = ntpExchange(world, host, ip);
    if (out.kind === 'timeout') {
      if (!l.failing) log(world, host, 'systemd-timesyncd', `Timed out waiting for reply from ${ip}:123 (${name}).`, opts);
      l.failing = true;
      l.synced = false;
      l.last = undefined;
      continue;
    }
    if (out.kind !== 'reply') { l.last = undefined; l.synced = false; continue; }
    l.packets++;
    l.failing = false;
    const offsetMs = out.reply.serverTime - hostClock(world, host);
    l.last = { ...out.reply, delayMs: out.delayMs, offsetMs };
    // timesyncd drops replies from unsynchronized servers (logged at debug level only).
    if (!ntpSynced(out.reply)) { l.synced = false; continue; }
    const first = !l.synced;
    host.clockOffset = (host.clockOffset ?? 0) + offsetMs;
    if (first) {
      const now = hostClock(world, host);
      log(world, host, 'systemd-timesyncd', `Contacted time server ${ip}:123 (${name}).`, opts);
      log(world, host, 'systemd-timesyncd', `Initial clock synchronization to ${new Date(now).toUTCString().slice(0, 3)} ${new Date(now).toISOString().replace('T', ' ').replace('Z', '')} UTC.`, opts);
    }
    l.synced = true;
    return;
  }
  l.synced = false;
}

export function timesyncLoad(world: World, host: Host, rt: ServiceRuntime): void {
  rt.loaded = { servers: timesyncServers(host), synced: false, packets: 0 } satisfies TimesyncLoaded;
  timesyncSync(world, host, rt);
}

/** Is this host's clock disciplined by a working NTP source (what timedatectl calls "synchronized")? */
export function clockSynchronized(host: Host): boolean {
  const ts = host.services['systemd-timesyncd'];
  const ch = host.services.chrony;
  return (ts?.state === 'active' && !!(ts.loaded as TimesyncLoaded | null)?.synced)
    || (ch?.state === 'active' && !!(ch.loaded as ChronyLoaded | null)?.synced);
}

/**
 * Let the NTP daemons poll again, as they would over the next minutes: servers
 * with reference clocks first, then the other chronyd instances (twice, so a
 * chain of servers converges), then the clients.
 */
export function ntpSettle(world: World): void {
  const hosts = Object.values(world.hosts);
  const chrony = hosts.filter((h) => h.services.chrony?.state === 'active');
  const ordered = [...chrony.filter((h) => (h.services.chrony.loaded as ChronyLoaded | null)?.refclock), ...chrony.filter((h) => !(h.services.chrony.loaded as ChronyLoaded | null)?.refclock)];
  for (let pass = 0; pass < 2; pass++) for (const h of ordered) chronySync(world, h, h.services.chrony);
  for (const h of hosts) if (h.services['systemd-timesyncd']?.state === 'active' && h.services['systemd-timesyncd'].loaded) timesyncSync(world, h, h.services['systemd-timesyncd']);
}
