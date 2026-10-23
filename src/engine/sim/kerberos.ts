// Kerberos 5 (MIT krb5 1.20, as in Debian 12): KDC location (krb5.conf or DNS
// SRV records), the AS exchange with encrypted-timestamp pre-authentication,
// the TGS exchange, ticket lifetimes and clock-skew checks, and kadmin (local
// and over the network to kadmind). Requests are real UDP/TCP packets through
// the network model, so routing, firewalls and DNS affect Kerberos as they
// would on real machines.

import { parseResolvConf } from '../config/netconf';
import {
  aclAllows, cachePath, deriveKey, ENCTYPES, formatCache, formatPrincipalDb, newPrincipal, parseCache,
  parseKrb5Conf, parsePrincipalDb, ProfileError, qualify, realmOf,
  type AclEntry, type CachedTicket, type CredCache, type KdcConf, type Krb5Conf, type KeytabEntry, type PrincipalEntry,
} from '../config/krb5';
import { readFile, writeFile } from '../fs';
import type { Host, Packet, World } from '../types';
import { seededInt } from '../util/sha256';
import { dnsQuery, resolve } from './dns';
import { log } from './journal';
import { icmpMeaning, nextId, sendIcmpError, sourceAddress, transmit } from './network';
import { findListener } from './services';
import { tcpConnect } from './tcp';
import { activeRecorder } from './trace';

export const KDC_SERVICE = 'krb5-kdc';
export const KADMIN_SERVICE = 'krb5-admin-server';

/** The host's own idea of the time (its clock may be wrong). */
export function hostTime(world: World, host: Host): number {
  return world.clock + (host.clockOffset ?? 0);
}

export interface KdcLoaded { conf: KdcConf }
export interface KadmindLoaded { conf: KdcConf; acl: AclEntry[]; aclFile: string }

/** MIT error codes the simulator produces, with the library's message text. */
export const KRB_ERRORS = {
  6: { name: 'KDC_ERR_C_PRINCIPAL_UNKNOWN', text: 'Client not found in Kerberos database' },
  7: { name: 'KDC_ERR_S_PRINCIPAL_UNKNOWN', text: 'Server not found in Kerberos database' },
  18: { name: 'KDC_ERR_CLIENT_REVOKED', text: "Client's credentials have been revoked" },
  24: { name: 'KDC_ERR_PREAUTH_FAILED', text: 'Preauthentication failed' },
  25: { name: 'KDC_ERR_PREAUTH_REQUIRED', text: 'Additional pre-authentication required' },
  29: { name: 'KDC_ERR_SVC_UNAVAILABLE', text: 'A service is not available that is required to process the request' },
  31: { name: 'KRB_AP_ERR_BAD_INTEGRITY', text: 'Decrypt integrity check failed' },
  32: { name: 'KRB_AP_ERR_TKT_EXPIRED', text: 'Ticket expired' },
  37: { name: 'KRB_AP_ERR_SKEW', text: 'Clock skew too great' },
} as const;
export type KrbCode = keyof typeof KRB_ERRORS;

const ETYPES_LOG = '2 etypes {aes256-cts-hmac-sha1-96(18), aes128-cts-hmac-sha1-96(17)}';
const ISSUE_ETYPES = 'etypes {rep=aes256-cts-hmac-sha1-96(18), tkt=aes256-cts-hmac-sha1-96(18), ses=aes256-cts-hmac-sha1-96(18)}';

export type KdcRequest =
  | { type: 'AS'; client: string; server: string; realm: string; preauth?: { key: string; time: number }; lifetime: number; renewable: number }
  | { type: 'TGS'; client: string; server: string; realm: string; tgt: CachedTicket; authTime: number };

export type KdcReply =
  | { ok: true; ticket: CachedTicket }
  | { ok: false; code: KrbCode };

// ---------------------------------------------------------------------------
// The KDC
// ---------------------------------------------------------------------------

function dbPath(conf: KdcConf, realm: string): string {
  return conf.realms[realm]?.databaseName ?? '/var/lib/krb5kdc/principal';
}

export function loadDb(host: Host, conf: KdcConf, realm: string): PrincipalEntry[] | null {
  return parsePrincipalDb(readFile(host, dbPath(conf, realm)));
}

export function saveDb(world: World, host: Host, conf: KdcConf, realm: string, db: PrincipalEntry[]): void {
  writeFile(host, dbPath(conf, realm), formatPrincipalDb(db), world.clock, { mode: 0o600 });
}

function kdcLog(world: World, kdc: Host, msg: string, priority: 'info' | 'err' = 'info') {
  log(world, kdc, 'krb5kdc', msg, { pid: kdc.services[KDC_SERVICE]?.pid ?? null, unit: 'krb5-kdc.service', priority });
}

/** What the KDC does with one request (reads the database live, like krb5kdc). */
export function kdcProcess(world: World, kdc: Host, req: KdcRequest, from: string): KdcReply {
  const loaded = kdc.services[KDC_SERVICE]?.loaded as KdcLoaded | undefined;
  const realmConf = loaded?.conf.realms[req.realm];
  const now = hostTime(world, kdc);
  const tag = req.type === 'AS' ? `AS_REQ (${ETYPES_LOG}) ${from}` : `TGS_REQ (${ETYPES_LOG}) ${from}`;
  const fail = (code: KrbCode, what: string): KdcReply => {
    kdcLog(world, kdc, `${tag}: ${what}: ${req.client} for ${req.server}, ${KRB_ERRORS[code].text}`);
    return { ok: false, code };
  };
  if (!loaded || !realmConf) return fail(6, 'CLIENT_NOT_FOUND');
  const db = loadDb(kdc, loaded.conf, req.realm);
  if (!db) return fail(29, 'UNKNOWN_REASON');
  const find = (n: string) => db.find((e) => e.name === n);
  const skew = 300_000;

  if (req.type === 'AS') {
    const client = find(req.client);
    if (!client) return fail(6, 'CLIENT_NOT_FOUND');
    const server = find(req.server);
    if (!server) return fail(7, 'SERVER_NOT_FOUND');
    if (client.attributes.includes('DISALLOW_ALL_TIX')) return fail(18, 'CLIENT_REVOKED');
    if (client.attributes.includes('REQUIRES_PRE_AUTH') && !req.preauth) return fail(25, 'NEEDED_PREAUTH');
    if (req.preauth) {
      if (req.preauth.key !== client.key) {
        client.lastFailed = now;
        client.failedCount += 1;
        saveDb(world, kdc, loaded.conf, req.realm, db);
        kdcLog(world, kdc, `preauth (encrypted_timestamp) verify failure: Preauthentication failed`);
        return fail(24, 'PREAUTH_FAILED');
      }
      if (Math.abs(req.preauth.time - now) > skew) {
        kdcLog(world, kdc, `preauth (encrypted_timestamp) verify failure: Clock skew too great`);
        return fail(37, 'PREAUTH_FAILED');
      }
    }
    client.lastSuccess = now;
    client.failedCount = 0;
    saveDb(world, kdc, loaded.conf, req.realm, db);
    const life = Math.min(req.lifetime, realmConf.maxLife) * 1000;
    const renew = Math.min(req.renewable, realmConf.maxRenewableLife) * 1000;
    const ticket: CachedTicket = { server: req.server, start: now, end: now + life, renewTill: renew > 0 ? now + Math.max(renew, life) : undefined, kvno: server.kvno, serviceKey: server.key };
    kdcLog(world, kdc, `${tag}: ISSUE: authtime ${Math.floor(now / 1000)}, ${ISSUE_ETYPES}, ${req.client} for ${req.server}`);
    return { ok: true, ticket };
  }

  // TGS: the TGT must decrypt with the current krbtgt key, be valid now, and the
  // authenticator's timestamp must be within the allowed skew.
  const krbtgt = find(`krbtgt/${req.realm}@${req.realm}`);
  if (!krbtgt || req.tgt.serviceKey !== krbtgt.key) return fail(31, 'PROCESS_TGS');
  if (req.tgt.end < now) return fail(32, 'PROCESS_TGS');
  if (Math.abs(req.authTime - now) > skew) return fail(37, 'PROCESS_TGS');
  const server = find(req.server);
  if (!server) return fail(7, 'LOOKING_UP_SERVER');
  const ticket: CachedTicket = { server: req.server, start: now, end: Math.min(req.tgt.end, now + realmConf.maxLife * 1000), kvno: server.kvno, serviceKey: server.key };
  kdcLog(world, kdc, `${tag}: ISSUE: authtime ${Math.floor(req.tgt.start / 1000)}, ${ISSUE_ETYPES}, ${req.client} for ${req.server}`);
  return { ok: true, ticket };
}

// ---------------------------------------------------------------------------
// Finding the KDC
// ---------------------------------------------------------------------------

export interface KdcTarget { name: string; ip: string; port: number; transport: 'udp' | 'tcp'; via: 'krb5.conf' | 'DNS SRV' }

function note(world: World, host: Host, title: string, detail: string) {
  activeRecorder()?.internal(world.clock, host.id, title, detail, 'Kerberos');
}

function srvLookup(world: World, host: Host, qname: string): { target: string; port: number; prio: number }[] | null {
  const rc = parseResolvConf(readFile(host, '/etc/resolv.conf'));
  for (const ns of rc.nameservers.length ? rc.nameservers : ['127.0.0.1']) {
    const ex = dnsQuery(world, host, ns, qname, rc.timeout, 'SRV');
    if (ex.outcome === 'timeout' || ex.outcome === 'unreachable' || ex.outcome === 'port-unreachable') continue;
    if (ex.outcome !== 'answer') return [];
    return ex.answer!.answers.filter((a) => a.type === 'SRV').map((a) => {
      const [prio, , port, target] = a.data.split(' ');
      return { target: target.replace(/\.$/, ''), port: Number(port), prio: Number(prio) };
    }).filter((s) => s.target !== '').sort((a, b) => a.prio - b.prio);
  }
  return null;
}

/** KDC (or admin server) addresses for a realm, in the order the library tries them. */
export function locate(world: World, host: Host, conf: Krb5Conf, realm: string, kind: 'kdc' | 'admin'): KdcTarget[] {
  const out: KdcTarget[] = [];
  const defPort = kind === 'kdc' ? 88 : 749;
  const add = (spec: string, via: KdcTarget['via'], transports: ('udp' | 'tcp')[], port?: number) => {
    const m = /^(\[[^\]]+\]|[^:]+)(?::(\d+))?$/.exec(spec.trim());
    if (!m) return;
    const name = m[1].replace(/^\[|\]$/g, '');
    const r = resolve(world, host, name, { family: 4 });
    if (!r.ok) return;
    for (const transport of transports) out.push({ name, ip: r.ip, port: port ?? (m[2] ? Number(m[2]) : defPort), transport, via });
  };
  const rc = conf.realms[realm];
  const listed = kind === 'kdc' ? rc?.kdc ?? [] : rc?.adminServer ? [rc.adminServer] : [];
  if (listed.length) {
    note(world, host, `krb5.conf names the ${kind === 'kdc' ? 'KDC' : 'admin server'} for ${realm}`, `[realms] ${realm} lists ${listed.join(', ')}, so no DNS SRV lookup is made. ${kind === 'kdc' ? 'Requests go over UDP first and fall back to TCP.' : 'kadmin connects to kadmind over TCP port 749.'}`);
    for (const k of listed) add(k, 'krb5.conf', kind === 'kdc' ? ['udp', 'tcp'] : ['tcp']);
    return out;
  }
  if (!conf.dnsLookupKdc) return out;
  const lower = realm.toLowerCase();
  const queries: [string, 'udp' | 'tcp'][] = kind === 'kdc' ? [[`_kerberos._udp.${lower}.`, 'udp'], [`_kerberos._tcp.${lower}.`, 'tcp']] : [[`_kerberos-adm._tcp.${lower}.`, 'tcp']];
  note(world, host, `Locate the ${kind === 'kdc' ? 'KDC' : 'admin server'} for ${realm} in DNS`, `krb5.conf has no ${kind === 'kdc' ? 'kdc' : 'admin_server'} entry for ${realm} and dns_lookup_kdc is on (the default), so the library asks DNS for SRV records: ${queries.map((q) => q[0]).join(' and ')}. Each SRV record names a host and port; the realm name is lower-cased to form the DNS domain.`);
  for (const [q, transport] of queries) {
    for (const s of srvLookup(world, host, q) ?? []) add(s.target, 'DNS SRV', [transport], s.port);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Sending a request to a KDC
// ---------------------------------------------------------------------------

type Exchange = { status: 'reply'; reply: KdcReply; kdc: Host } | { status: 'timeout' | 'refused' | 'unreachable' };

function requestInfo(req: KdcRequest, preauth: boolean): string {
  return req.type === 'AS' ? `AS-REQ ${req.client} → ${req.server}${preauth ? ' (PA-ENC-TIMESTAMP)' : ''}` : `TGS-REQ ${req.client} → ${req.server}`;
}

function replyInfo(r: KdcReply, req: KdcRequest): string {
  if (r.ok) return `${req.type}-REP ticket for ${r.ticket.server} (kvno ${r.ticket.kvno})`;
  return `KRB-ERROR ${KRB_ERRORS[r.code].name}`;
}

function describeRequest(req: KdcRequest): [string, string] {
  if (req.type === 'AS') {
    return req.preauth
      ? ['Kerberos AS-REQ with pre-authentication', `The client asks the Authentication Service for a ticket to ${req.server} again, this time with PA-ENC-TIMESTAMP: its current time (${new Date(req.preauth.time).toISOString()}), encrypted with the key derived from the password. The password itself never crosses the network. The KDC can only decrypt the timestamp if it has the same key, which proves the client knows the password.`]
      : ['Kerberos AS-REQ', `The client asks the Authentication Service (AS) of the KDC for a ticket-granting ticket (TGT): a ticket for the service ${req.server}, valid for ${req.client}. The request is sent in clear text and contains no secret, only names, the requested lifetime and the encryption types the client supports.`];
  }
  return ['Kerberos TGS-REQ', `The client asks the Ticket-Granting Service for a ticket to ${req.server}. It presents its TGT (which only the KDC can decrypt) and an authenticator (its current time, encrypted with the TGT's session key). No password is involved: this is why Kerberos is "single sign-on".`];
}

function describeReply(r: KdcReply, req: KdcRequest): [string, string] {
  if (r.ok) {
    return req.type === 'AS'
      ? ['Kerberos AS-REP: TGT issued', `The KDC returns the TGT (encrypted with the krbtgt key, unreadable for the client) plus a session key encrypted with the client's key. Only a client that knows the password can decrypt that part. The ticket is valid until ${new Date(r.ticket.end).toISOString().replace('.000Z', 'Z')} by the KDC's clock.`]
      : ['Kerberos TGS-REP: service ticket issued', `The KDC returns a ticket for ${r.ticket.server}, encrypted with that service's long-term key (key version ${r.ticket.kvno}). The client cannot read it; it hands it to the server, which decrypts it with the key in its keytab.`];
  }
  const e = KRB_ERRORS[r.code];
  const why: Record<number, string> = {
    6: 'The client principal does not exist in the KDC database (typo, wrong realm, or the account was never created).',
    7: 'There is no principal for the requested service in the KDC database (the service was never registered, or the name differs: host/ names must be the fully qualified host name).',
    18: 'The account is disabled (DISALLOW_ALL_TIX).',
    24: 'The KDC could not decrypt the encrypted timestamp with the stored key: the password is wrong.',
    25: 'Normal first step: the KDC requires pre-authentication (proof of the password) before it issues a TGT, so that attackers cannot request encrypted material for offline password guessing. The client now prompts for the password and retries.',
    29: 'The KDC cannot read its database.',
    31: 'The ticket was not encrypted with the key the KDC has now (the krbtgt key changed).',
    32: 'The TGT has expired. Run kinit again.',
    37: 'The client\'s timestamp differs from the KDC\'s clock by more than 5 minutes (clockskew = 300 s). Kerberos rejects such requests to stop replayed messages. Fix the time (NTP), not the tolerance.',
  };
  return [`Kerberos error: ${e.name}`, `${e.text}. ${why[r.code] ?? ''}`];
}

function exchange(world: World, client: Host, t: KdcTarget, req: KdcRequest): Exchange {
  const rec = activeRecorder();
  const prev = rec?.phase;
  if (rec) rec.phase = 'Kerberos';
  const done = (x: Exchange): Exchange => { if (rec && prev) rec.phase = prev; return x; };
  const size = req.type === 'AS' ? (req.preauth ? 320 : 230) : 640;
  const app = { protocol: 'KRB5' as const, info: requestInfo(req, !!(req.type === 'AS' && req.preauth)), fields: [{ name: 'msg-type', value: req.type === 'AS' ? 'krb-as-req (10)' : 'krb-tgs-req (12)' }, { name: 'cname', value: req.client }, { name: 'sname', value: req.server }, { name: 'realm', value: req.realm }] };
  const replyApp = (r: KdcReply) => ({ protocol: 'KRB5' as const, info: replyInfo(r, req), fields: r.ok ? [{ name: 'msg-type', value: req.type === 'AS' ? 'krb-as-rep (11)' : 'krb-tgs-rep (13)' }, { name: 'ticket', value: `${r.ticket.server}, kvno ${r.ticket.kvno} (encrypted)` }] : [{ name: 'msg-type', value: 'krb-error (30)' }, { name: 'error-code', value: `${KRB_ERRORS[r.code].name} (${r.code})` }], encrypted: false });

  if (t.transport === 'udp') {
    const q: Packet = { id: nextId(world), src: sourceAddress(client, t.ip), dst: t.ip, ttl: 64, proto: 'udp', udp: { sport: seededInt(`krb:${client.id}:${world.counter}`, 40000, 60999), dport: t.port, len: size }, app };
    const d = transmit(world, client.id, q);
    const [qt, qd] = describeRequest(req);
    rec?.describe(q.id, qt, qd);
    if (d.status === 'local-error') return done({ status: 'unreachable' });
    if (d.status !== 'delivered') {
      if (d.error?.delivered) return done({ status: icmpMeaning(d.error.packet) === 'port' ? 'refused' : 'unreachable' });
      world.clock += 1000; // the library waits 1 s for a UDP reply
      return done({ status: 'timeout' });
    }
    const kdc = world.hosts[d.host];
    const fq = d.final;
    if (!findListener(kdc, 'udp', fq.dst, fq.udp!.dport)) {
      const e = sendIcmpError(world, kdc, fq, 'port-unreachable');
      if (!e?.delivered) world.clock += 1000;
      return done({ status: e?.delivered ? 'refused' : 'timeout' });
    }
    const reply = kdcProcess(world, kdc, req, fq.src);
    const r: Packet = { id: nextId(world), src: fq.dst, dst: fq.src, ttl: 64, proto: 'udp', udp: { sport: fq.udp!.dport, dport: fq.udp!.sport, len: reply.ok ? 720 : 140 }, app: replyApp(reply) };
    world.clock += 0.6;
    const back = transmit(world, kdc.id, r);
    const [rt, rd] = describeReply(reply, req);
    rec?.describe(r.id, rt, rd);
    if (back.status !== 'delivered') { world.clock += 1000; return done({ status: 'timeout' }); }
    return done({ status: 'reply', reply, kdc });
  }
  const c = tcpConnect(world, client, t.ip, t.port, { timeoutMs: 10_000 });
  if (rec) rec.phase = 'Kerberos';
  if (!c.ok) return done({ status: c.errno === 'ECONNREFUSED' ? 'refused' : c.errno === 'ETIMEDOUT' ? 'timeout' : 'unreachable' });
  const s = c.conn.send('c2s', size + 4, app);
  const [qt, qd] = describeRequest(req);
  rec?.describe(s.packet.id, `${qt} (TCP)`, qd);
  if (!s.ok) return done({ status: 'timeout' });
  const reply = kdcProcess(world, c.conn.server, req, c.conn.sv.peer);
  const r = c.conn.send('s2c', reply.ok ? 724 : 144, replyApp(reply));
  const [rt, rd] = describeReply(reply, req);
  rec?.describe(r.packet.id, `${rt} (TCP)`, rd);
  c.conn.close('client');
  if (rec) rec.phase = 'Kerberos';
  return done(r.ok ? { status: 'reply', reply, kdc: c.conn.server } : { status: 'timeout' });
}

/** Try each KDC in turn (UDP ones up to three times) until one answers. */
function sendToKdcs(world: World, client: Host, targets: KdcTarget[], req: KdcRequest): KdcReply | null {
  for (const t of targets) {
    const tries = t.transport === 'udp' ? 3 : 1;
    for (let i = 0; i < tries; i++) {
      const x = exchange(world, client, t, req);
      if (x.status === 'reply') return x.reply;
      if (x.status !== 'timeout') break; // refused or unreachable: next KDC at once
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Client operations (kinit, kvno, kadmin)
// ---------------------------------------------------------------------------

export class KrbError extends Error {}

export function clientConf(host: Host): Krb5Conf {
  try {
    return parseKrb5Conf(readFile(host, '/etc/krb5.conf'));
  } catch (e) {
    if (e instanceof ProfileError) throw new KrbError('Improper format of Kerberos configuration file');
    throw e;
  }
}

export function defaultRealm(conf: Krb5Conf): string {
  if (!conf.defaultRealm) throw new KrbError('Configuration file does not specify default realm');
  return conf.defaultRealm;
}

export type KeySource = { password: () => string } | { keytab: KeytabEntry };

/**
 * Get initial credentials (AS exchange) for `principal`, for the service
 * `server` (the TGT by default). Errors are thrown as KrbError with the
 * library's message (callers append " while getting initial credentials").
 */
export function getInitialCreds(world: World, host: Host, principal: string, keys: KeySource, server?: string): CachedTicket {
  const conf = clientConf(host);
  const realm = realmOf(principal);
  const targets = locate(world, host, conf, realm, 'kdc');
  if (!targets.length) throw new KrbError(`Cannot find KDC for realm "${realm}"`);
  const base = { type: 'AS' as const, client: principal, server: server ?? `krbtgt/${realm}@${realm}`, realm, lifetime: conf.ticketLifetime, renewable: conf.renewLifetime };
  let reply = sendToKdcs(world, host, targets, base);
  if (!reply) throw new KrbError(`Cannot contact any KDC for realm '${realm}'`);
  if (!reply.ok && reply.code === 25) {
    const key = 'password' in keys ? deriveKey(principal, keys.password()) : keys.keytab.key;
    note(world, host, 'Encrypt the timestamp with the key', 'password' in keys
      ? 'The client turns the password into a key (string-to-key with the principal name as salt) and encrypts its current time with it.'
      : `The client takes the key for ${principal} (kvno ${keys.keytab.kvno}) from the keytab instead of a password: this is how services and scripts authenticate without a human.`);
    reply = sendToKdcs(world, host, targets, { ...base, preauth: { key, time: hostTime(world, host) } });
    if (!reply) throw new KrbError(`Cannot contact any KDC for realm '${realm}'`);
  }
  if (!reply.ok) {
    if (reply.code === 6) throw new KrbError(`Client '${principal}' not found in Kerberos database`);
    if (reply.code === 24) throw new KrbError('password' in keys ? 'Password incorrect' : 'Preauthentication failed');
    throw new KrbError(KRB_ERRORS[reply.code].text);
  }
  return reply.ticket;
}

export function readCache(host: Host, uid: number): CredCache | null {
  return parseCache(readFile(host, cachePath(uid)));
}

export function writeCache(world: World, host: Host, uid: number, user: string, group: string, cache: CredCache): void {
  writeFile(host, cachePath(uid), formatCache(cache), world.clock, { mode: 0o600, owner: user, group });
}

/** Get a service ticket with the TGT in the cache (reusing a cached ticket that is still valid). */
export function getServiceTicket(world: World, host: Host, cache: CredCache, server: string): { ticket: CachedTicket; cached: boolean } {
  const now = hostTime(world, host);
  const cached = cache.tickets.find((t) => t.server === server && t.end > now);
  if (cached) {
    note(world, host, `Service ticket for ${server} found in the cache`, 'The credential cache already holds a valid ticket for this service, so no request is sent to the KDC. (If the service\'s key changed since, this cached ticket is stale; kdestroy and kinit get a fresh one.)');
    return { ticket: cached, cached: true };
  }
  const realm = realmOf(cache.principal);
  const tgt = cache.tickets.find((t) => t.server === `krbtgt/${realm}@${realm}`);
  if (!tgt) throw new KrbError('Matching credential not found');
  if (tgt.end < now) throw new KrbError('Ticket expired');
  const conf = clientConf(host);
  const targets = locate(world, host, conf, realmOf(server), 'kdc');
  if (!targets.length) throw new KrbError(`Cannot find KDC for realm "${realmOf(server)}"`);
  const reply = sendToKdcs(world, host, targets, { type: 'TGS', client: cache.principal, server, realm, tgt, authTime: now });
  if (!reply) throw new KrbError(`Cannot contact any KDC for realm '${realm}'`);
  if (!reply.ok) throw new KrbError(KRB_ERRORS[reply.code].text);
  return { ticket: reply.ticket, cached: false };
}

// ---------------------------------------------------------------------------
// kadmin: the requests, executed by kadmin.local (directly on the database) or
// by kadmind for a remote kadmin client (after authentication and an ACL check)
// ---------------------------------------------------------------------------

export interface KadminContext {
  world: World;
  kdc: Host;
  conf: KdcConf;
  realm: string;
  /** The principal acting (for "Last modified" and the ACL check). */
  actor: string;
  /** kadmind's ACL for remote requests; undefined for kadmin.local (no ACL). */
  acl?: AclEntry[];
  local: boolean;
  ask(text: string, secret: boolean): string;
}

export interface KadminResult {
  lines: string[];
  /** Keys to write into the caller's keytab (ktadd runs on the client). */
  keytab?: { path: string; entries: KeytabEntry[] };
  /** Remove entries from the caller's keytab. */
  ktremove?: { path: string; principal: string; which: string };
}

function fmtDate(ms: number): string {
  const d = new Date(ms);
  const day = d.toUTCString().slice(0, 3);
  const mon = d.toUTCString().slice(8, 11);
  return `${day} ${mon} ${String(d.getUTCDate()).padStart(2, '0')} ${d.toISOString().slice(11, 19)} UTC ${d.getUTCFullYear()}`;
}

function dur(sec: number): string {
  const d = Math.floor(sec / 86400);
  const rest = sec % 86400;
  return `${d} day${d === 1 ? '' : 's'} ${String(Math.floor(rest / 3600)).padStart(2, '0')}:${String(Math.floor((rest % 3600) / 60)).padStart(2, '0')}:${String(rest % 60).padStart(2, '0')}`;
}

const PERM_NAMES: Record<string, string> = { a: 'add', d: 'delete', m: 'modify', c: 'change-password', i: 'get', l: 'list' };

export function kadminRequest(k: KadminContext, argv: string[]): KadminResult {
  const [cmd, ...args] = argv;
  const out: string[] = [];
  const db = loadDb(k.kdc, k.conf, k.realm);
  if (!db) return { lines: [`kadmin${k.local ? '.local' : ''}: Cannot open DB2 database '${dbPath(k.conf, k.realm)}': No such file or directory while initializing kadmin${k.local ? '.local' : ''} interface`] };
  const now = hostTime(k.world, k.kdc);
  const q = (n: string) => qualify(n, k.realm);
  const allowed = (perm: string, verb: string, what: string): boolean => {
    if (!k.acl || aclAllows(k.acl, k.actor, perm)) return true;
    out.push(`${verb}: Operation requires \`\`${PERM_NAMES[perm]}'' privilege while ${what}.`);
    return false;
  };
  const flag = (f: string) => args.includes(f);
  const opt = (f: string) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : undefined; };
  const positional = args.filter((a, i) => !a.startsWith('-') && !a.startsWith('+') && !['-pw', '-k', '-e', '-policy'].includes(args[i - 1] ?? ''));
  const save = () => saveDb(k.world, k.kdc, k.conf, k.realm, db);
  const askPw = (name: string, verb: string): string | null => {
    const a = k.ask(`Enter password for principal "${name}": `, true);
    const b = k.ask(`Re-enter password for principal "${name}": `, true);
    if (a !== b) { out.push(`${verb}: Password mismatch while reading password for "${name}".`); return null; }
    return a;
  };
  const randomSecret = (name: string) => `random:${name}:${k.world.counter}:${now}`;

  switch (cmd) {
    case 'addprinc': case 'add_principal': case 'ank': {
      if (!positional[0]) return { lines: ['usage: add_principal [options] principal'] };
      const name = q(positional[0]);
      if (!allowed('a', 'add_principal', `creating "${name}"`)) return { lines: out };
      if (db.some((e) => e.name === name)) return { lines: [`add_principal: Principal or policy already exists while creating "${name}".`] };
      out.push(`No policy specified for ${name}; defaulting to no policy`);
      const pw = flag('-randkey') ? randomSecret(name) : opt('-pw') ?? askPw(name, 'add_principal');
      if (pw === null) return { lines: out };
      const attrs = flag('-requires_preauth') ? [] : ['REQUIRES_PRE_AUTH'];
      db.push(newPrincipal(name, pw, now, k.actor, attrs));
      save();
      out.push(`Principal "${name}" created.`);
      return { lines: out };
    }
    case 'delprinc': case 'delete_principal': {
      if (!positional[0]) return { lines: ['usage: delete_principal [-force] principal'] };
      const name = q(positional[0]);
      if (!allowed('d', 'delete_principal', `deleting principal "${name}"`)) return { lines: out };
      if (!db.some((e) => e.name === name)) return { lines: [`delete_principal: Principal does not exist while deleting principal "${name}"`] };
      if (!flag('-force')) {
        const a = k.ask(`Are you sure you want to delete the principal "${name}"? (yes/no): `, false);
        if (a !== 'yes') return { lines: [`Principal "${name}" not deleted`] };
      }
      saveDb(k.world, k.kdc, k.conf, k.realm, db.filter((e) => e.name !== name));
      return { lines: [`Principal "${name}" deleted.`, 'Make sure that you have removed this principal from all ACLs before reusing.'] };
    }
    case 'cpw': case 'change_password': {
      if (!positional[0]) return { lines: ['usage: change_password [-randkey] [-pw password] principal'] };
      const name = q(positional[0]);
      if (!allowed('c', 'change_password', `changing password for "${name}"`)) return { lines: out };
      const e = db.find((x) => x.name === name);
      if (!e) return { lines: [`change_password: Principal does not exist while changing password for "${name}".`] };
      const pw = flag('-randkey') ? randomSecret(name) : opt('-pw') ?? askPw(name, 'change_password');
      if (pw === null) return { lines: out };
      Object.assign(e, { kvno: e.kvno + 1, key: deriveKey(name, pw), lastPwChange: now, modified: now, modifiedBy: k.actor });
      save();
      return { lines: [flag('-randkey') ? `Key for "${name}" randomized.` : `Password for "${name}" changed.`] };
    }
    case 'listprincs': case 'list_principals': case 'getprincs': case 'get_principals': {
      if (!allowed('l', 'get_principals', 'retrieving list')) return { lines: out };
      const glob = positional[0] ? new RegExp(`^${q(positional[0]).replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`) : null;
      return { lines: db.map((e) => e.name).filter((n) => !glob || glob.test(n)).sort() };
    }
    case 'getprinc': case 'get_principal': {
      if (!positional[0]) return { lines: ['usage: get_principal [-terse] principal'] };
      const name = q(positional[0]);
      if (!allowed('i', 'get_principal', `retrieving "${name}"`)) return { lines: out };
      const e = db.find((x) => x.name === name);
      if (!e) return { lines: [`get_principal: Principal does not exist while retrieving "${name}".`] };
      const realm = k.conf.realms[k.realm];
      return {
        lines: [
          `Principal: ${e.name}`, 'Expiration date: [never]', `Last password change: ${fmtDate(e.lastPwChange)}`, 'Password expiration date: [never]',
          `Maximum ticket life: ${dur(realm?.maxLife ?? 86400)}`, `Maximum renewable life: ${dur(realm?.maxRenewableLife ?? 0)}`,
          `Last modified: ${fmtDate(e.modified)} (${e.modifiedBy})`, `Last successful authentication: ${e.lastSuccess ? fmtDate(e.lastSuccess) : '[never]'}`,
          `Last failed authentication: ${e.lastFailed ? fmtDate(e.lastFailed) : '[never]'}`, `Failed password attempts: ${e.failedCount}`, `Number of keys: ${ENCTYPES.length}`,
          ...ENCTYPES.map((t) => `Key: vno ${e.kvno}, ${t}`), 'MKey: vno 1', `Attributes: ${e.attributes.join(' ')}`, 'Policy: [none]',
        ],
      };
    }
    case 'ktadd': case 'xst': {
      if (!positional.length) return { lines: ['Usage: ktadd [-k[eytab] keytab] [-q] [-e keysaltlist] [-norandkey] [principal | -glob princ-exp] [...]'] };
      const norand = flag('-norandkey');
      if (norand && !k.local) return { lines: ['ktadd: Option -norandkey only valid with kadmin.local'] };
      const path = (opt('-k') ?? opt('-keytab') ?? 'FILE:/etc/krb5.keytab').replace(/^(FILE|WRFILE):/, '');
      const entries: KeytabEntry[] = [];
      for (const p of positional) {
        const name = q(p);
        if (!norand && !allowed('c', 'ktadd', `changing key for ${name}`)) continue;
        const e = db.find((x) => x.name === name);
        if (!e) { out.push(`kadmin${k.local ? '.local' : ''}: Principal ${name} does not exist.`); continue; }
        if (!norand) Object.assign(e, { kvno: e.kvno + 1, key: deriveKey(name, randomSecret(name)), lastPwChange: now, modified: now, modifiedBy: k.actor });
        for (const t of ENCTYPES) {
          entries.push({ kvno: e.kvno, principal: name, enctype: t, key: e.key, timestamp: now });
          if (!flag('-q')) out.push(`Entry for principal ${p} with kvno ${e.kvno}, encryption type ${t} added to keytab FILE:${path}.`);
        }
      }
      save();
      return { lines: out, keytab: entries.length ? { path, entries } : undefined };
    }
    case 'ktremove': case 'ktrem': {
      const path = (opt('-k') ?? 'FILE:/etc/krb5.keytab').replace(/^(FILE|WRFILE):/, '');
      if (!positional[0]) return { lines: ['Usage: ktremove [-k[eytab] keytab] [-q] principal [kvno|"all"|"old"]'] };
      return { lines: [], ktremove: { path, principal: q(positional[0]), which: positional[1] ?? 'all' } };
    }
    case '?': case 'help': case 'list_requests': case 'lr':
      return { lines: ['Available kadmin requests:', '', 'add_principal, addprinc, ank     Add principal', 'delete_principal, delprinc       Delete principal', 'change_password, cpw             Change password', 'get_principal, getprinc          Get principal', 'list_principals, listprincs, get_principals, getprincs', '                                 List principals', 'ktadd, xst                       Add entry(s) to a keytab', 'ktremove, ktrem                  Remove entry(s) from a keytab'] };
    default:
      return { lines: [`kadmin${k.local ? '.local' : ''}: Unknown request "${cmd}".  Type "?" for a request list.`] };
  }
}

/** kadmind: authenticate a remote kadmin client and run one request (TCP 749). */
export function kadminRemote(world: World, client: Host, principal: string, password: () => string, argv: string[], ask: (t: string, s: boolean) => string): KadminResult {
  const conf = clientConf(client);
  const realm = realmOf(principal);
  // kadmin gets a ticket for the kadmin/admin service directly with the password (no TGT).
  getInitialCreds(world, client, principal, { password }, `kadmin/admin@${realm}`);
  const targets = locate(world, client, conf, realm, 'admin');
  if (!targets.length) throw new KrbError('Cannot resolve network address for admin server in requested realm');
  const t = targets[0];
  const rec = activeRecorder();
  const c = tcpConnect(world, client, t.ip, t.port, { timeoutMs: 10_000 });
  if (rec) rec.phase = 'Kerberos';
  if (!c.ok) throw new KrbError('Communication failure with server');
  const kdc = c.conn.server;
  const loaded = kdc.services[KADMIN_SERVICE]?.loaded as KadmindLoaded | undefined;
  const s = c.conn.send('c2s', 300, { protocol: 'KADMIN', info: `kadmin ${argv[0] ?? ''} (RPCSEC_GSS, ticket for kadmin/admin)`, fields: [{ name: 'request', value: argv.join(' ') }, { name: 'principal', value: principal }], encrypted: true });
  rec?.describe(s.packet.id, `kadmin request: ${argv[0] ?? ''}`, `kadmin connects to kadmind on TCP ${t.port} and authenticates with the service ticket for kadmin/admin it just obtained. The request is protected by the session key. kadmind then checks its ACL file (${loaded?.aclFile ?? '/etc/krb5kdc/kadm5.acl'}), which it read when it started, to decide whether ${principal} may do this.`);
  if (!s.ok || !loaded) { c.conn.close('client'); throw new KrbError('Communication failure with server'); }
  log(world, kdc, 'kadmind', `Request: kadm5_init, ${principal}, success, client=${principal}, service=kadmin/admin@${realm}, addr=${c.conn.sv.peer}, vers=4, flavor=6`, { pid: kdc.services[KADMIN_SERVICE].pid, unit: 'krb5-admin-server.service' });
  const res = kadminRequest({ world, kdc, conf: loaded.conf, realm, actor: principal, acl: loaded.acl, local: false, ask }, argv);
  const denied = res.lines.some((l) => l.includes('privilege while'));
  log(world, kdc, 'kadmind', `${denied ? 'Unauthorized request' : 'Request'}: ${argv[0] ?? ''}, ${argv.slice(1).filter((a) => !a.startsWith('-')).join(' ')}, ${denied ? 'Operation requires privilege' : 'success'}, client=${principal}, service=kadmin/admin@${realm}, addr=${c.conn.sv.peer}`, { pid: kdc.services[KADMIN_SERVICE].pid, unit: 'krb5-admin-server.service', priority: denied ? 'warning' : 'info' });
  const r = c.conn.send('s2c', 200, { protocol: 'KADMIN', info: denied ? 'kadmin reply: permission denied' : 'kadmin reply: success', fields: [], encrypted: true });
  rec?.describe(r.packet.id, denied ? 'kadmin reply: denied by the ACL' : 'kadmin reply', denied ? `No line of kadm5.acl grants ${principal} this operation.` : 'kadmind executed the request on the database and returns the result (for ktadd: the new keys, which the kadmin client writes into the local keytab).');
  c.conn.close('client');
  return res;
}
