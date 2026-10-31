// RADIUS with FreeRADIUS 3.2 as Debian 12 packages it (/etc/freeradius/3.0):
// clients.conf says which NAS may ask and with which shared secret, the ldap
// module looks users and groups up in Active Directory over LDAPS (with a
// service account) and checks passwords by binding as the user, and the files
// module (mods-config/files/authorize) decides by group. The NAS side is
// radtest (freeradius-utils) and pam_radius_auth, which lets sshd ask RADIUS.
//
// What matters for troubleshooting, as on a real server:
//  - a request from an address no client{} covers is ignored (logged on the
//    server; the NAS sees no reply);
//  - with a wrong shared secret a request carrying a Message-Authenticator is
//    dropped (radtest times out); one without it (pam_radius) is answered, but
//    the NAS cannot verify the reply's Response Authenticator;
//  - clients.conf is only read at start: a HUP (systemctl reload) re-reads the
//    modules, not the clients.

import { readFile, writeFile } from '../fs';
import type { Host, Packet, ServiceRuntime, World } from '../types';
import { inCidr, parseCidr } from '../net/ip';
import { isIpAddress } from '../net/addr';
import { resolve } from './dns';
import { log } from './journal';
import { type LdapClientConf, type LdapError, ldapBind, ldapConnect, ldapSearch, parseFilter, parseLdapUri } from './ldap';
import { nextId, sendIcmpError, sourceAddress, transmit } from './network';
import { findListener, type Listener } from './services';
import { activeRecorder } from './trace';

export const RADDB = '/etc/freeradius/3.0';
export const CLIENTS_CONF = `${RADDB}/clients.conf`;
export const LDAP_MODULE = `${RADDB}/mods-enabled/ldap`;
export const AUTHORIZE_FILE = `${RADDB}/mods-config/files/authorize`;
export const RADIUS_LOG = '/var/log/freeradius/radius.log';
export const PAM_RADIUS_CONF = '/etc/pam_radius_auth.conf';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface RadClient { name: string; ipaddr: string; secret: string; shortname: string; requireMA: boolean }
export interface LdapModule { server: string; port?: number; identity: string; password: string; baseDn: string; userFilter: string; caFile: string; requireCert: LdapClientConf['reqcert'] }
export interface AuthEntry { name: string; checks: { attr: string; op: string; value: string }[]; replies: { attr: string; value: string }[]; fallThrough: boolean }
export interface RadiusdLoaded { pid: number; clients: RadClient[]; ldap: LdapModule | null; entries: AuthEntry[]; nextId: number; started: number }

type ConfError = { file: string; line: number; msg: string };

/** A FreeRADIUS configuration file as nested sections of "name [label] { key = value }". */
interface Section { name: string; label?: string; line: number; items: Record<string, string>; children: Section[] }

function parseSections(text: string, file: string): Section | ConfError {
  const root: Section = { name: '', line: 0, items: {}, children: [] };
  const stack = [root];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].replace(/(^|\s)#.*$/, '').trim();
    if (!line) continue;
    const open = /^([A-Za-z0-9_.-]+)(?:\s+([^\s{]+))?\s*\{$/.exec(line);
    if (open) {
      const s: Section = { name: open[1], label: open[2], line: i + 1, items: {}, children: [] };
      stack[stack.length - 1].children.push(s);
      stack.push(s);
      continue;
    }
    if (line === '}') {
      if (stack.length === 1) return { file, line: i + 1, msg: 'Too many closing braces' };
      stack.pop();
      continue;
    }
    const kv = /^([A-Za-z0-9_.-]+)\s*=\s*(.*)$/.exec(line);
    if (kv) { stack[stack.length - 1].items[kv[1]] = kv[2].trim().replace(/^(['"])(.*)\1$/, '$2'); continue; }
    if (/^\$INCLUDE\b|^[A-Za-z0-9_.-]+$/.test(line)) continue;
    return { file, line: i + 1, msg: `Expecting section start brace '{' after "${line.split(/\s+/).slice(0, 2).join(' ')}"` };
  }
  if (stack.length > 1) return { file, line: stack[stack.length - 1].line, msg: `Failed to find closing brace for section "${stack[stack.length - 1].name}"` };
  return root;
}

const isErr = (x: unknown): x is ConfError => !!x && typeof x === 'object' && 'msg' in x;

function loadClients(host: Host): RadClient[] | ConfError {
  const root = parseSections(readFile(host, CLIENTS_CONF) ?? '', CLIENTS_CONF);
  if (isErr(root)) return root;
  const out: RadClient[] = [];
  for (const s of root.children.filter((c) => c.name === 'client')) {
    const ipaddr = s.items.ipaddr ?? s.items.ipv4addr ?? s.items.ipv6addr ?? s.label ?? '';
    if (!s.items.secret) return { file: CLIENTS_CONF, line: s.line, msg: `Missing secret for client "${s.label ?? ''}"` };
    if (!ipaddr || !(parseCidr(ipaddr.includes('/') ? ipaddr : `${ipaddr}/32`) || ipaddr === '*')) return { file: CLIENTS_CONF, line: s.line, msg: `No IP address defined for client ${s.label ?? ''}` };
    out.push({ name: s.label ?? ipaddr, ipaddr, secret: s.items.secret, shortname: s.items.shortname ?? s.label ?? ipaddr, requireMA: /^(yes|true)$/i.test(s.items.require_message_authenticator ?? 'no') });
  }
  return out;
}

function loadLdap(host: Host): LdapModule | null | ConfError {
  const text = readFile(host, LDAP_MODULE);
  if (text === undefined) return null;
  const root = parseSections(text, LDAP_MODULE);
  if (isErr(root)) return root;
  const m = root.children.find((c) => c.name === 'ldap');
  if (!m) return null;
  const sub = (n: string) => m.children.find((c) => c.name === n)?.items ?? {};
  const base = m.items.base_dn ?? '';
  const exp = (v: string | undefined) => (v ?? '').replace(/\$\{\.\.base_dn\}/g, base);
  if (!m.items.server) return { file: LDAP_MODULE, line: m.line, msg: 'Configuration item "server" must be set' };
  const reqcert = (sub('tls').require_cert ?? 'allow').toLowerCase();
  return {
    server: m.items.server, port: m.items.port ? Number(m.items.port) : undefined,
    identity: m.items.identity ?? '', password: m.items.password ?? '', baseDn: base,
    userFilter: exp(sub('user').filter) || '(uid=%{%{Stripped-User-Name}:-%{User-Name}})',
    caFile: sub('tls').ca_file ?? '/etc/ssl/certs/ca-certificates.crt',
    requireCert: (['never', 'allow', 'try', 'demand', 'hard'].includes(reqcert) ? reqcert : 'demand') as LdapClientConf['reqcert'],
  };
}

/** mods-config/files/authorize: "NAME check-items" lines, then indented reply items. */
export function parseAuthorize(text: string): AuthEntry[] | ConfError {
  const out: AuthEntry[] = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i].replace(/(^|\s)#.*$/, '');
    if (!raw.trim()) continue;
    const items = (s: string) => s.split(/,\s*(?=[A-Za-z-]+\s*[:=!<>]=?)/).map((x) => x.trim()).filter(Boolean);
    const attr = (s: string) => /^([A-Za-z0-9-]+)\s*(==|:=|=|!=|\+=)\s*(.*)$/.exec(s);
    if (/^\s/.test(raw)) {
      const e = out[out.length - 1];
      if (!e) return { file: AUTHORIZE_FILE, line: i + 1, msg: 'Entry does not begin with a user name' };
      for (const it of items(raw)) {
        const a = attr(it);
        if (!a) return { file: AUTHORIZE_FILE, line: i + 1, msg: `Parse error (reply) for entry ${e.name}: Expecting operator` };
        if (a[1].toLowerCase() === 'fall-through') e.fallThrough = /^(yes|1)$/i.test(a[3]);
        else e.replies.push({ attr: a[1], value: a[3].replace(/^"(.*)"$/, '$1') });
      }
      continue;
    }
    const m = /^(\S+)\s*(.*)$/.exec(raw.trim())!;
    const e: AuthEntry = { name: m[1], checks: [], replies: [], fallThrough: false };
    for (const it of items(m[2])) {
      const a = attr(it);
      if (!a) return { file: AUTHORIZE_FILE, line: i + 1, msg: `Parse error (check) for entry ${e.name}: Expecting operator` };
      e.checks.push({ attr: a[1], op: a[2], value: a[3].replace(/^"(.*)"$/, '$1') });
    }
    out.push(e);
  }
  return out;
}

function radLog(world: World, host: Host, level: 'Info' | 'Error' | 'Auth' | 'Warning', msg: string): void {
  const d = new Date(Math.floor(world.clock));
  const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const p2 = (n: number) => String(n).padStart(2, '0');
  const stamp = `${DAYS[d.getUTCDay()]} ${MONTHS[d.getUTCMonth()]} ${p2(d.getUTCDate())} ${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())} ${d.getUTCFullYear()}`;
  const prev = readFile(host, RADIUS_LOG) ?? '';
  writeFile(host, RADIUS_LOG, `${prev}${stamp} : ${level}: ${msg}\n`, world.clock, { owner: 'freerad', group: 'freerad', mode: 0o640 });
}

/** What "freeradius -C" checks: every file parses and every client has an address and a secret. */
export function radiusdCheck(host: Host): ConfError | { clients: RadClient[]; ldap: LdapModule | null; entries: AuthEntry[] } {
  const clients = loadClients(host);
  if (isErr(clients)) return clients;
  const ldap = loadLdap(host);
  if (isErr(ldap)) return ldap;
  const entries = parseAuthorize(readFile(host, AUTHORIZE_FILE) ?? '');
  if (isErr(entries)) return entries;
  return { clients, ldap, entries };
}

export const confErrorText = (e: ConfError) => `${e.file}[${e.line}]: ${e.msg}`;

export function radiusdStart(world: World, host: Host, rt: ServiceRuntime): RadiusdLoaded | null {
  const pid = rt.pid ?? 0;
  const c = radiusdCheck(host);
  if (isErr(c)) {
    log(world, host, 'freeradius', confErrorText(c), { pid, unit: 'freeradius.service', priority: 'err' });
    log(world, host, 'freeradius', 'Errors reading or parsing /etc/freeradius/3.0/radiusd.conf', { pid, unit: 'freeradius.service', priority: 'err' });
    return null;
  }
  radLog(world, host, 'Info', 'Debugger not attached');
  radLog(world, host, 'Info', 'Loaded virtual server <default>');
  radLog(world, host, 'Info', 'Ready to process requests');
  return { pid, clients: c.clients, ldap: c.ldap, entries: c.entries, nextId: 0, started: world.clock };
}

/** HUP: modules (ldap, files) are re-read; clients and listeners stay as they were loaded at start. */
export function radiusdReload(world: World, host: Host, rt: ServiceRuntime): boolean {
  const l = rt.loaded as RadiusdLoaded | null;
  if (!l) return false;
  const ldap = loadLdap(host);
  const entries = parseAuthorize(readFile(host, AUTHORIZE_FILE) ?? '');
  if (isErr(ldap) || isErr(entries)) {
    radLog(world, host, 'Error', `${confErrorText((isErr(ldap) ? ldap : entries) as ConfError)}`);
    radLog(world, host, 'Error', 'Failed to reload modules: keeping the previous configuration');
    return true;
  }
  l.ldap = ldap;
  l.entries = entries;
  radLog(world, host, 'Info', 'Received HUP signal');
  radLog(world, host, 'Info', 'HUP - Re-reading configuration files');
  return true;
}

export function radiusdListeners(rt: ServiceRuntime): Listener[] {
  const l = rt.loaded as RadiusdLoaded | null;
  if (!l) return [];
  const mk = (addr: string, port: number): Listener => ({ proto: 'udp', addr, port, process: 'freeradius', pid: l.pid, service: 'freeradius' });
  return [mk('0.0.0.0', 1812), mk('0.0.0.0', 1813), mk('127.0.0.1', 18120)];
}

// ---------------------------------------------------------------------------
// One Access-Request
// ---------------------------------------------------------------------------

export interface RadiusRequest {
  user: string;
  password: string;
  secret: string;
  /** radtest/radclient add a Message-Authenticator; pam_radius_auth 2.0 does not. */
  messageAuthenticator: boolean;
  nasPort?: number;
  callingStation?: string;
}

export type RadiusResult =
  | { kind: 'timeout'; id: number; sport: number }
  | { kind: 'accept' | 'reject'; id: number; sport: number; from: string; reply: { attr: string; value: string }[]; verified: boolean };

function clientFor(l: RadiusdLoaded, src: string): RadClient | undefined {
  // The most specific match wins, as in FreeRADIUS's client tree.
  return l.clients
    .filter((c) => c.ipaddr === '*' || (c.ipaddr.includes('/') ? inCidr(src, parseCidr(c.ipaddr)!) : c.ipaddr === src))
    .sort((a, b) => Number(b.ipaddr.split('/')[1] ?? 32) - Number(a.ipaddr.split('/')[1] ?? 32))[0];
}

const ldapFail = (e: LdapError) => `${e.name}${e.info ? `: ${e.info}` : ''}`;

/** The server's decision for a request it accepted from a known client. */
function authorize(world: World, srv: Host, l: RadiusdLoaded, user: string, password: string, n: number, clientLabel: string): { accept: boolean; reply: { attr: string; value: string }[] } {
  const reject = (why: string | null, reply: { attr: string; value: string }[] = []) => {
    radLog(world, srv, 'Auth', `(${n}) Login incorrect${why ? ` (${why})` : ''}: [${user}] (${clientLabel})`);
    return { accept: false, reply };
  };
  const m = l.ldap;
  if (!m) return reject('No Auth-Type found: rejecting the user via Post-Auth-Type = Reject');
  const uri = parseLdapUri(m.server.includes('://') ? m.server : `ldap://${m.server}`);
  if (!uri) return reject('rlm_ldap (ldap): Invalid server URI');
  if (m.port) uri.port = m.port;
  const conf: LdapClientConf = { caFile: m.caFile, reqcert: m.requireCert };
  const target = `${uri.scheme}://${uri.host}:${uri.port}`;
  // Service connection: bind as the identity, then search for the user.
  const c = ldapConnect(world, srv, uri, conf);
  if ('error' in c) {
    radLog(world, srv, 'Error', `(${n}) ldap: Bind with ${m.identity} to ${target} failed: ${c.error.name}`);
    if (c.error.info) radLog(world, srv, 'Error', `(${n}) ldap: Server said: ${c.error.info}`);
    radLog(world, srv, 'Error', `(${n}) ldap: No connections available and at max connection limit`);
    return reject('rlm_ldap (ldap): No connections available');
  }
  const be = ldapBind(world, c.session, srv, m.identity, m.password);
  if (be) {
    radLog(world, srv, 'Error', `(${n}) ldap: Bind with ${m.identity} to ${target} failed: ${be.name}`);
    if (be.info) radLog(world, srv, 'Error', `(${n}) ldap: Server said: ${be.info}`);
    return reject('rlm_ldap (ldap): Bind failed');
  }
  const filterText = m.userFilter.replace(/%\{%\{Stripped-User-Name\}:-%\{User-Name\}\}|%\{User-Name\}|%\{Stripped-User-Name\}/g, user.replace(/[*()\\]/g, (ch) => `\\${ch.charCodeAt(0).toString(16)}`));
  const f = parseFilter(filterText);
  if (!f) return reject(`rlm_ldap (ldap): Bad search filter: ${filterText}`);
  const r = ldapSearch(c.session, m.baseDn, 'sub', f, ['*']);
  if (r.error) {
    radLog(world, srv, 'Error', `(${n}) ldap: Failed performing search: ${ldapFail(r.error)}`);
    return reject('rlm_ldap (ldap): Search failed');
  }
  const entry = r.entries[0];
  if (!entry) return reject('No Auth-Type found: rejecting the user via Post-Auth-Type = Reject');
  const groups = (Object.entries(entry.attrs).find(([k]) => k.toLowerCase() === 'memberof')?.[1] ?? []).map((dn) => /^CN=([^,]+)/i.exec(dn)?.[1] ?? dn);
  // files: the first matching entry decides (unless it says Fall-Through).
  const reply: { attr: string; value: string }[] = [];
  let authType: string | null = null;
  for (const e of l.entries) {
    if (e.name !== 'DEFAULT' && e.name.toLowerCase() !== user.toLowerCase()) continue;
    let match = true;
    for (const ch of e.checks) {
      const a = ch.attr.toLowerCase();
      if (a === 'ldap-group' || a === 'ldap-group-name') {
        const isMember = groups.some((g) => g.toLowerCase() === ch.value.toLowerCase()) || false;
        if ((ch.op === '==' && !isMember) || (ch.op === '!=' && isMember)) match = false;
      } else if (a === 'auth-type' && ch.op === ':=') authType = ch.value;
      else if (ch.op !== ':=' && ch.op !== '=') match = false; // a comparison with an attribute the request does not carry (Framed-Protocol == PPP …)
    }
    if (!match) { if (e.checks.some((ch) => ch.attr.toLowerCase() === 'auth-type')) authType = null; continue; }
    reply.push(...e.replies.map((x) => ({ attr: x.attr, value: x.value.replace(/%\{User-Name\}/g, user) })));
    if (!e.fallThrough) break;
  }
  if (authType && authType.toLowerCase() === 'reject') return reject(null, reply);
  // Authenticate: bind as the user with the password from the request.
  const c2 = ldapConnect(world, srv, uri, conf);
  if ('error' in c2) return reject('rlm_ldap (ldap): No connections available');
  const ue = ldapBind(world, c2.session, srv, entry.dn, password);
  if (ue) {
    radLog(world, srv, 'Error', `(${n}) ldap: Bind as user "${entry.dn}" failed: ${ldapFail(ue)}`);
    return reject('ldap: Bind as user failed');
  }
  radLog(world, srv, 'Auth', `(${n}) Login OK: [${user}] (${clientLabel})`);
  return { accept: true, reply };
}

/**
 * Send one Access-Request from `host` to server:port and wait for the answer.
 * The world clock is restored afterwards (the tools wait; the network does not move).
 */
export function radiusExchange(world: World, host: Host, server: string, port: number, req: RadiusRequest): RadiusResult {
  const start = world.clock;
  const rec = activeRecorder();
  const prev = rec?.phase;
  if (rec) rec.phase = 'RADIUS';
  const id = (world.counter * 37) % 256;
  const sport = 40000 + ((world.counter * 7919) % 20000);
  try {
    const q: Packet = {
      id: nextId(world), src: sourceAddress(host, server), dst: server, ttl: 64, proto: 'udp',
      udp: { sport, dport: port, len: 70 + req.user.length },
      app: {
        protocol: 'RADIUS', info: `Access-Request id=${id}`,
        fields: [
          { name: 'Code', value: 'Access-Request (1)' }, { name: 'Packet identifier', value: String(id) },
          { name: 'User-Name', value: req.user }, { name: 'User-Password', value: '(encrypted with the shared secret)' },
          ...(req.messageAuthenticator ? [{ name: 'Message-Authenticator', value: '(HMAC-MD5 with the shared secret)' }] : []),
        ],
      },
    };
    const d = transmit(world, host.id, q);
    rec?.describe(q.id, 'RADIUS Access-Request', `The NAS asks the RADIUS server whether "${req.user}" may log in: one UDP datagram to port ${port}. The password is hidden with the shared secret (MD5), not sent in clear text${req.messageAuthenticator ? '; the Message-Authenticator attribute signs the whole packet with the secret' : ''}.`);
    if (d.status !== 'delivered') return { kind: 'timeout', id, sport };
    const srv = world.hosts[d.host];
    const fq = d.final;
    const listener = findListener(srv, 'udp', fq.dst, port);
    if (!listener || listener.process !== 'freeradius') {
      if (!listener) sendIcmpError(world, srv, fq, 'port-unreachable');
      return { kind: 'timeout', id, sport };
    }
    const l = srv.services.freeradius?.loaded as RadiusdLoaded | null;
    if (!l) return { kind: 'timeout', id, sport };
    const n = l.nextId++;
    const client = clientFor(l, fq.src);
    if (!client) {
      radLog(world, srv, 'Error', `Ignoring request to auth address * port ${port} bound to server default from unknown client ${fq.src} port ${sport} proto udp`);
      return { kind: 'timeout', id, sport };
    }
    const secretOk = client.secret === req.secret;
    if (!secretOk && req.messageAuthenticator) {
      radLog(world, srv, 'Error', `Dropping packet without response because of error: Received packet from ${fq.src} with invalid Message-Authenticator!  (Shared secret is incorrect.)`);
      return { kind: 'timeout', id, sport };
    }
    if (client.requireMA && !req.messageAuthenticator) {
      radLog(world, srv, 'Error', `Dropping packet without response because of error: Received packet from ${fq.src} without Message-Authenticator, and client ${client.shortname} requires it`);
      return { kind: 'timeout', id, sport };
    }
    // A wrong secret without Message-Authenticator: the server decrypts the password into garbage.
    const password = secretOk ? req.password : `\u0007${req.password.split('').reverse().join('')}\u0013`;
    const clientLabel = `from client ${client.shortname} port ${req.nasPort ?? 0}${req.callingStation ? ` cli ${req.callingStation}` : ''}`;
    const out = authorize(world, srv, l, req.user, password, n, clientLabel);
    world.clock += 0.5;
    const r: Packet = {
      id: nextId(world), src: fq.dst, dst: fq.src, ttl: 64, proto: 'udp', udp: { sport: port, dport: sport, len: 20 + out.reply.reduce((s, x) => s + 2 + x.value.length, 0) },
      app: { protocol: 'RADIUS', info: `${out.accept ? 'Access-Accept' : 'Access-Reject'} id=${id}`, fields: [{ name: 'Code', value: out.accept ? 'Access-Accept (2)' : 'Access-Reject (3)' }, ...out.reply.map((x) => ({ name: x.attr, value: x.value }))] },
    };
    if (rec) rec.phase = 'RADIUS';
    const back = transmit(world, srv.id, r);
    rec?.describe(r.id, out.accept ? 'RADIUS Access-Accept' : 'RADIUS Access-Reject', `${out.accept ? 'The server accepts the login' : 'The server refuses the login'}. The reply carries a Response Authenticator: an MD5 hash over the reply, the request authenticator and the shared secret, so the NAS can tell that the answer comes from a server that knows the secret.`);
    if (back.status !== 'delivered') return { kind: 'timeout', id, sport };
    return { kind: out.accept ? 'accept' : 'reject', id, sport, from: fq.dst, reply: out.reply, verified: secretOk };
  } finally {
    world.clock = start;
    if (rec && prev) rec.phase = prev;
  }
}

// ---------------------------------------------------------------------------
// pam_radius_auth (the NAS side for sshd)
// ---------------------------------------------------------------------------

export interface PamRadiusServer { host: string; port: number; secret: string; timeout: number }

/** /etc/pam_radius_auth.conf: "server[:port] shared_secret [timeout]" lines, tried in order. */
export function pamRadiusServers(host: Host): PamRadiusServer[] {
  const out: PamRadiusServer[] = [];
  for (const raw of (readFile(host, PAM_RADIUS_CONF) ?? '').split('\n')) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    const [hp, secret, timeout] = line.split(/\s+/);
    if (!secret) continue;
    const [h, p] = hp.split(':');
    out.push({ host: h, port: p ? Number(p) || 1812 : 1812, secret, timeout: Number(timeout ?? 3) || 3 });
  }
  return out;
}

/** Is pam_radius_auth in the service's auth stack, and how (sufficient: a reject falls back to the next modules). */
export function pamRadiusControl(host: Host, service: string): 'sufficient' | 'required' | null {
  for (const raw of (readFile(host, `/etc/pam.d/${service}`) ?? '').split('\n')) {
    const m = /^\s*auth\s+(\S+|\[[^\]]*\])\s+(?:\S*\/)?pam_radius_auth\.so\b/.exec(raw);
    if (!m) continue;
    return m[1] === 'sufficient' || /success=done/.test(m[1]) ? 'sufficient' : 'required';
  }
  return null;
}

/**
 * pam_radius_auth's authenticate step: ask each configured server in turn.
 * 'accept' = PAM_SUCCESS, 'reject' = PAM_AUTH_ERR, 'unavailable' = no server answered (PAM_AUTHINFO_UNAVAIL).
 */
export function pamRadiusAuth(world: World, host: Host, service: string, user: string, password: string, rhost: string, pid: number | null): 'accept' | 'reject' | 'unavailable' {
  const servers = pamRadiusServers(host);
  const plog = (msg: string) => log(world, host, service, `pam_radius_auth: ${msg}`, { pid, unit: service === 'sshd' ? 'ssh.service' : null, priority: 'err', facility: 'authpriv' });
  if (!servers.length) { plog(`Could not read any servers to talk to.`); return 'unavailable'; }
  for (const s of servers) {
    let ip = s.host;
    if (!isIpAddress(ip)) {
      const r = resolve(world, host, s.host, { family: 4 });
      if (!r.ok) { plog(`Failed looking up IP address for RADIUS server ${s.host} (errcode=-2)`); continue; }
      ip = r.ip;
    }
    const r = radiusExchange(world, host, ip, s.port, { user, password, secret: s.secret, messageAuthenticator: false, callingStation: rhost });
    if (r.kind === 'timeout') { plog(`RADIUS server ${s.host} failed to respond`); continue; }
    if (!r.verified) { plog(`packet from RADIUS server ${s.host} failed verification: The shared secret is probably incorrect.`); continue; }
    return r.kind === 'accept' ? 'accept' : 'reject';
  }
  plog('All RADIUS servers failed to respond.');
  return 'unavailable';
}
