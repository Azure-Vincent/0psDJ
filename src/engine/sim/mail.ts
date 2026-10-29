// Email with Postfix (SMTP server, queue and delivery). The model follows what
// matters when mail stops: main.cf parameters and their $name expansion,
// master.cf services (smtp 25, submission 587, smtps 465) with their -o
// overrides, the SMTP dialogue (EHLO, STARTTLS, AUTH through Dovecot's socket,
// relay and recipient checks), the queue (deferred mail and its reason, flush,
// delete), local delivery (aliases.db, Maildir or mbox) and relaying to the
// relayhost or the recipient domain's MX. Log lines follow Postfix 3.7 on
// Debian 12 and go to the mail facility (/var/log/mail.log).
//
// Postfix reads main.cf and master.cf when it starts or reloads (the snapshot
// in rt.loaded); aliases.db, the TLS files and Dovecot's auth socket are used
// when each connection or delivery happens, as in the real daemons.

import { canAccess, canTraverse, dirname, listDir, mkdir, readFile, writeFile } from '../fs';
import { inCidr, parseCidr } from '../net/ip';
import type { Host, ServiceRuntime, UserAccount, World } from '../types';
import { seededInt } from '../util/sha256';
import { accountExpired, passwordLocked } from './accounts';
import { dnsQuery, resolve, resolverConf } from './dns';
import { log } from './journal';
import { findHostByIp } from './network';
import { type Cert, parseCerts, parseKey } from './pki';
import { type TcpConn, tcpConnect } from './tcp';
import { allListeners } from './services';

export const MAIN_CF = '/etc/postfix/main.cf';
export const MASTER_CF = '/etc/postfix/master.cf';
export const ALIASES = '/etc/aliases';
export const ALIASES_DB = '/etc/aliases.db';
export const POSTFIX_VERSION = '3.7.11';
export const QUEUE_DIR = '/var/spool/postfix';

// ---------------------------------------------------------------------------
// Persistent mail state: the queue (/var/spool/postfix) and the compiled alias database
// ---------------------------------------------------------------------------

export interface QueuedRcpt { addr: string; orig?: string; reason?: string }
export interface QueuedMessage {
  id: string;
  from: string;
  rcpts: QueuedRcpt[];
  size: number;
  arrival: number;
  /** The message as stored, headers and body (with Postfix's Received: header). */
  content: string;
  /** Set once a delivery attempt failed temporarily (the deferred queue). */
  deferred?: boolean;
}
export interface MailState {
  queue: QueuedMessage[];
  /** /etc/aliases.db as newaliases last compiled it (key -> targets). */
  aliasDb?: Record<string, string[]>;
}

export function mailState(host: Host): MailState {
  return (host.mail ??= { queue: [] });
}

// ---------------------------------------------------------------------------
// main.cf
// ---------------------------------------------------------------------------

export interface MainCf { params: Record<string, string>; lines: Record<string, number>; order: string[] }

/** Parse main.cf: "name = value", continuation lines start with whitespace, # comments. */
export function parseMainCf(text: string): MainCf {
  const out: MainCf = { params: {}, lines: {}, order: [] };
  let last: string | null = null;
  text.split('\n').forEach((raw, i) => {
    if (/^\s*#/.test(raw) || !raw.trim()) return;
    if (/^\s/.test(raw)) {
      if (last) out.params[last] = `${out.params[last]} ${raw.trim()}`.trim();
      return;
    }
    const m = /^([A-Za-z0-9_.-]+)\s*=\s*(.*)$/.exec(raw);
    if (!m) { last = null; return; }
    last = m[1];
    if (!(m[1] in out.params)) out.order.push(m[1]);
    out.params[m[1]] = m[2].trim();
    out.lines[m[1]] = i + 1;
  });
  return out;
}

/** Built-in defaults (postconf -d) for the parameters the model uses or Debian's main.cf sets. */
export function postfixDefaults(host: Host): Record<string, string> {
  return {
    alias_database: 'hash:/etc/aliases',
    alias_maps: 'hash:/etc/aliases, nis:mail.aliases',
    append_dot_mydomain: 'no',
    biff: 'yes',
    command_directory: '/usr/sbin',
    compatibility_level: '0',
    daemon_directory: '/usr/lib/postfix/sbin',
    data_directory: '/var/lib/postfix',
    default_transport: 'smtp',
    disable_vrfy_command: 'no',
    home_mailbox: '',
    inet_interfaces: 'all',
    inet_protocols: 'all',
    local_recipient_maps: 'proxy:unix:passwd.byname $alias_maps',
    mail_name: 'Postfix',
    mail_owner: 'postfix',
    mail_spool_directory: '/var/mail',
    mail_version: POSTFIX_VERSION,
    mailbox_command: '',
    mailbox_size_limit: '51200000',
    maximal_queue_lifetime: '5d',
    message_size_limit: '10240000',
    minimal_backoff_time: '300s',
    mydestination: '$myhostname, localhost.$mydomain, localhost',
    mydomain: host.domain,
    myhostname: `${host.hostname}.${host.domain}`,
    mynetworks: '127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128',
    mynetworks_style: 'subnet',
    myorigin: '$myhostname',
    queue_directory: QUEUE_DIR,
    readme_directory: 'no',
    recipient_delimiter: '',
    relay_domains: '',
    relayhost: '',
    setgid_group: 'postdrop',
    smtp_connect_timeout: '30s',
    smtp_tls_CApath: '',
    smtp_tls_security_level: '',
    smtp_tls_session_cache_database: '',
    smtpd_banner: '$myhostname ESMTP $mail_name',
    smtpd_client_restrictions: '',
    smtpd_helo_required: 'no',
    smtpd_helo_restrictions: '',
    smtpd_recipient_restrictions: '',
    smtpd_relay_restrictions: 'permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination',
    smtpd_sasl_auth_enable: 'no',
    smtpd_sasl_path: 'smtpd',
    smtpd_sasl_security_options: 'noanonymous',
    smtpd_sasl_type: 'cyrus',
    smtpd_sender_restrictions: '',
    smtpd_tls_auth_only: 'no',
    smtpd_tls_cert_file: '',
    smtpd_tls_key_file: '$smtpd_tls_cert_file',
    smtpd_tls_loglevel: '0',
    smtpd_tls_received_header: 'no',
    smtpd_tls_security_level: '',
    smtpd_tls_session_cache_database: '',
    smtpd_tls_wrapper_mode: 'no',
    syslog_name: 'postfix',
  };
}

/** A parameter's raw value: main.cf, then the -o overrides of a master.cf service, then the default. */
export function rawParam(host: Host, cf: MainCf, name: string, overrides: Record<string, string> = {}): string | undefined {
  return overrides[name] ?? cf.params[name] ?? postfixDefaults(host)[name];
}

/** Expand $name, ${name} and $(name) the way Postfix does when it uses a value. */
export function expandParam(host: Host, cf: MainCf, value: string, overrides: Record<string, string> = {}, depth = 0): string {
  if (depth > 20) return value;
  return value.replace(/\$(?:\{([A-Za-z0-9_]+)\}|\(([A-Za-z0-9_]+)\)|([A-Za-z0-9_]+))/g, (_m, a, b, c) => {
    const v = rawParam(host, cf, a ?? b ?? c, overrides);
    return v === undefined ? '' : expandParam(host, cf, v, overrides, depth + 1);
  });
}

export const param = (host: Host, cf: MainCf, name: string, overrides: Record<string, string> = {}) => expandParam(host, cf, rawParam(host, cf, name, overrides) ?? '', overrides);
const yes = (v: string) => /^(yes|true|1|on)$/i.test(v.trim());
const list = (v: string) => v.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

export function loadMainCf(host: Host): MainCf {
  return parseMainCf(readFile(host, MAIN_CF) ?? '');
}

/** Configuration errors every Postfix program stops on. */
export function mainCfFatal(host: Host, cf: MainCf): string | null {
  for (const n of ['message_size_limit', 'mailbox_size_limit']) {
    const v = param(host, cf, n);
    if (!/^\d+$/.test(v)) return `fatal: bad numerical configuration: ${n} = ${cf.params[n] ?? v}`;
  }
  const msg = Number(param(host, cf, 'message_size_limit'));
  const box = Number(param(host, cf, 'mailbox_size_limit'));
  if (msg > 0 && box > 0 && msg > box) return 'fatal: main.cf configuration error: mailbox_size_limit is smaller than message_size_limit';
  const ii = param(host, cf, 'inet_interfaces').toLowerCase();
  if (!/^(all|loopback-only)$/.test(ii) && list(ii).some((a) => a !== 'localhost' && !/^[\d.]+$/.test(a.replace(/^\[|\]$/g, '')) && !a.includes(':'))) return `fatal: config variable inet_interfaces: host not found: ${list(ii)[0]}`;
  return null;
}

/** Names Debian's main.cf and the lessons use that Postfix knows (for "unused parameter" warnings). */
const KNOWN_EXTRA = ['smtpd_tls_CApath', 'smtpd_tls_CAfile', 'smtpd_tls_protocols', 'smtpd_tls_mandatory_protocols', 'smtpd_tls_ciphers', 'smtp_tls_CAfile', 'smtp_tls_protocols', 'smtp_sasl_auth_enable', 'smtp_sasl_password_maps', 'smtp_sasl_security_options', 'smtpd_sasl_local_domain', 'broken_sasl_auth_clients', 'smtpd_tls_chain_files', 'virtual_alias_maps', 'virtual_mailbox_domains', 'transport_maps', 'sender_canonical_maps', 'header_checks', 'milter_default_action', 'smtpd_milters', 'non_smtpd_milters', 'delay_warning_time', 'notify_classes', 'bounce_queue_lifetime', 'smtpd_error_sleep_time', 'smtpd_soft_error_limit', 'smtpd_hard_error_limit', 'mailbox_transport', 'local_transport', 'relay_transport', 'smtp_helo_name', 'maillog_file', 'smtputf8_enable', 'unknown_local_recipient_reject_code', 'smtpd_data_restrictions', 'smtpd_end_of_data_restrictions', 'show_user_unknown_table_name', 'smtpd_reject_unlisted_recipient', 'proxy_interfaces', 'smtp_bind_address', 'myorigin', 'masquerade_domains'];
export function unusedParams(host: Host, cf: MainCf): string[] {
  const known = new Set([...Object.keys(postfixDefaults(host)), ...KNOWN_EXTRA]);
  return cf.order.filter((n) => !known.has(n)).map((n) => `/usr/sbin/postconf: warning: ${MAIN_CF}: unused parameter: ${n}=${cf.params[n]}`);
}

// ---------------------------------------------------------------------------
// master.cf
// ---------------------------------------------------------------------------

export interface MasterService { name: string; type: string; chroot: string; command: string; args: string[]; overrides: Record<string, string>; line: number }

const SERVICE_PORTS: Record<string, number> = { smtp: 25, submission: 587, smtps: 465, submissions: 465 };
export const servicePort = (name: string): number | null => {
  const p = name.includes(':') ? name.slice(name.lastIndexOf(':') + 1) : name;
  return /^\d+$/.test(p) ? Number(p) : SERVICE_PORTS[p] ?? null;
};

export function parseMasterCf(text: string): { services: MasterService[]; errors: string[] } {
  const services: MasterService[] = [];
  const errors: string[] = [];
  text.split('\n').forEach((raw, i) => {
    if (/^\s*#/.test(raw) || !raw.trim()) return;
    if (/^\s/.test(raw)) {
      const s = services[services.length - 1];
      if (!s) { errors.push(`fatal: ${MASTER_CF}: line ${i + 1}: unexpected continuation line`); return; }
      const parts = raw.trim().split(/\s+/);
      for (let k = 0; k < parts.length; k++) {
        if (parts[k] === '-o' && parts[k + 1]) {
          const [n, ...v] = parts[++k].split('=');
          s.overrides[n] = v.join('=');
        } else s.args.push(parts[k]);
      }
      return;
    }
    const f = raw.trim().split(/\s+/);
    if (f.length < 8) { errors.push(`fatal: ${MASTER_CF}: line ${i + 1}: field "command": expected a command name`); return; }
    if (!['inet', 'unix', 'unix-dgram', 'fifo', 'pass'].includes(f[1])) { errors.push(`fatal: ${MASTER_CF}: line ${i + 1}: field "type": bad value: "${f[1]}"`); return; }
    const svc: MasterService = { name: f[0], type: f[1], chroot: f[4], command: f[7], args: [], overrides: {}, line: i + 1 };
    for (let k = 8; k < f.length; k++) {
      if (f[k] === '-o' && f[k + 1]) {
        const [n, ...v] = f[++k].split('=');
        svc.overrides[n] = v.join('=');
      } else svc.args.push(f[k]);
    }
    services.push(svc);
  });
  return { services, errors };
}

// ---------------------------------------------------------------------------
// The running Postfix (rt.loaded)
// ---------------------------------------------------------------------------

export interface SmtpdService { name: string; port: number; addrs: string[]; overrides: Record<string, string>; syslogName: string }
export interface PostfixLoaded {
  cf: MainCf;
  services: SmtpdService[];
  /** The addresses inet_interfaces gave at start (kept by reloads). */
  inetAddrs: string[];
  masterPid: number;
  qmgrPid: number;
}

function interfaceAddrs(host: Host, cf: MainCf): string[] {
  const ii = param(host, cf, 'inet_interfaces').toLowerCase().trim();
  const protos = param(host, cf, 'inet_protocols').toLowerCase();
  const v4 = protos === 'all' || protos.includes('ipv4');
  const v6 = protos === 'all' || protos.includes('ipv6');
  if (ii === 'all') return [...(v4 ? ['0.0.0.0'] : []), ...(v6 ? ['::'] : [])];
  if (ii === 'loopback-only') return [...(v4 ? ['127.0.0.1'] : []), ...(v6 ? ['::1'] : [])];
  return list(ii).map((a) => (a === 'localhost' ? '127.0.0.1' : a.replace(/^\[|\]$/g, '')));
}

const pf = (world: World, host: Host, prog: string, msg: string, pid: number, priority: 'info' | 'warning' | 'err' | 'crit' = 'info') =>
  log(world, host, prog, msg, { pid, unit: 'postfix@-.service', priority, facility: 'mail' });

/** Start or reload: returns null (and logs why) when Postfix refuses to run. */
export function postfixLoad(world: World, host: Host, rt: ServiceRuntime, reload: boolean): PostfixLoaded | null {
  const cf = loadMainCf(host);
  const pid = rt.pid!;
  const fatal = mainCfFatal(host, cf) ?? (readFile(host, MASTER_CF) === undefined ? `fatal: open ${MASTER_CF}: No such file or directory` : parseMasterCf(readFile(host, MASTER_CF)!).errors[0] ?? null);
  if (fatal) {
    pf(world, host, 'postfix/postfix-script', fatal, pid + 1, 'crit');
    return null;
  }
  const prev = reload ? (rt.loaded as PostfixLoaded | null) : null;
  // inet_interfaces only changes on stop/start: a reload keeps the addresses master already bound.
  const addrs = prev?.inetAddrs ?? interfaceAddrs(host, cf);
  if (prev && interfaceAddrs(host, cf).join() !== addrs.join()) pf(world, host, 'postfix/master', 'warning: inet_interfaces: changes require "postfix stop" and "postfix start"', pid, 'warning');
  const services = parseMasterCf(readFile(host, MASTER_CF)!).services
    .filter((s) => s.type === 'inet' && s.command === 'smtpd' && servicePort(s.name) !== null)
    .map((s) => ({ name: s.name, port: servicePort(s.name)!, addrs: s.name.includes(':') ? [s.name.slice(0, s.name.lastIndexOf(':'))] : addrs, overrides: s.overrides, syslogName: s.overrides.syslog_name ? expandParam(host, cf, s.overrides.syslog_name) : 'postfix' }));
  if (reload) {
    pf(world, host, 'postfix/postfix-script', 'refreshing the Postfix mail system', pid + 1);
    pf(world, host, 'postfix/master', `reload -- version ${POSTFIX_VERSION}, configuration /etc/postfix`, pid);
  } else {
    pf(world, host, 'postfix/postfix-script', 'starting the Postfix mail system', pid + 1);
    pf(world, host, 'postfix/master', `daemon started -- version ${POSTFIX_VERSION}, configuration /etc/postfix`, pid);
  }
  return { cf, services, inetAddrs: addrs, masterPid: pid, qmgrPid: prev?.qmgrPid ?? pid + 4 };
}

export function postfixLoaded(host: Host): PostfixLoaded | null {
  const rt = host.services.postfix;
  return rt?.state === 'active' ? (rt.loaded as PostfixLoaded) : null;
}

// ---------------------------------------------------------------------------
// Helpers: queue IDs, names, time
// ---------------------------------------------------------------------------

export function newQueueId(world: World, host: Host): string {
  world.counter++;
  return seededInt(`qid:${host.id}:${world.counter}:${world.clock}`, 0x10000000, 0x7fffffff).toString(16).toUpperCase().padStart(8, '0') + seededInt(`qid2:${world.counter}`, 16, 255).toString(16).toUpperCase();
}

function procPid(host: Host): number {
  host.nextPid += 3;
  return host.nextPid;
}

/** "name[ip]" as Postfix logs a peer (the host's name when the lab knows the address, else "unknown"). */
export function peerName(world: World, ip: string): string {
  if (ip.startsWith('127.') || ip === '::1') return `localhost[${ip}]`;
  const h = findHostByIp(world, ip);
  return `${h ? (h.domain ? `${h.hostname}.${h.domain}` : h.hostname) : 'unknown'}[${ip}]`;
}

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const p2 = (n: number) => String(n).padStart(2, '0');
/** RFC 5322 date: "Mon, 19 Oct 2026 08:31:02 +0000". */
export function rfcDate(t: number): string {
  const d = new Date(Math.floor(t));
  return `${DAYS[d.getUTCDay()]}, ${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()} ${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())} +0000`;
}
/** mailq's arrival time: "Mon Oct 19 08:31:02". */
export function queueTime(t: number): string {
  const d = new Date(Math.floor(t));
  return `${DAYS[d.getUTCDay()]} ${MONTHS[d.getUTCMonth()]} ${p2(d.getUTCDate())} ${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())}`;
}
/** The mbox "From " line date: "Mon Oct 19 08:31:02 2026". */
const mboxTime = (t: number) => `${queueTime(t)} ${new Date(Math.floor(t)).getUTCFullYear()}`;

export const domainOf = (addr: string) => (addr.includes('@') ? addr.slice(addr.lastIndexOf('@') + 1).toLowerCase() : '');
export const localOf = (addr: string) => (addr.includes('@') ? addr.slice(0, addr.lastIndexOf('@')) : addr);
/** Strip <> and spaces from a MAIL FROM / RCPT TO argument. */
export const bareAddr = (a: string) => a.trim().replace(/^<|>$/g, '').trim();

/** Is this domain delivered on this machine (mydestination)? */
export function isLocalDomain(host: Host, cf: MainCf, domain: string): boolean {
  if (!domain) return true;
  return list(param(host, cf, 'mydestination')).some((d) => d.toLowerCase() === domain.toLowerCase());
}

/** Is the client address in mynetworks? */
export function inMynetworks(host: Host, cf: MainCf, ip: string, overrides: Record<string, string> = {}): boolean {
  return list(param(host, cf, 'mynetworks', overrides)).some((n) => {
    const c = n.replace(/^\[|\]$/g, '').replace(/\]\//, '/').replace(/^\[/, '');
    if (c.includes(':') !== ip.includes(':')) return false;
    if (!c.includes('/')) return c === ip;
    const cidr = parseCidr(c);
    return !!cidr && inCidr(ip, cidr);
  });
}

// ---------------------------------------------------------------------------
// /etc/aliases and newaliases
// ---------------------------------------------------------------------------

export function parseAliases(text: string): { db: Record<string, string[]>; warnings: string[] } {
  const db: Record<string, string[]> = {};
  const warnings: string[] = [];
  const entries: { line: number; text: string }[] = [];
  text.split('\n').forEach((raw, i) => {
    if (/^\s*#/.test(raw) || !raw.trim()) return;
    if (/^\s/.test(raw) && entries.length) { entries[entries.length - 1].text += ' ' + raw.trim(); return; }
    entries.push({ line: i + 1, text: raw.trim() });
  });
  for (const e of entries) {
    const m = /^("?[^:"]+"?)\s*:\s*(.*)$/.exec(e.text);
    if (!m) { warnings.push(`postalias: warning: ${ALIASES}, line ${e.line}: need name:value pair`); continue; }
    const key = m[1].replace(/"/g, '').trim().toLowerCase();
    if (key in db) warnings.push(`postalias: warning: ${ALIASES}.db: duplicate entry: "${key}"`);
    db[key] = m[2].split(',').map((x) => x.trim()).filter(Boolean);
  }
  return { db, warnings };
}

/** newaliases (postalias /etc/aliases): compile the text file into aliases.db. */
export function newaliases(world: World, host: Host): string[] {
  const text = readFile(host, ALIASES);
  if (text === undefined) return [`postalias: fatal: open ${ALIASES}: No such file or directory`];
  const { db, warnings } = parseAliases(text);
  mailState(host).aliasDb = db;
  writeFile(host, ALIASES_DB, `\0\x06\x15a\0\0\0\0hash database (${Object.keys(db).length} entries)\0`, world.clock, { mode: 0o644 });
  return warnings;
}

// ---------------------------------------------------------------------------
// TLS for smtpd (loaded when an smtpd process starts, i.e. per connection here)
// ---------------------------------------------------------------------------

export interface TlsFiles { chain: Cert[]; keyId: string }

/** Load a certificate chain and key: the chain, or the warnings Postfix logs before it disables TLS. */
export function loadTlsPair(host: Host, certPath: string, keyPath: string): { tls?: TlsFiles; warnings: string[] } {
  if (!certPath) return { warnings: [] };
  const certText = readFile(host, certPath);
  if (certText === undefined) return { warnings: [`warning: cannot get RSA certificate from file "${certPath}": disabling TLS support`, `warning: TLS library problem: error:80000002:system library::No such file or directory:../crypto/bio/bss_file.c:67:calling fopen(${certPath}, r):`] };
  const chain = parseCerts(certText).filter((c): c is Cert => !!c);
  if (!chain.length) return { warnings: [`warning: cannot get RSA certificate from file "${certPath}": disabling TLS support`, 'warning: TLS library problem: error:0480006C:PEM routines::no start line:../crypto/pem/pem_lib.c:763:Expecting: CERTIFICATE:'] };
  const keyText = readFile(host, keyPath);
  const key = keyText === undefined ? undefined : parseKey(keyText);
  if (!key) return { warnings: [`warning: cannot get RSA private key from file "${keyPath}": disabling TLS support`, `warning: TLS library problem: error:${keyText === undefined ? `80000002:system library::No such file or directory:../crypto/bio/bss_file.c:67:calling fopen(${keyPath}, r)` : '1E08010C:DECODER routines::unsupported:../crypto/encode_decode/decoder_lib.c:102:No supported data to decode.'}:`] };
  if (key.keyId !== chain[0].keyId) return { warnings: [`warning: cannot get RSA private key from file "${keyPath}": disabling TLS support`, 'warning: TLS library problem: error:05800074:x509 certificate routines::key values mismatch:../crypto/x509/x509_cmp.c:405:'] };
  return { tls: { chain, keyId: key.keyId }, warnings: [] };
}

// ---------------------------------------------------------------------------
// SASL: Postfix asks Dovecot's auth service through a UNIX socket
// ---------------------------------------------------------------------------

export interface DovecotAuthView { sockets: string[]; mechanisms: string[]; check(user: string, password: string): boolean }
/** Filled by dovecot.ts (avoids an import cycle): Dovecot's auth service when it is running. */
export const saslHooks: { dovecot?: (world: World, host: Host) => DovecotAuthView | null } = {};

/** The UNIX socket path smtpd connects to for smtpd_sasl_path (relative paths are inside the queue directory). */
export function saslSocketPath(path: string): string {
  return path.startsWith('/') ? path : `${QUEUE_DIR}/${path.replace(/^\.\//, '')}`;
}

/** Check a Unix password the way PAM's pam_unix does for a mail login. */
export function unixPasswordOk(world: World, host: Host, user: string, password: string): UserAccount | null {
  const u = host.users[user];
  if (!u || passwordLocked(u) || accountExpired(u, world.clock) || u.password !== password) return null;
  return u;
}

// ---------------------------------------------------------------------------
// The SMTP server side (one smtpd process per connection)
// ---------------------------------------------------------------------------

export interface Reply { code: number; text: string[]; /** The server closed the connection after (or instead of) this reply. */ closed?: boolean }
const reply = (code: number, ...text: string[]): Reply => ({ code, text });

/** Format a reply as it travels on the wire ("250-..." continuation lines, "250 last"). */
export const replyLines = (r: Reply) => r.text.map((t, i) => `${r.code}${i < r.text.length - 1 ? '-' : ' '}${t}`);

export class Smtpd {
  pid: number;
  prog: string;
  helo = '';
  tlsActive = false;
  tls: TlsFiles | null = null;
  saslActive = false;
  saslMechs: string[] = [];
  authUser: string | null = null;
  authMethod = '';
  from: string | null = null;
  rcpts: string[] = [];
  counts: Record<string, number> = {};
  closed = false;
  private eff: (n: string) => string;

  constructor(public world: World, public host: Host, public loaded: PostfixLoaded, public svc: SmtpdService, public conn: TcpConn, public clientIp: string) {
    this.pid = procPid(host);
    this.prog = `${svc.syslogName}/smtpd`;
    this.eff = (n) => param(host, loaded.cf, n, svc.overrides);
  }

  get client() { return peerName(this.world, this.clientIp); }
  private logp(msg: string, priority: 'info' | 'warning' | 'err' | 'crit' = 'info') { pf(this.world, this.host, this.prog, msg, this.pid, priority); }
  private count(cmd: string) { this.counts[cmd] = (this.counts[cmd] ?? 0) + 1; }
  private tlsLevel() { return this.eff('smtpd_tls_security_level').toLowerCase() || (yes(this.eff('smtpd_use_tls') || 'no') ? 'may' : yes(this.eff('smtpd_enforce_tls') || 'no') ? 'encrypt' : ''); }
  get wrapper() { return yes(this.eff('smtpd_tls_wrapper_mode')); }

  /** A fatal error ends this smtpd: master logs the exit and the client loses the connection. */
  private die(msg: string): Reply {
    this.logp(`fatal: ${msg}`, 'crit');
    pf(this.world, this.host, 'postfix/master', `warning: process /usr/lib/postfix/sbin/smtpd pid ${this.pid} exit status 1`, this.loaded.masterPid, 'warning');
    pf(this.world, this.host, 'postfix/master', 'warning: /usr/lib/postfix/sbin/smtpd: bad command startup -- throttling', this.loaded.masterPid, 'warning');
    this.closed = true;
    return { code: 0, text: [], closed: true };
  }

  /** Connect SASL to Dovecot's socket and fetch the mechanisms; dies like smtpd when that fails. */
  private saslActivate(): Reply | null {
    if (!yes(this.eff('smtpd_sasl_auth_enable')) || this.saslActive) return null;
    const type = this.eff('smtpd_sasl_type').toLowerCase();
    const path = this.eff('smtpd_sasl_path');
    if (type !== 'dovecot') {
      this.logp('warning: SASL per-process initialization failed: generic failure', 'warning');
      return this.die('SASL per-process initialization failed');
    }
    const sock = saslSocketPath(path);
    const node = this.host.fs[sock];
    const view = saslHooks.dovecot?.(this.world, this.host) ?? null;
    if (!node) {
      this.logp(`warning: SASL: Connect to ${path} failed: No such file or directory`, 'warning');
      return this.die('no SASL authentication mechanisms');
    }
    if (!node.socket || !view || !view.sockets.includes(sock)) {
      this.logp(`warning: SASL: Connect to ${path} failed: Connection refused`, 'warning');
      return this.die('no SASL authentication mechanisms');
    }
    this.saslActive = true;
    this.saslMechs = view.mechanisms.map((m) => m.toUpperCase());
    return null;
  }

  /** The connection starts: TLS init, SASL (unless it waits for TLS), the banner or a fatal exit. */
  connect(): Reply {
    this.logp(`connect from ${this.client}`);
    if (this.tlsLevel() || this.wrapper) {
      const r = loadTlsPair(this.host, this.eff('smtpd_tls_cert_file'), this.eff('smtpd_tls_key_file'));
      for (const w of r.warnings) this.logp(w, 'warning');
      this.tls = r.tls ?? null;
      if (this.wrapper && !this.tls) {
        this.logp(`warning: TLS library problem: cannot start TLS: wrapper mode without a usable certificate`, 'warning');
        this.logp(`lost connection after CONNECT from ${this.client}`);
        this.disconnect();
        return { code: 0, text: [], closed: true };
      }
    }
    if (!this.wrapper && !this.authOnlyWaitsForTls()) {
      const dead = this.saslActivate();
      if (dead) return dead;
    }
    return reply(220, expandParam(this.host, this.loaded.cf, this.eff('smtpd_banner') || '$myhostname ESMTP $mail_name', this.svc.overrides));
  }

  private authOnlyWaitsForTls() { return yes(this.eff('smtpd_tls_auth_only')) && !this.tlsActive; }

  /** After a TLS handshake (STARTTLS or wrapper mode): SASL activation that waited for TLS happens now. */
  tlsStarted(): Reply | null {
    this.tlsActive = true;
    this.logp(`Anonymous TLS connection established from ${this.client}: TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits) key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256`);
    return this.saslActivate();
  }

  ehlo(name: string, helo = false): Reply {
    this.count(helo ? 'helo' : 'ehlo');
    this.helo = name;
    if (helo) return reply(250, param(this.host, this.loaded.cf, 'myhostname'));
    const ext = [param(this.host, this.loaded.cf, 'myhostname'), 'PIPELINING', `SIZE ${this.eff('message_size_limit')}`, 'VRFY', 'ETRN'];
    if (this.tls && !this.tlsActive && !this.wrapper) ext.push('STARTTLS');
    if (this.saslActive && !this.authOnlyWaitsForTls() && this.saslMechs.length) ext.push(`AUTH ${this.saslMechs.join(' ')}`);
    ext.push('ENHANCEDSTATUSCODES', '8BITMIME', 'DSN', 'SMTPUTF8', 'CHUNKING');
    return reply(250, ...ext);
  }

  starttls(): Reply {
    this.count('starttls');
    if (this.tlsActive) return reply(554, '5.5.1 Error: TLS already active');
    if (!this.tlsLevel()) return reply(502, '5.5.1 Error: command not implemented');
    if (!this.tls) return reply(454, '4.7.0 TLS not available due to local problem');
    return reply(220, '2.0.0 Ready to start TLS');
  }

  auth(mech: string, user: string, password: string): Reply {
    this.count('auth');
    if (!this.saslActive || this.authOnlyWaitsForTls()) return reply(503, '5.5.1 Error: authentication not enabled');
    if (this.authUser) return reply(503, '5.5.1 Error: already authenticated');
    if (!this.saslMechs.includes(mech.toUpperCase())) return reply(535, '5.7.8 Error: authentication failed: Invalid authentication mechanism');
    const view = saslHooks.dovecot?.(this.world, this.host);
    if (!view || !view.check(user, password)) {
      this.world.clock += 2000; // Dovecot's auth_failure_delay
      this.logp(`warning: ${this.client}: SASL ${mech.toUpperCase()} authentication failed: (reason unavailable), sasl_username=${user}`, 'warning');
      return reply(535, '5.7.8 Error: authentication failed: authentication failure');
    }
    this.authUser = user;
    this.authMethod = mech.toUpperCase();
    return reply(235, '2.7.0 Authentication successful');
  }

  private mustTls(): boolean { return this.tlsLevel() === 'encrypt' && !this.tlsActive; }

  mail(arg: string): Reply {
    this.count('mail');
    if (this.mustTls()) return reply(530, '5.7.0 Must issue a STARTTLS command first');
    if (!this.helo && yes(this.eff('smtpd_helo_required'))) return reply(503, '5.5.1 Error: send HELO/EHLO first');
    if (this.from !== null) return reply(503, '5.5.1 Error: nested MAIL command');
    const m = /^FROM:\s*<([^>]*)>(.*)$/i.exec(arg.trim());
    if (!m) return reply(501, '5.5.4 Syntax: MAIL FROM:<address>');
    const size = /SIZE=(\d+)/i.exec(m[2]);
    const limit = Number(this.eff('message_size_limit'));
    if (size && limit > 0 && Number(size[1]) > limit) return reply(552, '5.3.4 Message size exceeds fixed limit');
    this.from = m[1];
    return reply(250, '2.1.0 Ok');
  }

  /** Recipient checks: smtpd_relay_restrictions, then whether a local recipient exists. */
  rcpt(arg: string): Reply {
    this.count('rcpt');
    if (this.mustTls()) return reply(530, '5.7.0 Must issue a STARTTLS command first');
    if (this.from === null) return reply(503, '5.5.1 Error: need MAIL command');
    const m = /^TO:\s*<([^>]*)>/i.exec(arg.trim());
    if (!m || !m[1]) return reply(501, '5.1.3 Bad recipient address syntax');
    const to = m[1];
    const reject = (r: Reply) => {
      this.logp(`NOQUEUE: reject: RCPT from ${this.client}: ${r.code} ${r.text[0]}; from=<${this.from}> to=<${to}> proto=ESMTP helo=<${this.helo}>`);
      return r;
    };
    const decision = relayDecision(this.host, this.loaded.cf, this.svc.overrides, this.clientIp, !!this.authUser, to);
    if (decision !== 'permit') {
      if (decision === 'defer') return reject(reply(454, `4.7.1 <${to}>: Relay access denied`));
      return reject(reply(554, `5.7.1 <${to}>: Relay access denied`));
    }
    const known = isLocalDomain(this.host, this.loaded.cf, domainOf(to)) ? localRecipientKnown(this.world, this.host, this.loaded.cf, to) : 'yes';
    if (known === 'temp') {
      this.logp(`warning: hash:${ALIASES} is unavailable. open database ${ALIASES_DB}: No such file or directory`, 'warning');
      return reject(reply(451, `4.3.0 <${to}>: Temporary lookup failure`));
    }
    if (known === 'no') return reject(reply(550, `5.1.1 <${to}>: Recipient address rejected: User unknown in local recipient table`));
    this.rcpts.push(to);
    return reply(250, '2.1.5 Ok');
  }

  /** DATA and the message: queue it (cleanup, qmgr) and run delivery at once. */
  data(content: string): Reply {
    this.count('data');
    if (!this.rcpts.length) return reply(554, '5.5.1 Error: no valid recipients');
    const limit = Number(this.eff('message_size_limit'));
    if (limit > 0 && content.length > limit) return reply(552, '5.3.4 Message size exceeds fixed limit');
    const id = newQueueId(this.world, this.host);
    this.logp(`${id}: client=${this.client}${this.authUser ? `, sasl_method=${this.authMethod}, sasl_username=${this.authUser}` : ''}`);
    const received = `Received: from ${this.helo || 'unknown'} (${this.client.replace(/\[/, ' [')})\n\t${this.authUser ? '(Authenticated sender: ' + this.authUser + ')\n\t' : ''}by ${param(this.host, this.loaded.cf, 'myhostname')} (Postfix) with ${this.tlsActive ? 'ESMTPS' : 'ESMTP'}${this.authUser ? 'A' : ''} id ${id}\n\tfor <${this.rcpts[0]}>; ${rfcDate(this.world.clock)}\n`;
    enqueue(this.world, this.host, this.loaded, { id, from: this.from ?? '', rcpts: this.rcpts.map((addr) => ({ addr })), size: 0, arrival: this.world.clock, content: received + content });
    this.from = null;
    this.rcpts = [];
    return reply(250, `2.0.0 Ok: queued as ${id}`);
  }

  rset(): Reply { this.count('rset'); this.from = null; this.rcpts = []; return reply(250, '2.0.0 Ok'); }
  noop(): Reply { this.count('noop'); return reply(250, '2.0.0 Ok'); }

  quit(): Reply {
    this.count('quit');
    this.disconnect();
    return reply(221, '2.0.0 Bye');
  }

  /** A command smtpd does not know. */
  unknown(): Reply {
    this.count('unknown');
    return reply(502, '5.5.2 Error: command not recognized');
  }

  disconnect(lost?: string): void {
    if (this.closed) return;
    this.closed = true;
    if (lost) this.logp(`lost connection after ${lost} from ${this.client}`);
    const order = ['ehlo', 'helo', 'starttls', 'auth', 'mail', 'rcpt', 'data', 'rset', 'noop', 'quit', 'unknown'];
    const parts = order.filter((c) => this.counts[c]).map((c) => `${c}=${this.counts[c]}`);
    const total = Object.values(this.counts).reduce((a, b) => a + b, 0);
    this.logp(`disconnect from ${this.client}${parts.length ? ' ' + parts.join(' ') : ''} commands=${total}`);
  }
}

/** smtpd_relay_restrictions (with the service's -o overrides) for one recipient. */
/**
 * smtpd_relay_restrictions, then smtpd_recipient_restrictions (with the
 * service's -o overrides) for one recipient. Each list is evaluated on its
 * own (first match wins, no match = permit), and both must permit.
 */
export function relayDecision(host: Host, cf: MainCf, overrides: Record<string, string>, clientIp: string, authenticated: boolean, to: string): 'permit' | 'defer' | 'reject' {
  const local = isLocalDomain(host, cf, domainOf(to)) || list(param(host, cf, 'relay_domains', overrides)).some((d) => d.toLowerCase() === domainOf(to));
  const evaluate = (name: string): 'permit' | 'defer' | 'reject' => {
    for (const r of list(param(host, cf, name, overrides)).map((x) => x.toLowerCase())) {
      if (r === 'permit') return 'permit';
      if (r === 'reject') return 'reject';
      if (r === 'defer') return 'defer';
      if (r === 'permit_mynetworks' && inMynetworks(host, cf, clientIp, overrides)) return 'permit';
      if (r === 'permit_sasl_authenticated' && authenticated) return 'permit';
      if (r === 'reject_unauth_destination' && !local) return 'reject';
      if (r === 'defer_unauth_destination' && !local) return 'defer';
      if (r === 'permit_auth_destination' && local) return 'permit';
    }
    return 'permit';
  };
  const relay = evaluate('smtpd_relay_restrictions');
  return relay !== 'permit' ? relay : evaluate('smtpd_recipient_restrictions');
}

/** local_recipient_maps: a Unix account or an alias in aliases.db; 'temp' when the alias database cannot be opened. */
export function localRecipientKnown(world: World, host: Host, cf: MainCf, to: string): 'yes' | 'no' | 'temp' {
  const lrm = param(host, cf, 'local_recipient_maps');
  if (!lrm.trim()) return 'yes';
  const local = stripExtension(host, cf, localOf(to)).toLowerCase();
  if (lrm.includes('passwd.byname') && Object.keys(host.users).some((u) => u.toLowerCase() === local)) return 'yes';
  const db = aliasLookup(world, host, cf, local, false);
  return db === 'unavailable' ? 'temp' : db ? 'yes' : 'no';
}

function stripExtension(host: Host, cf: MainCf, local: string): string {
  const delim = param(host, cf, 'recipient_delimiter');
  if (!delim) return local;
  const i = [...delim].map((c) => local.indexOf(c)).filter((n) => n > 0).sort((a, b) => a - b)[0];
  return i === undefined ? local : local.slice(0, i);
}

/** Look KEY up in the alias maps: its targets, null when absent, 'unavailable' when the database is missing. */
function aliasLookup(world: World, host: Host, cf: MainCf, key: string, warn: boolean, pid = 0): string[] | null | 'unavailable' {
  const maps = list(param(host, cf, 'alias_maps')).filter((m) => /^(hash|lmdb|cdb):/.test(m));
  for (const m of maps) {
    const file = m.replace(/^\w+:/, '');
    if (file !== ALIASES) continue;
    const dbNode = host.fs[`${file}.db`];
    const db = mailState(host).aliasDb;
    if (!dbNode || !db) {
      if (warn) pf(world, host, 'postfix/local', `warning: hash:${file} is unavailable. open database ${file}.db: No such file or directory`, pid, 'warning');
      return 'unavailable';
    }
    const src = host.fs[file];
    if (warn && src && src.mtime > dbNode.mtime) pf(world, host, 'postfix/local', `warning: database ${file}.db is older than source file ${file}`, pid, 'warning');
    if (db[key]) return db[key];
  }
  return null;
}

// ---------------------------------------------------------------------------
// Queue manager and delivery agents
// ---------------------------------------------------------------------------

function enqueue(world: World, host: Host, loaded: PostfixLoaded, msg: QueuedMessage): void {
  const cleanup = procPid(host);
  const midMatch = /^Message-I[Dd]:\s*(\S+)/m.exec(msg.content);
  let content = msg.content;
  let messageId = midMatch?.[1];
  if (!messageId) {
    messageId = `<${new Date(Math.floor(world.clock)).toISOString().replace(/\D/g, '').slice(0, 14)}.${msg.id}@${param(host, loaded.cf, 'myhostname')}>`;
    content = content.replace(/\n\n/, `\nMessage-Id: ${messageId}\n\n`);
  }
  msg.content = content;
  msg.size = content.length;
  pf(world, host, 'postfix/cleanup', `${msg.id}: message-id=${messageId}`, cleanup);
  pf(world, host, 'postfix/qmgr', `${msg.id}: from=<${msg.from}>, size=${msg.size}, nrcpt=${msg.rcpts.length} (queue active)`, loaded.qmgrPid);
  mailState(host).queue.push(msg);
  deliver(world, host, loaded, msg);
}

/** Submit a message from a local program (sendmail(1), bounces): no smtpd involved. */
export function submitLocal(world: World, host: Host, from: string, to: string[], content: string): string | null {
  const loaded = postfixLoaded(host);
  if (!loaded) return null;
  const id = newQueueId(world, host);
  pf(world, host, 'postfix/pickup', `${id}: uid=0 from=<${from}>`, procPid(host));
  enqueue(world, host, loaded, { id, from, rcpts: to.map((addr) => ({ addr })), size: 0, arrival: world.clock, content });
  return id;
}

interface Outcome { status: 'sent' | 'deferred' | 'bounced'; dsn: string; text: string; relay: string }

function delays(world: World, msg: QueuedMessage): string {
  const total = Math.max(0.01, (world.clock - msg.arrival) / 1000);
  return `delay=${total < 10 ? total.toFixed(2) : Math.round(total)}, delays=${(total * 0.4).toFixed(2)}/0.01/${(total * 0.3).toFixed(2)}/${(total * 0.3).toFixed(2)}`;
}

/** Try every recipient still in the message; remove it from the queue when none is left. */
export function deliver(world: World, host: Host, loaded: PostfixLoaded, msg: QueuedMessage): void {
  const cf = loaded.cf;
  const remaining: QueuedRcpt[] = [];
  const queue = [...msg.rcpts];
  const seen = new Set<string>();
  while (queue.length) {
    const r = queue.shift()!;
    const key = `${r.addr.toLowerCase()}|${r.orig ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    world.clock += 20;
    const local = isLocalDomain(host, cf, domainOf(r.addr));
    const pid = procPid(host);
    const prog = local ? 'postfix/local' : 'postfix/smtp';
    let out: Outcome;
    if (local) {
      const res = deliverLocal(world, host, cf, msg, r, pid, (extra) => queue.push(...extra));
      if (res === 'expanded') continue;
      out = res;
    } else out = deliverRemote(world, host, cf, msg, r, pid);
    const orig = r.orig && r.orig !== r.addr ? `, orig_to=<${r.orig}>` : '';
    pf(world, host, prog, `${msg.id}: to=<${r.addr}>${orig}, relay=${out.relay}, ${delays(world, msg)}, dsn=${out.dsn}, status=${out.status} (${out.text})`, pid);
    if (out.status === 'deferred') remaining.push({ ...r, reason: out.text });
    if (out.status === 'bounced' && msg.from) bounce(world, host, msg, r, out);
  }
  msg.rcpts = remaining;
  if (remaining.length) {
    msg.deferred = true;
    return;
  }
  pf(world, host, 'postfix/qmgr', `${msg.id}: removed`, loaded.qmgrPid);
  const st = mailState(host);
  st.queue = st.queue.filter((m) => m.id !== msg.id);
}

function bounce(world: World, host: Host, msg: QueuedMessage, r: QueuedRcpt, out: Outcome): void {
  const loaded = postfixLoaded(host);
  if (!loaded) return;
  const id = newQueueId(world, host);
  pf(world, host, 'postfix/bounce', `${msg.id}: sender non-delivery notification: ${id}`, procPid(host));
  const myhost = param(host, loaded.cf, 'myhostname');
  const content = `From: MAILER-DAEMON@${myhost} (Mail Delivery System)\nSubject: Undelivered Mail Returned to Sender\nTo: ${msg.from}\nDate: ${rfcDate(world.clock)}\n\nThis is the mail system at host ${myhost}.\n\nI'm sorry to have to inform you that your message could not\nbe delivered to one or more recipients.\n\n<${r.addr}>: ${out.text}\n`;
  const nested: QueuedMessage = { id, from: '', rcpts: [{ addr: msg.from }], size: 0, arrival: world.clock, content };
  pf(world, host, 'postfix/qmgr', `${id}: from=<>, size=${content.length}, nrcpt=1 (queue active)`, loaded.qmgrPid);
  mailState(host).queue.push(nested);
  deliver(world, host, loaded, nested);
}

/** Where a local user's mail goes: home_mailbox (Maildir/ or a file) or the spool file in mail_spool_directory. */
export function mailboxOf(host: Host, cf: MainCf, u: UserAccount): { kind: 'maildir' | 'mbox'; path: string } {
  const hm = param(host, cf, 'home_mailbox');
  if (hm) return { kind: hm.endsWith('/') ? 'maildir' : 'mbox', path: `${u.home.replace(/\/$/, '')}/${hm.replace(/\/$/, '')}` };
  return { kind: 'mbox', path: `${param(host, cf, 'mail_spool_directory').replace(/\/$/, '')}/${u.name}` };
}

function deliverLocal(world: World, host: Host, cf: MainCf, msg: QueuedMessage, r: QueuedRcpt, pid: number, expand: (extra: QueuedRcpt[]) => void): Outcome | 'expanded' {
  const local = stripExtension(host, cf, localOf(r.addr)).toLowerCase();
  // Aliases first (only for addresses that did not already come out of an alias).
  if (!r.orig || r.orig === r.addr) {
    const targets = aliasLookup(world, host, cf, local, true, pid);
    if (targets === 'unavailable') return { status: 'deferred', dsn: '4.3.0', text: 'alias database unavailable', relay: 'local' };
    if (targets) {
      const mydom = param(host, cf, 'myorigin');
      const extra: QueuedRcpt[] = [];
      for (const t of targets) {
        if (t.startsWith('/') || t.startsWith('|') || t.startsWith(':include:')) {
          extra.push({ addr: t, orig: r.orig ?? r.addr });
          continue;
        }
        const addr = t.includes('@') ? t : `${t}@${mydom}`;
        // An alias that names itself delivers to the account of that name.
        extra.push({ addr, orig: r.orig ?? r.addr });
      }
      expand(extra);
      return 'expanded';
    }
  }
  if (r.addr.startsWith('/')) {
    writeFile(host, r.addr, (readFile(host, r.addr) ?? '') + `From ${msg.from || 'MAILER-DAEMON'}  ${mboxTime(world.clock)}\n${msg.content}\n`, world.clock);
    return { status: 'sent', dsn: '2.0.0', text: `delivered to file: ${r.addr}`, relay: 'local' };
  }
  if (r.addr.startsWith('|')) return { status: 'sent', dsn: '2.0.0', text: `delivered to command: ${r.addr.slice(1).trim()}`, relay: 'local' };
  const u = Object.values(host.users).find((x) => x.name.toLowerCase() === local);
  if (!u) return { status: 'bounced', dsn: '5.1.1', text: `unknown user: "${local}"`, relay: 'local' };
  const box = mailboxOf(host, cf, u);
  const headers = `Return-Path: <${msg.from}>\nX-Original-To: ${r.orig ?? r.addr}\nDelivered-To: ${r.addr}\n`;
  if (box.kind === 'maildir') {
    const tmpName = `${Math.floor(world.clock / 1000)}.P${pid}Q${msg.id}.${host.hostname}`;
    const e = ensureMaildir(world, host, u, box.path);
    if (e) return { status: 'deferred', dsn: '4.2.0', text: `maildir delivery failed: create maildir file ${box.path}/tmp/${tmpName}: ${e}`, relay: 'local' };
    writeFile(host, `${box.path}/new/${tmpName}`, headers + msg.content, world.clock, { mode: 0o600, owner: u.name, group: u.primaryGroup });
    return { status: 'sent', dsn: '2.0.0', text: 'delivered to maildir', relay: 'local' };
  }
  const dir = dirname(box.path);
  const existing = host.fs[box.path];
  const parent = host.fs[dir];
  const spool = box.path.startsWith(param(host, cf, 'mail_spool_directory'));
  if (!parent || parent.type !== 'dir') return { status: 'deferred', dsn: '4.2.0', text: `cannot update mailbox ${box.path} for user ${u.name}. cannot open file: No such file or directory`, relay: 'local' };
  // The spool directory is group mail (setgid); home mailboxes are written as the user.
  const canWrite = existing ? canAccess(existing, u, 'w') : spool || (canTraverse(host, box.path, u) && canAccess(parent, u, 'w'));
  if (!canWrite) return { status: 'deferred', dsn: '4.2.0', text: `cannot update mailbox ${box.path} for user ${u.name}. cannot open file: Permission denied`, relay: 'local' };
  writeFile(host, box.path, `${existing?.content ?? ''}From ${msg.from || 'MAILER-DAEMON'}  ${mboxTime(world.clock)}\n${headers}${msg.content.replace(/\n?$/, '\n')}\n`, world.clock, existing ? undefined : { mode: 0o600, owner: u.name, group: spool ? 'mail' : u.primaryGroup });
  return { status: 'sent', dsn: '2.0.0', text: 'delivered to mailbox', relay: 'local' };
}

/** Create DIR/{cur,new,tmp} as the user (local(8) does), or say why it cannot. */
export function ensureMaildir(world: World, host: Host, u: UserAccount, dir: string): string | null {
  const parent = host.fs[dirname(dir)];
  if (!parent || parent.type !== 'dir') return 'No such file or directory';
  if (!canTraverse(host, dir, u)) return 'Permission denied';
  if (!host.fs[dir]) {
    if (!canAccess(parent, u, 'w')) return 'Permission denied';
    mkdir(host, dir, world.clock, { mode: 0o700, owner: u.name, group: u.primaryGroup });
  }
  for (const sub of ['tmp', 'new', 'cur']) {
    const p = `${dir}/${sub}`;
    if (host.fs[p]) {
      if (!canAccess(host.fs[p], u, 'w') || !canAccess(host.fs[p], u, 'x')) return 'Permission denied';
      continue;
    }
    if (!canAccess(host.fs[dir], u, 'w')) return 'Permission denied';
    mkdir(host, p, world.clock, { mode: 0o700, owner: u.name, group: u.primaryGroup });
  }
  return null;
}

/** MX records for DOMAIN from the host's first name server: [preference, name]. */
export function mxLookup(world: World, host: Host, domain: string): { ok: true; mx: [number, string][] } | { ok: false; error: 'nxdomain' | 'nodata' | 'temp' } {
  const rc = resolverConf(host);
  const ns = rc.nameservers[0] ?? '127.0.0.1';
  const ex = dnsQuery(world, host, ns, `${domain.replace(/\.$/, '')}.`, rc.timeout, 'MX');
  if (ex.outcome === 'nxdomain') return { ok: false, error: 'nxdomain' };
  if (ex.outcome === 'nodata') return { ok: false, error: 'nodata' };
  if (ex.outcome !== 'answer') return { ok: false, error: 'temp' };
  const mx = ex.answer!.answers.filter((a) => a.type === 'MX').map((a) => {
    const [pref, name] = a.data.split(/\s+/);
    return [Number(pref), name.replace(/\.$/, '')] as [number, string];
  }).sort((a, b) => a[0] - b[0]);
  return mx.length ? { ok: true, mx } : { ok: false, error: 'nodata' };
}

/** The next hop for a remote recipient: relayhost ([host] = no MX lookup) or the domain's MX hosts. */
function nextHops(world: World, host: Host, cf: MainCf, domain: string): { ok: true; hops: { name: string; port: number }[] } | { ok: false; text: string; bounce?: boolean } {
  const rh = param(host, cf, 'relayhost').trim();
  if (rh) {
    const m = /^(\[)?([^\]:]+)\]?(?::(\d+))?$/.exec(rh);
    if (!m) return { ok: false, text: `bad relayhost syntax: ${rh}` };
    const port = Number(m[3] ?? 25);
    if (m[1] || /^[\d.]+$/.test(m[2])) return { ok: true, hops: [{ name: m[2], port }] };
    const mx = mxLookup(world, host, m[2]);
    if (mx.ok) return { ok: true, hops: mx.mx.map(([, n]) => ({ name: n, port })) };
    if (mx.error === 'temp') return { ok: false, text: `Host or domain name not found. Name service error for name=${m[2]} type=MX: Host not found, try again` };
    return { ok: true, hops: [{ name: m[2], port }] };
  }
  const mx = mxLookup(world, host, domain);
  if (mx.ok) return { ok: true, hops: mx.mx.map(([, n]) => ({ name: n, port: 25 })) };
  if (mx.error === 'temp') return { ok: false, text: `Host or domain name not found. Name service error for name=${domain} type=MX: Host not found, try again` };
  if (mx.error === 'nxdomain') return { ok: false, text: `Host or domain name not found. Name service error for name=${domain} type=MX: Host not found`, bounce: true };
  return { ok: true, hops: [{ name: domain, port: 25 }] };
}

function deliverRemote(world: World, host: Host, cf: MainCf, msg: QueuedMessage, r: QueuedRcpt, pid: number): Outcome {
  const hops = nextHops(world, host, cf, domainOf(r.addr));
  if (!hops.ok) return { status: hops.bounce ? 'bounced' : 'deferred', dsn: hops.bounce ? '5.4.4' : '4.4.3', text: hops.text, relay: 'none' };
  let lastText = '';
  for (const hop of hops.hops) {
    // smtp_host_lookup = dns: Postfix's SMTP client asks DNS, not /etc/hosts.
    const res = resolve(world, host, hop.name, { family: 4, useHostsFile: false });
    if (!res.ok) {
      lastText = `Host or domain name not found. Name service error for name=${hop.name} type=A: Host not found${res.error === 'EAI_AGAIN' ? ', try again' : ''}`;
      continue;
    }
    const ip = res.ip;
    const c = tcpConnect(world, host, ip, hop.port, { timeoutMs: 30_000 });
    if (!c.ok) {
      const why = c.errno === 'ECONNREFUSED' ? 'Connection refused' : c.errno === 'ETIMEDOUT' ? 'Connection timed out' : c.errno === 'EHOSTUNREACH' ? 'No route to host' : 'Network is unreachable';
      lastText = `connect to ${hop.name}[${ip}]:${hop.port}: ${why}`;
      pf(world, host, 'postfix/smtp', `${lastText}`, pid, 'info');
      continue;
    }
    const peer = `${hop.name}[${ip}]:${hop.port}`;
    const conv = smtpConversation(world, c.conn, {
      helo: param(host, cf, 'myhostname'), from: msg.from, to: [r.addr], content: msg.content,
      tls: param(host, cf, 'smtp_tls_security_level') === 'encrypt' ? 'required' : param(host, cf, 'smtp_tls_security_level') === 'may' ? 'opportunistic' : 'none',
    });
    c.conn.close('client');
    const dot = conv.steps.find((s) => s.cmd === '.');
    if (conv.result === 'sent') return { status: 'sent', dsn: '2.0.0', text: dot?.reply ? replyLines(dot.reply).join(' ') : '250 2.0.0 Ok', relay: peer };
    if (conv.result === 'closed') {
      const during: Record<string, string> = { banner: 'receiving the initial server greeting', ehlo: 'performing the EHLO handshake', tls: 'sending STARTTLS', auth: 'performing SASL authentication', mail: 'sending MAIL FROM', rcpt: 'sending RCPT TO', data: 'sending message body' };
      lastText = `lost connection with ${hop.name}[${ip}] while ${during[conv.failedAt ?? 'banner'] ?? during.banner}`;
      continue;
    }
    // The reply that failed: the last one with an error code (QUIT follows it).
    const failed = [...conv.steps].reverse().find((s) => s.reply && s.reply.code >= 400 && s.cmd !== 'QUIT');
    if (!failed?.reply) { lastText = `TLS is required, but was not offered by host ${hop.name}[${ip}]`; continue; }
    const code = failed.reply.code;
    const verb = failed.cmd.split(':')[0];
    const said = `host ${hop.name}[${ip}] said: ${replyLines(failed.reply).join(' ')} (in reply to ${failed.cmd === '.' ? 'end of DATA' : /^(MAIL FROM|RCPT TO)$/.test(verb) ? verb : verb.split(' ')[0]} command)`;
    const enh = /^(\d\.\d+\.\d+)/.exec(failed.reply.text[0])?.[1] ?? (code >= 500 ? '5.0.0' : '4.0.0');
    return { status: code >= 500 ? 'bounced' : 'deferred', dsn: enh, text: said, relay: peer };
  }
  return { status: 'deferred', dsn: lastText.startsWith('Host or domain') ? '4.4.3' : '4.4.1', text: lastText || 'delivery temporarily suspended', relay: 'none' };
}

/** postqueue -f / postfix flush: retry every deferred message now. */
export function flushQueue(world: World, host: Host): void {
  const loaded = postfixLoaded(host);
  if (!loaded) return;
  for (const msg of [...mailState(host).queue]) {
    msg.deferred = false;
    deliver(world, host, loaded, msg);
  }
}

// ---------------------------------------------------------------------------
// The client side of an SMTP conversation (swaks, Postfix's smtp client)
// ---------------------------------------------------------------------------

export interface ConvStep { cmd: string; reply?: Reply; tls: boolean; /** Not sent: a client-side event ("=== TLS started"). */ note?: string }
export interface ConvOptions {
  helo: string;
  from: string;
  to: string[];
  content: string;
  tls: 'none' | 'opportunistic' | 'required' | 'wrapper';
  auth?: { mech: string; user: string; password: string };
  /** swaks --quit-after */
  quitAfter?: string;
}
export interface ConvResult {
  steps: ConvStep[];
  result: 'sent' | 'rejected' | 'closed' | 'no-tls' | 'no-auth' | 'auth-failed' | 'tls-failed';
  /** The step that failed (index into steps). */
  failedAt?: string;
  /** Certificates the server presented (after STARTTLS or wrapper mode). */
  peerChain?: Cert[];
}

/** Find the smtpd that accepted this connection: Postfix's listener on the server port. */
function smtpdFor(world: World, conn: TcpConn): Smtpd | null {
  const server = conn.server;
  const loaded = postfixLoaded(server);
  if (!loaded) return null;
  const l = allListeners(server).find((x) => x.proto === 'tcp' && x.port === conn.sv.localPort && x.service === 'postfix');
  if (!l) return null;
  const svc = loaded.services.find((s) => s.port === conn.sv.localPort);
  return svc ? new Smtpd(world, server, loaded, svc, conn, conn.sv.peer) : null;
}

/** Is a mail service (Postfix or Dovecot) the program that owns this port? */
export function mailListenerOwner(host: Host, port: number): string | null {
  return allListeners(host).find((x) => x.proto === 'tcp' && x.port === port)?.service ?? null;
}

/**
 * Run an SMTP dialogue on an established TCP connection and record every step.
 * Traffic is sent on the connection so captures show it.
 */
export function smtpConversation(world: World, conn: TcpConn, o: ConvOptions): ConvResult {
  const steps: ConvStep[] = [];
  const smtpd = smtpdFor(world, conn);
  let tls = false;
  const wire = (dir: 'c2s' | 's2c', text: string) => conn.send(dir, text.length + 2, { protocol: tls ? 'TLS' : 'SMTP', info: tls ? 'Application Data' : text.split('\n')[0].slice(0, 80), fields: [] });
  const exchange = (cmd: string, fn: () => Reply): Reply | null => {
    wire('c2s', cmd);
    const r = fn();
    steps.push({ cmd, reply: r.closed ? undefined : r, tls });
    if (r.closed) return null;
    wire('s2c', replyLines(r).join('\n'));
    return r;
  };
  const end = (result: ConvResult['result'], failedAt?: string, quit = true): ConvResult => {
    if (quit && smtpd && !smtpd.closed) exchange('QUIT', () => smtpd.quit());
    else if (smtpd && !smtpd.closed) smtpd.disconnect(failedAt?.toUpperCase());
    return { steps, result, failedAt, peerChain: smtpd?.tls?.chain };
  };
  if (!smtpd) {
    // Something else answered on the port (or nothing that speaks SMTP).
    steps.push({ cmd: '', tls: false });
    return { steps, result: 'closed', failedAt: 'banner' };
  }
  const startTls = (): boolean => {
    if (!smtpd.tls) return false;
    conn.send('c2s', 517, { protocol: 'TLS', info: 'Client Hello', fields: [] });
    conn.send('s2c', 2400, { protocol: 'TLS', info: 'Server Hello, Change Cipher Spec, Application Data', fields: [] });
    tls = true;
    steps.push({ cmd: '', tls: true, note: 'tls-started' });
    return true;
  };
  if (smtpd.wrapper && o.tls !== 'wrapper') {
    // A plain client on a wrapper-mode port: the server waits for a ClientHello.
    smtpd.connect();
    steps.push({ cmd: '', tls: false });
    smtpd.disconnect('CONNECT');
    return { steps, result: 'closed', failedAt: 'banner' };
  }
  const banner = smtpd.connect();
  if (o.tls === 'wrapper') {
    // TLS from the first byte only works on a wrapper-mode port: elsewhere the client reads "220 ..." as a TLS record.
    if (banner.closed || !smtpd.tls || !smtpd.wrapper) {
      smtpd.disconnect('CONNECT');
      steps.push({ cmd: '', tls: false });
      return { steps, result: 'tls-failed', failedAt: 'tls' };
    }
    startTls();
    const dead = smtpd.tlsStarted();
    if (dead) { steps.push({ cmd: '', tls: true }); return { steps, result: 'closed', failedAt: 'banner' }; }
  }
  if (banner.closed) { steps.push({ cmd: '', tls }); return { steps, result: 'closed', failedAt: 'banner' }; }
  steps.push({ cmd: '', reply: banner, tls });
  wire('s2c', replyLines(banner).join('\n'));
  if (o.quitAfter === 'connect' || o.quitAfter === 'banner') return end('sent');
  let ehlo = exchange(`EHLO ${o.helo}`, () => smtpd.ehlo(o.helo));
  if (!ehlo) return end('closed', 'ehlo', false);
  if (o.quitAfter === 'ehlo' || o.quitAfter === 'first-helo') return end('sent');
  if (o.tls === 'opportunistic' || o.tls === 'required') {
    const offered = ehlo.text.some((t) => t.toUpperCase() === 'STARTTLS');
    if (!offered) {
      if (o.tls === 'required') return end('no-tls', 'tls');
    } else {
      const st = exchange('STARTTLS', () => smtpd.starttls());
      if (!st) return end('closed', 'tls', false);
      if (st.code !== 220) { if (o.tls === 'required') return end('tls-failed', 'tls'); } else {
        startTls();
        const dead = smtpd.tlsStarted();
        if (dead) {
          wire('c2s', `EHLO ${o.helo}`);
          steps.push({ cmd: `EHLO ${o.helo}`, tls: true });
          return end('closed', 'ehlo', false);
        }
        ehlo = exchange(`EHLO ${o.helo}`, () => smtpd.ehlo(o.helo));
        if (!ehlo) return end('closed', 'ehlo', false);
      }
    }
  }
  if (o.quitAfter === 'tls') return end('sent');
  if (o.auth) {
    const authLine = ehlo.text.find((t) => /^AUTH\b/i.test(t));
    if (!authLine) return end('no-auth', 'auth');
    const mechs = authLine.split(/\s+/).slice(1).map((m) => m.toUpperCase());
    const mech = o.auth.mech === 'ANY' ? (mechs.includes('PLAIN') ? 'PLAIN' : mechs[0]) : o.auth.mech.toUpperCase();
    if (!mechs.includes(mech)) return end('no-auth', 'auth');
    const b64 = typeof btoa === 'function' ? btoa(`\0${o.auth.user}\0${o.auth.password}`) : `\0${o.auth.user}\0${o.auth.password}`;
    const a = exchange(mech === 'PLAIN' ? `AUTH PLAIN ${b64}` : 'AUTH LOGIN', () => smtpd.auth(mech, o.auth!.user, o.auth!.password));
    if (!a) return end('closed', 'auth', false);
    if (a.code !== 235) return end('auth-failed', 'auth');
  }
  if (o.quitAfter === 'auth') return end('sent');
  const m = exchange(`MAIL FROM:<${o.from}>`, () => smtpd.mail(`FROM:<${o.from}>`));
  if (!m) return end('closed', 'mail', false);
  if (m.code !== 250) return end('rejected', 'mail');
  if (o.quitAfter === 'mail' || o.quitAfter === 'from') return end('sent');
  let accepted = 0;
  for (const to of o.to) {
    const r = exchange(`RCPT TO:<${to}>`, () => smtpd.rcpt(`TO:<${to}>`));
    if (!r) return end('closed', 'rcpt', false);
    if (r.code === 250) accepted++;
  }
  if (!accepted) return end('rejected', 'rcpt');
  if (o.quitAfter === 'rcpt' || o.quitAfter === 'to') return end('sent');
  const d = exchange('DATA', () => reply(354, 'End data with <CR><LF>.<CR><LF>'));
  if (!d) return end('closed', 'data', false);
  conn.send('c2s', o.content.length + 5, { protocol: tls ? 'TLS' : 'SMTP', info: tls ? 'Application Data' : 'DATA fragment', fields: [] });
  const fin = smtpd.data(o.content);
  steps.push({ cmd: '.', reply: fin, tls });
  wire('s2c', replyLines(fin).join('\n'));
  if (fin.code !== 250) return end('rejected', 'data');
  return end('sent');
}

/** For tests and goals: the content of every message delivered to a user's Maildir or mbox, oldest first. */
export function mailboxMessages(host: Host, path: string, kind: 'maildir' | 'mbox'): { name: string; content: string; seen: boolean }[] {
  if (kind === 'maildir') {
    const out: { name: string; content: string; seen: boolean; mtime: number }[] = [];
    for (const sub of ['cur', 'new']) {
      const dir = `${path}/${sub}`;
      if (host.fs[dir]?.type !== 'dir') continue;
      for (const f of listDir(host, dir)) {
        const n = host.fs[`${dir}/${f}`];
        if (n?.type === 'file') out.push({ name: `${sub}/${f}`, content: n.content, seen: sub === 'cur' && /:2,.*S/.test(f), mtime: n.mtime });
      }
    }
    // Delivery order (the file times), not the names: "P99" would sort after "P100".
    return out.sort((a, b) => a.mtime - b.mtime || a.name.localeCompare(b.name)).map(({ mtime: _m, ...m }) => m);
  }
  const text = readFile(host, path);
  if (!text) return [];
  return text.split(/^(?=From \S+ {1,2}\w{3} \w{3} )/m).filter((m) => m.startsWith('From ')).map((m, i) => ({ name: String(i + 1), content: m.slice(m.indexOf('\n') + 1).replace(/\n$/, ''), seen: /^Status: R/m.test(m) }));
}
