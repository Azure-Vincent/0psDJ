// Dovecot: the IMAP server users read their mail with, and the SASL
// authentication service Postfix uses for submission (port 587). The model
// covers what breaks in practice: dovecot.conf with its !include files,
// settings in nested sections (service imap-login { inet_listener ... },
// service auth { unix_listener /var/spool/postfix/private/auth ... }),
// ssl and disable_plaintext_auth, mail_location (where Dovecot looks for the
// mail Postfix delivered), PAM logins against the Unix passwords, and the log
// lines of imap-login and auth. Versions and texts follow Dovecot 2.3.19.1 on
// Debian 12.

import { dirname, listDir, mkdir, readFile, writeFile } from '../fs';
import type { Host, ServiceRuntime, UserAccount, World } from '../types';
import { seededInt } from '../util/sha256';
import { log } from './journal';
import { type DovecotAuthView, mailboxMessages, saslHooks, type TlsFiles, unixPasswordOk } from './mail';
import { parseCerts, parseKey, type Cert } from './pki';

export const DOVECOT_CONF = '/etc/dovecot/dovecot.conf';
export const DOVECOT_VERSION = '2.3.19.1 (9b53102964)';

export interface DcSection { type: string; name: string; settings: Record<string, string>; sections: DcSection[]; file: string; line: number }
export interface DcConfig { root: DcSection; errors: string[]; /** settings with the file and line that set them (for doveconf -n order). */ order: { key: string; file: string; line: number }[] }

/** Settings Dovecot accepts at the top level (and the defaults doveconf prints). */
export const DOVECOT_DEFAULTS: Record<string, string> = {
  auth_mechanisms: 'plain',
  auth_username_format: '%Lu',
  auth_verbose: 'no',
  auth_debug: 'no',
  auth_failure_delay: '2 secs',
  base_dir: '/run/dovecot',
  disable_plaintext_auth: 'yes',
  first_valid_uid: '500',
  hostname: '',
  info_log_path: '',
  instance_name: 'dovecot',
  listen: '*, ::',
  log_path: 'syslog',
  login_greeting: 'Dovecot ready.',
  login_trusted_networks: '',
  mail_access_groups: '',
  mail_debug: 'no',
  mail_location: '',
  mail_max_userip_connections: '10',
  mail_plugins: '',
  mail_privileged_group: '',
  postmaster_address: 'postmaster@%{if;%d;ne;;%d;%{hostname}}',
  protocols: 'imap pop3 lmtp',
  recipient_delimiter: '+',
  shutdown_clients: 'yes',
  ssl: 'yes',
  ssl_ca: '',
  ssl_cert: '',
  ssl_cipher_list: 'ALL:!kRSA:!SRP:!kDHd:!DSS:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK:!RC4:!ADH:!LOW@STRENGTH',
  ssl_client_ca_dir: '',
  ssl_client_ca_file: '',
  ssl_dh: '',
  ssl_key: '',
  ssl_min_protocol: 'TLSv1.2',
  ssl_prefer_server_ciphers: 'no',
  syslog_facility: 'mail',
  verbose_proctitle: 'no',
};
const SECTIONS = new Set(['service', 'inet_listener', 'unix_listener', 'fifo_listener', 'passdb', 'userdb', 'namespace', 'mailbox', 'protocol', 'plugin', 'dict', 'local', 'remote', 'auth_policy', 'ssl_server', 'ssl_client']);

/** Read dovecot.conf and its !include / !include_try files into a tree. */
export function loadDovecotConf(host: Host): DcConfig {
  const root: DcSection = { type: '', name: '', settings: {}, sections: [], file: DOVECOT_CONF, line: 0 };
  const errors: string[] = [];
  const order: DcConfig['order'] = [];
  const stack: DcSection[] = [root];
  const readOne = (file: string, depth: number) => {
    const text = readFile(host, file);
    if (text === undefined) { errors.push(`doveconf: Fatal: Error in configuration file ${file}: open(${file}) failed: No such file or directory`); return; }
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const at = `Error in configuration file ${file} line ${i + 1}`;
      const line = lines[i].replace(/(^|\s)#.*$/, '').trim();
      if (!line) continue;
      const inc = /^!(include|include_try)\s+(\S+)$/.exec(line);
      if (inc) {
        if (depth > 8) continue;
        const pattern = inc[2].startsWith('/') ? inc[2] : `${dirname(file)}/${inc[2]}`;
        const matches = expandGlob(host, pattern);
        if (!matches.length && inc[1] === 'include' && !pattern.includes('*')) errors.push(`doveconf: Fatal: ${at}: include ${pattern}: open(${pattern}) failed: No such file or directory`);
        for (const m of matches) readOne(m, depth + 1);
        continue;
      }
      if (line === '}') {
        if (stack.length === 1) { errors.push(`doveconf: Fatal: ${at}: Unexpected '}'`); continue; }
        stack.pop();
        continue;
      }
      const sec = /^([A-Za-z_][\w-]*)(?:\s+("[^"]*"|[^\s{]+))?\s*\{$/.exec(line);
      if (sec) {
        if (!SECTIONS.has(sec[1])) { errors.push(`doveconf: Fatal: ${at}: Unknown section name: ${sec[1]}`); }
        const s: DcSection = { type: sec[1], name: (sec[2] ?? '').replace(/"/g, ''), settings: {}, sections: [], file, line: i + 1 };
        stack[stack.length - 1].sections.push(s);
        stack.push(s);
        continue;
      }
      const kv = /^([A-Za-z_][\w-]*)\s*=\s*(.*)$/.exec(line);
      if (!kv) { errors.push(`doveconf: Fatal: ${at}: Expecting '='`); continue; }
      const cur = stack[stack.length - 1];
      let value = kv[2].trim().replace(/^"(.*)"$/, '$1');
      if (cur === root && !(kv[1] in DOVECOT_DEFAULTS)) { errors.push(`doveconf: Fatal: ${at}: Unknown setting: ${kv[1]}`); continue; }
      // "$name" refers to the earlier value of a setting (protocols = $protocols imap).
      value = value.replace(/\$(\w+)/g, (_m, n) => cur.settings[n] ?? (cur === root ? '' : ''));
      if (value.startsWith('<')) {
        const path = value.slice(1).trim();
        if (readFile(host, path) === undefined) { errors.push(`doveconf: Fatal: ${at}: ${kv[1]}: Can't open file ${path}: No such file or directory`); continue; }
      }
      cur.settings[kv[1]] = value;
      if (cur === root) order.push({ key: kv[1], file, line: i + 1 });
    }
  };
  readOne(DOVECOT_CONF, 0);
  if (stack.length > 1 && !errors.length) errors.push(`doveconf: Fatal: Error in configuration file ${stack[stack.length - 1].file}: Missing '}'`);
  return { root, errors, order };
}

function expandGlob(host: Host, pattern: string): string[] {
  if (!pattern.includes('*')) return host.fs[pattern]?.type === 'file' ? [pattern] : [];
  const dir = dirname(pattern);
  const re = new RegExp('^' + pattern.slice(dir.length + 1).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$');
  return host.fs[dir]?.type === 'dir' ? listDir(host, dir).filter((f) => re.test(f) && host.fs[`${dir}/${f}`].type === 'file').sort().map((f) => `${dir}/${f}`) : [];
}

export const dcSetting = (c: DcConfig, key: string) => c.root.settings[key] ?? DOVECOT_DEFAULTS[key] ?? '';
const yes = (v: string) => /^(yes|true|1)$/i.test(v.trim());
const sections = (s: DcSection, type: string, name?: string) => s.sections.filter((x) => x.type === type && (name === undefined || x.name === name));

export interface DovecotLoaded {
  pid: number;
  protocols: string[];
  listen: string[];
  imap: { name: string; port: number; ssl: boolean }[];
  ssl: 'no' | 'yes' | 'required';
  tls: TlsFiles | null;
  tlsError?: string;
  disablePlaintext: boolean;
  mechanisms: string[];
  mailLocation: string;
  /** UNIX sockets of the auth service (absolute paths), e.g. Postfix's /var/spool/postfix/private/auth. */
  authSockets: string[];
  greeting: string;
}

/** The effective values Dovecot runs with (also used by doveconf). */
export function dovecotEffective(host: Host, c: DcConfig): Omit<DovecotLoaded, 'pid'> {
  const protocols = dcSetting(c, 'protocols').split(/\s+/).filter(Boolean);
  const listen = dcSetting(c, 'listen').split(/[\s,]+/).filter(Boolean).map((a) => (a === '*' ? '0.0.0.0' : a));
  const ssl = (dcSetting(c, 'ssl').toLowerCase() as DovecotLoaded['ssl']);
  const login = sections(c.root, 'service', 'imap-login')[0];
  const listeners = login ? sections(login, 'inet_listener') : [];
  const def = [{ name: 'imap', port: 143, ssl: false }, { name: 'imaps', port: 993, ssl: true }];
  const imap = def.map((d) => {
    const l = listeners.find((x) => x.name === d.name);
    return { name: d.name, port: l?.settings.port !== undefined ? Number(l.settings.port) : d.port, ssl: l?.settings.ssl !== undefined ? yes(l.settings.ssl) : d.ssl };
  }).concat(listeners.filter((l) => !def.some((d) => d.name === l.name)).map((l) => ({ name: l.name, port: Number(l.settings.port ?? 0), ssl: yes(l.settings.ssl ?? 'no') })))
    .filter((l) => l.port > 0 && (!l.ssl || ssl !== 'no'));
  const auth = sections(c.root, 'service', 'auth')[0];
  const base = dcSetting(c, 'base_dir');
  const authSockets = [`${base}/auth-client`, `${base}/auth-userdb`, ...(auth ? sections(auth, 'unix_listener').map((u) => (u.name.startsWith('/') ? u.name : `${base}/${u.name}`)) : [])];
  let tls: TlsFiles | null = null;
  let tlsError: string | undefined;
  if (ssl !== 'no') {
    const certSpec = dcSetting(c, 'ssl_cert');
    const keySpec = dcSetting(c, 'ssl_key');
    if (!certSpec) tlsError = 'ssl enabled, but ssl_cert not set';
    else if (!keySpec) tlsError = 'ssl enabled, but ssl_key not set';
    else {
      const chain = parseCerts(readFile(host, certSpec.replace(/^</, '').trim()) ?? '').filter((x): x is Cert => !!x);
      const key = parseKey(readFile(host, keySpec.replace(/^</, '').trim()) ?? '');
      if (!chain.length) tlsError = "Can't load SSL certificate: There is no valid PEM certificate.";
      else if (!key) tlsError = "Can't load SSL private key: There is no valid PEM private key.";
      else if (key.keyId !== chain[0].keyId) tlsError = "Can't load SSL certificate: error:05800074:x509 certificate routines::key values mismatch";
      else tls = { chain, keyId: key.keyId };
    }
  }
  return {
    protocols, listen, imap, ssl, tls, tlsError,
    disablePlaintext: yes(dcSetting(c, 'disable_plaintext_auth')),
    mechanisms: dcSetting(c, 'auth_mechanisms').split(/\s+/).filter(Boolean),
    mailLocation: dcSetting(c, 'mail_location'),
    authSockets,
    greeting: dcSetting(c, 'login_greeting'),
  };
}

const dlog = (world: World, host: Host, msg: string, pid: number | null, priority: 'info' | 'warning' | 'err' | 'crit' = 'info') =>
  log(world, host, 'dovecot', msg, { pid, unit: 'dovecot.service', priority, facility: 'mail' });

export function dovecotStart(world: World, host: Host, rt: ServiceRuntime, reload: boolean): DovecotLoaded | null {
  saslHooks.dovecot ??= authView;
  const pid = rt.pid!;
  const c = loadDovecotConf(host);
  if (c.errors.length) {
    for (const e of c.errors) log(world, host, 'dovecot', e, { pid, unit: 'dovecot.service', priority: 'crit', facility: 'mail' });
    return null;
  }
  const eff = dovecotEffective(host, c);
  if (eff.ssl === 'required' && eff.tlsError) {
    dlog(world, host, `doveconf: Fatal: ${eff.tlsError}`, pid, 'crit');
    return null;
  }
  // The auth service creates its UNIX sockets; a listener in a missing directory stops Dovecot.
  for (const s of eff.authSockets) {
    const parent = dirname(s);
    if (!host.fs[parent]) {
      if (parent === '/run/dovecot') mkdir(host, parent, world.clock, { mode: 0o755 });
      else {
        dlog(world, host, `Fatal: service(auth) bind(${s}) failed: No such file or directory`, pid, 'crit');
        return null;
      }
    }
  }
  removeSockets(host, rt);
  const auth = sections(c.root, 'service', 'auth')[0];
  for (const s of eff.authSockets) {
    const l = auth ? sections(auth, 'unix_listener').find((u) => (u.name.startsWith('/') ? u.name : `${dcSetting(c, 'base_dir')}/${u.name}`) === s) : undefined;
    writeFile(host, s, '', world.clock, { mode: parseInt(l?.settings.mode ?? '0666', 8) || 0o666, owner: l?.settings.user || 'root', group: l?.settings.group || 'root' });
    host.fs[s].socket = true;
  }
  if (reload) dlog(world, host, 'master: Warning: SIGHUP received - reloading configuration', pid, 'warning');
  else dlog(world, host, `master: Dovecot v${DOVECOT_VERSION} starting up for ${eff.protocols.join(', ')} (core dumps disabled)`, pid);
  return { pid, ...eff };
}

/** Sockets go away when the service stops (the files a previous start created). */
export function removeSockets(host: Host, rt: ServiceRuntime): void {
  const l = rt.loaded as DovecotLoaded | null;
  for (const s of l?.authSockets ?? []) if (host.fs[s]?.socket) delete host.fs[s];
}

export function dovecotLoaded(host: Host): DovecotLoaded | null {
  const rt = host.services.dovecot;
  return rt?.state === 'active' ? (rt.loaded as DovecotLoaded) : null;
}

/** PAM (pam_unix) for a Dovecot login, with the log lines a failure leaves. */
export function dovecotAuth(world: World, host: Host, user: string, password: string, rhost: string): UserAccount | null {
  const u = unixPasswordOk(world, host, user, password);
  if (!u) {
    world.clock += 2000;
    log(world, host, 'dovecot', `auth: pam_unix(dovecot:auth): ${host.users[user] ? 'authentication failure' : `check pass; user unknown`}; logname= uid=0 euid=0 tty=dovecot ruser=${user} rhost=${rhost} ${host.users[user] ? ` user=${user}` : ''}`.trimEnd(), { pid: null, unit: 'dovecot.service', priority: 'notice', facility: 'auth' });
  }
  return u;
}

/** Dovecot's auth service as Postfix sees it through the socket (registered when Dovecot starts: mail.ts and this module import each other). */
function authView(world: World, host: Host): DovecotAuthView | null {
  const l = dovecotLoaded(host);
  if (!l) return null;
  return { sockets: l.authSockets, mechanisms: l.mechanisms, check: (user, password) => !!dovecotAuth(world, host, user, password, '127.0.0.1') };
}

/** Where Dovecot looks for a user's INBOX, from mail_location ("maildir:~/Maildir", "mbox:~/mail:INBOX=/var/mail/%u"). */
export function inboxOf(loc: string, u: UserAccount): { kind: 'maildir' | 'mbox'; path: string } | null {
  const sub = (p: string) => p.replace(/^~/, u.home.replace(/\/$/, '')).replace(/%u|%n|%\{user\}/g, u.name);
  const m = /^(maildir|mbox):([^:]+)(.*)$/.exec(loc.trim());
  if (!m) {
    // Empty mail_location: Dovecot autodetects ~/Maildir, then /var/mail/%u.
    return null;
  }
  if (m[1] === 'maildir') return { kind: 'maildir', path: sub(m[2]) };
  const inbox = /:INBOX=([^:]+)/.exec(m[3]);
  return { kind: 'mbox', path: inbox ? sub(inbox[1]) : `/var/mail/${u.name}` };
}

/** The messages in a user's INBOX as Dovecot sees them (oldest first, UID = position). */
export function inboxMessages(host: Host, loaded: DovecotLoaded, u: UserAccount): { uid: number; content: string; seen: boolean }[] {
  let loc = inboxOf(loaded.mailLocation, u);
  if (!loc) loc = host.fs[`${u.home}/Maildir`]?.type === 'dir' ? { kind: 'maildir', path: `${u.home}/Maildir` } : { kind: 'mbox', path: `/var/mail/${u.name}` };
  return mailboxMessages(host, loc.path, loc.kind).map((m, i) => ({ uid: i + 1, content: m.content, seen: m.seen }));
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
/** Dovecot's session ID: 16 base64 characters. */
export const sessionId = (world: World) => {
  const n = world.counter++;
  return Array.from({ length: 16 }, (_, i) => B64[seededInt(`dc:${n}:${i}`, 0, 63)]).join('');
};

/** imap-login's log line for a connection that ended. */
export function imapLoginLog(world: World, host: Host, text: string): void {
  dlog(world, host, `imap-login: ${text}`, null);
}

export { dlog as dovecotLog };

// ---------------------------------------------------------------------------
// IMAP (imap-login, then imap as the user)
// ---------------------------------------------------------------------------

const PRE_CAPS = 'IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+';
const POST_CAPS = 'IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY PREVIEW STATUS=SIZE SAVEDATE LITERAL+ NOTIFY SPECIAL-USE';

/** One IMAP connection to Dovecot: login (PAM), then mailbox commands on the user's INBOX. */
export class Imapd {
  tlsActive: boolean;
  user: UserAccount | null = null;
  session: string;
  mpid = 0;
  attempts = 0;
  lastUser = '';
  bytesOut = 0;
  selected = false;
  closed = false;
  private started: number;

  constructor(public world: World, public host: Host, public loaded: DovecotLoaded, public clientIp: string, public localIp: string, port: number) {
    this.tlsActive = !!loaded.imap.find((l) => l.port === port)?.ssl;
    this.session = sessionId(world);
    this.started = world.clock;
  }

  get tlsUsable() { return !!this.loaded.tls; }
  private get plaintextOk() { return this.tlsActive || !this.loaded.disablePlaintext || this.clientIp.startsWith('127.') || this.clientIp === this.localIp; }

  capabilities(): string {
    const caps = [PRE_CAPS];
    if (!this.tlsActive && this.tlsUsable) caps.push('STARTTLS');
    if (this.plaintextOk) caps.push(...this.loaded.mechanisms.map((m) => `AUTH=${m.toUpperCase()}`));
    else caps.push('LOGINDISABLED');
    return caps.join(' ');
  }

  greeting(): string {
    return `* OK [CAPABILITY ${this.capabilities()}] ${this.loaded.greeting === 'Dovecot ready.' ? 'Dovecot (Debian) ready.' : this.loaded.greeting}`;
  }

  /** TLS for imaps, or after STARTTLS: false (and a log line) when Dovecot cannot load its certificate. */
  tlsFailed(): boolean {
    if (this.loaded.tls) return false;
    dlog(this.world, this.host, `imap-login: Error: Failed to initialize SSL server context: ${this.loaded.tlsError ?? 'ssl disabled'}: user=<>, rip=${this.clientIp}, lip=${this.localIp}, session=<${this.session}>`, null, 'err');
    return true;
  }

  starttls(tag: string): string {
    if (this.tlsActive) return `${tag} BAD TLS is already active.`;
    if (!this.tlsUsable) return `${tag} BAD Unknown command.`;
    this.tlsActive = true;
    return `${tag} OK Begin TLS negotiation now.`;
  }

  private where() { return `rip=${this.clientIp}, lip=${this.localIp}${this.tlsActive ? ', TLS' : ''}, session=<${this.session}>`; }

  /** LOGIN or AUTHENTICATE PLAIN. */
  login(tag: string, user: string, password: string, method: string): string {
    if (!this.plaintextOk) {
      return `${tag} NO [PRIVACYREQUIRED] Plaintext authentication disallowed on non-secure (SSL/TLS) connections.`;
    }
    this.attempts++;
    this.lastUser = user;
    const u = dovecotAuth(this.world, this.host, user, password, this.clientIp);
    if (!u) return `${tag} NO [AUTHENTICATIONFAILED] Authentication failed.`;
    this.user = u;
    this.mpid = this.host.nextPid += 2;
    dlog(this.world, this.host, `imap-login: Login: user=<${u.name}>, method=${method}, rip=${this.clientIp}, lip=${this.localIp}, mpid=${this.mpid}${this.tlsActive ? ', TLS' : ''}, session=<${this.session}>`, null);
    return `${tag} OK [CAPABILITY ${POST_CAPS}] Logged in`;
  }

  private messages() { return this.user ? inboxMessages(this.host, this.loaded, this.user) : []; }

  list(): string[] {
    return ['* LIST (\\HasNoChildren) "." INBOX'];
  }

  select(mailbox: string, readOnly: boolean): string[] | null {
    if (mailbox.toUpperCase() !== 'INBOX') return null;
    this.selected = true;
    const msgs = this.messages();
    return [
      '* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)',
      readOnly ? '* OK [PERMANENTFLAGS ()] Read-only mailbox.' : '* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Flags permitted.',
      `* ${msgs.length} EXISTS`,
      '* 0 RECENT',
      ...(msgs.some((m) => !m.seen) ? [`* OK [UNSEEN ${msgs.findIndex((m) => !m.seen) + 1}] First unseen.`] : []),
      `* OK [UIDVALIDITY ${Math.floor(this.host.bootTime / 1000) % 1_000_000_000}] UIDs valid`,
      `* OK [UIDNEXT ${msgs.length + 1}] Predicted next UID`,
    ];
  }

  status(mailbox: string, items: string[]): string | null {
    if (mailbox.toUpperCase() !== 'INBOX') return null;
    const msgs = this.messages();
    const val: Record<string, number> = { MESSAGES: msgs.length, RECENT: 0, UIDNEXT: msgs.length + 1, UIDVALIDITY: Math.floor(this.host.bootTime / 1000) % 1_000_000_000, UNSEEN: msgs.filter((m) => !m.seen).length };
    return `* STATUS INBOX (${items.map((i) => i.toUpperCase()).filter((i) => i in val).map((i) => `${i} ${val[i]}`).join(' ')})`;
  }

  /** SEARCH with ALL, NEW/UNSEEN, SEEN, or a header match: SUBJECT, FROM or TO "text" (case-insensitive substring). */
  search(criteria: string): string {
    const msgs = this.messages();
    const m = /^(SUBJECT|FROM|TO)\s+"?([^"]*)"?$/i.exec(criteria.trim());
    const c = criteria.trim().toUpperCase();
    const header = (content: string, name: string) => (new RegExp(`^${name}:\\s*(.*)$`, 'im').exec(content.split(/\n\n/)[0])?.[1] ?? '').toLowerCase();
    const hits = msgs.filter((x) => (m ? header(x.content, m[1]).includes(m[2].toLowerCase()) : c === 'UNSEEN' || c === 'NEW' ? !x.seen : c === 'SEEN' ? x.seen : true));
    return `* SEARCH${hits.map((x) => ` ${x.uid}`).join('')}`;
  }

  fetch(uid: number): string | null {
    const m = this.messages().find((x) => x.uid === uid);
    if (!m) return null;
    this.bytesOut += m.content.length;
    return m.content;
  }

  /** The connection ends: imap-login or imap logs how. */
  logout(reason = 'Logged out'): void {
    if (this.closed) return;
    this.closed = true;
    const secs = Math.max(0, Math.round((this.world.clock - this.started) / 1000));
    if (this.user) {
      dlog(this.world, this.host, `imap(${this.user.name})<${this.mpid}><${this.session}>: ${reason} in=${40 + this.attempts * 30} out=${600 + this.bytesOut} deleted=0 expunged=0 trashed=0 hdr_count=0 hdr_bytes=0 body_count=${this.bytesOut ? 1 : 0} body_bytes=${this.bytesOut}`, null);
    } else if (this.attempts) {
      dlog(this.world, this.host, `imap-login: Disconnected: Connection closed (auth failed, ${this.attempts} attempts in ${secs} secs): user=<${this.lastUser}>, method=PLAIN, ${this.where()}`, null);
    } else {
      dlog(this.world, this.host, `imap-login: Disconnected: Aborted login by logging out (no auth attempts in ${secs} secs): user=<>, ${this.where()}`, null);
    }
  }
}
