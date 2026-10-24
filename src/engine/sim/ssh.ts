// End-to-end OpenSSH 9.2 (Debian 12) connection simulation.
//
// Client side: name resolution, TCP connect, identification exchange, KEXINIT
// negotiation, ECDH/hybrid key exchange, known_hosts verification, NEWKEYS,
// ssh-userauth with publickey (query + signature) and password methods, and
// session channel setup. Server side: the *loaded* sshd configuration (edits
// only apply after reload/restart), AllowUsers/DenyUsers, PermitRootLogin,
// StrictModes path checks, authorized_keys matching, PAM password checks and
// the exact journal lines sshd writes at the configured LogLevel.

import { effectiveConfig, LOG_LEVELS, type SshdEffective } from '../config/sshdConfig';
import { canAccess, dirname, mkdir, readFile, writeFile } from '../fs';
import type { Host, World } from '../types';
import { base64Decode } from '../util/sha256';
import { resolve } from './dns';
import { hostPort } from '../net/addr';
import { log } from './journal';
import { KEY_LABEL, parsePublicKey, publicFromPrivate, type ParsedPublicKey } from './keys';
import { findListener, type SshdLoaded } from './services';
import {
  encryptedBytes, encryptedSize, kexEcdhInit, kexEcdhReply, kexInitPacket, KEX_PUBLIC_SIZES, newKeysPacket,
} from './sshWire';
import { ERRNO_TEXT, tcpConnect } from './tcp';
import { activeRecorder } from './trace';
import { accountExpired, faillockConf, faillockLocked, faillockRecordFailure, faillockReset } from './accounts';
import { clientConf, getServiceTicket, hostTime, KrbError, readCache, writeCache } from './kerberos';
import { parseKeytab } from '../config/krb5';

export const CLIENT_VERSION = 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3';
export const SERVER_VERSION = 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3';

const CLIENT_KEX = [
  'sntrup761x25519-sha512@openssh.com', 'curve25519-sha256', 'curve25519-sha256@libssh.org',
  'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521', 'diffie-hellman-group-exchange-sha256',
  'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group14-sha256',
];
const CLIENT_HOSTKEY_ALGS = [
  'ssh-ed25519-cert-v01@openssh.com', 'ecdsa-sha2-nistp256-cert-v01@openssh.com', 'rsa-sha2-512-cert-v01@openssh.com',
  'rsa-sha2-256-cert-v01@openssh.com', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
  'ecdsa-sha2-nistp521', 'sk-ssh-ed25519@openssh.com', 'sk-ecdsa-sha2-nistp256@openssh.com', 'rsa-sha2-512', 'rsa-sha2-256',
];
const CLIENT_CIPHERS = ['chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com'];
const CLIENT_MACS = [
  'umac-64-etm@openssh.com', 'umac-128-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com',
  'hmac-sha1-etm@openssh.com', 'umac-64@openssh.com', 'umac-128@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1',
];
const DEFAULT_IDENTITIES = ['id_rsa', 'id_ecdsa', 'id_ecdsa_sk', 'id_ed25519', 'id_ed25519_sk', 'id_xmss', 'id_dsa'];

export interface SshClientOptions {
  clientHostId: string;
  localUser: string;
  target: string;
  user?: string;
  port?: number;
  identityFiles?: string[];
  verbose?: number;
  strictHostKeyChecking?: 'ask' | 'yes' | 'no' | 'accept-new';
  batchMode?: boolean;
  connectTimeoutS?: number;
  /** -4 / -6 (AddressFamily). */
  family?: 0 | 4 | 6;
  pubkeyAuthentication?: boolean;
  passwordAuthentication?: boolean;
  /** GSSAPIAuthentication (Debian's ssh_config default: yes). */
  gssapiAuthentication?: boolean;
  /** Answers to interactive prompts, consumed in order. */
  answers?: string[];
  remoteCommand?: string;
  /** NumberOfPasswordPrompts (default 3). Scoring engines and other programs try a password once. */
  passwordPrompts?: number;
  /** Do not consult or update known_hosts (like Go's ssh.InsecureIgnoreHostKey in scoring engines). */
  ignoreKnownHosts?: boolean;
}

export type SshFailure = 'resolve' | 'connect' | 'banner' | 'kex' | 'hostkey' | 'auth' | 'shell';

export interface SshResult {
  lines: string[];
  outcome: 'session' | 'failed' | 'need-input';
  failure?: SshFailure;
  errno?: string;
  prompt?: { text: string; secret: boolean };
  exitCode: number;
  session?: { hostId: string; user: string; fromIp: string; fromPort: number; pid: number };
  authMethod?: string;
  /** Authentication methods the server offered (the USERAUTH_FAILURE list). */
  methodsOffered?: string[];
  /** Methods the client actually tried, starting with "none". */
  methodsTried?: string[];
  /** The server closed the connection after authentication (PAM account check: expired account). */
  closedAfterAuth?: boolean;
  /** The server's offer when key exchange negotiation failed. */
  serverOffer?: string[];
}

class NeedInput {
  constructor(public text: string, public secret: boolean) {}
}

function levelEnabled(eff: SshdEffective, level: string): boolean {
  const order = ['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE', 'DEBUG1', 'DEBUG2', 'DEBUG3'];
  const cfg = eff.logLevel === 'DEBUG' ? 'DEBUG1' : eff.logLevel;
  return order.indexOf(cfg) >= order.indexOf(level) && LOG_LEVELS.includes(eff.logLevel);
}

// ---------------------------------------------------------------------------
// known_hosts
// ---------------------------------------------------------------------------

export interface KnownHostEntry {
  file: string;
  line: number;
  patterns: string[];
  key: ParsedPublicKey;
}

export function knownHostsEntries(host: Host, file: string): KnownHostEntry[] {
  const text = readFile(host, file);
  if (text === undefined) return [];
  const out: KnownHostEntry[] = [];
  text.split('\n').forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith('#')) return;
    const [pats, ...rest] = line.split(/\s+/);
    const key = parsePublicKey(rest.join(' '));
    if (key) out.push({ file, line: i + 1, patterns: pats.split(','), key });
  });
  return out;
}

export function knownHostName(target: string, port: number): string {
  return port === 22 ? target : `[${target}]:${port}`;
}

function patternMatches(pattern: string, name: string): boolean {
  const re = new RegExp('^' + pattern.replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', 'i');
  return re.test(name);
}

// ---------------------------------------------------------------------------
// Server-side helpers
// ---------------------------------------------------------------------------

interface AllowResult {
  allowed: boolean;
  reason?: string;
}

function allowedUser(server: Host, eff: SshdEffective, user: string, fromIp: string): AllowResult {
  const pw = server.users[user];
  if (!pw) return { allowed: false };
  const shell = server.fs[pw.shell];
  if (!shell) return { allowed: false, reason: `User ${user} not allowed because shell ${pw.shell} does not exist` };
  if ((shell.mode & 0o111) === 0) return { allowed: false, reason: `User ${user} not allowed because shell ${pw.shell} is not executable` };
  const match = (pat: string) => {
    const [u, h] = pat.split('@');
    return patternMatches(u, user) && (!h || patternMatches(h, fromIp));
  };
  if (eff.denyUsers.some(match)) return { allowed: false, reason: `User ${user} from ${fromIp} not allowed because listed in DenyUsers` };
  if (eff.allowUsers.length && !eff.allowUsers.some(match)) return { allowed: false, reason: `User ${user} from ${fromIp} not allowed because not listed in AllowUsers` };
  const groups = [pw.primaryGroup, ...pw.groups];
  if (eff.denyGroups.length && groups.some((g) => eff.denyGroups.some((p) => patternMatches(p, g)))) {
    return { allowed: false, reason: `User ${user} from ${fromIp} not allowed because a group is listed in DenyGroups` };
  }
  if (eff.allowGroups.length && !groups.some((g) => eff.allowGroups.some((p) => patternMatches(p, g)))) {
    return { allowed: false, reason: `User ${user} from ${fromIp} not allowed because none of user's groups are listed in AllowGroups` };
  }
  return { allowed: true };
}

/** OpenSSH secure_filename(): file and every directory up to $HOME must be owned by root or the user and not group/world-writable. */
function securePath(server: Host, file: string, user: string, home: string): string | null {
  const check = (path: string, kind: 'file' | 'directory'): string | null => {
    const n = server.fs[path];
    if (!n) return null;
    if ((n.owner !== 'root' && n.owner !== user) || (n.mode & 0o022) !== 0) return `bad ownership or modes for ${kind} ${path}`;
    return null;
  };
  const f = check(file, 'file');
  if (f) return f;
  let d = dirname(file);
  while (true) {
    const r = check(d, 'directory');
    if (r) return r;
    if (d === home || d === '/') break;
    d = dirname(d);
  }
  return null;
}

type KeyCheck = { ok: true; file: string; line: number } | { ok: false; logs: { level: string; msg: string; priority?: 'err' | 'info' }[] };

function checkAuthorizedKey(server: Host, eff: SshdEffective, user: string, key: ParsedPublicKey): KeyCheck {
  const pw = server.users[user];
  const logs: { level: string; msg: string; priority?: 'err' | 'info' }[] = [];
  for (const rel of eff.authorizedKeysFiles) {
    const path = (rel.startsWith('/') ? rel : `${pw.home}/${rel}`).replace('%h', pw.home).replace('%u', user);
    const node = server.fs[path];
    if (!node) continue;
    if (!canAccess(node, pw, 'r')) {
      logs.push({ level: 'ERROR', msg: `Could not open user '${user}' authorized keys '${path}': Permission denied`, priority: 'err' });
      continue;
    }
    if (eff.strictModes) {
      const bad = securePath(server, path, user, pw.home);
      if (bad) {
        logs.push({ level: 'INFO', msg: `Authentication refused: ${bad}` });
        continue;
      }
    }
    const lines = node.content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const k = parsePublicKey(lines[i]);
      if (k && k.blobB64 === key.blobB64) return { ok: true, file: path, line: i + 1 };
    }
  }
  return { ok: false, logs };
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export function runSsh(world: World, o: SshClientOptions): SshResult {
  const out: string[] = [];
  try {
    return runSshInner(world, o, out);
  } catch (e) {
    if (e instanceof NeedInput) return { lines: out, outcome: 'need-input', prompt: { text: e.text, secret: e.secret }, exitCode: -1 };
    throw e;
  }
}

function runSshInner(world: World, o: SshClientOptions, out: string[]): SshResult {
  const rec = activeRecorder();
  const verbose = o.verbose ?? 0;
  const dbg = (s: string, level = 1) => { if (verbose >= level) out.push(`debug${level}: ${s}`); };
  const answers = [...(o.answers ?? [])];
  const ask = (text: string, secret: boolean): string => {
    if (answers.length === 0) throw new NeedInput(text, secret);
    return answers.shift()!;
  };
  const client = world.hosts[o.clientHostId];
  const cuser = client.users[o.localUser];
  const user = o.user ?? o.localUser;
  const port = o.port ?? 22;
  const strict = o.strictHostKeyChecking ?? 'ask';
  const fail = (failure: SshFailure, extra: Partial<SshResult> = {}): SshResult => ({ lines: out, outcome: 'failed', failure, exitCode: 255, ...extra });
  const note = (title: string, detail: string, host = client.id) => rec?.internal(world.clock, host, title, detail);

  if (verbose) {
    out.push('OpenSSH_9.2p1 Debian-2+deb12u3, OpenSSL 3.0.14 4 Jun 2024');
    dbg('Reading configuration data /etc/ssh/ssh_config');
    dbg('/etc/ssh/ssh_config line 19: include /etc/ssh/ssh_config.d/*.conf matched no files');
    dbg('/etc/ssh/ssh_config line 21: Applying options for *');
  }

  // ---- 1. Name resolution ---------------------------------------------------------
  if (rec) {
    rec.phase = 'DNS';
    rec.setState(client.id, { ssh: 'resolving hostname', tcp: 'CLOSED', crypto: 'none' });
    note('ssh parses arguments and resolves the hostname',
      `The ssh client reads /etc/ssh/ssh_config and ~/.ssh/config, then calls getaddrinfo("${o.target}"). glibc's NSS consults /etc/hosts first ("hosts: files dns" in /etc/nsswitch.conf) and then the DNS servers listed in /etc/resolv.conf, appending search domains to short names.`);
  }
  const r = resolve(world, client, o.target.replace(/^\[(.*)\]$/, '$1'), { family: o.family ?? 0 });
  if (!r.ok) {
    out.push(`ssh: Could not resolve hostname ${o.target.toLowerCase()}: ${r.message}`);
    note('Name resolution failed', r.error === 'NXDOMAIN'
      ? 'Every DNS query returned NXDOMAIN (the name does not exist in the zone). ssh never sends a single TCP packet to the server.'
      : 'No DNS server gave a usable answer (timeouts, ICMP errors or SERVFAIL). glibc returns EAI_AGAIN: "Temporary failure in name resolution".');
    return fail('resolve');
  }
  if (rec && r.source === 'hosts') note(`/etc/hosts maps ${o.target} to ${r.ip}`, 'The name was found in /etc/hosts, so no DNS query was sent. Static entries silently override DNS, which is a common cause of "it works from one machine but not another".');
  if (rec && r.addrs.length > 1) note(`getaddrinfo returned ${r.addrs.length} addresses`, `${r.addrs.join(', ')}. ssh tries them in this order (IPv6 first, RFC 6724) and moves to the next only after the previous one fails, each with the full connect timeout: unlike browsers and curl, OpenSSH does not race IPv4 against IPv6 ("Happy Eyeballs"). A broken IPv6 path therefore delays every login.`);

  // ---- 2. TCP connection --------------------------------------------------------------
  let c: ReturnType<typeof tcpConnect> | null = null;
  let ip = r.ip;
  for (const addr of r.addrs) {
    ip = addr;
    dbg(`Connecting to ${o.target} [${addr}] port ${port}.`);
    if (rec) {
      rec.setState(client.id, { ssh: 'connecting (TCP)' });
      note('connect() to ' + hostPort(addr, port), `ssh opens a TCP socket and calls connect(). The kernel picks an ephemeral source port, chooses a route and source address, resolves the next hop with ${addr.includes(':') ? 'Neighbor Discovery' : 'ARP'}, and sends a SYN.`);
    }
    c = tcpConnect(world, client, addr, port, { timeoutMs: o.connectTimeoutS ? o.connectTimeoutS * 1000 : undefined });
    if (c.ok) break;
    dbg(`connect to address ${addr} port ${port}: ${ERRNO_TEXT[c.errno]}`);
    note(`connect() to ${addr} failed: ${c.errno}`, `${connectExplanation(c.errno)} (${c.detail}; ${c.attempts} SYN${c.attempts > 1 ? 's' : ''} sent over ${(c.elapsedMs / 1000).toFixed(1)} s)`);
  }
  if (!c || !c.ok) {
    const errno = c && !c.ok ? c.errno : 'ETIMEDOUT';
    out.push(`ssh: connect to host ${o.target} port ${port}: ${ERRNO_TEXT[errno]}`);
    return fail('connect', { errno });
  }
  const conn = c.conn;
  const server = conn.server;
  dbg('Connection established.');
  const sshDir = `${cuser.home}/.ssh`;
  const identityPaths = o.identityFiles?.length ? o.identityFiles : DEFAULT_IDENTITIES.map((n) => `${sshDir}/${n}`);
  for (const id of identityPaths) {
    const exists = client.fs[id];
    const t = exists ? (publicFromPrivate(exists.content)?.type ?? 'rsa') : null;
    dbg(`identity file ${id} type ${t === null ? -1 : t === 'ed25519' ? 3 : t === 'ecdsa' ? 2 : 0}`);
    dbg(`identity file ${id}-cert type -1`);
  }
  dbg(`Local version string ${CLIENT_VERSION}`);

  const listener = findListener(server, 'tcp', conn.sv.local, conn.sv.localPort)!;
  if (listener.service !== 'ssh') {
    // Something other than sshd answered (e.g. nginx on port 80).
    if (rec) rec.phase = 'SSH transport';
    conn.send('c2s', CLIENT_VERSION.length + 2, { protocol: 'SSH', info: `Client: Protocol (${CLIENT_VERSION})`, fields: [{ name: 'Protocol Version', value: CLIENT_VERSION }] });
    note(`${listener.process} is listening on port ${port}, not sshd`, `The TCP handshake succeeded because ${listener.process} owns this port. It does not speak SSH, so it rejects the identification string and closes the connection.`, server.id);
    conn.send('s2c', 157, { protocol: 'DATA', info: 'HTTP/1.1 400 Bad Request', fields: [{ name: 'Data', value: 'HTTP/1.1 400 Bad Request (nginx)' }] });
    conn.close('server');
    out.push('kex_exchange_identification: Connection closed by remote host');
    out.push(`Connection closed by ${ip} port ${port}`);
    return fail('banner');
  }

  const sshd = server.services.ssh;
  const loaded = sshd.loaded as SshdLoaded;
  const childPid = (server.nextPid += 3);
  // Server-side logs use the address the server sees (the router's address when NAT is involved).
  const cip = conn.sv.peer;
  const cport = conn.sv.peerPort;
  const globalEff = loaded.effective;
  const slog = (level: string, msg: string, priority: 'info' | 'err' | 'notice' = 'info', eff = globalEff) => {
    if (levelEnabled(eff, level)) log(world, server, 'sshd', msg, { pid: childPid, unit: 'ssh.service', priority });
  };
  slog('VERBOSE', `Connection from ${cip} port ${cport} on ${conn.sv.local} port ${conn.sv.localPort} rdomain ""`);
  if (rec) {
    rec.phase = 'SSH transport';
    note('sshd accepts the connection and forks a per-connection child',
      `The listening sshd (pid ${sshd.pid}) accept()s the socket and re-executes itself as a child (pid ${childPid}) that handles this client only. The pre-authentication part runs in an unprivileged, sandboxed process (privilege separation). With LogLevel VERBOSE it logs "Connection from ${cip} port ${cport}".`, server.id);
    rec.setState(client.id, { ssh: 'identification exchange' });
    rec.setState(server.id, { ssh: 'identification exchange', crypto: 'none' });
  }

  // ---- 3. Identification strings ---------------------------------------------------------
  const sv = conn.send('s2c', SERVER_VERSION.length + 2, {
    protocol: 'SSH', info: `Server: Protocol (${SERVER_VERSION})`,
    fields: [{ name: 'Protocol Version', value: SERVER_VERSION }, { name: 'Note', value: 'Plain text, terminated by CR LF (RFC 4253 §4.2)' }],
    bytes: new TextEncoder().encode(SERVER_VERSION + '\r\n'),
  });
  annotate(sv.packet, 'Server identification string', 'Immediately after the TCP handshake the server sends its identification string "SSH-protoversion-softwareversion comments". Protocol 2.0 is the only version modern OpenSSH supports. This is the "banner" you see with `nc host 22`.');
  const cv = conn.send('c2s', CLIENT_VERSION.length + 2, {
    protocol: 'SSH', info: `Client: Protocol (${CLIENT_VERSION})`,
    fields: [{ name: 'Protocol Version', value: CLIENT_VERSION }],
    bytes: new TextEncoder().encode(CLIENT_VERSION + '\r\n'),
  });
  annotate(cv.packet, 'Client identification string', 'The client sends its own identification string. Both strings are later fed into the exchange hash H, so tampering with them is detected.');
  dbg(`Remote protocol version 2.0, remote software version ${SERVER_VERSION.slice(8)}`);
  dbg(`compat_banner: match: ${SERVER_VERSION.slice(8)} pat OpenSSH* compat 0x04000000`);
  dbg(`Authenticating to ${o.target}:${port} as '${user}'`);

  // ---- 4. Algorithm negotiation -------------------------------------------------------------
  const khName = knownHostName(o.target, port);
  const khFiles = [`${sshDir}/known_hosts`, `${sshDir}/known_hosts2`, '/etc/ssh/ssh_known_hosts', '/etc/ssh/ssh_known_hosts2'];
  const known = khFiles.flatMap((f) => knownHostsEntries(client, f)).filter((e) => e.patterns.some((p) => patternMatches(p, khName)));
  for (const f of khFiles) if (!client.fs[f]) dbg(`load_hostkeys: fopen ${f}: No such file or directory`);

  const knownAlgs = new Set(known.flatMap((k) => (k.key.alg === 'ssh-rsa' ? ['rsa-sha2-512', 'rsa-sha2-256'] : [k.key.alg])));
  const clientHostKeyAlgs = [...CLIENT_HOSTKEY_ALGS.filter((a) => knownAlgs.has(a)), ...CLIENT_HOSTKEY_ALGS.filter((a) => !knownAlgs.has(a))];
  const serverHostKeyAlgs = loaded.hostKeys.flatMap((k) => (k.key.type === 'rsa' ? ['rsa-sha2-512', 'rsa-sha2-256'] : [k.key.alg]));
  const clientKex = [...CLIENT_KEX, 'ext-info-c', 'kex-strict-c-v00@openssh.com'];
  const serverKex = [...globalEff.kexAlgorithms, 'kex-strict-s-v00@openssh.com'];

  if (rec) {
    rec.phase = 'SSH key exchange';
    rec.setState(client.id, { ssh: 'algorithm negotiation' });
    rec.setState(server.id, { ssh: 'algorithm negotiation' });
  }
  const seedBase = `${cip}:${cport}`;
  const ski = kexInitPacket({ kex: serverKex, hostKey: serverHostKeyAlgs, ciphers: globalEff.ciphers, macs: globalEff.macs, compression: ['none', 'zlib@openssh.com'] }, seedBase + 's');
  const sk = conn.send('s2c', ski.length, {
    protocol: 'SSH', info: 'Server: Key Exchange Init',
    fields: [
      { name: 'Message Code', value: 'Key Exchange Init (20)' },
      { name: 'kex_algorithms', value: serverKex.join(',') },
      { name: 'server_host_key_algorithms', value: serverHostKeyAlgs.join(',') },
      { name: 'encryption_algorithms', value: globalEff.ciphers.join(',') },
      { name: 'mac_algorithms', value: globalEff.macs.join(',') },
      { name: 'compression_algorithms', value: 'none,zlib@openssh.com' },
    ],
    bytes: ski,
  });
  annotate(sk.packet, 'SSH_MSG_KEXINIT (server)', 'Each side sends a KEXINIT listing, in order of preference, the key-exchange, host-key, cipher, MAC and compression algorithms it supports, plus a random 16-byte cookie. The server\'s lists come from KexAlgorithms, HostKey files, Ciphers and MACs in the *loaded* sshd configuration. "kex-strict-s-v00@openssh.com" advertises the Terrapin (CVE-2023-48795) countermeasure.');
  const cki = kexInitPacket({ kex: clientKex, hostKey: clientHostKeyAlgs, ciphers: CLIENT_CIPHERS, macs: CLIENT_MACS, compression: ['none', 'zlib@openssh.com', 'zlib'] }, seedBase + 'c');
  const ck = conn.send('c2s', cki.length, {
    protocol: 'SSH', info: 'Client: Key Exchange Init',
    fields: [
      { name: 'Message Code', value: 'Key Exchange Init (20)' },
      { name: 'kex_algorithms', value: clientKex.join(',') },
      { name: 'server_host_key_algorithms', value: clientHostKeyAlgs.join(',') },
      { name: 'encryption_algorithms', value: CLIENT_CIPHERS.join(',') },
      { name: 'mac_algorithms', value: CLIENT_MACS.join(',') },
    ],
    bytes: cki,
  });
  annotate(ck.packet, 'SSH_MSG_KEXINIT (client)', `For every category the negotiated algorithm is the FIRST entry in the client's list that also appears in the server's list (RFC 4253 §7.1). The client moved host-key types it already has in known_hosts${knownAlgs.size ? ` (${[...knownAlgs].join(', ')})` : ''} to the front so it can verify the key it receives.`);
  dbg('SSH2_MSG_KEXINIT sent');
  dbg('SSH2_MSG_KEXINIT received');

  const pick = (c: string[], s: string[]) => c.find((a) => s.includes(a));
  const kexAlg = pick(CLIENT_KEX, globalEff.kexAlgorithms);
  const hkAlg = pick(clientHostKeyAlgs, serverHostKeyAlgs);
  const cipher = pick(CLIENT_CIPHERS, globalEff.ciphers);
  const mac = pick(CLIENT_MACS, globalEff.macs);
  const negotiationFail = (what: string, theirs: string[], ours: string[]) => {
    out.push(`Unable to negotiate with ${ip} port ${port}: no matching ${what} found. Their offer: ${theirs.join(',')}`);
    slog('ERROR', `Unable to negotiate with ${cip} port ${cport}: no matching ${what} found. Their offer: ${ours.join(',')} [preauth]`, 'err');
    note(`Negotiation failed: no common ${what}`, `No algorithm in the client's ${what} list appears in the server's list. The connection is closed before any key exchange happens. Typical causes: a hardened server allowing only modern algorithms contacted by an old client, or a legacy server (e.g. network appliance) offering only deprecated ones. Fix by aligning KexAlgorithms/Ciphers/MACs/HostKeyAlgorithms on one side, ideally upgrading the legacy side rather than weakening the modern one.`);
    conn.close('client');
    return fail('kex', { serverOffer: theirs });
  };
  if (!kexAlg) return negotiationFail('key exchange method', globalEff.kexAlgorithms, clientKex);
  if (!hkAlg) return negotiationFail('host key type', serverHostKeyAlgs, clientHostKeyAlgs);
  if (!cipher) return negotiationFail('cipher', globalEff.ciphers, CLIENT_CIPHERS);
  const aead = cipher.includes('chacha20') || cipher.includes('gcm');
  if (!aead && !mac) return negotiationFail('MAC', globalEff.macs, CLIENT_MACS);
  const macLabel = aead ? '<implicit>' : mac!;
  dbg(`kex: algorithm: ${kexAlg}`);
  dbg(`kex: host key algorithm: ${hkAlg}`);
  dbg(`kex: server->client cipher: ${cipher} MAC: ${macLabel} compression: none`);
  dbg(`kex: client->server cipher: ${cipher} MAC: ${macLabel} compression: none`);
  note('Both sides compute the same negotiation result',
    `kex: ${kexAlg}\nhost key: ${hkAlg}\ncipher: ${cipher} (MAC ${macLabel})\nNo message is needed for this step: each side runs the same deterministic algorithm on the two KEXINIT messages.`);

  // ---- 5. Key exchange ---------------------------------------------------------------------
  const ecdh = !kexAlg.startsWith('diffie-hellman');
  const initName = ecdh ? 'SSH2_MSG_KEX_ECDH_INIT' : 'SSH2_MSG_KEXDH_INIT';
  const replyName = ecdh ? 'SSH2_MSG_KEX_ECDH_REPLY' : 'SSH2_MSG_KEXDH_REPLY';
  const sizes = KEX_PUBLIC_SIZES[kexAlg] ?? { client: 32, server: 32 };
  dbg(`expecting ${replyName}`);
  const ei = kexEcdhInit(sizes.client, seedBase);
  const ein = conn.send('c2s', ei.length, {
    protocol: 'SSH', info: `Client: ${ecdh ? 'Elliptic Curve Diffie-Hellman' : 'Diffie-Hellman'} Key Exchange Init`,
    fields: [
      { name: 'Message Code', value: `${initName.replace('SSH2_MSG_', '')} (30)` },
      { name: ecdh ? 'Q_C (client ephemeral public key)' : 'e (client DH public value)', value: `${sizes.client} bytes` },
    ],
    bytes: ei,
  });
  annotate(ein.packet, initName, kexAlg.startsWith('sntrup')
    ? 'The client sends its ephemeral public values: a Streamlined NTRU Prime public key concatenated with an X25519 public key. This hybrid method stays secure if either the post-quantum or the classical component holds. Ephemeral keys are generated per connection, giving forward secrecy.'
    : 'The client sends an ephemeral public value. Each connection uses fresh ephemeral keys, so recording traffic today and stealing the host key later does not reveal past sessions (forward secrecy).');
  const hostKey = loaded.hostKeys.find((k) => (hkAlg.startsWith('rsa') ? k.key.type === 'rsa' : k.key.alg === hkAlg))!;
  const er = kexEcdhReply(base64Decode(hostKey.key.blobB64), sizes.server, hkAlg, seedBase);
  const ern = conn.send('s2c', er.length, {
    protocol: 'SSH', info: `Server: ${ecdh ? 'Elliptic Curve Diffie-Hellman' : 'Diffie-Hellman'} Key Exchange Reply, New Keys`,
    fields: [
      { name: 'Message Code', value: `${replyName.replace('SSH2_MSG_', '')} (31)` },
      { name: 'K_S (server public host key)', value: `${hostKey.key.alg} ${hostKey.key.fingerprint}` },
      { name: ecdh ? 'Q_S (server ephemeral public key)' : 'f (server DH public value)', value: `${sizes.server} bytes` },
      { name: 'Signature of H', value: `${hkAlg} signature over the exchange hash` },
    ],
    bytes: er,
  });
  annotate(ern.packet, replyName, `The server combines both ephemeral values into the shared secret K and computes the exchange hash H over: both identification strings, both KEXINITs, its host key, both ephemeral publics and K. It signs H with its long-term host key (${hostKey.path}) and sends the public host key, its ephemeral value and the signature. Only the holder of that private host key can produce this signature.`);
  if (rec) {
    rec.setState(server.id, { crypto: 'shared secret K derived (not yet in use)' });
  }
  dbg(`${replyName} received`);
  dbg(`Server host key: ${hostKey.key.alg} ${hostKey.key.fingerprint}`);
  note('Client verifies the signature and computes K', 'The client derives the same shared secret K and exchange hash H, then verifies the server\'s signature on H using the received host key. A valid signature proves the server holds the matching private key, but NOT that this is the right server: that is what the known_hosts check is for.');
  if (rec) rec.setState(client.id, { ssh: 'host key verification', crypto: 'shared secret K derived (not yet in use)' });

  // ---- 6. Host key verification -------------------------------------------------------------
  const label = KEY_LABEL[hostKey.key.type];
  const sameType = known.filter((k) => k.key.type === hostKey.key.type);
  const match = sameType.find((k) => k.key.blobB64 === hostKey.key.blobB64);
  const hostsFile = `${sshDir}/known_hosts`;
  if (o.ignoreKnownHosts) {
    note('Host key not checked', 'This client ignores known_hosts (as scoring engines usually do with Go\'s ssh.InsecureIgnoreHostKey): it would talk to an impostor just as happily.');
  } else if (match) {
    dbg(`Host '${khName}' is known and matches the ${label} host key.`);
    dbg(`Found key in ${match.file}:${match.line}`);
    note('known_hosts: key matches', `${match.file} line ${match.line} contains this exact ${label} key for "${khName}". The client is now talking to the same server it trusted before.`);
  } else if (sameType.length && strict !== 'no') {
    const off = sameType[0];
    out.push(
      '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@',
      '@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @',
      '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@',
      'IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!',
      'Someone could be eavesdropping on you right now (man-in-the-middle attack)!',
      'It is also possible that a host key has just been changed.',
      `The fingerprint for the ${label} key sent by the remote host is`,
      `${hostKey.key.fingerprint}.`,
      'Please contact your system administrator.',
      `Add correct host key in ${hostsFile} to get rid of this message.`,
      `Offending ${label} key in ${off.file}:${off.line}`,
      '  remove with:',
      `  ssh-keygen -f "${off.file}" -R "${khName}"`,
      `Host key for ${khName} has changed and you have requested strict checking.`,
      'Host key verification failed.',
    );
    note('known_hosts: KEY MISMATCH', `known_hosts line ${off.line} holds a different ${label} key (${off.key.fingerprint}) for "${khName}" than the one the server just proved it owns (${hostKey.key.fingerprint}). Either the server was reinstalled/its keys regenerated, the name now points to a different machine, or someone is intercepting the connection. The client refuses to continue. Verify the new fingerprint out-of-band (e.g. on the server console: ssh-keygen -lf ${hostKey.path}.pub) before removing the old entry.`);
    slog('INFO', `Connection closed by ${cip} port ${cport} [preauth]`);
    conn.close('client');
    return fail('hostkey');
  } else {
    const prompt = [
      `The authenticity of host '${khName} (${ip})' can't be established.`,
      `${label} key fingerprint is ${hostKey.key.fingerprint}.`,
      'This key is not known by any other names.',
    ];
    let accept = false;
    if (strict === 'no' || strict === 'accept-new') accept = true;
    else if (strict === 'yes' || o.batchMode) {
      out.push(`No ${label} host key is known for ${khName} and you have requested strict checking.`, 'Host key verification failed.');
      note('known_hosts: unknown host, strict checking', 'There is no known_hosts entry and StrictHostKeyChecking=yes (or BatchMode) forbids asking. The connection is aborted.');
      slog('INFO', `Connection closed by ${cip} port ${cport} [preauth]`);
      conn.close('client');
      return fail('hostkey');
    } else {
      out.push(...prompt);
      let ans = ask('Are you sure you want to continue connecting (yes/no/[fingerprint])? ', false).trim();
      out.push(`Are you sure you want to continue connecting (yes/no/[fingerprint])? ${ans}`);
      while (!['yes', 'no'].includes(ans) && ans !== hostKey.key.fingerprint) {
        ans = ask('Please type \'yes\', \'no\' or the fingerprint: ', false).trim();
        out.push(`Please type 'yes', 'no' or the fingerprint: ${ans}`);
      }
      accept = ans !== 'no';
      if (!accept) {
        out.push('Host key verification failed.');
        slog('INFO', `Connection closed by ${cip} port ${cport} [preauth]`);
        conn.close('client');
        return fail('hostkey');
      }
    }
    if (!client.fs[sshDir]) mkdir(client, sshDir, world.clock, { mode: 0o700, owner: cuser.name, group: cuser.primaryGroup });
    const prev = readFile(client, hostsFile) ?? '';
    writeFile(client, hostsFile, `${prev}${khName} ${hostKey.key.alg} ${hostKey.key.blobB64}\n`, world.clock, client.fs[hostsFile] ? undefined : { mode: 0o644, owner: cuser.name, group: cuser.primaryGroup });
    out.push(`Warning: Permanently added '${khName}' (${label}) to the list of known hosts.`);
    note('Trust on first use', `The key was not in known_hosts. After confirmation (or StrictHostKeyChecking=accept-new) it is appended to ${hostsFile}. This "trust on first use" moment is the one time an attacker in the path could substitute their key; enterprise environments avoid it by distributing known_hosts or using SSH host certificates.`);
  }

  // ---- 7. NEWKEYS --------------------------------------------------------------------------
  dbg('rekey out after 134217728 blocks');
  const nk1 = conn.send('c2s', 16, { protocol: 'SSH', info: 'Client: New Keys', fields: [{ name: 'Message Code', value: 'New Keys (21)' }], bytes: newKeysPacket(seedBase + 'nk1') });
  annotate(nk1.packet, 'SSH2_MSG_NEWKEYS (client)', 'NEWKEYS tells the peer: "every packet I send after this one uses the keys derived from K and H". Separate encryption and integrity keys are derived for each direction (RFC 4253 §7.2). The session identifier is the first H and stays fixed for the connection.');
  dbg('SSH2_MSG_NEWKEYS sent');
  dbg('expecting SSH2_MSG_NEWKEYS');
  const nk2 = conn.send('s2c', 16, { protocol: 'SSH', info: 'Server: New Keys', fields: [{ name: 'Message Code', value: 'New Keys (21)' }], bytes: newKeysPacket(seedBase + 'nk2') });
  annotate(nk2.packet, 'SSH2_MSG_NEWKEYS (server)', 'From here on, every SSH packet is encrypted and authenticated. A passive observer (or a packet capture) can still see IP addresses, ports, packet sizes and timing, but no longer the SSH message types or contents.');
  dbg('SSH2_MSG_NEWKEYS received');
  dbg('rekey in after 134217728 blocks');
  if (rec) {
    rec.setState(client.id, { ssh: 'transport established', crypto: `${cipher} (encrypted)` });
    rec.setState(server.id, { ssh: 'transport established', crypto: `${cipher} (encrypted)` });
  }

  // From here every packet is encrypted on the wire.
  let encSeq = 0;
  const enc = (dir: 'c2s' | 's2c', payload: number, info: string, fields: { name: string; value: string }[], title: string, detail: string) => {
    const res = conn.send(dir, encryptedSize(payload), {
      protocol: 'SSH', info: `${dir === 'c2s' ? 'Client' : 'Server'}: Encrypted packet (len=${encryptedSize(payload)})`,
      fields: [{ name: 'Decrypted (endpoint view only)', value: info }, ...fields],
      encrypted: true, bytes: encryptedBytes(payload, `${seedBase}:${encSeq++}`),
    });
    annotate(res.packet, title, detail);
    return res;
  };

  // ---- 8. Service request ------------------------------------------------------------------
  if (rec) rec.phase = 'SSH authentication';
  const idsWithKeys = identityPaths.filter((p) => client.fs[p]);
  for (const id of idsWithKeys) {
    const pk = publicFromPrivate(client.fs[id].content);
    if (pk) dbg(`Will attempt key: ${id} ${KEY_LABEL[pk.type]} ${pk.fingerprint}`);
  }
  enc('c2s', 22, 'SSH_MSG_SERVICE_REQUEST "ssh-userauth"', [], 'SERVICE_REQUEST ssh-userauth', 'The client asks to start the user authentication protocol (RFC 4252), the only service allowed before authentication.');
  enc('s2c', 240, 'SSH_MSG_EXT_INFO server-sig-algs=<ssh-ed25519,ecdsa-sha2-nistp256,...,rsa-sha2-512,rsa-sha2-256>', [], 'EXT_INFO', 'Because the client advertised "ext-info-c", the server tells it which public-key signature algorithms it accepts (RFC 8308). This is how clients know they may use rsa-sha2-512 instead of the deprecated SHA-1 "ssh-rsa" signatures.');
  dbg('SSH2_MSG_EXT_INFO received');
  dbg('kex_input_ext_info: server-sig-algs=<ssh-ed25519,sk-ssh-ed25519@openssh.com,ssh-rsa,rsa-sha2-256,rsa-sha2-512,ssh-dss,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ecdsa-sha2-nistp256@openssh.com,webauthn-sk-ecdsa-sha2-nistp256@openssh.com>');
  enc('s2c', 22, 'SSH_MSG_SERVICE_ACCEPT "ssh-userauth"', [], 'SERVICE_ACCEPT', 'The server accepts; authentication requests can now be sent.');
  dbg('SSH2_MSG_SERVICE_ACCEPT received');
  if (rec) {
    rec.setState(client.id, { ssh: 'authenticating' });
    rec.setState(server.id, { ssh: 'authenticating' });
  }

  // ---- 9. Authentication -------------------------------------------------------------------
  const pw = server.users[user];
  const ctxEff = pw ? effectiveConfig(loaded.parsed, { user, groups: [pw.primaryGroup, ...pw.groups], address: cip }) : globalEff;
  const allow = allowedUser(server, ctxEff, user, cip);
  const valid = !!pw && allow.allowed;
  if (!pw) slog('INFO', `Invalid user ${user} from ${cip} port ${cport}`);
  else if (!allow.allowed && allow.reason) slog('INFO', allow.reason);

  const methods: string[] = [];
  if (ctxEff.pubkeyAuthentication) methods.push('publickey');
  // Debian's sshd (GSSAPI key-exchange patch) offers both GSSAPI methods when GSSAPIAuthentication is on.
  if (ctxEff.gssapiAuthentication) methods.push('gssapi-keyex', 'gssapi-with-mic');
  if (ctxEff.passwordAuthentication) methods.push('password');
  if (ctxEff.kbdInteractiveAuthentication && ctxEff.usePAM) methods.push('keyboard-interactive');
  const methodList = methods.join(',');
  const invalidTag = valid ? '' : 'invalid user ';

  enc('c2s', 50, `SSH_MSG_USERAUTH_REQUEST user="${user}" service="ssh-connection" method="none"`, [], 'USERAUTH_REQUEST method "none"',
    'The client first tries the "none" method. Real servers reject it; the point is to learn which methods the server will accept for this user.');
  note(`sshd evaluates user "${user}"`, !pw
    ? `"${user}" does not exist on ${server.hostname}. sshd does NOT reveal this to the client: it continues the protocol with a fake user so attackers cannot enumerate accounts, but every attempt will fail. It logs "Invalid user ${user}".`
    : !allow.allowed
      ? `${allow.reason}. sshd treats the account as invalid for this connection: authentication can never succeed, but the client is not told why. Only the server log reveals the reason.`
      : `"${user}" exists (uid ${pw.uid}) and passes the AllowUsers/DenyUsers/AllowGroups/DenyGroups and shell checks. Effective config for this connection (including Match blocks) allows: ${methodList || 'nothing'}.`, server.id);
  enc('s2c', 30 + methodList.length, `SSH_MSG_USERAUTH_FAILURE methods="${methodList}" partial=false`, [], 'USERAUTH_FAILURE (list of methods)',
    `The server answers with the list of methods that can continue: "${methodList}". This list comes from PubkeyAuthentication, PasswordAuthentication and KbdInteractiveAuthentication in the loaded configuration (after Match blocks).`);
  dbg(`Authentications that can continue: ${methodList}`);

  let failures = 0;
  const maxTries = ctxEff.maxAuthTries;
  const tried: string[] = ['none'];
  const authFail = (extra: Partial<SshResult> = {}) => fail('auth', { methodsOffered: methods, methodsTried: tried, ...extra });
  // pam_faillock (auth): a locked account fails even with the right password.
  const fl = valid && ctxEff.usePAM ? faillockConf(server) : null;
  const tooMany = (): SshResult => {
    slog('ERROR', `maximum authentication attempts exceeded for ${invalidTag}${user} from ${cip} port ${cport} ssh2 [preauth]`, 'err');
    slog('INFO', `Disconnecting ${valid ? 'authenticating' : 'invalid'} user ${user} ${cip} port ${cport}: Too many authentication failures [preauth]`);
    out.push(`Received disconnect from ${ip} port ${port}:2: Too many authentication failures`);
    out.push(`Disconnected from ${ip} port ${port}`);
    conn.close('server');
    return authFail();
  };

  let authed: string | null = null;
  let authKey: ParsedPublicKey | null = null;
  let gssPrincipal = '';

  // gssapi-with-mic (Kerberos): OpenSSH tries it first (PreferredAuthentications), and
  // Debian's /etc/ssh/ssh_config sets GSSAPIAuthentication yes for the client.
  if (methods.includes('gssapi-with-mic') && o.gssapiAuthentication !== false) {
    dbg('Next authentication method: gssapi-with-mic');
    const gssFail = (minor: string, serverSide?: string) => {
      // A server-side rejection reaches the client only as USERAUTH_FAILURE: it just moves on.
      if (!serverSide) {
        dbg('Unspecified GSS failure.  Minor code may provide more information');
        dbg(minor);
      }
      if (serverSide) {
        slog('DEBUG1', `Unspecified GSS failure.  Minor code may provide more information\n${serverSide}`, 'info', ctxEff);
        note('sshd cannot accept the Kerberos ticket', `${serverSide}. sshd logs the GSSAPI error only with LogLevel DEBUG1; at INFO the login silently falls through to the next method. Compare the key version on both sides: "klist -k /etc/krb5.keytab" on the server and "kvno host/NAME" on the client.`, server.id);
      } else {
        note('No Kerberos ticket for the server', `${minor}. The client skips gssapi-with-mic and tries the next method.`);
      }
    };
    const cache = readCache(client, cuser.uid);
    if (!cache) gssFail(`No Kerberos credentials available (default cache: FILE:/tmp/krb5cc_${cuser.uid})`);
    else {
      // The service principal is host/<canonical name>: forward-canonicalised through DNS (CNAMEs), no reverse lookup (rdns = false).
      const canon = (r.ok && r.source === 'dns' ? (r.cname?.at(-1) ?? r.fqdn) : o.target).replace(/\.$/, '').toLowerCase();
      let sp = '';
      try {
        const conf = clientConf(client);
        const dom = Object.entries(conf.domainRealm).find(([d]) => (d.startsWith('.') ? canon.endsWith(d) : canon === d))?.[1];
        sp = `host/${canon}@${dom ?? conf.defaultRealm ?? ''}`;
        const { ticket, cached } = getServiceTicket(world, client, cache, sp);
        if (!cached) {
          cache.tickets.push(ticket);
          writeCache(world, client, cuser.uid, cuser.name, cuser.primaryGroup, cache);
        }
        enc('c2s', 1200, `SSH_MSG_USERAUTH_REQUEST method="gssapi-with-mic" (Kerberos AP-REQ for ${sp}, kvno ${ticket.kvno})`, [], 'GSSAPI authentication (Kerberos ticket)',
          `The client sends its service ticket for ${sp} (an AP-REQ wrapped in a GSSAPI token) plus an authenticator with its current time. No password and no key file are involved: the ticket came from the KDC with the TGT obtained by kinit.`);
        const kt = parseKeytab(server.fs['/etc/krb5.keytab']?.content);
        const entries = (kt ?? []).filter((e) => e.principal === sp);
        const k5login = pw ? server.fs[`${pw.home}/.k5login`]?.content : undefined;
        const local = cache.principal.split('@')[0];
        const serverConf = (() => { try { return clientConf(server); } catch { return null; } })();
        const userOk = k5login !== undefined ? k5login.split('\n').map((l) => l.trim()).includes(cache.principal) : local === user && cache.principal.endsWith(`@${serverConf?.defaultRealm ?? ''}`);
        let serverErr: string | undefined;
        if (!kt) serverErr = 'Key table file \'/etc/krb5.keytab\' not found';
        else if (!entries.length) serverErr = `No key table entry found matching ${sp.split('@')[0]}@`;
        else if (!entries.some((e) => e.kvno === ticket.kvno)) serverErr = `Key version number for principal in key table is incorrect (ticket kvno ${ticket.kvno}, keytab has ${[...new Set(entries.map((e) => e.kvno))].join(', ')})`;
        else if (!entries.some((e) => e.kvno === ticket.kvno && e.key === ticket.serviceKey)) serverErr = 'Decrypt integrity check failed';
        else if (Math.abs(hostTime(world, client) - hostTime(world, server)) > 300_000) serverErr = 'Clock skew too great';
        if (serverErr) {
          failures++;
          gssFail('', serverErr);
          enc('s2c', 30 + methodList.length, `SSH_MSG_USERAUTH_FAILURE methods="${methodList}"`, [], 'USERAUTH_FAILURE', 'The server could not decrypt or accept the ticket.');
          dbg(`Authentications that can continue: ${methodList}`);
        } else if (!valid || !userOk) {
          failures++;
          note('Kerberos principal not allowed for this account', !valid ? 'The account is invalid or not allowed.' : `The ticket is valid, but ${cache.principal} may not log in as "${user}": without a ~/.k5login file only the principal ${user}@${serverConf?.defaultRealm ?? 'DEFAULT.REALM'} maps to the local user ${user}; a ~/.k5login lists the principals allowed instead.`, server.id);
          slog('DEBUG1', `krb5_kuserok: ${cache.principal} is not authorized to log in as ${user}`, 'info', ctxEff);
          enc('s2c', 30 + methodList.length, `SSH_MSG_USERAUTH_FAILURE methods="${methodList}"`, [], 'USERAUTH_FAILURE', 'The principal is not allowed to log in as this user.');
        } else {
          note('sshd accepts the Kerberos ticket', `sshd decrypts the ticket with the key for ${sp} (kvno ${ticket.kvno}) from /etc/krb5.keytab, checks the authenticator's timestamp against its own clock, and maps ${cache.principal} to the local user ${user}. The MIC (message integrity code) binds the authentication to this SSH session.`, server.id);
          authed = 'gssapi-with-mic';
          gssPrincipal = cache.principal;
          dbg(`Authenticated to ${o.target} ([${ip}]:${port}) using "gssapi-with-mic".`);
        }
        if (failures >= maxTries) return tooMany();
      } catch (e) {
        if (!(e instanceof KrbError)) throw e;
        gssFail(`${e.message}${sp ? ` (${sp})` : ''}`);
      }
    }
  }

  // publickey
  const clientWantsPubkey = o.pubkeyAuthentication !== false;
  if (!authed && methods.includes('publickey') && clientWantsPubkey) {
    dbg('Next authentication method: publickey');
    for (const id of idsWithKeys) {
      const node = client.fs[id];
      const pubNode = client.fs[id + '.pub'];
      const pub = publicFromPrivate(node.content) ?? (pubNode ? parsePublicKey(pubNode.content) : null);
      if (!pub) continue;
      dbg(`Offering public key: ${id} ${KEY_LABEL[pub.type]} ${pub.fingerprint}`);
      if (!tried.includes('publickey')) tried.push('publickey');
      enc('c2s', 120, `SSH_MSG_USERAUTH_REQUEST method="publickey" (query, no signature) ${pub.alg} ${pub.fingerprint}`, [], 'Public key query',
        `The client asks "would you accept this key?" (${pub.fingerprint}) without proving possession yet. This avoids an expensive signature (or a passphrase prompt) for keys the server would reject.`);
      const check = valid ? checkAuthorizedKey(server, ctxEff, user, pub) : { ok: false as const, logs: [] };
      if (!check.ok) {
        for (const l of check.logs) slog(l.level, l.msg, l.priority);
        slog('VERBOSE', `Failed publickey for ${invalidTag}${user} from ${cip} port ${cport} ssh2: ${KEY_LABEL[pub.type]} ${pub.fingerprint}`);
        failures++;
        note('sshd: key not accepted', !valid
          ? 'The user is invalid/not allowed, so no key can match.'
          : check.logs.length
            ? `sshd could not use the authorized_keys file: ${check.logs.map((l) => l.msg).join('; ')}. With StrictModes yes, sshd ignores authorized_keys if the file, ~/.ssh or the home directory is writable by group/others or owned by someone else, because another user could have planted a key.`
            : `None of the AuthorizedKeysFile locations (${ctxEff.authorizedKeysFiles.join(', ')}) contains this public key for ${user}. Only LogLevel VERBOSE (or higher) records this as "Failed publickey".`, server.id);
        enc('s2c', 30 + methodList.length, `SSH_MSG_USERAUTH_FAILURE methods="${methodList}"`, [], 'USERAUTH_FAILURE', 'The key is not acceptable; the client may try another key or method.');
        if (failures >= maxTries) return tooMany();
        continue;
      }
      enc('s2c', 100, `SSH_MSG_USERAUTH_PK_OK ${pub.alg}`, [], 'USERAUTH_PK_OK', `The key appears in ${check.file} line ${check.line}. The server says it would accept a signature from this key.`);
      dbg(`Server accepts key: ${id} ${KEY_LABEL[pub.type]} ${pub.fingerprint}`);
      // Now the client must load the private key to sign.
      if ((node.mode & 0o077) !== 0 && node.owner === cuser.name) {
        out.push(
          '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@',
          '@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @',
          '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@',
          `Permissions 0${(node.mode & 0o777).toString(8)} for '${id}' are too open.`,
          'It is required that your private key files are NOT accessible by others.',
          'This private key will be ignored.',
          `Load key "${id}": bad permissions`,
        );
        note('Client refuses to use its private key', `The server would accept the key, but ${id} has mode 0${(node.mode & 0o777).toString(8)}. The ssh client refuses to use private keys readable by group/others, so it cannot produce the signature and moves on. The server logs nothing at INFO level because no signature was ever sent. Fix on the client: chmod 600 ${id}.`);
        continue;
      }
      if (!canAccess(node, cuser, 'r')) {
        out.push(`Load key "${id}": Permission denied`);
        continue;
      }
      enc('c2s', 200, `SSH_MSG_USERAUTH_REQUEST method="publickey" (with signature) ${pub.alg}`, [], 'Public key authentication (signed)',
        'The client signs a blob containing the session identifier H, the user name, service and key with its PRIVATE key. The private key never leaves the client. Because H is unique to this connection, the signature cannot be replayed on another connection.');
      note('sshd verifies the signature', `sshd verifies the signature with the public key from ${check.file}. Success means the client holds the matching private key.`, server.id);
      authed = 'publickey';
      authKey = pub;
      dbg(`Authenticated to ${o.target} ([${ip}]:${port}) using "publickey".`);
      break;
    }
  }

  // password
  if (!authed && methods.includes('password') && o.passwordAuthentication !== false && !o.batchMode) {
    dbg('Next authentication method: password');
    const prompts = o.passwordPrompts ?? 3;
    tried.push('password');
    for (let attempt = 0; attempt < prompts; attempt++) {
      const pwText = `${user}@${o.target}'s password: `;
      const given = ask(pwText, true);
      out.push(pwText);
      enc('c2s', 60 + given.length, `SSH_MSG_USERAUTH_REQUEST method="password" (password sent inside the encrypted channel)`, [], 'Password authentication',
        'The password is sent to the server in clear text INSIDE the encrypted transport. This is why host key verification matters: if you accepted an attacker\'s host key, they would receive your password.');
      const rootBlocked = user === 'root' && ctxEff.permitRootLogin !== 'yes';
      const flLocked = !!fl && !rootBlocked && faillockLocked(server, user, world.clock, fl);
      if (flLocked) log(world, server, 'sshd', `pam_faillock(sshd:auth): Consecutive login failures for user ${user} account temporarily locked`, { pid: childPid, unit: 'ssh.service', priority: 'err' });
      const correct = valid && pw!.password !== null && pw!.password === given && !rootBlocked && !flLocked;
      if (correct) {
        if (fl) faillockReset(server, user);
        authed = 'password';
        note('PAM authentication succeeded', ctxEff.usePAM ? 'With UsePAM yes, sshd hands the password to the PAM stack (/etc/pam.d/sshd → common-auth → pam_unix), which compares it with the hash in /etc/shadow.' : 'sshd compared the password with /etc/shadow directly.', server.id);
        break;
      }
      failures++;
      if (valid && ctxEff.usePAM && !rootBlocked && !flLocked) {
        log(world, server, 'sshd', `pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=${cip}  user=${user}`, { pid: childPid, unit: 'ssh.service', priority: 'notice' });
        if (fl && (user !== 'root' || fl.evenDenyRoot)) faillockRecordFailure(world, server, user, cip);
      }
      if (user === 'root' && ctxEff.permitRootLogin === 'no') slog('INFO', `ROOT LOGIN REFUSED FROM ${cip} port ${cport}`);
      slog('INFO', `Failed password for ${invalidTag}${user} from ${cip} port ${cport} ssh2`);
      note('Password rejected', !valid
        ? 'The account is invalid or not allowed, so even a correct password fails. The client sees exactly the same response as for a wrong password.'
        : rootBlocked ? `PermitRootLogin ${ctxEff.permitRootLogin} forbids password logins for root.`
          : flLocked ? `pam_faillock refused the attempt before the password was even checked: ${user} has ${fl!.deny} or more recent failures (faillock --user ${user}).${fl!.unlockTime === 0 ? ' unlock_time = 0: the account stays locked until an administrator resets it.' : ` It unlocks ${fl!.unlockTime} s after the last failure.`}`
            : 'pam_unix compared the password against /etc/shadow and it did not match.', server.id);
      enc('s2c', 30 + methodList.length, `SSH_MSG_USERAUTH_FAILURE methods="${methodList}"`, [], 'USERAUTH_FAILURE', 'Authentication failed.');
      if (failures >= maxTries) return tooMany();
      if (attempt < prompts - 1) out.push('Permission denied, please try again.');
    }
  }

  if (!authed) {
    out.push(`${user}@${o.target}: Permission denied (${methodList}).`);
    slog('INFO', `Connection closed by ${valid ? 'authenticating user ' : invalidTag}${user} ${cip} port ${cport} [preauth]`);
    note('Client gives up: "Permission denied"', `The client has no more methods to try that the server allows (${methodList}). The message lists the methods the SERVER offered, which is evidence about the server configuration: "Permission denied (publickey)" means password authentication is disabled on the server.`);
    conn.close('client');
    return authFail();
  }

  // PAM account management runs after any successful authentication (pam_unix account: expiry).
  if (pw && ctxEff.usePAM && accountExpired(pw, world.clock)) {
    log(world, server, 'sshd', `pam_unix(sshd:account): account ${user} has expired (account expired)`, { pid: childPid, unit: 'ssh.service', priority: 'notice' });
    slog('ERROR', `fatal: Access denied for user ${user} by PAM account configuration [preauth]`, 'err');
    out.push('Your account has expired; please contact your system administrator.');
    out.push(`Connection closed by ${ip} port ${port}`);
    note('PAM account check: account expired', `The ${authed} authentication succeeded, but PAM's account phase (pam_unix) found that ${user}'s account expired (chage -l ${user}: "Account expires"). sshd treats this as fatal and drops the connection before logging "Accepted": clients see the connection closed, not "Permission denied".`, server.id);
    conn.close('server');
    return authFail({ closedAfterAuth: true });
  }
  if (pw && !ctxEff.usePAM && accountExpired(pw, world.clock)) {
    slog('INFO', `User ${user} from ${cip} not allowed because account has expired`);
    out.push(`${user}@${o.target}: Permission denied (${methodList}).`);
    conn.close('client');
    return authFail();
  }

  if (authed === 'publickey') slog('INFO', `Accepted publickey for ${user} from ${cip} port ${cport} ssh2: ${KEY_LABEL[authKey!.type]} ${authKey!.fingerprint}`);
  else if (authed === 'gssapi-with-mic') slog('INFO', `Accepted gssapi-with-mic for ${user} from ${cip} port ${cport} ssh2: ${gssPrincipal}`);
  else slog('INFO', `Accepted password for ${user} from ${cip} port ${cport} ssh2`);
  enc('s2c', 12, 'SSH_MSG_USERAUTH_SUCCESS', [], 'USERAUTH_SUCCESS', 'Authentication is complete. sshd now switches to a process running with the user\'s privileges for the session.');
  if (authed === 'password') dbg(`Authenticated to ${o.target} ([${ip}]:${port}) using "password".`);
  if (rec) {
    rec.phase = 'SSH session';
    rec.setState(client.id, { ssh: 'authenticated' });
    rec.setState(server.id, { ssh: `authenticated as ${user}` });
  }

  // ---- 10. Session ----------------------------------------------------------------------
  const sessionNo = server.nextPid % 50;
  if (ctxEff.usePAM) log(world, server, 'sshd', `pam_unix(sshd:session): session opened for user ${user}(uid=${pw!.uid}) by (uid=0)`, { pid: childPid, unit: 'ssh.service' });
  log(world, server, 'systemd-logind', `New session ${sessionNo} of user ${user}.`, { pid: 412, unit: 'systemd-logind.service' });
  dbg('channel 0: new session [client-session] (inactive timeout: 0)');
  dbg('Requesting no-more-sessions@openssh.com');
  dbg('Entering interactive session.');
  enc('c2s', 40, 'SSH_MSG_CHANNEL_OPEN "session" sender-channel=0 window=2097152', [], 'CHANNEL_OPEN session',
    'The connection protocol (RFC 4254) multiplexes channels over the single encrypted transport. A "session" channel will carry the shell; port forwards would be additional channels.');
  enc('s2c', 30, 'SSH_MSG_CHANNEL_OPEN_CONFIRMATION recipient=0 sender=0', [], 'CHANNEL_OPEN_CONFIRMATION', 'The server allocated its side of the channel.');
  const remoteCmd = o.remoteCommand;
  if (!remoteCmd) {
    enc('c2s', 80, 'SSH_MSG_CHANNEL_REQUEST "pty-req" TERM=xterm-256color 80x24', [], 'pty-req', 'Interactive logins request a pseudo-terminal so that line editing, Ctrl-C and full-screen programs work.');
    enc('c2s', 30, 'SSH_MSG_CHANNEL_REQUEST "env" LANG=en_US.UTF-8', [], 'env', 'The client forwards variables permitted by the server\'s AcceptEnv (Debian allows LANG and LC_*).');
  }
  enc('c2s', 30 + (remoteCmd?.length ?? 0), remoteCmd ? `SSH_MSG_CHANNEL_REQUEST "exec" command="${remoteCmd}"` : 'SSH_MSG_CHANNEL_REQUEST "shell"', [], remoteCmd ? 'exec request' : 'shell request',
    `sshd starts the user's login shell (${pw!.shell}) via PAM session modules (pam_systemd creates a logind session, pam_motd prints the message of the day, pam_env sets the environment).`);

  const home = server.fs[pw!.home];
  if (pw!.shell.endsWith('nologin') || pw!.shell === '/bin/false') {
    enc('s2c', 48, 'SSH_MSG_CHANNEL_DATA "This account is currently not available."', [], 'Shell exits immediately', `The account's shell is ${pw!.shell}, which prints a message and exits. Authentication worked; the session is refused by design.`);
    out.push('This account is currently not available.');
    out.push(`Connection to ${o.target} closed.`);
    slog('INFO', `Received disconnect from ${cip} port ${cport}:11: disconnected by user`);
    slog('INFO', `Disconnected from user ${user} ${cip} port ${cport}`);
    if (ctxEff.usePAM) log(world, server, 'sshd', `pam_unix(sshd:session): session closed for user ${user}`, { pid: childPid, unit: 'ssh.service' });
    conn.close('client');
    return { lines: out, outcome: 'failed', failure: 'shell', exitCode: 1, authMethod: authed };
  }
  enc('s2c', 900, 'SSH_MSG_CHANNEL_DATA (MOTD and shell prompt)', [], 'Session data', 'Everything typed and displayed from now on travels as CHANNEL_DATA inside the encrypted transport.');
  if (!remoteCmd) {
    out.push(`Linux ${server.hostname} 6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30) x86_64`);
    const motd = readFile(server, '/etc/motd');
    if (motd) out.push('', ...motd.replace(/\n$/, '').split('\n'));
  }
  if (!home) out.push(`Could not chdir to home directory ${pw!.home}: No such file or directory`);
  if (remoteCmd) {
    // exec channel: output, exit status, channel close, disconnect, TCP teardown.
    enc('s2c', 40, 'SSH_MSG_CHANNEL_REQUEST "exit-status" 0', [], 'exit-status', 'The server reports the remote command\'s exit code, then closes the channel.');
    enc('s2c', 12, 'SSH_MSG_CHANNEL_EOF + SSH_MSG_CHANNEL_CLOSE', [], 'CHANNEL_CLOSE (server)', 'No more data will be sent on this channel.');
    enc('c2s', 12, 'SSH_MSG_CHANNEL_CLOSE', [], 'CHANNEL_CLOSE (client)', 'The client confirms the close.');
    enc('c2s', 40, 'SSH_MSG_DISCONNECT reason=11 "disconnected by user"', [], 'DISCONNECT', 'With no channels left, the client ends the SSH connection and closes TCP.');
    conn.close('client');
    slog('INFO', `Received disconnect from ${cip} port ${cport}:11: disconnected by user`);
    slog('INFO', `Disconnected from user ${user} ${cip} port ${cport}`);
    if (ctxEff.usePAM) log(world, server, 'sshd', `pam_unix(sshd:session): session closed for user ${user}`, { pid: childPid, unit: 'ssh.service' });
  }
  if (rec) {
    rec.setState(client.id, { ssh: 'session open' });
    rec.setState(server.id, { ssh: `session open (${pw!.shell})` });
  }
  return {
    lines: out,
    outcome: 'session',
    exitCode: 0,
    authMethod: authed,
    session: { hostId: server.id, user, fromIp: cip, fromPort: cport, pid: childPid },
  };
}

/** Called when an interactive session ends (logout / exit). */
export function endSession(world: World, session: NonNullable<SshResult['session']>): void {
  const server = world.hosts[session.hostId];
  log(world, server, 'sshd', `Received disconnect from ${session.fromIp} port ${session.fromPort}:11: disconnected by user`, { pid: session.pid, unit: 'ssh.service' });
  log(world, server, 'sshd', `Disconnected from user ${session.user} ${session.fromIp} port ${session.fromPort}`, { pid: session.pid, unit: 'ssh.service' });
  log(world, server, 'sshd', `pam_unix(sshd:session): session closed for user ${session.user}`, { pid: session.pid, unit: 'ssh.service' });
}

function connectExplanation(errno: string): string {
  switch (errno) {
    case 'ECONNREFUSED':
      return 'The destination host answered, but nothing accepted the connection: either no process listens on that address/port (the kernel replies with TCP RST) or a firewall rule actively rejects it. The network path itself works.';
    case 'ETIMEDOUT':
      return 'No reply of any kind arrived. Something silently discarded the SYN or the SYN-ACK: a firewall DROP rule/policy, a missing return route, or a host that is down. The client retransmitted the SYN with exponential backoff before giving up.';
    case 'EHOSTUNREACH':
      return 'An ICMP "host unreachable" or "administratively prohibited" message came back, or the client could not ARP its next hop. Note that a firewall "reject with icmp admin-prohibited" also produces "No route to host", even though routing is fine.';
    case 'ENETUNREACH':
      return 'The client\'s own routing table has no route to the destination (or a router returned ICMP net-unreachable). No packet left the machine if the route was missing locally.';
    default:
      return 'The local firewall output chain blocked the packet.';
  }
}

function annotate(packet: { id: number }, title: string, detail: string): void {
  activeRecorder()?.describe(packet.id, title, detail);
}
