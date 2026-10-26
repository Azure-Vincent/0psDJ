// SMB file sharing with Samba (smbd). The server shares directories defined in
// /etc/samba/smb.conf; a client connects to TCP 445, authenticates a user
// (session setup, checked against Samba's own password database, which
// smbpasswd -a fills), then connects to a share (tree connect: the share must
// exist, its path must exist, the user must be in "valid users"). From then on
// every file operation runs on the server as that user's Unix account: the
// share's "read only" and the directory's Unix permissions must both allow it.
//
// Unlike NFS (sec=sys), the client's own UIDs do not matter: identity comes
// from the password, and the server maps it to its local account.
//
// smbd re-reads smb.conf when a new connection starts (and every few minutes),
// so share changes apply to new connections without a restart; the model loads
// the file at each connection.

import { canAccess, dirname, listDir, readFile, writeFile } from '../fs';
import type { Host, UserAccount, World } from '../types';
import { resolve } from './dns';
import { allListeners } from './services';
import { tcpConnect } from './tcp';

export const SMB_CONF = '/etc/samba/smb.conf';
export const SAMBA_VERSION = '4.17.12-Debian';

export interface SmbShare { name: string; params: Record<string, string>; line: number }
export interface SmbConf { global: Record<string, string>; shares: SmbShare[]; unknown: { name: string; line: number }[] }

// Parameters the model knows (canonical names), and their synonyms.
const SYNONYMS: Record<string, string> = {
  writable: '!read only', writeable: '!read only', write_ok: '!read only', 'write ok': '!read only',
  public: 'guest ok', browsable: 'browseable', 'create mode': 'create mask', 'directory mode': 'directory mask',
  directory: 'path', 'allow hosts': 'hosts allow', 'deny hosts': 'hosts deny',
};
const KNOWN = new Set([
  'workgroup', 'server string', 'server role', 'netbios name', 'security', 'map to guest', 'log file', 'log level', 'max log size', 'logging',
  'panic action', 'obey pam restrictions', 'unix password sync', 'passwd program', 'passwd chat', 'pam password change', 'usershare allow guests',
  'server min protocol', 'server max protocol', 'smb encrypt', 'server signing', 'interfaces', 'bind interfaces only', 'restrict anonymous', 'load printers', 'printing', 'disable spoolss',
  'path', 'comment', 'read only', 'guest ok', 'browseable', 'valid users', 'invalid users', 'write list', 'read list', 'force user', 'force group',
  'create mask', 'directory mask', 'force create mode', 'force directory mode', 'hosts allow', 'hosts deny', 'available', 'inherit permissions', 'vfs objects',
]);

/** Parse smb.conf (ini format, case-insensitive names, ; and # comments, \ continuations). */
export function parseSmbConf(text: string): SmbConf {
  const conf: SmbConf = { global: {}, shares: [], unknown: [] };
  let cur: Record<string, string> = conf.global;
  const lines = text.replace(/\\\n/g, ' ').split('\n');
  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) return;
    const sec = /^\[([^\]]+)\]$/.exec(line);
    if (sec) {
      const name = sec[1].trim();
      if (name.toLowerCase() === 'global') { cur = conf.global; return; }
      const share: SmbShare = { name, params: {}, line: i + 1 };
      conf.shares.push(share);
      cur = share.params;
      return;
    }
    const eq = line.indexOf('=');
    if (eq < 0) return;
    let key = line.slice(0, eq).trim().toLowerCase().replace(/\s+/g, ' ');
    let value = line.slice(eq + 1).trim();
    const syn = SYNONYMS[key];
    if (syn) {
      if (syn.startsWith('!')) { key = syn.slice(1); value = boolValue(value) ? 'no' : 'yes'; } else key = syn;
    }
    if (!KNOWN.has(key)) { conf.unknown.push({ name: line.slice(0, eq).trim(), line: i + 1 }); return; }
    cur[key] = value;
  });
  return conf;
}

export const boolValue = (v: string | undefined): boolean => /^(yes|true|1|on)$/i.test((v ?? '').trim());

export function loadSmbConf(host: Host): SmbConf {
  return parseSmbConf(readFile(host, SMB_CONF) ?? '');
}

export const findShare = (conf: SmbConf, name: string) => conf.shares.find((s) => s.name.toLowerCase() === name.toLowerCase());
const param = (s: SmbShare, k: string, dflt = '') => s.params[k] ?? dflt;
export const shareReadOnly = (s: SmbShare) => boolValue(param(s, 'read only', 'yes'));
export const shareBrowseable = (s: SmbShare) => boolValue(param(s, 'browseable', 'yes'));
const list = (v: string | undefined) => (v ?? '').split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

/** Does a "valid users"-style list name this user (names, @group, +group)? */
function listMatches(entries: string[], user: UserAccount): boolean {
  return entries.some((e) => {
    if (/^[@+&]/.test(e)) {
      const g = e.replace(/^[@+&]+/, '');
      return user.primaryGroup === g || user.groups.includes(g);
    }
    return e.toLowerCase() === user.name.toLowerCase();
  });
}

// ---------------------------------------------------------------------------
// Samba's password database (passdb.tdb): smbpasswd -a / pdbedit
// ---------------------------------------------------------------------------

export interface SambaUser { name: string; password: string; disabled: boolean }

export function passdb(host: Host): Record<string, SambaUser> {
  return (host.sambaPassdb ??= {});
}

// ---------------------------------------------------------------------------
// Logging, as Samba writes it with "log level = 2" (auth_audit failures, tree connects)
// ---------------------------------------------------------------------------

function stamp(t: number): string {
  const d = new Date(Math.floor(t));
  const p = (n: number, w = 2) => String(n).padStart(w, '0');
  return `[${d.getUTCFullYear()}/${p(d.getUTCMonth() + 1)}/${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}.${p((Math.floor(t) % 1000) * 1000 + 123, 6)},`;
}

/** Append to /var/log/samba/log.<client>: Samba's "log file = /var/log/samba/log.%m". */
export function smbLog(world: World, server: Host, client: string, level: number, where: string, msg: string): void {
  const path = `/var/log/samba/log.${client.toLowerCase()}`;
  const cur = readFile(server, path) ?? '';
  writeFile(server, path, `${cur}${stamp(world.clock)}  ${level}] ${where}\n  ${msg}\n`, world.clock, { mode: 0o644 });
}

// ---------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------

export type SmbError =
  | 'NT_STATUS_UNSUCCESSFUL' | 'NT_STATUS_IO_TIMEOUT' | 'NT_STATUS_CONNECTION_REFUSED' | 'NT_STATUS_HOST_UNREACHABLE'
  | 'NT_STATUS_LOGON_FAILURE' | 'NT_STATUS_ACCOUNT_DISABLED' | 'NT_STATUS_ACCESS_DENIED' | 'NT_STATUS_BAD_NETWORK_NAME';

export interface SmbSession {
  server: Host;
  serverIp: string;
  conf: SmbConf;
  /** The Unix account on the server; null for an anonymous (guest) session. */
  user: UserAccount | null;
  share?: SmbShare;
  /** Share root on the server (path parameter). */
  root?: string;
  writable?: boolean;
}

export type SmbResult = { ok: true; session: SmbSession } | { ok: false; stage: 'connect' | 'session' | 'tree'; error: SmbError; serverIp?: string };

const GUEST: UserAccount = { name: 'nobody', uid: 65534, gid: 65534, primaryGroup: 'nogroup', groups: [], home: '/nonexistent', shell: '/usr/sbin/nologin', gecos: 'nobody', password: null };

/**
 * Connect to SERVER:445, authenticate (user null: anonymous) and, when share is
 * given, connect to it. Logs on the server as smbd would.
 */
export function smbConnect(world: World, client: Host, target: string, user: string | null, password: string, share?: string): SmbResult {
  const r = resolve(world, client, target, { family: 4 });
  if (!r.ok) return { ok: false, stage: 'connect', error: 'NT_STATUS_UNSUCCESSFUL' };
  const c = tcpConnect(world, client, r.ip, 445, { timeoutMs: 20_000 });
  if (!c.ok) return { ok: false, stage: 'connect', error: c.errno === 'ECONNREFUSED' ? 'NT_STATUS_CONNECTION_REFUSED' : c.errno === 'ETIMEDOUT' ? 'NT_STATUS_IO_TIMEOUT' : 'NT_STATUS_HOST_UNREACHABLE', serverIp: r.ip };
  const conn = c.conn;
  const server = conn.server;
  const ip = r.ip;
  const clientIp = conn.sv.peer;
  const clientName = client.hostname;
  const done = <T>(v: T): T => { conn.close('client'); return v; };
  conn.send('c2s', 220, { protocol: 'SMB2', info: 'Negotiate Protocol Request', fields: [{ name: 'Dialects', value: '0x0202, 0x0210, 0x0300, 0x0302, 0x0311' }] });
  const listener = allListeners(server).find((l) => l.proto === 'tcp' && l.port === 445);
  if (listener?.service !== 'smbd') return done({ ok: false, stage: 'connect', error: 'NT_STATUS_CONNECTION_REFUSED', serverIp: ip });
  conn.send('s2c', 300, { protocol: 'SMB2', info: 'Negotiate Protocol Response', fields: [{ name: 'Dialect', value: '0x0311 (SMB 3.1.1)' }] });
  const conf = loadSmbConf(server);
  const workgroup = (conf.global.workgroup ?? 'WORKGROUP').toUpperCase();

  // Session setup (NTLMv2): Samba's passdb, then the Unix account behind it.
  conn.send('c2s', 400, { protocol: 'SMB2', info: `Session Setup Request, NTLMSSP_AUTH, User: ${workgroup}\\${user ?? ''}`, fields: [] });
  let account: UserAccount | null = null;
  if (user) {
    const entry = Object.values(passdb(server)).find((u) => u.name.toLowerCase() === user.toLowerCase());
    const unix = entry ? server.users[entry.name] : undefined;
    const status = !entry || !unix ? 'NT_STATUS_NO_SUCH_USER' : entry.disabled ? 'NT_STATUS_ACCOUNT_DISABLED' : entry.password !== password ? 'NT_STATUS_WRONG_PASSWORD' : null;
    if (status) {
      smbLog(world, server, clientName, 2, '../../auth/auth_log.c:653(log_authentication_event_human_readable)',
        `Auth: [SMB2,(null)] user [${workgroup}]\\[${user}] at [${new Date(Math.floor(world.clock)).toUTCString().replace('GMT', 'UTC')}] with [NTLMv2] status [${status}] workstation [${clientName.toUpperCase()}] remote host [ipv4:${clientIp}:${conn.sv.peerPort}] mapped to [${workgroup}]\\[${user}]. local host [ipv4:${ip}:445]`);
      conn.send('s2c', 70, { protocol: 'SMB2', info: `Session Setup Response, Error: ${status === 'NT_STATUS_ACCOUNT_DISABLED' ? status : 'STATUS_LOGON_FAILURE'}`, fields: [] });
      return done({ ok: false, stage: 'session', error: status === 'NT_STATUS_ACCOUNT_DISABLED' ? 'NT_STATUS_ACCOUNT_DISABLED' : 'NT_STATUS_LOGON_FAILURE', serverIp: ip });
    }
    account = unix!;
  }
  conn.send('s2c', 300, { protocol: 'SMB2', info: 'Session Setup Response', fields: [] });
  const session: SmbSession = { server, serverIp: ip, conf, user: account };
  if (!share) return done({ ok: true, session });

  // Tree connect.
  conn.send('c2s', 120, { protocol: 'SMB2', info: `Tree Connect Request Tree: \\\\${target}\\${share}`, fields: [] });
  const fail = (error: SmbError, status: string): SmbResult => {
    conn.send('s2c', 70, { protocol: 'SMB2', info: `Tree Connect Response, Error: ${status}`, fields: [] });
    return done({ ok: false, stage: 'tree', error, serverIp: ip });
  };
  if (share.toUpperCase() === 'IPC$') { conn.send('s2c', 80, { protocol: 'SMB2', info: 'Tree Connect Response', fields: [] }); return done({ ok: true, session }); }
  const s = findShare(conf, share);
  if (!s || boolValue(s.params.available ?? 'yes') === false) return fail('NT_STATUS_BAD_NETWORK_NAME', 'STATUS_BAD_NETWORK_NAME');
  const who = account ?? GUEST;
  if (!account && !boolValue(s.params['guest ok'])) return fail('NT_STATUS_ACCESS_DENIED', 'STATUS_ACCESS_DENIED');
  const valid = list(s.params['valid users']);
  const invalid = list(s.params['invalid users']);
  if (account && ((valid.length && !listMatches(valid, account)) || listMatches(invalid, account))) {
    smbLog(world, server, clientName, 2, '../../source3/smbd/service.c:614(make_connection_snum)', `user '${account.name}' (from session setup) not permitted to access this share (${s.name})`);
    return fail('NT_STATUS_ACCESS_DENIED', 'STATUS_ACCESS_DENIED');
  }
  const root = (s.params.path ?? '').replace(/\/+$/, '') || '/';
  if (server.fs[root]?.type !== 'dir') {
    smbLog(world, server, clientName, 0, '../../source3/smbd/service.c:770(make_connection_snum)', `make_connection_snum: canonicalize_connect_path failed for service ${s.name}, path ${root}`);
    return fail('NT_STATUS_BAD_NETWORK_NAME', 'STATUS_BAD_NETWORK_NAME');
  }
  if (!canAccess(server.fs[root], who, 'x')) return fail('NT_STATUS_ACCESS_DENIED', 'STATUS_ACCESS_DENIED');
  const writeList = list(s.params['write list']);
  const writable = !shareReadOnly(s) || (!!account && listMatches(writeList, account));
  smbLog(world, server, clientName, 2, '../../source3/smbd/service.c:1124(make_connection_snum)',
    `${clientName} (ipv4:${clientIp}:${conn.sv.peerPort}) connect to service ${s.name} initially as user ${who.name} (uid=${who.uid}, gid=${who.gid}) (pid ${server.nextPid})`);
  conn.send('s2c', 80, { protocol: 'SMB2', info: 'Tree Connect Response', fields: [{ name: 'Share Type', value: 'Disk' }] });
  return done({ ok: true, session: { ...session, share: s, root, writable } });
}

/** The share list a client sees (browseable shares plus IPC$). */
export function shareList(session: SmbSession): { name: string; type: 'Disk' | 'IPC'; comment: string }[] {
  const server = session.conf.global['server string'] ?? 'Samba %v';
  return [
    ...session.conf.shares.filter((s) => shareBrowseable(s) && boolValue(s.params.available ?? 'yes')).map((s) => ({ name: s.name, type: 'Disk' as const, comment: s.params.comment ?? '' })),
    { name: 'IPC$', type: 'IPC', comment: `IPC Service (${server.replace('%v', SAMBA_VERSION).replace('%h', session.server.hostname)})` },
  ];
}

// ---------------------------------------------------------------------------
// File operations inside a connected share (run on the server as the user)
// ---------------------------------------------------------------------------

export type FileStatus = 'NT_STATUS_OK' | 'NT_STATUS_ACCESS_DENIED' | 'NT_STATUS_OBJECT_NAME_NOT_FOUND' | 'NT_STATUS_OBJECT_PATH_NOT_FOUND' | 'NT_STATUS_NO_SUCH_FILE' | 'NT_STATUS_OBJECT_NAME_COLLISION' | 'NT_STATUS_FILE_IS_A_DIRECTORY' | 'NT_STATUS_NOT_A_DIRECTORY' | 'NT_STATUS_DIRECTORY_NOT_EMPTY';

/** Share-relative path ("\\dir\\file" or "dir/file") → server path; null when it escapes the share. */
export function serverPath(session: SmbSession, rel: string): string | null {
  const parts: string[] = [];
  for (const p of rel.replace(/\\/g, '/').split('/')) {
    if (!p || p === '.') continue;
    if (p === '..') { if (!parts.length) return null; parts.pop(); continue; }
    parts.push(p);
  }
  return parts.length ? `${session.root === '/' ? '' : session.root}/${parts.join('/')}` : session.root!;
}

const who = (s: SmbSession) => s.user ?? GUEST;

export function smbList(session: SmbSession, dir: string): { status: FileStatus; entries?: { name: string; dir: boolean; size: number; mtime: number }[] } {
  const p = serverPath(session, dir);
  const h = session.server;
  if (!p || !h.fs[p]) return { status: 'NT_STATUS_NO_SUCH_FILE' };
  if (h.fs[p].type !== 'dir') return { status: 'NT_STATUS_OK', entries: [{ name: p.split('/').pop()!, dir: false, size: (h.fs[p].size ?? h.fs[p].content.length), mtime: h.fs[p].mtime }] };
  if (!canAccess(h.fs[p], who(session), 'r')) return { status: 'NT_STATUS_ACCESS_DENIED' };
  const entries = [{ name: '.', dir: true, size: 0, mtime: h.fs[p].mtime }, { name: '..', dir: true, size: 0, mtime: h.fs[p].mtime },
    ...listDir(h, p).map((name) => {
      const n = h.fs[`${p === '/' ? '' : p}/${name}`];
      return { name, dir: n.type === 'dir', size: n.type === 'dir' ? 0 : (n.size ?? n.content.length), mtime: n.mtime };
    })];
  return { status: 'NT_STATUS_OK', entries };
}

export function smbRead(session: SmbSession, rel: string): { status: FileStatus; content?: string } {
  const p = serverPath(session, rel);
  const h = session.server;
  if (!p || !h.fs[p]) return { status: 'NT_STATUS_OBJECT_NAME_NOT_FOUND' };
  if (h.fs[p].type === 'dir') return { status: 'NT_STATUS_FILE_IS_A_DIRECTORY' };
  if (!canAccess(h.fs[p], who(session), 'r')) return { status: 'NT_STATUS_ACCESS_DENIED' };
  return { status: 'NT_STATUS_OK', content: h.fs[p].content };
}

const octalParam = (v: string | undefined, d: number) => (v && /^0?[0-7]{3,4}$/.test(v.trim()) ? parseInt(v.trim(), 8) : d);

/** Create or overwrite a file: the share must be writable and the Unix permissions must allow it. */
export function smbWrite(world: World, session: SmbSession, rel: string, content: string): FileStatus {
  const p = serverPath(session, rel);
  const h = session.server;
  if (!p || p === session.root) return 'NT_STATUS_ACCESS_DENIED';
  const parent = h.fs[dirname(p)];
  if (!parent || parent.type !== 'dir') return 'NT_STATUS_OBJECT_PATH_NOT_FOUND';
  if (!session.writable) return 'NT_STATUS_ACCESS_DENIED';
  const u = who(session);
  const existing = h.fs[p];
  if (existing?.type === 'dir') return 'NT_STATUS_FILE_IS_A_DIRECTORY';
  if (existing ? !canAccess(existing, u, 'w') : !canAccess(parent, u, 'w')) return 'NT_STATUS_ACCESS_DENIED';
  const s = session.share!;
  const group = s.params['force group']?.replace(/^\+/, '') || existing?.group || u.primaryGroup;
  // Samba starts from 0666 for a writable file, then applies create mask (default 0744) and force create mode.
  const mode = existing?.mode ?? ((0o666 & octalParam(s.params['create mask'], 0o744)) | octalParam(s.params['force create mode'], 0));
  writeFile(h, p, content, world.clock, { mode, owner: existing?.owner ?? u.name, group });
  return 'NT_STATUS_OK';
}

export function smbMkdir(world: World, session: SmbSession, rel: string): FileStatus {
  const p = serverPath(session, rel);
  const h = session.server;
  if (!p || p === session.root) return 'NT_STATUS_OBJECT_NAME_COLLISION';
  const parent = h.fs[dirname(p)];
  if (!parent || parent.type !== 'dir') return 'NT_STATUS_OBJECT_PATH_NOT_FOUND';
  if (h.fs[p]) return 'NT_STATUS_OBJECT_NAME_COLLISION';
  const u = who(session);
  if (!session.writable || !canAccess(parent, u, 'w')) return 'NT_STATUS_ACCESS_DENIED';
  const s = session.share!;
  const mode = (0o777 & octalParam(s.params['directory mask'], 0o755)) | octalParam(s.params['force directory mode'], 0);
  h.fs[p] = { type: 'dir', mode, owner: u.name, group: s.params['force group']?.replace(/^\+/, '') || u.primaryGroup, content: '', mtime: world.clock };
  return 'NT_STATUS_OK';
}

export function smbDelete(session: SmbSession, rel: string, dir: boolean): FileStatus {
  const p = serverPath(session, rel);
  const h = session.server;
  if (!p || !h.fs[p] || p === session.root) return 'NT_STATUS_OBJECT_NAME_NOT_FOUND';
  if (dir !== (h.fs[p].type === 'dir')) return dir ? 'NT_STATUS_NOT_A_DIRECTORY' : 'NT_STATUS_FILE_IS_A_DIRECTORY';
  if (!session.writable || !canAccess(h.fs[dirname(p)], who(session), 'w')) return 'NT_STATUS_ACCESS_DENIED';
  if (dir && listDir(h, p).length) return 'NT_STATUS_DIRECTORY_NOT_EMPTY';
  delete h.fs[p];
  return 'NT_STATUS_OK';
}
