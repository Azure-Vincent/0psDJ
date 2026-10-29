// PostgreSQL 15 on Debian 12 (postgresql@15-main). The model covers what a
// database administrator sets up and what breaks: the cluster's data
// directory (ownership and mode checked at start), postgresql.conf with
// include_dir and postgresql.auto.conf (ALTER SYSTEM), which settings need a
// restart and which a reload, listen_addresses and port, pg_hba.conf rules
// matched top to bottom, the authentication methods (peer, scram-sha-256,
// md5, trust, reject) and the role's stored password hash, the LOGIN and
// CONNECT checks, connection limits, and the server log in Debian's format
// (/var/log/postgresql/postgresql-15-main.log).
//
// The cluster's contents (roles, databases, tables, privileges) live in
// Host.pg and survive restarts like the files in the data directory; the
// running server (settings in effect, pg_hba rules, sessions) is rt.loaded.

import { readFile, writeFile } from '../fs';
import { inCidr, parseCidr } from '../net/ip';
import { inCidr6, parseCidr6 } from '../net/ip6';
import type { Host, ServiceRuntime, World } from '../types';
import { sha256Hex } from '../util/sha256';
import { resolve } from './dns';
import { log } from './journal';
import { hostAddresses } from './network';
import { allListeners } from './services';
import { tcpConnect } from './tcp';

export const PG_VERSION = '15.8';
export const PG_FULL = '15.8 (Debian 15.8-0+deb12u1)';
export const PG_BUILD = `PostgreSQL ${PG_FULL} on x86_64-pc-linux-gnu, compiled by gcc (Debian 12.2.0-14) 12.2.0, 64-bit`;
export const CONF_DIR = '/etc/postgresql/15/main';
export const PG_CONF = `${CONF_DIR}/postgresql.conf`;
export const PG_HBA = `${CONF_DIR}/pg_hba.conf`;
export const DATA_DIR = '/var/lib/postgresql/15/main';
export const AUTO_CONF = `${DATA_DIR}/postgresql.auto.conf`;
export const PG_LOG = '/var/log/postgresql/postgresql-15-main.log';
export const SOCKET_DIR = '/var/run/postgresql';
export const PG_UNIT = 'postgresql@15-main.service';

// ---------------------------------------------------------------------------
// The cluster's contents (persistent)
// ---------------------------------------------------------------------------

export type Cell = string | number | boolean | null;
export interface PgRole {
  name: string;
  oid: number;
  superuser: boolean;
  login: boolean;
  createdb: boolean;
  createrole: boolean;
  replication: boolean;
  /** The password as typed (the simulation keeps it to check logins) and how it is stored. */
  password: string | null;
  hash: 'scram' | 'md5' | null;
  /** -1 = no limit. */
  connLimit: number;
  /** Password expiry (ms since epoch); null = never. */
  validUntil: number | null;
  memberOf: string[];
  /** Predefined roles (pg_read_all_data …) are not listed by \du. */
  predefined?: boolean;
}
export interface PgColumn { name: string; type: string; serial?: boolean; notNull?: boolean; primaryKey?: boolean }
export interface PgTable {
  name: string;
  owner: string;
  columns: PgColumn[];
  rows: Cell[][];
  /** grantee (role name or PUBLIC) -> privilege letters: r SELECT, a INSERT, w UPDATE, d DELETE, D TRUNCATE, x REFERENCES, t TRIGGER. */
  acl: Record<string, string>;
  nextSerial: number;
}
export interface PgDatabase {
  name: string;
  oid: number;
  owner: string;
  /** Roles with CONNECT (PUBLIC by default). */
  connect: string[];
  /** Roles that may CREATE in schema public (PostgreSQL 15: only the database owner by default). */
  schemaCreate: string[];
  tables: Record<string, PgTable>;
  /** ALTER DEFAULT PRIVILEGES: tables created later by `owner` get these grants. */
  defaultAcl: { owner: string; grantee: string; privs: string }[];
}
export interface PgCluster {
  roles: Record<string, PgRole>;
  databases: Record<string, PgDatabase>;
  nextOid: number;
  /** Stored hash -> password, so a hash re-imported from pg_dumpall still checks the right password. */
  hashes?: Record<string, string>;
}

export const PRIV_LETTERS: Record<string, string> = { SELECT: 'r', INSERT: 'a', UPDATE: 'w', DELETE: 'd', TRUNCATE: 'D', REFERENCES: 'x', TRIGGER: 't' };
export const ALL_TABLE_PRIVS = 'arwdDxt';

export function newRole(name: string, oid: number, opts: Partial<PgRole> = {}): PgRole {
  return { name, oid, superuser: false, login: false, createdb: false, createrole: false, replication: false, password: null, hash: null, connLimit: -1, validUntil: null, memberOf: [], ...opts };
}

/** A freshly initialised cluster (pg_createcluster / initdb): postgres, the predefined roles, postgres/template0/template1. */
export function initCluster(): PgCluster {
  const roles: Record<string, PgRole> = {
    postgres: newRole('postgres', 10, { superuser: true, login: true, createdb: true, createrole: true, replication: true }),
  };
  for (const [i, n] of ['pg_database_owner', 'pg_read_all_data', 'pg_write_all_data', 'pg_monitor', 'pg_read_all_settings', 'pg_read_all_stats', 'pg_stat_scan_tables', 'pg_signal_backend', 'pg_checkpoint'].entries()) {
    roles[n] = newRole(n, 6171 + i, { predefined: true });
  }
  const db = (name: string, oid: number): PgDatabase => ({ name, oid, owner: 'postgres', connect: ['PUBLIC'], schemaCreate: [], tables: {}, defaultAcl: [] });
  return { roles, databases: { postgres: db('postgres', 5), template1: db('template1', 1), template0: db('template0', 4) }, nextOid: 16384 };
}

export function cluster(host: Host): PgCluster {
  return (host.pg ??= initCluster());
}

/** Is `role` (directly or through membership) a member of `group`? */
export function memberOf(c: PgCluster, role: string, group: string, seen = new Set<string>()): boolean {
  if (role === group) return true;
  if (seen.has(role)) return false;
  seen.add(role);
  return (c.roles[role]?.memberOf ?? []).some((g) => memberOf(c, g, group, seen));
}

export const isSuper = (c: PgCluster, role: string) => !!c.roles[role]?.superuser;

/** Does `role` hold privilege letter `p` on the table (owner, grants to it, its groups, PUBLIC, predefined roles)? */
export function tablePriv(c: PgCluster, t: PgTable, role: string, p: string): boolean {
  if (isSuper(c, role) || memberOf(c, role, t.owner)) return true;
  if (p === 'r' && memberOf(c, role, 'pg_read_all_data')) return true;
  if ('awd'.includes(p) && memberOf(c, role, 'pg_write_all_data')) return true;
  return Object.entries(t.acl).some(([g, letters]) => letters.includes(p) && (g === 'PUBLIC' || memberOf(c, role, g)));
}

/** The stored form of a password, as pg_authid.rolpassword shows it. */
export function storedHash(r: PgRole): string | null {
  if (!r.password || !r.hash) return null;
  if (r.hash === 'md5') return 'md5' + sha256Hex(`md5:${r.password}${r.name}`).slice(0, 32);
  const h = sha256Hex(`scram:${r.name}:${r.password}`);
  return `SCRAM-SHA-256$4096:${btoaSafe(h.slice(0, 16))}$${btoaSafe(h.slice(16, 48))}:${btoaSafe(h.slice(32, 64))}`;
}
const btoaSafe = (s: string) => (typeof btoa === 'function' ? btoa(s) : s);

// ---------------------------------------------------------------------------
// Settings: postgresql.conf, conf.d, postgresql.auto.conf
// ---------------------------------------------------------------------------

type Context = 'postmaster' | 'sighup' | 'user';
type Kind = 'int' | 'bool' | 'string' | 'enum' | 'mem' | 'time';
interface SettingDef { def: string; ctx: Context; kind: Kind; values?: string[]; min?: number; max?: number }
const S = (def: string, ctx: Context, kind: Kind = 'string', extra: Partial<SettingDef> = {}): SettingDef => ({ def, ctx, kind, ...extra });

export const SETTINGS: Record<string, SettingDef> = {
  data_directory: S(DATA_DIR, 'postmaster'),
  hba_file: S(PG_HBA, 'postmaster'),
  ident_file: S(`${CONF_DIR}/pg_ident.conf`, 'postmaster'),
  external_pid_file: S('/var/run/postgresql/15-main.pid', 'postmaster'),
  listen_addresses: S('localhost', 'postmaster'),
  port: S('5432', 'postmaster', 'int', { min: 1, max: 65535 }),
  max_connections: S('100', 'postmaster', 'int', { min: 1, max: 262143 }),
  superuser_reserved_connections: S('3', 'postmaster', 'int', { min: 0, max: 262143 }),
  unix_socket_directories: S(SOCKET_DIR, 'postmaster'),
  shared_buffers: S('128MB', 'postmaster', 'mem'),
  shared_preload_libraries: S('', 'postmaster'),
  wal_level: S('replica', 'postmaster', 'enum', { values: ['minimal', 'replica', 'logical'] }),
  max_wal_senders: S('10', 'postmaster', 'int', { min: 0, max: 262143 }),
  cluster_name: S('15/main', 'postmaster'),
  dynamic_shared_memory_type: S('posix', 'postmaster', 'enum', { values: ['posix', 'sysv', 'mmap'] }),
  ssl: S('off', 'sighup', 'bool'),
  ssl_cert_file: S('server.crt', 'sighup'),
  ssl_key_file: S('server.key', 'sighup'),
  password_encryption: S('scram-sha-256', 'user', 'enum', { values: ['md5', 'scram-sha-256'] }),
  authentication_timeout: S('1min', 'sighup', 'time'),
  log_connections: S('off', 'sighup', 'bool'),
  log_disconnections: S('off', 'sighup', 'bool'),
  log_line_prefix: S('%m [%p] %q%u@%d ', 'sighup'),
  log_timezone: S('Etc/UTC', 'sighup'),
  log_statement: S('none', 'user', 'enum', { values: ['none', 'ddl', 'mod', 'all'] }),
  log_min_duration_statement: S('-1', 'user', 'int', { min: -1, max: 2147483647 }),
  autovacuum: S('on', 'sighup', 'bool'),
  max_wal_size: S('1GB', 'sighup', 'mem'),
  min_wal_size: S('80MB', 'sighup', 'mem'),
  work_mem: S('4MB', 'user', 'mem'),
  maintenance_work_mem: S('64MB', 'user', 'mem'),
  statement_timeout: S('0', 'user', 'time'),
  timezone: S('Etc/UTC', 'user'),
  datestyle: S('iso, mdy', 'user'),
  lc_messages: S('C.UTF-8', 'user'),
  lc_monetary: S('C.UTF-8', 'user'),
  lc_numeric: S('C.UTF-8', 'user'),
  lc_time: S('C.UTF-8', 'user'),
  default_text_search_config: S('pg_catalog.english', 'user'),
  search_path: S('"$user", public', 'user'),
  include_dir: S('', 'postmaster'),
};

export interface ConfEntry { name: string; value: string; file: string; line: number }

/** Parse a postgresql.conf-style file: name = value, # comments, quoted values. */
export function parseConf(text: string, file: string): { entries: ConfEntry[]; errors: string[] } {
  const entries: ConfEntry[] = [];
  const errors: string[] = [];
  text.split('\n').forEach((raw, i) => {
    let line = raw.trim();
    if (!line || line.startsWith('#')) return;
    const m = /^([A-Za-z_][\w.]*)\s*(?:=\s*|\s+)(.*)$/.exec(line);
    if (!m) { errors.push(`LOG:  syntax error in file "${file}" line ${i + 1}, near token "${line.split(/\s+/)[0]}"`); return; }
    line = m[2].trim();
    let value: string;
    if (line.startsWith("'")) {
      const end = line.indexOf("'", 1);
      if (end < 0) { errors.push(`LOG:  syntax error in file "${file}" line ${i + 1}, near end of line`); return; }
      value = line.slice(1, end);
    } else value = line.split('#')[0].trim();
    entries.push({ name: m[1].toLowerCase(), value, file, line: i + 1 });
  });
  return { entries, errors };
}

/** All configuration entries in the order PostgreSQL reads them (postgresql.conf, include_dir files, postgresql.auto.conf). */
export function confEntries(host: Host): { entries: ConfEntry[]; errors: string[] } {
  const out: ConfEntry[] = [];
  const errors: string[] = [];
  const read = (file: string) => {
    const text = readFile(host, file);
    if (text === undefined) { errors.push(`FATAL:  could not open file "${file}": No such file or directory`); return; }
    const p = parseConf(text, file);
    errors.push(...p.errors);
    for (const e of p.entries) {
      if (e.name === 'include_dir') {
        const dir = e.value.startsWith('/') ? e.value : `${CONF_DIR}/${e.value}`;
        for (const f of Object.keys(host.fs).filter((k) => k.startsWith(dir + '/') && k.endsWith('.conf') && !k.slice(dir.length + 1).includes('/')).sort()) read(f);
      } else if (e.name === 'include' || e.name === 'include_if_exists') {
        const f = e.value.startsWith('/') ? e.value : `${CONF_DIR}/${e.value}`;
        if (host.fs[f] || e.name === 'include') read(f);
      } else out.push(e);
    }
  };
  read(PG_CONF);
  if (host.fs[AUTO_CONF]) {
    const p = parseConf(readFile(host, AUTO_CONF) ?? '', AUTO_CONF);
    out.push(...p.entries);
    errors.push(...p.errors);
  }
  return { entries: out, errors };
}

function validValue(name: string, value: string): boolean {
  const d = SETTINGS[name];
  if (!d) return false;
  if (d.kind === 'int') return /^-?\d+$/.test(value) && Number(value) >= (d.min ?? -Infinity) && Number(value) <= (d.max ?? Infinity);
  if (d.kind === 'bool') return /^(on|off|true|false|yes|no|1|0)$/i.test(value);
  if (d.kind === 'enum') return d.values!.includes(value.toLowerCase());
  if (d.kind === 'mem') return /^\d+\s*(kB|MB|GB|TB)?$/.test(value);
  if (d.kind === 'time') return /^-?\d+\s*(ms|s|min|h|d)?$/.test(value);
  return true;
}

/** Effective settings and the errors PostgreSQL reports about the files. */
export function loadSettings(host: Host): { values: Record<string, string>; sources: Record<string, ConfEntry>; errors: string[] } {
  const { entries, errors } = confEntries(host);
  const values = Object.fromEntries(Object.entries(SETTINGS).map(([k, v]) => [k, v.def]));
  const sources: Record<string, ConfEntry> = {};
  for (const e of entries) {
    if (!SETTINGS[e.name]) { errors.push(`LOG:  unrecognized configuration parameter "${e.name}" in file "${e.file}" line ${e.line}`); continue; }
    if (!validValue(e.name, e.value)) { errors.push(`LOG:  invalid value for parameter "${e.name}": "${e.value}"`); continue; }
    values[e.name] = e.value;
    sources[e.name] = e;
  }
  return { values, sources, errors };
}

export const boolOn = (v: string | undefined) => /^(on|true|yes|1)$/i.test(v ?? '');

// ---------------------------------------------------------------------------
// pg_hba.conf
// ---------------------------------------------------------------------------

export interface HbaRule {
  line: number;
  raw: string;
  type: 'local' | 'host' | 'hostssl' | 'hostnossl';
  databases: string[];
  users: string[];
  address?: string;
  method: string;
}

const METHODS = ['trust', 'reject', 'scram-sha-256', 'md5', 'password', 'peer', 'ident', 'gss', 'sspi', 'pam', 'ldap', 'radius', 'cert'];

export function parseHba(text: string, file = PG_HBA): { rules: HbaRule[]; errors: string[] } {
  const rules: HbaRule[] = [];
  const errors: string[] = [];
  const ctx = (n: number) => `CONTEXT:  line ${n} of configuration file "${file}"`;
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) return;
    const f = line.split(/\s+/);
    const n = i + 1;
    const type = f[0] as HbaRule['type'];
    if (!['local', 'host', 'hostssl', 'hostnossl'].includes(type)) { errors.push(`LOG:  invalid connection type "${f[0]}"`, ctx(n)); return; }
    const local = type === 'local';
    if (f.length < (local ? 4 : 5)) { errors.push(`LOG:  end-of-line before authentication method`, ctx(n)); return; }
    let address: string | undefined;
    let mi = 3;
    if (!local) {
      address = f[3];
      mi = 4;
      // An address followed by a netmask column.
      if (/^\d+\.\d+\.\d+\.\d+$/.test(address) && /^\d+\.\d+\.\d+\.\d+$/.test(f[4] ?? '')) {
        const bits = f[4].split('.').map(Number).reduce((a, o) => a + o.toString(2).replace(/0/g, '').length, 0);
        address = `${address}/${bits}`;
        mi = 5;
      }
      if (!/^(all|samehost|samenet)$/.test(address) && !address.includes('/') && /^[\d.:]+$/.test(address)) { errors.push(`LOG:  specifying both host name and CIDR mask is invalid: "${address}"`, ctx(n)); return; }
      if (address.includes('/') && !(address.includes(':') ? parseCidr6(address) : parseCidr(address))) { errors.push(`LOG:  invalid IP address "${address.split('/')[0]}": Name or service not known`, ctx(n)); return; }
    }
    const method = f[mi];
    if (!method) { errors.push('LOG:  end-of-line before authentication method', ctx(n)); return; }
    if (!METHODS.includes(method)) { errors.push(`LOG:  invalid authentication method "${method}"`, ctx(n)); return; }
    if (method === 'peer' && !local) { errors.push('LOG:  peer authentication is only supported on local sockets', ctx(n)); return; }
    rules.push({ line: n, raw: raw.trim(), type, databases: f[1].split(','), users: f[2].split(','), address, method });
  });
  return { rules, errors };
}

/** The first pg_hba.conf rule that matches the connection (PostgreSQL never looks further). */
export function matchHba(c: PgCluster, rules: HbaRule[], conn: { local: boolean; ssl: boolean; ip: string; user: string; db: string; serverHost?: Host }): HbaRule | null {
  return rules.find((r) => {
    if (conn.local !== (r.type === 'local')) return false;
    if (r.type === 'hostssl' && !conn.ssl) return false;
    if (r.type === 'hostnossl' && conn.ssl) return false;
    const dbOk = r.databases.some((d) => d === 'all' || (d === 'sameuser' && conn.db === conn.user) || (d === 'samerole' && memberOf(c, conn.user, conn.db)) || (d !== 'replication' && d === conn.db));
    if (!dbOk) return false;
    const userOk = r.users.some((u) => u === 'all' || (u.startsWith('+') ? memberOf(c, conn.user, u.slice(1)) : u === conn.user));
    if (!userOk) return false;
    if (conn.local) return true;
    const a = r.address!;
    if (a === 'all') return true;
    if (a === 'samehost') return !!conn.serverHost && hostAddresses(conn.serverHost, 0).includes(conn.ip);
    if (a === 'samenet') return true;
    if (a.includes(':') !== conn.ip.includes(':')) return false;
    if (a.includes(':')) { const c6 = parseCidr6(a); return !!c6 && inCidr6(conn.ip, c6); }
    const c4 = parseCidr(a);
    return !!c4 && inCidr(conn.ip, c4);
  }) ?? null;
}

// ---------------------------------------------------------------------------
// The running server
// ---------------------------------------------------------------------------

export interface PgSession { pid: number; user: string; db: string; client: string | null; clientPort: number | null; start: number; app: string; state: 'idle' | 'active' }
export interface PgLoaded {
  pid: number;
  settings: Record<string, string>;
  /** Values from the files that differ from what runs and need a restart. */
  pendingRestart: string[];
  hba: HbaRule[];
  /** Addresses the postmaster listens on. */
  listen: string[];
  port: number;
  sessions: PgSession[];
  startedAt: number;
}

export function pgLoaded(host: Host): PgLoaded | null {
  const rt = host.services.postgresql;
  return rt?.state === 'active' ? (rt.loaded as PgLoaded) : null;
}

function stamp(t: number): string {
  const d = new Date(Math.floor(t));
  const p = (n: number, w = 2) => String(n).padStart(w, '0');
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}.${p(Math.floor(t) % 1000, 3)} UTC`;
}
export const pgTime = (t: number) => stamp(t).replace(/\.\d{3}/, '');

/**
 * Append to the server log in Debian's format (log_line_prefix '%m [%p] %q%u@%d ').
 * `who` is the session's user@db; postmaster and background messages have none.
 */
export function pgLog(world: World, host: Host, pid: number, level: string, msg: string, who?: { user?: string; db?: string }, extra: string[] = []): void {
  const prefix = `${stamp(world.clock)} [${pid}] ${who ? `${who.user ?? '[unknown]'}@${who.db ?? '[unknown]'} ` : ''}`;
  const lines = [`${prefix}${level}:  ${msg}`, ...extra.map((e) => `${prefix}${e}`)];
  const cur = readFile(host, PG_LOG) ?? '';
  writeFile(host, PG_LOG, cur + lines.join('\n') + '\n', world.clock, host.fs[PG_LOG] ? undefined : { mode: 0o640, owner: 'postgres', group: 'adm' });
}

function allocPid(host: Host): number {
  host.nextPid += 3;
  return host.nextPid;
}

/** listen_addresses → the addresses the postmaster can bind, and the failures it logs. */
function bindAddresses(host: Host, spec: string): { addrs: string[]; failed: string[] } {
  const addrs: string[] = [];
  const failed: string[] = [];
  for (const raw of spec.split(',').map((x) => x.trim()).filter(Boolean)) {
    if (raw === '*') { addrs.push('0.0.0.0', '::'); continue; }
    if (raw === 'localhost') { addrs.push('127.0.0.1', '::1'); continue; }
    if (raw === '0.0.0.0' || raw === '::') { addrs.push(raw); continue; }
    if (raw.startsWith('127.') || raw === '::1' || hostAddresses(host, 0).includes(raw)) addrs.push(raw);
    else failed.push(raw);
  }
  return { addrs, failed };
}

/** Data directory checks the postmaster makes before anything else. */
function dataDirProblem(host: Host): string[] | null {
  const n = host.fs[DATA_DIR];
  if (!n || n.type !== 'dir') return [`FATAL:  data directory "${DATA_DIR}" does not exist`];
  if (n.owner !== 'postgres') return [`FATAL:  data directory "${DATA_DIR}" has wrong ownership`, 'HINT:  The server must be started by the user that owns the data directory.'];
  if ((n.mode & 0o077) !== 0 && (n.mode & 0o777) !== 0o750) return [`FATAL:  data directory "${DATA_DIR}" has invalid permissions`, 'DETAIL:  Permissions should be u=rwx (0700) or u=rwx,g=rx (0750).'];
  const v = host.fs[`${DATA_DIR}/PG_VERSION`];
  if (!v) return [`FATAL:  "${DATA_DIR}" is not a valid data directory`, `DETAIL:  File "${DATA_DIR}/PG_VERSION" is missing.`];
  if (v.content.trim() !== '15') return ['FATAL:  database files are incompatible with server', `DETAIL:  The data directory was initialized by PostgreSQL version ${v.content.trim()}, which is not compatible with this version ${PG_FULL}.`];
  return null;
}

const SOCKET = (port: number) => `${SOCKET_DIR}/.s.PGSQL.${port}`;

export function pgStart(world: World, host: Host, rt: ServiceRuntime): PgLoaded | null {
  const pid = rt.pid!;
  const fail = (lines: string[]) => {
    for (const l of lines) { const [lvl, ...m] = l.split(':  '); pgLog(world, host, pid, lvl, m.join(':  ')); }
    log(world, host, 'postgresql@15-main', `Error: /usr/lib/postgresql/15/bin/pg_ctl /usr/lib/postgresql/15/bin/pg_ctl start -D ${DATA_DIR} -l ${PG_LOG} -s -o  -c config_file="${PG_CONF}"  exited with status 1:`, { pid: pid - 1, unit: PG_UNIT, priority: 'err' });
    for (const l of lines) log(world, host, 'postgresql@15-main', `${stamp(world.clock)} [${pid}] ${l}`, { pid: pid - 1, unit: PG_UNIT, priority: 'err' });
    return null;
  };
  const st = loadSettings(host);
  if (st.errors.length) return fail([...st.errors, `FATAL:  configuration file "${PG_CONF}" contains errors`]);
  const dd = dataDirProblem(host);
  if (dd) return fail(dd);
  const hbaText = readFile(host, st.values.hba_file);
  if (hbaText === undefined) return fail([`LOG:  could not open configuration file "${st.values.hba_file}": No such file or directory`, 'FATAL:  could not load pg_hba.conf']);
  const hba = parseHba(hbaText, st.values.hba_file);
  if (hba.errors.length) return fail([...hba.errors, 'FATAL:  could not load pg_hba.conf']);
  if (boolOn(st.values.ssl)) {
    for (const k of ['ssl_cert_file', 'ssl_key_file']) {
      const f = st.values[k].startsWith('/') ? st.values[k] : `${DATA_DIR}/${st.values[k]}`;
      if (!host.fs[f]) return fail([`FATAL:  could not load ${k === 'ssl_cert_file' ? 'server certificate' : 'private key'} file "${f}": No such file or directory`]);
    }
  }
  const port = Number(st.values.port);
  const { addrs, failed } = bindAddresses(host, st.values.listen_addresses);
  const lines: string[] = [];
  for (const f of failed) lines.push(`LOG:  could not bind IP${f.includes(':') ? 'v6' : 'v4'} address "${f}": Cannot assign requested address`, 'HINT:  Is another postmaster already running on port ' + port + '? If not, wait a few seconds and retry.', `WARNING:  could not create listen socket for "${f}"`);
  if (!addrs.length && st.values.listen_addresses.trim()) return fail([...lines, 'FATAL:  could not create any TCP/IP sockets']);
  pgLog(world, host, pid, 'LOG', `starting ${PG_BUILD}`);
  for (const l of lines) { const [lvl, ...m] = l.split(':  '); pgLog(world, host, pid, lvl, m.join(':  ')); }
  for (const a of addrs) pgLog(world, host, pid, 'LOG', `listening on IPv${a.includes(':') ? 6 : 4} address "${a}", port ${port}`);
  if (!host.fs[SOCKET_DIR]) host.fs[SOCKET_DIR] = { type: 'dir', mode: 0o2775, owner: 'postgres', group: 'postgres', content: '', mtime: world.clock };
  writeFile(host, SOCKET(port), '', world.clock, { mode: 0o777, owner: 'postgres', group: 'postgres' });
  host.fs[SOCKET(port)].socket = true;
  pgLog(world, host, pid, 'LOG', `listening on Unix socket "${SOCKET(port)}"`);
  writeFile(host, `${DATA_DIR}/postmaster.pid`, `${pid}\n${DATA_DIR}\n${Math.floor(world.clock / 1000)}\n${port}\n${SOCKET_DIR}\n${addrs[0] ?? ''}\n`, world.clock, { mode: 0o600, owner: 'postgres', group: 'postgres' });
  pgLog(world, host, pid + 2, 'LOG', `database system was shut down at ${pgTime(world.clock - 60_000)}`);
  pgLog(world, host, pid, 'LOG', 'database system is ready to accept connections');
  return { pid, settings: st.values, pendingRestart: [], hba: hba.rules, listen: addrs, port, sessions: [], startedAt: world.clock };
}

/** SIGHUP: re-read the files; postmaster-context changes wait for a restart; a broken pg_hba.conf is not loaded. */
export function pgReload(world: World, host: Host, rt: ServiceRuntime): boolean {
  const l = rt.loaded as PgLoaded;
  const pid = l.pid;
  pgLog(world, host, pid, 'LOG', 'received SIGHUP, reloading configuration files');
  const st = loadSettings(host);
  let errors = st.errors.length > 0;
  for (const e of st.errors) { const [lvl, ...m] = e.split(':  '); pgLog(world, host, pid, lvl, m.join(':  ')); }
  const pending: string[] = [];
  for (const [k, v] of Object.entries(st.values)) {
    if (l.settings[k] === v) continue;
    if (SETTINGS[k]?.ctx === 'postmaster') {
      pgLog(world, host, pid, 'LOG', `parameter "${k}" cannot be changed without restarting the server`);
      pending.push(k);
      errors = true;
      continue;
    }
    pgLog(world, host, pid, 'LOG', `parameter "${k}" changed to "${v}"`);
    l.settings[k] = v;
  }
  l.pendingRestart = pending;
  if (errors) pgLog(world, host, pid, 'LOG', `configuration file "${PG_CONF}" contains errors; unaffected changes were applied`);
  const hba = parseHba(readFile(host, l.settings.hba_file) ?? '', l.settings.hba_file);
  if (hba.errors.length) {
    for (const e of hba.errors) { const [lvl, ...m] = e.split(':  '); pgLog(world, host, pid, lvl, m.join(':  ')); }
    pgLog(world, host, pid, 'LOG', 'pg_hba.conf was not reloaded');
  } else l.hba = hba.rules;
  return true;
}

export function pgStop(world: World, host: Host, rt: ServiceRuntime): void {
  const l = rt.loaded as PgLoaded | null;
  if (!l) return;
  pgLog(world, host, l.pid, 'LOG', 'received fast shutdown request');
  pgLog(world, host, l.pid, 'LOG', 'aborting any active transactions');
  for (const s of l.sessions) pgLog(world, host, s.pid, 'FATAL', 'terminating connection due to administrator command', { user: s.user, db: s.db });
  pgLog(world, host, l.pid + 2, 'LOG', 'shutting down');
  pgLog(world, host, l.pid, 'LOG', 'database system is shut down');
  delete host.fs[SOCKET(l.port)];
  delete host.fs[`${DATA_DIR}/postmaster.pid`];
}

/** After a reboot the runtime directory is empty: remove a socket and pid file left by the previous run. */
export function pgCleanup(host: Host): void {
  for (const k of Object.keys(host.fs)) if (k.startsWith(`${SOCKET_DIR}/.s.PGSQL.`)) delete host.fs[k];
  delete host.fs[`${DATA_DIR}/postmaster.pid`];
}

// ---------------------------------------------------------------------------
// Client connections (libpq as psql, pg_dump, pg_isready use it)
// ---------------------------------------------------------------------------

export interface PgConnectOptions {
  /** Host name or address; undefined = the local Unix socket. */
  host?: string;
  port: number;
  user: string;
  db: string;
  /** The operating-system user running the client (for peer authentication). */
  osUser: string;
  app: string;
  /** Supplies the password when the server asks (from ~/.pgpass or a prompt); null = none available. */
  password: () => string | null;
}

export interface PgConnection { serverHostId: string; pid: number; user: string; db: string; ssl: boolean; local: boolean; hostLabel: string; addr: string; port: number }
export type PgConnectResult = { ok: true; conn: PgConnection } | { ok: false; message: string; code: number };

/**
 * Open a connection the way libpq does: TCP or Unix socket, SSL negotiation
 * (sslmode=prefer: try SSL, then without), pg_hba.conf, authentication, and
 * the role and database checks. Logs on the server like the postmaster does.
 */
export function pgConnect(world: World, client: Host, o: PgConnectOptions): PgConnectResult {
  const where = o.host === undefined
    ? `connection to server on socket "${SOCKET(o.port)}" failed: `
    : '';
  let server: Host;
  let ip: string;
  let clientIp: string;
  let clientPort: number | null = null;
  let label: string;
  if (o.host === undefined) {
    server = client;
    const node = client.fs[SOCKET(o.port)];
    const l = pgLoaded(client);
    if (!node || !l || l.port !== o.port) return { ok: false, code: 2, message: `${where}No such file or directory\n\tIs the server running locally and accepting connections on that socket?` };
    ip = '';
    clientIp = '[local]';
    label = '';
  } else {
    const r = resolve(world, client, o.host, {});
    if (!r.ok) return { ok: false, code: 2, message: `could not translate host name "${o.host}" to address: ${r.message}` };
    ip = r.ip;
    label = `connection to server at "${o.host}" (${ip}), port ${o.port} failed: `;
    const c = tcpConnect(world, client, ip, o.port, { timeoutMs: 130_000 });
    if (!c.ok) {
      const why = c.errno === 'ECONNREFUSED' ? 'Connection refused\n\tIs the server running on that host and accepting TCP/IP connections?' : c.errno === 'ETIMEDOUT' ? 'Connection timed out\n\tIs the server running on that host and accepting TCP/IP connections?' : c.errno === 'EHOSTUNREACH' ? 'No route to host\n\tIs the server running on that host and accepting TCP/IP connections?' : 'Network is unreachable\n\tIs the server running on that host and accepting TCP/IP connections?';
      return { ok: false, code: 2, message: `${label}${why}` };
    }
    server = c.conn.server;
    const owner = allListeners(server).find((x) => x.proto === 'tcp' && x.port === c.conn.sv.localPort)?.service;
    c.conn.send('c2s', 8, { protocol: 'PGSQL', info: 'SSLRequest', fields: [] });
    if (owner !== 'postgresql') {
      c.conn.close('server');
      return { ok: false, code: 2, message: `${label}received invalid response to SSL negotiation: H` };
    }
    clientIp = c.conn.sv.peer;
    clientPort = c.conn.sv.peerPort;
    c.conn.send('s2c', 1, { protocol: 'PGSQL', info: 'SSL response: S', fields: [] });
    c.conn.close('client');
  }
  const loaded = pgLoaded(server)!;
  const cl = cluster(server);
  const ssl = o.host !== undefined && boolOn(loaded.settings.ssl);
  const pid = allocPid(server);
  const logConn = boolOn(loaded.settings.log_connections);
  const who = { user: o.user, db: o.db };
  if (logConn) pgLog(world, server, pid, 'LOG', o.host === undefined ? 'connection received: host=[local]' : `connection received: host=${clientIp} port=${clientPort}`, { user: '[unknown]', db: '[unknown]' });
  const encLabel = (s: boolean) => (o.host === undefined ? '' : s ? ', SSL encryption' : ', no encryption');
  const fatal = (msg: string, detail: string[] = [], code = 2): PgConnectResult => {
    pgLog(world, server, pid, 'FATAL', msg, who, detail);
    return { ok: false, code, message: `${label}FATAL:  ${msg}` };
  };

  // pg_hba.conf, first with SSL (sslmode=prefer), then without if the server refused that attempt.
  const attempt = (useSsl: boolean) => matchHba(cl, loaded.hba, { local: o.host === undefined, ssl: useSsl, ip: clientIp, user: o.user, db: o.db, serverHost: server });
  const tries = ssl ? [true, false] : [false];
  const failures: string[] = [];
  let rule: HbaRule | null = null;
  let usedSsl = false;
  for (const s of tries) {
    rule = attempt(s);
    usedSsl = s;
    const hostTxt = o.host === undefined ? '"[local]"' : `"${clientIp}"`;
    if (!rule) {
      const msg = `no pg_hba.conf entry for host ${hostTxt}, user "${o.user}", database "${o.db}"${encLabel(s)}`;
      pgLog(world, server, pid, 'FATAL', msg, who);
      failures.push(`${label}FATAL:  ${msg}`);
      continue;
    }
    if (rule.method === 'reject') {
      const msg = `pg_hba.conf rejects connection for host ${hostTxt}, user "${o.user}", database "${o.db}"${encLabel(s)}`;
      pgLog(world, server, pid, 'FATAL', msg, who);
      failures.push(`${label}FATAL:  ${msg}`);
      rule = null;
      continue;
    }
    break;
  }
  if (!rule) return { ok: false, code: 2, message: failures.join('\n') };
  const matched = `Connection matched pg_hba.conf line ${rule.line}: "${rule.raw}"`;
  const role = cl.roles[o.user];

  // Authentication.
  const method = rule.method;
  if (method === 'peer') {
    if (o.osUser !== o.user) {
      pgLog(world, server, pid, 'LOG', `provided user name (${o.user}) and authenticated user name (${o.osUser}) do not match`, who);
      return fatal(`Peer authentication failed for user "${o.user}"`, [`DETAIL:  ${matched}`]);
    }
  } else if (method === 'scram-sha-256' || method === 'md5' || method === 'password') {
    const pw = o.password();
    if (pw === null) return { ok: false, code: 2, message: `${label}fe_sendauth: no password supplied` };
    let detail: string | null = null;
    if (!role) detail = `Role "${o.user}" does not exist.`;
    else if (!role.password) detail = `User "${o.user}" has no password assigned.`;
    else if (method === 'scram-sha-256' && role.hash === 'md5') detail = `User "${o.user}" does not have a valid SCRAM secret.`;
    else if (role.validUntil !== null && role.validUntil < world.clock) detail = `User "${o.user}" has an expired password.`;
    else if (role.password !== pw) detail = `Password does not match for user "${o.user}".`;
    if (detail) return fatal(`password authentication failed for user "${o.user}"`, [`DETAIL:  ${detail}`, `\t${matched}`]);
  } else if (method !== 'trust') {
    return fatal(`${method === 'ident' ? 'Ident' : method.toUpperCase()} authentication failed for user "${o.user}"`, [`DETAIL:  ${matched}`]);
  }
  if (!role) return fatal(`role "${o.user}" does not exist`);
  if (logConn) pgLog(world, server, pid, 'LOG', `connection authenticated: ${method === 'trust' ? `user="${o.user}"` : `identity="${method === 'peer' ? o.osUser : o.user}"`} method=${method} (${loaded.settings.hba_file}:${rule.line})`, who);

  // Database, LOGIN, CONNECT, limits.
  const db = cl.databases[o.db];
  if (!db) return fatal(`database "${o.db}" does not exist`);
  if (o.db === 'template0') return fatal('database "template0" is not currently accepting connections');
  if (!role.login) return fatal(`role "${o.user}" is not permitted to log in`);
  if (!role.superuser && !memberOf(cl, o.user, db.owner) && !db.connect.some((g) => g === 'PUBLIC' || memberOf(cl, o.user, g))) {
    return fatal(`permission denied for database "${o.db}"`, ['DETAIL:  User does not have CONNECT privilege.']);
  }
  const reserved = Number(loaded.settings.superuser_reserved_connections);
  if (loaded.sessions.length >= Number(loaded.settings.max_connections) - (role.superuser ? 0 : reserved)) {
    return fatal(role.superuser ? 'sorry, too many clients already' : 'remaining connection slots are reserved for non-replication superuser connections', [], 2);
  }
  if (role.connLimit >= 0 && !role.superuser && loaded.sessions.filter((s) => s.user === o.user).length >= role.connLimit) return fatal(`too many connections for role "${o.user}"`);
  if (logConn) pgLog(world, server, pid, 'LOG', `connection authorized: user=${o.user} database=${o.db} application_name=${o.app}${usedSsl ? ' SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)' : ''}`, who);
  loaded.sessions.push({ pid, user: o.user, db: o.db, client: o.host === undefined ? null : clientIp, clientPort, start: world.clock, app: o.app, state: 'idle' });
  return { ok: true, conn: { serverHostId: server.id, pid, user: o.user, db: o.db, ssl: usedSsl, local: o.host === undefined, hostLabel: o.host ?? SOCKET_DIR, addr: ip, port: o.port } };
}

/** The session ends (psql exits, pg_dump finishes). */
export function pgDisconnect(world: World, conn: PgConnection): void {
  const server = world.hosts[conn.serverHostId];
  const l = server && pgLoaded(server);
  if (!l) return;
  const s = l.sessions.find((x) => x.pid === conn.pid);
  if (!s) return;
  l.sessions = l.sessions.filter((x) => x !== s);
  if (boolOn(l.settings.log_disconnections)) {
    const secs = (world.clock - s.start) / 1000;
    pgLog(world, server, s.pid, 'LOG', `disconnection: session time: ${Math.floor(secs / 3600)}:${String(Math.floor(secs / 60) % 60).padStart(2, '0')}:${(secs % 60).toFixed(3).padStart(6, '0')} user=${s.user} database=${s.db} host=${s.client ?? '[local]'}${s.clientPort ? ` port=${s.clientPort}` : ''}`, { user: s.user, db: s.db });
  }
}

/** Is this connection's backend still alive (the server was not restarted, the session not terminated)? */
export function pgAlive(world: World, conn: PgConnection): boolean {
  const server = world.hosts[conn.serverHostId];
  return !!server && !!pgLoaded(server)?.sessions.some((s) => s.pid === conn.pid);
}
