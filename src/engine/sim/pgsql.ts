// SQL for the simulated PostgreSQL: the statements a DBA and an application
// use (roles, databases, privileges, tables and rows, settings, sessions),
// with PostgreSQL's privilege checks and error texts, a few system views
// (pg_stat_activity, pg_roles, pg_authid, pg_database, pg_settings,
// pg_hba_file_rules, pg_tables), psql's aligned output, and pg_dump /
// pg_restore archives that are replayed through the same SQL path.

import { readFile, writeFile } from '../fs';
import type { Host, World } from '../types';
import { base64Decode, base64Encode, utf8 } from '../util/sha256';
import {
  ALL_TABLE_PRIVS, AUTO_CONF, type Cell, cluster, isSuper, loadSettings, memberOf, newRole, parseHba, PG_FULL, PG_BUILD, pgLoaded, pgLog, pgReload, pgTime,
  type PgCluster, type PgColumn, type PgDatabase, type PgRole, type PgTable, PRIV_LETTERS, SETTINGS, storedHash, tablePriv,
} from './postgres';

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

export type SqlResult =
  | { kind: 'rows'; columns: string[]; align: ('l' | 'r')[]; rows: string[][]; notices?: string[] }
  | { kind: 'tag'; tag: string; notices?: string[] }
  | { kind: 'error'; message: string; detail?: string; hint?: string; position?: number; notices?: string[] }
  | { kind: 'copy'; table: string; columns: string[] };

export interface SqlSession {
  world: World;
  server: Host;
  user: string;
  db: string;
  pid: number;
  /** Session-level SET values (password_encryption …). */
  settings: Record<string, string>;
}

class SqlError extends Error {
  constructor(message: string, public pos?: number, public detail?: string, public hint?: string) { super(message); }
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

interface Tok { t: 'id' | 'qid' | 'str' | 'num' | 'op' | 'end'; v: string; pos: number }

function tokenize(sql: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  while (i < sql.length) {
    const ch = sql[i];
    if (/\s/.test(ch)) { i++; continue; }
    if (ch === '-' && sql[i + 1] === '-') { while (i < sql.length && sql[i] !== '\n') i++; continue; }
    if (ch === "'" || ((ch === 'E' || ch === 'e') && sql[i + 1] === "'")) {
      const start = i;
      if (ch !== "'") i++;
      let s = '';
      i++;
      for (;;) {
        if (i >= sql.length) throw new SqlError('unterminated quoted string at or near "' + sql.slice(start) + '"', start);
        if (sql[i] === "'" && sql[i + 1] === "'") { s += "'"; i += 2; continue; }
        if (sql[i] === "'") { i++; break; }
        s += sql[i++];
      }
      out.push({ t: 'str', v: s, pos: start });
      continue;
    }
    if (ch === '"') {
      const start = i;
      const end = sql.indexOf('"', i + 1);
      if (end < 0) throw new SqlError('unterminated quoted identifier at or near "' + sql.slice(start) + '"', start);
      out.push({ t: 'qid', v: sql.slice(i + 1, end), pos: start });
      i = end + 1;
      continue;
    }
    if (/\d/.test(ch)) {
      const m = /^\d+(\.\d+)?/.exec(sql.slice(i))!;
      out.push({ t: 'num', v: m[0], pos: i });
      i += m[0].length;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      const m = /^[A-Za-z_][\w$]*/.exec(sql.slice(i))!;
      out.push({ t: 'id', v: m[0], pos: i });
      i += m[0].length;
      continue;
    }
    const two = sql.slice(i, i + 2);
    if (['<>', '!=', '<=', '>=', '::'].includes(two)) { out.push({ t: 'op', v: two, pos: i }); i += 2; continue; }
    if ('(),;*=<>.+-/%'.includes(ch)) { out.push({ t: 'op', v: ch, pos: i }); i++; continue; }
    throw new SqlError(`syntax error at or near "${ch}"`, i);
  }
  out.push({ t: 'end', v: '', pos: sql.length });
  return out;
}

/** Index of the last semicolon outside quotes and -- comments (-1: no complete statement yet). */
export function lastStatementEnd(sql: string): number {
  let end = -1;
  let q: string | null = null;
  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];
    if (q) { if (ch === q) q = null; continue; }
    if (ch === '-' && sql[i + 1] === '-') { const nl = sql.indexOf('\n', i); i = nl < 0 ? sql.length : nl; continue; }
    if (ch === "'" || ch === '"') q = ch;
    else if (ch === ';') end = i;
  }
  return end;
}

class Parser {
  i = 0;
  constructor(public toks: Tok[]) {}
  get cur() { return this.toks[this.i]; }
  peek(n = 0) { return this.toks[this.i + n]; }
  isKw(...kws: string[]) { return this.cur.t === 'id' && kws.includes(this.cur.v.toUpperCase()); }
  isOp(v: string) { return this.cur.t === 'op' && this.cur.v === v; }
  next() { return this.toks[this.i++]; }
  syntax(): never {
    const c = this.cur;
    throw new SqlError(c.t === 'end' ? 'syntax error at end of input' : `syntax error at or near "${c.t === 'str' ? `'${c.v}'` : c.v}"`, c.pos);
  }
  kw(...kws: string[]) { if (!this.isKw(...kws)) this.syntax(); return this.next().v.toUpperCase(); }
  optKw(...kws: string[]) { if (this.isKw(...kws)) { this.next(); return true; } return false; }
  op(v: string) { if (!this.isOp(v)) this.syntax(); this.next(); }
  optOp(v: string) { if (this.isOp(v)) { this.next(); return true; } return false; }
  /** An identifier: lower-cased unless quoted. Returns the name and its position. */
  ident(): { name: string; pos: number } {
    const c = this.cur;
    if (c.t === 'qid') { this.next(); return { name: c.v, pos: c.pos }; }
    if (c.t === 'id') { this.next(); return { name: c.v.toLowerCase(), pos: c.pos }; }
    return this.syntax();
  }
  /** A possibly schema-qualified table name (only schema public exists). */
  tableName(): { name: string; pos: number; schema?: string } {
    const a = this.ident();
    if (this.optOp('.')) { const b = this.ident(); return { name: b.name, pos: a.pos, schema: a.name }; }
    return a;
  }
  str(): string { if (this.cur.t !== 'str') this.syntax(); return this.next().v; }
  end() { this.optOp(';'); if (this.cur.t !== 'end') this.syntax(); }
}

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

type Expr =
  | { k: 'lit'; v: Cell }
  | { k: 'col'; name: string; pos: number }
  | { k: 'star' }
  | { k: 'fn'; name: string; args: Expr[]; star?: boolean; pos: number }
  | { k: 'bin'; op: string; l: Expr; r: Expr }
  | { k: 'not'; e: Expr }
  | { k: 'isnull'; e: Expr; not: boolean };

const AGG = new Set(['count', 'sum', 'min', 'max', 'avg']);
const NOARG_FNS = new Set(['current_user', 'session_user', 'user', 'current_date', 'current_timestamp', 'current_role']);

function parseExpr(p: Parser): Expr { return parseOr(p); }
function parseOr(p: Parser): Expr {
  let l = parseAnd(p);
  while (p.optKw('OR')) l = { k: 'bin', op: 'OR', l, r: parseAnd(p) };
  return l;
}
function parseAnd(p: Parser): Expr {
  let l = parseNot(p);
  while (p.optKw('AND')) l = { k: 'bin', op: 'AND', l, r: parseNot(p) };
  return l;
}
function parseNot(p: Parser): Expr {
  if (p.optKw('NOT')) return { k: 'not', e: parseNot(p) };
  return parseCmp(p);
}
function parseCmp(p: Parser): Expr {
  const l = parseAdd(p);
  if (p.isKw('IS')) {
    p.next();
    const not = p.optKw('NOT');
    p.kw('NULL');
    return { k: 'isnull', e: l, not };
  }
  if (p.isKw('LIKE', 'ILIKE')) { const op = p.next().v.toUpperCase(); return { k: 'bin', op, l, r: parseAdd(p) }; }
  if (p.cur.t === 'op' && ['=', '<>', '!=', '<', '>', '<=', '>='].includes(p.cur.v)) {
    const op = p.next().v;
    return { k: 'bin', op: op === '!=' ? '<>' : op, l, r: parseAdd(p) };
  }
  return l;
}
function parseAdd(p: Parser): Expr {
  let l = parsePrimary(p);
  while (p.cur.t === 'op' && ['+', '-', '*', '/'].includes(p.cur.v)) {
    const op = p.next().v;
    l = { k: 'bin', op, l, r: parsePrimary(p) };
  }
  return l;
}
function parsePrimary(p: Parser): Expr {
  const c = p.cur;
  let e: Expr;
  if (c.t === 'str') { p.next(); e = { k: 'lit', v: c.v }; }
  else if (c.t === 'num') { p.next(); e = { k: 'lit', v: Number(c.v) }; }
  else if (p.isOp('(')) { p.next(); e = parseExpr(p); p.op(')'); }
  else if (p.isOp('-') && p.peek(1).t === 'num') { p.next(); e = { k: 'lit', v: -Number(p.next().v) }; }
  else if (c.t === 'id' && /^(NULL|TRUE|FALSE)$/i.test(c.v)) { p.next(); e = { k: 'lit', v: c.v.toUpperCase() === 'NULL' ? null : c.v.toUpperCase() === 'TRUE' }; }
  else if (c.t === 'id' || c.t === 'qid') {
    const id = p.ident();
    if (p.isOp('(')) {
      p.next();
      const args: Expr[] = [];
      let star = false;
      if (p.isOp('*')) { p.next(); star = true; } else if (!p.isOp(')')) {
        do args.push(parseExpr(p)); while (p.optOp(','));
      }
      p.op(')');
      e = { k: 'fn', name: id.name, args, star, pos: id.pos };
    } else if (c.t === 'id' && NOARG_FNS.has(id.name)) e = { k: 'fn', name: id.name, args: [], pos: id.pos };
    else if (p.isOp('.')) { p.next(); const col = p.ident(); e = { k: 'col', name: col.name, pos: col.pos }; }
    else e = { k: 'col', name: id.name, pos: id.pos };
  } else return p.syntax();
  // Casts are accepted and ignored: 'x'::text.
  while (p.optOp('::')) p.ident();
  return e;
}

interface Row { [col: string]: Cell }
interface EvalCtx { s: SqlSession; row?: Row; cols?: Set<string> }

function truthy(v: Cell): boolean { return v === true || v === 't'; }
function cmp(a: Cell, b: Cell): number {
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  if (typeof a === 'number' && typeof b === 'string' && /^-?\d+(\.\d+)?$/.test(b)) return a - Number(b);
  if (typeof b === 'number' && typeof a === 'string' && /^-?\d+(\.\d+)?$/.test(a)) return Number(a) - b;
  return String(a).localeCompare(String(b));
}

function evalExpr(e: Expr, x: EvalCtx): Cell {
  switch (e.k) {
    case 'lit': return e.v;
    case 'star': return null;
    case 'col':
      if (!x.row || !(e.name in x.row)) throw new SqlError(`column "${e.name}" does not exist`, e.pos);
      return x.row[e.name];
    case 'not': { const v = evalExpr(e.e, x); return v === null ? null : !truthy(v); }
    case 'isnull': { const v = evalExpr(e.e, x); return e.not ? v !== null : v === null; }
    case 'bin': {
      const l = evalExpr(e.l, x);
      if (e.op === 'AND') return truthy(l) && truthy(evalExpr(e.r, x));
      if (e.op === 'OR') return truthy(l) || truthy(evalExpr(e.r, x));
      const r = evalExpr(e.r, x);
      if (l === null || r === null) return null;
      switch (e.op) {
        case '=': return cmp(l, r) === 0;
        case '<>': return cmp(l, r) !== 0;
        case '<': return cmp(l, r) < 0;
        case '>': return cmp(l, r) > 0;
        case '<=': return cmp(l, r) <= 0;
        case '>=': return cmp(l, r) >= 0;
        case 'LIKE': case 'ILIKE': {
          const re = new RegExp('^' + String(r).replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/%/g, '.*').replace(/_/g, '.') + '$', e.op === 'ILIKE' ? 'i' : '');
          return re.test(String(l));
        }
        case '+': return Number(l) + Number(r);
        case '-': return Number(l) - Number(r);
        case '*': return Number(l) * Number(r);
        case '/': return Number(r) === 0 ? (() => { throw new SqlError('division by zero'); })() : Math.trunc(Number(l) / Number(r));
      }
      return null;
    }
    case 'fn': return callFn(e, x);
  }
}

function callFn(e: Extract<Expr, { k: 'fn' }>, x: EvalCtx): Cell {
  const s = x.s;
  const arg = (i: number) => evalExpr(e.args[i], x);
  switch (e.name) {
    case 'version': return PG_BUILD;
    case 'current_user': case 'session_user': case 'user': case 'current_role': return s.user;
    case 'current_database': return s.db;
    case 'now': case 'current_timestamp': return `${pgTime(s.world.clock)}+00`.replace(' UTC', '');
    case 'current_date': return pgTime(s.world.clock).slice(0, 10);
    case 'pg_backend_pid': return s.pid;
    case 'inet_server_addr': return null;
    case 'lower': return arg(0) === null ? null : String(arg(0)).toLowerCase();
    case 'upper': return arg(0) === null ? null : String(arg(0)).toUpperCase();
    case 'length': return arg(0) === null ? null : String(arg(0)).length;
    case 'coalesce': { for (let i = 0; i < e.args.length; i++) { const v = arg(i); if (v !== null) return v; } return null; }
    case 'pg_reload_conf': {
      if (!isSuper(cluster(s.server), s.user)) throw new SqlError('permission denied for function pg_reload_conf');
      const rt = s.server.services.postgresql;
      pgReload(s.world, s.server, rt);
      return true;
    }
    case 'pg_terminate_backend': case 'pg_cancel_backend': {
      const target = Number(arg(0));
      const l = pgLoaded(s.server)!;
      const sess = l.sessions.find((x) => x.pid === target);
      if (!sess) { s.settings.__warnings = `${s.settings.__warnings ?? ''}WARNING:  PID ${target} is not a PostgreSQL backend process\n`; return false; }
      const c = cluster(s.server);
      if (!isSuper(c, s.user) && !memberOf(c, s.user, sess.user) && !memberOf(c, s.user, 'pg_signal_backend')) throw new SqlError(`permission denied to ${e.name === 'pg_terminate_backend' ? 'terminate' : 'cancel'} process`, undefined, `Only roles with privileges of the role whose process is being ${e.name === 'pg_terminate_backend' ? 'terminated' : 'canceled'} or with privileges of the "pg_signal_backend" role may ${e.name === 'pg_terminate_backend' ? 'terminate' : 'cancel'} this process.`);
      if (e.name === 'pg_terminate_backend') {
        l.sessions = l.sessions.filter((x) => x !== sess);
        pgLog(s.world, s.server, sess.pid, 'FATAL', 'terminating connection due to administrator command', { user: sess.user, db: sess.db });
      }
      return true;
    }
    case 'pg_size_pretty': return `${Math.max(8, Number(arg(0)) / 1024).toFixed(0)} kB`;
    case 'pg_database_size': { const d = cluster(s.server).databases[String(arg(0))]; if (!d) throw new SqlError(`database "${arg(0)}" does not exist`); return 7_500_000 + Object.values(d.tables).reduce((n, t) => n + 8192 + t.rows.length * 120, 0); }
    default:
      if (AGG.has(e.name)) throw new SqlError(`aggregate functions are not allowed here`, e.pos);
      throw new SqlError(`function ${e.name}(${e.args.map(() => 'unknown').join(', ')}) does not exist`, e.pos, undefined, 'No function matches the given name and argument types. You might need to add explicit type casts.');
  }
}

function exprName(e: Expr): string {
  if (e.k === 'col') return e.name;
  if (e.k === 'fn') return e.name;
  return '?column?';
}
const hasAgg = (e: Expr): boolean => (e.k === 'fn' && AGG.has(e.name)) || (e.k === 'bin' && (hasAgg(e.l) || hasAgg(e.r))) || (e.k === 'not' && hasAgg(e.e));

function evalAgg(e: Expr, rows: Row[], x: EvalCtx): Cell {
  if (e.k === 'fn' && AGG.has(e.name)) {
    if (e.name === 'count') return e.star ? rows.length : rows.filter((r) => evalExpr(e.args[0], { ...x, row: r }) !== null).length;
    const vals = rows.map((r) => evalExpr(e.args[0], { ...x, row: r })).filter((v): v is number | string | boolean => v !== null);
    if (!vals.length) return null;
    if (e.name === 'sum') return vals.reduce((a: number, b) => a + Number(b), 0);
    if (e.name === 'avg') return Number((vals.reduce((a: number, b) => a + Number(b), 0) / vals.length).toFixed(2));
    return vals.reduce((a, b) => ((e.name === 'min' ? cmp(b, a) < 0 : cmp(b, a) > 0) ? b : a));
  }
  return evalExpr(e, { ...x, row: rows[0] });
}

// ---------------------------------------------------------------------------
// Catalog views
// ---------------------------------------------------------------------------

interface Source { columns: string[]; rows: Row[]; table?: PgTable }

const b = (v: boolean) => v;

function catalog(s: SqlSession, name: string, pos: number): Source | null {
  const c = cluster(s.server);
  const l = pgLoaded(s.server)!;
  const sup = isSuper(c, s.user);
  const visibleRoles = Object.values(c.roles);
  switch (name) {
    case 'pg_stat_activity':
      return {
        columns: ['datname', 'pid', 'usename', 'application_name', 'client_addr', 'client_port', 'backend_start', 'state', 'query'],
        rows: l.sessions.map((x) => ({
          datname: x.db, pid: x.pid, usename: x.user, application_name: x.app, client_addr: x.client, client_port: x.clientPort ?? -1,
          backend_start: `${pgTime(x.start).replace(' UTC', '')}+00`, state: x.pid === s.pid ? 'active' : x.state,
          query: sup || memberOf(c, s.user, x.user) || memberOf(c, s.user, 'pg_read_all_stats') ? (x.pid === s.pid ? '(this query)' : '') : '<insufficient privilege>',
        })),
      };
    case 'pg_roles': case 'pg_user':
      return {
        columns: ['rolname', 'rolsuper', 'rolcreaterole', 'rolcreatedb', 'rolcanlogin', 'rolreplication', 'rolconnlimit', 'rolpassword', 'rolvaliduntil'],
        rows: visibleRoles.filter((r) => name === 'pg_roles' || r.login).map((r) => ({ rolname: r.name, rolsuper: b(r.superuser), rolcreaterole: b(r.createrole), rolcreatedb: b(r.createdb), rolcanlogin: b(r.login), rolreplication: b(r.replication), rolconnlimit: r.connLimit, rolpassword: '********', rolvaliduntil: r.validUntil === null ? null : `${pgTime(r.validUntil).replace(' UTC', '')}+00` })),
      };
    case 'pg_authid':
      if (!sup) throw new SqlError('permission denied for table pg_authid', pos);
      return { columns: ['rolname', 'rolsuper', 'rolcanlogin', 'rolpassword'], rows: visibleRoles.map((r) => ({ rolname: r.name, rolsuper: b(r.superuser), rolcanlogin: b(r.login), rolpassword: storedHash(r) })) };
    case 'pg_database':
      return { columns: ['datname', 'datdba', 'encoding', 'datallowconn'], rows: Object.values(c.databases).map((d) => ({ datname: d.name, datdba: d.owner, encoding: 'UTF8', datallowconn: d.name !== 'template0' })) };
    case 'pg_tables':
      return { columns: ['schemaname', 'tablename', 'tableowner'], rows: Object.values(c.databases[s.db].tables).map((t) => ({ schemaname: 'public', tablename: t.name, tableowner: t.owner })) };
    case 'pg_settings': {
      const st = loadSettings(s.server);
      return {
        columns: ['name', 'setting', 'context', 'source', 'sourcefile', 'sourceline', 'pending_restart'],
        rows: Object.entries(SETTINGS).filter(([k]) => k !== 'include_dir').map(([k, d]) => ({
          name: k, setting: s.settings[k] ?? l.settings[k], context: d.ctx, source: st.sources[k] ? 'configuration file' : 'default',
          sourcefile: sup ? st.sources[k]?.file ?? null : null, sourceline: sup ? st.sources[k]?.line ?? null : null,
          pending_restart: d.ctx === 'postmaster' && st.values[k] !== l.settings[k],
        })),
      };
    }
    case 'pg_hba_file_rules': {
      if (!sup) throw new SqlError('permission denied for view pg_hba_file_rules', pos);
      const text = readFile(s.server, l.settings.hba_file) ?? '';
      const p = parseHba(text, l.settings.hba_file);
      const rows: Row[] = p.rules.map((r) => ({ line_number: r.line, type: r.type, database: `{${r.databases.join(',')}}`, user_name: `{${r.users.join(',')}}`, address: r.address?.split('/')[0] ?? null, netmask: r.address?.includes('/') ? maskOf(r.address) : null, auth_method: r.method, options: null, error: null }));
      for (let i = 0; i < p.errors.length; i += 2) {
        const line = Number(/line (\d+)/.exec(p.errors[i + 1] ?? '')?.[1] ?? 0);
        rows.push({ line_number: line, type: null, database: null, user_name: null, address: null, netmask: null, auth_method: null, options: null, error: p.errors[i].replace(/^LOG:\s+/, '') });
      }
      rows.sort((a, z) => Number(a.line_number) - Number(z.line_number));
      return { columns: ['line_number', 'type', 'database', 'user_name', 'address', 'netmask', 'auth_method', 'options', 'error'], rows };
    }
  }
  return null;
}

function maskOf(cidr: string): string {
  const [a, bits] = cidr.split('/');
  if (a.includes(':')) return `ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff`.slice(0, Math.ceil(Number(bits) / 16) * 5 - 1) + (Number(bits) < 128 ? '::' : '');
  const n = Number(bits) === 0 ? 0 : (0xffffffff << (32 - Number(bits))) >>> 0;
  return [24, 16, 8, 0].map((sh) => (n >>> sh) & 255).join('.');
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function db(s: SqlSession): PgDatabase { return cluster(s.server).databases[s.db]; }
function needTable(s: SqlSession, name: string, pos: number): PgTable {
  const t = db(s).tables[name];
  if (!t) throw new SqlError(`relation "${name}" does not exist`, pos);
  return t;
}
function needRole(c: PgCluster, name: string, pos?: number): PgRole {
  const r = c.roles[name];
  if (!r) throw new SqlError(`role "${name}" does not exist`, pos);
  return r;
}
function checkPriv(s: SqlSession, t: PgTable, p: string): void {
  if (!tablePriv(cluster(s.server), t, s.user, p)) throw new SqlError(`permission denied for table ${t.name}`);
}
const isOwnerOrSuper = (s: SqlSession, owner: string) => isSuper(cluster(s.server), s.user) || memberOf(cluster(s.server), s.user, owner);

function coerce(col: PgColumn, v: Cell, table: string): Cell {
  if (v === null) return null;
  const t = col.type.toLowerCase();
  if (/^(int|integer|bigint|smallint|serial|bigserial|int4|int8)/.test(t)) {
    if (typeof v === 'number' && Number.isInteger(v)) return v;
    if (typeof v === 'string' && /^\s*-?\d+\s*$/.test(v)) return Number(v);
    throw new SqlError(`invalid input syntax for type integer: "${v}"`);
  }
  if (/^(numeric|decimal|real|double|float)/.test(t)) {
    if (typeof v === 'number') return v;
    if (typeof v === 'string' && /^\s*-?\d+(\.\d+)?\s*$/.test(v)) return Number(v);
    throw new SqlError(`invalid input syntax for type numeric: "${v}"`);
  }
  if (/^bool/.test(t)) {
    if (typeof v === 'boolean') return v;
    if (/^(t|true|yes|on|1)$/i.test(String(v))) return true;
    if (/^(f|false|no|off|0)$/i.test(String(v))) return false;
    throw new SqlError(`invalid input syntax for type boolean: "${v}"`);
  }
  void table;
  return typeof v === 'boolean' ? (v ? 'true' : 'false') : String(v);
}

function insertRow(s: SqlSession, t: PgTable, cols: PgColumn[], vals: Cell[]): void {
  const row: Cell[] = t.columns.map((c) => {
    const i = cols.indexOf(c);
    if (i >= 0) return coerce(c, vals[i], t.name);
    if (c.serial) return t.nextSerial++;
    return null;
  });
  t.columns.forEach((c, i) => {
    if (row[i] === null && (c.notNull || c.primaryKey)) throw new SqlError(`null value in column "${c.name}" of relation "${t.name}" violates not-null constraint`, undefined, `Failing row contains (${row.map((v) => (v === null ? 'null' : String(v))).join(', ')}).`);
    if (c.primaryKey && t.rows.some((r) => r[i] === row[i])) throw new SqlError(`duplicate key value violates unique constraint "${t.name}_pkey"`, undefined, `Key (${c.name})=(${row[i]}) already exists.`);
    if (c.serial && typeof row[i] === 'number' && (row[i] as number) >= t.nextSerial) t.nextSerial = (row[i] as number) + 1;
  });
  void s;
  t.rows.push(row);
}

const rowObj = (t: PgTable, r: Cell[]): Row => Object.fromEntries(t.columns.map((c, i) => [c.name, r[i]]));

function parsePrivs(p: Parser, objectKind: 'table' | 'database' | 'schema'): { privs: string[]; pos: number } {
  const pos = p.cur.pos;
  if (p.optKw('ALL')) { p.optKw('PRIVILEGES'); return { privs: ['ALL'], pos }; }
  const privs: string[] = [];
  do {
    const w = p.kw('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'CONNECT', 'TEMPORARY', 'TEMP', 'CREATE', 'USAGE');
    const valid = objectKind === 'table' ? w in PRIV_LETTERS : objectKind === 'database' ? ['CONNECT', 'TEMPORARY', 'TEMP', 'CREATE'].includes(w) : ['USAGE', 'CREATE'].includes(w);
    if (!valid) throw new SqlError(`invalid privilege type ${w} for ${objectKind === 'table' ? 'relation' : objectKind}`, pos);
    privs.push(w);
  } while (p.optOp(','));
  return { privs, pos };
}

function grantees(p: Parser, c: PgCluster): string[] {
  const out: string[] = [];
  do {
    if (p.isKw('PUBLIC')) { p.next(); out.push('PUBLIC'); continue; }
    const g = p.ident();
    needRole(c, g.name, g.pos);
    out.push(g.name);
  } while (p.optOp(','));
  return out;
}

const tableLetters = (privs: string[]) => (privs[0] === 'ALL' ? ALL_TABLE_PRIVS : privs.map((x) => PRIV_LETTERS[x]).join(''));

/** Role options of CREATE/ALTER ROLE. */
function roleOptions(p: Parser, s: SqlSession, r: PgRole, creating: boolean): void {
  const c = cluster(s.server);
  p.optKw('WITH');
  while (p.cur.t !== 'end' && !p.isOp(';')) {
    const w = p.kw('LOGIN', 'NOLOGIN', 'SUPERUSER', 'NOSUPERUSER', 'CREATEDB', 'NOCREATEDB', 'CREATEROLE', 'NOCREATEROLE', 'REPLICATION', 'NOREPLICATION', 'INHERIT', 'NOINHERIT', 'BYPASSRLS', 'NOBYPASSRLS', 'PASSWORD', 'ENCRYPTED', 'CONNECTION', 'VALID', 'IN', 'ROLE');
    switch (w) {
      case 'LOGIN': r.login = true; break;
      case 'NOLOGIN': r.login = false; break;
      case 'SUPERUSER': case 'NOSUPERUSER':
        if (!isSuper(c, s.user)) throw new SqlError(creating ? 'must be superuser to create superusers' : 'must be superuser to alter superuser roles or change superuser attribute');
        r.superuser = w === 'SUPERUSER';
        break;
      case 'CREATEDB': r.createdb = true; break;
      case 'NOCREATEDB': r.createdb = false; break;
      case 'CREATEROLE': r.createrole = true; break;
      case 'NOCREATEROLE': r.createrole = false; break;
      case 'REPLICATION': case 'NOREPLICATION':
        if (!isSuper(c, s.user)) throw new SqlError('must be superuser to create replication users');
        r.replication = w === 'REPLICATION';
        break;
      case 'INHERIT': case 'NOINHERIT': case 'BYPASSRLS': case 'NOBYPASSRLS': break;
      case 'ENCRYPTED': p.kw('PASSWORD'); setPassword(p, s, r); break;
      case 'PASSWORD': setPassword(p, s, r); break;
      case 'CONNECTION': p.kw('LIMIT'); { const neg = p.optOp('-'); const n = Number(p.next().v); r.connLimit = neg ? -n : n; } break;
      case 'VALID': p.kw('UNTIL'); { const v = p.str(); r.validUntil = /infinity/i.test(v) ? null : Date.parse(v.replace(' ', 'T') + (/[Z+]/.test(v) ? '' : 'Z')); } break;
      case 'IN': p.kw('ROLE'); for (const g of grantees(p, c)) if (!r.memberOf.includes(g)) r.memberOf.push(g); break;
      case 'ROLE': grantees(p, c); break;
    }
  }
}

function setPassword(p: Parser, s: SqlSession, r: PgRole): void {
  if (p.isKw('NULL')) { p.next(); r.password = null; r.hash = null; return; }
  const v = p.str();
  const c = cluster(s.server);
  // A pre-hashed value (pg_dumpall output) is stored as it is.
  const known = c.hashes?.[v];
  if (/^md5[0-9a-f]{32}$/.test(v) || /^SCRAM-SHA-256\$/.test(v)) {
    r.password = known ?? null;
    r.hash = v.startsWith('md5') ? 'md5' : 'scram';
    if (!known) r.password = `\u0000unknown:${v}`;
    return;
  }
  r.password = v;
  const enc = s.settings.password_encryption ?? pgLoaded(s.server)!.settings.password_encryption;
  r.hash = enc === 'md5' ? 'md5' : 'scram';
  const h = storedHash(r);
  if (h) (c.hashes ??= {})[h] = v;
}

// ---------------------------------------------------------------------------
// Statements
// ---------------------------------------------------------------------------

function execOne(s: SqlSession, sql: string): SqlResult {
  const notices: string[] = [];
  const p = new Parser(tokenize(sql));
  const c = cluster(s.server);
  const first = p.cur;
  if (first.t !== 'id') return p.syntax();
  const verb = first.v.toUpperCase();
  const tag = (t: string): SqlResult => ({ kind: 'tag', tag: t, notices });

  switch (verb) {
    case 'SELECT': case 'TABLE': return select(s, p);
    case 'SHOW': {
      p.next();
      const n = p.ident();
      p.end();
      const l = pgLoaded(s.server)!;
      if (!(n.name in SETTINGS) || n.name === 'include_dir') throw new SqlError(`unrecognized configuration parameter "${n.name}"`);
      if (['data_directory', 'hba_file', 'ident_file', 'config_file'].includes(n.name) && !isSuper(c, s.user) && !memberOf(c, s.user, 'pg_read_all_settings')) throw new SqlError(`must be superuser or have privileges of pg_read_all_settings to examine "${n.name}"`);
      return { kind: 'rows', columns: [n.name], align: ['l'], rows: [[s.settings[n.name] ?? l.settings[n.name]]] };
    }
    case 'SET': {
      p.next();
      p.optKw('SESSION', 'LOCAL');
      const n = p.ident();
      if (!p.optOp('=')) p.kw('TO');
      const v = p.cur.t === 'str' ? p.str() : p.next().v;
      if (!(n.name in SETTINGS)) throw new SqlError(`unrecognized configuration parameter "${n.name}"`);
      if (SETTINGS[n.name].ctx !== 'user') throw new SqlError(`parameter "${n.name}" cannot be changed now`);
      s.settings[n.name] = v;
      return tag('SET');
    }
    case 'RESET': { p.next(); const n = p.ident(); delete s.settings[n.name]; return tag('RESET'); }
    case 'BEGIN': case 'START': return tag('BEGIN');
    case 'COMMIT': case 'END': return tag('COMMIT');
    case 'ROLLBACK': case 'ABORT': return { kind: 'tag', tag: 'ROLLBACK', notices: ['WARNING:  there is no transaction in progress'] };
    case 'CHECKPOINT':
      if (!isSuper(c, s.user) && !memberOf(c, s.user, 'pg_checkpoint')) throw new SqlError('must be superuser or have privileges of pg_checkpoint to do CHECKPOINT');
      return tag('CHECKPOINT');
    case 'VACUUM': case 'ANALYZE': return tag(verb);
    case 'INSERT': {
      p.next(); p.kw('INTO');
      const tn = p.tableName();
      const t = needTable(s, tn.name, tn.pos);
      let cols = t.columns;
      if (p.optOp('(')) {
        cols = [];
        do {
          const cn = p.ident();
          const col = t.columns.find((x) => x.name === cn.name);
          if (!col) throw new SqlError(`column "${cn.name}" of relation "${t.name}" does not exist`, cn.pos);
          cols.push(col);
        } while (p.optOp(','));
        p.op(')');
      }
      checkPriv(s, t, 'a');
      p.kw('VALUES');
      let n = 0;
      do {
        p.op('(');
        const vals: Cell[] = [];
        do vals.push(evalExpr(parseExpr(p), { s })); while (p.optOp(','));
        p.op(')');
        if (vals.length > cols.length) throw new SqlError('INSERT has more expressions than target columns');
        insertRow(s, t, cols, vals);
        n++;
      } while (p.optOp(','));
      p.end();
      return tag(`INSERT 0 ${n}`);
    }
    case 'UPDATE': {
      p.next();
      const tn = p.tableName();
      const t = needTable(s, tn.name, tn.pos);
      p.kw('SET');
      const sets: { i: number; e: Expr }[] = [];
      do {
        const cn = p.ident();
        const i = t.columns.findIndex((x) => x.name === cn.name);
        if (i < 0) throw new SqlError(`column "${cn.name}" of relation "${t.name}" does not exist`, cn.pos);
        p.op('=');
        sets.push({ i, e: parseExpr(p) });
      } while (p.optOp(','));
      const where = p.optKw('WHERE') ? parseExpr(p) : null;
      p.end();
      checkPriv(s, t, 'w');
      if (where) checkPriv(s, t, 'r');
      let n = 0;
      for (const r of t.rows) {
        const obj = rowObj(t, r);
        if (where && !truthy(evalExpr(where, { s, row: obj }))) continue;
        for (const st of sets) r[st.i] = coerce(t.columns[st.i], evalExpr(st.e, { s, row: obj }), t.name);
        n++;
      }
      return tag(`UPDATE ${n}`);
    }
    case 'DELETE': {
      p.next(); p.kw('FROM');
      const tn = p.tableName();
      const t = needTable(s, tn.name, tn.pos);
      const where = p.optKw('WHERE') ? parseExpr(p) : null;
      p.end();
      checkPriv(s, t, 'd');
      if (where) checkPriv(s, t, 'r');
      const before = t.rows.length;
      t.rows = t.rows.filter((r) => where && !truthy(evalExpr(where, { s, row: rowObj(t, r) })));
      return tag(`DELETE ${before - t.rows.length}`);
    }
    case 'TRUNCATE': {
      p.next(); p.optKw('TABLE');
      const tn = p.tableName();
      p.end();
      const t = needTable(s, tn.name, tn.pos);
      checkPriv(s, t, 'D');
      t.rows = [];
      return tag('TRUNCATE TABLE');
    }
    case 'COPY': {
      p.next();
      const tn = p.tableName();
      const t = needTable(s, tn.name, tn.pos);
      let cols = t.columns.map((x) => x.name);
      if (p.optOp('(')) { cols = []; do cols.push(p.ident().name); while (p.optOp(',')); p.op(')'); }
      if (p.optKw('TO')) {
        p.kw('STDOUT'); p.end();
        checkPriv(s, t, 'r');
        return { kind: 'rows', columns: cols, align: cols.map(() => 'l'), rows: t.rows.map((r) => cols.map((cn) => { const v = r[t.columns.findIndex((x) => x.name === cn)]; return v === null ? '\\N' : String(v); })) };
      }
      p.kw('FROM'); p.kw('STDIN'); p.end();
      checkPriv(s, t, 'a');
      return { kind: 'copy', table: t.name, columns: cols };
    }
    case 'CREATE': {
      p.next();
      if (p.isKw('TABLE')) return createTable(s, p, notices);
      if (p.isKw('ROLE', 'USER', 'GROUP')) {
        const kind = p.next().v.toUpperCase();
        const n = p.ident();
        if (!isSuper(c, s.user) && !c.roles[s.user]?.createrole) throw new SqlError('permission denied to create role');
        if (c.roles[n.name]) throw new SqlError(`role "${n.name}" already exists`);
        if (n.name.startsWith('pg_')) throw new SqlError(`role name "${n.name}" is reserved`, undefined, 'Role names starting with "pg_" are reserved.');
        const r = newRole(n.name, c.nextOid++, { login: kind === 'USER' });
        roleOptions(p, s, r, true);
        c.roles[n.name] = r;
        return tag('CREATE ROLE');
      }
      if (p.isKw('DATABASE')) {
        p.next();
        const n = p.ident();
        if (!isSuper(c, s.user) && !c.roles[s.user]?.createdb) throw new SqlError('permission denied to create database');
        if (c.databases[n.name]) throw new SqlError(`database "${n.name}" already exists`);
        let owner = s.user;
        p.optKw('WITH');
        while (p.cur.t !== 'end' && !p.isOp(';')) {
          const w = p.kw('OWNER', 'ENCODING', 'TEMPLATE', 'LC_COLLATE', 'LC_CTYPE', 'LOCALE', 'CONNECTION', 'TABLESPACE');
          p.optOp('=');
          if (w === 'CONNECTION') { p.kw('LIMIT'); p.next(); continue; }
          const v = p.cur.t === 'str' ? p.str() : p.ident().name;
          if (w === 'OWNER') {
            needRole(c, v);
            if (!isSuper(c, s.user) && !memberOf(c, s.user, v)) throw new SqlError(`must be member of role "${v}"`);
            owner = v;
          }
        }
        const sessions = pgLoaded(s.server)!.sessions.filter((x) => x.db === 'template1' && x.pid !== s.pid);
        if (sessions.length) throw new SqlError('source database "template1" is being accessed by other users', undefined, `There ${sessions.length === 1 ? 'is 1 other session' : `are ${sessions.length} other sessions`} using the database.`);
        c.databases[n.name] = { name: n.name, oid: c.nextOid++, owner, connect: ['PUBLIC'], schemaCreate: [], tables: {}, defaultAcl: [] };
        return tag('CREATE DATABASE');
      }
      if (p.isKw('SCHEMA', 'INDEX', 'UNIQUE', 'VIEW', 'SEQUENCE', 'EXTENSION', 'FUNCTION')) throw new SqlError(`CREATE ${p.cur.v.toUpperCase()} is not simulated in this lab (only schema public exists)`);
      return p.syntax();
    }
    case 'DROP': {
      p.next();
      if (p.isKw('TABLE')) {
        p.next();
        const ifExists = p.isKw('IF') ? (p.next(), p.kw('EXISTS'), true) : false;
        const tn = p.tableName();
        p.optKw('CASCADE', 'RESTRICT');
        p.end();
        const t = db(s).tables[tn.name];
        if (!t) {
          if (ifExists) return { kind: 'tag', tag: 'DROP TABLE', notices: [`NOTICE:  table "${tn.name}" does not exist, skipping`] };
          throw new SqlError(`table "${tn.name}" does not exist`);
        }
        if (!isOwnerOrSuper(s, t.owner)) throw new SqlError(`must be owner of table ${t.name}`);
        delete db(s).tables[tn.name];
        return tag('DROP TABLE');
      }
      if (p.isKw('ROLE', 'USER', 'GROUP')) {
        p.next();
        const ifExists = p.isKw('IF') ? (p.next(), p.kw('EXISTS'), true) : false;
        const names: string[] = [];
        do names.push(p.ident().name); while (p.optOp(','));
        p.end();
        for (const n of names) {
          const r = c.roles[n];
          if (!r) {
            if (ifExists) { notices.push(`NOTICE:  role "${n}" does not exist, skipping`); continue; }
            throw new SqlError(`role "${n}" does not exist`);
          }
          if (!isSuper(c, s.user) && !c.roles[s.user]?.createrole) throw new SqlError(`permission denied to drop role`);
          if (r.superuser && !isSuper(c, s.user)) throw new SqlError('must be superuser to drop superusers');
          if (n === s.user) throw new SqlError('current user cannot be dropped');
          if (r.predefined || n === 'postgres') throw new SqlError(`cannot drop role ${n} because it is required by the database system`);
          const deps: string[] = [];
          for (const d of Object.values(c.databases)) {
            if (d.owner === n) deps.push(`owner of database ${d.name}`);
            if (d.connect.includes(n)) deps.push(`privileges for database ${d.name}`);
            if (d.name === s.db) for (const t of Object.values(d.tables)) {
              if (t.owner === n) deps.push(`owner of table ${t.name}`);
              else if (t.acl[n]) deps.push(`privileges for table ${t.name}`);
            }
          }
          if (deps.length) throw new SqlError(`role "${n}" cannot be dropped because some objects depend on it`, undefined, deps.join('\n'));
          if (pgLoaded(s.server)!.sessions.some((x) => x.user === n)) throw new SqlError(`role "${n}" is being used by other users`);
          delete c.roles[n];
          for (const other of Object.values(c.roles)) other.memberOf = other.memberOf.filter((g) => g !== n);
        }
        return { kind: 'tag', tag: 'DROP ROLE', notices };
      }
      if (p.isKw('DATABASE')) {
        p.next();
        const ifExists = p.isKw('IF') ? (p.next(), p.kw('EXISTS'), true) : false;
        const n = p.ident();
        const force = p.optKw('WITH') ? (p.op('('), p.kw('FORCE'), p.op(')'), true) : false;
        p.end();
        const d = c.databases[n.name];
        if (!d) {
          if (ifExists) return { kind: 'tag', tag: 'DROP DATABASE', notices: [`NOTICE:  database "${n.name}" does not exist, skipping`] };
          throw new SqlError(`database "${n.name}" does not exist`);
        }
        if (!isOwnerOrSuper(s, d.owner)) throw new SqlError(`must be owner of database ${d.name}`);
        if (n.name === s.db) throw new SqlError('cannot drop the currently open database');
        if (['template0', 'template1'].includes(n.name)) throw new SqlError(`cannot drop a template database`);
        const l = pgLoaded(s.server)!;
        const others = l.sessions.filter((x) => x.db === n.name);
        if (others.length && !force) throw new SqlError(`database "${n.name}" is being accessed by other users`, undefined, `There ${others.length === 1 ? 'is 1 other session' : `are ${others.length} other sessions`} using the database.`);
        l.sessions = l.sessions.filter((x) => x.db !== n.name);
        delete c.databases[n.name];
        return tag('DROP DATABASE');
      }
      return p.syntax();
    }
    case 'ALTER': {
      p.next();
      if (p.isKw('ROLE', 'USER', 'GROUP')) {
        p.next();
        const n = p.ident();
        const r = needRole(c, n.name, n.pos);
        if (p.optKw('RENAME')) {
          p.kw('TO');
          const to = p.ident().name;
          p.end();
          if (!isSuper(c, s.user) && !c.roles[s.user]?.createrole) throw new SqlError('permission denied to rename role');
          if (n.name === s.user) throw new SqlError('session user cannot be renamed');
          if (c.roles[to]) throw new SqlError(`role "${to}" already exists`);
          delete c.roles[n.name];
          r.name = to;
          r.password = r.hash === 'md5' ? null : r.password;
          c.roles[to] = r;
          return { kind: 'tag', tag: 'ALTER ROLE', notices: r.hash === 'md5' ? ['NOTICE:  MD5 password cleared because of role rename'] : [] };
        }
        const self = n.name === s.user;
        const onlyPassword = p.isKw('PASSWORD', 'ENCRYPTED') || (p.isKw('WITH') && (p.peek(1).v.toUpperCase() === 'PASSWORD' || p.peek(1).v.toUpperCase() === 'ENCRYPTED'));
        if (!isSuper(c, s.user) && !(self && onlyPassword)) {
          if (!c.roles[s.user]?.createrole) throw new SqlError('permission denied');
          if (r.superuser) throw new SqlError('must be superuser to alter superuser roles or change superuser attribute');
        }
        roleOptions(p, s, r, false);
        return tag('ALTER ROLE');
      }
      if (p.isKw('DATABASE')) {
        p.next();
        const n = p.ident();
        const d = c.databases[n.name];
        if (!d) throw new SqlError(`database "${n.name}" does not exist`);
        if (!isOwnerOrSuper(s, d.owner)) throw new SqlError(`must be owner of database ${d.name}`);
        if (p.optKw('OWNER')) {
          p.kw('TO');
          const o = p.ident();
          needRole(c, o.name, o.pos);
          if (!isSuper(c, s.user) && !memberOf(c, s.user, o.name)) throw new SqlError(`must be member of role "${o.name}"`);
          d.owner = o.name;
          p.end();
          return tag('ALTER DATABASE');
        }
        if (p.optKw('RENAME')) {
          p.kw('TO');
          const to = p.ident().name;
          p.end();
          if (n.name === s.db) throw new SqlError('current database cannot be renamed');
          if (c.databases[to]) throw new SqlError(`database "${to}" already exists`);
          delete c.databases[n.name];
          d.name = to;
          c.databases[to] = d;
          return tag('ALTER DATABASE');
        }
        return p.syntax();
      }
      if (p.isKw('TABLE')) {
        p.next();
        const tn = p.tableName();
        const t = needTable(s, tn.name, tn.pos);
        if (!isOwnerOrSuper(s, t.owner)) throw new SqlError(`must be owner of table ${t.name}`);
        if (p.optKw('OWNER')) {
          p.kw('TO');
          const o = p.ident();
          needRole(c, o.name, o.pos);
          if (!isSuper(c, s.user) && !memberOf(c, s.user, o.name)) throw new SqlError(`must be member of role "${o.name}"`);
          // The owner's implicit privileges move with it.
          if (t.acl[t.owner] === ALL_TABLE_PRIVS) { delete t.acl[t.owner]; t.acl[o.name] = ALL_TABLE_PRIVS; }
          t.owner = o.name;
          p.end();
          return tag('ALTER TABLE');
        }
        if (p.optKw('ADD')) {
          p.optKw('COLUMN');
          const cn = p.ident().name;
          if (t.columns.some((x) => x.name === cn)) throw new SqlError(`column "${cn}" of relation "${t.name}" already exists`);
          t.columns.push(columnType(p, cn));
          p.end();
          for (const r of t.rows) r.push(null);
          return tag('ALTER TABLE');
        }
        return p.syntax();
      }
      if (p.isKw('SYSTEM')) {
        p.next();
        if (!isSuper(c, s.user)) throw new SqlError('must be superuser to execute ALTER SYSTEM command');
        return alterSystem(s, p);
      }
      if (p.isKw('DEFAULT')) {
        p.next(); p.kw('PRIVILEGES');
        let owner = s.user;
        if (p.optKw('FOR')) {
          p.kw('ROLE', 'USER');
          const o = p.ident();
          needRole(c, o.name, o.pos);
          if (!isSuper(c, s.user) && !memberOf(c, s.user, o.name)) throw new SqlError('permission denied to change default privileges');
          owner = o.name;
        }
        if (p.optKw('IN')) { p.kw('SCHEMA'); p.ident(); }
        const grant = p.kw('GRANT', 'REVOKE') === 'GRANT';
        const { privs } = parsePrivs(p, 'table');
        p.kw('ON'); p.kw('TABLES');
        p.kw(grant ? 'TO' : 'FROM');
        const gs = grantees(p, c);
        p.end();
        const letters = tableLetters(privs);
        const d = db(s);
        for (const g of gs) {
          const e = d.defaultAcl.find((x) => x.owner === owner && x.grantee === g);
          if (grant) { if (e) e.privs = [...new Set(e.privs + letters)].join(''); else d.defaultAcl.push({ owner, grantee: g, privs: letters }); } else if (e) e.privs = [...e.privs].filter((x) => !letters.includes(x)).join('');
        }
        d.defaultAcl = d.defaultAcl.filter((x) => x.privs);
        return tag('ALTER DEFAULT PRIVILEGES');
      }
      return p.syntax();
    }
    case 'GRANT': case 'REVOKE': return grantRevoke(s, p, verb === 'GRANT');
    default:
      return p.syntax();
  }
}

function columnType(p: Parser, name: string): PgColumn {
  const t = p.ident();
  let type = t.name;
  if (p.isKw('PRECISION') || p.isKw('VARYING')) type += ' ' + p.next().v.toLowerCase();
  if (p.optOp('(')) { const args: string[] = []; do args.push(p.next().v); while (p.optOp(',')); p.op(')'); type += `(${args.join(',')})`; }
  const known = /^(int|integer|bigint|smallint|serial|bigserial|int4|int8|text|varchar|character|char|numeric|decimal|real|double|float|date|timestamp|timestamptz|boolean|bool|uuid|json|jsonb|bytea|inet)/.test(type);
  if (!known) throw new SqlError(`type "${type}" does not exist`, t.pos);
  const col: PgColumn = { name, type: type === 'int' || type === 'int4' ? 'integer' : type === 'bool' ? 'boolean' : type };
  if (/serial/.test(type)) { col.serial = true; col.notNull = true; col.type = type === 'bigserial' ? 'bigint' : 'integer'; }
  for (;;) {
    if (p.optKw('PRIMARY')) { p.kw('KEY'); col.primaryKey = true; col.notNull = true; continue; }
    if (p.optKw('NOT')) { p.kw('NULL'); col.notNull = true; continue; }
    if (p.optKw('NULL')) continue;
    if (p.optKw('UNIQUE')) continue;
    if (p.optKw('DEFAULT')) { parsePrimary(p); continue; }
    if (p.optKw('REFERENCES')) { p.tableName(); if (p.optOp('(')) { p.ident(); p.op(')'); } continue; }
    break;
  }
  return col;
}

function createTable(s: SqlSession, p: Parser, notices: string[]): SqlResult {
  p.kw('TABLE');
  const ifNot = p.isKw('IF') ? (p.next(), p.kw('NOT'), p.kw('EXISTS'), true) : false;
  const tn = p.tableName();
  const c = cluster(s.server);
  const d = db(s);
  if (!isSuper(c, s.user) && !memberOf(c, s.user, d.owner) && !d.schemaCreate.some((g) => g === 'PUBLIC' || memberOf(c, s.user, g))) throw new SqlError('permission denied for schema public', tn.pos);
  if (d.tables[tn.name]) {
    if (ifNot) return { kind: 'tag', tag: 'CREATE TABLE', notices: [...notices, `NOTICE:  relation "${tn.name}" already exists, skipping`] };
    throw new SqlError(`relation "${tn.name}" already exists`);
  }
  p.op('(');
  const columns: PgColumn[] = [];
  do {
    if (p.isKw('PRIMARY')) { p.next(); p.kw('KEY'); p.op('('); const k = p.ident().name; p.op(')'); const col = columns.find((x) => x.name === k); if (col) { col.primaryKey = true; col.notNull = true; } continue; }
    if (p.isKw('CONSTRAINT', 'UNIQUE', 'FOREIGN', 'CHECK')) { let depth = 0; while (!(depth === 0 && (p.isOp(',') || p.isOp(')')))) { if (p.isOp('(')) depth++; if (p.isOp(')')) depth--; p.next(); } continue; }
    const cn = p.ident();
    if (columns.some((x) => x.name === cn.name)) throw new SqlError(`column "${cn.name}" specified more than once`);
    columns.push(columnType(p, cn.name));
  } while (p.optOp(','));
  p.op(')');
  p.end();
  const acl: Record<string, string> = {};
  for (const e of d.defaultAcl.filter((x) => x.owner === s.user)) acl[e.grantee] = e.privs;
  d.tables[tn.name] = { name: tn.name, owner: s.user, columns, rows: [], acl, nextSerial: 1 };
  return { kind: 'tag', tag: 'CREATE TABLE', notices };
}

function alterSystem(s: SqlSession, p: Parser): SqlResult {
  const lines = (readFile(s.server, AUTO_CONF) ?? '').split('\n').filter((l) => l && !l.startsWith('#'));
  const map = new Map(lines.map((l) => { const m = /^(\w+)\s*=\s*'?(.*?)'?$/.exec(l)!; return [m[1], m[2]] as [string, string]; }));
  if (p.optKw('RESET')) {
    if (p.optKw('ALL')) map.clear(); else map.delete(p.ident().name);
  } else {
    p.kw('SET');
    const n = p.ident();
    if (!(n.name in SETTINGS) || n.name === 'include_dir') throw new SqlError(`unrecognized configuration parameter "${n.name}"`);
    if (!p.optOp('=')) p.kw('TO');
    const vals: string[] = [];
    do vals.push(p.cur.t === 'str' ? p.str() : p.next().v); while (p.optOp(','));
    const v = vals.join(', ');
    if (p.cur.t !== 'end' && !p.isOp(';')) p.syntax();
    if (/^default$/i.test(v)) map.delete(n.name);
    else {
      const probe = loadSettingsProbe(n.name, v);
      if (probe) throw new SqlError(probe);
      map.set(n.name, v);
    }
  }
  writeFile(s.server, AUTO_CONF, `# Do not edit this file manually!\n# It will be overwritten by the ALTER SYSTEM command.\n${[...map].map(([k, v]) => `${k} = '${v}'`).join('\n')}${map.size ? '\n' : ''}`, s.world.clock, { mode: 0o600, owner: 'postgres', group: 'postgres' });
  return { kind: 'tag', tag: 'ALTER SYSTEM' };
}

/** Validate one value as postgresql.conf would (returns the error, or null). */
function loadSettingsProbe(name: string, value: string): string | null {
  const d = SETTINGS[name];
  const ok = d.kind === 'int' ? /^-?\d+$/.test(value) && Number(value) >= (d.min ?? -Infinity) && Number(value) <= (d.max ?? Infinity)
    : d.kind === 'bool' ? /^(on|off|true|false|yes|no|1|0)$/i.test(value)
    : d.kind === 'enum' ? d.values!.includes(value.toLowerCase())
    : d.kind === 'mem' ? /^\d+\s*(kB|MB|GB|TB)?$/.test(value)
    : d.kind === 'time' ? /^-?\d+\s*(ms|s|min|h|d)?$/.test(value) : true;
  return ok ? null : `invalid value for parameter "${name}": "${value}"`;
}

function grantRevoke(s: SqlSession, p: Parser, grant: boolean): SqlResult {
  p.next();
  const c = cluster(s.server);
  // Role membership: GRANT role TO role.
  const save = p.i;
  let isRoleGrant = false;
  if (!p.isKw('ALL', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'CONNECT', 'TEMPORARY', 'TEMP', 'CREATE', 'USAGE')) isRoleGrant = true;
  if (isRoleGrant) {
    const roles: string[] = [];
    do { const r = p.ident(); needRole(c, r.name, r.pos); roles.push(r.name); } while (p.optOp(','));
    p.kw(grant ? 'TO' : 'FROM');
    const gs = grantees(p, c);
    if (p.optKw('WITH')) { p.kw('ADMIN'); p.kw('OPTION'); }
    if (p.optKw('GRANTED')) { p.kw('BY'); p.ident(); }
    p.optKw('CASCADE');
    p.end();
    if (!isSuper(c, s.user) && !c.roles[s.user]?.createrole) throw new SqlError(`must have admin option on role "${roles[0]}"`);
    for (const r of roles) if (c.roles[r].superuser && !isSuper(c, s.user)) throw new SqlError(`must be superuser to alter superusers`);
    for (const g of gs) {
      const gr = c.roles[g];
      for (const r of roles) {
        if (grant && memberOf(c, r, g)) throw new SqlError(`role "${g}" is a member of role "${r}"`);
        if (grant) { if (!gr.memberOf.includes(r)) gr.memberOf.push(r); } else gr.memberOf = gr.memberOf.filter((x) => x !== r);
      }
    }
    return { kind: 'tag', tag: grant ? 'GRANT ROLE' : 'REVOKE ROLE' };
  }
  p.i = save;
  // Object privileges.
  const look = p.toks.slice(p.i).findIndex((t) => t.t === 'id' && t.v.toUpperCase() === 'ON');
  const onTok = p.toks[p.i + look + 1];
  const kind: 'table' | 'database' | 'schema' = onTok && /^DATABASE$/i.test(onTok.v) ? 'database' : onTok && /^SCHEMA$/i.test(onTok.v) ? 'schema' : 'table';
  const { privs } = parsePrivs(p, kind);
  p.kw('ON');
  const tag = grant ? 'GRANT' : 'REVOKE';
  if (kind === 'database') {
    p.kw('DATABASE');
    const names: string[] = [];
    do names.push(p.ident().name); while (p.optOp(','));
    p.kw(grant ? 'TO' : 'FROM');
    const gs = grantees(p, c);
    if (p.optKw('WITH')) { p.kw('GRANT'); p.kw('OPTION'); }
    p.optKw('CASCADE');
    p.end();
    for (const n of names) {
      const d = c.databases[n];
      if (!d) throw new SqlError(`database "${n}" does not exist`);
      if (!isOwnerOrSuper(s, d.owner)) throw new SqlError(`permission denied for database ${n}`);
      if (privs[0] === 'ALL' || privs.includes('CONNECT')) for (const g of gs) { if (grant) { if (!d.connect.includes(g)) d.connect.push(g); } else d.connect = d.connect.filter((x) => x !== g); }
    }
    return { kind: 'tag', tag };
  }
  if (kind === 'schema') {
    p.kw('SCHEMA');
    const sn = p.ident();
    if (sn.name !== 'public') throw new SqlError(`schema "${sn.name}" does not exist`);
    p.kw(grant ? 'TO' : 'FROM');
    const gs = grantees(p, c);
    p.optKw('CASCADE');
    p.end();
    const d = db(s);
    if (!isOwnerOrSuper(s, d.owner)) throw new SqlError('permission denied for schema public');
    if (privs[0] === 'ALL' || privs.includes('CREATE')) for (const g of gs) { if (grant) { if (!d.schemaCreate.includes(g)) d.schemaCreate.push(g); } else d.schemaCreate = d.schemaCreate.filter((x) => x !== g); }
    return { kind: 'tag', tag };
  }
  let tables: PgTable[];
  if (p.optKw('ALL')) {
    p.kw('TABLES'); p.kw('IN'); p.kw('SCHEMA');
    const sn = p.ident();
    if (sn.name !== 'public') throw new SqlError(`schema "${sn.name}" does not exist`);
    tables = Object.values(db(s).tables);
  } else {
    p.optKw('TABLE');
    tables = [];
    do { const tn = p.tableName(); tables.push(needTable(s, tn.name, tn.pos)); } while (p.optOp(','));
  }
  p.kw(grant ? 'TO' : 'FROM');
  const gs = grantees(p, c);
  if (p.optKw('WITH')) { p.kw('GRANT'); p.kw('OPTION'); }
  p.optKw('CASCADE');
  p.end();
  const letters = tableLetters(privs);
  for (const t of tables) {
    if (!isOwnerOrSuper(s, t.owner)) throw new SqlError(`permission denied for table ${t.name}`);
    for (const g of gs) {
      const cur = t.acl[g] ?? '';
      const nextLetters = grant ? [...new Set(cur + letters)] : [...cur].filter((x) => !letters.includes(x));
      const sorted = [...ALL_TABLE_PRIVS].filter((x) => nextLetters.includes(x)).join('');
      if (sorted) t.acl[g] = sorted; else delete t.acl[g];
    }
  }
  return { kind: 'tag', tag };
}

function select(s: SqlSession, p: Parser): SqlResult {
  const c = cluster(s.server);
  let items: { e: Expr; alias?: string }[] = [];
  let from: { name: string; pos: number } | null = null;
  if (p.isKw('TABLE')) { p.next(); from = p.tableName(); items = [{ e: { k: 'star' } }]; } else {
    p.kw('SELECT');
    p.optKw('DISTINCT');
    do {
      if (p.isOp('*')) { p.next(); items.push({ e: { k: 'star' } }); continue; }
      const e = parseExpr(p);
      let alias: string | undefined;
      if (p.optKw('AS')) alias = p.ident().name;
      else if (p.cur.t === 'id' && !p.isKw('FROM', 'WHERE', 'ORDER', 'LIMIT', 'GROUP')) alias = p.ident().name;
      items.push({ e, alias });
    } while (p.optOp(','));
    if (p.optKw('FROM')) from = p.tableName();
  }
  const where = p.optKw('WHERE') ? parseExpr(p) : null;
  let groupBy: Expr[] = [];
  if (p.optKw('GROUP')) { p.kw('BY'); do groupBy.push(parseExpr(p)); while (p.optOp(',')); }
  const orders: { e: Expr; desc: boolean }[] = [];
  if (p.optKw('ORDER')) {
    p.kw('BY');
    do {
      const e = p.cur.t === 'num' ? ({ k: 'lit', v: Number(p.next().v) } as Expr) : parseExpr(p);
      const desc = p.optKw('DESC');
      if (!desc) p.optKw('ASC');
      orders.push({ e, desc });
    } while (p.optOp(','));
  }
  const limit = p.optKw('LIMIT') ? Number(p.next().v) : null;
  p.end();

  let src: Source = { columns: [], rows: [{}] };
  if (from) {
    const cat = catalog(s, from.name, from.pos);
    if (cat) src = cat;
    else {
      const t = needTable(s, from.name, from.pos);
      checkPriv(s, t, 'r');
      src = { columns: t.columns.map((x) => x.name), rows: t.rows.map((r) => rowObj(t, r)), table: t };
    }
  }
  const x: EvalCtx = { s };
  let rows = where ? src.rows.filter((r) => truthy(evalExpr(where, { ...x, row: r }))) : src.rows;
  const expanded = items.flatMap((it) => (it.e.k === 'star' ? src.columns.map((cn) => ({ e: { k: 'col', name: cn, pos: 0 } as Expr, alias: cn })) : [it]));
  if (!from && items.some((it) => it.e.k === 'star')) throw new SqlError('SELECT * with no tables specified is not valid');
  const columns = expanded.map((it) => it.alias ?? exprName(it.e));
  let out: Cell[][];
  if (groupBy.length || expanded.some((it) => hasAgg(it.e))) {
    const groups = new Map<string, Row[]>();
    for (const r of rows) {
      const key = JSON.stringify(groupBy.map((g) => evalExpr(g, { ...x, row: r })));
      groups.set(key, [...(groups.get(key) ?? []), r]);
    }
    if (!groupBy.length && !groups.size) groups.set('[]', []);
    out = [...groups.values()].map((g) => expanded.map((it) => evalAgg(it.e, g, x)));
  } else out = rows.map((r) => expanded.map((it) => evalExpr(it.e, { ...x, row: r })));
  if (orders.length) {
    const keyed = out.map((vals, i) => ({ vals, row: rows[i] }));
    keyed.sort((a, z) => {
      for (const o of orders) {
        const va = o.e.k === 'lit' && typeof o.e.v === 'number' ? a.vals[o.e.v - 1] : o.e.k === 'col' && columns.includes(o.e.name) ? a.vals[columns.indexOf(o.e.name)] : evalExpr(o.e, { ...x, row: a.row });
        const vz = o.e.k === 'lit' && typeof o.e.v === 'number' ? z.vals[o.e.v - 1] : o.e.k === 'col' && columns.includes(o.e.name) ? z.vals[columns.indexOf(o.e.name)] : evalExpr(o.e, { ...x, row: z.row });
        const d = va === null ? 1 : vz === null ? -1 : cmp(va, vz);
        if (d) return o.desc ? -d : d;
      }
      return 0;
    });
    out = keyed.map((k) => k.vals);
  }
  if (limit !== null) out = out.slice(0, limit);
  void c;
  const align = columns.map((_, i) => (out.length && out.every((r) => typeof r[i] === 'number' || r[i] === null) && out.some((r) => typeof r[i] === 'number') ? 'r' : 'l') as 'l' | 'r');
  const warn = s.settings.__warnings;
  delete s.settings.__warnings;
  return { kind: 'rows', columns, align, rows: out.map((r) => r.map(fmtCell)), notices: warn ? warn.trim().split('\n') : undefined };
}

export const fmtCell = (v: Cell): string => (v === null ? '' : v === true ? 't' : v === false ? 'f' : String(v));

// ---------------------------------------------------------------------------
// Running SQL
// ---------------------------------------------------------------------------

/** Execute one statement; errors become results and are logged like the server does. */
export function execStatement(s: SqlSession, sql: string): SqlResult {
  try {
    return execOne(s, sql);
  } catch (e) {
    if (!(e instanceof SqlError)) throw e;
    pgLog(s.world, s.server, s.pid, 'ERROR', e.message, { user: s.user, db: s.db }, [...(e.detail ? [`DETAIL:  ${e.detail.split('\n').join('\n\t')}`] : []), `STATEMENT:  ${sql}`]);
    return { kind: 'error', message: e.message, detail: e.detail, hint: e.hint, position: e.pos };
  }
}

/** psql's rendering of an error: ERROR line, then LINE n with a caret when the server gave a position. */
export function formatError(r: Extract<SqlResult, { kind: 'error' }>, sql: string, prefix = ''): string[] {
  const out = [`${prefix}ERROR:  ${r.message}`];
  if (r.detail) out.push(`DETAIL:  ${r.detail}`);
  if (r.hint) out.push(`HINT:  ${r.hint}`);
  if (r.position !== undefined && r.position < sql.length) {
    const before = sql.slice(0, r.position);
    const lineNo = before.split('\n').length;
    const lineStart = before.lastIndexOf('\n') + 1;
    const lineText = sql.slice(lineStart).split('\n')[0];
    const head = `LINE ${lineNo}: `;
    out.splice(1, 0, `${head}${lineText}`, `${' '.repeat(head.length + r.position - lineStart)}^`);
  }
  return out;
}

/** psql's aligned table output (with the row count footer). */
export function formatRows(r: Extract<SqlResult, { kind: 'rows' }>, opts: { title?: string; expanded?: boolean; tuplesOnly?: boolean; unaligned?: boolean } = {}): string[] {
  const { columns, rows, align } = r;
  if (opts.unaligned) return [...(opts.tuplesOnly ? [] : [columns.join('|')]), ...rows.map((row) => row.join('|')), ...(opts.tuplesOnly ? [] : [`(${rows.length} row${rows.length === 1 ? '' : 's'})`])];
  if (opts.expanded) {
    const w = Math.max(...columns.map((c) => c.length));
    const out: string[] = [];
    rows.forEach((row, i) => {
      out.push(`-[ RECORD ${i + 1} ]${'-'.repeat(Math.max(0, w - 10))}`);
      columns.forEach((cname, j) => out.push(`${cname.padEnd(w)} | ${row[j]}`));
    });
    if (!rows.length) out.push('(0 rows)');
    return out;
  }
  const cellLines = rows.map((row) => row.map((v) => v.split('\n')));
  const widths = columns.map((c, i) => Math.max(c.length, ...cellLines.map((r) => Math.max(...r[i].map((l) => l.length)))));
  const out: string[] = [];
  const total = widths.reduce((a, w) => a + w + 3, -1);
  if (opts.title) out.push(' '.repeat(Math.max(0, Math.floor((total - opts.title.length) / 2))) + opts.title);
  if (!opts.tuplesOnly) {
    out.push(columns.map((c, i) => {
      const pad = widths[i] - c.length;
      const left = Math.floor(pad / 2);
      return ` ${' '.repeat(left)}${c}${' '.repeat(pad - left)} `;
    }).join('|'));
    out.push(widths.map((w) => '-'.repeat(w + 2)).join('+'));
  }
  for (const r of cellLines) {
    const h = Math.max(...r.map((c) => c.length));
    for (let k = 0; k < h; k++) {
      const cells = r.map((c, i) => {
        const v = c[k] ?? '';
        const cont = k < c.length - 1 ? '+' : ' ';
        const body = align[i] === 'r' ? v.padStart(widths[i]) : v.padEnd(widths[i]);
        return ` ${body}${cont}`;
      });
      out.push(cells.join('|').replace(/\s+$/, ''));
    }
  }
  if (!opts.tuplesOnly) out.push(`(${rows.length} row${rows.length === 1 ? '' : 's'})`);
  return out;
}

/**
 * Run a script the way psql -f does: statement by statement, with COPY ... FROM
 * stdin data blocks (ended by a line "\.") read from the script itself.
 */
export function runScript(s: SqlSession, text: string, onResult: (r: SqlResult, sql: string, line: number) => boolean): void {
  const lines = text.split('\n');
  let buf = '';
  let startLine = 1;
  let q: string | null = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!buf.trim()) startLine = i + 1;
    // Statement text up to a semicolon outside quotes ends a statement.
    let piece = '';
    for (let j = 0; j < line.length; j++) {
      const ch = line[j];
      if (!q && ch === '-' && line[j + 1] === '-') { piece += line.slice(j); break; }
      if (q) { piece += ch; if (ch === q) q = null; continue; }
      if (ch === "'" || ch === '"') { q = ch; piece += ch; continue; }
      if (ch === ';') {
        const sql = (buf + piece).trim();
        buf = '';
        piece = '';
        if (sql.replace(/--[^\n]*/g, '').trim()) {
          const r = execStatement(s, sql);
          if (r.kind === 'copy') {
            const t = cluster(s.server).databases[s.db].tables[r.table];
            let n = 0;
            let err: SqlResult | null = null;
            for (i++; i < lines.length && lines[i] !== '\\.'; i++) {
              if (err) continue;
              const vals = lines[i].split('\t').map((v) => (v === '\\N' ? null : v.replace(/\\([\\tn])/g, (_, c: string) => (c === 't' ? '\t' : c === 'n' ? '\n' : '\\'))));
              try { insertRow(s, t, r.columns.map((cn) => t.columns.find((x) => x.name === cn)!), vals); n++; } catch (e) {
                if (!(e instanceof SqlError)) throw e;
                err = { kind: 'error', message: e.message, detail: e.detail };
                t.rows.splice(t.rows.length - n, n);
              }
            }
            if (!onResult(err ?? { kind: 'tag', tag: `COPY ${n}` }, sql, startLine)) return;
          } else if (!onResult(r, sql, startLine)) return;
        }
        startLine = i + 1;
        continue;
      }
      piece += ch;
    }
    buf += piece + '\n';
  }
  if (buf.replace(/--[^\n]*/g, '').trim()) {
    const sql = buf.trim();
    onResult(execStatement(s, sql), sql, startLine);
  }
}

// ---------------------------------------------------------------------------
// pg_dump / pg_restore
// ---------------------------------------------------------------------------

export interface ArchiveEntry { id: number; kind: 'TABLE' | 'TABLE DATA' | 'ACL'; table: string; owner: string; sql: string }
export interface Archive { createdAt: number; db: string; entries: ArchiveEntry[] }

function quoteCopy(v: Cell): string {
  if (v === null) return '\\N';
  return fmtCell(v).replace(/\\/g, '\\\\').replace(/\t/g, '\\t').replace(/\n/g, '\\n');
}

function colDef(col: PgColumn): string {
  return `    ${col.name} ${col.serial ? (col.type === 'bigint' ? 'bigserial' : 'serial') : col.type}${col.primaryKey ? ' PRIMARY KEY' : col.notNull && !col.serial ? ' NOT NULL' : ''}`;
}

function aclSql(t: PgTable): string {
  const names: Record<string, string> = { r: 'SELECT', a: 'INSERT', w: 'UPDATE', d: 'DELETE', D: 'TRUNCATE', x: 'REFERENCES', t: 'TRIGGER' };
  return Object.entries(t.acl).filter(([g]) => g !== t.owner).map(([g, l]) => `GRANT ${l === ALL_TABLE_PRIVS ? 'ALL' : [...l].map((x) => names[x]).join(',')} ON TABLE public.${t.name} TO ${g === 'PUBLIC' ? 'PUBLIC' : g};`).join('\n');
}

/**
 * pg_dump: read every table as `s.user` (it needs SELECT on all of them: it
 * locks each table first and fails on the first it may not read).
 */
export function dumpDatabase(s: SqlSession, only?: string[]): { ok: true; archive: Archive } | { ok: false; error: string[] } {
  const c = cluster(s.server);
  const d = c.databases[s.db];
  const tables = Object.values(d.tables).filter((t) => !only?.length || only.includes(t.name)).sort((a, z) => a.name.localeCompare(z.name));
  if (only?.length && !tables.length) return { ok: false, error: [`pg_dump: error: no matching tables were found`] };
  for (const t of tables) {
    if (!tablePriv(c, t, s.user, 'r')) {
      pgLog(s.world, s.server, s.pid, 'ERROR', `permission denied for table ${t.name}`, { user: s.user, db: s.db }, [`STATEMENT:  LOCK TABLE public.${t.name} IN ACCESS SHARE MODE`]);
      return { ok: false, error: [`pg_dump: error: query failed: ERROR:  permission denied for table ${t.name}`, `pg_dump: detail: Query was: LOCK TABLE public.${t.name} IN ACCESS SHARE MODE`] };
    }
  }
  let id = 200;
  const entries: ArchiveEntry[] = [];
  for (const t of tables) {
    entries.push({ id: id++, kind: 'TABLE', table: t.name, owner: t.owner, sql: `CREATE TABLE public.${t.name} (\n${t.columns.map(colDef).join(',\n')}\n);\n\n\nALTER TABLE public.${t.name} OWNER TO ${t.owner};` });
  }
  for (const t of tables) {
    entries.push({ id: 3300 + id++, kind: 'TABLE DATA', table: t.name, owner: t.owner, sql: `COPY public.${t.name} (${t.columns.map((x) => x.name).join(', ')}) FROM stdin;\n${t.rows.map((r) => r.map(quoteCopy).join('\t')).join('\n')}${t.rows.length ? '\n' : ''}\\.` });
  }
  for (const t of tables) {
    const acl = aclSql(t);
    if (acl) entries.push({ id: 3400 + id++, kind: 'ACL', table: t.name, owner: t.owner, sql: acl });
  }
  return { ok: true, archive: { createdAt: s.world.clock, db: s.db, entries } };
}

const HEADER = `--\n-- PostgreSQL database dump\n--\n\n-- Dumped from database version ${PG_FULL}\n-- Dumped by pg_dump version ${PG_FULL}\n\nSET statement_timeout = 0;\nSET client_encoding = 'UTF8';\nSET standard_conforming_strings = on;\nSET default_tablespace = '';\n`;

/** The archive as a plain SQL script (pg_dump -Fp, pg_restore -f). */
export function archiveToSql(a: Archive, entries = a.entries, clean = false): string {
  const parts = [HEADER];
  if (clean) for (const e of [...entries].reverse().filter((x) => x.kind === 'TABLE')) parts.push(`DROP TABLE IF EXISTS public.${e.table};\n`);
  for (const e of entries) {
    const label = e.kind === 'TABLE' ? `Name: ${e.table}; Type: TABLE; Schema: public; Owner: ${e.owner}` : e.kind === 'TABLE DATA' ? `Data for Name: ${e.table}; Type: TABLE DATA; Schema: public; Owner: ${e.owner}` : `Name: TABLE ${e.table}; Type: ACL; Schema: public; Owner: ${e.owner}`;
    parts.push(`--\n-- ${label}\n--\n\n${e.sql}\n\n`);
  }
  parts.push('--\n-- PostgreSQL database dump complete\n--\n');
  return parts.join('\n');
}

const MAGIC = 'PGDMP';
/** pg_dump -Fc: a compressed archive (here: the archive encoded after the "PGDMP" magic). */
export function archiveToCustom(a: Archive): string {
  return `${MAGIC}\u0001\u000e\u0000\u0004\u0008\u0001\u0001\n${base64Encode(utf8(JSON.stringify(a)))}\n`;
}
export function parseCustom(text: string): Archive | null {
  if (!text.startsWith(MAGIC)) return null;
  try { return JSON.parse(new TextDecoder().decode(base64Decode(text.split('\n')[1] ?? ''))) as Archive; } catch { return null; }
}

/** pg_restore -l: the archive's table of contents. */
export function archiveToc(a: Archive): string {
  const t = pgTime(a.createdAt);
  return [
    ';', `; Archive created at ${t}`, `;     dbname: ${a.db}`, `;     TOC Entries: ${a.entries.length + 6}`, ';     Compression: gzip', ';     Dump Version: 1.14-0', ';     Format: CUSTOM',
    ';     Integer: 4 bytes', ';     Offset: 8 bytes', `;     Dumped from database version: ${PG_FULL}`, `;     Dumped by pg_dump version: ${PG_FULL}`, ';', ';', '; Selected TOC Entries:', ';',
    ...a.entries.map((e) => `${e.id}; ${e.kind === 'TABLE' ? '1259' : '0'} ${16390 + e.id} ${e.kind === 'ACL' ? `ACL public TABLE ${e.table}` : `${e.kind} public ${e.table}`} ${e.owner}`),
  ].join('\n');
}

/** Write a dump file as the OS user would (pg_dump -f). */

