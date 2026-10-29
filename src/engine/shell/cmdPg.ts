// PostgreSQL tools: psql (one-shot with -c/-f, or an interactive session with
// its meta-commands), pg_dump, pg_restore, pg_dumpall, pg_isready, createuser,
// createdb, dropuser, dropdb, and Debian's cluster tools pg_lsclusters and
// pg_ctlcluster. Output follows PostgreSQL 15.8 and postgresql-common 248 on
// Debian 12.

import { resolve } from '../sim/dns';
import {
  ALL_TABLE_PRIVS, cluster, DATA_DIR, isSuper, PG_FULL, PG_LOG, pgAlive, pgConnect, type PgConnection, pgDisconnect, pgLoaded, type PgRole, SOCKET_DIR, storedHash,
} from '../sim/postgres';
import {
  type Archive, archiveToc, archiveToCustom, archiveToSql, dumpDatabase, execStatement, formatError, formatRows, lastStatementEnd, parseCustom, runScript, type SqlResult, type SqlSession,
} from '../sim/pgsql';
import { allListeners, restartService, serviceDef, startService, stopService, reloadService } from '../sim/services';
import { tcpConnect } from '../sim/tcp';
import type { World } from '../types';
import { getFile, resolvePath, writeChecked } from './cmdFiles';
import { type CmdCtx, type CmdResult, type CommandDef, err, ok } from './types';

export interface PsqlState {
  conn: PgConnection;
  /** The password used (to reconnect after the server restarted). */
  password: string | null;
  /** Statement text typed so far (multi-line input). */
  buffer: string;
  expanded: boolean;
  timing: boolean;
  settings: Record<string, string>;
  /** -h value as given (for reconnecting). */
  host?: string;
}

// ---------------------------------------------------------------------------
// Connection options shared by the tools
// ---------------------------------------------------------------------------

interface ConnOpts { host?: string; port: number; user?: string; db?: string; noPassword: boolean; forcePrompt: boolean }

/** Parse libpq options; returns the remaining arguments. With dbOpt false, -d is a plain flag (createuser -d = --createdb). */
function parseConn(args: string[], extraValue: string[] = [], dbOpt = true): { o: ConnOpts; flags: Map<string, string[]>; rest: string[]; bad?: string } {
  const o: ConnOpts = { port: 5432, noPassword: false, forcePrompt: false };
  const flags = new Map<string, string[]>();
  const rest: string[] = [];
  const valueOpts = new Set(['-h', '--host', '-p', '--port', '-U', '--username', ...(dbOpt ? ['-d', '--dbname'] : []), ...extraValue]);
  for (let i = 0; i < args.length; i++) {
    let a = args[i];
    let v: string | undefined;
    if (a.startsWith('--') && a.includes('=')) { v = a.slice(a.indexOf('=') + 1); a = a.slice(0, a.indexOf('=')); }
    else if (/^-[A-Za-z]./.test(a) && valueOpts.has(a.slice(0, 2))) { v = a.slice(2); a = a.slice(0, 2); }
    const take = () => { const x = v ?? args[++i]; if (x === undefined) throw new Error(`option requires an argument -- '${a.replace(/^-+/, '')}'`); return x; };
    switch (a) {
      case '-h': case '--host': o.host = take(); break;
      case '-p': case '--port': o.port = Number(take()); break;
      case '-U': case '--username': o.user = take(); break;
      case '-d': case '--dbname': {
        if (!dbOpt) { flags.set(a, [...(flags.get(a) ?? []), '']); break; }
        const d = take();
        const uri = /^postgres(?:ql)?:\/\/(?:([^:@/]+)(?::([^@/]*))?@)?([^:/?]*)(?::(\d+))?(?:\/([^?]*))?/.exec(d);
        if (uri) { if (uri[1]) o.user = uri[1]; if (uri[3]) o.host = uri[3]; if (uri[4]) o.port = Number(uri[4]); if (uri[5]) o.db = uri[5]; } else o.db = d;
        break;
      }
      case '-w': case '--no-password': o.noPassword = true; break;
      case '-W': case '--password': o.forcePrompt = true; break;
      default:
        if (a.startsWith('-') && a.length > 1) {
          if (valueOpts.has(a)) flags.set(a, [...(flags.get(a) ?? []), take()]);
          else if (/^-[A-Za-z]{2,}$/.test(a)) for (const ch of a.slice(1)) flags.set(`-${ch}`, [...(flags.get(`-${ch}`) ?? []), '']);
          else flags.set(a, [...(flags.get(a) ?? []), '']);
        } else rest.push(a);
    }
  }
  if (o.host === '' || o.host === SOCKET_DIR || o.host?.startsWith('/')) o.host = undefined;
  return { o, flags, rest };
}

/** The password from ~/.pgpass (libpq's lookup, with its permission check). */
function pgpass(ctx: CmdCtx, host: string | undefined, port: number, db: string, user: string): { password: string | null; warning?: string } {
  const path = `${ctx.user.home.replace(/\/$/, '')}/.pgpass`;
  const node = ctx.host.fs[path];
  if (!node || node.type !== 'file') return { password: null };
  if ((node.mode & 0o077) !== 0) return { password: null, warning: `WARNING: password file "${path}" has group or world access; permissions should be u=rw (0600) or less` };
  const h = host ?? 'localhost';
  const match = (pat: string, v: string) => pat === '*' || pat === v;
  for (const line of node.content.split('\n')) {
    if (!line.trim() || line.startsWith('#')) continue;
    const f = line.split(':');
    if (f.length < 5) continue;
    if (match(f[0], h) && match(f[1], String(port)) && match(f[2], db) && match(f[3], user)) return { password: f.slice(4).join(':') };
  }
  return { password: null };
}

interface Opened { conn: PgConnection; password: string | null; warnings: string[] }

function open(ctx: CmdCtx, o: ConnOpts, db: string, user: string, app: string): { ok: true; v: Opened } | { ok: false; message: string; warnings: string[] } {
  const warnings: string[] = [];
  let used: string | null = null;
  const r = pgConnect(ctx.world, ctx.host, {
    host: o.host, port: o.port, user, db, osUser: ctx.user.name, app,
    password: () => {
      if (!o.forcePrompt) {
        const p = pgpass(ctx, o.host, o.port, db, user);
        if (p.warning) warnings.push(p.warning);
        if (p.password !== null) return (used = p.password);
      }
      if (o.noPassword) return null;
      return (used = ctx.ask(`Password for user ${user}: `, true));
    },
  });
  if (!r.ok) return { ok: false, message: r.message, warnings };
  return { ok: true, v: { conn: r.conn, password: used, warnings } };
}

function sessionFor(world: World, conn: PgConnection, settings: Record<string, string> = {}): SqlSession {
  return { world, server: world.hosts[conn.serverHostId], user: conn.user, db: conn.db, pid: conn.pid, settings };
}

// ---------------------------------------------------------------------------
// Printing results like psql
// ---------------------------------------------------------------------------

function printResult(r: SqlResult, sql: string, view: { expanded: boolean; tuplesOnly?: boolean; unaligned?: boolean; quiet?: boolean }, errPrefix = ''): { lines: string[]; error: boolean } {
  const notices = 'notices' in r && r.notices ? r.notices : [];
  if (r.kind === 'error') return { lines: [...notices, ...formatError(r, sql, errPrefix)], error: true };
  if (r.kind === 'rows') return { lines: [...notices, ...formatRows(r, { expanded: view.expanded, tuplesOnly: view.tuplesOnly, unaligned: view.unaligned }), ...(view.tuplesOnly || view.unaligned ? [] : [''])], error: false };
  if (r.kind === 'tag') return { lines: [...notices, ...(view.quiet ? [] : [r.tag])], error: false };
  return { lines: [], error: false };
}

// ---------------------------------------------------------------------------
// Meta-commands
// ---------------------------------------------------------------------------

const rolesAttr = (r: PgRole): string => {
  const a: string[] = [];
  if (r.superuser) a.push('Superuser');
  if (r.createrole) a.push('Create role');
  if (r.createdb) a.push('Create DB');
  if (!r.login) a.push('Cannot login');
  if (r.replication) a.push('Replication');
  if (r.superuser) a.push('Bypass RLS');
  const lines = [a.join(', ')];
  if (r.connLimit >= 0) lines.push(r.connLimit === 0 ? 'No connections' : `${r.connLimit} connection${r.connLimit === 1 ? '' : 's'}`);
  if (r.validUntil !== null) lines.push(`Password valid until ${new Date(r.validUntil).toISOString().replace('T', ' ').replace(/\.\d+Z/, '+00')}`);
  return lines.filter(Boolean).join('\n');
};

function dbAcl(owner: string, connect: string[], template: boolean): string {
  if (!template && connect.length === 1 && connect[0] === 'PUBLIC') return '';
  const out = [`${template ? '=c' : connect.includes('PUBLIC') ? '=Tc' : ''}${template || connect.includes('PUBLIC') ? `/${owner}` : ''}`, `${owner}=CTc/${owner}`, ...connect.filter((g) => g !== 'PUBLIC').map((g) => `${g}=c/${owner}`)];
  return out.filter((x) => x && !x.startsWith('/')).join('\n');
}

function tableAcl(owner: string, acl: Record<string, string>): string {
  const others = Object.entries(acl).filter(([g]) => g !== owner);
  if (!others.length && !acl[owner]) return '';
  return [`${owner}=${acl[owner] ?? ALL_TABLE_PRIVS}/${owner}`, ...others.map(([g, l]) => `${g === 'PUBLIC' ? '' : g}=${l}/${owner}`)].join('\n');
}

const META_HELP = `General
  \\q                     quit psql
  \\conninfo              display information about current connection
  \\c[onnect] [DBNAME [USER]]
                         connect to new database
  \\password [USERNAME]   securely change the password for a user
  \\x [on|off]            toggle expanded output
  \\timing [on|off]       toggle timing of commands
  \\i FILE                execute commands from file
Informational
  \\l                     list databases
  \\du                    list roles
  \\dt                    list tables
  \\d NAME                describe table
  \\dn                    list schemas
  \\dp  or  \\z            list table access privileges
  \\ddp                   list default privileges
  \\echo [STRING]         write string to standard output`;

/** Run a backslash command; returns output lines and whether psql should quit. */
function metaCommand(ctx: CmdCtx, st: PsqlState, line: string): { lines: string[]; quit?: boolean; error?: boolean } {
  const [cmdRaw, ...args] = line.trim().split(/\s+/);
  const cmd = cmdRaw.replace(/\+$/, '');
  const world = ctx.world;
  const server = world.hosts[st.conn.serverHostId];
  const c = cluster(server);
  const rows = (title: string | undefined, columns: string[], data: string[][], footer = true) => {
    const lines = formatRows({ kind: 'rows', columns, align: columns.map(() => 'l'), rows: data }, { title, expanded: st.expanded });
    return footer ? [...lines, ''] : [...lines.slice(0, -1), ''];
  };
  switch (cmd) {
    case '\\q': return { lines: [], quit: true };
    case '\\?': return { lines: META_HELP.split('\n') };
    case '\\echo': return { lines: [args.join(' ')] };
    case '\\x': {
      st.expanded = args[0] === 'on' ? true : args[0] === 'off' ? false : !st.expanded;
      return { lines: [`Expanded display is ${st.expanded ? 'on' : 'off'}.`] };
    }
    case '\\timing': {
      st.timing = args[0] === 'on' ? true : args[0] === 'off' ? false : !st.timing;
      return { lines: [`Timing is ${st.timing ? 'on' : 'off'}.`] };
    }
    case '\\conninfo': {
      const k = st.conn;
      if (k.local) return { lines: [`You are connected to database "${k.db}" as user "${k.user}" via socket in "${SOCKET_DIR}" at port "${k.port}".`] };
      return { lines: [`You are connected to database "${k.db}" as user "${k.user}" on host "${k.hostLabel}" (address "${k.addr}") at port "${k.port}".`, ...(k.ssl ? ['SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off)'] : [])] };
    }
    case '\\l': {
      const data = Object.values(c.databases).sort((a, z) => a.name.localeCompare(z.name)).map((d) => [d.name, d.owner, 'UTF8', 'C.UTF-8', 'C.UTF-8', '', 'libc', dbAcl(d.owner, d.connect, d.name.startsWith('template'))]);
      return { lines: rows('List of databases', ['Name', 'Owner', 'Encoding', 'Collate', 'Ctype', 'ICU Locale', 'Locale Provider', 'Access privileges'], data) };
    }
    case '\\du': case '\\dg': {
      const data = Object.values(c.roles).filter((r) => !r.predefined && (!args[0] || r.name === args[0])).sort((a, z) => a.name.localeCompare(z.name)).map((r) => [r.name, rolesAttr(r), `{${r.memberOf.join(',')}}`]);
      return { lines: rows('List of roles', ['Role name', 'Attributes', 'Member of'], data, false) };
    }
    case '\\dn': return { lines: rows('List of schemas', ['Name', 'Owner'], [['public', 'pg_database_owner']]) };
    case '\\dt': {
      const tables = Object.values(c.databases[st.conn.db].tables).filter((t) => !args[0] || t.name === args[0].replace(/^public\./, '')).sort((a, z) => a.name.localeCompare(z.name));
      if (!tables.length) return { lines: [args[0] ? `Did not find any relation named "${args[0]}".` : 'Did not find any relations.'] };
      return { lines: rows('List of relations', ['Schema', 'Name', 'Type', 'Owner'], tables.map((t) => ['public', t.name, 'table', t.owner])) };
    }
    case '\\dp': case '\\z': {
      const tables = Object.values(c.databases[st.conn.db].tables).filter((t) => !args[0] || t.name === args[0].replace(/^public\./, '')).sort((a, z) => a.name.localeCompare(z.name));
      return { lines: rows('Access privileges', ['Schema', 'Name', 'Type', 'Access privileges', 'Column privileges', 'Policies'], tables.map((t) => ['public', t.name, 'table', tableAcl(t.owner, t.acl), '', ''])) };
    }
    case '\\ddp': {
      const data = [...c.databases[st.conn.db].defaultAcl].sort((a, z) => a.owner.localeCompare(z.owner)).map((e) => [e.owner, '', 'table', `${e.grantee === 'PUBLIC' ? '' : e.grantee}=${e.privs}/${e.owner}`]);
      return { lines: rows('Default access privileges', ['Owner', 'Schema', 'Type', 'Access privileges'], data) };
    }
    case '\\d': {
      if (!args[0]) return metaCommand(ctx, st, '\\dt');
      const name = args[0].replace(/^public\./, '').replace(/"/g, '');
      const t = c.databases[st.conn.db].tables[name];
      if (!t) return { lines: [`Did not find any relation named "${args[0]}".`], error: true };
      const data = t.columns.map((col) => [col.name, col.type, '', col.notNull || col.primaryKey ? 'not null' : '', col.serial ? `nextval('${t.name}_${col.name}_seq'::regclass)` : '']);
      const lines = rows(`Table "public.${t.name}"`, ['Column', 'Type', 'Collation', 'Nullable', 'Default'], data, false);
      const pk = t.columns.find((x) => x.primaryKey);
      if (pk) lines.splice(lines.length - 1, 0, 'Indexes:', `    "${t.name}_pkey" PRIMARY KEY, btree (${pk.name})`);
      return { lines };
    }
    case '\\c': case '\\connect': {
      const db = args[0] && args[0] !== '-' ? args[0] : st.conn.db;
      const user = args[1] && args[1] !== '-' ? args[1] : st.conn.user;
      const o: ConnOpts = { host: st.host, port: st.conn.port, noPassword: false, forcePrompt: false };
      const r = open(ctx, o, db, user, 'psql');
      if (!r.ok) return { lines: [...r.warnings, r.message, 'Previous connection kept'], error: true };
      pgDisconnect(world, st.conn);
      st.conn = r.v.conn;
      st.settings = {};
      st.password = r.v.password;
      return { lines: [...r.v.warnings, `${r.v.conn.ssl ? 'SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off)\n' : ''}You are now connected to database "${db}" as user "${user}".`] };
    }
    case '\\password': {
      const user = args[0] ?? st.conn.user;
      const p1 = ctx.ask(`Enter new password for user "${user}": `, true);
      const p2 = ctx.ask('Enter it again: ', true);
      if (p1 !== p2) return { lines: ["Passwords didn't match."], error: true };
      const r = execStatement(sessionFor(world, st.conn, st.settings), `ALTER ROLE "${user}" PASSWORD '${p1.replace(/'/g, "''")}'`);
      return r.kind === 'error' ? { lines: formatError(r, ''), error: true } : { lines: [] };
    }
    case '\\i': case '\\ir': {
      const path = resolvePath(ctx, args[0] ?? '');
      const f = getFile(ctx, path);
      if (f.error) return { lines: [`${args[0]}: ${f.error}`], error: true };
      const out: string[] = [];
      let error = false;
      runScript(sessionFor(world, st.conn, st.settings), f.content!, (r, sql, ln) => {
        const p = printResult(r, sql, { expanded: st.expanded }, `psql:${args[0]}:${ln}: `);
        out.push(...p.lines);
        error ||= p.error;
        return true;
      });
      return { lines: out, error };
    }
    default:
      return { lines: [`invalid command ${cmdRaw}`, 'Try \\? for help.'], error: true };
  }
}

// ---------------------------------------------------------------------------
// psql
// ---------------------------------------------------------------------------

const BANNER = (ssl: boolean) => [`psql (${PG_FULL})`, ...(ssl ? ['SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off)'] : []), 'Type "help" for help.', ''];

const psql: CommandDef = {
  name: 'psql',
  summary: 'PostgreSQL interactive terminal (or run SQL with -c / -f)',
  usage: 'psql [-h HOST] [-p PORT] [-U USER] [-d DBNAME] [-c "SQL"] [-f FILE] [-l] [-x] [-A] [-t] [-v ON_ERROR_STOP=1] [DBNAME [USER]]',
  run(args, ctx) {
    let parsed;
    try { parsed = parseConn(args, ['-c', '--command', '-f', '--file', '-v', '--set', '-o']); } catch (e) { return err(`psql: error: ${(e as Error).message}\npsql: hint: Try "psql --help" for more information.`, 1); }
    const { o, flags, rest } = parsed;
    if (flags.has('--version') || flags.has('-V')) return ok(`psql (PostgreSQL) ${PG_FULL.split(' ')[0]} (Debian ${PG_FULL.match(/Debian ([^)]+)/)![1]})`);
    const user = o.user ?? rest[1] ?? ctx.user.name;
    const listOnly = flags.has('-l') || flags.has('--list');
    const db = o.db ?? rest[0] ?? (listOnly ? 'postgres' : user);
    const commands = [...(flags.get('-c') ?? []), ...(flags.get('--command') ?? [])];
    const files = [...(flags.get('-f') ?? []), ...(flags.get('--file') ?? [])];
    const stopOnError = [...(flags.get('-v') ?? []), ...(flags.get('--set') ?? [])].some((v) => /^ON_ERROR_STOP=(1|on|true)$/i.test(v));
    const view = { expanded: flags.has('-x'), tuplesOnly: flags.has('-t'), unaligned: flags.has('-A'), quiet: flags.has('-q') };
    const r = open(ctx, o, db, user, 'psql');
    if (!r.ok) return err([...r.warnings, `psql: error: ${r.message}`].join('\n'), 2);
    const { conn, password, warnings } = r.v;
    const out: string[] = [...warnings];
    const st: PsqlState = { conn, password, buffer: '', expanded: view.expanded, timing: false, settings: {}, host: o.host };
    const sess = () => sessionFor(ctx.world, st.conn, st.settings);
    const done = (code: number): CmdResult => { pgDisconnect(ctx.world, st.conn); return { out: out.join('\n').replace(/\n+$/, ''), code }; };

    if (listOnly) {
      out.push(...metaCommand(ctx, st, '\\l').lines);
      return done(0);
    }
    if (commands.length) {
      for (const c of commands) {
        if (c.trim().startsWith('\\')) {
          const m = metaCommand(ctx, st, c.trim());
          out.push(...m.lines);
          if (m.error) return done(1);
          continue;
        }
        let failed = false;
        runScript(sess(), c, (res, sql) => {
          const p = printResult(res, sql, view);
          out.push(...p.lines);
          failed ||= p.error;
          return !p.error;
        });
        if (failed) return done(1);
      }
      return done(0);
    }
    const scripts = files.map((f) => ({ name: f, text: (() => { if (f === '-') return ctx.stdin ?? ''; const g = getFile(ctx, resolvePath(ctx, f)); return g.error ? null : g.content!; })() }));
    if (!scripts.length && ctx.stdin !== undefined) scripts.push({ name: '<stdin>', text: ctx.stdin });
    if (scripts.length) {
      for (const s of scripts) {
        if (s.text === null) { out.push(`psql: error: ${s.name}: No such file or directory`); return done(1); }
        let stop = false;
        runScript(sess(), s.text, (res, sql, ln) => {
          const p = printResult(res, sql, view, s.name === '<stdin>' ? '' : `psql:${s.name}:${ln}: `);
          out.push(...p.lines);
          if (p.error && stopOnError) { stop = true; return false; }
          return true;
        });
        if (stop) return done(3);
      }
      return done(0);
    }
    // Interactive: a psql frame on top of the shell.
    return { out: [...out, ...BANNER(conn.ssl)].join('\n'), code: 0, enterSession: { hostId: ctx.frame.hostId, user: ctx.frame.user, cwd: ctx.frame.cwd, psql: st } };
  },
};

/** One line typed at the psql prompt. Returns the output and whether psql ends. */
export function psqlLine(ctx: CmdCtx, st: PsqlState, line: string): { out: string; quit: boolean; code: number } {
  const world = ctx.world;
  const lines: string[] = [];
  if (!st.buffer && /^(\\q|exit|quit)$/.test(line.trim())) { pgDisconnect(world, st.conn); return { out: '', quit: true, code: 0 }; }
  // The backend may be gone (server restarted, session terminated): psql notices at the next command.
  if (!pgAlive(world, st.conn) && line.trim()) {
    lines.push('FATAL:  terminating connection due to administrator command', 'server closed the connection unexpectedly', '\tThis probably means the server terminated abnormally', '\tbefore or while processing the request.');
    const o: ConnOpts = { host: st.host, port: st.conn.port, noPassword: true, forcePrompt: false };
    const pw = st.password;
    const r = pgConnect(world, ctx.host, { host: o.host, port: o.port, user: st.conn.user, db: st.conn.db, osUser: ctx.user.name, app: 'psql', password: () => pw ?? pgpass(ctx, o.host, o.port, st.conn.db, st.conn.user).password });
    if (!r.ok) {
      lines.push('The connection to the server was lost. Attempting reset: Failed.');
      return { out: lines.join('\n'), quit: true, code: 2 };
    }
    st.conn = r.conn;
    st.settings = {};
    lines.push('The connection to the server was lost. Attempting reset: Succeeded.');
    return { out: lines.join('\n'), quit: false, code: 0 };
  }
  const trimmed = line.trim();
  if (!st.buffer && trimmed === 'help') return { out: 'You are using psql, the command-line interface to PostgreSQL.\nType:  \\copyright for distribution terms\n       \\h for help with SQL commands\n       \\? for help with psql commands\n       \\g or terminate with semicolon to execute query\n       \\q to quit', quit: false, code: 0 };
  if (!st.buffer && trimmed.startsWith('\\')) {
    const m = metaCommand(ctx, st, trimmed);
    if (m.quit) pgDisconnect(world, st.conn);
    return { out: m.lines.join('\n').replace(/\n+$/, ''), quit: !!m.quit, code: m.error ? 1 : 0 };
  }
  st.buffer += (st.buffer ? '\n' : '') + line;
  // Execute the complete statements typed so far; keep an unfinished one.
  const text = st.buffer;
  const lastEnd = lastStatementEnd(text);
  if (lastEnd < 0) return { out: '', quit: false, code: 0 };
  const complete = text.slice(0, lastEnd + 1);
  st.buffer = text.slice(lastEnd + 1).trim();
  let code = 0;
  const started = world.clock;
  runScript(sessionFor(world, st.conn, st.settings), complete, (r, sql) => {
    const p = printResult(r, sql, { expanded: st.expanded });
    lines.push(...p.lines);
    if (p.error) code = 1;
    return true;
  });
  if (st.timing) lines.push(`Time: ${(Math.max(0.2, world.clock - started) + 0.317).toFixed(3)} ms`);
  return { out: lines.join('\n').replace(/\n+$/, ''), quit: false, code };
}

/** The psql prompt: DB=> (DB=# for a superuser), DB-> while a statement is unfinished. */
export function psqlPrompt(world: World, st: PsqlState): string {
  const server = world.hosts[st.conn.serverHostId];
  const sup = !!server && isSuper(cluster(server), st.conn.user);
  return `${st.conn.db}${st.buffer ? '-' : '='}${sup ? '#' : '>'} `;
}

// ---------------------------------------------------------------------------
// pg_dump, pg_restore, pg_dumpall
// ---------------------------------------------------------------------------

const pgDump: CommandDef = {
  name: 'pg_dump',
  summary: 'export one PostgreSQL database as an SQL script or a custom-format archive',
  usage: 'pg_dump [-h HOST] [-U USER] [-F p|c] [-f FILE] [-t TABLE] DBNAME',
  run(args, ctx) {
    let parsed;
    try { parsed = parseConn(args, ['-f', '--file', '-F', '--format', '-t', '--table']); } catch (e) { return err(`pg_dump: error: ${(e as Error).message}`, 1); }
    const { o, flags, rest } = parsed;
    const user = o.user ?? ctx.user.name;
    const db = o.db ?? rest[0] ?? user;
    const format = (flags.get('-F') ?? flags.get('--format') ?? ['p'])[0].toLowerCase();
    if (!['p', 'plain', 'c', 'custom'].includes(format)) return err(`pg_dump: error: invalid output format "${format}" specified`, 1);
    const file = (flags.get('-f') ?? flags.get('--file'))?.[0];
    const tables = [...(flags.get('-t') ?? []), ...(flags.get('--table') ?? [])].map((t) => t.replace(/^public\./, ''));
    const r = open(ctx, o, db, user, 'pg_dump');
    if (!r.ok) return err([...r.warnings, `pg_dump: error: ${r.message}`].join('\n'), 1);
    const s = sessionFor(ctx.world, r.v.conn);
    const d = dumpDatabase(s, tables);
    pgDisconnect(ctx.world, r.v.conn);
    if (!d.ok) return err([...r.v.warnings, ...d.error].join('\n'), 1);
    let archive = d.archive;
    if (flags.has('-a') || flags.has('--data-only')) archive = { ...archive, entries: archive.entries.filter((e) => e.kind === 'TABLE DATA') };
    if (flags.has('-s') || flags.has('--schema-only')) archive = { ...archive, entries: archive.entries.filter((e) => e.kind !== 'TABLE DATA') };
    const content = format.startsWith('c') ? archiveToCustom(archive) : archiveToSql(archive);
    if (!file) return ok([...r.v.warnings, content.replace(/\n$/, '')].join('\n'));
    const e = writeChecked(ctx, resolvePath(ctx, file), content);
    if (e) return err([...r.v.warnings, `pg_dump: error: could not open output file "${file}": ${e}`].join('\n'), 1);
    return ok(r.v.warnings.join('\n'));
  },
};

function loadArchive(ctx: CmdCtx, file: string | undefined): { a?: Archive; error?: string } {
  if (!file) return { error: 'pg_restore: error: one of -d/--dbname and -f/--file must be specified' };
  const f = getFile(ctx, resolvePath(ctx, file));
  if (f.error) return { error: `pg_restore: error: could not open input file "${file}": ${f.error}` };
  if (f.content!.startsWith('--')) return { error: 'pg_restore: error: input file appears to be a text format dump. Please use psql.' };
  const a = parseCustom(f.content!);
  if (!a) return { error: 'pg_restore: error: input file does not appear to be a valid archive' };
  return { a };
}

const pgRestore: CommandDef = {
  name: 'pg_restore',
  summary: 'restore a custom-format archive made by pg_dump -Fc (or list its contents with -l)',
  usage: 'pg_restore [-l] [-d DBNAME] [-h HOST] [-U USER] [-t TABLE] [-a|-s] [-c] [-f FILE] ARCHIVE',
  run(args, ctx) {
    let parsed;
    try { parsed = parseConn(args, ['-f', '--file', '-t', '--table']); } catch (e) { return err(`pg_restore: error: ${(e as Error).message}`, 1); }
    const { o, flags, rest } = parsed;
    const { a, error } = loadArchive(ctx, rest[0]);
    if (!a) return err(error!, 1);
    if (flags.has('-l') || flags.has('--list')) return ok(archiveToc(a));
    const only = [...(flags.get('-t') ?? []), ...(flags.get('--table') ?? [])].map((t) => t.replace(/^public\./, ''));
    let entries = a.entries.filter((e) => !only.length || only.includes(e.table));
    if (flags.has('-a') || flags.has('--data-only')) entries = entries.filter((e) => e.kind === 'TABLE DATA');
    if (flags.has('-s') || flags.has('--schema-only')) entries = entries.filter((e) => e.kind !== 'TABLE DATA');
    const clean = flags.has('-c') || flags.has('--clean');
    if (!o.db) {
      const sql = archiveToSql(a, entries, clean);
      const out = (flags.get('-f') ?? flags.get('--file'))?.[0];
      if (!out) return ok(sql.replace(/\n$/, ''));
      const e = writeChecked(ctx, resolvePath(ctx, out), sql);
      return e ? err(`pg_restore: error: could not open output file "${out}": ${e}`, 1) : ok('');
    }
    const user = o.user ?? ctx.user.name;
    const r = open(ctx, o, o.db, user, 'pg_restore');
    if (!r.ok) return err([...r.warnings, `pg_restore: error: ${r.message}`].join('\n'), 1);
    const s = sessionFor(ctx.world, r.v.conn);
    const out: string[] = [...r.v.warnings];
    let errors = 0;
    const exitOnError = flags.has('-e') || flags.has('--exit-on-error');
    if (clean) for (const e of [...entries].reverse().filter((x) => x.kind === 'TABLE')) runScript(s, `DROP TABLE IF EXISTS public.${e.table};`, () => true);
    for (const e of entries) {
      let stop = false;
      runScript(s, e.sql, (res, sql) => {
        if (res.kind !== 'error') return true;
        errors++;
        if (sql.startsWith('COPY')) out.push(`pg_restore: error: COPY failed for table "${e.table}": ERROR:  ${res.message}`, ...(res.detail ? [`DETAIL:  ${res.detail}`] : []));
        else out.push(`pg_restore: error: could not execute query: ERROR:  ${res.message}`, ...(res.detail ? [`DETAIL:  ${res.detail}`] : []), `Command was: ${sql.split('\n').slice(0, 6).join('\n')}${sql.endsWith(';') ? '' : ';'}`);
        if (exitOnError) stop = true;
        return false;
      });
      if (stop) break;
    }
    pgDisconnect(ctx.world, r.v.conn);
    if (errors) out.push(`pg_restore: warning: errors ignored on restore: ${errors}`);
    return { out: out.join('\n'), code: errors ? 1 : 0 };
  },
};

const pgDumpall: CommandDef = {
  name: 'pg_dumpall',
  summary: 'export cluster-wide objects (roles and their passwords) with --globals-only',
  usage: 'pg_dumpall -g [-h HOST] [-U USER] [-f FILE]',
  run(args, ctx) {
    let parsed;
    try { parsed = parseConn(args, ['-f', '--file']); } catch (e) { return err(`pg_dumpall: error: ${(e as Error).message}`, 1); }
    const { o, flags } = parsed;
    if (!flags.has('-g') && !flags.has('--globals-only') && !flags.has('-r') && !flags.has('--roles-only')) return err('[Cyber Owl Lab: only pg_dumpall --globals-only (-g) is simulated; dump each database with pg_dump]', 1);
    const user = o.user ?? ctx.user.name;
    const r = open(ctx, o, 'postgres', user, 'pg_dumpall');
    if (!r.ok) return err(`pg_dumpall: error: ${r.message}`, 1);
    const server = ctx.world.hosts[r.v.conn.serverHostId];
    const c = cluster(server);
    pgDisconnect(ctx.world, r.v.conn);
    if (!isSuper(c, user)) return err('pg_dumpall: error: query failed: ERROR:  permission denied for table pg_authid\npg_dumpall: detail: Query was: SELECT oid, rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolconnlimit, rolpassword, rolvaliduntil, rolreplication, rolbypassrls, pg_catalog.shobj_description(oid, \'pg_authid\') as rolcomment, rolname = current_user AS is_current_user FROM pg_authid WHERE rolname !~ \'^pg_\' ORDER BY 2', 1);
    const roles = Object.values(c.roles).filter((x) => !x.predefined).sort((a, z) => a.name.localeCompare(z.name));
    const lines = ['--', '-- PostgreSQL database cluster dump', '--', '', 'SET default_transaction_read_only = off;', '', "SET client_encoding = 'UTF8';", 'SET standard_conforming_strings = on;', '', '--', '-- Roles', '--', ''];
    for (const x of roles) {
      lines.push(`CREATE ROLE ${x.name};`);
      const pw = hashFor(x);
      lines.push(`ALTER ROLE ${x.name} WITH ${x.superuser ? 'SUPERUSER' : 'NOSUPERUSER'} INHERIT ${x.createrole ? 'CREATEROLE' : 'NOCREATEROLE'} ${x.createdb ? 'CREATEDB' : 'NOCREATEDB'} ${x.login ? 'LOGIN' : 'NOLOGIN'} ${x.replication ? 'REPLICATION' : 'NOREPLICATION'} ${x.superuser ? 'BYPASSRLS' : 'NOBYPASSRLS'}${x.connLimit >= 0 ? ` CONNECTION LIMIT ${x.connLimit}` : ''}${pw ? ` PASSWORD '${pw}'` : ''};`);
    }
    const members = roles.flatMap((x) => x.memberOf.map((g) => `GRANT ${g} TO ${x.name} GRANTED BY postgres;`));
    if (members.length) lines.push('', '--', '-- Role memberships', '--', '', ...members);
    lines.push('', '--', '-- PostgreSQL database cluster dump complete', '--', '');
    const text = lines.join('\n');
    const file = (flags.get('-f') ?? flags.get('--file'))?.[0];
    if (!file) return ok(text.replace(/\n$/, ''));
    const e = writeChecked(ctx, resolvePath(ctx, file), text);
    return e ? err(`pg_dumpall: error: could not open output file "${file}": ${e}`, 1) : ok('');
  },
};

/** The password as pg_authid stores it (a hash imported without its password is kept as it came). */
function hashFor(r: PgRole): string | null {
  if (r.password?.startsWith('\u0000unknown:')) return r.password.slice('\u0000unknown:'.length);
  return storedHash(r);
}

// ---------------------------------------------------------------------------
// Debian cluster tools and small client tools
// ---------------------------------------------------------------------------

const serverInstalled = (ctx: CmdCtx) => !!ctx.host.services.postgresql;
const notFound = (n: string): CmdResult => err(`-bash: ${n}: command not found`, 127);

const pgLsclusters: CommandDef = {
  name: 'pg_lsclusters',
  summary: 'list the PostgreSQL clusters on this host (Debian postgresql-common)',
  usage: 'pg_lsclusters',
  run(_args, ctx) {
    if (!serverInstalled(ctx)) return notFound('pg_lsclusters');
    const l = pgLoaded(ctx.host);
    const port = l?.port ?? 5432;
    return ok(`Ver Cluster Port Status Owner    Data directory              Log file\n15  main    ${String(port).padEnd(4)} ${l ? 'online' : 'down  '} postgres ${DATA_DIR} ${PG_LOG}`);
  },
};

const pgCtlcluster: CommandDef = {
  name: 'pg_ctlcluster',
  summary: 'start, stop, restart, reload or show the status of a PostgreSQL cluster',
  usage: 'pg_ctlcluster 15 main start|stop|restart|reload|status',
  run(args, ctx) {
    if (!serverInstalled(ctx)) return notFound('pg_ctlcluster');
    const [ver, name, action] = args;
    if (!ver || !name || !action) return err('Usage: /usr/bin/pg_ctlcluster <version> <cluster> <action> [-- <pg_ctl options>]', 1);
    if (ver !== '15' || name !== 'main') return err(`Error: specified cluster ${ver}/${name} does not exist`, 1);
    if (ctx.user.uid !== 0 && ctx.user.name !== 'postgres') return err('Error: You must run this program as the cluster owner (postgres) or root', 1);
    const def = serviceDef('postgresql')!;
    const rt = ctx.host.services.postgresql;
    const failed = () => err('Job for postgresql@15-main.service failed because the service did not take the steps required by its unit configuration.\nSee "systemctl status postgresql@15-main.service" and "journalctl -xeu postgresql@15-main.service" for details.', 1);
    switch (action) {
      case 'start':
        if (rt.state === 'active') return err('Cluster is already running.', 2);
        return startService(ctx.world, ctx.host, def) ? ok('') : failed();
      case 'stop':
        if (rt.state !== 'active') return err('Cluster is not running.', 2);
        stopService(ctx.world, ctx.host, def);
        return ok('');
      case 'restart':
        return restartService(ctx.world, ctx.host, def) ? ok('') : failed();
      case 'reload': {
        if (rt.state !== 'active') return err('Cluster is not running.', 2);
        const r = reloadService(ctx.world, ctx.host, def);
        return r.ok ? ok('') : err(r.message ?? '', 1);
      }
      case 'status': {
        const l = pgLoaded(ctx.host);
        if (!l) return err('pg_ctl: no server running', 3);
        return ok(`pg_ctl: server is running (PID: ${l.pid})\n/usr/lib/postgresql/15/bin/postgres "-D" "${DATA_DIR}" "-c" "config_file=/etc/postgresql/15/main/postgresql.conf"`);
      }
      default:
        return err(`Error: invalid action '${action}'`, 1);
    }
  },
};

const pgIsready: CommandDef = {
  name: 'pg_isready',
  summary: 'check whether a PostgreSQL server accepts connections (no login needed)',
  usage: 'pg_isready [-h HOST] [-p PORT]',
  run(args, ctx) {
    let parsed;
    try { parsed = parseConn(args, ['-t', '--timeout']); } catch (e) { return err(`pg_isready: ${(e as Error).message}`, 3); }
    const { o } = parsed;
    const label = `${o.host ?? SOCKET_DIR}:${o.port}`;
    if (!o.host) {
      const l = pgLoaded(ctx.host);
      return l && l.port === o.port && ctx.host.fs[`${SOCKET_DIR}/.s.PGSQL.${o.port}`] ? ok(`${label} - accepting connections`) : err(`${label} - no response`, 2);
    }
    const r = resolve(ctx.world, ctx.host, o.host, {});
    if (!r.ok) return err(`${label} - no attempt`, 3);
    const c = tcpConnect(ctx.world, ctx.host, r.ip, o.port, { timeoutMs: 3_000 });
    if (!c.ok) return err(`${label} - no response`, 2);
    const owner = allListeners(c.conn.server).find((x) => x.proto === 'tcp' && x.port === c.conn.sv.localPort)?.service;
    c.conn.close('client');
    return owner === 'postgresql' ? ok(`${label} - accepting connections`) : err(`${label} - no response`, 2);
  },
};

/** createuser / createdb / dropuser / dropdb: connect to the postgres database and run one statement. */
function wrapper(name: string, summary: string, usage: string, build: (rest: string[], flags: Map<string, string[]>, ctx: CmdCtx) => { sql?: string; error?: string }, failVerb: (target: string) => string, dbOpt = true): CommandDef {
  return {
    name, summary, usage,
    run(args, ctx) {
      let parsed;
      try { parsed = parseConn(args, ['-O', '--owner', '-c', '--connection-limit'], dbOpt); } catch (e) { return err(`${name}: error: ${(e as Error).message}`, 1); }
      const { o, flags, rest } = parsed;
      const b = build(rest, flags, ctx);
      if (b.error) return err(`${name}: error: ${b.error}`, 1);
      const r = open(ctx, o, o.db ?? 'postgres', o.user ?? ctx.user.name, name);
      if (!r.ok) return err(`${name}: error: ${r.message}`, 1);
      const res = execStatement(sessionFor(ctx.world, r.v.conn), b.sql!);
      pgDisconnect(ctx.world, r.v.conn);
      if (res.kind === 'error') return err(`${name}: error: ${failVerb(rest[0])} failed: ERROR:  ${res.message}${res.detail ? `\nDETAIL:  ${res.detail}` : ''}`, 1);
      return ok('');
    },
  };
}
const q = (n: string) => (/^[a-z_][a-z0-9_]*$/.test(n) ? n : `"${n.replace(/"/g, '""')}"`);

const createuser = wrapper('createuser', 'create a PostgreSQL role (CREATE ROLE)', 'createuser [-P] [-d] [-r] [-s] [-L] [-h HOST] [-U USER] ROLENAME', (rest, flags, ctx) => {
  const n = rest[0];
  if (!n) return { error: 'missing required argument role name' };
  const opts = [flags.has('-s') || flags.has('--superuser') ? 'SUPERUSER' : 'NOSUPERUSER', flags.has('-d') || flags.has('--createdb') ? 'CREATEDB' : 'NOCREATEDB', flags.has('-r') || flags.has('--createrole') ? 'CREATEROLE' : 'NOCREATEROLE', 'INHERIT', flags.has('-L') || flags.has('--no-login') ? 'NOLOGIN' : 'LOGIN'];
  if (flags.has('-P') || flags.has('--pwprompt')) {
    const a = ctx.ask('Enter password for new role: ', true);
    const b2 = ctx.ask('Enter it again: ', true);
    if (a !== b2) return { error: 'Passwords didn\'t match.' };
    opts.push(`PASSWORD '${a.replace(/'/g, "''")}'`);
  }
  return { sql: `CREATE ROLE ${q(n)} ${opts.join(' ')};` };
}, () => 'creation of new role', false);
const dropuser = wrapper('dropuser', 'remove a PostgreSQL role (DROP ROLE)', 'dropuser [-h HOST] [-U USER] ROLENAME', (rest) => (rest[0] ? { sql: `DROP ROLE ${q(rest[0])};` } : { error: 'missing required argument role name' }), (n) => `removal of role "${n}"`);
const createdb = wrapper('createdb', 'create a PostgreSQL database (CREATE DATABASE)', 'createdb [-O OWNER] [-h HOST] [-U USER] DBNAME', (rest, flags) => {
  const n = rest[0];
  if (!n) return { error: 'missing required argument database name' };
  const owner = (flags.get('-O') ?? flags.get('--owner'))?.[0];
  return { sql: `CREATE DATABASE ${q(n)}${owner ? ` OWNER ${q(owner)}` : ''};` };
}, () => 'database creation');
const dropdb = wrapper('dropdb', 'remove a PostgreSQL database (DROP DATABASE)', 'dropdb [-h HOST] [-U USER] DBNAME', (rest) => (rest[0] ? { sql: `DROP DATABASE ${q(rest[0])};` } : { error: 'missing required argument database name' }), () => 'database removal');

export const PG_COMMANDS: CommandDef[] = [psql, pgDump, pgRestore, pgDumpall, pgLsclusters, pgCtlcluster, pgIsready, createuser, createdb, dropuser, dropdb];
