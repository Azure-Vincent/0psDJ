// restic 0.14.0 (Debian 12): encrypted, deduplicating backups into a
// repository on a local path or on a backup server over SFTP.
//
// The repository is real files: config, keys/ (one per password, holding a
// salted hash), snapshots/ (one per backup: paths, host, tags and the file
// list), data/xx/ packs (file contents, each stored once by its SHA-256),
// index/ and locks/. So the permissions, the free space and the content of
// the backup server matter, and deleting or editing a pack is noticed by
// `restic check`. Real restic encrypts all of this; the simulator stores it
// as JSON so it can be inspected.

import { basename, canAccess, canTraverse, dirname } from '../fs';
import { noSpace } from '../sim/disk';
import type { FileNode, Host, UserAccount } from '../types';
import { sha256Hex } from '../util/sha256';
import { fileSize, globMatch, type Remote, sshTransport, subtree } from './cmdBackup';
import { getFile, resolvePath } from './cmdFiles';
import { type CmdCtx, type CmdResult, type CommandDef, err } from './types';

const VERSION = 'restic 0.14.0 compiled with go1.19.8 on linux/amd64';

interface SnapFile { p: string; t: 'f' | 'd'; m: number; o: string; g: string; u: number; gi: number; mt: number; h?: string; s?: number }
interface Snapshot { id: string; time: number; hostname: string; username: string; paths: string[]; tags: string[]; parent?: string; files: SnapFile[] }
interface Lock { time: number; exclusive: boolean; hostname: string; username: string; pid: number; uid: number; gid: number }

interface Repo {
  label: string;
  host: Host;
  user: UserAccount;
  path: string;
  sftp: boolean;
  conn?: Remote;
  id: string;
  lockId?: string;
}

class Fatal extends Error {
  constructor(msg: string, readonly code = 1) { super(msg); }
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(3)} ${units[i]}`;
}

const pad2 = (n: number) => String(n).padStart(2, '0');
function stamp(ms: number): string {
  const d = new Date(ms);
  return `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())} ${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}`;
}
const longStamp = (ms: number) => `${stamp(ms)}.${String(Math.floor(ms) % 1000).padStart(3, '0')} +0000 UTC`;
const short = (id: string) => id.slice(0, 8);
function agoText(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return `${h ? `${h}h` : ''}${h || m ? `${m}m` : ''}${s % 60}s`;
}

// ---------------------------------------------------------------------------
// Repository access (as the local user, or as the SFTP user on the server)
// ---------------------------------------------------------------------------

function ioError(repo: Repo, op: 'open' | 'write' | 'remove' | 'stat', path: string, why: 'denied' | 'missing' | 'space'): string {
  if (repo.sftp) return why === 'denied' ? `${op === 'write' ? 'OpenFile' : op === 'stat' ? 'Lstat' : 'Open'}: sftp: "Permission denied" (SSH_FX_PERMISSION_DENIED)` : why === 'space' ? `Write: sftp: "Failure" (SSH_FX_FAILURE)` : `${op === 'stat' ? 'Lstat' : 'Open'}: file does not exist`;
  const verb = op === 'write' ? 'open' : op === 'stat' ? 'stat' : op === 'remove' ? 'remove' : 'open';
  return `${verb} ${path}: ${why === 'denied' ? 'permission denied' : why === 'space' ? 'no space left on device' : 'no such file or directory'}`;
}

function repoRead(repo: Repo, rel: string): string {
  const p = `${repo.path}/${rel}`;
  const n = repo.host.fs[p];
  if (!n) throw new Fatal(ioError(repo, 'open', p, 'missing'));
  if (!canTraverse(repo.host, p, repo.user) || !canAccess(n, repo.user, 'r')) throw new Fatal(ioError(repo, 'open', p, 'denied'));
  return n.content;
}

function repoList(repo: Repo, rel: string): string[] {
  const base = `${repo.path}/${rel}`;
  const d = repo.host.fs[base];
  if (!d) return [];
  if (!canTraverse(repo.host, base, repo.user) || !canAccess(d, repo.user, 'r')) throw new Fatal(ioError(repo, 'open', base, 'denied'));
  const pre = base + '/';
  return Object.keys(repo.host.fs).filter((p) => p.startsWith(pre) && repo.host.fs[p].type === 'file').map((p) => p.slice(pre.length));
}

function repoWrite(ctx: CmdCtx, repo: Repo, rel: string, content: string, size?: number): void {
  const p = `${repo.path}/${rel}`;
  const parents: string[] = [];
  for (let d = dirname(p); !repo.host.fs[d]; d = dirname(d)) parents.unshift(d);
  const first = parents.length ? dirname(parents[0]) : dirname(p);
  const parent = repo.host.fs[first];
  if (!parent || !canTraverse(repo.host, first + '/x', repo.user) || !canAccess(parent, repo.user, 'w')) throw new Fatal(ioError(repo, 'write', p, 'denied'));
  if (noSpace(repo.host, p, size ?? content.length)) throw new Fatal(ioError(repo, 'write', p, 'space'));
  for (const d of parents) repo.host.fs[d] = { type: 'dir', mode: 0o700, owner: repo.user.name, group: repo.user.primaryGroup, content: '', mtime: ctx.world.clock };
  repo.host.fs[p] = { type: 'file', mode: 0o600, owner: repo.user.name, group: repo.user.primaryGroup, content, mtime: ctx.world.clock, ...(size !== undefined ? { size } : {}) };
}

function repoRemove(repo: Repo, rel: string): void {
  const p = `${repo.path}/${rel}`;
  const parent = repo.host.fs[dirname(p)];
  if (parent && !canAccess(parent, repo.user, 'w')) throw new Fatal(ioError(repo, 'remove', p, 'denied'));
  delete repo.host.fs[p];
}

/** Deterministic IDs: the world's monotonic counter makes every call unique. */
const newId = (ctx: CmdCtx, kind: string, salt = '') => sha256Hex(`${kind}:${ctx.host.id}:${ctx.world.clock}:${ctx.world.counter++}:${salt}`);

// ---------------------------------------------------------------------------
// Options, repository and password
// ---------------------------------------------------------------------------

interface Opts { flags: Map<string, string[]>; rest: string[] }
const VALUE = new Set(['-r', '--repo', '--repository-file', '-p', '--password-file', '--exclude', '-e', '--exclude-file', '--tag', '--host', '-H', '--path', '--target', '-t', '--include', '-i', '--keep-last', '--keep-hourly', '--keep-daily', '--keep-weekly', '--keep-monthly', '--keep-yearly', '--keep-within', '--keep-tag', '--stdin-filename', '--mode', '--cache-dir', '--latest', '--group-by', '--read-data-subset', '--option', '-o', '--files-from', '--compression', '--max-unused', '--parent']);
/** Short options that take a value only in `restic forget` (-l is --long elsewhere). */
const FORGET_SHORT = ['-l', '-d', '-w', '-m', '-y'];

function parseOpts(args: string[], forget = false): Opts {
  const flags = new Map<string, string[]>();
  const rest: string[] = [];
  const add = (k: string, v: string) => flags.set(k, [...(flags.get(k) ?? []), v]);
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--') { rest.push(...args.slice(i + 1)); break; }
    if (a.startsWith('--') && a.includes('=')) { const k = a.slice(0, a.indexOf('=')); add(k, a.slice(a.indexOf('=') + 1)); continue; }
    if (a.startsWith('-') && a.length > 1) {
      if (VALUE.has(a) || (forget && FORGET_SHORT.includes(a))) { add(a, args[++i] ?? ''); continue; }
      add(a, '');
      continue;
    }
    rest.push(a);
  }
  return { flags, rest };
}

const one = (o: Opts, ...names: string[]) => { for (const n of names) { const v = o.flags.get(n); if (v) return v[v.length - 1]; } return undefined; };
const all = (o: Opts, ...names: string[]) => names.flatMap((n) => o.flags.get(n) ?? []);
const has = (o: Opts, ...names: string[]) => names.some((n) => o.flags.has(n));
const nonInteractive = (ctx: CmdCtx) => !!ctx.env.INVOCATION_ID;

function repoSpec(ctx: CmdCtx, o: Opts): string {
  let spec = one(o, '-r', '--repo') ?? ctx.env.RESTIC_REPOSITORY;
  const file = one(o, '--repository-file') ?? ctx.env.RESTIC_REPOSITORY_FILE;
  if (!spec && file) {
    const f = getFile(ctx, resolvePath(ctx, file));
    if (f.error) throw new Fatal(f.error === 'No such file or directory' ? `${file} does not exist` : `Readfile: open ${file}: ${f.error.toLowerCase()}`);
    spec = (f.content ?? '').trim();
  }
  if (!spec) throw new Fatal('Please specify repository location (-r or --repository-file)');
  return spec;
}

function connect(ctx: CmdCtx, spec: string): Repo {
  const sftp = /^sftp:(?:([^@:/]+)@)?([^:/]+):(.*)$/.exec(spec);
  if (sftp) {
    const t = sshTransport(ctx, sftp[2], sftp[1], { batch: nonInteractive(ctx) });
    if ('error' in t) {
      const lines = t.error.out.split('\n').filter(Boolean).map((l) => `subprocess ssh: ${l}`);
      const fatal = `unable to open repository at ${spec}: unable to start the sftp session, error: EOF`;
      throw new Fatal(lines.length ? `${lines.join('\n')}\nFatal: ${fatal}` : fatal);
    }
    const host = ctx.world.hosts[t.hostId];
    const user = host.users[t.user];
    const path = sftp[3].startsWith('/') ? sftp[3] : `${user.home}/${sftp[3]}`;
    return { label: spec, host, user, path: path.replace(/\/+$/, ''), sftp: true, conn: t, id: '' };
  }
  if (/^(s3|b2|azure|gs|rest|rclone|swift):/.test(spec)) throw new Fatal(`the ${spec.split(':')[0]} backend is not modelled in the simulator (use a local path or sftp:)`);
  const local = spec.startsWith('local:') ? spec.slice(6) : spec;
  return { label: spec, host: ctx.host, user: ctx.user, path: resolvePath(ctx, local).replace(/\/+$/, '') || '/', sftp: false, id: '' };
}

function readPassword(ctx: CmdCtx, o: Opts, prompt = 'enter password for repository: '): string {
  const file = one(o, '-p', '--password-file') ?? ctx.env.RESTIC_PASSWORD_FILE;
  if (file) {
    const path = resolvePath(ctx, file);
    const f = getFile(ctx, path);
    if (f.error === 'No such file or directory') throw new Fatal(`${file} does not exist`);
    if (f.error) throw new Fatal(`Readfile: open ${file}: ${f.error.toLowerCase()}`);
    return (f.content ?? '').trim();
  }
  if (ctx.env.RESTIC_PASSWORD !== undefined) return ctx.env.RESTIC_PASSWORD;
  if (nonInteractive(ctx)) throw new Fatal('an empty password is not a password');
  const pw = ctx.ask(prompt, true);
  if (!pw) throw new Fatal('an empty password is not a password');
  return pw;
}

const keyHash = (salt: string, pw: string) => sha256Hex(`restic-key:${salt}:${pw}`);

/** Open the repository: config, then a key that the password unlocks. */
function open(ctx: CmdCtx, o: Opts, out: string[]): Repo {
  const spec = repoSpec(ctx, o);
  const repo = connect(ctx, spec);
  let config: string;
  try {
    config = repoRead(repo, 'config');
  } catch (e) {
    repo.conn?.done();
    const missing = !repo.host.fs[`${repo.path}/config`];
    if (missing) throw new Fatal(`unable to open config file: ${repo.sftp ? 'Lstat: file does not exist' : `Stat: stat ${repo.path}/config: no such file or directory`}\nIs there a repository at the following location?\n${spec}`);
    throw new Fatal(`unable to open config file: ${(e as Error).message}`);
  }
  let pw: string;
  try {
    pw = readPassword(ctx, o);
  } catch (e) {
    repo.conn?.done();
    throw e;
  }
  const keys = repoList(repo, 'keys');
  const ok = keys.some((k) => {
    try {
      const j = JSON.parse(repoRead(repo, `keys/${k}`)) as { salt: string; hash: string };
      return j.hash === keyHash(j.salt, pw);
    } catch { return false; }
  });
  if (!ok) { repo.conn?.done(); throw new Fatal('wrong password or no key found'); }
  try { repo.id = (JSON.parse(config.slice(config.indexOf('\n') + 1)) as { id: string }).id; } catch { repo.id = sha256Hex(config); }
  if (!has(o, '-q', '--quiet', '--json')) out.push(`repository ${short(repo.id)} opened (version 2, compression level auto)`);
  return repo;
}

function lock(ctx: CmdCtx, repo: Repo, exclusive: boolean, o: Opts, out: string[]): void {
  if (has(o, '--no-lock')) return;
  if (exclusive && !has(o, '-q', '--quiet')) out.push('create exclusive lock for repository');
  for (const id of repoList(repo, 'locks')) {
    let l: Lock;
    try { l = JSON.parse(repoRead(repo, `locks/${id}`)) as Lock; } catch { continue; }
    if (exclusive || l.exclusive) {
      throw new Fatal(`unable to create lock in backend: repository is already locked ${l.exclusive ? 'exclusively ' : ''}by PID ${l.pid} on ${l.hostname} by ${l.username} (UID ${l.uid}, GID ${l.gid})\nlock was created at ${stamp(l.time)} (${agoText(ctx.world.clock - l.time)} ago)\nstorage ID ${short(id)}\nthe \`unlock\` command can be used to remove stale locks`.replace(/^/, 'NOFATAL'));
    }
  }
  const pid = (ctx.host.nextPid += 3);
  const l: Lock = { time: ctx.world.clock, exclusive, hostname: ctx.host.hostname, username: ctx.user.name, pid, uid: ctx.user.uid, gid: ctx.user.gid };
  repo.lockId = newId(ctx, 'lock');
  repoWrite(ctx, repo, `locks/${repo.lockId}`, JSON.stringify(l));
}

function close(repo: Repo): void {
  if (repo.lockId) delete repo.host.fs[`${repo.path}/locks/${repo.lockId}`];
  repo.conn?.done();
}

// ---------------------------------------------------------------------------
// Snapshots, index and packs
// ---------------------------------------------------------------------------

function loadSnapshots(repo: Repo): Snapshot[] {
  const out: Snapshot[] = [];
  for (const id of repoList(repo, 'snapshots')) {
    try { out.push({ ...(JSON.parse(repoRead(repo, `snapshots/${id}`)) as Snapshot), id }); } catch { /* unreadable snapshot files are reported by check */ }
  }
  return out.sort((a, b) => a.time - b.time);
}

function loadIndex(repo: Repo): Map<string, string> {
  const blobToPack = new Map<string, string>();
  for (const id of repoList(repo, 'index')) {
    try {
      const j = JSON.parse(repoRead(repo, `index/${id}`)) as { packs: Record<string, string[]> };
      for (const [pack, blobs] of Object.entries(j.packs)) for (const b of blobs) blobToPack.set(b, pack);
    } catch { /* ignored */ }
  }
  return blobToPack;
}

function readBlob(repo: Repo, blobToPack: Map<string, string>, h: string): string {
  const pack = blobToPack.get(h);
  if (!pack) throw new Fatal(`blob ${short(h)} not found in index`);
  const rel = `data/${pack.slice(0, 2)}/${pack}`;
  if (!repo.host.fs[`${repo.path}/${rel}`]) throw new Fatal(`load blob ${short(h)}: pack ${short(pack)} does not exist`);
  const j = JSON.parse(repoRead(repo, rel)) as { blobs: Record<string, string> };
  const c = j.blobs[h];
  if (c === undefined) throw new Fatal(`load blob ${short(h)}: not found in pack ${short(pack)}`);
  return c;
}

function findSnapshot(snaps: Snapshot[], ref: string, o: Opts): Snapshot {
  let pool = snaps;
  const hostF = all(o, '--host', '-H');
  const pathF = all(o, '--path');
  const tagF = all(o, '--tag');
  if (ref === 'latest') {
    if (hostF.length) pool = pool.filter((s) => hostF.includes(s.hostname));
    if (pathF.length) pool = pool.filter((s) => pathF.every((p) => s.paths.includes(p)));
    if (tagF.length) pool = pool.filter((s) => tagF.some((t) => s.tags.includes(t)));
    const s = pool.at(-1);
    if (!s) throw new Fatal('latest snapshot: no snapshot found');
    return s;
  }
  const hits = snaps.filter((s) => s.id.startsWith(ref));
  if (hits.length === 1) return hits[0];
  if (hits.length > 1) throw new Fatal(`find snapshot: multiple IDs with prefix "${ref}" found`);
  throw new Fatal(`find snapshot: no matching ID found for prefix "${ref}"`);
}

function snapTable(snaps: Snapshot[], reasons?: Map<string, string[]>): string[] {
  const rows = snaps.map((s) => ({ id: short(s.id), time: stamp(s.time), host: s.hostname, tags: s.tags.join(','), reasons: reasons?.get(s.id) ?? [], paths: [...s.paths].sort() }));
  const hostW = Math.max(10, ...rows.map((r) => r.host.length));
  const tagW = Math.max(10, ...rows.map((r) => r.tags.length));
  const rsW = reasons ? Math.max(14, ...rows.flatMap((r) => r.reasons.map((x) => x.length))) : 0;
  const head = `ID        Time                 ${'Host'.padEnd(hostW)}  ${'Tags'.padEnd(tagW)}  ${reasons ? 'Reasons'.padEnd(rsW) + '  ' : ''}Paths`;
  const sep = '-'.repeat(head.length + 10);
  const out = [head, sep];
  for (const r of rows) {
    const lines = Math.max(r.paths.length, r.reasons.length, 1);
    for (let i = 0; i < lines; i++) {
      out.push(i === 0
        ? `${r.id}  ${r.time}  ${r.host.padEnd(hostW)}  ${r.tags.padEnd(tagW)}  ${reasons ? (r.reasons[0] ?? '').padEnd(rsW) + '  ' : ''}${r.paths[0] ?? ''}`
        : `${''.padEnd(8)}  ${''.padEnd(19)}  ${''.padEnd(hostW)}  ${''.padEnd(tagW)}  ${reasons ? (r.reasons[i] ?? '').padEnd(rsW) + '  ' : ''}${r.paths[i] ?? ''}`);
    }
  }
  out.push(sep, `${snaps.length} snapshots`);
  return out.map((l) => l.replace(/\s+$/, ''));
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

function cmdInit(ctx: CmdCtx, o: Opts, out: string[]): number {
  const spec = repoSpec(ctx, o);
  const repo = connect(ctx, spec);
  try {
    if (repo.host.fs[`${repo.path}/config`]) throw new Fatal(`create repository at ${spec} failed: Fatal: config file already exists`);
    const file = one(o, '-p', '--password-file') ?? ctx.env.RESTIC_PASSWORD_FILE;
    let pw: string;
    if (file || ctx.env.RESTIC_PASSWORD !== undefined || nonInteractive(ctx)) pw = readPassword(ctx, o);
    else {
      pw = ctx.ask('enter password for new repository: ', true);
      const again = ctx.ask('enter password again: ', true);
      if (pw !== again) throw new Fatal('passwords do not match');
      if (!pw) throw new Fatal('an empty password is not a password');
    }
    // The repository directory itself (like mkdir -p, as the repository user).
    const parents: string[] = [];
    for (let d = repo.path; !repo.host.fs[d]; d = dirname(d)) parents.unshift(d);
    const top = parents.length ? dirname(parents[0]) : repo.path;
    if (parents.length && !canAccess(repo.host.fs[top], repo.user, 'w')) throw new Fatal(`create repository at ${spec} failed: Fatal: unable to open repository at ${spec}: ${repo.sftp ? 'MkdirAll: sftp: "Permission denied" (SSH_FX_PERMISSION_DENIED)' : `mkdir ${parents[0]}: permission denied`}`);
    for (const d of parents) repo.host.fs[d] = { type: 'dir', mode: 0o700, owner: repo.user.name, group: repo.user.primaryGroup, content: '', mtime: ctx.world.clock };
    if (!canAccess(repo.host.fs[repo.path], repo.user, 'w')) throw new Fatal(`create repository at ${spec} failed: Fatal: ${repo.sftp ? 'Mkdir: sftp: "Permission denied" (SSH_FX_PERMISSION_DENIED)' : `mkdir ${repo.path}/data: permission denied`}`);
    const id = newId(ctx, 'repo', spec);
    for (const d of ['data', 'index', 'keys', 'locks', 'snapshots']) repo.host.fs[`${repo.path}/${d}`] = { type: 'dir', mode: 0o700, owner: repo.user.name, group: repo.user.primaryGroup, content: '', mtime: ctx.world.clock };
    repoWrite(ctx, repo, 'config', `(restic repository config: encrypted in a real repository)\n${JSON.stringify({ version: 2, id, chunker_polynomial: '3da3358b4dc173' })}`, 155);
    const salt = newId(ctx, 'salt').slice(0, 32);
    repoWrite(ctx, repo, `keys/${newId(ctx, 'key')}`, JSON.stringify({ created: new Date(ctx.world.clock).toISOString(), username: ctx.user.name, hostname: ctx.host.hostname, kdf: 'scrypt', N: 32768, r: 8, p: 6, salt, hash: keyHash(salt, pw) }), 460);
    out.push(`created restic repository ${short(id)} at ${spec}`, '', 'Please note that knowledge of your password is required to access', 'the repository. Losing your password means that your data is', 'irrecoverably lost.');
    return 0;
  } finally {
    repo.conn?.done();
  }
}

function cmdBackup(ctx: CmdCtx, o: Opts, out: string[]): number {
  const repo = open(ctx, o, out);
  try {
    lock(ctx, repo, false, o, out);
    const quiet = has(o, '-q', '--quiet');
    const excludes = [...all(o, '--exclude', '-e')];
    for (const f of all(o, '--exclude-file')) {
      const r = getFile(ctx, resolvePath(ctx, f));
      if (r.error) throw new Fatal(`failed to read exclude file ${f}: open ${f}: ${r.error.toLowerCase()}`);
      excludes.push(...(r.content ?? '').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')));
    }
    const excluded = (p: string) => excludes.some((pat) => (pat.includes('/') ? globMatch(pat, p) || p.startsWith(pat.replace(/\/$/, '') + '/') : basename(p) === pat || globMatch(pat, basename(p))));
    const files: SnapFile[] = [];
    const contents = new Map<string, { content: string; size: number }>();
    const warnings: string[] = [];
    let paths: string[];
    if (has(o, '--stdin')) {
      const name = one(o, '--stdin-filename') ?? 'stdin';
      const content = ctx.stdin ?? '';
      const h = sha256Hex(content);
      contents.set(h, { content, size: content.length });
      paths = [`/${name}`];
      files.push({ p: `/${name}`, t: 'f', m: 0o644, o: ctx.user.name, g: ctx.user.primaryGroup, u: ctx.user.uid, gi: ctx.user.gid, mt: ctx.world.clock, h, s: content.length });
    } else {
      const given = [...o.rest];
      for (const f of all(o, '--files-from')) {
        const r = getFile(ctx, resolvePath(ctx, f));
        if (!r.error) given.push(...(r.content ?? '').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')));
      }
      if (!given.length) throw new Fatal('nothing to backup, please specify target files/dirs');
      paths = given.map((g) => resolvePath(ctx, g).replace(/\/+$/, '') || '/');
      const existing = paths.filter((p) => ctx.host.fs[p]);
      for (const p of paths.filter((x) => !ctx.host.fs[x])) warnings.push(`error: lstat ${p}: no such file or directory`);
      if (!existing.length) throw new Fatal('all target directories/files do not exist');
      for (const root of existing) {
        if (excluded(root)) continue;
        // The parent directories of each target are part of the snapshot tree.
        for (let d = dirname(root); d !== '/' && !files.some((f) => f.p === d); d = dirname(d)) {
          const n = ctx.host.fs[d];
          if (n) files.push({ p: d, t: 'd', m: n.mode & 0o7777, o: n.owner, g: n.group, u: ctx.host.users[n.owner]?.uid ?? 0, gi: ctx.host.users[n.owner]?.gid ?? 0, mt: n.mtime });
        }
        const skip: string[] = [];
        for (const p of subtree(ctx.host, root)) {
          if (skip.some((s) => p.startsWith(s + '/'))) continue;
          const n: FileNode = ctx.host.fs[p];
          if (p !== root && excluded(p)) { if (n.type === 'dir') skip.push(p); continue; }
          if (n.socket) continue;
          if (!canTraverse(ctx.host, p, ctx.user) || !canAccess(n, ctx.user, 'r') || (n.type === 'dir' && !canAccess(n, ctx.user, 'x'))) {
            warnings.push(`error: open ${p}: permission denied`);
            if (n.type === 'dir') skip.push(p);
            continue;
          }
          const ou = ctx.host.users[n.owner];
          const f: SnapFile = { p, t: n.type === 'dir' ? 'd' : 'f', m: n.mode & 0o7777, o: n.owner, g: n.group, u: ou?.uid ?? 0, gi: ou?.gid ?? 0, mt: n.mtime };
          if (n.type === 'file') {
            const h = sha256Hex(n.content + (n.size !== undefined ? `\u0000${n.size}` : ''));
            contents.set(h, { content: n.content, size: fileSize(n) });
            f.h = h;
            f.s = fileSize(n);
          }
          files.push(f);
        }
      }
    }
    const snaps = loadSnapshots(repo);
    const hostname = one(o, '--host', '-H') ?? ctx.host.hostname;
    const key = [...paths].sort().join('\n');
    const parent = [...snaps].reverse().find((s) => s.hostname === hostname && [...s.paths].sort().join('\n') === key);
    if (!quiet) out.push(parent ? `using parent snapshot ${short(parent.id)}` : 'no parent snapshot found, will read all files');
    const prev = new Map((parent?.files ?? []).map((f) => [f.p, f]));
    const index = loadIndex(repo);
    const count = { f: [0, 0, 0], d: [0, 0, 0] };
    for (const f of files) {
      const p = prev.get(f.p);
      const changed = p && (p.h !== f.h || p.m !== f.m || p.o !== f.o || p.mt !== f.mt);
      const slot = !p ? 0 : changed ? 1 : 2;
      count[f.t === 'd' ? 'd' : 'f'][slot]++;
    }
    const newBlobs = [...contents.entries()].filter(([h]) => !index.has(h));
    const added = newBlobs.reduce((n, [, c]) => n + c.size, 0) + 360 * (count.d[0] + count.d[1] + 1);
    const stored = Math.round(newBlobs.reduce((n, [, c]) => n + Math.max(32, c.size * 0.42), 0)) + 180 * (count.d[0] + count.d[1] + 1);
    for (const w of warnings) out.push(w);
    if (!quiet) out.push('', `Files:       ${String(count.f[0]).padStart(5)} new, ${String(count.f[1]).padStart(5)} changed, ${String(count.f[2]).padStart(5)} unmodified`, `Dirs:        ${String(count.d[0]).padStart(5)} new, ${String(count.d[1]).padStart(5)} changed, ${String(count.d[2]).padStart(5)} unmodified`, `Added to the repository: ${fmtBytes(added)} (${fmtBytes(stored)} stored)`, '');
    try {
      if (newBlobs.length) {
        const pack = newId(ctx, 'pack');
        repoWrite(ctx, repo, `data/${pack.slice(0, 2)}/${pack}`, JSON.stringify({ blobs: Object.fromEntries(newBlobs.map(([h, c]) => [h, c.content])) }), stored);
        repoWrite(ctx, repo, `index/${newId(ctx, 'index')}`, JSON.stringify({ packs: { [pack]: newBlobs.map(([h]) => h) } }), 200 + 80 * newBlobs.length);
      }
      const id = newId(ctx, 'snapshot', key);
      const snap: Snapshot = { id, time: ctx.world.clock, hostname, username: ctx.user.name, paths, tags: all(o, '--tag').flatMap((t) => t.split(',')).filter(Boolean), ...(parent ? { parent: parent.id } : {}), files };
      repoWrite(ctx, repo, `snapshots/${id}`, JSON.stringify(snap), 300 + 40 * files.length);
      const total = files.reduce((n, f) => n + (f.s ?? 0), 0);
      if (!quiet) out.push(`processed ${count.f[0] + count.f[1] + count.f[2]} files, ${fmtBytes(total)} in 0:0${Math.min(9, 1 + Math.floor(total / 400_000))}`, `snapshot ${short(id)} saved`);
    } catch (e) {
      if (e instanceof Fatal) throw new Fatal(`unable to save snapshot: ${e.message}`);
      throw e;
    }
    if (warnings.length) { out.push('Warning: at least one source file could not be read'); return 3; }
    return 0;
  } finally {
    close(repo);
  }
}

function cmdSnapshots(ctx: CmdCtx, o: Opts, out: string[]): number {
  const repo = open(ctx, o, out);
  try {
    lock(ctx, repo, false, o, out);
    let snaps = loadSnapshots(repo);
    const hostF = all(o, '--host', '-H');
    const tagF = all(o, '--tag');
    const pathF = all(o, '--path');
    if (hostF.length) snaps = snaps.filter((s) => hostF.includes(s.hostname));
    if (tagF.length) snaps = snaps.filter((s) => tagF.some((t) => s.tags.includes(t)));
    if (pathF.length) snaps = snaps.filter((s) => pathF.every((p) => s.paths.includes(p)));
    const latest = one(o, '--latest');
    if (latest) snaps = snaps.slice(-Number(latest));
    if (has(o, '--json')) {
      out.push(JSON.stringify(snaps.map((s) => ({ time: new Date(s.time).toISOString(), ...(s.parent ? { parent: s.parent } : {}), paths: s.paths, hostname: s.hostname, username: s.username, ...(s.tags.length ? { tags: s.tags } : {}), id: s.id, short_id: short(s.id) }))));
      return 0;
    }
    out.push(...snapTable(snaps));
    return 0;
  } finally {
    close(repo);
  }
}

function cmdLs(ctx: CmdCtx, o: Opts, out: string[]): number {
  const repo = open(ctx, o, out);
  try {
    lock(ctx, repo, false, o, out);
    const [ref, ...filters] = o.rest;
    if (!ref) throw new Fatal('no snapshot ID specified');
    const s = findSnapshot(loadSnapshots(repo), ref, o);
    const long = has(o, '-l', '--long');
    out.push(`snapshot ${short(s.id)} of [${s.paths.join(' ')}] filtered by [${filters.join(' ')}] at ${longStamp(s.time)}):`);
    for (const f of s.files) {
      if (filters.length && !filters.some((x) => f.p === x || f.p.startsWith(x.replace(/\/$/, '') + '/'))) continue;
      if (!long) { out.push(f.p); continue; }
      const perm = `${f.t === 'd' ? 'd' : '-'}${[6, 3, 0].map((sh) => { const b = (f.m >> sh) & 7; return `${b & 4 ? 'r' : '-'}${b & 2 ? 'w' : '-'}${b & 1 ? 'x' : '-'}`; }).join('')}`;
      out.push(`${perm} ${String(f.u).padStart(5)} ${String(f.gi).padStart(5)} ${String(f.t === 'd' ? 0 : f.s ?? 0).padStart(6)} ${stamp(f.mt)} ${f.p}`);
    }
    return 0;
  } finally {
    close(repo);
  }
}

function cmdRestore(ctx: CmdCtx, o: Opts, out: string[]): number {
  const repo = open(ctx, o, out);
  try {
    lock(ctx, repo, false, o, out);
    const ref = o.rest[0];
    if (!ref) throw new Fatal('no snapshot ID specified');
    const targetArg = one(o, '--target', '-t');
    if (!targetArg) throw new Fatal('please specify a directory to restore to (--target)');
    const s = findSnapshot(loadSnapshots(repo), ref, o);
    const target = resolvePath(ctx, targetArg).replace(/\/+$/, '') || '/';
    const includes = all(o, '--include', '-i');
    const excludes = all(o, '--exclude', '-e');
    const matches = (p: string, pats: string[]) => pats.some((pat) => p === pat.replace(/\/$/, '') || p.startsWith(pat.replace(/\/$/, '') + '/') || globMatch(pat, p) || globMatch(pat, basename(p)));
    const parentOf = (p: string, pats: string[]) => pats.some((pat) => pat.startsWith(p + '/'));
    out.push(`restoring <Snapshot ${short(s.id)} of [${s.paths.join(' ')}] at ${longStamp(s.time)} by ${s.username}@${s.hostname}> to ${target}`);
    const index = loadIndex(repo);
    const errors: string[] = [];
    // Make the target (restic creates it).
    if (!ctx.host.fs[target]) {
      const parent = ctx.host.fs[dirname(target)];
      if (!parent || !canAccess(parent, ctx.user, 'w')) throw new Fatal(`mkdir ${target}: ${parent ? 'permission denied' : 'no such file or directory'}`);
      ctx.host.fs[target] = { type: 'dir', mode: 0o700, owner: ctx.user.name, group: ctx.user.primaryGroup, content: '', mtime: ctx.world.clock };
    }
    const root = ctx.user.uid === 0;
    const dirs: SnapFile[] = [];
    for (const f of s.files) {
      if (includes.length && !matches(f.p, includes) && !(f.t === 'd' && parentOf(f.p, includes))) continue;
      if (excludes.length && matches(f.p, excludes)) continue;
      const dest = `${target === '/' ? '' : target}${f.p}`;
      for (let d = dirname(dest); !ctx.host.fs[d]; d = dirname(d)) ctx.host.fs[d] = { type: 'dir', mode: 0o755, owner: ctx.user.name, group: ctx.user.primaryGroup, content: '', mtime: ctx.world.clock };
      const parent = ctx.host.fs[dirname(dest)];
      if (parent && !canAccess(parent, ctx.user, 'w') && !root) { errors.push(`ignoring error for ${f.p}: open ${dest}: permission denied`); continue; }
      if (f.t === 'd') {
        if (!ctx.host.fs[dest]) ctx.host.fs[dest] = { type: 'dir', mode: 0o700, owner: ctx.user.name, group: ctx.user.primaryGroup, content: '', mtime: ctx.world.clock };
        dirs.push(f);
        continue;
      }
      let content: string;
      try { content = readBlob(repo, index, f.h!); } catch (e) { errors.push(`ignoring error for ${f.p}: ${(e as Error).message}`); continue; }
      ctx.world.clock += 2;
      ctx.host.fs[dest] = { type: 'file', content, ...(f.s !== undefined && f.s !== content.length ? { size: f.s } : {}), mode: f.m, owner: root && ctx.host.users[f.o] ? f.o : ctx.user.name, group: root ? f.g : ctx.user.primaryGroup, mtime: f.mt };
    }
    // Directory metadata last (restic sets it after the contents).
    for (const f of dirs) Object.assign(ctx.host.fs[`${target === '/' ? '' : target}${f.p}`], { mode: f.m, owner: root && ctx.host.users[f.o] ? f.o : ctx.user.name, group: root ? f.g : ctx.user.primaryGroup, mtime: f.mt });
    if (errors.length) { out.push(...errors); throw new Fatal(`There were ${errors.length} errors`); }
    return 0;
  } finally {
    close(repo);
  }
}

/** restic's retention policy: keep the newest snapshot of each of the last N hours/days/weeks/months/years. */
function applyPolicy(snaps: Snapshot[], p: Record<string, number>, within: number | null, keepTags: string[], now: number): { keep: Snapshot[]; remove: Snapshot[]; reasons: Map<string, string[]> } {
  const newest = [...snaps].sort((a, b) => b.time - a.time);
  const reasons = new Map<string, string[]>();
  const add = (s: Snapshot, r: string) => reasons.set(s.id, [...(reasons.get(s.id) ?? []), r]);
  const bucket: Record<string, (t: number) => string> = {
    hourly: (t) => new Date(t).toISOString().slice(0, 13),
    daily: (t) => new Date(t).toISOString().slice(0, 10),
    weekly: (t) => { const d = new Date(t); const day = (d.getUTCDay() + 6) % 7; const mon = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() - day)); return mon.toISOString().slice(0, 10); },
    monthly: (t) => new Date(t).toISOString().slice(0, 7),
    yearly: (t) => new Date(t).toISOString().slice(0, 4),
  };
  if (p.last) newest.slice(0, p.last).forEach((s) => add(s, 'last snapshot'));
  for (const kind of ['hourly', 'daily', 'weekly', 'monthly', 'yearly']) {
    const n = p[kind];
    if (!n) continue;
    const seen = new Set<string>();
    for (const s of newest) {
      if (seen.size >= n) break;
      const b = bucket[kind](s.time);
      if (seen.has(b)) continue;
      seen.add(b);
      add(s, `${kind} snapshot`);
    }
  }
  if (within !== null) for (const s of newest) if (now - s.time <= within) add(s, 'within');
  for (const s of newest) if (keepTags.some((t) => s.tags.includes(t))) add(s, 'has tags');
  return { keep: newest.filter((s) => reasons.has(s.id)), remove: newest.filter((s) => !reasons.has(s.id)), reasons };
}

function prune(ctx: CmdCtx, repo: Repo, dry: boolean, out: string[]): void {
  const snaps = loadSnapshots(repo);
  const used = new Set(snaps.flatMap((s) => s.files.map((f) => f.h).filter((h): h is string => !!h)));
  out.push('loading indexes...', 'loading all snapshots...', `finding data that is still in use for ${snaps.length} snapshots`, `[0:00] 100.00%  ${snaps.length} / ${snaps.length} snapshots`, 'searching used packs...', 'collecting packs for deletion and repacking');
  const packs = repoList(repo, 'data').map((rel) => rel.split('/').pop()!);
  let delBlobs = 0, delBytes = 0, repackBlobs = 0, repackBytes = 0, removeRepack = 0, removeRepackBytes = 0, remainBlobs = 0, remainBytes = 0;
  const toDelete: string[] = [];
  const toRepack: { pack: string; keep: Record<string, string>; size: number }[] = [];
  for (const pack of packs) {
    const rel = `data/${pack.slice(0, 2)}/${pack}`;
    const node = repo.host.fs[`${repo.path}/${rel}`];
    let blobs: Record<string, string>;
    try { blobs = (JSON.parse(repoRead(repo, rel)) as { blobs: Record<string, string> }).blobs; } catch { continue; }
    const hs = Object.keys(blobs);
    const live = hs.filter((h) => used.has(h));
    const size = node ? fileSize(node) : 0;
    const per = hs.length ? size / hs.length : 0;
    if (!live.length) { toDelete.push(pack); delBlobs += hs.length; delBytes += size; continue; }
    if (live.length < hs.length) {
      toRepack.push({ pack, keep: Object.fromEntries(live.map((h) => [h, blobs[h]])), size: Math.round(per * live.length) });
      repackBlobs += live.length;
      repackBytes += Math.round(per * live.length);
      removeRepack += hs.length - live.length;
      removeRepackBytes += Math.round(per * (hs.length - live.length));
    }
    remainBlobs += live.length;
    remainBytes += Math.round(per * live.length);
  }
  out.push(`[0:00] 100.00%  ${packs.length} / ${packs.length} packs processed`, '',
    `to repack:     ${String(repackBlobs).padStart(9)} blobs / ${fmtBytes(repackBytes)}`,
    `this removes:  ${String(removeRepack).padStart(9)} blobs / ${fmtBytes(removeRepackBytes)}`,
    `to delete:     ${String(delBlobs).padStart(9)} blobs / ${fmtBytes(delBytes)}`,
    `total prune:   ${String(delBlobs + removeRepack).padStart(9)} blobs / ${fmtBytes(delBytes + removeRepackBytes)}`,
    `remaining:     ${String(remainBlobs).padStart(9)} blobs / ${fmtBytes(remainBytes)}`,
    `unused size after prune: 0 B (0.00% of remaining size)`, '');
  if (dry) { out.push('Would have made the following changes:'); return; }
  for (const r of toRepack) {
    const np = newId(ctx, 'pack');
    repoWrite(ctx, repo, `data/${np.slice(0, 2)}/${np}`, JSON.stringify({ blobs: r.keep }), r.size);
    toDelete.push(r.pack);
  }
  if (toRepack.length) out.push('repacking packs', `[0:00] 100.00%  ${toRepack.length} / ${toRepack.length} packs repacked`);
  // Rebuild the index from the packs that remain.
  for (const id of repoList(repo, 'index')) repoRemove(repo, `index/${id}`);
  for (const pack of toDelete) repoRemove(repo, `data/${pack.slice(0, 2)}/${pack}`);
  const packsNow: Record<string, string[]> = {};
  for (const rel of repoList(repo, 'data')) {
    const pack = rel.split('/').pop()!;
    try { packsNow[pack] = Object.keys((JSON.parse(repoRead(repo, `data/${rel}`)) as { blobs: Record<string, string> }).blobs); } catch { /* skipped */ }
  }
  repoWrite(ctx, repo, `index/${newId(ctx, 'index')}`, JSON.stringify({ packs: packsNow }), 200 + 80 * Object.values(packsNow).flat().length);
  out.push('rebuilding index', `[0:00] 100.00%  ${Object.keys(packsNow).length} / ${Object.keys(packsNow).length} packs processed`, 'deleting obsolete index files');
  if (toDelete.length) out.push(`removing ${toDelete.length} old packs`, `[0:00] 100.00%  ${toDelete.length} / ${toDelete.length} files deleted`);
  out.push('done');
}

function cmdForget(ctx: CmdCtx, o: Opts, out: string[]): number {
  const repo = open(ctx, o, out);
  try {
    lock(ctx, repo, true, o, out);
    const dry = has(o, '-n', '--dry-run');
    const snaps = loadSnapshots(repo);
    const n = (...names: string[]) => Number(one(o, ...names) ?? 0) || 0;
    const policy: Record<string, number> = { last: n('--keep-last', '-l'), hourly: n('--keep-hourly'), daily: n('--keep-daily', '-d'), weekly: n('--keep-weekly', '-w'), monthly: n('--keep-monthly', '-m'), yearly: n('--keep-yearly', '-y') };
    const withinArg = one(o, '--keep-within');
    const within = withinArg ? (() => { const m = /^(?:(\d+)y)?(?:(\d+)m)?(?:(\d+)d)?(?:(\d+)h)?$/.exec(withinArg); return m ? ((Number(m[1] ?? 0) * 365 + Number(m[2] ?? 0) * 30 + Number(m[3] ?? 0)) * 24 + Number(m[4] ?? 0)) * 3_600_000 : null; })() : null;
    const keepTags = all(o, '--keep-tag');
    const ids = o.rest;
    let removed: Snapshot[] = [];
    if (ids.length) {
      for (const ref of ids) removed.push(findSnapshot(snaps, ref, o));
    } else {
      const anyPolicy = Object.values(policy).some(Boolean) || within !== null || keepTags.length > 0;
      if (!anyPolicy) { out.push('no policy was specified, no snapshots will be removed'); return 0; }
      const desc: string[] = [];
      if (policy.last) desc.push(`${policy.last} latest`);
      for (const k of ['hourly', 'daily', 'weekly', 'monthly', 'yearly']) if (policy[k]) desc.push(`${policy[k]} ${k}`);
      if (within !== null) desc.push(`all within ${withinArg}`);
      if (keepTags.length) desc.push(`all with tags [${keepTags.join(' ')}]`);
      out.push(`Applying Policy: keep ${desc.join(', ')} snapshots`);
      let pool = snaps;
      const hostF = all(o, '--host', '-H');
      if (hostF.length) pool = pool.filter((s) => hostF.includes(s.hostname));
      const groups = new Map<string, Snapshot[]>();
      for (const s of pool) {
        const k = `${s.hostname}\u0000${[...s.paths].sort().join(', ')}`;
        groups.set(k, [...(groups.get(k) ?? []), s]);
      }
      for (const [k, g] of groups) {
        const [host, paths] = k.split('\u0000');
        const r = applyPolicy(g, policy, within, keepTags, ctx.world.clock);
        out.push(`snapshots for (host [${host}], paths [${paths}]):`);
        out.push(`keep ${r.keep.length} snapshots:`, ...snapTable(r.keep, r.reasons), '');
        if (r.remove.length) out.push(`remove ${r.remove.length} snapshots:`, ...snapTable(r.remove), '');
        removed.push(...r.remove);
      }
    }
    removed = [...new Map(removed.map((s) => [s.id, s])).values()];
    if (!dry && removed.length) {
      for (const s of removed) repoRemove(repo, `snapshots/${s.id}`);
      out.push(`[0:00] 100.00%  ${removed.length} / ${removed.length} files deleted`);
    } else if (dry && removed.length) out.push(`would have removed the following snapshots:\n${removed.map((s) => short(s.id)).join(', ')}`);
    if (has(o, '--prune') && (removed.length || !dry)) { out.push(''); prune(ctx, repo, dry, out); }
    return 0;
  } finally {
    close(repo);
  }
}

function cmdPrune(ctx: CmdCtx, o: Opts, out: string[]): number {
  const repo = open(ctx, o, out);
  try {
    lock(ctx, repo, true, o, out);
    prune(ctx, repo, has(o, '-n', '--dry-run'), out);
    return 0;
  } finally {
    close(repo);
  }
}

function cmdCheck(ctx: CmdCtx, o: Opts, out: string[]): number {
  out.push(`using temporary cache in /tmp/restic-check-cache-${String(Math.floor(ctx.world.clock) % 1_000_000_000)}`);
  const repo = open(ctx, o, out);
  try {
    out.push(`created new cache in /tmp/restic-check-cache-${String(Math.floor(ctx.world.clock) % 1_000_000_000)}`);
    lock(ctx, repo, true, o, out);
    out.push('load indexes');
    const index = loadIndex(repo);
    const errors: string[] = [];
    out.push('check all packs');
    const packsInIndex = new Set(index.values());
    for (const pack of packsInIndex) if (!repo.host.fs[`${repo.path}/data/${pack.slice(0, 2)}/${pack}`]) errors.push(`pack ${short(pack)}: does not exist`);
    out.push('check snapshots, trees and blobs');
    const snaps = loadSnapshots(repo);
    for (const s of snaps) {
      for (const f of s.files) {
        if (f.t !== 'f' || !f.h) continue;
        const pack = index.get(f.h);
        if (!pack) errors.push(`error for tree ${short(sha256Hex(s.id + dirname(f.p)))}:\n  tree ${short(sha256Hex(s.id + dirname(f.p)))}: file "${basename(f.p)}" blob ${short(f.h)} not found in index`);
        else if (!repo.host.fs[`${repo.path}/data/${pack.slice(0, 2)}/${pack}`]) errors.push(`error for tree ${short(sha256Hex(s.id + dirname(f.p)))}:\n  tree ${short(sha256Hex(s.id + dirname(f.p)))}: file "${basename(f.p)}" blob ${short(f.h)}: pack ${short(pack)} does not exist`);
      }
    }
    out.push(`[0:00] 100.00%  ${snaps.length} / ${snaps.length} snapshots`);
    if (has(o, '--read-data') || one(o, '--read-data-subset')) {
      out.push('read all data');
      const packs = repoList(repo, 'data');
      for (const rel of packs) {
        const pack = rel.split('/').pop()!;
        try {
          const blobs = (JSON.parse(repoRead(repo, `data/${rel}`)) as { blobs: Record<string, string> }).blobs;
          for (const [h, c] of Object.entries(blobs)) {
            const owner = snaps.flatMap((s) => s.files).find((f) => f.h === h);
            const hc = sha256Hex(c + (owner?.s !== undefined && owner.s !== c.length ? `\u0000${owner.s}` : ''));
            if (hc !== h) errors.push(`Pack ID does not match, want ${short(pack)}, got ${short(sha256Hex(JSON.stringify(blobs)))}`);
          }
        } catch {
          errors.push(`pack ${short(pack)}: unable to read pack: ciphertext verification failed`);
        }
      }
      out.push(`[0:00] 100.00%  ${packs.length} / ${packs.length} packs`);
    }
    if (errors.length) { out.push(...[...new Set(errors)]); throw new Fatal('repository contains errors'); }
    out.push('no errors were found');
    return 0;
  } finally {
    close(repo);
  }
}

function cmdStats(ctx: CmdCtx, o: Opts, out: string[]): number {
  const repo = open(ctx, o, out);
  try {
    lock(ctx, repo, false, o, out);
    let snaps = loadSnapshots(repo);
    if (o.rest[0]) snaps = [findSnapshot(snaps, o.rest[0], o)];
    const mode = one(o, '--mode') ?? 'restore-size';
    out.push('scanning...', `Stats in ${mode} mode:`, `     Snapshots processed:  ${snaps.length}`);
    if (mode === 'raw-data') {
      const packs = repoList(repo, 'data').map((rel) => repo.host.fs[`${repo.path}/data/${rel}`]);
      const stored = packs.reduce((n, p) => n + (p ? fileSize(p) : 0), 0);
      const blobs = new Set(snaps.flatMap((s) => s.files.map((f) => f.h).filter(Boolean)));
      const raw = snaps.flatMap((s) => s.files).filter((f, i, a) => f.h && a.findIndex((x) => x.h === f.h) === i).reduce((n, f) => n + (f.s ?? 0), 0);
      out.push(`        Total Blob Count:  ${blobs.size}`, ` Total Uncompressed Size:  ${fmtBytes(raw)}`, `              Total Size:  ${fmtBytes(stored)}`, `    Compression Progress:  100.00%`, `       Compression Ratio:  ${(raw / Math.max(1, stored)).toFixed(2)}x`);
    } else {
      const files = snaps.flatMap((s) => s.files.filter((f) => f.t === 'f'));
      out.push(`        Total File Count:  ${files.length + snaps.reduce((n, s) => n + s.files.filter((f) => f.t === 'd').length, 0)}`, `              Total Size:  ${fmtBytes(files.reduce((n, f) => n + (f.s ?? 0), 0))}`);
    }
    return 0;
  } finally {
    close(repo);
  }
}

function cmdUnlock(ctx: CmdCtx, o: Opts, out: string[]): number {
  const repo = open(ctx, o, out);
  try {
    let n = 0;
    for (const id of repoList(repo, 'locks')) {
      let l: Lock;
      try { l = JSON.parse(repoRead(repo, `locks/${id}`)) as Lock; } catch { continue; }
      // Stale: older than 30 minutes, or from this host (its process is not running any more).
      const stale = ctx.world.clock - l.time > 30 * 60_000 || l.hostname === ctx.host.hostname;
      if (stale || has(o, '--remove-all')) { repoRemove(repo, `locks/${id}`); n++; }
    }
    if (n) out.push(`successfully removed ${n} locks`);
    return 0;
  } finally {
    repo.conn?.done();
  }
}

const HELP = `restic is a backup program which allows saving multiple revisions of files and
directories in an encrypted repository stored on different backends.

Usage:
  restic [command]

Available Commands (simulated):
  backup        Create a new backup of files and/or directories
  check         Check the repository for errors
  forget        Remove snapshots from the repository
  init          Initialize a new repository
  ls            List files in a snapshot
  prune         Remove unneeded data from the repository
  restore       Extract the data from a snapshot
  snapshots     List all snapshots
  stats         Scan the repository and show basic statistics
  unlock        Remove locks other processes created
  version       Print version information

Flags:
  -r, --repo repository            repository to backup to or restore from (default: $RESTIC_REPOSITORY)
  -p, --password-file file         file to read the repository password from (default: $RESTIC_PASSWORD_FILE)
      --repository-file file       file to read the repository location from (default: $RESTIC_REPOSITORY_FILE)
      --no-lock                    do not lock the repository
  -q, --quiet                      do not output comprehensive progress report`;

const restic: CommandDef = {
  name: 'restic',
  summary: 'encrypted, deduplicating backups to a local or SFTP repository',
  usage: 'restic -r REPO [-p PASSWORD-FILE] init|backup PATH...|snapshots|ls ID|restore ID --target DIR|forget --keep-daily N --prune|prune|check|stats|unlock',
  run(args, ctx): CmdResult {
    const cmd = parseOpts(args).rest[0];
    const o = parseOpts(args, cmd === 'forget');
    o.rest.shift();
    const out: string[] = [];
    if (!cmd || cmd === 'help' || has(o, '-h', '--help')) return { out: HELP, code: 0 };
    if (cmd === 'version') return { out: VERSION, code: 0 };
    const cmds: Record<string, (c: CmdCtx, o: Opts, out: string[]) => number> = {
      init: cmdInit, backup: cmdBackup, snapshots: cmdSnapshots, ls: cmdLs, restore: cmdRestore,
      forget: cmdForget, prune: cmdPrune, check: cmdCheck, stats: cmdStats, unlock: cmdUnlock,
    };
    const f = cmds[cmd];
    if (!f) return err(`Error: unknown command "${cmd}" for "restic"\nRun 'restic --help' for usage.`, 1);
    try {
      const code = f(ctx, o, out);
      return { out: out.join('\n'), code };
    } catch (e) {
      if (!(e instanceof Fatal)) throw e;
      const msg = e.message.startsWith('NOFATAL') ? e.message.slice(7) : e.message.startsWith('subprocess ') ? e.message : `Fatal: ${e.message}`;
      return { out: [...out, msg].join('\n'), code: e.code };
    }
  },
};

export const RESTIC_COMMANDS: CommandDef[] = [restic];
