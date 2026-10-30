// Backup tools: GNU tar 1.34 (archives), rsync 3.2.7 (mirrors, locally and
// over SSH), sha256sum (checksums) and du (sizes), as on Debian 12.
//
// A tar archive is stored as a file whose content is a header line followed by
// the members as JSON (the simulator keeps text, not bytes); its nominal size
// follows tar's 512-byte blocks and a rough gzip ratio.

import { basename, canAccess, canTraverse, dirname, getNode, modeString } from '../fs';
import { runSsh, endSession } from '../sim/ssh';
import type { FileNode, Host, UserAccount, World } from '../types';
import { sha256Hex } from '../util/sha256';
import { getFile, resolvePath, writeChecked } from './cmdFiles';
import { type CmdCtx, type CmdResult, type CommandDef, err, ok } from './types';

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/** PATH and everything below it, parents before children. */
export function subtree(host: Host, path: string): string[] {
  if (!host.fs[path]) return [];
  const pre = path === '/' ? '/' : path + '/';
  return [path, ...Object.keys(host.fs).filter((p) => p.startsWith(pre)).sort()];
}

export function fileSize(n: FileNode): number {
  return n.type === 'dir' ? 4096 : n.size ?? n.content.length;
}

/** glob(7) match for exclude patterns: * ? [..]. */
export function globMatch(pattern: string, text: string): boolean {
  const re = '^' + pattern.replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]') + '$';
  try { return new RegExp(re).test(text); } catch { return false; }
}

/** Ensure the parent directories of PATH exist (mkdir -p), owned like the writer. Returns an error text or null. */
export function makeParents(host: Host, path: string, user: UserAccount, time: number): string | null {
  const missing: string[] = [];
  let d = dirname(path);
  while (!host.fs[d]) { missing.unshift(d); d = dirname(d); }
  if (host.fs[d].type !== 'dir') return 'Not a directory';
  if (missing.length && !canAccess(host.fs[d], user, 'w') && user.uid !== 0) return 'Permission denied';
  for (const m of missing) host.fs[m] = { type: 'dir', mode: 0o755, owner: user.name, group: user.primaryGroup, content: '', mtime: time };
  return null;
}

const num = (n: number) => n.toLocaleString('en-US');

// ---------------------------------------------------------------------------
// SSH transport (rsync -e ssh, restic sftp:)
// ---------------------------------------------------------------------------

export interface Remote { hostId: string; user: string; lines: string[]; done(): void }

/** Open an SSH connection the way `ssh` does (prompts included); null result carries the client's error output. */
export function sshTransport(ctx: CmdCtx, target: string, user: string | undefined, opts: { identity?: string; batch?: boolean; port?: number } = {}): Remote | { error: CmdResult } {
  const answers: string[] = [];
  for (let guard = 0; guard < 8; guard++) {
    const snapshot = structuredClone(ctx.world);
    const res = runSsh(snapshot, {
      clientHostId: ctx.host.id,
      localUser: ctx.user.name,
      target,
      user,
      port: opts.port,
      identityFiles: opts.identity ? [resolvePath(ctx, opts.identity)] : undefined,
      batchMode: opts.batch,
      answers,
      remoteCommand: 'sftp',
    });
    if (res.outcome === 'need-input') {
      answers.push(ctx.ask(res.prompt!.text, res.prompt!.secret, res.lines.join('\n')));
      continue;
    }
    Object.assign(ctx.world, snapshot);
    if (res.outcome !== 'session' || !res.session) return { error: { out: res.lines.join('\n'), code: res.exitCode || 255 } };
    const s = res.session;
    const world: World = ctx.world;
    return { hostId: s.hostId, user: s.user, lines: res.lines, done: () => endSession(world, s) };
  }
  return { error: err('ssh: too many prompts', 255) };
}

/** "[user@]host:path" → parts; null for a local path. */
export function parseRemoteSpec(spec: string): { user?: string; host: string; path: string } | null {
  const m = /^(?:([^@/:]+)@)?([^/:]+):(.*)$/.exec(spec);
  if (!m || spec.startsWith('/') || spec.startsWith('./')) return null;
  return { user: m[1], host: m[2], path: m[3] };
}

// ---------------------------------------------------------------------------
// tar
// ---------------------------------------------------------------------------

interface TarEntry { p: string; t: 'f' | 'd'; m: number; o: string; g: string; u: number; gi: number; mt: number; c?: string; s?: number }
const TAR_MAGIC = 'SIMTAR1';

function encodeTar(entries: TarEntry[], gz: boolean): { content: string; size: number } {
  const content = `${TAR_MAGIC} ${gz ? 'gzip' : 'plain'} (simulated ${gz ? 'gzip-compressed ' : ''}tar archive; the simulator stores members as text)\n${JSON.stringify(entries)}`;
  const raw = entries.reduce((n, e) => n + 512 + Math.ceil((e.t === 'f' ? e.s ?? e.c?.length ?? 0 : 0) / 512) * 512, 0) + 1024;
  const size = Math.max(10240, Math.ceil(raw / 10240) * 10240);
  return { content, size: gz ? Math.max(45, Math.round(entries.reduce((n, e) => n + 60 + (e.s ?? e.c?.length ?? 0) * 0.3, 20))) : size };
}

export function decodeTar(content: string): { entries: TarEntry[]; gz: boolean } | null {
  const nl = content.indexOf('\n');
  const head = content.slice(0, nl);
  if (!head.startsWith(TAR_MAGIC)) return null;
  try { return { entries: JSON.parse(content.slice(nl + 1)) as TarEntry[], gz: head.includes(' gzip ') }; } catch { return null; }
}

function tarDate(ms: number): string {
  return new Date(ms).toISOString().slice(0, 16).replace('T', ' ');
}

const tar: CommandDef = {
  name: 'tar',
  summary: 'create, list and extract tar archives (GNU tar)',
  usage: 'tar -c|-t|-x [-z] [-v] -f ARCHIVE [-C DIR] [--exclude=PATTERN] [-p] [--strip-components=N] [FILE...]',
  run(args, ctx) {
    let mode: 'c' | 't' | 'x' | null = null;
    let gz = false;
    let verbose = false;
    let file: string | undefined;
    let dir: string | undefined;
    let preserve = ctx.user.uid === 0;
    let absolute = false;
    let keep = false;
    let strip = 0;
    let sameOwner = ctx.user.uid === 0;
    const excludes: string[] = [];
    const names: string[] = [];
    const a = [...args];
    // Old-style first argument without a dash: "czvf archive.tgz".
    if (a[0] && /^[ctxzvfpPkC]+$/.test(a[0]) && !a[0].startsWith('-')) a[0] = '-' + a[0];
    for (let i = 0; i < a.length; i++) {
      const arg = a[i];
      const value = () => a[++i];
      if (arg.startsWith('--')) {
        const [k, v] = arg.split(/=(.*)/s);
        switch (k) {
          case '--create': mode = 'c'; break;
          case '--list': mode = 't'; break;
          case '--extract': case '--get': mode = 'x'; break;
          case '--gzip': case '--gunzip': gz = true; break;
          case '--verbose': verbose = true; break;
          case '--file': file = v ?? value(); break;
          case '--directory': dir = v ?? value(); break;
          case '--exclude': excludes.push(v ?? value()); break;
          case '--preserve-permissions': case '--same-permissions': preserve = true; break;
          case '--absolute-names': absolute = true; break;
          case '--keep-old-files': keep = true; break;
          case '--strip-components': strip = Number(v ?? value()) || 0; break;
          case '--numeric-owner': break;
          case '--same-owner': sameOwner = true; break;
          case '--no-same-owner': sameOwner = false; break;
          default: return err(`tar: unrecognized option '${arg}'\nTry 'tar --help' or 'tar --usage' for more information.`, 2);
        }
        continue;
      }
      if (arg.startsWith('-') && arg.length > 1) {
        for (let k = 1; k < arg.length; k++) {
          const c = arg[k];
          if (c === 'c' || c === 't' || c === 'x') {
            if (mode && mode !== c) return err(`tar: You may not specify more than one '-Acdtrux', '--delete' or  '--test-label' option\nTry 'tar --help' or 'tar --usage' for more information.`, 2);
            mode = c;
          } else if (c === 'z') gz = true;
          else if (c === 'v') verbose = true;
          else if (c === 'p') preserve = true;
          else if (c === 'P') absolute = true;
          else if (c === 'k') keep = true;
          else if (c === 'f' || c === 'C') {
            const rest = arg.slice(k + 1);
            const v = rest || value();
            if (c === 'f') file = v; else dir = v;
            break;
          } else return err(`tar: invalid option -- '${c}'\nTry 'tar --help' or 'tar --usage' for more information.`, 2);
        }
        continue;
      }
      names.push(arg);
    }
    if (!mode) return err(`tar: You must specify one of the '-Acdtrux', '--delete' or '--test-label' options\nTry 'tar --help' or 'tar --usage' for more information.`, 2);
    const errors: string[] = [];
    const base = dir ? resolvePath(ctx, dir) : ctx.frame.cwd;
    if (dir && ctx.host.fs[base]?.type !== 'dir') return err(`tar: ${dir}: Cannot open: No such file or directory\ntar: Error is not recoverable: exiting now`, 2);
    const finish = (out: string[], extra = ''): CmdResult => {
      if (errors.length) return { out: [...out, ...errors, 'tar: Exiting with failure status due to previous errors'].join('\n'), code: 2 };
      return { out: [...out, extra].filter(Boolean).join('\n'), code: 0 };
    };

    if (mode === 'c') {
      if (!file) return err('tar: Refusing to write archive contents to terminal (missing -f option?)\ntar: Error is not recoverable: exiting now', 2);
      if (!names.length) return err('tar: Cowardly refusing to create an empty archive\nTry \'tar --help\' or \'tar --usage\' for more information.', 2);
      const archivePath = file === '-' ? null : resolvePath(ctx, file);
      const entries: TarEntry[] = [];
      const out: string[] = [];
      let warnedSlash = false;
      const excluded = (stored: string) => excludes.some((p) => globMatch(p, basename(stored)) || globMatch(p, stored) || globMatch(p.replace(/\/$/, ''), stored));
      for (const n of names) {
        const abs = n.startsWith('/') ? n.replace(/\/+$/, '') || '/' : `${base === '/' ? '' : base}/${n}`.replace(/\/+$/, '').replace(/\/\.$/, '');
        let stored = n.replace(/\/+$/, '');
        if (stored.startsWith('/') && !absolute) {
          stored = stored.replace(/^\/+/, '');
          warnedSlash = true;
        }
        const node = ctx.host.fs[abs];
        if (!node || !canTraverse(ctx.host, abs, ctx.user)) { errors.push(`tar: ${n}: Cannot stat: ${node ? 'Permission denied' : 'No such file or directory'}`); continue; }
        for (const p of subtree(ctx.host, abs)) {
          const rel = p === abs ? stored : `${stored}/${p.slice(abs.length + 1)}`;
          if (excluded(rel) || excludes.some((pat) => rel.split('/').some((seg) => globMatch(pat, seg)))) continue;
          const nd = ctx.host.fs[p];
          if (p === archivePath) { out.push(`tar: ${rel}: file is the archive; not dumped`); continue; }
          if (!canTraverse(ctx.host, p, ctx.user) || !canAccess(nd, ctx.user, 'r') || (nd.type === 'dir' && !canAccess(nd, ctx.user, 'x'))) {
            errors.push(`tar: ${rel}: Cannot open: Permission denied`);
            continue;
          }
          if (nd.socket) { out.push(`tar: ${rel}: socket ignored`); continue; }
          const ou = ctx.host.users[nd.owner];
          entries.push({ p: nd.type === 'dir' ? rel + '/' : rel, t: nd.type === 'dir' ? 'd' : 'f', m: nd.mode & 0o7777, o: nd.owner, g: nd.group, u: ou?.uid ?? 0, gi: Object.values(ctx.host.users).find((x) => x.primaryGroup === nd.group)?.gid ?? ou?.gid ?? 0, mt: nd.mtime, ...(nd.type === 'file' ? { c: nd.content, ...(nd.size !== undefined ? { s: nd.size } : {}) } : {}) });
          if (verbose && archivePath) out.push(nd.type === 'dir' ? rel + '/' : rel);
        }
      }
      if (warnedSlash) out.unshift('tar: Removing leading `/\' from member names');
      const enc = encodeTar(entries, gz);
      if (!archivePath) return { out: enc.content, code: errors.length ? 2 : 0 };
      const e = writeChecked(ctx, archivePath, enc.content);
      if (e) return err(`tar: ${file}: Cannot open: ${e}\ntar: Error is not recoverable: exiting now`, 2);
      ctx.host.fs[archivePath].size = enc.size;
      return finish(out);
    }

    // List or extract: read the archive (gzip is detected automatically, like GNU tar).
    let content: string | undefined;
    if (!file) return err('tar: Refusing to read archive contents from terminal (missing -f option?)\ntar: Error is not recoverable: exiting now', 2);
    if (file === '-') content = ctx.stdin ?? '';
    else {
      const f = getFile(ctx, resolvePath(ctx, file));
      if (f.error) return err(`tar: ${file}: Cannot open: ${f.error}\ntar: Error is not recoverable: exiting now`, 2);
      content = f.content;
    }
    const dec = decodeTar(content ?? '');
    if (!dec) return err(`${gz ? 'gzip: stdin: not in gzip format\ntar: Child returned status 1\n' : ''}tar: This does not look like a tar archive\ntar: Exiting with failure status due to previous errors`, 2);
    const wanted = (p: string) => !names.length || names.some((n) => { const x = n.replace(/\/+$/, ''); return p === x || p === x + '/' || p.startsWith(x + '/'); });
    const selected = dec.entries.filter((e) => wanted(e.p) && !excludes.some((pat) => globMatch(pat, basename(e.p.replace(/\/$/, ''))) || globMatch(pat, e.p.replace(/\/$/, ''))));
    for (const n of names) if (!dec.entries.some((e) => wanted(e.p) && (e.p.replace(/\/$/, '') === n.replace(/\/+$/, '') || e.p.startsWith(n.replace(/\/+$/, '') + '/')))) errors.push(`tar: ${n}: Not found in archive`);

    if (mode === 't') {
      const out = selected.map((e) => {
        if (!verbose) return e.p;
        const size = e.t === 'd' ? 0 : e.s ?? e.c?.length ?? 0;
        const perm = modeString({ type: e.t === 'd' ? 'dir' : 'file', mode: e.m } as FileNode);
        return `${perm} ${e.o}/${e.g} ${String(size).padStart(14 - Math.min(13, `${e.o}/${e.g}`.length) + 3)} ${tarDate(e.mt)} ${e.p}`;
      });
      return finish(out);
    }

    // Extract.
    const out: string[] = [];
    const umask = ctx.user.uid === 0 ? 0o022 : 0o002;
    for (const e of selected) {
      let rel = e.p.replace(/\/$/, '');
      if (strip) { const parts = rel.split('/'); if (parts.length <= strip) continue; rel = parts.slice(strip).join('/'); }
      if (!rel) continue;
      const dest = rel.startsWith('/') && absolute ? rel : `${base === '/' ? '' : base}/${rel.replace(/^\/+/, '')}`;
      if (verbose) out.push(e.p);
      const parentErr = makeParents(ctx.host, dest, ctx.user, ctx.world.clock);
      if (parentErr) { errors.push(`tar: ${rel}: Cannot mkdir: ${parentErr}`); continue; }
      const existing = ctx.host.fs[dest];
      const owner = sameOwner && ctx.host.users[e.o] ? e.o : ctx.user.name;
      const group = sameOwner ? e.g : ctx.user.primaryGroup;
      const mode = preserve ? e.m : e.m & ~umask;
      if (e.t === 'd') {
        if (existing && existing.type !== 'dir') { errors.push(`tar: ${rel}: Cannot mkdir: File exists`); continue; }
        if (!existing && !canAccess(ctx.host.fs[dirname(dest)], ctx.user, 'w')) { errors.push(`tar: ${rel}: Cannot mkdir: Permission denied`); continue; }
        ctx.host.fs[dest] = { type: 'dir', mode, owner, group, content: '', mtime: e.mt };
        continue;
      }
      if (existing && keep) { errors.push(`tar: ${rel}: Cannot open: File exists`); continue; }
      if (existing?.type === 'dir') { errors.push(`tar: ${rel}: Cannot open: Is a directory`); continue; }
      const w = writeChecked(ctx, dest, e.c ?? '');
      if (w) { errors.push(`tar: ${rel}: Cannot open: ${w}`); continue; }
      const n = ctx.host.fs[dest];
      Object.assign(n, { mode, owner, group, mtime: e.mt });
      if (e.s !== undefined) n.size = e.s;
    }
    return finish(out);
  },
};

// ---------------------------------------------------------------------------
// rsync
// ---------------------------------------------------------------------------

interface Side { host: Host; user: UserAccount; path: string; label: string }

const RSYNC_VERSION = '3.2.7';

const rsync: CommandDef = {
  name: 'rsync',
  summary: 'fast incremental file copy, locally or over SSH',
  usage: 'rsync [-a] [-v] [-n] [-z] [--delete] [--exclude=PATTERN] [-e "ssh -i KEY"] SRC... [USER@]HOST:DEST | rsync [OPTIONS] SRC DEST',
  run(args, ctx) {
    const o = { r: false, l: false, p: false, t: false, g: false, oo: false, v: 0, n: false, del: false, stats: false, numeric: false, h: false };
    const excludes: string[] = [];
    let sshCmd: string | undefined;
    const paths: string[] = [];
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a.startsWith('--')) {
        const [k, v] = a.split(/=(.*)/s);
        switch (k) {
          case '--archive': Object.assign(o, { r: true, l: true, p: true, t: true, g: true, oo: true }); break;
          case '--recursive': o.r = true; break;
          case '--verbose': o.v++; break;
          case '--dry-run': o.n = true; break;
          case '--delete': case '--delete-after': case '--delete-before': case '--delete-during': o.del = true; break;
          case '--exclude': excludes.push(v ?? args[++i]); break;
          case '--rsh': sshCmd = v ?? args[++i]; break;
          case '--stats': o.stats = true; break;
          case '--numeric-ids': o.numeric = true; break;
          case '--perms': o.p = true; break;
          case '--times': o.t = true; break;
          case '--owner': o.oo = true; break;
          case '--group': o.g = true; break;
          case '--human-readable': o.h = true; break;
          case '--compress': case '--progress': case '--partial': case '--info': case '--hard-links': case '--acls': case '--xattrs': break;
          default: return err(`rsync: --${k.slice(2)}: unknown option\nrsync error: syntax or usage error (code 1) at main.c(1795) [client=${RSYNC_VERSION}]`, 1);
        }
        continue;
      }
      if (a.startsWith('-') && a.length > 1) {
        for (let k = 1; k < a.length; k++) {
          const c = a[k];
          switch (c) {
            case 'a': Object.assign(o, { r: true, l: true, p: true, t: true, g: true, oo: true }); break;
            case 'r': o.r = true; break;
            case 'v': o.v++; break;
            case 'n': o.n = true; break;
            case 'p': o.p = true; break;
            case 't': o.t = true; break;
            case 'o': o.oo = true; break;
            case 'g': o.g = true; break;
            case 'l': o.l = true; break;
            case 'h': o.h = true; break;
            case 'z': case 'P': case 'H': case 'A': case 'X': case 'D': case 'x': break;
            case 'e': sshCmd = a.slice(k + 1) || args[++i]; k = a.length; break;
            default: return err(`rsync: -${c}: unknown option\nrsync error: syntax or usage error (code 1) at main.c(1795) [client=${RSYNC_VERSION}]`, 1);
          }
        }
        continue;
      }
      paths.push(a);
    }
    if (paths.length < 2) return err(`rsync  version ${RSYNC_VERSION}  protocol version 31\nusage: rsync [OPTION]... SRC [SRC]... DEST\n(Simulated options: -a -r -v -n -p -t -o -g -z --delete --exclude --stats -e)`, 1);
    const destSpec = paths.pop()!;
    const srcSpecs = paths;
    // ssh options taken from -e "ssh -i KEY -p PORT -o BatchMode=yes".
    const sshArgs = (sshCmd ?? 'ssh').split(/\s+/);
    const identity = sshArgs.includes('-i') ? sshArgs[sshArgs.indexOf('-i') + 1] : undefined;
    const port = sshArgs.includes('-p') ? Number(sshArgs[sshArgs.indexOf('-p') + 1]) : undefined;
    const batch = sshArgs.some((x, i) => (x === '-o' && /^batchmode=yes$/i.test(sshArgs[i + 1] ?? '')) || /^-oBatchMode=yes$/i.test(x));
    const remotes = [destSpec, ...srcSpecs].map(parseRemoteSpec);
    if (remotes[0] && remotes.slice(1).some(Boolean)) return err(`The source and destination cannot both be remote.\nrsync error: syntax or usage error (code 1) at main.c(1428) [Receiver=${RSYNC_VERSION}]`, 1);
    const out: string[] = [];
    const errors: string[] = [];
    let conn: Remote | null = null;
    const remoteSpec = remotes.find(Boolean);
    if (remoteSpec) {
      const t = sshTransport(ctx, remoteSpec.host, remoteSpec.user, { identity, port, batch });
      if ('error' in t) return { out: [t.error.out, `rsync: connection unexpectedly closed (0 bytes received so far) [${remotes[0] ? 'sender' : 'Receiver'}]`, `rsync error: unexplained error (code 255) at io.c(231) [${remotes[0] ? 'sender' : 'Receiver'}=${RSYNC_VERSION}]`].filter(Boolean).join('\n'), code: 255 };
      conn = t;
      out.push(...t.lines);
    }
    const side = (spec: string): Side => {
      const r = parseRemoteSpec(spec);
      if (r && conn) {
        const host = ctx.world.hosts[conn.hostId];
        const user = host.users[conn.user];
        const p = r.path === '' ? user.home : r.path.startsWith('/') ? r.path : `${user.home}/${r.path}`;
        return { host, user, path: p.replace(/\/+$/, '') || '/', label: spec };
      }
      return { host: ctx.host, user: ctx.user, path: resolvePath(ctx, spec).replace(/\/+$/, '') || '/', label: spec };
    };
    const dest = side(destSpec);
    const role = remotes[0] ? 'sender' : 'Receiver';
    const excluded = (rel: string, isDir: boolean) => excludes.some((pat) => {
      const dirOnly = pat.endsWith('/');
      const p = pat.replace(/\/$/, '');
      if (dirOnly && !isDir) return false;
      if (p.startsWith('/')) return globMatch(p.slice(1), rel);
      if (p.includes('/')) return globMatch(p, rel) || globMatch(`*/${p}`, rel);
      return rel.split('/').some((seg) => globMatch(p, seg));
    });
    // Build the transfer list: [relative path under the destination, source node].
    const list: { rel: string; node: FileNode; src: Side; abs: string }[] = [];
    let total = 0;
    for (const spec of srcSpecs) {
      const src = side(spec);
      const contents = spec.endsWith('/') || spec.endsWith('/.');
      const node = src.host.fs[src.path];
      if (!node || !canTraverse(src.host, src.path, src.user)) {
        errors.push(`rsync: [sender] change_dir "${src.path}" failed: ${node ? 'Permission denied (13)' : 'No such file or directory (2)'}`);
        continue;
      }
      if (node.type === 'dir' && !o.r) { out.push(`skipping directory ${contents ? '.' : basename(src.path)}`); continue; }
      const rootName = contents ? '' : basename(src.path);
      for (const p of node.type === 'dir' ? subtree(src.host, src.path) : [src.path]) {
        const relInSrc = p === src.path ? '' : p.slice(src.path.length + 1);
        const rel = [rootName, relInSrc].filter(Boolean).join('/');
        const nd = src.host.fs[p];
        if (rel && excluded(rel, nd.type === 'dir')) continue;
        if (rel && list.some((x) => rel.startsWith(x.rel + '/') && excluded(x.rel, true))) continue;
        if (!canAccess(nd, src.user, 'r') || (nd.type === 'dir' && !canAccess(nd, src.user, 'x'))) {
          errors.push(nd.type === 'dir' ? `rsync: [sender] opendir "${p}" failed: Permission denied (13)` : `rsync: [sender] send_files failed to open "${p}": Permission denied (13)`);
          continue;
        }
        list.push({ rel, node: nd, src, abs: p });
        if (nd.type === 'file') total += fileSize(nd);
      }
    }
    // Destination: a directory when copying a directory, several sources, or an existing directory.
    const destNode = dest.host.fs[dest.path];
    const singleFile = list.length === 1 && list[0].node.type === 'file' && list[0].rel === basename(list[0].abs) && srcSpecs.length === 1 && destNode?.type !== 'dir' && !destSpec.endsWith('/');
    const target = (rel: string) => (singleFile ? dest.path : rel ? `${dest.path === '/' ? '' : dest.path}/${rel}` : dest.path);
    if (!destNode && !singleFile) {
      const parent = dest.host.fs[dirname(dest.path)];
      if (!parent) {
        errors.push(`rsync: [Receiver] mkdir "${dest.path}" failed: No such file or directory (2)`);
        out.push(...errors, `rsync error: error in file IO (code 11) at main.c(784) [Receiver=${RSYNC_VERSION}]`);
        conn?.done();
        return { out: out.join('\n'), code: 11 };
      }
      if (!canAccess(parent, dest.user, 'w')) {
        errors.push(`rsync: [Receiver] mkdir "${dest.path}" failed: Permission denied (13)`);
        out.push(...errors, `rsync error: error in file IO (code 11) at main.c(784) [Receiver=${RSYNC_VERSION}]`);
        conn?.done();
        return { out: out.join('\n'), code: 11 };
      }
      if (o.v) out.push(`created directory ${destSpec.replace(/^[^:]*:/, '').replace(/\/+$/, '') || '.'}`);
      if (!o.n) dest.host.fs[dest.path] = { type: 'dir', mode: 0o755, owner: dest.user.name, group: dest.user.primaryGroup, content: '', mtime: ctx.world.clock };
    }
    if (o.v) out.push(remotes[0] || !remoteSpec ? 'sending incremental file list' : 'receiving incremental file list');
    let sent = 0;
    const changed: string[] = [];
    const destUser = dest.user;
    for (const item of list) {
      const t = target(item.rel);
      const cur = dest.host.fs[t];
      const n = item.node;
      const label = item.rel ? (n.type === 'dir' ? `${item.rel}/` : item.rel) : n.type === 'dir' ? './' : basename(item.abs);
      if (n.type === 'dir') {
        if (cur && cur.type !== 'dir') { errors.push(`rsync: [${role}] cannot delete non-empty directory: ${item.rel}`); continue; }
        const needs = !cur || (o.p && (cur.mode & 0o7777) !== (n.mode & 0o7777)) || (o.oo && destUser.uid === 0 && cur.owner !== n.owner) || (o.t && cur.mtime !== n.mtime);
        if (needs && (o.v || !cur)) { if (o.v) changed.push(label); }
        if (o.n) continue;
        if (!cur) {
          if (!canAccess(dest.host.fs[dirname(t)] ?? { type: 'dir', mode: 0, owner: '', group: '', content: '', mtime: 0 }, destUser, 'w')) { errors.push(`rsync: [${role}] recv_generator: mkdir "${t}" failed: Permission denied (13)`); continue; }
          dest.host.fs[t] = { type: 'dir', mode: o.p ? n.mode & 0o7777 : (n.mode & 0o7777) & ~0o022, owner: destUser.name, group: destUser.primaryGroup, content: '', mtime: ctx.world.clock };
        }
        const d = dest.host.fs[t];
        if (o.p) d.mode = n.mode & 0o7777;
        if (o.oo && destUser.uid === 0) d.owner = n.owner;
        if (o.g && (destUser.uid === 0 || destUser.groups.includes(n.group) || destUser.primaryGroup === n.group)) d.group = n.group;
        if (o.t) d.mtime = n.mtime;
        continue;
      }
      const same = cur?.type === 'file' && cur.content === n.content && fileSize(cur) === fileSize(n) && (!o.t || cur.mtime === n.mtime);
      if (same) continue;
      changed.push(label);
      sent += fileSize(n);
      if (o.n) continue;
      const parent = dest.host.fs[dirname(t)];
      if (!parent) { errors.push(`rsync: [${role}] mkstemp "${t}" failed: No such file or directory (2)`); continue; }
      if (cur ? !canAccess(cur, destUser, 'w') && !canAccess(parent, destUser, 'w') : !canAccess(parent, destUser, 'w')) {
        errors.push(`rsync: [${role}] mkstemp "${dirname(t)}/.${basename(t)}.XXXXXX" failed: Permission denied (13)`);
        continue;
      }
      dest.host.fs[t] = {
        type: 'file', content: n.content, ...(n.size !== undefined ? { size: n.size } : {}),
        mode: o.p ? n.mode & 0o7777 : cur ? cur.mode : (n.mode & 0o7777) & ~0o022,
        owner: o.oo && destUser.uid === 0 ? n.owner : destUser.name,
        group: o.g && (destUser.uid === 0 || destUser.groups.includes(n.group) || destUser.primaryGroup === n.group) ? n.group : destUser.primaryGroup,
        mtime: o.t ? n.mtime : ctx.world.clock,
      };
    }
    // --delete: what is in the destination directory but not in the transfer (and not excluded).
    const deletions: string[] = [];
    if (o.del && o.r && !singleFile) {
      const keepRel = new Set(list.map((x) => x.rel));
      const roots = srcSpecs.map((s) => (s.endsWith('/') ? '' : basename(side(s).path)));
      for (const root of new Set(roots)) {
        const top = root ? `${dest.path === '/' ? '' : dest.path}/${root}` : dest.path;
        for (const p of subtree(dest.host, top).slice(1).reverse()) {
          const rel = (root ? root + '/' : '') + p.slice(top.length + 1);
          if (keepRel.has(rel) || excluded(rel, dest.host.fs[p].type === 'dir')) continue;
          deletions.push(`deleting ${dest.host.fs[p].type === 'dir' ? rel + '/' : rel}`);
          if (!o.n) delete dest.host.fs[p];
        }
      }
    }
    conn?.done();
    if (o.v) out.push(...deletions, ...changed.sort((a, b) => (a === './' ? -1 : b === './' ? 1 : a.localeCompare(b))));
    const fmt = o.h ? (n: number) => (n >= 1024 * 1024 ? `${(n / 1048576).toFixed(2)}M` : n >= 1024 ? `${(n / 1024).toFixed(2)}K` : String(n)) : num;
    const sentBytes = sent + 60 * changed.length + 120;
    const recv = 35 + 20 * changed.length;
    const speedup = total ? (total / (sentBytes + recv)).toFixed(2) : '0.00';
    if (o.stats) out.push('', `Number of files: ${num(list.length)}`, `Number of regular files transferred: ${num(changed.filter((c) => !c.endsWith('/')).length)}`, `Total file size: ${fmt(total)} bytes`, `Total transferred file size: ${fmt(sent)} bytes`);
    if (o.v || o.stats) out.push('', `sent ${fmt(sentBytes)} bytes  received ${fmt(recv)} bytes  ${(sentBytes + recv).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })} bytes/sec`, `total size is ${fmt(total)}  speedup is ${speedup}${o.n ? ' (DRY RUN)' : ''}`);
    if (errors.length) {
      return { out: [...out, ...errors, `rsync error: some files/attrs were not transferred (see previous errors) (code 23) at main.c(1338) [sender=${RSYNC_VERSION}]`].join('\n'), code: 23 };
    }
    return ok(out.join('\n'));
  },
};

// ---------------------------------------------------------------------------
// sha256sum, du
// ---------------------------------------------------------------------------

const sha256sum: CommandDef = {
  name: 'sha256sum',
  summary: 'compute and check SHA-256 checksums',
  usage: 'sha256sum FILE... | sha256sum -c CHECKSUM-FILE',
  run(args, ctx) {
    const check = args.includes('-c') || args.includes('--check');
    const files = args.filter((a) => !a.startsWith('-'));
    const out: string[] = [];
    let code = 0;
    const digest = (path: string): string | { error: string } => {
      const f = getFile(ctx, resolvePath(ctx, path));
      return f.error ? { error: f.error } : sha256Hex(f.content ?? '');
    };
    if (!files.length && ctx.stdin !== undefined) return ok(`${sha256Hex(ctx.stdin)}  -`);
    if (check) {
      let bad = 0;
      for (const cf of files) {
        const f = getFile(ctx, resolvePath(ctx, cf));
        if (f.error) { out.push(`sha256sum: ${cf}: ${f.error}`); code = 1; continue; }
        for (const line of (f.content ?? '').split('\n').filter(Boolean)) {
          const m = /^([0-9a-f]{64})\s+\*?(.+)$/.exec(line);
          if (!m) continue;
          const d = digest(m[2]);
          if (typeof d !== 'string') { out.push(`sha256sum: ${m[2]}: ${d.error}`, `${m[2]}: FAILED open or read`); bad++; continue; }
          if (d === m[1]) out.push(`${m[2]}: OK`); else { out.push(`${m[2]}: FAILED`); bad++; }
        }
      }
      if (bad) { out.push(`sha256sum: WARNING: ${bad} computed checksum${bad > 1 ? 's' : ''} did NOT match`); code = 1; }
      return { out: out.join('\n'), code };
    }
    for (const p of files) {
      const d = digest(p);
      if (typeof d === 'string') out.push(`${d}  ${p}`);
      else { out.push(`sha256sum: ${p}: ${d.error}`); code = 1; }
    }
    return { out: out.join('\n'), code };
  },
};

function human(n: number): string {
  if (n < 1024) return `${Math.max(4, Math.ceil(n / 1024) * 4)}K`.replace(/^0K$/, '0');
  const units = ['K', 'M', 'G', 'T'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v >= 10 ? Math.ceil(v) : Math.ceil(v * 10) / 10}${units[i]}`;
}

const du: CommandDef = {
  name: 'du',
  summary: 'estimate disk usage of files and directories',
  usage: 'du [-s] [-h] [--max-depth=N] [PATH...]',
  run(args, ctx) {
    const s = args.some((a) => /^-[a-z]*s/.test(a) && !a.startsWith('--'));
    const h = args.some((a) => /^-[a-z]*h/.test(a) && !a.startsWith('--'));
    const depthArg = args.find((a) => a.startsWith('--max-depth='));
    const maxDepth = s ? 0 : depthArg ? Number(depthArg.split('=')[1]) : Infinity;
    const paths = args.filter((a) => !a.startsWith('-'));
    const out: string[] = [];
    let code = 0;
    for (const arg of paths.length ? paths : ['.']) {
      const root = resolvePath(ctx, arg);
      if (!getNode(ctx.host, root)) { out.push(`du: cannot access '${arg}': No such file or directory`); code = 1; continue; }
      const sizes = new Map<string, number>();
      for (const p of subtree(ctx.host, root).reverse()) {
        const n = ctx.host.fs[p];
        const own = n.type === 'dir' ? 4096 : Math.ceil(fileSize(n) / 4096) * 4096;
        sizes.set(p, (sizes.get(p) ?? 0) + own);
        if (p !== root) sizes.set(dirname(p), (sizes.get(dirname(p)) ?? 0) + (sizes.get(p) ?? 0));
        if (n.type === 'dir' && !canAccess(n, ctx.user, 'r')) { out.push(`du: cannot read directory '${arg === '.' ? '.' : arg}${p.slice(root.length)}': Permission denied`); code = 1; }
      }
      const depth = (p: string) => (p === root ? 0 : p.slice(root.length + 1).split('/').length);
      for (const p of subtree(ctx.host, root).reverse()) {
        if (ctx.host.fs[p].type !== 'dir' || depth(p) > maxDepth) continue;
        const v = sizes.get(p) ?? 0;
        out.push(`${h ? human(v) : Math.ceil(v / 1024)}\t${arg === '.' ? '.' : arg.replace(/\/+$/, '')}${p.slice(root.length)}`);
      }
    }
    return { out: out.join('\n'), code };
  },
};

const find: CommandDef = {
  name: 'find',
  summary: 'search for files in a directory hierarchy',
  usage: 'find [PATH...] [-maxdepth N] [-mindepth N] [-type f|d] [-name GLOB] [-iname GLOB] [-mtime [+-]N] [-mmin [+-]N] [-newer FILE] [-user NAME] [-print]',
  run(args, ctx) {
    const starts: string[] = [];
    let i = 0;
    while (i < args.length && !args[i].startsWith('-')) starts.push(args[i++]);
    const tests: ((p: string, n: FileNode, depth: number) => boolean)[] = [];
    let maxDepth = Infinity;
    let minDepth = 0;
    const cmp = (spec: string, value: number) => (spec.startsWith('+') ? value > Number(spec.slice(1)) : spec.startsWith('-') ? value < Number(spec.slice(1)) : value === Number(spec));
    for (; i < args.length; i++) {
      const a = args[i];
      const v = args[i + 1];
      const need = () => { if (v === undefined) throw new Error(`find: missing argument to \`${a}'`); i++; return v; };
      try {
        switch (a) {
          case '-maxdepth': maxDepth = Number(need()); break;
          case '-mindepth': minDepth = Number(need()); break;
          case '-type': { const t = need(); tests.push((_p, n) => (t === 'd' ? n.type === 'dir' : t === 'f' ? n.type === 'file' && !n.socket : t === 's' ? !!n.socket : false)); break; }
          case '-name': { const g = need(); tests.push((p) => globMatch(g, basename(p))); break; }
          case '-iname': { const g = need().toLowerCase(); tests.push((p) => globMatch(g, basename(p).toLowerCase())); break; }
          case '-mtime': { const s = need(); tests.push((_p, n) => cmp(s, Math.floor((ctx.world.clock - n.mtime) / 86_400_000))); break; }
          case '-mmin': { const s = need(); tests.push((_p, n) => cmp(s, Math.ceil((ctx.world.clock - n.mtime) / 60_000))); break; }
          case '-newer': { const f = need(); const ref = ctx.host.fs[resolvePath(ctx, f)]; if (!ref) return err(`find: '${f}': No such file or directory`, 1); tests.push((_p, n) => n.mtime > ref.mtime); break; }
          case '-user': { const u = need(); tests.push((_p, n) => n.owner === u); break; }
          case '-print': case '-xdev': break;
          default: return err(`find: unknown predicate \`${a}'`, 1);
        }
      } catch (e) {
        return err((e as Error).message, 1);
      }
    }
    const out: string[] = [];
    let code = 0;
    for (const s of starts.length ? starts : ['.']) {
      const root = resolvePath(ctx, s);
      if (!ctx.host.fs[root]) { out.push(`find: '${s}': No such file or directory`); code = 1; continue; }
      const denied: string[] = [];
      for (const p of subtree(ctx.host, root)) {
        if (denied.some((d) => p.startsWith(d + '/'))) continue;
        const n = ctx.host.fs[p];
        const depth = p === root ? 0 : p.slice(root.length + (root === '/' ? 0 : 1)).split('/').length;
        if (depth > maxDepth) continue;
        const shown = s.replace(/\/+$/, '') + p.slice(root.length) || '/';
        if (depth >= minDepth && tests.every((t) => t(p, n, depth))) out.push(shown);
        if (n.type === 'dir' && p !== root && (!canAccess(n, ctx.user, 'r') || !canAccess(n, ctx.user, 'x'))) { out.push(`find: '${shown}': Permission denied`); denied.push(p); code = 1; }
      }
    }
    return { out: out.join('\n'), code };
  },
};

export const BACKUP_COMMANDS: CommandDef[] = [tar, rsync, sha256sum, du, find];
