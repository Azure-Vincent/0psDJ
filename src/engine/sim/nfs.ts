// NFS (Linux kernel server nfs-kernel-server, client mount.nfs). The server
// exports directories to clients named in /etc/exports; what the kernel uses is
// the export table loaded at start or by `exportfs -ra` (editing the file alone
// changes nothing). A client mounts an export over TCP 2049; from then on the
// mount point shows the server's files.
//
// Model: the client's mount point is a synchronized view of the server's
// directory. Before a command the view is refreshed from the server, after it
// changes are written back. Ownership travels as numbers (sec=sys): a file owned
// by uid 1000 on the server belongs to whoever has uid 1000 on the client.
// Export options apply on the way: ro, root_squash (default: client root is
// nobody) and all_squash, with anonuid/anongid.

import { mkdir, readFile } from '../fs';
import { inCidr, parseCidr } from '../net/ip';
import { isIpAddress } from '../net/addr';
import type { FileNode, Host, NfsMount, ServiceRuntime, World } from '../types';
import { resolve } from './dns';
import { log } from './journal';
import { hostAddresses } from './network';
import { tcpConnect } from './tcp';
import { withRecorder } from './trace';

export const EXPORTS = '/etc/exports';
export const NOBODY_UID = 65534;

export interface ExportOptions { rw: boolean; squash: 'root' | 'all' | 'none'; anonuid: number; anongid: number; sync: boolean; subtreeCheck: boolean }
export interface ExportClient { spec: string; options: ExportOptions }
export interface NfsExport { path: string; clients: ExportClient[]; line: number }
export interface NfsServerLoaded { exports: NfsExport[] }

const KNOWN_OPTS = new Set(['rw', 'ro', 'sync', 'async', 'root_squash', 'no_root_squash', 'all_squash', 'no_all_squash', 'subtree_check', 'no_subtree_check', 'secure', 'insecure', 'wdelay', 'no_wdelay', 'hide', 'nohide', 'crossmnt', 'sec=sys', 'sec=krb5', 'sec=krb5i', 'sec=krb5p']);

/** Parse /etc/exports; errors are worded like exportfs. */
export function parseExports(text: string): { exports: NfsExport[]; errors: string[] } {
  const exports: NfsExport[] = [];
  const errors: string[] = [];
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) return;
    const [path, ...specs] = line.split(/\s+/);
    if (!path.startsWith('/')) { errors.push(`exportfs: ${EXPORTS}:${i + 1}: unknown keyword "${path}"`); return; }
    const ex: NfsExport = { path: path.replace(/\/+$/, '') || '/', clients: [], line: i + 1 };
    for (const s of specs.length ? specs : ['*']) {
      const m = /^([^(]*)(?:\(([^)]*)\))?$/.exec(s);
      if (!m) { errors.push(`exportfs: ${EXPORTS}:${i + 1}: syntax error: bad option list`); continue; }
      const options: ExportOptions = { rw: false, squash: 'root', anonuid: NOBODY_UID, anongid: NOBODY_UID, sync: true, subtreeCheck: false };
      let bad = false;
      for (const o of (m[2] ?? '').split(',').filter(Boolean)) {
        const [k, v] = o.split('=');
        if (k === 'anonuid' || k === 'anongid') { options[k] = Number(v); continue; }
        if (!KNOWN_OPTS.has(o) && !KNOWN_OPTS.has(k)) { errors.push(`exportfs: ${EXPORTS}:${i + 1}: unknown keyword "${o}"`); bad = true; break; }
        if (o === 'rw') options.rw = true;
        if (o === 'ro') options.rw = false;
        if (o === 'no_root_squash') options.squash = options.squash === 'all' ? 'all' : 'none';
        if (o === 'all_squash') options.squash = 'all';
        if (o === 'async') options.sync = false;
        if (o === 'subtree_check') options.subtreeCheck = true;
      }
      if (!bad) ex.clients.push({ spec: m[1] || '*', options });
    }
    if (ex.clients.length) exports.push(ex);
  });
  return { exports, errors };
}

/** Does a client spec (*, CIDR, IP, host name or *.domain wildcard) cover this client? */
export function specMatches(spec: string, ip: string, names: string[]): boolean {
  if (spec === '*') return true;
  if (spec.includes('/')) {
    const c = parseCidr(spec);
    return !!c && inCidr(ip, c);
  }
  if (isIpAddress(spec)) return spec === ip;
  const s = spec.toLowerCase();
  if (s.startsWith('*.')) return names.some((n) => n.toLowerCase().endsWith(s.slice(1)));
  return names.some((n) => n.toLowerCase() === s || n.toLowerCase().split('.')[0] === s);
}

/** The export (and the options for this client) that covers path, as the server would decide. */
export function exportFor(server: Host, path: string, ip: string, names: string[]): { ex: NfsExport; opts: ExportOptions } | { error: 'no-export' | 'denied' } {
  const l = server.services['nfs-kernel-server']?.loaded as NfsServerLoaded | null | undefined;
  const p = path.replace(/\/+$/, '') || '/';
  const ex = l?.exports.find((e) => e.path === p);
  if (!ex) return { error: 'no-export' };
  const c = ex.clients.find((x) => specMatches(x.spec, ip, names));
  return c ? { ex, opts: c.options } : { error: 'denied' };
}

export function nfsServerStart(world: World, host: Host, rt: ServiceRuntime, pid: number): boolean {
  const opts = { pid, unit: 'nfs-server.service' };
  const r = parseExports(readFile(host, EXPORTS) ?? '');
  for (const e of r.errors) log(world, host, 'exportfs', e, { ...opts, priority: 'err' });
  const ok = r.exports.filter((e) => {
    if (host.fs[e.path]?.type === 'dir') return true;
    log(world, host, 'exportfs', `exportfs: Failed to stat ${e.path}: No such file or directory`, { ...opts, priority: 'err' });
    return false;
  });
  rt.loaded = { exports: ok } satisfies NfsServerLoaded;
  return true;
}

// ---------------------------------------------------------------------------
// Identity mapping (AUTH_SYS: numbers on the wire)
// ---------------------------------------------------------------------------

const uidOf = (h: Host, name: string): number | undefined => (/^\d+$/.test(name) ? Number(name) : name === 'nobody' ? NOBODY_UID : h.users[name]?.uid);
function gidOf(h: Host, group: string): number | undefined {
  if (/^\d+$/.test(group)) return Number(group);
  if (group === 'nogroup') return NOBODY_UID;
  return Object.values(h.users).find((u) => u.primaryGroup === group)?.gid ?? h.users[group]?.gid;
}
const nameForUid = (h: Host, uid: number | undefined): string => (uid === undefined ? 'nobody' : uid === NOBODY_UID ? 'nobody' : Object.values(h.users).find((u) => u.uid === uid)?.name ?? String(uid));
const nameForGid = (h: Host, gid: number | undefined): string => (gid === undefined ? 'nogroup' : gid === NOBODY_UID ? 'nogroup' : Object.values(h.users).find((u) => u.gid === gid)?.primaryGroup ?? String(gid));

// ---------------------------------------------------------------------------
// Mounts
// ---------------------------------------------------------------------------

export function hostNames(h: Host): string[] {
  return [h.hostname, `${h.hostname}.${h.domain}`];
}

export function mountFor(host: Host, path: string): NfsMount | undefined {
  return (host.mounts ?? []).find((m) => path === m.target || path.startsWith(m.target + '/'));
}

const sig = (n: FileNode) => JSON.stringify([n.type, n.mode, n.owner, n.group, n.content, n.mtime, n.size]);

/** Copy the server's exported tree into the client's mount point. */
function pull(world: World, client: Host, m: NfsMount): void {
  for (const p of Object.keys(client.fs)) if (p.startsWith(m.target + '/')) delete client.fs[p];
  const server = world.hosts[m.server];
  const ip = m.clientIp;
  const access = server?.services['nfs-kernel-server']?.state === 'active' ? exportFor(server, m.serverPath, ip, hostNames(client)) : { error: 'denied' as const };
  if ('error' in access || !server.fs[m.serverPath]) {
    // The server no longer serves this client: every access fails (Stale file handle / Permission denied).
    m.stale = true;
    client.fs[m.target] = { ...(client.fs[m.target] ?? m.underlying!), nfs: { ro: true, squash: 'all', stale: true } };
    m.snapshot = {};
    return;
  }
  m.stale = false;
  m.ro = !access.opts.rw || m.options.includes('ro');
  const marker = { ro: m.ro, squash: access.opts.squash };
  const snapshot: Record<string, string> = {};
  const prefix = m.serverPath === '/' ? '' : m.serverPath;
  for (const [p, n] of Object.entries(server.fs)) {
    if (p !== m.serverPath && !p.startsWith(prefix + '/')) continue;
    const cp = m.target + p.slice(prefix.length === 0 ? 0 : prefix.length);
    const node: FileNode = { ...n, owner: nameForUid(client, uidOf(server, n.owner)), group: nameForGid(client, gidOf(server, n.group)), nfs: marker };
    client.fs[p === m.serverPath ? m.target : cp] = node;
    snapshot[p === m.serverPath ? m.target : cp] = sig(node);
  }
  m.snapshot = snapshot;
}

/** Write the client's changes under the mount point back to the server. */
function push(world: World, client: Host, m: NfsMount): void {
  const server = world.hosts[m.server];
  if (!server || m.stale || !m.snapshot) return;
  const access = exportFor(server, m.serverPath, m.clientIp, hostNames(client));
  if ('error' in access) return;
  const prefix = m.serverPath === '/' ? '' : m.serverPath;
  const toServer = (cp: string) => (cp === m.target ? m.serverPath : prefix + cp.slice(m.target.length));
  const seen = new Set<string>();
  for (const [cp, n] of Object.entries(client.fs)) {
    if (cp !== m.target && !cp.startsWith(m.target + '/')) continue;
    seen.add(cp);
    if (m.snapshot[cp] === sig(n)) continue;
    const isNew = m.snapshot[cp] === undefined;
    let uid = uidOf(client, n.owner);
    let gid = gidOf(client, n.group);
    if (isNew && (access.opts.squash === 'all' || (access.opts.squash === 'root' && uid === 0))) { uid = access.opts.anonuid; gid = access.opts.anongid; }
    const plain: FileNode = { ...n, owner: nameForUid(server, uid), group: nameForGid(server, gid) };
    delete plain.nfs;
    server.fs[toServer(cp)] = plain;
  }
  for (const cp of Object.keys(m.snapshot)) if (!seen.has(cp)) delete server.fs[toServer(cp)];
}

/** Before a command: send pending changes, then refresh every mount from its server. After: send changes. */
export function nfsSync(world: World, phase: 'before' | 'after'): void {
  for (const h of Object.values(world.hosts)) {
    for (const m of h.mounts ?? []) {
      push(world, h, m);
      if (phase === 'before') pull(world, h, m);
      else if (!m.stale) pull(world, h, m);
    }
  }
}

function remoteName(world: World, client: Host, server: string): { ip: string; host: Host } | { error: string } {
  let ip = isIpAddress(server) ? server : undefined;
  if (!ip) {
    const r = resolve(world, client, server, { family: 4 });
    if (!r.ok) return { error: `mount.nfs4: Failed to resolve server ${server}: Name or service not known` };
    ip = r.ip;
  }
  const host = Object.values(world.hosts).find((h) => hostAddresses(h).includes(ip!));
  if (!host) return { error: 'mount.nfs4: No route to host' };
  return { ip, host };
}

/** mount -t nfs4 SERVER:/PATH TARGET: returns mount.nfs's error text, or null on success. */
export function mountNfs(world: World, client: Host, source: string, target: string, options: string[]): string | null {
  const m = /^([^:]+):(\/.*)$/.exec(source);
  if (!m) return `mount.nfs4: remote share not in 'host:dir' format`;
  if (client.fs[target]?.type !== 'dir') return `mount.nfs4: mount point ${target} does not exist`;
  if (mountFor(client, target)?.target === target) return `mount.nfs4: ${source} is already mounted on ${target}`;
  const r = remoteName(world, client, m[1]);
  if ('error' in r) return r.error;
  const c = withRecorder(null, () => tcpConnect(world, client, r.ip, 2049, { timeoutMs: 120_000 }));
  if (!c.ok) {
    if (c.errno === 'ECONNREFUSED') return 'mount.nfs4: Connection refused';
    if (c.errno === 'ETIMEDOUT') return 'mount.nfs4: Connection timed out';
    return 'mount.nfs4: No route to host';
  }
  c.conn.close('client');
  const clientIp = c.conn.sv.peer;
  const access = exportFor(r.host, m[2], clientIp, hostNames(client));
  if ('error' in access) {
    return access.error === 'denied'
      ? `mount.nfs4: access denied by server while mounting ${source}`
      : `mount.nfs4: mounting ${source} failed, reason given by server: No such file or directory`;
  }
  const mount: NfsMount = { source, server: r.host.id, serverPath: access.ex.path, target, options, clientIp, serverIp: r.ip, underlying: client.fs[target], ro: !access.opts.rw || options.includes('ro') };
  (client.mounts ??= []).push(mount);
  pull(world, client, mount);
  return null;
}

export function umountNfs(client: Host, target: string): string | null {
  const i = (client.mounts ?? []).findIndex((m) => m.target === target || m.source === target);
  if (i < 0) return `umount: ${target}: not mounted.`;
  const m = client.mounts![i];
  for (const p of Object.keys(client.fs)) if (p.startsWith(m.target + '/')) delete client.fs[p];
  if (m.underlying) client.fs[m.target] = m.underlying;
  client.mounts!.splice(i, 1);
  return null;
}

export interface FstabEntry { source: string; target: string; type: string; options: string[] }

export function parseFstab(text: string): FstabEntry[] {
  return text.split('\n').map((l) => l.replace(/#.*$/, '').trim()).filter(Boolean).map((l) => {
    const [source, target, type, opts] = l.split(/\s+/);
    return { source, target, type, options: (opts ?? 'defaults').split(',') };
  });
}

/** systemd's mount unit name for a path: /mnt/projects → mnt-projects.mount. */
export const mountUnit = (target: string) => `${target.replace(/^\//, '').replace(/\//g, '-') || '-'}.mount`;

/** At boot (remote-fs.target): mount the NFS entries of /etc/fstab, logging like systemd. */
export function mountFstabNfs(world: World, host: Host): void {
  host.mounts = [];
  for (const e of parseFstab(readFile(host, '/etc/fstab') ?? '')) {
    if (e.type !== 'nfs' && e.type !== 'nfs4') continue;
    if (e.options.includes('noauto')) continue;
    const unit = mountUnit(e.target);
    log(world, host, 'systemd', `Mounting ${unit} - ${e.target}...`, { pid: 1, unit });
    const error = mountNfs(world, host, e.source, e.target, e.options);
    if (!error) { log(world, host, 'systemd', `Mounted ${unit} - ${e.target}.`, { pid: 1, unit }); continue; }
    log(world, host, 'mount', error, { pid: 600, unit, priority: 'err' });
    log(world, host, 'systemd', `${unit}: Mount process exited, code=exited, status=32/n/a`, { pid: 1, unit, priority: 'err' });
    log(world, host, 'systemd', `${unit}: Failed with result 'exit-code'.`, { pid: 1, unit, priority: 'warning' });
    log(world, host, 'systemd', `Failed to mount ${unit} - ${e.target}.`, { pid: 1, unit, priority: 'err' });
  }
}

/** On reboot the client's mounts are gone (restore what was underneath the mount points). */
export function nfsReset(host: Host): void {
  for (const m of [...(host.mounts ?? [])].reverse()) umountNfs(host, m.target);
  host.mounts = [];
}

/** Make sure a directory chain exists (used by the lab setup). */
export function ensureDir(host: Host, path: string, t: number): void {
  const parts = path.split('/').filter(Boolean);
  for (let i = 1; i <= parts.length; i++) {
    const p = '/' + parts.slice(0, i).join('/');
    if (!host.fs[p]) mkdir(host, p, t);
  }
}
