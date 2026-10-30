// Virtual filesystem helpers. Paths are absolute and normalised; directories are
// explicit nodes so that ownership/mode checks (e.g. sshd StrictModes) work on
// every path component.

import type { FileNode, Host, UserAccount, World } from './types';

export function normalizePath(path: string, cwd = '/', home = '/root'): string {
  let p = path;
  if (p === '~' || p.startsWith('~/')) p = home + p.slice(1);
  if (!p.startsWith('/')) p = (cwd.endsWith('/') ? cwd : cwd + '/') + p;
  const out: string[] = [];
  for (const part of p.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') out.pop();
    else out.push(part);
  }
  return '/' + out.join('/');
}

export function dirname(path: string): string {
  const i = path.lastIndexOf('/');
  return i <= 0 ? '/' : path.slice(0, i);
}

export function basename(path: string): string {
  return path.slice(path.lastIndexOf('/') + 1);
}

export function getNode(host: Host, path: string): FileNode | undefined {
  return host.fs[path];
}

export function readFile(host: Host, path: string): string | undefined {
  const n = host.fs[path];
  return n && n.type === 'file' ? n.content : undefined;
}

export function writeFile(
  host: Host,
  path: string,
  content: string,
  time: number,
  meta?: Partial<Pick<FileNode, 'mode' | 'owner' | 'group'>>,
): void {
  const existing = host.fs[path];
  host.fs[path] = {
    type: 'file',
    mode: meta?.mode ?? existing?.mode ?? 0o644,
    owner: meta?.owner ?? existing?.owner ?? 'root',
    group: meta?.group ?? existing?.group ?? 'root',
    content,
    mtime: time,
  };
}

export function mkdir(host: Host, path: string, time: number, meta?: Partial<Pick<FileNode, 'mode' | 'owner' | 'group'>>): void {
  host.fs[path] = {
    type: 'dir',
    mode: meta?.mode ?? 0o755,
    owner: meta?.owner ?? 'root',
    group: meta?.group ?? 'root',
    content: '',
    mtime: time,
  };
}

export function listDir(host: Host, path: string): string[] {
  const prefix = path === '/' ? '/' : path + '/';
  return Object.keys(host.fs)
    .filter((p) => p.startsWith(prefix) && p !== path && !p.slice(prefix.length).includes('/'))
    .map((p) => p.slice(prefix.length))
    .sort();
}

export function modeString(node: FileNode): string {
  const t = node.type === 'dir' ? 'd' : node.socket ? 's' : '-';
  const bits = ['r', 'w', 'x'];
  let s = '';
  for (let i = 8; i >= 0; i--) s += node.mode & (1 << i) ? bits[(8 - i) % 3] : '-';
  return t + s;
}

export function octal(mode: number): string {
  return mode.toString(8).padStart(4, '0');
}

const NFS_NOBODY: UserAccount = { name: 'nobody', uid: 65534, gid: 65534, primaryGroup: 'nogroup', groups: [], home: '/nonexistent', shell: '/usr/sbin/nologin', gecos: 'nobody', password: null };

/** Unix permission check for a non-root user (root bypasses read/write checks). */
export function canAccess(node: FileNode, user: UserAccount, want: 'r' | 'w' | 'x'): boolean {
  // NFS: the server decides with the export's options (read-only, root or all users squashed to nobody).
  if (node.nfs) {
    if (node.nfs.stale) return false;
    if (want === 'w' && node.nfs.ro) return false;
    if (node.nfs.squash === 'all' || (node.nfs.squash === 'root' && user.uid === 0)) user = NFS_NOBODY;
  }
  if (user.uid === 0) return want !== 'x' || node.type === 'dir' || (node.mode & 0o111) !== 0;
  const bit = want === 'r' ? 4 : want === 'w' ? 2 : 1;
  if (node.owner === user.name) return (node.mode & (bit << 6)) !== 0;
  if (node.group === user.primaryGroup || user.groups.includes(node.group)) return (node.mode & (bit << 3)) !== 0;
  return (node.mode & bit) !== 0;
}

/**
 * chmod/chown on an NFS file: the server checks the request as the squashed
 * user, so client root gets EPERM unless the export has no_root_squash.
 * Returns the error text, or null when allowed.
 */
export function nfsMetaDenied(node: FileNode, user: UserAccount, op: 'chmod' | 'chown'): string | null {
  if (!node.nfs) return null;
  if (node.nfs.stale) return 'Stale file handle';
  if (node.nfs.ro) return 'Read-only file system';
  const eff = node.nfs.squash === 'all' || (node.nfs.squash === 'root' && user.uid === 0) ? NFS_NOBODY : user;
  if (eff.uid === 0) return null;
  return op === 'chmod' && node.owner === eff.name ? null : 'Operation not permitted';
}

/** Ensure every ancestor directory of `path` is traversable by `user`. */
export function canTraverse(host: Host, path: string, user: UserAccount): boolean {
  let cur = dirname(path);
  const chain: string[] = [];
  while (true) {
    chain.push(cur);
    if (cur === '/') break;
    cur = dirname(cur);
  }
  return chain.every((d) => {
    const n = host.fs[d];
    return !n || canAccess(n, user, 'x');
  });
}

/**
 * Commit a modified copy of the world into WORLD in place: callers keep
 * references to WORLD's host objects (ctx.host), so hosts are updated
 * property by property instead of being replaced.
 */
export function mergeWorld(world: World, copy: World): void {
  const { hosts, ...rest } = copy;
  Object.assign(world, rest);
  for (const [id, h] of Object.entries(hosts)) { if (world.hosts[id]) Object.assign(world.hosts[id], h); else world.hosts[id] = h; }
  for (const id of Object.keys(world.hosts)) if (!hosts[id]) delete world.hosts[id];
}
