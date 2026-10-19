// Virtual filesystem helpers. Paths are absolute and normalised; directories are
// explicit nodes so that ownership/mode checks (e.g. sshd StrictModes) work on
// every path component.

import type { FileNode, Host, UserAccount } from './types';

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
  const t = node.type === 'dir' ? 'd' : '-';
  const bits = ['r', 'w', 'x'];
  let s = '';
  for (let i = 8; i >= 0; i--) s += node.mode & (1 << i) ? bits[(8 - i) % 3] : '-';
  return t + s;
}

export function octal(mode: number): string {
  return mode.toString(8).padStart(4, '0');
}

/** Unix permission check for a non-root user (root bypasses read/write checks). */
export function canAccess(node: FileNode, user: UserAccount, want: 'r' | 'w' | 'x'): boolean {
  if (user.uid === 0) return want !== 'x' || node.type === 'dir' || (node.mode & 0o111) !== 0;
  const bit = want === 'r' ? 4 : want === 'w' ? 2 : 1;
  if (node.owner === user.name) return (node.mode & (bit << 6)) !== 0;
  if (node.group === user.primaryGroup || user.groups.includes(node.group)) return (node.mode & (bit << 3)) !== 0;
  return (node.mode & bit) !== 0;
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
