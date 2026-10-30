// Extra disks mounted on a host (e.g. bak01's /srv/backup). Usage is the sum
// of the nominal file sizes below the mount point plus a fixed base, so a
// backup repository that is never pruned really fills the disk. The backup
// tools (restic, rsync, tar) check the free space before writing.

import type { Host } from '../types';

export interface Disk {
  device: string;
  mount: string;
  /** Capacity in KiB. */
  sizeKB: number;
  /** KiB used by filesystem metadata and files the simulator does not model. */
  baseKB: number;
}

const blocksKB = (bytes: number) => Math.ceil(bytes / 4096) * 4;

/** The disk holding PATH (null: the root filesystem, which is never full in the simulator). */
export function diskOf(host: Host, path: string): Disk | null {
  let best: Disk | null = null;
  for (const d of host.disks ?? []) if ((path === d.mount || path.startsWith(d.mount + '/')) && (!best || d.mount.length > best.mount.length)) best = d;
  return best;
}

export function diskUsedKB(host: Host, d: Disk): number {
  let kb = d.baseKB;
  const pre = d.mount + '/';
  for (const [p, n] of Object.entries(host.fs)) if (p.startsWith(pre)) kb += n.type === 'dir' ? 4 : blocksKB(n.size ?? n.content.length);
  return kb;
}

/** Would writing BYTES more under PATH exceed the disk? */
export function noSpace(host: Host, path: string, bytes: number): boolean {
  const d = diskOf(host, path);
  return !!d && diskUsedKB(host, d) + blocksKB(bytes) > d.sizeKB;
}
