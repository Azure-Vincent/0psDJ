// NFS and mounts: mount, umount, df, exportfs, showmount (nfs-common and
// nfs-kernel-server tools, util-linux mount), plus useradd.

import { diskUsedKB } from '../sim/disk';
import { readFile } from '../fs';
import { mountFor, mountNfs, type NfsServerLoaded, parseExports, parseFstab, umountNfs, EXPORTS } from '../sim/nfs';
import { reloadService, serviceDef } from '../sim/services';
import { resolve } from '../sim/dns';
import { isIpAddress } from '../net/addr';
import { hostAddresses } from '../sim/network';
import { tcpConnect } from '../sim/tcp';
import { type CommandDef, err, ok, parseFlags } from './types';

const ROOT_LINE = '/dev/vda1 on / type ext4 (rw,relatime,errors=remount-ro)';

const mount: CommandDef = {
  name: 'mount',
  summary: 'list mounts, mount an NFS export (-t nfs4 SERVER:/PATH DIR), or everything in /etc/fstab (-a)',
  usage: 'mount | mount -t nfs|nfs4 [-o OPTIONS] SERVER:/PATH DIR | mount -a | mount DIR',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args, ['-t', '-o']);
    const host = ctx.host;
    if (!rest.length && !flags.has('-a')) {
      const lines = [ROOT_LINE, ...(host.mounts ?? []).map((m) => `${m.source} on ${m.target} type nfs4 (${m.ro ? 'ro' : 'rw'},relatime,vers=4.2,rsize=1048576,wsize=1048576,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=${m.clientIp},local_lock=none,addr=${m.serverIp ?? ''})`)];
      const t = flags.get('-t');
      return ok((t ? lines.filter((l) => l.includes(`type ${t}`)) : lines).join('\n'));
    }
    if (ctx.user.uid !== 0) return err('mount: only root can do that', 1);
    const fstab = parseFstab(readFile(host, '/etc/fstab') ?? '');
    const doMount = (source: string, target: string, opts: string[]) => mountNfs(ctx.world, host, source, target, opts);
    if (flags.has('-a')) {
      const errors: string[] = [];
      for (const e of fstab) {
        if ((e.type !== 'nfs' && e.type !== 'nfs4') || e.options.includes('noauto') || mountFor(host, e.target)?.target === e.target) continue;
        const r = doMount(e.source, e.target, e.options);
        if (r) errors.push(r);
      }
      return errors.length ? err(errors.join('\n'), 32) : ok('');
    }
    if (rest.length === 1) {
      const e = fstab.find((x) => x.target === rest[0] || x.source === rest[0]);
      if (!e) return err(`mount: ${rest[0]}: can't find in /etc/fstab.`, 1);
      if (e.type !== 'nfs' && e.type !== 'nfs4') return err(`mount: ${e.target}: already mounted or mount point busy.`, 32);
      const r = doMount(e.source, e.target, e.options);
      return r ? err(r, 32) : ok('');
    }
    const type = flags.get('-t') as string | undefined;
    if (type && type !== 'nfs' && type !== 'nfs4') return err(`mount: ${rest[1]}: unknown filesystem type '${type}'.`, 32);
    if (!type && !rest[0].includes(':')) return err(`mount: ${rest[1]}: special device ${rest[0]} does not exist.`, 32);
    const r = doMount(rest[0], rest[1].replace(/\/+$/, '') || '/', String(flags.get('-o') ?? 'defaults').split(','));
    return r ? err(r, 32) : ok('');
  },
};

const umount: CommandDef = {
  name: 'umount',
  summary: 'unmount a filesystem',
  usage: 'umount DIR',
  run(args, ctx) {
    if (ctx.user.uid !== 0) return err(`umount: ${args[0] ?? ''}: must be superuser to unmount.`, 32);
    if (!args[0]) return err('umount: bad usage\nTry \'umount --help\' for more information.', 1);
    const target = args[args.length - 1].replace(/\/+$/, '');
    if (ctx.frame.cwd === target || ctx.frame.cwd.startsWith(target + "/")) return err(`umount.nfs4: ${target}: device is busy`, 32);
    const e = umountNfs(ctx.host, target);
    return e ? err(e, 32) : ok('');
  },
};

const df: CommandDef = {
  name: 'df',
  summary: 'show mounted filesystems and their usage',
  usage: 'df [-h] [-T]',
  run(args, ctx) {
    const h = args.some((a) => /^-\w*h/.test(a));
    const t = args.some((a) => /^-\w*T/.test(a));
    const head = `Filesystem${t ? '                    Type ' : '                   '} ${h ? ' Size  Used Avail Use%' : '1K-blocks    Used Available Use%'} Mounted on`;
    const row = (fs: string, type: string, size: string, used: string, avail: string, pct: string, on: string) => `${fs.padEnd(t ? 30 : 31)}${t ? type.padEnd(5) + ' ' : ''}${size.padStart(h ? 5 : 9)} ${used.padStart(h ? 5 : 7)} ${avail.padStart(h ? 5 : 9)} ${pct.padStart(4)} ${on}`;
    const lines = [head, h ? row('/dev/vda1', 'ext4', '20G', '3.1G', '16G', '17%', '/') : row('/dev/vda1', 'ext4', '20466256', '3201564', '16200344', '17%', '/')];
    const errors: string[] = [];
    for (const d of ctx.host.disks ?? []) {
      const used = Math.min(d.sizeKB, diskUsedKB(ctx.host, d));
      const avail = Math.max(0, Math.round(d.sizeKB * 0.95) - used);
      const pct = `${Math.ceil((used / Math.max(1, used + avail)) * 100)}%`;
      const hs = (kb: number) => (kb >= 1048576 ? `${(kb / 1048576).toFixed(kb >= 10 * 1048576 ? 0 : 1)}G` : kb >= 1024 ? `${Math.round(kb / 1024)}M` : `${kb}K`);
      lines.push(h ? row(d.device, 'ext4', hs(d.sizeKB), hs(used), hs(avail), pct, d.mount) : row(d.device, 'ext4', String(d.sizeKB), String(used), String(avail), pct, d.mount));
    }
    for (const m of ctx.host.mounts ?? []) {
      if (m.stale) { errors.push(`df: ${m.target}: Stale file handle`); continue; }
      lines.push(h ? row(m.source, 'nfs4', '98G', '12G', '81G', '13%', m.target) : row(m.source, 'nfs4', '102687672', '12582912', '84862212', '13%', m.target));
    }
    return errors.length ? { out: [...errors, ...lines].join('\n'), code: 1 } : ok(lines.join('\n'));
  },
};

function exportLine(path: string, spec: string, o: NfsServerLoaded['exports'][number]['clients'][number]['options']): string {
  const opts = ['sync', 'wdelay', 'hide', o.subtreeCheck ? 'subtree_check' : 'no_subtree_check', 'sec=sys', o.rw ? 'rw' : 'ro', 'secure', o.squash === 'none' ? 'no_root_squash' : 'root_squash', o.squash === 'all' ? 'all_squash' : 'no_all_squash'];
  if (!o.sync) opts[0] = 'async';
  return `${path.padEnd(14)}\t${spec}(${opts.join(',')})`;
}

const exportfs: CommandDef = {
  name: 'exportfs',
  summary: 'show (-v) or reload (-ra) the NFS export table',
  usage: 'exportfs -v | exportfs -ra | exportfs -s',
  run(args, ctx) {
    const rt = ctx.host.services['nfs-kernel-server'];
    if (!rt) return err('-bash: exportfs: command not found', 127);
    if (ctx.user.uid !== 0) return err('exportfs: could not open /var/lib/nfs/.etab.lock for locking: errno 13 (Permission denied)', 1);
    const flags = args.join('');
    if (/r/.test(flags)) {
      const parsed = parseExports(readFile(ctx.host, EXPORTS) ?? '');
      const missing = parsed.exports.filter((e) => ctx.host.fs[e.path]?.type !== 'dir').map((e) => `exportfs: Failed to stat ${e.path}: No such file or directory`);
      if (rt.state === 'active') reloadService(ctx.world, ctx.host, serviceDef('nfs-kernel-server')!);
      const msgs = [...parsed.errors, ...missing];
      return msgs.length ? err(msgs.join('\n'), 1) : ok('');
    }
    if (rt.state !== 'active') return ok('');
    const l = rt.loaded as NfsServerLoaded;
    const lines = l.exports.flatMap((e) => e.clients.map((c) => exportLine(e.path, c.spec, c.options)));
    if (/s/.test(flags)) return ok(lines.map((x) => x.replace(/ *\t/, '  ')).join('\n'));
    return ok(lines.join('\n'));
  },
};

const showmount: CommandDef = {
  name: 'showmount',
  summary: 'ask an NFS server for its export list (rpcbind and mountd)',
  usage: 'showmount -e SERVER',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args);
    const target = rest[0] ?? 'localhost';
    if (!flags.has('-e')) return err('showmount: this simulator supports -e', 1);
    let ip = isIpAddress(target) ? target : target === 'localhost' ? '127.0.0.1' : undefined;
    if (!ip) {
      const r = resolve(ctx.world, ctx.host, target, { family: 4 });
      if (!r.ok) return err(`clnt_create: RPC: Unknown host`, 1);
      ip = r.ip;
    }
    const server = ip === '127.0.0.1' ? ctx.host : Object.values(ctx.world.hosts).find((h) => hostAddresses(h).includes(ip!));
    const c = tcpConnect(ctx.world, ctx.host, ip, 111, { timeoutMs: 25_000 });
    if (!c.ok) return err(c.errno === 'ETIMEDOUT' ? 'clnt_create: RPC: Timed out' : 'clnt_create: RPC: Port mapper failure - Unable to receive: errno 111 (Connection refused)', 1);
    c.conn.close('client');
    const l = server?.services['nfs-kernel-server']?.loaded as NfsServerLoaded | undefined;
    if (!server || server.services['nfs-kernel-server']?.state !== 'active' || !l) return err('clnt_create: RPC: Program not registered', 1);
    return ok([`Export list for ${target}:`, ...l.exports.map((e) => `${e.path.padEnd(14)} ${e.clients.map((x) => x.spec).join(',')}`)].join('\n'));
  },
};

const useradd: CommandDef = {
  name: 'useradd',
  summary: 'create a user account (-u UID, -m, -s SHELL, -G GROUPS)',
  usage: 'useradd [-u UID] [-m] [-s SHELL] [-G GROUP,...] NAME',
  run(args, ctx) {
    if (ctx.user.uid !== 0) return err('useradd: Permission denied.\nuseradd: cannot lock /etc/passwd; try again later.', 1);
    const { flags, rest } = parseFlags(args, ['-u', '-s', '-G', '-c', '-g']);
    const name = rest[0];
    if (!name) return err('Usage: useradd [options] LOGIN', 2);
    if (ctx.host.users[name]) return err(`useradd: user '${name}' already exists`, 9);
    const used = Object.values(ctx.host.users).map((u) => u.uid);
    const uid = flags.has('-u') ? Number(flags.get('-u')) : Math.max(999, ...used.filter((u) => u < 60000)) + 1;
    if (!Number.isInteger(uid) || uid < 0) return err(`useradd: invalid user ID '${flags.get('-u')}'`, 3);
    if (used.includes(uid)) return err(`useradd: UID ${uid} is not unique`, 4);
    const home = `/home/${name}`;
    ctx.host.users[name] = { name, uid, gid: uid, primaryGroup: name, groups: flags.has('-G') ? String(flags.get('-G')).split(',') : [], home, shell: String(flags.get('-s') ?? '/bin/sh'), gecos: String(flags.get('-c') ?? ''), password: null };
    if (flags.has('-m') && !ctx.host.fs[home]) ctx.host.fs[home] = { type: 'dir', mode: 0o755, owner: name, group: name, content: '', mtime: ctx.world.clock };
    return ok('');
  },
};

export const NFS_COMMANDS: CommandDef[] = [mount, umount, df, exportfs, showmount, useradd];
