// Backups in the lab: bak01 (10.0.20.45) is the backup server. It keeps one
// restic repository per client under /srv/backup/restic on its own disk; the
// clients (srv01, db01, fs01) reach it over SFTP as the user restic, each with
// a dedicated SSH key that bak01 accepts only from that client's address.
//
// Every client has /etc/restic/{env,password,excludes}, the script
// /usr/local/sbin/restic-backup (backup, then retention with forget --prune),
// and the units restic-backup.service + restic-backup.timer (nightly,
// Persistent=true). The lab starts on a Monday morning with a week of
// nightly snapshots already in each repository.

import { mkdir, readFile, writeFile } from '../fs';
import { makeKeyPair } from '../sim/keys';
import { runtime, startUserService } from '../sim/timers';
import { Shell } from '../shell/shell';
import type { Host, World } from '../types';
import { addUser, createHost, staticInterfaces } from './builder';
import { archiveToCustom, dumpDatabase } from '../sim/pgsql';
import { installRsyslog } from './logLab';
import { TIMESYNCD_CONF } from './krbLab';
import { trustCorpRoot } from './pkiLab';
import { DEBIAN_SSHD_CONFIG, installHostKeys } from './sshLab';

void Shell; // the shell registers the runner that executes unit commands

export const BAK01_IP = '10.0.20.45';
export const BACKUP_CLIENTS = { srv01: '10.0.20.10', db01: '10.0.20.35', fs01: '10.0.20.60' } as const;
export type BackupClient = keyof typeof BACKUP_CLIENTS;
export const RESTIC_PASSWORDS: Record<BackupClient, string> = { srv01: 'Rst-srv01-26', db01: 'Rst-db01-26', fs01: 'Rst-fs01-26' };
export const BAK01_PASSWORDS = { alice: 'bak01-alice', restic: 'Restic-bak01-26' };
export const REPO_ROOT = '/srv/backup/restic';
export const repoUrl = (client: string) => `sftp:restic@bak01.corp.lab:${REPO_ROOT}/${client}`;

/** What each client backs up, and when its timer fires (after db01's pg-backup at 02:15). */
export const BACKUP_JOBS: Record<BackupClient, { paths: string[]; at: string }> = {
  srv01: { paths: ['/etc', '/var/www', '/root'], at: '02:30' },
  db01: { paths: ['/etc', '/var/backups/postgresql'], at: '02:45' },
  fs01: { paths: ['/etc', '/srv/projects', '/srv/office'], at: '03:00' },
};

export const BAK01_NFT = `#!/usr/sbin/nft -f

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iif "lo" accept
		meta l4proto icmp accept
		# SSH/SFTP from the server network (backup clients) and the office (administrators)
		ip saddr { 10.0.20.0/24, 10.0.10.0/24 } tcp dport 22 accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

export function backupScript(client: BackupClient): string {
  return `#!/bin/sh
# Nightly backup of ${client} to bak01 (CHG-2541): back up, then apply the retention policy.
# Repository and password come from /etc/restic/env (EnvironmentFile= of restic-backup.service).
set -e
restic backup --tag nightly --exclude-file /etc/restic/excludes ${BACKUP_JOBS[client].paths.join(' ')}
restic forget --tag nightly --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune
`;
}

export const BACKUP_SERVICE = `[Unit]
Description=Nightly restic backup to bak01
Documentation=https://restic.readthedocs.io/
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/restic/env
ExecStart=/usr/local/sbin/restic-backup
Nice=10
IOSchedulingClass=idle
`;

export function backupTimer(at: string): string {
  return `[Unit]
Description=Run the restic backup every night

[Timer]
OnCalendar=*-*-* ${at}:00
RandomizedDelaySec=5min
Persistent=true

[Install]
WantedBy=timers.target
`;
}

export function clientKey(client: string) {
  return makeKeyPair('ed25519', `restic-${client}-ed25519`, `root@${client} (restic backups)`);
}

function installBak01(world: World): Host {
  const t = world.clock;
  const h = createHost(world, {
    id: 'bak01', hostname: 'bak01', domain: 'corp.lab', role: 'Backup server (restic repositories over SFTP)',
    ifaces: [{ name: 'eth0', mac: '52:54:00:ba:00:2d', segment: null }],
    services: ['rsyslog', 'systemd-timesyncd', 'nftables', 'ssh'],
  });
  writeFile(h, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: `${BAK01_IP}/24`, gateway: '10.0.20.1' }]), t);
  writeFile(h, '/etc/resolv.conf', 'search corp.lab\nnameserver 10.0.10.53\n', t);
  writeFile(h, '/etc/ssh/sshd_config', DEBIAN_SSHD_CONFIG, t);
  writeFile(h, '/etc/nftables.conf', BAK01_NFT, t, { mode: 0o755 });
  mkdir(h, '/etc/systemd', t);
  writeFile(h, '/etc/systemd/timesyncd.conf', TIMESYNCD_CONF, t);
  installHostKeys(h, t);
  trustCorpRoot(h, t);
  installRsyslog(h, t, true);
  addUser(h, { name: 'alice', uid: 1000, gid: 1000, primaryGroup: 'alice', groups: ['sudo', 'adm'], home: '/home/alice', shell: '/bin/bash', gecos: 'Alice Admin', password: BAK01_PASSWORDS.alice }, t);
  // The repositories' owner. Clients log in with keys only (no password login is needed).
  addUser(h, { name: 'restic', uid: 1100, gid: 1100, primaryGroup: 'restic', groups: [], home: '/home/restic', shell: '/bin/bash', gecos: 'restic repositories', password: BAK01_PASSWORDS.restic }, t);
  // A separate disk for the repositories.
  h.disks = [{ device: '/dev/vdb1', mount: '/srv/backup', sizeKB: 20_466_256, baseKB: 1_536_000 }];
  if (!h.fs['/srv']) mkdir(h, '/srv', t);
  mkdir(h, '/srv/backup', t);
  writeFile(h, '/srv/backup/README', 'Backup disk (/dev/vdb1). One restic repository per client under restic/.\nRepositories are encrypted: bak01 cannot read them. Passwords are in the password safe (CHG-2541).\n', t);
  mkdir(h, REPO_ROOT, t, { mode: 0o750, owner: 'restic', group: 'restic' });
  mkdir(h, '/home/restic/.ssh', t, { mode: 0o700, owner: 'restic', group: 'restic' });
  const keys = (Object.keys(BACKUP_CLIENTS) as BackupClient[]).map((c) => `restrict,from="${BACKUP_CLIENTS[c]}" ${clientKey(c).publicLine}`);
  writeFile(h, '/home/restic/.ssh/authorized_keys', `# One key per backup client, usable only from that client's address (CHG-2541)\n${keys.join('\n')}\n`, t, { mode: 0o600, owner: 'restic', group: 'restic' });
  return h;
}

function installClient(world: World, client: BackupClient): void {
  const h = world.hosts[client];
  const t = world.clock;
  const bak = world.hosts.bak01;
  for (const d of ['/root/.ssh', '/etc/restic', '/usr/local', '/usr/local/sbin', '/etc/systemd', '/etc/systemd/system']) if (!h.fs[d]) mkdir(h, d, t, d === '/root/.ssh' || d === '/etc/restic' ? { mode: 0o700 } : undefined);
  const k = clientKey(client);
  writeFile(h, '/root/.ssh/id_ed25519', k.privateFile, t, { mode: 0o600 });
  writeFile(h, '/root/.ssh/id_ed25519.pub', k.publicLine + '\n', t);
  const hostKey = (readFile(bak, '/etc/ssh/ssh_host_ed25519_key.pub') ?? '').trim().split(/\s+/).slice(0, 2).join(' ');
  writeFile(h, '/root/.ssh/known_hosts', `${readFile(h, '/root/.ssh/known_hosts') ?? ''}bak01.corp.lab ${hostKey}\n`, t, { mode: 0o644 });
  writeFile(h, '/etc/restic/env', `# restic settings for restic-backup.service (CHG-2541)\nRESTIC_REPOSITORY=${repoUrl(client)}\nRESTIC_PASSWORD_FILE=/etc/restic/password\n`, t, { mode: 0o600 });
  writeFile(h, '/etc/restic/password', RESTIC_PASSWORDS[client] + '\n', t, { mode: 0o600 });
  writeFile(h, '/etc/restic/excludes', '# Not worth backing up\n/root/.cache\n*.tmp\n*.swp\n', t, { mode: 0o644 });
  writeFile(h, '/usr/local/sbin/restic-backup', backupScript(client), t, { mode: 0o755 });
  writeFile(h, '/etc/systemd/system/restic-backup.service', BACKUP_SERVICE, t);
  writeFile(h, '/etc/systemd/system/restic-backup.timer', backupTimer(BACKUP_JOBS[client].at), t);
  runtime(h, 'restic-backup.timer').enabled = true;
}

/** bak01 and the backup jobs of srv01, db01 and fs01 (before the hosts boot). */
export function installBackups(world: World): Host {
  const h = installBak01(world);
  for (const c of Object.keys(BACKUP_CLIENTS) as BackupClient[]) installClient(world, c);
  return h;
}

/**
 * A week of nightly backups before the lab starts (Monday 2026-10-19, 07:58):
 * each repository was initialised on Sunday 2026-10-11 and the timers ran every
 * night since. Runs happen at their real times, so snapshots, the journal and
 * list-timers agree.
 */
export function seedBackupHistory(world: World): void {
  const now = world.clock;
  const day = (d: number, hhmm: string) => Date.parse(`2026-10-${String(d).padStart(2, '0')}T${hhmm}:00Z`);
  world.clock = day(11, '22:10');
  for (const c of Object.keys(BACKUP_CLIENTS) as BackupClient[]) {
    let w = world;
    const sh = new Shell(() => w, (n) => (w = n), { hostId: c, user: 'root', cwd: '/root', env: {}, vars: {} });
    sh.execute(`restic init -r ${repoUrl(c)} --password-file /etc/restic/password`);
    Object.assign(world, w);
    world.clock += 60_000;
  }
  for (let d = 12; d <= 19; d++) {
    // db01's pg-backup (02:15) writes the dump the restic job picks up.
    world.clock = day(d, '02:15');
    const db = world.hosts.db01;
    const dump = dumpDatabase({ world, server: db, user: 'backup', db: 'inventory', pid: 0, settings: {} });
    if (dump.ok) writeFile(db, '/var/backups/postgresql/inventory.dump', archiveToCustom({ ...dump.archive, createdAt: world.clock }), world.clock, { mode: 0o644 });
    // The file server changes during the day.
    const fs = world.hosts.fs01;
    writeFile(fs, `/srv/projects/inventory/report-2026-10-${String(d - 1).padStart(2, '0')}.txt`, `Daily inventory report ${d - 1} Oct: ${30 + d} items checked\n`, day(d - 1, '16:40'), { mode: 0o664, owner: 'alice', group: 'alice' });
    for (const c of Object.keys(BACKUP_CLIENTS) as BackupClient[]) {
      const h = world.hosts[c];
      world.clock = Math.max(world.clock, day(d, BACKUP_JOBS[c].at) + 7_000);
      const rt = runtime(h, 'restic-backup.timer');
      rt.lastTrigger = world.clock;
      for (const dir of ['/var/lib', '/var/lib/systemd', '/var/lib/systemd/timers']) if (!h.fs[dir]) mkdir(h, dir, world.clock);
      writeFile(h, '/var/lib/systemd/timers/stamp-restic-backup.timer', '', world.clock);
      startUserService(world, h, 'restic-backup.service');
    }
  }
  world.clock = Math.max(world.clock, now);
  // The machines booted at 07:58 this morning: these runs belong to earlier boots in the journal.
  for (const h of Object.values(world.hosts)) h.journal.sort((a, b) => a.time - b.time);
}
