// Backup tickets: restic over SFTP to bak01, scheduled by systemd timers on
// srv01, db01 and fs01. Each one breaks something an administrator meets in
// real backup operations: a timer edit that systemd rejects, a reinstalled
// backup server with new host keys, a stale repository lock after a power
// cut, a moved environment file, a full backup disk, a file restore, and an
// exclude pattern that silently drops the database dumps.

import { readFile, writeFile } from '../fs';
import { BACKUP_CLIENTS, type BackupClient, REPO_ROOT } from '../lab/backupLab';
import { hostKeyPair } from '../lab/sshLab';
import { nextElapse, parseCalendar, parseUnit, runDueTimers, runtime } from '../sim/timers';
import type { World } from '../types';
import { sha256Hex } from '../util/sha256';
import { script } from './engine';
import type { Constraint, Goal, Scenario } from './types';

const ENV = 'set -a; . /etc/restic/env; set +a';

const BRIEFING = [
  'bak01 (10.0.20.45) is the backup server: one restic repository per client in /srv/backup/restic/<host> on its own disk (/dev/vdb1, mounted on /srv/backup), owned by the user restic. Clients connect over SFTP (sftp:restic@bak01.corp.lab:…) with a dedicated key (/root/.ssh/id_ed25519) that bak01 accepts only from the client\'s address (authorized_keys from="…").',
  'On srv01, db01 and fs01: /etc/restic/env (RESTIC_REPOSITORY, RESTIC_PASSWORD_FILE), /etc/restic/password, /etc/restic/excludes; /usr/local/sbin/restic-backup backs up and applies the retention policy (forget --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune). restic-backup.timer starts restic-backup.service every night (srv01 02:30, db01 02:45 after pg-backup, fs01 03:00).',
  `Look at a job: systemctl list-timers, systemctl status restic-backup.service, journalctl -u restic-backup. Use restic by hand with the job's settings: ${ENV}; restic snapshots.`,
  'Policy: repositories keep their history (never re-initialise or delete one to "fix" it), host keys are verified, not ignored, and passwords stay readable by root only. Fixes must survive a reboot.',
];

const TERMINALS = [
  { hostId: 'srv01', user: 'root', label: 'srv01 (web server)', banner: `srv01: nightly backup to bak01. Try: systemctl list-timers, systemctl status restic-backup, journalctl -u restic-backup -n 20, ${ENV}; restic snapshots.` },
  { hostId: 'db01', user: 'root', label: 'db01 (database server)', banner: 'db01: pg-backup dumps the database at 02:15, restic backs up the dump at 02:45. Try: systemctl list-timers, ls -l /var/backups/postgresql.' },
  { hostId: 'fs01', user: 'root', label: 'fs01 (file server)', banner: 'fs01: /srv/projects and /srv/office are backed up at 03:00. Try: systemctl status restic-backup, cat /etc/restic/env.' },
  { hostId: 'bak01', user: 'root', label: 'bak01 (backup server)', banner: 'bak01: repositories in /srv/backup/restic. Try: df -h, du -sh /srv/backup/*, ls -l /srv/backup/restic, journalctl -u ssh -n 20.' },
];

const CANDIDATES = [
  'bk-timer-invalid', 'bk-timer-disabled', 'bk-hostkey-changed', 'bk-key-rejected', 'bk-stale-lock', 'bk-envfile-missing',
  'bk-wrong-password', 'bk-disk-full', 'bk-file-deleted', 'bk-exclude-too-broad', 'dns-wrong-record', 'firewall-drop',
];

const DAY = 24 * 3_600_000;

/** Nights pass: the timers fire at their times on every host. */
export function nights(world: World, n: number, morning = '08:40'): void {
  const d = new Date(world.clock + n * DAY);
  const [h, m] = morning.split(':').map(Number);
  world.clock = Math.max(world.clock, Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), h, m));
  runDueTimers(world);
}

const backupNow = (host: BackupClient): Goal => ({
  kind: 'command',
  description: `On ${host}, the backup job runs successfully (systemctl start restic-backup.service).`,
  steps: [{ host, user: 'root', command: 'systemctl start restic-backup.service && echo BACKUP-OK' }],
  expect: '^BACKUP-OK$',
});

interface RepoSnap { time: number; paths: string[]; files: { p: string }[] }
function repoSnapshots(world: World, client: string): RepoSnap[] {
  const pre = `${REPO_ROOT}/${client}/snapshots/`;
  const fs = world.hosts.bak01.fs;
  return Object.keys(fs).filter((p) => p.startsWith(pre)).map((p) => { try { return JSON.parse(fs[p].content) as RepoSnap; } catch { return null; } }).filter((s): s is RepoSnap => !!s).sort((a, b) => a.time - b.time);
}

/** The repositories keep their history: snapshots from before the incident are still there. */
function historyKept(...clients: BackupClient[]): Constraint {
  const before = Date.parse('2026-10-19T12:00:00Z');
  return {
    id: 'bk-history-kept', required: true,
    description: `The repositories of ${clients.join(', ')} still hold their snapshots from before the incident (at least 5 each) and are intact.`,
    check(world) {
      for (const c of clients) {
        const old = repoSnapshots(world, c).filter((s) => s.time < before).length;
        if (!world.hosts.bak01.fs[`${REPO_ROOT}/${c}/config`]) return { id: this.id, ok: false, required: true, message: `${c}'s repository has no config any more: it was deleted or re-initialised, and its history is gone.` };
        if (old < 5) return { id: this.id, ok: false, required: true, message: `${c}'s repository lost its history (${old} snapshots from before 19 Oct left): never delete snapshots or repositories to make a job pass.` };
      }
      return { id: this.id, ok: true, required: true, message: 'The repositories keep their history.' };
    },
  };
}

/** The world after each client's job ran once more (constraints look at what the job does now, not at old snapshots). */
function afterRun(world: World, clients: BackupClient[]): World {
  const copy = structuredClone(world);
  for (const c of clients) script(copy, c, ['systemctl start restic-backup.service']);
  return copy;
}
/** The jobs still write to the clients' own repositories (no new repository started next to the old one). */
function sameRepository(...clients: BackupClient[]): Constraint {
  return {
    id: 'bk-same-repo', required: true,
    description: `The backup jobs of ${clients.join(', ')} still write to their existing repositories in ${REPO_ROOT}, so history and retention continue.`,
    check(world) {
      const after = afterRun(world, clients);
      for (const c of clients) {
        const pre = `${REPO_ROOT}/${c}/snapshots/`;
        if (!Object.keys(after.hosts.bak01.fs).some((p) => p.startsWith(pre) && !world.hosts.bak01.fs[p])) {
          return { id: this.id, ok: false, required: true, message: `${c}'s job no longer adds snapshots to ${REPO_ROOT}/${c}: keep the existing repository (and its password) instead of starting a new one.` };
        }
      }
      return { id: this.id, ok: true, required: true, message: 'The jobs write to their existing repositories.' };
    },
  };
}
function passwordsProtected(...clients: BackupClient[]): Constraint {
  return {
    id: 'bk-password-protected', required: true,
    description: 'The repository password files stay readable by root only (mode 0600 or 0400, owner root).',
    check(world) {
      for (const c of clients) {
        const n = world.hosts[c].fs['/etc/restic/password'];
        if (!n || n.owner !== 'root' || (n.mode & 0o077) !== 0) return { id: this.id, ok: false, required: true, message: `/etc/restic/password on ${c} is ${n ? `mode ${(n.mode & 0o777).toString(8)} owner ${n.owner}` : 'missing'}: whoever reads it can decrypt every backup of ${c}.` };
      }
      return { id: this.id, ok: true, required: true, message: 'Password files are root-only.' };
    },
  };
}

const NEW_BAK01_KEY = hostKeyPair('bak01', 'ed25519', 2);

export const BACKUP_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'bk-timer-calendar',
    title: 'Backups twice a day',
    difficulty: 'intermediate',
    ticket: 'Web team: "On Monday (CHG-2560) srv01 was supposed to start backing up twice a day, at 02:30 and 14:30, because the site content now changes during the day. bak01\'s report says srv01\'s newest snapshot is from Monday 02:30, three days ago." The other servers are fine.',
    briefing: BRIEFING,
    goals: [
      { kind: 'command', description: 'On srv01, restic-backup.timer is active (waiting for its next run).', steps: [{ host: 'srv01', user: 'root', command: 'systemctl is-active restic-backup.timer' }], expect: '^active$' },
      { kind: 'command', description: 'srv01 has a snapshot from today (the missed run caught up).', steps: [{ host: 'srv01', user: 'root', command: `${ENV}; restic snapshots --latest 1 --json` }], expect: '"time":"2026-10-2[2-9]' },
    ],
    terminals: TERMINALS,
    setup(world) {
      script(world, 'srv01', [
        "sed -i 's/^OnCalendar=.*/OnCalendar=*-*-* 02:30 14:30/' /etc/systemd/system/restic-backup.timer",
        'systemctl daemon-reload',
        'systemctl restart restic-backup.timer',
      ]);
      nights(world, 3);
    },
    rootCauses: ['bk-timer-invalid'],
    acceptable: { 'bk-timer-disabled': 'Close: the timer is not running, but because systemd refused its OnCalendar= line, not because someone disabled it (it is still enabled).' },
    candidates: CANDIDATES,
    feedback: {
      'bk-hostkey-changed': 'The other servers back up to bak01 every night, and srv01 has no failed job in its journal: the job never started.',
      'bk-stale-lock': 'A lock would make the job start and fail; here restic-backup.service has not run at all since Monday.',
      'bk-envfile-missing': 'The service never ran, so it never read its environment file.',
    },
    hints: [
      'Is the job scheduled at all? systemctl list-timers on srv01 lists no restic timer; systemctl status restic-backup.timer says why.',
      'The timer failed when it was restarted after the edit: "Failed to parse calendar specification, ignoring: *-*-* 02:30 14:30" and "Timer unit lacks value setting. Refusing." Test expressions with systemd-analyze calendar.',
      'Use two OnCalendar= lines (02:30 and 14:30) or one expression such as "*-*-* 02,14:30:00", then systemctl daemon-reload and systemctl restart restic-backup.timer. With Persistent=true the missed run starts right away.',
    ],
    explanation: {
      rootCause: 'The new OnCalendar= value "*-*-* 02:30 14:30" is not a valid calendar expression (one expression has one time part). systemd ignored it, found no trigger left in the timer and refused to start it, so no backup has run since.',
      manifestation: 'No error anywhere the team looks: the timer simply disappeared from systemctl list-timers, and the newest snapshot ages day after day.',
      evidence: 'systemctl status restic-backup.timer: failed (Result: resources); journal: "Failed to parse calendar specification, ignoring: *-*-* 02:30 14:30" and "restic-backup.timer: Timer unit lacks value setting. Refusing."; systemd-analyze calendar "*-*-* 02:30 14:30" fails.',
      prevention: 'Check calendar expressions with systemd-analyze calendar (and units with systemd-analyze verify) before reloading; after any change look at systemctl list-timers; monitor the age of the newest snapshot, not only failed jobs.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i 's/^OnCalendar=.*/OnCalendar=*-*-* 02:30:00\\nOnCalendar=*-*-* 14:30:00/' /etc/systemd/system/restic-backup.timer", 'systemctl daemon-reload', 'systemctl restart restic-backup.timer'] }],
    constraints: [historyKept('srv01'), sameRepository('srv01'), {
      id: 'bk-twice-daily', required: true,
      description: 'srv01\'s timer fires at 02:30 and at 14:30 every day (CHG-2560) and keeps Persistent=true.',
      check(world) {
        const t = parseUnit(runtime(world.hosts.srv01, 'restic-backup.timer').loaded ?? readFile(world.hosts.srv01, '/etc/systemd/system/restic-backup.timer') ?? '');
        const specs = (t.Timer?.OnCalendar ?? []).map(parseCalendar).filter((c) => !!c);
        const day0 = Date.parse('2026-10-25T00:00:00Z');
        const times = new Set<string>();
        for (const c of specs) for (let at = day0 - 1; ;) { const n = nextElapse(c!, at); if (n === null || n >= day0 + DAY) break; times.add(new Date(n).toISOString().slice(11, 16)); at = n; }
        const ok = times.has('02:30') && times.has('14:30') && /^(yes|true|1|on)$/i.test(t.Timer?.Persistent?.at(-1) ?? '');
        return { id: this.id, ok, required: true, message: ok ? 'The timer fires at 02:30 and 14:30 and catches up missed runs.' : `The timer fires at ${[...times].sort().join(', ') || 'no time at all'}${/^(yes|true|1|on)$/i.test(t.Timer?.Persistent?.at(-1) ?? '') ? '' : ' and lost Persistent=true'}: the change asked for 02:30 and 14:30.` };
      },
    }],
    concepts: ['bk.schedule', 'svc.systemd'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'bk-hostkey-changed',
    title: 'After the backup server was reinstalled',
    difficulty: 'intermediate',
    ticket: `Infrastructure: "bak01 was reinstalled from the new Debian image yesterday (CHG-2563); the backup disk /srv/backup and /home were kept. Since then every nightly backup fails. Its new SSH host key fingerprint, from the console: ED25519 ${NEW_BAK01_KEY.fingerprint}."`,
    briefing: BRIEFING,
    goals: (['srv01', 'db01', 'fs01'] as BackupClient[]).map(backupNow),
    terminals: TERMINALS,
    setup(world) {
      const b = world.hosts.bak01;
      for (const type of ['rsa', 'ecdsa', 'ed25519'] as const) {
        const kp = hostKeyPair('bak01', type, 2);
        writeFile(b, `/etc/ssh/ssh_host_${type}_key`, kp.privateFile, world.clock, { mode: 0o600 });
        writeFile(b, `/etc/ssh/ssh_host_${type}_key.pub`, kp.publicLine + '\n', world.clock);
      }
      script(world, 'bak01', ['systemctl restart ssh']);
      nights(world, 1);
    },
    rootCauses: ['bk-hostkey-changed'],
    candidates: CANDIDATES,
    feedback: {
      'bk-key-rejected': 'The clients never get as far as offering their key: ssh stops at the host key check, before authentication.',
      'firewall-drop': 'The TCP connection works (ssh receives a host key); a drop would time out.',
      'bk-wrong-password': 'restic never reaches the repository, so the password is not checked.',
    },
    hints: [
      'journalctl -u restic-backup -n 20 on any client: what does "subprocess ssh:" print?',
      'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED: the clients remember bak01\'s old key in /root/.ssh/known_hosts. Here the change is expected (the reinstall), but confirm the new key against the fingerprint from the ticket before trusting it.',
      'On each client: ssh-keygen -R bak01.corp.lab, then ssh-keyscan -t ed25519 bak01.corp.lab > /tmp/k; ssh-keygen -lf /tmp/k (compare with the ticket); cat /tmp/k >> /root/.ssh/known_hosts. Then systemctl start restic-backup.service.',
    ],
    explanation: {
      rootCause: 'Reinstalling bak01 generated new SSH host keys. The clients\' known_hosts still hold the old ones, so OpenSSH refuses the connection (it cannot tell a reinstall from a man-in-the-middle), and restic\'s SFTP session never starts.',
      manifestation: 'Every client\'s nightly job fails at the same moment; bak01\'s sshd logs only a connection closed before authentication.',
      evidence: 'Client journal: "subprocess ssh: @@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@ … Host key verification failed." then "Fatal: unable to open repository at sftp:… unable to start the sftp session, error: EOF".',
      prevention: 'Back up /etc/ssh/ssh_host_* with the server (and restore them on reinstall), or publish the new fingerprints with the change and update known_hosts on the clients as part of it. Never disable StrictHostKeyChecking for backup jobs.',
    },
    solution: (['srv01', 'db01', 'fs01'] as BackupClient[]).map((host) => ({ host, commands: ['ssh-keygen -R bak01.corp.lab', 'ssh-keyscan -t ed25519 bak01.corp.lab > /tmp/bak01.key', 'ssh-keygen -lf /tmp/bak01.key', 'cat /tmp/bak01.key >> /root/.ssh/known_hosts'] })),
    constraints: [historyKept('srv01', 'db01', 'fs01'), sameRepository('srv01', 'db01', 'fs01'), {
      id: 'bk-known-host', required: true,
      description: 'Each client\'s known_hosts trusts exactly bak01\'s new key (no old key left for bak01.corp.lab, no checking switched off).',
      check(world) {
        const blob = NEW_BAK01_KEY.blobB64;
        for (const c of Object.keys(BACKUP_CLIENTS) as BackupClient[]) {
          const h = world.hosts[c];
          const kh = (readFile(h, '/root/.ssh/known_hosts') ?? '').split('\n').filter((l) => /(^|,)bak01\.corp\.lab(,|\s)/.test(l));
          const cfg = `${readFile(h, '/root/.ssh/config') ?? ''}\n${readFile(h, '/etc/ssh/ssh_config') ?? ''}`;
          if (/stricthostkeychecking\s*=?\s*no|userknownhostsfile\s*=?\s*\/dev\/null/i.test(cfg)) return { id: this.id, ok: false, required: true, message: `${c} switched host key checking off: anyone answering as bak01 would receive the backups.` };
          if (!kh.some((l) => l.includes(blob))) return { id: this.id, ok: false, required: true, message: `${c} does not trust bak01's new key in /root/.ssh/known_hosts.` };
          if (kh.some((l) => !l.includes(blob) && /ssh-ed25519|ecdsa|ssh-rsa/.test(l))) return { id: this.id, ok: false, required: true, message: `${c} still has another key for bak01.corp.lab in known_hosts (remove the old one with ssh-keygen -R).` };
        }
        return { id: this.id, ok: true, required: true, message: 'Every client trusts bak01\'s new key, and only it.' };
      },
    }],
    concepts: ['bk.transport', 'ssh.hostkeys'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'bk-stale-lock',
    title: 'After the power cut',
    difficulty: 'intermediate',
    ticket: 'Monitoring: "restic-backup.service on srv01 failed two nights in a row." Facilities note: bak01 lost power for a few minutes on Monday at 02:31 (UPS battery replaced since). db01 and fs01 back up normally.',
    briefing: BRIEFING,
    goals: [backupNow('srv01')],
    terminals: TERMINALS,
    setup(world) {
      // srv01's prune was running when bak01 lost power: its exclusive lock stayed in the repository.
      const b = world.hosts.bak01;
      const at = Date.parse('2026-10-19T02:31:12Z');
      const id = sha256Hex('stale-lock-srv01');
      writeFile(b, `${REPO_ROOT}/srv01/locks/${id}`, JSON.stringify({ time: at, exclusive: true, hostname: 'srv01', username: 'root', pid: 2011, uid: 0, gid: 0 }), at, { mode: 0o600, owner: 'restic', group: 'restic' });
      nights(world, 2);
    },
    rootCauses: ['bk-stale-lock'],
    candidates: CANDIDATES,
    feedback: {
      'bk-hostkey-changed': 'restic opens the repository (it prints "repository … opened"): SSH and the host key are fine.',
      'bk-wrong-password': 'The repository opens, so the password is right.',
      'bk-disk-full': 'db01 and fs01 write to the same disk every night without trouble.',
    },
    hints: [
      'journalctl -u restic-backup -n 20 on srv01: the job fails right after opening the repository. What does restic say?',
      '"repository is already locked exclusively by PID 2011 on srv01": restic\'s lock files (in the repository\'s locks/ directory) are normally removed when a command ends. This one is from the prune that was cut off on Monday. Is any restic process still running? (The lock is days old.)',
      `On srv01: ${ENV}; restic unlock (removes stale locks only), then systemctl start restic-backup.service.`,
    ],
    explanation: {
      rootCause: 'bak01 lost power while srv01\'s nightly prune held an exclusive lock on the repository. The lock file stayed behind, and restic refuses to back up into a repository that another process may be modifying.',
      manifestation: 'Only srv01\'s job fails, every night, right after "repository … opened"; nothing is wrong with SSH, the password or the disk.',
      evidence: 'Journal: "unable to create lock in backend: repository is already locked exclusively by PID 2011 on srv01 by root … lock was created at 2026-10-19 02:31:12 … the `unlock` command can be used to remove stale locks"; bak01: /srv/backup/restic/srv01/locks/ holds one old file.',
      prevention: 'After an outage, check every backup job the next day (systemctl --failed, list-timers, snapshot age). Keep prune on a separate, less frequent schedule; run restic check after crashes. A UPS with automatic shutdown protects the repositories.',
    },
    solution: [{ host: 'srv01', commands: [`${ENV}; restic unlock`] }],
    constraints: [historyKept('srv01'), sameRepository('srv01')],
    concepts: ['bk.operate'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'bk-envfile',
    title: 'Tidying up /etc/restic',
    difficulty: 'beginner',
    ticket: 'Monitoring: "restic-backup.service failed on fs01 last night." Change log: yesterday afternoon a colleague renamed the configuration files on fs01 to the new naming standard (*.env for environment files).',
    briefing: BRIEFING,
    goals: [backupNow('fs01')],
    terminals: TERMINALS,
    setup(world) {
      script(world, 'fs01', ['mv /etc/restic/env /etc/restic/restic.env']);
      nights(world, 1);
    },
    rootCauses: ['bk-envfile-missing'],
    candidates: CANDIDATES,
    feedback: {
      'bk-wrong-password': 'restic never ran: systemd stopped before starting it.',
      'bk-hostkey-changed': 'No ssh output at all in the journal: restic was never started.',
      'bk-timer-invalid': 'The timer did fire (systemctl list-timers shows last night\'s run); the service failed.',
    },
    hints: [
      'systemctl status restic-backup.service on fs01: Result is "resources", not "exit-code". What did systemd fail to do before starting the command?',
      '"Failed to load environment files: No such file or directory": the unit reads EnvironmentFile=/etc/restic/env, which no longer exists.',
      'Either rename the file back (mv /etc/restic/restic.env /etc/restic/env) or change EnvironmentFile= in /etc/systemd/system/restic-backup.service and run systemctl daemon-reload. Then systemctl start restic-backup.service.',
    ],
    explanation: {
      rootCause: 'The unit loads its settings with EnvironmentFile=/etc/restic/env. After the rename that file is gone; a missing EnvironmentFile (without the "-" prefix) is a hard error, so systemd never started the backup command.',
      manifestation: 'The timer fires on time but the service fails instantly with Result=resources and no output from restic.',
      evidence: 'Journal: "restic-backup.service: Failed to load environment files: No such file or directory", "Failed to run \'start\' task", "Failed with result \'resources\'".',
      prevention: 'Search for references (grep -r /etc/restic/env /etc/systemd /usr/local/sbin) before renaming files, and run the job by hand (systemctl start) after any change to it.',
    },
    solution: [{ host: 'fs01', commands: ['mv /etc/restic/restic.env /etc/restic/env'] }],
    constraints: [historyKept('fs01'), sameRepository('fs01'), passwordsProtected('fs01')],
    concepts: ['bk.schedule', 'svc.systemd'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'bk-disk-full',
    title: 'All backups failed',
    difficulty: 'intermediate',
    ticket: 'Monitoring: "restic-backup.service failed on srv01, db01 and fs01 last night." Background: during the September file server migration (CHG-2488, closed on 2 October) a disk image of the old server was parked on bak01; the migration team confirmed nothing on bak01 outside restic/ is needed any more.',
    briefing: BRIEFING,
    goals: [backupNow('srv01'), backupNow('fs01')],
    terminals: TERMINALS,
    setup(world) {
      const b = world.hosts.bak01;
      writeFile(b, '/srv/backup/fs-old.img', '(disk image of the old file server, CHG-2488)\n', Date.parse('2026-09-21T15:12:00Z'), { mode: 0o600 });
      const disk = b.disks![0];
      let used = disk.baseKB;
      for (const [p, n] of Object.entries(b.fs)) if (p.startsWith('/srv/backup/') && p !== '/srv/backup/fs-old.img') used += n.type === 'dir' ? 4 : Math.ceil((n.size ?? n.content.length) / 4096) * 4;
      // The image fills the disk up to the 5% ext4 keeps for root: restic (an ordinary user) can write nothing more.
      b.fs['/srv/backup/fs-old.img'].size = (Math.floor(disk.sizeKB * 0.95) - used) * 1024;
      nights(world, 1);
    },
    rootCauses: ['bk-disk-full'],
    candidates: CANDIDATES,
    feedback: {
      'bk-stale-lock': 'The jobs get further than locking: they fail while writing data.',
      'bk-hostkey-changed': 'SSH works: restic opens the repositories and starts writing.',
      'bk-wrong-password': 'The repositories open, so the passwords are right.',
    },
    hints: [
      'journalctl -u restic-backup -n 20 on srv01: which step fails, and what does the server answer?',
      'sftp: "Failure" (SSH_FX_FAILURE) while writing: look at bak01 itself. df -h /srv/backup, then du -sh /srv/backup/* to find what uses the space.',
      'fs-old.img fills the disk; the ticket confirms it is no longer needed. Remove it on bak01 (rm /srv/backup/fs-old.img), then run the backups again. Do not delete snapshots to make room.',
    ],
    explanation: {
      rootCause: 'bak01\'s backup disk is full: a forgotten 18 GB disk image from the migration took the space the repositories grow into. restic\'s writes over SFTP fail and the jobs exit with an error.',
      manifestation: 'Every client fails on the same night, after opening its repository, with a generic SFTP failure; the clients\' own disks are fine.',
      evidence: 'Client journal: "Fatal: unable to save snapshot: Write: sftp: "Failure" (SSH_FX_FAILURE)"; bak01: df shows /srv/backup at 100%; du -sh /srv/backup/* shows fs-old.img.',
      prevention: 'Monitor free space on backup storage with an alert well before 100%; keep the backup disk for repositories only; let prune enforce the retention policy so the repositories stay a predictable size.',
    },
    solution: [{ host: 'bak01', commands: ['rm /srv/backup/fs-old.img'] }],
    constraints: [historyKept('srv01', 'db01', 'fs01'), sameRepository('srv01', 'db01', 'fs01')],
    concepts: ['bk.operate'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'bk-restore-file',
    title: 'The budget file is gone',
    difficulty: 'beginner',
    ticket: 'Finance (dana): "I deleted budget-2025.txt from the office share by mistake this morning. Can you get back the version from yesterday? We already saved today\'s meeting minutes in the share, please don\'t lose those." The share is /srv/office on fs01.',
    briefing: BRIEFING,
    goals: [
      { kind: 'command', description: '/srv/office/budget-2025.txt is back on fs01 with its content, owner (dana), group (staff) and mode (0660).', steps: [{ host: 'fs01', user: 'root', command: 'ls -l /srv/office/budget-2025.txt' }], expect: '^-rw-rw---- 1 dana +staff .*budget-2025\\.txt$' },
      { kind: 'command', description: 'The restored file has yesterday\'s content.', steps: [{ host: 'fs01', user: 'root', command: 'cat /srv/office/budget-2025.txt' }], expect: '^licences 18500$' },
    ],
    terminals: TERMINALS,
    setup(world) {
      script(world, 'fs01', [
        'printf "Weekly IT meeting: backup restore drill planned for Friday.\\n" > /srv/office/minutes/2026-10-19.txt',
        'chown alice:staff /srv/office/minutes/2026-10-19.txt',
        'chmod 660 /srv/office/minutes/2026-10-19.txt',
        'rm /srv/office/budget-2025.txt',
      ]);
    },
    rootCauses: ['bk-file-deleted'],
    candidates: CANDIDATES,
    feedback: {
      'bk-envfile-missing': 'The backups run fine; this is a restore request.',
      'bk-disk-full': 'Nothing is failing: the file was deleted by a user.',
    },
    hints: [
      `Find the file in the backups on fs01: ${ENV}; restic snapshots, then restic ls latest /srv/office.`,
      'Restore it somewhere safe first, not over the share: restic restore latest --target /tmp/restore --include /srv/office/budget-2025.txt (it lands in /tmp/restore/srv/office/).',
      'Check it, then copy it back keeping owner, group and mode: cp -a /tmp/restore/srv/office/budget-2025.txt /srv/office/. Restoring the whole /srv/office would roll back today\'s minutes.',
    ],
    explanation: {
      rootCause: 'A user deleted a file on the share. Last night\'s restic snapshot of fs01 still has it.',
      manifestation: 'One file missing; the server and the share are fine.',
      evidence: 'restic ls latest /srv/office lists budget-2025.txt; ls /srv/office does not.',
      prevention: 'Restores are routine work: practise them (a monthly restore drill), restore to a separate place first, and restore only what was asked for so newer work is not overwritten. Shares with snapshots or a recycle bin let users recover such files themselves.',
    },
    solution: [{ host: 'fs01', commands: [`${ENV}; restic restore latest --target /tmp/restore --include /srv/office/budget-2025.txt`, 'cp -a /tmp/restore/srv/office/budget-2025.txt /srv/office/'] }],
    constraints: [{
      id: 'bk-today-kept', required: true,
      description: 'Today\'s minutes (/srv/office/minutes/2026-10-19.txt) are still in the share.',
      check(world) {
        const ok = !!world.hosts.fs01.fs['/srv/office/minutes/2026-10-19.txt'];
        return { id: this.id, ok, required: true, message: ok ? 'Today\'s minutes are still there.' : 'Today\'s minutes are gone: restoring the whole directory overwrote newer work. Restore only the file that was asked for.' };
      },
    }, historyKept('fs01')],
    concepts: ['bk.restore'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'bk-db-exclude',
    title: 'The restore drill',
    difficulty: 'advanced',
    ticket: 'Monthly restore drill (DBA): "I restored db01\'s latest backup to a test machine: /var/backups/postgresql is there but inventory.dump is not. Every job says it succeeded." Change log: last week the developers started keeping scratch dumps (tens of GB) in /var/backups/postgresql/scratch, and someone added a line to /etc/restic/excludes on db01 so they would not fill bak01 (CHG-2570).',
    briefing: BRIEFING,
    goals: [{
      kind: 'command',
      description: 'A new backup of db01 contains /var/backups/postgresql/inventory.dump.',
      steps: [{ host: 'db01', user: 'root', command: 'systemctl start restic-backup.service' }, { host: 'db01', user: 'root', command: `${ENV}; restic ls latest /var/backups/postgresql` }],
      expect: '^/var/backups/postgresql/inventory\\.dump$',
    }],
    terminals: TERMINALS,
    setup(world) {
      script(world, 'db01', [
        'mkdir /var/backups/postgresql/scratch',
        'printf "-- scratch dump for the reporting migration (dev team)\\n" > /var/backups/postgresql/scratch/reporting-test.dump',
        'printf "# CHG-2570: keep the scratch dumps of the developers out of the backup\\n*.dump\\n" >> /etc/restic/excludes',
      ]);
      world.hosts.db01.fs['/var/backups/postgresql/scratch/reporting-test.dump'].size = 32 * 1024 ** 3;
      nights(world, 2);
    },
    rootCauses: ['bk-exclude-too-broad'],
    candidates: CANDIDATES,
    feedback: {
      'bk-timer-invalid': 'The job runs every night (list-timers, journal): it just leaves the dump out.',
      'bk-file-deleted': 'inventory.dump exists on db01 (ls -l /var/backups/postgresql); it is missing from the backups only.',
    },
    hints: [
      `Compare the server with the backup: ls -l /var/backups/postgresql, and ${ENV}; restic ls latest /var/backups/postgresql.`,
      'Something filters the dump out: the job uses --exclude-file /etc/restic/excludes. A pattern without a slash ("*.dump") matches the file name anywhere in the tree.',
      'Exclude only the scratch directory (/var/backups/postgresql/scratch), then systemctl start restic-backup.service and check restic ls latest again.',
    ],
    explanation: {
      rootCause: 'The exclude pattern "*.dump" was meant for the scratch directory but matches every file ending in .dump, including the nightly database dump. restic reports success because skipping excluded files is not an error.',
      manifestation: 'Backups "succeed" every night, but nobody could restore the database: only a restore test shows it.',
      evidence: 'restic ls latest /var/backups/postgresql shows the directory and scratch/ but no inventory.dump; /etc/restic/excludes ends with "*.dump".',
      prevention: 'Make exclude patterns as narrow as possible (absolute paths), check a new snapshot with restic ls after changing them, and test restores regularly: a backup that was never restored is not known to work.',
    },
    solution: [{ host: 'db01', commands: ["sed -i 's|^\\*\\.dump$|/var/backups/postgresql/scratch|' /etc/restic/excludes"] }],
    constraints: [historyKept('db01'), {
      id: 'bk-scratch-excluded', required: true,
      description: 'The developers\' scratch dumps stay out of the backups (the newest snapshot has nothing under /var/backups/postgresql/scratch/).',
      check(world) {
        // What the job backs up now: run it once more on a copy and look at that snapshot.
        const s = repoSnapshots(afterRun(world, ['db01']), 'db01').at(-1);
        const bad = s?.files.some((f) => f.p.startsWith('/var/backups/postgresql/scratch/'));
        return { id: this.id, ok: !bad, required: true, message: bad ? 'The newest snapshot contains the scratch dumps (32 GB): they would fill bak01. Exclude the scratch directory, not every .dump file.' : 'Scratch dumps are not backed up.' };
      },
    }],
    concepts: ['bk.restore', 'bk.operate'],
  },
];
