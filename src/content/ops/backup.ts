// Backup services with restic and systemd timers. Examples follow the lab:
// bak01 (10.0.20.45) keeps one encrypted restic repository per client under
// /srv/backup/restic on its own disk; srv01, db01 and fs01 back up to it over
// SFTP every night (restic-backup.service + restic-backup.timer). The Deploy
// tab adds mail01 as a new client; Lab 8 does the same for wiki01. Windows
// Server Backup, RHEL and other tools are deployment notes.

import type { Assessment, Lesson, Primer, ServiceGuide } from '../types';

const ENV = 'set -a; . /etc/restic/env; set +a';

// --- Operate & recover guide ---------------------------------------------------------

export const BACKUP_GUIDE: ServiceGuide = {
  purpose:
    'A **backup service** keeps copies of an organisation\'s data somewhere else, at known points in time, so that anything lost (a deleted file, a dropped table, a dead disk, a server encrypted by ransomware) can be brought back. An administrator decides **what** is backed up, **how often** (how much work may be lost), **how long** copies are kept, and **where** they live; schedules the jobs, watches that they succeed, and regularly **restores** something to prove the copies are usable.',
  architecture: [
    { q: 'What does it accomplish?', a: 'Recovery from data loss: point-in-time copies kept away from the original, encrypted, retained for a defined period, and restorable file by file or as a whole.' },
    { q: 'How does it work internally?', a: 'restic reads the files, cuts them into variable-size **chunks**, and stores each chunk once (by its SHA-256 hash) in encrypted **pack files**. A **snapshot** is a small record of which files (with owner, mode and time) were where, pointing to their chunks. Unchanged data is never stored twice, so every snapshot is complete but only new chunks take space. **forget** removes snapshots from the list, **prune** deletes chunks no snapshot uses any more.' },
    { q: 'Which protocols does it use?', a: 'In the lab, **SFTP** inside **SSH**: restic starts `ssh restic@bak01.corp.lab -s sftp` and reads and writes repository files through it. Other backends: a local directory, REST server (HTTP/HTTPS), S3 and other object stores. rsync uses its own protocol over SSH; Windows Server Backup writes to SMB shares or local disks.' },
    { q: 'Which ports and transport?', a: 'TCP **22** (SSH/SFTP) from the clients to bak01. REST server 8000, S3 443, rsync daemon 873, SMB 445. Only the backup clients and administrators should reach the backup server.' },
    { q: 'Which processes and OS components implement it?', a: 'On each client: **restic** started by **restic-backup.service** (Type=oneshot), started by **restic-backup.timer**; `ssh` as the transport. On bak01: **sshd** and its **sftp-server**, running as the user restic, writing to the backup disk (/dev/vdb1 on /srv/backup).' },
    { q: 'Which other services does it depend on?', a: 'SSH (keys and host keys), DNS (bak01.corp.lab), the firewall (22 to bak01), **time** (schedules, snapshot times, retention), free **disk space** on the backup server, and the repository password, kept somewhere other than the backups.' },
    { q: 'How do requests travel?', a: 'At 02:30 srv01\'s timer starts restic-backup.service → systemd loads /etc/restic/env (EnvironmentFile=) and runs /usr/local/sbin/restic-backup → restic starts ssh to bak01 → sshd checks bak01\'s authorized_keys (key, from="10.0.20.10") → sftp session as restic → restic reads the repository config and keys, decrypts with the password, takes a lock, reads the latest snapshot as parent, uploads new chunks, writes the index and the new snapshot, releases the lock → forget/prune applies the retention policy.' },
    { q: 'How do authentication and authorisation work?', a: '**Client to server**: an SSH key per client, accepted for the user restic only from that client\'s address (`restrict,from="IP"` in authorized_keys); the client checks bak01\'s host key against known_hosts. **Data**: the repository password unlocks a master key stored encrypted in keys/; without it the repository is unreadable, also for bak01\'s administrators. Unix permissions (restic:restic, 0750) keep other users on bak01 out of the files.' },
    { q: 'How does it start at boot?', a: 'An **enabled** timer is pulled in by timers.target at boot. With **Persistent=true**, a run whose time passed while the machine was off starts right after boot (the last run time is kept in /var/lib/systemd/timers/stamp-…). The service itself is not enabled: the timer starts it.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'The snapshot is not written, so the previous one stays the newest; the already uploaded chunks are reused next time. A lock file can stay in the repository (locks/) and block the next run until `restic unlock` removes it. The service ends as **failed**, visible in `systemctl --failed` and the journal.' },
  ],
  ports: [
    { port: '22', proto: 'TCP', purpose: 'SSH / SFTP (restic sftp: backend, rsync over SSH, scp)' },
    { port: '8000', proto: 'TCP', purpose: 'restic REST server (rest-server), HTTP or HTTPS' },
    { port: '443', proto: 'TCP', purpose: 'S3-compatible object storage, cloud backup services' },
    { port: '873', proto: 'TCP', purpose: 'rsync daemon (rsync://, unencrypted)' },
    { port: '445', proto: 'TCP', purpose: 'SMB share as backup target (Windows Server Backup, many NAS)' },
  ],
  processes: [
    { name: 'restic', platform: 'Linux (client)', role: 'Reads, chunks, encrypts and uploads files; restores; applies retention' },
    { name: 'restic-backup.service / .timer', platform: 'Linux (systemd)', role: 'Runs the job with its environment and logs it; schedules it every night' },
    { name: 'sshd → sftp-server (user restic)', platform: 'Linux (bak01)', role: 'Accepts the clients\' keys and serves the repository files' },
    { name: 'rsync, tar', platform: 'Linux', role: 'File copies and archives (no deduplication, no encryption by themselves)' },
    { name: 'wbengine / wbadmin.exe', platform: 'Windows Server Backup', role: 'Volume and system-state backups of Windows servers' },
  ],
  dependencies: {
    title: 'What "srv01\'s nightly backup succeeded" depends on (top needs everything below it)',
    caption: 'Each layer fails in its own words: no trigger, Result=resources, Host key verification failed, Permission denied, already locked, SSH_FX_FAILURE.',
    rows: [
      { label: 'Schedule', nodes: [{ id: 'timer', label: 'restic-backup.timer', sub: 'OnCalendar=, enabled', kind: 'service' }, { id: 'svc', label: 'restic-backup.service', sub: 'EnvironmentFile=', kind: 'service' }] },
      { label: 'Client', nodes: [{ id: 'env', label: '/etc/restic/env', sub: 'repository, password file', kind: 'data' }, { id: 'restic', label: 'restic', sub: 'excludes, paths', kind: 'service' }] },
      { label: 'Transport', nodes: [{ id: 'ssh', label: 'SSH', sub: 'known_hosts, key', kind: 'network' }, { id: 'fw', label: 'bak01 firewall', sub: 'tcp dport 22', kind: 'network' }] },
      { label: 'Server', nodes: [{ id: 'ak', label: 'authorized_keys', sub: 'restrict,from=', kind: 'data' }, { id: 'repo', label: 'Repository', sub: 'password, locks', kind: 'data' }] },
      { label: 'Storage', nodes: [{ id: 'disk', label: 'Backup disk', sub: '/srv/backup, free space', kind: 'os' }] },
    ],
    edges: [['timer', 'svc'], ['svc', 'env'], ['svc', 'restic'], ['restic', 'ssh'], ['ssh', 'fw'], ['fw', 'ak'], ['ak', 'repo'], ['repo', 'disk']],
  },
  sequence: {
    title: 'srv01\'s nightly backup at 02:30',
    caption: 'restic 0.14 over SFTP to bak01. Where each ticket breaks the run is noted.',
    lanes: [{ id: 'sd', label: 'srv01', sub: 'systemd' }, { id: 'c', label: 'srv01', sub: 'restic' }, { id: 's', label: 'bak01', sub: 'sshd / sftp' }],
    steps: [
      { from: 'sd', to: 'sd', label: 'timer elapses (OnCalendar=*-*-* 02:30:00)', note: 'Invalid OnCalendar= → the timer refuses to start and nothing ever runs.' },
      { from: 'sd', to: 'c', label: 'load EnvironmentFile=/etc/restic/env, start restic-backup', note: 'File missing → Failed to load environment files, Result=resources.' },
      { from: 'c', to: 's', label: 'ssh restic@bak01.corp.lab -s sftp: host key check', note: 'Host key changed → Host key verification failed; unable to start the sftp session.' },
      { from: 'c', to: 's', label: 'public key authentication', note: 'Key not in authorized_keys, or from= does not match → Permission denied (publickey,password).' },
      { from: 'c', to: 's', label: 'read config and keys/, decrypt with the password', note: 'Wrong password → Fatal: wrong password or no key found.' },
      { from: 'c', to: 's', label: 'create a lock in locks/', note: 'An old exclusive lock → repository is already locked … use unlock.' },
      { from: 'c', to: 's', label: 'upload new chunks (data/), write index/, snapshots/', note: 'Disk full → sftp: "Failure" (SSH_FX_FAILURE).' },
      { from: 'c', to: 's', label: 'forget --keep-… --prune: remove old snapshots and unused data' },
      { from: 'c', to: 'sd', label: 'exit 0 → service inactive (dead), status=0/SUCCESS' },
    ],
  },
  files: [
    { path: '/etc/restic/env', platform: 'Clients (this lab)', kind: 'config', perms: 'root:root 0600', contains: 'RESTIC_REPOSITORY=sftp:restic@bak01.corp.lab:/srv/backup/restic/HOST and RESTIC_PASSWORD_FILE=/etc/restic/password.', accessed: 'By systemd (EnvironmentFile=) at each run, and by administrators with set -a; . /etc/restic/env; set +a.', problems: 'Renamed or deleted → the service fails before restic starts (Result=resources).' },
    { path: '/etc/restic/password', platform: 'Clients', kind: 'auth', perms: 'root:root 0600', contains: 'The repository password.', accessed: 'By restic at every command.', problems: 'Readable by others → anyone can read the backups. Lost → the backups cannot be decrypted: keep a copy in the password safe.' },
    { path: '/etc/restic/excludes', platform: 'Clients', kind: 'config', perms: 'root:root 0644', contains: 'One pattern per line: an absolute path, or a name pattern (*.tmp) that matches anywhere.', accessed: 'At each backup (--exclude-file).', problems: 'A pattern too broad silently drops data (the job still succeeds).' },
    { path: '/etc/systemd/system/restic-backup.{service,timer}', platform: 'Clients', kind: 'config', perms: 'root:root 0644', contains: 'The job (Type=oneshot, EnvironmentFile=, ExecStart=) and its schedule (OnCalendar=, Persistent=, WantedBy=timers.target).', accessed: 'At daemon-reload and boot.', problems: 'Edits apply only after systemctl daemon-reload; an invalid OnCalendar= stops the timer.' },
    { path: '/root/.ssh/{id_ed25519,known_hosts}', platform: 'Clients', kind: 'auth', perms: 'root 0600 / 0644', contains: 'The client\'s key for bak01, and bak01\'s host key.', accessed: 'By ssh, started by restic.', problems: 'A changed host key stops every backup; a private key readable by others is refused.' },
    { path: '/home/restic/.ssh/authorized_keys', platform: 'bak01', kind: 'auth', perms: 'restic:restic 0600', contains: 'One line per client: restrict,from="IP" ssh-ed25519 AAAA… comment.', accessed: 'By sshd at each login.', problems: 'Missing line or wrong from= address → Permission denied (publickey,password).' },
    { path: '/srv/backup/restic/HOST/', platform: 'bak01 (repositories)', kind: 'data', perms: 'restic:restic 0750', contains: 'config, keys/, snapshots/, index/, data/xx/ (packs), locks/.', accessed: 'Through SFTP by restic on the clients.', problems: 'Never edit or copy files into it by hand; a full disk stops every client\'s backup.' },
    { path: 'wbadmin / Windows Server Backup', platform: 'Windows Server', kind: 'config-dir', contains: 'Backup schedule and targets, configured in wbadmin.msc or with wbadmin enable backup.', accessed: 'By the Block Level Backup Engine Service.', problems: 'The same ideas: schedule, target, retention (by space), restore tests.' },
  ],
  management: [
    {
      platform: 'Client (srv01): the job',
      tasks: [
        { task: 'When does it run next, when did it last run?', command: 'systemctl list-timers restic-backup.timer', explain: 'NEXT, LEFT, LAST, PASSED for the timer; an empty list means the timer is not active.', sim: true },
        { task: 'Did the last run succeed?', command: 'journalctl -u restic-backup.service -n 20\nsystemctl --failed', explain: 'restic\'s summary (or its error) and systemd\'s result; a failed job stays listed in systemctl --failed until the next good run or systemctl reset-failed.', sim: true },
        { task: 'Run the job now', command: 'systemctl start restic-backup.service\njournalctl -u restic-backup.service -n 8', explain: 'Exactly what the timer runs (same environment, same user), with its output in the journal.', sim: true },
        { task: 'What does the job do?', command: 'systemctl cat restic-backup.service restic-backup.timer\ncat /usr/local/sbin/restic-backup', explain: 'The unit files as systemd loaded them, and the script with the paths and the retention policy.', sim: true },
        { task: 'Check a schedule before using it', command: 'systemd-analyze calendar "*-*-* 02,14:30:00"\nsystemd-analyze verify /etc/systemd/system/restic-backup.timer', explain: 'The normalised form and the next elapse; verify reports unit file errors.', sim: true },
      ],
    },
    {
      platform: 'Client (srv01): the repository',
      tasks: [
        { task: 'Use restic by hand with the job\'s settings', command: `${ENV}\nrestic snapshots`, explain: 'set -a exports every variable the file sets, so restic sees RESTIC_REPOSITORY and RESTIC_PASSWORD_FILE.', sim: true },
        { task: 'List snapshots and their content', command: `${ENV}; restic snapshots --latest 3\n${ENV}; restic ls latest /etc/nginx`, explain: 'ID, time, host, tags and paths; ls shows the files of one snapshot ("latest" or an ID).', sim: true },
        { task: 'Restore one file somewhere safe', command: `${ENV}; restic restore latest --target /tmp/restore --include /etc/hosts\ndiff /etc/hosts /tmp/restore/etc/hosts`, explain: 'Paths are recreated below the target; compare before copying anything back.', sim: true },
        { task: 'Check the repository', command: `${ENV}; restic check\n${ENV}; restic stats`, explain: 'check verifies the structure (add --read-data to read every pack); stats shows the restore size.', sim: true },
        { task: 'Preview the retention policy', command: `${ENV}; restic forget --tag nightly --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --dry-run`, explain: 'Which snapshots each rule keeps, and which would be removed.', sim: true },
      ],
    },
    {
      platform: 'Backup server (bak01)',
      tasks: [
        { task: 'Free space on the backup disk', command: 'df -h /srv/backup\ndu -sh /srv/backup/restic/*', explain: 'Total use and the size of each client\'s repository.', sim: true },
        { task: 'Which clients may log in?', command: 'cat /home/restic/.ssh/authorized_keys\nls -l /srv/backup/restic', explain: 'One restricted key per client, one repository per client.', sim: true },
        { task: 'Logins of the clients', command: 'journalctl -u ssh -n 20', explain: 'Accepted publickey for restic from … / refused keys and from= mismatches.', sim: true },
      ],
    },
    {
      platform: 'Other tools (srv01)',
      tasks: [
        { task: 'An archive of a directory, and its checksum', command: 'tar -czf /tmp/www.tar.gz -C /var www\ntar -tzvf /tmp/www.tar.gz\nsha256sum /tmp/www.tar.gz > /tmp/www.tar.gz.sha256\nsha256sum -c /tmp/www.tar.gz.sha256', explain: 'A single file that can be copied anywhere; the checksum proves later that it did not change.', sim: true },
        { task: 'A mirror of a directory', command: 'rsync -a --delete /var/www/ /tmp/www-mirror/\nrsync -a --delete -n -v /var/www/ /tmp/www-mirror/', explain: 'Copies only differences. A mirror is not a backup: a deletion is mirrored too. -n shows what would change.', sim: true },
      ],
    },
  ],
  actions: [
    { action: 'systemctl start restic-backup.service', when: 'After any change to the job, after an outage, before risky maintenance.', effect: 'Runs the job now, as the timer would.', risk: 'Uses bandwidth and I/O during the day.' },
    { action: 'restic forget … --prune', when: 'Every run (retention), or after removing snapshots by ID.', effect: 'Removes snapshots outside the policy and deletes the data only they used.', risk: 'Irreversible: a wrong policy (--keep-last 1) deletes history. Try --dry-run first.' },
    { action: 'restic unlock', when: 'A run was interrupted and its lock blocks the next one.', effect: 'Removes stale locks (it refuses to remove locks of processes that may still run; --remove-all forces).', risk: 'Removing a live lock can corrupt a running prune: check that no restic runs.' },
    { action: 'restic restore', when: 'A file, directory or server must come back.', effect: 'Writes the snapshot\'s files below --target (with owner and mode as root).', risk: 'Restoring over live data overwrites newer work: restore to a separate place and copy back what is needed.' },
    { action: 'ssh-keygen -R / editing known_hosts', when: 'The backup server\'s host key changed for a known reason.', effect: 'The clients trust the new key.', risk: 'Without checking the fingerprint you may trust an attacker; never set StrictHostKeyChecking=no.' },
  ],
  workflow: [
    { question: 'Did the job run at all?', why: 'A job that never starts produces no error: the newest snapshot just gets older.', command: 'systemctl list-timers restic-backup.timer\nsystemctl status restic-backup.timer', healthy: 'The timer is listed with NEXT tomorrow and LAST last night; active (waiting)', broken: 'Not listed; failed (Result: resources) with "Failed to parse calendar specification"; inactive and disabled', next: 'Then whether it succeeded.', sim: true },
    { question: 'Did the run succeed, and where did it stop?', why: 'systemd\'s result tells whether restic ran at all; restic\'s last lines tell which layer refused.', command: 'systemctl status restic-backup.service\njournalctl -u restic-backup.service -n 20', healthy: 'status=0/SUCCESS; "snapshot … saved"', broken: 'Result: resources (environment file); Host key verification failed; Permission denied (publickey,password); already locked; SSH_FX_FAILURE', next: 'Follow the message to its layer.', sim: true },
    { question: 'Can the client reach bak01 as restic?', why: 'Separates SSH problems from restic problems.', command: 'ssh -o BatchMode=yes restic@bak01.corp.lab true; echo $?', healthy: '0, no prompt', broken: 'Host key verification failed (known_hosts); Permission denied (publickey,password) (authorized_keys, from=); timeout (firewall)', next: 'Then the repository and the server\'s disk.', sim: true },
    { question: 'Is the repository usable, and is there room?', why: 'Locks, the password and free space are checked after the connection works.', command: `${ENV}; restic snapshots --latest 1\nssh -o BatchMode=yes restic@bak01.corp.lab df -h /srv/backup`, healthy: 'Last night\'s snapshot; enough free space', broken: 'wrong password or no key found; already locked; 100% used', next: 'Then what the snapshot contains.', sim: true },
    { question: 'Does the backup contain what it should?', why: 'A job that succeeds can still miss data (an exclude too broad, a path not listed).', command: `${ENV}; restic ls latest /etc\ncat /etc/restic/excludes`, healthy: 'Every important file appears', broken: 'A file or directory is missing: check the paths in the script and the excludes', next: 'Prove it with a restore.', sim: true },
  ],
  failures: [
    { symptom: 'The newest snapshot gets older; no failed job anywhere', causes: ['Timer not active (invalid OnCalendar=, disabled, not started)', 'Machine off at the scheduled time without Persistent=true'], diagnose: ['systemctl list-timers', 'systemctl status restic-backup.timer', 'systemd-analyze calendar'], fix: 'Fix the expression, daemon-reload, enable --now the timer.', verify: 'list-timers shows NEXT; a run appears in the journal.' },
    { symptom: 'Service fails instantly with Result=resources', causes: ['EnvironmentFile= missing', 'User= does not exist', 'ExecStart= not executable'], diagnose: ['systemctl status restic-backup.service', 'journalctl -u restic-backup.service'], fix: 'Restore the file or fix the unit, then daemon-reload.', verify: 'systemctl start restic-backup.service succeeds.' },
    { symptom: 'Host key verification failed / REMOTE HOST IDENTIFICATION HAS CHANGED', causes: ['bak01 reinstalled or its keys regenerated', 'Someone intercepting the connection'], diagnose: ['ssh-keyscan -t ed25519 bak01.corp.lab | ssh-keygen -lf -', 'Compare with the fingerprint from bak01\'s console'], fix: 'ssh-keygen -R bak01.corp.lab, then add the verified key.', verify: 'ssh -o BatchMode=yes restic@bak01.corp.lab true.' },
    { symptom: 'repository is already locked', causes: ['A run was interrupted (power cut, killed) and left its lock', 'Another restic command is really running'], diagnose: ['The lock\'s PID, host and age in the error', 'ps on that host'], fix: 'restic unlock when nothing runs.', verify: 'The job runs.' },
    { symptom: 'sftp: "Failure" (SSH_FX_FAILURE) while saving', causes: ['Backup disk full', 'Permissions on the repository files'], diagnose: ['df -h /srv/backup', 'du -sh /srv/backup/*'], fix: 'Free space (remove what does not belong there; enforce retention with prune), or grow the disk.', verify: 'Backups of all clients succeed; df leaves headroom.' },
    { symptom: 'A restore lacks files although every job succeeded', causes: ['Exclude pattern too broad', 'Path never listed in the job', 'Files unreadable (warning, exit code 3)'], diagnose: ['restic ls latest PATH', 'cat /etc/restic/excludes', 'journalctl for "could not be read"'], fix: 'Narrow the exclude; add the path; run as root.', verify: 'restic ls latest shows the file after the next run; a restore test.' },
  ],
  verification: [
    { check: 'Scheduled', command: 'systemctl list-timers restic-backup.timer && systemctl is-enabled restic-backup.timer', expect: 'NEXT tonight; enabled' },
    { check: 'Last run succeeded', command: 'systemctl status restic-backup.service', expect: 'status=0/SUCCESS, not failed' },
    { check: 'Fresh snapshot', command: `${ENV}; restic snapshots --latest 1`, expect: 'Last night\'s date' },
    { check: 'Restorable', command: `${ENV}; restic restore latest --target /tmp/restore-test --include /etc/hosts && diff /etc/hosts /tmp/restore-test/etc/hosts`, expect: 'No difference' },
    { check: 'Room on the backup server', command: 'df -h /srv/backup (on bak01)', expect: 'Well below 100% with the retention policy applied' },
  ],
  refIds: ['restic', 'file:systemd-timer', 'file:restic-env', 'systemd-analyze', 'rsync', 'tar', 'sha256sum', 'file:authorized_keys', 'proc:backup-new-client', 'proc:backup-restore'],
};

// --- Lesson -------------------------------------------------------------------------

export const BACKUP_LESSON: Lesson = {
  id: 'backup',
  moduleId: 'F',
  title: 'Backups (restic, systemd timers)',
  level: 'intermediate',
  summary: 'Plan and run backups: recovery objectives (RPO, RTO), 3-2-1, full, incremental and deduplicated backups, an encrypted restic repository over SSH, scheduling with systemd timers, retention, monitoring, restore tests, and the errors each layer produces.',
  concepts: ['bk.schedule', 'bk.transport', 'bk.operate', 'bk.restore'],
  what: `
A **backup** is a copy of data, taken at a known moment and kept somewhere else, so that what is lost can be brought back. Data gets lost in many ways: a user deletes a file, an update corrupts a database, a disk dies, a whole server burns, ransomware encrypts everything it can reach. A **backup service** makes those copies on a schedule, keeps them for a defined time, and lets an administrator restore a single file or a whole server.

Backups use services covered elsewhere: [SSH](#/lesson/ssh/what) carries the data and authenticates the clients, [systemd](#/lesson/systemd/what) runs the jobs, and the database lesson shows how to [dump a database](#/lesson/database/internals) so that a file backup can include it.

### Two numbers decide the design
- **RPO** (recovery point objective): how much work may be lost, measured in time. A nightly backup means up to a day of work can be lost; an RPO of one hour needs hourly backups (or replication).
- **RTO** (recovery time objective): how long the service may be down while it is restored. Restoring 2 TB over a slow link takes hours; a low RTO needs fast local copies or a standby system.

:::practice
Q: A team can lose at most four hours of work, and the service must be back within one hour after a failure. Which number is the RPO and which the RTO?
A: Four hours is the **RPO** (how much data may be lost: back up at least every four hours); one hour is the **RTO** (how long the restore may take).
:::

### The 3-2-1 rule
Keep **3** copies of the data (the original and two backups), on **2** different kinds of storage, with **1** copy off-site. Add an **offline or immutable** copy that ransomware with administrator rights cannot delete, and **0** errors in restore tests.

:::practice
Q: All backups are on a second disk inside the same server. Which part of 3-2-1 is missing?
A: The **off-site** copy (and arguably a second kind of storage): a fire, theft or ransomware on that server takes both copies.
:::

### The pieces
- **Clients**: the servers whose data is backed up (srv01, db01, fs01).
- **Backup server / repository**: where the copies live (bak01, one restic repository per client on its own disk).
- **Snapshots**: the copies, one per run, each a complete picture of the files at that moment.
- **Schedule**: when jobs run (systemd timers), and **retention**: how long snapshots are kept.
- **Restore tests**: the only proof that the backups work.

> In the lab, **bak01** (10.0.20.45) keeps encrypted **restic** repositories in /srv/backup/restic. Every night **srv01** (02:30), **db01** (02:45, after its database dump) and **fs01** (03:00) run **restic-backup.service** from **restic-backup.timer**: back up over SFTP as the user restic, then apply the retention policy. The lab starts on Monday morning with a week of snapshots. **Lab 8** puts a new server (wiki01) under backup. Simulated: environment variables (export, set -a, EnvironmentFile=), systemd services and timers written by the administrator (OnCalendar=, OnBootSec=, OnUnitActiveSec=, Persistent=, daemon-reload, enable --now, list-timers, the journal, Result=resources and exit codes), systemd-analyze calendar and verify, restic 0.14 (init, backup with parent snapshots, deduplication, excludes and tags, snapshots, ls, restore with --include, forget with --keep-* policies, prune, check, stats, unlock, locks left behind), the sftp: backend over SSH with known_hosts and authorized_keys restrict,from=, the backup disk with ext4's root reserve, tar, rsync (local and over SSH, --delete, -n), sha256sum, df and du. Simplified: chunks are whole files, repository files are JSON (only the password check is real), no REST or S3 backends, no mount, diff, find, copy or key commands, no RandomizedDelaySec spread, no ransomware.

:::practice
Q: Where do the backups of srv01, db01 and fs01 end up in the lab?
A: On **bak01**, in one encrypted restic repository per client under /srv/backup/restic (its own disk).
Q: What is the only real proof that a backup works?
A: A **restore test**: bringing data back from it and checking it.
:::

`,

  internals: `
### 1. Full, incremental, differential, deduplicated
- **Full**: copy everything every time. Simple to restore, slow and large.
- **Incremental**: copy what changed since the **last backup of any kind**. Small and fast, but a restore needs the full plus every incremental in order.
- **Differential**: copy what changed since the **last full**. Grows during the week; a restore needs the full plus the newest differential.
- **Deduplicated snapshots** (restic, Borg, many commercial products): each run stores only data chunks the repository does not have yet, yet every snapshot is complete. Restoring any snapshot is as simple as restoring a full one, and old snapshots can be deleted in any order.

**Mirrors** (rsync --delete, RAID, replication) are not backups: a deletion or corruption is copied too, within seconds. **Snapshots** of a filesystem or VM on the same storage protect against mistakes, not against losing that storage.

:::practice
Q: Full backup on Sunday, incrementals Monday to Thursday. The server dies on Friday morning. What do you need to restore Thursday night's state?
A: Sunday's **full** and **all four** incrementals (Monday, Tuesday, Wednesday, Thursday), applied in order.
Q: Why is an rsync --delete mirror to another server not a backup?
A: It reproduces deletions and corruption on the next run: it keeps only the **current** state, no earlier points in time.
:::

### 2. How restic stores data
A restic **repository** is a directory (local, or on a server reached by SFTP, REST or S3):
\`\`\`
config        repository ID and version
keys/         the master key, encrypted with each password
snapshots/    one small file per snapshot: time, host, paths, tags, tree
index/        which blob is in which pack
data/00…ff/   pack files: encrypted chunks of file contents and directory trees
locks/        one file per running command
\`\`\`
\`restic backup\` reads each file, cuts it into chunks, hashes each chunk (SHA-256) and uploads only chunks whose hash is not in the index. Unchanged files are detected from the **parent snapshot** (same size, time and inode: not even read). Everything is **encrypted and authenticated** (AES-256 and Poly1305) on the client, so bak01 sees only ciphertext. The password unlocks the master key in keys/: **losing the password loses the backups**.

:::practice
Q: The second backup of an unchanged server finishes in seconds and adds almost nothing. Is the second snapshot incomplete?
A: **No.** It is complete: it points to the same chunks as the first; only new chunks are stored (**deduplication**).
Q: bak01's disk is stolen. Can the thief read srv01's files from the repository?
A: Not without the repository **password**: everything is encrypted on the client before it is uploaded.
:::

### 3. Getting the data there safely: SSH
With \`RESTIC_REPOSITORY=sftp:restic@bak01.corp.lab:/srv/backup/restic/srv01\`, restic starts \`ssh restic@bak01.corp.lab -s sftp\`. Nobody types a password at 02:30, so:
- each client has its own **key** (/root/.ssh/id_ed25519, no passphrase, mode 0600);
- bak01 accepts it for the user restic only from that client: \`restrict,from="10.0.20.10" ssh-ed25519 AAAA… root@srv01\` in /home/restic/.ssh/authorized_keys;
- the client trusts bak01 only with the **host key** in /root/.ssh/known_hosts, verified by its fingerprint. When the host key changes, ssh refuses and every backup fails: verify the new fingerprint, never switch checking off.

The backup user on the server is not root, and one client cannot read another client's repository contents (each has its own password).

:::practice
Q: What does \`from="10.0.20.10"\` in front of a key in authorized_keys do?
A: The key is accepted **only from that address**: a copy of the key used elsewhere is refused.
Q: After bak01 was reinstalled, every backup fails with "REMOTE HOST IDENTIFICATION HAS CHANGED". What is the safe fix?
A: Get the **new fingerprint** from bak01's console, compare it with \`ssh-keyscan … | ssh-keygen -lf -\`, then replace the old key (\`ssh-keygen -R bak01.corp.lab\`, add the new one). Not StrictHostKeyChecking=no.
:::

### 4. Settings in the environment
restic reads its settings from **environment variables**: RESTIC_REPOSITORY, RESTIC_PASSWORD_FILE (or RESTIC_PASSWORD). A variable set in a shell (\`X=1\`) stays in that shell; **export** passes it to programs started from it. \`set -a\` exports every variable assigned until \`set +a\`, so

\`\`\`
set -a; . /etc/restic/env; set +a
\`\`\`

reads the file (\`.\` runs it in the current shell) and exports both settings. systemd reads the same file with **EnvironmentFile=/etc/restic/env** (a missing file is an error; \`EnvironmentFile=-/path\` makes it optional). \`sudo\` resets the environment: run \`sudo -i\` first, or load the file inside the root shell.

:::practice
Q: You run \`. /etc/restic/env\` (without set -a), then \`restic snapshots\`. restic says "Please specify repository location". Why?
A: The variables were set in the shell but not **exported**, so the restic process does not see them. Use \`set -a\` (or export).
Q: What happens when the file named in EnvironmentFile= (without "-") does not exist?
A: systemd does not start the command: "Failed to load environment files", Result=resources.
:::

### 5. Scheduling with systemd timers
A **timer** unit starts a **service** unit of the same name on a schedule:
\`\`\`
# /etc/systemd/system/restic-backup.timer
[Timer]
OnCalendar=*-*-* 02:30:00
Persistent=true
RandomizedDelaySec=5min

[Install]
WantedBy=timers.target
\`\`\`
- **OnCalendar=** *weekday year-month-day hour:minute:second*: \`*-*-* 02:30:00\` (daily), \`Mon..Fri 22:00\`, \`*-*-01 03:00\` (monthly), \`daily\`, \`hourly\`. Several OnCalendar= lines add up. \`systemd-analyze calendar EXPR\` shows the next run; an invalid expression is ignored, and a timer with no trigger left refuses to start.
- **OnBootSec=** / **OnUnitActiveSec=**: relative to boot, or to the last run.
- **Persistent=true**: if the machine was off at the scheduled time, run right after boot.
- The service is **Type=oneshot**: it is active while the job runs and inactive (dead) afterwards, with status=0/SUCCESS or failed.

Compared with **cron**: each run is logged under the unit (journalctl -u), failures show in \`systemctl --failed\`, the job gets a defined environment, dependencies (After=network-online.target) and resource limits (Nice=, IOSchedulingClass=idle), and missed runs can be caught up.

After editing unit files: **systemctl daemon-reload**. **enable** makes the timer start at boot; **--now** starts it immediately.

:::practice
Q: A timer has OnCalendar=*-*-* 02:30:00 and Persistent=true. The server was off from 01:00 to 07:00. When does the backup run?
A: Right after the server is up again (around 07:00): Persistent=true catches up the missed run.
Q: You edited OnCalendar= and restarted the timer, but list-timers still shows the old time. What did you forget?
A: **systemctl daemon-reload**: systemd still uses the unit as it was loaded.
:::

### 6. Retention
Without retention, snapshots pile up until the backup disk is full. \`restic forget\` applies a **policy** per host and paths:
- \`--keep-last N\`: the newest N snapshots;
- \`--keep-daily 7\`: the newest snapshot of each of the last 7 days that have one; similarly **--keep-weekly**, **--keep-monthly**, **--keep-yearly**;
- \`--keep-within 30d\`: everything from the last 30 days.

A snapshot is kept if any rule keeps it ("daily snapshot, weekly snapshot" in the reasons column). **forget** only removes snapshot records; **prune** (or \`forget --prune\`) deletes the data no remaining snapshot uses, which is what frees space. Always try a new policy with **--dry-run**.

:::practice
Q: After restic forget --keep-daily 7, df on bak01 shows the same usage. Why?
A: forget only removes the snapshot records: run **prune** (or forget --prune) to delete the unused data.
Q: Which policy gives a week of daily restore points, a month of weekly ones and half a year of monthly ones?
A: \`--keep-daily 7 --keep-weekly 4 --keep-monthly 6\`.
:::

### 7. Consistency: what is inside the files
Backing up the files of a running database can catch it in the middle of a write: the copy may not start. Back up a **dump** instead (db01 runs pg_dump at 02:15, the restic job at 02:45 picks up /var/backups/postgresql), or stop the service, or use filesystem/VM snapshots with the application's help (fsfreeze, VSS on Windows). The same applies to mail spools, VM disks and anything that writes continuously.

:::practice
Q: Why does db01 back up /var/backups/postgresql instead of /var/lib/postgresql?
A: The data directory changes while PostgreSQL runs, so a file copy may be inconsistent; the **dump** is a consistent copy taken by the database itself.
Q: What does Windows use to back up open files and databases consistently?
A: **VSS** (Volume Shadow Copy Service), which asks applications to flush and pause writes while a snapshot is taken.
:::

`,

  deployment: [
    {
      id: 'debian',
      platform: 'Debian 12: a new restic client (mail01) for bak01',
      summary: 'From nothing to a nightly, monitored, restore-tested backup of mail01. Steps marked simulated can be tried in the sandbox: "On bak01" in the bak01 console, the others on mail01. Lab 8 walks through the same steps for wiki01.',
      prerequisites: ['restic on the client (apt install restic) and an SSH server on the backup server.', 'On bak01: a user restic, a separate disk mounted on /srv/backup, /srv/backup/restic owned by restic (all there already).', 'A password safe entry for the new repository password.'],
      steps: [
        { title: 'On the client: a key for the job', command: 'ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519 -C "root@mail01 (restic backups)"\ncat /root/.ssh/id_ed25519.pub', what: 'A key pair without a passphrase for root on mail01.', why: 'The job runs unattended; the key file is root-only (0600), and the key gets its own restricted line on bak01.', expected: 'Your identification has been saved in /root/.ssh/id_ed25519', simulated: true },
        { title: 'On bak01: accept the key from mail01 only', command: "echo 'restrict,from=\"10.0.20.25\" ssh-ed25519 AAAA… root@mail01 (restic backups)' >> /home/restic/.ssh/authorized_keys", what: 'Paste the public key from the previous step, with the options in front.', why: 'from= makes a stolen key useless elsewhere; restrict disables forwarding and terminals.', expected: '' },
        { title: 'On the client: trust bak01\'s host key', command: 'ssh-keyscan -t ed25519 bak01.corp.lab > /tmp/bak01.key\nssh-keygen -lf /tmp/bak01.key\ncat /tmp/bak01.key >> /root/.ssh/known_hosts\nssh -o BatchMode=yes restic@bak01.corp.lab true', what: 'Fetch bak01\'s key, compare its fingerprint with the one from bak01\'s console (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub there), then trust it. The last line must succeed without any prompt.', why: 'The job must never send data to a machine that only claims to be bak01.', expected: '256 SHA256:… (ED25519)', simulated: true },
        { title: 'Password and settings', command: "mkdir -p /etc/restic\nchmod 700 /etc/restic\nprintf 'Rst-mail01-26\\n' > /etc/restic/password\nchmod 600 /etc/restic/password\nprintf 'RESTIC_REPOSITORY=sftp:restic@bak01.corp.lab:/srv/backup/restic/mail01\\nRESTIC_PASSWORD_FILE=/etc/restic/password\\n' > /etc/restic/env\nchmod 600 /etc/restic/env", what: 'The repository password in a root-only file, and the two settings restic and the unit use.', why: 'One file for systemd (EnvironmentFile=) and administrators (set -a; . …); the password never appears on a command line.', expected: '', simulated: true },
        { title: 'Initialise the repository and run the first backup', command: `${ENV}; restic init\n${ENV}; restic backup --tag nightly /etc /var/mail /home\n${ENV}; restic snapshots`, what: 'Creates /srv/backup/restic/mail01 on bak01, then the first snapshot.', why: 'init writes config and the encrypted master key; the first backup uploads everything, later ones only changes.', expected: 'created restic repository … at sftp:…\nsnapshot … saved', simulated: true },
        { title: 'The job: script, service and timer', command: "printf '%s\\n' '#!/bin/sh' 'set -e' 'restic backup --tag nightly /etc /var/mail /home' 'restic forget --tag nightly --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune' > /usr/local/sbin/restic-backup\nchmod 755 /usr/local/sbin/restic-backup\nprintf '%s\\n' '[Unit]' 'Description=Nightly restic backup to bak01' 'After=network-online.target' '' '[Service]' 'Type=oneshot' 'EnvironmentFile=/etc/restic/env' 'ExecStart=/usr/local/sbin/restic-backup' > /etc/systemd/system/restic-backup.service\nprintf '%s\\n' '[Unit]' 'Description=Run the restic backup every night' '' '[Timer]' 'OnCalendar=*-*-* 03:30:00' 'Persistent=true' '' '[Install]' 'WantedBy=timers.target' > /etc/systemd/system/restic-backup.timer\nsystemd-analyze verify /etc/systemd/system/restic-backup.timer", what: 'The script (backup, then retention), a oneshot service that loads the environment, and a nightly timer. (Write them with an editor; printf keeps the step runnable.)', why: 'set -e stops the script at the first failure, so the service ends as failed and monitoring sees it.', expected: '', simulated: true },
        { title: 'Enable and test the schedule', command: 'systemctl daemon-reload\nsystemctl enable --now restic-backup.timer\nsystemctl list-timers restic-backup.timer\nsystemctl start restic-backup.service\njournalctl -u restic-backup.service -n 5', what: 'Loads the new units, starts the timer (and at every boot), then runs the job once by hand. Its retention policy keeps one snapshot per day, so this run replaces the first backup of today: restic snapshots shows one.', why: 'A job that was never run by systemd is not known to work (environment, permissions, paths).', expected: 'Created symlink /etc/systemd/system/timers.target.wants/restic-backup.timer → /etc/systemd/system/restic-backup.timer.', simulated: true },
        { title: 'Restore test', command: `${ENV}; restic restore latest --target /tmp/restore-test --include /etc/postfix\ndiff -r /etc/postfix /tmp/restore-test/etc/postfix && echo identical`, what: 'Restores part of the snapshot into a separate directory and compares it with the original.', why: 'Only a restore proves the backup. Repeat regularly (a restore drill), and record the time it took (RTO).', expected: 'identical', simulated: true },
        { title: 'Monitoring', command: '# alert when: systemctl --failed lists restic-backup.service,\n# the newest snapshot is older than 26 hours, or /srv/backup on bak01 is above 85%', what: 'Watch the result of every run, the age of the newest snapshot, and the free space on the backup server.', why: 'A job that silently stopped running produces no failure: only the snapshot age shows it.', expected: '' },
      ],
    },
    {
      id: 'rhel',
      platform: 'RHEL 9 / Rocky / Alma',
      summary: 'restic comes from EPEL; everything else (systemd units, SSH keys, restic commands) is the same. Add the backup server to the firewall with firewall-cmd, and mind SELinux labels on restored files.',
      prerequisites: ['sudo dnf install epel-release && sudo dnf install restic'],
      steps: [
        { title: 'Restore with the right SELinux labels', command: 'restic restore latest --target / --include /var/www\nrestorecon -Rv /var/www', what: 'restic restores the files; restorecon resets their SELinux contexts.', why: 'Files restored with the wrong label are refused by services under SELinux.', expected: '' },
      ],
    },
    {
      id: 'windows',
      platform: 'Windows Server Backup (wbadmin)',
      summary: 'The built-in feature backs up volumes, system state and bare-metal recovery images to a local disk or an SMB share, using VSS for consistent copies. Install it with Install-WindowsFeature Windows-Server-Backup.',
      prerequisites: ['A dedicated backup disk or an SMB share (\\\\bak01\\winbackup) with an account that may write to it.'],
      steps: [
        { title: 'Daily backup of the system and data', command: 'wbadmin enable backup -addtarget:\\\\nas01\\winbackup -include:C:,D: -allCritical -systemState -schedule:21:00', what: 'A scheduled backup of the volumes, everything needed for bare-metal recovery, and the system state (registry, AD on a domain controller).', why: 'One schedule covers files and the recovery of the whole server.', expected: '' },
        { title: 'List backups and restore a folder', command: 'wbadmin get versions\nwbadmin start recovery -version:10/19/2026-21:00 -itemType:File -items:D:\\Shares\\Finance -recoveryTarget:D:\\Restore', what: 'Shows the restore points; restores a folder somewhere else.', why: 'Same rule as everywhere: restore to a separate place first.', expected: '' },
      ],
    },
    {
      id: 'other',
      platform: 'Other tools and targets',
      summary: 'BorgBackup works like restic (deduplicated, encrypted repositories over SSH, borg prune for retention). Bacula/Bareos and commercial products (Veeam, Commvault) add a central director, catalogues and tape. Object storage (S3) with object lock gives immutable off-site copies; rclone or restic\'s s3: backend write to it.',
      prerequisites: [],
      steps: [
        { title: 'BorgBackup equivalent', command: 'borg init --encryption=repokey ssh://borg@bak01/srv/backup/borg/mail01\nborg create ::{hostname}-{now} /etc /var/mail\nborg prune --keep-daily 7 --keep-weekly 4 --keep-monthly 6', what: 'Repository, archive (= snapshot) and retention.', why: 'The same ideas under different names.', expected: '' },
        { title: 'An immutable off-site copy', command: 'restic -r s3:https://s3.example.net/corp-backup copy --from-repo sftp:restic@bak01.corp.lab:/srv/backup/restic/srv01', what: 'Copies snapshots to a bucket with object lock (writes allowed, deletes refused until the retention date).', why: 'The 1 in 3-2-1, out of reach of an attacker on the network.', expected: '' },
      ],
    },
  ],

  configIntro: `
A backup job is configured in four places:
- **What and where**: the script or command line (paths, --exclude-file, --tag) and **/etc/restic/env** (repository and password file).
- **When**: the **timer** unit (OnCalendar=, Persistent=).
- **How it runs**: the **service** unit (Type=oneshot, EnvironmentFile=, User=, Nice=).
- **How long**: the retention policy (restic forget --keep-…), usually at the end of the script.

### Checking a change before it fails at night
- \`systemd-analyze calendar "EXPR"\`: is the expression valid, when is the next run?
- \`systemd-analyze verify /etc/systemd/system/restic-backup.timer\`: unit file errors.
- \`systemctl daemon-reload\`, then \`systemctl list-timers\` and one \`systemctl start restic-backup.service\`.
- After changing paths or excludes: \`restic ls latest PATH\` on the new snapshot.

:::practice
Q: How do you see when "Mon..Fri 22:00" will fire next, without changing any unit?
A: \`systemd-analyze calendar "Mon..Fri 22:00"\`.
Q: An exclude file contains "*.dump". Which files does it exclude?
A: **Every** file whose name ends in .dump, in any directory: a pattern without a slash matches names anywhere. Use an absolute path to exclude one place only.
:::

`,

  configFiles: [
    { platform: 'restic client (this lab)', items: [
      { path: '/etc/restic/env', purpose: 'RESTIC_REPOSITORY and RESTIC_PASSWORD_FILE (0600).' },
      { path: '/etc/restic/password', purpose: 'The repository password (0600, copy in the password safe).' },
      { path: '/etc/restic/excludes', purpose: 'Patterns left out of the backup.' },
      { path: '/usr/local/sbin/restic-backup', purpose: 'The job: backup, then forget --prune.' },
      { path: '/etc/systemd/system/restic-backup.service', purpose: 'Type=oneshot, EnvironmentFile=, ExecStart=.' },
      { path: '/etc/systemd/system/restic-backup.timer', purpose: 'OnCalendar=, Persistent=, WantedBy=timers.target.' },
      { path: '/root/.ssh/id_ed25519, /root/.ssh/known_hosts', purpose: 'The client\'s key for bak01 and bak01\'s host key.' },
    ] },
    { platform: 'Backup server (bak01)', items: [
      { path: '/home/restic/.ssh/authorized_keys', purpose: 'One restrict,from= line per client.' },
      { path: '/srv/backup/restic/HOST/', purpose: 'One repository per client, owned by restic.' },
      { path: '/etc/nftables.conf', purpose: 'SSH only from the server network and the administrators.' },
    ] },
  ],

  directives: [
    { name: 'OnCalendar=', compiledDefault: '(none)', recommended: 'A fixed night-time slot per server, e.g. *-*-* 02:30:00', explanation: 'When the timer elapses. Several lines add up; test with systemd-analyze calendar.', security: '' },
    { name: 'Persistent=', compiledDefault: 'false', recommended: 'true', explanation: 'Run a missed job right after boot.', security: 'Without it, a server that is off at night is never backed up.' },
    { name: 'RandomizedDelaySec=', compiledDefault: '0', recommended: 'A few minutes', explanation: 'Spreads many clients so they do not all start at once.', security: '' },
    { name: 'EnvironmentFile=', compiledDefault: '(none)', recommended: '/etc/restic/env (mode 0600)', explanation: 'Variables for the command. A missing file is an error unless written as EnvironmentFile=-/path.', security: 'Keep secrets in files readable by root only, not in the unit (systemctl show prints Environment=).' },
    { name: 'Type=oneshot', compiledDefault: 'simple', recommended: 'oneshot for jobs', explanation: 'The unit is active while the command runs; its exit code is the result.', security: '' },
    { name: 'restic forget --keep-*', compiledDefault: '(nothing is ever removed)', recommended: '--keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune', explanation: 'Which snapshots stay; prune frees the space.', security: 'Ransomware with the client\'s credentials can also forget snapshots: keep an immutable or offline copy too.' },
    { name: 'authorized_keys options', compiledDefault: '(none: full shell, forwarding)', recommended: 'restrict,from="CLIENT-IP"', explanation: 'Limit each client\'s key to its address and to what it needs.', security: 'An append-only REST server (rest-server --append-only) also stops clients from deleting backups.' },
  ],

  operateIntro: `
### Every morning: did it work?
- \`systemctl list-timers\` on the clients (or central monitoring): every timer has a NEXT and a recent LAST.
- \`systemctl --failed\` and \`journalctl -u restic-backup.service\`: last night's result and restic's summary.
- The **age of the newest snapshot** (restic snapshots --latest 1): the only check that also catches a job that stopped running.
- **Free space** on the backup server (df -h /srv/backup).

:::practice
Q: Every job in the monitoring is green, but one server's newest snapshot is four days old. How can that be?
A: Its job has **not run** for four days (timer stopped, disabled or invalid): a job that never runs never fails. Monitor the snapshot age, not only failures.
Q: Which command shows when each timer last ran and runs next?
A: \`systemctl list-timers\`.
:::

### Restoring
1. Find the right snapshot: \`restic snapshots\`, \`restic ls SNAPSHOT PATH\` (the version from before the mistake, not necessarily the latest).
2. Restore **somewhere else** first: \`restic restore SNAPSHOT --target /tmp/restore --include PATH\`.
3. Check it (content, owner, mode), then copy back only what was lost: \`cp -a\`. Restoring a whole directory over a live one rolls back everything changed since.
4. Record what happened and how long it took.

:::practice
Q: A user deleted one file from a share that colleagues kept using today. Why not restore the whole share from last night?
A: It would **overwrite today's work** with last night's state (and bring back files deleted on purpose). Restore only the one file.
Q: Where does \`restic restore latest --target /tmp/r --include /srv/office/a.txt\` put the file?
A: In **/tmp/r/srv/office/a.txt**: the original path is recreated below the target.
:::

### Restore drills and disaster recovery
Restore something every month, and once in a while a **whole server** onto a spare machine following the written procedure, timing it against the RTO. Keep the procedure, the repository passwords and the backup server's own configuration **outside** the systems they protect: a backup that needs the burnt-down server to be read is no backup.

:::practice
Q: The repository passwords are stored only in /etc/restic/password on each client. What is the problem?
A: If a client is lost, its **password is lost with it**, and its backups cannot be decrypted. Keep a copy in the password safe.
Q: Why time a full restore drill?
A: To know whether the restore fits the **RTO**, and to find missing steps before a real disaster.
:::

`,
  troubleshootingIntro: `
### Follow the run from the timer to the disk
1. **Did it run?** \`systemctl list-timers\`, \`systemctl status restic-backup.timer\`: an invalid OnCalendar= or a disabled timer means no run and no error.
2. **Did systemd start restic?** Result=resources: EnvironmentFile=, User= or ExecStart= is wrong.
3. **SSH?** "Host key verification failed": the host key changed (verify, then update known_hosts). "Permission denied (publickey,password)": authorized_keys line or from= address on bak01.
4. **The repository?** "wrong password or no key found": password file. "already locked": an interrupted run; \`restic unlock\`.
5. **The server's disk?** sftp "Failure" while saving: \`df -h /srv/backup\` on bak01.
6. **The content?** Success but data missing: paths and excludes; prove with \`restic ls\` and a restore.

:::practice
Q: restic-backup.service fails with Result=resources and nothing from restic in the journal. Where do you look?
A: At what systemd does **before** starting the command: EnvironmentFile= (missing file), User=, ExecStart= path.
Q: Every client's backup failed the same night with sftp "Failure" right after "repository … opened". What do you check first?
A: **Free space** on the backup server: \`df -h /srv/backup\` on bak01.
:::

`,

  errorMap: [
    { message: 'Failed to parse calendar specification, ignoring: … / Timer unit lacks value setting. Refusing.', layer: 'Timer', meaning: 'OnCalendar= is invalid; with no trigger left the timer does not start.', firstCheck: 'systemd-analyze calendar "EXPR"; systemctl status restic-backup.timer' },
    { message: 'restic-backup.service: Failed to load environment files: No such file or directory', layer: 'Service start', meaning: 'EnvironmentFile= names a missing file (Result=resources).', firstCheck: 'systemctl cat restic-backup.service; ls /etc/restic' },
    { message: 'Fatal: Please specify repository location (-r or --repository-file)', layer: 'Environment', meaning: 'RESTIC_REPOSITORY is not set (or not exported).', firstCheck: 'set -a; . /etc/restic/env; set +a' },
    { message: '@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@ … Host key verification failed.', layer: 'SSH (host key)', meaning: 'bak01\'s host key differs from known_hosts.', firstCheck: 'Compare fingerprints; ssh-keygen -R bak01.corp.lab' },
    { message: 'restic@bak01.corp.lab: Permission denied (publickey,password).', layer: 'SSH (client key)', meaning: 'bak01 does not accept this key from this address.', firstCheck: 'authorized_keys and from= on bak01; journalctl -u ssh there' },
    { message: 'Fatal: unable to open repository at sftp:…: unable to start the sftp session, error: EOF', layer: 'Transport', meaning: 'ssh exited before SFTP started; the lines before it say why.', firstCheck: 'ssh -o BatchMode=yes restic@bak01.corp.lab true' },
    { message: 'Fatal: wrong password or no key found', layer: 'Repository', meaning: 'The password does not unlock any key of this repository.', firstCheck: 'RESTIC_PASSWORD_FILE and its content' },
    { message: 'unable to create lock in backend: repository is already locked exclusively by PID … on HOST', layer: 'Repository lock', meaning: 'Another run holds a lock, or a crashed run left one.', firstCheck: 'Its age and PID; restic unlock if nothing runs' },
    { message: 'Fatal: unable to save snapshot: … sftp: "Failure" (SSH_FX_FAILURE)', layer: 'Backup server storage', meaning: 'The server could not write (usually a full disk).', firstCheck: 'df -h /srv/backup on bak01' },
    { message: 'Warning: at least one source file could not be read (exit code 3)', layer: 'Client files', meaning: 'The snapshot was saved without some files (permissions, vanished files).', firstCheck: 'Run as root; journal lines before it' },
    { message: 'Failed to enable unit: Unit file restic-backup.timer has no installation config', layer: 'Timer install', meaning: 'The timer lacks [Install] WantedBy=timers.target.', firstCheck: 'systemctl cat restic-backup.timer' },
  ],

  scenarioIds: ['bk-timer-calendar', 'bk-hostkey-changed', 'bk-stale-lock', 'bk-envfile', 'bk-disk-full', 'bk-restore-file', 'bk-db-exclude'],
  assessmentId: 'backup',
  references: [
    { title: 'restic documentation', url: 'https://restic.readthedocs.io/en/stable/' },
    { title: 'restic: Removing backup snapshots (forget, prune, policies)', url: 'https://restic.readthedocs.io/en/stable/060_forget.html' },
    { title: 'systemd.timer(5)', url: 'https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html' },
    { title: 'systemd.time(7): calendar events', url: 'https://www.freedesktop.org/software/systemd/man/latest/systemd.time.html' },
    { title: 'sshd(8): AUTHORIZED_KEYS FILE FORMAT', url: 'https://man.openbsd.org/sshd#AUTHORIZED_KEYS_FILE_FORMAT' },
    { title: 'CISA: Data backup options', url: 'https://www.cisa.gov/sites/default/files/publications/data_backup_options.pdf' },
    { title: 'Microsoft Learn: wbadmin', url: 'https://learn.microsoft.com/windows-server/administration/windows-commands/wbadmin' },
  ],
  guide: BACKUP_GUIDE,
  objectives: ['N10-009:3.3'],
};

// --- Primer -------------------------------------------------------------------------

export const BACKUP_PRIMER: Primer = {
  oneLiner: 'A **backup** is a copy of data from a known moment, kept somewhere else, that you have **proven** you can restore; a backup service makes those copies on a **schedule** and keeps them for a defined **time**.',
  analogy: `
A photographer who copies every day's pictures to an archive in another building. The archive keeps one folder per day (**snapshots**), but never stores the same picture twice: a folder for a day with no new pictures just points to the old ones (**deduplication**). The folders are sealed with a code (the **repository password**); the archive staff cannot open them, and neither can the photographer if the code is lost.

A courier takes the copies over every night at 02:30 (**the timer**), shows a pass that only works from the photographer's address (**from=** in authorized_keys), and checks the archive's ID before handing anything over (**the host key**). Old folders are thrown out by a rule: the last week every day, the last month every week (**retention**). And once a month, someone fetches a folder back and checks the pictures are really in it (**the restore test**).`,
  ideas: [
    {
      title: 'RPO, RTO and 3-2-1',
      explain: 'How much data may be lost, how long the restore may take, and enough copies in enough places.',
      example: 'Nightly backups give an RPO of up to 24 hours. bak01 is one copy on another server; 3-2-1 also asks for an off-site copy.',
    },
    {
      title: 'Snapshots and deduplication',
      explain: 'Every run makes a complete snapshot, but only new data is stored.',
      example: 'On srv01: `set -a; . /etc/restic/env; set +a; restic snapshots` lists a week of nightly snapshots; a second `restic backup` adds a few hundred bytes.',
    },
    {
      title: 'A scheduled job you can see',
      explain: 'A systemd timer starts the backup service; each run is logged and its result is visible.',
      example: '`systemctl list-timers` shows NEXT and LAST for restic-backup.timer; `journalctl -u restic-backup.service` shows last night\'s summary.',
    },
    {
      title: 'A safe path to the backup server',
      explain: 'Each client has its own SSH key, accepted only from its address, and checks the server\'s host key.',
      example: 'bak01\'s /home/restic/.ssh/authorized_keys has `restrict,from="10.0.20.10" ssh-ed25519 AAAA… root@srv01 (restic backups)`.',
    },
    {
      title: 'Retention and restores',
      explain: 'A policy removes old snapshots so the disk does not fill; restores go to a separate place first.',
      example: '`restic forget --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune`; `restic restore latest --target /tmp/restore --include /etc/hosts`.',
    },
  ],
  walkthrough: {
    title: 'srv01\'s backup at 02:30',
    steps: [
      { label: 'The timer fires', detail: 'restic-backup.timer elapses at 02:30 (OnCalendar=*-*-* 02:30:00) and starts restic-backup.service.' },
      { label: 'Settings loaded', detail: 'systemd reads /etc/restic/env (EnvironmentFile=): the repository on bak01 and the password file.' },
      { label: 'SSH to bak01', detail: 'restic starts ssh as root with /root/.ssh/id_ed25519; srv01 checks bak01\'s host key, bak01 accepts the key from 10.0.20.10 for the user restic.' },
      { label: 'Only new data', detail: 'restic compares with the previous snapshot, uploads the few changed chunks encrypted, and saves a new snapshot.' },
      { label: 'Retention', detail: 'restic forget --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune removes what the policy no longer keeps and frees its space.' },
    ],
  },
  misconceptions: [
    { myth: 'No failed jobs means the backups are fine.', truth: 'A job that never runs never fails: watch the age of the newest snapshot, and test restores.' },
    { myth: 'RAID or an rsync mirror is a backup.', truth: 'They copy deletions and corruption within seconds; a backup keeps earlier points in time.' },
    { myth: 'The backup server can read the backups, so the password is not critical.', truth: 'restic encrypts on the client: without the password nobody, including you, can restore.' },
    { myth: 'In an emergency, restore everything over the live system.', truth: 'Restore to a separate place and copy back only what was lost, or newer work is overwritten.' },
  ],
  checks: [
    { q: 'What does an RPO of four hours require?', a: 'A backup (or replication) at least every four hours.' },
    { q: 'Which unit setting runs a missed backup after the machine was off?', a: 'Persistent=true in the timer.' },
    { q: 'What frees disk space after restic forget?', a: 'prune (or forget --prune).' },
    { q: 'How do you load /etc/restic/env so restic sees it?', a: 'set -a; . /etc/restic/env; set +a' },
  ],
};

// --- Assessment -------------------------------------------------------------------------

export const BACKUP_ASSESSMENT: Assessment = {
  id: 'backup',
  title: 'Backup knowledge check',
  questions: [
    {
      id: 'bk-q-rpo',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/backup/what'],
      prompt: 'The business can lose at most one hour of orders. Which objective does that set, and what does it require?',
      options: [
        { text: 'An RPO of one hour: backups or replication at least hourly', correct: true },
        { text: 'An RTO of one hour: the restore must finish within an hour', misconception: 'RTO is the downtime allowed; the amount of data that may be lost is the RPO.' },
        { text: 'Nightly backups kept for one hour', misconception: 'Nightly backups can lose up to a day of orders.' },
      ],
      concepts: ['bk.operate'],
      explanation: 'RPO = how much data (time) may be lost; RTO = how long the restore may take.',
    },
    {
      id: 'bk-q-incremental',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/backup/internals'],
      prompt: 'Full backup on Sunday, incremental backups Monday to Friday. Which backups does a restore of Wednesday night\'s state need?',
      options: [
        { text: 'Sunday\'s full and the incrementals of Monday, Tuesday and Wednesday', correct: true },
        { text: 'Sunday\'s full and Wednesday\'s incremental', misconception: 'That is how a differential works; each incremental only holds changes since the previous backup.' },
        { text: 'Only Wednesday\'s incremental', misconception: 'An incremental holds only one day\'s changes.' },
      ],
      concepts: ['bk.restore'],
      explanation: 'Incremental: changes since the last backup of any kind, so the chain is needed. Differential: changes since the last full.',
    },
    {
      id: 'bk-q-321',
      kind: 'multi',
      level: 'beginner',
      learn: ['lesson/backup/what', 'lesson/backup/internals'],
      prompt: 'Which of these protect against ransomware that encrypted the file server and has its administrator password? (choose all that apply)',
      options: [
        { text: 'An off-site copy with object lock (immutable until a date)', correct: true },
        { text: 'An offline copy (disconnected disk or tape)', correct: true },
        { text: 'RAID 1 on the file server', misconception: 'RAID mirrors the encrypted data instantly.' },
        { text: 'An rsync --delete mirror to another server every hour', misconception: 'The next sync replaces the good copy with the encrypted files.' },
      ],
      concepts: ['bk.operate'],
      explanation: 'Only copies the attacker cannot change or delete survive: offline or immutable.',
    },
    {
      id: 'bk-q-timer',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/backup/internals'],
      prompt: 'A timer has OnCalendar=*-*-* 02:30:00. The server is powered off from 23:00 to 08:00 for maintenance. Without further settings, when does the next backup run?',
      options: [
        { text: 'At 02:30 the next night: the missed run is skipped', correct: true },
        { text: 'At 08:00, right after boot', misconception: 'Only with Persistent=true.' },
        { text: 'Never again until the timer is restarted', misconception: 'An enabled timer starts at boot and waits for the next 02:30.' },
      ],
      concepts: ['bk.schedule'],
      explanation: 'Persistent=true stores the last run and catches up missed runs after boot.',
    },
    {
      id: 'bk-q-calendar',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/backup/internals', 'lesson/backup/config'],
      prompt: 'Which timer configuration runs a job at 02:30 and at 14:30 every day?',
      options: [
        { text: 'Two lines: OnCalendar=*-*-* 02:30:00 and OnCalendar=*-*-* 14:30:00', correct: true },
        { text: 'OnCalendar=*-*-* 02:30 14:30', misconception: 'One expression has one time part: systemd rejects it, and the timer refuses to start.' },
        { text: 'OnUnitActiveSec=02:30,14:30', misconception: 'OnUnitActiveSec= takes a time span after the last run, not times of day.' },
      ],
      concepts: ['bk.schedule'],
      explanation: 'Several OnCalendar= lines add up; "*-*-* 02,14:30:00" also works. Test with systemd-analyze calendar.',
    },
    {
      id: 'bk-q-env',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/backup/internals'],
      prompt: 'An administrator runs ". /etc/restic/env" and then "restic snapshots", which says "Please specify repository location". What is wrong?',
      options: [
        { text: 'The variables were set but not exported to restic', correct: true },
        { text: 'The file must be executable', misconception: '"." reads the file into the current shell; it does not need to be executable.' },
        { text: 'restic only reads /etc/restic/env when run by systemd', misconception: 'restic reads its environment; systemd provides it through EnvironmentFile=.' },
      ],
      concepts: ['bk.operate'],
      explanation: 'set -a; . /etc/restic/env; set +a exports everything the file assigns.',
    },
    {
      id: 'bk-q-hostkey',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/backup/internals'],
      prompt: 'After the backup server was reinstalled, every client fails with "REMOTE HOST IDENTIFICATION HAS CHANGED". Which fix is right?',
      options: [
        { text: 'Compare the new host key fingerprint with the server console, then replace the old key in known_hosts', correct: true },
        { text: 'Set StrictHostKeyChecking no for the backup job', misconception: 'Then any machine answering as bak01 receives the backups.' },
        { text: 'Generate new client keys', misconception: 'The client keys are fine; the server\'s key changed.' },
      ],
      concepts: ['bk.transport'],
      explanation: 'Host key checking is what stops a man-in-the-middle: verify, then trust the new key.',
    },
    {
      id: 'bk-q-prune',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/backup/internals', 'lesson/backup/operate'],
      prompt: 'restic forget --keep-daily 7 removed 20 old snapshots, but the backup disk is as full as before. Why?',
      options: [
        { text: 'forget only removes snapshot records; prune deletes the unused data', correct: true },
        { text: 'The disk needs fsck', misconception: 'Nothing is wrong with the filesystem.' },
        { text: 'restic keeps deleted snapshots for 30 days', misconception: 'There is no recycle bin; the data stays until prune.' },
      ],
      concepts: ['bk.operate'],
      explanation: 'Use forget --prune (or a separate prune) to free space.',
    },
    {
      id: 'bk-q-restore',
      kind: 'order',
      level: 'beginner',
      learn: ['lesson/backup/operate'],
      prompt: 'Order the steps to bring back one file a user deleted this morning from a busy share.',
      items: ['Find the snapshot that still has the file (restic snapshots, restic ls)', 'Restore it into a separate directory', 'Check content, owner and mode', 'Copy only that file back (cp -a)'],
      concepts: ['bk.restore'],
      explanation: 'Restoring the whole share would roll back everyone\'s work since the backup.',
    },
    {
      id: 'bk-q-unlock',
      kind: 'text',
      level: 'intermediate',
      learn: ['lesson/backup/operate'],
      prompt: 'A backup fails with "repository is already locked exclusively" by a run that was interrupted by a power cut two days ago. Which restic command removes the stale lock?',
      accept: ['restic unlock', 'unlock'],
      placeholder: 'command',
      concepts: ['bk.operate'],
      explanation: 'restic unlock removes locks of processes that are no longer running.',
    },
  ],
};
