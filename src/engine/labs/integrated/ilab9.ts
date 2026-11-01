// Integrated Lab 9: Secure and Maintain an Enterprise Environment. srv01 is
// prepared for an audit: a departed contractor's account, an sshd that the
// hosting provider's script opened up again, authentication logs that no
// longer reach the central log server, and backups that nobody has ever
// restored. Every change must keep the services working; the incident shows
// a hardening change that silently cut monitoring.

import { readFile, writeFile } from '../../fs';
import { addUser } from '../../lab/builder';
import { buildSshLab } from '../../lab/sshLab';
import { script } from '../../scenarios/engine';
import type { World } from '../../types';
import { NO, OK, probe } from '../engine';
import type { GuidedLab, LabCheck } from '../types';
import { cmdCheck, evidence, hop } from './common';
import { applyTicket, ticketFault, ticketGoalChecks, ticketStep } from './tickets';

export const CONTRACTOR_PASSWORD = 'Contractor-2025';

export function buildIlab9World(): World {
  const w = buildSshLab();
  const s = w.hosts.srv01;
  const t = w.clock;
  // A contractor who left in August: still enabled, still in sudo.
  addUser(s, { name: 'contractor', uid: 1005, gid: 1005, primaryGroup: 'contractor', groups: ['sudo'], home: '/home/contractor', shell: '/bin/bash', gecos: 'External contractor (project ended 2026-08-31)', password: CONTRACTOR_PASSWORD }, t);
  // The hosting provider's "support access" script re-enabled passwords and root logins.
  writeFile(s, '/etc/ssh/sshd_config.d/00-support-access.conf', '# Hosting provider: remote support access (ticket HP-55120)\nPermitRootLogin yes\nPasswordAuthentication yes\n', t);
  script(w, 'srv01', ['systemctl reload ssh']);
  // "Noise reduction": authentication logs no longer leave srv01.
  applyTicket(w, 'log-auth-filtered');
  w.clock += 5 * 60_000;
  return w;
}

const accountsClosed: LabCheck = {
  id: 'contractor', description: 'The contractor account on srv01 is locked and expired (kept for the audit trail, but unusable)',
  check(w) {
    const st = probe(w, 'srv01', 'root', 'passwd -S contractor');
    if (!/^contractor\s+L\b/m.test(st.output)) return NO(`The contractor's password is not locked (usermod -L or passwd -l).\n${evidence('srv01', 'root', 'passwd -S contractor', st.output, st.code)}`);
    const ch = probe(w, 'srv01', 'root', 'chage -l contractor');
    if (/Account expires\s*:\s*never/i.test(ch.output)) return NO(`The account never expires: a locked password does not stop key-based logins. Expire it (chage -E 0).\n${evidence('srv01', 'root', 'chage -l contractor', ch.output, ch.code)}`);
    if (!w.hosts.srv01.users.contractor) return NO('The account was deleted: the audit needs it (and its files) to stay until the review is closed. Lock and expire it instead.');
    return OK('Locked and expired; files and audit trail kept.');
  },
};

const sshHardened: LabCheck = {
  id: 'ssh', description: 'sshd on srv01 refuses passwords and root logins again, and alice still logs in with her key',
  check(w) {
    const t = probe(w, 'srv01', 'root', 'sshd -T');
    if (!/^permitrootlogin no$/m.test(t.output)) return NO(`sshd -T: permitrootlogin is not "no".\n${evidence('srv01', 'root', 'sshd -T | grep permitrootlogin', t.output.split('\n').filter((l) => /permitrootlogin/.test(l)).join('\n'), 0)}`);
    if (!/^passwordauthentication no$/m.test(t.output)) return NO('sshd -T: passwordauthentication is not "no" (did you reload sshd after the change?).');
    const k = probe(w, 'ws01', 'alice', 'ssh -o BatchMode=yes srv01.corp.lab hostname');
    if (!/^srv01$/m.test(k.output)) return NO(`alice can no longer log in with her key: the hardening locked out the administrators.\n${evidence('ws01', 'alice', 'ssh -o BatchMode=yes srv01.corp.lab hostname', k.output, k.code)}`);
    return OK('Key-only SSH; no root logins; administrators still get in.');
  },
};

const restoreTested: LabCheck = {
  id: 'restore', description: 'A restore test was done: /etc/nginx/nginx.conf restored from the latest snapshot into /root/restore-test is identical to the live file',
  check(w) {
    const live = readFile(w.hosts.srv01, '/etc/nginx/nginx.conf');
    const restored = readFile(w.hosts.srv01, '/root/restore-test/etc/nginx/nginx.conf');
    if (restored === undefined) return NO('/root/restore-test/etc/nginx/nginx.conf does not exist: restore it from the latest snapshot (restic restore latest --target /root/restore-test --include /etc/nginx/nginx.conf, with /etc/restic/env loaded).');
    if (restored !== live) return NO('The restored file differs from the live one: compare them (sha256sum, diff) and find out why.');
    const timer = probe(w, 'srv01', 'root', 'systemctl is-enabled restic-backup.timer');
    if (!/^enabled/m.test(timer.output)) return NO('restic-backup.timer is not enabled: the nightly backups would stop after a reboot.');
    return OK('The latest backup restores correctly, and the nightly timer is enabled.');
  },
};

const servicesStillWork: LabCheck[] = [
  cmdCheck('web', 'The intranet on srv01 still answers from the office', 'ws01', 'alice', 'curl -sI -m 5 http://srv01.corp.lab/', (o) => (/^HTTP\/1\.1 200/.test(o) ? null : 'The intranet does not answer any more: a hardening step broke a business service.'), 'The web service is unaffected.'),
  cmdCheck('timer', 'The nightly backup timer is active on srv01', 'srv01', 'root', 'systemctl is-active restic-backup.timer', (o) => (/^active/m.test(o) ? null : 'restic-backup.timer is not active.'), 'Backups keep running.'),
];

export const ILAB9: GuidedLab = {
  id: 'ilab9',
  title: 'Integrated Lab 9: Secure and Maintain an Enterprise Environment',
  level: 'intermediate',
  duration: '60–90 min',
  summary: 'Prepare a production server for an audit without breaking it: close a departed contractor\'s account without destroying the audit trail, restore key-only SSH, bring authentication logs back to the central log server, and prove that the backups can be restored. Then find out which hardening change silently cut monitoring.',
  brief: `The auditors arrive on Friday. **srv01** (intranet, inventory application) must pass these points (AUD-2026-11):

1. **Accounts**: the external contractor (account **contractor**) left on 31 August. The account must not be usable, but HR and the auditors need it and its files to stay until the review is closed.
2. **Remote access**: key-only SSH, no root logins. The hosting provider ran its "support access" script last week, which changed sshd's configuration.
3. **Logging**: authentication events (logins, sudo) must reach the central log server **log01**. Someone "reduced the noise" in srv01's forwarding.
4. **Backups**: srv01 is backed up nightly with restic to bak01. Nobody has ever restored anything. Prove that a restore works (restore /etc/nginx/nginx.conf from the latest snapshot into /root/restore-test and compare it with the live file).

Every change must keep srv01's services working: the intranet, alice's key logins, the nightly backup.`,
  objectives: [
    'Close an account without deleting the evidence: lock, expire, keep the files.',
    'Harden sshd and verify the effective configuration (sshd -T) without locking the administrators out.',
    'Restore central logging of authentication events and verify that they arrive.',
    'Prove that backups work by restoring and comparing, not by reading "backup succeeded".',
    'Balance security and availability: verify the business services after every change.',
  ],
  prerequisites: [
    { label: 'SSH', link: 'lesson/ssh/what' },
    { label: 'Central logging (rsyslog)', link: 'lesson/logging/what' },
    { label: 'Backups (restic, systemd timers)', link: 'lesson/backup/what' },
    { label: 'Linux service administration', link: 'lesson/systemd/what' },
  ],
  setupNote: 'The standard lab network. srv01 forwards its logs to log01 (10.0.20.50) and is backed up nightly to bak01 (10.0.20.45); mon01 monitors the servers.',
  terminals: [
    { hostId: 'srv01', user: 'root', label: 'srv01 console (root)', banner: 'srv01 console (root). Try: getent passwd contractor, passwd -S contractor, chage -l contractor, sshd -T | grep -E "permitrootlogin|passwordauthentication", cat /etc/rsyslog.d/*.conf, systemctl list-timers, cat /etc/restic/env.' },
    { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01 (alice): her SSH key logs in to srv01. Try: ssh srv01.corp.lab, ssh -o PubkeyAuthentication=no srv01.corp.lab.' },
    { hostId: 'log01', user: 'root', label: 'log01 (log server)', banner: 'log01 (root): central logs in /var/log/remote/HOST/PROGRAM.log. Try: ls /var/log/remote/srv01/, tail /var/log/remote/srv01/sshd.log.' },
    { hostId: 'mon01', user: 'root', label: 'mon01 (monitoring)', banner: 'mon01 (root): Prometheus. Try: promtool query instant http://localhost:9090 \'up\', amtool alert.' },
  ],
  build: buildIlab9World,
  steps: [
    {
      id: 'accounts', title: 'Close the contractor\'s account (keep the evidence)',
      objective: 'The contractor account on srv01 can no longer be used by any method, but the account and its files remain for the audit.',
      background: 'Deleting an account destroys evidence (its files, the mapping of its UID in old logs and backups) and auditors need it. **Lock** the password (usermod -L puts a "!" in /etc/shadow) **and expire** the account (chage -E 0): a locked password alone does not stop logins with an SSH key in ~/.ssh/authorized_keys. Expiry blocks every method, because PAM\'s account phase checks it.',
      tasks: [
        'Look: `getent passwd contractor`, `id contractor`, `passwd -S contractor`, `chage -l contractor`, `ls -la /home/contractor/.ssh`.',
        '`usermod -L contractor` and `chage -E 0 contractor`.',
        'Check again with `passwd -S` (L) and `chage -l` (Account expires: Jan 01, 1970).',
      ],
      hints: ['userdel would remove the evidence; the auditors asked to keep it.', 'Expiry is what stops key logins: sshd asks PAM\'s account phase after any authentication method.'],
      checks: [accountsClosed],
      solution: [{ host: 'srv01', user: 'root', commands: ['usermod -L contractor', 'chage -E 0 contractor', 'passwd -S contractor'] }],
      commands: [
        { host: 'srv01', command: 'chage -E 0 contractor', what: 'Sets the account\'s expiry date to 1 January 1970: the account is expired.', why: 'Locking the password only stops password logins; an expired account cannot log in with any method (keys, Kerberos).', where: 'The 8th field of /etc/shadow.', success: 'No output.', verify: 'chage -l contractor; ssh as contractor is refused (the log says "account expired").' },
      ],
      learn: [{ label: 'Accounts and expiry', link: 'reference?id=chage' }, { label: 'passwd', link: 'reference?id=passwd' }],
      concepts: ['ssh.authz', 'linux.permissions'],
    },
    {
      id: 'ssh', title: 'Key-only SSH, no root logins',
      objective: 'sshd on srv01 refuses passwords and root logins (effective configuration), and alice still logs in with her key.',
      background: 'The **effective** configuration is what counts: `sshd -T` prints it after reading sshd_config and every included file. sshd uses the **first** value it reads for most keywords, and the drop-ins in /etc/ssh/sshd_config.d/ are read in name order at the Include line (near the top of sshd_config): a file named 00-… beats your 10-hardening.conf.\n\nChange the configuration, check it with `sshd -t`, **reload** (existing sessions stay), and test from a second session before closing yours. If the administrators cannot log in afterwards, the hardening has made the server unmanageable.',
      tasks: [
        '`sshd -T | grep -E "permitrootlogin|passwordauthentication"`. Find where the values come from (`grep -rn -E "PermitRootLogin|PasswordAuthentication" /etc/ssh/`).',
        'Remove (or neutralise) the file that overrides the hardening, keeping 10-hardening.conf, then `sshd -t` and `systemctl reload ssh`.',
        'From ws01: `ssh srv01.corp.lab` (key, works) and `ssh -o PubkeyAuthentication=no srv01.corp.lab` (refused).',
      ],
      hints: ['10-hardening.conf already says "no": why does sshd -T say "yes"? ls /etc/ssh/sshd_config.d/ and think about the order.', 'Keep your root console open until the key login is tested.'],
      checks: [sshHardened],
      solution: [{ host: 'srv01', user: 'root', commands: ['rm /etc/ssh/sshd_config.d/00-support-access.conf', 'sshd -t', 'systemctl reload ssh', 'sshd -T | grep -E "permitrootlogin|passwordauthentication"'] }],
      commands: [
        { host: 'srv01', command: 'sshd -T', what: 'Prints the effective sshd configuration (after defaults, sshd_config and includes).', why: 'Several files and defaults combine; the file you edited is not necessarily the one that wins.', where: '/etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*.conf', success: '"permitrootlogin no", "passwordauthentication no".', verify: 'Test both methods from a client after the reload.' },
      ],
      learn: [{ label: 'SSH hardening', link: 'lesson/ssh/config' }, { label: 'Safe sshd changes', link: 'reference?id=proc:sshd-safe-restart' }],
      concepts: ['ssh.config', 'ssh.userauth'],
    },
    ticketStep('log-auth-filtered', {
      id: 'logging', title: 'Authentication logs back to log01',
      objective: 'Authentication events from srv01 (facilities auth and authpriv) reach log01 again.',
      background: 'The auditors (and incident responders) need **who logged in where and when**, stored somewhere an intruder on srv01 cannot edit: the central log server. rsyslog forwards what its **selector** matches: `*.*` is everything; `*.*;auth,authpriv.none` explicitly leaves the authentication facilities out. Test with `logger -p authpriv.notice …` on srv01 and look on log01.',
      tasks: [
        'On srv01: `cat /etc/rsyslog.d/50-central.conf`: which facilities does the forwarding action match?',
        'Fix the selector so auth and authpriv are forwarded again, `rsyslogd -N1`, `systemctl restart rsyslog`.',
        'Test: `logger -p authpriv.notice -t audittest "audit test"` on srv01, then on log01 `ls /var/log/remote/srv01/` and look for it.',
      ],
      concepts: ['logs.central'],
      learn: [{ label: 'Central logging', link: 'lesson/logging/internals' }, { label: 'rsyslog.conf', link: 'reference?id=file:rsyslog-conf' }],
    }),
    {
      id: 'backup', title: 'Prove that a restore works',
      objective: '/etc/nginx/nginx.conf restored from the latest snapshot into /root/restore-test is identical to the live file, and the nightly backup timer is enabled.',
      background: 'A backup is only as good as the last **restore** that worked. "The job succeeded" says that data was sent, not that it can be read back (wrong paths, excludes, a lost password). A restore test: list the snapshots, restore one file to a **separate** place (never over the live file), and compare.\n\nrestic needs the repository and its password: srv01 keeps them in /etc/restic/env (RESTIC_REPOSITORY, RESTIC_PASSWORD_FILE), the EnvironmentFile of the backup service.',
      tasks: [
        '`systemctl list-timers` and `journalctl -u restic-backup -n 5`: when did it last run, and did it succeed?',
        'Load the settings: `set -a; . /etc/restic/env; set +a`, then `restic snapshots`.',
        '`restic restore latest --target /root/restore-test --include /etc/nginx/nginx.conf`, then `sha256sum /etc/nginx/nginx.conf /root/restore-test/etc/nginx/nginx.conf`.',
      ],
      hints: ['restic restore recreates the full path under --target: /root/restore-test/etc/nginx/nginx.conf.', 'Restoring into / would overwrite the live file: always restore elsewhere first.'],
      checks: [restoreTested],
      solution: [{ host: 'srv01', user: 'root', commands: ['set -a; . /etc/restic/env; set +a; restic snapshots', 'set -a; . /etc/restic/env; set +a; restic restore latest --target /root/restore-test --include /etc/nginx/nginx.conf', 'sha256sum /etc/nginx/nginx.conf /root/restore-test/etc/nginx/nginx.conf'] }],
      commands: [
        { host: 'srv01', command: 'restic restore latest --target /root/restore-test --include /etc/nginx/nginx.conf', what: 'Restores one file from the newest snapshot into a separate directory.', why: 'It proves that the repository, the password and the backed-up paths all work, without touching the live system.', where: 'Repository and password from /etc/restic/env; the restored copy under /root/restore-test.', success: '"restoring <Snapshot … of [/etc /var/www /root] …> to /root/restore-test".', verify: 'sha256sum (or diff) against the live file.' },
      ],
      learn: [{ label: 'Restores', link: 'lesson/backup/operate' }, { label: 'Restore procedure', link: 'reference?id=proc:backup-restore' }],
      concepts: ['bk.restore'],
    },
    {
      id: 'verify', title: 'Verify security and availability, and after a reboot', stage: 'verify',
      objective: 'Every audit point holds and every business service works, also after every machine restarts.',
      background: 'Security changes are verified twice: the **control** works (the contractor cannot log in, passwords are refused, logs arrive) and the **business** still works (the intranet, the administrators\' logins, the backups). Then reboot: runtime-only changes disappear.',
      tasks: ['From ws01: `ssh srv01.corp.lab`, `curl -sI http://srv01.corp.lab/`. On srv01: `systemctl is-active restic-backup.timer`.', 'Run the check (reboots every machine on a copy and repeats every check).'],
      hints: ['If logs stop arriving after the reboot, the selector fix is not in the file.'],
      checks: [...servicesStillWork, ...ticketGoalChecks('log-auth-filtered')],
      solution: [],
      learn: [{ label: 'Operating servers', link: 'lesson/systemd/operate' }],
      concepts: ['ops.recovery'],
      afterReboot: true,
    },
  ],
  integrated: {
    number: 9,
    scenario: {
      organisation: 'corp.lab: srv01 runs the intranet and the inventory application and is part of this year\'s audit.',
      situation: 'Four findings from a pre-audit scan: an active account of a departed contractor, password and root logins allowed over SSH, no authentication logs on the central log server since a "noise reduction", and backups that were never restored.',
      goal: 'Fix every finding with the least disruptive correct change, and prove that the server\'s services still work.',
      whyItMatters: 'Hardening that breaks production gets rolled back, and hardening that nobody verifies is not there. In competitions the same balance applies: lock attackers out without taking down the scored services.',
    },
    technologies: ['Linux accounts (shadow, lock, expiry)', 'SSH hardening (sshd -T, reload)', 'Central logging (rsyslog selectors, log01)', 'Backups and restores (restic, systemd timers)', 'Monitoring (Prometheus) as a check on hardening'],
    systems: [
      { host: 'srv01', role: 'The production server under audit' },
      { host: 'ws01', role: 'alice\'s workstation: administrator key logins' },
      { host: 'log01', role: 'Central log server (10.0.20.50)' },
      { host: 'bak01', role: 'Backup server (restic repositories over SFTP)' },
      { host: 'mon01', role: 'Monitoring (Prometheus scrapes node_exporter on the servers)' },
    ],
    startingState: [
      'srv01: account contractor (enabled, in sudo, with a password).',
      'srv01: the hosting provider added /etc/ssh/sshd_config.d/00-support-access.conf (passwords and root logins allowed).',
      'srv01: forwards everything to log01 except auth and authpriv.',
      'srv01: nightly restic backups to bak01, never tested.',
    ],
    tools: [
      { command: 'passwd -S, chage -l / -E, usermod -L', platform: 'Linux', use: 'Account state, lock and expiry', refId: 'chage' },
      { command: 'sshd -T, sshd -t, systemctl reload ssh', platform: 'Linux', use: 'Effective SSH configuration, check, apply', refId: 'sshd-t' },
      { command: 'logger -p FACILITY.LEVEL, rsyslogd -N1', platform: 'Linux', use: 'Test and check log forwarding', refId: 'logger' },
      { command: 'restic snapshots / restore, sha256sum', platform: 'Linux', use: 'Backups and restore tests', refId: 'restic' },
      { command: 'systemctl list-timers, journalctl -u restic-backup', platform: 'Linux', use: 'When the backup ran, and its result', refId: 'systemd-analyze' },
      { command: 'promtool query instant … up', platform: 'Linux', use: 'Whether monitoring still sees the servers', refId: 'promtool' },
      { command: 'Get-LocalUser, Disable-LocalUser', platform: 'Windows', use: 'The same account controls on a Windows server', refId: 'passwd' },
    ],
    dependencies: {
      explanation: `Every control here has something it must not break:

| Control | Must keep working |
|---|---|
| Lock and expire contractor | Other accounts; the files for the audit (do not delete) |
| Key-only SSH, no root | alice's key login (test before closing your session) |
| Forward auth logs to log01 | log01's disk and filters (it stores per host and program) |
| Restore test | The live files (restore elsewhere), the nightly timer |
| Any firewall hardening | Monitoring's scrape (mon01 → TCP 9100), backups (srv01 → bak01:22), logs (→ log01:514) |

The last line is where hardening most often breaks something nobody tests: monitoring and backups run in the background, so their failure shows up later, as an alert, or as a missing backup.`,
      paths: [
        {
          id: 'admin', label: 'alice administers srv01',
          nodes: [
            hop('port', 'TCP 22 answers', 'sshd on srv01.', 'ws01', 'alice', 'nc -z -w 3 10.0.20.10 22', (_o, c) => c === 0),
            hop('key', 'Key login', 'alice\'s key; key-only SSH must keep this working.', 'ws01', 'alice', 'ssh -o BatchMode=yes srv01.corp.lab hostname', (o) => /^srv01$/m.test(o)),
          ],
        },
        {
          id: 'logs', label: 'srv01\'s logs reach log01',
          nodes: [
            hop('rsyslog', 'rsyslog runs on srv01', 'The forwarder.', 'srv01', 'root', 'systemctl is-active rsyslog', (o) => /^active/m.test(o)),
            hop('port', 'log01 accepts TCP 514', 'The receiver and its firewall.', 'srv01', 'root', 'nc -z -w 3 log01.corp.lab 514', (_o, c) => c === 0),
            hop('stored', 'srv01\'s logs are stored on log01', '/var/log/remote/srv01/ on log01.', 'log01', 'root', 'ls /var/log/remote/srv01', (o, c) => c === 0 && o.trim() !== ''),
          ],
        },
        {
          id: 'monitoring', label: 'monitoring scrapes the servers',
          nodes: [
            hop('srv01', 'srv01 is up in Prometheus', 'mon01 → srv01:9100.', 'mon01', 'root', 'promtool query instant http://localhost:9090 \'up{instance="srv01.corp.lab:9100"}\'', (o) => /=> 1 @/.test(o)),
            hop('fs01', 'fs01 is up in Prometheus', 'mon01 → fs01:9100 (allowed by fs01\'s firewall).', 'mon01', 'root', 'promtool query instant http://localhost:9090 \'up{instance="fs01.corp.lab:9100"}\'', (o) => /=> 1 @/.test(o)),
          ],
        },
      ],
    },
    mistakes: [
      'Deleting the contractor (userdel -r): the audit trail and the files are gone.',
      'Locking the password but not expiring the account: SSH keys still work.',
      'Disabling passwords before checking that the administrators\' keys work.',
      'Forwarding with a selector that leaves auth/authpriv out, and not testing with logger.',
      'Calling backups "fine" because the job succeeded, without restoring anything.',
      'A firewall hardening that forgets monitoring, backups or logging: the damage shows up later.',
    ],
    verification: 'Checks look at the effective state (passwd -S and chage on srv01, sshd -T, a log message travelling to log01, the restored file compared byte for byte with the live one) and at the services that must keep working (alice\'s key login, the intranet, the backup timer). The final check reboots every machine and repeats them. The incident is repaired when Prometheus scrapes fs01 again with its port still restricted to mon01.',
    fault: ticketFault('mon-fs01-firewall', {
      title: 'After the hardening of fs01: a page for a healthy server',
      report: 'On call (dana, Saturday 07:12): "I was paged: InstanceDown for fs01.corp.lab:9100. But the shares work, and I can log in to fs01." The security team (Friday evening): "We applied the same audit hardening to fs01\'s firewall: only NFS, SMB and SSH are needed on a file server."',
    }),
    review: [
      { id: 'q1', question: 'Why lock AND expire the contractor\'s account instead of only locking its password?', choices: ['A locked password still allows SSH key logins; expiry blocks every authentication method', 'Expiry deletes the home directory', 'Locking is undone at the next reboot', 'chage is required by sudo'], answer: 0, explanation: 'usermod -L only invalidates the password hash. sshd still accepts keys, but PAM\'s account phase refuses an expired account.', concepts: ['ssh.authz'] },
      { id: 'q2', question: '10-hardening.conf says "PasswordAuthentication no", but sshd -T shows "yes". Why?', choices: ['Another file read earlier (00-support-access.conf) sets it first, and sshd keeps the first value', 'sshd -T reads only the defaults', 'The change needs a reboot', 'Drop-ins are ignored'], answer: 0, explanation: 'Drop-ins are read in name order at the Include line, and for most keywords the first value wins.', concepts: ['ssh.config'] },
      { id: 'q3', question: 'What does a successful restore test prove that "backup job succeeded" does not?', choices: ['That the repository, its password and the backed-up paths actually give the data back', 'That the backup ran on time', 'That bak01 has free space', 'Nothing more'], answer: 0, explanation: 'A job can succeed while backing up the wrong paths, excluding what matters, or with a password nobody has any more.', concepts: ['bk.restore'] },
      { id: 'q4', question: 'After a firewall hardening, a server is "down" in monitoring but its users see no problem. What is the most likely cause?', choices: ['The hardening dropped the monitoring server\'s scrape port (e.g. TCP 9100 from mon01)', 'The server is really down', 'Prometheus needs a restart', 'DNS is broken'], answer: 0, explanation: 'Background dependencies (monitoring, backups, logging) are easy to forget in "only what users need" firewall rules.', concepts: ['mon.metrics', 'fw.path'] },
      { id: 'q5', question: 'Why send authentication logs to a central server rather than keeping them only on srv01?', choices: ['An intruder with root on srv01 can delete local logs, not those already on log01', 'Local logs are not timestamped', 'log01 compresses them', 'sshd cannot write local logs'], answer: 0, explanation: 'Central logs survive the compromise (or loss) of the machine that produced them.', concepts: ['logs.central'] },
    ],
    after: ['ssh', 'logging', 'backup', 'monitoring', 'systemd'],
  },
};
