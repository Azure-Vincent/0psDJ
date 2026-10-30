// Lab 8: Backup Server. A new server, wiki01 (the internal wiki), went into
// production without backups. The learner puts it under the same backup
// system as the other servers: a dedicated SSH key that bak01 accepts only
// from wiki01, the backup server's host key verified, an encrypted restic
// repository with a root-only password file, a first backup, a systemd
// service and nightly timer, a retention policy, a restore test, and a
// reboot test.

import { mkdir, readFile, writeFile } from '../fs';
import { BAK01_IP, clientKey, REPO_ROOT } from '../lab/backupLab';
import { addUser, createHost, staticInterfaces } from '../lab/builder';
import { TIMESYNCD_CONF } from '../lab/krbLab';
import { installRsyslog } from '../lab/logLab';
import { trustCorpRoot } from '../lab/pkiLab';
import { buildSshLab, CORP_ZONE, DEBIAN_SSHD_CONFIG, hostKeyPair, installHostKeys, SW01_INTERFACES } from '../lab/sshLab';
import { script } from '../scenarios/engine';
import { recomputeL2 } from '../sim/l2';
import { bootHost } from '../sim/services';
import { nextElapse, parseCalendar, parseUnit, runtime } from '../sim/timers';
import type { World } from '../types';
import { NO, OK, printfTo, probe } from './engine';
import type { GuidedLab, LabCheck } from './types';

export const WIKI01_IP = '10.0.20.47';
export const WIKI01_ALICE = 'wiki01-alice';
export const WIKI_REPO_PASSWORD = 'Rst-wiki01-26';
const REPO = `sftp:restic@bak01.corp.lab:${REPO_ROOT}/wiki01`;
const ENV = 'set -a; . /etc/restic/env; set +a';

const LAB8_ZONE = CORP_ZONE.replace('2026101901 ; serial', '2026101903 ; serial').replace(`bak01   IN A    ${BAK01_IP}\n`, `bak01   IN A    ${BAK01_IP}\nwiki01  IN A    ${WIKI01_IP}\n`);

const WIKI01_NFT = `#!/usr/sbin/nft -f

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iif "lo" accept
		meta l4proto icmp accept
		tcp dport { 22, 80 } accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

const PAGES: Record<string, string> = {
  'home.md': '# corp.lab wiki\n\nStart here: [[network]], [[backups]], [[on-call]].\n',
  'network.md': '# Network\n\nVLAN 10 office, VLAN 20 servers, VLAN 30 development. rtr01 routes between them.\n',
  'backups.md': '# Backups\n\nEvery server backs up to bak01 at night with restic (CHG-2541). Restore drills: first Friday of the month.\n',
  'on-call.md': '# On-call\n\nWeek 43: alice. Escalation: dana.\n',
};

export function buildLab8World(): World {
  const world = buildSshLab();
  const t = world.clock;
  const sw = world.hosts.sw01;
  sw.ifaces.push({ name: 'swp19', mac: '52:54:00:5e:00:13', segment: null, address: null, prefix: null, up: false, staticSegment: null, addrs6: [] });
  writeFile(sw, '/etc/network/interfaces', SW01_INTERFACES
    .replace('auto br0\n', 'auto swp19\niface swp19\n    alias wiki01 (internal wiki)\n    bridge-access 20\n\nauto br0\n')
    .replace(/(bridge-ports .*)\n/, '$1 swp19\n'), t);
  world.links = [...(world.links ?? []), { a: { host: 'wiki01', iface: 'eth0' }, b: { host: 'sw01', iface: 'swp19' } }];
  writeFile(world.hosts.ns1, '/etc/bind/db.corp.lab', LAB8_ZONE, t, { group: 'bind' });

  const h = createHost(world, {
    id: 'wiki01', hostname: 'wiki01', domain: 'corp.lab', role: 'Internal wiki (new: no backups yet)',
    ifaces: [{ name: 'eth0', mac: '52:54:00:1c:00:2f', segment: null }],
    services: ['rsyslog', 'systemd-timesyncd', 'nftables', 'ssh'],
  });
  writeFile(h, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: `${WIKI01_IP}/24`, gateway: '10.0.20.1' }]), t);
  writeFile(h, '/etc/resolv.conf', 'search corp.lab\nnameserver 10.0.10.53\n', t);
  writeFile(h, '/etc/ssh/sshd_config', DEBIAN_SSHD_CONFIG, t);
  writeFile(h, '/etc/nftables.conf', WIKI01_NFT, t, { mode: 0o755 });
  mkdir(h, '/etc/systemd', t);
  writeFile(h, '/etc/systemd/timesyncd.conf', TIMESYNCD_CONF, t);
  mkdir(h, '/etc/systemd/system', t);
  installHostKeys(h, t);
  trustCorpRoot(h, t);
  installRsyslog(h, t, true);
  addUser(h, { name: 'alice', uid: 1000, gid: 1000, primaryGroup: 'alice', groups: ['sudo', 'adm'], home: '/home/alice', shell: '/bin/bash', gecos: 'Alice Admin', password: WIKI01_ALICE }, t);
  addUser(h, { name: 'wiki', uid: 1200, gid: 1200, primaryGroup: 'wiki', groups: [], home: '/srv/wiki', shell: '/usr/sbin/nologin', gecos: 'wiki application', password: '' }, t, false);
  if (!h.fs['/srv']) mkdir(h, '/srv', t);
  mkdir(h, '/srv/wiki', t, { owner: 'wiki', group: 'wiki', mode: 0o750 });
  mkdir(h, '/srv/wiki/pages', t, { owner: 'wiki', group: 'wiki', mode: 0o750 });
  mkdir(h, '/srv/wiki/uploads', t, { owner: 'wiki', group: 'wiki', mode: 0o750 });
  for (const [name, text] of Object.entries(PAGES)) writeFile(h, `/srv/wiki/pages/${name}`, text, t - 86_400_000 * (name.length % 5), { owner: 'wiki', group: 'wiki', mode: 0o640 });
  writeFile(h, '/srv/wiki/uploads/network-diagram.png', '(PNG image)\n', t - 86_400_000 * 3, { owner: 'wiki', group: 'wiki', mode: 0o640 });
  h.fs['/srv/wiki/uploads/network-diagram.png'].size = 245_760;
  if (!h.fs['/var/lib']) mkdir(h, '/var/lib', t);

  recomputeL2(world);
  script(world, 'sw01', ['ifreload -a']);
  script(world, 'ns1', ['rndc reload']);
  bootHost(world, h);
  world.clock += 5 * 60_000;
  return world;
}

// ---------------------------------------------------------------- checks

const NEW_KEY_PATH = '/root/.ssh/id_ed25519';

function wikiPubKey(w: World): string | null {
  const pub = readFile(w.hosts.wiki01, `${NEW_KEY_PATH}.pub`);
  const m = pub && /^(ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa) (\S+)/.exec(pub.trim());
  return m ? m[2] : null;
}

const keyMade: LabCheck = {
  id: 'key', description: 'wiki01 has its own SSH key pair for root (/root/.ssh/id_ed25519, private key mode 0600)',
  check(w) {
    const h = w.hosts.wiki01;
    const priv = h.fs[NEW_KEY_PATH];
    if (!priv) return NO('/root/.ssh/id_ed25519 does not exist (ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519).');
    if ((priv.mode & 0o077) !== 0) return NO(`The private key has mode ${(priv.mode & 0o777).toString(8)}: ssh refuses keys that others can read (chmod 600).`);
    if (!wikiPubKey(w)) return NO('/root/.ssh/id_ed25519.pub is missing or not a public key.');
    return OK('A key pair for root on wiki01.');
  },
};

const accessGranted: LabCheck = {
  id: 'access', description: 'bak01 accepts wiki01\'s key for the user restic, only from wiki01\'s address; wiki01 trusts bak01\'s verified host key',
  check(w) {
    const blob = wikiPubKey(w);
    if (!blob) return NO('Create the key first.');
    const ak = readFile(w.hosts.bak01, '/home/restic/.ssh/authorized_keys') ?? '';
    const line = ak.split('\n').find((l) => l.includes(blob));
    if (!line) return NO('wiki01\'s public key is not in /home/restic/.ssh/authorized_keys on bak01.');
    const from = /(?:^|,)from="([^"]*)"/.exec(line.split(/\s+/)[0]);
    if (!from) return NO(`The key line has no from="…" restriction: a copy of this key would work from anywhere. Prefix it with from="${WIKI01_IP}" (and restrict).`);
    if (from[1].split(',').some((p) => p !== WIKI01_IP && p !== `${WIKI01_IP}/32`)) return NO(`from="${from[1]}" allows more than wiki01 (${WIKI01_IP}).`);
    const kh = readFile(w.hosts.wiki01, '/root/.ssh/known_hosts') ?? '';
    const real = hostKeyPair('bak01', 'ed25519').blobB64;
    if (!kh.split('\n').some((l) => /(^|,)bak01\.corp\.lab[\s,]/.test(l) && l.includes(real))) return NO('wiki01 does not know bak01\'s host key (/root/.ssh/known_hosts): add it after comparing its fingerprint (ssh-keyscan, ssh-keygen -lf).');
    const t = probe(w, 'wiki01', 'root', 'ssh -o BatchMode=yes restic@bak01.corp.lab true');
    if (t.code !== 0) return NO(`ssh -o BatchMode=yes restic@bak01.corp.lab true: ${t.output.trim().split('\n').slice(-2).join(' ')}`);
    return OK(`restic@bak01 accepts the key from ${WIKI01_IP} only; bak01's host key is verified.`);
  },
};

const repoReady: LabCheck = {
  id: 'repo', description: 'An initialised restic repository for wiki01 on bak01, used through /etc/restic/env and a root-only password file',
  check(w) {
    const h = w.hosts.wiki01;
    const pw = h.fs['/etc/restic/password'];
    if (!pw) return NO('/etc/restic/password does not exist.');
    if (pw.owner !== 'root' || (pw.mode & 0o077) !== 0) return NO(`/etc/restic/password is mode ${(pw.mode & 0o777).toString(8)}, owner ${pw.owner}: only root may read the key to every backup (chmod 600).`);
    if (pw.content.trim().length < 12) return NO('The repository password is shorter than 12 characters.');
    const env = readFile(h, '/etc/restic/env') ?? '';
    if (!/^RESTIC_REPOSITORY=sftp:restic@bak01\.corp\.lab:\/srv\/backup\/restic\/wiki01\/?$/m.test(env)) return NO(`/etc/restic/env must set RESTIC_REPOSITORY=${REPO}.`);
    if (!/^RESTIC_PASSWORD_FILE=\/etc\/restic\/password$/m.test(env)) return NO('/etc/restic/env must set RESTIC_PASSWORD_FILE=/etc/restic/password (never the password itself).');
    if (!w.hosts.bak01.fs[`${REPO_ROOT}/wiki01/config`]) return NO(`There is no repository in ${REPO_ROOT}/wiki01 on bak01 yet (${ENV}; restic init).`);
    const s = probe(w, 'wiki01', 'root', `${ENV}; restic snapshots`);
    if (s.code !== 0) return NO(`restic snapshots with /etc/restic/env: ${s.output.trim().split('\n').slice(-2).join(' ')}`);
    return OK(`Repository ${REPO} opens with the password file.`);
  },
};

function snapshots(w: World): { time: number; paths: string[]; files: { p: string }[] }[] {
  const pre = `${REPO_ROOT}/wiki01/snapshots/`;
  return Object.entries(w.hosts.bak01.fs).filter(([p]) => p.startsWith(pre)).map(([, n]) => { try { return JSON.parse(n.content); } catch { return null; } }).filter(Boolean).sort((a, b) => a.time - b.time);
}

const firstBackup: LabCheck = {
  id: 'first-backup', description: 'A snapshot of wiki01 holds /etc and the wiki data (/srv/wiki, with every page)',
  check(w) {
    const s = snapshots(w).at(-1);
    if (!s) return NO('No snapshot in wiki01\'s repository yet (restic backup /etc /srv/wiki).');
    for (const p of ['/etc', '/srv/wiki']) if (!s.paths.includes(p)) return NO(`The newest snapshot does not include ${p} (its paths: ${s.paths.join(' ')}).`);
    const missing = Object.keys(PAGES).find((name) => !s.files.some((f) => f.p === `/srv/wiki/pages/${name}`));
    if (missing) return NO(`/srv/wiki/pages/${missing} is not in the snapshot: is it excluded, or was the backup not run as root?`);
    return OK(`${snapshots(w).length} snapshot(s); the newest has /etc and /srv/wiki.`);
  },
};

const scheduled: LabCheck = {
  id: 'schedule', description: 'restic-backup.service runs the backup with /etc/restic/env, and restic-backup.timer (enabled, Persistent=true) starts it every night',
  check(w) {
    const h = w.hosts.wiki01;
    const svc = readFile(h, '/etc/systemd/system/restic-backup.service');
    const tim = readFile(h, '/etc/systemd/system/restic-backup.timer');
    if (!svc || !tim) return NO('Create /etc/systemd/system/restic-backup.service and restic-backup.timer.');
    const u = parseUnit(svc);
    if (!(u.Service?.EnvironmentFile ?? []).some((f) => f.replace(/^-/, '') === '/etc/restic/env')) return NO('The service does not load EnvironmentFile=/etc/restic/env.');
    if (!(u.Service?.ExecStart ?? []).length) return NO('The service has no ExecStart=.');
    const t = parseUnit(tim);
    if (!/^(yes|true|1|on)$/i.test(t.Timer?.Persistent?.at(-1) ?? '')) return NO('Persistent=true is missing: a night when wiki01 was off would be skipped instead of caught up.');
    const specs = (t.Timer?.OnCalendar ?? []).map(parseCalendar);
    if (!specs.length || specs.some((c) => !c)) return NO('OnCalendar= is missing or not valid (check with systemd-analyze calendar).');
    const day0 = Date.parse('2026-10-26T00:00:00Z');
    const runs = specs.map((c) => nextElapse(c!, day0 - 1)).filter((n): n is number => n !== null && n < day0 + 86_400_000);
    if (!runs.length) return NO('The timer does not fire every day.');
    const rt = runtime(h, 'restic-backup.timer');
    if (!rt.enabled) return NO('restic-backup.timer is not enabled (systemctl enable --now restic-backup.timer).');
    if (rt.state !== 'active') return NO('restic-backup.timer is not active (systemctl start restic-backup.timer, or enable --now).');
    const run = probe(w, 'wiki01', 'root', 'systemctl start restic-backup.service');
    if (run.code !== 0) return NO(`systemctl start restic-backup.service failed: ${run.output.trim().split('\n')[0]} (journalctl -u restic-backup).`);
    return OK(`Nightly at ${new Date(runs[0]).toISOString().slice(11, 16)} UTC, Persistent; the service runs successfully.`);
  },
};

const retention: LabCheck = {
  id: 'retention', description: 'Every run applies a retention policy (restic forget with --keep-daily 7 or more, and --prune), and the repository keeps its snapshots',
  check(w) {
    const h = w.hosts.wiki01;
    const u = parseUnit(readFile(h, '/etc/systemd/system/restic-backup.service') ?? '');
    const execs = (u.Service?.ExecStart ?? []).map((e) => e.replace(/^[-@:+!]+/, ''));
    const text = execs.map((e) => `${e}\n${readFile(h, e.split(/\s+/)[0]) ?? ''}`).join('\n');
    const forget = /restic\s+forget[^\n]*/.exec(text)?.[0];
    if (!forget) return NO('Neither ExecStart= nor the script it runs calls restic forget: snapshots would pile up forever.');
    const daily = /--keep-daily[ =](\d+)/.exec(forget);
    if (!daily || Number(daily[1]) < 7) return NO('Keep at least a week of daily snapshots (--keep-daily 7 or more).');
    if (!/--prune/.test(forget)) return NO('forget only removes snapshots from the list; --prune (or a separate restic prune) frees the space.');
    if (snapshots(w).length < 1) return NO('The repository has no snapshot left.');
    return OK(`Retention: ${forget.replace(/^restic\s+forget\s*/, '')}`);
  },
};

const restoreTested: LabCheck = {
  id: 'restore', description: 'The wiki was restored from the backup into /tmp/restore-test, with the same pages, owner and mode as on the server',
  check(w) {
    const h = w.hosts.wiki01;
    for (const name of Object.keys(PAGES)) {
      const a = h.fs[`/srv/wiki/pages/${name}`];
      const b = h.fs[`/tmp/restore-test/srv/wiki/pages/${name}`];
      if (!b) return NO(`/tmp/restore-test/srv/wiki/pages/${name} does not exist (restic restore latest --target /tmp/restore-test --include /srv/wiki).`);
      if (!a || a.content !== b.content) return NO(`${name} differs from the server's copy.`);
      if (b.owner !== 'wiki' || (b.mode & 0o777) !== 0o640) return NO(`${name} was restored as ${b.owner} with mode ${(b.mode & 0o777).toString(8)}: restore as root so owner and mode come back (wiki, 640).`);
    }
    return OK('Every page restored with its content, owner and mode.');
  },
};

// ---------------------------------------------------------------- the lab

const SCRIPT = `#!/bin/sh
# Nightly backup of wiki01 to bak01, then the retention policy.
set -e
restic backup --tag nightly /etc /srv/wiki
restic forget --tag nightly --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune
`;
const SERVICE = `[Unit]
Description=Nightly restic backup to bak01
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/restic/env
ExecStart=/usr/local/sbin/restic-backup
`;
const TIMER = `[Unit]
Description=Run the restic backup every night

[Timer]
OnCalendar=*-*-* 03:15:00
Persistent=true

[Install]
WantedBy=timers.target
`;

export const LAB8: GuidedLab = {
  id: 'lab8',
  title: 'Lab 8: Backup Server',
  level: 'intermediate',
  duration: '60–90 min',
  summary: 'Put a new server under backup the way the other servers are: a dedicated SSH key restricted to the client, a verified host key, an encrypted restic repository on bak01, a systemd service and nightly timer, a retention policy, a restore test and a reboot test.',
  brief: `The internal wiki moved to a new server, **wiki01** (${WIKI01_IP}), last week, and nobody set up its backups. Every other server already backs up to **bak01** (${BAK01_IP}) at night (change CHG-2541): restic over SFTP as the user **restic**, one encrypted repository per server under **${REPO_ROOT}**. Do the same for wiki01:

- A **dedicated SSH key** for root on wiki01 that bak01 accepts for the user restic **only from wiki01's address**. Verify bak01's host key before you trust it (ED25519 fingerprint **${hostKeyPair('bak01', 'ed25519').fingerprint}**).
- A **repository** at **${REPO}**, its password (use **${WIKI_REPO_PASSWORD}**) in **/etc/restic/password** readable by root only, and the settings in **/etc/restic/env**.
- **What to back up:** /etc and the wiki data in /srv/wiki.
- **When:** every night, via **restic-backup.service** and **restic-backup.timer**; a night missed while wiki01 was off must be caught up.
- **Retention:** at least a week of daily snapshots, and old data actually freed.
- **Proof:** a restore test into /tmp/restore-test.

Everything must keep working after every machine restarts.`,
  objectives: [
    'Create a dedicated SSH key for an unattended job and restrict it on the server (authorized_keys from=, restrict).',
    'Verify a server\'s host key fingerprint before trusting it.',
    'Initialise an encrypted restic repository over SFTP and keep its password safe.',
    'Run a backup and read restic\'s summary (new, changed, unmodified, added).',
    'Schedule a job with a systemd service and timer (OnCalendar=, Persistent=, EnvironmentFile=).',
    'Apply a retention policy (forget --keep-… --prune) and understand what it keeps.',
    'Prove a backup by restoring it somewhere safe and comparing.',
  ],
  prerequisites: [
    { label: 'SSH', link: 'lesson/ssh/what' },
    { label: 'Linux service administration', link: 'lesson/systemd/what' },
    { label: 'Backup services', link: 'lesson/backup/what' },
  ],
  setupNote: `This lab adds **wiki01** (${WIKI01_IP}) on sw01 port swp19 (VLAN 20; wiki01.corp.lab is in DNS). **bak01** is the backup server of the lab (restic repositories of srv01, db01 and fs01 are already there).`,
  terminals: [
    { hostId: 'wiki01', user: 'root', label: 'wiki01 console (root)', banner: 'wiki01 console, logged in as root. The wiki data is in /srv/wiki. No backups yet. Try: ls -lR /srv/wiki, systemctl list-timers.' },
    { hostId: 'bak01', user: 'root', label: 'bak01 (backup server)', banner: 'bak01: the backup server. Repositories in /srv/backup/restic; clients log in as restic (keys in /home/restic/.ssh/authorized_keys).' },
  ],
  build: buildLab8World,
  steps: [
    {
      id: 'key', title: 'A key for the backup job',
      objective: 'Create an SSH key pair for root on wiki01 (no passphrase: the job runs unattended).',
      background: 'The nightly job logs in to bak01 without anyone at the keyboard, so it uses an **SSH key** instead of a password. A key without a passphrase is only as safe as the file it is in: it must be readable by root only (ssh refuses private keys others can read), and on the server it must be limited to what the job needs (next step).\n\nUse a **separate key per purpose**: if this key leaks, you remove one line on bak01 and nothing else breaks.',
      tasks: [
        'Generate it: `ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519 -C "root@wiki01 (restic backups)"`.',
        'Look at the result: `ls -l /root/.ssh` (the private key is 600) and `cat /root/.ssh/id_ed25519.pub`.',
      ],
      hints: ['-N "" sets an empty passphrase; -f chooses the file; -C is only a comment.', 'id_ed25519 is one of the files ssh (and restic\'s sftp) try by default, so no ssh configuration is needed.'],
      checks: [keyMade],
      solution: [{ host: 'wiki01', user: 'root', commands: ['mkdir -p /root/.ssh', 'chmod 700 /root/.ssh', printfTo(clientKey('wiki01').privateFile, NEW_KEY_PATH), `chmod 600 ${NEW_KEY_PATH}`, printfTo(clientKey('wiki01').publicLine + '\n', `${NEW_KEY_PATH}.pub`)] }],
      learn: [{ label: 'SSH keys', link: 'lesson/ssh/internals' }],
      concepts: ['bk.transport', 'ssh.authorized-keys'],
    },
    {
      id: 'access', title: 'Let wiki01 in on bak01, and trust bak01',
      objective: `Add wiki01's public key to /home/restic/.ssh/authorized_keys on bak01 with \`restrict,from="${WIKI01_IP}"\`, and add bak01's verified host key to /root/.ssh/known_hosts on wiki01.`,
      background: 'Options in front of a key in **authorized_keys** limit what it can do: **from="ADDRESS"** accepts it only from that client (a stolen key is useless elsewhere), and **restrict** turns off port forwarding, agent forwarding and terminals. The other backup clients\' lines on bak01 look the same.\n\nThe other direction matters too: the backup job must not send data to whoever claims to be bak01. Before adding a host key to known_hosts, **compare its fingerprint** with one obtained independently (here: from the brief). `ssh-keyscan` fetches the key; `ssh-keygen -lf` shows its fingerprint.',
      tasks: [
        'On wiki01: `cat /root/.ssh/id_ed25519.pub`. On bak01, append that line to /home/restic/.ssh/authorized_keys with the options in front: `restrict,from="10.0.20.47" ssh-ed25519 AAAA… root@wiki01 (restic backups)` (keep the file 600, owner restic).',
        'On wiki01: `ssh-keyscan -t ed25519 bak01.corp.lab > /tmp/bak01.key`, `ssh-keygen -lf /tmp/bak01.key` (compare with the brief), then `cat /tmp/bak01.key >> /root/.ssh/known_hosts`.',
        'Test without any prompt: `ssh -o BatchMode=yes restic@bak01.corp.lab true` exits 0.',
      ],
      hints: ['Copy the public key by hand (select, paste into an editor on bak01: `nano /home/restic/.ssh/authorized_keys`), or from wiki01 with ssh-copy-id restic@bak01.corp.lab (password ' + 'Restic-bak01-26) and add the options afterwards.', 'Permission denied (publickey,password)? Look at bak01: journalctl -u ssh. "not from a permitted host" means the from= address is wrong.'],
      checks: [accessGranted],
      solution: [
        { host: 'bak01', user: 'root', commands: [printfTo(`restrict,from="${WIKI01_IP}" ${clientKey('wiki01').publicLine}\n`, '/home/restic/.ssh/authorized_keys', true)] },
        { host: 'wiki01', user: 'root', commands: ['ssh-keyscan -t ed25519 bak01.corp.lab > /tmp/bak01.key', 'ssh-keygen -lf /tmp/bak01.key', 'cat /tmp/bak01.key >> /root/.ssh/known_hosts'] },
      ],
      learn: [{ label: 'authorized_keys options', link: 'reference?id=file:authorized_keys' }, { label: 'Host keys', link: 'lesson/ssh/internals' }],
      concepts: ['bk.transport', 'ssh.hostkeys'],
    },
    {
      id: 'repo', title: 'An encrypted repository on bak01',
      objective: `Write /etc/restic/password (root only) and /etc/restic/env, then initialise the repository ${REPO}.`,
      background: 'restic **encrypts** everything it stores with a key derived from the repository password: bak01 (and anyone who steals its disk) sees only ciphertext. The flip side: **without the password, the backups are gone**. Keep it in a root-only file on the client and in the password safe.\n\nrestic reads its settings from the environment: **RESTIC_REPOSITORY** (where) and **RESTIC_PASSWORD_FILE** (the password\'s file, not the password itself). Keeping them in /etc/restic/env lets the systemd unit (EnvironmentFile=) and an administrator (`set -a; . /etc/restic/env; set +a`) use the same settings.',
      tasks: [
        `\`mkdir -p /etc/restic\`, \`printf '${WIKI_REPO_PASSWORD}\\n' > /etc/restic/password\`, \`chmod 600 /etc/restic/password\`.`,
        `Create /etc/restic/env with two lines: \`RESTIC_REPOSITORY=${REPO}\` and \`RESTIC_PASSWORD_FILE=/etc/restic/password\`.`,
        `Load it and initialise: \`${ENV}\`, then \`restic init\`.`,
        'Look at what restic created on bak01: `ls -l /srv/backup/restic/wiki01` (config, data, index, keys, locks, snapshots; owner restic).',
      ],
      hints: ['set -a exports every variable assigned while it is on, so restic (a child process) sees them.', 'Fatal: unable to open repository … Permission denied (publickey,password): step 2 is not complete.'],
      checks: [repoReady],
      solution: [{ host: 'wiki01', user: 'root', commands: ['mkdir -p /etc/restic', 'chmod 700 /etc/restic', `printf '${WIKI_REPO_PASSWORD}\\n' > /etc/restic/password`, 'chmod 600 /etc/restic/password', printfTo(`RESTIC_REPOSITORY=${REPO}\nRESTIC_PASSWORD_FILE=/etc/restic/password\n`, '/etc/restic/env'), 'chmod 600 /etc/restic/env', `${ENV}; restic init`] }],
      learn: [{ label: 'How restic stores data', link: 'lesson/backup/internals' }, { label: 'restic', link: 'reference?id=restic' }],
      concepts: ['bk.operate'],
    },
    {
      id: 'first-backup', title: 'The first backup',
      objective: 'Back up /etc and /srv/wiki and look at the snapshot.',
      background: 'restic splits files into chunks and stores each chunk **once** (deduplication): the first backup stores everything, the following ones only what changed, yet every **snapshot** is a complete picture of the files at that moment. The summary shows new, changed and unmodified files and how much data was added.\n\nRun backups as **root**: the wiki\'s files belong to the user wiki with mode 640, and a backup that cannot read a file only warns (exit code 3) and leaves it out.',
      tasks: [
        `\`${ENV}; restic backup --tag nightly /etc /srv/wiki\` and read the summary.`,
        '`restic snapshots`, then `restic ls latest /srv/wiki`.',
        'Run the backup a second time: nothing new is added, but a second snapshot exists.',
      ],
      hints: ['"Warning: at least one source file could not be read" (exit code 3) means a permission problem: as root this does not happen.'],
      checks: [firstBackup],
      solution: [{ host: 'wiki01', user: 'root', commands: [`${ENV}; restic backup --tag nightly /etc /srv/wiki`] }],
      learn: [{ label: 'Snapshots and deduplication', link: 'lesson/backup/internals' }],
      concepts: ['bk.operate'],
    },
    {
      id: 'schedule', title: 'Every night, automatically',
      objective: 'Create /usr/local/sbin/restic-backup, restic-backup.service (oneshot, EnvironmentFile=/etc/restic/env) and restic-backup.timer (nightly, Persistent=true), then enable the timer.',
      background: 'A **systemd timer** starts a service on a schedule. The **service** (Type=oneshot) says what to run and with which environment; the **timer** says when (**OnCalendar=**, tested with `systemd-analyze calendar`) and, with **Persistent=true**, runs a missed job as soon as the machine is up again. Unlike cron, every run is logged under the unit (`journalctl -u restic-backup`), its result is visible in `systemctl status`, and a failure shows in `systemctl --failed` where monitoring can see it.\n\nAfter creating or editing unit files run **systemctl daemon-reload**; the timer is **enabled** (started at boot, through timers.target) and **started** now with `systemctl enable --now`.',
      tasks: [
        'The script /usr/local/sbin/restic-backup (mode 755): `#!/bin/sh`, `set -e`, `restic backup --tag nightly /etc /srv/wiki` (the retention line comes in the next step).',
        '/etc/systemd/system/restic-backup.service: [Service] Type=oneshot, EnvironmentFile=/etc/restic/env, ExecStart=/usr/local/sbin/restic-backup.',
        '/etc/systemd/system/restic-backup.timer: [Timer] OnCalendar=*-*-* 03:15:00, Persistent=true; [Install] WantedBy=timers.target.',
        '`systemctl daemon-reload`, `systemctl enable --now restic-backup.timer`, `systemctl list-timers`, then a test run: `systemctl start restic-backup.service` and `journalctl -u restic-backup -n 20`.',
      ],
      hints: ['"The unit files have no installation config" when enabling: the [Install] section with WantedBy=timers.target is missing from the timer.', 'Result: resources in systemctl status means systemd could not start the command at all (for example a missing EnvironmentFile).'],
      checks: [scheduled],
      solution: [{ host: 'wiki01', user: 'root', commands: [printfTo(SCRIPT.replace(/restic forget.*\n/, ''), '/usr/local/sbin/restic-backup'), 'chmod 755 /usr/local/sbin/restic-backup', printfTo(SERVICE, '/etc/systemd/system/restic-backup.service'), printfTo(TIMER, '/etc/systemd/system/restic-backup.timer'), 'systemctl daemon-reload', 'systemctl enable --now restic-backup.timer', 'systemctl start restic-backup.service'] }],
      learn: [{ label: 'Scheduling with systemd timers', link: 'lesson/backup/internals' }, { label: 'systemd timers', link: 'reference?id=file:systemd-timer' }],
      concepts: ['bk.schedule'],
    },
    {
      id: 'retention', title: 'A retention policy',
      objective: 'Make every run apply a retention policy: `restic forget --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune` (at least 7 daily, and --prune).',
      background: 'Without retention, snapshots accumulate until the backup disk is full. **restic forget** applies a policy: keep the newest snapshot of each of the last N days, weeks, months…; everything else is removed from the list. **--prune** then deletes the data no snapshot references any more, which is what frees space.\n\nA common policy is 7 daily, 4 weekly and 6 monthly snapshots: you can go back to any of the last seven days, any of the last four weeks, and roughly half a year. `--dry-run` shows what a policy would remove before you apply it.',
      tasks: [
        'Try the policy first: `restic forget --tag nightly --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --dry-run`.',
        'Add it to /usr/local/sbin/restic-backup after the backup line, with --prune.',
        'Run the job: `systemctl start restic-backup.service`, then `journalctl -u restic-backup -n 30`.',
      ],
      hints: ['"keep N snapshots" and the reasons column explain which rule keeps each snapshot.', 'forget without --prune only shortens the list; the space comes back with prune.'],
      checks: [retention],
      solution: [{ host: 'wiki01', user: 'root', commands: [printfTo(SCRIPT, '/usr/local/sbin/restic-backup'), 'systemctl start restic-backup.service'] }],
      learn: [{ label: 'Retention', link: 'lesson/backup/operate' }],
      concepts: ['bk.operate'],
    },
    {
      id: 'restore', title: 'Prove it: a restore test',
      objective: 'Restore the wiki from the latest snapshot into /tmp/restore-test and compare it with the server.',
      background: 'A backup is only proven by a **restore**. Restore into a separate directory (never over live data during a test), then compare: contents (diff, sha256sum), owners and modes (ls -l). restic restores owners and modes when it runs as root.\n\nIn a real incident you would then copy back only what was lost (`cp -a`), so newer work is not overwritten.',
      tasks: [
        `\`${ENV}; restic restore latest --target /tmp/restore-test --include /srv/wiki\`.`,
        'Compare: `ls -l /tmp/restore-test/srv/wiki/pages` and `/srv/wiki/pages`; `sha256sum /srv/wiki/pages/home.md /tmp/restore-test/srv/wiki/pages/home.md`.',
      ],
      hints: ['restic restores paths below the target as they were: /srv/wiki ends up in /tmp/restore-test/srv/wiki.'],
      checks: [restoreTested],
      solution: [{ host: 'wiki01', user: 'root', commands: [`${ENV}; restic restore latest --target /tmp/restore-test --include /srv/wiki`] }],
      learn: [{ label: 'Restores', link: 'lesson/backup/operate' }],
      concepts: ['bk.restore'],
    },
    {
      id: 'reboot', title: 'Reboot test',
      objective: 'Every check of the earlier steps still passes after all machines restart.',
      background: 'An enabled timer is started again at boot by timers.target, and Persistent=true catches up a run missed while the machine was down. Keys, known_hosts and the repository are files and survive; a timer that was only started (not enabled) would not.',
      tasks: ['Run the check: it reboots every host on a copy of the lab and runs all checks again.'],
      hints: ['A failing schedule check after the reboot usually means the timer was started but not enabled.'],
      checks: [],
      solution: [],
      learn: [{ label: 'Scheduling with systemd timers', link: 'lesson/backup/internals' }],
      concepts: ['bk.schedule'],
      afterReboot: true,
    },
  ],
};
