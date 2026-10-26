// Lab 5: Enterprise Infrastructure. A new application server, app01, was
// provisioned from the standard template (address, switch port, packages) and
// now has to become a proper member of corp.lab: a DNS name, synchronized time,
// central logs, shared storage over NFS that finance reads over SMB,
// publication through the reverse proxy, a default-deny firewall, and a reboot
// test. Each step uses a service from the earlier lessons and has to keep the
// others working.

import { mkdir, readFile, writeFile } from '../fs';
import { addUser, createHost, staticInterfaces } from '../lab/builder';
import { FORWARD_CONF, installRsyslog } from '../lab/logLab';
import { FS01_SMB_PASSWORDS } from '../lab/nfsLab';
import { trustCorpRoot } from '../lab/pkiLab';
import { buildSshLab, CORP_ZONE, DEBIAN_SSHD_CONFIG, installHostKeys, SW01_INTERFACES } from '../lab/sshLab';
import { checkGoal, firewallStillRestrictive, script } from '../scenarios/engine';
import { proxiedNginxConf, deployProxy } from '../scenarios/proxyScenarios';
import { parseExports, type NfsServerLoaded } from '../sim/nfs';
import { findShare, loadSmbConf, shareReadOnly } from '../sim/smb';
import { recomputeL2 } from '../sim/l2';
import { hostAddresses } from '../sim/network';
import { bootHost } from '../sim/services';
import type { World } from '../types';
import { lastLines as last, NO, OK, printfTo, probe } from './engine';
import type { GuidedLab, LabCheck } from './types';


export const APP01_IP = '10.0.20.70';
export const APP01_PASSWORD = 'app01-alice';
export const REPORTS_UID = 1500;
const DANA = FS01_SMB_PASSWORDS.dana;
const ALICE_SMB = FS01_SMB_PASSWORDS.alice;

/** Debian's default timesyncd.conf: no NTP= line, only the public pool as fallback. */
const DEBIAN_TIMESYNCD = `#  This file is part of systemd.
#
# Entries in this file show the compile time defaults. Local configuration
# should be created by either modifying this file (or a copy of it placed in
# /etc/ if the original file is shipped in /usr/), or by creating "drop-ins" in
# the /etc/systemd/timesyncd.conf.d/ directory.
#
# See timesyncd.conf(5) for details.

[Time]
#NTP=
#FallbackNTP=0.debian.pool.ntp.org 1.debian.pool.ntp.org 2.debian.pool.ntp.org 3.debian.pool.ntp.org
#RootDistanceMaxSec=5
#PollIntervalMinSec=32
#PollIntervalMaxSec=2048
`;

const APP01_NGINX_CONF = `user www-data;
worker_processes auto;
http {
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        root /var/www/html;
    }
}
`;

const REPORTS_INDEX = '<!doctype html>\n<title>Finance reports</title>\n<h1>Finance reports</h1>\n<p>Q3 2026 ledger summaries are generated nightly into /mnt/reports.</p>\n';

/** The finished pieces, also used by the reference solution. */
export const LAB5_ZONE = CORP_ZONE.replace('2026101901 ; serial', '2026101902 ; serial').replace('fs01    IN A    10.0.20.60\n', `fs01    IN A    10.0.20.60\napp01   IN A    ${APP01_IP}\n`);
export const LAB5_TIMESYNCD = '[Time]\nNTP=rtr01.corp.lab\n';
export const LAB5_EXPORT = `/srv/reports   ${APP01_IP}(rw,sync,no_subtree_check)`;
export const LAB5_FSTAB = 'fs01.corp.lab:/srv/reports /mnt/reports nfs4 defaults,_netdev 0 0';
export const LAB5_SHARE = '\n[reports]\n   comment = Finance reports (read-only)\n   path = /srv/reports\n   valid users = @finance\n   read only = yes\n';
export const LAB5_PROXY_LOCATION = `        location /reports/ {
            proxy_pass http://app01.corp.lab/;
            proxy_set_header Host $host;
        }
`;
export const LAB5_NFT = `#!/usr/sbin/nft -f
# app01 host firewall (CHG-2330): SSH from the internal networks, HTTP only
# from the reverse proxy srv01.

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		ct state invalid drop
		iif "lo" accept
		meta l4proto icmp accept
		meta l4proto ipv6-icmp accept
		ip saddr 10.0.0.0/16 tcp dport 22 accept
		ip saddr 10.0.20.10 tcp dport 80 accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

export function buildLab5World(): World {
  const world = buildSshLab();
  // The reverse proxy as it runs today: apps.corp.lab/inventory/ on srv01 (CHG-2230).
  deployProxy(world);
  const t = world.clock;

  // The switch port was patched and configured by the network team (access VLAN 20).
  const sw = world.hosts.sw01;
  sw.ifaces.push({ name: 'swp14', mac: '52:54:00:5e:00:0e', segment: null, address: null, prefix: null, up: false, staticSegment: null, addrs6: [] });
  writeFile(sw, '/etc/network/interfaces', SW01_INTERFACES
    .replace('auto br0\n', 'auto swp14\niface swp14\n    alias app01 (finance reports)\n    bridge-access 20\n\nauto br0\n')
    .replace('swp11 swp12 swp13\n', 'swp11 swp12 swp13 swp14\n'), t);
  world.links = [...(world.links ?? []), { a: { host: 'app01', iface: 'eth0' }, b: { host: 'sw01', iface: 'swp14' } }];

  // app01 as the platform team delivered it: the standard template, not integrated yet.
  const h = createHost(world, {
    id: 'app01', hostname: 'app01', domain: 'corp.lab', role: 'Finance reports server (new, to integrate in Lab 5)',
    ifaces: [{ name: 'eth0', mac: '52:54:00:a9:00:46', segment: null }],
    services: ['rsyslog', 'systemd-timesyncd', 'nftables', 'ssh', 'nginx'],
  });
  h.services.nftables.enabled = false;
  writeFile(h, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: `${APP01_IP}/24`, gateway: '10.0.20.1' }]), t);
  writeFile(h, '/etc/resolv.conf', 'search corp.lab\nnameserver 10.0.10.53\n', t);
  writeFile(h, '/etc/ssh/sshd_config', DEBIAN_SSHD_CONFIG, t);
  mkdir(h, '/etc/systemd', t);
  writeFile(h, '/etc/systemd/timesyncd.conf', DEBIAN_TIMESYNCD, t);
  installHostKeys(h, t);
  trustCorpRoot(h, t);
  installRsyslog(h, t, false);
  mkdir(h, '/etc/nginx', t);
  writeFile(h, '/etc/nginx/nginx.conf', APP01_NGINX_CONF, t);
  if (!h.fs['/var/www']) mkdir(h, '/var/www', t);
  if (!h.fs['/var/www/html']) mkdir(h, '/var/www/html', t);
  writeFile(h, '/var/www/html/index.html', REPORTS_INDEX, t);
  writeFile(h, '/etc/nftables.conf', '#!/usr/sbin/nft -f\n\nflush ruleset\n\ntable inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter;\n\t}\n\tchain forward {\n\t\ttype filter hook forward priority filter;\n\t}\n\tchain output {\n\t\ttype filter hook output priority filter;\n\t}\n}\n', t, { mode: 0o755 });
  addUser(h, { name: 'alice', uid: 1000, gid: 1000, primaryGroup: 'alice', groups: ['sudo'], home: '/home/alice', shell: '/bin/bash', gecos: 'Alice Admin', password: APP01_PASSWORD }, t);
  // The reporting application's service account (from its package).
  addUser(h, { name: 'reports', uid: REPORTS_UID, gid: REPORTS_UID, primaryGroup: 'reports', groups: [], home: '/var/lib/reports', shell: '/usr/sbin/nologin', gecos: 'Finance reports generator', password: null }, t);
  // A fresh VM's clock is a few minutes off until NTP disciplines it.
  h.clockOffset = 7 * 60_000;

  recomputeL2(world);
  script(world, 'sw01', ['ifreload -a']);
  // script() replaces the host objects with the shell's copies: boot the current one.
  bootHost(world, world.hosts.app01);
  world.clock += 5 * 60_000;
  return world;
}


// ---------------------------------------------------------------- checks

const named: LabCheck = {
  id: 'dns-name', description: 'app01.corp.lab resolves to 10.0.20.70 for the clients (ws01) and for the proxy (srv01)',
  check(w) {
    for (const host of ['ws01', 'srv01']) {
      const r = checkGoal(w, { kind: 'resolve', description: '', fromHost: host, name: 'app01.corp.lab', expect: APP01_IP });
      if (!r.ok) return NO(`${host}: ${last(r)}`);
    }
    return OK(`app01.corp.lab → ${APP01_IP} on ws01 and srv01.`);
  },
};

const zoneValid: LabCheck = {
  id: 'zone-serial', description: 'The corp.lab zone on ns1 still loads every other record (ns1, fs01, log01 resolve) and its serial was increased',
  check(w) {
    const zone = readFile(w.hosts.ns1, '/etc/bind/db.corp.lab') ?? '';
    const serial = Number(/(\d{10})\s*;\s*serial/.exec(zone)?.[1] ?? 0);
    if (serial <= 2026101901) return NO(`The serial is ${serial || 'missing'}: increase it with every change, or secondaries never transfer the new zone.`);
    for (const [name, ip] of [['fs01.corp.lab', '10.0.20.60'], ['log01.corp.lab', '10.0.20.50']]) {
      const r = checkGoal(w, { kind: 'resolve', description: '', fromHost: 'ws01', name, expect: ip });
      if (!r.ok) return NO(`${name} no longer resolves: ${last(r)}`);
    }
    return OK(`serial ${serial}; the existing records still resolve.`);
  },
};

const timeOk: LabCheck = {
  id: 'time', description: 'app01\'s clock is synchronized by NTP (from rtr01) and correct to within a second',
  check(w) {
    const r = checkGoal(w, { kind: 'time', description: '', host: 'app01' });
    if (!r.ok) return NO(r.lines.filter((l) => /synchronized|this clock is/.test(l)).join(' ') || 'not synchronized');
    // Any of rtr01's addresses counts (10.0.20.1 is app01's gateway); nothing else does.
    const status = probe(w, 'app01', 'root', 'timedatectl timesync-status');
    const server = /^\s*Server:\s*(\S+)/m.exec(status.output)?.[1];
    if (!server || server === 'null') return NO(`timedatectl timesync-status shows no server: ${status.output.trim().split('\n')[0] ?? ''}`);
    const rtr = [...hostAddresses(w.hosts.rtr01, 4), ...hostAddresses(w.hosts.rtr01, 6)];
    return rtr.includes(server) ? OK(`System clock synchronized: yes (server ${server}, rtr01).`) : NO(`Synchronized from ${server}, not from rtr01: use the internal time source.`);
  },
};

const logsOk: LabCheck = {
  id: 'logs', description: 'A message logged on app01 (also authpriv) arrives on log01 under /var/log/remote/app01/',
  check(w) {
    for (const priority of [undefined, 'authpriv.notice']) {
      const r = checkGoal(w, { kind: 'syslog', description: '', fromHost: 'app01', priority, server: 'log01', path: '/var/log/remote/app01/%PROGRAMNAME%.log' });
      if (!r.ok) return NO(`${priority ?? 'user.notice'}: ${last(r)}`);
    }
    return OK('logger on app01 → log01:/var/log/remote/app01/labcheck.log (user and authpriv).');
  },
};

const nfsOk: LabCheck = {
  id: 'nfs', description: 'The account reports on app01 writes to /mnt/reports, and the file belongs to reports on fs01',
  check(w) {
    const mounted = probe(w, 'app01', 'root', 'mount -t nfs4').output;
    if (!/fs01(\.corp\.lab)?:\/srv\/reports on \/mnt\/reports/.test(mounted)) return NO('/mnt/reports is not an NFS mount of fs01:/srv/reports.');
    const r = checkGoal(w, { kind: 'command', description: '', steps: [{ host: 'app01', user: 'reports', command: 'touch /mnt/reports/lab5-check.txt' }, { host: 'fs01', user: 'root', command: 'ls -l /srv/reports/lab5-check.txt' }], expect: '^\\S+ \\d+ reports ' });
    return r.ok ? OK('reports@app01 writes; fs01 shows owner reports.') : NO(last(r));
  },
};

const exportNarrow: LabCheck = {
  id: 'nfs-export', description: 'fs01 exports /srv/reports to app01 only, with root squashed, and /etc/fstab on app01 mounts it at boot',
  check(w) {
    const l = w.hosts.fs01.services['nfs-kernel-server']?.loaded as NfsServerLoaded | undefined;
    const ex = l?.exports.find((e) => e.path === '/srv/reports');
    if (!ex) return NO('exportfs -v on fs01 has no /srv/reports (edit /etc/exports, then exportfs -ra).');
    const wide = ex.clients.filter((c) => c.spec !== APP01_IP && !/^app01(\.corp\.lab)?$/.test(c.spec));
    if (wide.length) return NO(`/srv/reports is also exported to ${wide.map((c) => c.spec).join(', ')}: only app01 writes reports.`);
    if (ex.clients.some((c) => c.options.squash === 'none')) return NO('no_root_squash: app01\'s root would own the share.');
    const fileOk = parseExports(readFile(w.hosts.fs01, '/etc/exports') ?? '').exports.some((e) => e.path === '/srv/reports');
    if (!fileOk) return NO('The export is loaded but not in /etc/exports: it disappears at the next restart.');
    if (!/^\S+:\/srv\/reports\s+\/mnt\/reports\s+nfs4?\s/m.test(readFile(w.hosts.app01, '/etc/fstab') ?? '')) return NO('No /etc/fstab line on app01 for /mnt/reports: the mount will not come back after a reboot.');
    return OK(`/srv/reports → ${ex.clients.map((c) => c.spec).join(', ')} (root_squash); fstab entry present.`);
  },
};

const smbOk: LabCheck = {
  id: 'smb', description: 'dana (finance) maps \\\\fs01\\reports on win01 and keeps [office]; the share is read-only; alice (not in finance) is refused',
  check(w) {
    const s = findShare(loadSmbConf(w.hosts.fs01), 'reports');
    if (!s) return NO('No [reports] share in /etc/samba/smb.conf.');
    if (!shareReadOnly(s)) return NO('[reports] is writable: finance only reads the reports.');
    const map = probe(w, 'win01', 'Administrator', `net use R: \\\\fs01\\reports /user:dana ${DANA}`);
    if (!/completed successfully/.test(map.output)) return NO(`win01: ${map.output.trim().split('\n').filter(Boolean).slice(-1)[0]}`);
    const alice = probe(w, 'ws01', 'alice', `smbclient //fs01/reports -U alice%${ALICE_SMB} -c ls`);
    if (alice.code === 0) return NO('alice (not in finance) can open the share: restrict it with valid users = @finance.');
    const office = probe(w, 'ws01', 'alice', `smbclient //fs01/office -U dana%${DANA} -c ls`);
    if (office.code !== 0) return NO(`dana lost [office] (${office.output.trim()}): add finance with usermod -aG, which keeps her other groups.`);
    return OK('dana maps R: and still opens [office]; alice gets NT_STATUS_ACCESS_DENIED; read only.');
  },
};

const proxied: LabCheck = {
  id: 'proxy', description: 'From ws01, http://apps.corp.lab/reports/ shows the Finance reports page through srv01, and /inventory/ still works',
  check(w) {
    const r = probe(w, 'ws01', 'alice', 'curl -sS http://apps.corp.lab/reports/');
    if (!/Finance reports/.test(r.output)) return NO(`curl http://apps.corp.lab/reports/: ${r.output.trim().split('\n').slice(0, 2).join(' ') || `exit ${r.code}`}`);
    const inv = checkGoal(w, { kind: 'http', description: '', fromHost: 'ws01', fromUser: 'alice', url: 'http://apps.corp.lab/inventory/health' });
    return inv.ok ? OK('/reports/ → app01; /inventory/ → dock01.') : NO(`/inventory/ broke: ${last(inv)}`);
  },
};

const firewalled: LabCheck = {
  id: 'app01-firewall', description: 'app01 has a persistent default-deny firewall: HTTP only from srv01 (ws01 cannot reach app01:80 directly), SSH from the internal networks',
  check(w) {
    const c = firewallStillRestrictive('app01').check(w);
    if (!c.ok) return NO(c.message);
    if (!w.hosts.app01.services.nftables?.enabled) return NO('nftables.service is not enabled: the rules vanish at the next boot (systemctl enable nftables).');
    const direct = probe(w, 'ws01', 'alice', `nc -zv -w 2 ${APP01_IP} 80`);
    if (direct.code === 0) return NO('ws01 connects to app01:80 directly: allow HTTP only from srv01 (10.0.20.10).');
    const ssh = probe(w, 'ws01', 'alice', `nc -zv -w 2 ${APP01_IP} 22`);
    return ssh.code === 0 ? OK('input policy drop; 80 only from srv01; SSH open internally.') : NO('ws01 cannot reach SSH on app01: keep tcp dport 22 for 10.0.0.0/16.');
  },
};

// ---------------------------------------------------------------- the lab

export const LAB5: GuidedLab = {
  id: 'lab5',
  title: 'Lab 5: Enterprise Infrastructure',
  level: 'advanced',
  duration: '90–120 min',
  summary: 'Integrate a new server into every enterprise service: a DNS record, NTP from the internal time source, central logging, shared storage over NFS (with matching UIDs) that finance reads over SMB, publication through the reverse proxy, a default-deny firewall that keeps all of it working, and a reboot test.',
  brief: `The finance department has a new reporting server, **app01** (${APP01_IP}, Debian 12). The platform team built it from the standard server template (change CHG-2330): it has its network address, it is connected to switch sw01 (port swp14, VLAN 20), nginx serves the reports page, and the application's service account **reports** (uid ${REPORTS_UID}) exists. Nothing else has been done.

Your job is to make app01 a full member of the corp.lab network, like every other server. The finance team needs the following:

- **A name.** Everyone should reach it as **app01.corp.lab**.
- **Correct time**, from the internal time server rtr01. Kerberos logons and the ability to line up logs from different servers both depend on it.
- **Central logs.** Its log messages must also arrive on the log server, **log01**.
- **Shared storage.** A directory **/srv/reports** on the file server **fs01**, mounted on app01 at **/mnt/reports** over NFS so that the reports account can write there.
- **Access for finance staff.** The same directory, shared read-only over SMB as **\\\\fs01\\reports** to the **finance** group. dana is in finance; her Samba password is ${DANA}.
- **Publication.** The reports page must be reachable as **http://apps.corp.lab/reports/**, through the existing reverse proxy on srv01.
- **Protection.** A firewall on app01 that lets web traffic in **only from srv01** (the proxy).

Everything must still work after every machine restarts. Each step below tells you what to achieve and why; hints and a reference solution are there if you get stuck.`,
  objectives: [
    'Add a host to an authoritative zone safely: increase the serial, check, reload, test from the clients.',
    'Point a client at the internal NTP server and verify synchronization, not just the configuration.',
    'Forward a host\'s logs to the central log server and prove it end to end, including the authentication facility.',
    'Share storage between Linux hosts over NFS with a narrow export, root squashing and a UID that matches on both sides.',
    'Offer the same data to Windows users over SMB, read-only, to one group.',
    'Publish an internal application through an existing reverse proxy without breaking what it already serves.',
    'Write a default-deny host firewall that keeps every one of these paths working.',
  ],
  prerequisites: [
    { label: 'TCP, UDP and DNS', link: 'lesson/transport/what' },
    { label: 'Time synchronisation (NTP)', link: 'lesson/ntp/what' },
    { label: 'Central logging', link: 'lesson/logging/what' },
    { label: 'File sharing (NFS)', link: 'lesson/nfs/what' },
    { label: 'File sharing (SMB)', link: 'lesson/smb/what' },
    { label: 'Web servers and reverse proxies', link: 'lesson/webproxy/what' },
  ],
  setupNote: `This lab adds **app01** (${APP01_IP}) on sw01 port swp14 (VLAN 20, configured). It touches **ns1** (DNS), **fs01** (NFS and Samba), **srv01** (reverse proxy) and is tested from **ws01** and **win01**. The reverse proxy already publishes the inventory application at http://apps.corp.lab/inventory/.`,
  terminals: [
    { hostId: 'app01', user: 'root', label: 'app01 console (root)', banner: 'app01 console (hypervisor), logged in as root. Debian 12 from the standard template (CHG-2330). Try: ip -br addr, timedatectl, cat /etc/systemd/timesyncd.conf, id reports.' },
    { hostId: 'ns1', user: 'root', label: 'ns1 console (root)', banner: 'ns1: BIND for corp.lab (/etc/bind/db.corp.lab). Check with named-checkzone corp.lab /etc/bind/db.corp.lab, apply with rndc reload.' },
    { hostId: 'fs01', user: 'root', label: 'fs01 console (root)', banner: 'fs01: NFS (/etc/exports, exportfs) and Samba (/etc/samba/smb.conf, testparm, smbpasswd).' },
    { hostId: 'srv01', user: 'root', label: 'srv01 console (root)', banner: 'srv01: the reverse proxy (nginx 1.22). apps.corp.lab is in /etc/nginx/nginx.conf. Check with nginx -t, apply with systemctl reload nginx.' },
    { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01: the office. Try: getent hosts app01.corp.lab, curl -sS http://apps.corp.lab/reports/.' },
    { hostId: 'win01', user: 'Administrator', label: 'win01 (Administrator)', banner: `win01: finance's view. Try: net use R: \\\\fs01\\reports /user:dana ${DANA}.` },
  ],
  build: buildLab5World,
  steps: [
    {
      id: 'dns', title: 'Give app01 its name',
      objective: `Add **app01.corp.lab → ${APP01_IP}** to the corp.lab zone on ns1, without breaking the rest of the zone.`,
      background: 'Every later step refers to app01 by name: the mount on app01 names fs01, the proxy names app01, and log01 files messages by host name. So the name comes first.\n\nThe zone file on ns1 is the single source of truth for corp.lab names, but BIND only uses a changed file after `rndc reload`. Other DNS servers (secondaries) and caches only notice a change when the zone\'s **serial number** goes up, so always increase it. One syntax error makes BIND refuse the **whole** zone, which would break every corp.lab name at once, so check the file with `named-checkzone` before reloading.',
      tasks: [
        `On ns1, edit /etc/bind/db.corp.lab: add \`app01   IN A    ${APP01_IP}\` and increase the serial (2026101901 → 2026101902).`,
        '`named-checkzone corp.lab /etc/bind/db.corp.lab` (OK, with the new serial), then `rndc reload`.',
        'From ws01 and srv01: `getent hosts app01.corp.lab`.',
      ],
      hints: ['Forgot the serial? The record still works on ns1 itself, but nothing tells a secondary or a cache that the zone changed.', '`journalctl -u named -n 5` shows whether the reload loaded the zone.'],
      checks: [named, zoneValid],
      solution: [{ host: 'ns1', user: 'root', commands: [printfTo(LAB5_ZONE, '/etc/bind/db.corp.lab'), 'named-checkzone corp.lab /etc/bind/db.corp.lab', 'rndc reload'] }],
      learn: [{ label: 'DNS zones', link: 'lesson/transport/internals' }, { label: 'named-checkzone', link: 'reference?id=named-checkzone' }],
      concepts: ['dns.zone', 'dns.resolution'],
    },
    {
      id: 'time', title: 'Synchronize its clock',
      objective: 'Make app01 synchronize with **rtr01** (the internal time server) and verify that the clock is correct.',
      background: 'The template ships Debian\'s default timesyncd.conf: it names no time server (`NTP=` is empty) and only falls back to the public NTP pool, which the server network cannot reach. As a result, app01\'s clock is 7 minutes fast. That is enough to break Kerberos (which allows at most 300 seconds of difference) and to put app01\'s log lines in the wrong place on log01.\n\nsystemd-timesyncd, the small time client on Debian, reads its servers when it starts. `timedatectl` shows whether the clock is synchronized, and `timedatectl timesync-status` shows which server it uses. Check the result, not just the configuration file.',
      tasks: [
        'On app01: `timedatectl` (synchronized: no) and `cat /etc/systemd/timesyncd.conf`.',
        'Set `NTP=rtr01.corp.lab` in the [Time] section, then `systemctl restart systemd-timesyncd`.',
        '`timedatectl timesync-status`: Server 10.0.10.1 (rtr01.corp.lab), Leap normal; `timedatectl`: synchronized yes.',
      ],
      hints: ['rtr01 serves the server network (chronyc clients on rtr01 lists who asks).', 'A drift of minutes is stepped at the first synchronization.'],
      checks: [timeOk],
      solution: [{ host: 'app01', user: 'root', commands: [printfTo(LAB5_TIMESYNCD, '/etc/systemd/timesyncd.conf'), 'systemctl restart systemd-timesyncd'] }],
      learn: [{ label: 'NTP: clients', link: 'lesson/ntp/config' }],
      concepts: ['ntp.sync'],
    },
    {
      id: 'logs', title: 'Send its logs to log01',
      objective: 'Forward everything app01 logs to **log01** over TCP with a queue, the same way the other servers do.',
      background: 'The other servers already forward their logs with the file **/etc/rsyslog.d/50-central.conf** (change CHG-2270). It sends every message (`*.*`) to log01.corp.lab on port 514 over TCP, with a queue in memory (LinkedList), so that messages wait instead of being lost while log01 is unavailable. log01 files what it receives under /var/log/remote/HOST/PROGRAM.log.\n\nWhen you test, use the facility that matters most for security, **authpriv** (logins, sudo, sshd), not only a plain test message: some forwarding rules leave it out.',
      tasks: [
        'Copy the forwarding file from another server (e.g. `cat /etc/rsyslog.d/50-central.conf` on srv01) to app01.',
        '`rsyslogd -N1`, `systemctl restart rsyslog`.',
        '`logger -p authpriv.notice -t test "app01 test"` on app01, then on log01 `ls /var/log/remote/app01/`.',
      ],
      hints: ['@@ (or protocol="tcp") is TCP; one @ would be UDP, which log01 also accepts but loses silently.', 'Name, not address: log01 may move; the DNS record follows it.'],
      checks: [logsOk],
      solution: [{ host: 'app01', user: 'root', commands: [printfTo(FORWARD_CONF, '/etc/rsyslog.d/50-central.conf'), 'systemctl restart rsyslog'] }],
      learn: [{ label: 'Central logging: forwarding', link: 'lesson/logging/config' }],
      concepts: ['logs.central'],
    },
    {
      id: 'nfs', title: 'Shared storage for the reports (NFS)',
      objective: 'Create **/srv/reports** on fs01 owned by the **reports** account, export it to **app01 only**, and mount it on app01 at **/mnt/reports** from /etc/fstab, so that reports (uid 1500) can write there.',
      background: `NFS (with the default security, sec=sys) identifies users by **number**, not by name: files written by reports on app01 arrive as uid ${REPORTS_UID}. fs01 must have the same account with the **same uid** (\`useradd -u ${REPORTS_UID}\`), or the files belong to a number nobody owns. Export to the one client that writes (narrowest client list), keep root_squash, run \`exportfs -ra\`. On app01, a line in /etc/fstab (with \`_netdev\`) brings the mount back at boot; \`mount -a\` tests it now.`,
      tasks: [
        `On fs01: \`useradd -u ${REPORTS_UID} -s /usr/sbin/nologin reports\`, \`mkdir /srv/reports\`, \`chown reports:reports /srv/reports\`.`,
        `Add \`${LAB5_EXPORT}\` to /etc/exports, then \`exportfs -ra\` and \`exportfs -v\`.`,
        `On app01: \`mkdir -p /mnt/reports\`, add \`${LAB5_FSTAB}\` to /etc/fstab, \`mount -a\`, \`df -h /mnt/reports\`.`,
        'Test as the account: the check writes /mnt/reports/lab5-check.txt as reports and looks at its owner on fs01.',
      ],
      hints: ['"access denied by server": the export is not loaded (exportfs -ra) or names another client.', 'On fs01 `ls -ln /srv/reports` shows the numbers that travel over NFS.'],
      checks: [nfsOk, exportNarrow],
      solution: [
        { host: 'fs01', user: 'root', commands: [`useradd -u ${REPORTS_UID} -s /usr/sbin/nologin reports`, 'mkdir /srv/reports', 'chown reports:reports /srv/reports', `echo '${LAB5_EXPORT}' >> /etc/exports`, 'exportfs -ra'] },
        { host: 'app01', user: 'root', commands: ['mkdir -p /mnt/reports', `echo '${LAB5_FSTAB}' >> /etc/fstab`, 'mount -a'] },
      ],
      learn: [{ label: 'NFS: how it works', link: 'lesson/nfs/internals' }, { label: 'exportfs', link: 'reference?id=exportfs' }],
      concepts: ['files.nfs', 'linux.permissions'],
    },
    {
      id: 'smb', title: 'Finance reads the reports (SMB)',
      objective: 'Share **/srv/reports** over SMB as **\\\\fs01\\reports**: read-only, for the **finance** group, with **dana** in finance.',
      background: 'The same directory can be offered over both protocols at once: NFS for app01, SMB for the Windows desktops. Samba checks access in two stages: first the share\'s own settings (valid users, read only), then the Linux permissions of the account dana maps to. /srv/reports is rwxr-xr-x, so other users may read it.\n\nSamba shares are read-only by default, but write `read only = yes` explicitly anyway, so that nobody "fixes" it later. Samba reads a user\'s groups when they log on.',
      tasks: [
        `On fs01: \`usermod -aG finance dana\` (keep her other groups) and append to /etc/samba/smb.conf:\n\n\`\`\`${LAB5_SHARE}\`\`\``,
        '`testparm -s` (the [reports] section, no unknown parameters).',
        `On win01: \`net use R: \\\\fs01\\reports /user:dana ${DANA}\`; on ws01: \`smbclient //fs01/reports -U alice -c ls\` must be refused.`,
      ],
      hints: ['`usermod -G finance dana` without -a would remove her from staff and lock her out of [office].', 'smbd reads smb.conf again for new connections: no restart needed.'],
      checks: [smbOk],
      solution: [{ host: 'fs01', user: 'root', commands: ['usermod -aG finance dana', printfTo(LAB5_SHARE, '/etc/samba/smb.conf', true), 'testparm -s'] }],
      learn: [{ label: 'SMB: shares', link: 'lesson/smb/internals' }, { label: 'net use', link: 'reference?id=net-use' }],
      concepts: ['files.smb'],
    },
    {
      id: 'proxy', title: 'Publish it through the reverse proxy',
      objective: 'Add **/reports/** to the apps.corp.lab server block on srv01, proxied to **http://app01.corp.lab/**, without breaking **/inventory/**.',
      background: 'srv01\'s nginx already publishes the inventory API (`location /inventory/ { proxy_pass http://dock01.corp.lab:8000/; }`). A second location sends /reports/ to app01. With a URI on proxy_pass (`http://app01.corp.lab/`), nginx replaces the matched prefix: /reports/ becomes / on app01. nginx resolves upstream names when it loads its configuration: the DNS step must be done first, and `nginx -t` would say "host not found in upstream" otherwise.',
      tasks: [
        `On srv01, inside \`server { ... server_name apps.corp.lab; ...}\`, after the /inventory/ location:\n\n\`\`\`\n${LAB5_PROXY_LOCATION}\`\`\``,
        '`nginx -t`, then `systemctl reload nginx`.',
        'From ws01: `curl -sS http://apps.corp.lab/reports/` (the Finance reports page) and `curl -sS http://apps.corp.lab/inventory/health`.',
      ],
      hints: ['A 404 from app01 means the prefix was passed through: proxy_pass needs the trailing slash.', 'A failed `nginx -t` leaves the running configuration in place: fix and test again before reloading.'],
      checks: [proxied],
      solution: [{ host: 'srv01', user: 'root', commands: [printfTo(proxiedNginxConf().replace('            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        }\n', `            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        }\n${LAB5_PROXY_LOCATION}`), '/etc/nginx/nginx.conf'), 'nginx -t', 'systemctl reload nginx'] }],
      learn: [{ label: 'Reverse proxies', link: 'lesson/webproxy/internals' }],
      concepts: ['web.proxy'],
    },
    {
      id: 'firewall', title: 'Close app01 behind its proxy',
      objective: 'Give app01 a persistent default-deny firewall: HTTP **only from srv01**, SSH from the internal networks. Every earlier step must keep working.',
      background: 'With the proxy in front, nobody needs to reach app01\'s web server directly. Allowing port 80 only from srv01 forces everyone through the published path, where requests are logged.\n\nEverything app01 starts itself is **outgoing**: NTP to rtr01, syslog to log01, NFS to fs01, DNS to ns1. A default-deny input chain still has to let the **replies** back in; that is the job of the rule `ct state established,related accept`. Without it, every one of those services breaks.\n\nThe Debian template ships nftables **disabled**. Enable it, or your rules are gone after the next boot.',
      tasks: [
        `Write /etc/nftables.conf on app01:\n\n\`\`\`\n${LAB5_NFT}\`\`\``,
        '`systemctl enable --now nftables` and `nft list ruleset`.',
        'Re-run the checks of the earlier steps (they must all still pass), and from ws01 `nc -zv -w 2 10.0.20.70 80` (no connection).',
      ],
      hints: ['Forgot `ct state established,related accept`? NTP, DNS and NFS replies are then dropped: the time and storage checks fail.', '`systemctl is-enabled nftables` must say enabled.'],
      checks: [firewalled, proxied, timeOk, logsOk, nfsOk],
      solution: [{ host: 'app01', user: 'root', commands: [printfTo(LAB5_NFT, '/etc/nftables.conf'), 'systemctl enable --now nftables'] }],
      learn: [{ label: 'Host firewalls with nftables', link: 'lesson/nftables/internals' }],
      concepts: ['fw.path', 'fw.persistence'],
    },
    {
      id: 'reboot', title: 'Reboot test',
      objective: 'Restart every machine and confirm everything above still holds.',
      background: 'A restart rebuilds everything from the saved configuration: ns1 loads the zone from its file, fs01 exports what /etc/exports lists, app01 mounts what /etc/fstab lists (after the network is up, because of `_netdev`), timesyncd and rsyslog start with their files, nftables loads /etc/nftables.conf if the service is enabled, and srv01\'s nginx looks up app01.corp.lab when it starts.\n\nAnything you changed only in the running system, and not in a file, is gone after the restart. This step proves that every earlier step was saved.',
      tasks: ['Run "Check" on this step: it restarts every machine on a copy of the lab and re-runs all checks.'],
      hints: ['If only the reboot test fails: an export not in /etc/exports, a mount not in fstab, nftables not enabled, or dana\'s group changed only in memory?'],
      checks: [],
      solution: [],
      learn: [{ label: 'Safe configuration change', link: 'reference?id=proc:safe-config-change' }],
      concepts: ['ops.recovery'],
      afterReboot: true,
    },
  ],
};
