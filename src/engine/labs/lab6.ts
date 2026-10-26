// Lab 6: Infrastructure Recovery. A power cut took the whole server room down
// on Sunday night; everything came back on, but little works. The faults were
// latent for days (a hardening script that only took effect at the next boot,
// an unreloaded zone edit, containers started without a restart policy), and
// most of what the users see is a consequence: mounts, the proxy, Kerberos and
// central logs all depend on routing, names and time. The learner restores the
// service in dependency order, leaves the things that heal themselves alone,
// avoids the tempting wrong fix (restoring an old zone backup), and proves the
// result survives the next power cut.

import { readFile, writeFile } from '../fs';
import { ALICE_KRB_PASSWORD } from '../lab/krbLab';
import { buildSshLab, CORP_ZONE } from '../lab/sshLab';
import { INVENTORY_CHECK, INVENTORY_COMPOSE, INVENTORY_DIR } from '../scenarios/containerScenarios';
import { checkGoal, rebootAll, script } from '../scenarios/engine';
import { APPS_CHECK, deployProxy } from '../scenarios/proxyScenarios';
import { loadProject } from '../sim/compose';
import { sysctlFiles } from '../sim/services';
import type { World } from '../types';
import { lastLines as last, NO, OK, printfTo, probe } from './engine';
import type { GuidedLab, LabCheck } from './types';


export const ROUTER_SYSCTL = '# Enable IPv4 forwarding between eth0 (LAN) and eth1 (servers)\nnet.ipv4.ip_forward=1\n# IPv6 routing for the pilot (NET-40)\nnet.ipv6.conf.all.forwarding=1\n';
/** Friday's unfinished zone edit (CHG-2341): a typo in log01's address, saved but never reloaded. */
export const LAB6_BROKEN_ZONE = CORP_ZONE.replace('2026101901 ; serial', '2026102301 ; serial').replace('log01   IN A    10.0.20.50', 'log01   IN A    10.0.20.5O').replace('fs01    IN A    10.0.20.60\n', 'fs01    IN A    10.0.20.60\n; CHG-2341: printers moved to the server network\nprn01   IN A    10.0.20.80\n');
export const LAB6_FIXED_ZONE = LAB6_BROKEN_ZONE.replace('10.0.20.5O', '10.0.20.50').replace('2026102301 ; serial', '2026102601 ; serial');
/** The nightly zone backup from two weeks ago: before log01, fs01 and the printers existed. */
export const LAB6_OLD_BACKUP = CORP_ZONE.replace('2026101901 ; serial', '2026101201 ; serial').replace('log01   IN A    10.0.20.50\n', '').replace('fs01    IN A    10.0.20.60\n', '');
const COMPOSE_NO_RESTART = INVENTORY_COMPOSE.replace(/ {4}restart: unless-stopped\n/g, '');

/** The lab before the power cut, with the latent faults in place. */
export function buildLab6World(): World {
  const world = buildSshLab();
  // The inventory app and its reverse proxy, as deployed in Labs 4 and the proxy lesson,
  // but started by hand from a compose file without restart policies (DEV-881).
  deployProxy(world);
  writeFile(world.hosts.dock01, `${INVENTORY_DIR}/compose.yaml`, COMPOSE_NO_RESTART, world.clock);
  script(world, 'dock01', [`cd ${INVENTORY_DIR} && docker compose up -d`], 30_000);

  // Thursday: the hardening script SEC-150 "removed unknown sysctl overrides and disabled
  // unused services" on rtr01. The running kernel and chronyd were not affected.
  const rtr = world.hosts.rtr01;
  delete rtr.fs['/etc/sysctl.d/99-router.conf'];
  rtr.services.chrony.enabled = false;
  writeFile(rtr, '/var/log/sec150-hardening.log', [
    '2026-10-22 16:02:11 SEC-150 hardening run on rtr01',
    '2026-10-22 16:02:11 removed /etc/sysctl.d/99-router.conf (not in baseline)',
    '2026-10-22 16:02:12 systemctl disable chrony (not in the service allow-list)',
    '2026-10-22 16:02:12 done: 2 changes, reboot not required',
    '',
  ].join('\n'), world.clock);

  // Friday: a zone edit saved on ns1 without named-checkzone or reload.
  const ns1 = world.hosts.ns1;
  writeFile(ns1, '/etc/bind/db.corp.lab', LAB6_BROKEN_ZONE, world.clock, { group: 'bind' });
  script(world, 'ns1', ['mkdir -p /var/backups/bind']);
  writeFile(world.hosts.ns1, '/var/backups/bind/db.corp.lab.2026-10-12', LAB6_OLD_BACKUP, world.clock);

  // Sunday night, the power cut. The clocks of the servers that lost power drift.
  // Monday 26 October, one week after the lab's baseline (the cut was in the night).
  world.clock += 7 * 86_400_000 - 40 * 60_000;
  world.hosts.ws01.clockOffset = 6 * 60_000;
  world.hosts.srv01.clockOffset = 7 * 60_000;
  const after = rebootAll(world);
  after.clock += 25 * 60_000;
  return after;
}

// ---------------------------------------------------------------- checks

const routing: LabCheck = {
  id: 'routing', description: 'rtr01 forwards between the office and the servers again (ws01 reaches srv01), and the setting is persistent',
  check(w) {
    const ping = probe(w, 'ws01', 'alice', 'ping -c 1 -W 1 10.0.20.10');
    if (ping.code !== 0) return NO(`ws01 → srv01: ${ping.output.trim().split('\n').slice(-2).join(' ')}`);
    // What the next boot applies (sysctlFiles: /etc/sysctl.conf and /etc/sysctl.d/*.conf).
    const persisted = sysctlFiles(w.hosts.rtr01).map((p) => w.hosts.rtr01.fs[p].content).join('\n');
    if (!/^\s*net\.ipv4\.ip_forward\s*=\s*1\s*$/m.test(persisted)) return NO('Forwarding is on now, but no /etc/sysctl.d/*.conf file sets net.ipv4.ip_forward=1: it is off again after the next boot (files without .conf are ignored).');
    return OK('ws01 reaches srv01; net.ipv4.ip_forward=1 is in /etc/sysctl.d.');
  },
};

const NAMES: [string, string][] = [['srv01.corp.lab', '10.0.20.10'], ['fs01.corp.lab', '10.0.20.60'], ['log01.corp.lab', '10.0.20.50'], ['dock01.corp.lab', '10.0.20.40'], ['prn01.corp.lab', '10.0.20.80']];

const names: LabCheck = {
  id: 'dns', description: 'ns1 serves the whole corp.lab zone again, including Friday\'s new record (prn01) and the servers added since the last backup (fs01, log01)',
  check(w) {
    for (const [name, ip] of NAMES) {
      const r = checkGoal(w, { kind: 'resolve', description: '', fromHost: 'ws01', name, expect: ip });
      if (!r.ok) return NO(`${name}: ${last(r)}`);
    }
    const zone = readFile(w.hosts.ns1, '/etc/bind/db.corp.lab') ?? '';
    if (Number(/(\d{10})\s*;\s*serial/.exec(zone)?.[1] ?? 0) <= 2026102301) return NO('The records resolve, but the serial was not increased past Friday\'s 2026102301: secondaries and caches would keep the broken version.');
    return OK('srv01, fs01, log01, dock01 and prn01 resolve; the serial is new.');
  },
};

const time: LabCheck = {
  id: 'time', description: 'rtr01 serves time again (chrony enabled and running); ws01 and srv01 are synchronized and alice gets a Kerberos ticket on ws01',
  check(w) {
    const c = w.hosts.rtr01.services.chrony;
    if (!c?.enabled) return NO('chrony is not enabled on rtr01: it will not start after the next power cut.');
    if (c.state !== 'active') return NO('chrony is not running on rtr01.');
    for (const host of ['ws01', 'srv01']) {
      const r = checkGoal(w, { kind: 'time', description: '', host });
      if (!r.ok) return NO(`${host}: ${r.lines.filter((l) => /synchronized|this clock is/.test(l)).join(' ')}`);
    }
    const k = checkGoal(w, { kind: 'kerberos', description: '', fromHost: 'ws01', localUser: 'alice', password: ALICE_KRB_PASSWORD });
    return k.ok ? OK('chrony serves; ws01 and srv01 synchronized; kinit alice works.') : NO(`kinit on ws01: ${last(k)}`);
  },
};

const mounts: LabCheck = {
  id: 'mounts', description: 'The NFS mounts that failed at boot are back: /mnt/projects on ws01 and /opt/software on srv01',
  check(w) {
    const a = probe(w, 'ws01', 'alice', 'ls /mnt/projects');
    if (!/plan\.txt/.test(a.output)) return NO('ws01: /mnt/projects is empty (not mounted). Look at journalctl -b -u mnt-projects.mount.');
    const b = probe(w, 'srv01', 'root', 'ls /opt/software');
    return /agent-install\.sh/.test(b.output) ? OK('ws01 /mnt/projects and srv01 /opt/software are mounted.') : NO('srv01: /opt/software is empty (not mounted).');
  },
};

const inventory: LabCheck = {
  id: 'inventory', description: 'The inventory app runs on dock01 (http://inventory.corp.lab:8000/health answers 200) and both containers restart unless stopped',
  check(w) {
    const p = loadProject(w.hosts.dock01, INVENTORY_DIR);
    if ('error' in p) return NO(`compose.yaml: ${p.error.split('\n')[0]}`);
    const missing = p.services.filter((s) => s.restart !== 'unless-stopped' && s.restart !== 'always').map((s) => s.name);
    const r = checkGoal(w, INVENTORY_CHECK);
    if (!r.ok) return NO(`inventory: ${last(r)}`);
    if (!missing.length) return OK('inventory answers 200; restart: unless-stopped on both services.');
    const desc = missing.map((n) => `${n} (restart: ${p.services.find((s) => s.name === n)?.restart ?? 'no'})`).join(' and ');
    return NO(`Running now, but ${desc} will not be started by dockerd after the next reboot: use restart: unless-stopped (or always).`);
  },
};

const proxy: LabCheck = {
  id: 'proxy', description: 'nginx runs again on srv01: http://apps.corp.lab/inventory/health answers 200 from ws01',
  check(w) {
    const r = checkGoal(w, APPS_CHECK);
    return r.ok ? OK('apps.corp.lab/inventory/ → 200 through srv01.') : NO(last(r));
  },
};

const logs: LabCheck = {
  id: 'logs', description: 'Central logging works again: a message from srv01 and one from ns1 arrive on log01',
  check(w) {
    for (const h of ['srv01', 'ns1']) {
      const r = checkGoal(w, { kind: 'syslog', description: '', fromHost: h, server: 'log01', path: `/var/log/remote/${h}/%PROGRAMNAME%.log` });
      if (!r.ok) return NO(`${h}: ${last(r)}`);
    }
    return OK('srv01 and ns1 → log01 (their queues delivered the backlog).');
  },
};

// ---------------------------------------------------------------- the lab

export const LAB6: GuidedLab = {
  id: 'lab6',
  title: 'Lab 6: Infrastructure Recovery',
  level: 'advanced',
  duration: '60–90 min',
  summary: 'After a power cut nothing works: no routing between the networks, no DNS, wrong clocks, empty shares, a dead reverse proxy and a stopped application. Find the few root causes among the many symptoms, restore the services in dependency order (network, names, time, then what depends on them), avoid the wrong fix of restoring an old backup, and prove that the next power cut will not repeat the outage.',
  brief: 'Monday morning. A power cut on Sunday night took the whole server room down; everything is powered on again, but the helpdesk queue is full: **"the intranet is down"**, **"my project folder is empty"**, **"I cannot log in (Kerberos)"**, **"inventory does not load"**. You are the on-call administrator. Nobody changed anything over the weekend, but last week saw the SEC-150 hardening run on rtr01 (Thursday, log in /var/log/sec150-hardening.log), an edit of the corp.lab zone on ns1 (Friday, CHG-2341: printers moved, prn01 added), and the inventory app was started by the developers. Restore service, keep the fixes persistent, and be ready to explain what happened.',
  objectives: [
    'Triage an outage with many symptoms: find the shared dependencies (routing, DNS, time) before fixing individual services.',
    'Recover in dependency order, and re-check dependents after each fix: some heal themselves, others need an action.',
    'Recognise faults that were latent until a reboot (runtime vs persistent configuration).',
    'Prefer repairing current configuration to restoring an old backup that silently loses newer changes.',
    'Make every fix persistent and prove it with a full restart.',
  ],
  prerequisites: [
    { label: 'Safe recovery', link: 'lesson/recovery/what' },
    { label: 'Network operations', link: 'lesson/netops/what' },
    { label: 'Time synchronisation (NTP)', link: 'lesson/ntp/what' },
    { label: 'File sharing (NFS)', link: 'lesson/nfs/what' },
    { label: 'Web servers and reverse proxies', link: 'lesson/webproxy/what' },
  ],
  setupNote: 'The whole corp.lab network after an unplanned restart of every machine. The inventory application (dock01) and the reverse proxy apps.corp.lab (srv01) are deployed. Start from the clients\' symptoms, then work down.',
  terminals: [
    { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01, the helpdesk\'s test machine. Symptoms: curl -sS http://apps.corp.lab/inventory/health, ls /mnt/projects, kinit, ping srv01.corp.lab.' },
    { hostId: 'rtr01', user: 'root', label: 'rtr01 console (root)', banner: 'rtr01 console (the router and time server). Try: sysctl net.ipv4.ip_forward, systemctl status chrony, cat /var/log/sec150-hardening.log.' },
    { hostId: 'ns1', user: 'root', label: 'ns1 console (root)', banner: 'ns1 console (DNS, DHCP, KDC). Try: systemctl status named, journalctl -u named -b, named-checkzone corp.lab /etc/bind/db.corp.lab, ls /var/backups/bind.' },
    { hostId: 'srv01', user: 'root', label: 'srv01 console (root)', banner: 'srv01 console (intranet and reverse proxy). Try: systemctl --failed, journalctl -b -u nginx, mount -t nfs4.' },
    { hostId: 'dock01', user: 'root', label: 'dock01 console (root)', banner: 'dock01 console (Docker). Try: docker ps -a, cat /srv/inventory/compose.yaml.' },
    { hostId: 'log01', user: 'root', label: 'log01 console (root)', banner: 'log01: the central logs. ls -l /var/log/remote/*/ shows who has been sending since the restart.' },
  ],
  build: buildLab6World,
  steps: [
    {
      id: 'routing', title: 'Network first: the router',
      objective: 'Restore routing between the office (10.0.10.0/24) and the servers (10.0.20.0/24), **persistently**.',
      background: 'Many symptoms, few causes: before touching any service, find what everything shares. From ws01, `ping 10.0.20.10` (an address: no DNS involved) gets "Destination Host Unreachable" **from 10.0.10.1**, while `ping 10.0.10.1` works: the router receives the packets and refuses to forward them. A Linux router forwards only with **net.ipv4.ip_forward=1**. The value set at runtime (`sysctl -w`) survived until the power cut; at boot the kernel reads it from **/etc/sysctl.d/**, and Thursday\'s hardening run removed that file. Nothing broke on Thursday: the fault waited for the next reboot.',
      tasks: [
        'On ws01: `ping -c1 10.0.10.1` (the router answers) and `ping -c1 10.0.20.10` (unreachable, reported by 10.0.10.1). On rtr01: `sysctl net.ipv4.ip_forward`.',
        'Read the hardening log: `cat /var/log/sec150-hardening.log`.',
        `Restore the file: \`printf '${ROUTER_SYSCTL.replace(/\n/g, '\\n')}' > /etc/sysctl.d/99-router.conf\`, then \`sysctl --system\`.`,
        'From ws01: `ping -c1 10.0.20.10`.',
      ],
      hints: ['`sysctl -w net.ipv4.ip_forward=1` alone fixes it until the next reboot: that is how the latent fault was created.', 'Name resolution is still broken after this step: that is the next layer.'],
      checks: [routing],
      solution: [{ host: 'rtr01', user: 'root', commands: [printfTo(ROUTER_SYSCTL, '/etc/sysctl.d/99-router.conf'), 'sysctl --system'] }],
      learn: [{ label: 'Routing and forwarding', link: 'lesson/netops/internals' }, { label: 'Safe recovery', link: 'lesson/recovery/what' }],
      concepts: ['net.routing', 'fw.persistence', 'ops.recovery'],
    },
    {
      id: 'dns', title: 'Names: the corp.lab zone',
      objective: 'Make ns1 serve the complete corp.lab zone again, keeping Friday\'s change (prn01).',
      background: 'BIND loaded the zone file for the first time since Friday\'s edit, found an error and **refused the whole zone**: every corp.lab name now fails (SERVFAIL), which breaks almost everything else (mounts by name, the proxy\'s upstream, Kerberos\'s SRV records, log forwarding). `named-checkzone` names the line. There is a tempting shortcut, **/var/backups/bind/db.corp.lab.2026-10-12**: it loads, but it is two weeks old and silently drops fs01, log01 and prn01. Fix the current file instead, and increase the serial past Friday\'s.',
      tasks: [
        'On ns1: `journalctl -u named -b` and `named-checkzone corp.lab /etc/bind/db.corp.lab` (the line and the error).',
        'Edit /etc/bind/db.corp.lab: correct the address on that line and set the serial to 2026102601.',
        '`named-checkzone corp.lab /etc/bind/db.corp.lab`, then `rndc reload`.',
        'From ws01: `getent hosts fs01.corp.lab log01.corp.lab prn01.corp.lab`.',
        'Compare with the backup to see what it would have lost: `diff /var/backups/bind/db.corp.lab.2026-10-12 /etc/bind/db.corp.lab`.',
      ],
      hints: ['"bad dotted quad": an address with a character that is not a digit.', 'Restoring a backup is right when the current file is lost; when it is only damaged, repair it, or you lose every change since the backup.'],
      checks: [names],
      solution: [{ host: 'ns1', user: 'root', commands: [printfTo(LAB6_FIXED_ZONE, '/etc/bind/db.corp.lab'), 'named-checkzone corp.lab /etc/bind/db.corp.lab', 'rndc reload'] }],
      learn: [{ label: 'DNS zones', link: 'lesson/transport/internals' }, { label: 'named-checkzone', link: 'reference?id=named-checkzone' }],
      concepts: ['dns.zone', 'ops.recovery'],
    },
    {
      id: 'time', title: 'Time: the reference clock',
      objective: 'Get rtr01 serving time again (persistently), so that the clients synchronize and Kerberos works.',
      background: 'The power cut left ws01 and srv01 several minutes fast, more than Kerberos tolerates (300 s): `kinit` fails with "Clock skew too great" even now that DNS is back. Their timesyncd asks rtr01, and rtr01 does not answer: the hardening run also **disabled chrony**, so it did not start at boot. Clients poll again by themselves once the server answers: no action is needed on them.',
      tasks: [
        'On ws01: `timedatectl` (not synchronized) and `kinit` (alice\'s Kerberos password Corp-Lab-2026).',
        'On rtr01: `systemctl status chrony` (inactive, disabled).',
        '`systemctl enable --now chrony`, then `chronyc tracking` and, a moment later, `chronyc clients`.',
        'On ws01: `timedatectl` (synchronized: yes) and `kinit` again.',
      ],
      hints: ['`systemctl start` alone works until the next power cut: enable it.', 'chronyd itself synchronizes from ext01 over the Internet link, which does not depend on routing between the internal networks.'],
      checks: [time],
      solution: [{ host: 'rtr01', user: 'root', commands: ['systemctl enable --now chrony'] }],
      learn: [{ label: 'NTP and Kerberos', link: 'lesson/ntp/internals' }],
      concepts: ['ntp.sync', 'ad.kerberos'],
    },
    {
      id: 'mounts', title: 'Storage: mounts that gave up at boot',
      objective: 'Bring back the NFS mounts on ws01 (/mnt/projects) and srv01 (/opt/software).',
      background: 'fs01 itself is fine: it booted and exports both shares. The **clients** tried to mount `fs01.corp.lab:...` at boot, when neither DNS nor routing worked, failed after the timeout, and systemd does not retry a failed mount unit. The directories show the empty local folders underneath. Nothing is wrong with the configuration: the fix is to mount again now that the dependencies are back.',
      tasks: [
        'On ws01 (sudo) or srv01: `journalctl -b -u mnt-projects.mount` / `-u opt-software.mount` (why it failed at boot), `mount -t nfs4` (nothing).',
        'On ws01 as root: `mount -a`; on srv01: `mount -a`.',
        'ws01: `ls /mnt/projects`; srv01: `ls /opt/software`.',
      ],
      hints: ['Programs that wrote into the empty /mnt/projects while it was not mounted wrote to ws01\'s local disk: after mounting, those files are hidden underneath.', 'alice\'s sudo password on ws01 is ws01-alice.'],
      checks: [mounts],
      solution: [{ host: 'ws01', user: 'root', commands: ['mount -a'] }, { host: 'srv01', user: 'root', commands: ['mount -a'] }],
      learn: [{ label: 'NFS: mounts at boot', link: 'lesson/nfs/troubleshoot' }],
      concepts: ['files.nfs', 'ops.recovery'],
    },
    {
      id: 'apps', title: 'Applications: what did not come back',
      objective: 'Get the inventory app (dock01) and the reverse proxy (srv01) running, so that it survives the next reboot too; confirm that central logging recovered on its own.',
      background: 'Two different reasons. **srv01**: nginx resolves upstream names when it starts; at boot dock01.corp.lab did not resolve, nginx refused its configuration ("host not found in upstream") and stayed down. Its configuration is correct: start it. **dock01**: dockerd started fine, but the containers were started by hand from a compose file **without restart policies**, so dockerd did not restart them: add `restart: unless-stopped` to both services and `docker compose up -d`. **Logging** needs nothing: the senders\' rsyslog queues kept retrying and delivered their backlog once routing and DNS were back. Check, do not "fix" it.',
      tasks: [
        'srv01: `systemctl --failed`, `journalctl -b -u nginx` ("host not found in upstream"), `nginx -t` (now OK), `systemctl start nginx`.',
        `dock01: \`docker ps -a\` (Exited), add \`restart: unless-stopped\` to db and app in ${INVENTORY_DIR}/compose.yaml, \`cd ${INVENTORY_DIR} && docker compose up -d\`.`,
        'From ws01: `curl -sS http://apps.corp.lab/inventory/health`.',
        'log01: `ls -l /var/log/remote/srv01/` (recent messages, including from the outage).',
      ],
      hints: ['`docker start` would bring the containers back now, but not after the next power cut.', 'Order matters: the proxy only answers 200 once the app behind it runs.'],
      checks: [inventory, proxy, logs],
      solution: [
        { host: 'srv01', user: 'root', commands: ['systemctl start nginx'] },
        { host: 'dock01', user: 'root', commands: [printfTo(INVENTORY_COMPOSE, `${INVENTORY_DIR}/compose.yaml`), `cd ${INVENTORY_DIR} && docker compose up -d`] },
      ],
      learn: [{ label: 'Reverse proxy: upstream names', link: 'troubleshoot/proxy-host-not-found' }, { label: 'Docker restart policies', link: 'troubleshoot/docker-no-restart' }],
      concepts: ['web.proxy', 'docker.lifecycle', 'logs.central'],
    },
    {
      id: 'reboot', title: 'Prove it: the next power cut',
      objective: 'Restart every machine and confirm that everything comes back by itself.',
      background: 'The outage happened because four changes lived only in memory or in files nobody had tested at boot. Restarting everything on purpose, in a calm moment, is how you find the next one. Then write the incident report: timeline, root causes (hardening run, untested zone edit, missing restart policies), the cascade, and the preventive actions (test hardening with a reboot, named-checkzone before saving, restart policies in review, monitoring that alerts on a service that is enabled but not running).',
      tasks: ['Run "Check" on this step: it restarts every machine on a copy of the lab and re-runs all checks.'],
      hints: ['If only this step fails: something was started or set at runtime only (sysctl -w, systemctl start without enable, docker start).'],
      checks: [],
      solution: [],
      learn: [{ label: 'Safe recovery', link: 'lesson/recovery/operate' }, { label: 'Safe configuration change', link: 'reference?id=proc:safe-config-change' }],
      concepts: ['ops.recovery'],
      afterReboot: true,
    },
  ],
};
