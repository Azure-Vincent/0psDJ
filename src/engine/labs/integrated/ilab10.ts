// Integrated Lab 10: Complete Infrastructure Deployment. A new server goes
// from "delivered by the platform team" to a fully integrated production
// service: name, time, central logs, shared storage over NFS, the same data
// for Windows users over SMB, publication through the reverse proxy, a
// default-deny firewall, key-only administration and monitoring. Then a
// maintenance night leaves two unrelated failures at once. It prepares for
// the end-to-end case studies, which assess the same skills without guidance.

import { mkdir } from '../../fs';
import { installNodeExporter, MON01_IP, PROMETHEUS_YML } from '../../lab/monLab';
import type { World } from '../../types';
import { NO, OK, printfTo, probe, probeSeq } from '../engine';
import { APP01_IP, APP01_PASSWORD, LAB5, LAB5_NFT } from '../lab5';
import type { GuidedLab, LabCheck } from '../types';
import { evidence, hop } from './common';
import { combinedFault, reuseStep, ticketFault } from './tickets';

const TARGET = 'app01.corp.lab:9100';
const PROM = 'http://localhost:9090';

export function buildIlab10World(): World {
  const w = LAB5.build();
  const h = w.hosts.app01;
  // The template ships the monitoring agent, installed but not enabled.
  if (!h.fs['/var/lib']) mkdir(h, '/var/lib', w.clock);
  installNodeExporter(h, w.clock);
  const rt = h.services['prometheus-node-exporter'];
  if (rt) { rt.enabled = false; rt.state = 'inactive'; rt.pid = null; rt.loaded = null; }
  return w;
}

const adminKeys: LabCheck = {
  id: 'admin', description: 'alice administers app01 from ws01 with her key; passwords are refused',
  check(w) {
    const k = probe(w, 'ws01', 'alice', 'ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new app01.corp.lab hostname');
    if (!/^app01$/m.test(k.output)) return NO(`alice cannot log in to app01 with her key.\n${evidence('ws01', 'alice', 'ssh -o BatchMode=yes app01.corp.lab hostname', k.output, k.code)}`);
    const p = probe(w, 'ws01', 'alice', 'ssh -o PubkeyAuthentication=no -o BatchMode=yes -o StrictHostKeyChecking=accept-new app01.corp.lab true');
    if (!/Permission denied \(publickey\)/.test(p.output)) return NO('sshd on app01 still accepts passwords: PasswordAuthentication no (sshd -t, systemctl reload ssh).');
    return OK('Key-only administration.');
  },
};

const monitored: LabCheck = {
  id: 'monitoring', description: `Prometheus on mon01 scrapes ${TARGET} (node_exporter enabled on app01, TCP 9100 open to mon01 only, target in the node job)`,
  check(w) {
    const rt = w.hosts.app01.services['prometheus-node-exporter'];
    if (!rt || rt.state !== 'active' || !rt.enabled) return NO('prometheus-node-exporter is not running and enabled on app01 (systemctl enable --now prometheus-node-exporter).');
    const fromMon = probe(w, 'mon01', 'root', `curl -s -m 5 http://${TARGET}/metrics`);
    if (!/node_/.test(fromMon.output)) return NO(`mon01 cannot fetch http://${TARGET}/metrics: app01's firewall must allow TCP 9100 from mon01 (${MON01_IP}).`);
    const fromWs = probe(w, 'ws01', 'alice', `curl -s -m 5 http://${TARGET}/metrics`);
    if (fromWs.code === 0 && /node_/.test(fromWs.output)) return NO('ws01 can read app01\'s metrics too: allow TCP 9100 from mon01 only.');
    // Give Prometheus a scrape interval after a reload.
    const up = probeSeq(w, 'mon01', 'root', ['sleep 20', `promtool query instant ${PROM} 'up{instance="${TARGET}"}'`]);
    if (!/=> 1 @/.test(up.output)) return NO(`Prometheus does not scrape ${TARGET} (yet): add it to the node job in /etc/prometheus/prometheus.yml, promtool check config, systemctl reload prometheus.\n${evidence('mon01', 'root', `promtool query instant … up{instance="${TARGET}"}`, up.output, up.code)}`);
    return OK(`${TARGET} is up in Prometheus.`);
  },
};

const NFT_MON = LAB5_NFT.replace('\t\tip saddr 10.0.20.10 tcp dport 80 accept\n', `\t\tip saddr 10.0.20.10 tcp dport 80 accept\n\t\t# Monitoring: node_exporter for mon01 only\n\t\tip saddr ${MON01_IP} tcp dport 9100 accept\n`);
const PROM_DONE = PROMETHEUS_YML.replace("          - 'log01.corp.lab:9100'\n", `          - 'log01.corp.lab:9100'\n          - '${TARGET}'\n`);

export const ILAB10: GuidedLab = {
  id: 'ilab10',
  title: 'Integrated Lab 10: Complete Infrastructure Deployment',
  level: 'advanced',
  duration: '120–180 min',
  summary: 'Take a new server from "delivered" to production in the whole environment: DNS, time, central logs, NFS storage shared with Windows users over SMB, the reverse proxy, a default-deny firewall that keeps every dependency working, key-only administration and monitoring. Then a maintenance night leaves two unrelated failures at once. The last integrated lab before the unguided case studies.',
  brief: `${LAB5.brief}

When the integration is done, finish the production checklist (CHG-3300):

- **Administration**: alice manages app01 from ws01 with her SSH key only (her initial password on app01 is \`${APP01_PASSWORD}\`); no password logins.
- **Monitoring**: the template installed **prometheus-node-exporter** but left it disabled. Enable it, open TCP 9100 to **mon01** (${MON01_IP}) only, and add **${TARGET}** to the node job of Prometheus on mon01.`,
  objectives: [
    ...LAB5.objectives,
    'Finish a deployment with key-only administration and monitoring, and verify the whole service from every side (users, Windows, proxy, monitoring).',
    'Diagnose two unrelated failures that appear at the same time, without treating them as one.',
  ],
  prerequisites: [...LAB5.prerequisites, { label: 'Monitoring and alerting', link: 'lesson/monitoring/what' }],
  setupNote: LAB5.setupNote,
  terminals: [
    ...LAB5.terminals,
    { hostId: 'mon01', user: 'root', label: 'mon01 (monitoring)', banner: 'mon01 (root): Prometheus. Try: cat /etc/prometheus/prometheus.yml, promtool check config /etc/prometheus/prometheus.yml, promtool query instant http://localhost:9090 \'up\'.' },
  ],
  build: buildIlab10World,
  steps: [
    reuseStep(LAB5, 'dns'),
    reuseStep(LAB5, 'time'),
    reuseStep(LAB5, 'logs'),
    reuseStep(LAB5, 'nfs'),
    reuseStep(LAB5, 'smb'),
    reuseStep(LAB5, 'proxy'),
    reuseStep(LAB5, 'firewall'),
    {
      id: 'admin', title: 'Key-only administration',
      objective: 'alice logs in to app01 from ws01 with her key; sshd refuses passwords.',
      background: 'Install the key with one last password login (`ssh-copy-id`), **test it**, then switch passwords off in a drop-in and reload. The firewall from the previous step already allows SSH from the internal networks.',
      tasks: [
        'On ws01 (alice): `ssh-copy-id app01.corp.lab` (accept the host key, then her app01 password), then `ssh -o BatchMode=yes app01.corp.lab hostname`.',
        'On app01: `printf \'PasswordAuthentication no\\nPermitRootLogin no\\n\' > /etc/ssh/sshd_config.d/10-hardening.conf`, `sshd -t`, `systemctl reload ssh`.',
      ],
      hints: ['Test the key before disabling passwords.'],
      checks: [adminKeys],
      solution: [
        { host: 'ws01', user: 'alice', commands: ['ssh-copy-id app01.corp.lab'], answers: ['yes', APP01_PASSWORD] },
        { host: 'app01', user: 'root', commands: ["printf 'PasswordAuthentication no\\nPermitRootLogin no\\n' > /etc/ssh/sshd_config.d/10-hardening.conf", 'sshd -t', 'systemctl reload ssh'] },
      ],
      learn: [{ label: 'SSH authentication', link: 'lesson/ssh/internals' }],
      concepts: ['ssh.userauth'],
    },
    {
      id: 'monitoring', title: 'Bring app01 under monitoring',
      objective: `node_exporter runs on app01 (enabled), TCP 9100 is open to mon01 only, and Prometheus scrapes ${TARGET}.`,
      background: 'Monitoring is part of the deployment, not an afterthought: a service nobody watches fails silently. Prometheus **pulls**: mon01 connects to each exporter, so the exporter must run, app01\'s **default-deny** firewall must let mon01 in on 9100 (and nobody else), and the target must be in prometheus.yml (checked with promtool before the reload).',
      tasks: [
        'On app01: `systemctl enable --now prometheus-node-exporter`, `curl -s localhost:9100/metrics | head -3`.',
        `Add \`ip saddr ${MON01_IP} tcp dport 9100 accept\` to /etc/nftables.conf on app01, \`nft -c -f /etc/nftables.conf\`, \`nft -f /etc/nftables.conf\`.`,
        `On mon01: add \`- '${TARGET}'\` to the node job in /etc/prometheus/prometheus.yml, \`promtool check config /etc/prometheus/prometheus.yml\`, \`systemctl reload prometheus\`; after a scrape interval \`promtool query instant ${PROM} 'up{instance="${TARGET}"}'\`.`,
      ],
      hints: ['"context deadline exceeded" in the target list: the firewall on app01.', 'Indentation in YAML: spaces, the same as the other targets.'],
      checks: [monitored],
      solution: [
        { host: 'app01', user: 'root', commands: ['systemctl enable --now prometheus-node-exporter', printfTo(NFT_MON, '/etc/nftables.conf'), 'nft -c -f /etc/nftables.conf', 'nft -f /etc/nftables.conf'] },
        { host: 'mon01', user: 'root', commands: [printfTo(PROM_DONE, '/etc/prometheus/prometheus.yml'), 'promtool check config /etc/prometheus/prometheus.yml', 'systemctl reload prometheus'] },
      ],
      learn: [{ label: 'Monitoring', link: 'lesson/monitoring/internals' }, { label: 'Monitor a new server', link: 'reference?id=proc:monitor-new-server' }],
      concepts: ['mon.metrics'],
    },
    {
      id: 'verify', title: 'Verify the whole deployment, and after a reboot', stage: 'verify',
      objective: 'Every integration works from every side (users through the proxy, Windows over SMB, storage, time, logs, administration, monitoring), also after every machine restarts.',
      background: 'The final check repeats every earlier check after rebooting every machine: DNS, NTP, logs, NFS, SMB, the proxy, the firewall, SSH and monitoring. Anything that only lived in the running state fails here.',
      tasks: ['Walk through the dependency map (stage 2) once more.', 'Run the check (reboots every machine on a copy and repeats every check).'],
      hints: ['If NFS fails only after the reboot: the fstab line (and _netdev).', 'If monitoring fails only after the reboot: is the exporter enabled, and is the firewall rule in the file?'],
      checks: [],
      solution: [],
      learn: [{ label: 'Infrastructure recovery', link: 'lesson/recovery/operate' }],
      concepts: ['ops.recovery'],
      afterReboot: true,
    },
  ],
  integrated: {
    number: 10,
    scenario: {
      organisation: 'corp.lab: finance gets a reports server (app01) that must fit into every company service.',
      situation: 'The platform team delivered app01 from the standard template: an address, a cable, an application account, and nothing else integrated.',
      goal: 'A production service: reachable by name through the proxy, synchronised, logging centrally, storing reports on the file server, readable by finance on Windows, firewalled, administered with keys, and monitored.',
      whyItMatters: 'This is the whole curriculum on one server: each integration has its own dependencies, and the firewall at the end must keep all of them working. The end-to-end case studies ask for the same, without the steps.',
    },
    technologies: ['DNS', 'NTP (timesyncd → chrony on rtr01)', 'rsyslog → log01', 'NFS (UIDs, exports, fstab)', 'Samba and Windows net use', 'nginx reverse proxy', 'nftables default deny', 'SSH keys', 'Prometheus and node_exporter'],
    systems: [
      { host: 'app01', role: `New finance reports server (${APP01_IP})` },
      { host: 'ns1', role: 'DNS (corp.lab)' },
      { host: 'rtr01', role: 'Router and NTP server (chrony)' },
      { host: 'log01', role: 'Central log server' },
      { host: 'fs01', role: 'File server: NFS for app01, SMB for finance' },
      { host: 'win01', role: 'Finance\'s Windows view of the reports (SMB)' },
      { host: 'srv01', role: 'Reverse proxy (apps.corp.lab)' },
      { host: 'mon01', role: 'Monitoring (Prometheus)' },
      { host: 'ws01', role: 'The office and the administrator' },
    ],
    startingState: [
      'app01: static address, no DNS name, clock 7 minutes off, logs only locally, no storage, nginx serving reports locally, firewall disabled, sshd with Debian\'s defaults, node_exporter installed but disabled.',
      'Everything else in the company works.',
    ],
    tools: [
      { command: 'named-checkzone, rndc reload, getent hosts', platform: 'Linux', use: 'DNS', refId: 'named-checkzone' },
      { command: 'timedatectl, chronyc sources', platform: 'Linux', use: 'Time', refId: 'timedatectl' },
      { command: 'logger, rsyslogd -N1', platform: 'Linux', use: 'Central logging', refId: 'logger' },
      { command: 'exportfs -ra, showmount -e, mount -a', platform: 'Linux', use: 'NFS', refId: 'exportfs' },
      { command: 'testparm, smbpasswd, net use', platform: 'Windows', use: 'SMB, from the server and from Windows', refId: 'net-use' },
      { command: 'nginx -t, curl', platform: 'Linux', use: 'The reverse proxy', refId: 'nginx' },
      { command: 'nft -c -f, nft list ruleset', platform: 'Linux', use: 'The firewall', refId: 'nft' },
      { command: 'ssh-copy-id, sshd -t', platform: 'Linux', use: 'Administration', refId: 'sshd-t' },
      { command: 'promtool check config / query instant', platform: 'Linux', use: 'Monitoring', refId: 'promtool' },
    ],
    dependencies: {
      explanation: `What app01 needs, and in which direction the traffic flows (that decides which firewall it crosses):

| Integration | app01 → … (outgoing) | … → app01 (incoming) |
|---|---|---|
| DNS | ns1 :53 | |
| Time | rtr01 :123 | |
| Logs | log01 :514 | |
| Storage | fs01 :2049 (NFS) | |
| Publication | | srv01 → :80 |
| Administration | | office → :22 |
| Monitoring | | mon01 → :9100 |

Outgoing connections need **replies** back in: \`ct state established,related accept\`. Incoming ones need an explicit rule each, restricted to the one source that needs it. Finance's SMB access goes to **fs01**, not app01: the same files, through another server.`,
      paths: [
        {
          id: 'reports', label: 'alice opens http://apps.corp.lab/reports/',
          nodes: [
            hop('dns', 'apps.corp.lab resolves', 'The proxy\'s name.', 'ws01', 'alice', 'getent hosts apps.corp.lab', (o, c) => c === 0 && /apps\.corp\.lab/.test(o)),
            hop('proxy-to-app', 'srv01 reaches app01:80', 'app01\'s firewall allows srv01 only.', 'srv01', 'root', `curl -sI -m 5 http://${APP01_IP}/`, (o) => /^HTTP\/1\.1 200/.test(o)),
            hop('page', 'The reports page through the proxy', 'location /reports/ on srv01.', 'ws01', 'alice', 'curl -s -m 5 http://apps.corp.lab/reports/', (o, c) => c === 0 && o.trim() !== '' && !/50\d|404/.test(o.split('\n')[0] ?? '')),
          ],
        },
        {
          id: 'operations', label: 'operations: time, logs and storage on app01',
          nodes: [
            hop('time', 'app01\'s clock is synchronised', 'timesyncd → rtr01.', 'app01', 'root', 'timedatectl', (o) => /System clock synchronized: yes/.test(o)),
            hop('nfs', '/mnt/reports is mounted from fs01', 'NFS with matching UIDs.', 'app01', 'root', 'mount', (o) => /fs01\.corp\.lab:\/srv\/reports on \/mnt\/reports/.test(o)),
            hop('logs', 'log01 stores app01\'s logs', 'rsyslog forwarding.', 'log01', 'root', 'ls /var/log/remote/app01', (o, c) => c === 0 && o.trim() !== ''),
          ],
        },
        {
          id: 'monitoring', label: 'mon01 monitors app01',
          nodes: [
            hop('exporter', 'node_exporter runs on app01', 'Enabled at boot.', 'app01', 'root', 'systemctl is-active prometheus-node-exporter', (o) => /^active/m.test(o)),
            hop('port', 'mon01 reaches app01:9100', 'app01\'s firewall rule for mon01.', 'mon01', 'root', `nc -z -w 3 ${APP01_IP} 9100`, (_o, c) => c === 0),
            { id: 'up', label: 'Prometheus scrapes it', role: 'The target in the node job (after one scrape interval).', host: 'mon01', probe: (w) => { const cmd = `promtool query instant ${PROM} 'up{instance="${TARGET}"}'`; const r = probeSeq(w, 'mon01', 'root', ['sleep 20', cmd]); return { ok: /=> 1 @/.test(r.output), evidence: evidence('mon01', 'root', cmd, r.output, r.code) }; } },
          ],
        },
      ],
    },
    mistakes: [
      'A default-deny firewall without the established rule: time, DNS and NFS replies are dropped.',
      'Opening port 80 or 9100 to everybody instead of to the proxy and to mon01.',
      'An NFS export that works for root but not for the application account (UIDs differ).',
      'Disabling SSH passwords before installing and testing the key.',
      'Forgetting monitoring until the first silent failure.',
      'Treating two simultaneous failures as one and looking for a single cause.',
    ],
    verification: 'Each step checks its integration from the side that uses it (clients by name, the proxy, Windows over SMB, app01\'s mounts and clock, log01, mon01). The final check reboots every machine and runs every check of every step again. The incident has two independent causes; both must be diagnosed and repaired.',
    fault: combinedFault(
      'After the maintenance night: two problems at once',
      'Tuesday 08:40, after the network team\'s firewall review on rtr01 (SEC-130) and an "inventory API port clean-up" on srv01: alice\'s kinit fails with "Clock skew too great" and clocks drift; at the same time the inventory site (http://apps.corp.lab/inventory/) answers 502 Bad Gateway. The reports site still works.',
      [ticketFault('ntp-blocked'), ticketFault('proxy-bad-gateway')],
    ),
    review: [
      { id: 'q1', question: 'app01 gets a default-deny input firewall. Which rule keeps NTP, DNS, syslog and NFS working, although they are all connections app01 opens itself?', choices: ['ct state established,related accept (the replies come back in as input)', 'An output accept rule', 'A rule for port 123 only', 'None: outgoing traffic is never filtered'], answer: 0, explanation: 'Replies to outgoing connections arrive on the input chain; without the stateful rule the default drop discards them.', concepts: ['fw.stateful'] },
      { id: 'q2', question: 'Finance reads the reports from Windows. Where does their traffic go?', choices: ['To fs01 over SMB (the share of the same directory app01 writes over NFS)', 'To app01 over SMB', 'Through the proxy on srv01', 'To mon01'], answer: 0, explanation: 'app01 writes the reports to fs01 over NFS; finance reads the same files from fs01 over SMB. app01 needs no SMB rule.', concepts: ['files.smb', 'files.nfs'] },
      { id: 'q3', question: 'Two failures appear the same morning: Kerberos clock skew and a 502 on one site. What is the best approach?', choices: ['Treat them as separate until the evidence links them: each has its own path (NTP through rtr01, the proxy\'s upstream on srv01)', 'Look for one cause that explains both', 'Reboot everything', 'Restore last week\'s backups'], answer: 0, explanation: 'Coincidence in time is not a shared cause. Evidence decides: here the time path and the proxy path share nothing.', concepts: ['ops.recovery'] },
      { id: 'q4', question: 'Why add app01 to monitoring as part of the deployment?', choices: ['Without it, the first failure of the new service is found by its users', 'Prometheus requires every host', 'node_exporter replaces logging', 'It is needed for NFS'], answer: 0, explanation: 'Monitoring turns silent failures into alerts; a service that is not monitored is not finished.', concepts: ['mon.metrics'] },
      { id: 'q5', question: 'app01\'s web server should only be reachable through the proxy. Which rule expresses that?', choices: ['ip saddr 10.0.20.10 tcp dport 80 accept (srv01 only)', 'tcp dport 80 accept', 'ip saddr 10.0.0.0/16 tcp dport 80 accept', 'No rule: the proxy uses port 443'], answer: 0, explanation: 'Only the proxy needs port 80; everybody else goes through it, where requests are logged and controlled.', concepts: ['fw.path', 'web.proxy'] },
    ],
    after: ['netops', 'ntp', 'logging', 'nfs', 'smb', 'webproxy', 'nftables', 'ssh', 'monitoring'],
  },
};
