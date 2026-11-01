// Integrated Lab 4: Troubleshoot Cross-Platform Connectivity. Monday morning,
// four complaints that look alike ("I cannot get to the server"), on Linux
// and Windows, each with a different cause: routing, a host firewall, a
// service that listens in the wrong place, and an authentication problem.
// The lab teaches to place each failure in its layer from the evidence
// (timeout, refused, an error from the service, a logon failure).

import { buildSshLab } from '../../lab/sshLab';
import { checkGoal } from '../../scenarios/engine';
import type { World } from '../../types';
import type { GuidedLab, LabCheck } from '../types';
import { hop } from './common';
import { applyTicket, ticketFault, ticketGoalChecks, ticketStep } from './tickets';

const TICKETS = ['ssh-missing-gateway', 'win-rdp-firewall', 'db-listen-default', 'smb-new-user'] as const;

export function buildIlab4World(): World {
  const w = buildSshLab();
  for (const id of TICKETS) applyTicket(w, id);
  w.clock += 5 * 60_000;
  return w;
}

const everything: LabCheck[] = TICKETS.flatMap((id) => ticketGoalChecks(id));

const METHOD = 'Before you change anything, place the failure in its layer: **name** (does it resolve?), **network** (does the host answer? does the port answer: timeout, or refused?), **service** (does the program answer with an error?), **authentication** (does it reject the credentials?). The kind of failure says where to look.';

export const ILAB4: GuidedLab = {
  id: 'ilab4',
  title: 'Integrated Lab 4: Troubleshoot Cross-Platform Connectivity',
  level: 'intermediate',
  duration: '60–90 min',
  summary: 'Four "I cannot reach the server" complaints on a Monday morning, on Linux and Windows, each with a different cause. Collect evidence for each, decide whether it is routing, a firewall, a service or authentication, repair it with the smallest correct change, and verify. Then a fifth complaint arrives.',
  brief: `Monday, 08:30. The administrators (who mostly work from Windows) report, at the same time:

1. **SSH to srv01** (10.0.20.10) from ws01 **times out**, ping too. The web team says srv01 is fine for the app servers next to it.
2. **Remote Desktop to win01** (10.0.20.30) "spins and cannot connect". The security team ran a hardening script on the servers over the weekend (SEC-31).
3. The **inventory application** on srv01 says "database unavailable" since the patch window on db01 (CHG-2520).
4. **carol** (new in HR) cannot open the **office share** on fs01: "NT_STATUS_LOGON_FAILURE", although IT created her account yesterday (password Welcome-Carol1).

They look alike to the users. They are not. Find each cause, fix it so it survives a reboot, and do not "fix" anything that is not broken.`,
  objectives: [
    'Tell a network problem (timeout), a firewall drop, a service problem (refused or an application error) and an authentication problem apart from their evidence.',
    'Use the same reasoning on Linux (ip, ss, nft, journalctl) and Windows (Get-NetFirewallRule, Test-NetConnection, the event log).',
    'Fix each problem with the smallest correct, persistent change, and verify from the user\'s side.',
  ],
  prerequisites: [
    { label: 'IP networking', link: 'lesson/ipnet/what' },
    { label: 'Host firewalls (nftables)', link: 'lesson/nftables/what' },
    { label: 'Windows Server administration and RDP', link: 'lesson/windows-rdp/what' },
    { label: 'File sharing (SMB)', link: 'lesson/smb/what' },
  ],
  setupNote: 'The standard lab network, after a weekend of patching and hardening. ws01 is alice\'s workstation in the office (VLAN 10); srv01, win01, db01 and fs01 are on the server network (VLAN 20) behind rtr01.',
  terminals: [
    { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01 (alice): where the complaints come from. Try: ssh srv01.corp.lab, xfreerdp /v:win01.corp.lab /u:alice (password Corp-Lab-2026), smbclient //fs01/office -U carol%Welcome-Carol1 -c ls, nc -z -w 3 HOST PORT.' },
    { hostId: 'srv01', user: 'root', label: 'srv01 console', banner: 'srv01 console (root, hypervisor). Try: ip -br addr, ip route, ss -tlnp, inventory-check, journalctl -u ssh.' },
    { hostId: 'win01', user: 'Administrator', label: 'win01 console (PowerShell)', banner: 'Windows PowerShell\nwin01 console, local Administrator. Try: Get-NetFirewallRule -DisplayGroup "Remote Desktop", Get-NetTCPConnection -State Listen, Get-Service TermService.' },
    { hostId: 'db01', user: 'root', label: 'db01 console', banner: 'db01 console (root). Try: ss -tlnp, pg_lsclusters, tail /var/log/postgresql/postgresql-15-main.log, grep listen /etc/postgresql/15/main/postgresql.conf.' },
    { hostId: 'fs01', user: 'root', label: 'fs01 console', banner: 'fs01 console (root): Samba. Try: pdbedit -L, id carol, testparm -s, tail /var/log/samba/log.ws01.' },
  ],
  build: buildIlab4World,
  steps: [
    ticketStep('ssh-missing-gateway', {
      id: 'srv01-ssh', title: 'srv01: SSH and ping time out',
      objective: 'alice can log in to srv01 from ws01 again (SSH with her key), and the fix survives a reboot.',
      background: `${METHOD}\n\nA **timeout** means a packet (or its answer) vanished: a drop in a firewall, or a reply that never finds its way back. "The servers next to it can reach it" is evidence too: what is different about traffic from another network?`,
      tasks: [
        'From ws01: `ping -c 1 10.0.20.10`, `nc -z -w 3 10.0.20.10 22`. Timeout or refused?',
        'On the srv01 console: `ip -br addr`, `ip route`, `ss -tlnp | grep :22`, `nft list ruleset`. What would srv01 do with a reply to 10.0.10.25?',
        'Fix it persistently (the file that configures the interface), apply, and test from ws01.',
      ],
      concepts: ['net.routing', 'tcp.handshake'],
      learn: [{ label: 'Routing', link: 'lesson/ipnet/internals' }, { label: 'ip', link: 'reference?id=ip' }],
    }),
    ticketStep('win-rdp-firewall', {
      id: 'win01-rdp', title: 'win01: Remote Desktop cannot connect',
      objective: 'alice can open a Remote Desktop session on win01 from ws01, without turning the firewall off.',
      background: `${METHOD}\n\nOn Windows the same questions apply: is TermService running and listening on 3389 (Get-NetTCPConnection)? Does Windows Defender Firewall let the connection in (Get-NetFirewallRule -DisplayGroup "Remote Desktop")? "It spins, then cannot connect" is a timeout, not an error from RDP itself.`,
      tasks: [
        'From ws01: `nc -z -w 3 10.0.20.30 3389`.',
        'On win01: `Get-Service TermService`, `Get-NetTCPConnection -LocalPort 3389 -State Listen`, `Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Format-Table DisplayName, Enabled`.',
        'Re-enable what the hardening script disabled (not the whole firewall), then test with xfreerdp from ws01.',
      ],
      concepts: ['win.firewall', 'win.rdp'],
      learn: [{ label: 'Windows Defender Firewall', link: 'lesson/windows-firewall/what' }, { label: 'Get-NetFirewallRule', link: 'reference?id=get-netfirewallrule' }],
    }),
    ticketStep('db-listen-default', {
      id: 'db01-listen', title: 'Inventory: "database unavailable"',
      objective: 'The inventory application on srv01 gets answers from its database on db01 again.',
      background: `${METHOD}\n\nHere the user sees an **application error**: the web site works, so the network to srv01 is fine. The application's own dependency (srv01 → db01:5432) is what to test. "The DBA can use psql on db01" proves the database runs, not that it accepts connections from other machines.`,
      tasks: [
        'On srv01: `inventory-check`, then `nc -z -w 3 db01.corp.lab 5432`: refused or timeout?',
        'On db01: `ss -tlnp | grep 5432`. Which address does PostgreSQL listen on? Compare with /etc/postgresql/15/main/postgresql.conf (and the patch notes).',
        'Fix the setting, restart PostgreSQL (listen_addresses needs a restart), test with inventory-check.',
      ],
      concepts: ['svc.listening', 'db.access'],
      learn: [{ label: 'Databases (PostgreSQL)', link: 'lesson/database/internals' }, { label: 'ss', link: 'reference?id=ss' }],
    }),
    ticketStep('smb-new-user', {
      id: 'fs01-carol', title: 'fs01: carol cannot open the share',
      objective: 'carol can list the office share from ws01 with her password.',
      background: `${METHOD}\n\nNT_STATUS_LOGON_FAILURE means the server **answered**: the network and smbd are fine, and the credentials were rejected. On Samba, a Unix account is not enough: Samba keeps its own password database.`,
      tasks: [
        'From ws01: `smbclient //fs01/office -U carol%Welcome-Carol1 -c ls` (the error), and the same for an existing user to compare.',
        'On fs01: `id carol`, `pdbedit -L`, and `tail /var/log/samba/log.ws01` (what does smbd say?).',
        'Give carol her Samba password (`smbpasswd -a carol`), then test again from ws01.',
      ],
      concepts: ['files.smb'],
      learn: [{ label: 'File sharing (SMB)', link: 'lesson/smb/internals' }, { label: 'smbpasswd', link: 'reference?id=smbpasswd' }],
    }),
    {
      id: 'verify', title: 'Verify every service, and after a reboot', stage: 'verify',
      objective: 'All four services work for their users, and still work after every machine restarts.',
      background: 'Four repairs on four machines: each must be persistent (a route added with ip route, a rule enabled only until the next policy refresh, a setting not written to the file would all come back broken). Verify from the users\' side, then reboot.',
      tasks: ['From ws01: ssh srv01.corp.lab, xfreerdp /v:win01.corp.lab /u:alice, smbclient //fs01/office -U carol%Welcome-Carol1 -c ls; on srv01: inventory-check.', 'Run the check (reboots every machine on a copy and repeats every check).'],
      hints: ['If one service fails only after the reboot, its fix lived in the running state only.'],
      checks: everything,
      solution: [],
      learn: [{ label: 'Network configuration and recovery', link: 'lesson/netops/what' }],
      concepts: ['net.ops'],
      afterReboot: true,
    },
  ],
  integrated: {
    number: 4,
    scenario: {
      organisation: 'corp.lab: Linux and Windows servers side by side, administered from the office.',
      situation: 'After a weekend of patching and hardening, four complaints arrive within ten minutes. The help desk has opened one ticket: "server network down?".',
      goal: 'Find the four separate causes, fix each persistently and verify from the users\' side.',
      whyItMatters: 'In real outages (and in competitions) several unrelated problems arrive together. Treating them as one ("the network is down") wastes time; classifying each by its evidence leads straight to the right machine and layer.',
    },
    technologies: ['IPv4 routing and default gateways', 'Linux nftables and Windows Defender Firewall', 'SSH and RDP', 'PostgreSQL listen addresses', 'Samba authentication', 'Evidence-based troubleshooting'],
    systems: [
      { host: 'ws01', role: 'alice\'s workstation (10.0.10.25), where the complaints come from' },
      { host: 'srv01', role: 'Web and application server (10.0.20.10): SSH, nginx, the inventory application' },
      { host: 'win01', role: 'Windows Server (10.0.20.30): Remote Desktop' },
      { host: 'db01', role: 'PostgreSQL server (10.0.20.35) for the inventory application' },
      { host: 'fs01', role: 'File server (10.0.20.60): NFS and Samba (the office share)' },
      { host: 'rtr01', role: 'Router between the office (VLAN 10) and the servers (VLAN 20)' },
    ],
    startingState: ['Four services fail for their users; everything else works (DNS, rtr01, the web site on srv01 from the server network, logons).', 'The causes are on four different machines and in four different layers.'],
    tools: [
      { command: 'ping, nc -z -w 3 HOST PORT', platform: 'Linux', use: 'Does the host answer? Does the port answer (refused) or not at all (timeout)?', refId: 'nc' },
      { command: 'ip route, ip -br addr', platform: 'Linux', use: 'Routing on the server', refId: 'ip' },
      { command: 'ss -tlnp', platform: 'Linux', use: 'Which address and port a service listens on', refId: 'ss' },
      { command: 'nft list ruleset, journalctl -u …', platform: 'Linux', use: 'Firewall and service logs', refId: 'journalctl' },
      { command: 'Test-NetConnection HOST -Port N', platform: 'Windows', use: 'Reachability and port test from Windows', refId: 'tnc' },
      { command: 'Get-NetFirewallRule, Get-NetTCPConnection, Get-Service', platform: 'Windows', use: 'Windows firewall, listeners and services', refId: 'get-netfirewallrule' },
      { command: 'pdbedit -L, smbpasswd -a, testparm', platform: 'Linux', use: 'Samba accounts and configuration', refId: 'smbpasswd' },
      { command: 'show ip route, show access-lists', platform: 'Cisco IOS', use: 'The same questions on a Cisco router (not simulated here)', refId: 'ios-show-ip-route' },
    ],
    dependencies: {
      explanation: `Every access from ws01 to a service crosses the same layers; the **first** one that fails decides what the user sees:

| Layer | Fails as | Check with |
|---|---|---|
| Name | "Could not resolve" | getent hosts, Resolve-DnsName |
| Route there and **back** | timeout (even ping) | ping, ip route on **both** ends |
| Firewall on the path / host | timeout (port only) | nc -z / Test-NetConnection; nft, Get-NetFirewallRule |
| Service listening | "Connection refused" | ss -tlnp, Get-NetTCPConnection |
| The service's own dependencies | an application error | the application's log, its dependency (e.g. the database) |
| Authentication | logon failure | the service's log (auth.log, Samba log, Security event log) |

A reply needs a route **back**: a server without a default gateway answers its own network and nobody else.`,
      paths: [
        {
          id: 'ssh', label: 'alice: SSH to srv01',
          nodes: [
            hop('dns', 'srv01.corp.lab resolves', 'ns1.', 'ws01', 'alice', 'getent hosts srv01.corp.lab', (o, c) => c === 0 && /srv01/.test(o)),
            hop('ping', 'srv01 answers ping', 'Routing there (rtr01) and back (srv01\'s default route).', 'ws01', 'alice', 'ping -c 1 -W 2 10.0.20.10', (_o, c) => c === 0),
            hop('port', 'TCP 22 answers', 'Firewall and sshd.', 'ws01', 'alice', 'nc -z -w 3 10.0.20.10 22', (_o, c) => c === 0),
            hop('login', 'Key login', 'alice\'s key.', 'ws01', 'alice', 'ssh -o BatchMode=yes srv01.corp.lab hostname', (o) => /^srv01$/m.test(o)),
          ],
        },
        {
          id: 'rdp', label: 'alice: Remote Desktop to win01',
          nodes: [
            hop('ping', 'win01 answers on the network', 'Routing (ICMP may be blocked by Windows: a failure here is not conclusive).', 'ws01', 'alice', 'getent hosts win01.corp.lab', (o, c) => c === 0 && /10\.0\.20\.30/.test(o)),
            hop('port', 'TCP 3389 answers', 'Windows Defender Firewall and TermService.', 'ws01', 'alice', 'nc -z -w 3 10.0.20.30 3389', (_o, c) => c === 0),
            { id: 'session', label: 'RDP session', role: 'Authentication and the logon right.', host: 'ws01', probe: (w) => { const g = { kind: 'rdp' as const, description: '', fromHost: 'ws01', localUser: 'alice', target: 'win01.corp.lab', user: 'alice', password: 'Corp-Lab-2026' }; const r = checkGoal(w, g); return { ok: r.ok, evidence: r.lines.filter(Boolean).slice(-5).join('\n') }; } },
          ],
        },
        {
          id: 'inventory', label: 'the inventory application reads its database',
          nodes: [
            hop('dns', 'db01.corp.lab resolves (from srv01)', 'ns1.', 'srv01', 'root', 'getent hosts db01.corp.lab', (o, c) => c === 0 && /10\.0\.20\.35/.test(o)),
            hop('port', 'TCP 5432 answers', 'PostgreSQL listening on the network address; db01\'s firewall.', 'srv01', 'root', 'nc -z -w 3 db01.corp.lab 5432', (_o, c) => c === 0),
            hop('query', 'Query answered', 'pg_hba.conf and the role\'s rights.', 'srv01', 'root', 'inventory-check', (o) => /^\d+$/m.test(o)),
          ],
        },
        {
          id: 'smb', label: 'carol opens the office share',
          nodes: [
            hop('port', 'TCP 445 answers', 'fs01\'s firewall and smbd.', 'ws01', 'alice', 'nc -z -w 3 10.0.20.60 445', (_o, c) => c === 0),
            hop('auth', 'carol\'s logon and the share', 'Samba\'s password database, valid users.', 'ws01', 'alice', 'smbclient //fs01/office -U carol%Welcome-Carol1 -c ls', (o) => /budget-2025\.txt/.test(o)),
          ],
        },
      ],
    },
    mistakes: [
      'Treating all four as "the network": the share answered with a logon failure, which proves the network works.',
      'Turning a firewall off instead of enabling the specific rule.',
      'Adding the missing route with ip route add only: the complaint returns after the next reboot.',
      'Restarting services that are not broken (sshd on srv01 is fine).',
      'Opening PostgreSQL to everything (listen_addresses = \'*\' plus a wide pg_hba.conf line) instead of restoring the intended setting.',
    ],
    verification: 'Each repair is checked the way the user experiences it (an SSH login with a key, an RDP session, the inventory query, listing the share), plus the constraints each ticket enforces (no disabled firewall, no wider access than needed). The verification step reboots every machine on a copy and repeats all checks.',
    fault: ticketFault('net-hosts-override', {
      title: 'One more: "No route to host", although DNS is right',
      report: 'alice (10:40): "Now ssh srv01.corp.lab fails with No route to host after a few seconds. I checked DNS with dig and it returns 10.0.20.10, which is correct!" She mentions that a colleague "set up a test entry on her machine last week".',
    }),
    review: [
      { id: 'q1', question: 'smbclient answers NT_STATUS_LOGON_FAILURE. Which layers are proven to work?', choices: ['Name resolution, the network path, the firewall and smbd: the server answered', 'Only DNS', 'Nothing: it could be any layer', 'Only the firewall'], answer: 0, explanation: 'A logon failure is an answer from the service. Everything below it must work to deliver that answer.', concepts: ['files.smb'] },
      { id: 'q2', question: 'Ping and SSH from the office to srv01 time out, but servers on srv01\'s own network reach it. What is the most likely cause?', choices: ['srv01 has no route back to other networks (default gateway missing)', 'sshd is stopped', 'The DNS record is wrong', 'alice\'s key is missing'], answer: 0, explanation: 'Local traffic needs no gateway; replies to another network do. sshd or the key would not make ping fail.', concepts: ['net.routing'] },
      { id: 'q3', question: 'What does "Connection refused" (instead of a timeout) tell you?', choices: ['The host answered: nothing listens on that port (or a firewall rejects actively)', 'A firewall dropped the packet silently', 'The route is missing', 'The password is wrong'], answer: 0, explanation: 'Refused is an answer (TCP RST or ICMP reject). A silent drop or a missing route produces a timeout.', concepts: ['tcp.handshake'] },
      { id: 'q4', question: 'The inventory site says "database unavailable"; the DBA can use psql on db01. What should you check next?', choices: ['Which address PostgreSQL listens on, and whether srv01 reaches db01:5432', 'The web server on srv01', 'The router', 'alice\'s password'], answer: 0, explanation: 'psql on the server uses a local connection. The application connects over the network, which needs the server to listen on a network address (and pg_hba.conf, and the firewall).', concepts: ['svc.listening'] },
      { id: 'q5', question: 'dig srv01.corp.lab returns the right address, but ssh srv01.corp.lab goes elsewhere. What explains it?', choices: ['The client resolves through /etc/hosts first; dig asks DNS directly', 'DNS caches are always wrong', 'ssh does not use DNS', 'The router rewrites the address'], answer: 0, explanation: 'Applications use the resolver (getent follows /etc/nsswitch.conf: files before dns). dig bypasses it, so compare dig with getent hosts.', concepts: ['dns.resolution'] },
    ],
    after: ['ipnet', 'nftables', 'windows-rdp', 'windows-firewall', 'smb', 'database'],
  },
};
