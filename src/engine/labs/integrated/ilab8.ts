// Integrated Lab 8: Restore a Multi-Service Outage. After a change window,
// nothing works for the office: no server is reachable, the intranet and the
// inventory site are down, the application reports database errors. Three
// independent changes caused it (router patching, a moved upstream on the
// reverse proxy, a PostgreSQL package update). The learner maps the impact,
// restores in dependency order (network first), verifies after each repair,
// and sees why restarting everything changes nothing.

import { buildSshLab } from '../../lab/sshLab';
import type { World } from '../../types';
import type { GuidedLab } from '../types';
import { hop } from './common';
import { applyTicket, ticketFault, ticketGoalChecks, ticketStep } from './tickets';

const TICKETS = ['net-ip-forward', 'proxy-host-not-found', 'db-listen-default'] as const;

export function buildIlab8World(): World {
  const w = buildSshLab();
  for (const id of TICKETS) applyTicket(w, id);
  w.clock += 10 * 60_000;
  return w;
}

const PRIORITY = 'Restore in **dependency order**: the network first (nothing above it can work or even be tested without it), then the shared services, then the applications. After each repair, **verify** before moving on: a repair that "should" work but was not tested hides the next problem.';

export const ILAB8: GuidedLab = {
  id: 'ilab8',
  title: 'Integrated Lab 8: Restore a Multi-Service Outage',
  level: 'advanced',
  duration: '60–90 min',
  summary: 'After a change window nothing works for the office. Map the impact, find the independent causes (routing, the reverse proxy, the database), restore them in dependency order with a verification after each repair, and resist the urge to restart everything. Then a security review breaks the server\'s outbound lookups.',
  brief: `Monday 07:45, after the weekend change window (patching rtr01, a reboot of srv01, PostgreSQL 15.8 on db01). The office reports:

- **no server is reachable** from the office: SSH to srv01 times out, so does the intranet;
- the web team says **nginx on srv01 does not even start** since its reboot;
- the application team: the **inventory site says "database unavailable"**, although the DBA can use psql on db01.

Management wants the intranet back first, then the inventory application. Restore every service, verify each repair, and leave every change persistent. Changes of the weekend: *rtr01: kernel and package updates (patch window)*; *srv01: the inventory API moved to dock01 on Friday, reboot on Sunday*; *db01: CHG-2520, postgresql 15.8, "install the package maintainer's version" at the configuration prompt*.`,
  objectives: [
    'Map the impact of an outage: which services, for whom, and what they depend on.',
    'Find several independent causes and restore them in dependency order (network, shared services, applications).',
    'Verify after each repair, and prove that the result survives a reboot.',
    'Explain why restarting every service rarely fixes an outage caused by configuration and dependencies.',
  ],
  prerequisites: [
    { label: 'Network configuration and recovery', link: 'lesson/netops/what' },
    { label: 'Web servers and reverse proxies', link: 'lesson/webproxy/what' },
    { label: 'Databases (PostgreSQL)', link: 'lesson/database/what' },
    { label: 'Infrastructure recovery', link: 'lesson/recovery/what' },
  ],
  setupNote: 'The standard lab network after a change window: rtr01 patched, srv01 rebooted, PostgreSQL updated on db01. dock01 runs the inventory API that srv01\'s reverse proxy publishes as apps.corp.lab.',
  terminals: [
    { hostId: 'ws01', user: 'alice', label: 'ws01 (alice, office)', banner: 'ws01 (alice). Try: ping -c 1 10.0.10.1, ping -c 1 10.0.20.10, ssh srv01.corp.lab, curl -sI https://www.corp.lab/, curl -s http://apps.corp.lab/inventory/health.' },
    { hostId: 'rtr01', user: 'root', label: 'rtr01 (router)', banner: 'rtr01 (root). Try: ip -br addr, ip route, sysctl net.ipv4.ip_forward, cat /etc/sysctl.d/*.conf.' },
    { hostId: 'srv01', user: 'root', label: 'srv01 (web, proxy, app)', banner: 'srv01 (root). Try: systemctl status nginx, journalctl -u nginx -n 10, nginx -t, inventory-check.' },
    { hostId: 'db01', user: 'root', label: 'db01 (PostgreSQL)', banner: 'db01 (root). Try: pg_lsclusters, ss -tlnp, grep listen_addresses /etc/postgresql/15/main/postgresql.conf.' },
    { hostId: 'dock01', user: 'root', label: 'dock01 (containers)', banner: 'dock01 (root): the inventory API container. Try: docker ps, curl -s http://localhost:8000/health.' },
  ],
  build: buildIlab8World,
  steps: [
    ticketStep('net-ip-forward', {
      id: 'network', title: 'Priority 1: the office reaches the servers again',
      goals: [0],
      objective: 'From the office, the server network is reachable again (alice logs in to srv01 over SSH), persistently.',
      background: `${PRIORITY}\n\n"Nothing on the server network answers the office" is a network symptom. Split the path: does ws01 reach its gateway (10.0.10.1)? Does the server reach its gateway (10.0.20.1)? Then the router must **forward** between them: what changed on rtr01 during patching?`,
      tasks: [
        'From ws01: `ping -c 1 10.0.10.1` (the router), `ping -c 1 10.0.20.1` (the router\'s other side), `ping -c 1 10.0.20.10` (srv01).',
        'On rtr01: `ip -br addr`, `ip route`, `sysctl net.ipv4.ip_forward`, and the files in /etc/sysctl.d/.',
        'Restore forwarding at runtime and in the configuration, then retest from ws01.',
      ],
      concepts: ['net.routing'],
      learn: [{ label: 'Routing', link: 'lesson/ipnet/internals' }, { label: 'sysctl', link: 'reference?id=sysctl' }],
    }),
    ticketStep('proxy-host-not-found', {
      id: 'web', title: 'Priority 2: the intranet and the reverse proxy',
      objective: 'https://www.corp.lab/ and http://apps.corp.lab/inventory/ answer again through nginx on srv01.',
      background: `${PRIORITY}\n\nnginx does not start, so both sites are down even though only one of them changed. When a service fails at start, a restart will fail the same way: read **why** (journalctl -u nginx, nginx -t). nginx resolves every upstream name when it loads its configuration; one unresolvable name stops the whole server.`,
      tasks: [
        'On srv01: `systemctl status nginx`, `journalctl -u nginx -n 10`, `nginx -t`.',
        'Which upstream does the configuration name, and does it resolve (`getent hosts …`)? Where does the inventory API run now (Friday\'s move)?',
        'Fix the upstream, `nginx -t`, `systemctl start nginx`, then test both sites from ws01.',
      ],
      concepts: ['web.proxy', 'dns.resolution'],
      learn: [{ label: 'Reverse proxies', link: 'lesson/webproxy/internals' }, { label: 'nginx', link: 'reference?id=nginx' }],
    }),
    ticketStep('db-listen-default', {
      id: 'database', title: 'Priority 3: the inventory database',
      objective: 'The inventory application on srv01 gets answers from its database on db01 again.',
      background: `${PRIORITY}\n\nThe application\'s error names its dependency. The database runs (the DBA uses psql locally), so test it the way the application connects: over the network from srv01. A package update that replaced the configuration file can silently undo a local setting.`,
      tasks: [
        'On srv01: `inventory-check`, `nc -z -w 3 db01.corp.lab 5432`.',
        'On db01: `ss -tlnp | grep 5432` and `grep -n listen_addresses /etc/postgresql/15/main/postgresql.conf` (and the .dpkg-old file, if there is one).',
        'Restore the setting, restart PostgreSQL (listen_addresses needs a restart), test with inventory-check.',
      ],
      concepts: ['svc.listening', 'db.access'],
      learn: [{ label: 'PostgreSQL configuration', link: 'lesson/database/config' }],
    }),
    {
      id: 'verify', title: 'Verify every service, and after a reboot', stage: 'verify',
      objective: 'Every service the office uses works, and still works after every machine restarts.',
      background: 'Three repairs on three machines. The proof is from the users\' side and after a reboot: a forwarding switched on with sysctl -w only, an nginx started by hand but not enabled, or a setting not written to the file would come back as the next outage.',
      tasks: ['From ws01: ssh srv01.corp.lab, curl -sI https://www.corp.lab/, curl -s http://apps.corp.lab/inventory/health; on srv01: inventory-check.', 'Run the check (reboots every machine on a copy and repeats every check).'],
      hints: ['A service that works now but not after the reboot was fixed at runtime only.'],
      checks: TICKETS.flatMap((id) => ticketGoalChecks(id)),
      solution: [],
      learn: [{ label: 'Infrastructure recovery', link: 'lesson/recovery/operate' }],
      concepts: ['ops.recovery'],
      afterReboot: true,
    },
  ],
  integrated: {
    number: 8,
    scenario: {
      organisation: 'corp.lab: a weekend change window touched the router, the web/proxy server and the database server.',
      situation: 'Monday morning the office cannot reach any server, nginx on srv01 does not start, and the inventory application cannot reach its database. Three teams each say "our change was fine".',
      goal: 'Restore every service in the right order, verify each repair, and leave the infrastructure in a state that survives the next reboot.',
      whyItMatters: 'Outages after change windows are usually several small, independent problems at once. Fixing them in dependency order and verifying each one is faster than parallel guessing, and in a competition it decides how quickly points come back.',
    },
    technologies: ['IPv4 forwarding on a Linux router (sysctl)', 'nginx reverse proxy and upstream resolution', 'systemd start failures and the journal', 'PostgreSQL listen_addresses and package updates', 'Dependency-ordered recovery'],
    systems: [
      { host: 'rtr01', role: 'Router between the office (10.0.10.0/24) and the servers (10.0.20.0/24), patched' },
      { host: 'srv01', role: 'Intranet (https://www.corp.lab) and reverse proxy (apps.corp.lab), rebooted' },
      { host: 'dock01', role: 'Runs the inventory API (port 8000) since Friday' },
      { host: 'db01', role: 'PostgreSQL for the inventory application, updated' },
      { host: 'ws01', role: 'The office' },
    ],
    startingState: ['rtr01 does not forward packets between its networks.', 'nginx on srv01 failed to start after the reboot.', 'PostgreSQL on db01 listens on localhost only.', 'Everything else (DNS, the containers on dock01, logins on each machine) works.'],
    tools: [
      { command: 'ping (step by step along the path)', platform: 'Linux', use: 'Which segment of the path fails', refId: 'ping-linux' },
      { command: 'sysctl net.ipv4.ip_forward, /etc/sysctl.d/', platform: 'Linux', use: 'Routing on a Linux router, at runtime and at boot', refId: 'sysctl' },
      { command: 'systemctl status, journalctl -u, nginx -t', platform: 'Linux', use: 'Why a service did not start', refId: 'systemctl' },
      { command: 'ss -tlnp, nc -z -w 3', platform: 'Linux', use: 'Where a service listens; whether a port answers from a client', refId: 'ss' },
      { command: 'pg_lsclusters, postgresql.conf', platform: 'Linux', use: 'PostgreSQL state and settings', refId: 'psql' },
      { command: 'Test-NetConnection, tracert', platform: 'Windows', use: 'The same path tests from a Windows client', refId: 'tracert' },
      { command: 'show ip route, show ip interface brief', platform: 'Cisco IOS', use: 'Routing checks on a Cisco router (not simulated)', refId: 'ios-show-ip-int-brief' },
    ],
    dependencies: {
      explanation: `What the office uses, and what each needs (bottom first):

1. **Routing**: ws01 → rtr01 → the server network. Without it, nothing on the servers can even be **tested** from the office: fix it first.
2. **nginx on srv01**: serves the intranet **and** proxies apps.corp.lab. It resolves every upstream name at start; one bad name and **both** sites are down.
3. **The inventory API on dock01** behind the proxy.
4. **PostgreSQL on db01**, which srv01's application reaches over the network.

**Why "restart everything" fails**: rtr01 reads its forwarding setting from the configuration at boot; nginx fails on the same line on every start; PostgreSQL reads the same listen_addresses on every restart. A restart only helps when the running state, not the configuration, is wrong.`,
      paths: [
        {
          id: 'office-srv01', label: 'the office reaches srv01',
          nodes: [
            hop('gw', 'ws01 reaches its gateway', 'rtr01 on the office network (10.0.10.1).', 'ws01', 'alice', 'ping -c 1 -W 2 10.0.10.1', (_o, c) => c === 0),
            hop('far', 'The router\'s server side answers', 'rtr01 itself on 10.0.20.1 (answered by the router, not forwarded).', 'ws01', 'alice', 'ping -c 1 -W 2 10.0.20.1', (_o, c) => c === 0),
            hop('fwd', 'srv01 answers', 'rtr01 forwards between the networks.', 'ws01', 'alice', 'ping -c 1 -W 2 10.0.20.10', (_o, c) => c === 0),
            hop('ssh', 'SSH to srv01', 'sshd and alice\'s key.', 'ws01', 'alice', 'ssh -o BatchMode=yes srv01.corp.lab hostname', (o) => /^srv01$/m.test(o)),
          ],
        },
        {
          id: 'web', label: 'the office opens the intranet and the inventory site',
          nodes: [
            hop('nginx', 'nginx runs on srv01', 'Started with a valid configuration (every upstream resolvable).', 'srv01', 'root', 'systemctl is-active nginx', (o) => /^active/m.test(o)),
            hop('intranet', 'The intranet answers', 'https://www.corp.lab/', 'ws01', 'alice', 'curl -sI -m 5 https://www.corp.lab/', (o) => /^HTTP\/1\.1 200/.test(o)),
            hop('proxy', 'The inventory site answers through the proxy', 'apps.corp.lab → dock01:8000.', 'ws01', 'alice', 'curl -s -m 5 http://apps.corp.lab/inventory/health', (o, c) => c === 0 && /ok|status/i.test(o)),
          ],
        },
        {
          id: 'db', label: 'the application reaches its database',
          nodes: [
            hop('port', 'db01:5432 answers from srv01', 'PostgreSQL on its network address.', 'srv01', 'root', 'nc -z -w 3 db01.corp.lab 5432', (_o, c) => c === 0),
            hop('query', 'The query is answered', 'pg_hba.conf and the role.', 'srv01', 'root', 'inventory-check', (o) => /^\d+$/m.test(o)),
          ],
        },
      ],
    },
    mistakes: [
      'Starting with the most visible complaint (the web site) while the network underneath is broken: none of the tests from the office can succeed.',
      'Restarting nginx, PostgreSQL and the router repeatedly: each comes back with the same configuration and the same failure.',
      'Enabling forwarding with sysctl -w only: the next reboot of rtr01 brings the outage back.',
      'Removing the apps.corp.lab block to get nginx started: the intranet works again, the inventory site stays down.',
      'Closing the incident after the first service works, without checking the others.',
    ],
    verification: 'Each repair is verified as the office experiences it (SSH, both web sites through nginx, the application\'s database query), with the tickets\' constraints (the proxy design stays, PostgreSQL is not opened wider than needed). The final check reboots every machine on a copy and repeats every check. The incident is repaired when srv01 resolves names again with its firewall still default-deny.',
    fault: ticketFault('fw-no-established', {
      title: 'After the security review: srv01 cannot look anything up',
      report: 'srv01 admin (Tuesday, after the security team reviewed srv01\'s firewall): "apt update fails with Temporary failure resolving deb.debian.org, and the application on srv01 cannot reach the database by name. Inbound SSH and the website work fine. Ping to ns1 works too!"',
    }),
    review: [
      { id: 'q1', question: 'Three things are broken: routing between the office and the servers, nginx on srv01, and the database\'s listen address. In which order do you work?', choices: ['Routing first: without it nothing on the servers can be reached or tested from the office', 'The database first: it is the deepest layer', 'nginx first: it is what users see', 'All at once by restarting the servers'], answer: 0, explanation: 'Dependency order: the network carries every test you will make afterwards. Then the shared service (nginx serves two sites), then the application\'s backend.', concepts: ['ops.recovery'] },
      { id: 'q2', question: 'nginx fails to start and both the intranet and the inventory site are down, although only the inventory upstream changed. Why?', choices: ['nginx resolves every upstream at start; one unresolvable name stops the whole server', 'The intranet uses the inventory API', 'The certificate expired', 'The firewall blocks port 443'], answer: 0, explanation: 'A configuration error anywhere in nginx.conf prevents the master from starting, which takes every site with it.', concepts: ['web.proxy'] },
      { id: 'q3', question: 'ws01 pings 10.0.20.1 (the router\'s server-side address) but not 10.0.20.10. What does that tell you?', choices: ['The router answers for its own addresses, but does not forward to other hosts', 'srv01\'s firewall drops everything', 'DNS is broken', 'The cable to rtr01 is unplugged'], answer: 0, explanation: 'The router answers pings to any of its addresses itself; reaching a host behind it needs forwarding.', concepts: ['net.routing'] },
      { id: 'q4', question: 'Why does restarting PostgreSQL not fix "database unavailable" here?', choices: ['It reads the same listen_addresses (localhost) from the replaced configuration file on every start', 'Restarting clears the database', 'Clients cache the error', 'PostgreSQL needs a reboot'], answer: 0, explanation: 'The configuration is wrong, not the running state; a restart reproduces the problem exactly.', concepts: ['svc.listening'] },
      { id: 'q5', question: 'After the security review, srv01 can be reached (SSH, web) but cannot resolve names, although ping to ns1 works. Which rule is missing?', choices: ['ct state established,related accept: the DNS replies are dropped by the default-drop input chain', 'An output rule for port 53', 'A rule for ICMP', 'A NAT rule'], answer: 0, explanation: 'Replies to connections srv01 opens arrive as input; without the stateful rule the default drop discards them. Inbound services work because their ports are explicitly allowed.', concepts: ['fw.stateful'] },
    ],
    after: ['netops', 'webproxy', 'database', 'recovery', 'nftables'],
  },
};
