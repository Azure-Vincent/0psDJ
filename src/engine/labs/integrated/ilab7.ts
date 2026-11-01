// Integrated Lab 7: Investigate an Enterprise DNS Failure. Several unrelated
// services stop at once: SSH, the intranet, builds in the development VLAN,
// the Windows servers' lookups of internal names. The learner gathers
// evidence on Linux, Windows and containers, finds the shared dependency,
// repairs it, and then verifies every dependent service, not just DNS. The
// incident: the zone is regenerated without its service (SRV) records and
// Kerberos breaks while everything else works.

import { ALICE_SERVER_PASSWORD, buildSshLab } from '../../lab/sshLab';
import { checkGoal } from '../../scenarios/engine';
import type { World } from '../../types';
import { NO, OK, printfTo } from '../engine';
import type { GuidedLab, LabCheck } from '../types';
import { cmdCheck, hop } from './common';
import { applyTicket, ticketFault, ticketGoalChecks, ticketStep } from './tickets';

export function buildIlab7World(): World {
  const w = buildSshLab();
  applyTicket(w, 'case-dns-outage');
  w.clock += 3 * 60_000;
  return w;
}

/** alice gets a ticket from the KDC on ns1 (kinit). */
const kinitWorks: LabCheck = {
  id: 'kinit', description: 'On ws01, alice gets a Kerberos ticket from the KDC on ns1 (kinit)',
  check(w) {
    const r = checkGoal(w, { kind: 'kerberos', description: '', fromHost: 'ws01', localUser: 'alice', password: ALICE_SERVER_PASSWORD });
    return r.ok ? OK('kinit gets a ticket-granting ticket.') : NO(r.lines.filter(Boolean).slice(-2).join(' '));
  },
};

/** ns1's firewall from CHG-2207, corrected (/16) and with the KDC allowed. */
const NS1_NFT_DONE = `#!/usr/sbin/nft -f
# CHG-2207: harden ns1 (default deny). DNS and Kerberos for the internal networks only.
flush ruleset
table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		ct state invalid drop
		iif "lo" accept
		meta l4proto icmp accept
		meta l4proto ipv6-icmp accept
		tcp dport 22 accept
		udp dport 67 accept
		ip saddr 10.0.0.0/16 udp dport 53 accept
		ip saddr 10.0.0.0/16 tcp dport 53 accept
		# Kerberos KDC, kpasswd and kadmin (ns1 is the KDC for CORP.LAB)
		ip saddr 10.0.0.0/16 udp dport 88 accept
		ip saddr 10.0.0.0/16 tcp dport { 88, 464, 749 } accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

const dependents = [
  ...ticketGoalChecks('case-dns-outage'),
  cmdCheck('win01-names', 'win01 (Windows) resolves internal names', 'win01', 'Administrator', 'Resolve-DnsName www.corp.lab', (o) => (/10\.0\.20\.10|srv01/.test(o) ? null : 'win01 cannot resolve www.corp.lab.'), 'Windows clients resolve.'),
  cmdCheck('dc01-forward', 'dc01 resolves corp.lab names through its forwarder (ns1)', 'dc01', 'Administrator', 'Resolve-DnsName www.corp.lab', (o) => (/10\.0\.20\.10|srv01/.test(o) ? null : 'dc01 cannot resolve www.corp.lab.'), 'The domain\'s DNS forwards to ns1 again.'),
  kinitWorks,
  cmdCheck('app-db-name', 'The inventory application on srv01 reaches its database by name (db01.corp.lab)', 'srv01', 'root', 'inventory-check', (o) => (/^\d+$/m.test(o) ? null : 'inventory-check fails.'), 'Applications that use names work again.'),
];

export const ILAB7: GuidedLab = {
  id: 'ilab7',
  title: 'Integrated Lab 7: Investigate an Enterprise DNS Failure',
  level: 'advanced',
  duration: '45–75 min',
  summary: 'Several unrelated services fail at once, on Linux, Windows and in the development VLAN. Collect evidence on each platform, find the dependency they share, repair it with one change, and verify every service that depends on it. Then a regenerated zone breaks Kerberos while everything else keeps working.',
  brief: `09:02, three tickets in ten minutes and more coming:

- **alice** (office): "ssh srv01 says *Could not resolve hostname*."
- **dana** (old laptop ws02): "The intranet site is down."
- **erin** (developers, VLAN 30): "Our build cannot find www.corp.lab."
- The **Windows team**: "win01 cannot look up internal servers."
- The **web team** says nginx on srv01 is running; the **SSH team** says sshd is fine; **ns1 is up** (it answers ping and SSH).

Find out whether these failures share a cause, fix it, and prove that every affected service works again. Last night's change log has one entry for ns1: *CHG-2207: default-deny firewall on ns1, allow DNS from the internal networks*.`,
  objectives: [
    'Recognise a shared dependency behind several "unrelated" outages, and test it directly (by IP vs by name).',
    'Read DNS evidence on Linux (getent, dig), Windows (Resolve-DnsName, nslookup) and from containers.',
    'Repair with one targeted change and verify every dependent service, not only the component you fixed.',
    'Understand how DNS also carries service locations (SRV records) for Kerberos and Active Directory.',
  ],
  prerequisites: [
    { label: 'TCP, UDP and DNS', link: 'lesson/transport/what' },
    { label: 'Host firewalls (nftables)', link: 'lesson/nftables/what' },
    { label: 'Kerberos and DNS service records', link: 'lesson/kerberos/what' },
  ],
  setupNote: 'The standard lab network. ns1 (10.0.10.53) is the DNS server for every network; dc01 forwards non-AD names to it; containers on dock01 use it too.',
  terminals: [
    { hostId: 'ws01', user: 'alice', label: 'ws01 (alice, office)', banner: 'ws01 (alice). Try: ssh srv01.corp.lab, ssh 10.0.20.10, getent hosts srv01.corp.lab, dig srv01.corp.lab, dig @10.0.10.53 srv01.corp.lab.' },
    { hostId: 'dev01', user: 'root', label: 'dev01 (VLAN 30)', banner: 'dev01 (root), development VLAN. Try: getent hosts www.corp.lab, cat /etc/resolv.conf.' },
    { hostId: 'win01', user: 'Administrator', label: 'win01 (PowerShell)', banner: 'Windows PowerShell\nwin01. Try: Resolve-DnsName www.corp.lab, Get-DnsClientServerAddress, nslookup www.corp.lab.' },
    { hostId: 'ns1', user: 'root', label: 'ns1 (DNS server)', banner: 'ns1 (root): BIND. Try: systemctl status named, ss -ulnp, dig @127.0.0.1 srv01.corp.lab, nft list ruleset, tcpdump -n -i eth0 port 53.' },
    { hostId: 'srv01', user: 'root', label: 'srv01 (web and app)', banner: 'srv01 (root). Try: inventory-check, getent hosts db01.corp.lab, systemctl status nginx.' },
  ],
  build: buildIlab7World,
  steps: [
    ticketStep('case-dns-outage', {
      id: 'shared-cause', title: 'Find the shared dependency and fix it',
      objective: 'Name resolution works again from every network (office, development VLAN, servers), with ns1 still behind a default-deny firewall.',
      background: 'When many services fail at the same moment, look for what they **share** before investigating each one. A quick split: does the operation work **by IP address**? If yes, the services are fine and the shared dependency is **name resolution**.\n\nThen locate the DNS failure: does the client get an **error** from the server (SERVFAIL, NXDOMAIN) or **no answer at all** ("connection timed out; no servers could be reached")? Does the server answer **itself** (dig @127.0.0.1)? A server that answers locally but not to clients points at something between them.',
      tasks: [
        'On ws01: `ssh 10.0.20.10` and `curl -sI http://10.0.20.10/` (by IP), then `dig srv01.corp.lab` (by name).',
        'On win01: `Resolve-DnsName www.corp.lab`. On dev01: `getent hosts www.corp.lab`. Same symptom?',
        'On ns1: `dig @127.0.0.1 srv01.corp.lab`, `ss -ulnp | grep :53`, `nft list ruleset`. Compare the rule\'s network with the clients\' addresses.',
        'Fix /etc/nftables.conf (keep the default deny), check it (`nft -c -f`), load it, and test from each network.',
      ],
      concepts: ['dns.resolution', 'net.cidr', 'fw.stateful'],
      learn: [{ label: 'DNS', link: 'lesson/transport/internals' }, { label: 'dig', link: 'reference?id=dig' }, { label: 'Resolve-DnsName', link: 'reference?id=resolve-dnsname' }],
    }),
    {
      id: 'kerberos', title: 'Check the other dependents: Kerberos',
      objective: 'alice gets a Kerberos ticket again, with ns1 still behind its default-deny firewall.',
      background: 'Names resolve again, so the incident looks closed. But **ns1 is more than a DNS server**: it is also the Kerberos KDC for CORP.LAB (port 88, kadmin on 749, password changes on 464). The same change that broke DNS may have hidden a second failure: while names did not resolve, kinit failed earlier and for a different reason.\n\nAfter fixing a shared dependency, walk through **every service on the machine you changed** and every service that depends on it.',
      tasks: [
        'On ws01: `kinit` (alice\'s password: Corp-Lab-2026). What does it say now?',
        'On ns1: `ss -ulnp`, `ss -tlnp`: what else listens besides named? Is it allowed in /etc/nftables.conf?',
        'Allow the KDC (UDP and TCP 88) and kadmin/kpasswd (TCP 749, 464) for the internal networks, check and load the file, then `kinit` and `klist` again.',
      ],
      hints: ['"Cannot contact any KDC" means the client found the KDC\'s address (DNS works) but got no answer from it.', 'Compare with the error before the DNS fix: different message, different layer.'],
      checks: [kinitWorks],
      solution: [{ host: 'ns1', user: 'root', commands: [printfTo(NS1_NFT_DONE, '/etc/nftables.conf'), 'nft -c -f /etc/nftables.conf', 'nft -f /etc/nftables.conf'] }],
      learn: [{ label: 'Kerberos', link: 'lesson/kerberos/internals' }, { label: 'Kerberos diagnosis', link: 'reference?id=proc:kerberos-diagnose' }],
      concepts: ['ad.kerberos', 'fw.stateful'],
    },
    {
      id: 'verify', title: 'Verify every dependent service, and after a reboot', stage: 'verify',
      objective: 'Every service that failed works again for its users (SSH, the intranet, builds, Windows lookups, the application\'s database connection), also after every machine restarts.',
      background: 'Fixing the shared cause is not the end: services may have cached failures, or have a second, independent problem the first one hid. Check each symptom from the user\'s side. A resolver that works on Linux tells you nothing about Windows clients that resolve through the DC\'s forwarder, or containers with their own DNS settings.',
      tasks: ['From ws01: `ssh srv01.corp.lab`; from ws02: `curl -I http://srv01.corp.lab/`; from dev01: `getent hosts www.corp.lab`; on win01: `Resolve-DnsName www.corp.lab`; on srv01: `inventory-check`.', 'Run the check (reboots every machine on a copy and repeats every check).'],
      hints: ['If a check fails only after the reboot, the firewall fix is not in /etc/nftables.conf.'],
      checks: dependents,
      solution: [],
      learn: [{ label: 'Network configuration and recovery', link: 'lesson/netops/what' }],
      concepts: ['dns.resolution'],
      afterReboot: true,
    },
  ],
  integrated: {
    number: 7,
    scenario: {
      organisation: 'corp.lab: one DNS server (ns1) serves every network; Windows servers resolve through the domain controller, which forwards to ns1; containers use ns1 too.',
      situation: 'Overnight, ns1 got a default-deny firewall (CHG-2207). In the morning, SSH, the intranet, builds and Windows lookups fail, and every team says its own service is fine.',
      goal: 'Find the common cause, restore name resolution for every network with one correct change, and verify every dependent service.',
      whyItMatters: '"Everything is broken" is usually one broken dependency. Recognising it saves hours of parallel investigations, and in a competition it is the difference between restoring one service and restoring all of them at once.',
    },
    technologies: ['DNS (BIND, resolvers, forwarders)', 'nftables on a DNS server (CIDR prefixes)', 'Linux, Windows and container resolvers', 'SRV records for Kerberos and AD', 'SSH, HTTP and database clients as DNS consumers'],
    systems: [
      { host: 'ns1', role: 'DNS for corp.lab (10.0.10.53), with a new default-deny firewall' },
      { host: 'ws01', role: 'alice\'s office workstation (Linux)' },
      { host: 'ws02', role: 'dana\'s old laptop in the office (Linux, DHCP)' },
      { host: 'dev01', role: 'Development VLAN 30 (dual-stack)' },
      { host: 'win01', role: 'Windows Server: resolves through ns1' },
      { host: 'dc01', role: 'Domain controller: its DNS service forwards non-AD names to ns1' },
      { host: 'srv01', role: 'Intranet and the inventory application (connects to db01 by name)' },
    ],
    startingState: ['ns1: named and the Kerberos KDC running; a new nftables configuration with policy drop.', 'Every client fails to resolve names; everything works by IP address.'],
    tools: [
      { command: 'getent hosts NAME', platform: 'Linux', use: 'Resolve as applications do (nsswitch: /etc/hosts, then DNS)', refId: 'getent' },
      { command: 'dig NAME, dig @SERVER NAME', platform: 'Linux', use: 'Ask DNS directly; error vs no answer', refId: 'dig' },
      { command: 'Resolve-DnsName, nslookup', platform: 'Windows', use: 'The same on Windows', refId: 'resolve-dnsname' },
      { command: 'ss -ulnp, nft list ruleset, tcpdump -n port 53', platform: 'Linux', use: 'On the server: listening? filtered? packets arriving?', refId: 'tcpdump' },
      { command: 'host -t SRV _kerberos._udp.corp.lab', platform: 'Linux', use: 'Service records', refId: 'dig' },
      { command: 'docker exec … getent hosts', platform: 'Linux', use: 'Name resolution inside a container', refId: 'docker' },
    ],
    dependencies: {
      explanation: `Almost every service depends on DNS, often in ways users never see:

- **SSH, web, builds**: the client resolves the server's name before connecting.
- **Applications**: srv01's inventory application connects to **db01.corp.lab**.
- **Windows**: win01 asks ns1 directly; the domain controller **dc01** answers for ad.corp.lab and **forwards** everything else to ns1, so an ns1 failure also reaches every domain member indirectly.
- **ns1 itself runs more than DNS**: it is also the Kerberos KDC. A firewall change for "DNS only" can break that too.
- **Kerberos and Active Directory**: clients find KDCs and domain controllers through **SRV records** (_kerberos._udp, _ldap._tcp). A zone that loses them breaks logons while every A record still works.
- **Containers**: dockerd gives containers ns1 as their DNS server.

So: when several services fail together, test the shared dependency first: **by name vs by IP**, then **error vs no answer**, then **the server itself vs from the network**.`,
      paths: [
        {
          id: 'office', label: 'alice: ssh srv01.corp.lab (Linux client)',
          nodes: [
            hop('ip', 'srv01 answers by IP', 'Routing and the service itself, without DNS.', 'ws01', 'alice', 'nc -z -w 3 10.0.20.10 22', (_o, c) => c === 0),
            hop('dns-server', 'ns1 answers on the network', 'ns1\'s firewall must let the client\'s network in on port 53.', 'ws01', 'alice', 'dig @10.0.10.53 srv01.corp.lab +short', (o) => /10\.0\.20\.10/.test(o)),
            hop('resolver', 'The client resolves the name', 'The resolver in /etc/resolv.conf.', 'ws01', 'alice', 'getent hosts srv01.corp.lab', (o, c) => c === 0 && /srv01/.test(o)),
            hop('ssh', 'SSH by name', 'The whole chain.', 'ws01', 'alice', 'ssh -o BatchMode=yes srv01.corp.lab hostname', (o) => /^srv01$/m.test(o)),
          ],
        },
        {
          id: 'windows', label: 'the domain controller looks up www.corp.lab (Windows, through its forwarder)',
          nodes: [
            hop('dc', 'dc01 is its own DNS server', 'A DC resolves through its own DNS service.', 'dc01', 'Administrator', 'Get-DnsClientServerAddress', (o) => /127\.0\.0\.1/.test(o)),
            hop('forward', 'dc01 forwards to ns1 and gets an answer', 'dc01 → ns1 (10.0.10.53): behind ns1\'s firewall too.', 'dc01', 'Administrator', 'Resolve-DnsName www.corp.lab', (o) => /10\.0\.20\.10|srv01/.test(o)),
          ],
        },
        {
          id: 'kerberos', label: 'alice gets a Kerberos ticket (kinit)',
          nodes: [
            hop('srv', 'The KDC\'s SRV record resolves', '_kerberos._udp.corp.lab in the zone: how clients find the KDC.', 'ws01', 'alice', 'host -t SRV _kerberos._udp.corp.lab', (o) => /has SRV record/.test(o)),
            hop('port', 'The KDC answers on port 88', 'krb5kdc on ns1, allowed by ns1\'s firewall.', 'ws01', 'alice', 'nc -z -w 3 10.0.10.53 88', (_o, c) => c === 0),
            { id: 'kinit', label: 'kinit gets a ticket', role: 'The whole Kerberos exchange (AS-REQ/AS-REP).', host: 'ws01', probe: (w) => { const r = checkGoal(w, { kind: 'kerberos', description: '', fromHost: 'ws01', localUser: 'alice', password: ALICE_SERVER_PASSWORD }); return { ok: r.ok, evidence: r.lines.filter(Boolean).slice(-4).join('\n') }; } },
          ],
        },
        {
          id: 'app', label: 'the inventory application connects to db01.corp.lab',
          nodes: [
            hop('dns', 'srv01 resolves db01.corp.lab', 'srv01 → ns1 across the router.', 'srv01', 'root', 'getent hosts db01.corp.lab', (o) => /10\.0\.20\.35/.test(o)),
            hop('query', 'The database answers', 'PostgreSQL on db01.', 'srv01', 'root', 'inventory-check', (o) => /^\d+$/m.test(o)),
          ],
        },
      ],
    },
    mistakes: [
      'Investigating each ticket separately (restarting nginx, sshd, the build) while all of them share one cause.',
      'Seeing "ns1 answers ping and SSH" and concluding DNS is fine: only port 53 matters.',
      'Removing ns1\'s firewall entirely instead of fixing the rule.',
      'Writing /24 for "the internal networks": 10.0.0.0/24 covers 10.0.0.0–10.0.0.255 only.',
      'Stopping after the first client works: Windows, the DC\'s forwarder, applications and Kerberos are separate consumers.',
      'Fixing only DNS on ns1 when the same change also blocked the KDC on the same machine.',
    ],
    verification: 'Checks repeat each user\'s failing operation (SSH by name from the office, the intranet from ws02, a lookup from VLAN 30, a lookup on Windows, the application\'s database query) and enforce that ns1 keeps a default-deny firewall. The final check reboots every machine and repeats them. The incident is repaired when Kerberos finds its KDC through DNS again.',
    fault: ticketFault('krb-missing-srv', {
      title: 'Kerberos cannot find its KDC after the zone was regenerated',
      report: 'Service desk (next morning): "Nobody in the office can get a Kerberos ticket since this morning: kinit: Cannot find KDC for realm CORP.LAB. Everything else works: web, SSH with keys, names." Network team: "We regenerated the corp.lab zone from the IPAM export last night (NET-95)."',
    }),
    review: [
      { id: 'q1', question: 'SSH, the intranet and the build all fail; all of them work by IP address. What is the most efficient next step?', choices: ['Test name resolution directly (dig/getent) from a client and from the DNS server itself', 'Restart nginx, sshd and the build', 'Reboot the router', 'Check each service\'s logs one by one'], answer: 0, explanation: 'Working by IP proves the services and the network are fine; the shared dependency is DNS. Test it directly before touching anything else.', concepts: ['dns.resolution'] },
      { id: 'q2', question: 'dig from a client says "connection timed out; no servers could be reached", while dig @127.0.0.1 on ns1 answers. What does that locate?', choices: ['Between the client and named: a firewall or the network on port 53', 'The zone file is broken', 'named is stopped', 'The client\'s /etc/hosts'], answer: 0, explanation: 'A broken zone gives SERVFAIL and a stopped named would not answer locally. No answer to remote clients while local queries work points at filtering.', concepts: ['fw.path', 'dns.resolution'] },
      { id: 'q3', question: 'Domain members use dc01 as their DNS server. Why would they still lose corp.lab names when ns1 fails?', choices: ['dc01 forwards non-AD names to ns1, so it inherits ns1\'s outage', 'Windows caches failures for a day', 'dc01 was also firewalled', 'Windows uses /etc/resolv.conf'], answer: 0, explanation: 'Forwarders create indirect dependencies: the DC answers its own zone and forwards the rest.', concepts: ['ad.dns'] },
      { id: 'q6', question: 'After the DNS fix, kinit says "Cannot contact any KDC" (before the fix it failed to resolve). What changed?', choices: ['DNS now works and finds the KDC, but the KDC\'s port on ns1 is still blocked: a second problem hidden by the first', 'The password expired', 'The SRV records are missing', 'The client clock is wrong'], answer: 0, explanation: 'A new error message means you moved one layer further. ns1 also runs the KDC, and the "DNS only" firewall blocks port 88.', concepts: ['ad.kerberos', 'fw.stateful'] },
      { id: 'q4', question: 'After a zone was regenerated, kinit says "Cannot find KDC", yet every host name resolves. What is missing?', choices: ['The SRV records (_kerberos._udp/_tcp) that tell clients where the KDC is', 'The A record of ns1', 'The reverse zone', 'The KDC\'s keytab'], answer: 0, explanation: 'With dns_lookup_kdc, clients locate the KDC through SRV records. AD members find DCs the same way (_ldap._tcp).', concepts: ['ad.dns', 'ad.kerberos'] },
      { id: 'q5', question: 'Which prefix covers 10.0.10.0/24, 10.0.20.0/24 and 10.0.30.0/24?', choices: ['10.0.0.0/16', '10.0.0.0/24', '10.0.10.0/22', '10.0.0.0/30'], answer: 0, explanation: '/16 fixes the first two octets (10.0.x.x). /24 fixes three (10.0.0.x only).', concepts: ['net.cidr'] },
    ],
    after: ['transport', 'nftables', 'kerberos', 'ad-kerberos', 'netops'],
  },
};
