// DHCP and NAT tickets. DHCP: ns1 serves the office LAN; ws02 (dana) is a DHCP
// client. NAT: rtr01 masquerades the private networks on eth2 (203.0.113.2)
// and forwards public port 80 to srv01; ext01 (203.0.113.80) is on the Internet.

import { readFile, writeFile } from '../fs';
import { formatLease } from '../config/dhcpd';
import { explainPacket } from '../config/nft';
import type { World } from '../types';
import { firewallStillRestrictive, script } from './engine';
import type { Constraint, Goal, Scenario } from './types';

const DANA_WEB: Goal = { kind: 'http', description: 'On ws02 (DHCP client), "curl -I http://srv01.corp.lab/" returns HTTP 200.', fromHost: 'ws02', fromUser: 'dana', url: 'http://srv01.corp.lab/' };
const OFFICE_TO_INTERNET: Goal = { kind: 'http', description: 'From ws01, "curl -I http://203.0.113.80/" (a web server on the Internet) returns HTTP 200.', fromHost: 'ws01', fromUser: 'alice', url: 'http://203.0.113.80/' };
const INTERNET_TO_WEB = (port?: number): Goal => ({ kind: 'http', description: `From the Internet host ext01, "curl -I http://203.0.113.2${port ? ':' + port : ''}/" (the published intranet web server) returns HTTP 200.`, fromHost: 'ext01', fromUser: 'guest', url: `http://203.0.113.2${port ? ':' + port : ''}/` });

const DHCP_TERMINALS = [
  { hostId: 'ws02', user: 'dana', label: 'ws02 (dana)', banner: 'ws02, a laptop that gets its address by DHCP. sudo password: ws02-dana.' },
  { hostId: 'ns1', user: 'root', label: 'ns1 console', banner: 'Console on ns1 (root): DNS (BIND) and DHCP server (isc-dhcp-server).' },
  { hostId: 'rtr01', user: 'root', label: 'rtr01 console', banner: 'Console on the router rtr01 (root).' },
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01, statically configured workstation. sudo password: ws01-alice.' },
];
const NAT_TERMINALS = [
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01 in the office (10.0.10.25). sudo password: ws01-alice.' },
  { hostId: 'ext01', user: 'guest', label: 'ext01 (Internet)', banner: 'ext01 = a host on the Internet (203.0.113.80). It has no route to private networks.' },
  { hostId: 'rtr01', user: 'root', label: 'rtr01 console', banner: 'Console on the router rtr01 (root): eth0 LAN, eth1 servers, eth2 Internet 203.0.113.2.' },
  { hostId: 'srv01', user: 'root', label: 'srv01 console', banner: 'Console on srv01 (root): the intranet web server 10.0.20.10.' },
];

const DHCP_BRIEFING = [
  'Office LAN 10.0.10.0/24: router rtr01 (10.0.10.1), DNS and DHCP server ns1 (10.0.10.53, isc-dhcp-server), static workstation ws01, DHCP laptop ws02.',
  'DHCP should hand out 10.0.10.100-150 with router 10.0.10.1, DNS 10.0.10.53 and domain corp.lab.',
  'Fixes must survive a reboot of every machine; clients must get correct settings automatically (no static workarounds on ws02).',
];
const NAT_BRIEFING = [
  'rtr01 connects the office (10.0.10.0/24, eth0), the servers (10.0.20.0/24, eth1) and the Internet uplink 203.0.113.0/24 (eth2, public address 203.0.113.2).',
  'Policy: inside hosts reach the Internet through masquerade on eth2; the intranet web server srv01 (10.0.20.10:80) is published on 203.0.113.2.',
  'ext01 (203.0.113.80) stands in for any host on the Internet: it only knows public addresses.',
];

const DHCP_CANDIDATES = ['dhcp-server-down', 'dhcp-pool-exhausted', 'dhcp-bad-option', 'dns-client-config', 'routing-client', 'client-netmask', 'firewall-drop', 'server-down'];
const NAT_CANDIDATES = ['nat-missing-masquerade', 'nat-wrong-dnat', 'nat-filter-order', 'fw-router-forward', 'router-forwarding-disabled', 'routing-server-gateway', 'web-not-running', 'firewall-drop', 'dns-wrong-record'];

function edit(world: World, host: string, path: string, fn: (s: string) => string, gapMs = 60_000) {
  world.clock += gapMs;
  const h = world.hosts[host];
  writeFile(h, path, fn(readFile(h, path) ?? ''), world.clock);
}

function dhcpStillDefault(): Constraint {
  return {
    id: 'ws02-dhcp', required: true,
    description: 'ws02 must still be configured by DHCP (no static address or resolver workaround).',
    check(world) {
      const ok = /iface eth0 inet dhcp/.test(readFile(world.hosts.ws02, '/etc/network/interfaces') ?? '');
      return { id: this.id, ok, required: true, message: ok ? 'ws02 uses DHCP.' : 'ws02 was switched to a static configuration.' };
    },
  };
}

function wanNotWideOpen(): Constraint {
  return {
    id: 'wan-closed', required: true,
    description: 'Only the published web server may be reachable from the Internet (e.g. SSH to srv01 must not be).',
    check(world) {
      const rs = world.hosts.rtr01.nft;
      const fwd = explainPacket(rs, 'forward', { src: '203.0.113.80', dst: '10.0.20.10', proto: 'tcp', sport: 50000, dport: 22, ctState: 'new', len: 60, iif: 'eth2', oif: 'eth1' }).result.verdict;
      const dnat22 = rs.tables.some((t) => t.chains.some((c) => c.base?.type === 'nat' && c.rules.some((r) => r.verdict && (r.verdict.kind === 'dnat') && !r.matches.some((m) => m.kind === 'port'))));
      const open = fwd === 'accept' && dnat22;
      return { id: this.id, ok: !open, required: true, message: open ? 'Every port is forwarded from the Internet to srv01.' : 'Only the intended port is published.' };
    },
  };
}

function routerForwardDrop(): Constraint {
  return {
    id: 'rtr-forward-drop', required: true,
    description: 'rtr01 must keep its default-drop forward policy; SSH from the Internet to srv01 must stay blocked.',
    check(world) {
      const fwdChain = world.hosts.rtr01.nft.tables.flatMap((t) => t.chains).find((c) => c.base?.hook === 'forward' && c.base.type === 'filter');
      if (!fwdChain || fwdChain.base!.policy !== 'drop') return { id: this.id, ok: false, required: true, message: 'The forward policy is no longer drop.' };
      const v = explainPacket(world.hosts.rtr01.nft, 'forward', { src: '203.0.113.80', dst: '10.0.20.10', proto: 'tcp', sport: 50000, dport: 22, ctState: 'new', len: 60, iif: 'eth2', oif: 'eth1' }).result.verdict;
      return v === 'accept'
        ? { id: this.id, ok: false, required: true, message: 'SSH from the Internet to srv01 would be forwarded.' }
        : { id: this.id, ok: true, required: true, message: 'Forward policy is drop and only the published service is allowed from eth2.' };
    },
  };
}

export const DHCP_NAT_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'dhcp-interface',
    title: 'Nobody new gets an address',
    difficulty: 'beginner',
    ticket: 'Dana: "My laptop shows no network at all since this morning: ip a has no IPv4 address." The sysadmin migrated ns1\'s configuration from the old Proxmox VM template yesterday and restarted the services.',
    briefing: DHCP_BRIEFING,
    goals: [DANA_WEB],
    terminals: DHCP_TERMINALS,
    setup(world) {
      edit(world, 'ns1', '/etc/default/isc-dhcp-server', (s) => s.replace('INTERFACESv4="eth0"', 'INTERFACESv4="ens18"'));
      script(world, 'ns1', ['systemctl restart isc-dhcp-server']);
      world.clock += 12 * 3600_000;
      script(world, 'ws02', ['reboot']);
      world.clock += 3600_000;
    },
    rootCauses: ['dhcp-server-down'],
    candidates: DHCP_CANDIDATES,
    feedback: {
      'dhcp-pool-exhausted': 'The server log would say "no free leases". Here it does not log the DISCOVERs at all. Is it even running?',
      'routing-client': 'ws02 has no address at all, so there is nothing to route yet. The failure is earlier: address assignment.',
    },
    hints: [
      'Without an address nothing else matters. Look at ws02\'s log (sudo journalctl -u networking) and then ask: did any DHCP server answer?',
      'On ns1, check systemctl status isc-dhcp-server and its journal. What does it say about interfaces?',
      'INTERFACESv4 in /etc/default/isc-dhcp-server names "ens18", an interface from the old template; ns1\'s NIC is eth0. Fix it, restart isc-dhcp-server, then renew on ws02 (sudo dhclient eth0).',
    ],
    explanation: {
      rootCause: 'The migrated /etc/default/isc-dhcp-server listens on "ens18" (the old VM\'s NIC name). ns1 only has eth0, so dhcpd found no interface to serve and exited: "Not configured to listen on any interfaces!".',
      manifestation: 'ws02 broadcasts DHCPDISCOVER four to six times with growing intervals; nobody answers; dhclient gives up ("No DHCPOFFERS received") and the interface stays without an IPv4 address. Everything else fails with "Network is unreachable". Statically configured hosts (ws01) are unaffected.',
      evidence: 'ws02 journal: repeated DHCPDISCOVER, "No DHCPOFFERS received"; ns1: systemctl status isc-dhcp-server = failed; journal: "No subnet declaration for ens18 (no IPv4 addresses)", "Not configured to listen on any interfaces!".',
      prevention: 'Interface names differ between hypervisors and templates (eth0, ens18, enp1s0): parametrise them in configuration management and monitor the DHCP service and pool.',
    },
    solution: [
      { host: 'ns1', commands: ["sed -i 's/INTERFACESv4=\"ens18\"/INTERFACESv4=\"eth0\"/' /etc/default/isc-dhcp-server", 'systemctl restart isc-dhcp-server', 'systemctl is-active isc-dhcp-server'] },
      { host: 'ws02', user: 'root', commands: ['dhclient -v eth0', 'ip -4 addr'], note: 'As dana: sudo dhclient -v eth0.' },
    ],
    constraints: [dhcpStillDefault(), firewallStillRestrictive()],
    concepts: ['net.dhcp', 'svc.systemd'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'dhcp-pool-exhausted',
    title: 'Works for everyone who came early',
    difficulty: 'intermediate',
    ticket: 'Dana: "After the all-hands meeting my laptop has no network. People who were here before the meeting are fine." Facilities note: 30 visitors connected their phones to the office network during the meeting.',
    briefing: [...DHCP_BRIEFING, 'Last week the pool was shrunk "temporarily" while testing reservations.'],
    goals: [DANA_WEB],
    terminals: DHCP_TERMINALS,
    setup(world) {
      edit(world, 'ns1', '/etc/dhcp/dhcpd.conf', (s) => s.replace('range 10.0.10.100 10.0.10.150;', 'range 10.0.10.100 10.0.10.104;    # temporary while testing reservations').replace('default-lease-time 600;', 'default-lease-time 86400;'), 7 * 24 * 3600_000);
      script(world, 'ns1', ['systemctl restart isc-dhcp-server']);
      world.clock += 3600_000;
      const ns1 = world.hosts.ns1;
      const leases = [100, 101, 102, 103, 104].map((n, i) => formatLease({ ip: `10.0.10.${n}`, mac: `0a:1b:2c:3d:4e:${(0x50 + i).toString(16)}`, hostname: `visitor-phone-${i + 1}`, starts: world.clock, ends: world.clock + 86_400_000, state: 'active' })).join('');
      writeFile(ns1, '/var/lib/dhcp/dhcpd.leases', (readFile(ns1, '/var/lib/dhcp/dhcpd.leases') ?? '').replace(/lease 10\.0\.10\.100 \{[^}]*\}\n/, '') + leases, world.clock);
      world.clock += 2 * 3600_000;
      script(world, 'ws02', ['reboot']);
      world.clock += 600_000;
    },
    rootCauses: ['dhcp-pool-exhausted'],
    candidates: DHCP_CANDIDATES,
    feedback: {
      'dhcp-server-down': 'isc-dhcp-server is active, and its journal DOES log Dana\'s DHCPDISCOVER. Read the end of that line.',
    },
    hints: [
      'Does ns1 hear ws02\'s DISCOVER? Check the DHCP server\'s journal (journalctl -u isc-dhcp-server).',
      'The server logs "no free leases". Compare the range in /etc/dhcp/dhcpd.conf with the active leases in /var/lib/dhcp/dhcpd.leases.',
      'Restore the full range 10.0.10.100-10.0.10.150 (and consider a shorter lease time for visitors), restart isc-dhcp-server, then sudo dhclient eth0 on ws02.',
    ],
    explanation: {
      rootCause: 'The pool was shrunk to 5 addresses (10.0.10.100-104) and the lease time raised to 24 h. Visitors\' phones took all five leases.',
      manifestation: 'Clients that already held a lease renew it and keep working. A new or rebooted client gets no offer: dhcpd logs "no free leases" and does not answer, so dhclient ends with "No DHCPOFFERS received".',
      evidence: 'ns1 journal: "DHCPDISCOVER from 52:54:00:d4:00:42 (ws02) via eth0: network 10.0.10.0/24: no free leases"; dhcpd.leases: five active leases for visitor-phone-*; dhcpd.conf: range .100-.104.',
      prevention: 'Size pools for peak demand, use a separate guest network with short leases, revert temporary changes, and alert on pool utilisation.',
    },
    solution: [
      { host: 'ns1', commands: ["sed -i 's/range 10.0.10.100 10.0.10.104;    # temporary while testing reservations/range 10.0.10.100 10.0.10.150;/' /etc/dhcp/dhcpd.conf", 'dhcpd -t', 'systemctl restart isc-dhcp-server'] },
      { host: 'ws02', user: 'root', commands: ['dhclient -v eth0'] },
    ],
    constraints: [dhcpStillDefault()],
    concepts: ['net.dhcp', 'logs.journal'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'dhcp-wrong-router',
    title: 'Laptops can print but not browse',
    difficulty: 'intermediate',
    ticket: 'Several laptop users: "We can reach the printer and the DNS server, but nothing on the server network or the Internet. Desktop PCs (static addresses) are fine."',
    briefing: [...DHCP_BRIEFING, 'Yesterday someone copied subnet settings from the old office (where the router was .254) into dhcpd.conf.'],
    goals: [DANA_WEB],
    terminals: DHCP_TERMINALS,
    setup(world) {
      edit(world, 'ns1', '/etc/dhcp/dhcpd.conf', (s) => s.replace('option routers 10.0.10.1;', 'option routers 10.0.10.254;'));
      script(world, 'ns1', ['systemctl restart isc-dhcp-server']);
      world.clock += 3600_000;
      script(world, 'ws02', ['reboot']);
      world.clock += 3600_000;
    },
    rootCauses: ['dhcp-bad-option'],
    acceptable: { 'routing-client': 'Correct for the symptom: ws02\'s default gateway is wrong. The underlying cause is that DHCP hands out that wrong gateway, so fixing ws02 by hand would not fix the other laptops.' },
    candidates: DHCP_CANDIDATES,
    feedback: {
      'dhcp-server-down': 'ws02 does have an address from 10.0.10.100-150, so the DHCP server answered.',
      'client-netmask': 'ws02 has a /24 (ip -4 addr).',
    },
    hints: [
      'Only DHCP clients are affected and only off-subnet destinations. What do DHCP clients get that static clients configure themselves?',
      'On ws02: ip route, ip neigh. Then look at the lease (cat /var/lib/dhcp/dhclient.eth0.leases) and at the option lines in ns1\'s /etc/dhcp/dhcpd.conf.',
      '"option routers 10.0.10.254" should be 10.0.10.1. Fix it on ns1, restart isc-dhcp-server, and renew on ws02 (sudo dhclient -r eth0; sudo dhclient eth0).',
    ],
    explanation: {
      rootCause: 'dhcpd.conf on ns1 hands out "option routers 10.0.10.254", the old office\'s router address.',
      manifestation: 'Every DHCP client installs "default via 10.0.10.254". On-link destinations (printer, ns1) work; everything else needs the gateway, ARP for 10.0.10.254 fails and the client reports "No route to host".',
      evidence: 'ws02: ip route shows "default via 10.0.10.254"; ip neigh shows 10.0.10.254 FAILED; /var/lib/dhcp/dhclient.eth0.leases contains "option routers 10.0.10.254"; ns1 dhcpd.conf has the same line.',
      prevention: 'Review DHCP option changes like routing changes; test with a real client after every change; keep per-site values in configuration management.',
    },
    solution: [
      { host: 'ns1', commands: ["sed -i 's/option routers 10.0.10.254;/option routers 10.0.10.1;/' /etc/dhcp/dhcpd.conf", 'systemctl restart isc-dhcp-server'] },
      { host: 'ws02', user: 'root', commands: ['dhclient -r eth0', 'dhclient -v eth0', 'ip route'] },
    ],
    constraints: [dhcpStillDefault()],
    concepts: ['net.dhcp', 'net.routing'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'nat-no-masquerade',
    title: 'The router can browse, nobody else can',
    difficulty: 'intermediate',
    ticket: 'Office: "Since the firewall migration no website on the Internet loads: requests just hang." Network team: "rtr01 itself reaches the Internet fine, we tested from it."',
    briefing: NAT_BRIEFING,
    goals: [OFFICE_TO_INTERNET, INTERNET_TO_WEB()],
    terminals: NAT_TERMINALS,
    setup(world) {
      edit(world, 'rtr01', '/etc/nftables.conf', (s) => s.replace('\t\toifname "eth2" masquerade\n', ''));
      script(world, 'rtr01', ['systemctl reload nftables']);
      world.clock += 5 * 3600_000;
    },
    rootCauses: ['nat-missing-masquerade'],
    candidates: NAT_CANDIDATES,
    feedback: {
      'fw-router-forward': 'rtr01\'s forward policy is accept and the SYN does leave on eth2 (tcpdump -i eth2). Look at its SOURCE address.',
      'router-forwarding-disabled': 'tcpdump on rtr01 eth2 shows the packets leaving: forwarding works.',
      'routing-server-gateway': 'The problem is the reply path from the INTERNET host. Why can ext01 not answer 10.0.10.25?',
    },
    hints: [
      'It hangs (timeout): something is not answered. Follow one connection: capture on rtr01 eth2 while curl runs on ws01. What source address leaves the router?',
      'Private addresses (10.0.0.0/8) are not routed on the Internet, so ext01 cannot send replies to 10.0.10.25. What should the router have done to the source address? (nft list table ip nat)',
      'The "oifname \\"eth2\\" masquerade" rule is missing from rtr01\'s postrouting chain. Restore it in /etc/nftables.conf and reload.',
    ],
    explanation: {
      rootCause: 'The migration dropped "oifname "eth2" masquerade" from rtr01\'s postrouting NAT chain. Traffic from the office now leaves with its private source address.',
      manifestation: 'The SYN reaches the Internet host with source 10.0.10.25. Its reply must be routed to a private address the Internet does not route (in reality the ISP drops such packets; in the lab ext01\'s upstream cannot be reached): the client times out. The router\'s own traffic uses its public address, so tests from rtr01 succeed.',
      evidence: 'tcpdump -i eth2 on rtr01: "IP 10.0.10.25.5xxxx > 203.0.113.80.80: Flags [S]" (a private source on the Internet side); ext01 sees SYNs from 10.0.10.25 and cannot answer; nft list table ip nat has no masquerade rule; conntrack -L shows no NAT entries for office flows.',
      prevention: 'Test a migration from an inside client, not from the router. Keep NAT rules in the same reviewed file as the filter rules.',
    },
    solution: [{ host: 'rtr01', commands: ["sed -i 's/^\\t\\ttype nat hook postrouting priority srcnat; policy accept;$/\\t\\ttype nat hook postrouting priority srcnat; policy accept;\\n\\t\\toifname \"eth2\" masquerade/' /etc/nftables.conf", 'systemctl reload nftables', 'nft list table ip nat'] }],
    constraints: [firewallStillRestrictive()],
    concepts: ['net.nat', 'net.routing'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'nat-dnat-typo',
    title: 'The published website is unreachable from outside',
    difficulty: 'intermediate',
    ticket: 'Customer support: "Customers report our website (http://203.0.113.2) fails: No route to host." Internally http://srv01.corp.lab works fine.',
    briefing: [...NAT_BRIEFING, 'Yesterday the port forward was edited while documenting the new server addressing plan.'],
    goals: [INTERNET_TO_WEB()],
    terminals: NAT_TERMINALS,
    setup(world) {
      edit(world, 'rtr01', '/etc/nftables.conf', (s) => s.replace('dnat to 10.0.20.10:80', 'dnat to 10.0.20.100:80'));
      script(world, 'rtr01', ['systemctl reload nftables']);
      world.clock += 20 * 3600_000;
    },
    rootCauses: ['nat-wrong-dnat'],
    candidates: NAT_CANDIDATES,
    feedback: {
      'web-not-running': 'From the office, http://srv01.corp.lab answers 200. nginx is fine.',
      'nat-missing-masquerade': 'The office can reach the Internet (masquerade works). The problem is traffic coming IN.',
      'server-down': 'srv01 (10.0.20.10) answers. But is 10.0.20.10 where rtr01 sends the traffic?',
    },
    hints: [
      'From ext01 the error is immediate "No route to host": an ICMP error came back. From which address? (tcpdump on ext01, or read curl/ping carefully.)',
      'On rtr01 look at what the published port is translated to (nft list table ip nat), and at conntrack -L / ip neigh after a test.',
      'The DNAT rule sends traffic to 10.0.20.100, which does not exist. Fix it to 10.0.20.10:80 in /etc/nftables.conf and reload.',
    ],
    explanation: {
      rootCause: 'The port-forward rule was changed to "dnat to 10.0.20.100:80" (a typo for 10.0.20.10).',
      manifestation: 'rtr01 rewrites the destination to 10.0.20.100, routes it to eth1, and ARPs for that address. Nobody answers, so after ~3 s rtr01 sends ICMP host unreachable to the outside client, which reports "No route to host". Inside users use the server\'s real address and are unaffected.',
      evidence: 'nft list table ip nat: "dnat to 10.0.20.100:80"; conntrack -L on rtr01 shows the flow translated to 10.0.20.100; ip neigh on rtr01: "10.0.20.100 dev eth1 FAILED"; ext01 receives ICMP host unreachable from 203.0.113.2.',
      prevention: 'Reference servers by named sets/variables in the ruleset, review NAT changes, and monitor published services from outside.',
    },
    solution: [{ host: 'rtr01', commands: ["sed -i 's/dnat to 10.0.20.100:80/dnat to 10.0.20.10:80/' /etc/nftables.conf", 'systemctl reload nftables'] }],
    constraints: [wanNotWideOpen()],
    concepts: ['net.nat', 'net.arp'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'nat-filter-order',
    title: 'Port 8080 is open... isn\'t it?',
    difficulty: 'advanced',
    ticket: 'Web team: "We moved the public website to port 8080 (http://203.0.113.2:8080) and the network team added a firewall rule for 8080 on the router. It still times out from outside."',
    briefing: [...NAT_BRIEFING, 'Change NET-31: public port 8080 → srv01:80; the router\'s forward chain was tightened to default-drop at the same time.'],
    goals: [INTERNET_TO_WEB(8080), OFFICE_TO_INTERNET],
    terminals: NAT_TERMINALS,
    setup(world) {
      edit(world, 'rtr01', '/etc/nftables.conf', (s) => s
        .replace('iifname "eth2" tcp dport 80 dnat to 10.0.20.10:80', 'iifname "eth2" tcp dport 8080 dnat to 10.0.20.10:80')
        .replace('\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n\t}\n',
          '\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t\tct state established,related accept\n\t\tiifname "eth0" accept\n\t\tiifname "eth1" accept\n\t\tiifname "eth2" tcp dport 8080 accept comment "NET-31 public web"\n\t}\n'));
      script(world, 'rtr01', ['systemctl reload nftables']);
      world.clock += 6 * 3600_000;
    },
    rootCauses: ['nat-filter-order'],
    acceptable: { 'fw-router-forward': 'Yes: rtr01\'s forward chain drops it. The precise mistake is WHICH port the rule matches.' },
    candidates: NAT_CANDIDATES,
    feedback: {
      'nat-wrong-dnat': 'The DNAT target 10.0.20.10:80 is right. Check where the packet dies: does it reach srv01 at all?',
      'web-not-running': 'Nothing reaches srv01 (tcpdump there is silent), so nginx is not even asked.',
    },
    hints: [
      'Timeout = something drops silently. Capture on srv01 while ext01 connects: does anything arrive? Then look at rtr01\'s ruleset with counters (nft -a list ruleset).',
      'The "tcp dport 8080 accept" counter stays at 0 while the forward policy drops. In which order do prerouting NAT and the forward filter run, and what does the packet look like by the time the filter sees it?',
      'DNAT happens in prerouting, BEFORE forward filtering: the filter sees 10.0.20.10:80, not 203.0.113.2:8080. Change the forward rule to match the translated destination (iifname "eth2" ip daddr 10.0.20.10 tcp dport 80 accept) and reload.',
    ],
    explanation: {
      rootCause: 'The forward rule was written for the public port: "iifname "eth2" tcp dport 8080 accept". But netfilter applies DNAT in prerouting, before the forward hook, so the filter sees destination 10.0.20.10 port 80.',
      manifestation: 'The rule never matches; the packet falls through to "policy drop"; the outside client retransmits SYNs and times out. Outbound office traffic still works because "iifname eth0 accept" and the established rule cover it.',
      evidence: 'nft -a list ruleset on rtr01: the 8080 rule counter stays at 0 while the conntrack table shows the DNAT translation; tcpdump on srv01 is silent; the hop trace shows "forward hook: … policy drop" for a packet already rewritten to 10.0.20.10:80.',
      prevention: 'Remember the hook order: prerouting (DNAT) → routing → forward (filter) → postrouting (SNAT). Write forward rules for the inside address/port, or match "ct status dnat". Test published services from outside after each change.',
    },
    solution: [{ host: 'rtr01', commands: ["sed -i 's/iifname \"eth2\" tcp dport 8080 accept comment \"NET-31 public web\"/iifname \"eth2\" ip daddr 10.0.20.10 tcp dport 80 accept comment \"NET-31 public web (post-DNAT)\"/' /etc/nftables.conf", 'systemctl reload nftables', 'nft -a list chain inet filter forward'] }],
    constraints: [routerForwardDrop(), firewallStillRestrictive()],
    concepts: ['net.nat', 'fw.stateful', 'fw.path'],
  },
];
