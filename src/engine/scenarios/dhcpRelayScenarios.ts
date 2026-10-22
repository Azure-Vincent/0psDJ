// DHCP relay and lease-lifetime tickets. dev02 (VLAN 30) gets its address from
// ns1 (VLAN 10) through isc-dhcp-relay on rtr01 (giaddr 10.0.30.1); ws02 is a
// DHCP client on ns1's own network. Leases last 600 s: clients renew at 300 s
// (unicast to ns1), rebind at 525 s (broadcast) and lose the address at 600 s.

import { readFile, writeFile } from '../fs';
import type { World } from '../types';
import { firewallStillRestrictive, script } from './engine';
import type { Constraint, Goal, Scenario } from './types';

// IPv4 explicitly: dev02 is dual-stack (DHCPv6 on rtr01), and IPv6 would hide a broken IPv4 DHCP path.
const DEV2_WEB: Goal = { kind: 'http', description: 'On dev02 (VLAN 30, DHCP via the relay), "curl -4 -I http://srv01.corp.lab/" returns HTTP 200 over IPv4.', fromHost: 'dev02', fromUser: 'jordan', url: 'http://srv01.corp.lab/', curlFlags: '-4' };
const DANA_WEB: Goal = { kind: 'http', description: 'On ws02 (office, DHCP), "curl -I http://srv01.corp.lab/" returns HTTP 200.', fromHost: 'ws02', fromUser: 'dana', url: 'http://srv01.corp.lab/' };

const RELAY_TERMINALS = [
  { hostId: 'dev02', user: 'jordan', label: 'dev02 (jordan)', banner: 'dev02, a hot-desk laptop on VLAN 30 that gets its address by DHCP. sudo password: dev02-jordan.' },
  { hostId: 'rtr01', user: 'root', label: 'rtr01 console', banner: 'Console on rtr01 (root): routes VLAN 10/20/30 and runs isc-dhcp-relay for VLAN 30.' },
  { hostId: 'ns1', user: 'root', label: 'ns1 console', banner: 'Console on ns1 (root): DNS and the DHCP server (isc-dhcp-server) for 10.0.10.0/24 and, through the relay, 10.0.30.0/24.' },
  { hostId: 'ws02', user: 'dana', label: 'ws02 (dana)', banner: 'ws02, an office laptop (DHCP, same network as ns1). sudo password: ws02-dana.' },
];

const RELAY_BRIEFING = [
  'ns1 (10.0.10.53, VLAN 10) is the only DHCP server. Clients on VLAN 30 (10.0.30.0/24) reach it through the DHCP relay agent on rtr01: isc-dhcp-relay listens on eth3.30 (10.0.30.1) and forwards to ns1 (NET-58).',
  'Relay configuration: /etc/default/isc-dhcp-relay (SERVERS, INTERFACES, OPTIONS with -id downstream / -iu upstream interfaces). Server configuration: /etc/dhcp/dhcpd.conf on ns1, one subnet declaration per network it serves.',
  'Clients must keep using DHCP (no static addresses). Fixes must survive a reboot of every machine and must not open rtr01\'s firewall.',
  'dev02 is dual-stack: its IPv6 address comes from DHCPv6 on rtr01, a separate service, so IPv6 can keep working while IPv4 DHCP is broken. Test IPv4 explicitly (curl -4, ping -4).',
];

const RELAY_CANDIDATES = ['dhcp-relay-wrong-server', 'dhcp-relay-upstream', 'dhcp-no-subnet', 'dhcp-server-down', 'dhcp-pool-exhausted', 'vlan-access-wrong', 'firewall-drop', 'dns-client-config'];

function edit(world: World, host: string, path: string, fn: (s: string) => string, gapMs = 60_000) {
  world.clock += gapMs;
  const h = world.hosts[host];
  writeFile(h, path, fn(readFile(h, path) ?? ''), world.clock);
}

function dhcpStill(host: string): Constraint {
  return {
    id: `${host}-dhcp`, required: true,
    description: `${host} must still be configured by DHCP (no static address or resolver workaround).`,
    check(world) {
      const ok = /iface eth0 inet dhcp/.test(readFile(world.hosts[host], '/etc/network/interfaces') ?? '');
      return { id: this.id, ok, required: true, message: ok ? `${host} uses DHCP.` : `${host} was switched to a static configuration.` };
    },
  };
}

/** A hot-desk laptop that has never been on this network: no remembered lease. */
function newLaptop(world: World) {
  world.clock += 3 * 3600_000;
  script(world, 'dev02', ['rm /var/lib/dhcp/dhclient.eth0.leases', 'reboot']);
  world.clock += 15 * 60_000;
}

export const DHCP_RELAY_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'dhcp-relay-server',
    title: 'Only the dev VLAN gets no address',
    difficulty: 'intermediate',
    ticket: 'Jordan (tester): "I took a hot desk in the development area this morning and my laptop dev02 has no network: no IPv4 address at all. In the office area yesterday it worked fine." Change log NET-62 (yesterday): "rtr01: tidy up /etc/default/isc-dhcp-relay".',
    briefing: RELAY_BRIEFING,
    goals: [DEV2_WEB, DANA_WEB],
    terminals: RELAY_TERMINALS,
    setup(world) {
      edit(world, 'rtr01', '/etc/default/isc-dhcp-relay', (s) => s.replace('SERVERS="10.0.10.53"', 'SERVERS="10.0.10.35"'));
      script(world, 'rtr01', ['systemctl restart isc-dhcp-relay']);
      newLaptop(world);
    },
    rootCauses: ['dhcp-relay-wrong-server'],
    candidates: RELAY_CANDIDATES,
    feedback: {
      'dhcp-relay-upstream': 'That fault would show the server answering ("DHCPOFFER ... via 10.0.30.1" in ns1\'s journal). Here ns1 never sees dev02\'s requests at all.',
      'dhcp-no-subnet': 'ns1 would log "unknown network segment" for requests via 10.0.30.1. It logs nothing for dev02: the requests never reach it.',
      'dhcp-server-down': 'ns1\'s dhcpd is running and ws02 (same network as ns1) renews its lease normally. Only relayed clients are affected.',
      'dhcp-pool-exhausted': 'A full pool is logged as "no free leases" by the server, which here never even receives dev02\'s requests.',
      'vlan-access-wrong': 'dev02 is in VLAN 30 (bridge vlan show on sw01) and its DISCOVERs arrive on rtr01\'s eth3.30; tcpdump there shows them.',
      'firewall-drop': 'No firewall blocks the requests: rtr01 receives them and the relay forwards them, just to the wrong address.',
      'dns-client-config': 'dev02 has no address at all; DNS comes later. Fix address assignment first.',
    },
    hints: [
      'dev02 has no address, so test from the infrastructure side: does ns1 see dev02\'s requests? (journalctl -u isc-dhcp-server on ns1). Then follow the request from the client network to the server.',
      'On rtr01: is isc-dhcp-relay running, and where does it send the requests? "tcpdump -n -i eth3.30 port 67" (client side) and "tcpdump -n -i eth0 port 67 or arp" (server side). Compare the destination with ns1\'s address.',
      'SERVERS in /etc/default/isc-dhcp-relay says 10.0.10.35, but ns1 is 10.0.10.53 (digits swapped). Fix it, "systemctl restart isc-dhcp-relay", then on dev02 "sudo dhclient -v eth0" (or wait: dhclient retries every 5 minutes).',
    ],
    explanation: {
      rootCause: 'The tidy-up changed SERVERS in /etc/default/isc-dhcp-relay to 10.0.10.35, an address no host uses, instead of ns1\'s 10.0.10.53.',
      manifestation: 'dev02 broadcasts DHCPDISCOVER on VLAN 30. Broadcasts stop at the router; the relay on rtr01 does receive them and forwards each one as unicast to 10.0.10.35, which never answers (rtr01 cannot even resolve its MAC address). ns1 never sees the request, so dev02 gets no address. Clients on ns1\'s own network (ws02) are unaffected because their broadcasts reach ns1 directly.',
      evidence: 'dev02: journal "DHCPDISCOVER ... No DHCPOFFERS received"; rtr01: isc-dhcp-relay active, tcpdump on eth3.30 shows the DISCOVERs, tcpdump on eth0 shows "ARP, Request who-has 10.0.10.35 tell 10.0.10.1" and no DHCP to ns1; ns1: journal shows nothing for 52:54:00:e7:00:2a.',
      prevention: 'Review relay changes against the server inventory; monitor DHCP per network (a synthetic client per VLAN, or alerting on ns1 when a relayed subnet stops getting requests); keep relay targets in configuration management.',
    },
    solution: [
      { host: 'rtr01', commands: ["sed -i 's/SERVERS=\"10.0.10.35\"/SERVERS=\"10.0.10.53\"/' /etc/default/isc-dhcp-relay", 'systemctl restart isc-dhcp-relay'] },
      { host: 'dev02', user: 'root', commands: ['dhclient -v eth0'], note: 'As jordan: sudo dhclient -v eth0, or wait up to 5 minutes for dhclient to retry.' },
    ],
    constraints: [dhcpStill('dev02'), firewallStillRestrictive('rtr01')],
    concepts: ['net.dhcp', 'net.routing'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'dhcp-relay-iu',
    title: 'The server offers, the laptop never hears it',
    difficulty: 'advanced',
    ticket: 'Jordan: "dev02 again has no address in the development area." Network team: "ns1\'s log says it is offering 10.0.30.100 to that laptop, so DHCP is fine; must be the laptop." Change log NET-63: "rtr01: restrict dhcrelay to VLAN 30, we do not want to relay office broadcasts".',
    briefing: RELAY_BRIEFING,
    goals: [DEV2_WEB, DANA_WEB],
    terminals: RELAY_TERMINALS,
    setup(world) {
      edit(world, 'rtr01', '/etc/default/isc-dhcp-relay', (s) => s.replace('OPTIONS="-id eth3.30 -iu eth0"', 'OPTIONS="-id eth3.30"'));
      script(world, 'rtr01', ['systemctl restart isc-dhcp-relay']);
      newLaptop(world);
    },
    rootCauses: ['dhcp-relay-upstream'],
    candidates: RELAY_CANDIDATES,
    feedback: {
      'dhcp-relay-wrong-server': 'The relay forwards to the right server: ns1 logs "DHCPDISCOVER from 52:54:00:e7:00:2a (dev02) via 10.0.30.1" and answers it.',
      'dhcp-no-subnet': 'ns1 has a subnet for 10.0.30.0/24: it offers 10.0.30.100 instead of logging "unknown network segment".',
      'dhcp-server-down': 'ns1\'s dhcpd is running and answering; the offers just never get back to dev02.',
      'dhcp-pool-exhausted': 'The server offers an address, so the pool is not empty.',
      'vlan-access-wrong': 'dev02\'s DISCOVERs arrive on rtr01 eth3.30 (VLAN 30) and are relayed; the switch is fine.',
      'firewall-drop': 'Partly true: rtr01\'s input policy drops the replies. But the firewall did not change and must stay closed. The relay is supposed to read replies with a packet socket on the server-side interface, which bypasses nftables; NET-63 removed that interface.',
      'dns-client-config': 'dev02 has no address at all; DNS comes later.',
    },
    hints: [
      'Do not trust "DHCP is fine" until the reply is seen on the client side. Follow one exchange: ns1\'s journal, then tcpdump on rtr01 eth0 (server side) and eth3.30 (client side).',
      'The OFFER from 10.0.10.53 to 10.0.30.1 arrives on rtr01 eth0 but nothing goes out on eth3.30. How does dhcrelay receive packets? Compare /etc/default/isc-dhcp-relay with NET-63 and look at rtr01\'s input chain (nft list ruleset).',
      'dhcrelay listens with packet sockets only on the interfaces it was given; -iu eth0 (upstream) was removed, so replies hit the fallback UDP socket and rtr01\'s "policy drop" input chain. Restore OPTIONS="-id eth3.30 -iu eth0" and restart isc-dhcp-relay.',
    ],
    explanation: {
      rootCause: 'NET-63 removed "-iu eth0" from the relay options. dhcrelay now listens with packet sockets only on eth3.30. Server replies arrive on eth0 and fall through to its ordinary UDP socket, where rtr01\'s input chain (policy drop) discards them.',
      manifestation: 'Requests flow normally: DISCOVER broadcast on VLAN 30 → relay → unicast to ns1 with giaddr 10.0.30.1. ns1 offers 10.0.30.100 and sends the OFFER to 10.0.30.1. The packet reaches rtr01 but is dropped before dhcrelay sees it, so dev02 keeps sending DISCOVERs and ends with "No DHCPOFFERS received". Looking only at the server suggests DHCP works.',
      evidence: 'ns1 journal: DHCPDISCOVER/DHCPOFFER via 10.0.30.1 repeated; rtr01: tcpdump -i eth0 shows "10.0.10.53.67 > 10.0.30.1.67: BOOTP/DHCP, Reply", tcpdump -i eth3.30 shows only requests; nft list ruleset: input policy drop with no rule for UDP 67; /etc/default/isc-dhcp-relay: OPTIONS="-id eth3.30".',
      prevention: 'With ISC dhcrelay, always give both directions explicitly (-id client side, -iu server side). Test relay changes end-to-end from a client on the relayed network, not by reading the server log. Document that DHCP software uses packet sockets, which is why it usually works through host firewalls and fails mysteriously when that changes.',
    },
    solution: [
      { host: 'rtr01', commands: ["sed -i 's/OPTIONS=\"-id eth3.30\"/OPTIONS=\"-id eth3.30 -iu eth0\"/' /etc/default/isc-dhcp-relay", 'systemctl restart isc-dhcp-relay'] },
      { host: 'dev02', user: 'root', commands: ['dhclient -v eth0'], note: 'As jordan: sudo dhclient -v eth0. Allowing "ip saddr 10.0.10.53 udp sport 67 udp dport 67" in rtr01\'s input chain (persistently) also works.' },
    ],
    constraints: [dhcpStill('dev02'), firewallStillRestrictive('rtr01')],
    concepts: ['net.dhcp', 'fw.stateful'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'dhcp-relay-subnet',
    title: '"unknown network segment"',
    difficulty: 'intermediate',
    ticket: 'Jordan: "No network on dev02 in the development area, again." The DHCP admin cleaned up dhcpd.conf on ns1 last night (CHG-1301: "remove subnets for networks that are not connected to ns1").',
    briefing: RELAY_BRIEFING,
    goals: [DEV2_WEB, DANA_WEB],
    terminals: RELAY_TERMINALS,
    setup(world) {
      edit(world, 'ns1', '/etc/dhcp/dhcpd.conf', (s) => s.replace(/\n# Development VLAN 30[^\n]*\nsubnet 10\.0\.30\.0 netmask 255\.255\.255\.0 \{[^}]*\}\n/, '\n'));
      script(world, 'ns1', ['dhcpd -t', 'systemctl restart isc-dhcp-server']);
      newLaptop(world);
    },
    rootCauses: ['dhcp-no-subnet'],
    candidates: RELAY_CANDIDATES,
    feedback: {
      'dhcp-relay-wrong-server': 'The relay reaches the right server: ns1 logs dev02\'s DISCOVERs "via 10.0.30.1".',
      'dhcp-relay-upstream': 'ns1 never offers anything, so there is no reply for the relay to lose. Read ns1\'s message after "via 10.0.30.1".',
      'dhcp-server-down': 'dhcpd is running (ws02 renews fine) and it even logs dev02\'s requests; it just does not answer them.',
      'dhcp-pool-exhausted': 'That would log "no free leases" for a known network. "unknown network segment" means there is no network declaration at all.',
      'vlan-access-wrong': 'The request reaches ns1 with giaddr 10.0.30.1, so dev02 is in VLAN 30 and the relay works.',
      'firewall-drop': 'The requests are delivered to dhcpd, which logs them.',
      'dns-client-config': 'dev02 has no address at all; DNS comes later.',
    },
    hints: [
      'Check whether the request reaches the server: journalctl -u isc-dhcp-server on ns1. Read the whole line.',
      'dhcpd says "via 10.0.30.1: unknown network segment". How does a DHCP server decide which subnet a relayed request belongs to? Look at giaddr and at the subnet declarations in /etc/dhcp/dhcpd.conf.',
      'CHG-1301 removed "subnet 10.0.30.0 netmask 255.255.255.0" because ns1 has no interface there, but relayed networks need a declaration too. Add it back (range 10.0.30.100 10.0.30.150; option routers 10.0.30.1;), "dhcpd -t", restart isc-dhcp-server, renew on dev02.',
    ],
    explanation: {
      rootCause: 'The subnet declaration for 10.0.30.0/24 was deleted from dhcpd.conf. dhcpd selects the subnet of a relayed request by giaddr (10.0.30.1); without a matching declaration it ignores the request.',
      manifestation: 'Relay and network work: every DISCOVER from dev02 reaches ns1 with giaddr 10.0.30.1. dhcpd logs "unknown network segment" and answers nothing, so dev02 ends with "No DHCPOFFERS received". The office (10.0.10.0/24, declared) is unaffected, and dhcpd -t reports no error because the file is valid.',
      evidence: 'ns1 journal: "DHCPDISCOVER from 52:54:00:e7:00:2a via 10.0.30.1: unknown network segment"; dhcpd.conf has only the 10.0.10.0 subnet; rtr01 tcpdump: requests forwarded, no replies.',
      prevention: 'Comment every subnet with the networks it serves through relays; check dhcpd.conf against the list of relayed VLANs before cleanup; alert on "unknown network segment" in the DHCP server log.',
    },
    solution: [
      { host: 'ns1', commands: ["sed -i 's/^# Reservations$/subnet 10.0.30.0 netmask 255.255.255.0 {\\n    range 10.0.30.100 10.0.30.150;\\n    option routers 10.0.30.1;\\n}\\n\\n# Reservations/' /etc/dhcp/dhcpd.conf", 'dhcpd -t', 'systemctl restart isc-dhcp-server'] },
      { host: 'dev02', user: 'root', commands: ['dhclient -v eth0'], note: 'As jordan: sudo dhclient -v eth0.' },
    ],
    constraints: [dhcpStill('dev02'), dhcpStill('ws02')],
    concepts: ['net.dhcp'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'dhcp-lease-expiry',
    title: 'Laptops drop off one after another',
    difficulty: 'intermediate',
    ticket: 'Helpdesk: "For the last half hour, laptops have been losing their network one after the other, in the office and in the development area. Desktops with fixed addresses (ws01) are fine. Nobody changed anything on the laptops." The DHCP admin added a printer reservation on ns1 shortly before the first call.',
    briefing: [
      'ns1 is the DHCP server for the office (ws02, directly) and VLAN 30 (dev02, through the relay on rtr01). Leases last 600 s (default-lease-time).',
      'A DHCP client renews at half the lease time (T1) by unicast to its server, rebinds at 7/8 (T2) by broadcast, and must stop using the address when the lease expires. "sleep SECONDS" lets simulated time pass.',
      'Clients must keep using DHCP. Fixes must survive a reboot of every machine.',
    ],
    goals: [DANA_WEB, DEV2_WEB],
    terminals: [...RELAY_TERMINALS.slice(2), RELAY_TERMINALS[0], RELAY_TERMINALS[1]],
    setup(world) {
      edit(world, 'ns1', '/etc/dhcp/dhcpd.conf', (s) => s + '\nhost printer02 {\n    hardware ethernet 52:54:00:e5:00:22\n    fixed-address 10.0.10.22;\n}\n');
      script(world, 'ns1', ['systemctl restart isc-dhcp-server']);
      world.clock += 45 * 60_000;
    },
    rootCauses: ['dhcp-server-down'],
    candidates: ['dhcp-server-down', 'dhcp-relay-wrong-server', 'dhcp-pool-exhausted', 'dhcp-bad-option', 'dhcp-no-subnet', 'dns-client-config', 'routing-client', 'server-down'],
    feedback: {
      'dhcp-relay-wrong-server': 'The office laptop ws02 is on ns1\'s own network and fails too, so the relay cannot be the common cause.',
      'dhcp-pool-exhausted': 'A full pool is logged by a running server. Here isc-dhcp-server is not running at all.',
      'dhcp-bad-option': 'The laptops did not get wrong options; they lost their addresses entirely when the leases expired.',
      'dhcp-no-subnet': 'Both networks are declared; the server is simply not running.',
      'dns-client-config': 'Name resolution fails only because the laptops have no address any more.',
      'routing-client': 'The laptops have no address and therefore no route; the cause is that their leases could not be renewed.',
      'server-down': 'ns1 itself is up (ping works, DNS answers); only its DHCP service failed.',
    },
    hints: [
      'Why one after another? Read a laptop\'s DHCP history: journalctl -t dhclient on ws02 (as root). What happened at T1, T2 and expiry?',
      'The renewals are addressed to 10.0.10.53 and get no answer. On ns1: systemctl status isc-dhcp-server and journalctl -u isc-dhcp-server: what happened when the reservation was added?',
      'The printer02 reservation is missing a semicolon after "hardware ethernet ...", so the restart failed ("semicolon expected"). Fix the line, check with "dhcpd -t", start isc-dhcp-server. The laptops retry on their own within 5 minutes (sleep 300) or immediately with "sudo dhclient -v eth0".',
    ],
    explanation: {
      rootCause: 'The printer reservation added this morning has a syntax error (missing semicolon). The restart of isc-dhcp-server failed, so no DHCP server has been running since then.',
      manifestation: 'Existing clients keep their addresses until the leases run out, which is why the outage spreads gradually: each laptop tries to renew with ns1 at T1 (unicast, no answer), rebinds at T2 (broadcast, no answer) and drops its address at expiry, a different time for each laptop. Statically configured hosts are unaffected. After the fix the laptops recover by themselves at their next retry (every 5 minutes) or at once with dhclient.',
      evidence: 'ws02: journalctl -t dhclient shows "DHCPREQUEST ... to 10.0.10.53 port 67" without DHCPACK, then "to 255.255.255.255", then DISCOVERs and "No DHCPOFFERS received" once the lease expired; "ip -4 addr" shows no address. ns1: systemctl status isc-dhcp-server failed; journal "/etc/dhcp/dhcpd.conf line N: semicolon expected." and "Configuration file errors encountered -- exiting".',
      prevention: 'Always run "dhcpd -t" before restarting (or let configuration management validate); monitor the DHCP service itself, not only the clients; longer leases buy time to react (a 600 s lease leaves at most 10 minutes).',
    },
    solution: [
      { host: 'ns1', commands: ["sed -i 's/hardware ethernet 52:54:00:e5:00:22$/hardware ethernet 52:54:00:e5:00:22;/' /etc/dhcp/dhcpd.conf", 'dhcpd -t', 'systemctl restart isc-dhcp-server'] },
      { host: 'ws02', user: 'root', commands: ['dhclient -v eth0'], note: 'As dana: sudo dhclient -v eth0, or wait for the automatic retry (sleep 300).' },
      { host: 'dev02', user: 'root', commands: ['dhclient -v eth0'] },
    ],
    constraints: [dhcpStill('ws02'), dhcpStill('dev02')],
    concepts: ['net.dhcp', 'svc.systemd'],
  },
];
