// DHCPv6 tickets on VLAN 30: dev02 gets its IPv6 address (and DNS) from dhcpd -6
// on rtr01, and its default route from radvd. Firewalls matter for DHCPv6 on both
// ends, unlike DHCPv4.

import { readFile, writeFile } from '../fs';
import { bootHost } from '../sim/services';
import type { World } from '../types';
import { firewallStillRestrictive, script } from './engine';
import type { Constraint, Goal, Scenario } from './types';

const DEV2_WEB6: Goal = { kind: 'http', description: 'On dev02, "curl -6 -I http://srv01.corp.lab/" returns HTTP 200 over IPv6.', fromHost: 'dev02', fromUser: 'jordan', url: 'http://srv01.corp.lab/', curlFlags: '-6' };
const DEV1_WEB6: Goal = { kind: 'http', description: 'On dev01 (SLAAC), "curl -6 -I http://srv01.corp.lab/" still returns HTTP 200.', fromHost: 'dev01', fromUser: 'erin', url: 'http://srv01.corp.lab/', curlFlags: '-6' };

const TERMINALS = [
  { hostId: 'dev02', user: 'jordan', label: 'dev02 (jordan)', banner: 'dev02, a hot-desk laptop on VLAN 30 (DHCP and DHCPv6). sudo password: dev02-jordan.' },
  { hostId: 'rtr01', user: 'root', label: 'rtr01 console', banner: 'Console on rtr01 (root): routes VLAN 10/20/30, runs radvd and the DHCPv6 server (isc-dhcp-server, dhcpd -6) for VLAN 30.' },
  { hostId: 'dev01', user: 'erin', label: 'dev01 (erin)', banner: 'dev01, a developer workstation on VLAN 30 that uses SLAAC. sudo password: dev01-erin.' },
];

const BRIEFING = [
  'VLAN 30 (2001:db8:30::/64) is the IPv6 pilot. radvd on rtr01 advertises the prefix with the M and O flags set; hot-desk laptops such as dev02 get their IPv6 address and DNS server from DHCPv6 (dhcpd -6 on rtr01, /etc/dhcp/dhcpd6.conf, INTERFACESv6 in /etc/default/isc-dhcp-server) and their default route from the router advertisement (NET-77).',
  'dev02 runs "iface eth0 inet6 dhcp" with "autoconf 0": without DHCPv6 it has only a link-local address. dev01 keeps using SLAAC.',
  'dev02 must keep getting its IPv6 address from DHCPv6 (no static address, SLAAC stays off on it). Fixes must survive a reboot of every machine; firewalls must keep their default-deny input policy.',
];

const CANDIDATES = ['dhcp6-client-firewall', 'dhcp6-server-firewall', 'dhcp6-wrong-interface', 'dhcp-server-down', 'ipv6-icmp-blocked', 'ipv6-forwarding-off', 'ipv6-server-no-route', 'dns-wrong-record'];

function edit(world: World, host: string, path: string, fn: (s: string) => string, gapMs = 60_000) {
  world.clock += gapMs;
  const h = world.hosts[host];
  writeFile(h, path, fn(readFile(h, path) ?? ''), world.clock);
}

function dev02UsesDhcp6(): Constraint {
  return {
    id: 'dev02-dhcpv6', required: true,
    description: 'dev02 must get its IPv6 address from DHCPv6: keep "iface eth0 inet6 dhcp" with "autoconf 0", no static IPv6 address.',
    check(world) {
      const cfg = readFile(world.hosts.dev02, '/etc/network/interfaces') ?? '';
      const ok = /iface eth0 inet6 dhcp/.test(cfg) && /autoconf 0/.test(cfg) && !/inet6 static/.test(cfg);
      return { id: this.id, ok, required: true, message: ok ? 'dev02 is configured for DHCPv6 without SLAAC.' : 'dev02 no longer uses DHCPv6 only (static address, SLAAC or the inet6 dhcp stanza changed).' };
    },
  };
}

/** Let the old lease run out: valid lifetime 600 s, so two hours is plenty. */
function expire(world: World) {
  world.clock += 2 * 3600_000;
}

export const DEV02_HARDENED_NFT = `#!/usr/sbin/nft -f
# SEC-12 laptop baseline (applied by the configuration management run of 06:00)
flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		ct state invalid drop
		iif "lo" accept
		meta l4proto icmp accept
		meta l4proto ipv6-icmp accept
		tcp dport 22 ip saddr 10.0.10.0/24 accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

export const DHCPV6_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'dhcp6-client-firewall',
    title: 'Hardened laptop, no IPv6',
    difficulty: 'intermediate',
    ticket: 'Jordan (dev02): "Since the security baseline was rolled out this morning (SEC-12), the IPv6 monitoring check on my laptop fails. IPv4 is fine. Erin\'s desktop on the same VLAN has IPv6."',
    briefing: BRIEFING,
    goals: [DEV2_WEB6, DEV1_WEB6],
    terminals: TERMINALS,
    setup(world) {
      edit(world, 'dev02', '/etc/nftables.conf', () => DEV02_HARDENED_NFT);
      world.clock += 60_000;
      bootHost(world, world.hosts.dev02);
      expire(world);
    },
    rootCauses: ['dhcp6-client-firewall'],
    candidates: CANDIDATES,
    feedback: {
      'dhcp6-server-firewall': 'rtr01 receives dev02\'s Solicit messages and answers them: "journalctl -u isc-dhcp-server" shows "Sending Advertise to fe80::5054:ff:fee7:2a". The server side is fine.',
      'dhcp6-wrong-interface': 'isc-dhcp-server is running and listening on eth3.30; it advertises an address to dev02.',
      'dhcp-server-down': 'The DHCPv6 server runs and answers. The answer just never reaches dhclient on dev02.',
      'ipv6-icmp-blocked': 'dev02\'s ruleset accepts ICMPv6 (meta l4proto ipv6-icmp accept); it has a default route from the router advertisement. What it lacks is an address.',
      'ipv6-forwarding-off': 'dev01 reaches srv01 over IPv6 through the same router, so rtr01 forwards IPv6.',
      'ipv6-server-no-route': 'dev01 gets replies from srv01 over IPv6. srv01 routes fine.',
      'dns-wrong-record': 'srv01.corp.lab resolves to 2001:db8:20::10 (AAAA). The problem is that dev02 has no global IPv6 address to connect from.',
    },
    hints: [
      'Compare dev02 with dev01: "ip -6 addr" on both. Which address is missing on dev02, and where should it come from?',
      'Look at both ends of the DHCPv6 exchange: on rtr01 "journalctl -u isc-dhcp-server" (does it answer?), on dev02 "sudo journalctl -t dhclient" and "sudo tcpdump -n -i eth0 port 546" (does the answer arrive?).',
      'The Advertise arrives but dhclient never sees it: dev02\'s new firewall drops it. The reply comes from rtr01\'s link-local address to UDP 546, which conntrack does not link to the multicast Solicit. Add "udp dport 546 accept" (ideally "ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept") to /etc/nftables.conf, reload nftables and run "sudo dhclient -6 eth0" (or wait for the next retry).',
    ],
    explanation: {
      rootCause: 'The SEC-12 laptop baseline replaced dev02\'s firewall with a default-drop input chain that allows only established traffic, ICMP and SSH. DHCPv6 replies are not "established": the client sent its Solicit to the multicast group ff02::1:2, and the Advertise comes from the server\'s own link-local address, so conntrack sees a new flow and the policy drops it.',
      manifestation: 'With the new ruleset loaded, dev02 can no longer renew its DHCPv6 lease: when the valid lifetime (600 s) ran out, the address was removed, and every new Solicit goes unanswered. With "autoconf 0" it keeps only its link-local address; IPv4 (DHCPv4 uses packet sockets that bypass nftables) keeps working, so only IPv6 fails: "curl -6" gets "No route to host" because rtr01 refuses to forward packets with a link-local source ("beyond scope of source address").',
      evidence: 'rtr01: "Solicit message from fe80::5054:ff:fee7:2a ... Sending Advertise to fe80::5054:ff:fee7:2a port 546" repeated. dev02: tcpdump shows "dhcp6 advertise" arriving on port 546; "journalctl -t dhclient" only shows "XMT: Solicit"; "nft list ruleset" has no rule for UDP 546.',
      prevention: 'Firewall baselines for clients must include the DHCPv6 client rule (firewalld has the "dhcpv6-client" service enabled by default for exactly this reason). Test baselines on an IPv6-enabled pilot host before rolling them out.',
    },
    solution: [{ host: 'dev02', commands: ["sed -i 's/^\\t\\tmeta l4proto ipv6-icmp accept$/\\t\\tmeta l4proto ipv6-icmp accept\\n\\t\\tip6 saddr fe80::\\/10 udp sport 547 udp dport 546 accept/' /etc/nftables.conf", 'systemctl reload nftables', 'dhclient -6 eth0'] }],
    constraints: [dev02UsesDhcp6(), firewallStillRestrictive('dev02')],
    concepts: ['net.ipv6', 'fw.stateful'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'dhcp6-server-firewall',
    title: 'The firewall cleanup',
    difficulty: 'intermediate',
    ticket: 'Network team: "We tidied rtr01\'s ruleset last night (NET-90) and removed the DHCP rule: DHCP traffic never touches nftables anyway, the IPv4 relay on this box works without any rule. This morning several VLAN 30 laptops report missing IPv6."',
    briefing: BRIEFING,
    goals: [DEV2_WEB6, DEV1_WEB6],
    terminals: TERMINALS,
    setup(world) {
      edit(world, 'rtr01', '/etc/nftables.conf', (s) => s.replace(/\t\t# DHCPv6 server \(dhcpd -6\)[^\n]*\n\t\tiifname "eth3\.30" udp dport 547 accept\n/, ''));
      script(world, 'rtr01', ['systemctl reload nftables']);
      expire(world);
    },
    rootCauses: ['dhcp6-server-firewall'],
    candidates: CANDIDATES,
    feedback: {
      'dhcp6-client-firewall': 'dev02 never gets an Advertise to drop: rtr01\'s dhcpd logs no Solicit at all.',
      'dhcp6-wrong-interface': 'isc-dhcp-server runs and listens on eth3.30 ("Listening on Socket/eth3.30/2001:db8:30::/64"). It simply never receives the requests.',
      'dhcp-server-down': 'The service is active. Its socket does not get the packets.',
      'ipv6-icmp-blocked': 'Router advertisements and Neighbor Discovery work: dev02 has a default route via fe80::5054:ff:fea1:4.',
      'ipv6-forwarding-off': 'dev01 reaches srv01 over IPv6 through rtr01.',
      'ipv6-server-no-route': 'srv01 answers dev01 over IPv6.',
      'dns-wrong-record': 'The name resolves; dev02 has no address to use.',
    },
    hints: [
      'dev02 has only a link-local IPv6 address. Is the DHCPv6 server answering? "journalctl -u isc-dhcp-server" on rtr01.',
      'The server logs nothing for dev02. Do the requests reach rtr01? "tcpdump -n -i eth3.30 port 547" on rtr01, then compare with "nft list ruleset".',
      'DHCPv4 is read with packet sockets that bypass nftables, so the relay needs no rule. dhcpd -6 uses an ordinary UDP socket: restore "iifname \\"eth3.30\\" udp dport 547 accept" in rtr01\'s /etc/nftables.conf and reload nftables. dev02 retries every 2 minutes; "sudo dhclient -6 eth0" asks at once.',
    ],
    explanation: {
      rootCause: 'The cleanup removed the rule that accepts UDP 547 on eth3.30. The assumption "DHCP bypasses the firewall" is true for ISC DHCPv4 (dhcpd, dhclient and dhcrelay read with LPF packet sockets) but not for DHCPv6, which uses normal UDP sockets that netfilter filters.',
      manifestation: 'Clients keep their existing addresses until the leases run out (valid lifetime 600 s), then lose IPv6 one by one. New Solicit messages reach rtr01\'s interface (tcpdump sees them) but the input chain drops them before dhcpd: the server log stays silent.',
      evidence: 'rtr01: tcpdump shows "dhcp6 solicit" from fe80::5054:ff:fee7:2a to ff02::1:2.547; journalctl -u isc-dhcp-server has no Solicit lines since the reload; nft list ruleset has no udp dport 547 rule and input policy drop.',
      prevention: 'Document why each firewall rule exists (a comment per rule) and test both address families after a cleanup. Know which daemons bypass netfilter (packet sockets) and which do not.',
    },
    solution: [{ host: 'rtr01', commands: ["sed -i 's/^\\t\\tiifname \"eth0\" tcp dport 22 accept$/\\t\\tiifname \"eth0\" tcp dport 22 accept\\n\\t\\tiifname \"eth3.30\" udp dport 547 accept/' /etc/nftables.conf", 'systemctl reload nftables'] }, { host: 'dev02', commands: ['dhclient -6 eth0'] }],
    constraints: [dev02UsesDhcp6(), firewallStillRestrictive('rtr01')],
    concepts: ['net.ipv6', 'fw.stateful'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'dhcp6-wrong-interface',
    title: 'Listening on the trunk',
    difficulty: 'beginner',
    ticket: 'Monitoring: "isc-dhcp-server on rtr01: failed" since the maintenance window. The change log says INTERFACESv6 was "corrected to the physical port" (CHG-1410). VLAN 30 laptops are losing IPv6.',
    briefing: BRIEFING,
    goals: [DEV2_WEB6, DEV1_WEB6],
    terminals: TERMINALS,
    setup(world) {
      edit(world, 'rtr01', '/etc/default/isc-dhcp-server', (s) => s.replace('INTERFACESv6="eth3.30"', 'INTERFACESv6="eth3"'));
      script(world, 'rtr01', ['systemctl restart isc-dhcp-server']);
      expire(world);
    },
    rootCauses: ['dhcp6-wrong-interface'],
    candidates: CANDIDATES,
    feedback: {
      'dhcp6-client-firewall': 'No DHCPv6 server answers at all; dev02\'s firewall is not involved.',
      'dhcp6-server-firewall': 'rtr01\'s firewall still accepts UDP 547 on eth3.30, but nothing listens: the service is failed.',
      'dhcp-server-down': 'Close: the server is down, but why? Its log names the configuration problem (No subnet6 declaration for eth3).',
      'ipv6-icmp-blocked': 'Router advertisements still work; dev02 has a default route.',
      'ipv6-forwarding-off': 'dev01 reaches srv01 over IPv6.',
      'ipv6-server-no-route': 'srv01 answers dev01 over IPv6.',
      'dns-wrong-record': 'DNS is not involved: dev02 has no global address.',
    },
    hints: [
      'Start with the server: "systemctl status isc-dhcp-server" on rtr01.',
      '"No subnet6 declaration for eth3": dhcpd -6 serves a link when the interface has an address inside a subnet6. Which interface carries 2001:db8:30::1? (ip -6 addr)',
      'VLAN 30 is the sub-interface eth3.30; eth3 is only the trunk with a link-local address. Set INTERFACESv6="eth3.30" in /etc/default/isc-dhcp-server and restart isc-dhcp-server. Then "sudo dhclient -6 eth0" on dev02 (or wait for its next retry).',
    ],
    explanation: {
      rootCause: 'INTERFACESv6 was changed from the VLAN sub-interface eth3.30 to its parent eth3. eth3 carries the 802.1Q trunk and has only a link-local address, so no subnet6 declaration matches it.',
      manifestation: 'dhcpd -6 logs "No subnet6 declaration for eth3 (fe80::5054:ff:fea1:4)" and "Not configured to listen on any interfaces!", the init script reports "Starting ISC DHCPv6 server: dhcpd6check syslog for diagnostics. ... failed!" and the unit is failed. Clients keep their addresses until the valid lifetime (600 s) runs out, then lose IPv6.',
      evidence: 'systemctl status isc-dhcp-server (failed, the messages above); grep INTERFACESv6 /etc/default/isc-dhcp-server; ip -6 addr show eth3 (link-local only) vs eth3.30 (2001:db8:30::1/64).',
      prevention: 'On routers with VLAN sub-interfaces, services bind to the sub-interface. Check "systemctl is-failed" for every service after a change, and alert on failed units.',
    },
    solution: [{ host: 'rtr01', commands: [`sed -i 's/INTERFACESv6="eth3"/INTERFACESv6="eth3.30"/' /etc/default/isc-dhcp-server`, 'systemctl restart isc-dhcp-server'] }, { host: 'dev02', commands: ['dhclient -6 eth0'] }],
    constraints: [dev02UsesDhcp6(), firewallStillRestrictive('rtr01')],
    concepts: ['net.ipv6', 'svc.systemd'],
  },
];
