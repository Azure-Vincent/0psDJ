// Tickets that reproduce end-to-end case studies B and G (see
// src/content/casestudies/linux.ts): a server with no Internet access, and
// several "unrelated" services failing because of one shared dependency.

import { readFile, writeFile } from '../fs';
import { renderRule } from '../config/nft';
import type { World } from '../types';
import { firewallStillRestrictive, script } from './engine';
import type { Constraint, Goal, Scenario } from './types';

function edit(world: World, host: string, path: string, fn: (s: string) => string, gapMs = 60_000) {
  world.clock += gapMs;
  const h = world.hosts[host];
  writeFile(h, path, fn(readFile(h, path) ?? ''), world.clock);
}

const SRV_TO_INTERNET: Goal = { kind: 'http', description: 'On srv01, "curl -I http://203.0.113.80/" (the vendor\'s update mirror on the Internet) returns HTTP 200.', fromHost: 'srv01', fromUser: 'root', url: 'http://203.0.113.80/' };
const SRV_RESOLVES: Goal = { kind: 'resolve', description: 'srv01 resolves internal names: "getent hosts ns1.corp.lab" returns 10.0.10.53.', fromHost: 'srv01', name: 'ns1.corp.lab', expect: '10.0.10.53' };
const OFFICE_TO_INTERNET: Goal = { kind: 'http', description: 'The office still reaches the Internet: on ws01, "curl -I http://203.0.113.80/" returns HTTP 200.', fromHost: 'ws01', fromUser: 'alice', url: 'http://203.0.113.80/' };

const ALICE_SSH: Goal = {
  description: 'alice on ws01 can run "ssh srv01.corp.lab" and log in with her ed25519 key.',
  localUser: 'alice', user: 'alice', target: 'srv01.corp.lab', method: 'publickey',
};
const DANA_WEB: Goal = { kind: 'http', description: 'On ws02, "curl -I http://srv01.corp.lab/" (the intranet) returns HTTP 200.', fromHost: 'ws02', fromUser: 'dana', url: 'http://srv01.corp.lab/' };
const DEV_RESOLVES: Goal = { kind: 'resolve', description: 'On dev01 (VLAN 30, dual-stack), "getent hosts www.corp.lab" resolves to srv01 (its IPv6 address 2001:db8:20::10 is preferred).', fromHost: 'dev01', name: 'www.corp.lab', expect: '2001:db8:20::10' };

const NO_INTERNET_TERMINALS = [
  { hostId: 'srv01', user: 'root', label: 'srv01 console', banner: 'Out-of-band console on srv01 (root), the server that cannot reach the Internet.' },
  { hostId: 'rtr01', user: 'root', label: 'rtr01 console', banner: 'Console on the router rtr01 (root): eth0 office, eth1 servers, eth2 Internet 203.0.113.2.' },
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01 in the office (10.0.10.25). Its Internet access works. sudo password: ws01-alice.' },
  { hostId: 'ext01', user: 'guest', label: 'ext01 (Internet)', banner: 'ext01 = the update mirror on the Internet (203.0.113.80). It only knows public addresses.' },
];

const OUTAGE_TERMINALS = [
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01, alice\'s workstation. sudo password: ws01-alice.' },
  { hostId: 'ws02', user: 'dana', label: 'ws02 (dana)', banner: 'ws02, dana\'s DHCP laptop. sudo password: ws02-dana.' },
  { hostId: 'dev01', user: 'erin', label: 'dev01 (erin)', banner: 'dev01 on VLAN 30 (developers). sudo password: dev01-erin.' },
  { hostId: 'srv01', user: 'root', label: 'srv01 console', banner: 'Console on srv01 (root): SSH and the intranet web server.' },
  { hostId: 'ns1', user: 'root', label: 'ns1 console', banner: 'Console on ns1 (root): DNS (BIND) and DHCP for the office.' },
  { hostId: 'rtr01', user: 'root', label: 'rtr01 console', banner: 'Console on the router rtr01 (root).' },
];

/** Outbound NAT on rtr01 must still be limited to the uplink (not every interface). */
function natOnlyOnUplink(): Constraint {
  return {
    id: 'nat-uplink-only', required: true,
    description: 'rtr01 must masquerade only traffic leaving the Internet uplink (eth2); internal traffic between subnets must keep its real source addresses.',
    check(world) {
      const post = world.hosts.rtr01.nft.tables.flatMap((t) => t.chains).find((c) => c.base?.hook === 'postrouting');
      const masq = post?.rules.filter((r) => r.verdict?.kind === 'masquerade' || r.verdict?.kind === 'snat') ?? [];
      const unscoped = masq.find((r) => !r.matches.some((m) => m.kind === 'iface' && (m.field === 'oif' || m.field === 'oifname') && !m.negate));
      return unscoped
        ? { id: this.id, ok: false, required: true, message: `rtr01 rule "${renderRule(unscoped)}" masquerades traffic on every interface: servers would see the router instead of the real clients.` }
        : { id: this.id, ok: true, required: true, message: 'Masquerade is limited to the uplink.' };
    },
  };
}

/** ns1 must keep the new default-drop policy (the hardening change was approved; only its mistake is the problem). */
function ns1StillHardened(): Constraint {
  return {
    id: 'ns1-hardened', required: true,
    description: 'ns1 must keep the approved hardening: default-drop input policy, and DNS only for the internal networks (10.0.0.0/16), not the whole world.',
    check(world) {
      const h = world.hosts.ns1;
      const input = h.nft.tables.flatMap((t) => t.chains).find((c) => c.base?.hook === 'input');
      if (!input || input.base!.policy !== 'drop') return { id: this.id, ok: false, required: true, message: 'ns1: the input policy is no longer drop (the hardening change was reverted instead of fixed).' };
      const open = input.rules.find((r) => r.verdict?.kind === 'accept'
        && r.matches.some((m) => m.kind === 'port' && m.field === 'dport' && m.values.includes('53'))
        && !r.matches.some((m) => m.kind === 'addr' && m.field === 'saddr' && !m.negate && !m.values.some((v) => v === '0.0.0.0/0' || v === '::/0')));
      if (open) return { id: this.id, ok: false, required: true, message: `ns1: "${renderRule(open)}" answers DNS for any source address, which the change was meant to prevent.` };
      return { id: this.id, ok: true, required: true, message: 'ns1: default-drop with DNS limited to internal sources.' };
    },
  };
}

const NS1_HARDENED = `#!/usr/sbin/nft -f
# CHG-2207: harden ns1 (default deny). DNS for internal networks only.

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
		ip saddr 10.0.0.0/24 udp dport 53 accept
		ip saddr 10.0.0.0/24 tcp dport 53 accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

export const CASE_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'case-no-internet',
    title: 'The server has no Internet (case study B)',
    difficulty: 'intermediate',
    ticket: 'Ops: "srv01 cannot download security updates since yesterday afternoon: every connection to the mirror hangs. The office still has Internet. I already changed srv01\'s DNS to 8.8.8.8 in case it was DNS, but that did not help."',
    briefing: [
      'srv01 (10.0.20.10/24, gateway 10.0.20.1) is on the server network. rtr01 routes between office (eth0), servers (eth1) and the Internet uplink (eth2, public 203.0.113.2), and hides the private networks behind 203.0.113.2.',
      'The update mirror is 203.0.113.80 (ext01). Internal names (corp.lab) are served by ns1 (10.0.10.53).',
      'Yesterday at 14:00 a change "tidied up" rtr01\'s NAT rules. Fixes must survive a reboot of every machine.',
      'There may be more than one fault.',
    ],
    goals: [SRV_TO_INTERNET, SRV_RESOLVES, OFFICE_TO_INTERNET],
    terminals: NO_INTERNET_TERMINALS,
    setup(world) {
      edit(world, 'rtr01', '/etc/nftables.conf', (s) => s
        .replace('\t\toifname "eth2" masquerade\n', '\t\t# only the office needs Internet access (CHG-2191)\n\t\toifname "eth2" ip saddr 10.0.10.0/24 masquerade\n'));
      script(world, 'rtr01', ['systemctl reload nftables']);
      world.clock += 18 * 3600_000;
      edit(world, 'srv01', '/etc/resolv.conf', () => '# changed while troubleshooting the update problem\nnameserver 8.8.8.8\n');
      script(world, 'srv01', ['curl -m 5 -I http://203.0.113.80/', 'getent hosts ns1.corp.lab'], 120_000);
      world.clock += 3600_000;
    },
    rootCauses: ['nat-missing-masquerade', 'dns-client-config'],
    candidates: ['routing-server-gateway', 'routing-client', 'firewall-drop', 'nat-missing-masquerade', 'nat-filter-order', 'router-forwarding-disabled', 'dns-client-config', 'dns-zone-error', 'server-down', 'web-not-running'],
    acceptable: {},
    feedback: {
      'routing-server-gateway': 'srv01 has its default route via 10.0.20.1 (ip route), and tracepath/traceroute show packets leaving through rtr01. The path out exists; it is the way back that fails.',
      'router-forwarding-disabled': 'rtr01 forwards: srv01 reaches the office, and ws01 reaches the Internet through the same router.',
      'firewall-drop': 'Nothing is dropped. Capture on rtr01 eth2: srv01\'s packets do leave, with source 10.0.20.10, and replies never come back because a private address is not routable on the Internet.',
      'server-down': 'The mirror answers the office (curl from ws01 works).',
      'web-not-running': 'The mirror answers the office (curl from ws01 works).',
    },
    hints: [
      'Work up the layers on srv01: address and route (ip -br addr, ip route), the gateway (ping 10.0.20.1), a hop beyond (ping 203.0.113.80 by IP, so DNS is not involved), then names. Which is the first check that fails? And did the 8.8.8.8 change help, or add a second problem?',
      'Compare srv01 with ws01, which works. Both go through rtr01. On rtr01, run tcpdump -n -i eth2 while srv01 pings 203.0.113.80: what source address do srv01\'s packets carry when they leave for the Internet? Then read rtr01\'s nat table (nft list table ip nat).',
      'Restore "oifname "eth2" masquerade" in rtr01\'s /etc/nftables.conf and reload nftables. Then undo the "workaround" on srv01: 8.8.8.8 does not know corp.lab, so put nameserver 10.0.10.53 and search corp.lab back in /etc/resolv.conf.',
    ],
    explanation: {
      rootCause: 'The NAT "tidy-up" restricted masquerade to the office (ip saddr 10.0.10.0/24), so packets from the server network leave rtr01 with their private source 10.0.20.10. Internet hosts cannot reply to a private address. The DNS change made while troubleshooting was a second fault: 8.8.8.8 is unreachable for the same reason, and would not know corp.lab anyway.',
      manifestation: 'Everything inside the organisation works for srv01 (gateway, other subnets, ns1). Anything on the Internet times out, by name or by IP. Since the resolver change, internal names fail too ("Temporary failure in name resolution"), which looked like a DNS problem and hid the real one.',
      evidence: 'srv01: ping 10.0.20.1 works, ping 203.0.113.80 gets no replies, curl times out. rtr01: tcpdump -n -i eth2 shows "IP 10.0.20.10 > 203.0.113.80" (not 203.0.113.2), and ext01 has no route back to 10.0.20.0/24; nft list table ip nat shows the masquerade rule limited to 10.0.10.0/24; conntrack -L shows srv01\'s flows without a [dst=203.0.113.2] reply tuple. srv01: /etc/resolv.conf names 8.8.8.8 and dig ns1.corp.lab times out.',
      prevention: 'Review NAT changes against the list of networks that need Internet access, test from every subnet after a change, and record troubleshooting changes so they can be rolled back (a workaround that did not work must be undone).',
    },
    solution: [
      { host: 'rtr01', commands: ["sed -i 's/oifname \"eth2\" ip saddr 10.0.10.0\\/24 masquerade/oifname \"eth2\" masquerade/' /etc/nftables.conf", 'nft -c -f /etc/nftables.conf', 'systemctl reload nftables', 'nft list table ip nat'] },
      { host: 'srv01', commands: ["sed -i 's/nameserver 8.8.8.8/search corp.lab\\nnameserver 10.0.10.53/' /etc/resolv.conf", 'cat /etc/resolv.conf', 'getent hosts ns1.corp.lab', 'curl -I http://203.0.113.80/'] },
    ],
    constraints: [natOnlyOnUplink(), firewallStillRestrictive()],
    concepts: ['net.nat', 'dns.resolution', 'net.routing'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'case-dns-outage',
    title: 'Everything is broken at once (case study G)',
    difficulty: 'advanced',
    ticket: 'Three tickets in ten minutes. Alice: "ssh srv01 says Could not resolve hostname." Dana: "The intranet site is down." Erin (developers, VLAN 30): "Our build cannot find www.corp.lab." The web team says nginx on srv01 is running and the SSH team says sshd is fine.',
    briefing: [
      'Office 10.0.10.0/24 (ws01 static, ws02 DHCP), servers 10.0.20.0/24 (srv01: SSH and intranet web), developers VLAN 30 10.0.30.0/24 (dev01). rtr01 routes between them.',
      'ns1 (10.0.10.53) is the DNS server for every network (zone corp.lab) and the DHCP server for the office.',
      'This morning change CHG-2207 "hardened" ns1 with a default-deny firewall. The change itself is approved and must stay; fix it, do not revert it.',
    ],
    goals: [ALICE_SSH, DANA_WEB, DEV_RESOLVES],
    terminals: OUTAGE_TERMINALS,
    setup(world) {
      edit(world, 'ns1', '/etc/nftables.conf', () => NS1_HARDENED);
      script(world, 'ns1', ['systemctl restart nftables']);
      world.clock += 25 * 60_000;
    },
    rootCauses: ['fw-cidr-error'],
    acceptable: {
      'firewall-drop': 'Correct: ns1\'s firewall drops the DNS queries. The precise cause is the prefix: 10.0.0.0/24 only covers 10.0.0.0-10.0.0.255, none of the client networks.',
    },
    candidates: ['sshd-not-running', 'web-not-running', 'server-down', 'routing-client', 'dns-client-config', 'dns-zone-error', 'dns-wrong-record', 'firewall-drop', 'fw-cidr-error', 'dhcp-server-down'],
    feedback: {
      'sshd-not-running': 'ssh 10.0.20.10 works from ws01. sshd is fine; the client never gets an address to connect to.',
      'web-not-running': 'curl -I http://10.0.20.10/ returns 200 from ws02. nginx is fine; only the name fails.',
      'server-down': 'srv01 answers by IP from every network.',
      'dns-zone-error': 'On ns1 itself, dig @127.0.0.1 srv01.corp.lab answers correctly: the zone is loaded. The queries from clients never reach named.',
      'dns-client-config': 'All three clients have the right nameserver (10.0.10.53), and they are configured in three different ways (static file, DHCP, VLAN host). A shared server-side cause is much more likely.',
      'dhcp-server-down': 'ws02 has a valid lease; DHCP (udp/67) is still allowed on ns1.',
      'routing-client': 'Every client reaches srv01 by IP, and pings ns1 successfully.',
    },
    hints: [
      'Three teams, three symptoms. Before investigating each one, list what the failing operations have in common. Try each failing operation by IP address instead of by name: what changes?',
      'Everything works by IP. So test name resolution directly from a client: dig srv01.corp.lab. Is the DNS server answering with an error (status: SERVFAIL/NXDOMAIN) or not answering at all ("connection timed out; no servers could be reached")? Then query ns1 from ns1 itself (dig @127.0.0.1).',
      'named answers locally but not to clients, and ping to ns1 works: look at ns1\'s new firewall (nft list ruleset). The DNS rules allow "ip saddr 10.0.0.0/24", which is 10.0.0.0-10.0.0.255. The internal networks are 10.0.0.0/16. Fix /etc/nftables.conf and reload nftables.',
    ],
    explanation: {
      rootCause: 'CHG-2207 limited DNS on ns1 to "ip saddr 10.0.0.0/24" instead of 10.0.0.0/16. No client address (10.0.10.x, 10.0.20.x, 10.0.30.x) is inside 10.0.0.0/24, so the new default-drop policy silently discards every DNS query from every network.',
      manifestation: 'Every service accessed by name appears broken: SSH ("Could not resolve hostname ... Temporary failure in name resolution"), the intranet web site (curl: "Could not resolve host"), builds on VLAN 30. The services themselves are healthy and everything works by IP. DHCP and SSH to ns1 keep working, because udp/67 and tcp/22 are allowed, which made "ns1 is up" look reassuring.',
      evidence: 'Clients: dig srv01.corp.lab → "connection timed out; no servers could be reached"; ssh/curl by IP succeed; ping 10.0.10.53 succeeds. ns1: dig @127.0.0.1 srv01.corp.lab answers 10.0.20.10; ss -ulnp shows named on :53; nft list ruleset shows policy drop and the 10.0.0.0/24 rules; tcpdump -n -i eth0 port 53 on ns1 shows queries arriving and no replies.',
      prevention: 'Test firewall changes from every client network before closing the change; compute prefixes with a calculator (ipcalc) and peer review; monitor name resolution from each network, not just "is named running"; when many services fail at once, look for the shared dependency first.',
    },
    solution: [
      { host: 'ns1', commands: ["sed -i 's#ip saddr 10.0.0.0/24#ip saddr 10.0.0.0/16#' /etc/nftables.conf", 'nft -c -f /etc/nftables.conf', 'systemctl reload nftables', 'nft list chain inet filter input'] },
      { host: 'ws01', user: 'alice', commands: ['dig +short srv01.corp.lab', 'getent hosts www.corp.lab'] },
    ],
    constraints: [ns1StillHardened()],
    concepts: ['dns.resolution', 'fw.stateful', 'net.cidr'],
  },
];
