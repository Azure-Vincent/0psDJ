// VLAN and IPv6 tickets. sw01 is a VLAN-aware Linux bridge (ifupdown2): VLAN 10
// office, VLAN 20 servers, VLAN 30 development. rtr01 routes VLAN 30 over a
// trunk (eth3, sub-interface eth3.30) and advertises 2001:db8:30::/64 with
// radvd; dev01 (VLAN 30) is dual-stack with SLAAC; srv01 has 2001:db8:20::10.

import { readFile, writeFile } from '../fs';
import type { World } from '../types';
import { firewallStillRestrictive, script } from './engine';
import type { Constraint, Goal, Scenario } from './types';

const DEV_WEB: Goal = { kind: 'http', description: 'On dev01, "curl -I http://srv01.corp.lab/" returns HTTP 200.', fromHost: 'dev01', fromUser: 'erin', url: 'http://srv01.corp.lab/' };
const DEV_WEB6: Goal = { kind: 'http', description: 'On dev01, "curl -6 -I http://srv01.corp.lab/" (IPv6 only) returns HTTP 200.', fromHost: 'dev01', fromUser: 'erin', url: 'http://srv01.corp.lab/', curlFlags: '-6' };
const DEV_WEB4: Goal = { kind: 'http', description: 'On dev01, "curl -4 -I http://srv01.corp.lab/" (IPv4 only) still returns HTTP 200.', fromHost: 'dev01', fromUser: 'erin', url: 'http://srv01.corp.lab/', curlFlags: '-4' };
const OFFICE_WEB: Goal = { kind: 'http', description: 'From ws01 (office VLAN), "curl -I http://srv01.corp.lab/" still returns HTTP 200.', fromHost: 'ws01', fromUser: 'alice', url: 'http://srv01.corp.lab/' };

const VLAN_TERMINALS = [
  { hostId: 'dev01', user: 'erin', label: 'dev01 (erin)', banner: 'dev01, developer workstation on VLAN 30 (10.0.30.25, IPv6 by SLAAC). sudo password: dev01-erin.' },
  { hostId: 'sw01', user: 'root', label: 'sw01 console', banner: 'Serial console on the switch sw01 (Debian, VLAN-aware bridge br0 configured with ifupdown2). Try: bridge vlan show, bridge fdb show.' },
  { hostId: 'rtr01', user: 'root', label: 'rtr01 console', banner: 'Console on the router rtr01 (root): eth0 VLAN 10, eth1 VLAN 20, eth3 trunk with eth3.30 for VLAN 30.' },
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01 in the office VLAN 10. sudo password: ws01-alice.' },
];
const IPV6_TERMINALS = [
  { hostId: 'dev01', user: 'erin', label: 'dev01 (erin)', banner: 'dev01 on VLAN 30: 10.0.30.25 and an IPv6 address from router advertisements. sudo password: dev01-erin.' },
  { hostId: 'rtr01', user: 'root', label: 'rtr01 console', banner: 'Console on rtr01 (root): routes IPv4 and IPv6, runs radvd on eth3.30.' },
  { hostId: 'srv01', user: 'root', label: 'srv01 console', banner: 'Console on srv01 (root): 10.0.20.10 and 2001:db8:20::10, nginx and sshd on both families.' },
  { hostId: 'ns1', user: 'root', label: 'ns1 console', banner: 'Console on ns1 (root): DNS for corp.lab (A and AAAA records).' },
];

const VLAN_BRIEFING = [
  'sw01 is the access switch: a Linux bridge with VLAN filtering. VLAN 10 = office (10.0.10.0/24), VLAN 20 = servers (10.0.20.0/24), VLAN 30 = development (10.0.30.0/24, 2001:db8:30::/64).',
  'rtr01 is the gateway of every VLAN: eth0 (VLAN 10) and eth1 (VLAN 20) are access ports; VLAN 30 arrives tagged on the trunk eth3 and is routed on the sub-interface eth3.30 (10.0.30.1).',
  'The switch is configured in /etc/network/interfaces (ifupdown2: bridge-access, bridge-vids, bridge-pvid) and applied with ifreload -a. Fixes must survive a reboot of every device.',
];
const IPV6_BRIEFING = [
  'IPv6 pilot (NET-40): VLAN 30 (dev01) gets 2001:db8:30::/64 by SLAAC from radvd on rtr01; srv01 has 2001:db8:20::10/64; ns1 publishes an AAAA record for srv01.',
  'dev01 is dual-stack, so applications try IPv6 first. Browsers and curl fall back to IPv4 quickly (Happy Eyeballs); ssh and many scripts do not.',
  'Fixes must survive a reboot of every device and must not weaken host firewalls.',
];

const VLAN_CANDIDATES = ['vlan-access-wrong', 'vlan-trunk-missing', 'vlan-subif-mismatch', 'client-netmask', 'routing-client', 'router-forwarding-disabled', 'firewall-drop', 'dns-client-config'];
const IPV6_CANDIDATES = ['ipv6-icmp-blocked', 'ipv6-forwarding-off', 'ipv6-server-no-route', 'firewall-drop', 'web-not-running', 'dns-wrong-record', 'vlan-trunk-missing', 'routing-server-gateway'];

function edit(world: World, host: string, path: string, fn: (s: string) => string, gapMs = 60_000) {
  world.clock += gapMs;
  const h = world.hosts[host];
  writeFile(h, path, fn(readFile(h, path) ?? ''), world.clock);
}

/** VLAN isolation: dev01 stays in VLAN 30 and VLAN 30 does not leak onto office/server ports. */
function vlanIsolation(): Constraint {
  return {
    id: 'vlan-isolation', required: true,
    description: 'dev01 must stay in VLAN 30 with its 10.0.30.25 address, and office/server ports (swp1–swp6) must not carry VLAN 30.',
    check(world) {
      const b = world.hosts.sw01.bridge;
      const devPort = b?.ports.swp8;
      if (!devPort || devPort.pvid !== 30) return { id: this.id, ok: false, required: true, message: 'swp8 (dev01) is no longer an access port in VLAN 30.' };
      const leak = ['swp1', 'swp2', 'swp3', 'swp4', 'swp5', 'swp6'].find((p) => b!.ports[p]?.vids.includes(30));
      if (leak) return { id: this.id, ok: false, required: true, message: `${leak} now carries VLAN 30: the development VLAN leaks into the office/server network.` };
      const devCfg = readFile(world.hosts.dev01, '/etc/network/interfaces') ?? '';
      if (!/address 10\.0\.30\.25\/24/.test(devCfg)) return { id: this.id, ok: false, required: true, message: 'dev01 was readdressed instead of fixing the switch.' };
      return { id: this.id, ok: true, required: true, message: 'VLAN 30 is isolated and dev01 is still in it.' };
    },
  };
}

function devStillSlaac(): Constraint {
  return {
    id: 'dev01-slaac', required: true,
    description: 'dev01 must keep getting IPv6 by SLAAC ("iface eth0 inet6 auto"), not a static workaround.',
    check(world) {
      const ok = /iface eth0 inet6 auto/.test(readFile(world.hosts.dev01, '/etc/network/interfaces') ?? '') && !/inet6 static/.test(readFile(world.hosts.dev01, '/etc/network/interfaces') ?? '');
      return { id: this.id, ok, required: true, message: ok ? 'dev01 uses SLAAC.' : 'dev01 was switched to a static IPv6 configuration.' };
    },
  };
}

function hardeningKept(): Constraint {
  return {
    id: 'hardening-kept', required: true,
    description: 'Keep the CIS hardening file on rtr01 (its other settings are required by the security team).',
    check(world) {
      const f = readFile(world.hosts.rtr01, '/etc/sysctl.d/99-zz-cis-hardening.conf') ?? '';
      const ok = /send_redirects\s*=\s*0/.test(f);
      return { id: this.id, ok, required: true, message: ok ? 'The hardening settings are still in place.' : 'The hardening file (or its other settings) was removed.' };
    },
  };
}

export const VLAN_IPV6_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'vlan-access-port',
    title: 'Plugged in, link up, nothing works',
    difficulty: 'beginner',
    ticket: 'Erin (developer): "Since the desk move my workstation dev01 can\'t reach anything, not even the gateway. The cable is fine, the link LED is on and my settings haven\'t changed." Network team: "We standardised all desk ports on sw01 yesterday."',
    briefing: VLAN_BRIEFING,
    goals: [DEV_WEB],
    terminals: VLAN_TERMINALS,
    setup(world) {
      edit(world, 'sw01', '/etc/network/interfaces', (s) => s.replace('    alias dev01\n    bridge-access 30', '    alias dev01\n    bridge-access 10 # standard desk port'));
      script(world, 'sw01', ['ifreload -a']);
      world.clock += 10 * 3600_000;
      script(world, 'dev01', ['reboot']);
      world.clock += 3600_000;
    },
    rootCauses: ['vlan-access-wrong'],
    candidates: VLAN_CANDIDATES,
    feedback: {
      'client-netmask': 'dev01\'s address and prefix are unchanged (10.0.30.25/24). The host side is fine: look at the switch port.',
      'routing-client': 'dev01\'s default route points at 10.0.30.1, which is correct. The problem is that 10.0.30.1 does not answer ARP at all.',
      'vlan-trunk-missing': 'The trunk to the router still carries VLAN 30 (bridge vlan show, swp7). It is dev01\'s own port that changed.',
    },
    hints: [
      'Start on dev01: "ip neigh" after a ping to 10.0.30.1. Is it FAILED (no ARP reply) or REACHABLE? A FAILED gateway with a correct host configuration points at layer 2.',
      'On sw01: "bridge vlan show" and "bridge fdb show". In which VLAN was dev01\'s MAC address (52:54:00:e7:00:1e) learned, and which VLAN should port swp8 be in?',
      'swp8 was changed to "bridge-access 10 # standard desk port". dev01 belongs in VLAN 30: set "bridge-access 30" in /etc/network/interfaces on sw01 and run "ifreload -a".',
    ],
    explanation: {
      rootCause: 'The "standardisation" set dev01\'s switch port swp8 to "bridge-access 10" (the office VLAN). dev01 is configured for VLAN 30 (10.0.30.0/24).',
      manifestation: 'The link is up and dev01 sends ARP requests for 10.0.30.1, but they are flooded in VLAN 10, where nobody has that address. ping prints "Destination Host Unreachable" from dev01 itself; IPv6 never gets a router advertisement (no global address after the reboot). In VLAN 10, dev01 would even see office broadcasts and could get an office address via DHCP.',
      evidence: 'dev01: "ip neigh" shows 10.0.30.1 FAILED, "ip -6 addr" only a link-local address. sw01: "bridge vlan show" lists swp8 with "10 PVID Egress Untagged"; "bridge fdb show" learned 52:54:00:e7:00:1e on swp8 in vlan 10.',
      prevention: 'Describe ports (alias) and generate switch configuration from an inventory; after changes compare "bridge vlan show" against the documentation; a monitoring check that pings each VLAN gateway from an access port.',
    },
    solution: [{ host: 'sw01', commands: ["sed -i 's/bridge-access 10 # standard desk port/bridge-access 30/' /etc/network/interfaces", 'ifreload -a', 'bridge vlan show'] }],
    constraints: [vlanIsolation()],
    concepts: ['net.vlan', 'net.arp'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'vlan-trunk-pruned',
    title: 'The whole development VLAN is cut off',
    difficulty: 'intermediate',
    ticket: 'Erin: "Nobody on the dev network can reach anything since last night\'s switch maintenance. We can ping each other, but not the gateway." Change log NET-52: "sw01: pruned unused VLANs from trunk ports".',
    briefing: VLAN_BRIEFING,
    goals: [DEV_WEB, OFFICE_WEB],
    terminals: VLAN_TERMINALS,
    setup(world) {
      edit(world, 'sw01', '/etc/network/interfaces', (s) => s.replace('    alias rtr01 eth3 (trunk)\n    bridge-vids 30', '    alias rtr01 eth3 (trunk)\n    bridge-vids 20'));
      script(world, 'sw01', ['ifreload -a']);
      world.clock += 9 * 3600_000;
    },
    rootCauses: ['vlan-trunk-missing'],
    acceptable: { 'vlan-access-wrong': 'Close: a switch VLAN setting is wrong, but dev01\'s access port is fine; it is the trunk to the router (swp7).' },
    candidates: VLAN_CANDIDATES,
    feedback: {
      'router-forwarding-disabled': 'Then dev01 could still reach 10.0.30.1 itself (and ARP would succeed). Here the gateway does not even answer ARP.',
      'vlan-subif-mismatch': 'rtr01\'s eth3.30 is still VLAN 30 ("ip -d link show eth3.30"). Compare with what the switch allows on swp7.',
    },
    hints: [
      'dev01 cannot ARP its gateway 10.0.30.1, but the office (VLAN 10) is fine. What connects VLAN 30 to the router?',
      'On rtr01: "tcpdump -e -n -i eth3" while dev01 pings. Do tagged frames (vlan 30) leave rtr01 and does anything come back? On sw01: "bridge vlan show" for swp7.',
      'swp7 (trunk to rtr01) now carries VLAN 20 instead of 30 ("bridge-vids 20"). Set "bridge-vids 30" for swp7 in /etc/network/interfaces on sw01 and run "ifreload -a".',
    ],
    explanation: {
      rootCause: 'The pruning change replaced VLAN 30 with VLAN 20 on the trunk port swp7. The router\'s sub-interface eth3.30 sends frames tagged 30; the switch drops them at ingress (VLAN not configured on the port) and never sends VLAN 30 traffic to the router.',
      manifestation: 'Hosts inside VLAN 30 still reach each other (same switch, same VLAN), but ARP for the gateway 10.0.30.1 goes unanswered: "Destination Host Unreachable". rtr01 shows eth3.30 UP with the correct address, which makes it look fine. Other VLANs are unaffected.',
      evidence: 'sw01: "bridge vlan show" lists swp7 with 1 PVID Egress Untagged and 20 (no 30). rtr01: "tcpdump -e -i eth3" shows only outgoing frames with "vlan 30"; "ip neigh" on dev01: 10.0.30.1 FAILED.',
      prevention: 'Prune trunks from an inventory of which VLANs are used behind each port, never by guesswork; test every VLAN gateway after trunk changes.',
    },
    solution: [{ host: 'sw01', commands: ["sed -i 's/    bridge-vids 20$/    bridge-vids 30/' /etc/network/interfaces", 'ifreload -a', 'bridge vlan show'] }],
    constraints: [vlanIsolation()],
    concepts: ['net.vlan'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'vlan-subif-id',
    title: 'The router came back from the backup with a typo',
    difficulty: 'intermediate',
    ticket: 'Erin: "After rtr01 was restored from backup this morning, dev01 has no network. Office and servers are fine." Ops: "We reused the config backup and fixed some interface names that looked inconsistent."',
    briefing: VLAN_BRIEFING,
    goals: [DEV_WEB, OFFICE_WEB],
    terminals: VLAN_TERMINALS,
    setup(world) {
      edit(world, 'rtr01', '/etc/network/interfaces', (s) => s.replaceAll('eth3.30', 'eth3.3'));
      script(world, 'rtr01', ['reboot']);
      world.clock += 3 * 3600_000;
    },
    rootCauses: ['vlan-subif-mismatch'],
    acceptable: { 'vlan-trunk-missing': 'The symptom is the same, but the switch still allows VLAN 30 on swp7. It is the router that tags with the wrong ID.' },
    candidates: VLAN_CANDIDATES,
    feedback: {
      'vlan-access-wrong': 'dev01\'s port is still in VLAN 30 (bridge vlan show, swp8). Follow the path to the router.',
    },
    hints: [
      'The gateway 10.0.30.1 does not answer ARP. Is the switch carrying VLAN 30 to the router (bridge vlan show)? If yes, look at the router\'s side.',
      'On rtr01: "ip -d link show" or "ip -br addr". Which VLAN ID does the sub-interface holding 10.0.30.1 use? radvd\'s journal also complains about an interface.',
      'The sub-interface is eth3.3 (VLAN 3). Rename it back to eth3.30 in /etc/network/interfaces (all three lines) and restart networking, then restart radvd.',
    ],
    explanation: {
      rootCause: 'Debian derives the VLAN ID from the interface name: eth3.3 is VLAN 3 on eth3. The "inconsistent names" edit changed eth3.30 to eth3.3, so 10.0.30.1 now lives on VLAN 3, which the switch does not carry on swp7.',
      manifestation: 'rtr01 looks healthy ("ip addr" shows 10.0.30.1/24 UP), but its frames are tagged 3 and the switch drops them; dev01 cannot ARP its gateway. radvd logs "interface eth3.30 does not exist", so IPv6 advertisements stop as well.',
      evidence: '"ip -d link show eth3.3" on rtr01: "vlan protocol 802.1Q id 3"; "tcpdump -e -i eth3" shows "vlan 3"; sw01 "bridge vlan show": swp7 carries 30; "journalctl -u radvd": interface eth3.30 does not exist.',
      prevention: 'Treat interface names of VLAN sub-interfaces as configuration, not cosmetics (or use explicit "vlan-raw-device"/"vlan-id" naming like vlan30); diff restored configs against the running state before rebooting.',
    },
    solution: [{ host: 'rtr01', commands: ["sed -i 's/eth3\\.3$/eth3.30/; s/eth3\\.3 /eth3.30 /' /etc/network/interfaces", 'systemctl restart networking', 'systemctl restart radvd', 'ip -d link show eth3.30'] }],
    constraints: [vlanIsolation(), firewallStillRestrictive('rtr01')],
    concepts: ['net.vlan'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'ipv6-icmp-hardening',
    title: 'IPv6 to the web server fails, IPv4 is fine',
    difficulty: 'intermediate',
    ticket: 'Erin: "Our deployment script uses curl -6 against srv01 and fails with \'No route to host\'. In the browser the site works (slowly?)." Security ticket SEC-88 (yesterday): "srv01: restrict ICMPv6 to echo only".',
    briefing: IPV6_BRIEFING,
    goals: [DEV_WEB6, DEV_WEB4],
    terminals: IPV6_TERMINALS,
    setup(world) {
      edit(world, 'srv01', '/etc/nftables.conf', (s) => s.replace('meta l4proto ipv6-icmp accept', 'icmpv6 type { echo-request, echo-reply } accept comment "SEC-88"'));
      script(world, 'srv01', ['systemctl reload nftables']);
      world.clock += 20 * 3600_000;
      for (const h of Object.values(world.hosts)) h.neighbors = [];
    },
    rootCauses: ['ipv6-icmp-blocked'],
    acceptable: { 'firewall-drop': 'Yes, srv01\'s firewall drops it, but not the TCP connection: it drops the Neighbor Discovery that IPv6 needs before any TCP packet can be delivered.' },
    candidates: IPV6_CANDIDATES,
    feedback: {
      'ipv6-server-no-route': 'The error comes from the router ("Address unreachable" from 2001:db8:20::1): the packet never reached srv01. Where would srv01\'s routes matter?',
      'dns-wrong-record': 'The AAAA record (2001:db8:20::10) is correct, and that is srv01\'s address.',
    },
    hints: [
      'Who sends the error? ping -6 srv01.corp.lab from dev01 and read the "From" address and the message.',
      'On rtr01: "ip -6 neigh" after the test. What is the state of 2001:db8:20::10? How does a router learn an IPv6 neighbour\'s MAC address, and which protocol carries that?',
      'NDP is ICMPv6 (neighbor solicitation/advertisement), and nftables filters it. SEC-88 limited ICMPv6 to echo. Restore "meta l4proto ipv6-icmp accept" (or allow the nd-* types) on srv01 and reload nftables.',
    ],
    explanation: {
      rootCause: 'SEC-88 replaced "meta l4proto ipv6-icmp accept" with "icmpv6 type { echo-request, echo-reply } accept". IPv6 has no ARP: neighbour resolution uses ICMPv6 Neighbor Solicitations, which now hit srv01\'s input policy drop.',
      manifestation: 'rtr01 cannot resolve srv01\'s MAC address for 2001:db8:20::10, so it discards the packets and reports ICMPv6 "address unreachable": curl -6 fails with "No route to host", ping -6 with "Address unreachable" (not even ping works, despite the echo rule). Dual-stack clients like curl quietly fall back to IPv4, which hides the problem from most users.',
      evidence: 'rtr01 "ip -6 neigh": 2001:db8:20::10 dev eth1 FAILED; srv01 "nft list ruleset": only echo types accepted; "tcpdump -i eth0 icmp6" on srv01 shows neighbor solicitations arriving and no advertisements leaving.',
      prevention: 'Never filter ICMPv6 like ICMP: RFC 4890 lists what must pass (at least neighbor/router solicitation and advertisement, packet-too-big, destination-unreachable, time-exceeded). Test both address families after firewall changes.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i 's/icmpv6 type { echo-request, echo-reply } accept comment \"SEC-88\"/meta l4proto ipv6-icmp accept/' /etc/nftables.conf", 'systemctl reload nftables', 'nft list chain inet filter input'] }],
    constraints: [firewallStillRestrictive(), devStillSlaac()],
    concepts: ['net.ndp', 'net.ipv6', 'fw.stateful'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'ipv6-forwarding-hardening',
    title: 'Addresses yes, connectivity no',
    difficulty: 'advanced',
    ticket: 'Erin: "dev01 still gets its 2001:db8:30:: address and can ping the router over IPv6, but nothing beyond it. Our IPv6-only test (curl -6) times out." Ops: "rtr01 got the new CIS sysctl baseline and was rebooted last night."',
    briefing: IPV6_BRIEFING,
    goals: [DEV_WEB6, DEV_WEB4],
    terminals: IPV6_TERMINALS,
    setup(world) {
      world.clock += 60_000;
      writeFile(world.hosts.rtr01, '/etc/sysctl.d/99-zz-cis-hardening.conf', '# CIS Debian 12 benchmark, network parameters (host only)\nnet.ipv4.conf.all.send_redirects = 0\nnet.ipv4.conf.default.send_redirects = 0\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv6.conf.all.accept_redirects = 0\nnet.ipv6.conf.all.forwarding = 0\n', world.clock);
      script(world, 'rtr01', ['reboot']);
      world.clock += 8 * 3600_000;
    },
    rootCauses: ['ipv6-forwarding-off'],
    candidates: IPV6_CANDIDATES,
    feedback: {
      'ipv6-icmp-blocked': 'Nothing returns an error, and srv01\'s neighbour entries resolve fine. The packets die silently somewhere: where does a packet stop being forwarded without an error in IPv6?',
      'ipv6-server-no-route': 'tcpdump on srv01 shows no IPv6 SYNs arriving at all, so srv01\'s return route is not involved yet.',
      'vlan-trunk-missing': 'dev01 reaches the router (ping -6 2001:db8:30::1 works), so VLAN 30 is fine.',
    },
    hints: [
      'Narrow it down: ping -6 the router\'s near address (2001:db8:30::1), its far address (2001:db8:20::1) and srv01. Where does it stop? Is there any error message?',
      'A router silently dropping IPv6 that is not addressed to itself: check "sysctl net.ipv6.conf.all.forwarding" on rtr01, and "journalctl -u radvd".',
      'The CIS baseline file /etc/sysctl.d/99-zz-cis-hardening.conf sets net.ipv6.conf.all.forwarding = 0 and is applied after 99-router.conf. Set it to 1 there (keep the other settings) and run "sysctl --system".',
    ],
    explanation: {
      rootCause: 'The hardening baseline is written for end hosts and disables IPv6 forwarding. Files in /etc/sysctl.d are applied in name order, so 99-zz-cis-hardening.conf overrides 99-router.conf after the reboot.',
      manifestation: 'radvd keeps advertising the prefix (it only warns "IPv6 forwarding seems to be disabled, but continuing anyway"), so dev01 has a global address and a default route. Packets to the router itself work, but everything to be forwarded is discarded silently: IPv6 sends no error for this, so curl -6 and ssh -6 time out. IPv4 forwarding is a separate switch and still works.',
      evidence: 'rtr01: "sysctl net.ipv6.conf.all.forwarding" = 0; "sysctl --system" shows the order of files; "journalctl -u radvd": forwarding warning. dev01: ping -6 2001:db8:30::1 works, ping -6 2001:db8:20::1 (the router\'s other side, still local to the router) works, srv01 does not; srv01 tcpdump: silence.',
      prevention: 'Apply host baselines to routers only with documented exceptions; check "sysctl --system" output (the last file wins) and test IPv6 separately from IPv4 after changes.',
    },
    solution: [{ host: 'rtr01', commands: ["sed -i 's/net.ipv6.conf.all.forwarding = 0/net.ipv6.conf.all.forwarding = 1/' /etc/sysctl.d/99-zz-cis-hardening.conf", 'sysctl --system', 'sysctl net.ipv6.conf.all.forwarding'] }],
    constraints: [hardeningKept(), firewallStillRestrictive('rtr01'), devStillSlaac()],
    concepts: ['net.ipv6', 'net.routing'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'ipv6-server-gateway',
    title: 'SYNs arrive, nothing comes back (IPv6 edition)',
    difficulty: 'intermediate',
    ticket: 'Erin: "curl -6 to srv01 hangs until it times out. IPv4 works." Ops: "We cleaned up srv01\'s interfaces file during the NIC replacement and restarted networking."',
    briefing: IPV6_BRIEFING,
    goals: [DEV_WEB6, DEV_WEB4],
    terminals: IPV6_TERMINALS,
    setup(world) {
      edit(world, 'srv01', '/etc/network/interfaces', (s) => s.replace('    gateway 2001:db8:20::1\n', ''));
      script(world, 'srv01', ['systemctl restart networking']);
      world.clock += 5 * 3600_000;
    },
    rootCauses: ['ipv6-server-no-route'],
    acceptable: { 'routing-server-gateway': 'Exactly the same mistake as the IPv4 classic, for the IPv6 family: srv01 has no IPv6 default route.' },
    candidates: IPV6_CANDIDATES,
    feedback: {
      'ipv6-forwarding-off': 'tcpdump on srv01 shows the SYNs arriving, so rtr01 forwards fine. Look at the return path.',
      'ipv6-icmp-blocked': 'Neighbour discovery works: the SYNs are delivered to srv01. The problem is the reply.',
    },
    hints: [
      'Run curl -6 on dev01 and capture on srv01 at the same time ("tcpdump -n -i eth0 ip6"). Do the SYNs arrive? Does srv01 answer?',
      'If SYNs arrive but no SYN-ACK leaves, check srv01\'s IPv6 routing table: "ip -6 route". Where would it send a packet to 2001:db8:30::/64?',
      'The "gateway 2001:db8:20::1" line was removed from the inet6 stanza. Restore it in /etc/network/interfaces and add the route now: ip -6 route add default via 2001:db8:20::1.',
    ],
    explanation: {
      rootCause: 'The inet6 stanza for eth0 lost its "gateway 2001:db8:20::1" line. srv01 is not a router and does not use router advertisements here, so it has no IPv6 default route: only 2001:db8:20::/64 and fe80::/64 are reachable.',
      manifestation: 'SYNs from dev01 arrive, but the SYN-ACK to 2001:db8:30::/64 has no route and is never sent. The client retransmits and times out. IPv4 still has its default route, so dual-stack clients fall back and most users notice nothing.',
      evidence: 'srv01: "ip -6 route" has no default; "tcpdump -i eth0 ip6" shows only incoming SYNs; "ip -6 route get 2001:db8:30::1" → Network is unreachable.',
      prevention: 'Keep the IPv4 and IPv6 stanzas together in reviews; monitor IPv6 reachability separately (an IPv4 check cannot see this).',
    },
    solution: [{ host: 'srv01', commands: ["sed -i 's|    address 2001:db8:20::10/64|    address 2001:db8:20::10/64\\n    gateway 2001:db8:20::1|' /etc/network/interfaces", 'ip -6 route add default via 2001:db8:20::1', 'ip -6 route'] }],
    constraints: [firewallStillRestrictive(), devStillSlaac()],
    concepts: ['net.ipv6', 'net.routing'],
  },
];
