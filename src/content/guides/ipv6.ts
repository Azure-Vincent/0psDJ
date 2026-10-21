// Operate & recover guide: IPv6 on hosts and the router (SLAAC via radvd,
// Neighbor Discovery, IPv6 routing and forwarding, ICMPv6 in firewalls).

import type { ServiceGuide } from '../types';

export const IPV6_GUIDE: ServiceGuide = {
  purpose:
    'IPv6 hosts usually configure themselves: the router sends **Router Advertisements** (RAs) with the prefix and itself as default gateway, and each host builds its address with **SLAAC**. Neighbours are found with **NDP** (ICMPv6) instead of ARP. Operationally this means three things break IPv6 that never break IPv4: no RAs (radvd stopped, wrong interface, forwarding off), **ICMPv6 blocked** by a firewall (NDP is ICMPv6, so blocking it breaks even the local link), and dual-stack clients **preferring IPv6** so that an IPv6-only fault looks like "the server is down" while IPv4 is fine. In the lab, rtr01 runs radvd on VLAN 30 (2001:db8:30::/64) and srv01 is dual-stack (2001:db8:20::10).',
  architecture: [
    { q: 'What does it accomplish?', a: 'IP connectivity with 128-bit addresses: no NAT needed, /64 per link, automatic host configuration, and link-local addresses (fe80::/10) on every interface for neighbour discovery and routing protocols.' },
    { q: 'How does it work internally?', a: 'Each interface gets a link-local address at link-up (from the MAC via modified EUI-64, or a stable random identifier). A host sends a Router Solicitation; routers answer (and periodically send) Router Advertisements carrying prefixes with flags (A = autonomous: use SLAAC; L = on-link), the router lifetime (default route), and optionally DNS (RDNSS). The host forms a global address from the prefix plus an interface identifier, installs `default via fe80::<router>` from the RA, and uses NDP (Neighbor Solicitation/Advertisement to the solicited-node multicast address) to resolve link-layer addresses.' },
    { q: 'Which protocols does it use?', a: 'IPv6 (RFC 8200), ICMPv6 (RFC 4443) for errors and echo, NDP (RFC 4861: RS 133, RA 134, NS 135, NA 136, Redirect 137), SLAAC (RFC 4862), address selection (RFC 6724), Happy Eyeballs in clients (RFC 8305). DHCPv6 (RFC 8415) is an alternative/addition, not used in the lab.' },
    { q: 'Which ports and transport?', a: 'NDP and RAs are ICMPv6, not TCP/UDP: firewalls must allow `meta l4proto ipv6-icmp` (at least types 133–136 and the error types 1–4). DHCPv6 uses UDP 546/547.' },
    { q: 'Which processes and OS components implement it?', a: 'Linux kernel IPv6 stack (SLAAC is done by the kernel when `accept_ra` is enabled; NetworkManager and systemd-networkd may handle RAs themselves); `radvd` on the router (`radvd.service`, `/etc/radvd.conf`); `rdisc6` (ndisc6 package) to request an RA by hand. Windows: the IPv6 stack, `netsh interface ipv6`, `Get-NetIPAddress -AddressFamily IPv6`. pfSense: router advertisements under Services > DHCPv6 Server & RA (radvd/rtadvd), Track Interface for delegated prefixes.' },
    { q: 'Which other services does it depend on?', a: 'Layer 2 with working multicast (NDP uses multicast; some virtual switches/Wi-Fi drop it), a router sending RAs on the link, **IPv6 forwarding** on that router, routes for every prefix in both directions (servers with static addresses also need an IPv6 default gateway), ICMPv6 allowed everywhere on the path, and AAAA records in DNS for names to prefer IPv6.' },
    { q: 'How do requests travel?', a: 'A dual-stack client resolves both A and AAAA; RFC 6724 orders global IPv6 first; curl and browsers race both (Happy Eyeballs), while ssh tries addresses in order and only falls back after a timeout. The first IPv6 packet to the router triggers an NS to the router\'s solicited-node group; the router answers with an NA; from then on routing is like IPv4, hop by hop, with the Hop Limit decremented.' },
    { q: 'How do authentication and authorisation work?', a: 'NDP and RAs are **unauthenticated**: any host can send RAs (rogue RA, e.g. from a misconfigured Windows ICS host) and redirect traffic. Switch features (RA Guard, ND inspection) and SEND (rarely deployed) mitigate it. Address configuration needs no credentials.' },
    { q: 'How does it start at boot?', a: 'Hosts: the interface comes up, the kernel creates the link-local address, sends RSs and configures SLAAC addresses when an RA arrives (seconds later). Routers: `net.ipv6.conf.all.forwarding=1` from sysctl.d, static IPv6 addresses from /etc/network/interfaces (`iface eth3.30 inet6 static`), then `radvd.service` starts sending RAs. **When forwarding is enabled, Linux ignores RAs** unless `accept_ra=2`, so routers configure their own uplink statically.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'If radvd stops, hosts keep their addresses and default route until the lifetimes expire (router lifetime 1800 s by default in the lab, prefix valid lifetime 86400 s), then lose IPv6 connectivity; new hosts get no global address at all. Dual-stack clients then fall back to IPv4 (fast with Happy Eyeballs, slow for ssh).' },
  ],
  ports: [
    { port: 'ICMPv6 133–137', proto: 'ICMPv6', purpose: 'Router/Neighbor Solicitation and Advertisement, Redirect' },
    { port: 'ICMPv6 1–4, 128/129', proto: 'ICMPv6', purpose: 'Errors (incl. Packet Too Big: needed for PMTU) and echo' },
    { port: '546/547', proto: 'UDP', purpose: 'DHCPv6 client/server (not in the lab)' },
  ],
  processes: [
    { name: 'kernel IPv6 stack', platform: 'Linux', role: 'Link-local, SLAAC (accept_ra), NDP, routing, forwarding' },
    { name: 'radvd', platform: 'Debian/Ubuntu/RHEL routers (rtr01)', role: 'Sends RAs from /etc/radvd.conf' },
    { name: 'NetworkManager / systemd-networkd', platform: 'Desktops, Ubuntu Server', role: 'May process RAs in user space (ipv6.method auto / IPv6AcceptRA=)' },
    { name: 'Windows IPv6 stack', platform: 'Windows 10/11, Server', role: 'SLAAC with temporary (privacy) addresses by default' },
    { name: 'rtadvd/radvd (pfSense)', platform: 'pfSense', role: 'RA per interface (Services > Router Advertisement)' },
  ],
  dependencies: {
    title: 'What dev01 needs to reach srv01 over IPv6',
    rows: [
      { label: 'App', nodes: [{ id: 'app', label: 'curl / ssh', sub: 'AAAA preferred', kind: 'client' }] },
      { label: 'Host', nodes: [{ id: 'addr', label: 'SLAAC address', sub: '2001:db8:30::/64', kind: 'os' }, { id: 'dr', label: 'Default route', sub: 'fe80:: from RA', kind: 'os' }, { id: 'nd', label: 'NDP', sub: 'router NA', kind: 'network' }] },
      { label: 'Router', nodes: [{ id: 'radvd', label: 'radvd', sub: 'RAs on eth3.30', kind: 'service' }, { id: 'fwd6', label: 'IPv6 forwarding', sub: 'sysctl', kind: 'os' }, { id: 'icmp', label: 'ICMPv6 allowed', sub: 'all firewalls', kind: 'network' }] },
      { label: 'Server', nodes: [{ id: 'sgw', label: 'srv01 IPv6 gw', sub: '2001:db8:20::1', kind: 'network' }, { id: 'svc', label: 'Service on [::]', sub: 'nginx, sshd', kind: 'service' }] },
    ],
    edges: [['app', 'addr'], ['app', 'dr'], ['dr', 'nd'], ['addr', 'radvd'], ['dr', 'radvd'], ['nd', 'icmp'], ['dr', 'fwd6'], ['fwd6', 'sgw'], ['sgw', 'svc']],
  },
  sequence: {
    title: 'dev01 comes up on VLAN 30 and reaches srv01',
    lanes: [{ id: 'h', label: 'dev01', sub: 'SLAAC host' }, { id: 'r', label: 'rtr01', sub: 'radvd' }, { id: 's', label: 'srv01', sub: '2001:db8:20::10' }],
    steps: [
      { from: 'h', to: 'h', label: 'link-local fe80::5054:ff:fee7:1e' },
      { from: 'h', to: 'r', label: 'RS to ff02::2', note: 'No answer (radvd stopped, wrong interface in radvd.conf) → only a link-local address.' },
      { from: 'r', to: 'h', label: 'RA 2001:db8:30::/64, lifetime 1800', note: 'Firewall blocking ipv6-icmp on the host drops the RA.' },
      { from: 'h', to: 'h', label: 'SLAAC 2001:db8:30:0:5054:ff:fee7:1e' },
      { from: 'h', to: 'r', label: 'NS for router / data packet' },
      { from: 'r', to: 's', label: 'forward (Hop Limit 63)', note: 'forwarding=0 → dropped; a missing route → ICMPv6 unreachable.' },
      { from: 's', to: 'h', label: 'reply via its IPv6 gateway', note: 'Server without an IPv6 default route → IPv6 times out while IPv4 works.' },
    ],
  },
  files: [
    { path: '/etc/radvd.conf', platform: 'Linux routers (rtr01)', kind: 'config', perms: 'root:root 0644', contains: '`interface eth3.30 { AdvSendAdvert on; prefix 2001:db8:30::/64 { AdvOnLink on; AdvAutonomous on; }; };`, optional RDNSS.', accessed: 'By radvd at start and on reload (SIGHUP).', problems: 'Wrong interface name → no RAs on the link. radvd refuses to start (or warns) when IPv6 forwarding is off. A prefix other than /64 breaks SLAAC.' },
    { path: '/etc/sysctl.d/*.conf (net.ipv6.conf.*)', platform: 'Linux', kind: 'config', contains: '`net.ipv6.conf.all.forwarding = 1` on routers; `accept_ra`, `disable_ipv6`, `use_tempaddr` on hosts.', accessed: 'At boot (systemd-sysctl) and `sysctl --system`.', problems: 'A hardening baseline with `forwarding = 0` or `disable_ipv6 = 1` silently removes IPv6 after the next reboot. Enabling forwarding on a host makes it ignore RAs (accept_ra must be 2).' },
    { path: '/etc/network/interfaces (inet6 stanzas)', platform: 'Debian (the lab)', kind: 'config', contains: '`iface eth0 inet6 static` with `address 2001:db8:20::10/64` and `gateway 2001:db8:20::1`; `inet6 auto` for SLAAC.', accessed: 'ifup at boot/ifreload.', problems: 'Servers with static IPv6 need an explicit IPv6 gateway: no RA reaches the server network.' },
    { path: '/etc/netplan/*.yaml, NetworkManager profiles', platform: 'Ubuntu, RHEL', kind: 'config', contains: '`accept-ra: true`, `addresses: [2001:db8::10/64]`, `routes: [{to: default, via: ...}]`; nmcli `ipv6.method auto|manual|disabled`.', accessed: 'On apply / connection up.', problems: '`ipv6.method disabled`/`ignore` on a profile disables SLAAC for that connection.' },
    { path: '/etc/nftables.conf (ICMPv6 rules)', platform: 'Linux', kind: 'config', contains: '`meta l4proto ipv6-icmp accept` (or specific `icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, ... }`).', accessed: 'With the firewall.', problems: 'Dropping ICMPv6 for "hardening" breaks NDP: neighbours never resolve and IPv6 fails even on the local link.' },
    { path: 'Registry / netsh interface ipv6', platform: 'Windows', kind: 'registry', contains: 'Per-interface IPv6 settings (`HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters`, DisabledComponents).', accessed: 'At boot.', problems: 'Microsoft does not support disabling IPv6 (DisabledComponents=0xFF) and some components (e.g. Exchange, DirectAccess) break; prefer prefer-IPv4 policies if needed.' },
  ],
  management: [
    {
      platform: 'Debian (dev01, rtr01, srv01: the lab)',
      tasks: [
        { task: 'Addresses and their origin', command: 'ip -6 addr', explain: 'A `scope global dynamic mngtmpaddr` address with valid_lft counting down came from SLAAC; only `scope link` = no RA received.', sim: true },
        { task: 'Routes', command: 'ip -6 route', explain: '`default via fe80::... proto ra` = learned from an RA (with expiry). Static servers show `default via 2001:db8:20::1`.', sim: true },
        { task: 'Neighbours', command: 'ip -6 neigh', explain: 'Router and peers with `REACHABLE`/`STALE`; `FAILED` = NDP gets no answer (ICMPv6 blocked, wrong VLAN).', sim: true },
        { task: 'Ask for an RA now', command: 'sudo rdisc6 eth0', explain: 'Prints the RA (prefix, lifetimes, router) or "Timed out" when no router answers. Needs root.', sim: true },
        { task: 'Router: radvd status and config', command: 'systemctl status radvd\ncat /etc/radvd.conf', explain: 'Active and advertising on the right interface.', sim: true },
        { task: 'Router: apply radvd changes', command: 'sudo systemctl reload radvd\nsudo systemctl restart radvd', explain: 'Reload re-reads the config (configtest first); restart if the interface changed.', sim: true },
        { task: 'Router: forwarding', command: 'sysctl net.ipv6.conf.all.forwarding', explain: 'Must be 1 on routers (separate from the IPv4 switch).', sim: true },
        { task: 'Test the path and the protocol', command: 'ping -6 -c 2 2001:db8:20::10\ntraceroute -6 -n 2001:db8:20::10\ncurl -6 -I http://srv01.corp.lab/', explain: 'Force IPv6 to separate an IPv6 fault from IPv4.', sim: true },
      ],
    },
    {
      platform: 'Ubuntu / RHEL',
      tasks: [
        { task: 'NetworkManager', command: 'nmcli -f IP6 device show eth0\nsudo nmcli connection modify eth0 ipv6.method auto && sudo nmcli connection up eth0', explain: 'Shows IPv6 addresses, gateway and DNS from RAs.' },
        { task: 'systemd-networkd', command: 'networkctl status eth0', explain: 'Shows addresses and the RA-learned gateway; `IPv6AcceptRA=` in the .network file.' },
      ],
    },
    {
      platform: 'Windows Server 2019/2022, Windows 10/11',
      tasks: [
        { task: 'Addresses and routes', command: 'Get-NetIPAddress -AddressFamily IPv6\nGet-NetRoute -AddressFamily IPv6 -DestinationPrefix ::/0\nnetsh interface ipv6 show neighbors', explain: 'SuffixOrigin `Link`/`Random` = SLAAC; temporary addresses are used for outgoing connections by default.' },
        { task: 'Test', command: 'Test-NetConnection 2001:db8:20::10 -Port 80\nping -6 srv01.corp.lab', explain: '—' },
      ],
    },
    {
      platform: 'pfSense',
      tasks: [
        { task: 'Router advertisements', command: 'Services > Router Advertisement > <interface> (Router mode: Unmanaged = SLAAC)\nStatus > System Logs > Routing', explain: 'Interface needs a static IPv6 or Track Interface. Firewall rules must pass IPv6 for the interface (separate from IPv4 rules).' },
      ],
    },
    {
      platform: 'Docker',
      tasks: [
        { task: 'Enable IPv6 for containers', command: '/etc/docker/daemon.json: { "ipv6": true, "fixed-cidr-v6": "2001:db8:1::/64" }\nsudo systemctl restart docker', explain: 'Containers get IPv6 only when the daemon/network has it enabled; restart affects all containers.', risk: 'Daemon restart stops every container unless live-restore is on.' },
      ],
    },
  ],
  actions: [
    { action: 'systemctl reload radvd', when: 'After changing prefixes or options in /etc/radvd.conf.', effect: 'radvd re-reads its config and advertises the new values.', risk: 'Low; run `radvd --configtest` first.' },
    { action: 'systemctl restart radvd', when: 'Interface renamed or radvd failed.', effect: 'Stops and starts advertising; hosts keep addresses during the short gap.', risk: 'Low, as long as the gap is far shorter than the router lifetime.' },
    { action: 'Interface restart / ip link set dev eth0 down; up', when: 'A host must re-run SLAAC after a prefix change.', effect: 'Removes and re-creates addresses.', risk: 'Drops sessions over that interface.' },
    { action: 'sysctl --system / reboot', when: 'After fixing a sysctl baseline (forwarding, disable_ipv6).', effect: 'Reapplies kernel settings.', risk: 'A reboot shows whether the fix is persistent; do it in a window.' },
  ],
  workflow: [
    { question: '1. Is this an IPv6-only problem?', command: 'curl -4 -I http://srv01.corp.lab/\ncurl -6 -I http://srv01.corp.lab/', healthy: 'HTTP/1.1 200 OK (both)', broken: 'IPv4 works, IPv6 fails → follow this guide. Clients that prefer IPv6 (ssh) will look broken or slow.', next: 'Step 2.', sim: true },
    { question: '2. Does the host have a global address and a default route?', command: 'ip -6 addr\nip -6 route', healthy: 'inet6 2001:db8:30:0:5054:ff:fee7:1e/64 scope global dynamic mngtmpaddr\ndefault via fe80::5054:ff:fea1:4 dev eth0 proto ra', broken: 'Only `scope link` and no default route → no RA received (step 3).', next: 'Global address present → step 4.', sim: true },
    { question: '3. Is a router advertising on this link?', command: 'systemctl status radvd   (router)\ncat /etc/radvd.conf   (router)\nsudo rdisc6 eth0   (host)', healthy: 'Active: active (running)\ninterface eth3.30 { ... prefix 2001:db8:30::/64', broken: 'radvd stopped/failed, wrong interface, or the host firewall drops ICMPv6 (step 5).', next: 'Fix radvd, then the host re-runs SLAAC on the next RA.', sim: true },
    { question: '4. Is the router reachable via NDP?', command: 'ping -6 -c 2 2001:db8:30::1\nip -6 neigh', healthy: '64 bytes from 2001:db8:30::1 ...\nfe80::5054:ff:fea1:4 dev eth0 lladdr 52:54:00:a1:00:04 router REACHABLE', broken: 'Neighbour `FAILED` → NDP blocked or layer-2 problem.', next: 'Step 5.', sim: true },
    { question: '5. Do the firewalls allow ICMPv6?', command: 'nft list ruleset | grep -n icmp', healthy: 'meta l4proto ipv6-icmp accept', broken: 'No ICMPv6 rule before a drop policy: NS/NA/RA dropped. Restrict types if you must, but allow 133–136 and errors.', next: 'Fix the persistent ruleset and reload.', sim: true },
    { question: '6. Does the router forward IPv6?', command: 'sysctl net.ipv6.conf.all.forwarding', healthy: 'net.ipv6.conf.all.forwarding = 1', broken: '0 → routed IPv6 dropped; radvd may also warn and stop.', next: 'Fix in /etc/sysctl.d/ (after any hardening file), `sysctl --system`.', sim: true },
    { question: '7. Can the destination route back over IPv6?', command: 'ip -6 route   (srv01)', healthy: 'default via 2001:db8:20::1 dev eth0', broken: 'No IPv6 default route on a statically addressed server → replies never leave.', next: 'Add `gateway` to the inet6 stanza and re-apply.', sim: true },
  ],
  failures: [
    { symptom: 'Host has only a link-local IPv6 address', causes: ['radvd stopped or advertising on the wrong interface', 'Host firewall drops RAs (ICMPv6)', 'Host has forwarding enabled (ignores RAs)'], diagnose: ['sudo rdisc6 eth0', 'systemctl status radvd (router)', 'nft list ruleset | grep icmp'], fix: 'Fix radvd config/service; allow ICMPv6; set accept_ra=2 if the host must forward.', verify: 'ip -6 addr shows a global dynamic address' },
    { symptom: 'IPv6 fails even to the local router; ip -6 neigh FAILED', causes: ['ICMPv6 "hardening" dropping NS/NA'], diagnose: ['nft list ruleset', 'tcpdump -n -i eth0 icmp6'], fix: 'Allow ipv6-icmp (at least ND types) in the persistent ruleset; reload.', verify: 'ping -6 to the router' },
    { symptom: 'IPv6 to other subnets fails, local works', causes: ['Router IPv6 forwarding off (sysctl baseline)', 'Missing route on the router'], diagnose: ['sysctl net.ipv6.conf.all.forwarding', 'ip -6 route (router)'], fix: 'Enable forwarding persistently; add routes.', verify: 'traceroute -6 reaches the destination' },
    { symptom: 'IPv6 to a server times out, IPv4 fine; ssh slow to connect', causes: ['Server lacks an IPv6 default route', 'Server firewall missing IPv6 rules'], diagnose: ['ip -6 route (server)', 'curl -6 vs curl -4', 'ssh -v (shows the IPv6 attempt timing out first)'], fix: 'Add the IPv6 gateway on the server; use `inet` family rules in nftables.', verify: 'curl -6 -I returns 200' },
    { symptom: 'Hosts get an unexpected prefix / default router', causes: ['Rogue RA (e.g. Windows ICS, test router)'], diagnose: ['rdisc6 eth0 (lists every advertising router)', 'ip -6 route'], fix: 'Remove the rogue source; enable RA Guard on switches.', verify: 'Only rtr01\'s RA is seen' },
  ],
  verification: [
    { check: 'Host addressing', command: 'ip -6 addr; ip -6 route', expect: 'Global SLAAC address in 2001:db8:30::/64; default via the router\'s link-local' },
    { check: 'Router advertising', command: 'systemctl is-active radvd', expect: 'active' },
    { check: 'Forwarding', command: 'sysctl net.ipv6.conf.all.forwarding', expect: '= 1' },
    { check: 'End-to-end over IPv6', command: 'curl -6 -I http://srv01.corp.lab/', expect: 'HTTP/1.1 200 OK' },
    { check: 'Persistent', command: 'grep -rn forwarding /etc/sysctl.d/; reboot test', expect: 'Forwarding still 1 and SLAAC works after reboot' },
  ],
  refIds: ['ip', 'ping-linux', 'traceroute', 'tcpdump', 'nft', 'sysctl', 'systemctl', 'curl', 'nmcli', 'networkctl', 'get-netipconfiguration', 'file:radvd.conf', 'file:sysctl.conf', 'file:etc-network-interfaces', 'file:nftables.conf', 'proc:nft-safe-reload'],
};
