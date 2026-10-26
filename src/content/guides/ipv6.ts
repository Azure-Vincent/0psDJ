// Operate & recover guide: IPv6 on hosts and the router (SLAAC via radvd,
// Neighbor Discovery, IPv6 routing and forwarding, ICMPv6 in firewalls).

import type { ServiceGuide } from '../types';

export const IPV6_GUIDE: ServiceGuide = {
  purpose:
    'IPv6 hosts usually configure themselves. The router sends **Router Advertisements** (RAs) announcing the network prefix and offering itself as the default gateway, and each host builds its own address from that prefix with **SLAAC**. Hosts find their neighbours with **NDP** (Neighbor Discovery, carried in ICMPv6) instead of ARP. In practice this means three things can break IPv6 that never break IPv4: no RAs (radvd stopped, configured on the wrong interface, or forwarding switched off); **ICMPv6 blocked** by a firewall (NDP is ICMPv6, so blocking it breaks even the local network); and dual-stack clients that **prefer IPv6**, so an IPv6-only fault looks like "the server is down" while IPv4 works fine. In the lab, rtr01 runs radvd on VLAN 30 (2001:db8:30::/64) and srv01 has both IPv4 and IPv6 (2001:db8:20::10).',
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
    { port: '546/547', proto: 'UDP', purpose: 'DHCPv6 client/server (dev02 ↔ rtr01 in the lab); requests go to ff02::1:2, replies are unicast to the client\'s link-local address' },
  ],
  processes: [
    { name: 'kernel IPv6 stack', platform: 'Linux', role: 'Link-local, SLAAC (accept_ra), NDP, routing, forwarding' },
    { name: 'radvd', platform: 'Debian/Ubuntu/RHEL routers (rtr01)', role: 'Sends RAs from /etc/radvd.conf (incl. the M/O flags)' },
    { name: 'dhcpd -6 (isc-dhcp-server)', platform: 'Debian (rtr01)', role: 'DHCPv6 server: addresses (IA_NA) and DNS from /etc/dhcp/dhcpd6.conf; started when INTERFACESv6 is set' },
    { name: 'dhclient -6', platform: 'Debian (dev02, ifupdown "inet6 dhcp")', role: 'DHCPv6 client: Solicit/Request, Renew at T1, Rebind at T2; dhclient-script adds the /128 and writes resolv.conf' },
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
    { path: '/etc/dhcp/dhcpd6.conf', platform: 'Debian DHCPv6 server (rtr01)', kind: 'config', perms: 'root:root 0644', contains: '`subnet6 2001:db8:30::/64 { range6 ...; }`, `option dhcp6.name-servers`, `option dhcp6.domain-search`, host reservations with `fixed-address6`.', accessed: 'When dhcpd -6 starts (isc-dhcp-server restart); `dhcpd -t -6 -cf` checks it.', problems: 'IPv4 option names (domain-name-servers) are errors; no subnet6 matching the listening interface → "No subnet6 declaration"; there is no routers option (default route = RA).' },
    { path: '/etc/default/isc-dhcp-server (INTERFACESv6)', platform: 'Debian', kind: 'config', contains: '`INTERFACESv4=""` and `INTERFACESv6="eth3.30"`: which daemons the init script starts and on which interfaces.', accessed: 'At service start.', problems: 'The parent interface (eth3) instead of the VLAN sub-interface (eth3.30) → dhcpd -6 refuses to start.' },
    { path: '/var/lib/dhcp/dhcpd6.leases', platform: 'Debian DHCPv6 server', kind: 'data', contains: '`server-duid`, then `ia-na "<IAID+DUID>" { cltt ...; iaaddr <address> { binding state active; preferred-life; max-life; ends ...; } }` blocks (append-only).', accessed: 'Written on every Reply.', problems: 'Deleting it while clients hold leases can hand out duplicate addresses; the server DUID changes if the file is lost.' },
    { path: '/var/lib/dhcp/dhclient6.<if>.leases', platform: 'Debian DHCPv6 client', kind: 'data', contains: '`default-duid` (the client\'s identity) and the current lease6 with ia-na, iaaddr, lifetimes and options.', accessed: 'Written by dhclient -6.', problems: 'Cloned VMs share the DUID and fight over the same lease: delete the default-duid line (or the file) on clones.' },
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
        { task: 'DHCPv6 client: lease and history', command: 'sudo dhclient -6 -v eth0\nsudo journalctl -t dhclient\ncat /var/lib/dhcp/dhclient6.eth0.leases', explain: '"PRC: Bound to lease" = success; only "XMT: Solicit" lines = no Advertise reached dhclient.', sim: true },
        { task: 'DHCPv6 stateless / release', command: 'sudo dhclient -6 -S -v eth0\nsudo dhclient -6 -r eth0', explain: 'Information-request (DNS only) and Release.', sim: true },
        { task: 'DHCPv6 server: status, log, leases', command: 'systemctl status isc-dhcp-server\njournalctl -u isc-dhcp-server -n 20\ncat /var/lib/dhcp/dhcpd6.leases', explain: '"Solicit message from fe80::..." and "Reply NA: address ..." per client; "No subnet6 declaration" when INTERFACESv6 is wrong.', sim: true },
        { task: 'DHCPv6 server: check config and restart', command: 'sudo dhcpd -t -6 -cf /etc/dhcp/dhcpd6.conf\nsudo systemctl restart isc-dhcp-server', explain: 'Syntax check first; restart reloads both daemons of the unit.', risk: 'A failed restart stops DHCPv4 too when both run in the same unit.', sim: true },
        { task: 'DHCPv6 on the wire', command: 'sudo tcpdump -n -i eth0 port 546 or port 547', explain: 'dhcp6 solicit/advertise/request/reply; arriving packets that dhclient or dhcpd never logs point at the firewall.', sim: true },
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
    { question: 'Is this an IPv6-only problem?', why: 'On a dual-stack network, IPv4 and IPv6 fail independently. Forcing each family separately tells you at once whether this is an IPv6 problem at all.', command: 'curl -4 -I http://srv01.corp.lab/\ncurl -6 -I http://srv01.corp.lab/', healthy: 'HTTP/1.1 200 OK (both)', broken: 'IPv4 works, IPv6 fails → continue with the next steps. Clients that prefer IPv6 (ssh) will look broken or slow.', next: 'Step 2.', sim: true },
    { question: 'Does the host have a global address and a default route?', why: 'Without a global address and a default route, the host can only talk on its own link. Both normally come from the router\'s advertisements.', command: 'ip -6 addr\nip -6 route', healthy: 'inet6 2001:db8:30:0:5054:ff:fee7:1e/64 scope global dynamic mngtmpaddr\ndefault via fe80::5054:ff:fea1:4 dev eth0 proto ra', broken: 'Only `scope link` and no default route → no RA received (step 3).', next: 'Global address present → step 4.', sim: true },
    { question: 'Is a router advertising on this link?', why: 'If the host never received an RA, the router side is the first suspect: is anything advertising on this link?', command: 'systemctl status radvd   (router)\ncat /etc/radvd.conf   (router)\nsudo rdisc6 eth0   (host)', healthy: 'Active: active (running)\ninterface eth3.30 { ... prefix 2001:db8:30::/64', broken: 'radvd stopped/failed, wrong interface, or the host firewall drops ICMPv6 (step 5).', next: 'Fix radvd, then the host re-runs SLAAC on the next RA.', sim: true },
    { question: 'Is the router reachable via NDP?', why: 'NDP is how IPv6 finds the router\'s MAC address. If it fails, nothing beyond the local link can work.', command: 'ping -6 -c 2 2001:db8:30::1\nip -6 neigh', healthy: '64 bytes from 2001:db8:30::1 ...\nfe80::5054:ff:fea1:4 dev eth0 lladdr 52:54:00:a1:00:04 router REACHABLE', broken: 'Neighbour `FAILED` → NDP blocked or layer-2 problem.', next: 'Step 5.', sim: true },
    { question: 'Do the firewalls allow ICMPv6?', why: 'Because NDP and router advertisements are ICMPv6, a firewall that drops ICMPv6 silently breaks IPv6 even on the local link.', command: 'nft list ruleset | grep -n icmp', healthy: 'meta l4proto ipv6-icmp accept', broken: 'No ICMPv6 rule before a drop policy: NS/NA/RA dropped. Restrict types if you must, but allow 133–136 and errors.', next: 'Fix the persistent ruleset and reload.', sim: true },
    { question: 'Hosts that use DHCPv6: did the exchange complete?', why: 'Hosts configured for DHCPv6 depend on a four-message exchange with a server. Logs and a capture on both ends show which message gets lost.', command: 'sudo journalctl -t dhclient   (client)\njournalctl -u isc-dhcp-server   (server)\nsudo tcpdump -n -i eth0 port 546 or port 547', healthy: 'PRC: Bound to lease ... / Reply NA: address 2001:db8:30::... to client with duid ...', broken: 'Server silent but Solicits on the wire → server firewall (UDP 547). Server sends Advertise, client never logs it → client firewall (UDP 546). Service failed → INTERFACESv6 / dhcpd6.conf.', next: 'Fix the firewall or server configuration; then "dhclient -6 eth0" on the client (it retries by itself every few minutes).', sim: true },
    { question: 'Does the router forward IPv6?', why: 'Like IPv4, a Linux router only passes IPv6 packets on when forwarding is switched on, and IPv6 has its own separate setting.', command: 'sysctl net.ipv6.conf.all.forwarding', healthy: 'net.ipv6.conf.all.forwarding = 1', broken: '0 → routed IPv6 dropped; radvd may also warn and stop.', next: 'Fix in /etc/sysctl.d/ (after any hardening file), `sysctl --system`.', sim: true },
    { question: 'Can the destination route back over IPv6?', why: 'Replies are routed by the destination\'s own table. A server with a static IPv6 address and no IPv6 default route receives requests but cannot answer.', command: 'ip -6 route   (srv01)', healthy: 'default via 2001:db8:20::1 dev eth0', broken: 'No IPv6 default route on a statically addressed server → replies never leave.', next: 'Add `gateway` to the inet6 stanza and re-apply.', sim: true },
  ],
  failures: [
    { symptom: 'Host has only a link-local IPv6 address', causes: ['radvd stopped or advertising on the wrong interface', 'Host firewall drops RAs (ICMPv6)', 'Host has forwarding enabled (ignores RAs)'], diagnose: ['sudo rdisc6 eth0', 'systemctl status radvd (router)', 'nft list ruleset | grep icmp'], fix: 'Fix radvd config/service; allow ICMPv6; set accept_ra=2 if the host must forward.', verify: 'ip -6 addr shows a global dynamic address' },
    { symptom: 'IPv6 fails even to the local router; ip -6 neigh FAILED', causes: ['ICMPv6 "hardening" dropping NS/NA'], diagnose: ['nft list ruleset', 'tcpdump -n -i eth0 icmp6'], fix: 'Allow ipv6-icmp (at least ND types) in the persistent ruleset; reload.', verify: 'ping -6 to the router' },
    { symptom: 'IPv6 to other subnets fails, local works', causes: ['Router IPv6 forwarding off (sysctl baseline)', 'Missing route on the router'], diagnose: ['sysctl net.ipv6.conf.all.forwarding', 'ip -6 route (router)'], fix: 'Enable forwarding persistently; add routes.', verify: 'traceroute -6 reaches the destination' },
    { symptom: 'IPv6 to a server times out, IPv4 fine; ssh slow to connect', causes: ['Server lacks an IPv6 default route', 'Server firewall missing IPv6 rules'], diagnose: ['ip -6 route (server)', 'curl -6 vs curl -4', 'ssh -v (shows the IPv6 attempt timing out first)'], fix: 'Add the IPv6 gateway on the server; use `inet` family rules in nftables.', verify: 'curl -6 -I returns 200' },
    { symptom: 'DHCPv6 laptops lose IPv6 one after another; SLAAC hosts fine', causes: ['DHCPv6 server stopped or failed (wrong INTERFACESv6, dhcpd6.conf error)', 'Server firewall dropping UDP 547 (assumed "DHCP bypasses the firewall", true only for ISC DHCPv4)', 'Client firewall baseline without UDP 546'], diagnose: ['systemctl status isc-dhcp-server', 'journalctl -u isc-dhcp-server', 'tcpdump port 546 or port 547 on both ends', 'nft list ruleset on both ends'], fix: 'Restore the service or the firewall rule; clients re-solicit (or run dhclient -6).', verify: 'ip -6 addr shows the /128 "dynamic" address again; curl -6 works' },
    { symptom: 'DHCPv6 address present but no IPv6 connectivity', causes: ['No router advertisement (radvd stopped): DHCPv6 gives no default route', 'RA prefix without the on-link flag and the address is a /128'], diagnose: ['ip -6 route (default via fe80::... proto ra?)', 'rdisc6 eth0'], fix: 'Run radvd on the link (keep AdvManagedFlag on).', verify: 'default via fe80::... proto ra' },
    { symptom: 'Hosts get an unexpected prefix / default router', causes: ['Rogue RA (e.g. Windows ICS, test router)'], diagnose: ['rdisc6 eth0 (lists every advertising router)', 'ip -6 route'], fix: 'Remove the rogue source; enable RA Guard on switches.', verify: 'Only rtr01\'s RA is seen' },
  ],
  verification: [
    { check: 'Host addressing', command: 'ip -6 addr; ip -6 route', expect: 'Global SLAAC address in 2001:db8:30::/64; default via the router\'s link-local' },
    { check: 'Router advertising', command: 'systemctl is-active radvd', expect: 'active' },
    { check: 'Forwarding', command: 'sysctl net.ipv6.conf.all.forwarding', expect: '= 1' },
    { check: 'End-to-end over IPv6', command: 'curl -6 -I http://srv01.corp.lab/', expect: 'HTTP/1.1 200 OK' },
    { check: 'DHCPv6 clients bound', command: 'ip -6 addr (dev02); journalctl -u isc-dhcp-server (rtr01)', expect: 'A /128 "dynamic" address from the pool; Reply NA lines for the client' },
    { check: 'Persistent', command: 'grep -rn forwarding /etc/sysctl.d/; reboot test', expect: 'Forwarding still 1 and SLAAC works after reboot' },
  ],
  refIds: ['ip', 'ping-linux', 'traceroute', 'tcpdump', 'nft', 'sysctl', 'systemctl', 'curl', 'nmcli', 'networkctl', 'get-netipconfiguration', 'file:radvd.conf', 'file:dhcpd6.conf', 'proc:dhcpv6-diagnose', 'file:sysctl.conf', 'file:etc-network-interfaces', 'file:nftables.conf', 'proc:nft-safe-reload'],
};
