import type { Lesson } from '../types';

export const IPV6_LESSON: Lesson = {
  id: 'ipv6',
  moduleId: 'A',
  title: 'IPv6: addressing, SLAAC, DHCPv6 and Neighbor Discovery',
  level: 'intermediate',
  summary: 'IPv6 addresses and notation, link-local and global addresses, /64 subnets, router advertisements and SLAAC, stateful and stateless DHCPv6 (DUID, IA_NA, M/O flags), Neighbor Discovery instead of ARP, ICMPv6 and firewalls, and how dual-stack hosts choose between IPv4 and IPv6.',
  concepts: ['net.ipv6', 'net.ndp', 'net.routing', 'fw.stateful'],

  what: `
**IPv6** is the successor of IPv4 with **128-bit addresses** (3.4 × 10³⁸ of them). Every subnet is normally a **/64**, so there is no address shortage and no need for NAT. Most networks today run **dual stack**: IPv4 and IPv6 side by side, with applications preferring IPv6 when both work.

### What changes compared to IPv4
| | IPv4 | IPv6 |
|---|---|---|
| Address | 32 bit, 10.0.20.10 | 128 bit, 2001:db8:20::10 |
| Subnet size | anything (/24 common) | /64 for LANs |
| Address configuration | static or DHCP | static, **SLAAC** (router advertisements), DHCPv6 |
| Next-hop MAC | ARP (broadcast) | **Neighbor Discovery** (ICMPv6, multicast) |
| Gateway | configured/DHCP | learned from **router advertisements** (link-local address) |
| Every interface has | one address | several: **link-local** fe80::/64 + global(s) |
| Broadcast | yes | no (multicast instead) |
| ICMP | optional for most functions | **essential** (ND, PMTUD): must not be blocked |
| Header checksum / fragmentation by routers | yes | no |

### In the lab
The **IPv6 pilot** runs in the development VLAN 30: rtr01 advertises **2001:db8:30::/64** with **radvd** (M and O flags set); dev01 configures itself (SLAAC), the laptop dev02 gets its address and DNS server from **DHCPv6** (dhcpd -6 on rtr01) and only its default route from the RA. srv01 has the static address **2001:db8:20::10**, ns1 has **2001:db8:10::53** (the DNS server handed out by DHCPv6) and publishes an **AAAA** record for srv01. The office clients stay IPv4-only, like many real networks in transition. (2001:db8::/32 is the documentation prefix.)

> The simulator implements IPv6 addresses (link-local EUI-64, static, SLAAC), routing with longest-prefix match, Neighbor Discovery (NS/NA via solicited-node multicast) and router discovery (RS/RA from radvd), ICMPv6 echo and errors, IPv6 forwarding (silent drop when disabled), nftables ip6/inet/icmpv6 matching with "untracked" ND messages, AAAA records with getaddrinfo() address selection, curl Happy Eyeballs vs ssh sequential fallback, and IPv6/ICMPv6 in tcpdump and PCAP export. DHCPv6 between dhclient -6 and ISC dhcpd -6 (Solicit/Advertise/Request/Reply, Information-request, Renew/Rebind/Release, DUID-LLT, IA_NA, lifetimes and T1/T2, dhcpd6.conf and dhcpd6.leases, nftables on both ends, ff02::1:2 in tcpdump and PCAP), the RA M/O flags and on-link prefixes, "beyond scope of source address" for link-local senders. ICMPv6 "packet too big" and path-MTU discovery are covered in the MTU lesson. Not modelled: DHCPv6 relays and prefix delegation, rapid commit, privacy (temporary) addresses, duplicate address detection, MLD, extension headers.
`,

  internals: `
### Writing addresses
128 bits as 8 groups of 4 hex digits: \`2001:0db8:0020:0000:0000:0000:0000:0010\`. Shorten by
1. dropping leading zeros in each group: \`2001:db8:20:0:0:0:0:10\`
2. replacing **one** run of zero groups with \`::\`: \`2001:db8:20::10\`.
RFC 5952 canonical form: lower case, the longest run compressed (leftmost if tied), never a single group. In URLs and with ports: \`http://[2001:db8:20::10]:80/\`.

### Address types
| Prefix | Type | Example |
|---|---|---|
| ::1/128 | loopback | ::1 |
| fe80::/10 | **link-local**: every IPv6 interface has one, valid only on that link | fe80::5054:ff:fee7:1e |
| 2000::/3 | global unicast (routed on the Internet) | 2a00:1450:4001:80b::200e |
| fc00::/7 | unique local (private, like RFC 1918) | fd12:3456:789a:1::10 |
| ff00::/8 | multicast (ff02::1 all nodes, ff02::2 all routers) | ff02::1:ff00:10 |
| 2001:db8::/32 | documentation (never routed) | 2001:db8:20::10 |

### Interface identifier and SLAAC
A /64 leaves 64 bits for the host. With **EUI-64** they come from the MAC: 52:54:00:e7:00:1e → split in half, insert **ff:fe**, flip the "universal/local" bit (7th bit of the first byte): **5054:00ff:fee7:001e**. Hence dev01's link-local fe80::5054:ff:fee7:1e and its global 2001:db8:30::5054:ff:fee7:1e. (Desktops normally add random *privacy addresses* for outgoing connections; servers often use static addresses.)

**SLAAC** (RFC 4862):
1. Interface up → link-local address (fe80:: + identifier).
2. Host sends a **Router Solicitation** (ICMPv6 133) to ff02::2.
3. Routers answer with a **Router Advertisement** (134) to ff02::1: prefix(es) with flags *on-link* and *autonomous*, the router lifetime, optional DNS servers (RDNSS), and the M/O flags pointing to DHCPv6.
4. The host forms prefix + identifier for every autonomous /64 and installs **default via the router's link-local address**.
Routers send RAs periodically too. A Linux host ignores RAs while it forwards IPv6 (it is a router itself).

### DHCPv6 (RFC 8415)
SLAAC gives an address and a router, but no central record of who has which address and (without RDNSS) no DNS server. **DHCPv6** fills that gap. Two flags in the RA tell hosts what to use:
| RA flags | Meaning | Typical client behaviour |
|---|---|---|
| M=0, O=0 | SLAAC only | address from the prefix, DNS from RDNSS |
| M=0, O=1 | **stateless DHCPv6** | SLAAC address + DNS/domain from DHCPv6 (Information-request) |
| M=1 | **stateful DHCPv6** | address (IA_NA) and options from DHCPv6; SLAAC still happens if the prefix is autonomous (A flag) |
NetworkManager, systemd-networkd, Windows, macOS, Android (no stateful DHCPv6 at all) and iOS follow the flags. Debian's ifupdown does not: \`iface eth0 inet6 dhcp\` simply runs \`dhclient -6\`.

**Message flow** (client UDP 546, server UDP 547):
1. **Solicit** from the client's link-local address to **ff02::1:2** (all DHCPv6 servers and relays on the link). No broadcast exists in IPv6.
2. **Advertise** from each server, unicast to the client's link-local address, with an offered address.
3. **Request** (again to ff02::1:2) naming the chosen server by its **server identifier**.
4. **Reply**: the binding is committed. At **T1** the client sends **Renew** to that server, at **T2** **Rebind** to any server; when the **valid lifetime** ends the address is removed.
Stateless clients send one **Information-request** and get a Reply with options only.

**What is different from DHCPv4**
- **Identity**: clients are identified by a **DUID** (DHCP Unique Identifier, e.g. DUID-LLT = type + time + MAC), not by their MAC. Addresses belong to an **IA_NA** (identity association for non-temporary addresses) with an **IAID**; dhclient derives the IAID from the last four bytes of the MAC. Reinstalling a machine creates a new DUID, so reservations by DUID break; ISC dhcpd also accepts \`hardware ethernet\` when the DUID contains the MAC.
- **No default route and no prefix length**: DHCPv6 has no "routers" option. The default route always comes from router advertisements, and dhclient installs the address as a **/128**; the on-link /64 route also comes from the RA. A network with DHCPv6 but no RAs gives hosts an address they cannot route with.
- **Lifetimes**: each address has a preferred and a valid lifetime (ISC dhcpd: valid = default-lease-time, preferred = 5/8 of it unless set); T1 and T2 are 0.5 and 0.8 of the preferred lifetime (sent by the server, or chosen by the client when the server sends 0, as RFC 8415 recommends).
- **Firewalls matter on both ends**. ISC dhcpd, dhclient and dhcrelay read **DHCPv4** with packet sockets that bypass nftables; **DHCPv6 uses ordinary UDP sockets**. The server's input chain must accept UDP 547; the client's must accept UDP 546, and "ct state established" does not cover it, because the Solicit went to a multicast group and the Advertise comes from the server's own address (a new flow for conntrack). firewalld enables its "dhcpv6-client" service by default for this reason.
- **Different option names** in ISC dhcpd: \`dhcp6.name-servers\`, \`dhcp6.domain-search\`, \`subnet6\`, \`range6\`, \`fixed-address6\`, in /etc/dhcp/dhcpd6.conf. dhcpd -6 serves a link only when the interface has a global address inside a \`subnet6\` declaration ("No subnet6 declaration for eth3 (fe80::…)").
- **resolv.conf**: Debian's dhclient-script replaces /etc/resolv.conf with the DHCPv6 DNS servers on every bind or renewal, and the IPv4 dhclient does the same with its own; on a dual-stack laptop the file alternates between them.
- **Without a global address** a host still has its link-local address, and Linux uses it as the source for global destinations. Routers must not forward such packets; they answer ICMPv6 "beyond scope of source address", which applications report as "No route to host".

### Neighbor Discovery replaces ARP (RFC 4861)
To send to 2001:db8:20::10 on the link, a node sends a **Neighbor Solicitation** (135) to the **solicited-node multicast** group ff02::1:ff00:10 (last 24 bits of the target), Ethernet 33:33:ff:00:00:10, so only nodes with matching addresses are interrupted. The owner answers with a unicast **Neighbor Advertisement** (136) containing its MAC. \`ip -6 neigh\` shows the cache (REACHABLE, STALE, FAILED).

**ND is ICMPv6, so it passes through the firewall.** ARP is invisible to nftables, ND is not: a host whose input chain drops ICMPv6 cannot be reached at all over IPv6, not even by ping. Conntrack does not track ND (it appears as "ct state untracked"), so "ct state established,related accept" does not help; you need an explicit rule such as \`meta l4proto ipv6-icmp accept\` or the RFC 4890 list of types.

### Routing and forwarding
Longest-prefix match exactly as in IPv4 (\`ip -6 route\`). A router must have **net.ipv6.conf.all.forwarding=1**; this switch is **independent** from net.ipv4.ip_forward. When forwarding is off, IPv6 packets not addressed to the router are discarded **silently** (IPv4 answers with host unreachable). Routers do not fragment and there is no header checksum.

### Dual stack: which family does a client use?
getaddrinfo() asks for **A and AAAA**, but only for families the host can use (AI_ADDRCONFIG: AAAA only if the host has a global IPv6 address). The result is sorted by RFC 6724: IPv6 first when a suitable source address exists. Then:
- **Browsers, curl**: *Happy Eyeballs* (RFC 8305): start IPv6, start IPv4 after ~200 ms if not connected, use whichever wins. Broken IPv6 is almost invisible.
- **ssh, many scripts and libraries**: try addresses one after the other, each with the full connect timeout. Broken IPv6 means slow or failing logins.
So "it works in the browser" proves little: test with \`curl -6\` / \`curl -4\`, \`ping -6\`, \`ssh -6\`.
`,

  deployment: [
    {
      id: 'linux-router6',
      platform: 'Linux router: IPv6 forwarding and radvd',
      summary: 'Route a /64 and let clients configure themselves. Steps marked "simulated" work on rtr01 in the sandbox.',
      prerequisites: ['Debian 12 router with a static IPv6 address on each link.', 'A /64 per LAN from your provider or a ULA prefix (fdxx::/48).'],
      steps: [
        { title: 'Enable IPv6 forwarding', command: 'echo "net.ipv6.conf.all.forwarding = 1" | sudo tee /etc/sysctl.d/99-ipv6-router.conf\nsudo sysctl --system\nsysctl net.ipv6.conf.all.forwarding', what: 'Turns the host into an IPv6 router, persistently.', why: 'Independent of net.ipv4.ip_forward. Later files in /etc/sysctl.d override earlier ones.', expected: 'net.ipv6.conf.all.forwarding = 1', simulated: true },
        { title: 'Static addresses on the router', command: 'sudoedit /etc/network/interfaces\n\niface eth3.30 inet6 static\n    address 2001:db8:30::1/64', what: 'Adds an inet6 stanza next to the inet one.', why: 'Routers use static addresses; clients learn the router from RAs anyway.', expected: '', simulated: true },
        { title: 'Install and configure radvd', command: 'sudo apt install radvd\nsudoedit /etc/radvd.conf\n\ninterface eth3.30 {\n    AdvSendAdvert on;\n    prefix 2001:db8:30::/64 {\n        AdvOnLink on;\n        AdvAutonomous on;\n    };\n    RDNSS 2001:db8:20::53 { };\n};', what: 'Advertises the prefix (autonomous = clients may build addresses) and optionally DNS servers.', why: 'Without RAs, SLAAC clients get no global address and no default route.', expected: '', simulated: true },
        { title: 'Start and check', command: 'sudo systemctl restart radvd\njournalctl -u radvd -n 5\nip -6 addr show eth3.30', what: 'Starts radvd and shows its log.', why: 'radvd warns (but keeps running) when forwarding is disabled: a classic trap.', expected: 'radvd[407]: version 2.19 started', simulated: true },
        { title: 'Firewall: allow ICMPv6', command: 'sudo nft add rule inet filter input meta l4proto ipv6-icmp accept\n# persistent: add the line to /etc/nftables.conf before the policy drop', what: 'Lets Neighbor Discovery, router solicitations and ICMPv6 errors in.', why: 'Without it the router cannot be reached by its neighbours over IPv6.', expected: '', simulated: true },
      ],
    },
    {
      id: 'linux-host6',
      platform: 'Linux host: SLAAC or static IPv6',
      summary: 'Configure and verify a dual-stack client or server.',
      prerequisites: ['Debian 12 host on a link with a router advertising a prefix (for SLAAC).'],
      steps: [
        { title: 'SLAAC (client)', command: 'sudoedit /etc/network/interfaces\n\niface eth0 inet6 auto\n\nsudo systemctl restart networking\nip -6 addr show eth0\nip -6 route', what: 'Accept router advertisements and autoconfigure.', why: 'The global address shows "dynamic mngtmpaddr" with lifetimes; the default route points to a fe80:: address with "proto ra".', expected: 'inet6 2001:db8:30:0:5054:ff:fee7:1e/64 scope global dynamic mngtmpaddr\ndefault via fe80::5054:ff:fea1:4 dev eth0 proto ra metric 1024 expires 1791sec', simulated: true },
        { title: 'Static (server)', command: 'iface eth0 inet6 static\n    address 2001:db8:20::10/64\n    gateway 2001:db8:20::1', what: 'Fixed address and default route for a server.', why: 'Servers need stable addresses for DNS (AAAA) and firewall rules.', expected: '', simulated: true },
        { title: 'Router discovery by hand', command: 'sudo rdisc6 eth0', what: 'Sends a router solicitation and prints every advertisement (ndisc6 package).', why: 'Answers "is there a router on this link and what does it announce?" directly.', expected: ' Prefix                   : 2001:db8:30::/64\n  On-link                 :          Yes\n  Autonomous address conf.:          Yes\n from fe80::5054:ff:fea1:4', simulated: true },
        { title: 'Test each family separately', command: 'ping -6 -c 2 srv01.corp.lab\ncurl -6 -I http://srv01.corp.lab/\ncurl -4 -I http://srv01.corp.lab/\nip -6 neigh', what: 'Forces IPv6 or IPv4.', why: 'Dual-stack fallbacks hide broken IPv6; only family-specific tests show it.', expected: '64 bytes from 2001:db8:20::10: icmp_seq=1 ttl=63 time=0.6 ms', simulated: true },
      ],
    },
    {
      id: 'dhcpv6-server',
      platform: 'Linux: DHCPv6 server (ISC dhcpd -6) with radvd',
      summary: 'Stateful DHCPv6 for one VLAN, as on rtr01. Steps marked "simulated" work in the sandbox.',
      prerequisites: ['A router (radvd) already advertising the prefix on the link.', 'The server has a global address inside the subnet on the interface it serves.', 'IPv6 DNS servers to hand out.'],
      steps: [
        { title: 'Tell hosts to use DHCPv6 (radvd)', command: 'sudoedit /etc/radvd.conf   # inside interface eth3.30 { ... }\n    AdvManagedFlag on;\n    AdvOtherConfigFlag on;\n\nsudo systemctl restart radvd\nrdisc6 eth0   # on a client', what: 'M (managed) = addresses from DHCPv6, O (other) = options from DHCPv6.', why: 'Clients that follow the flags (NetworkManager, systemd-networkd, Windows) start DHCPv6 only when they see them. Keep AdvAutonomous on if SLAAC hosts share the VLAN; turn it off to force managed addresses.', expected: 'Stateful address conf.    :          Yes\nStateful other conf.      :          Yes', simulated: true },
        { title: 'Write dhcpd6.conf', command: 'sudoedit /etc/dhcp/dhcpd6.conf\n\ndefault-lease-time 600;\nmax-lease-time 7200;\noption dhcp6.name-servers 2001:db8:10::53;\noption dhcp6.domain-search "corp.lab";\nsubnet6 2001:db8:30::/64 {\n    range6 2001:db8:30::1000 2001:db8:30::1fff;\n}\n\nsudo dhcpd -t -6 -cf /etc/dhcp/dhcpd6.conf', what: 'A pool in the VLAN\'s /64 plus DNS options, then a syntax check.', why: 'DHCPv6 has its own option names (dhcp6.*) and no "routers" option: the default route comes from the RA.', expected: 'Internet Systems Consortium DHCP Server 4.4.3-P1', simulated: true },
        { title: 'Choose the interface', command: 'sudoedit /etc/default/isc-dhcp-server\n\nINTERFACESv4=""\nINTERFACESv6="eth3.30"', what: 'The init script starts dhcpd -6 because INTERFACESv6 is set (and dhcpd -4 only if INTERFACESv4 is).', why: 'Use the VLAN sub-interface that carries the subnet6 address, not its parent.', expected: 'isc-dhcp-server[407]: Launching IPv6 server only.', simulated: true },
        { title: 'Open the firewall', command: 'sudo nft add rule inet filter input iifname "eth3.30" udp dport 547 accept\n# persistent: add the same line to /etc/nftables.conf', what: 'dhcpd -6 receives on an ordinary UDP socket.', why: 'Unlike DHCPv4, nftables filters DHCPv6. Without this rule the server log stays silent.', expected: '', simulated: true },
        { title: 'Start and watch', command: 'sudo systemctl restart isc-dhcp-server\njournalctl -u isc-dhcp-server -n 12\nss -ulnp | grep 547', what: 'Starts the server and shows it listening.', why: '"Listening on Socket/eth3.30/2001:db8:30::/64" confirms the interface and subnet6 match.', expected: 'dhcpd[414]: Listening on Socket/eth3.30/2001:db8:30::/64\nUNCONN 0 0 [::]:547 [::]:* users:(("dhcpd",pid=414,fd=6))', simulated: true },
        { title: 'Leases and reservations', command: 'cat /var/lib/dhcp/dhcpd6.leases\n\n# reservation (by client DUID or by MAC)\nhost printer30 {\n    host-identifier option dhcp6.client-id 00:01:00:01:2b:e0:4a:64:52:54:00:e7:00:30;\n    fixed-address6 2001:db8:30::30;\n}', what: 'ia-na blocks keyed by IAID + DUID, and a fixed address.', why: 'The DUID is the client\'s identity; read it from the server log ("client with duid ...").', expected: 'ia-na "*\\000\\347\\000..." {\n  iaaddr 2001:db8:30::18b8 {\n    binding state active;', simulated: true },
      ],
    },
    {
      id: 'dhcpv6-client',
      platform: 'Linux client: dhclient -6 (ifupdown)',
      summary: 'Get an address (stateful) or only DNS (stateless) from DHCPv6.',
      prerequisites: ['Debian with isc-dhcp-client; a router advertising the prefix (for the default route).'],
      steps: [
        { title: 'Configure', command: 'sudoedit /etc/network/interfaces\n\niface eth0 inet6 dhcp\n    autoconf 0\n\nsudo systemctl restart networking', what: 'Runs dhclient -6 at boot; "autoconf 0" stops SLAAC so the host uses only its managed address.', why: 'Without autoconf 0 the host gets both a SLAAC and a DHCPv6 address when the prefix is autonomous. NetworkManager: ipv6.method dhcp; netplan: dhcp6: true.', expected: '', simulated: true },
        { title: 'Firewall on the client', command: 'sudo nft add rule inet filter input ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept', what: 'Lets DHCPv6 replies in.', why: 'The Advertise/Reply comes from the server\'s link-local address to UDP 546; conntrack does not match it to the multicast Solicit.', expected: '', simulated: true },
        { title: 'Ask by hand', command: 'sudo dhclient -6 -v eth0\nip -6 addr show eth0\nip -6 route', what: 'Solicit, Advertise, Request, Reply; then the /128 address and the RA routes.', why: 'The address is a /128 with lifetimes ("dynamic"); the default route and the on-link /64 come from the router advertisement (proto ra).', expected: 'PRC: Bound to lease 00:01:00:01:2b:61:b7:3a:52:54:00:a1:00:04.\ninet6 2001:db8:30::18b8/128 scope global dynamic\n2001:db8:30::/64 dev eth0 proto ra metric 1024', simulated: true },
        { title: 'Stateless (DNS only)', command: 'sudo dhclient -6 -S -v eth0\ncat /etc/resolv.conf', what: 'Information-request: options only, no address.', why: 'For SLAAC hosts on networks with the O flag.', expected: 'RCV: Reply message on eth0 from fe80::5054:ff:fea1:4.\nsearch corp.lab.\nnameserver 2001:db8:10::53', simulated: true },
        { title: 'Release', command: 'sudo dhclient -6 -r eth0', what: 'Sends a Release and removes the address.', why: 'Before moving a machine or when testing a server change.', expected: '', simulated: true },
        { title: 'Windows', command: 'ipconfig /all   # "DHCPv6 IAID" and "DHCPv6 Client DUID"\nipconfig /renew6\nGet-NetIPAddress -AddressFamily IPv6 | ? PrefixOrigin -eq Dhcp', what: 'Windows shows its DUID and IAID and renews DHCPv6 separately.', why: 'The DUID is what the DHCPv6 server reservation must match.', expected: 'DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-2B-...' },
      ],
    },
    {
      id: 'windows6',
      platform: 'Windows',
      summary: 'Client checks.',
      prerequisites: ['Windows 10/11.'],
      steps: [
        { title: 'Addresses, routes, neighbours', command: 'ipconfig /all\nGet-NetIPAddress -AddressFamily IPv6\nGet-NetRoute -AddressFamily IPv6 -DestinationPrefix ::/0\nGet-NetNeighbor -AddressFamily IPv6', what: 'IPv6 addresses (including temporary privacy addresses), the default route and the ND cache.', why: 'Windows uses random interface IDs and temporary addresses by default instead of EUI-64.', expected: 'IPv6 Address. . . . . . . . . . . : 2001:db8:30::8d2f:1a7e:...(Preferred)\nTemporary IPv6 Address. . . . . . : 2001:db8:30::5c1:...' },
        { title: 'Force a family', command: 'Test-NetConnection srv01.corp.lab -Port 80\nping -6 srv01.corp.lab\ncurl.exe -6 -I http://srv01.corp.lab/', what: 'Connection tests per family.', why: 'Same reason as on Linux.', expected: 'TcpTestSucceeded : True' },
      ],
    },
  ],

  configIntro: `
IPv6 configuration is mostly about prefixes, router advertisements and not breaking ICMPv6. The address explorer below shows how the simulator (and the kernel) derives the link-local, SLAAC and solicited-node addresses from a MAC, and how any address is written and classified.
`,

  configFiles: [
    {
      platform: 'Linux',
      items: [
        { path: '/etc/network/interfaces (inet6 static | auto | dhcp)', purpose: 'Static IPv6 addresses and gateway, SLAAC, or DHCPv6 (dhclient -6); "autoconf 0" disables SLAAC addresses.' },
        { path: '/etc/radvd.conf', purpose: 'Router advertisements: prefixes, flags (AdvManagedFlag / AdvOtherConfigFlag for DHCPv6), RDNSS (routers only).' },
        { path: '/etc/dhcp/dhcpd6.conf', purpose: 'ISC dhcpd -6: subnet6, range6, dhcp6.name-servers, dhcp6.domain-search, host reservations (fixed-address6).' },
        { path: '/etc/default/isc-dhcp-server (INTERFACESv6)', purpose: 'Interfaces dhcpd -6 serves; setting it makes the init script start the IPv6 daemon.' },
        { path: '/var/lib/dhcp/dhcpd6.leases, /var/lib/dhcp/dhclient6.<if>.leases', purpose: 'Server bindings (ia-na by IAID + DUID) and the client\'s lease with its default-duid.' },
        { path: '/etc/sysctl.d/*.conf', purpose: 'net.ipv6.conf.all.forwarding (routers), accept_ra, disable_ipv6; last file wins.' },
        { path: '/etc/nftables.conf', purpose: 'inet tables cover both families; allow ipv6-icmp (ND) explicitly.' },
        { path: '/etc/gai.conf', purpose: 'getaddrinfo() address-selection policy (e.g. prefer IPv4).' },
      ],
    },
  ],

  directives: [
    { name: 'net.ipv6.conf.all.forwarding', compiledDefault: '0', recommended: '1 on routers only', explanation: 'Route IPv6 between interfaces; also makes the host ignore RAs.', security: 'Host hardening baselines set it to 0: apply them to routers only with an exception.' },
    { name: 'iface X inet6 auto', compiledDefault: '— (kernel accepts RAs by default)', recommended: 'Clients', explanation: 'Use SLAAC on the interface.', security: 'Rogue RAs from any host can redirect clients: use RA Guard on switches.' },
    { name: 'AdvAutonomous on (radvd)', compiledDefault: 'on', recommended: 'on for SLAAC networks', explanation: 'Clients may form addresses from this prefix.', security: '' },
    { name: 'RDNSS', compiledDefault: '—', recommended: 'Your resolvers', explanation: 'DNS servers in the RA (RFC 8106); used by NetworkManager, systemd-networkd, rdnssd, Windows, Android, iOS.', security: 'Same trust model as DHCP DNS options.' },
    { name: 'AdvManagedFlag / AdvOtherConfigFlag (radvd)', compiledDefault: 'off / off', recommended: 'M on for stateful DHCPv6; O on for DNS via DHCPv6', explanation: 'The M and O flags in router advertisements: use DHCPv6 for addresses / for other configuration.', security: 'Only hosts that follow the flags react; ifupdown runs dhclient -6 whenever "inet6 dhcp" is configured.' },
    { name: 'subnet6 / range6 (dhcpd6.conf)', compiledDefault: '—', recommended: 'One subnet6 per served link, matching an address on the listening interface', explanation: 'Declares the link and its pool. Without a matching subnet6 the server ignores the interface.', security: 'Keep pools inside the /64 that the RA announces on that link.' },
    { name: 'option dhcp6.name-servers / dhcp6.domain-search', compiledDefault: '—', recommended: 'IPv6 addresses of your resolvers', explanation: 'DNS options 23 and 24. IPv4 option names (domain-name-servers) are errors in dhcpd6.conf.', security: 'The resolvers must accept queries over IPv6 (listen-on-v6, firewall rules for both families).' },
    { name: 'default-lease-time / preferred-lifetime (dhcpd6.conf)', compiledDefault: '43200 / 5/8 of it', recommended: 'Hours to days in production (the lab uses 600 s)', explanation: 'Valid and preferred lifetime of addresses; T1/T2 are normally 0.5/0.8 of the preferred lifetime.', security: 'Short lifetimes make a server outage visible quickly.' },
    { name: 'udp dport 547 (server) / udp dport 546 (client) accept', compiledDefault: '—', recommended: 'Always where nftables has a drop policy', explanation: 'DHCPv6 uses ordinary UDP sockets, which netfilter filters (unlike ISC DHCPv4\'s packet sockets).', security: 'Restrict to the link: ip6 saddr fe80::/10 on the client, iifname on the server.' },
    { name: 'meta l4proto ipv6-icmp accept (nftables)', compiledDefault: '—', recommended: 'Always on IPv6 hosts (or the RFC 4890 type list)', explanation: 'Lets Neighbor Discovery, router discovery and ICMPv6 errors through the input chain.', security: 'Dropping ICMPv6 breaks IPv6 entirely; it is not like dropping ping.' },
  ],

  troubleshootingIntro: `
### Test IPv6 on its own
1. **Does the host have a global address and a default route?** \`ip -6 addr\`, \`ip -6 route\`. Only fe80:: → no RA received (router, radvd, VLAN, firewall dropping RA).
2. **Is the router reachable?** \`ping -6 <gateway>\`, \`ip -6 neigh\`, \`rdisc6 eth0\`.
3. **Where does it stop?** \`traceroute -6\` / ping each hop. *Address unreachable* = the last router could not resolve the destination (ND failing: host down, wrong address, ICMPv6 blocked). *Silence* = forwarding disabled, a firewall drop, or no route back.
4. **Name resolution**: \`dig AAAA name\`, \`getent ahosts name\` (order of addresses).
4b. **DHCPv6 hosts without an address** (only fe80::): \`journalctl -t dhclient\` on the client (Solicit only? Advertise received?), \`journalctl -u isc-dhcp-server\` on the server (Solicit logged? Advertise sent?), \`tcpdump -n port 546 or port 547\` on both ends, and both firewalls. Server silent although tcpdump sees the Solicit → its input chain (UDP 547). Server sends Advertise but the client never logs it → the client's input chain (UDP 546). Service failed → \`systemctl status isc-dhcp-server\` ("No subnet6 declaration").
5. **Compare families**: \`curl -4\` vs \`curl -6\`, \`ssh -4\` vs \`ssh -6\`.
`,

  errorMap: [
    { message: 'Destination unreachable: Address unreachable (From <router>)', layer: 'Neighbor Discovery', meaning: 'The last router\'s Neighbor Solicitations for the target got no answer.', firstCheck: 'Is the host up with that address? Does its firewall accept ipv6-icmp? ip -6 neigh on the router' },
    { message: 'connect: Network is unreachable (-6)', layer: 'Host routing', meaning: 'No IPv6 route: no global address/default route (no RA, or static config missing).', firstCheck: 'ip -6 addr; ip -6 route; rdisc6' },
    { message: 'IPv6 times out silently, IPv4 works', layer: 'Forwarding / return path', meaning: 'Router with forwarding=0, a firewall drop, or no IPv6 route back on the server.', firstCheck: 'sysctl net.ipv6.conf.all.forwarding on routers; tcpdump on the server' },
    { message: 'Only fe80:: addresses', layer: 'Router discovery', meaning: 'No router advertisement received.', firstCheck: 'rdisc6 eth0; radvd status; VLAN of the port' },
    { message: 'Browser fine, ssh slow / scripts fail', layer: 'Dual stack', meaning: 'Broken IPv6 hidden by Happy Eyeballs.', firstCheck: 'curl -6 / ssh -6 tests' },
    { message: 'XMT: Solicit on eth0, interval ...ms. (repeated, no RCV)', layer: 'DHCPv6 client', meaning: 'No Advertise reached dhclient: no server on the link, the server\'s firewall (547) or the client\'s firewall (546).', firstCheck: 'Server log; tcpdump -n port 546 on the client' },
    { message: 'No subnet6 declaration for eth3 (fe80::5054:ff:fea1:4).', layer: 'DHCPv6 server', meaning: 'INTERFACESv6 names an interface without a global address inside any subnet6.', firstCheck: 'INTERFACESv6; ip -6 addr on that interface; subnet6 declarations' },
    { message: 'Starting ISC DHCPv6 server: dhcpd6check syslog for diagnostics. ... failed!', layer: 'DHCPv6 server', meaning: 'The init script could not start dhcpd -6.', firstCheck: 'journalctl -u isc-dhcp-server for the dhcpd lines above it' },
    { message: 'Destination unreachable: Beyond scope (ping -6) / No route to host', layer: 'Addressing', meaning: 'The host has only a link-local address; the router refuses to forward link-local sources.', firstCheck: 'ip -6 addr: missing global address (SLAAC, DHCPv6, static)' },
    { message: 'unknown option dhcp6.domain-name-servers / domain-name-servers is an IPv4 option', layer: 'DHCPv6 server config', meaning: 'DHCPv4 option names used in dhcpd6.conf.', firstCheck: 'Use dhcp6.name-servers and dhcp6.domain-search' },
  ],

  scenarioIds: ['ipv6-icmp-hardening', 'ipv6-forwarding-hardening', 'ipv6-server-gateway', 'dhcp6-client-firewall', 'dhcp6-server-firewall', 'dhcp6-wrong-interface'],
  assessmentId: 'ipv6',
  references: [
    { title: 'RFC 8200: Internet Protocol, Version 6 (IPv6) Specification', url: 'https://www.rfc-editor.org/rfc/rfc8200' },
    { title: 'RFC 4291: IP Version 6 Addressing Architecture', url: 'https://www.rfc-editor.org/rfc/rfc4291' },
    { title: 'RFC 4861: Neighbor Discovery for IPv6', url: 'https://www.rfc-editor.org/rfc/rfc4861' },
    { title: 'RFC 4862: IPv6 Stateless Address Autoconfiguration', url: 'https://www.rfc-editor.org/rfc/rfc4862' },
    { title: 'RFC 5952: A Recommendation for IPv6 Address Text Representation', url: 'https://www.rfc-editor.org/rfc/rfc5952' },
    { title: 'RFC 6724: Default Address Selection for IPv6', url: 'https://www.rfc-editor.org/rfc/rfc6724' },
    { title: 'RFC 8305: Happy Eyeballs Version 2', url: 'https://www.rfc-editor.org/rfc/rfc8305' },
    { title: 'RFC 4890: Recommendations for Filtering ICMPv6 Messages in Firewalls', url: 'https://www.rfc-editor.org/rfc/rfc4890' },
    { title: 'radvd.conf(5)', url: 'https://manpages.debian.org/bookworm/radvd/radvd.conf.5.en.html' },
    { title: 'RFC 8415: Dynamic Host Configuration Protocol for IPv6 (DHCPv6)', url: 'https://www.rfc-editor.org/rfc/rfc8415' },
    { title: 'RFC 4861 §4.2: Router Advertisement flags (M, O)', url: 'https://www.rfc-editor.org/rfc/rfc4861#section-4.2' },
    { title: 'dhcpd.conf(5) (DHCPv6 declarations: subnet6, range6, fixed-address6)', url: 'https://manpages.debian.org/bookworm/isc-dhcp-server/dhcpd.conf.5.en.html' },
    { title: 'dhclient(8)', url: 'https://manpages.debian.org/bookworm/isc-dhcp-client/dhclient.8.en.html' },
    { title: 'interfaces(5): inet6 dhcp method', url: 'https://manpages.debian.org/bookworm/ifupdown/interfaces.5.en.html' },
  ],
};
