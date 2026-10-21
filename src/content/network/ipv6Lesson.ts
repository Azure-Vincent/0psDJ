import type { Lesson } from '../types';

export const IPV6_LESSON: Lesson = {
  id: 'ipv6',
  moduleId: 'A',
  title: 'IPv6: addressing, SLAAC and Neighbor Discovery',
  level: 'intermediate',
  summary: 'IPv6 addresses and notation, link-local and global addresses, /64 subnets, router advertisements and SLAAC, Neighbor Discovery instead of ARP, ICMPv6 and firewalls, and how dual-stack hosts choose between IPv4 and IPv6.',
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
The **IPv6 pilot** runs in the development VLAN 30: rtr01 advertises **2001:db8:30::/64** with **radvd**; dev01 configures itself (SLAAC). srv01 has the static address **2001:db8:20::10** and ns1 publishes an **AAAA** record for srv01. Everything else stays IPv4-only, like many real networks in transition. (2001:db8::/32 is the documentation prefix.)

> The simulator implements IPv6 addresses (link-local EUI-64, static, SLAAC), routing with longest-prefix match, Neighbor Discovery (NS/NA via solicited-node multicast) and router discovery (RS/RA from radvd), ICMPv6 echo and errors, IPv6 forwarding (silent drop when disabled), nftables ip6/inet/icmpv6 matching with "untracked" ND messages, AAAA records with getaddrinfo() address selection, curl Happy Eyeballs vs ssh sequential fallback, and IPv6/ICMPv6 in tcpdump and PCAP export. ICMPv6 "packet too big" and path-MTU discovery are covered in the MTU lesson. Not modelled: DHCPv6, privacy (temporary) addresses, duplicate address detection, MLD, extension headers.
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
        { path: '/etc/network/interfaces (inet6 static | auto)', purpose: 'Static IPv6 addresses and gateway, or SLAAC.' },
        { path: '/etc/radvd.conf', purpose: 'Router advertisements: prefixes, flags, RDNSS (routers only).' },
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
    { name: 'meta l4proto ipv6-icmp accept (nftables)', compiledDefault: '—', recommended: 'Always on IPv6 hosts (or the RFC 4890 type list)', explanation: 'Lets Neighbor Discovery, router discovery and ICMPv6 errors through the input chain.', security: 'Dropping ICMPv6 breaks IPv6 entirely; it is not like dropping ping.' },
  ],

  troubleshootingIntro: `
### Test IPv6 on its own
1. **Does the host have a global address and a default route?** \`ip -6 addr\`, \`ip -6 route\`. Only fe80:: → no RA received (router, radvd, VLAN, firewall dropping RA).
2. **Is the router reachable?** \`ping -6 <gateway>\`, \`ip -6 neigh\`, \`rdisc6 eth0\`.
3. **Where does it stop?** \`traceroute -6\` / ping each hop. *Address unreachable* = the last router could not resolve the destination (ND failing: host down, wrong address, ICMPv6 blocked). *Silence* = forwarding disabled, a firewall drop, or no route back.
4. **Name resolution**: \`dig AAAA name\`, \`getent ahosts name\` (order of addresses).
5. **Compare families**: \`curl -4\` vs \`curl -6\`, \`ssh -4\` vs \`ssh -6\`.
`,

  errorMap: [
    { message: 'Destination unreachable: Address unreachable (From <router>)', layer: 'Neighbor Discovery', meaning: 'The last router\'s Neighbor Solicitations for the target got no answer.', firstCheck: 'Is the host up with that address? Does its firewall accept ipv6-icmp? ip -6 neigh on the router' },
    { message: 'connect: Network is unreachable (-6)', layer: 'Host routing', meaning: 'No IPv6 route: no global address/default route (no RA, or static config missing).', firstCheck: 'ip -6 addr; ip -6 route; rdisc6' },
    { message: 'IPv6 times out silently, IPv4 works', layer: 'Forwarding / return path', meaning: 'Router with forwarding=0, a firewall drop, or no IPv6 route back on the server.', firstCheck: 'sysctl net.ipv6.conf.all.forwarding on routers; tcpdump on the server' },
    { message: 'Only fe80:: addresses', layer: 'Router discovery', meaning: 'No router advertisement received.', firstCheck: 'rdisc6 eth0; radvd status; VLAN of the port' },
    { message: 'Browser fine, ssh slow / scripts fail', layer: 'Dual stack', meaning: 'Broken IPv6 hidden by Happy Eyeballs.', firstCheck: 'curl -6 / ssh -6 tests' },
  ],

  scenarioIds: ['ipv6-icmp-hardening', 'ipv6-forwarding-hardening', 'ipv6-server-gateway'],
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
  ],
};
