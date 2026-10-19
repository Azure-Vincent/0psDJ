import type { Lesson } from '../types';

export const IP_LESSON: Lesson = {
  id: 'ipnet',
  moduleId: 'A',
  title: 'IP networking: addressing, ARP and routing',
  level: 'beginner',
  summary: 'How a host decides where to send a packet, how it finds the next hop on the wire, and how routers move packets between networks, hop by hop, in both directions.',
  concepts: ['net.cidr', 'net.arp', 'net.routing', 'net.icmp'],

  what: `
Every service in this curriculum depends on one thing working first: **getting an IP packet from one host to another**. This lesson covers the machinery underneath: IPv4 addresses and prefixes, Ethernet and ARP, routing tables and default gateways, routers, TTL and ICMP, and encapsulation.

### The layers involved
| Layer (TCP/IP) | OSI | Unit | Addresses | Example |
|---|---|---|---|---|
| Application | 5–7 | message | names, URLs | SSH, HTTP, DNS |
| Transport | 4 | segment / datagram | ports | TCP, UDP |
| Internet | 3 | packet | IP addresses | IPv4, ICMP |
| Link | 2 | frame | MAC addresses | Ethernet, ARP, VLAN tags |
| Physical | 1 | bits | — | copper, fibre, radio |

Each layer **encapsulates** the one above: an HTTP request becomes the payload of a TCP segment, inside an IP packet, inside an Ethernet frame. Routers look at layer 3 and rebuild layer 2 for every hop; switches only look at layer 2.

### Questions this lesson answers
- Is this destination on my own network, or do I need a router? (**prefix / subnet mask**)
- What is the MAC address of the next hop? (**ARP**)
- Which router, which interface, which source address? (**routing table, longest prefix match**)
- What happens at each router? (**TTL decrement, new frame, forwarding policy**)
- How do failures announce themselves? (**ICMP errors**, or silence)

> IPv6 (neighbour discovery instead of ARP, 128-bit addresses) follows the same logic; the simulator models IPv4 only.
`,

  internals: `
### IPv4 addresses and prefixes
An IPv4 address is 32 bits, written as four decimal octets. A **prefix length** (/24) or **subnet mask** (255.255.255.0) splits it into a network part and a host part. For 10.0.10.25/24 the network is 10.0.10.0/24, the broadcast address is 10.0.10.255 and usable hosts are .1–.254.

- Shorter prefix = bigger network: /23 = 512 addresses (two /24s), /16 = 65 536.
- A host considers every address inside its own prefix to be **on-link**: reachable directly, without a router.
- A wrong prefix is therefore a routing bug: too short and the host tries to reach remote hosts directly; too long and it sends local traffic to the router.

### The routing decision on a host
For every outgoing packet the kernel performs a **longest prefix match** over its routing table (\`ip route\`):

| Route | Meaning |
|---|---|
| \`10.0.10.0/24 dev eth0 proto kernel scope link src 10.0.10.25\` | Connected route, created from the interface address. Destinations here are on-link. |
| \`default via 10.0.10.1 dev eth0\` | 0.0.0.0/0: everything else goes to the gateway 10.0.10.1. |

The most specific matching route wins. The result is an outgoing interface, a **next hop** (the gateway, or the destination itself when on-link) and a source address. \`ip route get ADDR\` performs exactly this lookup.

### ARP: from next hop to MAC address
Ethernet frames carry MAC addresses, not IP addresses. To send to the next hop, the host needs its MAC:
1. Look in the neighbour cache (\`ip neigh\`).
2. If missing, broadcast an **ARP request** (\`who has 10.0.10.1? tell 10.0.10.25\`) to ff:ff:ff:ff:ff:ff.
3. The owner answers with a unicast **ARP reply**; both sides cache the mapping.
4. If no one answers (~3 s of retries), the entry becomes FAILED and the sender reports **EHOSTUNREACH: "No route to host"** although no route is missing.

ARP never crosses a router. Note *whose* MAC is resolved: for a remote destination it is the **gateway's**, never the final host's.

### What a router does
A router is a host with \`net.ipv4.ip_forward=1\` and interfaces in several networks. For each packet not addressed to itself it:
1. Decrements the **TTL**; at 0 it drops the packet and sends ICMP *time exceeded* (this is how traceroute works).
2. Performs its own longest-prefix-match lookup.
3. Applies its forward-chain firewall, if any.
4. ARPs for the next hop on the outgoing network and sends a **new Ethernet frame** (new source and destination MAC; the IP header keeps the original addresses).

With forwarding disabled, a Linux router answers packets it may not route with **ICMP host unreachable**.

### Both directions
Routing is decided independently at every hop and **in each direction**. The reply from the server is routed by the server's own table, and the server needs a route back to the client's network (usually its default gateway). A missing return route produces the same client symptom as a firewall drop: a timeout.

### ICMP: how the network reports problems
| ICMP | Sent when | Client sees |
|---|---|---|
| Echo request / reply (8/0) | ping | replies with RTT and TTL |
| Destination unreachable, host (3/1) | a router cannot ARP the destination, or will not forward | "No route to host" |
| Destination unreachable, net (3/0) | a router has no route | "Network is unreachable" |
| Destination unreachable, port (3/3) | UDP to a closed port | "Connection refused" / resolver moves on |
| Time exceeded (11/0) | TTL reached 0 | traceroute hop line |

Silence (no ICMP at all) is also information: something dropped the packet without telling anyone.

### Encapsulation on the wire
A frame on the LAN for an HTTP request is: Ethernet header (14 bytes: destination MAC, source MAC, EtherType 0x0800) → IPv4 header (20 bytes: version/IHL, length, ID, flags, TTL, protocol, checksum, source, destination) → TCP header (20–60 bytes) → HTTP payload. The explorer below colours each region of a real frame produced by the simulator.
`,

  deployment: [
    {
      id: 'debian-ifupdown',
      platform: 'Debian 12 (ifupdown)',
      summary: 'Configure a static address, prefix and gateway, apply them, and verify routing and neighbours. Run on a real VM; commands marked "simulated" also work in the sandbox.',
      prerequisites: ['Debian 12 VM with console access (a wrong address can cut your SSH session).', 'Root or sudo.'],
      steps: [
        { title: 'Inspect the current configuration', command: 'ip -4 addr\nip route\ncat /etc/network/interfaces', what: 'Shows runtime addresses and routes, and the persistent configuration that recreates them at boot.', why: 'Runtime and persistent state can differ; know both before changing anything.', expected: '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ...\n    inet 10.0.10.25/24 brd 10.0.10.255 scope global eth0\ndefault via 10.0.10.1 dev eth0 onlink\n10.0.10.0/24 dev eth0 proto kernel scope link src 10.0.10.25', simulated: true },
        { title: 'Edit the persistent configuration', command: 'sudo nano /etc/network/interfaces\n\nauto eth0\niface eth0 inet static\n    address 10.0.10.25/24\n    gateway 10.0.10.1', what: 'Declares the address with its prefix and the default gateway for eth0.', why: 'The prefix decides what is on-link; the gateway must be inside that prefix.', expected: '' },
        { title: 'Apply', command: 'sudo systemctl restart networking', what: 'ifdown/ifup all auto interfaces: addresses and routes are rebuilt from the file.', why: 'Edits to the file do nothing until applied. Run this from the console: it briefly removes the address.', expected: '(no output on success)', simulated: true },
        { title: 'Verify the routing decision', command: 'ip route get 10.0.20.10\nip route get 10.0.10.53', what: 'Asks the kernel which route, next hop and source address it would use.', why: 'A remote address must show "via <gateway>"; a local one must not.', expected: '10.0.20.10 via 10.0.10.1 dev eth0 src 10.0.10.25 uid 0\n10.0.10.53 dev eth0 src 10.0.10.25 uid 0', simulated: true },
        { title: 'Verify layer 2 and layer 3', command: 'ping -c 2 10.0.10.1\nip neigh\nping -c 2 10.0.20.10', what: 'Pings the gateway (must be REACHABLE in ip neigh), then a remote host (TTL one lower than the host\'s default).', why: 'Separates "my LAN works" from "routing beyond my LAN works".', expected: '64 bytes from 10.0.10.1: icmp_seq=1 ttl=64 time=0.31 ms\n10.0.10.1 dev eth0 lladdr 52:54:00:a1:00:01 REACHABLE\n64 bytes from 10.0.20.10: icmp_seq=1 ttl=63 time=0.52 ms', simulated: true },
        { title: 'Trace the path', command: 'traceroute -n 10.0.20.10\nsudo traceroute -n -I 10.0.20.10', what: 'Lists each router by provoking ICMP time-exceeded with increasing TTL.', why: 'Shows where packets stop. UDP probes may be dropped by the destination firewall; -I uses ICMP echo, -T TCP SYN.', expected: '# UDP probes (default): srv01\'s firewall drops them\n 1  10.0.10.1  0.31 ms  0.29 ms  0.28 ms\n 2  * * *\n# ICMP probes (-I): srv01 accepts ICMP\n 1  10.0.10.1  0.31 ms  0.29 ms  0.28 ms\n 2  10.0.20.10  0.51 ms  0.49 ms  0.48 ms', simulated: true },
      ],
    },
    {
      id: 'netplan',
      platform: 'Ubuntu (netplan)',
      summary: 'Ubuntu describes networking in YAML; netplan renders it for systemd-networkd or NetworkManager.',
      prerequisites: ['Ubuntu 22.04/24.04 VM with console access.'],
      steps: [
        { title: 'Write the configuration', command: 'sudo nano /etc/netplan/01-static.yaml\n\nnetwork:\n  version: 2\n  ethernets:\n    eth0:\n      addresses: [10.0.10.25/24]\n      routes:\n        - to: default\n          via: 10.0.10.1\n      nameservers:\n        addresses: [10.0.10.53]\n        search: [corp.lab]', what: 'Address with prefix, default route and DNS for eth0.', why: 'YAML indentation matters; "gateway4" is deprecated in favour of routes.', expected: '' },
        { title: 'Try with automatic rollback', command: 'sudo netplan try', what: 'Applies the configuration and reverts after 120 s unless you confirm.', why: 'Protects remote sessions from a lock-out.', expected: 'Do you want to keep these settings?\nPress ENTER before the timeout to accept the new configuration\nChanges will revert in 118 seconds' },
        { title: 'Verify', command: 'ip route get 10.0.20.10\nresolvectl status eth0', what: 'Routing decision and per-link DNS servers.', why: 'On Ubuntu, /etc/resolv.conf points to the local stub 127.0.0.53; the real servers are shown by resolvectl.', expected: '10.0.20.10 via 10.0.10.1 dev eth0 src 10.0.10.25\nCurrent DNS Server: 10.0.10.53' },
      ],
    },
    {
      id: 'rhel-nmcli',
      platform: 'RHEL 9 / Rocky (NetworkManager)',
      summary: 'RHEL manages interfaces through NetworkManager connection profiles.',
      prerequisites: ['RHEL-compatible 9 VM with console access.'],
      steps: [
        { title: 'Configure a static profile', command: 'sudo nmcli con mod eth0 ipv4.method manual ipv4.addresses 10.0.10.25/24 ipv4.gateway 10.0.10.1 ipv4.dns 10.0.10.53\nsudo nmcli con up eth0', what: 'Changes the stored profile and re-activates it.', why: 'Profiles are persistent (/etc/NetworkManager/system-connections/); "con up" applies them.', expected: 'Connection successfully activated (D-Bus active path: /org/freedesktop/NetworkManager/ActiveConnection/3)' },
        { title: 'Verify', command: 'nmcli -g ipv4.addresses,ipv4.gateway con show eth0\nip route', what: 'Stored values and the runtime routing table.', why: 'Confirms what NetworkManager applied.', expected: '10.0.10.25/24\n10.0.10.1\ndefault via 10.0.10.1 dev eth0 proto static metric 100' },
      ],
    },
    {
      id: 'windows-ip',
      platform: 'Windows Server',
      summary: 'Static addressing with PowerShell.',
      prerequisites: ['Windows Server 2019/2022, elevated PowerShell.'],
      steps: [
        { title: 'Set address and gateway', command: 'New-NetIPAddress -InterfaceAlias Ethernet0 -IPAddress 10.0.10.40 -PrefixLength 24 -DefaultGateway 10.0.10.1\nSet-DnsClientServerAddress -InterfaceAlias Ethernet0 -ServerAddresses 10.0.10.53', what: 'Assigns the address, creates the default route and sets the DNS server.', why: 'PrefixLength is the same concept as /24.', expected: 'IPAddress         : 10.0.10.40\nPrefixLength      : 24' },
        { title: 'Verify', command: 'Get-NetRoute -DestinationPrefix 0.0.0.0/0\nFind-NetRoute -RemoteIPAddress 10.0.20.10\narp -a', what: 'Default route, the route chosen for a destination (like ip route get) and the ARP cache.', why: 'Same checks as on Linux.', expected: 'NextHop : 10.0.10.1' },
      ],
    },
  ],

  configIntro: `
Network configuration has two forms: **runtime** state in the kernel (\`ip addr\`, \`ip route\`, \`ip neigh\`, \`sysctl\`) and **persistent** files that recreate it at boot. Commands like \`ip route add\` change only the runtime state. Use the route-lookup tool to see how longest-prefix match picks a route from any table you type.
`,

  configFiles: [
    {
      platform: 'Linux',
      items: [
        { path: '/etc/network/interfaces', purpose: 'ifupdown (Debian): address/prefix, gateway, extra routes ("up ip route add ...").' },
        { path: '/etc/netplan/*.yaml', purpose: 'netplan (Ubuntu).' },
        { path: '/etc/NetworkManager/system-connections/', purpose: 'NetworkManager profiles (RHEL, desktops).' },
        { path: '/etc/sysctl.conf, /etc/sysctl.d/*.conf', purpose: 'net.ipv4.ip_forward (router), rp_filter and other kernel settings, applied at boot.' },
        { path: 'ip addr / ip route / ip neigh', purpose: 'Runtime addresses, routing table and ARP cache.' },
      ],
    },
    {
      platform: 'Windows',
      items: [
        { path: 'Get-NetIPAddress / Get-NetRoute', purpose: 'Addresses and routes.' },
        { path: 'arp -a / Get-NetNeighbor', purpose: 'ARP cache.' },
      ],
    },
  ],

  directives: [
    { name: 'address A.B.C.D/N', compiledDefault: '—', recommended: 'Correct prefix for the subnet', explanation: 'Interface address and prefix length; creates the connected route.', security: 'A wrong prefix silently breaks reachability in one direction or the other.' },
    { name: 'gateway A.B.C.D', compiledDefault: '—', recommended: 'The router on this subnet', explanation: 'Creates "default via" the gateway. Must be inside the interface prefix.', security: 'Only one default route per host (unless using metrics/policy routing).' },
    { name: 'up ip route add NET via GW', compiledDefault: '—', recommended: 'For additional networks behind other routers', explanation: 'Static routes for specific networks; more specific than the default route.', security: 'Static routes override the default for their prefix: check them first when one network misbehaves.' },
    { name: 'net.ipv4.ip_forward', compiledDefault: '0', recommended: '1 on routers only', explanation: 'Allows the kernel to route packets between interfaces.', security: 'Hardening baselines disable it on servers; never apply them blindly to routers.' },
    { name: 'net.ipv4.conf.all.rp_filter', compiledDefault: '0 (kernel), 2 on many distros', recommended: '1 (strict) on hosts with one path', explanation: 'Reverse-path filter: drop packets whose source would not be routed back through the interface they arrived on.', security: 'Blocks spoofed sources; breaks asymmetric routing setups when strict.' },
    { name: 'MTU (ip link set dev eth0 mtu 1500)', compiledDefault: '1500 on Ethernet', recommended: 'Consistent along the path', explanation: 'Largest packet the interface sends. Tunnels (VPN, VXLAN) reduce the effective MTU.', security: 'Blocking all ICMP breaks path-MTU discovery: large transfers hang while small ones work.' },
  ],

  troubleshootingIntro: `
### Work outwards from the host
1. **Addressing**: \`ip -4 addr\`: right address and prefix? (A 169.254.x.x address means DHCP failed.)
2. **Routing decision**: \`ip route get <destination>\`: right gateway/interface? "via" present for remote hosts?
3. **Next hop**: \`ping <gateway>\`, \`ip neigh\`: REACHABLE or FAILED?
4. **Beyond the gateway**: \`ping\`/\`traceroute\` to the destination. Who answers with an ICMP error, if anyone?
5. **Return path**: from the destination's console, \`ip route get <client>\`. Capture on both ends when a timeout gives no clue.

Read ping's error lines: "From 10.0.10.25 … Destination Host Unreachable" comes from **yourself** (local ARP failure); "From 10.0.10.1 …" comes from **the router**.
`,

  errorMap: [
    { message: 'connect: Network is unreachable', layer: 'Local routing', meaning: 'No route matches the destination (no default route).', firstCheck: 'ip route; ip route get DEST' },
    { message: 'From <own IP> … Destination Host Unreachable', layer: 'Local ARP', meaning: 'This host tried to ARP the next hop and nobody answered: wrong gateway, wrong prefix, or the on-link host is down.', firstCheck: 'ip route get DEST; ip neigh (FAILED entries)' },
    { message: 'From <router IP> … Destination Host Unreachable', layer: 'Router', meaning: 'The router could not deliver: ARP failed on its far side, or it does not forward (ip_forward=0).', firstCheck: 'On the router: ip neigh, sysctl net.ipv4.ip_forward, tcpdump on both interfaces' },
    { message: 'Request timeout / 100% packet loss', layer: 'Path or return path', meaning: 'Packets or replies are silently dropped: firewall, missing return route, dead host.', firstCheck: 'tcpdump on the destination; ip route on the destination' },
    { message: 'traceroute stops with * * * after hop N', layer: 'Path', meaning: 'Probes beyond hop N get no answer: filtered probes or a broken hop. Destination firewalls often drop UDP probes.', firstCheck: 'traceroute -I or -T -p PORT; capture at the next hop' },
    { message: 'Time to live exceeded', layer: 'Routing loop', meaning: 'A packet circled between routers until TTL reached 0.', firstCheck: 'traceroute (repeating hops); routing tables of the looping routers' },
  ],

  scenarioIds: ['net-wrong-mask', 'net-wrong-gateway', 'net-ip-forward', 'ssh-missing-gateway', 'ssh-dns-stale'],
  assessmentId: 'ipnet',
  references: [
    { title: 'RFC 791: Internet Protocol', url: 'https://www.rfc-editor.org/rfc/rfc791' },
    { title: 'RFC 826: An Ethernet Address Resolution Protocol', url: 'https://www.rfc-editor.org/rfc/rfc826' },
    { title: 'RFC 792: Internet Control Message Protocol', url: 'https://www.rfc-editor.org/rfc/rfc792' },
    { title: 'RFC 1812: Requirements for IP Version 4 Routers', url: 'https://www.rfc-editor.org/rfc/rfc1812' },
    { title: 'RFC 4632: Classless Inter-domain Routing (CIDR)', url: 'https://www.rfc-editor.org/rfc/rfc4632' },
    { title: 'RFC 1918: Address Allocation for Private Internets', url: 'https://www.rfc-editor.org/rfc/rfc1918' },
    { title: 'ip-route(8) and ip-neighbour(8) manual pages', url: 'https://man7.org/linux/man-pages/man8/ip-route.8.html' },
    { title: 'Debian Reference: Network setup', url: 'https://www.debian.org/doc/manuals/debian-reference/ch05.en.html' },
  ],
};
