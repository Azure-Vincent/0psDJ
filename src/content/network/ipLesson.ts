import type { Lesson } from '../types';

export const IP_LESSON: Lesson = {
  id: 'ipnet',
  moduleId: 'A',
  title: 'IP networking: addressing, ARP and routing',
  level: 'beginner',
  summary: 'How a host decides where to send a packet, how it finds the next hop on the wire, and how routers move packets between networks, hop by hop, in both directions.',
  concepts: ['net.cidr', 'net.arp', 'net.routing', 'net.icmp'],

  what: `
Before any service can work (a web site, a file share, a remote login), one computer has to be able to send data to another. On almost every network today that data travels as **IP packets**: small chunks of data, each labelled with the address of the computer that sent it and the computer that should receive it.

This lesson explains how that delivery works. You will learn how a computer decides whether a destination is nearby or far away, how it finds the next device to hand the packet to, and how **routers** pass packets from one network to the next until they arrive. Everything else in this course builds on these ideas, so it is worth taking your time here.

### Why it matters
When something "can't connect", the cause is very often here: a wrong address, a missing gateway, a router that does not forward, or a server that cannot send its reply back. If you understand how a packet travels, you can test each part of its journey and find the broken one, instead of guessing.

### The layers involved
Network communication is usually described in **layers**. Each layer has one job and relies on the layer below it. You do not need to memorise the whole model, but you will see these names everywhere:

| Layer (TCP/IP) | OSI number | What travels | Addressed by | Examples |
|---|---|---|---|---|
| Application | 5–7 | message | names, URLs | SSH, HTTP, DNS |
| Transport | 4 | segment / datagram | ports | TCP, UDP |
| Internet | 3 | packet | IP addresses | IPv4, ICMP |
| Link | 2 | frame | MAC addresses | Ethernet, ARP, VLAN tags |
| Physical | 1 | bits | — | copper, fibre, radio |

Each layer wraps the data from the layer above it, like putting a letter in an envelope and then that envelope in a parcel. This is called **encapsulation**: an HTTP request travels inside a TCP segment, which travels inside an IP packet, which travels inside an Ethernet frame.

This lesson is about layers 2 and 3. **Switches** only look at layer 2 (MAC addresses) and move frames within one local network. **Routers** look at layer 3 (IP addresses) and move packets between networks, building a new layer 2 frame for each hop.

### What you will be able to answer
- Is this destination on my own network, or do I need a router? (the **prefix**, also called the subnet mask)
- Which device is the next stop for my packet, and what is its hardware address? (**ARP**)
- Which router, which network card and which source address will my computer use? (the **routing table** and **longest prefix match**)
- What does each router do with the packet? (**TTL**, forwarding, a new frame)
- How does the network tell me something went wrong? (**ICMP** error messages, or silence)

> IPv6 uses the same logic with longer addresses and Neighbor Discovery instead of ARP. Once this lesson makes sense, the [IPv6 lesson](#/lesson/ipv6/what) shows the differences. Ports, TCP and DNS, the next layer up, are in [Transport and DNS](#/lesson/transport/what).
`,

  internals: `
### IPv4 addresses and prefixes
An IPv4 address is a 32-bit number, normally written as four numbers from 0 to 255 separated by dots, for example 10.0.10.25. Each of the four numbers is called an **octet** (8 bits).

An address on its own is not enough. The computer also needs to know which part of the address names the **network** and which part names the individual **host** (the computer) on that network. The **prefix length** says this. In 10.0.10.25/24, the "/24" means the first 24 bits (the first three octets, 10.0.10) are the network part, and the last octet (25) identifies the host. The same information is sometimes written as a **subnet mask**: /24 is 255.255.255.0.

For 10.0.10.25/24:
- the network is **10.0.10.0/24**,
- the **broadcast address** (a special address meaning "everyone on this network") is 10.0.10.255,
- the usable host addresses are 10.0.10.1 to 10.0.10.254.

A few rules of thumb:
- A shorter prefix means a bigger network: /23 has 512 addresses (two /24s), /16 has 65 536.
- A host treats every address inside its own prefix as **on-link**: it believes it can reach that address directly, without a router.
- That is why a wrong prefix is a routing problem, not a cosmetic one. Too short (for example /16 instead of /24) and the host tries to reach remote computers directly and nothing answers. Too long and it sends local traffic to the router unnecessarily, or cannot reach some neighbours at all.

### How a host decides where to send a packet
Every computer, not just routers, has a **routing table**: a list of networks it knows about and how to reach each one. On Linux you can see it with \`ip route\`. For every packet it sends, the kernel (the core of the operating system) looks for the entry that matches the destination most precisely. This is called **longest prefix match**: if two routes both match, the one with the longer prefix (the smaller, more specific network) wins.

A typical workstation has just two routes:

| Route | What it means |
|---|---|
| \`10.0.10.0/24 dev eth0 proto kernel scope link src 10.0.10.25\` | A **connected route**, created automatically from the interface address. Anything in 10.0.10.0/24 is on-link: send it straight out of eth0. |
| \`default via 10.0.10.1 dev eth0\` | The **default route** (0.0.0.0/0, "everything else"). Send it to the **default gateway** 10.0.10.1, the router on this network. |

The result of the lookup is three things: the outgoing interface, the **next hop** (the gateway, or the destination itself if it is on-link) and the source address to use. You can ask the kernel to show you its decision for any address with \`ip route get ADDR\`. This is one of the most useful commands in network troubleshooting.

### ARP: finding the next hop's hardware address
On an Ethernet network (wired or Wi-Fi), data is actually delivered in **frames** addressed to a **MAC address**: a hardware address burned into each network card, such as 52:54:00:a1:00:01. IP addresses are for finding the way across networks; MAC addresses are for the last step, delivery on the local wire.

So before a host can send a packet to its next hop, it needs that next hop's MAC address. It uses **ARP** (Address Resolution Protocol):
1. It looks in its neighbour cache first (\`ip neigh\` shows it).
2. If the address is not there, it sends an **ARP request** to everyone on the local network (the broadcast MAC ff:ff:ff:ff:ff:ff): "who has 10.0.10.1? tell 10.0.10.25".
3. The device that owns 10.0.10.1 answers directly with an **ARP reply** containing its MAC address. Both sides remember the answer for a while.
4. If nobody answers after about 3 seconds of retries, the entry is marked FAILED and the program that tried to send gets the error **EHOSTUNREACH: "No route to host"**. That message is confusing, because the route exists; what failed is ARP.

Two things to remember. ARP only works within one local network; it never crosses a router. And for a destination on another network, the host ARPs for the **gateway's** MAC address, never for the final destination's.

### What a router does
A router is a computer with network interfaces in more than one network and **forwarding** switched on (on Linux, \`net.ipv4.ip_forward=1\`). When a packet arrives that is not addressed to the router itself, it:
1. Lowers the packet's **TTL** (time to live) by one. The TTL starts at a number such as 64; if it reaches 0, the router drops the packet and sends back an ICMP "time exceeded" message. This stops packets from looping forever, and it is how \`traceroute\` discovers each router on a path.
2. Looks up the destination in its own routing table (longest prefix match again).
3. Applies its firewall rules for forwarded traffic, if it has any.
4. Uses ARP to find the next hop on the outgoing network, and sends the packet inside a **new Ethernet frame**. The MAC addresses change at every hop; the source and destination IP addresses inside the packet stay the same.

If forwarding is switched off, a Linux router behaves like an ordinary host and answers packets it should have forwarded with **ICMP host unreachable**.

### Traffic must work in both directions
Each router, and each end of the conversation, makes its own routing decision, independently, for every packet. A reply from a server is routed using the **server's** routing table, so the server needs a route back to the client's network (usually its own default gateway).

A missing return route is a classic trap: the request arrives, the server tries to answer, and the answer never leaves. From the client it looks exactly like a firewall silently dropping traffic: a timeout.

### ICMP: how the network reports problems
**ICMP** (Internet Control Message Protocol) carries status and error messages for IP. \`ping\` uses it, and routers use it to tell a sender why a packet could not be delivered. The message type tells you how far the packet got:

| ICMP message (type/code) | Sent when | What the client shows |
|---|---|---|
| Echo request / reply (8/0) | ping | replies with round-trip time and TTL |
| Destination unreachable, host (3/1) | a router cannot ARP the destination, or will not forward | "No route to host" |
| Destination unreachable, net (3/0) | a router has no route to the destination network | "Network is unreachable" |
| Destination unreachable, port (3/3) | UDP sent to a port where nothing listens | "Connection refused", or the resolver tries another server |
| Time exceeded (11/0) | the TTL reached 0 | one hop line in traceroute |

Silence is information too. If you get no ICMP message at all, something dropped the packet without telling anyone, very often a firewall.

### Encapsulation on the wire
Here is what one frame carrying a web request looks like, from the outside in:
- **Ethernet header** (14 bytes): destination MAC, source MAC, and EtherType 0x0800 ("an IPv4 packet follows").
- **IPv4 header** (20 bytes): version and header length, total length, ID, flags, TTL, protocol (6 = TCP), checksum, source IP, destination IP.
- **TCP header** (20–60 bytes): ports, sequence numbers, flags.
- **HTTP payload**: the actual request.

The explorer below colours each of these regions in a real frame produced by the simulator, so you can see where every field sits.
`,

  deployment: [
    {
      id: 'debian-ifupdown',
      platform: 'Debian 12 (ifupdown)',
      summary: 'Give a Debian server a fixed (static) address, prefix and default gateway, apply the change, and check that routing and ARP work. Do this on a real VM; steps marked "simulated" also work in the sandbox below.',
      prerequisites: ['A Debian 12 VM with console access. Console means the hypervisor\'s screen, not SSH: if you make a mistake in the address, an SSH session over that address is cut off.', 'Root or sudo rights.'],
      steps: [
        { title: 'Inspect the current configuration', command: 'ip -4 addr\nip route\ncat /etc/network/interfaces', what: '`ip -4 addr` lists the IPv4 addresses the kernel is using right now, `ip route` the routing table, and the file shows the configuration that will be applied at the next boot.', why: 'What is running now (the runtime state) and what is saved in the file (the persistent state) are not always the same. Look at both before you change anything, so you know what you are starting from.', expected: '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ...\n    inet 10.0.10.25/24 brd 10.0.10.255 scope global eth0\ndefault via 10.0.10.1 dev eth0 onlink\n10.0.10.0/24 dev eth0 proto kernel scope link src 10.0.10.25', simulated: true },
        { title: 'Edit the persistent configuration', command: 'sudo nano /etc/network/interfaces\n\nauto eth0\niface eth0 inet static\n    address 10.0.10.25/24\n    gateway 10.0.10.1', what: 'The stanza tells ifupdown to bring eth0 up at boot (`auto eth0`) with a fixed address and prefix (`address 10.0.10.25/24`) and a default gateway.', why: 'The prefix decides which addresses the server treats as local (on-link). The gateway must be one of those local addresses, otherwise the server cannot reach it.', expected: '' },
        { title: 'Apply', command: 'sudo systemctl restart networking', what: 'Takes every `auto` interface down and up again (ifdown, then ifup), so the addresses and routes are rebuilt from the file you just edited.', why: 'Saving the file changes nothing by itself; the kernel only learns about it when the interface is re-applied. Run this from the console: for a moment the server has no address, and a typo would leave it unreachable over the network.', expected: '(no output on success)', simulated: true },
        { title: 'Verify the routing decision', command: 'ip route get 10.0.20.10\nip route get 10.0.10.53', what: 'Asks the kernel which route, next hop and source address it would use for each destination, without sending anything.', why: 'This confirms the prefix and gateway are right. An address on another network must show "via 10.0.10.1" (it goes through the router); an address on the local network must not (it is delivered directly).', expected: '10.0.20.10 via 10.0.10.1 dev eth0 src 10.0.10.25 uid 0\n10.0.10.53 dev eth0 src 10.0.10.25 uid 0', simulated: true },
        { title: 'Verify layer 2 and layer 3', command: 'ping -c 2 10.0.10.1\nip neigh\nping -c 2 10.0.20.10', what: 'First pings the gateway and checks that ARP found its MAC address (`REACHABLE` in `ip neigh`), then pings a host on another network. That reply shows ttl=63: one lower than the 64 it started with, because it crossed one router.', why: 'Testing in this order separates two questions: "does my local network work?" (the gateway answers) and "does routing beyond my network work?" (the remote host answers).', expected: '64 bytes from 10.0.10.1: icmp_seq=1 ttl=64 time=0.31 ms\n10.0.10.1 dev eth0 lladdr 52:54:00:a1:00:01 REACHABLE\n64 bytes from 10.0.20.10: icmp_seq=1 ttl=63 time=0.52 ms', simulated: true },
        { title: 'Trace the path', command: 'traceroute -n 10.0.20.10\nsudo traceroute -n -I 10.0.20.10', what: 'traceroute sends probes with TTL 1, then 2, then 3, and so on. Each router that lowers the TTL to 0 answers with ICMP time exceeded, so each line of output is one router on the path.', why: 'It shows where packets stop. By default traceroute sends UDP probes, which the destination\'s firewall may drop (the `* * *` line). `-I` sends ICMP echo instead, and `-T` sends TCP SYN, which often get through.', expected: '# UDP probes (default): srv01\'s firewall drops them\n 1  10.0.10.1  0.31 ms  0.29 ms  0.28 ms\n 2  * * *\n# ICMP probes (-I): srv01 accepts ICMP\n 1  10.0.10.1  0.31 ms  0.29 ms  0.28 ms\n 2  10.0.20.10  0.51 ms  0.49 ms  0.48 ms', simulated: true },
      ],
    },
    {
      id: 'netplan',
      platform: 'Ubuntu (netplan)',
      summary: 'Ubuntu Server describes its network configuration in YAML files. A tool called netplan reads them and passes the settings to the program that actually configures the interfaces (systemd-networkd on servers, NetworkManager on desktops).',
      prerequisites: ['Ubuntu 22.04/24.04 VM with console access.'],
      steps: [
        { title: 'Write the configuration', command: 'sudo nano /etc/netplan/01-static.yaml\n\nnetwork:\n  version: 2\n  ethernets:\n    eth0:\n      addresses: [10.0.10.25/24]\n      routes:\n        - to: default\n          via: 10.0.10.1\n      nameservers:\n        addresses: [10.0.10.53]\n        search: [corp.lab]', what: 'Sets the address and prefix, a default route through 10.0.10.1, and the DNS server and search domain for eth0.', why: 'In YAML, indentation is part of the meaning: a line indented one space too far belongs to a different section. Older guides use `gateway4:`, which is deprecated; use a `routes:` entry with `to: default` instead.', expected: '' },
        { title: 'Try with automatic rollback', command: 'sudo netplan try', what: 'Applies the new configuration, then automatically goes back to the old one after 120 seconds unless you press Enter to keep it.', why: 'If the new settings cut off your SSH session, you cannot press Enter, so the server rolls back by itself and you can reconnect. Always prefer this over `netplan apply` when working remotely.', expected: 'Do you want to keep these settings?\nPress ENTER before the timeout to accept the new configuration\nChanges will revert in 118 seconds' },
        { title: 'Verify', command: 'ip route get 10.0.20.10\nresolvectl status eth0', what: 'Shows the routing decision for a remote address and the DNS servers configured for eth0.', why: 'On Ubuntu, /etc/resolv.conf only lists 127.0.0.53, a small local DNS forwarder (systemd-resolved). The real DNS servers it forwards to are shown by `resolvectl`.', expected: '10.0.20.10 via 10.0.10.1 dev eth0 src 10.0.10.25\nCurrent DNS Server: 10.0.10.53' },
      ],
    },
    {
      id: 'rhel-nmcli',
      platform: 'RHEL 9 / Rocky (NetworkManager)',
      summary: 'Red Hat Enterprise Linux and its relatives (Rocky, AlmaLinux) manage interfaces with NetworkManager. Each interface has a saved **connection profile**, which you change with `nmcli`.',
      prerequisites: ['RHEL-compatible 9 VM with console access.'],
      steps: [
        { title: 'Configure a static profile', command: 'sudo nmcli con mod eth0 ipv4.method manual ipv4.addresses 10.0.10.25/24 ipv4.gateway 10.0.10.1 ipv4.dns 10.0.10.53\nsudo nmcli con up eth0', what: '`nmcli con mod` changes the saved profile; `nmcli con up` re-activates the profile so the change takes effect.', why: 'Profiles are stored on disk in /etc/NetworkManager/system-connections/, so they survive a reboot. Changing a profile does nothing to the running interface until you bring it up again.', expected: 'Connection successfully activated (D-Bus active path: /org/freedesktop/NetworkManager/ActiveConnection/3)' },
        { title: 'Verify', command: 'nmcli -g ipv4.addresses,ipv4.gateway con show eth0\nip route', what: 'The first command prints the address and gateway saved in the profile; `ip route` shows what the kernel is actually using.', why: 'If the two disagree, the profile was changed but not re-activated.', expected: '10.0.10.25/24\n10.0.10.1\ndefault via 10.0.10.1 dev eth0 proto static metric 100' },
      ],
    },
    {
      id: 'windows-ip',
      platform: 'Windows Server',
      summary: 'Set a static address on Windows Server with PowerShell. The concepts are exactly the same as on Linux; only the commands differ.',
      prerequisites: ['Windows Server 2019/2022, elevated PowerShell.'],
      steps: [
        { title: 'Set address and gateway', command: 'New-NetIPAddress -InterfaceAlias Ethernet0 -IPAddress 10.0.10.40 -PrefixLength 24 -DefaultGateway 10.0.10.1\nSet-DnsClientServerAddress -InterfaceAlias Ethernet0 -ServerAddresses 10.0.10.53', what: '`New-NetIPAddress` assigns the address and prefix and creates the default route through the gateway; `Set-DnsClientServerAddress` sets the DNS server.', why: '`-PrefixLength 24` means the same as /24 on Linux: the first three octets are the network.', expected: 'IPAddress         : 10.0.10.40\nPrefixLength      : 24' },
        { title: 'Verify', command: 'Get-NetRoute -DestinationPrefix 0.0.0.0/0\nFind-NetRoute -RemoteIPAddress 10.0.20.10\narp -a', what: 'Shows the default route, the route Windows would choose for 10.0.20.10 (the equivalent of `ip route get`) and the ARP cache.', why: 'These are the same three checks as on Linux: is there a default route, which route is chosen, and was the gateway\'s MAC address found?', expected: 'NextHop : 10.0.10.1' },
      ],
    },
  ],

  configIntro: `
Network settings exist in two places, and it is important to keep them apart:
- **Runtime state**: what the kernel is using right now. You see it with \`ip addr\`, \`ip route\`, \`ip neigh\` and \`sysctl\`. Commands such as \`ip route add\` change only this, and the change disappears at the next reboot or when the interface is restarted.
- **Persistent configuration**: the files that recreate the runtime state every time the machine boots. Which files depends on the distribution (listed below).

A fix that only changes the runtime state is a workaround: it helps now and is gone after a reboot. A real fix goes into the persistent configuration.

The route-lookup tool below lets you type in any routing table and see which route longest prefix match picks for a destination.
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
    { name: 'address A.B.C.D/N', compiledDefault: '—', recommended: 'Correct prefix for the subnet', explanation: 'The interface address and its prefix length. Setting it also creates the connected route for that network automatically.', security: 'A wrong prefix gives no error message; it just makes some destinations unreachable, depending on whether it is too short or too long.' },
    { name: 'gateway A.B.C.D', compiledDefault: '—', recommended: 'The router on this subnet', explanation: 'Creates the default route ("default via ..."): everything not on a local network goes to this router. The gateway address must be inside the interface\'s own network.', security: 'A host normally has exactly one default route. Two default routes only make sense with route metrics or policy routing, which are advanced setups.' },
    { name: 'up ip route add NET via GW', compiledDefault: '—', recommended: 'For additional networks behind other routers', explanation: 'A static route for one specific network that sits behind a different router. Because it is more specific than the default route, longest prefix match picks it first.', security: 'A static route overrides the default route for its network. When only one remote network is unreachable, look for a wrong static route first.' },
    { name: 'net.ipv4.ip_forward', compiledDefault: '0', recommended: '1 on routers only', explanation: 'Switches forwarding on: the kernel will pass packets from one interface to another. This is what turns a Linux machine into a router.', security: 'Security hardening guides switch it off on ordinary servers, which is correct there. Applied to a router, the same setting silently stops all routed traffic.' },
    { name: 'net.ipv4.conf.all.rp_filter', compiledDefault: '0 (kernel), 2 on many distros', recommended: '1 (strict) on hosts with one path', explanation: 'Reverse-path filter: when a packet arrives, the kernel checks whether a reply to its source address would leave through the same interface. If not, the packet is dropped.', security: 'Protects against forged (spoofed) source addresses. In strict mode it breaks networks where traffic deliberately goes out one way and comes back another (asymmetric routing).' },
    { name: 'MTU (ip link set dev eth0 mtu 1500)', compiledDefault: '1500 on Ethernet', recommended: 'Consistent along the path', explanation: 'MTU (maximum transmission unit) is the largest packet the interface will send, in bytes. Tunnels such as VPNs and VXLAN add their own headers, so the space left for data is smaller.', security: 'Do not block all ICMP: hosts learn the usable packet size from ICMP messages, and without them large transfers hang while small ones work. See the [MTU lesson](#/lesson/mtu/what).' },
  ],

  troubleshootingIntro: `
### Start at your own computer and work outwards
A packet's journey has several stages, and each depends on the one before it. Check them in the order the packet uses them; the first one that fails is where to look.

1. **Address**: \`ip -4 addr\`. Does the interface have the address and prefix you expect? An address starting with 169.254 means the computer asked for an address by DHCP and got no answer (see the [DHCP lesson](#/lesson/dhcp/what)).
2. **Routing decision**: \`ip route get <destination>\`. Which gateway and interface does the kernel choose? For a destination on another network, the output must contain "via" and your gateway's address.
3. **Next hop**: \`ping <gateway>\` and \`ip neigh\`. Does the gateway answer? Is its entry REACHABLE, or FAILED (no ARP reply)?
4. **Beyond the gateway**: \`ping\` and \`traceroute\` to the destination. Does any router answer with an ICMP error? The router that answers tells you how far the packet got.
5. **The way back**: on the destination's console, run \`ip route get <client address>\`. Can it route its reply to you? If a timeout gives you no other clue, capture traffic with \`tcpdump\` on both ends to see where packets stop.

### Read who sent the error
\`ping\` prints where an error came from, and that tells you a lot:
- "From 10.0.10.25 … Destination Host Unreachable" comes from **your own computer**: its ARP request for the next hop got no answer. Look at your gateway and prefix.
- "From 10.0.10.1 … Destination Host Unreachable" comes from **the router**: your packet reached it, but the router could not deliver it further. Look at the router.

`,

  errorMap: [
    { message: 'connect: Network is unreachable', layer: 'Local routing', meaning: 'The kernel found no route at all for the destination. Usually there is no default route, so everything outside the local network is unreachable.', firstCheck: 'ip route; ip route get DEST' },
    { message: 'From <own IP> … Destination Host Unreachable', layer: 'Local ARP', meaning: 'Your own computer asked (with ARP) for the MAC address of the next hop and nobody answered. Typical causes: a wrong gateway address, a wrong prefix, or the local host you are trying to reach is down.', firstCheck: 'ip route get DEST; ip neigh (FAILED entries)' },
    { message: 'From <router IP> … Destination Host Unreachable', layer: 'Router', meaning: 'The packet reached the router, but the router could not deliver it: either ARP failed on the router\'s other side, or forwarding is switched off (ip_forward=0).', firstCheck: 'On the router: ip neigh, sysctl net.ipv4.ip_forward, tcpdump on both interfaces' },
    { message: 'Request timeout / 100% packet loss', layer: 'Path or return path', meaning: 'Packets or their replies disappear without any error message. Typical causes: a firewall dropping them, a destination with no route back to you, or a host that is switched off.', firstCheck: 'tcpdump on the destination; ip route on the destination' },
    { message: 'traceroute stops with * * * after hop N', layer: 'Path', meaning: 'Nothing answers beyond hop N. Either a router there is broken, or the probes are being filtered. Destination firewalls often drop traceroute\'s UDP probes, so a `* * *` at the very last hop is not proof of a problem.', firstCheck: 'traceroute -I or -T -p PORT; capture at the next hop' },
    { message: 'Time to live exceeded', layer: 'Routing loop', meaning: 'Two or more routers keep passing the packet back and forth (a routing loop) until its TTL reaches 0.', firstCheck: 'traceroute (repeating hops); routing tables of the looping routers' },
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
