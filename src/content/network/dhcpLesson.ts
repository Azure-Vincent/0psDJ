import type { Lesson } from '../types';

export const DHCP_LESSON: Lesson = {
  id: 'dhcp',
  moduleId: 'A',
  title: 'DHCP: automatic address assignment',
  level: 'beginner',
  summary: 'How a host without an address obtains one: DORA over broadcast, relay agents for other VLANs, pools and reservations, lease timers (renew, rebind, expiry, NAK), and the options (router, DNS, domain) that decide whether the client can actually work.',
  concepts: ['net.dhcp', 'net.arp', 'net.routing', 'dns.resolution'],

  what: `
**DHCP** (Dynamic Host Configuration Protocol, RFC 2131) lets a host that has no IP configuration ask the network for one. A **DHCP server** answers with an address from a **pool** (or a **reservation** for that client's MAC address) plus **options**: subnet mask, default **router**, **DNS servers**, domain name, and a **lease time** after which the client must renew.

### Why it matters
Every laptop, phone, printer and most VMs use DHCP. When it fails, the symptoms rarely say "DHCP": the client ends up with **no address**, a **169.254.x.x** link-local address (Windows, some Linux setups), or an address with a **wrong gateway or DNS server**, which looks like a routing or DNS problem.

### Where it runs
- **Client**: dhclient (ISC, Debian ifupdown), systemd-networkd, NetworkManager; on Windows the DHCP Client service.
- **Server**: ISC dhcpd (\`isc-dhcp-server\`, used in the lab), its successor **Kea**, dnsmasq, Windows Server DHCP, and most routers/firewalls.
- DHCP uses **UDP**: the server listens on port **67**, the client on **68**.

### In the lab
ns1 (10.0.10.53) runs isc-dhcp-server for the office LAN 10.0.10.0/24, handing out 10.0.10.100–150 with router 10.0.10.1 and DNS 10.0.10.53. The laptop **ws02** is configured with \`iface eth0 inet dhcp\` and gets its address at boot. The development VLAN 30 has no DHCP server of its own: **rtr01** runs the **DHCP relay agent** isc-dhcp-relay, which forwards requests from VLAN 30 to ns1, so the hot-desk laptop **dev02** gets 10.0.30.100–150 with router 10.0.30.1. Leases last 600 seconds, so you can watch renewals happen (\`sleep 300\` lets simulated time pass).

> The simulator implements DISCOVER/OFFER/REQUEST/ACK and NAK with real BOOTP encoding (exportable to PCAP), the relay agent (giaddr, hops, forwarding to the server and back, \`-id\`/\`-iu\`), lease timers (renewal by unicast at T1, rebinding by broadcast at T2, expiry, retry every 5 minutes), INIT-REBOOT with a remembered lease, DHCPRELEASE, packet-socket reception that bypasses host firewalls, dhcpd.conf parsing (subnets, ranges, routers/DNS/domain options, host reservations, lease times, authoritative), the dhcpd.leases file, and dhclient applying the lease (address with lifetime, default route, resolv.conf). Not modelled: DECLINE/INFORM, the broadcast flag, relay agent information (option 82), failover, DHCPv6.
`,

  internals: `
### DORA: four messages
1. **DISCOVER** (client → broadcast). The client has no address, so it sends from **0.0.0.0:68** to **255.255.255.255:67** in an Ethernet frame to **ff:ff:ff:ff:ff:ff**. The message carries a transaction ID (xid), the client's MAC (*chaddr*), and a **parameter request list** (option 55).
2. **OFFER** (server → client). The server picks an address and offers it in *yiaddr* together with the options. ISC dhcpd sends it unicast to the client MAC (the client asked without the broadcast flag).
3. **REQUEST** (client → broadcast). The client accepts **one** offer, naming the server in option 54 (*server identifier*) and the address in option 50. It is broadcast so that other servers that made offers learn they were declined.
4. **ACK** (server → client). The server records the lease and confirms. Only now does the client configure the address. A server that cannot honour the request answers **NAK** instead and the client starts over.

### Broadcasts stay on the segment: DHCP relay agents
A router does not forward 255.255.255.255. A DHCP server must therefore have an interface on each client subnet, **or** the router must run a **DHCP relay agent** (\`ip helper-address\` on Cisco, \`isc-dhcp-relay\`/\`dhcrelay\` on Linux, "DHCP Relay" on pfSense and Windows RRAS). For dev02 on VLAN 30:
1. dev02 broadcasts DISCOVER on VLAN 30. rtr01's relay receives it on **eth3.30**.
2. The relay sets **giaddr = 10.0.30.1** (its own address on the client's network), increments *hops*, and sends the message as an ordinary **unicast UDP packet, port 67 → 67**, to each configured server (10.0.10.53).
3. ns1 picks the subnet that **contains giaddr** (10.0.30.0/24), allocates an address from that pool and sends the OFFER **to giaddr** (10.0.30.1:67), not to the client.
4. The relay forwards the OFFER onto VLAN 30, addressed to dev02's MAC. REQUEST and ACK take the same path.

Consequences you can troubleshoot:
- The server needs a **subnet declaration for every relayed network**, even though it has no interface there. Without it: \`DHCPDISCOVER from … via 10.0.30.1: unknown network segment\`.
- The relay must know the right server (\`SERVERS\` in /etc/default/isc-dhcp-relay) and must receive the replies on the server side. ISC dhcrelay 4.4 takes \`-id\` (downstream, client side) and \`-iu\` (upstream, server side) interfaces; a plain interface list makes it relay in both directions, including broadcasts from the server's own LAN.
- Once a client has an address, **renewals do not use the relay**: they are unicast from the client straight to the server identifier, routed like any other packet.

### DHCP software and host firewalls
ISC dhcpd, dhclient and dhcrelay send and receive DHCP through **packet sockets (LPF)** on the interfaces they listen on. A packet socket gets its copy of each frame **before netfilter**, so a host firewall with \`policy drop\` does not stop DHCP to these daemons: a common source of "but the firewall blocks port 67 and it still works". The exception matters for relays: a reply that arrives on an interface dhcrelay does not listen on goes to its ordinary UDP socket, where the input chain applies.

### How the server picks an address (ISC dhcpd)
1. A **host** declaration with a matching \`hardware ethernet\` and \`fixed-address\` (a **reservation**).
2. The address this MAC had before, if it is still in the **lease file** (\`/var/lib/dhcp/dhcpd.leases\`): clients tend to keep their address.
3. The first free address in the **range** of the subnet the request arrived on.
4. Nothing free → the server logs **"no free leases"** and does not answer at all.

The subnet is chosen by the **interface the request arrived on** (or *giaddr* for relayed requests). That is why dhcpd refuses to start if no \`subnet\` declaration matches an interface it listens on, and why \`INTERFACESv4\` in \`/etc/default/isc-dhcp-server\` matters: an interface name that does not exist means dhcpd is "Not configured to listen on any interfaces!".

### Leases and their timers (RFC 2131 §4.4.5)
A lease is valid for the lease time (option 51); the server also sends T1 (option 58) and T2 (option 59). With the lab's 600-second leases:

| Time after the ACK | Client state | What it does |
|---|---|---|
| 0 s | BOUND | uses the address (\`ip addr\` shows \`dynamic\`, \`valid_lft 600sec\` counting down) |
| T1 = 50 % = 300 s | RENEWING | DHCPREQUEST **unicast to the server that granted the lease** (ciaddr = its address), retransmitted until T2. An ACK restarts the clock. |
| T2 = 87.5 % = 525 s | REBINDING | the server did not answer: DHCPREQUEST **broadcast**, retransmitted until expiry, so any server (or relay) for this network may extend the lease |
| 100 % = 600 s | INIT | the lease expired: the address and default route are **removed**; dhclient starts over with DISCOVER and retries every 5 minutes while nobody answers |

So when a DHCP server dies, **nothing happens at first**: clients keep working until their own lease runs out, then drop off one by one at different times. Long leases (8–24 h in offices) ride out short outages; short ones recycle addresses quickly (guest Wi-Fi). dhcpd appends every change to the lease file; the last entry for an address wins.

### INIT-REBOOT and NAK
A client that remembers a lease (\`/var/lib/dhcp/dhclient.eth0.leases\`) starts by broadcasting a REQUEST for **its old address**, without DISCOVER. If that address belongs to the network the client is now on, the server ACKs (that is why \`sudo dhclient -v eth0\` usually shows only REQUEST and ACK). If the laptop moved to another network, or the address was given to someone else, an **authoritative** server answers **DHCPNAK**; the client discards the old lease and starts with DISCOVER. A non-authoritative server stays silent and the client waits before falling back.

### What the client does with the options (dhclient-script on Debian)
- \`ip addr add <yiaddr>/<mask> dev eth0\`
- \`ip route add default via <option routers>\`
- write \`/etc/resolv.conf\` from \`domain-name-servers\` and \`domain-name\`
- save the lease to \`/var/lib/dhcp/dhclient.eth0.leases\`

So a typo in \`option routers\` produces a client with an address but no working gateway, and a wrong \`domain-name-servers\` produces DNS failures, on **every** DHCP client at once.

### Ports and security
Servers and relays use UDP 67, clients UDP 68. Document the ports in your firewall policy (and open them for DHCP servers that use ordinary UDP sockets, such as Kea with \`"dhcp-socket-type": "udp"\`), but remember that ISC's daemons bypass the input chain as described above. DHCP has **no authentication**: any host can answer DISCOVERs. A **rogue DHCP server** (a misconfigured home router plugged into the office, or an attacker) hands out its own gateway/DNS. Switches mitigate this with **DHCP snooping** (only trusted ports may send OFFER/ACK).
`,

  deployment: [
    {
      id: 'isc-dhcpd',
      platform: 'Linux: ISC DHCP server (Debian 12)',
      summary: 'Install isc-dhcp-server, serve one subnet with a reservation, and verify a client lease. ISC DHCP is end-of-life upstream (Kea is the successor) but still shipped by Debian 12 and very common. Steps marked "simulated" work on ns1/ws02 in the sandbox.',
      prerequisites: ['A Debian 12 VM with a static address on the client LAN.', 'No other DHCP server on that LAN (disable the hypervisor\'s / home router\'s DHCP for the lab network).', 'A second VM as the client.'],
      steps: [
        { title: 'Install the server', command: 'sudo apt install isc-dhcp-server', what: 'Installs dhcpd, its systemd unit (isc-dhcp-server.service) and default files.', why: 'The service will fail to start until it is configured; that is expected right after installation.', expected: 'Setting up isc-dhcp-server (4.4.3-P1-2) ...\nJob for isc-dhcp-server.service failed because the control process exited with error code.' },
        { title: 'Choose the interface', command: 'sudoedit /etc/default/isc-dhcp-server\n\nINTERFACESv4="eth0"\nINTERFACESv6=""', what: 'Lists the interfaces dhcpd listens on.', why: 'An empty or wrong name (e.g. ens18 on a host whose NIC is eth0) means dhcpd serves nothing. Check names with "ip -br link".', expected: '', simulated: true },
        { title: 'Write dhcpd.conf', command: 'sudoedit /etc/dhcp/dhcpd.conf\n\noption domain-name "corp.lab";\noption domain-name-servers 10.0.10.53;\ndefault-lease-time 600;\nmax-lease-time 7200;\nauthoritative;\n\nsubnet 10.0.10.0 netmask 255.255.255.0 {\n    range 10.0.10.100 10.0.10.150;\n    option routers 10.0.10.1;\n}\n\nhost printer01 {\n    hardware ethernet 52:54:00:e5:00:21;\n    fixed-address 10.0.10.21;\n}', what: 'Global options, one subnet with a pool and a gateway, and one reservation outside the pool.', why: 'The subnet must match the address of the listening interface. Keep reservations outside the dynamic range so they can never be handed to someone else.', expected: '', simulated: true },
        { title: 'Check the syntax', command: 'sudo dhcpd -t -cf /etc/dhcp/dhcpd.conf', what: 'Parses the configuration without starting the server.', why: 'Errors are reported with file and line; a failed restart would otherwise only say "exited with error code".', expected: 'Internet Systems Consortium DHCP Server 4.4.3-P1\nCopyright 2004-2022 Internet Systems Consortium.\nAll rights reserved.', simulated: true },
        { title: 'Document the firewall rule', command: 'sudo nft add rule inet filter input udp dport 67 accept\n# and make it persistent in /etc/nftables.conf', what: 'Allows DHCP requests (UDP 67) into the server.', why: 'ISC dhcpd reads DHCP with a packet socket and is not stopped by the input chain, so this rule is not what makes it work; it documents the service in the policy and is required for DHCP servers that use ordinary UDP sockets (e.g. Kea configured with "dhcp-socket-type": "udp").', expected: '' },
        { title: 'Start and verify', command: 'sudo systemctl restart isc-dhcp-server\nsystemctl status isc-dhcp-server\nsudo ss -ulnp | grep :67', what: 'Starts dhcpd and confirms it listens on UDP 67.', why: 'status shows the "Listening on LPF/eth0/…/10.0.10.0/24" line: proof that interface and subnet match.', expected: 'Active: active (running)\nListening on LPF/eth0/52:54:00:b2:00:35/10.0.10.0/24\nUNCONN 0 0 0.0.0.0:67 0.0.0.0:* users:(("dhcpd",pid=414,fd=6))', simulated: true },
        { title: 'Get a lease on the client', command: 'sudo dhclient -r eth0\nsudo dhclient -v eth0\nip -4 addr show eth0; ip route; cat /etc/resolv.conf', what: 'Releases and re-acquires a lease verbosely, then shows the applied settings.', why: 'The verbose output shows each DORA step and which server answered.', expected: 'DHCPDISCOVER on eth0 to 255.255.255.255 port 67 interval 3\nDHCPOFFER of 10.0.10.100 from 10.0.10.53\nDHCPREQUEST for 10.0.10.100 on eth0 to 255.255.255.255 port 67\nDHCPACK of 10.0.10.100 from 10.0.10.53\nbound to 10.0.10.100 -- renewal in 300 seconds.', simulated: true },
        { title: 'Inspect leases on the server', command: 'cat /var/lib/dhcp/dhcpd.leases\njournalctl -u isc-dhcp-server -n 20', what: 'The lease database and the DORA log lines.', why: 'This is how you answer "which machine had 10.0.10.104 yesterday?" and see "no free leases".', expected: 'lease 10.0.10.100 {\n  binding state active;\n  hardware ethernet 52:54:00:d4:00:42;\n  client-hostname "ws02";\n}', simulated: true },
      ],
    },
    {
      id: 'dhcp-relay',
      platform: 'DHCP relay: Linux isc-dhcp-relay and Cisco ip helper-address',
      summary: 'Serve a VLAN without a DHCP server of its own. Steps marked "simulated" work on rtr01, ns1 and dev02 in the sandbox.',
      prerequisites: ['A router with an address on the client VLAN (rtr01 eth3.30, 10.0.30.1).', 'A reachable DHCP server (ns1, 10.0.10.53) and a route back from it to the client network.'],
      steps: [
        { title: 'Declare the relayed network on the server', command: 'sudoedit /etc/dhcp/dhcpd.conf   # on ns1\n\nsubnet 10.0.30.0 netmask 255.255.255.0 {\n    range 10.0.30.100 10.0.30.150;\n    option routers 10.0.30.1;\n}\n\nsudo dhcpd -t && sudo systemctl restart isc-dhcp-server', what: 'Tells dhcpd which pool and options belong to requests whose giaddr is in 10.0.30.0/24.', why: 'dhcpd has no interface in that network; without the declaration it logs "unknown network segment" and stays silent. The router option must be the relay\'s own address on the client VLAN.', expected: '', simulated: true },
        { title: 'Install and configure the relay (Debian)', command: 'sudo apt install isc-dhcp-relay\nsudoedit /etc/default/isc-dhcp-relay\n\nSERVERS="10.0.10.53"\nINTERFACES=""\nOPTIONS="-id eth3.30 -iu eth0"', what: 'SERVERS: where to forward. -id: interfaces with clients (downstream). -iu: interface towards the server (upstream), where its replies arrive.', why: 'Without -iu the replies reach dhcrelay only through its fallback UDP socket, where the host firewall applies. A plain INTERFACES list also relays broadcasts from the server\'s own LAN.', expected: '', simulated: true },
        { title: 'Start and check the relay', command: 'sudo systemctl restart isc-dhcp-relay\njournalctl -u isc-dhcp-relay -n 12', what: 'Starts dhcrelay and shows which interfaces it opened.', why: '"Listening on LPF/eth3.30/…" and "LPF/eth0/…" confirm both directions.', expected: 'dhcrelay[407]: Listening on LPF/eth3.30/52:54:00:a1:00:04\ndhcrelay[407]: Listening on LPF/eth0/52:54:00:a1:00:01\ndhcrelay[407]: Sending on   Socket/fallback', simulated: true },
        { title: 'Test from a client on the relayed VLAN', command: 'sudo dhclient -v eth0   # on dev02\nip -4 addr show eth0', what: 'A full exchange through the relay.', why: 'The OFFER comes "from 10.0.30.1" (the relay), and the server identifier in the lease is ns1.', expected: 'DHCPOFFER of 10.0.30.100 from 10.0.30.1\nDHCPACK of 10.0.30.100 from 10.0.30.1\nbound to 10.0.30.100 -- renewal in 300 seconds.', simulated: true },
        { title: 'Watch it on the wire', command: 'sudo tcpdump -n -i eth3.30 port 67 or port 68   # client side (on rtr01)\nsudo tcpdump -n -i eth0 port 67   # server side', what: 'Broadcasts on the client VLAN, unicasts between 10.0.10.1 and 10.0.10.53 on the server side.', why: 'This is where you see whether requests leave the relay and whether replies come back.', expected: 'IP 10.0.10.1.67 > 10.0.10.53.67: BOOTP/DHCP, Request from 52:54:00:e7:00:2a, length 300\nIP 10.0.10.53.67 > 10.0.30.1.67: BOOTP/DHCP, Reply, length 300', simulated: true },
        { title: 'Cisco IOS equivalent', command: 'interface Vlan30\n ip address 10.0.30.1 255.255.255.0\n ip helper-address 10.0.10.53\n!\nshow ip interface Vlan30 | include Helper', what: 'Configures the SVI of VLAN 30 as relay to ns1.', why: 'ip helper-address also forwards a few other UDP broadcasts (TFTP, DNS, NetBIOS…) unless restricted with "no ip forward-protocol udp …".', expected: '  Helper address is 10.0.10.53' },
      ],
    },
    {
      id: 'client-debian',
      platform: 'Linux client: ifupdown, NetworkManager, systemd-networkd',
      summary: 'Make an interface use DHCP persistently.',
      prerequisites: ['Debian/Ubuntu client.'],
      steps: [
        { title: 'ifupdown (Debian server default)', command: 'sudoedit /etc/network/interfaces\n\nauto eth0\niface eth0 inet dhcp\n\nsudo systemctl restart networking', what: 'ifup runs dhclient for eth0 at boot.', why: 'This is how ws02 is configured in the lab.', expected: '', simulated: true },
        { title: 'NetworkManager', command: 'nmcli con mod "Wired connection 1" ipv4.method auto\nnmcli con up "Wired connection 1"\nnmcli dev show eth0 | grep IP4', what: 'Sets the profile to DHCP and re-activates it.', why: 'Desktops and RHEL-family servers use NetworkManager.', expected: 'IP4.ADDRESS[1]: 10.0.10.100/24\nIP4.GATEWAY: 10.0.10.1\nIP4.DNS[1]: 10.0.10.53' },
        { title: 'systemd-networkd', command: '# /etc/systemd/network/20-wired.network\n[Match]\nName=eth0\n\n[Network]\nDHCP=ipv4\n\nsudo systemctl restart systemd-networkd\nnetworkctl status eth0', what: 'Declarative DHCP for networkd.', why: 'Common on minimal and container hosts.', expected: 'Address: 10.0.10.100 (DHCP4 via 10.0.10.53)' },
      ],
    },
    {
      id: 'windows',
      platform: 'Windows',
      summary: 'Client-side checks and the Windows Server DHCP role.',
      prerequisites: ['Windows 10/11 client; Windows Server for the role.'],
      steps: [
        { title: 'Client lease', command: 'ipconfig /all\nipconfig /release\nipconfig /renew', what: 'Shows "DHCP Enabled", the lease times and the DHCP server; releases and renews.', why: 'An "Autoconfiguration IPv4 Address 169.254.x.x" means no DHCP server answered.', expected: 'DHCP Enabled. . . . . . . . . . . : Yes\nIPv4 Address. . . . . . . . . . . : 10.0.10.101(Preferred)\nDHCP Server . . . . . . . . . . . : 10.0.10.53' },
        { title: 'Server role (PowerShell)', command: 'Install-WindowsFeature DHCP -IncludeManagementTools\nAdd-DhcpServerInDC -DnsName dc01.corp.lab\nAdd-DhcpServerv4Scope -Name Office -StartRange 10.0.10.100 -EndRange 10.0.10.150 -SubnetMask 255.255.255.0\nSet-DhcpServerv4OptionValue -ScopeId 10.0.10.0 -Router 10.0.10.1 -DnsServer 10.0.10.53 -DnsDomain corp.lab', what: 'Installs and authorises the role, creates a scope and its options.', why: 'In an AD domain, an unauthorised Windows DHCP server will not start: a guard against rogue servers.', expected: '' },
      ],
    },
  ],

  configIntro: `
ISC dhcpd reads \`/etc/dhcp/dhcpd.conf\` at start; options can be global or inside a \`subnet\`/\`host\` block (the most specific wins). The allocation simulator below runs the simulator's own parser and allocation function on whatever configuration you type.
`,

  configFiles: [
    {
      platform: 'Linux (ISC DHCP server)',
      items: [
        { path: '/etc/dhcp/dhcpd.conf', purpose: 'Subnets, ranges, options, reservations, lease times.' },
        { path: '/etc/default/isc-dhcp-server', purpose: 'INTERFACESv4 / INTERFACESv6: where dhcpd listens.' },
        { path: '/var/lib/dhcp/dhcpd.leases', purpose: 'Append-only lease database (the last entry per address wins).' },
        { path: 'journalctl -u isc-dhcp-server', purpose: 'DISCOVER/OFFER/REQUEST/ACK log lines, "no free leases", config errors.' },
      ],
    },
    {
      platform: 'Linux (DHCP relay on the router)',
      items: [
        { path: '/etc/default/isc-dhcp-relay', purpose: 'SERVERS (where to forward), INTERFACES, OPTIONS (-id downstream / -iu upstream interfaces).' },
        { path: 'journalctl -u isc-dhcp-relay', purpose: 'Start-up lines: which interfaces dhcrelay listens on; errors for unknown interfaces or servers.' },
      ],
    },
    {
      platform: 'Linux (client)',
      items: [
        { path: '/etc/network/interfaces', purpose: '"iface eth0 inet dhcp" (ifupdown).' },
        { path: '/var/lib/dhcp/dhclient.eth0.leases', purpose: 'The lease the client holds: address, options, server.' },
        { path: '/etc/dhcp/dhclient.conf', purpose: 'What the client requests, sends (hostname) or overrides (supersede domain-name-servers …).' },
        { path: '/etc/resolv.conf', purpose: 'Written by dhclient-script from the DNS options.' },
      ],
    },
  ],

  directives: [
    { name: 'subnet N netmask M { … }', compiledDefault: '(none)', recommended: 'One per served network', explanation: 'Declares a network dhcpd knows. Requests arriving on an interface (or via a relay) in that network use this block.', security: 'dhcpd refuses to start if an interface it listens on has no matching subnet declaration.' },
    { name: 'range A B', compiledDefault: '(none: no dynamic addresses)', recommended: 'Sized for the expected clients plus margin', explanation: 'The dynamic pool. Without it, only reservations are served.', security: 'A pool much larger than needed lets any device on the LAN get an address; a too small one causes "no free leases".' },
    { name: 'option routers', compiledDefault: '(none)', recommended: 'The subnet\'s gateway', explanation: 'Default gateway installed by the client.', security: 'A wrong value breaks off-subnet access for every client; a rogue server uses it to intercept traffic.' },
    { name: 'option domain-name-servers', compiledDefault: '(none)', recommended: 'Your resolvers, two if possible', explanation: 'Written to the client\'s resolv.conf.', security: 'Clients trust these unconditionally.' },
    { name: 'option domain-name', compiledDefault: '(none)', recommended: 'Your internal domain', explanation: 'Becomes the client\'s search domain.', security: '' },
    { name: 'default-lease-time / max-lease-time', compiledDefault: '43200 / 86400 s', distroDefault: 'Debian sample: 600 / 7200', recommended: 'Hours for offices, minutes for guest Wi-Fi', explanation: 'Lease length when the client does not ask for one / the maximum granted.', security: 'Short leases recycle addresses quickly; long ones ride out server outages and keep logs meaningful.' },
    { name: 'authoritative', compiledDefault: 'off', recommended: 'on for the server that owns the network', explanation: 'Lets dhcpd NAK clients that request an address that is wrong for this network (e.g. after moving from another LAN).', security: 'Leave it off on a server that is not the owner of the segment.' },
    { name: 'host NAME { hardware ethernet MAC; fixed-address IP; }', compiledDefault: '(none)', recommended: 'Printers, servers, network gear: outside the range', explanation: 'A reservation: this MAC always gets this address.', security: 'MACs are trivially spoofed; a reservation is not authentication.' },
    { name: 'SERVERS (/etc/default/isc-dhcp-relay)', compiledDefault: '""', recommended: 'Your DHCP server(s); two for redundancy', explanation: 'The relay forwards every client request to each listed server.', security: 'A wrong address silently breaks DHCP for every relayed VLAN; a foreign server would hand out its own gateway and DNS.' },
    { name: '-id IFACE / -iu IFACE (dhcrelay OPTIONS)', compiledDefault: '— (plain -i / INTERFACES: both directions)', recommended: '-id on each client VLAN, -iu towards the server', explanation: 'Downstream interfaces accept client broadcasts and get giaddr; upstream interfaces receive server replies with a packet socket.', security: 'Do not list the server\'s LAN as downstream: the relay would relay its broadcasts too.' },
    { name: 'option dhcp-renewal-time / dhcp-rebinding-time', compiledDefault: '50 % / 87.5 % of the lease', recommended: 'Leave the defaults', explanation: 'T1 and T2 sent to clients (options 58 and 59).', security: '' },
    { name: 'INTERFACESv4 (/etc/default/isc-dhcp-server)', compiledDefault: '""', recommended: 'Exactly the client-facing interfaces', explanation: 'Interfaces dhcpd listens on.', security: 'Never serve on an uplink or another organisation\'s network.' },
  ],

  troubleshootingIntro: `
### Work from the client to the server
1. **What did the client get?** \`ip -4 addr\`, \`ip route\`, \`cat /etc/resolv.conf\`, \`cat /var/lib/dhcp/dhclient.eth0.leases\`. No address → DORA failed. Address but wrong router/DNS → the server's options.
2. **Try again verbosely:** \`sudo dhclient -r eth0; sudo dhclient -v eth0\`. Only DISCOVERs → nobody offers.
3. **Is the server running and listening?** \`systemctl status isc-dhcp-server\` (look for "Listening on LPF/eth0/…"), \`ss -ulnp | grep :67\`.
4. **Did the request arrive?** \`journalctl -u isc-dhcp-server\` on the server: no DISCOVER line → it never got there (wrong interface, different segment without relay, relay sending elsewhere). DISCOVER but no OFFER → "no free leases" or "unknown network segment" (no subnet for that giaddr).
5. **Relayed network?** On the router: \`systemctl status isc-dhcp-relay\`, \`cat /etc/default/isc-dhcp-relay\`, then \`tcpdump\` on the client side **and** the server side. Requests leave but no replies arrive → server or routing; replies arrive but nothing goes out on the client side → the relay does not receive them (\`-iu\` missing, firewall on its fallback socket).
6. **Capture:** \`tcpdump -n -i eth0 port 67 or port 68\` on the server.

### Clients that lose their address later
A client that worked and then lost its address is a **renewal** problem: read its history with \`journalctl -t dhclient\` (as root). REQUESTs "to 10.0.10.53" without ACK (T1), then "to 255.255.255.255" (T2), then DISCOVERs: the server stopped answering at least one lease time ago. \`ip -4 addr\` shows the remaining lifetime of a DHCP address (\`valid_lft\`).
`,

  errorMap: [
    { message: 'No DHCPOFFERS received.', layer: 'DHCP (client)', meaning: 'Nobody answered the DISCOVERs.', firstCheck: 'Server status and logs; is the server on this segment (or is there a relay)?' },
    { message: 'Not configured to listen on any interfaces!', layer: 'DHCP (server)', meaning: 'INTERFACESv4 is empty or names interfaces that do not exist / have no matching subnet.', firstCheck: 'ip -br link; cat /etc/default/isc-dhcp-server' },
    { message: 'No subnet declaration for eth0 (10.0.10.53).', layer: 'DHCP (server)', meaning: 'The listening interface\'s network is not declared in dhcpd.conf.', firstCheck: 'Compare ip addr on the server with the subnet lines' },
    { message: 'DHCPDISCOVER from … via eth0: network 10.0.10.0/24: no free leases', layer: 'DHCP (server)', meaning: 'Every address in the range is leased.', firstCheck: 'dhcpd.leases: which MACs hold the pool? Enlarge the range or shorten leases' },
    { message: 'DHCPDISCOVER from 52:54:00:e7:00:2a via 10.0.30.1: unknown network segment', layer: 'DHCP (server, relayed)', meaning: 'No subnet declaration contains the relay\'s giaddr.', firstCheck: 'Add a subnet for the relayed network to dhcpd.conf' },
    { message: 'DHCPNAK on 10.0.10.100 to … / DHCPNAK from 10.0.10.53', layer: 'DHCP (INIT-REBOOT)', meaning: 'The client asked for an address that is wrong for this network (moved laptop) or no longer its own; it starts over with DISCOVER.', firstCheck: 'Normal after moving; repeated NAKs for the same client: duplicate servers or a mismatched pool' },
    { message: 'DHCPREQUEST for 10.0.10.100 on eth0 to 10.0.10.53 port 67 (repeated, no DHCPACK)', layer: 'DHCP (renewal)', meaning: 'The client is renewing at T1 and the server does not answer.', firstCheck: 'Is the server running and reachable by unicast from the client?' },
    { message: 'Only clients on one VLAN get no address', layer: 'DHCP relay', meaning: 'Relay missing, stopped, pointed at the wrong server, or not receiving replies.', firstCheck: 'systemctl status isc-dhcp-relay; tcpdump both sides of the router' },
    { message: 'Client has 169.254.x.x (APIPA)', layer: 'DHCP (client)', meaning: 'Windows/zeroconf fallback after DHCP failed.', firstCheck: 'Treat as "No DHCPOFFERS received"' },
    { message: 'Address OK, cannot leave the subnet', layer: 'DHCP options', meaning: 'Wrong or missing option routers.', firstCheck: 'ip route on the client; option routers in dhcpd.conf' },
    { message: 'Address OK, names do not resolve', layer: 'DHCP options', meaning: 'Wrong domain-name-servers.', firstCheck: 'cat /etc/resolv.conf on the client' },
  ],

  scenarioIds: ['dhcp-interface', 'dhcp-pool-exhausted', 'dhcp-wrong-router', 'dhcp-lease-expiry', 'dhcp-relay-server', 'dhcp-relay-subnet', 'dhcp-relay-iu'],
  assessmentId: 'dhcp',
  references: [
    { title: 'RFC 2131: Dynamic Host Configuration Protocol', url: 'https://www.rfc-editor.org/rfc/rfc2131' },
    { title: 'RFC 2132: DHCP Options and BOOTP Vendor Extensions', url: 'https://www.rfc-editor.org/rfc/rfc2132' },
    { title: 'dhcpd.conf(5) and dhcpd.leases(5)', url: 'https://manpages.debian.org/bookworm/isc-dhcp-server/dhcpd.conf.5.en.html' },
    { title: 'dhclient(8) / dhclient-script(8)', url: 'https://manpages.debian.org/bookworm/isc-dhcp-client/dhclient.8.en.html' },
    { title: 'dhcrelay(8)', url: 'https://manpages.debian.org/bookworm/isc-dhcp-relay/dhcrelay.8.en.html' },
    { title: 'RFC 1542: Clarifications and Extensions for BOOTP (relay agents)', url: 'https://www.rfc-editor.org/rfc/rfc1542' },
    { title: 'ISC Kea (successor to ISC DHCP)', url: 'https://www.isc.org/kea/' },
    { title: 'Microsoft: DHCP Server in Windows Server', url: 'https://learn.microsoft.com/windows-server/networking/technologies/dhcp/dhcp-top' },
  ],
};
