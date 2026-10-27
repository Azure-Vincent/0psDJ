import type { Lesson } from '../types';

export const DHCP_LESSON: Lesson = {
  id: 'dhcp',
  moduleId: 'A',
  title: 'DHCP: automatic address assignment',
  level: 'beginner',
  summary: 'How a host without an address obtains one: DORA over broadcast, relay agents for other VLANs, pools and reservations, lease timers (renew, rebind, expiry, NAK), and the options (router, DNS, domain) that decide whether the client can actually work.',
  concepts: ['net.dhcp', 'net.arp', 'net.routing', 'dns.resolution'],

  what: `
In the [IP networking lesson](#/lesson/ipnet/what) you saw that every computer needs an address, a prefix, a default gateway and, to use names, a DNS server. Typing these in by hand works for a few servers, but not for hundreds of laptops, phones and printers that come and go. **DHCP** (Dynamic Host Configuration Protocol, RFC 2131) solves this: a computer that has no network settings asks the network for them, and a **DHCP server** answers.

The server hands out:
- an **address**, either from a **pool** (a range of addresses it may give away) or from a **reservation** (a fixed address kept for one particular device, recognised by its MAC address);
- **options**: the subnet mask, the default **router** (gateway), the **DNS servers**, the domain name;
- a **lease time**: how long the client may keep the address before it has to ask again (**renew**).

Think of it as a hotel reception: you arrive with nothing, ask at the desk, and get a room number (the address), directions to the lift (the gateway) and the phone number of the concierge (DNS), for a fixed number of nights (the lease).

### Why it matters
Nearly every laptop, phone, printer and virtual machine uses DHCP. When it fails, the symptoms rarely mention DHCP. The client ends up with **no address**, with a **169.254.x.x** address (a "link-local" address that Windows and some Linux systems give themselves when nobody answers), or with an address but a **wrong gateway or DNS server**. That last case looks exactly like a routing or DNS problem, which is why it helps to know what DHCP hands out.

### Where it runs
- **Client**: dhclient (ISC, used by Debian's ifupdown), systemd-networkd or NetworkManager on Linux; the DHCP Client service on Windows.
- **Server**: ISC dhcpd (the package \`isc-dhcp-server\`, used in this lab), its successor **Kea**, dnsmasq, the Windows Server DHCP role, and most routers and firewalls.
- DHCP travels over **UDP** (see [Transport and DNS](#/lesson/transport/what)): the server listens on port **67**, the client on port **68**.

### In the lab
ns1 (10.0.10.53) runs isc-dhcp-server for the office network 10.0.10.0/24. It hands out 10.0.10.100–150, with router 10.0.10.1 and DNS server 10.0.10.53. The laptop **ws02** is configured with \`iface eth0 inet dhcp\` and gets its address at boot.

The development network, VLAN 30, has no DHCP server of its own. Instead, **rtr01** runs a **DHCP relay agent** (isc-dhcp-relay), which passes requests from VLAN 30 on to ns1. That is how the hot-desk laptop **dev02** gets an address in 10.0.30.100–150 with router 10.0.30.1. Leases in the lab last only 600 seconds, so you can watch renewals happen (\`sleep 300\` lets simulated time pass).

> What the simulator models: DISCOVER, OFFER, REQUEST, ACK and NAK with real BOOTP encoding (exportable as PCAP); the relay agent (giaddr, hops, forwarding to the server and back, \`-id\`/\`-iu\`); lease timers (renewal by unicast at T1, rebinding by broadcast at T2, expiry, retries every 5 minutes); INIT-REBOOT with a remembered lease; DHCPRELEASE; packet sockets that bypass host firewalls; dhcpd.conf parsing (subnets, ranges, router/DNS/domain options, host reservations, lease times, authoritative); the dhcpd.leases file; and dhclient applying the lease (address with lifetime, default route, resolv.conf). Not modelled: DECLINE/INFORM, the broadcast flag, relay agent information (option 82), failover. DHCPv6 is taught and simulated in the [IPv6 lesson](#/lesson/ipv6/what).
`,

  internals: `
### DORA: the four messages
A client without an address cannot send normal packets to a server it does not know yet. So the first messages are **broadcasts**: sent to every device on the local network. The exchange has four steps, remembered as **DORA**:

1. **DISCOVER** (client to everyone). "Is there a DHCP server out there?" The client has no address yet, so it sends from **0.0.0.0** port 68 to the broadcast address **255.255.255.255** port 67, inside an Ethernet frame addressed to **ff:ff:ff:ff:ff:ff**. The message carries a random transaction ID (*xid*) to match the replies, the client's MAC address (*chaddr*), and a **parameter request list** (option 55) saying which settings it wants.
2. **OFFER** (server to client). "You can have 10.0.10.100." The server picks an address and offers it in the *yiaddr* field ("your IP address"), together with the options. ISC dhcpd sends the OFFER straight to the client's MAC address.
3. **REQUEST** (client to everyone). "I'll take 10.0.10.100 from server 10.0.10.53." The client accepts **one** offer, naming the server (option 54, *server identifier*) and the address (option 50). It broadcasts this so that any other server that made an offer knows it was turned down.
4. **ACK** (server to client). "Confirmed." The server records the lease. Only now does the client configure the address. If the server cannot give that address after all, it answers **NAK** ("no") instead, and the client starts again from DISCOVER.

### Broadcasts do not cross routers: DHCP relay agents
Routers do not forward broadcasts to 255.255.255.255; otherwise a single broadcast would flood every network. So either the DHCP server needs an interface in every client network, or the router in each client network runs a **DHCP relay agent**. On Cisco this is \`ip helper-address\`; on Linux it is \`isc-dhcp-relay\` (the program dhcrelay); pfSense and Windows RRAS call it "DHCP Relay".

Here is what happens for dev02 on VLAN 30:
1. dev02 broadcasts its DISCOVER on VLAN 30. rtr01's relay receives it on the interface **eth3.30**.
2. The relay writes its own address on the client's network into the **giaddr** field ("gateway IP address", here 10.0.30.1), adds one to the *hops* counter, and forwards the message as an ordinary **unicast UDP packet, from port 67 to port 67**, to each server it knows (10.0.10.53).
3. ns1 looks at giaddr to see which network the client is on. It picks the subnet that **contains giaddr** (10.0.30.0/24), takes an address from that pool, and sends the OFFER **back to giaddr** (10.0.30.1 port 67), not to the client.
4. The relay passes the OFFER onto VLAN 30, addressed to dev02's MAC. REQUEST and ACK travel the same way.

What this means when you troubleshoot:
- The server needs a **subnet declaration for every network it serves through a relay**, even though it has no interface there. Without one, it logs \`DHCPDISCOVER from … via 10.0.30.1: unknown network segment\` and does not answer.
- The relay must point at the right server (\`SERVERS\` in /etc/default/isc-dhcp-relay) and must be able to receive the replies on the server side. ISC dhcrelay 4.4 takes \`-id\` for the **downstream** interfaces (towards the clients) and \`-iu\` for the **upstream** interface (towards the server). A plain list of interfaces makes it relay in both directions, including broadcasts from the server's own network. The upstream side matters for the **replies**: with \`-iu eth0\`, dhcrelay reads them on eth0 with a packet socket, before the host firewall. Without \`-iu\`, the replies only reach its fallback UDP socket on port 67, which the host firewall filters like any other port: if rtr01's input chain does not allow UDP 67, the OFFER arrives at the router and goes no further.
- Once a client has an address, **renewals do not go through the relay**: the client sends them straight to the server (by unicast), routed like any other packet.

### DHCP software and host firewalls
ISC dhcpd, dhclient and dhcrelay send and receive DHCP through **packet sockets** (called LPF, Linux Packet Filter). A packet socket gets its copy of each frame **before** the kernel's firewall (netfilter) sees it, so a host firewall with \`policy drop\` does not stop DHCP to these programs. This explains the common puzzle "the firewall blocks port 67, but DHCP still works".

There is one exception that matters for relays: a reply that arrives on an interface dhcrelay is not listening on goes to its ordinary UDP socket instead, and there the firewall's input chain does apply.

### How the server chooses an address (ISC dhcpd)
dhcpd tries these in order:
1. A **host** declaration whose \`hardware ethernet\` matches the client's MAC and which has a \`fixed-address\`. This is a **reservation**.
2. The address this MAC address had before, if it is still in the **lease file** (\`/var/lib/dhcp/dhcpd.leases\`). This is why clients tend to keep the same address.
3. The first free address in the **range** of the subnet the request came from.
4. If nothing is free, the server logs **"no free leases"** and does **not answer at all**.

Which subnet a request "came from" is decided by the **interface it arrived on**, or by *giaddr* for relayed requests. That is why dhcpd refuses to start if no \`subnet\` declaration matches an interface it listens on, and why \`INTERFACESv4\` in \`/etc/default/isc-dhcp-server\` matters: if it names an interface that does not exist, dhcpd reports "Not configured to listen on any interfaces!".

### Leases and their timers (RFC 2131 §4.4.5)
A lease is valid for the lease time (option 51). The server also sends two timers: **T1** (option 58) and **T2** (option 59). With the lab's 600-second leases:

| Time after the ACK | Client state | What it does |
|---|---|---|
| 0 s | BOUND | uses the address (\`ip addr\` shows \`dynamic\` and \`valid_lft 600sec\`, counting down) |
| T1 = 50 % = 300 s | RENEWING | sends a DHCPREQUEST **directly to the server that gave the lease** (unicast, with its current address in *ciaddr*), and keeps resending until T2. An ACK restarts the lease. |
| T2 = 87.5 % = 525 s | REBINDING | that server has not answered, so the client **broadcasts** its DHCPREQUEST, so that any server (or relay) for this network can extend the lease |
| 100 % = 600 s | INIT | the lease has expired: the address and default route are **removed**, and dhclient starts again with DISCOVER, retrying every 5 minutes while nobody answers |

So when a DHCP server dies, **nothing happens at first**. Clients keep working until their own lease runs out, then lose their addresses one by one, at different times. That delay can make the cause hard to spot. Long leases (8–24 hours in offices) ride out short outages; short leases (guest Wi-Fi) recycle addresses quickly. dhcpd adds every change to the end of its lease file; for each address, the last entry wins.

### INIT-REBOOT and NAK
A client that remembers a lease (in \`/var/lib/dhcp/dhclient.eth0.leases\`) skips DISCOVER and broadcasts a REQUEST for **its old address** straight away. If that address belongs to the network the client is now on, the server ACKs it. That is why \`sudo dhclient -v eth0\` often shows only REQUEST and ACK.

If the laptop has moved to another network, or the address now belongs to someone else, an **authoritative** server answers **DHCPNAK**. The client throws away the old lease and starts over with DISCOVER. A server that is not authoritative stays silent, and the client waits a while before falling back to DISCOVER.

### What the client does with the answer (dhclient-script on Debian)
When the ACK arrives, a script applies the settings:
- \`ip addr add <yiaddr>/<mask> dev eth0\` (the address)
- \`ip route add default via <option routers>\` (the default gateway)
- writes \`/etc/resolv.conf\` from \`domain-name-servers\` and \`domain-name\` (DNS)
- saves the lease to \`/var/lib/dhcp/dhclient.eth0.leases\`

So a typo in \`option routers\` gives clients an address but no working gateway, and a wrong \`domain-name-servers\` breaks DNS, on **every** DHCP client at once.

### Ports and security
Servers and relays use UDP 67, clients UDP 68. Document these ports in your firewall policy, and open them for DHCP servers that use ordinary UDP sockets (such as Kea with \`"dhcp-socket-type": "udp"\`), but remember that ISC's programs bypass the input chain as described above.

DHCP has **no authentication**: any device on the network can answer a DISCOVER. A **rogue DHCP server** (a home router plugged into the office network by mistake, or an attacker) can hand out its own gateway and DNS server and so redirect traffic. Managed switches protect against this with **DHCP snooping**: only trusted ports are allowed to send OFFER and ACK messages. In an Active Directory domain, Windows DHCP servers must also be **authorised** in AD, and an unauthorised Windows DHCP server refuses to hand out addresses. That only stops Windows servers: a home router or a Linux box does not check AD, so snooping is still needed.
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
ISC dhcpd reads \`/etc/dhcp/dhcpd.conf\` when it starts, so every change needs a restart (check the syntax first). Options can be written at the top of the file (global), inside a \`subnet\` block or inside a \`host\` block; the most specific one wins. For example, a \`option routers\` line inside a subnet block overrides a global one for clients in that subnet.

The allocation simulator below runs the simulator's own parser and address-allocation logic on whatever configuration you type, so you can try out changes safely.
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
### Work from the client towards the server
Start with what the client actually got, because that tells you which half of the exchange failed.

1. **What did the client get?** Run \`ip -4 addr\`, \`ip route\` and \`cat /etc/resolv.conf\`, and look at the saved lease with \`cat /var/lib/dhcp/dhclient.eth0.leases\`. No address at all means the DORA exchange failed. An address with a wrong gateway or DNS server means DHCP worked, but the server's **options** are wrong.
2. **Ask again and watch.** Run \`sudo dhclient -r eth0\` (release the lease) and then \`sudo dhclient -v eth0\` (request a new one, verbosely). If you only see DISCOVER lines repeating, no server is offering anything.
3. **Is the server running and listening?** On the server, \`systemctl status isc-dhcp-server\` should show a line like "Listening on LPF/eth0/…", which proves the interface and subnet match. \`ss -ulnp | grep :67\` shows the socket.
4. **Did the request reach the server?** Read \`journalctl -u isc-dhcp-server\` on the server. No DISCOVER line from the client: the request never got there (wrong interface, a different network without a relay, or a relay sending to the wrong server). A DISCOVER line but no OFFER: look for "no free leases" (the pool is full) or "unknown network segment" (no subnet declaration for that relay's giaddr).
5. **Is the client behind a relay?** On the router, check \`systemctl status isc-dhcp-relay\` and \`cat /etc/default/isc-dhcp-relay\`, then run \`tcpdump\` on the client side **and** on the server side of the router. Requests leave but no replies come back: look at the server or the routing between them. Replies come back but nothing goes out on the client side: the relay is not receiving them (\`-iu\` missing, or a firewall in front of its fallback socket).
6. **Look at the wire.** \`tcpdump -n -i eth0 port 67 or port 68\` on the server shows exactly which messages arrive and leave.

### Clients that lose their address later
If a client had an address and later lost it, the problem is with **renewal**, not with the first request. Read the client's history with \`journalctl -t dhclient\` (as root). A typical pattern: REQUESTs "to 10.0.10.53" with no ACK (that is T1), then REQUESTs "to 255.255.255.255" (T2), then DISCOVERs. That means the server stopped answering at least one lease time ago. \`ip -4 addr\` shows how long the current address is still valid (\`valid_lft\`).
`,

  errorMap: [
    { message: 'No DHCPOFFERS received.', layer: 'DHCP (client)', meaning: 'The client broadcast DISCOVER messages and no DHCP server answered.', firstCheck: 'Server status and logs; is the server on this segment (or is there a relay)?' },
    { message: 'Not configured to listen on any interfaces!', layer: 'DHCP (server)', meaning: 'INTERFACESv4 is empty, or names interfaces that do not exist or have no matching subnet declaration.', firstCheck: 'ip -br link; cat /etc/default/isc-dhcp-server' },
    { message: 'No subnet declaration for eth0 (10.0.10.53).', layer: 'DHCP (server)', meaning: 'The listening interface\'s network is not declared in dhcpd.conf.', firstCheck: 'Compare ip addr on the server with the subnet lines' },
    { message: 'DHCPDISCOVER from … via eth0: network 10.0.10.0/24: no free leases', layer: 'DHCP (server)', meaning: 'Every address in the range is already leased to someone, so the server stays silent.', firstCheck: 'dhcpd.leases: which MACs hold the pool? Enlarge the range or shorten leases' },
    { message: 'DHCPDISCOVER from 52:54:00:e7:00:2a via 10.0.30.1: unknown network segment', layer: 'DHCP (server, relayed)', meaning: 'The request came through a relay, and no subnet declaration in dhcpd.conf contains the relay\'s address (giaddr).', firstCheck: 'Add a subnet for the relayed network to dhcpd.conf' },
    { message: 'DHCPNAK on 10.0.10.100 to … / DHCPNAK from 10.0.10.53', layer: 'DHCP (INIT-REBOOT)', meaning: 'The client asked for an address that is wrong for this network (moved laptop) or no longer its own; it starts over with DISCOVER.', firstCheck: 'Normal after moving; repeated NAKs for the same client: duplicate servers or a mismatched pool' },
    { message: 'DHCPREQUEST for 10.0.10.100 on eth0 to 10.0.10.53 port 67 (repeated, no DHCPACK)', layer: 'DHCP (renewal)', meaning: 'The client is renewing at T1 and the server does not answer.', firstCheck: 'Is the server running and reachable by unicast from the client?' },
    { message: 'Only clients on one VLAN get no address', layer: 'DHCP relay', meaning: 'Relay missing, stopped, pointed at the wrong server, or not receiving replies.', firstCheck: 'systemctl status isc-dhcp-relay; tcpdump both sides of the router' },
    { message: 'Client has 169.254.x.x (APIPA)', layer: 'DHCP (client)', meaning: 'The address a client gives itself when no DHCP server answered (APIPA on Windows, zeroconf on Linux).', firstCheck: 'Treat as "No DHCPOFFERS received"' },
    { message: 'Address OK, cannot leave the subnet', layer: 'DHCP options', meaning: 'DHCP worked, but the server handed out a wrong (or no) default gateway in option routers.', firstCheck: 'ip route on the client; option routers in dhcpd.conf' },
    { message: 'Address OK, names do not resolve', layer: 'DHCP options', meaning: 'DHCP worked, but the server handed out wrong DNS servers in domain-name-servers.', firstCheck: 'cat /etc/resolv.conf on the client' },
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
