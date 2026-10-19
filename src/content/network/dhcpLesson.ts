import type { Lesson } from '../types';

export const DHCP_LESSON: Lesson = {
  id: 'dhcp',
  moduleId: 'A',
  title: 'DHCP: automatic address assignment',
  level: 'beginner',
  summary: 'How a host without an address obtains one: DORA over broadcast, pools and reservations, leases, and the options (router, DNS, domain) that decide whether the client can actually work.',
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
ns1 (10.0.10.53) runs isc-dhcp-server for the office LAN 10.0.10.0/24, handing out 10.0.10.100–150 with router 10.0.10.1 and DNS 10.0.10.53. The laptop **ws02** is configured with \`iface eth0 inet dhcp\` and gets its address at boot.

> The simulator implements DISCOVER/OFFER/REQUEST/ACK with real BOOTP encoding (exportable to PCAP), release (recorded in the lease files and logs, no packet on the wire), broadcast delivery on the segment, both hosts' firewalls, dhcpd.conf parsing (subnets, ranges, routers/DNS/domain options, host reservations, lease times), the dhcpd.leases file, and dhclient applying the lease (address, default route, resolv.conf). It does not model lease renewal timers (T1/T2), DHCPNAK/DECLINE, relays, or failover.
`,

  internals: `
### DORA: four messages
1. **DISCOVER** (client → broadcast). The client has no address, so it sends from **0.0.0.0:68** to **255.255.255.255:67** in an Ethernet frame to **ff:ff:ff:ff:ff:ff**. The message carries a transaction ID (xid), the client's MAC (*chaddr*), and a **parameter request list** (option 55).
2. **OFFER** (server → client). The server picks an address and offers it in *yiaddr* together with the options. ISC dhcpd sends it unicast to the client MAC (the client asked without the broadcast flag).
3. **REQUEST** (client → broadcast). The client accepts **one** offer, naming the server in option 54 (*server identifier*) and the address in option 50. It is broadcast so that other servers that made offers learn they were declined.
4. **ACK** (server → client). The server records the lease and confirms. Only now does the client configure the address. A server that cannot honour the request answers **NAK** instead and the client starts over.

### Broadcasts stay on the segment
A router does not forward 255.255.255.255. A DHCP server must therefore have an interface on each client subnet, **or** routers must run a **DHCP relay** (\`ip helper-address\` on Cisco, \`isc-dhcp-relay\`/\`dhcrelay\` on Linux). The relay unicasts the request to the server and fills in *giaddr*, which tells the server which subnet's pool to use.

### How the server picks an address (ISC dhcpd)
1. A **host** declaration with a matching \`hardware ethernet\` and \`fixed-address\` (a **reservation**).
2. The address this MAC had before, if it is still in the **lease file** (\`/var/lib/dhcp/dhcpd.leases\`): clients tend to keep their address.
3. The first free address in the **range** of the subnet the request arrived on.
4. Nothing free → the server logs **"no free leases"** and does not answer at all.

The subnet is chosen by the **interface the request arrived on** (or *giaddr* for relayed requests). That is why dhcpd refuses to start if no \`subnet\` declaration matches an interface it listens on, and why \`INTERFACESv4\` in \`/etc/default/isc-dhcp-server\` matters: an interface name that does not exist means dhcpd is "Not configured to listen on any interfaces!".

### Leases
A lease is valid for the lease time (option 51). The client renews at **T1 = 50 %** (unicast to its server) and, if that fails, at **T2 = 87.5 %** (broadcast to any server). If the lease expires, the client must stop using the address. dhcpd appends every change to the lease file; the last entry for an address wins. Short leases make pools recycle quickly; long leases survive server outages.

### What the client does with the options (dhclient-script on Debian)
- \`ip addr add <yiaddr>/<mask> dev eth0\`
- \`ip route add default via <option routers>\`
- write \`/etc/resolv.conf\` from \`domain-name-servers\` and \`domain-name\`
- save the lease to \`/var/lib/dhcp/dhclient.eth0.leases\`

So a typo in \`option routers\` produces a client with an address but no working gateway, and a wrong \`domain-name-servers\` produces DNS failures, on **every** DHCP client at once.

### Ports, firewalls, security
Servers listen on UDP 67 and need an input rule for it (DHCP clients cannot complete conntrack-style "established" handshakes before they have an address). DHCP has **no authentication**: any host can answer DISCOVERs. A **rogue DHCP server** (a misconfigured home router plugged into the office, or an attacker) hands out its own gateway/DNS. Switches mitigate this with **DHCP snooping** (only trusted ports may send OFFER/ACK).
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
        { title: 'Open the firewall', command: 'sudo nft add rule inet filter input udp dport 67 accept\n# and make it persistent in /etc/nftables.conf', what: 'Allows DHCP requests (broadcast to UDP 67) into the server.', why: 'With an input policy of drop, DISCOVERs are silently discarded and clients time out.', expected: '' },
        { title: 'Start and verify', command: 'sudo systemctl restart isc-dhcp-server\nsystemctl status isc-dhcp-server\nsudo ss -ulnp | grep :67', what: 'Starts dhcpd and confirms it listens on UDP 67.', why: 'status shows the "Listening on LPF/eth0/…/10.0.10.0/24" line: proof that interface and subnet match.', expected: 'Active: active (running)\nListening on LPF/eth0/52:54:00:b2:00:35/10.0.10.0/24\nUNCONN 0 0 0.0.0.0:67 0.0.0.0:* users:(("dhcpd",pid=414,fd=6))', simulated: true },
        { title: 'Get a lease on the client', command: 'sudo dhclient -r eth0\nsudo dhclient -v eth0\nip -4 addr show eth0; ip route; cat /etc/resolv.conf', what: 'Releases and re-acquires a lease verbosely, then shows the applied settings.', why: 'The verbose output shows each DORA step and which server answered.', expected: 'DHCPDISCOVER on eth0 to 255.255.255.255 port 67 interval 3\nDHCPOFFER of 10.0.10.100 from 10.0.10.53\nDHCPREQUEST for 10.0.10.100 on eth0 to 255.255.255.255 port 67\nDHCPACK of 10.0.10.100 from 10.0.10.53\nbound to 10.0.10.100 -- renewal in 300 seconds.', simulated: true },
        { title: 'Inspect leases on the server', command: 'cat /var/lib/dhcp/dhcpd.leases\njournalctl -u isc-dhcp-server -n 20', what: 'The lease database and the DORA log lines.', why: 'This is how you answer "which machine had 10.0.10.104 yesterday?" and see "no free leases".', expected: 'lease 10.0.10.100 {\n  binding state active;\n  hardware ethernet 52:54:00:d4:00:42;\n  client-hostname "ws02";\n}', simulated: true },
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
    { name: 'INTERFACESv4 (/etc/default/isc-dhcp-server)', compiledDefault: '""', recommended: 'Exactly the client-facing interfaces', explanation: 'Interfaces dhcpd listens on.', security: 'Never serve on an uplink or another organisation\'s network.' },
  ],

  troubleshootingIntro: `
### Work from the client to the server
1. **What did the client get?** \`ip -4 addr\`, \`ip route\`, \`cat /etc/resolv.conf\`, \`cat /var/lib/dhcp/dhclient.eth0.leases\`. No address → DORA failed. Address but wrong router/DNS → the server's options.
2. **Try again verbosely:** \`sudo dhclient -r eth0; sudo dhclient -v eth0\`. Only DISCOVERs → nobody offers.
3. **Is the server running and listening?** \`systemctl status isc-dhcp-server\` (look for "Listening on LPF/eth0/…"), \`ss -ulnp | grep :67\`.
4. **Did the request arrive?** \`journalctl -u isc-dhcp-server\` on the server: no DISCOVER line → it never got there (wrong interface, firewall, different segment without relay). DISCOVER but no OFFER → "no free leases" or no matching subnet.
5. **Capture:** \`tcpdump -n -i eth0 port 67 or port 68\` on the server.
`,

  errorMap: [
    { message: 'No DHCPOFFERS received.', layer: 'DHCP (client)', meaning: 'Nobody answered the DISCOVERs.', firstCheck: 'Server status and logs; is the server on this segment (or is there a relay)?' },
    { message: 'Not configured to listen on any interfaces!', layer: 'DHCP (server)', meaning: 'INTERFACESv4 is empty or names interfaces that do not exist / have no matching subnet.', firstCheck: 'ip -br link; cat /etc/default/isc-dhcp-server' },
    { message: 'No subnet declaration for eth0 (10.0.10.53).', layer: 'DHCP (server)', meaning: 'The listening interface\'s network is not declared in dhcpd.conf.', firstCheck: 'Compare ip addr on the server with the subnet lines' },
    { message: 'DHCPDISCOVER from … via eth0: network 10.0.10.0/24: no free leases', layer: 'DHCP (server)', meaning: 'Every address in the range is leased.', firstCheck: 'dhcpd.leases: which MACs hold the pool? Enlarge the range or shorten leases' },
    { message: 'Client has 169.254.x.x (APIPA)', layer: 'DHCP (client)', meaning: 'Windows/zeroconf fallback after DHCP failed.', firstCheck: 'Treat as "No DHCPOFFERS received"' },
    { message: 'Address OK, cannot leave the subnet', layer: 'DHCP options', meaning: 'Wrong or missing option routers.', firstCheck: 'ip route on the client; option routers in dhcpd.conf' },
    { message: 'Address OK, names do not resolve', layer: 'DHCP options', meaning: 'Wrong domain-name-servers.', firstCheck: 'cat /etc/resolv.conf on the client' },
  ],

  scenarioIds: ['dhcp-interface', 'dhcp-pool-exhausted', 'dhcp-wrong-router'],
  assessmentId: 'dhcp',
  references: [
    { title: 'RFC 2131: Dynamic Host Configuration Protocol', url: 'https://www.rfc-editor.org/rfc/rfc2131' },
    { title: 'RFC 2132: DHCP Options and BOOTP Vendor Extensions', url: 'https://www.rfc-editor.org/rfc/rfc2132' },
    { title: 'dhcpd.conf(5) and dhcpd.leases(5)', url: 'https://manpages.debian.org/bookworm/isc-dhcp-server/dhcpd.conf.5.en.html' },
    { title: 'dhclient(8) / dhclient-script(8)', url: 'https://manpages.debian.org/bookworm/isc-dhcp-client/dhclient.8.en.html' },
    { title: 'ISC Kea (successor to ISC DHCP)', url: 'https://www.isc.org/kea/' },
    { title: 'Microsoft: DHCP Server in Windows Server', url: 'https://learn.microsoft.com/windows-server/networking/technologies/dhcp/dhcp-top' },
  ],
};
