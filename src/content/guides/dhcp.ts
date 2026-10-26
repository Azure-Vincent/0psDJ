// Operate & recover guide: DHCP servers (ISC dhcpd on ns1, Kea, Windows,
// pfSense) and clients (dhclient, NetworkManager, Windows).

import type { ServiceGuide } from '../types';

export const DHCP_GUIDE: ServiceGuide = {
  purpose:
    'DHCP gives clients an address, a prefix, a default gateway, DNS servers and a domain name, for a limited time called a **lease**. When it fails, a client either has **no address at all** (on Linux, no IPv4 address on the interface; on Windows, a 169.254.x.x address), or it gets an address with **wrong options** and fails later in confusing ways (no Internet, no name resolution). In the lab, ns1 runs ISC dhcpd for the office network (ws02) and, through the relay agent on rtr01, for development VLAN 30 (dev02). ISC DHCP reached end of life in 2022 and its successor is ISC **Kea**, but the way you diagnose problems is the same for both.',
  architecture: [
    { q: 'What does it do?', a: 'It configures IPv4 on clients automatically and from one central place. The server manages **pools** of addresses, **reservations** (a fixed address for one MAC address), and **options** (router, DNS servers, domain, NTP server, network boot server).' },
    { q: 'How does it work inside?', a: 'The server keeps a **lease database** (`/var/lib/dhcp/dhcpd.leases`). It is a journal: every change is added to the end, and the last entry for an address wins. For each request, the server picks an address in this order: a reservation for the client\'s MAC, the address the client had before, the address the client asks for (if free), and otherwise the next free address in the pool. Clients **renew** halfway through the lease (T1, 50%) by asking the same server directly, **rebind** at T2 (87.5%) by asking any server, and lose the address when the lease expires.' },
    { q: 'Which protocols does it use?', a: 'DHCP (RFC 2131) and its options (RFC 2132), carried in BOOTP messages over UDP. A client getting a new address goes through **DORA**: Discover, Offer, Request, Ack (or NAK when the server says no). DHCPv6 is a separate protocol with its own programs and rules (client IDs called DUIDs, the multicast address ff02::1:2, no default route, filtered by nftables); it is covered in the [IPv6 lesson](#/lesson/ipv6/internals). In the lab, `dhcpd -6` on rtr01 serves VLAN 30.' },
    { q: 'Which ports does it use?', a: 'UDP port 67 on the server and port 68 on the client. Discover and Request are **broadcasts** to 255.255.255.255, because the client has no address yet. Routers do not forward broadcasts, so a client in another subnet needs a **DHCP relay** on its router (`ip helper-address` on Cisco), which forwards the request to the server as a normal unicast packet.' },
    { q: 'Which processes and system components are involved?', a: 'Servers: `dhcpd` (ISC, package isc-dhcp-server; it is started by an old-style init script that systemd wraps in a generated unit called `isc-dhcp-server.service`), `kea-dhcp4` (Kea), the Windows **DHCP Server** service (managed in dhcpmgmt.msc), and the pfSense DHCP server (ISC or Kea in version 2.7). Clients: `dhclient` (used by ifupdown and in the lab), NetworkManager\'s built-in client, systemd-networkd, and the Windows **DHCP Client** service (Dhcp).' },
    { q: 'What does it depend on?', a: 'The server needs an interface **with an address in every subnet it serves directly**, a `subnet` declaration for every network it serves through a relay, a valid configuration and a lease file it can write. A client needs to be in the same VLAN as the server, or behind a router whose relay points at the server and receives its replies. Renewals also need a normal routed path from client to server. And every option the server hands out points at another dependency: a router must really exist at the `routers` address, and a DNS server at `domain-name-servers`.' },
    { q: 'How do the messages travel?', a: 'The client broadcasts DISCOVER (from 0.0.0.0:68 to 255.255.255.255:67). The server answers with an OFFER (an address and options). The client broadcasts REQUEST naming the server it chose, so any other servers withdraw their offers. The server records the lease and sends ACK. The client configures the address and announces it with a "gratuitous" ARP. Through a relay, the relay picks up the broadcast on the client\'s VLAN, writes its own address there into **giaddr**, and sends the message to the server by unicast (UDP 67 to 67). The server chooses the subnet that contains giaddr and answers to the relay, which delivers the reply to the client\'s MAC address. Renewals skip the relay: they go straight between client and server.' },
    { q: 'Is there any authentication?', a: '**None.** Any device on the network can answer as a DHCP server. A **rogue DHCP server** (for example a home router plugged in the wrong way round) hands out its own gateway and DNS server. The defences are in the network: **DHCP snooping** on switches (only trusted ports may send OFFER and ACK), 802.1X port authentication, and `authoritative;` on the real server so it quickly refuses (NAKs) wrong requests.' },
    { q: 'How does it start at boot?', a: 'On Debian, `isc-dhcp-server.service` reads `INTERFACESv4` from `/etc/default/isc-dhcp-server` and starts dhcpd on those interfaces. It has to start after the interfaces have their addresses. Clients run dhclient when ifupdown brings up an interface configured as `inet dhcp`.' },
    { q: 'What happens if the server stops?', a: 'Clients that already have a lease keep working until it expires; their renewals fail silently first. New clients and clients that reboot get no address. With short leases (the lab uses 600 seconds) an outage shows up within minutes; with 8-day leases, days later. dhcpd reads its lease file again when it starts, so existing leases survive a restart.' },
  ],
  ports: [
    { port: '67', proto: 'UDP', purpose: 'Server (and relay agents)' },
    { port: '68', proto: 'UDP', purpose: 'Client' },
    { port: '547/546', proto: 'UDP', purpose: 'DHCPv6 server/client (dhcpd -6 on rtr01; see the IPv6 lesson)' },
  ],
  processes: [
    { name: 'dhcpd (isc-dhcp-server)', platform: 'Debian/Ubuntu (the lab), RHEL ≤ 8 (dhcp-server)', role: 'Server; config /etc/dhcp/dhcpd.conf; leases /var/lib/dhcp/dhcpd.leases' },
    { name: 'kea-dhcp4', platform: 'Debian 12, RHEL 9, pfSense 2.7+ (optional)', role: 'Successor of ISC DHCP; JSON config /etc/kea/kea-dhcp4.conf' },
    { name: 'dhclient', platform: 'Debian ifupdown', role: 'Client; leases in /var/lib/dhcp/dhclient.<iface>.leases' },
    { name: 'DHCP Server (DHCPServer)', platform: 'Windows Server 2019/2022', role: 'Scopes, reservations, failover; database %windir%\\System32\\dhcp' },
    { name: 'DHCP Client (Dhcp)', platform: 'Windows 10/11, Server', role: 'Client service; ipconfig /renew' },
  ],
  dependencies: {
    title: 'What a DHCP client needs to come up with a working configuration',
    rows: [
      { label: 'Result', nodes: [{ id: 'ok', label: 'Working client', sub: 'address + options', kind: 'client' }] },
      { label: 'Options', nodes: [{ id: 'rtr', label: 'routers option', sub: 'real gateway', kind: 'data' }, { id: 'dns', label: 'DNS option', sub: 'reachable server', kind: 'data' }] },
      { label: 'Server', nodes: [{ id: 'svc', label: 'dhcpd running', sub: 'isc-dhcp-server', kind: 'service' }, { id: 'iface', label: 'INTERFACESv4', sub: 'right NIC', kind: 'data' }, { id: 'pool', label: 'Free address', sub: 'range, leases', kind: 'data' }] },
      { label: 'Path', nodes: [{ id: 'l2', label: 'Same VLAN', sub: 'broadcast reaches dhcpd', kind: 'network' }, { id: 'relay', label: 'or relay agent', sub: 'SERVERS, -id/-iu', kind: 'service' }, { id: 'subnet', label: 'subnet for giaddr', sub: 'on the server', kind: 'data' }] },
    ],
    edges: [['ok', 'rtr'], ['ok', 'dns'], ['rtr', 'svc'], ['dns', 'svc'], ['svc', 'iface'], ['svc', 'pool'], ['svc', 'l2'], ['svc', 'relay'], ['relay', 'subnet']],
  },
  sequence: {
    title: 'DORA: ws02 gets a lease from ns1',
    lanes: [{ id: 'c', label: 'ws02', sub: 'dhclient' }, { id: 's', label: 'ns1', sub: 'dhcpd' }],
    steps: [
      { from: 'c', to: 's', label: 'DISCOVER (broadcast)', note: 'No server on this VLAN / dhcpd not listening on this interface → no OFFER; dhclient retries, then "No DHCPOFFERS received".' },
      { from: 's', to: 'c', label: 'OFFER 10.0.10.100 + options', note: 'Pool empty → server logs "no free leases" and sends nothing.' },
      { from: 'c', to: 's', label: 'REQUEST 10.0.10.100 (broadcast)' },
      { from: 's', to: 'c', label: 'ACK (lease 600 s)', note: 'Wrong options (router, DNS) are applied as given: the failure shows up later.' },
      { from: 'c', to: 'c', label: 'configure address, route, DNS' },
    ],
  },
  files: [
    { path: '/etc/dhcp/dhcpd.conf', platform: 'Debian/Ubuntu (ns1)', kind: 'config', perms: 'root:root 0644', contains: 'Global options (`domain-name`, `domain-name-servers`, lease times, `authoritative`), one `subnet` block per served network with `range` and `option routers`, `host` reservations.', accessed: 'When dhcpd starts (no reload: changes require a restart).', problems: 'A syntax error stops dhcpd from starting. A `subnet` declaration is required for each interface dhcpd listens on ("No subnet declaration for eth0"). Wrong `routers`/`domain-name-servers` are handed out silently.' },
    { path: '/etc/default/isc-dhcp-server', platform: 'Debian/Ubuntu', kind: 'startup', perms: 'root:root 0644', contains: '`INTERFACESv4="eth0"` (and INTERFACESv6).', accessed: 'By the init script at start.', problems: 'A wrong interface name (e.g. `ens18` copied from another VM) → "Not configured to listen on any interfaces!" and the service fails.' },
    { path: '/var/lib/dhcp/dhcpd.leases', platform: 'Debian/Ubuntu', kind: 'data', perms: 'root:root 0644 (dhcpd must write it)', contains: 'Append-only lease records: `lease 10.0.10.100 { starts ...; ends ...; binding state active; hardware ethernet ...; client-hostname "ws02"; }`. The **last** record for an address wins.', accessed: 'Read at start, appended on every grant; periodically rewritten (dhcpd.leases~ is the previous copy).', problems: 'Deleting it while dhcpd runs is pointless (it rewrites it); deleting it while stopped forgets every lease and can cause duplicate addresses. A full disk stops lease writes.' },
    { path: '/var/lib/dhcp/dhclient.eth0.leases', platform: 'Debian client (ws02, dev02)', kind: 'data', contains: 'The leases this client received, with all options (routers, DNS, server identifier, lease time) and the `renew`, `rebind` and `expire` times (weekday number, UTC).', accessed: 'Written by dhclient; read at start to request the previous address (INIT-REBOOT).', problems: 'The evidence for "what did the server actually hand out?" and "when will it renew?". Deleting it makes the client start with DISCOVER like a new device.' },
    { path: '/etc/default/isc-dhcp-relay', platform: 'Debian/Ubuntu routers (rtr01)', kind: 'startup', perms: 'root:root 0644', contains: '`SERVERS="10.0.10.53"`, `INTERFACES=""`, `OPTIONS="-id eth3.30 -iu eth0"`.', accessed: 'By the init script when isc-dhcp-relay starts (restart after changes).', problems: 'A wrong SERVERS address: requests go nowhere, the server never logs them. Missing -iu: server replies reach the router but not dhcrelay (they hit its fallback socket and the firewall). Listing the server\'s LAN as a client interface makes the relay forward that LAN\'s broadcasts too.' },
    { path: 'journalctl -u isc-dhcp-relay', platform: 'Linux routers', kind: 'log', contains: 'Start-up: version, "Listening on LPF/<iface>/<mac>" per interface, "Sending on Socket/fallback"; errors such as "No servers specified." or "Error getting hardware address for …".', accessed: 'At start.', problems: 'dhcrelay logs little per packet: use tcpdump on both sides of the router to follow requests and replies.' },
    { path: '/etc/kea/kea-dhcp4.conf', platform: 'Kea (Debian 12, RHEL 9)', kind: 'config', contains: 'JSON: `Dhcp4.interfaces-config`, `subnet4` with `pools` and `option-data`, `lease-database` (memfile /var/lib/kea/kea-leases4.csv).', accessed: 'At start; `kea-shell`/control socket `config-reload`.', problems: 'JSON syntax errors; validate with `kea-dhcp4 -t /etc/kea/kea-dhcp4.conf`.' },
    { path: 'journalctl -u isc-dhcp-server', platform: 'Linux', kind: 'log', contains: 'One line per DHCPDISCOVER/OFFER/REQUEST/ACK/NAK with MAC, hostname and interface; "no free leases"; start-up errors.', accessed: 'Continuously.', problems: 'If DISCOVERs from a client never appear, the server is not hearing it (VLAN, relay, interface, firewall).' },
    { path: '%windir%\\System32\\dhcp\\ (dhcp.mdb, DhcpSrvLog-*.log)', platform: 'Windows Server', kind: 'data', contains: 'Server database and daily audit logs (event IDs 10 new lease, 11 renew, 14 pool exhausted…).', accessed: 'Continuously; backup every 60 min to \\dhcp\\backup.', problems: 'Event 1063/1046 in System: server not authorised in AD → it will not lease.' },
    { path: 'Event Viewer: Microsoft-Windows-Dhcp-Client/Admin', platform: 'Windows clients', kind: 'eventlog', contains: 'Lease failures, APIPA fallback (169.254.x.x), address conflicts.', accessed: 'Continuously.', problems: '—' },
  ],
  management: [
    {
      platform: 'Debian (ns1 server, the lab)',
      tasks: [
        { task: 'Is the server running?', command: 'systemctl status isc-dhcp-server', explain: '`Loaded: loaded (/etc/init.d/isc-dhcp-server; generated)` shows it is an LSB script wrapped by systemd. Journal lines show "Listening on LPF/eth0/...". `systemctl cat isc-dhcp-server` shows the generated unit.', sim: true },
        { task: 'Validate the configuration', command: 'dhcpd -t', explain: 'Parses dhcpd.conf; prints the banner only when valid, otherwise the line and error.', sim: true },
        { task: 'Which interfaces does it serve?', command: 'cat /etc/default/isc-dhcp-server\nss -ulnp', explain: '`INTERFACESv4` must name a real interface with an address in a declared subnet; ss shows dhcpd on 0.0.0.0:67.', sim: true },
        { task: 'Apply configuration changes', command: 'sudo dhcpd -t && sudo systemctl restart isc-dhcp-server', explain: 'ISC dhcpd has no reload: restart after every change. Leases are kept in the lease file.', risk: 'A few seconds without DHCP; with an invalid config the service stays down.', sim: true },
        { task: 'Logs: who asked, what was offered', command: 'journalctl -u isc-dhcp-server -n 20', explain: 'DISCOVER without OFFER + "no free leases" = pool exhausted. No DISCOVER at all = the server does not hear the client.', sim: true },
        { task: 'Lease database', command: 'cat /var/lib/dhcp/dhcpd.leases', explain: 'Active leases per address; the last record for an address is current.', sim: true },
        { task: 'Enable at boot', command: 'systemctl is-enabled isc-dhcp-server', explain: 'Generated units report the SysV enablement state.', sim: true },
      ],
    },
    {
      platform: 'Linux clients',
      tasks: [
        { task: 'Request a lease verbosely', command: 'sudo dhclient -v eth0', explain: 'Shows DISCOVER/OFFER/REQUEST/ACK and "bound to ... renewal in N seconds".', sim: true },
        { task: 'Release and renew', command: 'sudo dhclient -r eth0\nsudo dhclient -v eth0', explain: '`-r` sends a release and removes the address.', risk: 'Your session over that interface drops until the new lease arrives.', sim: true },
        { task: 'What options did we get?', command: 'cat /var/lib/dhcp/dhclient.eth0.leases\nip route\ncat /etc/resolv.conf', explain: 'Compare `option routers` and `domain-name-servers` with what they should be; renew/rebind/expire show the timers.', sim: true },
        { task: 'Lease lifetime left', command: 'ip -4 addr show eth0', explain: 'A DHCP address is `dynamic` with `valid_lft` counting down to expiry.', sim: true },
        { task: 'Renewal history', command: 'sudo journalctl -t dhclient', explain: 'REQUEST "to <server>" = renewal at T1, "to 255.255.255.255" = rebinding at T2 or INIT-REBOOT, DISCOVER = starting over.', sim: true },
        { task: 'Let time pass (simulator)', command: 'sleep 300', explain: 'In the lab, timers such as renewals run while simulated time passes.', sim: true },
        { task: 'NetworkManager / networkd clients', command: 'nmcli device show eth0\nsudo nmcli connection up eth0\nnetworkctl status eth0', explain: 'Re-activating the connection renews; `networkctl status` shows the DHCP server address and lease.' },
      ],
    },
    {
      platform: 'DHCP relay on a Linux router (rtr01)',
      tasks: [
        { task: 'Relay status and interfaces', command: 'systemctl status isc-dhcp-relay\ncat /etc/default/isc-dhcp-relay', explain: 'Active, and which server(s) and interfaces it uses.', sim: true },
        { task: 'Apply a configuration change', command: 'sudo systemctl restart isc-dhcp-relay', explain: 'dhcrelay has no reload; a restart takes a moment and does not affect existing leases.', sim: true },
        { task: 'Follow a relayed exchange', command: 'sudo tcpdump -n -i eth3.30 port 67 or port 68\nsudo tcpdump -n -i eth0 port 67 or arp', explain: 'Client side: broadcasts in, offers out. Server side: unicast 10.0.10.1 → 10.0.10.53 and replies 10.0.10.53 → 10.0.30.1. ARP for an unknown address = wrong SERVERS.', sim: true },
        { task: 'Cisco equivalent', command: 'show running-config interface Vlan30 | include helper\nshow ip interface Vlan30 | include Helper', explain: '`ip helper-address 10.0.10.53` on the client-facing SVI.' },
      ],
    },
    {
      platform: 'Windows Server 2019/2022 (DHCP role)',
      tasks: [
        { task: 'Service and scopes', command: 'Get-Service DHCPServer\nGet-DhcpServerv4Scope\nGet-DhcpServerv4ScopeStatistics', explain: 'Scope state Active, free addresses and percentage in use.' },
        { task: 'Leases and options', command: 'Get-DhcpServerv4Lease -ScopeId 10.0.10.0\nGet-DhcpServerv4OptionValue -ScopeId 10.0.10.0', explain: 'Option 003 = router, 006 = DNS, 015 = domain.' },
        { task: 'Authorisation in AD', command: 'Get-DhcpServerInDC', explain: 'Unauthorised servers in a domain do not lease.' },
        { task: 'Restart', command: 'Restart-Service DHCPServer', explain: 'Configuration changes in the console apply immediately; a restart is rarely needed.' },
      ],
    },
    {
      platform: 'Windows 10/11 clients',
      tasks: [
        { task: 'Lease details', command: 'ipconfig /all', explain: 'DHCP Server, Lease Obtained/Expires, the options received. 169.254.x.x = no server answered.' },
        { task: 'Renew', command: 'ipconfig /release\nipconfig /renew', explain: '/renew alone keeps the address if possible.', risk: '/release disconnects RDP immediately.' },
      ],
    },
    {
      platform: 'pfSense',
      tasks: [
        { task: 'Server and leases', command: 'Services > DHCP Server > <interface>\nStatus > DHCP Leases\nStatus > System Logs > DHCP', explain: 'One server per interface; pool, gateway and DNS default to the interface address. In 2.7 choose ISC or Kea under System > Advanced > Networking.' },
        { task: 'Restart', command: 'Status > Services > dhcpd (restart)', explain: 'Applies after saving changes.' },
      ],
    },
    {
      platform: 'Docker',
      tasks: [
        { task: 'Not used inside containers', command: 'docker network inspect bridge', explain: 'Docker\'s IPAM assigns container addresses itself; DHCP is not involved (except macvlan networks that must not overlap the LAN\'s DHCP pool).' },
      ],
    },
  ],
  actions: [
    { action: 'systemctl restart isc-dhcp-server', when: 'After every change to dhcpd.conf or /etc/default/isc-dhcp-server. ISC dhcpd has no "reload": it only reads its configuration at start.', effect: 'Reads the configuration and the lease file again.', risk: 'A few seconds without DHCP, and an invalid configuration leaves the server stopped. Run `dhcpd -t` first.' },
    { action: 'Renew on the client (dhclient, ipconfig /renew, nmcli con up)', when: 'After fixing the server or its options, or simply to test the server.', effect: 'A new DORA exchange or a renewal; the options are applied again.', risk: 'Releasing first removes the address, which drops any remote session to that client.' },
    { action: 'Restart an interface on the server', when: 'Only when the server\'s own interface configuration changed.', effect: 'dhcpd may need a restart afterwards to start listening on the interface again.', risk: 'Interrupts every service on that interface.' },
    { action: 'Reboot', when: 'Not a DHCP fix.', effect: 'Clients renew at boot, and the server restarts.', risk: 'If the configuration is still wrong, every client fails at the same time.' },
  ],
  workflow: [
    { question: 'Does the client have an address, and where did it come from?', why: 'Start with the result. No address and "an address with wrong settings" are different problems with different causes.', command: 'ip -4 addr show eth0\ncat /var/lib/dhcp/dhclient.eth0.leases', healthy: 'inet 10.0.10.100/24 brd 10.0.10.255 scope global eth0\noption dhcp-server-identifier 10.0.10.53;', broken: 'No `inet` line: the client has no lease (continue with steps 2 to 5). An address but wrong options: go straight to step 6. A lease from an unexpected server: suspect a rogue DHCP server.', next: 'Go to step 2, or step 6 if the address is there but the settings are wrong.', sim: true },
    { question: 'What does the client see during the exchange?', why: 'Running the client by hand in verbose mode shows each DHCP message, so you can see exactly which step gets no answer.', command: 'sudo dhclient -v eth0', healthy: 'DHCPREQUEST for 10.0.10.100 on eth0 to 255.255.255.255 port 67\nDHCPACK of 10.0.10.100 from 10.0.10.53\nbound to 10.0.10.100 -- renewal in 300 seconds.', broken: 'A client that remembers a lease starts with REQUEST (INIT-REBOOT); a new one with DISCOVER and OFFER. Repeated DISCOVERs and "No DHCPOFFERS received": nobody answered. The server is down, not listening on this network, out of addresses, or the VLAN or relay is wrong. DHCPNAK: the remembered address is wrong for this network. That is normal after moving a laptop; the client starts over.', next: 'Look at the server side next (and at the relay for clients in other VLANs).', sim: true },
    { question: 'Is the server running and listening on the right interface?', why: 'dhcpd only serves the interfaces listed in INTERFACESv4, and only if a subnet declaration matches each one. Its status output says exactly which networks it serves.', command: 'systemctl status isc-dhcp-server\ncat /etc/default/isc-dhcp-server', healthy: 'Active: active (running)\nListening on LPF/eth0/52:54:00:b2:00:35/10.0.10.0/24\nINTERFACESv4="eth0"', broken: '`failed` with "Not configured to listen on any interfaces!" or "No subnet declaration for ens18": INTERFACESv4 names the wrong interface, or the subnet block for that interface\'s network is missing.', next: 'Fix the file, check it with `dhcpd -t`, then restart the service.', sim: true },
    { question: 'Does the server hear the client?', why: 'dhcpd logs every DISCOVER it receives. Whether the client\'s requests appear in the log splits the problem in two: "the request never arrives" or "the server receives it but does not answer".', command: 'journalctl -u isc-dhcp-server -n 20', healthy: 'DHCPDISCOVER from 52:54:00:d4:00:42 (ws02) via eth0\nDHCPOFFER on 10.0.10.100 to 52:54:00:d4:00:42 (ws02) via eth0', broken: 'No DISCOVER lines for this client: it is in the wrong VLAN, or the relay does not reach the server (step 4b). "via 10.0.30.1: unknown network segment": there is no subnet declaration for the relayed network. "no free leases": the pool is used up (step 5).', next: 'A pool problem: step 5. A client behind a relay: step 4b.', sim: true },
    { question: 'Client behind a relay: does the relay forward, and do the replies come back?', why: 'A relayed exchange has two halves: from the relay to the server, and back. Capturing on the router\'s server-side interface shows which half breaks.', command: 'systemctl status isc-dhcp-relay\ncat /etc/default/isc-dhcp-relay\ntcpdump -n -i eth0 port 67 or arp', healthy: 'SERVERS="10.0.10.53"\nOPTIONS="-id eth3.30 -iu eth0"\nIP 10.0.10.1.67 > 10.0.10.53.67: BOOTP/DHCP, Request from 52:54:00:e7:00:2a\nIP 10.0.10.53.67 > 10.0.30.1.67: BOOTP/DHCP, Reply', broken: 'The relay is stopped: start it. The router sends ARP requests for some other address: SERVERS points at the wrong server. Replies arrive on eth0 but nothing goes out on the client VLAN: `-iu` is missing, so the replies hit the host firewall.', next: 'Fix /etc/default/isc-dhcp-relay and restart the relay.', sim: true },
    { question: 'Is the pool big enough?', why: 'When every address in the range is leased, dhcpd stays completely silent towards new clients, which looks like the server is down.', command: 'grep -n range /etc/dhcp/dhcpd.conf\ngrep -c "binding state active" /var/lib/dhcp/dhcpd.leases', healthy: '9:    range 10.0.10.100 10.0.10.150;', broken: 'A small range with every address actively leased (long lease times, lots of visitor devices).', next: 'Enlarge the range, shorten the lease time, or move guests to their own network; then restart.', sim: true },
    { question: 'Are the options correct?', why: 'DHCP can work perfectly and still hand out a wrong gateway or DNS server. Compare what the server is configured to send with what the client actually uses.', command: 'cat /etc/dhcp/dhcpd.conf\nip route\ncat /etc/resolv.conf', healthy: 'option routers 10.0.10.1;\noption domain-name-servers 10.0.10.53;', broken: 'A wrong `routers` option: clients can only reach their own subnet. A wrong DNS option: name resolution fails, but only on DHCP clients. Hosts with static settings still work, which is a strong clue.', next: 'Fix the option on the server, restart dhcpd, then renew the clients.', sim: true },
    { question: 'Do the clients pick up the fix?', why: 'Clients only learn new options when they get or renew a lease. Until then they keep the old, wrong ones.', command: 'sudo dhclient -r eth0\nsudo dhclient -v eth0\nip route', healthy: 'default via 10.0.10.1 dev eth0', broken: 'The old options are still in use: the client has not renewed yet. With long leases, clients can keep wrong settings for days.', next: 'Renew the affected clients, or wait until T1. Before a planned change, consider shortening the lease time in advance.', sim: true },
  ],
  failures: [
    { symptom: 'Client has no IPv4 address; "No DHCPOFFERS received"', causes: ['dhcpd not running (bad config, wrong INTERFACESv4)', 'Client on a VLAN without server or relay'], diagnose: ['sudo dhclient -v eth0 (client)', 'systemctl status isc-dhcp-server', 'journalctl -u isc-dhcp-server -n 20'], fix: 'Fix the server config/interface and restart; fix VLAN membership or configure a relay.', verify: 'dhclient -v shows DHCPACK; ip -4 addr' },
    { symptom: 'Only clients on a relayed VLAN get no address', causes: ['Relay stopped or SERVERS wrong (server never logs the client)', 'No subnet declaration for the relayed network ("unknown network segment")', 'Relay not receiving replies (-iu missing, firewall on its fallback socket)'], diagnose: ['journalctl -u isc-dhcp-server (server)', 'systemctl status isc-dhcp-relay; cat /etc/default/isc-dhcp-relay (router)', 'tcpdump on both sides of the router'], fix: 'Point the relay at the server with -id/-iu set; declare the subnet on the server; restart the service you changed.', verify: 'A client on that VLAN completes the exchange (DHCPACK from the relay address)' },
    { symptom: 'Laptops lose their network one after another; static hosts fine', causes: ['DHCP server stopped answering at least one lease time ago (failed restart, crash, unreachable)'], diagnose: ['sudo journalctl -t dhclient (client): unanswered renewals, then rebinding, then DISCOVER', 'systemctl status isc-dhcp-server'], fix: 'Bring the server back (dhcpd -t first); clients recover at their next retry (5 min) or with dhclient.', verify: 'Clients bound again; ip -4 addr shows a fresh valid_lft' },
    { symptom: 'New clients fail, existing ones work', causes: ['Pool exhausted (no free leases)'], diagnose: ['journalctl -u isc-dhcp-server | grep "no free leases"', 'grep range /etc/dhcp/dhcpd.conf'], fix: 'Enlarge the pool / shorten lease time / move guests to their own network.', verify: 'New client gets an address' },
    { symptom: 'DHCP clients reach the local subnet only', causes: ['Wrong `option routers`'], diagnose: ['ip route (client)', 'cat /var/lib/dhcp/dhclient.eth0.leases', 'grep routers /etc/dhcp/dhcpd.conf'], fix: 'Correct the option, restart dhcpd, renew clients.', verify: 'ip route shows the right default gateway' },
    { symptom: 'Only DHCP clients cannot resolve names', causes: ['Wrong `domain-name-servers` option'], diagnose: ['cat /etc/resolv.conf (client)', 'grep domain-name-servers /etc/dhcp/dhcpd.conf'], fix: 'Correct the option, restart, renew.', verify: 'getent hosts srv01.corp.lab' },
    { symptom: 'Clients get addresses from an unknown network (e.g. 192.168.1.x)', causes: ['Rogue DHCP server (consumer router, misconfigured VM)'], diagnose: ['dhclient lease: dhcp-server-identifier', 'tcpdump -n -i eth0 port 67 or port 68'], fix: 'Find and disconnect the rogue device (MAC → switch port); enable DHCP snooping.', verify: 'Leases come from 10.0.10.53 only' },
    { symptom: 'Windows server event 1046/1059: DHCP server not authorised', causes: ['Server not authorised in AD, or cannot contact a DC'], diagnose: ['Get-DhcpServerInDC', 'System event log'], fix: 'Authorise the server (`Add-DhcpServerInDC`), check DC connectivity.', verify: 'Scope statistics show new leases' },
  ],
  verification: [
    { check: 'Server running and valid', command: 'systemctl is-active isc-dhcp-server; dhcpd -t', expect: 'active; banner without errors' },
    { check: 'A client completes DORA', command: 'sudo dhclient -v eth0', expect: 'DHCPACK of 10.0.10.100 from 10.0.10.53 ... bound to 10.0.10.100' },
    { check: 'Options are correct on the client', command: 'ip route; cat /etc/resolv.conf', expect: 'default via 10.0.10.1; nameserver 10.0.10.53' },
    { check: 'The client works beyond its subnet', command: 'curl -I http://srv01.corp.lab/', expect: 'HTTP/1.1 200 OK' },
    { check: 'Survives a reboot', command: 'systemctl is-enabled isc-dhcp-server; reboot the client and check ip -4 addr', expect: 'enabled; lease obtained at boot' },
  ],
  refIds: ['ip', 'journalctl', 'systemctl', 'tcpdump', 'ipconfig', 'get-netipconfiguration', 'file:dhcpd.conf', 'file:dhcpd.leases', 'file:isc-dhcp-relay', 'file:resolv.conf', 'proc:dhcp-renew', 'proc:dhcp-relay', 'proc:safe-config-change'],
};
