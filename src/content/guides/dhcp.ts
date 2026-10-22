// Operate & recover guide: DHCP servers (ISC dhcpd on ns1, Kea, Windows,
// pfSense) and clients (dhclient, NetworkManager, Windows).

import type { ServiceGuide } from '../types';

export const DHCP_GUIDE: ServiceGuide = {
  purpose:
    'DHCP hands clients an address, prefix, default gateway, DNS servers and domain, for a limited time (a lease). When it fails, the client has **no address at all** (Linux: no IPv4 on the interface; Windows: 169.254.x.x), or it gets an address with **wrong options** and fails later in confusing ways (no Internet, no name resolution). In the lab, ns1 runs ISC dhcpd for the office LAN (ws02) and, through the relay agent on rtr01, for the development VLAN 30 (dev02). ISC DHCP reached end of life in 2022; its successor is ISC **Kea**, and the diagnostic method is the same.',
  architecture: [
    { q: 'What does it accomplish?', a: 'Automatic, centrally managed IPv4 configuration: pools of addresses, reservations (fixed address per MAC), and options (router, DNS servers, domain, NTP, PXE boot server).' },
    { q: 'How does it work internally?', a: 'The server keeps a **lease database** (`/var/lib/dhcp/dhcpd.leases`, an append-only journal of lease states). For a request it picks an address in this order: a reservation for the client\'s MAC, the client\'s previous lease, the address the client asks for if free, then the next free address in the pool. Clients renew at T1 (50% of the lease) directly with the server, rebind at T2 (87.5%) with any server, and lose the address at expiry.' },
    { q: 'Which protocols does it use?', a: 'DHCP (RFC 2131) with options (RFC 2132), carried in BOOTP messages over UDP. The four-step exchange is **DORA**: Discover, Offer, Request, Ack (or NAK). DHCPv6 is a separate protocol with its own daemons and rules (DUIDs, ff02::1:2, no default route, filtered by nftables); see the IPv6 lesson. In the lab dhcpd -6 on rtr01 serves VLAN 30.' },
    { q: 'Which ports and transport?', a: 'UDP: server 67, client 68. Discover and Request are **broadcasts** (255.255.255.255), because the client has no address yet, so they do not cross routers: other subnets need a **DHCP relay** (ip helper-address) on the router, which forwards them as unicast to the server.' },
    { q: 'Which processes and OS components implement it?', a: 'Server: `dhcpd` (ISC, package isc-dhcp-server, an LSB init script wrapped by systemd: unit `isc-dhcp-server.service` generated in /run/systemd/generator.late), `kea-dhcp4` (Kea), Windows **DHCP Server** service (dhcpmgmt.msc), pfSense DHCP server (ISC or Kea backend in 2.7). Client: `dhclient` (ifupdown, the lab), NetworkManager\'s internal client, systemd-networkd, Windows **DHCP Client** service (Dhcp).' },
    { q: 'Which other services does it depend on?', a: 'The server needs an interface **with an address in each subnet it serves directly**, a `subnet` declaration for every relayed network, a valid configuration and a writable lease file. Clients need layer 2 to the server (same VLAN) or a relay agent on their router that points at the server and receives its replies; renewals additionally need a routed path from the client to the server. Every option it hands out points at another dependency: the router must exist at the `routers` address and DNS at `domain-name-servers`.' },
    { q: 'How do requests travel?', a: 'Client broadcasts DISCOVER (src 0.0.0.0:68 → 255.255.255.255:67) → server answers with OFFER (address + options) → client broadcasts REQUEST naming the chosen server (so other servers withdraw their offers) → server records the lease and sends ACK → client configures the address and sends gratuitous ARP. Through a relay: the relay receives the broadcast on the client VLAN, sets giaddr to its own address there and unicasts it (UDP 67 → 67) to the server; the server picks the subnet containing giaddr and answers to the relay, which delivers it to the client\'s MAC. Renewals are unicast REQUEST/ACK straight between client and server, without the relay.' },
    { q: 'How do authentication and authorisation work?', a: '**None.** Any host on the segment can answer as a DHCP server (a **rogue DHCP server**, e.g. a home router plugged in backwards) and hand out its own gateway and DNS. Defences are on the network: DHCP snooping on switches (only trusted ports may send OFFER/ACK), 802.1X, and `authoritative;` on the legitimate server so it NAKs wrong requests quickly.' },
    { q: 'How does it start at boot?', a: 'Debian: `isc-dhcp-server.service` (from `/etc/init.d/isc-dhcp-server`) reads `/etc/default/isc-dhcp-server` for `INTERFACESv4` and starts dhcpd on those interfaces; it must start after the interfaces have their addresses. Clients run dhclient when ifupdown raises an `inet dhcp` interface.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'Existing clients keep working until their lease expires (renewals fail silently first). New and rebooted clients get no address. With short leases (the lab uses 600 s) an outage becomes visible within minutes; with 8-day leases, days later. dhcpd re-reads its lease file at start, so leases survive a restart.' },
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
    { action: 'systemctl restart isc-dhcp-server', when: 'After every dhcpd.conf or /etc/default change (ISC dhcpd has no reload).', effect: 'Re-reads configuration and the lease file.', risk: 'Seconds without DHCP; invalid config leaves it down. Run `dhcpd -t` first.' },
    { action: 'Client renew (dhclient, ipconfig /renew, nmcli con up)', when: 'After fixing the server or its options, or to test the server.', effect: 'New DORA or renewal; options re-applied.', risk: 'Release first drops the address and any remote session.' },
    { action: 'Interface restart on the server', when: 'Only if the server\'s own interface configuration changed.', effect: 'dhcpd may need a restart afterwards to rebind to the interface.', risk: 'All services on that interface interrupted.' },
    { action: 'reboot', when: 'Not a DHCP fix.', effect: 'Clients renew at boot; the server restarts.', risk: 'If the configuration is still wrong, every client fails at once.' },
  ],
  workflow: [
    { question: '1. Does the client have an address, and from where?', command: 'ip -4 addr show eth0\ncat /var/lib/dhcp/dhclient.eth0.leases', healthy: 'inet 10.0.10.100/24 brd 10.0.10.255 scope global eth0\noption dhcp-server-identifier 10.0.10.53;', broken: 'No `inet` line → no lease (steps 2–5). An address with wrong options → step 6.', next: 'Step 2 or 6.', sim: true },
    { question: '2. What does the client see during the exchange?', command: 'sudo dhclient -v eth0', healthy: 'DHCPREQUEST for 10.0.10.100 on eth0 to 255.255.255.255 port 67\nDHCPACK of 10.0.10.100 from 10.0.10.53\nbound to 10.0.10.100 -- renewal in 300 seconds.', broken: 'A client with a remembered lease starts with REQUEST (INIT-REBOOT); a new one with DISCOVER/OFFER. Repeated DISCOVER and "No DHCPOFFERS received" → nobody answered: server down, not listening on this segment, pool empty, or layer-2/relay problem. DHCPNAK → the remembered address is wrong for this network (normal after moving; the client starts over).', next: 'Look at the server side (and the relay for other VLANs).', sim: true },
    { question: '3. Is the server running and listening on the right interface?', command: 'systemctl status isc-dhcp-server\ncat /etc/default/isc-dhcp-server', healthy: 'Active: active (running)\nListening on LPF/eth0/52:54:00:b2:00:35/10.0.10.0/24\nINTERFACESv4="eth0"', broken: '`failed` with "Not configured to listen on any interfaces!" or "No subnet declaration for ens18" → wrong INTERFACESv4 or missing subnet block.', next: 'Fix, `dhcpd -t`, restart.', sim: true },
    { question: '4. Does the server hear the client?', command: 'journalctl -u isc-dhcp-server -n 20', healthy: 'DHCPDISCOVER from 52:54:00:d4:00:42 (ws02) via eth0\nDHCPOFFER on 10.0.10.100 to 52:54:00:d4:00:42 (ws02) via eth0', broken: 'No DISCOVER lines for the client → wrong VLAN or the relay does not reach the server (step 4b). "via 10.0.30.1: unknown network segment" → no subnet for the relayed network. "no free leases" → pool exhausted (step 5).', next: 'Pool problem → step 5; relayed client → step 4b.', sim: true },
    { question: '4b. Relayed client: does the relay forward, and do replies come back?', command: 'systemctl status isc-dhcp-relay\ncat /etc/default/isc-dhcp-relay\ntcpdump -n -i eth0 port 67 or arp', healthy: 'SERVERS="10.0.10.53"\nOPTIONS="-id eth3.30 -iu eth0"\nIP 10.0.10.1.67 > 10.0.10.53.67: BOOTP/DHCP, Request from 52:54:00:e7:00:2a\nIP 10.0.10.53.67 > 10.0.30.1.67: BOOTP/DHCP, Reply', broken: 'Relay stopped → start it. ARP for another address → SERVERS wrong. Replies arrive on eth0 but nothing leaves on the client VLAN → -iu missing (replies hit the firewall).', next: 'Fix /etc/default/isc-dhcp-relay and restart the relay.', sim: true },
    { question: '5. Is the pool large enough?', command: 'grep -n range /etc/dhcp/dhcpd.conf\ngrep -c "binding state active" /var/lib/dhcp/dhcpd.leases', healthy: '9:    range 10.0.10.100 10.0.10.150;', broken: 'A small range with all addresses actively leased (long lease times, visitor devices).', next: 'Enlarge the range / shorten leases / separate guest network; restart.', sim: true },
    { question: '6. Are the options correct?', command: 'cat /etc/dhcp/dhcpd.conf\nip route\ncat /etc/resolv.conf', healthy: 'option routers 10.0.10.1;\noption domain-name-servers 10.0.10.53;', broken: 'Wrong `routers` → clients reach the local subnet only. Wrong DNS → name resolution fails only on DHCP clients (static hosts are fine: a strong clue).', next: 'Fix the server option, restart, then renew clients.', sim: true },
    { question: '7. Do clients pick up the fix?', command: 'sudo dhclient -r eth0\nsudo dhclient -v eth0\nip route', healthy: 'default via 10.0.10.1 dev eth0', broken: 'Old options remain until renewal; with long leases clients may keep wrong settings for days.', next: 'Renew affected clients or wait for T1; consider shorter leases before planned changes.', sim: true },
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
