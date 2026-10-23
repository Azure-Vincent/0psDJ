// pfSense lesson. Output samples, menu paths and labels are representative of
// pfSense CE 2.7.2 on FreeBSD 14. The lab's fw01 is a simulated pfSense
// (config.xml, pf, the webConfigurator pages that matter for rules and NAT):
// the sandbox, the pfSense tickets and Lab 3 use it. Console commands marked
// sim work on fw01.

import type { Assessment, Lesson, ServiceGuide } from '../types';

export const PFSENSE_GUIDE: ServiceGuide = {
  purpose:
    'pfSense CE is a FreeBSD-based firewall/router distribution managed through a PHP web interface (the **webConfigurator**). The service at its heart is **pf**, the FreeBSD packet filter in the kernel: it filters packets (rules evaluated on the interface where traffic **enters**, first match wins, implicit default deny), translates addresses (outbound NAT, port forwards, 1:1) and keeps a **state table** of every allowed flow. Around pf, pfSense runs the services a small network needs: DHCP (ISC dhcpd or Kea), the DNS Resolver (unbound), VPNs (OpenVPN, IPsec, WireGuard), gateway monitoring (dpinger) and logging. Every setting lives in one XML file, `/cf/conf/config.xml`; the GUI validates changes, writes that file, and regenerates the real configuration files (such as `/tmp/rules.debug` for pf and `/var/unbound/unbound.conf`) from it. Troubleshooting pfSense means finding which of those layers (interface, route, rule, NAT, state, service) makes the decision you did not expect.',
  architecture: [
    { q: 'What does it accomplish?', a: 'Perimeter and inter-segment firewalling (LAN, VLANs, DMZ, WAN), routing between those segments and one or more upstream gateways, NAT so private networks reach the Internet, and the edge services clients depend on: DHCP, DNS, NTP and remote-access/site-to-site VPN. It replaces a Linux router with nftables (see the nftables and NAT lessons) with an appliance whose configuration is driven from a GUI.' },
    { q: 'How does it work internally?', a: 'The kernel runs **pf**. pfSense never edits pf rules incrementally: when you click **Apply Changes**, PHP code reads `config.xml`, generates a complete ruleset (aliases → tables, NAT, filter rules, automatic rules such as anti-lockout and the default block rules) into `/tmp/rules.debug`, and loads it atomically with `pfctl -f`. If the generated file has an error, pf keeps the **previous** ruleset and the GUI shows "There were error(s) loading the rules" with the line number. Services are similarly regenerated: changing DHCP settings rewrites `/var/dhcpd/etc/dhcpd.conf` and restarts dhcpd. Requests from the GUI are queued through the `check_reload_status` daemon, which runs the actual reload scripts (for example `/etc/rc.filter_configure`).' },
    { q: 'Which protocols does it use?', a: 'It forwards any IP protocol you allow. It speaks itself: HTTPS (webConfigurator), SSH (optional), DNS (unbound, 53/udp+tcp), DHCPv4/v6 (67/68, 546/547), NTP (123/udp), ICMP for gateway monitoring (dpinger pings each gateway monitor IP), syslog to a remote server (514/udp, optional), and VPN protocols (OpenVPN 1194/udp by default, IPsec IKE 500/udp + NAT-T 4500/udp + ESP, WireGuard 51820/udp by default in the package). Optional pfsync/CARP for HA.' },
    { q: 'Which ports and transport?', a: 'WebGUI: TCP 443 (HTTPS, default) with an HTTP→HTTPS redirect on 80, configurable at System > Advanced > Admin Access. SSH: TCP 22 when enabled. DNS Resolver: 53 UDP/TCP on all interfaces by default. These listen on **This Firewall** (self) addresses: a rule must pass traffic to them on each interface except where an automatic rule exists (anti-lockout on LAN, DHCP on DHCP-enabled interfaces).' },
    { q: 'Which processes and OS components implement it?', a: 'Kernel: pf (filter, NAT, states), `pflog0` (logging pseudo-interface), the network drivers (`vtnet` on KVM/Proxmox, `igb`/`igc`/`ix` on Intel NICs, `em` on older Intel/VMware e1000, `vmx` on VMware VMXNET3). Userland: `filterlog` (turns pflog packets into `/var/log/filter.log` lines), `php-fpm` + `nginx` (webConfigurator), `check_reload_status`, `unbound`, `dhcpd` or `kea-dhcp4`, `dpinger` (one per monitored gateway), `openvpn`, `charon` (strongSwan, IPsec), `syslogd`, `sshd`, `ntpd`.' },
    { q: 'Which other services does it depend on?', a: 'Correct **interface assignment** (the logical WAN/LAN/OPTx names must point to the right physical NIC or VLAN), link on those NICs, a valid WAN address and default gateway (DHCP from upstream or static), the hypervisor or switch delivering the right VLAN tags, the upstream router having a route back to anything not NATed, and DNS servers for the resolver to reach the root servers (or forwarders). The GUI depends on php-fpm and nginx; the console menu works even when both are down.' },
    { q: 'How do requests travel?', a: 'A client in VLAN 30 sends a packet to its gateway 10.0.30.1. It **enters** pfSense on OPT1 (`vtnet1.30`): pf first checks the state table (an existing flow passes without rule evaluation), then NAT redirects (port forwards would apply here for inbound WAN traffic), then the OPT1 rules from top to bottom; the first match decides. If passed, a state is created, the routing table chooses the egress interface (WAN), outbound NAT rewrites the source to the WAN address, and the packet leaves. The reply matches the state on the way back and is un-NATed automatically. **No rule on the egress interface is needed**: pfSense passes outbound traffic with an automatic rule; you filter on ingress.' },
    { q: 'How do authentication and authorisation work?', a: 'The webConfigurator and SSH authenticate against the local user manager (`admin`, default password `pfsense` until the wizard changes it) or a RADIUS/LDAP server (System > User Manager > Authentication Servers). Privileges are per user or group ("WebCfg - All pages", "User - System: Shell account access"). Console access is protected only if "Password protect the console menu" is set (System > Advanced > Admin Access); physical/hypervisor console access otherwise means full control. Traffic itself is authorised by firewall rules, not by user identity (unless you use the Captive Portal or VPN user authentication).' },
    { q: 'How does it start at boot?', a: 'FreeBSD boots, then pfSense rc scripts read `config.xml` (cached as `/tmp/config.cache`), configure interfaces in assignment order, generate and load the pf ruleset, start dpinger, unbound, DHCP, VPNs and packages, and finally the webConfigurator. If the configured NICs do not exist (new hardware, changed NIC type in the hypervisor), boot stops at the **interface assignment** prompt on the console. A corrupt `config.xml` can stop the boot; pfSense then offers to restore the most recent backup from `/cf/conf/backup/`.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'pf is in the kernel and does not "crash" independently: filtering and existing states continue even if the GUI, php-fpm or check_reload_status die. If **unbound** stops, clients lose DNS (but ping by IP works); if **dhcpd** stops, existing leases keep working until they expire while new clients get 169.254.x.x addresses; if **dpinger** stops, gateways show as down/unknown and gateway groups may fail over. The service watchdog package can restart services automatically; by default nothing does, so check Status > Services.' },
  ],
  ports: [
    { port: '443 (80 redirect)', proto: 'TCP', purpose: 'webConfigurator (nginx + php-fpm); System > Advanced > Admin Access' },
    { port: '22', proto: 'TCP', purpose: 'SSH to the firewall (disabled by default; console option 14)' },
    { port: '53', proto: 'UDP/TCP', purpose: 'DNS Resolver (unbound) or DNS Forwarder (dnsmasq): only one can bind it' },
    { port: '67/68', proto: 'UDP', purpose: 'DHCPv4 server (ISC dhcpd or Kea) per interface' },
    { port: '123', proto: 'UDP', purpose: 'NTP server (ntpd)' },
    { port: '1194', proto: 'UDP', purpose: 'OpenVPN server (default port, configurable per instance)' },
    { port: '500, 4500 + ESP (IP 50)', proto: 'UDP / IP', purpose: 'IPsec IKE, NAT traversal and payload (strongSwan charon)' },
    { port: '51820', proto: 'UDP', purpose: 'WireGuard tunnel listen port (package default)' },
    { port: 'ICMP', proto: 'ICMP', purpose: 'dpinger gateway monitoring; Diagnostics > Ping' },
  ],
  processes: [
    { name: 'pf (kernel)', platform: 'pfSense CE 2.7.2 / FreeBSD 14', role: 'Filtering, NAT and the state table; controlled with `pfctl`' },
    { name: 'filterlog', platform: 'pfSense', role: 'Reads logged packets from `pflog0` and writes them to `/var/log/filter.log`' },
    { name: 'nginx + php-fpm', platform: 'pfSense', role: 'webConfigurator; console option 11 restarts the GUI, 16 restarts PHP-FPM' },
    { name: 'check_reload_status', platform: 'pfSense', role: 'Queues and runs filter reloads, interface reconfigurations and service restarts requested by the GUI' },
    { name: 'unbound', platform: 'pfSense', role: 'DNS Resolver (Services > DNS Resolver); config `/var/unbound/unbound.conf`' },
    { name: 'dhcpd / kea-dhcp4', platform: 'pfSense 2.7.x', role: 'DHCPv4 server; ISC is the 2.7.2 default, Kea selectable in System > Advanced > Networking' },
    { name: 'dpinger', platform: 'pfSense', role: 'One instance per monitored gateway; latency/loss drives gateway status and failover' },
    { name: 'openvpn / charon / wg', platform: 'pfSense', role: 'OpenVPN instances, IPsec (strongSwan) and WireGuard (package, kernel `if_wg`)' },
  ],
  dependencies: {
    title: 'What a client in VLAN 30 needs to reach the Internet through pfSense',
    caption: 'Check from the bottom up: the wrong layer is usually the lowest one that fails. A rule cannot fix a wrong assignment, and NAT cannot fix a missing route.',
    rows: [
      { label: 'Service', nodes: [{ id: 'dns', label: 'DNS Resolver', sub: 'unbound, ACLs', kind: 'service' }, { id: 'dhcp', label: 'DHCP server', sub: 'per interface', kind: 'service' }] },
      { label: 'Translate', nodes: [{ id: 'nat', label: 'Outbound NAT', sub: 'auto/hybrid/manual', kind: 'service' }, { id: 'state', label: 'State table', sub: 'pfctl -ss', kind: 'data' }] },
      { label: 'Filter', nodes: [{ id: 'rules', label: 'OPT1 rules', sub: 'ingress, first match', kind: 'service' }, { id: 'float', label: 'Floating rules', sub: 'evaluated first', kind: 'service' }] },
      { label: 'Route', nodes: [{ id: 'gw', label: 'Default gateway', sub: 'WAN, dpinger', kind: 'network' }, { id: 'routes', label: 'Static routes', sub: 'netstat -rn', kind: 'network' }] },
      { label: 'Interface', nodes: [{ id: 'assign', label: 'Assignment', sub: 'OPT1 = vtnet1.30', kind: 'os' }, { id: 'vlan', label: 'VLAN 30 tag', sub: 'switch trunk', kind: 'network' }, { id: 'wan', label: 'WAN address', sub: 'DHCP/static', kind: 'network' }] },
    ],
    edges: [
      ['dns', 'rules'], ['dhcp', 'assign'], ['nat', 'gw'], ['state', 'rules'], ['rules', 'assign'], ['float', 'assign'],
      ['gw', 'wan'], ['routes', 'assign'], ['assign', 'vlan'], ['nat', 'state'],
    ],
  },
  sequence: {
    title: 'dev01 (VLAN 30) opens https://203.0.113.80 through pfSense',
    caption: 'Representative of pfSense CE 2.7.2. Each note says what you see when that step fails.',
    lanes: [{ id: 'c', label: 'dev01', sub: '10.0.30.25' }, { id: 'p', label: 'pfSense', sub: 'OPT1 vtnet1.30 / WAN' }, { id: 'u', label: 'Upstream router', sub: '192.168.1.1' }, { id: 's', label: 'Web server', sub: '203.0.113.80' }],
    steps: [
      { from: 'c', to: 'p', label: 'DNS query to 10.0.30.1:53', note: 'No pass rule to "This Firewall" port 53, or unbound ACL refuses the subnet → "connection timed out" / REFUSED.' },
      { from: 'c', to: 'p', label: 'TCP SYN :443 (enters OPT1)', note: 'No matching pass rule on OPT1 → default deny, logged as "Default deny rule IPv4"; the client times out.' },
      { from: 'p', to: 'p', label: 'rule match → state → route → NAT', note: 'No default route → "no route to host"; outbound NAT missing for 10.0.30.0/24 (manual mode) → packet leaves with a private source and replies never return.' },
      { from: 'p', to: 'u', label: 'SYN src 192.168.1.50:21837', note: 'A capture on WAN shows the translated source; if it still shows 10.0.30.25, NAT is wrong.' },
      { from: 'u', to: 's', label: 'SYN (upstream NAT again)' },
      { from: 's', to: 'u', label: 'SYN-ACK' },
      { from: 'u', to: 'p', label: 'SYN-ACK to 192.168.1.50', note: 'Matches the state, so WAN rules are not consulted for replies.' },
      { from: 'p', to: 'c', label: 'SYN-ACK un-NATed to 10.0.30.25' },
    ],
  },
  files: [
    { path: '/cf/conf/config.xml', platform: 'pfSense CE 2.7.2', kind: 'config', perms: 'root:wheel 0644', contains: 'The **single source of truth** for every setting: interfaces and assignments, VLANs, gateways, routes, aliases, filter and NAT rules, DHCP, DNS, VPN, users, packages. `/conf` is a symlink to `/cf/conf`.', accessed: 'Read at boot (and cached in `/tmp/config.cache`); written by the GUI, the console menu and `pfSsh.php` on every saved change.', problems: 'Hand edits bypass validation; an XML syntax error can prevent the boot or make the GUI fail to load. Edits do nothing until the config cache is removed and the affected subsystem is reloaded (or the firewall rebooted). Prefer the GUI; if you must edit, copy it first.' },
    { path: '/cf/conf/backup/config-<epoch>.xml', platform: 'pfSense', kind: 'data', perms: 'root:wheel', contains: 'Automatic previous revisions of config.xml, one per saved change (the number kept is set at Diagnostics > Backup & Restore > Config History; 30 by default on a normal install).', accessed: 'Written before every config write; read by Diagnostics > Backup & Restore > Config History and by console option 15 "Restore recent configuration".', problems: 'Only covers changes saved through supported interfaces. Revisions live on the same disk: export a full backup (Diagnostics > Backup & Restore > Download configuration as XML) off the box too.' },
    { path: '/tmp/config.cache', platform: 'pfSense', kind: 'runtime', contains: 'Serialized (parsed) copy of config.xml used by PHP for speed.', accessed: 'Whenever PHP code reads the configuration.', problems: 'After a manual edit of config.xml, the cache still holds the old values: `rm /tmp/config.cache` so the next read re-parses the file.' },
    { path: '/tmp/rules.debug', platform: 'pfSense', kind: 'runtime', contains: 'The complete pf ruleset generated from config.xml: macros, tables (aliases), scrub, NAT/rdr rules, automatic rules, user rules with `label "USER_RULE: ..."` and tracker ids.', accessed: 'Regenerated and loaded (`pfctl -f /tmp/rules.debug`) on every filter reload.', problems: 'Never edit it: it is overwritten at the next reload. Read it (or `pfctl -sr`) to see what pf actually enforces. A load error message quotes its line number: `pfctl -nf /tmp/rules.debug` reproduces the check.' },
    { path: '/var/log/filter.log', platform: 'pfSense 2.7.x (plain-text logs)', kind: 'log', perms: 'root:wheel 0600', contains: 'One comma-separated line per logged packet: rule number, tracker id, real interface, reason, action (pass/block), direction, IP version, addresses, ports, TCP flags. Shown parsed at Status > System Logs > Firewall.', accessed: 'Written by filterlog for every packet matching a rule with logging enabled, and by the default block rules (logged by default).', problems: 'Pass rules are not logged unless you tick "Log" on the rule. Disk-based logs rotate by size (Status > System Logs > Settings); a busy WAN fills them with noise.' },
    { path: '/var/log/system.log', platform: 'pfSense', kind: 'log', contains: 'General system messages: interface up/down, check_reload_status, php-fpm errors, rule load errors ("There were error(s) loading the rules"), dpinger alarms (also in gateways.log).', accessed: 'Continuously; Status > System Logs > System > General.', problems: 'Other services have their own files: `resolver.log` (unbound), `dhcpd.log`, `openvpn.log`, `ipsec.log`, `gateways.log`, `nginx.log`.' },
    { path: '/var/unbound/unbound.conf', platform: 'pfSense', kind: 'config', contains: 'Generated unbound configuration (chroot /var/unbound): interfaces, access-control lines per local subnet, forwarding, DNSSEC. Host overrides are in `/var/unbound/host_entries.conf`.', accessed: 'Rewritten when DNS Resolver settings are saved, then unbound restarts.', problems: 'Manual edits are lost on the next save. Use Services > DNS Resolver > Custom options for extra directives (a syntax error there stops unbound: check resolver.log).' },
    { path: '/var/dhcpd/var/db/dhcpd.leases', platform: 'pfSense (ISC DHCP backend)', kind: 'data', contains: 'ISC dhcpd lease database (chroot /var/dhcpd); config generated in `/var/dhcpd/etc/dhcpd.conf`. With the Kea backend the leases are in `/var/lib/kea/dhcp4.leases`.', accessed: 'Updated by dhcpd on every lease; displayed at Status > DHCP Leases.', problems: 'Deleting it while dhcpd runs causes address conflicts; use the GUI to delete individual leases. Pool exhaustion shows as "no free leases" in dhcpd.log.' },
    { path: '/var/etc/openvpn/, /var/etc/ipsec/', platform: 'pfSense', kind: 'config-dir', contains: 'Generated OpenVPN instance configs (server1/config.ovpn …) and strongSwan swanctl configuration.', accessed: 'Rewritten when the VPN is saved or the service restarted.', problems: 'Regenerated from config.xml; read them for diagnosis, change settings in the GUI.' },
  ],
  management: [
    {
      platform: 'pfSense web UI (webConfigurator)',
      tasks: [
        { task: 'Status of all services', command: 'Status > Services', explain: 'Lists unbound, dhcpd/kea-dhcp4, dpinger, ntpd, openvpn instances, ipsec, sshd, syslogd with a running/stopped icon and start/stop/restart buttons. The dashboard "Services Status" widget shows the same.' },
        { task: 'Start / stop / restart one service', command: 'Status > Services > (restart icon) unbound\nStatus > Services > (stop / start icon) dhcpd', explain: 'Restarts only that daemon after regenerating its config from config.xml. Clients of that service see a short interruption; other traffic is unaffected.', risk: 'Restarting unbound flushes its cache; restarting an OpenVPN server disconnects all its clients.' },
        { task: 'Reload the firewall rules', command: 'Firewall > Rules > Apply Changes\nStatus > Filter Reload > Reload Filter', explain: 'Regenerates /tmp/rules.debug and loads it atomically. Existing states are kept: a connection that is already established keeps flowing until its state expires or is killed.' },
        { task: 'Enable / disable at boot', command: 'Services > DNS Resolver > Enable\nServices > DHCP Server > OPT1 > Enable DHCP server on OPT1 interface', explain: 'There is no separate "enabled" flag: a service runs at boot if it is enabled in its own settings page (stored in config.xml). Disabling it there stops it now and at boot.' },
        { task: 'Failed / stopped services and why', command: 'Status > Services\nStatus > System Logs > System > General (and the DNS Resolver, DHCP, OpenVPN tabs)', explain: 'A stopped service that should run shows a red icon. The reason is in its log tab, e.g. unbound "error: bind: address already in use" (DNS Forwarder also enabled) or a syntax error in custom options.' },
        { task: 'Dependencies', command: 'Status > Interfaces\nStatus > Gateways\nInterfaces > Assignments', explain: 'Services depend on interfaces and gateways: check that the interface is up with the right address, that gateways are online (dpinger), and that the assignment points to the expected NIC/VLAN before blaming the service.' },
        { task: 'Recent logs', command: 'Status > System Logs > Firewall (Normal / Dynamic / Summary view)\nStatus > System Logs > System > General', explain: 'The Firewall log shows action icon, time, interface, rule description (hover/click the icon), source, destination and protocol. The funnel icon filters by IP, port or interface.' },
        { task: 'Find which rule matched', command: 'Status > System Logs > Firewall > (click the block/pass icon)', explain: 'Shows the rule label, e.g. "Default deny rule IPv4 (1000000103)" or "USER_RULE: Allow DEV to any". Tracker ids also appear in Firewall > Rules when you hover the rule.' },
        { task: 'States: view, filter, kill, reset', command: 'Diagnostics > States (filter: 10.0.30.25)\nDiagnostics > States > Reset States', explain: 'Filter by address to see states for one host; the X icon kills individual states (or all matching the filter). Reset States flushes the whole table.', risk: 'Reset States drops every connection through the firewall, including your GUI session and every VPN tunnel. Kill only the states you need.' },
        { task: 'Packet capture', command: 'Diagnostics > Packet Capture: Interface OPT1, Host 10.0.30.25, Count 100 > Start', explain: 'Runs tcpdump on the chosen interface and offers the .pcap for download (open in Wireshark). Capture on both ingress and egress interfaces to see where a packet disappears and whether NAT rewrote it.' },
        { task: 'Ping / traceroute / test port from the firewall', command: 'Diagnostics > Ping (Source address: OPT1)\nDiagnostics > Traceroute\nDiagnostics > Test Port (host 10.0.20.10, port 443, source OPT1)', explain: 'Choosing the **source address** matters: from the WAN address a test proves the firewall can reach it, from the OPT1 address it tests the same routing/NAT path as clients (without passing the OPT1 inbound rules).' },
        { task: 'Restore a previous configuration', command: 'Diagnostics > Backup & Restore > Config History', explain: 'Lists revisions with timestamp and description ("Firewall: Rules - saved/edited a firewall rule"), with diff and restore buttons. Restoring writes config.xml; some changes then need a reboot or a filter/interface reload.', risk: 'Restoring an old revision also reverts every change made since then.' },
        { task: 'Run a shell command from the GUI', command: 'Diagnostics > Command Prompt: pfctl -si', explain: 'Executes a shell (or PHP) command and shows the output; useful when SSH is disabled. Avoid long-running commands (no interactive tty).' },
      ],
    },
    {
      platform: 'pfSense shell / console (FreeBSD 14)',
      tasks: [
        { task: 'Console menu', command: ' 1) Assign Interfaces        9) pfTop\n 2) Set interface(s) IP address 10) Filter Logs\n 5) Reboot system            11) Restart webConfigurator\n 8) Shell                    15) Restore recent configuration\n 4) Reset to factory defaults 16) Restart PHP-FPM', explain: 'Shown on the VGA/serial/hypervisor console and after SSH login as admin. Option 8 opens a root shell. Options 1 and 2 fix assignment/addressing when the GUI is unreachable.', risk: 'Option 4 erases the entire configuration. Option 1 can move LAN to another NIC and cut you off.' },
        { task: 'Service status / restart', command: 'pfSsh.php playback svc status unbound\npfSsh.php playback svc restart unbound\npfSsh.php playback svc restart dhcpd', explain: 'The supported way to control pfSense services from the shell: it regenerates configuration from config.xml like the GUI does. Running `service unbound restart` or killing processes bypasses that.' },
        { task: 'Filter reload', command: '/etc/rc.filter_configure\npfctl -nf /tmp/rules.debug', explain: 'Regenerates and reloads the ruleset (like Apply Changes). `pfctl -nf` only parses the file: no output means it would load.' , sim: true },
        { task: 'Inspect rules, NAT, states', command: 'pfctl -sr\npfctl -vvsr | grep -A3 USER_RULE\npfctl -sn\npfctl -ss | grep 10.0.30.25\npfctl -si', explain: '`-sr` filter rules, `-sn` NAT/rdr rules, `-ss` states, `-si` counters and state-table size; `-vv` adds evaluation/packet counters and rule numbers.' , sim: true },
        { task: 'Kill states', command: 'pfctl -k 10.0.30.25\npfctl -k 10.0.30.25 -k 203.0.113.80', explain: 'Kills states from a host (or between two hosts) so the next packet is evaluated against the current rules.', risk: '`pfctl -F states` flushes all states: every connection drops.' , sim: true },
        { task: 'Disable / enable the packet filter (emergency only)', command: 'pfctl -d\npfctl -e', explain: 'Disables pf entirely: all filtering **and NAT** stop. Used only to regain GUI access after a lockout; re-enable (or reload the filter) as soon as the rule is fixed.', risk: 'While disabled, the firewall forwards everything unfiltered and LAN clients lose Internet (no NAT). A filter reload re-enables pf.' , sim: true },
        { task: 'Add an emergency pass rule', command: 'easyrule pass lan tcp 10.0.10.25 10.0.10.1 443\neasyrule block wan 203.0.113.9', explain: 'Adds a real rule to config.xml (top of the interface\'s rules) and reloads the filter. Syntax: `easyrule pass <interface> <proto> <src> <dst> [port]`.' , sim: true },
        { task: 'Logs', command: 'tail -f /var/log/filter.log\ntail -n 50 /var/log/system.log\ntcpdump -n -e -ttt -i pflog0', explain: '2.7.x writes plain-text logs (older 2.4 used circular clog files). `pflog0` shows logged packets live with the rule number.' },
        { task: 'Routes and interfaces', command: 'netstat -rn -f inet\nifconfig -a\nifconfig vtnet1.30', explain: 'FreeBSD routing table and interface state (status: active / no carrier, vlan tag and parent).' },
        { task: 'Why a service failed to start', command: 'tail -n 30 /var/log/resolver.log\ntail -n 30 /var/log/dhcpd.log\nsockstat -4l | grep :53', explain: 'Typical: unbound cannot bind port 53 (dnsmasq running), syntax error in custom options; dhcpd "No subnet declaration for vtnet1.30" (interface has no address in a DHCP-enabled subnet).' },
        { task: 'Restore after a config error', command: 'Console option 15 (Restore recent configuration)\ncp /cf/conf/backup/config-1729500000.xml /cf/conf/config.xml\nrm /tmp/config.cache\nreboot', explain: 'Option 15 lists recent backups and restores one. The manual equivalent copies a backup over config.xml, clears the cache and reboots so every subsystem rereads it.', risk: 'Reboot interrupts all traffic for a minute or two.' },
      ],
    },
  ],
  actions: [
    { action: 'Filter reload (Apply Changes, Status > Filter Reload, /etc/rc.filter_configure)', when: 'After changing firewall rules, aliases, NAT or schedules.', effect: 'Regenerates /tmp/rules.debug and loads it atomically. Existing states continue: new rules affect **new** connections only. If loading fails, the previous ruleset stays.', risk: 'Low. To make a new block apply to existing flows, kill the matching states as well.' },
    { action: 'Service restart (Status > Services, pfSsh.php playback svc restart X)', when: 'After changing that service\'s settings when it did not restart itself, or when it is stopped/hung.', effect: 'Regenerates the service\'s config and restarts only that daemon.', risk: 'Interrupts that service only (DNS cache flushed, VPN clients disconnected). Traffic through the firewall is unaffected.' },
    { action: 'Interface reconfigure (Interfaces > X > Save + Apply Changes; console option 2)', when: 'After changing an interface\'s address, type (DHCP/static), VLAN or MTU.', effect: 'Brings the interface down and up, re-applies addresses, restarts dependent services (DHCP on it, dpinger, VPNs bound to it) and reloads the filter.', risk: 'Every connection over that interface drops; a wrong address cuts off clients (and you, if you manage it through that interface).' },
    { action: 'Reset States', when: 'After NAT changes or to force all flows through new rules; rarely needed.', effect: 'Flushes the whole state table.', risk: 'All connections through and to the firewall break at once, including your session.' },
    { action: 'Reboot (console option 5, Diagnostics > Reboot)', when: 'After firmware updates, manual config.xml edits, or to prove the configuration survives a cold start.', effect: 'Everything reloads from config.xml.', risk: 'Full outage for every network behind the firewall. A changed NIC type or bad config.xml can stop the boot at the assignment prompt: have console access.' },
  ],
  workflow: [
    { question: '1. Is the client in the right network with the right gateway?', command: 'On the client: ip -br addr; ip route\nOn pfSense: Status > DHCP Leases; Status > Interfaces', healthy: 'eth0  UP  10.0.30.25/24\ndefault via 10.0.30.1 dev eth0\nOPT1 (vtnet1.30): up, 10.0.30.1/24', broken: '169.254.x.x or no address → DHCP not reaching pfSense (VLAN tag, DHCP disabled on OPT1, or no rule needed: DHCP has automatic rules). Wrong subnet → client on the wrong VLAN. OPT1 shows "no carrier" or the wrong parent → assignment/hypervisor problem.', next: 'Address and gateway correct → step 2.' },
    { question: '2. Is the interface assignment what you think it is?', command: 'Interfaces > Assignments\nifconfig vtnet1.30', healthy: 'OPT1 → VLAN 30 on vtnet1 - lan (DEV)\nvtnet1.30: flags=...<UP,BROADCAST,RUNNING> ... inet 10.0.30.1 netmask 0xffffff00 ... vlan: 30 vlanproto: 802.1q vlanpcp: 0 parent interface: vtnet1', broken: 'OPT1 assigned to the wrong NIC or VLAN, or WAN and LAN swapped (common after console option 1): the rules you edit are on a different interface than the traffic uses.', next: 'Correct → step 3.' },
    { question: '3. Can the client reach the firewall itself?', command: 'From the client: ping -c 2 10.0.30.1\nDiagnostics > Ping from pfSense to 10.0.30.25 (source OPT1)', healthy: '64 bytes from 10.0.30.1: icmp_seq=1 ttl=64 time=0.4 ms', broken: 'Timeout from the client while pfSense can ping it → OPT1 has no pass rule (a new OPTx interface has **no rules**, so everything is blocked). Neither direction works → Layer 2 (VLAN, switch, assignment).', next: 'Gateway reachable → step 4.' },
    { question: '4. Does a rule on the ingress interface pass the traffic?', command: 'Firewall > Rules > OPT1\nStatus > System Logs > Firewall (filter: 10.0.30.25)', healthy: 'Pass  IPv4 *  DEV subnets  *  *  *  *  Allow DEV to any\n(log shows "USER_RULE: Allow DEV to any" or nothing blocked)', broken: 'Log entries "Default deny rule IPv4 (1000000103)" on OPT1 → no pass rule matched. A block rule above the pass rule → first match wins. Rule edited on the WAN tab instead of OPT1 → rules apply where traffic **enters**.', next: 'Fix or add the rule on OPT1, Apply Changes, and if old flows persist kill their states. Passed → step 5.' },
    { question: '5. Is there a route to the destination?', command: 'Diagnostics > Routes\nnetstat -rn -f inet\nStatus > Gateways', healthy: 'default            192.168.1.1        UGS      vtnet0\n10.0.30.0/24       link#5             U    vtnet1.30\nWANGW 192.168.1.1 Online 0.6ms 0.0%', broken: 'No default route or gateway "Offline" → WAN gateway problem (DHCP lease, upstream). Missing route for an internal network behind another router → add System > Routing > Static Routes. Return path: the remote network must also route back to 10.0.30.0/24 if it is not NATed.', next: 'Route present → step 6.' },
    { question: '6. Is outbound NAT translating the source?', command: 'Firewall > NAT > Outbound (mode, mappings)\nDiagnostics > States (filter 10.0.30.25)\npfctl -ss | grep 10.0.30.25', healthy: 'all tcp 192.168.1.50:21837 (10.0.30.25:51514) -> 203.0.113.80:443       ESTABLISHED:ESTABLISHED', broken: 'State shows SYN_SENT:CLOSED and no (orig) translated address on WAN, or a WAN capture shows source 10.0.30.25 → no NAT mapping for 10.0.30.0/24 (Manual mode does not add new subnets automatically).', next: 'Add the mapping (or switch to Hybrid/Automatic), Apply, kill states of the affected host. NAT fine → step 7.' },
    { question: '7. Does the packet leave and does a reply come back?', command: 'Diagnostics > Packet Capture on OPT1 and on WAN\ntcpdump -ni vtnet0 host 203.0.113.80 and port 443', healthy: 'IP 192.168.1.50.21837 > 203.0.113.80.443: Flags [S] ...\nIP 203.0.113.80.443 > 192.168.1.50.21837: Flags [S.] ...', broken: 'SYN on OPT1 but not on WAN → blocked or not routed/NATed on pfSense (steps 4–6). SYN on WAN without reply → upstream problem (upstream firewall, ISP, server). Reply on WAN but not on OPT1 → state/NAT mismatch (reset the host\'s states).', next: 'Traffic works by IP but not by name → step 8.' },
    { question: '8. Do pfSense services (DNS, DHCP) answer?', command: 'From the client: dig @10.0.30.1 example.com\nStatus > Services; Status > System Logs > System > DNS Resolver', healthy: ';; ->>HEADER<<- opcode: QUERY, status: NOERROR\n;; SERVER: 10.0.30.1#53(10.0.30.1)', broken: 'Timeout → no rule passing DNS to "This Firewall" on OPT1, or unbound stopped. status: REFUSED → unbound access list does not include the client subnet (e.g. a subnet reached through a static route or VPN). SERVFAIL → unbound cannot reach upstream/DNSSEC failure.', next: 'Fix the rule, start unbound or add an access list entry (Services > DNS Resolver > Access Lists).' },
  ],
  failures: [
    { symptom: 'Clients on a new VLAN/OPT interface cannot reach anything, not even the gateway', causes: ['A newly assigned OPT interface has **no firewall rules**, so the implicit default deny blocks everything', 'Interface not enabled or no IPv4 address set', 'VLAN not tagged on the switch/hypervisor trunk'], diagnose: ['Firewall > Rules > OPT1', 'Status > System Logs > Firewall (Default deny on OPT1)', 'Status > Interfaces', 'tcpdump -ni vtnet1 -e vlan 30'], fix: 'Add pass rules on the OPT1 tab (e.g. source OPT1 subnets, destination any, or narrower), Apply Changes. Enable the interface and set its address if missing. Fix the trunk.', verify: 'ping 10.0.30.1 and curl -I https://example.com from a VLAN 30 client' },
    { symptom: 'New subnet can reach other LANs but not the Internet', causes: ['Outbound NAT in Manual mode: no mapping for the new subnet', 'Rule on OPT1 only allows internal destinations', 'Policy routing: rule has a gateway set to a down gateway'], diagnose: ['Firewall > NAT > Outbound', 'pfctl -sn | grep 10.0.30', 'Diagnostics > Packet Capture on WAN (source still private?)', 'Diagnostics > States'], fix: 'Add a Manual/Hybrid mapping: interface WAN, source 10.0.30.0/24, translation Interface Address; or switch to Automatic. Apply and kill the host\'s states.', verify: 'pfctl -ss | grep 10.0.30.25 shows the WAN address as translated source' },
    { symptom: 'Port forward from WAN does not work', causes: ['No associated filter rule (or "None" selected)', 'Block private networks on WAN while testing from an RFC1918 upstream network', 'Testing from inside without NAT reflection', 'Internal server has a different default gateway'], diagnose: ['Firewall > NAT > Port Forward', 'Firewall > Rules > WAN', 'Status > System Logs > Firewall', 'tcpdump -ni vtnet2 host 10.0.20.10 and port 443'], fix: 'Create the port forward with "Add associated filter rule"; untick "Block private networks" only in a lab whose WAN is RFC1918; test from outside or use split DNS (host override) instead of reflection; fix the server gateway.', verify: 'From an external host: curl -I https://<WAN address>/ ; state appears in Diagnostics > States' },
    { symptom: 'Locked out of the webConfigurator after a rule change', causes: ['Anti-lockout rule disabled and the LAN rule edited/removed', 'Block rule placed above the management pass rule', 'Managing via WAN or OPT with no rule to "This Firewall"'], diagnose: ['Console: option 8, pfctl -sr | grep -i anti-lockout', 'tail /var/log/filter.log'], fix: 'From the console: `easyrule pass lan tcp <admin IP> <LAN address> 443`, or `pfctl -d`, fix the rule in the GUI, then `pfctl -e` / reload the filter; or option 15 to restore the previous configuration.', verify: 'GUI reachable from the admin host with pf enabled (pfctl -si shows Status: Enabled)' },
    { symptom: 'A blocked host still has a working connection after the block rule was applied', causes: ['Existing state: rules are evaluated only for new connections'], diagnose: ['Diagnostics > States (filter by host)', 'pfctl -ss | grep <host>'], fix: 'Kill that host\'s states (Diagnostics > States > X, or `pfctl -k <host>`). Do not Reset States for the whole firewall.', verify: 'New connection attempts appear as blocked in the firewall log' },
    { symptom: 'Clients get addresses but DNS fails', causes: ['Unbound stopped (port 53 conflict with DNS Forwarder, bad custom options)', 'No rule on that interface passing DNS to the firewall', 'Unbound access list refuses the subnet', 'DHCP hands out a DNS server the clients cannot reach'], diagnose: ['Status > Services', 'Status > System Logs > System > DNS Resolver', 'dig @10.0.30.1 example.com (status REFUSED?)', 'sockstat -4l | grep :53'], fix: 'Disable dnsmasq if both are enabled, fix custom options, add the DNS rule or an access list entry, restart unbound.', verify: 'dig @10.0.30.1 example.com returns NOERROR' },
    { symptom: 'No Internet for anyone; WAN shows 0.0.0.0 or gateway offline', causes: ['WAN DHCP lease lost (upstream down, cable, MAC change)', 'Static WAN with wrong gateway', 'WAN and LAN swapped by an assignment change'], diagnose: ['Status > Interfaces', 'Status > Gateways', 'Interfaces > Assignments', 'netstat -rn -f inet'], fix: 'Renew/release on Status > Interfaces, correct the static gateway at System > Routing > Gateways, or fix the assignment (console option 1).', verify: 'Diagnostics > Ping 1.1.1.1 from WAN succeeds; default route present' },
    { symptom: 'Rules show "There were error(s) loading the rules"', causes: ['Alias contains an invalid entry (e.g. an unresolvable hostname is fine, a malformed network is not)', 'Rule references a deleted interface or gateway', 'Too many table entries for Firewall Maximum Table Entries'], diagnose: ['Status > System Logs > System > General', 'pfctl -nf /tmp/rules.debug'], fix: 'Fix the item quoted by the error (the line of /tmp/rules.debug points to it). The previous ruleset stays loaded until then.', verify: 'Status > Filter Reload completes with "done"; pfctl -nf /tmp/rules.debug prints nothing' },
  ],
  verification: [
    { check: 'Packet filter enabled and state table healthy', command: 'pfctl -si | head -5', expect: 'Status: Enabled for 0 days 02:14:07           Debug: Urgent\n...\n  current entries                      214' },
    { check: 'Assignments as designed', command: 'Interfaces > Assignments (or console banner)', expect: 'WAN (wan) -> vtnet0, LAN (lan) -> vtnet1, OPT1 (opt1) -> vtnet1.30' },
    { check: 'Default route and gateway online', command: 'netstat -rn -f inet | grep default; Status > Gateways', expect: 'default 192.168.1.1 UGS vtnet0; WANGW Online' },
    { check: 'Rules in effect contain your rule', command: 'pfctl -sr | grep "Allow DEV"', expect: 'pass in quick on vtnet1.30 inet from 10.0.30.0/24 to any flags S/SA keep state label "USER_RULE: Allow DEV to any"' },
    { check: 'NAT mapping present for every internal subnet', command: 'pfctl -sn | grep vtnet0', expect: 'nat on vtnet0 inet from 10.0.30.0/24 to any -> 192.168.1.50 port 1024:65535' },
    { check: 'Services running', command: 'Status > Services', expect: 'unbound, dhcpd, dpinger, ntpd: running' },
    { check: 'End-to-end from a client of each segment', command: 'ping 10.0.30.1; dig example.com; curl -I https://example.com', expect: 'replies, NOERROR, HTTP/2 200' },
    { check: 'Configuration exported off the box', command: 'Diagnostics > Backup & Restore > Download configuration as XML', expect: 'config-pfSense.home.arpa-<date>.xml stored in your backup location' },
  ],
  refIds: ['pfctl', 'pfsense-console', 'tcpdump', 'dig', 'file:config.xml', 'file:pfsense-conf-backup', 'file:pfsense-rules-debug', 'file:pfsense-filter-log', 'file:unbound-conf', 'proc:pfsense-lockout', 'proc:pfsense-restore-config', 'proc:pfsense-service-restart', 'proc:safe-config-change', 'proc:rollback', 'proc:incident-record'],
};

export const PFSENSE_LESSON: Lesson = {
  id: 'pfsense',
  moduleId: 'D',
  title: 'pfSense: firewall, NAT and troubleshooting',
  level: 'intermediate',
  summary: 'How a pfSense firewall assigns interfaces, routes, filters and translates traffic, where its configuration and logs live, and how to find out (and safely fix) why traffic is blocked.',
  concepts: ['pfsense.rules', 'pfsense.nat', 'fw.stateful', 'fw.path', 'net.nat', 'net.vlan', 'net.routing', 'net.dhcp', 'dns.resolution', 'ops.recovery'],
  mode: 'simulated',
  guide: PFSENSE_GUIDE,
  caseStudyIds: ['pfsense-blocks'],
  objectives: ['N10-009:1.2', 'N10-009:2.1', 'N10-009:2.2', 'N10-009:3.4', 'N10-009:4.3', 'N10-009:5.3', 'N10-009:5.5', '200-301:4.1', '200-301:5.6'],

  what: `
**pfSense CE** (Community Edition) is an open-source firewall and router distribution built on FreeBSD and the **pf** packet filter, managed through a web interface. It is a common perimeter firewall in small and medium networks and labs, and the network appliance you are most likely to meet next to Linux servers.

It does in one box what the lab's rtr01 does with several Linux components:

| Function | Linux router (rtr01) | pfSense |
|---|---|---|
| Interfaces, VLANs | /etc/network/interfaces, \`eth3.30\` | Interfaces > Assignments, \`vtnet1.30\` |
| Routing | \`ip route\`, \`net.ipv4.ip_forward\` | System > Routing; always forwards |
| Filtering | nftables forward chain | Firewall > Rules (per interface) |
| NAT | nftables \`masquerade\`, \`dnat\` | Firewall > NAT (Outbound, Port Forward, 1:1) |
| DHCP / DNS | isc-dhcp-server, bind9 on ns1 | Services > DHCP Server, DNS Resolver (unbound) |

### In the simulator
The lab's perimeter firewall **fw01** is a simulated pfSense CE 2.7.2: WAN \`vtnet0\` 203.0.113.10, LAN \`vtnet1\` 10.0.20.254 (server network; rtr01 routes the internal networks 10.0.0.0/16 to it), DMZ (opt1) \`vtnet2\` 172.16.50.1/24 with the web server **dmz01** (172.16.50.10, published as portal.corp.lab). Its state is \`/conf/config.xml\`, compiled into a pf ruleset with pf's semantics (ingress filtering, first match, keep state, rdr before filtering, outbound NAT, logged default deny). You can use the **webConfigurator** (Interfaces, Aliases, Rules, NAT, Firewall log, States) from a browser on ws01 and the console shell (\`pfctl\`, \`easyrule\`, \`viconfig\`, \`/etc/rc.filter_configure\`, \`ifconfig\`, \`netstat -rn\`, \`/var/log/filter.log\`). The sandbox below, the pfSense tickets and **Lab 3** run on it. DHCP and DNS services, VLANs, VPNs, gateway monitoring, floating rules and packages are not simulated; for those, the examples in this lesson are from real systems.

### The example network
- **WAN** = \`vtnet0\`, DHCP from an upstream router: 192.168.1.50/24, gateway 192.168.1.1 (an RFC1918 address: typical of labs and home networks).
- **LAN** = \`vtnet1\`, 10.0.10.1/24 (office, admin workstation 10.0.10.25).
- **OPT1 "DEV"** = \`vtnet1.30\` (VLAN 30 on vtnet1), 10.0.30.1/24, client dev01 10.0.30.25.
- **OPT2 "SERVERS"** = \`vtnet2\`, 10.0.20.1/24, srv01 10.0.20.10.

### What pfSense is not
- It is not a switch: VLAN tags must be carried to it on a trunk by the switch or hypervisor.
- It does not filter traffic that never crosses it (two hosts in the same VLAN talk directly).
- It is not configured by editing files: the GUI (or console menu) writes \`config.xml\`, from which everything else is generated.
`,

  internals: `
### Interfaces: physical, logical and VLAN
pfSense separates the **physical** interface (driver name + unit: \`vtnet0\` on KVM/Proxmox VirtIO, \`igb0\`/\`igc0\` on Intel NICs, \`em0\` on e1000, \`vmx0\` on VMware) from the **logical** name used everywhere in the GUI and config: \`wan\`, \`lan\`, \`opt1\`, \`opt2\`… (you can add a description such as DEV). Rules, DHCP and NAT refer to the logical name, so if an assignment changes, all of them silently follow the new NIC.
- Assign at **Interfaces > Assignments**, or from the console with **option 1 "Assign Interfaces"** (it first asks "Should VLANs be set up now?", then which NIC is WAN, LAN and optional interfaces).
- Address them with **option 2 "Set interface(s) IP address"** (also offers to enable DHCP on LAN and to revert the GUI to HTTP) or at Interfaces > (name).
- A **VLAN** is created at Interfaces > Assignments > VLANs (parent \`vtnet1\`, tag 30), which creates \`vtnet1.30\`; it must then be **assigned** (becomes OPTx), **enabled**, and given an address. The parent carries untagged LAN traffic and the tagged VLANs on the same wire, so the switch port must be a trunk.

### WAN and LAN
- WAN is usually DHCP (from an ISP or upstream router) or static with an explicit **gateway** (System > Routing > Gateways). An interface with a gateway set is treated as a WAN-type interface: automatic outbound NAT translates traffic leaving it, and it gets no automatic "allow" rules.
- On WAN the wizard ticks **Block private networks and loopback addresses** and **Block bogon networks**. These automatic rules drop inbound packets from RFC1918 (10/8, 172.16/12, 192.168/16) and unassigned address space. In a lab where the WAN itself is 192.168.1.0/24, every connection *initiated* from the upstream network (port forwards, GUI on WAN, VPN from the upstream LAN) is dropped before your WAN rules are evaluated. Untick it only when the WAN really is a private network.
- LAN gets two default rules: **Default allow LAN to any rule** (IPv4 and IPv6) and the **anti-lockout rule**, an automatic rule that always passes the webGUI and SSH ports to the LAN address (System > Advanced > Admin Access to disable it).

### Routing
Diagnostics > Routes (or \`netstat -rn -f inet\` in the shell) shows the FreeBSD routing table: connected networks, the default route via the default gateway, and static routes from System > Routing > Static Routes. **dpinger** pings each gateway's monitor IP; a gateway marked down can be removed from the routing table or fail over in a gateway group. A firewall rule may set a **gateway** (policy routing), which overrides the routing table for traffic matching that rule; note that this also sends traffic for local networks out of that gateway unless a rule above it passes local traffic without a gateway.

### Firewall rules: where and in which order
- Rules are configured **per interface** and evaluated on the interface where the traffic **enters** pfSense. To control what VLAN 30 can reach, edit the **OPT1** tab, not WAN. Outbound traffic is passed automatically.
- Order: floating rules (quick) → interface group rules → interface rules, each **top to bottom, first match wins** (pfSense generates \`quick\` rules).
- If nothing matches: **implicit default deny** ("Default deny rule IPv4/IPv6", logged by default).
- A **newly assigned OPT interface has no rules**, so everything entering it is blocked, including ping to its own gateway (DHCP is the exception: the DHCP server adds automatic rules).
- **Floating rules** apply to several interfaces and directions, and can be non-quick (last match wins); use them sparingly (traffic shaping, "block this everywhere").
- **Aliases** (Firewall > Aliases) name hosts, networks, ports or URL tables; they become pf tables and keep rules readable.
- Changes take effect on **Apply Changes**: the whole ruleset is regenerated and reloaded atomically. **Existing states keep flowing** until they expire or are killed: a new block rule does not cut a connection that is already established.

### NAT
- **Outbound NAT** (Firewall > NAT > Outbound) rewrites the source of traffic leaving a WAN-type interface. Modes: **Automatic** (generated mappings for every internal subnet), **Hybrid** (your manual mappings first, then automatic ones), **Manual** (only your mappings; when you switch to Manual the current automatic ones are copied, but **subnets added later are not**), **Disabled**.
- **Port Forward** (destination NAT, \`rdr\`) translates inbound WAN traffic to an internal host. The rdr happens before filtering, so the filter rule must match the **internal** address and port: use "Add associated filter rule".
- **NAT reflection** lets internal clients use the public address of a port forward (System > Advanced > Firewall & NAT, disabled by default). Split DNS (a DNS Resolver host override pointing to the internal address) is usually cleaner.
- **1:1 NAT** maps a whole external address to one internal address in both directions.

### States
Every passed connection creates a **state** (Diagnostics > States; \`pfctl -ss\`). Replies match the state, not the rules, which is why you never write rules for return traffic. \`pfctl -si\` shows the table size and counters; the limit is Firewall Maximum States (System > Advanced > Firewall & NAT). **Reset States** flushes the whole table and drops every connection; killing the states of one host (\`pfctl -k 10.0.30.25\`) is the targeted alternative.

### Services on the firewall
- **DHCP** (Services > DHCP Server, one tab per static interface). pfSense 2.7.x has two back-ends: **ISC DHCP** (default in 2.7.2, deprecated upstream) and **Kea** (System > Advanced > Networking > Server Backend). Leases: Status > DHCP Leases.
- **DNS Resolver** (unbound, Services > DNS Resolver): resolves recursively by default (or forwards to System > General DNS servers in forwarding mode), registers DHCP leases if asked, supports **host overrides**. It answers subnets of local interfaces automatically; other subnets (behind static routes, VPN) need an **access list** entry or get REFUSED. Its config is generated as \`/var/unbound/unbound.conf\`. The **DNS Forwarder** (dnsmasq) is the alternative; only one can use port 53.
- **VPN**: OpenVPN (VPN > OpenVPN), IPsec (VPN > IPsec), WireGuard (package). Each VPN gets its own **rules tab** (OpenVPN, IPsec, WireGuard); traffic arriving through the tunnel is filtered there, so a working tunnel with an empty tab passes nothing. Check: Status > Services, Status > OpenVPN / IPsec / WireGuard, the VPN log tab, and the WAN rule allowing the VPN port.

### Logs and captures
- **Status > System Logs > Firewall** shows logged packets (default block rules log; pass rules only if "Log" is ticked on the rule). Each entry's icon names the matching rule; the **Easy Rule** icons add a pass or block rule for that source in one click.
- Raw: \`/var/log/filter.log\`, one CSV line per packet:
\`\`\`
Oct 21 09:14:02 pfSense filterlog[40312]: 5,,,1000000103,vtnet1.30,match,block,in,4,0x0,,64,51344,0,DF,6,tcp,60,10.0.30.25,10.0.20.10,51514,443,0,S,3912442117,,64240,,mss;sackOK;TS;nop;wscale
\`\`\`
  Rule number 5, tracker 1000000103 (default deny IPv4), interface vtnet1.30, block, in, IPv4 … TCP 10.0.30.25:51514 → 10.0.20.10:443, flags S (a new connection).
- **Diagnostics > Packet Capture** runs tcpdump on an interface. From the shell: \`tcpdump -ni vtnet1.30 host 10.0.30.25\` (on the parent, \`tcpdump -ni vtnet1 vlan 30 and host 10.0.30.25\`, because frames there carry the tag).
- **Diagnostics > Ping / Traceroute / Test Port** test from the firewall with a chosen source address; **Diagnostics > Command Prompt** runs shell commands from the GUI.

### config.xml: the single source of truth
Everything above is stored in \`/cf/conf/config.xml\`. The GUI validates input, writes the file, keeps the previous version in \`/cf/conf/backup/\` (Diagnostics > Backup & Restore > Config History), and then reloads the affected subsystem, which **regenerates** the real configuration (\`/tmp/rules.debug\`, \`/var/unbound/unbound.conf\`, \`/var/dhcpd/etc/dhcpd.conf\`…). Editing those generated files is pointless (they are overwritten); editing config.xml by hand skips validation and history, is not applied until the subsystem reloads, is shadowed by \`/tmp/config.cache\`, and an XML error can stop the next boot. If a hand edit is truly unavoidable: back up the file, edit, \`rm /tmp/config.cache\`, then reload the subsystem or reboot.
`,

  deployment: [
    {
      id: 'pfsense-install',
      platform: 'pfSense CE 2.7.2',
      summary: 'Install pfSense in a VM with three NICs, assign WAN/LAN, run the setup wizard, then add VLAN 30 as OPT1 with DHCP, firewall rules and a check of outbound NAT. Representative of pfSense CE 2.7.2 (FreeBSD 14) on KVM/Proxmox with VirtIO NICs; on VMware or hardware the NIC names differ (vmx0, igb0, em0).',
      prerequisites: [
        'A hypervisor VM: 1–2 vCPU, 1 GB RAM (2 GB recommended), 16 GB disk, NICs: WAN bridge, LAN trunk (VLAN-aware bridge), servers bridge.',
        'The pfSense CE 2.7.2 installer ISO (netgate installer or CE ISO) and console access to the VM.',
        'Note the MAC address of each virtual NIC so you can tell them apart during assignment.',
      ],
      steps: [
        { title: 'Install', command: 'Boot the ISO > Install pfSense > Auto (ZFS) > Stripe > select disk > Reboot', what: 'Installs FreeBSD + pfSense to the disk with the default ZFS layout.', why: 'ZFS boot environments make rollbacks after upgrades possible; defaults are fine for a lab.', expected: 'Installation complete. Remove the installation media and reboot.' },
        { title: 'Assign interfaces (console option 1)', command: 'Should VLANs be set up now [y|n]? n\nEnter the WAN interface name or \'a\' for auto-detection: vtnet0\nEnter the LAN interface name or \'a\' for auto-detection: vtnet1\nEnter the Optional 1 interface name or \'a\' for auto-detection\n(or nothing if finished): (Enter)\nDo you want to proceed [y|n]? y', what: 'Maps logical WAN and LAN to physical NICs (vtnet2 for the servers can be assigned later as OPT2). The console prints the valid interfaces with their MAC addresses and link state.', why: 'Every rule and service refers to logical names; if WAN and LAN are swapped here, the default LAN rules end up on the Internet-facing NIC and nothing works.', expected: 'Valid interfaces are:\nvtnet0   bc:24:11:4e:01:10   (up) VirtIO Networking Adapter\nvtnet1   bc:24:11:4e:01:11   (up) VirtIO Networking Adapter\nvtnet2   bc:24:11:4e:01:12   (up) VirtIO Networking Adapter' },
        { title: 'Set the LAN address (console option 2)', command: 'Enter the number of the interface you wish to configure: 2 (LAN)\nConfigure IPv4 address LAN interface via DHCP? (y/n) n\nEnter the new LAN IPv4 address: 10.0.10.1\nEnter the new LAN IPv4 subnet bit count: 24\nDo you want to enable the DHCP server on LAN? (y/n) y\nEnter the start address of the IPv4 client address range: 10.0.10.100\nEnter the end address of the IPv4 client address range: 10.0.10.199', what: 'Sets the LAN address and DHCP range from the console.', why: 'The default LAN is 192.168.1.1/24, which collides with a 192.168.1.0/24 WAN: pfSense would have the same network on two interfaces.', expected: 'The IPv4 LAN address has been set to 10.0.10.1/24\nYou can now access the webConfigurator by opening the following URL in your web browser:\n                https://10.0.10.1/' },
        { title: 'Check the console banner', command: '(console main menu)', what: 'The banner lists each logical interface, its NIC and address.', why: 'Quickest proof that assignment and addressing are what you intended, before touching the GUI.', expected: '*** Welcome to pfSense 2.7.2-RELEASE (amd64) on pfSense ***\n\n WAN (wan)       -> vtnet0     -> v4/DHCP4: 192.168.1.50/24\n LAN (lan)       -> vtnet1     -> v4: 10.0.10.1/24' },
        { title: 'Run the setup wizard', command: 'Browse https://10.0.10.1 from 10.0.10.25, log in admin / pfsense > System > Setup Wizard', what: 'Sets hostname/domain, DNS servers, time zone, WAN type, LAN address and a new admin password.', why: 'The default password is public. On the WAN page, untick "Block RFC1918 Private Networks" only because this lab WAN is 192.168.1.0/24.', expected: 'Wizard completed. Congratulations! pfSense is now configured.' },
        { title: 'Create VLAN 30', command: 'Interfaces > Assignments > VLANs > Add: Parent vtnet1, VLAN Tag 30, Description DEV > Save', what: 'Creates the 802.1Q subinterface vtnet1.30.', why: 'VLAN 30 arrives tagged on the LAN trunk; pfSense needs a subinterface to receive it.', expected: 'vtnet1.30   vtnet1   30   DEV' },
        { title: 'Assign and address OPT', command: 'Interfaces > Assignments > Available network ports: VLAN 30 on vtnet1 > Add\nInterfaces > OPT1: Enable, Description DEV, IPv4 Configuration Type: Static IPv4, 10.0.30.1/24, IPv4 Upstream gateway: None > Save > Apply Changes', what: 'Turns the VLAN into a logical interface with an address.', why: 'Upstream gateway must be **None** on internal interfaces: setting one would make pfSense treat it as a WAN (outbound NAT on it, no automatic NAT for its subnet).', expected: 'Interfaces > Assignments: DEV  VLAN 30 on vtnet1 - lan (DEV)' },
        { title: 'Enable DHCP on DEV', command: 'Services > DHCP Server > DEV: Enable, Address Pool Range 10.0.30.100 – 10.0.30.199 > Save', what: 'Starts serving leases on vtnet1.30 (automatic rules allow DHCP itself).', why: 'Without it, clients self-assign 169.254.x.x addresses. DNS and gateway default to the interface address 10.0.30.1.', expected: 'Status > DHCP Leases: 10.0.30.100  bc:24:11:7a:30:25  dev01  active' },
        { title: 'Add firewall rules on DEV', command: 'Firewall > Rules > DEV > Add (top):\n  Pass, IPv4, TCP/UDP, Source DEV subnets, Destination This Firewall, port 53 (DNS)\n  Block, IPv4, any, Source DEV subnets, Destination LAN subnets, Log\n  Pass, IPv4, any, Source DEV subnets, Destination any, Description "Allow DEV to any"\n> Save > Apply Changes', what: 'Allows DNS to the firewall, blocks the office LAN, allows everything else (the Internet and servers).', why: 'A new OPT interface has **no rules**: without these, everything from VLAN 30 hits the default deny. Order matters: the block must be above the broad pass.', expected: 'The changes have been applied successfully. The firewall rules are now reloading in the background.' },
        { title: 'Check outbound NAT', command: 'Firewall > NAT > Outbound', what: 'Shows the mode and the mappings in effect.', why: 'In Automatic or Hybrid mode, 10.0.30.0/24 appears automatically. In **Manual** mode it does not: add a mapping (Interface WAN, Source 10.0.30.0/24, Translation Interface address).', expected: 'Automatic Rules:\nWAN  10.0.30.0/24  *  *  500  WAN address  *  Auto created rule for ISAKMP - DEV to WAN\nWAN  10.0.30.0/24  *  *  *    WAN address  *  Auto created rule - DEV to WAN' },
        { title: 'Verify from a VLAN 30 client and on pfSense', command: 'dev01$ ip -br addr; ping -c 2 10.0.30.1; dig example.com; curl -I https://example.com\npfSense shell: pfctl -ss | grep 10.0.30.100', what: 'End-to-end test plus the NATed state on the firewall.', why: 'Proves VLAN, DHCP, rules, DNS and NAT together; also test that 10.0.10.0/24 is blocked as intended.', expected: 'all tcp 192.168.1.50:18322 (10.0.30.100:41862) -> 93.184.215.14:443       ESTABLISHED:ESTABLISHED' },
        { title: 'Export the configuration', command: 'Diagnostics > Backup & Restore > Backup area: All > Download configuration as XML', what: 'Saves config.xml off the firewall.', why: 'The local history in /cf/conf/backup is lost with the disk; an exported XML restores the whole firewall onto a fresh install.', expected: 'config-pfSense.home.arpa-20261021091500.xml' },
      ],
    },
    {
      id: 'pfsense-linux',
      platform: 'Linux (equivalent concepts)',
      summary: 'On Linux the same router is built from separate parts, which is what the simulator\'s rtr01 runs: VLAN subinterfaces in /etc/network/interfaces, `net.ipv4.ip_forward=1`, an nftables forward chain (the equivalent of per-interface pfSense rules, but one chain for all interfaces, matched with `iifname`), `masquerade` in a postrouting NAT chain (outbound NAT), `dnat` (port forward), conntrack (the state table), isc-dhcp-server and a DNS server. See the nftables and NAT lessons for hands-on practice in the simulator.',
      prerequisites: ['Debian 12 router VM (or the simulator\'s rtr01).'],
      steps: [
        { title: 'pfSense concept → Linux command', command: 'pfctl -sr        → nft list chain inet filter forward\npfctl -sn        → nft list table ip nat\npfctl -ss        → conntrack -L\npfctl -k HOST    → conntrack -D -s HOST\nnetstat -rn      → ip route\nfilter.log       → journalctl -k (log prefix)', what: 'Maps the pfSense diagnostic commands to their Linux equivalents.', why: 'The reasoning (ingress interface, first match, states, NAT before/after routing) is the same; only the tools differ. One difference: nftables chain policy and rule order are yours to write, pfSense generates both.', expected: '' },
      ],
    },
    {
      id: 'pfsense-windows',
      platform: 'Windows Server 2019/2022',
      summary: 'Not applicable as a perimeter firewall. Windows Defender Firewall is a host firewall (it protects the server itself); RRAS (Routing and Remote Access) can route and NAT between interfaces and terminate VPNs, but it is not used as a network firewall in production. Windows Server can run pfSense as a Hyper-V guest (Generation 2 VM, Secure Boot disabled, hv_netvsc NICs appear as `hn0`, `hn1`).',
      prerequisites: ['Hyper-V role if you want to host pfSense as a VM.'],
      steps: [
        { title: 'Hyper-V: VLAN trunk to the pfSense VM', command: 'Set-VMNetworkAdapterVlan -VMName pfSense -VMNetworkAdapterName LAN -Trunk -AllowedVlanIdList "30" -NativeVlanId 0', what: 'Lets tagged VLAN 30 frames reach the pfSense LAN NIC.', why: 'Without trunk mode Hyper-V strips or drops tagged frames and the pfSense VLAN interface sees nothing.', expected: '(no output on success)' },
      ],
    },
    {
      id: 'pfsense-docker',
      platform: 'Docker / Compose',
      summary: 'Not applicable: pfSense is a complete FreeBSD operating system with its own kernel (pf), and cannot run in a Linux container. Run it as a VM. OPNsense, a fork with a similar model (per-interface rules, config.xml, /conf), is also VM/hardware only. Docker hosts behind pfSense are ordinary clients; published container ports are reached through port forwards to the Docker host.',
      prerequisites: [],
      steps: [
        { title: 'Reach a published container through pfSense', command: 'Firewall > NAT > Port Forward > Add: Interface WAN, Protocol TCP, Destination WAN address, port 8443, Redirect target IP 10.0.20.10, port 8443, Filter rule association: Add associated filter rule', what: 'Forwards WAN:8443 to the Docker host that publishes the container port.', why: 'Docker publishes on the host; pfSense only needs to forward to the host address.', expected: 'Firewall > Rules > WAN shows "NAT Pass to 10.0.20.10:8443"' },
      ],
    },
    {
      id: 'pfsense-linux-distros',
      platform: 'Ubuntu/Debian, RHEL-compatible',
      summary: 'Not applicable: pfSense is not a package for Linux distributions. Linux clients and servers behind pfSense need only the correct gateway and DNS (normally from pfSense DHCP).',
      prerequisites: [],
      steps: [
        { title: 'Check a Linux client behind pfSense', command: 'ip -br addr\nip route\nresolvectl status   # Ubuntu (systemd-resolved)\ncat /etc/resolv.conf # Debian/RHEL', what: 'Address, default gateway (the pfSense interface address) and DNS server.', why: 'Most "pfSense is blocking" tickets start with a client on the wrong VLAN or with the wrong gateway.', expected: 'default via 10.0.30.1 dev eth0 proto dhcp' },
      ],
    },
  ],

  configIntro: `
pfSense settings are made in the GUI and stored in \`/cf/conf/config.xml\`. The table explains the settings that most often decide whether traffic flows, their defaults in pfSense CE 2.7.2 and their security impact. Generated files (rules.debug, unbound.conf, dhcpd.conf) are listed for **reading** during diagnosis, not for editing.
`,

  configFiles: [
    {
      platform: 'pfSense CE 2.7.2 (configuration)',
      items: [
        { path: '/cf/conf/config.xml', purpose: 'All settings; single source of truth (/conf is a symlink to /cf/conf).' },
        { path: '/cf/conf/backup/', purpose: 'Automatic previous revisions; Diagnostics > Backup & Restore > Config History; console option 15.' },
        { path: '/tmp/config.cache', purpose: 'Parsed cache of config.xml; delete after a manual edit.' },
        { path: '/tmp/rules.debug', purpose: 'Generated pf ruleset loaded by pfctl -f (read-only for you).' },
        { path: '/var/unbound/unbound.conf', purpose: 'Generated DNS Resolver configuration; host_entries.conf holds host overrides.' },
        { path: '/var/dhcpd/etc/dhcpd.conf', purpose: 'Generated ISC DHCP configuration (Kea: /usr/local/etc/kea/kea-dhcp4.conf).' },
      ],
    },
    {
      platform: 'pfSense CE 2.7.2 (logs and state)',
      items: [
        { path: '/var/log/filter.log', purpose: 'Firewall log (Status > System Logs > Firewall).' },
        { path: '/var/log/system.log', purpose: 'General system log, rule load errors, check_reload_status.' },
        { path: '/var/log/resolver.log, dhcpd.log, gateways.log, openvpn.log, ipsec.log', purpose: 'Per-service logs (System Logs tabs).' },
        { path: '/var/dhcpd/var/db/dhcpd.leases', purpose: 'ISC DHCP leases (Kea: /var/lib/kea/dhcp4.leases); Status > DHCP Leases.' },
        { path: 'pfctl -ss / -si', purpose: 'State table and counters (Diagnostics > States).' },
      ],
    },
  ],

  directives: [
    { name: 'Interfaces > WAN: Block private networks and loopback addresses', compiledDefault: 'Checked on WAN (wizard default)', recommended: 'Checked when WAN is public; unchecked when WAN is an RFC1918 lab/upstream network', explanation: 'Automatic rule at the top of WAN blocking inbound packets whose source is 10/8, 172.16/12, 192.168/16 or 127/8.', security: 'Protects a public WAN from spoofed private sources. In a lab with a 192.168.x WAN it silently breaks every inbound test from the upstream network (blocked before your rules).' },
    { name: 'Interfaces > WAN: Block bogon networks', compiledDefault: 'Checked on WAN', recommended: 'Checked on a public WAN', explanation: 'Blocks inbound sources from unallocated/reserved space (list updated periodically).', security: 'Low cost, filters obvious spoofing; can block legitimate traffic briefly when a range is newly allocated and the list is stale.' },
    { name: 'System > Advanced > Admin Access: Anti-lockout', compiledDefault: 'Enabled (rule on LAN, or WAN if it is the only interface)', recommended: 'Keep enabled until a tested management rule exists', explanation: 'Automatic rule passing the webGUI and SSH ports to the LAN address from LAN, regardless of user rules.', security: 'Any LAN host can reach the login page; disable only after adding a narrower management rule (source = admin alias).' },
    { name: 'Firewall > Rules > LAN: Default allow LAN to any rule', compiledDefault: 'Present (IPv4 and IPv6)', recommended: 'Replace with explicit rules in segmented networks', explanation: 'Pass rule letting the LAN reach everything, including other OPT networks.', security: 'Without a block above it, LAN can reach every internal segment: segmentation is only as strict as the ingress rules of each interface.' },
    { name: 'New OPT interface rules', compiledDefault: 'No rules (default deny)', recommended: 'Add explicit pass rules after assignment', explanation: 'Interfaces other than LAN start empty, so all traffic entering them is blocked.', security: 'Fail-closed, which is good; the usual symptom is "new VLAN cannot reach its gateway".' },
    { name: 'Firewall > NAT > Outbound: Mode', compiledDefault: 'Automatic outbound NAT rule generation', recommended: 'Automatic, or Hybrid when you need a few custom mappings', explanation: 'Automatic: mappings for every local subnet. Hybrid: manual first, then automatic. Manual: only listed mappings; new subnets are NOT added. Disabled: no outbound NAT (routed public networks).', security: 'Manual mode is where forgotten subnets lose Internet access; it also makes NAT changes explicit and reviewable.' },
    { name: 'Port Forward: Filter rule association', compiledDefault: 'Add associated filter rule', recommended: 'Add associated filter rule (restrict source if possible)', explanation: 'Creates a WAN pass rule matching the internal target, linked to the port forward so edits follow.', security: '"None" means the forward exists but is blocked by default deny; a "Pass" association hides the rule from the WAN tab, which makes reviews harder.' },
    { name: 'System > Advanced > Firewall & NAT: NAT Reflection mode for port forwards', compiledDefault: 'Disabled', recommended: 'Disabled; use split DNS (host overrides)', explanation: 'NAT + proxy or Pure NAT lets internal clients reach a port forward via the public address.', security: 'Reflection adds hidden NAT rules and hairpin traffic through the firewall; split DNS keeps internal traffic internal.' },
    { name: 'System > Advanced > Firewall & NAT: Firewall Maximum States', compiledDefault: 'Auto (about 10% of RAM; roughly 100 000 per GB)', recommended: 'Default unless pfctl -si shows the table near the limit', explanation: 'Size of the pf state table.', security: 'A full table drops new connections (state-insert failures in pfctl -si); a DoS can fill it.' },
    { name: 'Status > System Logs > Settings: Log firewall default blocks', compiledDefault: 'Default block rules logged; pass rules not logged', recommended: 'Keep; tick "Log" on important pass and block rules', explanation: 'Controls whether the automatic default deny and bogon/private blocks write to filter.log.', security: 'Without logging you cannot prove which rule dropped a packet; on a noisy WAN, rotate logs or send them to a syslog server.' },
    { name: 'Services > DNS Resolver: Access Lists', compiledDefault: 'Automatic allow for subnets of local interfaces', recommended: 'Add entries for subnets behind static routes or VPNs', explanation: 'Unbound answers only the networks it allows; others get REFUSED.', security: 'Prevents the firewall from becoming an open resolver on WAN.' },
    { name: 'System > Advanced > Networking: DHCP Server Backend', compiledDefault: 'ISC DHCP (2.7.2)', recommended: 'ISC for stability in 2.7.2 labs; Kea if you need it and accept its feature gaps in 2.7.x', explanation: 'Selects the DHCPv4/v6 daemon; settings pages stay the same.', security: 'ISC DHCP is end-of-life upstream; Netgate moved new development to Kea.' },
  ],

  troubleshootingIntro: `
### Which layer on pfSense made the decision?
1. **Client side first.** Address, mask, gateway and DNS from DHCP; is the client in the VLAN you think? (Status > DHCP Leases.)
2. **Interface assignment.** Is OPT1 really \`vtnet1.30\`? Are WAN and LAN swapped? Is the interface enabled with the right address? (Interfaces > Assignments, Status > Interfaces.)
3. **Rules on the ingress interface.** Firewall log filtered by the client IP: "Default deny rule" means no pass rule matched on the interface where the packet **entered**. A new OPT interface has none. A block above a pass wins. Floating rules come first.
4. **States.** A rule change does not affect existing connections: kill the host's states before concluding the rule "does not work". Conversely, a connection that still works after you blocked it is a state, not a broken rule.
5. **Routing.** Diagnostics > Routes: default route, static routes to internal networks, gateway status. Does the far side have a route back (only needed when traffic is not NATed)?
6. **NAT.** Outbound mode (Manual forgets new subnets), port forward with its associated rule, the internal server's gateway pointing to pfSense, Block private networks on a lab WAN.
7. **Capture to prove it.** Diagnostics > Packet Capture on the ingress and egress interface: where does the packet stop, and is its source translated?

### Fix safely
- Change one thing, Apply, test, and note it (config history records each save).
- Prefer **filter reload** (Apply) and targeted **state kills** over Reset States, interface re-saves or reboots.
- Before changing rules that carry your own management traffic, keep the console reachable. If you lock yourself out: console → option 8 → \`easyrule pass lan tcp 10.0.10.25 10.0.10.1 443\`, or \`pfctl -d\` (filtering and NAT stop), fix the rule in the GUI, \`pfctl -e\` / reload the filter; or console option 15 to restore the previous configuration.
- Never fix a block by disabling pf or adding "any to any" on WAN; fix the specific rule.
`,

  errorMap: [
    { message: 'Connection timed out (client), firewall log: Default deny rule IPv4 (1000000103) on OPT1', layer: 'Firewall rules (ingress interface)', meaning: 'No pass rule matched on the interface where the traffic entered; new OPT interfaces have no rules.', firstCheck: 'Status > System Logs > Firewall filtered by client IP; Firewall > Rules > OPT1' },
    { message: 'Ping to own gateway 10.0.30.1 fails, DHCP lease works', layer: 'Firewall rules', meaning: 'DHCP has automatic rules; ICMP and everything else on a new OPT interface does not.', firstCheck: 'Firewall > Rules > OPT1 (empty?)' },
    { message: 'Internal networks reachable, Internet times out', layer: 'Outbound NAT / gateway', meaning: 'Source not translated (Manual outbound NAT without the subnet), or default gateway down.', firstCheck: 'Firewall > NAT > Outbound; Status > Gateways; capture on WAN' },
    { message: 'ping: sendto: No route to host / Destination Host Unreachable from 10.0.30.1', layer: 'Routing', meaning: 'pfSense has no route for the destination (no default route or missing static route).', firstCheck: 'Diagnostics > Routes; System > Routing > Static Routes' },
    { message: 'Port forward times out from outside', layer: 'NAT + WAN rules', meaning: 'Missing associated filter rule, Block private networks with an RFC1918 test client, or the internal server routes replies elsewhere.', firstCheck: 'Firewall > NAT > Port Forward; Firewall > Rules > WAN; capture on the server interface' },
    { message: 'Port forward works from outside, not from inside using the public address', layer: 'NAT reflection', meaning: 'Internal clients hit the WAN address; reflection is disabled by default.', firstCheck: 'Use a DNS Resolver host override (split DNS) or enable reflection' },
    { message: 'Temporary failure in name resolution / dig status: REFUSED from 10.0.30.1', layer: 'DNS Resolver', meaning: 'Unbound stopped, no rule to This Firewall port 53, or the subnet is not in unbound access lists.', firstCheck: 'Status > Services; dig @10.0.30.1; Services > DNS Resolver > Access Lists' },
    { message: 'Client has 169.254.x.x address', layer: 'DHCP / VLAN', meaning: 'DHCP not enabled on that interface, pool exhausted, or VLAN not delivered to pfSense.', firstCheck: 'Services > DHCP Server > OPT1; Status > DHCP Leases; capture on vtnet1 vlan 30' },
    { message: 'Blocked host keeps its existing connection', layer: 'State table', meaning: 'Rules only apply to new connections; the established state still matches.', firstCheck: 'Diagnostics > States filtered by host; kill its states' },
    { message: 'webConfigurator unreachable after a rule change (connection timed out)', layer: 'Firewall rules / anti-lockout', meaning: 'Management traffic now blocked; anti-lockout disabled or wrong interface.', firstCheck: 'Console option 8: pfctl -sr | grep -i anti-lockout; easyrule pass' },
    { message: '502 Bad Gateway from the webConfigurator', layer: 'GUI service', meaning: 'nginx is up but php-fpm is not answering; traffic forwarding is unaffected.', firstCheck: 'Console option 16 (Restart PHP-FPM), then 11 (Restart webConfigurator)' },
    { message: 'VPN connected, but nothing reachable through it', layer: 'VPN rules tab / routes', meaning: 'Traffic from the tunnel is filtered on the OpenVPN/IPsec/WireGuard tab (often empty), or the remote network lacks a route/NAT.', firstCheck: 'Firewall > Rules > OpenVPN; Status > OpenVPN; Diagnostics > Routes' },
  ],

  scenarioIds: ['pf-forward-no-rule', 'pf-rule-order', 'pf-outbound-manual', 'pf-alias-wrong', 'pf-rule-source'],
  assessmentId: 'pfsense',
  references: [
    { title: 'pfSense documentation (Netgate)', url: 'https://docs.netgate.com/pfsense/en/latest/' },
    { title: 'pfSense: Firewall rule processing order', url: 'https://docs.netgate.com/pfsense/en/latest/firewall/rule-methodology.html' },
    { title: 'pfSense: Outbound NAT', url: 'https://docs.netgate.com/pfsense/en/latest/nat/outbound.html' },
    { title: 'pfSense: Port forwards', url: 'https://docs.netgate.com/pfsense/en/latest/nat/port-forwards.html' },
    { title: 'pfSense: Console menu', url: 'https://docs.netgate.com/pfsense/en/latest/config/console-menu.html' },
    { title: 'pfSense: Locked out of the GUI', url: 'https://docs.netgate.com/pfsense/en/latest/recipes/lockout-recovery.html' },
    { title: 'pfSense: Firewall log format (filterlog)', url: 'https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html' },
    { title: 'pfSense: Configuration backup and restore', url: 'https://docs.netgate.com/pfsense/en/latest/backup/index.html' },
    { title: 'pfSense CE 2.7.2 release notes', url: 'https://docs.netgate.com/pfsense/en/latest/releases/2-7-2.html' },
    { title: 'FreeBSD pfctl(8) manual page', url: 'https://man.freebsd.org/cgi/man.cgi?query=pfctl&sektion=8' },
  ],
};

export const PFSENSE_ASSESSMENT: Assessment = {
  id: 'pfsense',
  title: 'pfSense knowledge check',
  questions: [
    {
      id: 'pfsense-q-new-opt',
      kind: 'single',
      level: 'beginner',
      prompt: 'You created VLAN 30, assigned it as OPT1 "DEV" with 10.0.30.1/24 and enabled DHCP. Clients get leases but cannot even ping 10.0.30.1. The firewall log shows the entries below. What is the cause?',
      exhibit: 'Oct 21 09:14:02  DEV  Default deny rule IPv4 (1000000103)  10.0.30.25  10.0.30.1  ICMP\nOct 21 09:14:05  DEV  Default deny rule IPv4 (1000000103)  10.0.30.25:51514  10.0.20.10:443  TCP:S',
      options: [
        { text: 'A new OPT interface has no pass rules, so everything entering it hits the implicit default deny', correct: true },
        { text: 'The WAN rules block ICMP', misconception: 'Rules are evaluated on the interface where traffic enters; this traffic enters on DEV, never on WAN.' },
        { text: 'The VLAN tag is wrong on the switch', misconception: 'Then DHCP would fail too, and pfSense would not see (and log) the packets on DEV.' },
        { text: 'Outbound NAT is missing for 10.0.30.0/24', misconception: 'NAT only matters for traffic leaving WAN; these packets are dropped on ingress, before routing or NAT.' },
      ],
      concepts: ['pfsense.rules', 'fw.path'],
      explanation: 'Only LAN receives a default "allow LAN to any" rule. DHCP works because the DHCP server adds automatic rules. Add pass rules on the DEV tab and Apply Changes.',
    },
    {
      id: 'pfsense-q-ingress',
      kind: 'single',
      level: 'beginner',
      prompt: 'You want to stop hosts in VLAN 30 (OPT1) from reaching the office LAN 10.0.10.0/24. On which rules tab do you add the block rule?',
      options: [
        { text: 'OPT1 (DEV), above the rule that passes DEV to any', correct: true },
        { text: 'LAN, because LAN is the destination', misconception: 'pfSense filters traffic where it enters. Traffic from VLAN 30 enters on OPT1; LAN rules apply to traffic coming from the LAN.' },
        { text: 'WAN', misconception: 'WAN rules apply to traffic arriving from the WAN side only.' },
        { text: 'OPT1, at the bottom of the list', misconception: 'First match wins: below a broad pass rule, the block is never reached.' },
      ],
      concepts: ['pfsense.rules', 'fw.path'],
      explanation: 'Ingress filtering plus first-match evaluation: put specific blocks above broad passes on the interface the traffic enters.',
    },
    {
      id: 'pfsense-q-manual-nat',
      kind: 'single',
      level: 'intermediate',
      prompt: 'A new subnet 10.0.30.0/24 can reach the servers but not the Internet. The OPT1 rule passes to any. Outbound NAT is in **Manual** mode with the mappings shown. A capture on WAN shows `IP 10.0.30.25.51514 > 203.0.113.80.443: Flags [S]`. What is wrong?',
      exhibit: 'Firewall > NAT > Outbound   Mode: Manual Outbound NAT rule generation\nInterface  Source          Translation\nWAN        10.0.10.0/24    WAN address\nWAN        10.0.20.0/24    WAN address',
      options: [
        { text: 'Manual mode does not add mappings for new subnets; add one for 10.0.30.0/24 (or use Hybrid/Automatic)', correct: true },
        { text: 'The OPT1 rule needs a gateway set', misconception: 'Policy routing is not needed; the packet already leaves WAN, it just is not translated.' },
        { text: 'Block private networks on WAN drops the outgoing packet', misconception: 'That automatic rule blocks inbound private sources on WAN; it does not filter outbound traffic.' },
        { text: 'There is no default route', misconception: 'The capture shows the packet leaving WAN, so routing works.' },
      ],
      concepts: ['pfsense.nat', 'net.nat'],
      explanation: 'The private source leaves untranslated, so replies are never routed back. In Manual mode pfSense only uses the listed mappings; the subnets that existed when you switched were copied, later ones were not.',
    },
    {
      id: 'pfsense-q-states',
      kind: 'single',
      level: 'intermediate',
      prompt: 'You add a block rule for 10.0.30.25 on OPT1 and click Apply Changes. The user\'s existing SSH session to srv01 keeps working, while new connections are blocked. Why, and what is the targeted fix?',
      options: [
        { text: 'The established connection matches an existing state; kill that host\'s states (Diagnostics > States or pfctl -k 10.0.30.25)', correct: true },
        { text: 'The filter did not reload; reboot the firewall', misconception: 'New connections are blocked, so the new ruleset is loaded. A reboot would work only by dropping every connection on every network.' },
        { text: 'Use Diagnostics > States > Reset States', misconception: 'It works but drops every connection through the firewall (including VPNs and your own session); kill only the affected states.' },
        { text: 'SSH is exempt from firewall rules', misconception: 'Only management traffic to the firewall itself has the anti-lockout exception; forwarded SSH is not exempt.' },
      ],
      concepts: ['fw.stateful', 'pfsense.rules'],
      explanation: 'pf evaluates rules only for packets that do not match a state. A filter reload keeps states; killing them forces the next packet through the new rules.',
    },
    {
      id: 'pfsense-q-portforward',
      kind: 'multi',
      level: 'intermediate',
      prompt: 'A port forward WAN TCP 443 → 10.0.20.10:443 does not work when tested from a laptop on the upstream network 192.168.1.0/24 (the lab WAN is 192.168.1.50). Which of these can cause it? (Select all that apply.)',
      options: [
        { text: '"Block private networks and loopback addresses" is enabled on WAN', correct: true },
        { text: 'The port forward was created with Filter rule association "None"', correct: true },
        { text: 'srv01 uses a default gateway other than pfSense', correct: true },
        { text: 'There is no pass rule on the SERVERS interface for the reply', misconception: 'Replies match the state created by the inbound connection; no rule is needed on the egress interface.' },
        { text: 'Outbound NAT is in Automatic mode', misconception: 'Outbound NAT does not affect inbound port forwards.' },
      ],
      concepts: ['pfsense.nat', 'fw.stateful', 'net.routing'],
      explanation: 'The private-networks rule blocks RFC1918 sources on WAN before user rules; a forward without an associated pass rule hits default deny; and if the server replies via another gateway, the reply never comes back through the state.',
    },
    {
      id: 'pfsense-q-filterlog',
      kind: 'single',
      level: 'intermediate',
      prompt: 'Read this raw line from `/var/log/filter.log`. What happened?',
      exhibit: 'Oct 21 09:20:11 pfSense filterlog[40312]: 5,,,1000000103,vtnet1.30,match,block,in,4,0x0,,64,51344,0,DF,6,tcp,60,10.0.30.25,10.0.20.10,51514,443,0,S,3912442117,,64240,,mss;sackOK;TS;nop;wscale',
      options: [
        { text: 'A new TCP connection from 10.0.30.25 to 10.0.20.10:443 entering on vtnet1.30 was blocked by the default deny rule', correct: true },
        { text: 'srv01 refused the connection with a reset', misconception: 'The line records pf blocking an inbound SYN (flag S); a reset from the server would not be a block entry.' },
        { text: 'The traffic was blocked on WAN', misconception: 'The interface field is vtnet1.30 (the VLAN 30 interface), direction in.' },
        { text: 'An established connection was dropped', misconception: 'Flag S without ACK is the first packet of a new connection.' },
      ],
      concepts: ['pfsense.rules', 'tcp.handshake'],
      explanation: 'Fields: rule number, sub-rule, anchor, tracker (1000000103 = default deny IPv4), real interface, reason, action, direction, IP version, … protocol, length, source, destination, ports, TCP flags.',
    },
    {
      id: 'pfsense-q-lockout-order',
      kind: 'order',
      level: 'advanced',
      prompt: 'You disabled the anti-lockout rule and saved a LAN rule change that blocks your admin PC from the webConfigurator. Put the recovery steps in order (console access is available).',
      items: [
        'Open the console and choose option 8 (Shell)',
        'Run pfctl -d to disable the packet filter temporarily (filtering and NAT stop)',
        'Log in to the webConfigurator and correct the LAN rule (or re-enable anti-lockout)',
        'Apply Changes, which reloads the filter, and confirm pf is enabled again with pfctl -si (pfctl -e if not)',
        'Test GUI access from the admin PC with the packet filter enabled',
      ],
      concepts: ['ops.recovery', 'pfsense.rules'],
      explanation: 'Disabling pf is a short emergency measure: LAN clients lose NAT and nothing is filtered while it is off. Alternatives: `easyrule pass lan tcp <admin IP> <LAN IP> 443` keeps pf running, and console option 15 restores the previous configuration.',
    },
    {
      id: 'pfsense-q-config-xml',
      kind: 'multi',
      level: 'intermediate',
      prompt: 'Why is editing `/cf/conf/config.xml` by hand discouraged? (Select all that apply.)',
      options: [
        { text: 'It bypasses the GUI validation and an XML error can prevent the next boot', correct: true },
        { text: 'The change is not applied until /tmp/config.cache is removed and the subsystem is reloaded or the firewall rebooted', correct: true },
        { text: 'It does not create a config history revision with a description the way GUI saves do', correct: true },
        { text: 'config.xml is regenerated from /tmp/rules.debug at every boot, so edits are lost', misconception: 'The direction is the opposite: rules.debug (and unbound.conf, dhcpd.conf) are generated from config.xml.' },
      ],
      concepts: ['ops.recovery', 'fw.persistence'],
      explanation: 'config.xml is the source of truth. If an edit is unavoidable: back it up, edit, rm /tmp/config.cache, then reload the subsystem or reboot.',
    },
    {
      id: 'pfsense-q-actions',
      kind: 'single',
      level: 'intermediate',
      prompt: 'You changed only the DNS Resolver host overrides and clients still get the old answer. Which action is proportionate?',
      options: [
        { text: 'Restart the unbound service (Status > Services, or pfSsh.php playback svc restart unbound)', correct: true },
        { text: 'Reset States', misconception: 'States are about forwarded connections; it would drop every connection and does nothing for DNS answers.' },
        { text: 'Save and apply the LAN interface', misconception: 'An interface reconfigure bounces LAN and interrupts every LAN client; DNS settings live in unbound.' },
        { text: 'Reboot the firewall', misconception: 'It works but causes a full outage for a single-service change.' },
      ],
      concepts: ['dns.resolution', 'ops.recovery'],
      explanation: 'Pick the smallest action that applies the change: filter reload for rules and NAT, service restart for a service, interface apply for addressing, reboot only when required. Clients may also cache the old answer until its TTL expires.',
    },
    {
      id: 'pfsense-q-dns-refused',
      kind: 'single',
      level: 'advanced',
      prompt: 'Clients on 10.0.40.0/24, behind a router reached via a static route on LAN, get the answer below from pfSense. Clients on LAN resolve fine. What is the cause?',
      exhibit: '$ dig @10.0.10.1 example.com\n;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 40211\n;; SERVER: 10.0.10.1#53(10.0.10.1) (UDP)',
      options: [
        { text: 'Unbound only automatically allows subnets of local interfaces; 10.0.40.0/24 needs a DNS Resolver access list entry', correct: true },
        { text: 'A LAN firewall rule blocks DNS', misconception: 'A firewall block would give a timeout; REFUSED is an answer from unbound itself.' },
        { text: 'Unbound is stopped', misconception: 'A stopped resolver does not answer at all (timeout or ICMP unreachable).' },
        { text: 'The static route is missing', misconception: 'Without a route back, the answer would never reach the client; here it arrives.' },
      ],
      concepts: ['dns.resolution', 'net.routing'],
      explanation: 'REFUSED proves the packet reached unbound and the answer came back. Add 10.0.40.0/24 under Services > DNS Resolver > Access Lists (Allow).',
    },
    {
      id: 'pfsense-q-capture',
      kind: 'text',
      level: 'intermediate',
      prompt: 'From the pfSense shell, type a tcpdump command that captures traffic of host 10.0.30.25 on the VLAN 30 interface `vtnet1.30` without resolving names.',
      accept: [/^tcpdump\s+(-ni|-in|-n\s+-i)\s*vtnet1\.30\s+host\s+10\.0\.30\.25$/, /^tcpdump\s+-i\s*vtnet1\.30\s+-n\s+host\s+10\.0\.30\.25$/],
      placeholder: 'tcpdump ...',
      concepts: ['net.vlan', 'pfsense.rules'],
      explanation: '`tcpdump -ni vtnet1.30 host 10.0.30.25`. On the parent vtnet1 the frames are tagged, so you would need `tcpdump -ni vtnet1 vlan 30 and host 10.0.30.25`. Diagnostics > Packet Capture does the same from the GUI.',
    },
    {
      id: 'pfsense-q-assign',
      kind: 'single',
      level: 'beginner',
      prompt: 'After replacing the VM\'s NICs (e1000 → VirtIO), pfSense stops at boot asking to assign interfaces. Why?',
      options: [
        { text: 'config.xml refers to em0/em1, which no longer exist; the new NICs are vtnet0/vtnet1 and must be assigned to WAN/LAN', correct: true },
        { text: 'config.xml is corrupt and must be restored from backup', misconception: 'The configuration is fine; only the physical names it references changed.' },
        { text: 'VirtIO is not supported by FreeBSD', misconception: 'FreeBSD has the vtnet driver; vtnet is the usual NIC on KVM/Proxmox.' },
      ],
      concepts: ['net.vlan', 'ops.recovery'],
      explanation: 'Logical names (wan, lan, opt1) map to physical driver names. Reassign with console option 1; rules and services follow the logical names, so the rest of the configuration is kept.',
    },
  ],
};
