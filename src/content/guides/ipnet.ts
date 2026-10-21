// Operate & recover guide: host IP networking (interfaces, addresses, routes,
// neighbours, forwarding) and the components that manage it on each platform.

import type { ServiceGuide } from '../types';

export const IPNET_GUIDE: ServiceGuide = {
  purpose:
    'IP networking on a host is not one daemon but a set of kernel state (interfaces, addresses, routes, the ARP/neighbour table, and the `ip_forward` switch on routers) plus a **network manager** that writes that state from configuration files at boot and on changes. Every other service in this application depends on it. The most important operational skill is to know **which component manages the configuration on this host** (ifupdown, NetworkManager, systemd-networkd/netplan, Windows TCP/IP, pfSense) before changing or restarting anything, because restarting the wrong one, or restarting the right one remotely with a broken file, disconnects you.',
  architecture: [
    { q: 'What does it accomplish?', a: 'Gives the host addresses on its links, decides for every packet which interface and next hop to use (longest-prefix match in the routing table), resolves next-hop MAC addresses (ARP for IPv4, NDP for IPv6), and on routers forwards packets between interfaces.' },
    { q: 'How does it work internally?', a: 'The kernel holds the **runtime** state: `ip link` (interfaces and their up/down and carrier state), `ip addr` (addresses; adding one also adds a connected route), `ip route` (routing table), `ip neigh` (neighbour cache). A user-space manager reads **persistent** configuration and programs the kernel via netlink at boot: on Debian servers (and in the lab) `ifupdown` (`/etc/network/interfaces`, run by `networking.service`), on RHEL and desktops **NetworkManager**, on Ubuntu Server **netplan** which renders YAML into systemd-networkd (or NetworkManager) configuration. Changes made with `ip addr add` / `ip route add` are runtime-only and vanish at reboot or interface restart.' },
    { q: 'Which protocols does it use?', a: 'IPv4 (RFC 791), ICMP (RFC 792) for errors and ping, ARP (RFC 826) to map next-hop IPv4 addresses to MAC addresses, Ethernet framing; DHCP when addresses are assigned automatically (see the DHCP guide); IPv6/NDP covered in the IPv6 guide.' },
    { q: 'Which ports and transport?', a: 'None of its own: IP sits below TCP/UDP. ICMP has types instead of ports (echo 8/0, destination unreachable 3, time exceeded 11). ARP is not IP at all (EtherType 0x0806), which is why IP firewall rules never filter it.' },
    { q: 'Which processes and OS components implement it?', a: 'The Linux kernel network stack; `networking.service` running `ifup -a` (Debian ifupdown/ifupdown2); `NetworkManager.service` (+ `nmcli`, keyfiles); `systemd-networkd.service` (+ `networkctl`); `netplan` (a generator, not a daemon); `systemd-sysctl.service` applying `net.ipv4.ip_forward` at boot. Windows: the TCP/IP driver, **DHCP Client** (Dhcp) and **Network Location Awareness** (NlaSvc) services, `netsh`/NetTCPIP PowerShell module. pfSense: FreeBSD kernel, interfaces configured from config.xml.' },
    { q: 'Which other services does it depend on?', a: 'Physical/virtual link (cable, switch port, VLAN membership, hypervisor vSwitch), the driver, and for dynamic addresses a DHCP server. Routing beyond the local subnet depends on a router that forwards **and** on every router knowing the way back. Almost everything else (DNS, SSH, web, AD) depends on it.' },
    { q: 'How do requests travel?', a: 'For each outgoing packet: route lookup (`ip route get <dst>` shows the decision) → if the destination is on-link, ARP for the destination itself; otherwise ARP for the **gateway** → frame sent with the gateway\'s MAC and the final IP destination → each router decrements TTL, does its own lookup, ARPs on the next segment, and builds a new frame → the reply is routed independently by the destination host, so **both directions** must work.' },
    { q: 'How do authentication and authorisation work?', a: 'IP and ARP have **no authentication**: any host on a segment can answer ARP for any address (ARP spoofing) or configure any IP (address conflicts). Protection comes from the network: switch port security, DHCP snooping and dynamic ARP inspection, VLAN segmentation, and firewalls. Changing network configuration requires root/Administrator.' },
    { q: 'How does it start at boot?', a: 'Debian: `networking.service` (oneshot, `ExecStart=/sbin/ifup -a`) runs before `network.target`; units that need a configured address order themselves after `network-online.target`. NetworkManager and systemd-networkd are long-running daemons that also react to link changes. `systemd-sysctl` applies `/etc/sysctl.conf` and `/etc/sysctl.d/*.conf` (e.g. `ip_forward=1`) early in boot. Windows brings adapters up through NDIS and the DHCP Client service.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'Kernel state persists if the manager dies: addresses and routes stay until something removes them, so a crashed NetworkManager does not immediately cut traffic (but DHCP renewals and link-change handling stop, so a lease can later expire). `networking.service` is a oneshot: "inactive" after boot is not a failure as long as it shows `active (exited)`. Stopping `networking.service` runs `ifdown -a`, which **removes** addresses: never do it over the network.' },
  ],
  ports: [
    { port: '—', proto: 'ICMP', purpose: 'Echo (ping), destination unreachable, time exceeded (traceroute)' },
    { port: '—', proto: 'ARP (EtherType 0x0806)', purpose: 'Next-hop MAC resolution on each segment' },
  ],
  processes: [
    { name: 'kernel (net stack)', platform: 'Linux', role: 'Interfaces, addresses, routes, neighbour table, forwarding' },
    { name: 'networking.service (ifup -a)', platform: 'Debian (the lab), Ubuntu < 17.10', role: 'Applies `/etc/network/interfaces` at boot (oneshot)' },
    { name: 'NetworkManager', platform: 'RHEL/Fedora, Ubuntu Desktop, Debian desktop', role: 'Daemon; `nmcli`; keyfiles in /etc/NetworkManager/system-connections' },
    { name: 'systemd-networkd + netplan', platform: 'Ubuntu Server 18.04+', role: 'netplan YAML → /run/systemd/network/*; `networkctl`' },
    { name: 'Dhcp, NlaSvc, TCP/IP driver', platform: 'Windows Server 2019/2022, Windows 10/11', role: 'DHCP client, network profile detection, the stack itself' },
  ],
  dependencies: {
    title: 'What a host needs to reach a remote server by IP',
    caption: 'Check from the bottom: no carrier makes everything above fail; a missing route on the far side makes only the return path fail.',
    rows: [
      { label: 'Remote', nodes: [{ id: 'ret', label: 'Return route', sub: 'remote gateway', kind: 'network' }, { id: 'rfw', label: 'Remote firewall', sub: 'allows ICMP/TCP', kind: 'network' }] },
      { label: 'Path', nodes: [{ id: 'fwd', label: 'Router forwards', sub: 'ip_forward=1', kind: 'network' }, { id: 'rtab', label: 'Router routes', sub: 'knows dest subnet', kind: 'network' }] },
      { label: 'Local L3', nodes: [{ id: 'gw', label: 'Default gateway', sub: 'ip route', kind: 'os' }, { id: 'arp', label: 'ARP for gateway', sub: 'ip neigh', kind: 'os' }, { id: 'addr', label: 'Address/prefix', sub: 'ip addr', kind: 'os' }] },
      { label: 'Local L1/L2', nodes: [{ id: 'link', label: 'Link + carrier', sub: 'ip link, ethtool', kind: 'network' }, { id: 'vlan', label: 'Switch port/VLAN', sub: 'access VLAN', kind: 'network' }] },
      { label: 'Config', nodes: [{ id: 'mgr', label: 'Network manager', sub: 'ifupdown/NM/networkd', kind: 'service' }, { id: 'file', label: 'Persistent config', sub: 'interfaces, YAML', kind: 'data' }] },
    ],
    edges: [['ret', 'rtab'], ['rfw', 'rtab'], ['rtab', 'fwd'], ['fwd', 'gw'], ['gw', 'arp'], ['arp', 'addr'], ['addr', 'link'], ['link', 'vlan'], ['addr', 'mgr', 'set by'], ['mgr', 'file', 'reads']],
  },
  sequence: {
    title: 'ws01 pings srv01 (10.0.20.10) through rtr01',
    lanes: [{ id: 'ws', label: 'ws01', sub: '10.0.10.25' }, { id: 'r', label: 'rtr01', sub: '.10.1 / .20.1' }, { id: 's', label: 'srv01', sub: '10.0.20.10' }],
    steps: [
      { from: 'ws', to: 'ws', label: 'route: via 10.0.10.1', note: 'No default route → "Network is unreachable" immediately.' },
      { from: 'ws', to: 'r', label: 'ARP who-has 10.0.10.1', note: 'No reply (wrong gateway, wrong VLAN) → "Destination Host Unreachable" from ws01 itself.' },
      { from: 'r', to: 'ws', label: 'ARP reply (rtr01 MAC)' },
      { from: 'ws', to: 'r', label: 'ICMP echo, TTL 64' },
      { from: 'r', to: 's', label: 'forwarded, TTL 63', note: 'ip_forward=0 → dropped or ICMP host unreachable from the router.' },
      { from: 's', to: 'r', label: 'echo reply via 10.0.20.1', note: 'srv01 without a route back → silence: ping shows 100% loss although the request arrived.' },
      { from: 'r', to: 'ws', label: 'reply delivered' },
    ],
  },
  files: [
    { path: '/etc/network/interfaces, interfaces.d/', platform: 'Debian (the lab)', kind: 'config', perms: 'root:root 0644', contains: '`auto eth0` / `iface eth0 inet static` with `address`, `gateway`, `dns-nameservers` (with resolvconf), VLAN and bridge stanzas (ifupdown2).', accessed: 'By `ifup`/`ifdown`/`ifreload` and at boot by networking.service.', problems: 'A wrong prefix or gateway is applied silently. A syntax error can stop `ifup -a`, leaving interfaces down after reboot. Interfaces without `auto` are not raised at boot.' },
    { path: '/etc/netplan/*.yaml', platform: 'Ubuntu Server 18.04+', kind: 'config', perms: 'root:root 0600 (netplan warns if world-readable)', contains: 'YAML: `network: { version: 2, renderer: networkd, ethernets: { eth0: { addresses: [...], routes: [{ to: default, via: ... }], nameservers: ... } } }`.', accessed: 'By `netplan generate` at boot and by `netplan apply`/`netplan try`.', problems: 'YAML indentation errors ("Invalid YAML: inconsistent indentation") stop the whole configuration from being rendered. Files are merged in lexical order; a cloud-init file (`50-cloud-init.yaml`) may override yours.' },
    { path: '/etc/NetworkManager/system-connections/*.nmconnection', platform: 'RHEL 9, Fedora, desktops', kind: 'config', perms: 'root:root 0600 (NM ignores readable files)', contains: 'Keyfile per connection profile: `[ipv4] method=manual address1=...`, `dns=`, `autoconnect`.', accessed: 'By NetworkManager when profiles load (`nmcli connection reload`).', problems: 'Editing the file without `nmcli connection reload` has no effect. RHEL 8 still uses ifcfg files in /etc/sysconfig/network-scripts/.' },
    { path: '/etc/systemd/network/*.network', platform: 'systemd-networkd', kind: 'config', perms: 'root:root 0644', contains: '`[Match] Name=eth0`, `[Network] Address=`, `Gateway=`, `DNS=`.', accessed: 'By systemd-networkd at start and on `networkctl reload`.', problems: 'An interface matched by no file is shown "unmanaged" by `networkctl` and keeps no configuration.' },
    { path: '/etc/sysctl.conf, /etc/sysctl.d/*.conf', platform: 'Linux', kind: 'config', perms: 'root:root 0644', contains: '`net.ipv4.ip_forward = 1` on routers; rp_filter, IPv6 forwarding.', accessed: 'By systemd-sysctl at boot and by `sysctl --system`/`sysctl -p`.', problems: 'A hardening file later in the order can set `ip_forward = 0` and silently turn a router into a host after the next reboot. `sysctl -w` changes are runtime-only.' },
    { path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{GUID}', platform: 'Windows Server 2019/2022, Windows 10/11', kind: 'registry', contains: 'Per-adapter `EnableDHCP`, `IPAddress`, `SubnetMask`, `DefaultGateway`, `NameServer`, DHCP lease details.', accessed: 'By the TCP/IP stack and DHCP Client service.', problems: 'Do not edit directly; use `New-NetIPAddress`/`Set-DnsClientServerAddress` or the adapter properties. A stale static entry for a removed NIC can produce "address already assigned to another adapter".' },
    { path: 'Event Viewer: System (Tcpip, Dhcp-Client), Microsoft-Windows-NetworkProfile/Operational', platform: 'Windows', kind: 'eventlog', contains: 'IP address conflicts (Tcpip 4199), DHCP client failures (1001/1002 in Dhcp-Client), network profile changes (Domain/Private/Public).', accessed: 'Written as events happen.', problems: 'A network detected as **Public** applies the stricter firewall profile and can block management traffic.' },
    { path: '/cf/conf/config.xml (<interfaces>)', platform: 'pfSense', kind: 'config', contains: 'Interface assignments, addresses, gateways.', accessed: 'At boot and when interfaces are applied in the GUI.', problems: 'Wrong assignment after a NIC change (vtnet0/vtnet1 swapped) puts WAN and LAN on the wrong networks; fix from the console menu option 1.' },
  ],
  management: [
    {
      platform: 'Debian (ifupdown, the lab)',
      tasks: [
        { task: 'Interfaces, carrier and addresses', command: 'ip -br link\nip -br addr', explain: '`UP` with `LOWER_UP` = link has carrier. `NO-CARRIER` = cable/switch/VLAN problem below IP. No address on an UP interface = configuration or DHCP problem.', sim: true },
        { task: 'Routes and the decision for one destination', command: 'ip route\nip route get 10.0.20.10', explain: '`route get` shows exactly which route, gateway and source address the kernel will use.', sim: true },
        { task: 'Neighbour (ARP) table', command: 'ip neigh', explain: '`REACHABLE`/`STALE` entries are fine; `FAILED` or `INCOMPLETE` for the gateway means no ARP reply: wrong gateway address, wrong VLAN, or the router is down.', sim: true },
        { task: 'Status of the manager', command: 'systemctl status networking', explain: 'A oneshot: `active (exited)` is healthy. `failed` means `ifup -a` reported an error at boot; read `journalctl -u networking -b`.', sim: true },
        { task: 'Apply a changed interface stanza', command: 'sudo ifreload -a', explain: 'ifupdown2: applies differences only. Classic ifupdown: `sudo ifdown eth0 && sudo ifup eth0` (run as one line, or from a console).', risk: 'Briefly drops traffic on the interface; a broken stanza leaves it down. Over SSH, schedule a rollback first.', sim: true },
        { task: 'Restart all networking', command: 'sudo systemctl restart networking', explain: 'Runs `ifdown -a` then `ifup -a`.', risk: 'Removes every address and route, including the one your SSH session uses. Console only.', sim: true },
        { task: 'Router forwarding', command: 'sysctl net.ipv4.ip_forward\ngrep -r ip_forward /etc/sysctl.conf /etc/sysctl.d/', explain: 'Runtime value and the files that set it at boot. `sudo sysctl --system` reapplies the files.', sim: true },
        { task: 'Test the path', command: 'ping -c 2 10.0.10.1\ntraceroute -n 10.0.20.10\ntracepath -n 203.0.113.80', explain: 'Gateway first, then beyond. traceroute/tracepath show the last hop that answers; `* * *` after it means drops or no return path.', sim: true },
        { task: 'Link-level details', command: 'ethtool eth0', explain: '`Link detected: no`, wrong speed/duplex point below IP.', sim: true },
      ],
    },
    {
      platform: 'RHEL / NetworkManager',
      tasks: [
        { task: 'State', command: 'nmcli general status\nnmcli device status\nnmcli connection show', explain: 'Which devices NM manages, which profile is active on each. `unmanaged` devices are configured elsewhere.' },
        { task: 'Change and apply an address', command: 'sudo nmcli connection modify "System eth0" ipv4.addresses 10.0.20.10/24 ipv4.gateway 10.0.20.1 ipv4.method manual\nsudo nmcli connection up "System eth0"', explain: '`modify` writes the keyfile; `up` re-activates the profile to apply it.', risk: 'Re-activation interrupts traffic on that device.' },
        { task: 'Restart the daemon', command: 'sudo systemctl restart NetworkManager', explain: 'Usually keeps existing addresses (NM takes over the running state), but can re-run DHCP.', risk: 'Avoid remotely unless necessary.' },
        { task: 'Logs', command: 'journalctl -u NetworkManager -b', explain: 'Device activation, DHCP, carrier changes.' },
      ],
    },
    {
      platform: 'Ubuntu Server (netplan + systemd-networkd)',
      tasks: [
        { task: 'State', command: 'networkctl list\nnetworkctl status eth0', explain: '`routable`/`configured` is healthy; `degraded` = only link-local; `unmanaged` = no .network file matches.' },
        { task: 'Validate and test changes safely', command: 'sudo netplan generate\nsudo netplan try', explain: '`generate` validates the YAML; `try` applies it and **reverts automatically after 120 s** unless you confirm, which protects remote sessions.' },
        { task: 'Apply', command: 'sudo netplan apply', explain: 'Renders and applies the configuration.', risk: 'Can bounce interfaces and drop sessions; prefer `netplan try`.' },
        { task: 'Reconfigure one interface', command: 'sudo networkctl reconfigure eth0', explain: 'Re-reads configuration for that link only.' },
      ],
    },
    {
      platform: 'Windows Server 2019/2022, Windows 10/11',
      tasks: [
        { task: 'Configuration', command: 'ipconfig /all\nGet-NetIPConfiguration\nGet-NetAdapter', explain: 'Address, gateway, DNS servers, DHCP state; adapter Status `Up`/`Disconnected` and LinkSpeed.' },
        { task: 'Routes and path', command: 'Get-NetRoute -AddressFamily IPv4\nroute print\nTest-NetConnection 10.0.20.10 -TraceRoute', explain: 'Default route 0.0.0.0/0 via the gateway; TraceRoute lists hops.' },
        { task: 'Neighbours', command: 'Get-NetNeighbor -AddressFamily IPv4\narp -a', explain: 'Unreachable/Incomplete entry for the gateway = layer-2 problem.' },
        { task: 'Restart an adapter', command: 'Restart-NetAdapter -Name "Ethernet0"', explain: 'Disables and re-enables the adapter.', risk: 'Disconnects RDP over that adapter; use the hypervisor/iLO console.' },
        { task: 'Network profile', command: 'Get-NetConnectionProfile', explain: '`Public` applies the restrictive firewall profile.' },
      ],
    },
    {
      platform: 'pfSense',
      tasks: [
        { task: 'Interfaces and gateways', command: 'Status > Interfaces; Status > Gateways\nconsole: ifconfig; netstat -rn', explain: 'Link state, addresses, gateway monitoring (dpinger) status.' },
        { task: 'Reassign or re-address', command: 'Console menu 1 (Assign Interfaces), 2 (Set interface IP address)', explain: 'Recover from wrong assignments without the GUI.' },
      ],
    },
    {
      platform: 'Docker',
      tasks: [
        { task: 'Container networking', command: 'docker network ls\ndocker network inspect bridge\nip -br addr show docker0', explain: 'Each bridge network is a Linux bridge with its own subnet; containers reach the outside through the host\'s routing and Docker\'s masquerade rules.' },
      ],
    },
  ],
  actions: [
    { action: 'Fix runtime state only (ip addr add / ip route add)', when: 'To test a hypothesis or restore service immediately.', effect: 'Changes the kernel state now; nothing is written to disk.', risk: 'Lost at the next reboot or interface restart: a workaround, not a fix. Always follow up with the persistent file.' },
    { action: 'ifreload -a / ifdown+ifup / nmcli con up / networkctl reconfigure / Restart-NetAdapter', when: 'After changing that interface\'s persistent configuration.', effect: 'Re-applies configuration to one interface.', risk: 'Interrupts traffic on it; a broken config leaves it down. Over SSH, use a console or a scheduled rollback (`netplan try` does this for you).' },
    { action: 'systemctl restart networking / NetworkManager / systemd-networkd', when: 'Rarely: when the manager itself is stuck, or for multi-interface changes from a console.', effect: 'Re-applies all interfaces (networking: ifdown -a then ifup -a).', risk: 'Drops every session; on a router, cuts every routed flow.' },
    { action: 'Renew DHCP (dhclient -r/dhclient, ipconfig /release /renew)', when: 'The DHCP server or its options changed, or the client has no/old lease.', effect: 'Gets a new lease and options; does not touch static configuration.', risk: 'Release drops the address (and your session) until the new lease arrives.' },
    { action: 'reboot', when: 'Proving persistence in a maintenance window; kernel updates.', effect: 'Everything is rebuilt from files.', risk: 'Runtime-only fixes disappear; a bad persistent file leaves the host unreachable.' },
  ],
  workflow: [
    { question: '1. Does the interface have a link?', command: 'ip -br link\nethtool eth0', healthy: 'eth0             UP             52:54:00:d4:00:19 <BROADCAST,MULTICAST,UP,LOWER_UP>\n\tLink detected: yes', broken: '`NO-CARRIER` / `Link detected: no`: cable, switch port shut, wrong VLAN on a virtual switch, or the peer is down. `DOWN`: interface administratively down (not `auto`, or ifdown).', next: 'No carrier → physical/switch side. Link up → step 2.', sim: true },
    { question: '2. Does it have the right address and prefix?', command: 'ip -br addr', healthy: 'eth0             UP             10.0.10.25/24 fe80::5054:ff:fed4:19/64', broken: 'No IPv4 address → DHCP failure (see the DHCP guide) or `iface` stanza not applied. Wrong prefix (e.g. /16 instead of /24) → the host thinks remote hosts are local and ARPs for them directly ("Destination Host Unreachable").', next: 'Correct address → step 3.', sim: true },
    { question: '3. Is there a default route to the right gateway?', command: 'ip route\nip route get 10.0.20.10', healthy: 'default via 10.0.10.1 dev eth0 onlink\n10.0.20.10 via 10.0.10.1 dev eth0 src 10.0.10.25 uid 1000', broken: 'No `default` line → "Network is unreachable" for everything off-subnet. Gateway outside the subnet or a typo → ARP for it fails.', next: 'Route present → step 4.', sim: true },
    { question: '4. Can the gateway be resolved and reached?', command: 'ping -c 2 10.0.10.1\nip neigh', healthy: '64 bytes from 10.0.10.1: icmp_seq=1 ttl=64 time=0.950 ms\n10.0.10.1 dev eth0 lladdr 52:54:00:a1:00:01 REACHABLE', broken: '`FAILED`/`INCOMPLETE` neighbour entry → nobody answers ARP: wrong gateway address, wrong VLAN, router interface down.', next: 'Gateway answers → step 5.', sim: true },
    { question: '5. How far does traffic get towards the destination?', command: 'tracepath -n 203.0.113.80\ntraceroute -n 10.0.20.10', healthy: ' 1:  10.0.10.1   0.950ms\n 2:  203.0.113.80   1.150ms reached', broken: 'Stops after the first router → the router does not forward (ip_forward=0), has no route, a forward-chain firewall drops, or the destination has no route back. Note: the destination\'s own firewall may drop traceroute\'s UDP probes, so `* * *` at the last hop alone is not proof.', next: 'Check the router (step 6) and the far end\'s return route (step 7).', sim: true },
    { question: '6. Does the router forward and know the destination?', command: 'sysctl net.ipv4.ip_forward\nip route', healthy: 'net.ipv4.ip_forward = 1\n10.0.20.0/24 dev eth1 proto kernel scope link src 10.0.20.1', broken: '`ip_forward = 0` → router behaves as a host. Missing connected/static route → "Destination Net Unreachable" from the router.', next: 'Router fine → step 7.', sim: true },
    { question: '7. Can the destination route the reply back?', command: 'ip route   (on the destination)\ntcpdump -n -i eth0 icmp   (on the destination)', healthy: 'default via 10.0.20.1 dev eth0 onlink', broken: 'Requests arrive (tcpdump) but no route back → client sees a timeout. A classic after re-addressing a server or adding a second NIC.', next: 'Fix the far side\'s gateway, persistently.', sim: true },
    { question: '8. Is the fix persistent?', command: 'cat /etc/network/interfaces\ngrep -r ip_forward /etc/sysctl.conf /etc/sysctl.d/', healthy: 'iface eth0 inet static\n    address 10.0.10.25/24\n    gateway 10.0.10.1', broken: 'The working state was set with `ip`/`sysctl -w` only → lost at reboot.', next: 'Write the file, apply it the safe way, and verify after a reboot.', sim: true },
  ],
  failures: [
    { symptom: 'connect: Network is unreachable', causes: ['No default route', 'Interface has no address (DHCP failed)'], diagnose: ['ip route', 'ip -br addr'], fix: 'Add `gateway` to the interface configuration (or fix DHCP) and re-apply the interface.', verify: 'ip route get 10.0.20.10' },
    { symptom: 'From 10.0.10.25 icmp_seq=1 Destination Host Unreachable (from the host itself)', causes: ['ARP for the next hop gets no reply: wrong gateway IP, wrong VLAN, gateway down', 'Prefix too wide: the host ARPs for an off-subnet destination'], diagnose: ['ip neigh', 'ip -br addr', 'ip route get <dst>'], fix: 'Correct the gateway or prefix in the persistent configuration; fix VLAN membership on the switch.', verify: 'ip neigh (gateway REACHABLE); ping the gateway' },
    { symptom: 'ping/ssh time out, but the destination sees the packets', causes: ['Destination has no route back (missing/wrong gateway)', 'Asymmetric path through a stateful firewall'], diagnose: ['tcpdump -n -i eth0 on the destination', 'ip route on the destination'], fix: 'Fix the destination\'s default gateway persistently.', verify: 'ping from the client' },
    { symptom: 'Routed traffic stopped after a reboot / hardening', causes: ['net.ipv4.ip_forward reset to 0 by a sysctl file', 'Static route added only at runtime'], diagnose: ['sysctl net.ipv4.ip_forward', 'grep -r ip_forward /etc/sysctl.d/'], fix: 'Set `net.ipv4.ip_forward = 1` in a file that sorts after the hardening file, `sysctl --system`.', verify: 'traceroute through the router; check again after reboot' },
    { symptom: 'Interface NO-CARRIER / "Link detected: no"', causes: ['Cable, switch port disabled', 'Virtual NIC disconnected or on the wrong vSwitch/VLAN'], diagnose: ['ip -br link', 'ethtool eth0', 'switch: port status / bridge vlan show'], fix: 'Fix the physical or virtual connection; nothing in IP configuration can help.', verify: 'ip -br link shows LOWER_UP' },
    { symptom: 'Windows: 169.254.x.x address', causes: ['APIPA: DHCP failed'], diagnose: ['ipconfig /all', 'Get-WinEvent -LogName Microsoft-Windows-Dhcp-Client/Admin -MaxEvents 10'], fix: 'Fix DHCP reachability (server, relay, VLAN), then `ipconfig /renew`.', verify: 'ipconfig shows a lease from the DHCP server' },
    { symptom: 'Server unreachable after a remote network change', causes: ['Typo in the new configuration applied over SSH', 'Applied with restart instead of try/rollback'], diagnose: ['Console: ip -br addr; journalctl -u networking -b'], fix: 'From the console restore the backup file and re-apply; next time use `netplan try` or a scheduled rollback.', verify: 'SSH from a client network' },
  ],
  verification: [
    { check: 'Link and address', command: 'ip -br addr', expect: 'eth0 UP 10.0.10.25/24 ...' },
    { check: 'Route decision for a remote destination', command: 'ip route get 10.0.20.10', expect: '10.0.20.10 via 10.0.10.1 dev eth0 src 10.0.10.25' },
    { check: 'Gateway resolved', command: 'ip neigh', expect: '10.0.10.1 dev eth0 lladdr 52:54:00:a1:00:01 REACHABLE' },
    { check: 'End-to-end by IP', command: 'ping -c 2 10.0.20.10', expect: '2 packets transmitted, 2 received, 0% packet loss' },
    { check: 'Application traffic, not just ICMP', command: 'nc -zv 10.0.20.10 22', expect: 'Connection to 10.0.20.10 22 port [tcp/ssh] succeeded!' },
    { check: 'Persistent configuration matches runtime', command: 'cat /etc/network/interfaces; sysctl net.ipv4.ip_forward (router)', expect: 'Same address/gateway as `ip` shows; forwarding = 1 on routers' },
  ],
  refIds: ['ip', 'ping-linux', 'traceroute', 'tracepath', 'ethtool', 'tcpdump', 'sysctl', 'nmcli', 'networkctl', 'netplan', 'ipconfig', 'get-netipconfiguration', 'get-netroute', 'restart-netadapter', 'file:etc-network-interfaces', 'file:netplan', 'file:networkmanager', 'file:sysctl.conf', 'proc:remote-network-change', 'proc:netplan-try', 'proc:nm-reconnect', 'proc:networkd-reconfigure'],
};
