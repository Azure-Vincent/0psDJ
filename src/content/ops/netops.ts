// Lesson A: Network configuration and recovery on Linux and Windows hosts.
// Simulator-backed commands are marked sim/simulated; their sample output was
// captured from the lab (Debian 12, ifupdown). nmcli, networkctl, netplan and
// resolvectl output is representative output from the named real systems.

import type { Assessment, Lesson, ServiceGuide } from '../types';

// ---------------------------------------------------------------------------
// Operate & recover guide: the "service" is host networking management
// (the network manager in use plus the DNS resolver).
// ---------------------------------------------------------------------------

export const NETOPS_GUIDE: ServiceGuide = {
  purpose:
    'Every host needs four things before any application can talk: a **link** (carrier on the interface), an **address and prefix**, **routes** (at least a default gateway), and a **resolver** (DNS servers). The kernel holds this state; a **network manager** puts it there from configuration files at boot and whenever something changes. Linux has several managers (ifupdown on Debian and in this lab, systemd-networkd behind Netplan on Ubuntu server, NetworkManager on RHEL and desktops), Windows has its own TCP/IP stack and DHCP/DNS client services, and each one has different files, commands and restart behaviour. This lesson teaches you to find out **which manager is in charge before touching anything**, to investigate from the physical interface up to the application, and to apply changes without cutting off your own remote session.',
  architecture: [
    { q: 'What does it accomplish?', a: 'Brings interfaces up, assigns static or DHCP/SLAAC addresses, installs routes, configures DNS servers and search domains, and keeps them correct when links flap, leases renew or Wi-Fi roams. On routers it also enables forwarding (`net.ipv4.ip_forward=1`).' },
    { q: 'How does it work internally?', a: 'The **kernel** owns the live state: interfaces, addresses, routes and the neighbour (ARP/NDP) cache, changed through **netlink** (what `ip` uses). A **manager** translates configuration files into netlink calls: `ifup` reads `/etc/network/interfaces` once and exits; NetworkManager and systemd-networkd are daemons that watch links and re-apply configuration; Netplan is not a daemon at all, it only **generates** networkd or NetworkManager configuration from YAML. The **resolver** is separate: glibc reads `/etc/nsswitch.conf` (`hosts: files dns`), then `/etc/hosts`, then the DNS servers in `/etc/resolv.conf`, which may point to a local stub (systemd-resolved on 127.0.0.53).' },
    { q: 'Which protocols does it use?', a: 'Ethernet and ARP (IPv4 neighbour discovery), IPv6 Neighbour Discovery and Router Advertisements (SLAAC), DHCPv4 (DISCOVER/OFFER/REQUEST/ACK) and DHCPv6, DNS for name resolution, ICMP for diagnostics (ping, traceroute errors, PMTU), and netlink between user space and the kernel.' },
    { q: 'Which ports and transport?', a: 'DHCPv4: UDP 67 (server) / 68 (client). DHCPv6: UDP 546/547. DNS: UDP and TCP 53 (to the server; systemd-resolved listens on 127.0.0.53:53 locally). Router Advertisements and Neighbour Discovery: ICMPv6 types 133–136. traceroute uses UDP 33434+ by default (ICMP with `-I`).' },
    { q: 'Which processes and OS components implement it?', a: 'Debian (the lab): `networking.service` runs `ifup -a` at boot and exits; `dhclient` stays running on DHCP interfaces (ws02). Ubuntu server: `systemd-networkd` + `systemd-resolved`, configured through Netplan. RHEL 9 and desktops: `NetworkManager` (+ `nmcli`, `nmtui`), with keyfiles in `/etc/NetworkManager/system-connections/`. Windows: the TCP/IP stack, the **DHCP Client** (Dhcp) and **DNS Client** (Dnscache) services, Network Location Awareness. pfSense: FreeBSD `ifconfig`, configured from `config.xml`.' },
    { q: 'Which other services does it depend on?', a: 'Physical/virtual layer (cable, switch port, VLAN, hypervisor vSwitch), the switch and router (gateway), a DHCP server for dynamic hosts (ns1 in the lab), DNS servers (ns1), and the host firewall (nftables) which can drop DHCP, DNS or ICMP. Almost every other service depends on host networking, so a broken network config looks like "everything is down".' },
    { q: 'How do requests travel?', a: 'For `ping srv01.corp.lab` from ws01: NSS → /etc/hosts (no match) → DNS query to 10.0.10.53 (ARP for 10.0.10.53 first, same subnet) → answer 10.0.20.10 → route lookup: not on 10.0.10.0/24, so use the default route via 10.0.10.1 → ARP for 10.0.10.1 → ICMP echo to rtr01\'s MAC with destination IP 10.0.20.10 → rtr01 forwards to eth1 (ARP for 10.0.20.10) → srv01 replies via **its** default gateway 10.0.20.1. Each arrow is a separate check in the workflow below.' },
    { q: 'How do authentication and authorisation work?', a: 'Changing addresses, routes or links needs root or `CAP_NET_ADMIN` (`ip addr add` as a normal user: "RTNETLINK answers: Operation not permitted"). nmcli as a normal user is allowed by polkit only for some actions (e.g. local console users on desktops). On Windows, `New-NetIPAddress`, `Restart-NetAdapter` and `ipconfig /release` need an elevated prompt; `ipconfig /all` does not.' },
    { q: 'How does it start at boot?', a: 'Debian/ifupdown: `networking.service` (Type=oneshot, `ExecStart=/sbin/ifup -a --read-environment`, `Before=network.target network-online.target`) brings up every `auto` interface. Ubuntu: Netplan\'s generator writes `/run/systemd/network/*.network` at boot, then `systemd-networkd` applies it and `systemd-networkd-wait-online` gates `network-online.target`. RHEL: `NetworkManager.service` activates connection profiles with `autoconnect=yes`; `NetworkManager-wait-online` gates network-online.target.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'Addresses and routes live in the kernel, so stopping or crashing a manager usually leaves the network **working as it is**. The danger is restarting it: `systemctl restart networking` runs `ifdown -a` then `ifup -a` and drops every connection; `systemctl stop NetworkManager` leaves addresses in place, but DHCP leases are no longer renewed and expire. If `dhclient` dies on a DHCP host, the address disappears when the lease expires (600 s in the lab).' },
  ],
  ports: [
    { port: '67 / 68', proto: 'UDP', purpose: 'DHCPv4 server / client (broadcast DISCOVER from 0.0.0.0:68 to 255.255.255.255:67)' },
    { port: '546 / 547', proto: 'UDP', purpose: 'DHCPv6 client / server' },
    { port: '53', proto: 'UDP, TCP', purpose: 'DNS queries to the configured nameserver' },
    { port: '127.0.0.53:53', proto: 'UDP, TCP', purpose: 'systemd-resolved stub listener (Ubuntu): /etc/resolv.conf says nameserver 127.0.0.53' },
    { port: 'ICMPv6 133–136', proto: 'ICMPv6', purpose: 'Router Solicitation/Advertisement, Neighbour Solicitation/Advertisement (SLAAC, IPv6 "ARP")' },
    { port: '33434+', proto: 'UDP', purpose: 'traceroute/tracepath probes (often dropped by host firewalls: "* * *")' },
  ],
  processes: [
    { name: 'networking.service → ifup -a', platform: 'Debian (the lab)', role: 'Oneshot: applies /etc/network/interfaces at boot, then exits ("active (exited)")' },
    { name: 'dhclient', platform: 'Debian with ifupdown (ws02)', role: 'DHCP client; renews the lease, rewrites /etc/resolv.conf' },
    { name: 'systemd-networkd', platform: 'Ubuntu server (via Netplan), minimal systems', role: 'Daemon that applies /etc/systemd/network and /run/systemd/network *.network files; DHCP client built in' },
    { name: 'NetworkManager', platform: 'RHEL 9, Fedora, Ubuntu desktop', role: 'Daemon managing connection profiles; tools nmcli, nmtui; writes /etc/resolv.conf unless resolved is used' },
    { name: 'systemd-resolved', platform: 'Ubuntu (default), optional elsewhere', role: 'Local caching stub resolver on 127.0.0.53; per-link DNS servers; `resolvectl`' },
    { name: 'Dhcp, Dnscache, NlaSvc services', platform: 'Windows Server 2019/2022, Windows 10/11', role: 'DHCP Client, DNS Client (cache: ipconfig /flushdns), Network Location Awareness (firewall profile)' },
  ],
  dependencies: {
    title: 'What "the network works" depends on (investigate bottom-up)',
    caption: 'Stop at the first layer that fails: a missing default route explains every failure above it. Identify the manager before changing anything.',
    rows: [
      { label: 'Application', nodes: [{ id: 'app', label: 'Service port', sub: 'ss -tlnp, nc -zv', kind: 'service' }] },
      { label: 'Names', nodes: [{ id: 'dns', label: 'Resolver', sub: 'resolv.conf, dig', kind: 'network' }, { id: 'hosts', label: '/etc/hosts', sub: 'nsswitch order', kind: 'data' }] },
      { label: 'Path', nodes: [{ id: 'route', label: 'Routes', sub: 'ip route', kind: 'network' }, { id: 'gw', label: 'Gateway', sub: 'ip neigh, ping', kind: 'network' }, { id: 'fw', label: 'Firewalls', sub: 'nft list ruleset', kind: 'network' }] },
      { label: 'Address', nodes: [{ id: 'addr', label: 'IP + prefix', sub: 'ip -br addr', kind: 'network' }, { id: 'dhcp', label: 'DHCP / SLAAC', sub: 'lease, RA', kind: 'service' }] },
      { label: 'Link', nodes: [{ id: 'link', label: 'Carrier', sub: 'ip link, ethtool', kind: 'network' }, { id: 'mgr', label: 'Network manager', sub: 'ifupdown/NM/networkd', kind: 'os' }] },
    ],
    edges: [
      ['app', 'dns'], ['app', 'route'], ['dns', 'hosts'], ['dns', 'route'], ['route', 'gw'], ['gw', 'addr'], ['fw', 'route'],
      ['route', 'addr'], ['addr', 'dhcp'], ['addr', 'link'], ['dhcp', 'link'], ['addr', 'mgr'], ['link', 'mgr'],
    ],
  },
  sequence: {
    title: 'ping srv01.corp.lab from ws01: every dependency in order',
    lanes: [{ id: 'w', label: 'ws01', sub: '10.0.10.25' }, { id: 'n', label: 'ns1', sub: '10.0.10.53' }, { id: 'r', label: 'rtr01', sub: '10.0.10.1' }, { id: 's', label: 'srv01', sub: '10.0.20.10' }],
    steps: [
      { from: 'w', to: 'n', label: 'ARP who-has 10.0.10.53', note: 'Same subnet: no gateway involved. No reply → wrong address/mask or link problem.' },
      { from: 'w', to: 'n', label: 'DNS A? srv01.corp.lab', note: 'Timeout → server down or firewall; "host unreachable" → wrong nameserver in resolv.conf.' },
      { from: 'n', to: 'w', label: 'A 10.0.20.10' },
      { from: 'w', to: 'r', label: 'ARP who-has 10.0.10.1', note: 'Remote destination → default route. ip neigh "FAILED" → wrong gateway address (net-wrong-gateway).', fail: false },
      { from: 'w', to: 'r', label: 'ICMP echo dst 10.0.20.10' },
      { from: 'r', to: 's', label: 'forward via eth1', note: 'ip_forward=0 on rtr01 → "Destination Host Unreachable" from 10.0.10.1 (net-ip-forward).' },
      { from: 's', to: 'r', label: 'echo reply via 10.0.20.1', note: 'Missing default route on srv01 → no reply at all (ssh-missing-gateway): the return path matters.' },
      { from: 'r', to: 'w', label: 'echo reply, ttl=63' },
    ],
  },
  files: [
    { path: '/etc/network/interfaces, /etc/network/interfaces.d/', platform: 'Debian (the lab), older Ubuntu', kind: 'config', perms: 'root:root 0644', contains: '`auto eth0`, `iface eth0 inet static` with `address 10.0.20.10/24`, `gateway 10.0.20.1`; or `iface eth0 inet dhcp`; `inet6` stanzas; VLAN and bridge options (ifupdown2 on sw01).', accessed: 'By ifup/ifdown: at boot (networking.service) and when you run them.', problems: 'Edits do nothing until the interface is re-applied. A wrong prefix (`/16`) or gateway is applied silently. ifdown uses the recorded state in /run/network/ifstate: changing a stanza before ifdown can leave old addresses behind.' },
    { path: '/etc/netplan/*.yaml', platform: 'Ubuntu 18.04+ (server and cloud images)', kind: 'config', perms: 'root:root 0600 (Ubuntu 24.04 warns if more open)', contains: 'YAML: `network: version: 2`, `renderer: networkd` or `NetworkManager`, `ethernets: ens18: addresses: [...]`, `routes: - to: default via: ...`, `nameservers:`. Files are merged in lexical order (50-cloud-init.yaml, 99-local.yaml).', accessed: 'By `netplan generate` (at boot and by `netplan apply/try`), which writes backend config to /run.', problems: 'YAML indentation errors ("Invalid YAML: inconsistent indentation") stop generation. cloud-init can regenerate 50-cloud-init.yaml at boot unless disabled with `network: {config: disabled}` in /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg.' },
    { path: '/etc/systemd/network/*.network, /run/systemd/network/', platform: 'systemd-networkd (Ubuntu via Netplan, minimal Debian, Arch)', kind: 'config', perms: 'root:root 0644', contains: '`[Match] Name=ens18`, `[Network] Address=`, `Gateway=`, `DNS=`, `DHCP=yes`. Netplan writes its generated files (`10-netplan-ens18.network`) to /run/systemd/network.', accessed: 'When systemd-networkd starts or on `networkctl reload` / `reconfigure`.', problems: 'On Netplan systems never edit /run/systemd/network: it is regenerated. A link not matched by any file is shown as "unmanaged" in `networkctl list`.' },
    { path: '/etc/NetworkManager/system-connections/*.nmconnection', platform: 'RHEL 9, Fedora, Ubuntu desktop', kind: 'config', perms: 'root:root 0600 (NM ignores files readable by others)', contains: 'Keyfile per connection profile: `[connection] id=`, `interface-name=`, `autoconnect=`; `[ipv4] method=manual`, `address1=10.0.20.10/24,10.0.20.1`, `dns=10.0.10.53;`.', accessed: 'At NetworkManager start and on `nmcli connection reload`; applied on `nmcli connection up`.', problems: 'Editing the file by hand needs `nmcli connection reload` and then `up` to take effect. RHEL 8 used `/etc/sysconfig/network-scripts/ifcfg-*`, deprecated in RHEL 9.' },
    { path: '/etc/resolv.conf', platform: 'Linux', kind: 'config', perms: 'root:root 0644 (or a symlink)', contains: '`nameserver` (up to 3), `search` domains, `options timeout:2 attempts:2`.', accessed: 'By glibc on every lookup (re-read when it changes).', problems: 'Often generated: a symlink to /run/systemd/resolve/stub-resolv.conf (systemd-resolved), "# Generated by NetworkManager", or rewritten by dhclient on DHCP hosts. Edit it directly only when it is a static regular file (ws01, srv01 in the lab).' },
    { path: '/etc/hosts, /etc/nsswitch.conf', platform: 'Linux', kind: 'config', perms: 'root:root 0644', contains: 'Static names; the order of name sources (`hosts: files dns`, on Ubuntu also `mdns4_minimal resolve`).', accessed: 'On every lookup through getent/glibc. `dig` and `nslookup` bypass both and query DNS directly.', problems: 'A stale /etc/hosts line wins over DNS: `getent hosts` and `dig` then disagree (net-hosts-override ticket).' },
    { path: '/var/lib/dhcp/dhclient.<iface>.leases', platform: 'Debian/Ubuntu with dhclient', kind: 'data', perms: 'root 0644', contains: 'Leases received: `fixed-address`, `option routers`, `option domain-name-servers`, lease time.', accessed: 'Written at every bind/renew; read at start to request the same address.', problems: 'Shows what the DHCP server actually handed out: a wrong router or DNS here is a DHCP server problem (dhcp-wrong-router), not a client one.' },
    { path: '/etc/sysctl.conf, /etc/sysctl.d/*.conf', platform: 'Linux', kind: 'config', perms: 'root:root 0644', contains: '`net.ipv4.ip_forward = 1` (routers), `net.ipv6.conf.all.forwarding`, `accept_ra` settings.', accessed: 'At boot by systemd-sysctl; `sysctl --system` re-applies.', problems: '`sysctl -w` alone is lost at reboot; a router that stops forwarding after a reboot usually lacks the persistent line (net-ip-forward).' },
    { path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{GUID}', platform: 'Windows Server 2019/2022, Windows 10/11', kind: 'registry', contains: 'Per-adapter IPAddress, SubnetMask, DefaultGateway, NameServer, EnableDHCP, DhcpIPAddress.', accessed: 'By the TCP/IP stack and DHCP Client service.', problems: 'Do not edit directly; use `New-NetIPAddress`, `Set-DnsClientServerAddress` or the adapter GUI. `netsh int ip reset` rewrites these keys (needs a reboot).' },
  ],
  management: [
    {
      platform: 'Any Linux: identify the manager first',
      tasks: [
        { task: 'Which manager runs this host?', command: 'systemctl status NetworkManager systemd-networkd networking\nls /etc/netplan /etc/network/interfaces /etc/NetworkManager/system-connections', explain: 'Exactly one should be active and own your interface. In the lab: NetworkManager and systemd-networkd "could not be found", networking is "active (exited)", /etc/netplan does not exist → **ifupdown**. Ubuntu server: networkd active + /etc/netplan/*.yaml → **Netplan + networkd**. RHEL: NetworkManager active + keyfiles.', sim: true },
        { task: 'Confirm with the manager\'s own tool', command: 'nmcli general status\nnetworkctl list', explain: 'NM: "STATE connected". networkd: the interface shows SETUP "configured"; "unmanaged" means networkd does **not** manage it (another manager does, or no .network file matches). On a host without them: "command not found" (the lab).' },
        { task: 'Who writes /etc/resolv.conf?', command: 'ls -l /etc/resolv.conf\nhead -3 /etc/resolv.conf', explain: 'Symlink to ../run/systemd/resolve/stub-resolv.conf → systemd-resolved. "# Generated by NetworkManager" → NM. Regular file on a DHCP host → dhclient rewrites it. Regular static file → edit it directly.', sim: true },
      ],
    },
    {
      platform: 'Debian / ifupdown (the lab)',
      tasks: [
        { task: 'Status of the network service', command: 'systemctl status networking\njournalctl -u networking -b', explain: '`active (exited)` is normal: ifup ran at boot and finished. The journal shows ifup and dhclient messages (DHCPDISCOVER, "No DHCPOFFERS received").', sim: true },
        { task: 'Live state', command: 'ip -br link\nip -br addr\nip route\nip neigh', explain: 'Compare with /etc/network/interfaces: what is configured vs what the kernel has.', sim: true },
        { task: 'Re-apply one interface', command: 'sudo ifdown eth0 && sudo ifup eth0', explain: 'Removes and re-adds the addresses and routes of that interface only. Not in the simulator: use `ifreload -a` (ifupdown2) or `systemctl restart networking` there.', risk: 'Run over SSH on that interface, your session dies after ifdown and ifup never runs. Use the console, or `nohup sh -c "ifdown eth0; ifup eth0" &`, or a scheduled rollback.' },
        { task: 'Re-apply everything', command: 'sudo systemctl restart networking\nsudo ifreload -a', explain: '`restart networking` = `ifdown -a` + `ifup -a` (all interfaces except lo). `ifreload -a` (ifupdown2, used on sw01) applies only differences.', risk: 'Drops every connection on every interface; if the new file is wrong, the host stays unreachable. On routers it interrupts all forwarded traffic.', sim: true },
        { task: 'Renew a DHCP lease', command: 'sudo dhclient -r eth0 && sudo dhclient -v eth0\ncat /var/lib/dhcp/dhclient.eth0.leases', explain: '`-r` releases, then DISCOVER/OFFER/REQUEST/ACK. The leases file shows the router and DNS servers received.', risk: '`-r` removes the address: your session over that interface drops.', sim: true },
        { task: 'Runtime-only changes (testing)', command: 'sudo ip addr add 10.0.10.26/24 dev eth0\nsudo ip route replace default via 10.0.10.1', explain: 'Immediate, no file changed: lost at the next ifdown/reboot. Good for testing a hypothesis, then make it persistent in /etc/network/interfaces. (The simulator models one IPv4 address per interface, so `ip addr add` of a second address is refused there; `ip route replace` works.)', risk: '`ip route del default` over SSH from another subnet cuts your session.' },
        { task: 'Why did it fail to come up?', command: 'journalctl -u networking -b -p warning\nsystemctl status networking', explain: 'ifup errors ("RTNETLINK answers: File exists", "Cannot find device", DHCP timeouts) are logged under networking.service.', sim: true },
      ],
    },
    {
      platform: 'Ubuntu 22.04/24.04: Netplan + systemd-networkd',
      tasks: [
        { task: 'Status', command: 'systemctl status systemd-networkd systemd-resolved\nnetworkctl list\nnetworkctl status ens18', explain: '`networkctl status` shows addresses, gateway, DNS and the last log lines for the link. OPERATIONAL "routable" + SETUP "configured" is healthy; "degraded" = link-local only; "no-carrier" = cable/vSwitch.' },
        { task: 'See the effective Netplan config', command: 'sudo netplan get\nls -l /etc/netplan/', explain: '`netplan get` prints the merged YAML of all files. Files must be 0600 on 24.04.' },
        { task: 'Validate YAML', command: 'sudo netplan generate', explain: 'Parses YAML and writes backend files to /run; prints the file, line and column of an error. Generates only: nothing is applied.' },
        { task: 'Apply with automatic rollback', command: 'sudo netplan try', explain: 'Applies, then waits 120 s for you to press ENTER; if you do not (because you lost the connection), it reverts to the previous config. `--timeout 60` changes the wait.', risk: 'Some changes (bonds, bridges, renaming) cannot always be reverted cleanly; netplan prints a warning. Keep console access.' },
        { task: 'Apply permanently', command: 'sudo netplan apply', explain: 'Regenerates backend config and reconfigures links. Unchanged interfaces usually keep their sessions; changed ones are re-applied.', risk: 'An address or gateway change on the interface you are connected through drops your session with no rollback.' },
        { task: 'Re-apply one link', command: 'sudo networkctl reconfigure ens18\nsudo systemctl restart systemd-networkd', explain: '`reconfigure` re-reads and re-applies config for one link (systemd 244+). Restarting the daemon re-applies all links.', risk: 'Both can briefly remove addresses on the affected links.' },
        { task: 'DNS', command: 'resolvectl status\nresolvectl query srv01.corp.lab\nsudo resolvectl flush-caches', explain: 'Per-link DNS servers and search domains; queries through the stub; flushes the cache. Change servers in Netplan `nameservers:`, not in /etc/resolv.conf.' },
      ],
    },
    {
      platform: 'RHEL 9 / Rocky / Alma: NetworkManager',
      tasks: [
        { task: 'Status', command: 'systemctl status NetworkManager\nnmcli general status\nnmcli device status\nnmcli connection show', explain: 'Device = interface, connection = profile. A device "disconnected" with an existing profile means the profile is not active (autoconnect off or failed); "unmanaged" means NM ignores it.' },
        { task: 'Details of one profile', command: 'nmcli connection show "ens18" | grep -E "^(ipv4|connection.autoconnect)"\nnmcli device show ens18', explain: 'Configured values (ipv4.addresses, ipv4.gateway, ipv4.dns, ipv4.method) vs live values (IP4.ADDRESS[1], IP4.GATEWAY, IP4.DNS[1]).' },
        { task: 'Change and re-apply a profile', command: 'sudo nmcli connection modify "ens18" ipv4.dns "10.0.10.53" ipv4.dns-search corp.lab\nsudo nmcli connection up "ens18"', explain: '`modify` writes the keyfile; `up` re-activates the profile so the change applies. `nmcli device reapply ens18` applies some changes without a full down/up.', risk: '`connection down` on your SSH interface disconnects you; `up` alone re-activates in place and is usually safer.' },
        { task: 'Restart the daemon', command: 'sudo systemctl restart NetworkManager', explain: 'NM re-reads everything; by design it tries to take over existing connections without tearing them down.', risk: 'Usually keeps sessions, but profiles with errors may not come back. Not a fix for a single bad profile.' },
        { task: 'Logs', command: 'journalctl -u NetworkManager -b', explain: 'State changes ("device (ens18): state change: activated -> deactivating"), DHCP transactions, errors.' },
      ],
    },
    {
      platform: 'Windows Server 2019/2022, Windows 10/11',
      tasks: [
        { task: 'Status', command: 'ipconfig /all\nGet-NetAdapter\nGet-NetIPConfiguration', explain: 'Adapter status and link speed, addresses (IPv4, Autoconfiguration 169.254.x.x = DHCP failed), gateway, DNS servers, DHCP lease times.' },
        { task: 'Routes and reachability', command: 'Get-NetRoute -DestinationPrefix 0.0.0.0/0\nTest-NetConnection srv01.corp.lab -Port 22\nTest-NetConnection srv01.corp.lab -TraceRoute', explain: 'Default route and metric; TCP test (TcpTestSucceeded True/False) including name resolution and ping.' },
        { task: 'DNS', command: 'Resolve-DnsName srv01.corp.lab\nipconfig /flushdns\nGet-DnsClientServerAddress -AddressFamily IPv4', explain: 'Resolve-DnsName uses the DNS client like applications do; /flushdns clears negative and positive cache entries.' },
        { task: 'Renew DHCP', command: 'ipconfig /release\nipconfig /renew', explain: 'Releases and requests a new lease.', risk: '`/release` over RDP disconnects you before `/renew` runs. Use `ipconfig /renew` alone, or run both in one line from a script.' },
        { task: 'Restart an adapter', command: 'Restart-NetAdapter -Name "Ethernet"', explain: 'Disables and re-enables the adapter: link down, all addresses re-applied.', risk: 'Drops every connection over it, including RDP. Use the hypervisor/iLO console.' },
        { task: 'Static configuration', command: 'New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 10.0.10.40 -PrefixLength 24 -DefaultGateway 10.0.10.1\nSet-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 10.0.10.53', explain: 'Persistent immediately (no separate apply).', risk: 'Remove the old address/gateway first (`Remove-NetIPAddress`, `Remove-NetRoute`) or you end up with two.' },
      ],
    },
    {
      platform: 'pfSense',
      tasks: [
        { task: 'Assign and address interfaces', command: 'Console menu: 1) Assign Interfaces, 2) Set interface(s) IP address', explain: 'Use the console (or hypervisor console) when the WebGUI is unreachable. Web: Interfaces > Assignments, Interfaces > [LAN].', risk: 'Changing the LAN address from the WebGUI cuts your browser session; pfSense offers to keep the anti-lockout rule on LAN.' },
        { task: 'Status and logs', command: 'Status > Interfaces; Diagnostics > Ping / Traceroute; Status > System Logs > System > General', explain: 'Link state, addresses, gateway status (Status > Gateways shows dpinger loss/latency).' },
      ],
    },
    {
      platform: 'Docker',
      tasks: [
        { task: 'Container networks', command: 'docker network ls\ndocker network inspect bridge\nip -br addr show docker0', explain: 'Docker creates its own bridges (docker0 172.17.0.1/16, br-xxxx for user networks) and NAT rules; containers do not use the host\'s network manager.', risk: 'Restarting nftables with a `flush ruleset` file removes Docker\'s NAT rules: containers lose outbound access until `systemctl restart docker`. NetworkManager must ignore docker0/veth (it does by default).' },
      ],
    },
  ],
  actions: [
    { action: 'Renew the DHCP lease (dhclient, ipconfig /renew)', when: 'The DHCP server changed (new router, DNS, address reservation) or the client has no/expired lease.', effect: 'New DHCP exchange; the address usually stays the same; router and DNS options are updated.', risk: 'Low with renew alone; a release first drops the address and your session.' },
    { action: 'Flush DNS / restart the resolver (resolvectl flush-caches, ipconfig /flushdns)', when: 'A DNS record was corrected but clients still get the old answer.', effect: 'Clears cached answers; nothing else changes.', risk: 'None. Does not help when the resolver configuration itself is wrong.' },
    { action: 'Re-apply one interface (ifdown/ifup, nmcli con up, networkctl reconfigure, Restart-NetAdapter)', when: 'You changed the configuration of that interface, or its state is wedged.', effect: 'Addresses and routes of that interface are removed and re-added from the configuration.', risk: 'Drops all sessions over it. If the config is wrong you stay disconnected: console or scheduled rollback required.' },
    { action: 'Restart the network manager (networking, NetworkManager, systemd-networkd)', when: 'Several interfaces changed, or the manager itself misbehaves.', effect: 'ifupdown: everything down then up. NM/networkd: re-read and re-apply all configuration (they try to keep unchanged links).', risk: '`systemctl restart networking` on a remote server is the classic self-lockout. Never use it to fix a DNS or single-service problem.' },
    { action: 'Reboot', when: 'Kernel/driver updates; proving that the persistent configuration is right.', effect: 'Everything is rebuilt from files: runtime `ip`/`sysctl -w` changes disappear.', risk: 'Longest outage; a broken config means the host returns unreachable, and boot may wait on network-online.target.' },
  ],
  workflow: [
    { question: '1. Which network manager is in charge?', command: 'systemctl status NetworkManager systemd-networkd networking\nls /etc/netplan', healthy: 'Unit NetworkManager.service could not be found.\nUnit systemd-networkd.service could not be found.\n● networking.service - Raise network interfaces\n     Active: active (exited) since Mon 2026-10-19 07:58:06 UTC; 35min ago\nls: cannot access \'/etc/netplan\': No such file or directory', broken: 'Two managers active for the same interface (e.g. ifupdown and NetworkManager both configuring eth0) → addresses that "come back" or vanish. Nothing active → configuration is never applied at boot.', next: 'Use only that manager\'s files and commands from now on. Lab → /etc/network/interfaces.', sim: true },
    { question: '2. Is there a link?', command: 'ip -br link\nethtool eth0', healthy: 'eth0             UP             52:54:00:d4:00:19 <BROADCAST,MULTICAST,UP,LOWER_UP>\n\tSpeed: 1000Mb/s\n\tDuplex: Full\n\tLink detected: yes', broken: '`<NO-CARRIER,...,UP>` / `state DOWN` / "Link detected: no" → cable, switch port, VM NIC disconnected in the hypervisor. `<BROADCAST,MULTICAST>` without UP → administratively down (`ip link set eth0 up`). `Speed: 100Mb/s` / `Duplex: Half` on a gigabit link → negotiation problem: slow, errors (`ip -s link` RX errors).', next: 'Link OK → step 3.', sim: true },
    { question: '3. Correct address and prefix?', command: 'ip -br addr', healthy: 'eth0             UP             10.0.10.25/24 fe80::5054:ff:fed4:19/64', broken: 'No IPv4 → DHCP failed (`journalctl -u networking`: "No DHCPOFFERS received"). `169.254.x.x` (Windows APIPA) → same. Wrong prefix (`10.0.10.25/16`) → hosts on other 10.0.x.x subnets are treated as local and ARPed directly (net-wrong-mask). Address from the wrong subnet → wrong VLAN or DHCP scope.', next: 'Compare with the config file and the DHCP lease; then step 4.', sim: true },
    { question: '4. Is there a correct default route?', command: 'ip route\nip route get 10.0.20.10', healthy: 'default via 10.0.10.1 dev eth0 onlink\n10.0.10.0/24 dev eth0 proto kernel scope link src 10.0.10.25\n10.0.20.10 via 10.0.10.1 dev eth0 src 10.0.10.25 uid 1000', broken: 'No `default` line → "Network is unreachable" for every remote address (ssh-missing-gateway: `RTNETLINK answers: Network is unreachable`). Gateway not on the local subnet or wrong (10.0.10.254) → step 5 fails.', next: 'Route present → is the gateway alive?', sim: true },
    { question: '5. Does the gateway answer (ARP + ICMP)?', command: 'ping -c 2 10.0.10.1\nip neigh', healthy: '64 bytes from 10.0.10.1: icmp_seq=1 ttl=64 time=0.950 ms\n10.0.10.1 dev eth0 lladdr 52:54:00:a1:00:01 REACHABLE', broken: '`10.0.10.254 dev eth0 FAILED` and "From 10.0.10.25 icmp_seq=1 Destination Host Unreachable" → nobody has that IP: wrong gateway address (net-wrong-gateway), or a VLAN/link problem. tcpdump shows repeated "ARP, Request who-has 10.0.10.254" without replies.', next: 'Gateway OK → beyond it (step 6).', sim: true },
    { question: '6. Can you reach a host beyond the gateway, by IP?', command: 'ping -c 2 10.0.20.10\ntracepath -n 203.0.113.80', healthy: '64 bytes from 10.0.20.10: icmp_seq=1 ttl=63 time=1.350 ms\n 1:  10.0.10.1     0.950ms\n 2:  203.0.113.80  1.150ms reached', broken: '"From 10.0.10.1 ... Destination Host Unreachable" → the **router** cannot deliver (forwarding off: net-ip-forward, or its own ARP fails). No replies at all → the return path (target\'s gateway, NAT) or a firewall drop. `* * *` / "no reply" for the last hops may only mean the target drops traceroute probes (srv01 does).', next: 'IP works → names (step 7). IP fails → the router and the far side.', sim: true },
    { question: '7. Does name resolution work, and through which server?', command: 'cat /etc/resolv.conf\ndig srv01.corp.lab\ngetent hosts srv01.corp.lab', healthy: 'nameserver 10.0.10.53\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR\nsrv01.corp.lab.		3600	IN	A	10.0.20.10\n;; SERVER: 10.0.10.53#53(10.0.10.53) (UDP)', broken: '";; communications error to 10.0.10.35#53: host unreachable" → wrong nameserver (net-dns-resolvconf). "timed out; no servers could be reached" while ping to the server works → firewall/DNS service down (case-dns-outage). status NXDOMAIN/SERVFAIL → the DNS server answers but the zone is wrong. `dig` OK but `getent` differs → /etc/hosts override.', next: 'Fix resolver config with the right manager (resolv.conf, Netplan, nmcli, DHCP option).', sim: true },
    { question: '8. Does the application port answer?', command: 'nc -zv srv01.corp.lab 22\ncurl -I http://srv01.corp.lab/', healthy: 'Connection to srv01.corp.lab (10.0.20.10) 22 port [tcp/ssh] succeeded!\nHTTP/1.1 200 OK', broken: 'Refused / timed out with all layers below OK → a service or firewall problem on the target, not a network configuration problem (see the SSH and nftables guides).', next: 'Done: record what was wrong and verify persistence.', sim: true },
  ],
  failures: [
    { symptom: 'connect: Network is unreachable (for every remote address)', causes: ['No default route (gateway line missing/typo)', 'Interface down or without address'], diagnose: ['ip route', 'ip -br addr', 'cat /etc/network/interfaces / netplan get / nmcli con show <name>'], fix: 'Add the gateway to the persistent config (`gateway 10.0.20.1`, Netplan `routes: - to: default`, `nmcli con mod ... ipv4.gateway`) and re-apply the interface from the console.', verify: 'ip route | grep default; ping -c 2 <gateway>' },
    { symptom: 'Destination Host Unreachable from the host\'s own address', causes: ['ARP for the gateway (or local target) fails: wrong gateway IP, wrong prefix, wrong VLAN, link problem'], diagnose: ['ip neigh (FAILED/INCOMPLETE)', 'tcpdump -n -i eth0 arp', 'ip -br addr (prefix)'], fix: 'Correct the gateway/prefix in the configuration; check the switch port VLAN.', verify: 'ip neigh shows REACHABLE for the gateway' },
    { symptom: 'Destination Host Unreachable from the router', causes: ['Router has forwarding disabled (net.ipv4.ip_forward=0)', 'Router cannot ARP the destination (host down, wrong VLAN)'], diagnose: ['sysctl net.ipv4.ip_forward (on router)', 'ip neigh (on router)', 'traceroute -n <dest> ("!H")'], fix: 'Enable forwarding persistently in /etc/sysctl.d/ and `sysctl --system`; fix the far-side host or VLAN.', verify: 'ping <dest> from the client' },
    { symptom: 'Pings by IP work, names fail ("Temporary failure in name resolution")', causes: ['Wrong nameserver in resolv.conf (typo, 8.8.8.8 that cannot see internal zones)', 'DNS server or its firewall down', 'resolv.conf rewritten by a manager'], diagnose: ['cat /etc/resolv.conf; ls -l /etc/resolv.conf', 'dig srv01.corp.lab; dig @10.0.10.53 srv01.corp.lab', 'resolvectl status (Ubuntu); nmcli device show (RHEL)'], fix: 'Correct the DNS servers where they come from (static file, Netplan, NM profile, DHCP option 6) and re-apply.', verify: 'getent hosts srv01.corp.lab' },
    { symptom: 'No IPv4 address on a DHCP client (APIPA 169.254.x.x on Windows)', causes: ['DHCP server down or listening on the wrong interface (dhcp-interface)', 'Pool exhausted', 'Wrong VLAN, no DHCP relay'], diagnose: ['journalctl -u networking -b (DHCPDISCOVER without OFFER)', 'systemctl status isc-dhcp-server (server)', 'tcpdump -n -i eth0 port 67 or port 68'], fix: 'Fix the server or relay, then renew on the client (`dhclient -v eth0`, `ipconfig /renew`).', verify: 'ip -br addr shows an address in the right subnet; lease file lists the expected router/DNS' },
    { symptom: 'Works until reboot, then the network is wrong again', causes: ['Change made only at runtime (`ip addr`, `ip route`, `sysctl -w`)', 'Edited a generated file (/run/systemd/network, resolv.conf managed by resolved/NM, cloud-init netplan file)'], diagnose: ['diff of live state (ip addr/route) vs config files', 'ls -l /etc/resolv.conf; head of generated files', 'netplan get / nmcli connection show'], fix: 'Write the change into the authoritative configuration of the active manager.', verify: 'Reboot in a maintenance window and repeat the workflow' },
    { symptom: 'Locked out after a network change on a remote server', causes: ['ifdown/restart networking/netplan apply/Restart-NetAdapter with a wrong config', 'Changed the address of the interface you were connected through'], diagnose: ['Console: ip -br addr; ip route; the config file'], fix: 'From the hypervisor/IPMI/iLO console restore the known-good copy and re-apply. Next time use netplan try or a scheduled rollback.', verify: 'SSH from your workstation works again' },
  ],
  verification: [
    { check: 'Link up at the expected speed', command: 'ip -br link; ethtool eth0 | grep -E "Speed|Duplex|Link detected"', expect: 'UP; Speed: 1000Mb/s; Duplex: Full; Link detected: yes' },
    { check: 'Address and prefix as designed', command: 'ip -br addr', expect: 'eth0 UP 10.0.10.25/24 ...' },
    { check: 'Default route via the right gateway', command: 'ip route | grep default', expect: 'default via 10.0.10.1 dev eth0' },
    { check: 'Gateway and a remote network reachable', command: 'ping -c 2 10.0.10.1 && ping -c 2 10.0.20.10', expect: '0% packet loss twice' },
    { check: 'Names resolve through the intended server', command: 'dig srv01.corp.lab | grep -E "status|SERVER"', expect: 'status: NOERROR; SERVER: 10.0.10.53#53' },
    { check: 'The configuration is persistent', command: 'grep -A3 "iface eth0" /etc/network/interfaces  # or netplan get / nmcli con show', expect: 'The same address, gateway and DNS as the live state' },
    { check: 'Survives a reboot', command: 'sudo reboot  # then repeat the checks above from the console and remotely', expect: 'Identical results' },
  ],
  refIds: ['ip', 'ss', 'ping-linux', 'traceroute', 'tracepath', 'ethtool', 'dig', 'getent', 'tcpdump', 'nft', 'sysctl', 'nmcli', 'networkctl', 'netplan', 'resolvectl', 'ipconfig', 'get-netadapter', 'get-netipconfiguration', 'get-netroute', 'tnc', 'resolve-dnsname', 'restart-netadapter', 'file:etc-network-interfaces', 'file:netplan', 'file:networkmanager', 'file:resolv.conf', 'file:hosts', 'file:nsswitch.conf', 'file:sysctl.conf', 'file:dhcpd.leases', 'proc:remote-network-change', 'proc:netplan-try', 'proc:nm-reconnect', 'proc:networkd-reconfigure', 'proc:dns-resolver-fix', 'proc:dhcp-renew', 'proc:windows-network-reset', 'proc:rollback'],
};

// ---------------------------------------------------------------------------
// Lesson
// ---------------------------------------------------------------------------

export const NETOPS_LESSON: Lesson = {
  id: 'netops',
  moduleId: 'A',
  title: 'Network configuration and recovery',
  level: 'intermediate',
  summary: 'Investigate a host\'s network from the physical interface up to the application, find out which network manager owns the configuration, and change it without locking yourself out.',
  concepts: ['net.ops', 'net.routing', 'net.arp', 'net.cidr', 'net.dhcp', 'dns.resolution', 'ops.recovery', 'svc.systemd'],
  mode: 'simulated',
  guide: NETOPS_GUIDE,
  caseStudyIds: ['linux-no-internet', 'shared-dependency'],
  objectives: ['N10-009:5.1', 'N10-009:5.2', 'N10-009:5.3', 'N10-009:5.5', '200-301:1.10', '200-301:3.1'],

  what: `
"The network is down" is a symptom, not a diagnosis. On a host, networking is a stack of separate pieces of state, and each one can be checked with one command:

| Layer | Question | Linux | Windows |
|---|---|---|---|
| Link | Is there carrier, at the right speed? | \`ip -br link\`, \`ethtool eth0\` | \`Get-NetAdapter\` |
| Address | Right address and prefix? | \`ip -br addr\` | \`ipconfig /all\`, \`Get-NetIPConfiguration\` |
| Route | Is there a default gateway? | \`ip route\`, \`ip route get X\` | \`Get-NetRoute\`, \`route print\` |
| Neighbour | Does the gateway answer ARP? | \`ip neigh\`, \`ping gw\` | \`arp -a\`, \`Get-NetNeighbor\` |
| Path | Can packets cross routers? | \`ping\`, \`tracepath\`, \`traceroute\` | \`tracert\`, \`Test-NetConnection -TraceRoute\` |
| Names | Do names resolve, via which server? | \`dig\`, \`getent hosts\`, \`resolvectl\` | \`Resolve-DnsName\`, \`nslookup\` |
| Port | Does the service answer? | \`nc -zv\`, \`curl\`, \`ss -tlnp\` (server) | \`Test-NetConnection -Port\` |
| Firewall | Is something dropping it? | \`nft list ruleset\`, \`tcpdump\` | \`Get-NetFirewallRule\` |

**Stop at the first layer that fails.** If there is no default route, DNS, SSH and HTTP will all fail, and none of them is the problem.

`,

  internals: `
### Three kinds of state
1. **Configuration** on disk: /etc/network/interfaces, /etc/netplan/*.yaml, NM keyfiles, /etc/resolv.conf, /etc/sysctl.d/.
2. **Live kernel state**: interfaces, addresses, routes, neighbour cache, sysctls. This is what \`ip\` shows and what packets use.
3. **The manager** that turns 1 into 2: once at boot (ifupdown), or continuously (NetworkManager, systemd-networkd).

Most "mysterious" network faults are a mismatch between 1 and 2: a runtime change that was never saved (lost at reboot), or a saved change that was never applied (works only after the next reboot). \`ip link set eth0 down\` followed by \`up\` shows this nicely in the lab: the kernel deletes the default route when the link goes down, and bringing the link up does not restore it; only \`systemctl restart networking\` (re-reading the file) does.

`,

  deployment: [
    {
      id: 'debian',
      platform: 'Debian 12 / ifupdown (the lab)',
      summary: 'Inspect and change a static interface configuration on a Debian host the safe way. Simulated steps work in the sandbox (ws01 as root, or alice with sudo).',
      prerequisites: ['Console access to the host (in the lab: the sandbox terminal is the console).', 'A copy of the current configuration.'],
      steps: [
        { title: 'Identify the manager', command: 'systemctl status NetworkManager systemd-networkd networking\nls /etc/netplan', what: 'Checks which network managers exist and which is active.', why: 'Changing the wrong files does nothing, and restarting the wrong service can break the right one.', expected: 'Unit NetworkManager.service could not be found.\nUnit systemd-networkd.service could not be found.\n● networking.service - Raise network interfaces\n     Active: active (exited) since ...\nls: cannot access \'/etc/netplan\': No such file or directory', simulated: true },
        { title: 'Record the live state', command: 'ip -br addr\nip route\ncat /etc/resolv.conf', what: 'Saves what currently works.', why: 'You need a baseline to compare with after the change, and to restore.', expected: 'eth0             UP             10.0.10.25/24 fe80::5054:ff:fed4:19/64\ndefault via 10.0.10.1 dev eth0 onlink\n10.0.10.0/24 dev eth0 proto kernel scope link src 10.0.10.25', simulated: true },
        { title: 'Back up the configuration', command: 'sudo cp -a /etc/network/interfaces /root/interfaces.good', what: 'Keeps a known-good copy.', why: 'Restoring a file is faster and safer than remembering what you changed.', expected: '' },
        { title: 'Arm a rollback (real systems)', command: 'sudo systemd-run --on-active=5min --unit=net-rollback /bin/sh -c \'cp /root/interfaces.good /etc/network/interfaces; systemctl restart networking\'', what: 'Creates a transient timer that restores the backup in 5 minutes.', why: 'If the change disconnects you, the host repairs itself.', expected: 'Running timer as unit: net-rollback.timer\nWill run service as unit: net-rollback.service' },
        { title: 'Edit the stanza', command: 'sudo nano /etc/network/interfaces', what: 'Change `address`, `gateway`, or switch `inet static` ↔ `inet dhcp`.', why: 'This file is the source of truth for ifupdown; `ip addr add` alone is lost at reboot.', expected: 'auto eth0\niface eth0 inet static\n    address 10.0.10.25/24\n    gateway 10.0.10.1', simulated: true },
        { title: 'Apply', command: 'sudo systemctl restart networking', what: 'Runs ifdown -a and ifup -a with the new file (on a single interface: `sudo ifdown eth0 && sudo ifup eth0`).', why: 'Configuration changes are only applied when ifup runs.', expected: '(no output on success; errors appear in journalctl -u networking)', simulated: true },
        { title: 'Verify layer by layer', command: 'ip -br addr\nip route\nping -c 2 10.0.10.1\ndig +short srv01.corp.lab', what: 'Link, address, route, gateway, DNS.', why: 'Proves the change did what you intended and nothing else broke.', expected: 'eth0             UP             10.0.10.25/24 ...\ndefault via 10.0.10.1 dev eth0 onlink\n64 bytes from 10.0.10.1: icmp_seq=1 ttl=64 time=0.950 ms\n10.0.20.10', simulated: true },
        { title: 'Cancel the rollback', command: 'sudo systemctl stop net-rollback.timer', what: 'Disarms the timer once you have confirmed access from a second session.', why: 'Otherwise the good change is reverted after 5 minutes.', expected: '' },
        { title: 'DHCP client: renew and read the lease', command: 'sudo dhclient -v eth0\ncat /var/lib/dhcp/dhclient.eth0.leases', what: 'On a DHCP host (ws02), renews and shows the options received.', why: 'The lease tells you whether a wrong router/DNS comes from the server.', expected: 'DHCPACK of 10.0.10.100 from 10.0.10.53\nbound to 10.0.10.100 -- renewal in 300 seconds.\n...\n  option routers 10.0.10.1;\n  option domain-name-servers 10.0.10.53;', simulated: true },
      ],
    },
    {
      id: 'ubuntu',
      platform: 'Ubuntu 24.04 Server: Netplan + systemd-networkd',
      summary: 'Change a static address with Netplan using its built-in rollback. Run on a real Ubuntu VM.',
      prerequisites: ['Ubuntu 22.04/24.04 server with console access.', 'sudo rights.'],
      steps: [
        { title: 'Confirm the stack', command: 'systemctl is-active systemd-networkd systemd-resolved\nnetworkctl list\nls -l /etc/netplan/', what: 'networkd active, links "configured", YAML files present.', why: 'Ubuntu desktop uses `renderer: NetworkManager` instead; check the YAML.', expected: 'active\nactive\n  2 ens18 ether    routable    configured\n-rw------- 1 root root 412 Apr 23 09:12 50-cloud-init.yaml' },
        { title: 'Stop cloud-init from overwriting your file (cloud images)', command: 'echo "network: {config: disabled}" | sudo tee /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg', what: 'Tells cloud-init not to regenerate 50-cloud-init.yaml.', why: 'Otherwise your manual change can be replaced at the next boot (the file header says so).', expected: 'network: {config: disabled}' },
        { title: 'Edit and validate', command: 'sudo nano /etc/netplan/50-cloud-init.yaml\nsudo netplan generate', what: 'Change addresses/routes/nameservers; generate checks the YAML.', why: 'YAML indentation mistakes are the most common Netplan error.', expected: '(no output when valid)' },
        { title: 'Apply with automatic rollback', command: 'sudo netplan try', what: 'Applies and waits 120 s for confirmation.', why: 'If you lose the connection, the old config returns by itself.', expected: 'Do you want to keep these settings?\n\nPress ENTER before the timeout to accept the new configuration\n\nChanges will revert in 120 seconds\nConfiguration accepted.' },
        { title: 'Verify', command: 'networkctl status ens18\nresolvectl status ens18\nip route', what: 'Addresses, gateway, DNS per link.', why: 'Confirm all three, not just "I can still log in".', expected: 'Current DNS Server: 10.0.10.53\ndefault via 10.0.20.1 dev ens18 proto static' },
      ],
    },
    {
      id: 'rhel',
      platform: 'RHEL 9 / Rocky / Alma: NetworkManager',
      summary: 'Configure a static address with nmcli; profiles are stored as keyfiles in /etc/NetworkManager/system-connections/. Run on a real VM.',
      prerequisites: ['RHEL-compatible 9.x with console access.'],
      steps: [
        { title: 'Inspect', command: 'nmcli device status\nnmcli connection show', what: 'Devices and profiles.', why: 'You modify the **profile** (connection name), which may differ from the device name.', expected: 'DEVICE  TYPE      STATE      CONNECTION\nens18   ethernet  connected  ens18' },
        { title: 'Modify the profile', command: 'sudo nmcli connection modify ens18 ipv4.method manual ipv4.addresses 10.0.20.10/24 ipv4.gateway 10.0.20.1 ipv4.dns 10.0.10.53 ipv4.dns-search corp.lab', what: 'Writes /etc/NetworkManager/system-connections/ens18.nmconnection.', why: 'Persistent configuration; nothing changes on the wire yet.', expected: '' },
        { title: 'Activate', command: 'sudo nmcli connection up ens18', what: 'Applies the profile to the device.', why: 'Changes made with modify only take effect on activation (or `nmcli device reapply`).', expected: 'Connection successfully activated (D-Bus active path: /org/freedesktop/NetworkManager/ActiveConnection/3)' },
        { title: 'Verify', command: 'nmcli device show ens18 | grep -E "IP4.(ADDRESS|GATEWAY|DNS)"\ncat /etc/resolv.conf', what: 'Live values and the NM-generated resolv.conf.', why: 'resolv.conf starts with "# Generated by NetworkManager": never edit it directly here.', expected: 'IP4.ADDRESS[1]:   10.0.20.10/24\nIP4.GATEWAY:      10.0.20.1\nIP4.DNS[1]:       10.0.10.53' },
      ],
    },
    {
      id: 'windows',
      platform: 'Windows Server 2019/2022, Windows 10/11 (PowerShell NetTCPIP)',
      summary: 'Inspect and configure a Windows host. Elevated PowerShell on a real machine; for remote servers use the hypervisor console or iLO.',
      prerequisites: ['Local Administrator rights for changes.'],
      steps: [
        { title: 'Inspect', command: 'Get-NetAdapter\nGet-NetIPConfiguration', what: 'Link state and speed; address, gateway, DNS per interface.', why: 'Same layers as on Linux.', expected: 'Name       InterfaceDescription                ifIndex Status  MacAddress         LinkSpeed\n----       --------------------                ------- ------  ----------         ---------\nEthernet   Microsoft Hyper-V Network Adapter         6 Up      00-15-5D-01-0A-28  10 Gbps\n\nInterfaceAlias       : Ethernet\nIPv4Address          : 10.0.10.40\nIPv4DefaultGateway   : 10.0.10.1\nDNSServer            : 10.0.10.53' },
        { title: 'Test the path and a port', command: 'Test-NetConnection srv01.corp.lab -Port 22\nResolve-DnsName srv01.corp.lab', what: 'Resolves, pings and opens TCP 22.', why: 'One command covers DNS + routing + port.', expected: 'ComputerName     : srv01.corp.lab\nRemoteAddress    : 10.0.20.10\nRemotePort       : 22\nTcpTestSucceeded : True' },
        { title: 'Static address and DNS', command: 'New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 10.0.10.40 -PrefixLength 24 -DefaultGateway 10.0.10.1\nSet-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 10.0.10.53', what: 'Persistent configuration, applied immediately.', why: 'No separate apply step, so a mistake over RDP disconnects you instantly.', expected: '' },
        { title: 'DHCP renew and DNS cache', command: 'ipconfig /renew\nipconfig /flushdns', what: 'Renews the lease; clears the resolver cache.', why: 'Different problems: lease vs cached answers.', expected: 'Successfully flushed the DNS Resolver Cache.' },
        { title: 'Last resort: restart the adapter', command: 'Restart-NetAdapter -Name Ethernet', what: 'Disables and enables the NIC.', why: 'Only for a wedged adapter; it drops all connections.', expected: '' },
      ],
    },
    {
      id: 'pfsense',
      platform: 'pfSense CE 2.7',
      summary: 'Firewall/router appliance: interfaces are assigned and addressed from the console menu or the WebGUI, and stored in config.xml. See the pfsense lesson.',
      prerequisites: ['Console access (VGA/serial or hypervisor console).'],
      steps: [
        { title: 'Assign interfaces', command: 'Console menu option 1 (Assign Interfaces)', what: 'Maps physical NICs (vtnet0, igb1) to WAN/LAN/OPTx, optionally with VLANs.', why: 'A wrong assignment after a hardware change or VM clone is a common reason nothing works.', expected: 'WAN  -> vtnet0\nLAN  -> vtnet1' },
        { title: 'Set addresses', command: 'Console menu option 2 (Set interface(s) IP address)', what: 'Sets static IPv4/IPv6 or DHCP on an interface and optionally enables the DHCP server on LAN.', why: 'Recovers access when the LAN address was changed wrongly from the WebGUI.', expected: 'The IPv4 LAN address has been set to 10.0.10.1/24' },
      ],
    },
    {
      id: 'docker',
      platform: 'Docker Engine 27 on Linux',
      summary: 'Containers get their network from Docker, not from the host\'s network manager. See the docker lesson.',
      prerequisites: ['Docker Engine installed.'],
      steps: [
        { title: 'Inspect Docker networks', command: 'docker network ls\ndocker network inspect bridge --format \'{{json .IPAM.Config}}\'', what: 'Lists bridge/host/none and user networks and their subnets.', why: 'A Docker subnet that overlaps a real LAN (e.g. 172.17.0.0/16 used in the company) makes those hosts unreachable from the Docker host.', expected: '[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]' },
        { title: 'After restarting the host firewall', command: 'sudo systemctl restart docker', what: 'Recreates Docker\'s NAT and filter rules.', why: 'A firewall reload that flushes the ruleset removes them; containers lose connectivity.', expected: '' },
      ],
    },
  ],

  configIntro: `
Each manager has its own configuration format, and only the active one's files matter. The directives below are the ones that cause most network outages; "compiled default" is the behaviour when the setting is absent.

> Validate before applying: \`netplan generate\` (YAML), \`nmcli connection show <name>\` (what NM will apply), \`ifup --no-act eth0\` (ifupdown dry run), and always keep the previous file.

### DNS: which resolver to touch
| How /etc/resolv.conf looks | Who owns DNS | How to change it | What to restart |
|---|---|---|---|
| Symlink to \`../run/systemd/resolve/stub-resolv.conf\`, \`nameserver 127.0.0.53\` | systemd-resolved (Ubuntu) | Netplan \`nameservers:\` / networkd \`DNS=\`; check with \`resolvectl status\` | \`netplan apply\`; \`resolvectl flush-caches\` for stale answers |
| "# Generated by NetworkManager" | NetworkManager | \`nmcli con mod <name> ipv4.dns ...\` then \`nmcli con up <name>\` | Nothing else |
| Regular file on a DHCP client (ws02) | dhclient (DHCP option 6) | Fix the DHCP server's \`option domain-name-servers\` | \`dhclient -v eth0\` to renew |
| Regular static file (ws01, srv01) | Nobody | Edit /etc/resolv.conf directly | Nothing: glibc re-reads it |

Representative \`resolvectl status\` (Ubuntu 24.04):
\`\`\`
Global
         Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
  resolv.conf mode: stub

Link 2 (ens18)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
Current DNS Server: 10.0.10.53
       DNS Servers: 10.0.10.53
        DNS Domain: corp.lab
\`\`\`
With resolved, \`dig\` against 127.0.0.53 tests the stub; \`dig @10.0.10.53\` tests the real server. Windows: \`ipconfig /all\` (DNS Servers), \`Resolve-DnsName\`, \`ipconfig /flushdns\`, \`Set-DnsClientServerAddress\`.

`,

  configFiles: [
    {
      platform: 'Debian / ifupdown (the lab)',
      items: [
        { path: '/etc/network/interfaces', purpose: 'auto/iface stanzas: static address, gateway, dhcp, inet6.' },
        { path: '/etc/network/interfaces.d/*', purpose: 'Additional stanzas included with `source`.' },
        { path: '/etc/resolv.conf', purpose: 'Static resolver file on ws01/srv01; rewritten by dhclient on ws02.' },
        { path: '/var/lib/dhcp/dhclient.eth0.leases', purpose: 'Leases received by dhclient.' },
        { path: '/etc/sysctl.conf, /etc/sysctl.d/', purpose: 'Persistent kernel settings (ip_forward on rtr01).' },
      ],
    },
    {
      platform: 'Ubuntu (Netplan + networkd/resolved)',
      items: [
        { path: '/etc/netplan/*.yaml', purpose: 'Source configuration (0600).' },
        { path: '/run/systemd/network/10-netplan-*.network', purpose: 'Generated networkd files; do not edit.' },
        { path: '/etc/systemd/resolved.conf(.d/)', purpose: 'Global resolver settings (fallback DNS, DNSSEC).' },
        { path: '/etc/resolv.conf → /run/systemd/resolve/stub-resolv.conf', purpose: 'Stub resolver 127.0.0.53.' },
      ],
    },
    {
      platform: 'RHEL 9 (NetworkManager)',
      items: [
        { path: '/etc/NetworkManager/system-connections/*.nmconnection', purpose: 'Keyfile profiles (0600).' },
        { path: '/etc/NetworkManager/NetworkManager.conf, conf.d/', purpose: 'Daemon settings (dns=, unmanaged-devices).' },
        { path: '/etc/sysconfig/network-scripts/ifcfg-*', purpose: 'Legacy format (RHEL 8 and earlier), deprecated in RHEL 9.' },
      ],
    },
    {
      platform: 'Windows',
      items: [
        { path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{GUID}', purpose: 'Per-adapter IPv4 configuration (use PowerShell, not regedit).' },
        { path: 'C:\\Windows\\System32\\drivers\\etc\\hosts', purpose: 'Static names, checked before DNS.' },
      ],
    },
  ],

  directives: [
    { name: 'address (ifupdown) / addresses (Netplan) / ipv4.addresses (NM)', compiledDefault: '(none)', recommended: 'CIDR notation with the correct prefix, e.g. 10.0.10.25/24', explanation: 'The interface address and prefix length. The prefix decides which destinations are "on-link" (ARPed directly) and which go to the gateway.', security: 'A too-large prefix (/16 instead of /24) makes the host ARP for addresses that are behind the router: they become unreachable (net-wrong-mask).' },
    { name: 'gateway / routes: - to: default via / ipv4.gateway', compiledDefault: '(none: no default route)', recommended: 'The router\'s address on the same subnet', explanation: 'Installs `default via <gw>`. Without it, only the local subnet is reachable ("Network is unreachable").', security: 'A wrong gateway sends traffic to a host that may not exist (ARP FAILED) or to the wrong device.' },
    { name: 'iface eth0 inet dhcp / dhcp4: true / ipv4.method auto', compiledDefault: 'static/manual if absent (ifupdown: interface not configured)', recommended: 'DHCP for clients, static for servers and infrastructure', explanation: 'Gets address, prefix, router (option 3) and DNS (option 6) from a DHCP server.', security: 'Servers on DHCP change address when the lease or reservation changes; DNS records then point to the old address.' },
    { name: 'dns-nameservers (ifupdown + resolvconf) / nameservers: / ipv4.dns', compiledDefault: '(from DHCP, or none)', recommended: 'Internal DNS servers (10.0.10.53) for hosts that need internal names', explanation: 'DNS servers the manager writes into the resolver configuration.', security: 'Public resolvers (8.8.8.8) do not know internal zones such as corp.lab and leak internal query names.' },
    { name: 'auto eth0 / optional: true (Netplan) / connection.autoconnect', compiledDefault: 'ifupdown: not brought up at boot without auto; Netplan: required; NM: yes', recommended: 'auto for every interface the host needs; optional: true for interfaces that may be absent', explanation: 'Whether the interface is configured at boot, and whether boot waits for it (network-online.target).', security: 'A missing NIC that is not optional delays boot ("A start job is running for Wait for Network to be Configured").' },
    { name: 'renderer (Netplan)', compiledDefault: 'networkd', recommended: 'networkd on servers, NetworkManager on desktops', explanation: 'Which backend Netplan generates configuration for.', security: 'Two managers for one interface fight; keep exactly one.' },
    { name: 'net.ipv4.ip_forward (sysctl)', compiledDefault: '0', recommended: '1 only on routers', explanation: 'Whether the kernel forwards packets between interfaces.', security: 'Enabling it on a normal server can turn it into an unintended router between networks.' },
    { name: 'search / ipv4.dns-search', compiledDefault: '(none, or the domain from DHCP option 15)', recommended: 'The internal domain (corp.lab)', explanation: 'Appended to short names: `ssh srv01` tries srv01.corp.lab.', security: 'Long search lists slow down every failed lookup.' },
  ],

  operateIntro: `
### Before you restart anything: who manages this host?
Every fix must go into the configuration of the manager that is actually running, otherwise it is overwritten or ignored. Check:
- \`systemctl status NetworkManager systemd-networkd networking\`: which one is active?
- \`ls /etc/netplan\`: YAML here means Netplan generates the real config (Ubuntu).
- \`nmcli general status\` / \`nmcli device status\`: NetworkManager's view.
- \`networkctl list\`: SETUP "configured" = networkd manages the link; "unmanaged" = it does not.
- \`/etc/network/interfaces\` with \`auto\`/\`iface\` stanzas and \`networking.service\` active: ifupdown (the lab).

In the lab, ws01 answers: "Unit NetworkManager.service could not be found.", "Unit systemd-networkd.service could not be found.", \`networking.service\` active (exited), and no /etc/netplan. So: **ifupdown**, configured in /etc/network/interfaces.

> **Remote sessions.** Re-applying an interface, restarting a network manager, releasing a DHCP lease or restarting an adapter on Windows all **disconnect sessions over that interface**. If the new configuration is wrong, you will not get back in. Have a console (hypervisor, IPMI/iLO/iDRAC, serial) or a scheduled rollback ready before you start.

### Procedures per network manager
**ifupdown (Debian, the lab)**
- Inspect: \`systemctl status networking\`, \`cat /etc/network/interfaces\`, \`journalctl -u networking -b\`.
- Re-apply one interface: \`sudo ifdown eth0 && sudo ifup eth0\` (bring it down **before** editing the stanza if you change addresses, because ifdown removes what the file says now).
- Re-apply all: \`sudo systemctl restart networking\` (= \`ifdown -a\` + \`ifup -a\`). ifupdown2 (sw01) has \`ifreload -a\`, which only applies differences.
- Risk: the restart briefly removes every address and route; on a remote server with a broken file you stay locked out.

**systemd-networkd**
- Inspect: \`systemctl status systemd-networkd\`, \`networkctl list\`, \`networkctl status ens18\`.
- Re-apply: \`sudo networkctl reload\` (re-read files), \`sudo networkctl reconfigure ens18\` (one link), \`sudo systemctl restart systemd-networkd\` (all links).

Representative output (Ubuntu 24.04 server):
\`\`\`
$ networkctl list
IDX LINK  TYPE     OPERATIONAL SETUP
  1 lo    loopback carrier     unmanaged
  2 ens18 ether    routable    configured

2 links listed.
\`\`\`
"routable/configured" is healthy. "degraded" = only link-local addresses; "no-carrier" = no link; "configuring" stuck = waiting for DHCP; "unmanaged" on your main NIC = networkd is not the manager (or no .network file matches).

**Netplan (Ubuntu)**
Netplan is a **generator**, not a daemon: it reads \`/etc/netplan/*.yaml\` and writes networkd files to \`/run/systemd/network/\` (or NetworkManager profiles to \`/run/NetworkManager/system-connections/\`).
\`\`\`
# /etc/netplan/50-cloud-init.yaml (Ubuntu 24.04, mode 0600)
network:
  version: 2
  renderer: networkd
  ethernets:
    ens18:
      addresses: [10.0.20.10/24]
      routes:
        - to: default
          via: 10.0.20.1
      nameservers:
        addresses: [10.0.10.53]
        search: [corp.lab]
\`\`\`
- \`sudo netplan get\`: merged configuration of all YAML files.
- \`sudo netplan generate\`: validate and generate only; YAML errors are reported with file, line and column.
- \`sudo netplan try\`: apply, then **revert automatically after 120 s** unless you press ENTER. This is the safe way to change a remote server's network: if you lose the connection, you simply wait two minutes.
- \`sudo netplan apply\`: apply permanently. Interfaces whose config changed are re-applied; if that is the interface you are connected through and the new config is wrong, your session is gone with no rollback.

**NetworkManager (RHEL 9, desktops)**
- Inspect: \`systemctl status NetworkManager\`, \`nmcli general status\`, \`nmcli device status\`, \`nmcli connection show\`.
- Change: \`sudo nmcli connection modify "ens18" ipv4.addresses 10.0.20.10/24 ipv4.gateway 10.0.20.1 ipv4.dns 10.0.10.53 ipv4.method manual\`, then \`sudo nmcli connection up "ens18"\`.
- Reconnect: \`sudo nmcli connection down "ens18" && sudo nmcli connection up "ens18"\` (disconnects!); \`sudo systemctl restart NetworkManager\` re-reads everything and normally keeps active connections.

Representative output (RHEL 9.4):
\`\`\`
$ nmcli general status
STATE      CONNECTIVITY  WIFI-HW  WIFI     WWAN-HW  WWAN
connected  full          enabled  enabled  enabled  enabled
$ nmcli device status
DEVICE  TYPE      STATE                   CONNECTION
ens18   ethernet  connected               ens18
lo      loopback  connected (externally)  lo
\`\`\`
Abnormal: STATE \`disconnected\` or \`connecting (getting IP configuration)\` (DHCP not answering), a device "unmanaged" (NM ignores it), CONNECTIVITY \`limited\` (no route to the Internet check host).

> Restarting the network is never the fix for "DNS does not resolve" or "the website is down": find the failing layer first.
### Safe recovery for remote servers
- **Out-of-band access first**: hypervisor console (Proxmox/VMware/Hyper-V), IPMI/iLO/iDRAC remote console, serial console, cloud provider serial console. Test it *before* the change.
- **Keep a known-good copy**: \`sudo cp -a /etc/network/interfaces /root/interfaces.good\` (or the netplan YAML / NM keyfile).
- **Scheduled rollback**: arm a timer that restores the good copy unless you cancel it:
\`\`\`
sudo systemd-run --on-active=5min --unit=net-rollback \\
  /bin/sh -c 'cp /root/interfaces.good /etc/network/interfaces; systemctl restart networking'
# change and test; if you can still log in:
sudo systemctl stop net-rollback.timer
\`\`\`
With \`at\`: \`echo 'cp /root/interfaces.good /etc/network/interfaces; systemctl restart networking' | sudo at now + 5 minutes\`, cancel with \`sudo atrm <job>\`.
- **Use the tool's own safety net**: \`netplan try\`; on NetworkManager, \`nmcli connection modify\` + \`nmcli connection up\` (a failed activation leaves the device disconnected, so pair it with a rollback timer too).
- **Change one thing at a time, test from a second session**, and keep the first session open until the new one works.

`,
  troubleshootingIntro: `
### A method for "the network does not work"
1. **Find the manager** (systemctl status NetworkManager systemd-networkd networking; ls /etc/netplan). Do not restart anything yet.
2. **Bottom-up on the client**: link (\`ip -br link\`, \`ethtool\`) → address (\`ip -br addr\`) → route (\`ip route\`) → gateway (\`ping\`, \`ip neigh\`) → beyond the gateway by IP (\`ping\`, \`tracepath\`) → names (\`dig\`, \`getent\`) → port (\`nc -zv\`).
3. **Stop at the first failing check** and explain it before going on. A failure higher up is usually a consequence.
4. **Compare live state with configuration**: is the fault in the file (it will come back after reboot) or only at runtime (it will disappear, or a correct change was never applied)?
5. **Remember the return path**: the far host needs a route back (its own gateway) and private addresses need NAT to reach the Internet.
6. **Apply safely**: console or scheduled rollback, one change at a time, verify from a second session, then verify persistence.

The tickets below cover a wrong prefix, a wrong gateway, a router that stopped forwarding, a wrong resolver address, a server without default route, a DHCP server handing out the wrong router, a switch port in the wrong VLAN, a missing IPv6 gateway, and two multi-fault case studies.

### Investigating with real output (lab, Debian 12)
**Link: \`ip -br link\`, \`ethtool eth0\`**
\`\`\`
lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP>
eth0             UP             52:54:00:d4:00:19 <BROADCAST,MULTICAST,UP,LOWER_UP>
\`\`\`
\`UP\` + \`LOWER_UP\` = administratively up **and** carrier. Abnormal: \`<NO-CARRIER,BROADCAST,MULTICAST,UP>\` with state \`DOWN\` (cable, switch port, VM NIC disconnected), or no \`UP\` flag at all (someone ran \`ip link set eth0 down\`). \`ethtool eth0\` should show \`Speed: 1000Mb/s\`, \`Duplex: Full\`, \`Link detected: yes\`; \`100Mb/s\` or \`Half\` on a gigabit port means a negotiation or cabling problem (slow transfers, errors in \`ip -s link\`). As a normal user, ethtool prints "netlink error: Operation not permitted" for some fields; that is not a fault.

**Address: \`ip -br addr\`**
\`\`\`
eth0             UP             10.0.10.25/24 fe80::5054:ff:fed4:19/64
\`\`\`
Abnormal: only a \`fe80::\` address (no IPv4: DHCP failed), a wrong prefix such as \`10.0.10.25/16\` (the net-wrong-mask ticket: the host then thinks 10.0.20.10 is on its own wire and ARPs for it instead of using the gateway).

**Route: \`ip route\`, \`ip route get\`**
\`\`\`
default via 10.0.10.1 dev eth0 onlink
10.0.10.0/24 dev eth0 proto kernel scope link src 10.0.10.25
$ ip route get 10.0.20.10
10.0.20.10 via 10.0.10.1 dev eth0 src 10.0.10.25 uid 1000
\`\`\`
\`ip route get\` shows the decision the kernel makes for one destination. Abnormal: no \`default\` line ("connect: Network is unreachable", "RTNETLINK answers: Network is unreachable"), or \`via 10.0.10.254\` when the router is .1.

**Neighbours: \`ip neigh\`**
\`\`\`
10.0.10.53 dev eth0 lladdr 52:54:00:b2:00:35 REACHABLE
10.0.10.1 dev eth0 lladdr 52:54:00:a1:00:01 REACHABLE
\`\`\`
Abnormal: \`10.0.10.254 dev eth0 FAILED\`: ARP got no answer, nobody has that address. ping then reports "From 10.0.10.25 icmp_seq=1 Destination Host Unreachable" (from **your own** address).

**Path: \`ping\`, \`tracepath\`, \`traceroute\`**
\`\`\`
$ tracepath -n 203.0.113.80
 1?: [LOCALHOST]                      pmtu 1500
 1:  10.0.10.1                                        0.950ms
 2:  203.0.113.80                                     1.150ms reached
     Resume: pmtu 1500 hops 2 back 2
\`\`\`
Abnormal: "From 10.0.10.1 icmp_seq=1 Destination Host Unreachable" (the **router** cannot deliver: net-ip-forward), \`!H\` in traceroute, or the first hop already silent. Caution: \`traceroute -n 10.0.20.10\` in the lab shows hop 1 and then \`* * *\`, because srv01's firewall drops the UDP probes while ping and SSH work. Silence is not proof of a fault.

**Names: \`dig\`, \`getent\`**
\`\`\`
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 33015
;; ANSWER SECTION:
srv01.corp.lab.		3600	IN	A	10.0.20.10
;; SERVER: 10.0.10.53#53(10.0.10.53) (UDP)
\`\`\`
Check \`status:\` and \`SERVER:\`. Abnormal: ";; communications error to 10.0.10.35#53: host unreachable" (a typo in resolv.conf: net-dns-resolvconf), "timed out ... no servers could be reached" while \`ping 10.0.10.53\` works (DNS blocked or named down: case-dns-outage), \`status: NXDOMAIN\` / \`SERVFAIL\` (the server answers, the zone is wrong). \`dig\` asks DNS directly; \`getent hosts\` follows \`/etc/nsswitch.conf\` like applications do, so a stale \`/etc/hosts\` line shows up only in getent.

**Ports and packets: \`ss\`, \`nc\`, \`tcpdump\`, \`nft\`**
\`ss -tlnp\` on the server lists listeners; \`nc -zv host 22\` tests from the client; \`tcpdump -n -i eth0 arp\` or \`port 53\` proves what is on the wire (e.g. repeated "ARP, Request who-has 10.0.10.254" with no reply); \`nft list ruleset\` shows what the host firewall drops.

**Real systems only (not in the simulator):** \`nmcli\`, \`networkctl\`, \`resolvectl\`, \`netplan\`. The Operate & recover tab covers them with output from named platforms.

`,

  errorMap: [
    { message: 'connect: Network is unreachable / RTNETLINK answers: Network is unreachable', layer: 'Route', meaning: 'No route matches the destination: typically no default route. No packet was sent.', firstCheck: 'ip route; ip route get DEST' },
    { message: 'From <own IP> icmp_seq=1 Destination Host Unreachable', layer: 'Neighbour (ARP)', meaning: 'Your host could not resolve the next hop\'s MAC: wrong gateway, wrong prefix, wrong VLAN, or the target is down.', firstCheck: 'ip neigh (FAILED); tcpdump -n -i eth0 arp' },
    { message: 'From <router IP> icmp_seq=1 Destination Host Unreachable / !H', layer: 'Remote router', meaning: 'The router received the packet but could not deliver it: forwarding disabled or it cannot ARP the destination.', firstCheck: 'sysctl net.ipv4.ip_forward and ip neigh on the router' },
    { message: '100% packet loss, no error lines', layer: 'Path / return path / firewall', meaning: 'Packets left but nothing came back: a drop rule, a missing return route on the far side, or missing NAT.', firstCheck: 'tcpdump on each hop; ip route on the target; nft list table ip nat on the router' },
    { message: ';; communications error to X#53: host unreachable', layer: 'Resolver configuration', meaning: 'The nameserver address in resolv.conf is not reachable (often a typo).', firstCheck: 'cat /etc/resolv.conf; ping the nameserver' },
    { message: ';; communications error to X#53: timed out / no servers could be reached', layer: 'DNS server / firewall', meaning: 'The DNS server got no answer through: named down or UDP/TCP 53 dropped.', firstCheck: 'ping X; dig @X from another network; ss -ulnp and nft on the DNS server' },
    { message: 'Temporary failure in name resolution', layer: 'Name resolution', meaning: 'The resolver got no usable answer (any of the two above).', firstCheck: 'dig NAME; getent hosts NAME' },
    { message: 'No DHCPOFFERS received.', layer: 'DHCP', meaning: 'DISCOVERs got no answer: DHCP server down, listening on another interface, wrong VLAN or no relay.', firstCheck: 'journalctl -u networking -b; systemctl status isc-dhcp-server on the server' },
    { message: 'eth0: <NO-CARRIER,BROADCAST,MULTICAST,UP> ... state DOWN', layer: 'Link', meaning: 'Interface enabled but no carrier: cable, switch port, or VM NIC disconnected.', firstCheck: 'ethtool eth0 (Link detected); switch port status; hypervisor NIC settings' },
    { message: 'Invalid YAML ... / Error in network definition (netplan)', layer: 'Configuration (Netplan)', meaning: 'The YAML cannot be parsed or a key is invalid; nothing is generated.', firstCheck: 'sudo netplan generate (shows file:line:column)' },
    { message: 'Error: Connection activation failed: IP configuration could not be reserved (nmcli)', layer: 'Configuration (NetworkManager)', meaning: 'DHCP got no lease or the static configuration could not be applied within the timeout.', firstCheck: 'journalctl -u NetworkManager -b; nmcli connection show <name>' },
  ],

  scenarioIds: ['net-wrong-mask', 'net-wrong-gateway', 'net-ip-forward', 'net-dns-resolvconf', 'ssh-missing-gateway', 'dhcp-wrong-router', 'vlan-access-port', 'ipv6-server-gateway', 'case-no-internet', 'case-dns-outage'],
  assessmentId: 'netops',
  references: [
    { title: 'ip(8), ip-route(8), ip-neighbour(8) (iproute2)', url: 'https://man7.org/linux/man-pages/man8/ip.8.html' },
    { title: 'Debian Reference: Network setup (ifupdown)', url: 'https://www.debian.org/doc/manuals/debian-reference/ch05.en.html' },
    { title: 'interfaces(5): ifupdown configuration', url: 'https://manpages.debian.org/bookworm/ifupdown/interfaces.5.en.html' },
    { title: 'Netplan documentation (netplan try, apply, YAML reference)', url: 'https://netplan.readthedocs.io/' },
    { title: 'systemd.network(5) and networkctl(1)', url: 'https://www.freedesktop.org/software/systemd/man/latest/systemd.network.html' },
    { title: 'resolvectl(1) / systemd-resolved.service(8)', url: 'https://www.freedesktop.org/software/systemd/man/latest/resolvectl.html' },
    { title: 'Red Hat: Configuring and managing networking (RHEL 9)', url: 'https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_and_managing_networking/index' },
    { title: 'nmcli(1)', url: 'https://networkmanager.dev/docs/api/latest/nmcli.html' },
    { title: 'Microsoft Learn: NetTCPIP PowerShell module', url: 'https://learn.microsoft.com/powershell/module/nettcpip/' },
    { title: 'Microsoft Learn: ipconfig', url: 'https://learn.microsoft.com/windows-server/administration/windows-commands/ipconfig' },
    { title: 'pfSense documentation: Console menu', url: 'https://docs.netgate.com/pfsense/en/latest/config/console-menu.html' },
    { title: 'RFC 1122: Requirements for Internet Hosts', url: 'https://www.rfc-editor.org/rfc/rfc1122' },
  ],
};

// ---------------------------------------------------------------------------
// Assessment
// ---------------------------------------------------------------------------

export const NETOPS_ASSESSMENT: Assessment = {
  id: 'netops',
  title: 'Network configuration and recovery: knowledge check',
  questions: [
    {
      id: 'netops-q-order',
      kind: 'order',
      level: 'beginner',
      prompt: 'A user says "the Internet is down". Put the checks on their Linux workstation in the order you should run them.',
      items: [
        'ip -br link (carrier on the interface)',
        'ip -br addr (address and prefix)',
        'ip route (default route present)',
        'ping the default gateway',
        'ping a remote host by IP address',
        'dig a name (resolver and DNS server)',
        'nc -zv / curl the application port',
      ],
      concepts: ['net.ops', 'net.routing', 'dns.resolution'],
      explanation: 'Bottom-up: each check depends on all checks before it. Stop at the first failure; everything above it is a consequence.',
    },
    {
      id: 'netops-q-identify',
      kind: 'single',
      level: 'beginner',
      prompt: 'You must change the gateway on this host. Which file do you edit?',
      exhibit: '$ systemctl status NetworkManager systemd-networkd networking\nUnit NetworkManager.service could not be found.\nUnit systemd-networkd.service could not be found.\n● networking.service - Raise network interfaces\n     Loaded: loaded (/lib/systemd/system/networking.service; enabled; preset: enabled)\n     Active: active (exited) since Mon 2026-10-19 07:58:06 UTC; 35min ago\n$ ls /etc/netplan\nls: cannot access \'/etc/netplan\': No such file or directory',
      options: [
        { text: '/etc/network/interfaces (ifupdown)', correct: true },
        { text: '/etc/netplan/50-cloud-init.yaml', misconception: 'There is no /etc/netplan on this host; Netplan is not used.' },
        { text: '/etc/NetworkManager/system-connections/eth0.nmconnection', misconception: 'NetworkManager is not even installed ("could not be found").' },
        { text: 'Nothing: use ip route replace default via ...', misconception: 'That changes only the live kernel state; it is lost at the next ifdown or reboot.' },
      ],
      concepts: ['net.ops', 'svc.systemd'],
      explanation: 'Only networking.service (ifupdown) is present and active, so /etc/network/interfaces is the source of truth. Identify the manager before editing or restarting anything.',
    },
    {
      id: 'netops-q-wrong-gateway',
      kind: 'single',
      level: 'intermediate',
      prompt: 'ws01 cannot reach any other subnet. What is the most likely cause?',
      exhibit: '$ ip route\ndefault via 10.0.10.254 dev eth0 onlink\n10.0.10.0/24 dev eth0 proto kernel scope link src 10.0.10.25\n$ ping -c 2 10.0.20.10\nFrom 10.0.10.25 icmp_seq=1 Destination Host Unreachable\nFrom 10.0.10.25 icmp_seq=2 Destination Host Unreachable\n$ ip neigh\n10.0.10.254 dev eth0 FAILED',
      options: [
        { text: 'The configured gateway 10.0.10.254 does not exist; ARP for it fails.', correct: true },
        { text: 'srv01 is down.', misconception: 'The error comes from ws01 itself (From 10.0.10.25): the packet never left the subnet because the next hop could not be resolved.' },
        { text: 'The router has IP forwarding disabled.', misconception: 'Then the "Destination Host Unreachable" would come from the router\'s address, and ARP for the gateway would succeed.' },
        { text: 'DNS is broken.', misconception: 'The ping uses an IP address; DNS is not involved.' },
      ],
      concepts: ['net.routing', 'net.arp'],
      explanation: 'An unreachable error from your own address plus a FAILED neighbour entry for the gateway means the next hop does not answer ARP. Fix the `gateway` line in the configuration (here 10.0.10.1) and re-apply.',
    },
    {
      id: 'netops-q-unreachable-source',
      kind: 'single',
      level: 'intermediate',
      prompt: 'ping 10.0.20.10 from ws01 prints "From 10.0.10.1 icmp_seq=1 Destination Host Unreachable". Where do you look next?',
      options: [
        { text: 'On rtr01 (10.0.10.1): forwarding (sysctl net.ipv4.ip_forward) and its neighbour table on eth1', correct: true },
        { text: 'ws01\'s default route', misconception: 'The packet reached the router, so ws01\'s route and ARP work.' },
        { text: '/etc/resolv.conf on ws01', misconception: 'No name is involved.' },
        { text: 'Restart networking on ws01', misconception: 'Nothing is wrong on ws01; restarting would only interrupt it.' },
      ],
      concepts: ['net.routing', 'net.ops'],
      explanation: 'The source of the ICMP error tells you which device gave up. Here the router could not deliver (net-ip-forward ticket: `net.ipv4.ip_forward = 0`).',
    },
    {
      id: 'netops-q-dns-exhibit',
      kind: 'single',
      level: 'beginner',
      prompt: 'Pinging srv01 by IP works. Names fail. What is wrong?',
      exhibit: '$ cat /etc/resolv.conf\n# Generated for corp.lab\nsearch corp.lab\nnameserver 10.0.10.35\noptions timeout:2 attempts:2\n$ dig srv01.corp.lab\n;; communications error to 10.0.10.35#53: host unreachable\n;; no servers could be reached',
      options: [
        { text: 'The nameserver address is mistyped (10.0.10.35 instead of 10.0.10.53).', correct: true },
        { text: 'The corp.lab zone has an error.', misconception: 'A zone error gives SERVFAIL or NXDOMAIN from a server that answers. Here no server is reached at all.' },
        { text: 'The default route is missing.', misconception: 'Pinging srv01 by IP works, so routing is fine.' },
        { text: 'Restart the network to refresh DNS.', misconception: 'A restart re-applies the same wrong address. Fix the file.' },
      ],
      concepts: ['dns.resolution'],
      explanation: '"host unreachable" for the DNS server itself, with a resolv.conf that names a different address than the real DNS server, points to the client configuration. On ws01 the file is static, so editing it is the correct fix.',
    },
    {
      id: 'netops-q-actions',
      kind: 'multi',
      level: 'intermediate',
      prompt: 'Which statements about renewing, re-applying, restarting and rebooting are correct? (Select all that apply.)',
      options: [
        { text: 'Renewing a DHCP lease picks up a corrected router or DNS option from the DHCP server.', correct: true },
        { text: '`systemctl restart networking` on Debian takes every interface down and up again.', correct: true },
        { text: 'Flushing the DNS cache fixes a wrong nameserver in the resolver configuration.', misconception: 'It only removes cached answers; the same wrong server is asked again.' },
        { text: 'A reboot proves that the persistent configuration is correct.', correct: true },
        { text: 'Restarting the network manager is a good first step when one website is down.', misconception: 'It disconnects sessions and does not fix service or DNS problems. Find the failing layer first.' },
      ],
      concepts: ['net.ops', 'ops.recovery', 'net.dhcp'],
      explanation: 'Each action fixes a different class of problem; choose by diagnosis, not by habit. Interface and manager restarts are disruptive; renew and cache flush are not.',
    },
    {
      id: 'netops-q-remote-safety',
      kind: 'multi',
      level: 'intermediate',
      prompt: 'You must change the address of a remote Ubuntu server\'s only interface over SSH. Which precautions are appropriate? (Select all that apply.)',
      options: [
        { text: 'Confirm that the hypervisor or iLO console works before starting.', correct: true },
        { text: 'Use `sudo netplan try` so the change reverts automatically if you cannot confirm it.', correct: true },
        { text: 'Keep a copy of the working YAML file.', correct: true },
        { text: 'Run `sudo netplan apply` and close the session immediately.', misconception: 'apply has no rollback, and closing the session removes your chance to test and confirm.' },
        { text: 'Test a new SSH login to the new address from a second terminal before confirming.', correct: true },
      ],
      concepts: ['ops.recovery', 'net.ops'],
      explanation: 'Plan for losing the session: out-of-band access, an automatic rollback (netplan try, systemd-run --on-active, at), a known-good copy, and testing from a second session before confirming.',
    },
    {
      id: 'netops-q-resolver-owner',
      kind: 'single',
      level: 'advanced',
      prompt: 'On a RHEL 9 server, /etc/resolv.conf begins with "# Generated by NetworkManager" and lists the wrong DNS server. What is the persistent fix?',
      options: [
        { text: 'sudo nmcli connection modify <profile> ipv4.dns 10.0.10.53 && sudo nmcli connection up <profile>', correct: true },
        { text: 'Edit /etc/resolv.conf and save.', misconception: 'NetworkManager rewrites the file the next time the connection is activated or the DHCP lease changes.' },
        { text: 'sudo resolvectl dns ens18 10.0.10.53', misconception: 'systemd-resolved is not in charge here (the header says NetworkManager), and resolvectl changes are runtime-only anyway.' },
        { text: 'sudo systemctl restart networking', misconception: 'RHEL 9 has no networking.service; NetworkManager manages the interfaces.' },
      ],
      concepts: ['dns.resolution', 'net.ops'],
      explanation: 'Change DNS where it comes from: the NM profile (or the DHCP server if the profile uses DHCP DNS). The header comment tells you who owns the file.',
    },
    {
      id: 'netops-q-link-down',
      kind: 'text',
      level: 'beginner',
      prompt: 'After `ip link set eth0 down` and `ip link set eth0 up` on ws01, `ip route` shows only `10.0.10.0/24 dev eth0 ...` and no default route. Which single command (as root, ifupdown) re-applies the full configuration from the file on the lab hosts?',
      accept: [/^(sudo\s+)?systemctl\s+restart\s+networking(\.service)?$/i, /^(sudo\s+)?ifreload\s+-a$/i, /^(sudo\s+)?ifdown\s+eth0\s*(&&|;)\s*(sudo\s+)?ifup\s+eth0$/i],
      placeholder: 'command',
      concepts: ['net.ops', 'net.routing', 'svc.systemd'],
      explanation: 'When a link goes down, the kernel deletes the routes through it; bringing the link up does not read the configuration again. `systemctl restart networking` (ifdown -a + ifup -a) or, for one interface, `ifdown eth0 && ifup eth0` restores what /etc/network/interfaces says. Over SSH on that interface, use the console.',
    },
    {
      id: 'netops-q-windows',
      kind: 'single',
      level: 'intermediate',
      prompt: 'A Windows Server shows `IPv4 Address: 169.254.18.7` in `ipconfig /all`. What does it mean, and what is the right next step?',
      options: [
        { text: 'DHCP failed and Windows assigned an APIPA address; check the DHCP server/relay and VLAN, then run ipconfig /renew.', correct: true },
        { text: 'The server has a valid public address.', misconception: '169.254.0.0/16 is link-local (APIPA), only usable on the local segment.' },
        { text: 'Run ipconfig /flushdns.', misconception: 'DNS cache has nothing to do with address assignment.' },
        { text: 'Restart-NetAdapter is always the fix.', misconception: 'If the DHCP server does not answer, the adapter gets APIPA again.' },
      ],
      concepts: ['net.dhcp', 'net.ops'],
      explanation: 'APIPA is the Windows equivalent of "No DHCPOFFERS received" on Linux. Fix the DHCP path first, then renew.',
    },
    {
      id: 'netops-q-traceroute',
      kind: 'single',
      level: 'advanced',
      prompt: 'From ws01, `ssh srv01` and `ping 10.0.20.10` work, but `traceroute -n 10.0.20.10` shows hop 1 (10.0.10.1) followed by `* * *` lines. What do you conclude?',
      options: [
        { text: 'Nothing is broken: srv01\'s firewall drops traceroute\'s UDP probes, so the last hop stays silent.', correct: true },
        { text: 'The router drops all traffic to srv01.', misconception: 'ping and SSH through the same router work.' },
        { text: 'srv01 has no default route.', misconception: 'Then ping replies would not come back either.' },
      ],
      concepts: ['net.icmp', 'fw.stateful', 'net.ops'],
      explanation: 'traceroute uses UDP to high ports by default; a default-deny host firewall drops them without an ICMP port-unreachable reply. Interpret silence together with other tests (ping, nc, `traceroute -I`, `tracepath`).',
    },
  ],
};
