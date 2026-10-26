// Operate & recover guide: NAT on the lab router (nftables masquerade/DNAT,
// conntrack), with the Windows, pfSense and Docker equivalents.

import type { ServiceGuide } from '../types';

export const NAT_GUIDE: ServiceGuide = {
  purpose:
    'NAT rewrites addresses as packets cross a router. **Source NAT (masquerade)** lets networks with private addresses (RFC 1918) reach the Internet behind one public address. **Destination NAT (port forwarding)** makes a server inside reachable on the public address. In the lab, rtr01 masquerades everything that leaves through its Internet-facing interface eth2 as 203.0.113.2, and forwards public port 80 to srv01. NAT is **stateful**: it remembers each connection in the kernel\'s connection tracking table. It is configured as part of the firewall (nftables `nat` chains), and it only works if the router routes and has IP forwarding switched on.',
  architecture: [
    { q: 'What does it do?', a: 'It saves public addresses and draws a clear boundary: thousands of inside hosts can share one public IPv4 address, because the router tells their connections apart by port number. This is called **PAT** (port address translation). Selected inside services can be made reachable from outside on chosen ports. NAT is **not** a security feature on its own; the filter rules are what decide which traffic is allowed.' },
    { q: 'How does it work inside?', a: 'netfilter evaluates the `nat` chains only for the **first packet of a connection**. `prerouting` (type nat, priority dstnat) can rewrite the destination (DNAT) before the routing decision; `postrouting` (priority srcnat) rewrites the source (SNAT/masquerade) after it. The decision is stored in the conntrack entry, and every later packet of the flow, in both directions, is translated from that entry. `masquerade` uses the outgoing interface\'s current address; `snat to` uses a fixed one. If the chosen source port is in use, the kernel picks another (that is PAT).' },
    { q: 'Which protocols does it use?', a: 'Rewrites IPv4 (and IPv6 with NPTv6/NAT66, rarely used) headers and TCP/UDP ports, fixing checksums. ICMP echo uses the identifier as a "port". Protocols that carry addresses inside the payload (FTP active mode, SIP) need helpers. NAT is defined in RFC 3022; private ranges in RFC 1918.' },
    { q: 'Which ports does it use?', a: 'No ports of its own. Port forwards are defined per protocol and port (e.g. `tcp dport 80 dnat to 10.0.20.10:80`). Masquerade allocates source ports from the ephemeral range on the public address.' },
    { q: 'Which processes and system components are involved?', a: 'Linux kernel netfilter (`nf_nat`, `nf_conntrack`), configured with `nft` from `/etc/nftables.conf` by `nftables.service`; `conntrack` (conntrack-tools) to inspect the table. Windows: `WinNAT` (`New-NetNat`, used by Hyper-V/containers) or RRAS NAT. pfSense: pf `nat`/`rdr` rules generated from Firewall > NAT. Docker: its own `DOCKER` chains (iptables-nft) for published ports and masquerade of container networks.' },
    { q: 'What does it depend on?', a: '**IP forwarding** on the router (`net.ipv4.ip_forward = 1`), routes to the inside and outside networks, and **filter rules** that allow the translated traffic (the forward chain sees the destination after DNAT). On the far side it needs nothing at all: that is the whole point. Port forwards also depend on the inside server listening, and on the inside server\'s default route pointing back through the NAT router (otherwise replies bypass the translation).' },
    { q: 'How does a connection travel?', a: 'Outbound: ws01 10.0.10.25:51177 → 203.0.113.80:80 arrives on eth0 → routed to eth2 → postrouting masquerade rewrites the source to 203.0.113.2:51177 → the reply to 203.0.113.2:51177 matches the conntrack entry and is rewritten back to 10.0.10.25:51177. Inbound port forward: ext01 → 203.0.113.2:80 → prerouting DNAT to 10.0.20.10:80 → routed to eth1 → forward chain filters it → srv01 replies to ext01 via its gateway rtr01 → reverse translation restores the source 203.0.113.2.' },
    { q: 'Is there any authentication?', a: 'None: NAT has no idea of users. Exposure is controlled by which ports are forwarded and by the forward-chain filter rules. A broad DNAT (all ports) publishes every service on the inside host, including SSH.' },
    { q: 'How does it start at boot?', a: 'The rules are part of `/etc/nftables.conf`, loaded by `nftables.service` (Before=network-pre.target). `ip_forward` is set by systemd-sysctl from `/etc/sysctl.d/`. Both must be persistent; NAT rules added with `nft add rule` at runtime disappear at reboot.' },
    { q: 'What happens if the rules disappear?', a: 'There is no NAT program that could crash; it is part of the kernel. If the ruleset is flushed (`systemctl stop nftables`, `restart`, or `nft flush ruleset`), new connections leave untranslated (private source, no replies from the Internet) and port forwards stop; existing flows keep their conntrack translation until they end. Clearing conntrack (`conntrack -F`) breaks existing translated connections.' },
  ],
  ports: [
    { port: 'per rule', proto: 'TCP/UDP', purpose: 'Port forwards, e.g. 203.0.113.2:80 → 10.0.20.10:80' },
    { port: '32768–60999', proto: 'TCP/UDP', purpose: 'Source ports chosen for masqueraded flows (kept from the client when free)' },
  ],
  processes: [
    { name: 'netfilter nat + conntrack (kernel)', platform: 'Linux (rtr01)', role: 'Translation on the first packet, then per-flow from the conntrack entry' },
    { name: 'nftables.service', platform: 'Debian/Ubuntu/RHEL', role: 'Loads /etc/nftables.conf (oneshot)' },
    { name: 'WinNAT / RRAS', platform: 'Windows Server 2019/2022, Windows 10/11', role: '`Get-NetNat`; RRAS NAT for routing-role servers' },
    { name: 'pf (nat/rdr)', platform: 'pfSense', role: 'Outbound NAT and port forwards from Firewall > NAT' },
    { name: 'dockerd (DOCKER chains)', platform: 'Docker hosts', role: 'DNAT for published ports, masquerade for container networks' },
  ],
  dependencies: {
    title: 'What a port forward (DNAT) on rtr01 needs',
    caption: 'Outbound masquerade needs the same chain minus the inside server, plus a masquerade rule covering every inside subnet.',
    rows: [
      { label: 'Outside', nodes: [{ id: 'ext', label: 'ext01', sub: '203.0.113.80', kind: 'external' }] },
      { label: 'Router', nodes: [{ id: 'dnat', label: 'prerouting DNAT', sub: 'eth2 tcp 80', kind: 'service' }, { id: 'fwd', label: 'forward filter', sub: 'allows post-DNAT', kind: 'network' }, { id: 'ipf', label: 'ip_forward=1', sub: 'sysctl', kind: 'os' }, { id: 'ct', label: 'conntrack', sub: 'reverse mapping', kind: 'data' }] },
      { label: 'Inside', nodes: [{ id: 'srv', label: 'srv01 nginx', sub: '10.0.20.10:80', kind: 'server' }, { id: 'gw', label: 'srv01 gateway', sub: 'via rtr01', kind: 'network' }] },
    ],
    edges: [['ext', 'dnat'], ['dnat', 'fwd'], ['fwd', 'ipf'], ['fwd', 'srv'], ['srv', 'gw', 'reply'], ['gw', 'ct', 'un-NAT']],
  },
  sequence: {
    title: 'ws01 → Internet through masquerade',
    lanes: [{ id: 'c', label: 'ws01', sub: '10.0.10.25' }, { id: 'r', label: 'rtr01', sub: 'eth2 203.0.113.2' }, { id: 'x', label: 'ext01', sub: '203.0.113.80' }],
    steps: [
      { from: 'c', to: 'r', label: 'SYN 10.0.10.25:51177 → .80:80' },
      { from: 'r', to: 'r', label: 'postrouting: masquerade', note: 'No matching masquerade rule (e.g. limited to another subnet) → packet leaves with a private source: no reply ever comes back (timeout).' },
      { from: 'r', to: 'x', label: 'SYN 203.0.113.2:51177 → .80:80' },
      { from: 'x', to: 'r', label: 'SYN-ACK → 203.0.113.2:51177' },
      { from: 'r', to: 'c', label: 'un-NAT via conntrack → 10.0.10.25', note: 'Filter must allow `ct state established,related` in forward, or replies are dropped.' },
    ],
  },
  files: [
    { path: '/etc/nftables.conf (table ip nat)', platform: 'Debian (rtr01, the lab), Ubuntu, RHEL', kind: 'config', perms: 'root:root 0755 (Debian ships it executable)', contains: '`table ip nat { chain prerouting { type nat hook prerouting priority dstnat; ... dnat to ... } chain postrouting { type nat hook postrouting priority srcnat; oifname "eth2" masquerade } }`.', accessed: 'At boot by nftables.service; on `systemctl reload nftables` / `nft -f`.', problems: 'A masquerade rule without `oifname` translates traffic between internal subnets too (servers see the router instead of the client). Restricting it by `ip saddr` forgets networks added later. A DNAT typo sends traffic to the wrong host/port.' },
    { path: '/etc/sysctl.d/*.conf (net.ipv4.ip_forward)', platform: 'Linux routers', kind: 'config', contains: '`net.ipv4.ip_forward = 1`.', accessed: 'At boot (systemd-sysctl), `sysctl --system`.', problems: 'Without forwarding, nothing is routed, so nothing is translated.' },
    { path: '/proc/net/nf_conntrack (via conntrack -L)', platform: 'Linux', kind: 'runtime', contains: 'One entry per flow with the original and reply tuples. A NATed flow\'s reply tuple shows the translated address (e.g. `dst=203.0.113.2`).', accessed: 'Updated per packet; entries time out.', problems: '`[UNREPLIED]` entries whose reply tuple still names a private address prove masquerade did not apply. A full table (`nf_conntrack: table full, dropping packet` in the kernel log) drops new connections.' },
    { path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\RemoteAccess\\Parameters; Get-NetNat', platform: 'Windows Server', kind: 'registry', contains: 'RRAS NAT configuration; WinNAT objects (internal prefix).', accessed: 'By RRAS / WinNAT at start.', problems: 'Only one WinNAT object per host is supported; overlapping prefixes with Hyper-V or Docker break each other.' },
    { path: '/cf/conf/config.xml (<nat>), /tmp/rules.debug', platform: 'pfSense', kind: 'config', contains: 'Outbound NAT mode and rules, port forwards; the generated pf ruleset.', accessed: 'On filter reload.', problems: 'Manual outbound NAT mode does not add rules for new interfaces/VLANs: new subnets go out untranslated. Port forwards without their associated filter rule are blocked.' },
    { path: 'iptables -t nat -S (DOCKER chain)', platform: 'Docker hosts', kind: 'runtime', contains: 'Docker\'s DNAT rules for published ports and MASQUERADE for container subnets.', accessed: 'Rewritten by dockerd when containers start/stop.', problems: 'Flushing the firewall (e.g. restarting nftables with `flush ruleset`) removes Docker\'s rules until dockerd is restarted.' },
  ],
  management: [
    {
      platform: 'Debian / nftables (rtr01, the lab)',
      tasks: [
        { task: 'Show the NAT rules', command: 'nft list table ip nat', explain: 'Check the masquerade rule covers every inside network (normally just `oifname "eth2" masquerade`) and each DNAT names the right host:port.', sim: true },
        { task: 'Show translated flows', command: 'conntrack -L', explain: 'For outbound flows the reply tuple should end in `dst=203.0.113.2` (translated) and be `[ASSURED]`; `[UNREPLIED]` with a private reply address = not translated.', sim: true },
        { task: 'Is forwarding on?', command: 'sysctl net.ipv4.ip_forward', explain: 'Must be 1 on the router.', sim: true },
        { task: 'Forward-chain filtering', command: 'nft list chain inet filter forward', explain: 'The forward chain sees the **post-DNAT** destination (10.0.20.10:80), so allow rules must use the inside address and port.', sim: true },
        { task: 'Validate and apply', command: 'nft -c -f /etc/nftables.conf\nsudo systemctl reload nftables', explain: 'Atomic replacement of the ruleset; existing flows keep their translations.', sim: true },
        { task: 'Watch the uplink', command: 'tcpdump -n -i eth2 -c 4', explain: 'Outbound packets must carry 203.0.113.2 as source; private sources here are the clearest sign of missing masquerade.', sim: true },
        { task: 'Logs', command: 'journalctl -u nftables -b\njournalctl -k -g conntrack', explain: 'Ruleset load errors; conntrack table-full messages.', sim: true },
      ],
    },
    {
      platform: 'RHEL (firewalld)',
      tasks: [
        { task: 'Masquerade and port forwards', command: 'sudo firewall-cmd --zone=external --add-masquerade --permanent\nsudo firewall-cmd --zone=external --add-forward-port=port=80:proto=tcp:toaddr=10.0.20.10 --permanent\nsudo firewall-cmd --reload', explain: 'firewalld generates the nftables nat rules; `--list-all --zone=external` shows them.' },
      ],
    },
    {
      platform: 'Windows Server 2019/2022, Windows 10/11',
      tasks: [
        { task: 'WinNAT', command: 'Get-NetNat\nGet-NetNatStaticMapping\nAdd-NetNatStaticMapping -NatName LabNAT -Protocol TCP -ExternalIPAddress 0.0.0.0 -ExternalPort 8080 -InternalIPAddress 172.20.0.10 -InternalPort 80', explain: 'Used for Hyper-V internal switches and containers. RRAS (Routing and Remote Access) provides classic NAT on a routing server.' },
      ],
    },
    {
      platform: 'pfSense',
      tasks: [
        { task: 'Outbound NAT', command: 'Firewall > NAT > Outbound (Automatic / Hybrid / Manual)', explain: 'Automatic covers every local interface subnet; Manual must be updated for each new network.' },
        { task: 'Port forward', command: 'Firewall > NAT > Port Forward (Filter rule association: add associated filter rule)', explain: 'pf needs both the rdr rule and a pass rule on WAN.' },
        { task: 'States', command: 'Diagnostics > States (filter by address)\npfctl -ss | grep 10.0.10.25', explain: 'Shows translations per flow (inside → public port mapping).' },
      ],
    },
    {
      platform: 'Docker',
      tasks: [
        { task: 'Published ports and their NAT', command: 'docker port web\nsudo iptables -t nat -S DOCKER', explain: '`-p 8080:80` creates `DNAT tcp dpt:8080 to:172.18.0.2:80`. Published ports bypass ufw/firewalld rules in INPUT; filter them in DOCKER-USER.' },
      ],
    },
  ],
  actions: [
    { action: 'systemctl reload nftables (nft -f)', when: 'After changing NAT or filter rules in /etc/nftables.conf.', effect: 'Atomically replaces the ruleset; established flows keep their conntrack translations.', risk: 'Low. Validate with `nft -c -f` first; a syntax error leaves the old ruleset in place.' },
    { action: 'systemctl restart nftables', when: 'Avoid on a router.', effect: '`ExecStop=nft flush ruleset` removes all rules (NAT and filter), then reloads.', risk: 'A window with no NAT and no filtering; if the file is broken, the router stays unfiltered and untranslated. Also deletes Docker\'s rules on a Docker host.' },
    { action: 'conntrack -D / -F', when: 'A flow is stuck with an old translation after a DNAT change (e.g. UDP flows that never time out).', effect: 'Deletes entries; the next packet is evaluated against the new rules.', risk: '`-F` breaks every translated connection through the router.' },
    { action: 'Interface restart / reboot', when: 'Not for NAT problems.', effect: 'Masquerade picks up a changed uplink address automatically.', risk: 'Interrupts every routed flow; runtime-only NAT rules are lost.' },
  ],
  workflow: [
    { question: 'Does the inside client reach the router, and does the problem start only beyond it?', why: 'NAT happens at the router. First make sure the client\'s own network works, so you know the problem is at or beyond the router.', command: 'ping -c 2 10.0.10.1\ncurl -m 5 -I http://203.0.113.80/', healthy: '64 bytes from 10.0.10.1 ...\nHTTP/1.1 200 OK', broken: '`curl: (28) ... Couldn\'t connect to server` while the gateway answers: the path breaks at the router or beyond it.', next: 'Go to step 2.', sim: true },
    { question: 'Does the router forward packets?', why: 'Without forwarding, the router never passes packets on, so NAT rules are never reached.', command: 'sysctl net.ipv4.ip_forward\nip route', healthy: 'net.ipv4.ip_forward = 1\ndefault via 203.0.113.1 dev eth2 onlink', broken: '0: nothing is routed at all. No default route on the router: it cannot reach the Internet itself.', next: 'Go to step 3.', sim: true },
    { question: 'Which source address do packets have when they leave?', why: 'This is the direct proof of whether masquerade works. Packets on the Internet side must carry the router\'s public address, otherwise replies can never find their way back.', command: 'tcpdump -n -i eth2 -c 4', healthy: 'IP 203.0.113.2.46573 > 203.0.113.80.80: Flags [S] ...', broken: '`IP 10.0.20.10 > 203.0.113.80`: masquerade did not apply to that inside network, so replies can never come back.', next: 'Go to step 4.', sim: true },
    { question: 'What do the NAT rules say?', why: 'If packets leave untranslated, the rules either do not exist or do not match these packets.', command: 'nft list table ip nat', healthy: 'chain postrouting {\n\ttype nat hook postrouting priority srcnat; policy accept;\n\toifname "eth2" masquerade\n}', broken: 'The masquerade rule is missing, names the wrong interface in `oifname`, or has a source condition (`ip saddr 10.0.10.0/24`) that leaves some inside networks out.', next: 'Fix the rule in /etc/nftables.conf, check it with `nft -c -f`, then reload.', sim: true },
    { question: 'Confirm with conntrack', why: 'The connection tracking table shows how the router actually translated each connection, and whether a reply ever arrived.', command: 'conntrack -L', healthy: 'tcp 6 117 ESTABLISHED src=10.0.10.25 dst=203.0.113.80 ... src=203.0.113.80 dst=203.0.113.2 ... [ASSURED]', broken: '`[UNREPLIED]`, with the reply direction addressed to the private source: the connection was not translated and no answer came back.', next: 'For port forward problems, go to step 6.', sim: true },
    { question: 'Port forward: can the outside reach the published service?', why: 'Test from outside, the way a real visitor would. Testing from inside does not go through the DNAT rule in the same way.', command: 'curl -I http://203.0.113.2/   (from ext01)', healthy: 'HTTP/1.1 200 OK', broken: 'A timeout: the DNAT rule is missing or has a typo, the forward chain drops the translated traffic, or the inside server sends its replies another way. "No route to host": the DNAT rule points at an inside address that does not exist.', next: 'Check the DNAT target with `nft list table ip nat`, the forward rules with `nft list chain inet filter forward` (they must allow 10.0.20.10:80), and srv01\'s `ip route`.', sim: true },
    { question: 'Is the inside server healthy, and does it reply through the NAT router?', why: 'Replies must go back through the same router so it can translate them back. A server with a different default gateway sends replies that the client will ignore.', command: 'ss -tlnp   (on srv01)\nip route   (on srv01)', healthy: 'LISTEN 0 511 0.0.0.0:80 ... nginx\ndefault via 10.0.20.1 dev eth0 onlink', broken: 'Nothing listening: a problem with the service itself. A default route through another gateway: replies bypass rtr01 and are never translated back.', next: 'Fix the server, then test again from outside.', sim: true },
  ],
  failures: [
    { symptom: 'Inside hosts (or one subnet) cannot reach the Internet; gateway reachable', causes: ['Masquerade missing or restricted to other subnets', 'Wrong oifname after an interface rename', 'ip_forward = 0'], diagnose: ['tcpdump -n -i eth2 (private source?)', 'nft list table ip nat', 'sysctl net.ipv4.ip_forward'], fix: 'Masquerade everything leaving the uplink (`oifname "eth2" masquerade`), persistently; reload.', verify: 'curl from each inside subnet; conntrack shows dst=203.0.113.2' },
    { symptom: 'Published service unreachable from outside', causes: ['DNAT typo (wrong address/port)', 'Forward filter written for the public port instead of the inside port', 'Inside server not listening or wrong gateway'], diagnose: ['nft list table ip nat', 'nft list chain inet filter forward', 'ss -tlnp and ip route on the server'], fix: 'Correct the DNAT target; allow the post-DNAT destination in forward; fix the server.', verify: 'curl -I http://203.0.113.2/ from ext01' },
    { symptom: 'Everything inside works except from the Internet after a firewall change', causes: ['Port forward rule lost (runtime-only rule, ruleset restarted)'], diagnose: ['nft list ruleset vs /etc/nftables.conf'], fix: 'Put the rule in the file and reload.', verify: 'Test after reboot' },
    { symptom: 'Servers see the router\'s address instead of real clients', causes: ['Masquerade without `oifname` (applies to internal traffic too)'], diagnose: ['nft list table ip nat', 'Server logs show 10.0.20.1 as client'], fix: 'Restrict masquerade to the uplink interface.', verify: 'Server log shows the real client address' },
    { symptom: 'pfSense: new VLAN has no Internet', causes: ['Outbound NAT in Manual mode without a rule for the new subnet', 'Missing pass rule on the new interface'], diagnose: ['Firewall > NAT > Outbound', 'Status > System Logs > Firewall'], fix: 'Add the subnet to outbound NAT (or use Hybrid/Automatic) and add pass rules.', verify: 'Diagnostics > States shows the translated flow' },
    { symptom: 'Docker published port stops working after a firewall reload', causes: ['nftables restart flushed Docker\'s DOCKER chains'], diagnose: ['sudo iptables -t nat -S DOCKER'], fix: 'Restart dockerd to recreate its rules; avoid `flush ruleset` on Docker hosts or exclude Docker tables.', verify: 'curl to the published port' },
  ],
  verification: [
    { check: 'NAT rules match the design', command: 'nft list table ip nat', expect: 'oifname "eth2" masquerade; iifname "eth2" tcp dport 80 dnat to 10.0.20.10:80' },
    { check: 'Outbound from every inside network', command: 'curl -I http://203.0.113.80/ (ws01, srv01, dev01)', expect: 'HTTP/1.1 200 OK from each' },
    { check: 'Translation visible', command: 'conntrack -L', expect: 'Reply tuples addressed to 203.0.113.2, [ASSURED]' },
    { check: 'Port forward from outside', command: 'curl -I http://203.0.113.2/ (ext01)', expect: 'HTTP/1.1 200 OK' },
    { check: 'Nothing else published', command: 'nc -zv -w 3 203.0.113.2 22 (ext01)', expect: 'timed out / refused' },
    { check: 'Persistent', command: 'grep -n masquerade /etc/nftables.conf; sysctl net.ipv4.ip_forward', expect: 'Rule in the file; forwarding 1 (and set in /etc/sysctl.d)' },
  ],
  refIds: ['nft', 'conntrack', 'tcpdump', 'sysctl', 'curl', 'iptables', 'firewall-cmd', 'pfctl', 'docker-network', 'file:nftables.conf', 'file:sysctl.conf', 'file:config.xml', 'file:pfsense-rules-debug', 'proc:nft-safe-reload', 'proc:remote-network-change'],
};
