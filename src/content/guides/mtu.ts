// Operate & recover guide: MTU on links and tunnels, path MTU discovery, and
// MSS clamping on routers.

import type { ServiceGuide } from '../types';

export const MTU_GUIDE: ServiceGuide = {
  purpose:
    'Every link has a **maximum transmission unit**: the largest IP packet it carries (Ethernet 1500, PPPoE 1492, typical VPNs 1380–1420, jumbo frames 9000). Hosts and routers cooperate to keep packets within the smallest MTU on the path: TCP announces an **MSS** from its own MTU, and routers report smaller links with **ICMP "fragmentation needed" / ICMPv6 "packet too big"** (path MTU discovery). Operationally, MTU faults have one recognisable signature: **small packets work, large ones vanish**. They come from MTU changes on one side of a link only, tunnels and PPPoE, and firewalls that drop ICMP. In the lab, rtr01\'s eth2 is the Internet uplink to ext01, which offers a large download and an HTTPS site.',
  architecture: [
    { q: 'What does it accomplish?', a: 'Keeps packets small enough for every link on the path without (IPv4) fragmentation, which is slow, fragile and often filtered.' },
    { q: 'How does it work internally?', a: 'Each interface has an MTU; the kernel never sends a packet larger than the egress MTU (or the cached path MTU for that destination). TCP sets DF and announces MSS = MTU − 40 (IPv4). A router that cannot forward a DF packet drops it and returns ICMP type 3 code 4 with the next-hop MTU; the sender caches that PMTU (10 minutes on Linux) and resends smaller. Frames larger than a receiving NIC\'s MTU are discarded by that NIC or driver without any notification.' },
    { q: 'Which protocols does it use?', a: 'IPv4 DF bit and fragmentation (RFC 791), PMTUD (RFC 1191), IPv6 PMTUD (RFC 8201, ICMPv6 type 2), TCP MSS option (RFC 879/9293), PLPMTUD (RFC 4821/8899) as a fallback that needs no ICMP.' },
    { q: 'Which ports and transport?', a: 'None of its own: ICMP type 3 code 4 and ICMPv6 type 2 must be allowed (as related traffic) wherever TCP or UDP flows.' },
    { q: 'Which processes and OS components implement it?', a: 'The kernel IP and TCP stacks and NIC drivers. Configuration: ifupdown (`mtu`), netplan, NetworkManager, systemd-networkd; nftables/iptables for MSS clamping; tunnel software (WireGuard, strongSwan, OpenVPN) sets tunnel MTUs. Windows: `netsh interface ipv4 ... mtu`. Cisco: `mtu`, `ip mtu`, `ip tcp adjust-mss`.' },
    { q: 'Which other services does it depend on?', a: 'Consistent MTU configuration on both ends of every link (including switches for jumbo frames), ICMP reachability back to the sender, and correct tunnel/encapsulation sizing. Applications that send large UDP (DNS with EDNS, NFS, some VPNs) depend on fragmentation working or on choosing small sizes.' },
    { q: 'How do requests travel?', a: 'ws01 → rtr01 → ext01: ws01 announces MSS 1460; ext01 announces 1460. A 1500-byte packet from ws01 meets rtr01\'s eth2: if eth2 has MTU 1492, rtr01 answers "fragmentation needed (mtu 1492)" and ws01 lowers its PMTU. Packets from ext01 to rtr01 that exceed eth2\'s MTU are dropped by rtr01\'s NIC on receipt, which no ICMP can report.' },
    { q: 'How do authentication and authorisation work?', a: 'Not applicable. Security note: ICMP "fragmentation needed" is unauthenticated, so modern kernels sanity-check it (minimum MTU, quoted packet must match a connection); dropping it entirely is still the wrong response.' },
    { q: 'How does it start at boot?', a: 'Interface MTUs are applied when interfaces come up (ifupdown/netplan/NM). Learned path MTUs start empty after boot. MSS clamping rules load with nftables.service.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'Nothing to terminate. But an MTU change takes effect immediately and clears learned PMTUs; a tunnel restart can change the MTU of its interface.' },
  ],
  ports: [
    { port: 'ICMP type 3 code 4', proto: 'ICMP', purpose: 'Fragmentation needed and DF set (carries the next-hop MTU)' },
    { port: 'ICMPv6 type 2', proto: 'ICMPv6', purpose: 'Packet too big (IPv6 PMTUD)' },
    { port: 'TCP option 2 (MSS)', proto: 'TCP', purpose: 'Maximum segment size announced in SYN and SYN-ACK' },
  ],
  processes: [
    { name: 'kernel (IP/TCP stack, NIC driver)', platform: 'Linux', role: 'Enforces MTU, PMTU cache, MSS, DF' },
    { name: 'ifupdown / netplan / NetworkManager / systemd-networkd', platform: 'Linux', role: 'Applies the configured MTU at interface up' },
    { name: 'nftables', platform: 'Linux routers (rtr01)', role: 'MSS clamping (`tcp option maxseg size set rt mtu`)' },
    { name: 'netsh / Set-NetIPInterface', platform: 'Windows', role: 'Interface MTU (NlMtu)' },
  ],
  dependencies: {
    title: 'What a 4.5 MB download from ext01 needs',
    rows: [
      { label: 'Client', nodes: [{ id: 'ws', label: 'ws01', sub: 'MTU 1500, MSS 1460', kind: 'client' }] },
      { label: 'LAN', nodes: [{ id: 'lan', label: 'Office link', sub: 'both ends 1500', kind: 'network' }] },
      { label: 'Router', nodes: [{ id: 'rtr', label: 'rtr01', sub: 'forwarding', kind: 'service' }, { id: 'icmp', label: 'ICMP type 3 passes', sub: 'related', kind: 'network' }, { id: 'clamp', label: 'MSS clamp', sub: 'if uplink < 1500', kind: 'os' }] },
      { label: 'Uplink', nodes: [{ id: 'wan', label: 'eth2 ↔ ext01', sub: 'same MTU both ends', kind: 'network' }] },
      { label: 'Server', nodes: [{ id: 'ext', label: 'ext01 nginx', sub: 'sends full segments', kind: 'external' }] },
    ],
    edges: [['ws', 'lan'], ['lan', 'rtr'], ['rtr', 'icmp'], ['rtr', 'clamp'], ['rtr', 'wan'], ['wan', 'ext']],
  },
  sequence: {
    title: 'Path MTU discovery when rtr01\'s uplink carries 1492',
    lanes: [{ id: 'w', label: 'ws01', sub: 'sender' }, { id: 'r', label: 'rtr01', sub: 'eth2 mtu 1492' }, { id: 'e', label: 'ext01', sub: '203.0.113.80' }],
    steps: [
      { from: 'w', to: 'r', label: '1500-byte packet, DF set' },
      { from: 'r', to: 'w', label: 'ICMP 3/4 fragmentation needed, mtu 1492', note: 'Dropped by a firewall → black hole: the sender retransmits 1500 forever.' },
      { from: 'w', to: 'w', label: 'cache PMTU 1492 for 203.0.113.80' },
      { from: 'w', to: 'r', label: '1492-byte packet' },
      { from: 'r', to: 'e', label: 'forwarded' },
      { from: 'e', to: 'r', label: '1500-byte frame', note: 'If ext01\'s side is 1500 and rtr01\'s eth2 1492: dropped on receipt, no ICMP at all.', fail: true },
    ],
  },
  files: [
    { path: '/etc/network/interfaces (mtu)', platform: 'Debian (the lab)', kind: 'config', contains: '`mtu 1492` inside an iface stanza.', accessed: 'ifup / ifreload -a / boot.', problems: 'Set on one side of a link only → silent drops of large frames from the other side.' },
    { path: '/etc/netplan/*.yaml, NetworkManager profiles, *.network', platform: 'Ubuntu, RHEL, systemd-networkd', kind: 'config', contains: '`mtu: 9000`; `802-3-ethernet.mtu`; `MTUBytes=`.', accessed: 'On apply / connection up.', problems: 'Jumbo frames enabled on hosts but not on the switch → large frames dropped by the switch.' },
    { path: '/etc/nftables.conf (forward chain)', platform: 'Linux routers', kind: 'config', contains: '`oifname "ppp0" tcp flags syn tcp option maxseg size set rt mtu`; ICMP accepted as related.', accessed: 'With nftables.service.', problems: 'A "drop icmp" rule before `ct state established,related accept` breaks PMTUD for everyone behind the router.' },
    { path: '/etc/wireguard/wg0.conf ([Interface] MTU =), OpenVPN tun-mtu / mssfix, strongSwan', platform: 'VPN gateways and clients', kind: 'config', contains: 'The tunnel interface MTU (wg-quick default 1420) and, for OpenVPN, `mssfix 1360` which clamps TCP inside the tunnel.', accessed: 'When the tunnel comes up.', problems: 'A tunnel MTU larger than the underlying path minus the encapsulation overhead makes large packets disappear inside the tunnel; a smaller one only costs a little throughput. Remote-access users report "some sites load, others hang".' },
    { path: '/proc/sys/net/ipv4/{ip_no_pmtu_disc,tcp_mtu_probing}, /proc/sys/net/ipv6/conf/*/mtu', platform: 'Linux', kind: 'runtime', contains: 'PMTUD switches (0 = PMTUD on), packetization-layer probing (0 = off, 1 = after black-hole detection, 2 = always), per-interface IPv6 MTU.', accessed: 'By the kernel on every connection; set persistently in /etc/sysctl.d/.', problems: '`ip_no_pmtu_disc = 1` sends without DF: hides black holes but relies on fragmentation, which firewalls often drop. `tcp_mtu_probing = 1` is a useful safety net on hosts behind networks you do not control.' },
    { path: 'Switch port / VLAN MTU (jumbo frames)', platform: 'Switches (Cisco `system mtu jumbo 9198`, Linux bridges)', kind: 'config', contains: 'Maximum frame size the switch forwards.', accessed: 'At port/VLAN configuration; some switches need a reload.', problems: 'Hosts with MTU 9000 behind a 1500-byte switch: every large frame is dropped by the switch, with no ICMP, because a switch is not a router.' },
    { path: 'ip route get DST (PMTU cache)', platform: 'Linux', kind: 'runtime', contains: '`cache expires 599sec mtu 1492` for destinations with a learned PMTU.', accessed: 'Updated by ICMP fragmentation-needed messages.', problems: 'Stale after a fix: changing the interface MTU or `ip route flush cache` clears it.' },
  ],
  management: [
    {
      platform: 'Debian (ws01, rtr01, ext01: the lab)',
      tasks: [
        { task: 'Interface MTUs', command: 'ip link show', explain: '`mtu N` per interface. Compare both ends of each link.', sim: true },
        { task: 'Change at runtime', command: 'ip link set dev eth2 mtu 1500', explain: 'Immediate; clears learned PMTUs. Persist in /etc/network/interfaces.', risk: 'Lowering the MTU of the interface you are connected through can cut your session.', sim: true },
        { task: 'Apply the persistent configuration', command: 'ifreload -a', explain: 'Re-applies /etc/network/interfaces, including mtu lines (removing a line restores 1500).', sim: true },
        { task: 'Largest packet that passes', command: 'ping -c 1 -M do -s 1472 203.0.113.80\nping -c 1 -M do -s 1464 203.0.113.80', explain: '-M do sets DF; -s is the data size (+28 bytes of headers). An error reply names the bottleneck MTU.', sim: true },
        { task: 'Path MTU hop by hop', command: 'tracepath -n 203.0.113.80', explain: 'Shows where pmtu drops and the final "Resume: pmtu N".', sim: true },
        { task: 'Cached path MTU', command: 'ip route get 203.0.113.80', explain: '`mtu 1492` after a fragmentation-needed message.', sim: true },
        { task: 'MSS in SYNs and retransmissions', command: 'tcpdump -n -i eth2 -c 20 tcp', explain: '`options [mss N]` in SYNs; the same seq range repeated = retransmissions of lost segments.', sim: true },
        { task: 'MSS clamping', command: 'nft add rule inet filter forward oifname "eth2" tcp flags syn tcp option maxseg size set rt mtu\nnft list chain inet filter forward', explain: 'Rewrites SYN MSS on the router; persist it in /etc/nftables.conf.', sim: true },
        { task: 'Does a download really complete?', command: 'curl -m 20 -o /dev/null -w "%{http_code} %{size_download}\\n" http://203.0.113.80/downloads/tools-2.4.1.tar.gz', explain: 'A real GET with a time limit; -I only tests headers.', sim: true },
      ],
    },
    {
      platform: 'Windows',
      tasks: [
        { task: 'Show and test', command: 'netsh interface ipv4 show subinterfaces\nping -f -l 1472 203.0.113.80', explain: '-f = DF, -l = data size. "Packet needs to be fragmented but DF set." = too big.' },
        { task: 'Set', command: 'netsh interface ipv4 set subinterface "Ethernet0" mtu=1400 store=persistent', explain: 'For VPN clients that need a lower MTU.' },
      ],
    },
    {
      platform: 'Cisco IOS',
      tasks: [
        { task: 'Interface and IP MTU, MSS adjust', command: 'show interfaces Gi0/1 | include MTU\nshow ip interface Gi0/1 | include MTU\ninterface Tunnel0\n ip mtu 1400\n ip tcp adjust-mss 1360', explain: '`mtu` is the layer-2 payload, `ip mtu` the IP packet size; adjust-mss clamps TCP.' },
      ],
    },
  ],
  actions: [
    { action: 'ip link set dev X mtu N', when: 'Test an MTU change.', effect: 'Immediate; learned PMTUs are flushed.', risk: 'Runtime only; lost at reboot. Remote sessions over that interface may stall.' },
    { action: 'Edit the interface configuration + ifreload -a', when: 'Make the MTU persistent.', effect: 'Re-applies all interface settings.', risk: 'Re-applying may briefly reconfigure addresses: use the console for remote routers.' },
    { action: 'MSS clamping rule', when: 'A router has a smaller uplink/tunnel MTU than its LAN (PPPoE, VPN).', effect: 'TCP endpoints use segments that fit; no PMTUD needed.', risk: 'Only TCP benefits; UDP (DNS, VPN, QUIC) still needs correct MTUs or PMTUD.' },
    { action: 'Allow ICMP type 3 / ICMPv6 type 2', when: 'Black holes caused by filtering.', effect: 'PMTUD works again.', risk: 'None worth the breakage of blocking it.' },
  ],
  workflow: [
    { question: '1. Is it size-related?', command: 'curl -I http://203.0.113.80/downloads/tools-2.4.1.tar.gz\ncurl -m 20 -o /dev/null http://203.0.113.80/downloads/tools-2.4.1.tar.gz', healthy: 'HTTP/1.1 200 OK, then a completed transfer', broken: 'Headers fine, download "0 out of N bytes received": large packets do not arrive.', next: 'Step 2.', sim: true },
    { question: '2. What is the largest packet that passes?', command: 'ping -c 1 -M do -s 1472 203.0.113.80\nping -c 1 -M do -s 1400 203.0.113.80', healthy: '1480 bytes from 203.0.113.80: icmp_seq=1 ttl=63', broken: '"Frag needed and DF set (mtu = N)" names a smaller link (PMTUD works). Silence at 1472 but replies at smaller sizes: large packets vanish without ICMP.', next: 'Step 3.', sim: true },
    { question: '3. Where is the smaller MTU?', command: 'tracepath -n 203.0.113.80\nip link show', healthy: 'Resume: pmtu 1500', broken: 'pmtu drops at a hop: that router\'s next link is smaller. Compare MTUs on both ends of that link.', next: 'Mismatch → step 4. Legitimate smaller link → step 5.', sim: true },
    { question: '4. Do both ends of the link agree?', command: 'ip link show eth2   (rtr01)\nip link show eth0   (ext01)', healthy: 'Same mtu on both', broken: 'Different values: frames from the bigger side are dropped by the smaller side.', next: 'Fix the wrong side persistently (ifupdown/netplan) and ifreload.', sim: true },
    { question: '5. Is PMTUD allowed to work?', command: 'nft list ruleset | grep -n icmp', healthy: 'ct state established,related accept before any ICMP drop', broken: 'ICMP dropped → black hole.', next: 'Allow ICMP type 3/ICMPv6 type 2; on routers with tunnels/PPPoE add MSS clamping.', sim: true },
    { question: '6. Is the fix effective and persistent?', command: 'curl -m 20 -o /dev/null http://203.0.113.80/downloads/tools-2.4.1.tar.gz\ngrep -n mtu /etc/network/interfaces', healthy: 'Transfer completes; configuration matches the intended MTU', broken: 'Works now, wrong after reboot → runtime-only change.', next: 'Done after a reboot test.', sim: true },
  ],
  failures: [
    { symptom: 'Downloads and HTTPS stall, ping/ssh/curl -I work', causes: ['MTU mismatch on one link (one side lowered)', 'PMTUD black hole (ICMP filtered) behind a tunnel/PPPoE link', 'Jumbo frames on hosts but not on the switch'], diagnose: ['ping -M do -s 1472 / smaller', 'tracepath -n', 'ip link on both ends', 'tcpdump: repeated full-size retransmissions'], fix: 'Make both ends agree; allow ICMP type 3; clamp MSS at the bottleneck.', verify: 'curl -o /dev/null completes; ping -M do -s 1472 passes (or reports the expected MTU)' },
    { symptom: 'VPN users: some sites load, others hang', causes: ['Tunnel MTU smaller than 1500 and remote sites drop ICMP'], diagnose: ['ping -M do -s 1372 across the tunnel', 'tcpdump on the tunnel interface'], fix: 'MSS clamping on the VPN gateway; correct tunnel MTU.', verify: 'Affected sites load' },
    { symptom: 'Storage/backup traffic between two jumbo-frame servers hangs, everything else fine', causes: ['Both servers at MTU 9000 but a switch (or a hypervisor vSwitch) in between at 1500'], diagnose: ['ping -M do -s 8972 OTHER-SERVER', 'ip link on both servers', 'switch port/VLAN MTU'], fix: 'Enable jumbo frames on every hop of that VLAN, or return the servers to 1500.', verify: 'ping -M do -s 8972 succeeds between the servers' },
    { symptom: 'IPv6 large transfers stall, IPv4 fine', causes: ['ICMPv6 type 2 (packet too big) filtered: IPv6 routers never fragment, so PMTUD is the only mechanism'], diagnose: ['ping -6 -M do -s 1452 DST', 'nft list ruleset | grep -n icmpv6'], fix: 'Allow ICMPv6 type 2 (and the other RFC 4890 types) on every firewall.', verify: 'ping -6 -M do reports "Packet too big" or succeeds; transfers complete' },
    { symptom: 'Everything behind a new PPPoE/DSL router: some HTTPS sites never load', causes: ['Uplink MTU 1492 and no MSS clamping; remote sites that filter ICMP never learn the smaller MTU'], diagnose: ['tcpdump -n -i ppp0 tcp (SYN options: mss 1460 leaving a 1492 link)', 'tracepath -n SITE'], fix: 'Add MSS clamping on the router ("tcp option maxseg size set rt mtu"), persistently.', verify: 'SYNs leave with mss 1452; the sites load' },
    { symptom: 'Large UDP (DNS over 1232 bytes, NFS) fails, TCP fine', causes: ['Fragments filtered or reassembly blocked'], diagnose: ['dig +bufsize=1232 vs larger', 'tcpdump for IP fragments'], fix: 'Smaller EDNS buffer (1232), allow fragments, or use TCP.', verify: 'Large responses succeed' },
  ],
  verification: [
    { check: 'Full-size path', command: 'ping -c 1 -M do -s 1472 203.0.113.80', expect: '1480 bytes from 203.0.113.80 (or a deliberate, documented lower PMTU)' },
    { check: 'Bulk transfer', command: 'curl -m 30 -o /dev/null http://203.0.113.80/downloads/tools-2.4.1.tar.gz', expect: 'Completes' },
    { check: 'TLS handshake over the path', command: 'curl -I https://203.0.113.80/', expect: 'HTTP/1.1 200 OK' },
    { check: 'Both ends of each link agree', command: 'ip link show (on both ends)', expect: 'Identical mtu values (or a documented, deliberate difference handled by clamping)' },
    { check: 'Clamped MSS on a small uplink', command: 'tcpdump -n -i eth2 -c 4 tcp', expect: 'SYNs leave with mss = uplink MTU − 40' },
    { check: 'Persistent', command: 'grep -n mtu /etc/network/interfaces; reboot test', expect: 'Same MTU after reboot' },
  ],
  refIds: ['ip', 'ping-linux', 'tracepath', 'tcpdump', 'nft', 'curl', 'file:etc-network-interfaces', 'file:nftables.conf', 'proc:mtu-diagnose'],
};
