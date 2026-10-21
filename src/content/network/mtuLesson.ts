import type { Lesson } from '../types';

export const MTU_LESSON: Lesson = {
  id: 'mtu',
  moduleId: 'A',
  title: 'MTU, fragmentation and path MTU discovery',
  level: 'advanced',
  summary: 'Why packet size matters: link MTU and frame size, IPv4 fragmentation and the DF bit, TCP MSS, path MTU discovery with ICMP "fragmentation needed" / "packet too big", black holes, MSS clamping on tunnels and PPPoE, and how to measure the path MTU with ping and tracepath.',
  concepts: ['net.mtu', 'net.icmp', 'tcp.handshake'],
  mode: 'simulated',

  what: `
The **MTU (maximum transmission unit)** is the largest IP packet a link can carry in one frame. Standard Ethernet: **1500 bytes** of IP packet (the frame adds 14 bytes of header and 4 of FCS, 18 more with an 802.1Q tag). Links with extra encapsulation carry less: PPPoE 1492, WireGuard 1420, GRE 1476, IPsec around 1400; data-centre links with **jumbo frames** carry 9000.

When a packet is larger than the next link's MTU, something has to give:
- **IPv4 without DF**: the router **fragments** it; the receiver reassembles.
- **IPv4 with DF (Don't Fragment)**, which is what TCP uses on Linux, Windows and macOS: the router **drops** it and sends back **ICMP "fragmentation needed"** with the next-hop MTU. The sender lowers its packet size for that destination. This is **path MTU discovery (PMTUD)**.
- **IPv6**: routers never fragment; they send **ICMPv6 "packet too big"**.

### Why this is a troubleshooting topic
MTU problems have a signature that confuses people: **small things work, big things hang**. ping works, DNS works, the SSH login works, \`curl -I\` returns headers, but file downloads stop at 0 bytes, TLS handshakes never finish (the certificate message fills full-size packets), \`git clone\` or \`apt update\` hang, a web page loads half. Two causes:
1. **MTU mismatch on a link**: the two ends disagree (1500 vs 1492, 9000 vs 1500). Frames larger than the receiver's MTU are dropped **silently**: there is no ICMP for this.
2. **PMTUD black hole**: a router with a smaller MTU sends "fragmentation needed", but a firewall somewhere drops ICMP, so the sender never learns and keeps retransmitting full-size packets.

### In the lab
Every link uses MTU 1500 in the baseline. rtr01's **eth2** is the Internet uplink to ext01 (203.0.113.80), which offers a 4.5 MB download (\`http://203.0.113.80/downloads/tools-2.4.1.tar.gz\`) and an HTTPS site. Change MTUs with \`ip link set dev X mtu N\` (runtime) or \`mtu N\` in /etc/network/interfaces (persistent) and watch the effects.

> The simulator implements per-interface MTU, packet sizes from headers and payload, the DF bit (set for TCP and for \`ping -M do\`), router-generated ICMP "fragmentation needed" / ICMPv6 "packet too big" with the next-hop MTU, the per-destination PMTU cache (\`ip route get\` shows it), silent drops of frames larger than the receiving interface's MTU, TCP MSS in SYNs, segmentation, retransmission with exponential backoff (tcp_retries2), \`ping -s/-M\`, \`tracepath\`, and nftables MSS clamping (\`tcp option maxseg size set rt mtu\`). Simplified: IPv4 fragments are not shown as separate packets, no PLPMTUD (RFC 8899) probing, large HTTP bodies beyond 64 KiB are accounted for in time rather than sent segment by segment.
`,

  internals: `
### Sizes on the wire
\`\`\`
| Ethernet 14 | IPv4 20 | TCP 20 (+12 options) | data | FCS 4 |
              |<------------------ IP packet: MTU 1500 ------->|
                        |<- MSS 1460 announced in the SYN ->|
\`\`\`
- **MTU** counts the IP packet: IP header + transport header + data.
- **MSS** (maximum segment size) counts TCP data only: MTU − 20 (IPv4) − 20 (TCP) = **1460**; IPv6: MTU − 40 − 20 = **1440**. Linux announces this in the SYN (option "mss 1460" in tcpdump). With timestamps each segment then carries 12 bytes of options, so full segments hold 1448 bytes of data.
- **ping -s N** sets the ICMP data size: the packet is N + 8 (ICMP) + 20 (IP) bytes. So \`ping -M do -s 1472\` is exactly 1500 bytes: the largest that fits standard Ethernet.

### TCP's protection: the MSS
Each side announces the MSS derived from **its own** interface MTU, and each sender uses the smaller of the peer's MSS and its own path MTU. So a host on a 1492 link announces 1452 and the other side never sends more. That is why MTU problems appear only when the bottleneck is **between** the endpoints (a tunnel, PPPoE on a router) or when **one side of a link** disagrees with the other.

### Path MTU discovery step by step (RFC 1191, RFC 8201)
1. The sender transmits a 1500-byte segment with DF set.
2. A router whose next hop has MTU 1492 cannot forward it: it drops it and returns **ICMP type 3 code 4** "fragmentation needed", including the next-hop MTU (1492) and the start of the dropped packet.
3. The sender's kernel stores **PMTU 1492** for that destination (\`ip route get DST\` shows \`mtu 1492\`, expiring after 10 minutes), and TCP retransmits the data in smaller segments.
4. Applications notice nothing but a short delay. \`ping -M do\` shows the mechanism: the first attempt reports "Frag needed and DF set (mtu = 1492)" from the router, the next one fails locally with "message too long, mtu=1492".

### What breaks it
- **ICMP filtered**: "block all ICMP" rules on firewalls or hosts drop the "fragmentation needed" messages. Stateful firewalls normally accept them as **related** to the connection (\`ct state established,related accept\`); rules placed before that, or stateless ACLs, break PMTUD. Result: a **black hole**.
- **Mismatched MTU on one link**: if a host or router interface has a smaller MTU than the other end of the same link, frames from the other end are discarded on receipt. No router is involved, so no ICMP is generated at all.
- **Tunnels and overlays** (VPN, VXLAN, GRE, PPPoE) that reduce the MTU on a path whose endpoints do not know about it.

### The fixes, from best to worst
1. **Correct MTUs**: both ends of each link equal; tunnel interfaces set to the real payload size.
2. **Allow the ICMP that PMTUD needs**: ICMP type 3 (all codes, especially 4) and ICMPv6 type 2 (packet too big). Never "drop all ICMP" (RFC 4890 for IPv6).
3. **MSS clamping** on the router at the bottleneck: rewrite the MSS option in SYNs so endpoints never send packets that do not fit: \`tcp flags syn tcp option maxseg size set rt mtu\` (nftables) or \`ip tcp adjust-mss 1452\` (Cisco). Standard on PPPoE and VPN gateways. Only helps TCP.
4. Lowering the MTU on clients: works for those clients only; a workaround, not a fix.

### Measuring
- \`ping -M do -s 1472 DST\` (Linux) / \`ping -f -l 1472 DST\` (Windows): does a full-size packet pass? Then bisect the size down until it does: largest size + 28 = path MTU.
- \`tracepath -n DST\`: discovers the path MTU hop by hop (\`pmtu 1492\` lines, "Resume: pmtu 1492").
- \`ip link\` on both ends of every link; \`ip route get DST\` for the cached PMTU.
- \`tcpdump\`: SYN MSS values, repeated retransmissions of the same full-size segment, and any ICMP "need to frag" messages.
`,

  deployment: [
    {
      id: 'linux-mtu',
      platform: 'Linux: set and verify MTU',
      summary: 'Runtime and persistent MTU changes, and checking the path. Steps marked "simulated" work in the sandbox.',
      prerequisites: ['Root access; know the MTU of the other end of the link (switch port, provider, tunnel).'],
      steps: [
        { title: 'Show MTUs', command: 'ip link show\nip -d link show eth2', what: 'The mtu value of every interface.', why: 'Both ends of a link must agree; sub-interfaces (VLAN) cannot exceed their parent.', expected: '4: eth2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP', simulated: true },
        { title: 'Change at runtime', command: 'sudo ip link set dev eth2 mtu 1500', what: 'Takes effect immediately and clears the learned path MTUs.', why: 'Use to test; lost at reboot.', expected: '', simulated: true },
        { title: 'Make it persistent (ifupdown)', command: 'sudoedit /etc/network/interfaces\n\niface eth2 inet static\n    address 203.0.113.2/24\n    gateway 203.0.113.1\n    mtu 1500\n\nsudo ifreload -a', what: 'The mtu option in the interface stanza.', why: 'netplan: `mtu: 1500` under the interface; NetworkManager: `nmcli con mod NAME 802-3-ethernet.mtu 1500`; systemd-networkd: `MTUBytes=` in [Link].', expected: '', simulated: true },
        { title: 'Verify the path', command: 'ping -c 2 -M do -s 1472 203.0.113.80\ntracepath -n 203.0.113.80', what: 'A full-size packet with DF set, then the hop-by-hop PMTU.', why: 'Proves the whole path carries 1500 bytes, not just the first link.', expected: '1480 bytes from 203.0.113.80: icmp_seq=1 ttl=63 time=0.9 ms\n     Resume: pmtu 1500 hops 2 back 2 ', simulated: true },
      ],
    },
    {
      id: 'mss-clamp',
      platform: 'Linux router: MSS clamping (PPPoE, VPN)',
      summary: 'Make TCP endpoints use segments that fit a smaller uplink.',
      prerequisites: ['A router whose uplink or tunnel has a smaller MTU than the LAN.'],
      steps: [
        { title: 'Add the rule', command: 'sudo nft add rule inet filter forward oifname "eth2" tcp flags syn tcp option maxseg size set rt mtu', what: 'Rewrites the MSS option of SYNs leaving via eth2 to the route MTU minus 40.', why: '"rt mtu" follows the interface/route MTU automatically; a fixed value (`set 1452`) is also possible. Clamping in both directions needs the rule for SYN-ACKs too (iifname "eth2").', expected: '', simulated: true },
        { title: 'Persist it', command: 'sudoedit /etc/nftables.conf   # in chain forward:\n        oifname "eth2" tcp flags syn tcp option maxseg size set rt mtu\nsudo nft -c -f /etc/nftables.conf && sudo systemctl reload nftables', what: 'Same rule in the configuration file.', why: 'Runtime rules disappear at reboot.', expected: '', simulated: true },
        { title: 'Check the effect', command: 'sudo tcpdump -n -i eth2 -c 4 tcp', what: 'SYNs leaving eth2 should carry the clamped MSS.', why: 'Compare with the same SYN on the LAN side (mss 1460).', expected: 'IP 203.0.113.2.45451 > 203.0.113.80.80: Flags [S], seq ..., options [mss 1452,...]', simulated: true },
        { title: 'iptables equivalent', command: 'iptables -t mangle -A FORWARD -o ppp0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu', what: 'The classic form on older systems and many appliances.', why: 'Older systems and many appliances still use iptables. --clamp-mss-to-pmtu is the equivalent of nft "set rt mtu"; the rule belongs in the mangle table FORWARD chain for traffic leaving the smaller interface.', expected: '' },
      ],
    },
    {
      id: 'windows-cisco-mtu',
      platform: 'Windows and Cisco IOS',
      summary: 'Checking and setting MTU elsewhere.',
      prerequisites: [],
      steps: [
        { title: 'Windows', command: 'netsh interface ipv4 show subinterfaces\nping -f -l 1472 203.0.113.80\nnetsh interface ipv4 set subinterface "Ethernet0" mtu=1500 store=persistent', what: 'Show MTU, test with DF (-f) and data size (-l), set persistently.', why: '"Packet needs to be fragmented but DF set." = too big for the path.', expected: 'Reply from 203.0.113.80: bytes=1472 time<1ms TTL=63' },
        { title: 'Cisco IOS', command: 'show interfaces Gi0/1 | include MTU\ninterface Gi0/1\n ip mtu 1492\n ip tcp adjust-mss 1452', what: 'Interface MTU, IP MTU and MSS clamping.', why: 'adjust-mss is the IOS equivalent of nft maxseg clamping.', expected: 'MTU 1500 bytes, BW 1000000 Kbit/sec' },
      ],
    },
  ],

  configIntro: `
MTU arithmetic is where most mistakes happen. The calculator below works out the IP MTU, TCP MSS (IPv4/IPv6), the largest \`ping -M do -s\` that fits, and the clamping rule for common encapsulations.
`,

  configFiles: [
    {
      platform: 'Linux',
      items: [
        { path: '/etc/network/interfaces (mtu N)', purpose: 'Persistent MTU per interface (ifupdown, the lab).' },
        { path: '/etc/netplan/*.yaml (mtu:)', purpose: 'Ubuntu netplan.' },
        { path: '/etc/NetworkManager/system-connections/*.nmconnection ([ethernet] mtu=)', purpose: 'NetworkManager profiles.' },
        { path: '/etc/systemd/network/*.network ([Link] MTUBytes=)', purpose: 'systemd-networkd.' },
        { path: '/etc/nftables.conf (tcp option maxseg size set rt mtu)', purpose: 'MSS clamping on routers.' },
        { path: '/proc/sys/net/ipv4/ip_no_pmtu_disc, tcp_mtu_probing', purpose: 'Kernel PMTUD behaviour (default: PMTUD on, probing off).' },
      ],
    },
  ],

  directives: [
    { name: 'mtu (interface)', compiledDefault: '1500 (Ethernet), 65536 (lo)', recommended: 'Equal on both ends of each link', explanation: 'Largest IP packet sent on the interface; frames larger than it are dropped on receipt.', security: 'Not a security setting, but oversized frames dropped on receipt produce failures that look like filtering; document MTUs so they are not mistaken for firewall problems.' },
    { name: 'tcp option maxseg size set rt mtu', compiledDefault: '—', recommended: 'On routers with PPPoE/VPN/tunnel uplinks', explanation: 'Clamps the MSS of forwarded SYNs to the route MTU − 40.', security: 'Rewrites a TCP header field of forwarded traffic; harmless, and it affects only SYN segments.' },
    { name: 'ICMP type 3 (destination unreachable) / ICMPv6 type 2', compiledDefault: 'accepted as related by stateful firewalls', recommended: 'Never drop ("ct state related accept" first; RFC 4890 for IPv6)', explanation: 'Carries "fragmentation needed" / "packet too big" for PMTUD.', security: 'Dropping it does not improve security; it creates black holes.' },
    { name: 'net.ipv4.tcp_mtu_probing', compiledDefault: '0', recommended: '1 on hosts behind known black holes', explanation: 'Packetization-layer PMTUD: TCP lowers the segment size itself after repeated timeouts (RFC 4821). Not modelled in the simulator.', security: 'None; it only changes how the host reacts to lost large segments.' },
    { name: 'net.ipv4.ip_no_pmtu_disc', compiledDefault: '0', recommended: '0', explanation: '1 = send without DF (allow fragmentation). Hides problems and costs performance.', security: 'Fragmented packets are harder for firewalls and IDS to inspect and are often dropped; keep PMTUD on.' },
  ],

  troubleshootingIntro: `
### When small things work and big things hang
1. **Prove it is size-related**: \`curl -I URL\` works but \`curl -m 20 -o /dev/null URL\` times out with "0 out of N bytes received"; SSH logs in but \`cat\` of a large file freezes; HTTPS handshakes time out ("SSL connection timeout") while HTTP headers work.
2. **Find the largest packet that passes**: \`ping -M do -s 1472 DST\`, then smaller (1464, 1400...). An ICMP reply "Frag needed and DF set (mtu = N)" means PMTUD works and tells you the bottleneck. **Silence** for big sizes and replies for small ones means the big packets vanish: a mismatch or a black hole.
3. **Locate it**: \`tracepath -n DST\` (where does pmtu drop?), \`ip link\` on both ends of each suspicious link, tunnel and PPPoE interfaces.
4. **Check ICMP filtering** on every firewall on the path: is ICMP type 3 / ICMPv6 type 2 allowed (related)?
5. **Capture**: \`tcpdump -n -i IF tcp\` shows the MSS in SYNs and repeated retransmissions of the same full-size segment.
`,

  errorMap: [
    { message: 'From 10.0.10.1 icmp_seq=1 Frag needed and DF set (mtu = 1492)', layer: 'PMTUD', meaning: 'A router\'s next hop has MTU 1492; PMTUD works.', firstCheck: 'Is 1492 expected (tunnel, PPPoE) or a misconfiguration?' },
    { message: 'ping: local error: message too long, mtu=1492', layer: 'Sender', meaning: 'The local kernel already knows the path MTU (cache or interface) and refuses to send.', firstCheck: 'ip route get DST; ip link' },
    { message: 'curl: (28) Operation timed out after 20000 milliseconds with 0 out of 4718592 bytes received', layer: 'Transport', meaning: 'Connection and headers fine, data never arrives: classic MTU symptom.', firstCheck: 'ping -M do with decreasing sizes' },
    { message: 'curl: (28) SSL connection timeout', layer: 'Transport / TLS', meaning: 'The server\'s certificate flight (full-size packets) never arrived.', firstCheck: 'Compare with curl -I http:// to the same host; ping -M do' },
    { message: 'Packet needs to be fragmented but DF set. (Windows ping -f)', layer: 'Sender', meaning: 'Windows equivalent of "message too long".', firstCheck: 'Lower -l until it passes' },
    { message: 'ICMP 203.0.113.80 unreachable - need to frag (mtu 1492) (tcpdump)', layer: 'PMTUD', meaning: 'The fragmentation-needed message on the wire. If you see it leave the router but not arrive at the sender, a firewall drops it.', firstCheck: 'Firewall rules for ICMP on the path' },
  ],

  scenarioIds: ['mtu-uplink-mismatch'],
  assessmentId: 'mtu',
  references: [
    { title: 'RFC 1191: Path MTU Discovery', url: 'https://www.rfc-editor.org/rfc/rfc1191' },
    { title: 'RFC 8201: Path MTU Discovery for IP version 6', url: 'https://www.rfc-editor.org/rfc/rfc8201' },
    { title: 'RFC 2923: TCP Problems with Path MTU Discovery (black holes)', url: 'https://www.rfc-editor.org/rfc/rfc2923' },
    { title: 'RFC 4821: Packetization Layer Path MTU Discovery', url: 'https://www.rfc-editor.org/rfc/rfc4821' },
    { title: 'RFC 4890: Recommendations for Filtering ICMPv6 Messages in Firewalls', url: 'https://www.rfc-editor.org/rfc/rfc4890' },
    { title: 'nftables wiki: Mangling packet headers (maxseg)', url: 'https://wiki.nftables.org/wiki-nftables/index.php/Mangling_packet_headers' },
    { title: 'tracepath(8)', url: 'https://manpages.debian.org/bookworm/iputils-tracepath/tracepath.8.en.html' },
  ],
};
