// Traced command runs used by lesson visualisations. Each run builds a fresh lab,
// optionally applies a change, then executes one command with the trace
// recorder active, so the diagram shows exactly what the engine did.

import { readFile, writeFile } from '../fs';
import { script } from '../scenarios/engine';
import { Shell } from '../shell/shell';
import { Recorder, withRecorder, type TraceEvent } from '../sim/trace';
import type { World } from '../types';
import { freshLab } from './dependencies';
import { formatLease } from '../config/dhcpd';
import { RTR01_NFT } from './sshLab';
import { ALICE_KRB_PASSWORD } from './krbLab';
import { DEV02_HARDENED_NFT } from '../scenarios/dhcpv6Scenarios';
import { fullchain, WWW_CERT, WWW_CERT_2025 } from './pkiLab';
import { certPem, CORP_ISSUING, keyPem } from '../sim/pki';

export interface VisualRun {
  id: string;
  label: string;
  description: string;
  host: string;
  user: string;
  command: string;
  /** Answers to prompts the command asks (passwords). */
  answers?: string[];
  setup?: (w: World) => void;
}

export interface VisualResult {
  trace: TraceEvent[];
  output: string;
}

export function runVisual(v: VisualRun): VisualResult {
  const w0 = freshLab();
  v.setup?.(w0);
  for (const h of Object.values(w0.hosts)) h.capture = [];
  let w = w0;
  const sh = new Shell(() => w, (n) => (w = n), { hostId: v.host, user: v.user, cwd: w0.hosts[v.host].users[v.user].home });
  const rec = new Recorder();
  const r = withRecorder(rec, () => sh.execute(v.command, v.answers ?? []));
  return { trace: rec.events, output: r.output };
}

function edit(w: World, host: string, path: string, fn: (s: string) => string) {
  const h = w.hosts[host];
  writeFile(h, path, fn(readFile(h, path) ?? ''), w.clock);
}

export const FIREWALL_RUNS: VisualRun[] = [
  {
    id: 'web-ok', label: 'HTTP allowed (baseline)', host: 'ws01', user: 'alice', command: 'curl -I http://srv01.corp.lab/',
    description: 'The SYN passes rtr01\'s forward hook (policy accept) and srv01\'s input chain matches "tcp dport { 80, 443 } accept". Every later packet of the flow is accepted by "ct state established,related accept", the first rule. Open "Path taken" in the inspector to see each decision.',
  },
  {
    id: 'ssh-drop', label: 'Input policy drop (no rule for tcp/22)', host: 'ws01', user: 'alice', command: 'ssh -o ConnectTimeout=20 srv01.corp.lab',
    description: 'The tcp/22 accept rule is removed. Each SYN falls through to "policy drop". Nothing is sent back, so the client retransmits the same SYN at 1, 2, 4, 8 s… until its timeout.',
    setup: (w) => { edit(w, 'srv01', '/etc/nftables.conf', (s) => s.replace('\t\ttcp dport 22 accept\n', '')); script(w, 'srv01', ['nft -f /etc/nftables.conf']); },
  },
  {
    id: 'web-reset', label: 'Reject with tcp reset', host: 'ws01', user: 'alice', command: 'curl -I http://srv01.corp.lab/',
    description: '"tcp dport { 80, 443 } reject with tcp reset": the firewall itself answers the SYN with RST. On the client this is indistinguishable from a closed port.',
    setup: (w) => { edit(w, 'srv01', '/etc/nftables.conf', (s) => s.replace('tcp dport { 80, 443 } accept', 'tcp dport { 80, 443 } reject with tcp reset')); script(w, 'srv01', ['nft -f /etc/nftables.conf']); },
  },
  {
    id: 'admin-prohibited', label: 'Reject with ICMP admin-prohibited', host: 'ws01', user: 'alice', command: 'ssh srv01.corp.lab',
    description: 'An inserted rule rejects SSH from the LAN with ICMP type 3 code 13. The client prints "No route to host" although routing is fine.',
    setup: (w) => script(w, 'srv01', ['nft insert rule inet filter input ip saddr 10.0.10.0/24 tcp dport 22 reject with icmpx type admin-prohibited']),
  },
  {
    id: 'forward-drop', label: 'Dropped in the path (router forward chain)', host: 'ws01', user: 'alice', command: 'curl -I -m 8 http://srv01.corp.lab/',
    description: 'rtr01\'s forward chain (policy drop) only allows tcp/22 to the servers. HTTP SYNs die at the router: srv01 never sees them.',
    setup: (w) => {
      edit(w, 'rtr01', '/etc/nftables.conf', () => RTR01_NFT.replace('\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n\t}\n',
        '\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t\tct state established,related accept\n\t\tiifname "eth0" oifname "eth1" tcp dport 22 accept\n\t\tiifname "eth1" oifname "eth0" accept\n\t}\n'));
      script(w, 'rtr01', ['nft -f /etc/nftables.conf']);
    },
  },
  {
    id: 'no-established', label: 'Missing "ct state established,related accept"', host: 'srv01', user: 'root', command: 'dig ns1.corp.lab',
    description: 'srv01 queries ns1. The query leaves (output policy accept) and the answer arrives, but no input rule matches a reply from port 53 to an ephemeral port, so the policy drops it. dig retries and gives up.',
    setup: (w) => { edit(w, 'srv01', '/etc/nftables.conf', (s) => s.replace('\t\tct state established,related accept\n', '')); script(w, 'srv01', ['nft -f /etc/nftables.conf']); },
  },
  {
    id: 'traceroute', label: 'traceroute (TTL expiry and dropped UDP probes)', host: 'ws01', user: 'alice', command: 'traceroute -n -m 3 srv01.corp.lab',
    description: 'Probes with TTL 1 expire at rtr01, which answers "time exceeded" (rtr01\'s input chain accepts ICMP and its output is open). Probes with TTL 2+ reach srv01, whose input policy drops UDP to ports 33434+: no answer, "* * *".',
  },
];

export const IP_RUNS: VisualRun[] = [
  {
    id: 'onlink', label: 'Same subnet: direct ARP', host: 'ws01', user: 'alice', command: 'ping -c 1 10.0.10.53',
    description: '10.0.10.53 is inside ws01\'s connected 10.0.10.0/24, so ws01 ARPs for the destination itself and sends the frame straight to it. No router is involved; TTL arrives unchanged (64).',
  },
  {
    id: 'routed', label: 'Other subnet: via the gateway', host: 'ws01', user: 'alice', command: 'ping -c 1 10.0.20.10',
    description: '10.0.20.10 only matches the default route, so ws01 ARPs for its gateway 10.0.10.1 and sends the frame to rtr01\'s MAC. rtr01 decrements the TTL, ARPs for srv01 on eth1 and builds a new frame. srv01 routes the reply back via its own gateway. Compare the Ethernet hops in the inspector.',
  },
  {
    id: 'traceroute', label: 'traceroute -I: TTL expiry hop by hop', host: 'ws01', user: 'root', command: 'traceroute -n -I -q 1 srv01.corp.lab',
    description: 'ICMP probes with TTL 1 expire at rtr01 (time exceeded); TTL 2 reaches srv01, which replies. Each probe is a separate packet with a growing TTL.',
  },
  {
    id: 'wrong-mask', label: 'Wrong prefix (/16): ARP for a remote host', host: 'ws01', user: 'alice', command: 'ping -c 1 10.0.20.10',
    description: 'ws01 is set to 10.0.10.25/16. Its connected route now covers 10.0.20.10, so it ARPs for srv01 on the office LAN. Nobody answers; ws01 itself reports Destination Host Unreachable.',
    setup: (w) => { edit(w, 'ws01', '/etc/network/interfaces', (s) => s.replace('address 10.0.10.25/24', 'address 10.0.10.25/16')); script(w, 'ws01', ['systemctl restart networking']); },
  },
  {
    id: 'wrong-gw', label: 'Wrong gateway: ARP for a router that does not exist', host: 'ws01', user: 'alice', command: 'ping -c 1 10.0.20.10',
    description: 'The default route points at 10.0.10.254. ARP for it fails, so nothing leaves the LAN.',
    setup: (w) => { edit(w, 'ws01', '/etc/network/interfaces', (s) => s.replace('gateway 10.0.10.1', 'gateway 10.0.10.254')); script(w, 'ws01', ['systemctl restart networking']); },
  },
  {
    id: 'no-forward', label: 'Router with ip_forward=0', host: 'ws01', user: 'alice', command: 'ping -c 1 10.0.20.10',
    description: 'rtr01 receives the packet but may not route it, and answers with ICMP host unreachable (from 10.0.10.1).',
    setup: (w) => script(w, 'rtr01', ['sysctl -w net.ipv4.ip_forward=0']),
  },
  {
    id: 'no-return', label: 'Server without a return route', host: 'ws01', user: 'alice', command: 'ping -c 1 10.0.20.10',
    description: 'srv01 has no default route. The request arrives, but srv01 cannot route the reply to 10.0.10.0/24: silence.',
    setup: (w) => script(w, 'srv01', ['ip route del default']),
  },
];

export const TRANSPORT_RUNS: VisualRun[] = [
  {
    id: 'tcp-life', label: 'TCP lifecycle: handshake, data, teardown', host: 'ws01', user: 'alice', command: 'curl -I http://srv01.corp.lab/',
    description: 'DNS over UDP, then SYN / SYN-ACK / ACK, the HTTP request and response (each acknowledging the other side\'s bytes), and FIN / FIN-ACK / ACK. Check how seq and ack advance by the payload length.',
  },
  {
    id: 'tcp-refused', label: 'Nothing listening: RST', host: 'ws01', user: 'alice', command: 'curl -I http://srv01.corp.lab/',
    description: 'nginx is stopped. The firewall accepts the SYN, but no socket matches, so srv01\'s kernel answers RST, ACK. curl fails immediately.',
    setup: (w) => script(w, 'srv01', ['systemctl stop nginx']),
  },
  {
    id: 'tcp-timeout', label: 'No answer: SYN retransmission', host: 'ws01', user: 'alice', command: 'nc -zv -w 20 srv01.corp.lab 3306',
    description: 'srv01 drops tcp/3306 by policy. The client resends the identical SYN at exponentially growing intervals until nc\'s 20 s limit.',
  },
  {
    id: 'udp-dns', label: 'UDP: a DNS query and its answer', host: 'ws01', user: 'alice', command: 'dig www.corp.lab',
    description: 'One datagram out, one back; no handshake. The answer contains a CNAME (www → srv01) and the A record.',
  },
  {
    id: 'udp-unreach', label: 'UDP to a closed port: ICMP port unreachable', host: 'ns1', user: 'root', command: 'dig @10.0.10.25 srv01.corp.lab',
    description: 'ws01 runs no DNS server. Its kernel answers the datagram with ICMP port unreachable, and dig reports "connection refused" instead of waiting for a timeout.',
  },
  {
    id: 'search-list', label: 'Short name: search domain and NXDOMAIN', host: 'ws01', user: 'alice', command: 'getent hosts nosuchhost',
    description: '"nosuchhost" has no dots, so the resolver tries nosuchhost.corp.lab. first (NXDOMAIN), then nosuchhost. (refused: ns1 is authoritative only for corp.lab).',
  },
  {
    id: 'loopback-bind', label: 'Service bound to 127.0.0.1', host: 'ws01', user: 'alice', command: 'curl -I http://srv01.corp.lab/',
    description: 'nginx listens on 127.0.0.1:80 only. A SYN to 10.0.20.10:80 matches no socket: RST.',
    setup: (w) => { edit(w, 'srv01', '/etc/nginx/nginx.conf', (s) => s.replace('listen 80 default_server;', 'listen 127.0.0.1:80 default_server;').replace('        listen [::]:80 default_server;\n', '')); script(w, 'srv01', ['systemctl reload nginx']); },
  },
];

export const DHCP_RUNS: VisualRun[] = [
  {
    id: 'dora', label: 'DORA: Discover, Offer, Request, Ack', host: 'ws02', user: 'root', command: 'dhclient -v eth0',
    description: 'ws02 releases its lease and forgets it (as a brand-new client would have no lease file), then asks again. DISCOVER and REQUEST are broadcasts from 0.0.0.0 (every host on the LAN receives them, only ns1 runs a DHCP server); OFFER and ACK are unicast to ws02\'s MAC. Open the packets to see yiaddr and the options (router, DNS, lease time, renewal T1 and rebinding T2).',
    setup: (w) => script(w, 'ws02', ['dhclient -r eth0', 'rm /var/lib/dhcp/dhclient.eth0.leases']),
  },
  {
    id: 'relay', label: 'Through a relay: dev02 on VLAN 30', host: 'dev02', user: 'root', command: 'dhclient -v eth0',
    description: 'dev02 has no DHCP server on its VLAN. Its DISCOVER broadcast reaches rtr01\'s eth3.30, where isc-dhcp-relay sets giaddr = 10.0.30.1 and unicasts it to ns1 (10.0.10.1:67 → 10.0.10.53:67). ns1 picks the 10.0.30.0/24 pool because it contains giaddr and answers to the relay, which delivers the OFFER to dev02\'s MAC. REQUEST and ACK repeat the path.',
    setup: (w) => script(w, 'dev02', ['dhclient -r eth0', 'rm /var/lib/dhcp/dhclient.eth0.leases']),
  },
  {
    id: 'init-reboot', label: 'INIT-REBOOT: asking for the remembered address', host: 'ws02', user: 'root', command: 'dhclient -v eth0',
    description: 'ws02 remembers its lease in /var/lib/dhcp/dhclient.eth0.leases, so it skips DISCOVER and broadcasts a REQUEST for 10.0.10.100 directly. ns1 knows this MAC and this address and answers ACK. This is what you see most of the time when you run dhclient or reboot a client.',
  },
  {
    id: 'nak', label: 'Moved to another network: DHCPNAK', host: 'dev02', user: 'root', command: 'dhclient -v eth0',
    description: 'dev02 last had 10.0.10.104 in the office and was plugged in on VLAN 30. It asks for its old address; the relay forwards the request with giaddr 10.0.30.1, and ns1 (authoritative) answers NAK: 10.0.10.104 does not belong to 10.0.30.0/24. dev02 forgets the old lease and starts over with DISCOVER, receiving 10.0.30.100.',
    setup: (w) => {
      script(w, 'dev02', ['dhclient -r eth0']);
      edit(w, 'dev02', '/var/lib/dhcp/dhclient.eth0.leases', (s) => s.replace(/fixed-address [\d.]+;/, 'fixed-address 10.0.10.104;'));
    },
  },
  {
    id: 'renew', label: 'Lease renewal at T1 (sleep 300)', host: 'ws02', user: 'root', command: 'sleep 300',
    description: 'Simulated time passes. Half-way through their 600-second leases, ws02 and dev02 renew: each sends a DHCPREQUEST by unicast from its own address to the server identifier 10.0.10.53, and ns1 answers ACK by unicast. dev02\'s renewal is routed through rtr01 like any other traffic: the relay is only needed while a client has no address.',
  },
  {
    id: 'wrong-router', label: 'Lease with a wrong router option', host: 'ws02', user: 'dana', command: 'ping -c 1 10.0.20.10',
    description: 'dhcpd.conf hands out "option routers 10.0.10.254" (an address nobody uses). ws02 gets an address and can reach its own LAN, but its default route points at a non-existent gateway: ARP for 10.0.10.254 fails and nothing leaves the subnet.',
    setup: (w) => {
      edit(w, 'ns1', '/etc/dhcp/dhcpd.conf', (s) => s.replace('option routers 10.0.10.1;', 'option routers 10.0.10.254;'));
      script(w, 'ns1', ['systemctl restart isc-dhcp-server']);
      script(w, 'ws02', ['dhclient -r eth0', 'dhclient eth0']);
    },
  },
  {
    id: 'no-server', label: 'No DHCP server answering', host: 'ws02', user: 'root', command: 'dhclient -v eth0',
    description: 'isc-dhcp-server is stopped on ns1. ws02 first asks for its remembered address (INIT-REBOOT), then broadcasts DISCOVERs; they reach every host on the LAN but nobody answers. dhclient backs off (3, 8, 18, 20 s…), gives up and sleeps (it retries every 5 minutes). ws02 is left without an address.',
    setup: (w) => { script(w, 'ws02', ['dhclient -r eth0']); script(w, 'ns1', ['systemctl stop isc-dhcp-server']); },
  },
  {
    id: 'exhausted', label: 'Pool exhausted: "no free leases"', host: 'ws02', user: 'root', command: 'dhclient -v eth0',
    description: 'The range is shrunk to 10.0.10.100-10.0.10.100 and that address is now leased to another MAC. ws02 asks for its old address and ns1 answers NAK (no longer available). ws02 starts over with DISCOVER, but ns1 has nothing to offer: it logs "no free leases" (journalctl -u isc-dhcp-server) and stays silent on the wire.',
    setup: (w) => {
      script(w, 'ws02', ['dhclient -r eth0']);
      edit(w, 'ns1', '/etc/dhcp/dhcpd.conf', (s) => s.replace('range 10.0.10.100 10.0.10.150;', 'range 10.0.10.100 10.0.10.100;'));
      edit(w, 'ns1', '/var/lib/dhcp/dhcpd.leases', (s) => s + formatLease({ ip: '10.0.10.100', mac: '52:54:00:77:00:01', hostname: 'visitor-1', starts: w.clock, ends: w.clock + 7200_000, state: 'active' }));
      script(w, 'ns1', ['systemctl restart isc-dhcp-server']);
    },
  },
];

export const NAT_RUNS: VisualRun[] = [
  {
    id: 'masquerade', label: 'Outbound: masquerade (source NAT)', host: 'ws01', user: 'alice', command: 'curl -I http://203.0.113.80/',
    description: 'ws01 (10.0.10.25) talks to a host on the Internet. In postrouting, rtr01 rewrites the source to its eth2 address 203.0.113.2 and a new source port is kept if free; ext01 only ever sees 203.0.113.2. The reply comes back to 203.0.113.2 and conntrack reverses the translation. Compare src/dst in the hop notes on each side of rtr01.',
  },
  {
    id: 'dnat', label: 'Inbound: port forward (destination NAT)', host: 'ext01', user: 'guest', command: 'curl -I http://203.0.113.2/',
    description: 'ext01 connects to the router\'s public address. In prerouting (before the routing decision) rtr01 rewrites the destination to 10.0.20.10:80, routes it out eth1, and srv01 answers its private address. The reply is un-DNATed so ext01 sees an answer from 203.0.113.2.',
  },
  {
    id: 'no-masquerade', label: 'Missing masquerade: private source on the Internet', host: 'ws01', user: 'alice', command: 'curl -I -m 6 http://203.0.113.80/',
    description: 'The masquerade rule is removed. The SYN leaves eth2 with source 10.0.10.25. ext01 receives it, but cannot route a reply to a private address (on the real Internet providers drop such packets), so the client times out.',
    setup: (w) => { edit(w, 'rtr01', '/etc/nftables.conf', (s) => s.replace('\t\toifname "eth2" masquerade\n', '')); script(w, 'rtr01', ['systemctl reload nftables']); },
  },
  {
    id: 'filter-after-dnat', label: 'Forward filter sees the translated packet', host: 'ext01', user: 'guest', command: 'curl -I -m 6 http://203.0.113.2:8080/',
    description: 'Public port 8080 is forwarded to srv01:80, and the forward chain (policy drop) has "iifname eth2 tcp dport 8080 accept". DNAT already rewrote the packet in prerouting, so the forward hook sees dport 80: the rule never matches and the policy drops it.',
    setup: (w) => {
      edit(w, 'rtr01', '/etc/nftables.conf', (s) => s
        .replace('iifname "eth2" tcp dport 80 dnat to 10.0.20.10:80', 'iifname "eth2" tcp dport 8080 dnat to 10.0.20.10:80')
        .replace('\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n\t}\n',
          '\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t\tct state established,related accept\n\t\tiifname "eth0" accept\n\t\tiifname "eth1" accept\n\t\tiifname "eth2" tcp dport 8080 accept\n\t}\n'));
      script(w, 'rtr01', ['systemctl reload nftables']);
    },
  },
];

export const VLAN_RUNS: VisualRun[] = [
  {
    id: 'same-vlan', label: 'Same VLAN: switched, no router', host: 'ws01', user: 'alice', command: 'ping -c 1 10.0.10.53',
    description: 'ws01 (swp1) and ns1 (swp3) are both access ports in VLAN 10. The ARP broadcast is flooded only to VLAN 10 ports; the switch forwards the frames untagged. Open a packet: the hop note shows "in swp1 (untagged) → VLAN 10 → out swp3".',
  },
  {
    id: 'inter-vlan', label: 'Between VLANs: router-on-a-stick over the trunk', host: 'dev01', user: 'erin', command: 'ping -4 -c 1 10.0.20.10',
    description: 'dev01 (VLAN 30) reaches srv01 (VLAN 20) only through rtr01. dev01 sends untagged frames into swp8; the switch sends them tagged with VLAN 30 on the trunk swp7 to rtr01\'s sub-interface eth3.30; rtr01 routes and sends them out eth1 (VLAN 20, untagged). Check the hop notes for "tagged 30".',
  },
  {
    id: 'wrong-access', label: 'Access port in the wrong VLAN', host: 'dev01', user: 'erin', command: 'ping -4 -c 1 10.0.30.1',
    description: 'swp8 was set to "bridge-access 10". dev01\'s ARP request for its gateway is flooded in VLAN 10 (ws01, ws02, ns1 and rtr01 eth0 see it), where nobody owns 10.0.30.1. The link is up and dev01\'s configuration is correct, yet nothing answers.',
    setup: (w) => { edit(w, 'sw01', '/etc/network/interfaces', (s) => s.replace('    alias dev01\n    bridge-access 30', '    alias dev01\n    bridge-access 10')); script(w, 'sw01', ['ifreload -a']); },
  },
  {
    id: 'trunk-pruned', label: 'VLAN missing on the trunk', host: 'dev01', user: 'erin', command: 'ping -4 -c 1 10.0.30.1',
    description: 'swp7 (trunk to rtr01) carries VLAN 20 instead of 30. dev01\'s ARP stays inside VLAN 30, which now has no port towards the router: the gateway is unreachable although rtr01\'s eth3.30 is up and correctly addressed.',
    setup: (w) => { edit(w, 'sw01', '/etc/network/interfaces', (s) => s.replace('    alias rtr01 eth3 (trunk)\n    bridge-vids 30', '    alias rtr01 eth3 (trunk)\n    bridge-vids 20')); script(w, 'sw01', ['ifreload -a']); },
  },
];

export const IPV6_RUNS: VisualRun[] = [
  {
    id: 'slaac', label: 'SLAAC: router solicitation and advertisement', host: 'dev01', user: 'root', command: 'systemctl restart networking',
    description: 'dev01 brings eth0 up with only a link-local address (fe80:: + EUI-64 from its MAC) and sends a Router Solicitation to ff02::2. radvd on rtr01 answers with a Router Advertisement for 2001:db8:30::/64 from its link-local address; dev01 builds 2001:db8:30::5054:ff:fee7:1e and a default route via fe80::5054:ff:fea1:4.',
  },
  {
    id: 'ndp-ping', label: 'Neighbor Discovery and ping -6', host: 'dev01', user: 'erin', command: 'ping -6 -c 1 srv01.corp.lab',
    description: 'Name resolution asks for the AAAA record (over IPv4: the DNS server is IPv4-only). Then IPv6 replaces ARP with ICMPv6: dev01 solicits its router\'s link-local address, rtr01 solicits srv01 (2001:db8:20::10) on eth1, and srv01 solicits the router to send the reply. Each Neighbor Solicitation goes to a solicited-node multicast group and passes the target\'s firewall.',
  },
  {
    id: 'dual-stack', label: 'Dual stack: curl prefers IPv6', host: 'dev01', user: 'erin', command: 'curl -v -I http://srv01.corp.lab/',
    description: 'getaddrinfo() returns 2001:db8:20::10 and 10.0.20.10; with a global IPv6 address dev01 sorts IPv6 first (RFC 6724) and the whole HTTP exchange runs over IPv6. Frames to the router carry the 802.1Q tag 30 on the trunk.',
  },
  {
    id: 'icmpv6-blocked', label: 'Firewall drops ICMPv6: "Address unreachable"', host: 'dev01', user: 'erin', command: 'ping -6 -c 1 srv01.corp.lab',
    description: 'srv01\'s ruleset only accepts ICMPv6 echo. rtr01\'s Neighbor Solicitation for 2001:db8:20::10 is dropped by srv01\'s input chain (ct state untracked, no matching rule, policy drop), so rtr01 cannot deliver and returns ICMPv6 destination unreachable, code 3 (address unreachable).',
    setup: (w) => { edit(w, 'srv01', '/etc/nftables.conf', (s) => s.replace('meta l4proto ipv6-icmp accept', 'icmpv6 type { echo-request, echo-reply } accept')); script(w, 'srv01', ['systemctl reload nftables']); },
  },
  {
    id: 'happy-eyeballs', label: 'Broken IPv6, curl falls back to IPv4', host: 'dev01', user: 'erin', command: 'curl -v -I http://srv01.corp.lab/',
    description: 'Same broken firewall. curl tries [2001:db8:20::10]:80 first, gets "No route to host" from the router, and immediately tries 10.0.20.10: the page loads. Users see nothing wrong; IPv6-only tools (curl -6, scripts, ssh with long timeouts) fail.',
    setup: (w) => { edit(w, 'srv01', '/etc/nftables.conf', (s) => s.replace('meta l4proto ipv6-icmp accept', 'icmpv6 type { echo-request, echo-reply } accept')); script(w, 'srv01', ['systemctl reload nftables']); },
  },
  {
    id: 'no-forwarding', label: 'Router with IPv6 forwarding disabled', host: 'dev01', user: 'erin', command: 'curl -6 -I -m 3 http://srv01.corp.lab/',
    description: 'net.ipv6.conf.all.forwarding=0 on rtr01. The SYN reaches rtr01, which is not its destination and may not route it: IPv6 discards it silently (no ICMPv6 error, unlike IPv4\'s host-unreachable). curl retries and times out.',
    setup: (w) => script(w, 'rtr01', ['sysctl -w net.ipv6.conf.all.forwarding=0']),
  },
  {
    id: 'dhcpv6', label: 'Stateful DHCPv6: Solicit, Advertise, Request, Reply', host: 'dev02', user: 'root', command: 'dhclient -6 -v eth0',
    description: 'dev02 has released its DHCPv6 lease. dhclient -6 sends a Solicit from its link-local address to ff02::1:2 (UDP 546 → 547). dhcpd -6 on rtr01 picks an address from range6 for dev02\'s DUID and IAID and advertises it by unicast to dev02\'s link-local address; dev02 requests it (naming the server DUID) and the Reply commits the lease. dhclient-script adds the address as a /128; the default route and the on-link /64 still come from radvd\'s router advertisements.',
    setup: (w) => script(w, 'dev02', ['dhclient -6 -r eth0']),
  },
  {
    id: 'dhcpv6-stateless', label: 'Stateless DHCPv6: Information-request', host: 'dev02', user: 'root', command: 'dhclient -6 -S -v eth0',
    description: 'The O flag case: the client only asks for options. One Information-request to ff02::1:2 and a Reply with the DNS server (option 23) and the domain search list (option 24); no IA_NA, no address. dhclient-script writes them to /etc/resolv.conf.',
  },
  {
    id: 'dhcpv6-client-fw', label: 'Client firewall drops the Advertise (UDP 546)', host: 'dev02', user: 'root', command: 'dhclient -6 -v eth0',
    description: 'dev02 runs a hardened ruleset (policy drop, established/related, ICMP, SSH). Its Solicit leaves and rtr01 answers, but the Advertise comes from rtr01\'s link-local address to UDP 546 while the Solicit went to a multicast group: conntrack sees a new flow and the input chain drops it. dhclient keeps soliciting. DHCPv4 is not affected because ISC dhclient reads DHCPv4 with a packet socket that bypasses nftables.',
    setup: (w) => { writeFile(w.hosts.dev02, '/etc/nftables.conf', DEV02_HARDENED_NFT, w.clock); script(w, 'dev02', ['dhclient -6 -r eth0', 'systemctl restart nftables']); },
  },
];

function serveCert(w: World, chainPem: string, keyPem?: string) {
  writeFile(w.hosts.srv01, '/etc/ssl/certs/www.corp.lab.crt', chainPem, w.clock);
  if (keyPem) writeFile(w.hosts.srv01, '/etc/ssl/private/www.corp.lab.key', keyPem, w.clock);
  script(w, 'srv01', ['systemctl reload nginx']);
}

export const TLS_RUNS: VisualRun[] = [
  {
    id: 'https-ok', label: 'HTTPS with a verified chain', host: 'ws01', user: 'alice', command: 'curl -v -I https://www.corp.lab/',
    description: 'After the TCP handshake ws01 sends a ClientHello with SNI www.corp.lab. nginx answers with ServerHello and its certificate flight (www.corp.lab + Corp Lab Issuing CA 1): about 2.6 kB, so it spans two full-size segments. curl builds the chain up to Corp Lab Root CA from /etc/ssl/certs/ca-certificates.crt, checks the dates and finds www.corp.lab in the subjectAltName; only then does the encrypted HTTP request travel.',
  },
  {
    id: 'tls-expired', label: 'Expired certificate: the client aborts', host: 'ws01', user: 'alice', command: 'curl -v -I https://www.corp.lab/',
    description: 'srv01 serves last year\'s certificate (notAfter 17 Oct 2026). TCP and the first half of the handshake are identical, but after receiving the certificate curl sends a fatal "certificate expired" alert and closes: no HTTP request is ever sent. Nothing in the network is wrong.',
    setup: (w) => serveCert(w, fullchain(WWW_CERT_2025.cert, CORP_ISSUING.cert), keyPem(WWW_CERT_2025.key)),
  },
  {
    id: 'tls-chain', label: 'Missing intermediate', host: 'ws01', user: 'alice', command: 'openssl s_client -connect www.corp.lab:443 </dev/null',
    description: 'The certificate file holds only the leaf. The certificate flight is smaller (one certificate) and s_client cannot link www.corp.lab to any trusted root: error 20 at depth 0, then 21 "unable to verify the first certificate". The fix belongs on the server (full chain), not on every client.',
    setup: (w) => serveCert(w, certPem(WWW_CERT.cert)),
  },
  {
    id: 'tls-name', label: 'Name not in the certificate', host: 'ws01', user: 'alice', command: 'curl -v -I https://10.0.20.10/',
    description: 'Same server, same certificate, but the client asked for 10.0.20.10. The chain verifies; the name check fails because the subjectAltName lists only www.corp.lab and srv01.corp.lab. curl closes the connection after the handshake.',
  },
];

export const MTU_RUNS: VisualRun[] = [
  {
    id: 'pmtud', label: 'Path MTU discovery: "fragmentation needed"', host: 'ws01', user: 'alice', command: 'ping -c 2 -M do -s 1472 203.0.113.80',
    description: 'rtr01\'s eth2 has MTU 1492. The first 1500-byte echo request (DF set) reaches rtr01, which cannot forward it: it drops the packet and returns ICMP type 3 code 4 with mtu 1492. ws01 caches PMTU 1492 for 203.0.113.80, so the second ping fails locally with "message too long" without sending anything.',
    setup: (w) => script(w, 'rtr01', ['ip link set dev eth2 mtu 1492']),
  },
  {
    id: 'mismatch', label: 'MTU mismatch: large segments vanish', host: 'ws01', user: 'alice', command: 'curl -m 5 -o /dev/null http://203.0.113.80/downloads/tools-2.4.1.tar.gz',
    description: 'Same 1492 on rtr01\'s eth2, but ext01\'s side of the link is 1500. The handshake and the request are small and pass; the response headers (a short segment) arrive; the first full 1500-byte data segment from ext01 is dropped by rtr01\'s eth2 on receipt. No router forwards it, so no ICMP is sent; ext01 retransmits with exponential backoff until curl gives up.',
    setup: (w) => script(w, 'rtr01', ['ip link set dev eth2 mtu 1492']),
  },
  {
    id: 'clamp', label: 'MSS clamping fixes TCP', host: 'ws01', user: 'alice', command: 'curl -I http://203.0.113.80/downloads/tools-2.4.1.tar.gz',
    description: 'rtr01 rewrites the MSS option of forwarded SYNs leaving eth2 to the route MTU minus 40 (1452). ws01\'s SYN leaves with mss 1460 and arrives at ext01 with mss 1452, so ext01 never sends a segment larger than 1492 bytes. Compare the SYN on both sides of rtr01 in the packet inspector.',
    setup: (w) => script(w, 'rtr01', ['ip link set dev eth2 mtu 1492', 'nft add rule inet filter forward oifname "eth2" tcp flags syn tcp option maxseg size set rt mtu']),
  },
  {
    id: 'tracepath', label: 'tracepath finds the bottleneck', host: 'ws01', user: 'alice', command: 'tracepath -n 203.0.113.80',
    description: 'tracepath sends UDP probes with DF set and increasing TTL. The first full-size probe draws "fragmentation needed (mtu 1492)" from rtr01; tracepath reports pmtu 1492 at that hop, shrinks its probes and continues to the destination.',
    setup: (w) => script(w, 'rtr01', ['ip link set dev eth2 mtu 1492']),
  },
];

/** Run a command as a user (with prompt answers), mutating the world (setup steps). */
function asUser(w: World, host: string, user: string, line: string, answers: string[] = []) {
  let cur = w;
  const sh = new Shell(() => cur, (n) => (cur = n), { hostId: host, user, cwd: w.hosts[host].users[user].home });
  sh.execute(line, answers);
  Object.assign(w, cur);
}

function kerberosSso(w: World) {
  writeFile(w.hosts.srv01, '/etc/ssh/sshd_config.d/20-kerberos.conf', 'GSSAPIAuthentication yes\n', w.clock);
  script(w, 'srv01', ['systemctl reload ssh']);
}

export const KRB_RUNS: VisualRun[] = [
  {
    id: 'kinit', label: 'kinit: find the KDC, pre-authenticate, get a TGT', host: 'ws01', user: 'alice', command: 'kinit', answers: [ALICE_KRB_PASSWORD],
    description: 'krb5.conf names no KDC, so the library asks DNS for _kerberos._udp.corp.lab (SRV → ns1 port 88). The first AS-REQ carries no proof; the KDC answers "pre-authentication required". kinit asks for the password, turns it into a key, encrypts its current time with it and sends a second AS-REQ. The KDC decrypts the timestamp with its copy of alice\'s key, checks the clock and returns the TGT.',
  },
  {
    id: 'kvno', label: 'kvno: a service ticket from the TGS', host: 'ws01', user: 'alice', command: 'kvno host/srv01.corp.lab',
    description: 'With a TGT in the cache, no password is needed: the client sends the TGT and an authenticator to the ticket-granting service and receives a ticket for host/srv01.corp.lab, encrypted with srv01\'s key (kvno 2). This is single sign-on: one password, many services.',
    setup: (w) => asUser(w, 'ws01', 'alice', 'kinit', [ALICE_KRB_PASSWORD]),
  },
  {
    id: 'ssh-gssapi', label: 'SSH login with Kerberos (gssapi-with-mic)', host: 'ws01', user: 'alice', command: 'ssh -o PubkeyAuthentication=no srv01.corp.lab hostname',
    description: 'sshd on srv01 has GSSAPIAuthentication yes. After the SSH key exchange the client gets a service ticket for host/srv01.corp.lab (TGS exchange) and sends it in the gssapi-with-mic request. sshd decrypts it with the key in /etc/krb5.keytab and maps alice@CORP.LAB to the local user alice. No key file and no password.',
    setup: (w) => { kerberosSso(w); asUser(w, 'ws01', 'alice', 'kinit', [ALICE_KRB_PASSWORD]); },
  },
  {
    id: 'skew', label: 'Clock skew: the KDC refuses the timestamp', host: 'ws01', user: 'alice', command: 'kinit', answers: [ALICE_KRB_PASSWORD],
    description: 'ws01\'s clock is 9 minutes fast. The password is right, so the KDC can decrypt the timestamp, but it is more than 300 s away from the KDC\'s own time: KRB_AP_ERR_SKEW, "Clock skew too great". Kerberos uses timestamps instead of challenges, so it needs synchronised clocks.',
    setup: (w) => { w.hosts.ws01.clockOffset = 9 * 60_000; },
  },
  {
    id: 'stale-keytab', label: 'Stale keytab: the ticket cannot be decrypted', host: 'ws01', user: 'alice', command: 'ssh -v -o PubkeyAuthentication=no -o PasswordAuthentication=no srv01.corp.lab hostname',
    description: 'The KDC changed host/srv01\'s key (kvno 3), srv01\'s keytab still has kvno 2. The client gets a perfectly valid ticket and sends it; sshd cannot decrypt it and answers USERAUTH_FAILURE, and with no other method left the login fails. Compare kvno on the client with klist -k on the server.',
    setup: (w) => { kerberosSso(w); script(w, 'ns1', ['kadmin.local -q "cpw -randkey host/srv01.corp.lab"']); asUser(w, 'ws01', 'alice', 'kinit', [ALICE_KRB_PASSWORD]); },
  },
  {
    id: 'no-srv', label: 'No SRV records: "Cannot find KDC"', host: 'ws01', user: 'alice', command: 'kinit', answers: [ALICE_KRB_PASSWORD],
    description: 'The Kerberos SRV records were removed from the corp.lab zone. The library asks DNS for _kerberos._udp and _kerberos._tcp, gets NXDOMAIN for both and gives up without contacting any KDC.',
    setup: (w) => { edit(w, 'ns1', '/etc/bind/db.corp.lab', (z) => z.replace(/; Kerberos realm CORP\.LAB[\s\S]*$/, '')); script(w, 'ns1', ['rndc reload']); },
  },
];
