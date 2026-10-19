// Traced command runs used by lesson visualisations. Each run builds a fresh lab,
// optionally applies a change, then executes one command with the trace
// recorder active, so the diagram shows exactly what the engine did.

import { readFile, writeFile } from '../fs';
import { script } from '../scenarios/engine';
import { Shell } from '../shell/shell';
import { Recorder, withRecorder, type TraceEvent } from '../sim/trace';
import type { World } from '../types';
import { freshLab } from './dependencies';
import { RTR01_NFT } from './sshLab';

export interface VisualRun {
  id: string;
  label: string;
  description: string;
  host: string;
  user: string;
  command: string;
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
  const r = withRecorder(rec, () => sh.execute(v.command));
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
