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
