// SSH dependency map. Each node can be "switched off" by applying a concrete
// fault to a fresh baseline lab; the learner predicts the client-visible result
// before the simulator runs the connection.

import { readFile, writeFile } from '../fs';
import { script } from '../scenarios/engine';
import { runSsh, type SshResult } from '../sim/ssh';
import { Recorder, withRecorder, type TraceEvent } from '../sim/trace';
import type { World } from '../types';
import { buildSshLab, installHostKeys, HARDENING_CONF } from './sshLab';

export type OutcomeClass =
  | 'resolve-nx' | 'resolve-temp' | 'netunreach' | 'noroute' | 'timeout' | 'refused'
  | 'negotiate' | 'hostkey' | 'denied' | 'shell' | 'success';

export const OUTCOME_LABELS: Record<OutcomeClass, string> = {
  'resolve-nx': 'Could not resolve hostname: Name or service not known',
  'resolve-temp': 'Could not resolve hostname: Temporary failure in name resolution',
  netunreach: 'connect to host: Network is unreachable',
  noroute: 'connect to host: No route to host',
  timeout: 'connect to host: Connection timed out',
  refused: 'connect to host: Connection refused',
  negotiate: 'Unable to negotiate (no matching algorithm)',
  hostkey: 'REMOTE HOST IDENTIFICATION HAS CHANGED / Host key verification failed',
  denied: 'Permission denied (publickey)',
  shell: 'Authenticated, then "This account is currently not available."',
  success: 'Logged in successfully',
};

export interface DependencyNode {
  id: string;
  label: string;
  host: string;
  layer: string;
  dependsOn: string[];
  /** What switching it off means, in words. */
  failure: string;
  apply(world: World): void;
}

export const SSH_DEPENDENCIES: DependencyNode[] = [
  {
    id: 'dns', label: 'DNS server (ns1: named)', host: 'ns1', layer: 'Name resolution', dependsOn: [],
    failure: 'named is stopped on ns1.',
    apply: (w) => { script(w, 'ns1', ['systemctl stop named']); },
  },
  {
    id: 'dns-record', label: 'A record srv01.corp.lab', host: 'ns1', layer: 'Name resolution', dependsOn: ['dns'],
    failure: 'The srv01 record is deleted from the zone and the zone reloaded.',
    apply: (w) => {
      const h = w.hosts.ns1;
      writeFile(h, '/etc/bind/db.corp.lab', (readFile(h, '/etc/bind/db.corp.lab') ?? '').replace(/^srv01 .*\n/m, '').replace(/^www .*\n/m, ''), w.clock);
      script(w, 'ns1', ['rndc reload']);
    },
  },
  {
    id: 'client-route', label: 'Client default route (ws01)', host: 'ws01', layer: 'IP routing', dependsOn: [],
    failure: 'ws01 has no default gateway.',
    apply: (w) => { script(w, 'ws01', ['ip route del default']); },
  },
  {
    id: 'router', label: 'Router forwarding (rtr01)', host: 'rtr01', layer: 'IP routing', dependsOn: ['client-route'],
    failure: 'IP forwarding is disabled on rtr01 (net.ipv4.ip_forward=0). The kernel answers packets it may not route with ICMP host unreachable.',
    apply: (w) => { script(w, 'rtr01', ['sysctl -w net.ipv4.ip_forward=0']); },
  },
  {
    id: 'server-route', label: 'Server return route (srv01)', host: 'srv01', layer: 'IP routing', dependsOn: ['router'],
    failure: 'srv01 has no default gateway, so it cannot answer other subnets.',
    apply: (w) => { script(w, 'srv01', ['ip route del default']); },
  },
  {
    id: 'firewall', label: 'Host firewall allows tcp/22 (srv01)', host: 'srv01', layer: 'Packet filtering', dependsOn: ['server-route'],
    failure: 'The "tcp dport 22 accept" rule is removed; the input policy (drop) applies.',
    apply: (w) => {
      const h = w.hosts.srv01;
      writeFile(h, '/etc/nftables.conf', (readFile(h, '/etc/nftables.conf') ?? '').replace('\t\ttcp dport 22 accept\n', ''), w.clock);
      script(w, 'srv01', ['nft -f /etc/nftables.conf']);
    },
  },
  {
    id: 'sshd', label: 'sshd listening on :22', host: 'srv01', layer: 'Service', dependsOn: ['firewall'],
    failure: 'ssh.service is stopped.',
    apply: (w) => { script(w, 'srv01', ['systemctl stop ssh']); },
  },
  {
    id: 'algorithms', label: 'Common key-exchange algorithm', host: 'srv01', layer: 'SSH transport', dependsOn: ['sshd'],
    failure: 'sshd only allows diffie-hellman-group1-sha1, which modern clients no longer offer.',
    apply: (w) => {
      writeFile(w.hosts.srv01, '/etc/ssh/sshd_config.d/10-hardening.conf', HARDENING_CONF + 'KexAlgorithms diffie-hellman-group1-sha1\n', w.clock);
      script(w, 'srv01', ['systemctl reload ssh']);
    },
  },
  {
    id: 'hostkey', label: 'Host key matches known_hosts', host: 'srv01', layer: 'SSH transport', dependsOn: ['algorithms'],
    failure: 'srv01\'s host keys are regenerated (as after a reinstall).',
    apply: (w) => {
      installHostKeys(w.hosts.srv01, w.clock, 3);
      script(w, 'srv01', ['systemctl restart ssh']);
    },
  },
  {
    id: 'authz', label: 'Account allowed (AllowUsers)', host: 'srv01', layer: 'Authorization', dependsOn: ['hostkey'],
    failure: '"AllowUsers bob" is added: alice is no longer allowed.',
    apply: (w) => {
      writeFile(w.hosts.srv01, '/etc/ssh/sshd_config.d/10-hardening.conf', HARDENING_CONF + 'AllowUsers bob\n', w.clock);
      script(w, 'srv01', ['systemctl reload ssh']);
    },
  },
  {
    id: 'authkeys', label: 'Key in authorized_keys', host: 'srv01', layer: 'Authentication', dependsOn: ['authz'],
    failure: 'alice\'s authorized_keys file is removed.',
    apply: (w) => { script(w, 'srv01', ['rm /home/alice/.ssh/authorized_keys']); },
  },
  {
    id: 'shell', label: 'Valid login shell', host: 'srv01', layer: 'Session', dependsOn: ['authkeys'],
    failure: 'alice\'s shell is set to /usr/sbin/nologin.',
    apply: (w) => { script(w, 'srv01', ['usermod -s /usr/sbin/nologin alice']); },
  },
];

export function classifyOutcome(r: SshResult): OutcomeClass {
  const text = r.lines.join('\n');
  if (r.outcome === 'session') return 'success';
  if (/Name or service not known/.test(text)) return 'resolve-nx';
  if (/Temporary failure in name resolution/.test(text)) return 'resolve-temp';
  if (/Network is unreachable/.test(text)) return 'netunreach';
  if (/No route to host/.test(text)) return 'noroute';
  if (/timed out/.test(text)) return 'timeout';
  if (/Connection refused/.test(text)) return 'refused';
  if (/Unable to negotiate/.test(text)) return 'negotiate';
  if (/Host key verification failed/.test(text)) return 'hostkey';
  if (/currently not available/.test(text)) return 'shell';
  return 'denied';
}

export interface DependencyRun {
  outcome: OutcomeClass;
  lines: string[];
  serverLog: string[];
  trace: TraceEvent[];
  elapsedMs: number;
}

/** Fresh lab with ARP caches cleared, so traces include ARP. */
export function freshLab(): World {
  const w = buildSshLab();
  for (const h of Object.values(w.hosts)) {
    h.neighbors = [];
    h.conntrack = [];
    h.capture = [];
  }
  return w;
}

export function runWithFault(nodeId: string | null, opts: { verbose?: number } = {}): DependencyRun {
  const w = freshLab();
  if (nodeId) {
    SSH_DEPENDENCIES.find((n) => n.id === nodeId)!.apply(w);
    for (const h of Object.values(w.hosts)) h.capture = [];
  }
  const journalStart = w.hosts.srv01.journal.length;
  const rec = new Recorder();
  const start = w.clock;
  const r = withRecorder(rec, () =>
    runSsh(w, { clientHostId: 'ws01', localUser: 'alice', target: 'srv01.corp.lab', batchMode: true, verbose: opts.verbose ?? 1 }),
  );
  const serverLog = w.hosts.srv01.journal.slice(journalStart).map((e) => `${e.ident}${e.pid ? `[${e.pid}]` : ''}: ${e.message}`);
  return { outcome: classifyOutcome(r), lines: r.lines, serverLog, trace: rec.events, elapsedMs: w.clock - start };
}
