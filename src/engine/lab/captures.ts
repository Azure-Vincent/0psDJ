// Packet Lab capture presets. Every capture is produced by running the
// simulator on a fresh lab and collecting the frames seen on one interface,
// so the packets are protocol-consistent (sequence numbers, ICMP quoting, ARP)
// and identical every time.

import { Shell } from '../shell/shell';
import type { CapturedFrame, World } from '../types';
import { SSH_DEPENDENCIES, freshLab } from './dependencies';
import { script } from '../scenarios/engine';
import { readFile, writeFile } from '../fs';

export interface CapturePreset {
  id: string;
  title: string;
  description: string;
  host: string;
  iface: string;
  /** Things to look for in this capture. */
  lookFor: string[];
  build(world: World): void;
}

function as(world: World, host: string, user: string, lines: string[]) {
  let w = world;
  const sh = new Shell(() => w, (n) => (w = n), { hostId: host, user, cwd: w.hosts[host].users[user].home });
  for (const l of lines) {
    w.clock += 1500;
    sh.execute(l);
  }
  Object.assign(world, w);
}

export const CAPTURE_PRESETS: CapturePreset[] = [
  {
    id: 'ssh-login', title: 'Successful SSH login (exec "hostname")', host: 'ws01', iface: 'eth0',
    description: 'alice runs "ssh srv01.corp.lab hostname" with cold ARP caches: ARP, DNS, TCP handshake, SSH negotiation, encrypted authentication, an exec channel and the TCP teardown.',
    lookFor: ['ARP for the default gateway before the first packet leaves', 'DNS query and authoritative answer', 'SYN / SYN-ACK / ACK and the relative sequence numbers', 'Plaintext identification strings and KEXINIT (algorithm lists are readable)', 'After New Keys: only "Encrypted packet" entries. The user name is NOT visible.', 'FIN, FIN/ACK, ACK at the end'],
    build: (w) => as(w, 'ws01', 'alice', ['ssh srv01.corp.lab hostname']),
  },
  {
    id: 'ssh-refused', title: 'Connection refused (sshd stopped)', host: 'ws01', iface: 'eth0',
    description: 'sshd is stopped on srv01; the client tries to connect.',
    lookFor: ['The SYN reaches srv01 and is answered immediately with RST, ACK', 'No retransmissions: the client gives up at once'],
    build: (w) => {
      SSH_DEPENDENCIES.find((n) => n.id === 'sshd')!.apply(w);
      w.hosts.ws01.capture = [];
      as(w, 'ws01', 'alice', ['ssh srv01.corp.lab']);
    },
  },
  {
    id: 'ssh-timeout', title: 'Connection timed out (firewall drop), client view', host: 'ws01', iface: 'eth0',
    description: 'srv01\'s firewall no longer accepts tcp/22. The client uses ConnectTimeout=20.',
    lookFor: ['Identical SYNs (same sequence number) at growing intervals: 1 s, 2 s, 4 s, 8 s', 'Nothing comes back'],
    build: (w) => {
      SSH_DEPENDENCIES.find((n) => n.id === 'firewall')!.apply(w);
      w.hosts.ws01.capture = [];
      as(w, 'ws01', 'alice', ['ssh -o ConnectTimeout=20 srv01.corp.lab']);
    },
  },
  {
    id: 'asymmetric', title: 'Missing return route, server view', host: 'srv01', iface: 'eth0',
    description: 'srv01 has lost its default gateway. Captured ON THE SERVER while ws01 connects.',
    lookFor: ['SYNs arrive from 10.0.10.25', 'No SYN-ACK ever leaves srv01', 'Compare with the client-side timeout capture: identical from the client\'s point of view'],
    build: (w) => {
      SSH_DEPENDENCIES.find((n) => n.id === 'server-route')!.apply(w);
      w.hosts.srv01.capture = [];
      as(w, 'ws01', 'alice', ['ssh -o ConnectTimeout=10 srv01.corp.lab']);
    },
  },
  {
    id: 'admin-prohibited', title: '"No route to host" from a reject rule', host: 'ws01', iface: 'eth0',
    description: 'srv01 rejects SSH from 10.0.10.0/24 with ICMP admin-prohibited.',
    lookFor: ['ICMP type 3 code 13 sent by the server itself (not a router)', 'The ICMP payload quotes the original SYN header (look at the hex dump)'],
    build: (w) => {
      script(w, 'srv01', ['nft insert rule inet filter input ip saddr 10.0.10.0/24 tcp dport 22 reject with icmpx type admin-prohibited']);
      w.hosts.ws01.capture = [];
      as(w, 'ws01', 'alice', ['ssh srv01.corp.lab']);
    },
  },
  {
    id: 'stale-dns', title: 'Wrong A record → ARP failure on the router', host: 'ws01', iface: 'eth0',
    description: 'srv01.corp.lab points to 10.0.20.11, which does not exist.',
    lookFor: ['The DNS answer contains 10.0.20.11', 'About 3 s later, rtr01 (10.0.10.1) sends ICMP host unreachable'],
    build: (w) => {
      const ns = w.hosts.ns1;
      writeFile(ns, '/etc/bind/db.corp.lab', (readFile(ns, '/etc/bind/db.corp.lab') ?? '').replace('10.0.20.10', '10.0.20.11'), w.clock);
      script(w, 'ns1', ['rndc reload']);
      w.hosts.ws01.capture = [];
      as(w, 'ws01', 'alice', ['ssh srv01.corp.lab']);
    },
  },
  {
    id: 'dns', title: 'DNS: NOERROR, NXDOMAIN and REFUSED', host: 'ws01', iface: 'eth0',
    description: 'Three dig queries: an existing name, a missing name inside corp.lab, and a name outside any zone ns1 serves (ns1 is authoritative-only).',
    lookFor: ['Flags in the responses: authoritative answer vs refused', 'Transaction IDs pairing queries with responses', 'UDP, no handshake'],
    build: (w) => as(w, 'ws01', 'alice', ['dig srv01.corp.lab', 'dig nosuchhost.corp.lab', 'dig www.example.com']),
  },
  {
    id: 'dhcp-dora', title: 'DHCP: release and DORA, server view', host: 'ns1', iface: 'eth0',
    description: 'ws02 releases its lease and asks again (dhclient -r; dhclient -v), captured on the DHCP server ns1. (The simulator records the release in the lease files and logs but does not put a DHCPRELEASE packet on the wire.)',
    lookFor: ['DISCOVER and REQUEST from 0.0.0.0:68 to 255.255.255.255:67 (Ethernet destination ff:ff:ff:ff:ff:ff)', 'OFFER and ACK unicast to the client MAC with yiaddr 10.0.10.100', 'Options in the BOOTP payload: message type (53), server identifier (54), lease time (51), router (3), DNS (6)', 'The same transaction ID in all four DORA messages'],
    build: (w) => as(w, 'ws02', 'root', ['dhclient -r eth0', 'dhclient -v eth0']),
  },
  {
    id: 'nat-uplink', title: 'NAT: the Internet side of rtr01', host: 'rtr01', iface: 'eth2',
    description: 'ws01 fetches a page from the Internet host 203.0.113.80, then ext01 fetches the published intranet site from 203.0.113.2. Captured on rtr01\'s uplink eth2.',
    lookFor: ['Outbound flow: source 203.0.113.2 (masqueraded), never 10.0.10.25', 'Inbound flow: destination 203.0.113.2:80; the replies also come from 203.0.113.2 (un-DNATed)', 'No private address appears anywhere on this interface', 'Compare with "tcpdump -n -i eth0" / "conntrack -L" on rtr01 in a sandbox terminal'],
    build: (w) => { as(w, 'ws01', 'alice', ['curl -I http://203.0.113.80/']); as(w, 'ext01', 'guest', ['curl -I http://203.0.113.2/']); },
  },
  {
    id: 'ping-traceroute', title: 'ping and traceroute (ICMP echo, TTL exceeded)', host: 'ws01', iface: 'eth0',
    description: 'ping -c 2 srv01, then traceroute -n srv01 (UDP probes), which srv01\'s firewall drops after the first hop.',
    lookFor: ['Echo request/reply pairs with the same id and sequence', 'TTL=1 probes answered by rtr01 with "time exceeded"', 'Later probes get no answer: srv01 drops UDP 33434+'],
    build: (w) => as(w, 'ws01', 'alice', ['ping -c 2 srv01.corp.lab', 'traceroute -n -m 3 srv01.corp.lab']),
  },
];

export function runCapture(id: string): { preset: CapturePreset; frames: CapturedFrame[] } {
  const preset = CAPTURE_PRESETS.find((p) => p.id === id)!;
  const w = freshLab();
  preset.build(w);
  const frames = w.hosts[preset.host].capture.filter((f) => f.iface === preset.iface);
  return { preset, frames };
}
