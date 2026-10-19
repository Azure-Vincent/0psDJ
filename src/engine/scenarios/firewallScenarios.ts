// Firewall (nftables) troubleshooting scenarios. Same lab as the SSH set; the
// faults live in packet filtering on srv01 and on the router rtr01.

import { readFile, writeFile } from '../fs';
import { explainPacket } from '../config/nft';
import { RTR01_NFT } from '../lab/sshLab';
import type { World } from '../types';
import { firewallStillRestrictive, script, sessionStillWorks, sshdPolicy } from './engine';
import type { Constraint, Goal, Scenario } from './types';

const ALICE_SSH: Goal = { description: 'alice on ws01 can still ssh to srv01.corp.lab.', localUser: 'alice', user: 'alice', target: 'srv01.corp.lab', method: 'publickey' };
const WEB_FROM_WS01: Goal = { kind: 'http', description: 'From ws01, "curl -I http://srv01.corp.lab/" returns HTTP 200.', fromHost: 'ws01', fromUser: 'alice', url: 'http://srv01.corp.lab/' };

const BRIEFING = [
  'Client: ws01 (10.0.10.25/24). Server: srv01.corp.lab (10.0.20.10/24) runs sshd and nginx (intranet site). DNS: ns1 (10.0.10.53).',
  'rtr01 routes between the office LAN 10.0.10.0/24 (eth0) and the server network 10.0.20.0/24 (eth1), and filters forwarded traffic with nftables.',
  'You have a terminal on ws01 as alice and root consoles on srv01, ns1 and rtr01.',
  'Policy: default-deny input on servers; changes must be persistent (/etc/nftables.conf).',
];

const CANDIDATES = [
  'web-not-running', 'firewall-drop', 'firewall-reject', 'fw-cidr-error', 'fw-missing-established', 'fw-router-forward',
  'routing-server-gateway', 'dns-wrong-record', 'dns-client-config', 'server-down', 'firewall-not-persistent',
];

function editFile(world: World, host: string, path: string, fn: (s: string) => string, gapMs = 60_000) {
  world.clock += gapMs;
  const h = world.hosts[host];
  writeFile(h, path, fn(readFile(h, path) ?? ''), world.clock);
}

function packetVerdict(world: World, host: string, hook: 'input' | 'forward', p: Parameters<typeof explainPacket>[2]): string {
  return explainPacket(world.hosts[host].nft, hook, p).result.verdict;
}

function routerForwardRestrictive(): Constraint {
  return {
    id: 'rtr-forward-restrictive',
    required: true,
    description: 'rtr01 must keep a default-drop forward policy (only intended services may cross from the LAN to the servers).',
    check(world) {
      const fwd = world.hosts.rtr01.nft.tables.flatMap((t) => t.chains).find((c) => c.base?.hook === 'forward');
      if (!fwd || fwd.base!.policy !== 'drop') return { id: this.id, ok: false, required: true, message: 'rtr01 forward policy is no longer drop: everything can cross between the networks.' };
      const probe = packetVerdict(world, 'rtr01', 'forward', { src: '10.0.10.25', dst: '10.0.20.10', proto: 'tcp', sport: 50000, dport: 3306, ctState: 'new', len: 60, iif: 'eth0', oif: 'eth1' });
      if (probe === 'accept') return { id: this.id, ok: false, required: true, message: 'rtr01 forwards MySQL (3306) from the LAN to the servers: the rule is broader than needed.' };
      return { id: this.id, ok: true, required: true, message: 'Forward policy is drop and unrelated ports (e.g. 3306) are still blocked.' };
    },
  };
}

function guestStillBlocked(): Constraint {
  return {
    id: 'guest-blocked',
    required: true,
    description: 'SEC-88 must stay in force: the guest Wi-Fi 10.0.11.0/24 may not reach srv01.',
    check(world) {
      const v = packetVerdict(world, 'srv01', 'input', { src: '10.0.11.20', dst: '10.0.20.10', proto: 'tcp', sport: 50000, dport: 22, ctState: 'new', len: 60, iif: 'eth0' });
      return v === 'accept'
        ? { id: this.id, ok: false, required: true, message: 'A guest (10.0.11.20) can now open SSH to srv01.' }
        : { id: this.id, ok: true, required: true, message: 'Guest addresses are still dropped.' };
    },
  };
}

function noStatelessDnsHole(): Constraint {
  return {
    id: 'no-sport-53-hole',
    required: true,
    description: 'Do not open the firewall based on source port (e.g. "udp sport 53 accept"): anyone can send packets from port 53.',
    check(world) {
      const v = packetVerdict(world, 'srv01', 'input', { src: '198.51.100.7', dst: '10.0.20.10', proto: 'udp', sport: 53, dport: 41000, ctState: 'new', len: 60, iif: 'eth0' });
      return v === 'accept'
        ? { id: this.id, ok: false, required: true, message: 'An unsolicited UDP packet from 198.51.100.7 port 53 to a random port is accepted.' }
        : { id: this.id, ok: true, required: true, message: 'Unsolicited packets from source port 53 are still dropped; replies are matched by connection state.' };
    },
  };
}

export const FIREWALL_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'fw-nginx-stopped',
    title: '"Security broke the website again"',
    difficulty: 'beginner',
    ticket: 'Helpdesk: "The intranet (http://srv01.corp.lab) is down: curl says Couldn\'t connect to server. Security changed firewalls this week, it must be them." SSH to srv01 works.',
    briefing: [...BRIEFING, 'Yesterday evening the web team upgraded nginx on srv01.'],
    goals: [WEB_FROM_WS01],
    setup(world) {
      script(world, 'srv01', ['systemctl stop nginx', 'systemctl disable nginx']);
      world.clock += 10 * 3600_000;
    },
    rootCauses: ['web-not-running'],
    candidates: CANDIDATES,
    feedback: {
      'firewall-reject': 'A "reject with tcp reset" rule would look identical from the client. Check the server: is the SYN accepted by nft (counters, nft list ruleset), and is anything listening on :80?',
      'firewall-drop': 'A drop gives a timeout. Here the failure is immediate: something answered.',
      'fw-router-forward': 'A forward-chain drop gives a timeout and the server would see nothing. Here the server answers with RST.',
    },
    hints: [
      '"Couldn\'t connect to server" immediately = an RST came back. Both a firewall reject AND a closed port produce that. How can you tell them apart?',
      'On srv01: is anything listening on port 80 (ss -tlnp)? What does systemctl say about nginx? Look at the nft ruleset too.',
      'nginx is stopped AND disabled. systemctl enable --now nginx, then verify (Verify also reboots the server).',
    ],
    explanation: {
      rootCause: 'During the upgrade nginx was stopped and disabled, and never started again. The firewall was not involved.',
      manifestation: 'srv01\'s firewall accepts the SYN to port 80, but no socket listens there, so the kernel answers RST and curl reports "Couldn\'t connect to server" immediately. SSH works because sshd is unaffected.',
      evidence: 'ss -tlnp on srv01 shows no :80 listener; systemctl status nginx is "inactive (dead)" and "disabled"; the journal shows "Stopped nginx.service"; nft list ruleset still has "tcp dport { 80, 443 } accept".',
      prevention: 'After maintenance, check service state and enablement (systemctl is-enabled), and monitor the service endpoint, not just the host. Collect evidence before assigning blame: firewall rejects and closed ports look the same from the client.',
    },
    solution: [{ host: 'srv01', commands: ['ss -tlnp', 'systemctl status nginx', 'systemctl enable --now nginx', 'ss -tlnp'] }],
    constraints: [firewallStillRestrictive(), sshdPolicy()],
    concepts: ['svc.listening', 'svc.systemd', 'tcp.handshake'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'fw-tcp-reset',
    title: 'nginx is running, but…',
    difficulty: 'beginner',
    ticket: 'Web team: "nginx is up (systemctl says active, and curl http://localhost works ON srv01), but from the office curl http://srv01.corp.lab says Couldn\'t connect to server. We did not change anything."',
    briefing: [...BRIEFING, 'Last night was maintenance window MW-311 for srv01.'],
    goals: [WEB_FROM_WS01],
    setup(world) {
      editFile(world, 'srv01', '/etc/nftables.conf', (s) => s.replace('\t\ttcp dport { 80, 443 } accept\n', '\t\ttcp dport { 80, 443 } reject with tcp reset comment "MW-311 maintenance"\n'));
      script(world, 'srv01', ['systemctl restart nftables']);
      world.clock += 9 * 3600_000;
    },
    rootCauses: ['firewall-reject'],
    candidates: CANDIDATES,
    feedback: {
      'web-not-running': 'ss -tlnp shows nginx on 0.0.0.0:80 and curl from srv01 itself works (loopback is accepted by "iif lo accept"). The RST comes from somewhere else.',
      'firewall-drop': 'A drop is silent (timeout). This fails instantly.',
    },
    hints: [
      'Local access works, remote access is refused. What lies between a remote client and nginx that local connections skip?',
      'On srv01 run nft -a list ruleset. Which rule does a TCP SYN to port 80 from 10.0.10.25 match first? Check its counter after another curl attempt.',
      'A leftover maintenance rule rejects ports 80/443 with tcp reset. Restore "tcp dport { 80, 443 } accept" in /etc/nftables.conf and reload it.',
    ],
    explanation: {
      rootCause: 'A maintenance rule "tcp dport { 80, 443 } reject with tcp reset" replaced the accept rule in /etc/nftables.conf and was never reverted.',
      manifestation: 'The firewall answers the SYN with a TCP RST on behalf of the host, which is indistinguishable on the client from "nothing listening". Loopback tests on the server pass because "iif lo accept" comes first.',
      evidence: 'nft -a list ruleset shows the reject rule with the MW-311 comment and its counter increasing with each attempt; ss shows nginx listening; curl http://localhost on srv01 works.',
      prevention: 'Track temporary rules with an owner and expiry; test from the client network, not from the server itself.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i 's/ reject with tcp reset comment \"MW-311 maintenance\"/ accept/' /etc/nftables.conf", 'nft -c -f /etc/nftables.conf', 'nft -f /etc/nftables.conf'] }],
    constraints: [firewallStillRestrictive(), sessionStillWorks(ALICE_SSH, 'ssh-still-works', 'SSH from the admin LAN must keep working.')],
    concepts: ['fw.stateful', 'tcp.handshake', 'svc.listening'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'fw-cidr-guest',
    title: 'Blocking the guests (and everyone else)',
    difficulty: 'intermediate',
    ticket: 'alice: "Since this morning srv01 is unreachable from the office: ssh and the website time out, ping gets nothing. The hypervisor shows the VM running fine." Security note: "SEC-88: we blocked the guest Wi-Fi from the servers today."',
    briefing: [...BRIEFING, 'Guest Wi-Fi network: 10.0.11.0/24. It must stay blocked from srv01 (SEC-88).'],
    goals: [{ ...ALICE_SSH, description: 'alice on ws01 can ssh to srv01.corp.lab.' }, WEB_FROM_WS01],
    setup(world) {
      editFile(world, 'srv01', '/etc/nftables.conf', (s) => s.replace('\t\tct state invalid drop\n', '\t\tct state invalid drop\n\t\tip saddr 10.0.10.0/23 counter drop comment "SEC-88 block guest Wi-Fi"\n'));
      script(world, 'srv01', ['nft -f /etc/nftables.conf']);
      world.clock += 3 * 3600_000;
    },
    rootCauses: ['fw-cidr-error'],
    acceptable: { 'firewall-drop': 'Correct: srv01\'s firewall drops the traffic. The underlying mistake is the prefix of the new rule.' },
    candidates: CANDIDATES,
    feedback: {
      'server-down': 'srv01 is up: rtr01 can ARP it (ip neigh on rtr01 shows REACHABLE), and tcpdump on srv01 shows your packets arriving.',
      'routing-server-gateway': 'srv01 still has its default route (ip route), and tcpdump on srv01 shows no reply even being attempted: the packets are discarded before any socket sees them.',
      'fw-router-forward': 'tcpdump on srv01 shows the packets arriving, so the router forwarded them.',
    },
    hints: [
      'Everything from the office times out, including ping. Do the packets reach srv01 at all? (tcpdump on the srv01 console.)',
      'They arrive and are dropped. Read srv01\'s ruleset with nft -a list ruleset and look at counters. Which addresses does each prefix cover?',
      '10.0.10.0/23 covers 10.0.10.0–10.0.11.255: the office LAN AND the guest network. The guest network alone is 10.0.11.0/24. Fix /etc/nftables.conf and reload.',
    ],
    explanation: {
      rootCause: 'The SEC-88 rule was written as "ip saddr 10.0.10.0/23 drop". A /23 spans two /24 networks: 10.0.10.0/24 (the office LAN) and 10.0.11.0/24 (guests).',
      manifestation: 'The rule sits above the ICMP and service accept rules, so every new connection from the office (SSH, HTTP, ping) is silently dropped: timeouts everywhere, as if the server were down. Established flows and traffic from other networks are unaffected.',
      evidence: 'tcpdump on srv01 shows incoming SYNs/echo requests from 10.0.10.25 with no replies; the rule\'s counter increases with each attempt; 10.0.10.25 is inside 10.0.10.0/23 (mask 255.255.254.0).',
      prevention: 'Calculate ranges before writing rules (ipcalc/sipcalc), review firewall changes, test from both the network you block and the one you must not block, and add counters/logging to new drop rules.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i 's|ip saddr 10.0.10.0/23|ip saddr 10.0.11.0/24|' /etc/nftables.conf", 'nft -f /etc/nftables.conf', 'nft -a list chain inet filter input'] }],
    constraints: [guestStillBlocked(), firewallStillRestrictive(), sshdPolicy()],
    concepts: ['net.cidr', 'fw.stateful', 'tcp.handshake'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'fw-no-established',
    title: 'The server cannot look anything up',
    difficulty: 'intermediate',
    ticket: 'srv01 admin: "apt update fails with Temporary failure resolving deb.debian.org, and our app on srv01 cannot reach the database by name. Inbound SSH and the website work fine. Ping to ns1 works too!"',
    briefing: [...BRIEFING, 'This morning someone "cleaned up" srv01\'s ruleset to make it shorter.'],
    goals: [{ kind: 'resolve', description: 'On srv01, "getent hosts ns1.corp.lab" returns 10.0.10.53.', fromHost: 'srv01', name: 'ns1.corp.lab', expect: '10.0.10.53' }],
    setup(world) {
      editFile(world, 'srv01', '/etc/nftables.conf', (s) => s.replace('\t\tct state established,related accept\n', ''));
      script(world, 'srv01', ['nft -f /etc/nftables.conf']);
      world.clock += 4 * 3600_000;
    },
    rootCauses: ['fw-missing-established'],
    candidates: CANDIDATES,
    feedback: {
      'dns-client-config': 'srv01\'s /etc/resolv.conf points at 10.0.10.53, which is correct (ws01 uses the same server successfully).',
      'server-down': 'ns1 answers ws01\'s queries, and tcpdump on srv01 shows its answers ARRIVING at srv01.',
      'firewall-drop': 'Close, but which direction? Outgoing queries are allowed (output policy accept). Look at what happens to the replies.',
      'dns-wrong-record': 'There is no answer at all (timeout), not a wrong answer.',
    },
    hints: [
      'Inbound works, outbound lookups fail, ICMP works. Run "dig ns1.corp.lab" on srv01, then tcpdump -i eth0 -n port 53. Does the answer come back?',
      'The answer arrives on the wire but dig never sees it. Which chain decides whether an arriving packet reaches a local socket, and which rule would match a DNS reply (source port 53, destination a random high port)?',
      'Nothing matches replies any more: the "ct state established,related accept" rule was removed. Put it back at the top of the input chain in /etc/nftables.conf and reload. Do NOT open "udp sport 53".',
    ],
    explanation: {
      rootCause: 'The "ct state established,related accept" rule was removed from srv01\'s input chain. With policy drop, only packets matching an explicit rule are accepted.',
      manifestation: 'Inbound services still work because their packets match "tcp dport 22/80" rules, and outbound replies leave freely (output policy accept). But replies to connections srv01 initiates (DNS answers from port 53 to a random port) match no rule and are dropped. ICMP echo replies still pass because of the blanket "meta l4proto icmp accept", which makes ping misleading.',
      evidence: 'tcpdump on srv01 shows the query leaving and the answer from 10.0.10.53.53 arriving; dig still times out; conntrack -L shows the UDP flow; the input chain has no established,related rule.',
      prevention: 'Keep "ct state established,related accept" as the first rule of every stateful input chain. Never "fix" this with source-port rules such as "udp sport 53 accept": an attacker can choose their source port.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i 's/^\\t\\tct state invalid drop$/\\t\\tct state established,related accept\\n\\t\\tct state invalid drop/' /etc/nftables.conf", 'nft -f /etc/nftables.conf', 'getent hosts ns1.corp.lab'] }],
    constraints: [noStatelessDnsHole(), firewallStillRestrictive(), sessionStillWorks(ALICE_SSH, 'ssh-still-works', 'Inbound SSH must keep working.')],
    concepts: ['fw.stateful', 'dns.resolution'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'fw-router-forward',
    title: 'Only the admins can get through',
    difficulty: 'intermediate',
    ticket: 'Whole office: "The intranet http://srv01.corp.lab times out." The admins say: "Strange, ssh to srv01 works perfectly for us." Network team: "We applied the new inter-VLAN policy NET-17 on rtr01 yesterday."',
    briefing: [...BRIEFING, 'NET-17 intent: from the office LAN, servers may be reached for SSH (admins) and the intranet web site (HTTP/HTTPS). Nothing else.'],
    goals: [WEB_FROM_WS01, { ...ALICE_SSH }],
    setup(world) {
      const fwd = '\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t\tct state established,related accept\n\t\tmeta l4proto icmp accept\n\t\tiifname "eth0" oifname "eth1" tcp dport 22 accept comment "NET-17 admin access"\n\t\tiifname "eth1" oifname "eth0" accept\n\t}\n';
      editFile(world, 'rtr01', '/etc/nftables.conf', () => RTR01_NFT.replace('\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n\t}\n', fwd));
      script(world, 'rtr01', ['nft -f /etc/nftables.conf']);
      world.clock += 16 * 3600_000;
    },
    rootCauses: ['fw-router-forward'],
    candidates: CANDIDATES,
    feedback: {
      'firewall-drop': 'srv01\'s own ruleset accepts tcp/80 and its counters do not move during your attempts; tcpdump on srv01 shows nothing for port 80. The packets never reach srv01.',
      'web-not-running': 'nginx is listening (ss -tlnp on srv01), and a failure would be immediate ("refused"), not a timeout.',
      'server-down': 'SSH to the same server works through the same router.',
    },
    hints: [
      'SSH works, HTTP times out, same client, same server. Which devices are on the path, and which of them filter traffic?',
      'Capture on srv01 (tcpdump -i eth0 -n port 80) while running curl from ws01. If nothing arrives, look at the router: nft list ruleset on rtr01.',
      'rtr01\'s forward chain only allows tcp/22 from eth0 to eth1. Extend that rule to { 22, 80, 443 } in rtr01\'s /etc/nftables.conf and reload. Keep the policy drop.',
    ],
    explanation: {
      rootCause: 'NET-17 implemented only the SSH half of the intent: rtr01\'s forward chain (policy drop) accepts tcp/22 from the LAN to the servers but not tcp/80 or 443.',
      manifestation: 'HTTP SYNs are dropped by rtr01 while forwarding, so they never reach srv01. The client retransmits and times out. SSH and ping match explicit forward rules and work, which points away from the router if you only look at the server.',
      evidence: 'tcpdump on srv01 sees no port-80 traffic; srv01\'s nft counters for dport 80 do not change; on rtr01 the forward chain lacks 80/443, and traceroute -T -p 80 from ws01 stops after rtr01.',
      prevention: 'Translate the written intent into a test matrix (source network × destination × port) and run it after every policy change. Remember that a packet passes several filtering points: client output, every router\'s forward chain, server input.',
    },
    solution: [{ host: 'rtr01', commands: ["sed -i 's/tcp dport 22 accept comment \"NET-17 admin access\"/tcp dport { 22, 80, 443 } accept comment \"NET-17 admin + web\"/' /etc/nftables.conf", 'nft -f /etc/nftables.conf', 'nft list chain inet filter forward'] }],
    constraints: [routerForwardRestrictive(), firewallStillRestrictive()],
    concepts: ['fw.path', 'fw.stateful', 'net.routing'],
  },
];
