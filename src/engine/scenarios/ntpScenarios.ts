// Time synchronisation tickets. rtr01 runs chrony: it follows the provider's
// stratum-1 server (ext01, 203.0.113.80) and serves the internal networks; the
// Debian machines run systemd-timesyncd against rtr01. Each ticket breaks one
// link of that chain: the router's firewall, chrony's allow list, chrony's own
// upstream, and chronyd itself.

import { readFile, writeFile } from '../fs';
import { ALICE_KRB_PASSWORD } from '../lab/krbLab';
import { RTR01_CHRONY_CONF } from '../lab/ntpLab';
import { RTR01_NFT } from '../lab/sshLab';
import { type ChronyLoaded, ntpSettle } from '../sim/ntp';
import type { World } from '../types';
import { firewallStillRestrictive, script } from './engine';
import type { Constraint, Goal, Scenario } from './types';

const time = (host: string): Goal => ({ kind: 'time', host, description: `${host}'s clock is synchronized by NTP (timedatectl: "System clock synchronized: yes") and correct to within a second.` });

const KINIT: Goal = {
  kind: 'kerberos', fromHost: 'ws01', localUser: 'alice', password: ALICE_KRB_PASSWORD,
  description: 'On ws01, alice gets a Kerberos ticket (kinit alice@CORP.LAB): her clock must be within 5 minutes of the KDC\'s.',
};

/** A file's contents as one printf command line (reference solutions). */
const printfTo = (text: string, path: string) => `printf '${text.replace(/\\/g, '\\\\').replace(/\n/g, '\\n')}' > ${path}`;

const NTP_RULE = '\t\t# NTP for the internal networks (chrony, CHG-0912)\n\t\tiifname != "eth2" udp dport 123 accept\n';

/** Days pass without synchronisation: the clocks wander (a few seconds per day is normal for a VM; these are worse). */
function drift(world: World, offsets: Record<string, number>): void {
  world.clock += 3 * 24 * 3600_000;
  for (const [id, ms] of Object.entries(offsets)) world.hosts[id].clockOffset = (world.hosts[id].clockOffset ?? 0) + ms;
  ntpSettle(world);
}

/** rtr01 must keep following a real upstream: "local stratum" would hand out its own unsynchronized clock. */
function rtr01Upstream(): Constraint {
  return {
    id: 'rtr01-upstream', required: true,
    description: 'rtr01 is synchronized to the provider\'s server (203.0.113.80), not serving its own clock with "local stratum".',
    check(world) {
      const l = world.hosts.rtr01.services.chrony?.loaded as ChronyLoaded | null | undefined;
      const ok = !!l?.synced && l.refName === '203.0.113.80';
      return { id: this.id, ok, required: true, message: ok ? 'rtr01: chrony follows 203.0.113.80 (stratum 2).' : `rtr01: chrony is ${l?.synced ? `synchronized to ${l.refName}` : l?.localStratum !== undefined ? 'serving its own clock (local stratum)' : 'not synchronized'}; it must follow 203.0.113.80.` };
    },
  };
}

/** chrony serves the internal networks only, not the whole Internet. */
function chronyAllowScoped(): Constraint {
  return {
    id: 'chrony-allow-scoped', required: true,
    description: 'rtr01\'s chrony serves the internal networks only (no "allow" or "allow all" for every address).',
    check(world) {
      const l = world.hosts.rtr01.services.chrony?.loaded as ChronyLoaded | null | undefined;
      const open = l?.allow.find((a) => !a.deny && (a.cidr === '0.0.0.0/0' || Number(a.cidr.split('/')[1]) < 16));
      return { id: this.id, ok: !open, required: true, message: open ? `rtr01: "allow ${open.cidr}" serves time to anyone, including the Internet side.` : 'rtr01: chrony allows the internal subnets only.' };
    },
  };
}

const BRIEFING = [
  'Time service of corp.lab: ext01 (203.0.113.80) stands in for the provider\'s stratum-1 server ntp.example.net. rtr01 runs chrony (/etc/chrony/chrony.conf): it follows that server and serves time to the office (10.0.10.0/24), the servers (10.0.20.0/24) and VLAN 30 (10.0.30.0/24).',
  'Every Debian machine runs systemd-timesyncd with NTP=rtr01.corp.lab (/etc/systemd/timesyncd.conf). Kerberos (the KDC on ns1) refuses clocks more than 5 minutes apart.',
  'Tools: timedatectl, timedatectl timesync-status, journalctl -u systemd-timesyncd, date on the clients; chronyc tracking / sources / clients, journalctl -u chrony, nft list ruleset, tcpdump -n udp port 123 on rtr01.',
  'Fixes must survive a reboot. Keep rtr01\'s firewall restrictive and its chrony following the real upstream.',
];

const TERMINALS = [
  { hostId: 'rtr01', user: 'root', label: 'rtr01 console (root)', banner: 'rtr01 console: the NTP server (chrony). Try: chronyc tracking, chronyc sources, chronyc clients, journalctl -u chrony, nft list ruleset.' },
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01, alice\'s workstation (sudo password ws01-alice). Try: timedatectl, timedatectl timesync-status, date, kinit.' },
  { hostId: 'dev01', user: 'erin', label: 'dev01 (erin)', banner: 'dev01 on VLAN 30 (sudo password dev01-erin). Try: timedatectl, timedatectl timesync-status.' },
];

const CANDIDATES = ['ntp-server-firewall', 'ntp-allow-missing', 'ntp-upstream-unreachable', 'ntp-server-down', 'krb-clock-skew', 'dns-wrong-record', 'routing-client'];

export const NTP_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'ntp-blocked',
    title: 'Clock skew after the firewall review',
    difficulty: 'intermediate',
    ticket: 'Since the router firewall review (SEC-130) last week, alice\'s kinit fails with "Clock skew too great". Her workstation shows 08:4x while the wall clock says 08:3x. Desktop support: "NTP is enabled on the PC, we checked."',
    briefing: BRIEFING,
    goals: [KINIT, time('ws01'), time('srv01')],
    terminals: TERMINALS,
    setup(world) {
      writeFile(world.hosts.rtr01, '/etc/nftables.conf', RTR01_NFT.replace(NTP_RULE, ''), world.clock, { mode: 0o755 });
      script(world, 'rtr01', ['systemctl restart nftables']);
      drift(world, { ws01: 6 * 60_000 + 41_000, srv01: -95_000 });
    },
    rootCauses: ['ntp-server-firewall'],
    candidates: CANDIDATES,
    feedback: {
      'ntp-allow-missing': 'chrony on rtr01 never sees the requests (tcpdump on rtr01 shows them arriving, chronyc clients does not count them): the kernel drops them first.',
      'ntp-upstream-unreachable': 'rtr01 itself is synchronized (chronyc tracking: stratum 2, Leap status Normal).',
      'ntp-server-down': 'chronyd is running on rtr01 and listening on UDP 123 (ss -ulnp).',
      'krb-clock-skew': 'Close: the skew is the symptom. But NTP is enabled on ws01; it cannot reach its server (timesyncd logs a timeout).',
      'dns-wrong-record': 'rtr01.corp.lab resolves to 10.0.10.1, the address timesyncd uses.',
      'routing-client': 'ws01 reaches rtr01 (ping, SSH to other servers work); only UDP 123 gets no answer.',
    },
    hints: [
      'On ws01: timedatectl ("System clock synchronized: no" although the NTP service is active), then journalctl -u systemd-timesyncd (as root, or sudo).',
      '"Timed out waiting for reply from 10.0.10.1:123": the request leaves, no reply comes back. On rtr01: is chrony running and synchronized (chronyc tracking)? Does the packet reach it (tcpdump -n -i eth0 udp port 123)? What does the input chain say (nft list ruleset)?',
      'The review removed the NTP rule from the input chain (policy drop). Put "iifname != \\"eth2\\" udp dport 123 accept" back in /etc/nftables.conf and restart nftables; the clients correct their clocks at their next poll.',
    ],
    explanation: {
      rootCause: 'The firewall review removed the rule that accepted NTP (UDP 123) from the internal interfaces in rtr01\'s input chain, whose policy is drop. chrony itself is healthy, but its requests never reach it.',
      manifestation: 'systemd-timesyncd keeps polling rtr01 and times out, so the clients run free: after a few days ws01\'s clock is almost 7 minutes fast and Kerberos refuses it (more than 5 minutes from the KDC). Servers drift too, just not yet far enough to break logins.',
      evidence: 'timedatectl on ws01: "System clock synchronized: no", "NTP service: active"; journalctl -u systemd-timesyncd: "Timed out waiting for reply from 10.0.10.1:123 (rtr01.corp.lab)."; tcpdump on rtr01 shows "NTPv4, Client" packets and no "Server" replies; nft list ruleset has no udp dport 123 rule.',
      prevention: 'When reviewing a ruleset, list the services the host provides (ss -ulnp, ss -tlnp) and keep a rule for each. Monitor "System clock synchronized" on every machine: the clock breaks Kerberos, TLS and log correlation long before anyone notices it is wrong.',
    },
    solution: [{ host: 'rtr01', commands: [printfTo(RTR01_NFT, '/etc/nftables.conf'), 'systemctl restart nftables'] }],
    constraints: [firewallStillRestrictive('rtr01')],
    concepts: ['ntp.sync', 'fw.path'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'ntp-vlan30-allow',
    title: 'Only VLAN 30 is late',
    difficulty: 'intermediate',
    ticket: 'Developers on VLAN 30: "make" warns "Clock skew detected" and our commit times are wrong; dev01 is minutes ahead. Office PCs and servers are fine. Someone tidied up rtr01\'s chrony.conf on Monday (CHG-2251) and says nothing functional changed.',
    briefing: BRIEFING,
    goals: [time('dev01'), time('dev02')],
    terminals: TERMINALS,
    setup(world) {
      writeFile(world.hosts.rtr01, '/etc/chrony/chrony.conf', RTR01_CHRONY_CONF.replace('# Serve time to the internal networks (CHG-0912): office, servers, VLAN 30.\nallow 10.0.10.0/24\nallow 10.0.20.0/24\nallow 10.0.30.0/24\n', '# Serve time to the internal networks: office and servers (CHG-2251).\nallow 10.0.10.0/24\nallow 10.0.20.0/24\n'), world.clock);
      script(world, 'rtr01', ['systemctl restart chrony']);
      drift(world, { dev01: 4 * 60_000 + 12_000, dev02: 2 * 60_000 + 3_000 });
    },
    rootCauses: ['ntp-allow-missing'],
    candidates: CANDIDATES,
    feedback: {
      'ntp-server-firewall': 'rtr01\'s input chain accepts udp dport 123 from every internal interface, and the office PCs are synchronized through it.',
      'ntp-upstream-unreachable': 'rtr01 is synchronized (chronyc tracking) and serves the office and servers.',
      'ntp-server-down': 'chronyd runs and answers ws01 and srv01.',
      'krb-clock-skew': 'NTP is enabled on dev01; its requests get no answer.',
      'dns-wrong-record': 'rtr01.corp.lab resolves correctly on dev01.',
      'routing-client': 'dev01 reaches rtr01 (it is its default gateway); only the NTP replies are missing.',
    },
    hints: [
      'On dev01: timedatectl, and journalctl -u systemd-timesyncd (sudo): "Timed out waiting for reply from 10.0.10.1:123". The office PCs get replies from the same server: what is different about VLAN 30?',
      'On rtr01, follow one request: tcpdump -n -i eth3.30 udp port 123 shows it arriving; the firewall accepts it (it is the same rule as for the office). Does chrony answer? chronyc clients lists who it served and who it dropped.',
      'chronyd serves only the networks named in "allow" lines and silently drops the rest. Add "allow 10.0.30.0/24" back to /etc/chrony/chrony.conf and restart chrony.',
    ],
    explanation: {
      rootCause: 'The "tidy-up" of chrony.conf dropped "allow 10.0.30.0/24". chronyd answers only clients covered by an allow line, and drops everything else without a reply (it does not send an error, to avoid being used for reflection attacks).',
      manifestation: 'dev01 and dev02 time out on every poll and their clocks run free; the office and server networks, still allowed, are fine. From VLAN 30 it looks exactly like a firewall drop.',
      evidence: 'journalctl -u systemd-timesyncd on dev01: "Timed out waiting for reply"; tcpdump on rtr01: requests from 10.0.30.25 arrive, no replies leave; chronyc clients on rtr01: 10.0.30.25 with NTP 0 and a growing Drop count; chrony.conf has no allow line for 10.0.30.0/24.',
      prevention: 'Treat access lists in service configurations like firewall rules: review them per network, and test from every client network after a change (chronyc clients on the server shows who is served and who is dropped).',
    },
    solution: [{ host: 'rtr01', commands: ['echo "allow 10.0.30.0/24" >> /etc/chrony/chrony.conf', 'systemctl restart chrony'] }],
    constraints: [chronyAllowScoped()],
    concepts: ['ntp.sync'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'ntp-upstream-lost',
    title: 'Synchronized to nothing',
    difficulty: 'advanced',
    ticket: 'Monitoring has been raising "clock not synchronized" for every Linux machine since Tuesday\'s maintenance on rtr01 (CHG-2240, "chrony.conf clean-up, new provider address"). There is nothing in timesyncd\'s logs on the clients, and the clocks still look about right.',
    briefing: BRIEFING,
    goals: [time('ws01'), time('srv01')],
    terminals: TERMINALS,
    setup(world) {
      writeFile(world.hosts.rtr01, '/etc/chrony/chrony.conf', RTR01_CHRONY_CONF.replace('server 203.0.113.80 iburst', 'server 203.0.113.8 iburst'), world.clock);
      script(world, 'rtr01', ['systemctl restart chrony']);
      drift(world, { ws01: 2_400, srv01: -1_700 });
    },
    rootCauses: ['ntp-upstream-unreachable'],
    candidates: CANDIDATES,
    feedback: {
      'ntp-server-firewall': 'The clients get replies from rtr01 (timedatectl timesync-status shows a packet from it), so the firewall lets NTP through.',
      'ntp-allow-missing': 'chrony answers the clients (they get replies); it just has nothing good to tell them.',
      'ntp-server-down': 'chronyd is running and answering on UDP 123.',
      'krb-clock-skew': 'The clocks are only seconds off for now; NTP is enabled everywhere. The problem is upstream of the clients.',
      'dns-wrong-record': 'rtr01.corp.lab resolves and answers.',
      'routing-client': 'Clients reach rtr01 and get replies.',
    },
    hints: [
      'No timeout in timesyncd\'s log means replies do arrive. What do they say? timedatectl timesync-status on ws01: look at Leap and Stratum.',
      '"Leap: not synchronized", "Stratum: 16": rtr01 itself is not synchronized, so it tells its clients not to trust it, and they ignore it. On rtr01: chronyc tracking, chronyc sources.',
      'chronyc sources shows "^? 203.0.113.8" with Reach 0: the clean-up mistyped the provider\'s address (203.0.113.80). Fix the server line, systemctl restart chrony. Do not add "local stratum": rtr01 would then serve its own unsynchronized clock as if it were good.',
    ],
    explanation: {
      rootCause: 'The clean-up changed the upstream to 203.0.113.8, an address with no NTP server. rtr01\'s chrony has no usable source, so it is unsynchronized and answers its clients with leap indicator 3 ("alarm") and stratum 16.',
      manifestation: 'Clients receive replies but must reject them; systemd-timesyncd logs that only at debug level, so its journal looks clean while "System clock synchronized: no" spreads to every machine. The clocks start to drift apart slowly.',
      evidence: 'timedatectl timesync-status on a client: Leap: not synchronized, Stratum: 16; chronyc tracking on rtr01: Reference ID 00000000, Leap status: Not synchronised; chronyc sources: "^? 203.0.113.8 … 0" (never reached); journalctl -u chrony: "Can\'t synchronise: no selectable sources".',
      prevention: 'Monitor the time server itself (chronyc tracking: Leap status, stratum), not only the clients, and give it more than one upstream (several server lines, or the provider\'s pool) so one bad address does not leave it with none.',
    },
    solution: [{ host: 'rtr01', commands: ['sed -i \'s/^server 203.0.113.8 iburst$/server 203.0.113.80 iburst/\' /etc/chrony/chrony.conf', 'systemctl restart chrony'] }],
    constraints: [rtr01Upstream()],
    concepts: ['ntp.sync'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'ntp-chronyd-dead',
    title: 'One letter',
    difficulty: 'beginner',
    ticket: 'Every Linux machine has reported "System clock synchronized: no" since Monday, when a colleague added a comment and a new allow line to rtr01\'s chrony.conf and restarted chrony.',
    briefing: BRIEFING,
    goals: [time('ws01'), time('dev01')],
    terminals: TERMINALS,
    setup(world) {
      const conf = readFile(world.hosts.rtr01, '/etc/chrony/chrony.conf')!;
      writeFile(world.hosts.rtr01, '/etc/chrony/chrony.conf', conf.replace('allow 10.0.30.0/24\n', 'allow 10.0.30.0/24\n# lab VLAN 40 (CHG-2260)\nalow 10.0.40.0/24\n'), world.clock);
      script(world, 'rtr01', ['systemctl restart chrony']);
      drift(world, { ws01: 3_100, dev01: 2_200 });
    },
    rootCauses: ['ntp-server-down'],
    candidates: CANDIDATES,
    feedback: {
      'ntp-server-firewall': 'The firewall accepts the requests; rtr01\'s kernel answers them with "port unreachable" because nothing listens on UDP 123.',
      'ntp-allow-missing': 'chrony is not running at all, so no allow line is consulted.',
      'ntp-upstream-unreachable': 'chrony is not running, so it has no upstream state at all.',
      'krb-clock-skew': 'NTP is enabled on the clients; their server is down.',
      'dns-wrong-record': 'rtr01.corp.lab resolves correctly.',
      'routing-client': 'Clients reach rtr01; its kernel answers them.',
    },
    hints: [
      'Start at the server: systemctl status chrony on rtr01.',
      'journalctl -u chrony: "Fatal error : Invalid directive at line N in file /etc/chrony/chrony.conf". chronyd refuses to start with an unknown directive.',
      'Fix the typo (alow → allow) and start chrony: systemctl start chrony. Then chronyc tracking.',
    ],
    explanation: {
      rootCause: 'A typo ("alow") in chrony.conf. chronyd treats an unknown directive as fatal, so after the reboot it did not start and nothing listens on UDP 123.',
      manifestation: 'Clients get ICMP port unreachable for every request and stay unsynchronized; timesyncd logs nothing about it at the default level.',
      evidence: 'systemctl status chrony on rtr01: failed; journalctl -u chrony: "Fatal error : Invalid directive at line 12 in file /etc/chrony/chrony.conf"; ss -ulnp: nothing on 123; tcpdump on rtr01: "udp port 123 unreachable" ICMP replies.',
      prevention: 'Restart a service right after editing its configuration and check that it is active (a typo then fails at once, while you are watching, not at the next reboot). Note that the new allow line would have been useless anyway: VLAN 40 does not exist yet.',
    },
    solution: [{ host: 'rtr01', commands: ['sed -i \'s/^alow /allow /\' /etc/chrony/chrony.conf', 'systemctl start chrony'] }],
    constraints: [chronyAllowScoped()],
    concepts: ['ntp.sync', 'svc.systemd'],
  },
];
