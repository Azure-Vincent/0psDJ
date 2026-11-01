// Integrated Lab 1: Build a Functional Small Office Network. The development
// team moves into its own office network (VLAN 30, 10.0.30.0/24). The build
// server dev01 has an address but no way out, the laptops get no address, the
// name dev01.corp.lab does not exist, and nothing separates the new office
// from the main office. Addressing, the gateway, DHCP through the relay, DNS,
// a router firewall rule and NAT to the Internet all depend on one another.

import { readFile, writeFile } from '../../fs';
import { buildSshLab, DHCPD_CONF } from '../../lab/sshLab';
import { script } from '../../scenarios/engine';
import type { World } from '../../types';
import { NO, OK, probe } from '../engine';
import type { GuidedLab, LabCheck } from '../types';
import { cmdCheck, evidence, gatewayHop, hop } from './common';

const DEV_SUBNET = `# Development VLAN 30: requests arrive through the relay agent on rtr01 (giaddr 10.0.30.1)
subnet 10.0.30.0 netmask 255.255.255.0 {
    range 10.0.30.100 10.0.30.150;
    option routers 10.0.30.1;
}
`;

export function buildIlab1World(): World {
  const w = buildSshLab();
  const t = w.clock;
  // dev01 was configured in a hurry: address yes, gateway no.
  const dev = w.hosts.dev01;
  writeFile(dev, '/etc/network/interfaces', (readFile(dev, '/etc/network/interfaces') ?? '').replace('    gateway 10.0.30.1\n', ''), t);
  // The DHCP server has no scope for the new office yet.
  writeFile(w.hosts.ns1, '/etc/dhcp/dhcpd.conf', DHCPD_CONF.replace(DEV_SUBNET, ''), t);
  // The zone has no record for the build server.
  const ns1 = w.hosts.ns1;
  writeFile(ns1, '/etc/bind/db.corp.lab', (readFile(ns1, '/etc/bind/db.corp.lab') ?? '').replace('dev01   IN A    10.0.30.25\n', ''), t, { group: 'bind' });
  script(w, 'ns1', ['systemctl restart isc-dhcp-server', 'rndc reload']);
  script(w, 'dev02', ['dhclient -r eth0']);
  script(w, 'dev01', ['systemctl restart networking']);
  w.clock += 5 * 60_000;
  return w;
}

// ---------------------------------------------------------------- checks

const gatewaySet: LabCheck = {
  id: 'dev01-gateway', description: 'dev01 has a default route via 10.0.30.1 (in /etc/network/interfaces and in the running routing table) and reaches srv01 (10.0.20.10)',
  check(w) {
    const file = readFile(w.hosts.dev01, '/etc/network/interfaces') ?? '';
    if (!/^\s*gateway\s+10\.0\.30\.1\s*$/m.test(file)) return NO('/etc/network/interfaces on dev01 has no "gateway 10.0.30.1" line: a route added with "ip route add" is gone after the next reboot.');
    const r = probe(w, 'dev01', 'root', 'ip route');
    if (!/^default via 10\.0\.30\.1 dev eth0/m.test(r.output)) return NO(`The running routing table has no default route via 10.0.30.1: apply the file (systemctl restart networking, or ifdown/ifup eth0).\n${evidence('dev01', 'root', 'ip route', r.output, r.code)}`);
    const p = probe(w, 'dev01', 'root', 'ping -c 1 -W 2 10.0.20.10');
    if (p.code !== 0) return NO(`dev01 still cannot reach srv01.\n${evidence('dev01', 'root', 'ping -c 1 -W 2 10.0.20.10', p.output, p.code)}`);
    return OK('dev01 routes through rtr01 and reaches the server network.');
  },
};

const dhcpScope: LabCheck = {
  id: 'dhcp-scope', description: 'ns1 serves VLAN 30: dhcpd.conf has a subnet 10.0.30.0/24 with a range and "option routers 10.0.30.1", and isc-dhcp-server runs with it',
  check(w) {
    const conf = readFile(w.hosts.ns1, '/etc/dhcp/dhcpd.conf') ?? '';
    const block = /subnet\s+10\.0\.30\.0\s+netmask\s+255\.255\.255\.0\s*\{([^}]*)\}/.exec(conf)?.[1];
    if (!block) return NO('/etc/dhcp/dhcpd.conf on ns1 has no "subnet 10.0.30.0 netmask 255.255.255.0 { … }" declaration: the server ignores relayed requests from a network it has no subnet for ("unknown network segment").');
    if (!/range\s+10\.0\.30\.\d+\s+10\.0\.30\.\d+\s*;/.test(block)) return NO('The VLAN 30 subnet has no "range" inside 10.0.30.0/24: there is nothing to hand out.');
    if (!/option\s+routers\s+10\.0\.30\.1\s*;/.test(block)) return NO('The VLAN 30 subnet does not hand out "option routers 10.0.30.1": clients would get an address but no way out of their network.');
    if (w.hosts.ns1.services.dhcpd?.state !== 'active') return NO('isc-dhcp-server is not running on ns1 (dhcpd -t, then systemctl restart isc-dhcp-server; journalctl -u isc-dhcp-server).');
    return OK('The scope is configured and served.');
  },
};

const dev02Lease: LabCheck = {
  id: 'dev02-lease', description: 'dev02 holds a lease from the VLAN 30 range with the default route via 10.0.30.1 and ns1 as DNS server',
  check(w) {
    const a = probe(w, 'dev02', 'root', 'ip -4 -br addr show eth0');
    if (!/10\.0\.30\.(1[0-4]\d|150)\//.test(a.output)) return NO(`dev02 has no address from 10.0.30.100–150 yet: once the scope is served, ask for one (dhclient eth0).\n${evidence('dev02', 'root', 'ip -4 -br addr show eth0', a.output, a.code)}`);
    const r = probe(w, 'dev02', 'root', 'ip route');
    if (!/^default via 10\.0\.30\.1 /m.test(r.output)) return NO(`dev02's lease came without the right default route.\n${evidence('dev02', 'root', 'ip route', r.output, r.code)}`);
    const dns = readFile(w.hosts.dev02, '/etc/resolv.conf') ?? '';
    if (!/nameserver\s+(10\.0\.10\.53|2001:db8:10::53)/.test(dns)) return NO('dev02\'s /etc/resolv.conf does not name ns1: the lease should carry the DNS server (option domain-name-servers).');
    return OK('dev02 got its address, gateway and DNS server by DHCP through the relay.');
  },
};

const zoneRecord: LabCheck = {
  id: 'dns-dev01', description: 'dev01.corp.lab resolves to 10.0.30.25 for every client (record added, serial increased, zone reloaded)',
  check(w) {
    const z = readFile(w.hosts.ns1, '/etc/bind/db.corp.lab') ?? '';
    if (!/^dev01\s+(\d+\s+)?(IN\s+)?A\s+10\.0\.30\.25\s*$/m.test(z)) return NO('The zone file /etc/bind/db.corp.lab has no "dev01 IN A 10.0.30.25" record.');
    const serial = Number(/(\d+)\s*;\s*serial/i.exec(z)?.[1] ?? 0);
    if (serial <= 2026101901) return NO(`The serial is still ${serial}: increase it whenever the zone changes.`);
    const r = probe(w, 'ws01', 'alice', 'getent hosts dev01.corp.lab');
    if (!/^10\.0\.30\.25\s/m.test(r.output)) return NO(`ws01 cannot resolve dev01.corp.lab yet: check the file with named-checkzone, then rndc reload.\n${evidence('ws01', 'alice', 'getent hosts dev01.corp.lab', r.output, r.code)}`);
    return OK('dev01.corp.lab resolves.');
  },
};

const officeIsolated: LabCheck = {
  id: 'segmentation', description: 'rtr01 keeps VLAN 30 out of the office VLAN 10 (except DNS on ns1), persistently; the office can still reach VLAN 30',
  check(w) {
    const nft = readFile(w.hosts.rtr01, '/etc/nftables.conf') ?? '';
    const fwd = /chain forward \{([\s\S]*?)\n\t\}/.exec(nft)?.[1] ?? '';
    if (!/eth3\.30/.test(fwd)) return NO('/etc/nftables.conf on rtr01 has no forward rule about VLAN 30 (iifname "eth3.30"): a rule added only with "nft add rule" disappears at the next reboot.');
    const ping = probe(w, 'dev02', 'root', 'ping -c 1 -W 2 10.0.10.25');
    if (ping.code === 0) return NO(`dev02 still reaches ws01 in the office VLAN.\n${evidence('dev02', 'root', 'ping -c 1 -W 2 10.0.10.25', ping.output, ping.code)}`);
    const dns = probe(w, 'dev02', 'root', 'getent hosts srv01.corp.lab');
    if (dns.code !== 0) return NO(`The rule also blocks DNS: ns1 (10.0.10.53, and 2001:db8:10::53 over IPv6) is in the office VLAN. Allow UDP and TCP 53 to ns1 before the drop, for both address families.\n${evidence('dev02', 'root', 'getent hosts srv01.corp.lab', dns.output, dns.code)}`);
    const back = probe(w, 'ws01', 'alice', 'ping -c 1 -W 2 10.0.30.25');
    if (back.code !== 0) return NO(`The office can no longer reach dev01: replies from VLAN 30 must be allowed (ct state established,related accept before the drop).\n${evidence('ws01', 'alice', 'ping -c 1 -W 2 10.0.30.25', back.output, back.code)}`);
    return OK('VLAN 30 reaches DNS on ns1 but not the office machines; the office reaches VLAN 30.');
  },
};

const endToEnd: LabCheck[] = [
  cmdCheck('web', 'From dev02, the intranet (http://www.corp.lab) answers 200', 'dev02', 'root', 'curl -sI -m 5 http://www.corp.lab', (o) => (/^HTTP\/1\.1 200/.test(o) ? null : 'dev02 does not get the intranet page.'), 'Name resolution, routing to the server VLAN and the web server work together.'),
  cmdCheck('internet', 'From dev02, the Internet (ext01, 203.0.113.80) answers through NAT on rtr01', 'dev02', 'root', 'curl -sI -m 5 http://203.0.113.80', (o) => (/^HTTP\/1\.1 200/.test(o) ? null : 'dev02 does not reach the Internet.'), 'Outbound NAT on rtr01 hides VLAN 30 behind 203.0.113.2.'),
  cmdCheck('dev01-by-name', 'From ws01, dev01 is reachable by name', 'ws01', 'alice', 'ping -c 1 -W 2 dev01.corp.lab', (_o, c) => (c === 0 ? null : 'ws01 cannot reach dev01.corp.lab.'), 'DNS and routing from the office to VLAN 30 work.'),
];

// ---------------------------------------------------------------- the lab

const NFT_FORWARD = `	chain forward {
		type filter hook forward priority filter; policy accept;
		ct state established,related accept
		# VLAN 30 (development): DNS on ns1, nothing else in the office VLAN (CHG-3001)
		iifname "eth3.30" ip daddr 10.0.10.53 udp dport 53 accept
		iifname "eth3.30" ip daddr 10.0.10.53 tcp dport 53 accept
		# the same over IPv6: DHCPv6 gives the laptops the IPv6 address of ns1 as DNS server
		iifname "eth3.30" ip6 daddr 2001:db8:10::53 udp dport 53 accept
		iifname "eth3.30" ip6 daddr 2001:db8:10::53 tcp dport 53 accept
		iifname "eth3.30" oifname "eth0" drop
	}`;

export const ILAB1: GuidedLab = {
  id: 'ilab1',
  title: 'Integrated Lab 1: Build a Functional Small Office Network',
  level: 'beginner',
  duration: '45–75 min',
  summary: 'Bring a new office network to life: a static server with its default gateway, DHCP for the laptops through the router\'s relay, a DNS record, a router rule that keeps the new office out of the old one without breaking DNS, and Internet access through NAT. Then find out why the laptops lose the network after a DHCP change.',
  brief: `The development team moves into its own office network, **VLAN 30 (10.0.30.0/24)**, behind the router **rtr01** (10.0.30.1). Make it work (change CHG-3001):

- **dev01**, the team's build server, has the static address 10.0.30.25 but cannot reach anything outside its own network.
- The laptops (here **dev02**) use DHCP. The DHCP server is **ns1** in the main office (10.0.10.53); rtr01 already relays requests from VLAN 30 to it, but ns1 has no address pool for VLAN 30.
- Colleagues must reach the build server by name: **dev01.corp.lab**.
- Security asks that VLAN 30 cannot reach the machines of the main office (VLAN 10, 10.0.10.0/24). The main office may still reach VLAN 30.
- Everybody needs the intranet (www.corp.lab on srv01) and the Internet.`,
  objectives: [
    'Read an addressing plan: network, prefix, gateway, DHCP range, DNS server.',
    'Configure a static address with its default gateway, persistently.',
    'Serve a remote network by DHCP through a relay agent.',
    'Publish a name in a DNS zone (serial, check, reload).',
    'Write a router firewall rule without cutting the services it depends on (DNS).',
    'Verify end to end, then diagnose a DHCP problem from its symptoms.',
  ],
  prerequisites: [
    { label: 'IP networking', link: 'lesson/ipnet/what' },
    { label: 'DHCP', link: 'lesson/dhcp/what' },
    { label: 'TCP, UDP and DNS', link: 'lesson/transport/what' },
    { label: 'Host firewalls (nftables)', link: 'lesson/nftables/what' },
  ],
  setupNote: 'The lab is the standard network: **VLAN 30** behind rtr01\'s sub-interface eth3.30, with dev01 (static) and dev02 (DHCP). ns1 is DNS and DHCP server for every network; rtr01 routes, relays DHCP and does NAT to the Internet.',
  terminals: [
    { hostId: 'dev01', user: 'root', label: 'dev01 (build server)', banner: 'dev01 console (root). Try: ip -br addr, ip route, cat /etc/network/interfaces, ping -c 1 10.0.30.1.' },
    { hostId: 'dev02', user: 'root', label: 'dev02 (laptop)', banner: 'dev02 console (root): a DHCP client. Try: ip -br addr, dhclient -v eth0, cat /etc/resolv.conf, journalctl -t dhclient.' },
    { hostId: 'ns1', user: 'root', label: 'ns1 (DNS + DHCP)', banner: 'ns1 (root): BIND (/etc/bind/db.corp.lab) and isc-dhcp-server (/etc/dhcp/dhcpd.conf). Try: dhcpd -t, journalctl -u isc-dhcp-server, named-checkzone corp.lab /etc/bind/db.corp.lab.' },
    { hostId: 'rtr01', user: 'root', label: 'rtr01 (router)', banner: 'rtr01 (root): routing, DHCP relay, NAT, firewall. Try: ip -br addr, nft list ruleset, cat /etc/default/isc-dhcp-relay.' },
    { hostId: 'ws01', user: 'alice', label: 'ws01 (main office)', banner: 'ws01 (alice), a workstation in the main office VLAN 10. Try: getent hosts dev01.corp.lab, ping -c 1 10.0.30.25.' },
  ],
  build: buildIlab1World,
  steps: [
    {
      id: 'gateway', title: 'Give dev01 its default gateway',
      objective: 'dev01 reaches networks outside 10.0.30.0/24 through rtr01 (10.0.30.1), and keeps doing so after a reboot.',
      background: 'An address and a prefix only let a machine talk to its **own network**. Everything else goes to the **default gateway**, the router on that network. Without one, the kernel has no route: `ping 10.0.20.10` fails at once with "Network is unreachable".\n\nOn Debian with ifupdown the configuration is **/etc/network/interfaces** (other distributions use NetworkManager, Netplan or systemd-networkd: different files, same idea). `ip route add` changes only the running table and is gone after a reboot.',
      tasks: [
        'Look first: `ip -br addr`, `ip route` and `cat /etc/network/interfaces` on dev01. What is missing?',
        'Add `gateway 10.0.30.1` to the eth0 stanza in /etc/network/interfaces.',
        'Apply it: `systemctl restart networking`, then `ip route` and `ping -c 1 10.0.20.10`.',
      ],
      hints: ['"connect: Network is unreachable" means the kernel has no route at all, not that a packet was lost.', 'The router\'s address on VLAN 30 is the first address of the network: 10.0.30.1.'],
      checks: [gatewaySet],
      solution: [{ host: 'dev01', user: 'root', commands: ["sed -i 's|^    address 10.0.30.25/24$|    address 10.0.30.25/24\\n    gateway 10.0.30.1|' /etc/network/interfaces", 'systemctl restart networking', 'ip route'] }],
      commands: [
        { host: 'dev01', command: 'ip route', what: 'Shows the kernel\'s routing table: one line per network it knows how to reach, plus "default via …" for everything else.', why: 'To see whether a default route exists before changing anything.', where: 'Runtime state (built from /etc/network/interfaces at boot).', success: '"default via 10.0.30.1 dev eth0" and "10.0.30.0/24 dev eth0 proto kernel scope link src 10.0.30.25".', verify: 'ping -c 1 10.0.20.10 answers.' },
        { host: 'dev01', command: 'systemctl restart networking', what: 'Re-applies /etc/network/interfaces (ifdown/ifup of the configured interfaces).', why: 'Edits to the file change nothing until they are applied.', where: '/etc/network/interfaces (ifupdown, Debian).', success: 'No output; the command returns 0.', verify: 'A silent restart is not proof: check ip route and ping. A typo can leave the interface without an address.' },
      ],
      learn: [{ label: 'Routing and gateways', link: 'lesson/ipnet/internals' }, { label: 'ip', link: 'reference?id=ip' }, { label: '/etc/network/interfaces', link: 'reference?id=file:etc-network-interfaces' }],
      concepts: ['net.routing', 'net.cidr'],
    },
    {
      id: 'dhcp', title: 'An address pool for the laptops',
      objective: 'ns1 hands out addresses 10.0.30.100–150 to VLAN 30 with the gateway 10.0.30.1, and dev02 gets a lease.',
      background: 'DHCP clients broadcast for an address, and broadcasts do not cross routers. rtr01 runs a **relay agent**: it receives the broadcast on VLAN 30 and forwards it as unicast to ns1, adding its own VLAN 30 address (**giaddr 10.0.30.1**). ns1 picks the pool from the **subnet declaration that contains the giaddr**. Without one it logs "unknown network segment" and answers nothing.\n\nThe pool also carries **options**: `routers` becomes the client\'s default gateway; `domain-name-servers` (set globally here) its DNS server. A wrong option gives clients an address that "works" only on their own network.',
      tasks: [
        'On dev02: `dhclient -v eth0`. No answer. On ns1: `journalctl -u isc-dhcp-server -n 5`: what does the server say about the request?',
        'Add to /etc/dhcp/dhcpd.conf on ns1: `subnet 10.0.30.0 netmask 255.255.255.0 { range 10.0.30.100 10.0.30.150; option routers 10.0.30.1; }`',
        'Check the syntax with `dhcpd -t`, then `systemctl restart isc-dhcp-server`.',
        'On dev02: `dhclient -v eth0`, then `ip -br addr`, `ip route` and `cat /etc/resolv.conf`.',
      ],
      hints: ['"DHCPDISCOVER from … via 10.0.30.1: unknown network segment": the server got the relayed request but has no subnet for 10.0.30.1.', 'Keep the global "option domain-name-servers 10.0.10.53;": the subnet inherits it.'],
      checks: [dhcpScope, dev02Lease],
      solution: [
        { host: 'ns1', user: 'root', commands: [`printf '\\n${DEV_SUBNET.replace(/\n/g, '\\n')}' >> /etc/dhcp/dhcpd.conf`, 'dhcpd -t', 'systemctl restart isc-dhcp-server'] },
        { host: 'dev02', user: 'root', commands: ['dhclient -v eth0', 'ip -br addr'] },
      ],
      commands: [
        { host: 'ns1', command: 'dhcpd -t', what: 'Parses /etc/dhcp/dhcpd.conf without starting the server.', why: 'A syntax error makes isc-dhcp-server fail to start, and then nobody gets an address.', where: '/etc/dhcp/dhcpd.conf; the interfaces to serve are in /etc/default/isc-dhcp-server.', success: 'Only the version banner, exit status 0.', verify: 'systemctl status isc-dhcp-server shows active (running).' },
        { host: 'dev02', command: 'dhclient -v eth0', what: 'Runs the DHCP exchange (DISCOVER, OFFER, REQUEST, ACK) and configures the address, route and DNS server from the lease.', why: 'A client asks again only when its lease expires or it is told to.', where: 'Leases: /var/lib/dhcp/dhclient.leases; DNS: /etc/resolv.conf.', success: '"DHCPACK of 10.0.30.1xx from 10.0.10.53" and "bound to 10.0.30.1xx".', verify: 'ip route shows "default via 10.0.30.1"; cat /etc/resolv.conf names 10.0.10.53.' },
      ],
      learn: [{ label: 'DHCP relay', link: 'lesson/dhcp/internals' }, { label: 'Relay procedure', link: 'reference?id=proc:dhcp-relay' }],
      concepts: ['net.dhcp'],
    },
    {
      id: 'dns', title: 'A name for the build server',
      objective: 'dev01.corp.lab resolves to 10.0.30.25 for every client.',
      background: 'People and scripts use names. ns1 is authoritative for **corp.lab**: its zone file holds the records. After an edit, the **serial** must increase (secondaries and caches compare it), the file should be checked (`named-checkzone`), and named must **reload** it: until then it serves the old version.',
      tasks: [
        'Back up the zone: `cp -a /etc/bind/db.corp.lab /root/db.corp.lab.bak`.',
        'Add `dev01   IN A    10.0.30.25` and increase the serial (2026101901 → 2026110101).',
        '`named-checkzone corp.lab /etc/bind/db.corp.lab`, then `rndc reload`.',
        'From ws01 and dev02: `getent hosts dev01.corp.lab`.',
      ],
      hints: ['getent asks the resolver configured in /etc/resolv.conf, like applications do; dig asks DNS directly.', 'If named-checkzone complains, nothing is reloaded until you fix it; the backup lets you roll back.'],
      checks: [zoneRecord],
      solution: [{ host: 'ns1', user: 'root', commands: ['cp -a /etc/bind/db.corp.lab /root/db.corp.lab.bak', "sed -i 's/2026101901 ; serial/2026110101 ; serial/' /etc/bind/db.corp.lab", "echo 'dev01   IN A    10.0.30.25' >> /etc/bind/db.corp.lab", 'named-checkzone corp.lab /etc/bind/db.corp.lab', 'rndc reload'] }],
      commands: [
        { host: 'ns1', command: 'named-checkzone corp.lab /etc/bind/db.corp.lab', what: 'Loads the zone file the way named would and reports errors.', why: 'A broken zone makes named answer SERVFAIL for every corp.lab name: one typo would take down every service that uses names.', where: '/etc/bind/db.corp.lab (declared in /etc/bind/named.conf.local).', success: '"zone corp.lab/IN: loaded serial 2026110101" and "OK".', verify: 'After rndc reload, dig @10.0.10.53 dev01.corp.lab or getent hosts dev01.corp.lab.' },
        { host: 'ns1', command: 'rndc reload', what: 'Tells the running named to re-read its zone files.', why: 'named keeps zones in memory; edits are invisible until a reload.', success: '"server reload successful".', verify: 'The new name resolves from a client; a zone with errors is NOT loaded (journalctl -u named says why).' },
      ],
      learn: [{ label: 'DNS zones', link: 'lesson/transport/internals' }, { label: 'Zone change procedure', link: 'reference?id=proc:bind-zone-change' }, { label: 'named-checkzone', link: 'reference?id=named-checkzone' }],
      concepts: ['dns.zone', 'dns.resolution'],
    },
    {
      id: 'segment', title: 'Keep VLAN 30 out of the main office',
      objective: 'rtr01 forwards nothing from VLAN 30 into VLAN 10 except DNS to ns1; the main office still reaches VLAN 30; the rules survive a reboot.',
      background: 'rtr01\'s **forward** chain decides what may cross between its networks. A rule that drops VLAN 30 → VLAN 10 is easy, but the new office **depends on ns1 for DNS**, and ns1 is in VLAN 10. Rules are evaluated top to bottom: the exceptions (DNS to ns1) must come before the drop. VLAN 30 is **dual-stack**: DHCPv6 gives the laptops ns1\'s IPv6 address (2001:db8:10::53) as DNS server too, and the `inet` table filters both families, so the exception is needed for IPv4 and IPv6.\n\nThe main office must still reach VLAN 30: its packets go 10 → 30, which is allowed, but the **replies** go 30 → 10. `ct state established,related accept` lets replies of allowed connections through.',
      tasks: [
        'Look at the forward chain: `nft list chain inet filter forward`.',
        'In /etc/nftables.conf, in the forward chain: `ct state established,related accept`, then accept UDP and TCP 53 from eth3.30 to 10.0.10.53 and to 2001:db8:10::53 (`ip6 daddr`), then `iifname "eth3.30" oifname "eth0" drop`.',
        'Check and load: `nft -c -f /etc/nftables.conf`, `nft -f /etc/nftables.conf`.',
        'Test: from dev02, `ping -c 1 10.0.10.25` fails but `getent hosts srv01.corp.lab` works; from ws01, `ping -c 1 10.0.30.25` works.',
      ],
      hints: ['If names stopped working on dev02, your drop also hits DNS: ns1 lives in VLAN 10. cat /etc/resolv.conf on dev02 shows which address(es) it asks, IPv4 and IPv6.', 'If ws01 cannot reach dev01 any more, the replies are dropped: add the established rule first.'],
      checks: [officeIsolated],
      solution: [{ host: 'rtr01', user: 'root', commands: ["sed -i '/^\\tchain forward {$/,/^\\t}$/d' /etc/nftables.conf", `sed -i 's|^\\tchain output {$|${NFT_FORWARD.replace(/\n/g, '\\n').replace(/\|/g, '\\|')}\\n\\tchain output {|' /etc/nftables.conf`, 'nft -c -f /etc/nftables.conf', 'nft -f /etc/nftables.conf'] }],
      commands: [
        { host: 'rtr01', command: 'nft -c -f /etc/nftables.conf', what: 'Checks the file without loading it.', why: 'On a router a broken ruleset can cut every network at once (including your own session).', where: '/etc/nftables.conf (loaded at boot by nftables.service).', success: 'No output, exit status 0.', verify: 'nft -f loads it; nft list chain inet filter forward shows the rules in order.' },
      ],
      learn: [{ label: 'Firewall chains and state', link: 'lesson/nftables/internals' }, { label: 'nft', link: 'reference?id=nft' }, { label: 'Safe reload', link: 'reference?id=proc:nft-safe-reload' }],
      concepts: ['fw.stateful', 'fw.path'],
    },
    {
      id: 'verify', title: 'Verify end to end, and after a reboot', stage: 'verify',
      objective: 'From the new office the intranet and the Internet work, the main office reaches dev01 by name, and all of it still works after every machine restarts.',
      background: 'A command that printed no error is not a working service. Verify the way users use the network: by name, across the router, to the real service. Then reboot everything: anything that only lived in the running state (an `ip route add`, an `nft add rule`, a lease that was never configured) is gone.',
      tasks: [
        'From dev02: `curl -sI http://www.corp.lab` and `curl -sI http://203.0.113.80` (ext01 on the Internet).',
        'From ws01: `ping -c 1 dev01.corp.lab`.',
        'Use the dependency map (stage 2) to see each hop of the paths.',
        'Run the check: it reboots every machine on a copy of the lab and re-runs every check.',
      ],
      hints: ['If the Internet fails but the intranet works, look at NAT on rtr01 (nft list table ip nat).'],
      checks: endToEnd,
      solution: [],
      learn: [{ label: 'Network configuration and recovery', link: 'lesson/netops/what' }],
      concepts: ['net.routing', 'net.nat'],
      afterReboot: true,
    },
  ],
  integrated: {
    number: 1,
    scenario: {
      organisation: 'corp.lab, a 40-person company: a main office (VLAN 10), a server room (VLAN 20) and, from today, a development office (VLAN 30).',
      situation: 'The developers moved in this morning. The build server has an address but reaches nothing; the laptops get no address; nobody can find the build server by name.',
      goal: 'A working office network: addressing, gateway, DHCP, DNS, a firewall rule between the offices, and Internet access.',
      whyItMatters: 'Every other service (logins, web, mail, backups) assumes that this layer works. Most "the application is down" calls in a small office end here: a gateway, a DHCP option, a DNS record.',
    },
    technologies: ['IPv4 addressing and subnetting', 'Default gateway and routing', 'DHCP with a relay agent', 'DNS (BIND zone)', 'Router firewall (nftables forward chain)', 'NAT to the Internet'],
    systems: [
      { host: 'dev01', role: 'Build server, static 10.0.30.25/24' },
      { host: 'dev02', role: 'Laptop, DHCP client in VLAN 30' },
      { host: 'rtr01', role: 'Router: 10.0.10.1 (office), 10.0.20.1 (servers), 10.0.30.1 (development), NAT to 203.0.113.2; DHCP relay' },
      { host: 'ns1', role: 'DNS for corp.lab and DHCP server for every network (10.0.10.53)' },
      { host: 'srv01', role: 'Intranet web server www.corp.lab (10.0.20.10)' },
      { host: 'ext01', role: 'A server on the Internet (203.0.113.80)' },
    ],
    startingState: [
      'dev01: address 10.0.30.25/24 configured, no gateway line in /etc/network/interfaces.',
      'ns1: dhcpd.conf has subnets for VLAN 10 only; dev02 has released its address.',
      'ns1: the zone corp.lab has no record for dev01 (serial 2026101901).',
      'rtr01: routes between all networks, relays DHCP from VLAN 30 to ns1, NAT to the Internet; the forward chain allows everything.',
    ],
    tools: [
      { command: 'ip -br addr / ip route', platform: 'Linux', use: 'Addresses and routes as the kernel uses them', refId: 'ip' },
      { command: 'ping, curl -sI', platform: 'Linux', use: 'Reachability and the real service', refId: 'ping-linux' },
      { command: 'dhclient -v eth0', platform: 'Linux', use: 'Ask for a lease and watch the exchange', refId: 'proc:dhcp-renew' },
      { command: 'dhcpd -t, journalctl -u isc-dhcp-server', platform: 'Linux', use: 'Check the server\'s configuration and what it did with a request', refId: 'journalctl' },
      { command: 'named-checkzone, rndc reload, getent hosts, dig', platform: 'Linux', use: 'Change and verify DNS', refId: 'named-checkzone' },
      { command: 'nft list ruleset, nft -c -f, nft -f', platform: 'Linux', use: 'Router firewall', refId: 'nft' },
      { command: 'ipconfig /all, Test-NetConnection', platform: 'Windows', use: 'The same checks on a Windows client', refId: 'ipconfig' },
      { command: 'show ip interface brief, show ip route', platform: 'Cisco IOS', use: 'The same questions on a Cisco router (not simulated here)', refId: 'ios-show-ip-route' },
    ],
    dependencies: {
      explanation: `A laptop opening the intranet needs every layer below it, in order:

1. **An address on its network** (from DHCP: which needs the relay on rtr01 and a matching subnet on ns1).
2. **A default gateway** (option routers in the lease, or the gateway line for a static server).
3. **A DNS server** that knows the name (option domain-name-servers → ns1, which is in another VLAN: so routing and the router's firewall must let DNS through).
4. **A route to the server's network** on the router, and a firewall that allows it.
5. **The service itself** (nginx on srv01). For the Internet: **NAT** on rtr01 instead of 4–5.

When something fails, find the first layer that does not work: everything above it fails too, whatever its own configuration.`,
      paths: [
        {
          id: 'dev02-web', label: 'dev02 (laptop) opens http://www.corp.lab',
          nodes: [
            hop('address', 'dev02 has an address', 'DHCP through the relay: an address from 10.0.30.100–150.', 'dev02', 'root', 'ip -4 -br addr show eth0', (o) => /10\.0\.30\.\d+\//.test(o)),
            gatewayHop('dev02', 'root'),
            hop('dns', 'Name resolves', 'ns1 (10.0.10.53 or 2001:db8:10::53), across the router, answers for www.corp.lab.', 'dev02', 'root', 'getent hosts www.corp.lab', (o, c) => c === 0 && /www\.corp\.lab/.test(o)),
            hop('route', 'Server network reachable', 'rtr01 forwards VLAN 30 → VLAN 20.', 'dev02', 'root', 'ping -c 1 -W 2 10.0.20.10', (_o, c) => c === 0),
            hop('service', 'Web server answers', 'nginx on srv01 serves the page.', 'dev02', 'root', 'curl -sI -m 5 http://www.corp.lab', (o) => /^HTTP\/1\.1 200/.test(o)),
          ],
        },
        {
          id: 'dev01-internet', label: 'dev01 (build server) downloads from the Internet',
          nodes: [
            hop('address', 'dev01 has its address', 'Static 10.0.30.25/24 from /etc/network/interfaces.', 'dev01', 'root', 'ip -4 -br addr show eth0', (o) => /10\.0\.30\.25\/24/.test(o)),
            gatewayHop('dev01', 'root'),
            hop('nat', 'Internet server answers through NAT', 'rtr01 masquerades VLAN 30 behind 203.0.113.2.', 'dev01', 'root', 'curl -sI -m 5 http://203.0.113.80', (o) => /^HTTP\/1\.1 200/.test(o)),
          ],
        },
        {
          id: 'ws01-dev01', label: 'ws01 (main office) reaches dev01 by name',
          nodes: [
            hop('dns', 'dev01.corp.lab resolves', 'The A record in the corp.lab zone on ns1.', 'ws01', 'alice', 'getent hosts dev01.corp.lab', (o) => /^10\.0\.30\.25\s/m.test(o)),
            hop('reach', 'dev01 answers', 'Routing 10 → 30, and replies 30 → 10 allowed by the router.', 'ws01', 'alice', 'ping -c 1 -W 2 dev01.corp.lab', (_o, c) => c === 0),
          ],
        },
      ],
    },
    mistakes: [
      'Adding the route with `ip route add default via …` only: it works until the next reboot.',
      'Writing the DHCP subnet for the wrong network, or without `option routers`: clients get an address but no way out.',
      'Editing the zone without increasing the serial or without `rndc reload`.',
      'A drop rule for VLAN 30 → VLAN 10 placed before the DNS exception, or without the established rule: DNS or replies break.',
      'Declaring success because a command printed nothing: always test the way users use the service.',
    ],
    verification: 'Each step is checked against the running machines (routing tables, leases, the zone as named serves it, packets through the router), and the final check reboots every machine on a copy of the lab and runs every check again. The incident in stage 5 is repaired when the laptop gets a working lease again, including after a reboot.',
    fault: {
      title: 'The laptops lose the network after the DHCP clean-up',
      report: 'Developers (Monday 09:10): "Since the DHCP clean-up on Friday (CHG-3014: \'tidy up the scopes\') our laptops can reach the build server dev01, but nothing else: no intranet, no Internet, not even the printer in the main office. dev01 itself is fine."',
      inject(w) {
        const ns1 = w.hosts.ns1;
        writeFile(ns1, '/etc/dhcp/dhcpd.conf', (readFile(ns1, '/etc/dhcp/dhcpd.conf') ?? '').replace(/(subnet\s+10\.0\.30\.0\s+netmask\s+255\.255\.255\.0\s*\{[^}]*?)option routers 10\.0\.30\.1;/, '$1option routers 10.0.30.254;'), w.clock);
        script(w, 'ns1', ['systemctl restart isc-dhcp-server']);
        script(w, 'dev02', ['dhclient -r eth0', 'dhclient eth0']);
      },
      rootCauses: ['dhcp-bad-option'],
      candidates: ['dhcp-bad-option', 'routing-client', 'client-netmask', 'dns-client-config', 'dhcp-server-down', 'router-forwarding-disabled', 'fw-router-forward', 'dhcp-relay-wrong-server'],
      hints: [
        'Compare dev01 (works) and dev02 (does not): `ip route` on both. What differs?',
        'Where does dev02 get its default route from? `journalctl -t dhclient` and /var/lib/dhcp/dhclient.leases show the options it received.',
        'Look at the VLAN 30 subnet in /etc/dhcp/dhcpd.conf on ns1. Then: fix it, restart isc-dhcp-server, and renew the lease on dev02 (dhclient -r eth0; dhclient eth0).',
      ],
      checks: [
        cmdCheck('lease-gateway', 'dev02\'s lease has the default route via 10.0.30.1', 'dev02', 'root', 'ip route', (o) => (/^default via 10\.0\.30\.1 /m.test(o) ? null : 'dev02 still has the wrong (or no) default route: fix the server, then renew the lease.'), 'The lease carries the right gateway.'),
        cmdCheck('lease-web', 'dev02 reaches the intranet again', 'dev02', 'root', 'curl -sI -m 5 http://www.corp.lab', (o) => (/^HTTP\/1\.1 200/.test(o) ? null : 'The intranet is still unreachable from dev02.'), 'The laptops work again.'),
      ],
      solution: [
        { host: 'ns1', user: 'root', commands: ["sed -i 's/option routers 10.0.30.254;/option routers 10.0.30.1;/' /etc/dhcp/dhcpd.conf", 'dhcpd -t', 'systemctl restart isc-dhcp-server'] },
        { host: 'dev02', user: 'root', commands: ['dhclient -r eth0', 'dhclient eth0'] },
      ],
      explanation: {
        rootCause: 'The clean-up changed "option routers" of the VLAN 30 scope to 10.0.30.254, an address nobody has. Laptops that renewed got a valid address and a gateway that does not exist: they reach their own network (dev01) and nothing else.',
        evidence: 'dev02: "default via 10.0.30.254"; ping 10.0.30.254 fails (no ARP answer); dev01 (static, gateway 10.0.30.1) works; dhcpd.conf on ns1 shows the wrong option.',
        lesson: 'Compare a working and a broken client: what differs (here the gateway) points at its source (the DHCP option). Fixing the server is not enough: clients keep the bad lease until they renew.',
      },
      concepts: ['net.dhcp', 'net.routing'],
    },
    review: [
      { id: 'q1', question: 'dev02 has an address in 10.0.30.0/24 but cannot reach anything outside it; dev01 (static) in the same network works. Which is the most likely cause?', choices: ['The DHCP lease gave dev02 a wrong or missing default gateway', 'rtr01 does not forward between networks', 'ns1\'s DNS zone has an error', 'srv01\'s web server is stopped'], answer: 0, explanation: 'Forwarding, DNS and the web server would affect dev01 too. Only something dev02 gets differently (its lease) explains the difference.', concepts: ['net.dhcp', 'net.routing'] },
      { id: 'q2', question: 'How does a DHCP request from dev02 (VLAN 30) reach ns1 in VLAN 10, when broadcasts do not cross routers?', choices: ['The relay agent on rtr01 forwards it as unicast with giaddr 10.0.30.1', 'The switch floods it into every VLAN', 'ns1 has an interface in every VLAN', 'dev02 is configured with ns1\'s address'], answer: 0, explanation: 'The relay turns the broadcast into a unicast to the server and marks which network it came from (giaddr); the server picks the subnet that contains it.', concepts: ['net.dhcp'] },
      { id: 'q3', question: 'After the router rule that blocks VLAN 30 → VLAN 10, names still resolve on dev02. Why?', choices: ['The rule allows DNS to ns1 before the drop, and rules are evaluated in order', 'DNS uses the gateway, not the firewall', 'dev02 caches every name forever', 'DNS travels inside the DHCP lease'], answer: 0, explanation: 'ns1 is in VLAN 10. Without the explicit exception before the drop, the router would block DNS and every name lookup from VLAN 30 would fail.', concepts: ['fw.path', 'dns.resolution'] },
      { id: 'q4', question: 'You added "dev01 IN A 10.0.30.25" to the zone file, but clients still get no answer for dev01.corp.lab. What is the most likely omission?', choices: ['named was not reloaded (or the zone failed to load: check named-checkzone)', 'dev01 has no default gateway', 'The DHCP lease of the clients expired', 'The router does not forward DNS'], answer: 0, explanation: 'named serves the zone it loaded. An edit takes effect after rndc reload, and only if the file loads without errors (serial increased for secondaries and caches).', concepts: ['dns.zone'] },
      { id: 'q5', question: 'Which change would NOT survive a reboot of dev01?', choices: ['ip route add default via 10.0.30.1', 'A gateway line in /etc/network/interfaces', 'A rule in /etc/nftables.conf loaded with nft -f', 'An A record in /etc/bind/db.corp.lab after rndc reload'], answer: 0, explanation: 'ip route changes the running table only. The files are read again at boot.', concepts: ['net.routing'] },
    ],
    after: ['ipnet', 'transport', 'dhcp', 'nat', 'vlan', 'nftables'],
  },
};

