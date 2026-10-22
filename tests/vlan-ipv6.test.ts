import { describe, expect, it } from 'vitest';
import { IPV6_ASSESSMENT, VLAN_ASSESSMENT } from '../src/content/network/assessments';
import { ASSESSMENTS, LESSONS } from '../src/content/lessons';
import { parseRulesetFile, evaluate } from '../src/engine/config/nft';
import { parseInterfaces } from '../src/engine/config/netconf';
import { parseZone } from '../src/engine/config/zone';
import { runCapture } from '../src/engine/lab/captures';
import { IPV6_RUNS, VLAN_RUNS, runVisual } from '../src/engine/lab/visualRuns';
import { CORP_ZONE, RADVD_CONF } from '../src/engine/lab/sshLab';
import { canonicalIp6, classify6, expandIp6, linkLocalFromMac, parseIp6, slaacAddress, solicitedNode, multicastMac } from '../src/engine/net/ip6';
import { findScenario } from '../src/engine/scenarios';
import { buildPcap, checksum, frameBytes } from '../src/engine/pcap';
import { parseRadvdConf } from '../src/engine/sim/slaac';
import { gradeQuestion } from '../src/learning/grading';
import { Lab } from './helpers';

describe('IPv6 addresses', () => {
  it('parses and prints RFC 5952 text', () => {
    expect(canonicalIp6('2001:0DB8:0000:0000:0000:0000:0020:0010')).toBe('2001:db8::20:10');
    expect(canonicalIp6('2001:db8:0:0:1:0:0:1')).toBe('2001:db8::1:0:0:1'); // first of two equal runs
    expect(canonicalIp6('2001:db8:0:1:1:1:1:1')).toBe('2001:db8:0:1:1:1:1:1'); // a single zero group is not compressed
    expect(canonicalIp6('::')).toBe('::');
    expect(canonicalIp6('::ffff:10.0.0.1')).toBe('::ffff:a00:1');
    expect(parseIp6('2001:db8::1::2')).toBeNull();
    expect(parseIp6('2001:db8:::1')).toBeNull();
    expect(expandIp6(parseIp6('fe80::1')!)).toBe('fe80:0000:0000:0000:0000:0000:0000:0001');
  });
  it('derives EUI-64, SLAAC and solicited-node addresses', () => {
    expect(linkLocalFromMac('52:54:00:e7:00:1e')).toBe('fe80::5054:ff:fee7:1e');
    expect(slaacAddress('2001:db8:30::/64', '52:54:00:e7:00:1e')).toBe('2001:db8:30:0:5054:ff:fee7:1e');
    expect(solicitedNode('2001:db8:20::10')).toBe('ff02::1:ff00:10');
    expect(multicastMac('ff02::1:ff00:10')).toBe('33:33:ff:00:00:10');
    expect(classify6('fe80::1')).toBe('link-local');
    expect(classify6('fd00::1')).toBe('unique-local');
    expect(classify6('2001:db8::1')).toBe('documentation');
  });
});

describe('configuration parsers', () => {
  it('ifupdown inet6 stanzas and VLAN sub-interfaces', () => {
    const r = parseInterfaces('auto eth3.30\niface eth3.30 inet static\n    address 10.0.30.1/24\niface eth3.30 inet6 static\n    address 2001:DB8:30::1/64\n    gateway 2001:db8:30::fffe\niface eth0 inet6 auto\n');
    expect(r.errors).toEqual([]);
    const v6 = r.ifaces.find((i) => i.family === 'inet6' && i.name === 'eth3.30')!;
    expect(v6).toMatchObject({ method: 'static', address: '2001:db8:30::1', prefix: 64, gateway: '2001:db8:30::fffe' });
    expect(r.ifaces.find((i) => i.name === 'eth0')!.method).toBe('auto');
  });
  it('AAAA records and radvd.conf', () => {
    const z = parseZone(CORP_ZONE, 'corp.lab', 'db.corp.lab');
    expect(z.records.find((r) => r.type === 'AAAA')).toMatchObject({ name: 'srv01.corp.lab.', data: '2001:db8:20::10' });
    expect(() => parseZone(CORP_ZONE + 'bad IN AAAA 10.0.0.1\n', 'corp.lab', 'f')).toThrow(/bad IPv6 address/);
    const r = parseRadvdConf(RADVD_CONF + 'interface eth1 {\n    AdvSendAdvert off;\n    RDNSS 2001:DB8:20::53 { };\n};\n');
    expect(r[0]).toMatchObject({ name: 'eth3.30', sendAdvert: true, prefixes: [{ prefix: '2001:db8:30::/64', autonomous: true, onLink: true }] });
    expect(r[1]).toMatchObject({ name: 'eth1', sendAdvert: false, rdnss: ['2001:db8:20::53'] });
    expect(() => parseRadvdConf('interface eth0 {\n  AdvSendAdvert maybe;\n};\n')).toThrow(/line 2/);
  });
  it('nftables families: ip6 saddr, icmpv6 type, ipv6-icmp; "icmp" does not match ICMPv6', () => {
    const rs = parseRulesetFile('table inet f {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n\t\tmeta l4proto icmp accept\n\t\tip6 saddr 2001:db8:30::/64 tcp dport 22 accept\n\t\ticmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept\n\t}\n}\n');
    const ctx = { family: 6 as const, src: 'fe80::1', dst: 'ff02::1:ff00:10', proto: 'icmp' as const, ctState: 'untracked' as const, len: 72 };
    expect(evaluate(rs, 'input', { ...ctx, icmpType: 'nd-neighbor-solicit' }).verdict).toBe('accept');
    expect(evaluate(rs, 'input', { ...ctx, icmpType: 'echo-request' }).verdict).toBe('drop');
    expect(evaluate(rs, 'input', { family: 6, src: '2001:db8:30::5', dst: '2001:db8:20::10', proto: 'tcp', dport: 22, ctState: 'new', len: 60 }).verdict).toBe('accept');
    expect(evaluate(rs, 'input', { family: 4, src: '10.0.30.5', dst: '10.0.20.10', proto: 'tcp', dport: 22, ctState: 'new', len: 60 }).verdict).toBe('drop');
    const ip6only = parseRulesetFile('table ip6 t {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n\t}\n}\n');
    expect(evaluate(ip6only, 'input', { family: 4, src: '10.0.0.1', dst: '10.0.0.2', proto: 'icmp', ctState: 'new', len: 84 }).verdict).toBe('accept');
  });
});

describe('VLANs on sw01', () => {
  it('builds broadcast domains from the bridge configuration', () => {
    const lab = new Lab();
    const seg = (h: string, i: string) => lab.world.hosts[h].ifaces.find((x) => x.name === i)!.segment;
    expect(seg('ws01', 'eth0')).toBe('lan10');
    expect(seg('srv01', 'eth0')).toBe('srv20');
    expect(seg('dev01', 'eth0')).toBe('dev30');
    expect(seg('rtr01', 'eth3.30')).toBe('dev30');
    expect(lab.run('sw01', 'root', 'bridge vlan show').output).toMatch(/swp7 +1 PVID Egress Untagged\n +30\n/);
    expect(lab.run('rtr01', 'root', 'ip -d link show eth3.30').output).toMatch(/eth3\.30@eth3:[\s\S]*vlan protocol 802\.1Q id 30/);
  });
  it('isolates VLANs: a broadcast stays in its VLAN and inter-VLAN traffic is routed', () => {
    const lab = new Lab();
    lab.world.hosts.dev01.capture = [];
    lab.run('ws01', 'alice', 'ping -c 1 10.0.10.53');
    // (dev01 may see ARP of its own VLAN, e.g. for dev02's DHCP renewals, but never the office's)
    expect(lab.world.hosts.dev01.capture.some((f) => f.arp && (f.arp.targetIp === '10.0.10.53' || f.arp.senderIp === '10.0.10.25'))).toBe(false);
    expect(lab.run('dev01', 'erin', 'ping -4 -c 1 10.0.20.10').output).toMatch(/ttl=63/);
    const trunk = lab.run('rtr01', 'root', 'tcpdump -e -n -i eth3 icmp').output;
    expect(trunk).toMatch(/ethertype 802\.1Q \(0x8100\), vlan 30, p 0, ethertype IPv4 \(0x0800\), IP 10\.0\.30\.25 > 10\.0\.20\.10: ICMP echo request/);
    expect(lab.run('rtr01', 'root', 'tcpdump -n -i eth3 vlan 20').output).toMatch(/0 packets captured/);
    expect(lab.run('sw01', 'root', 'bridge fdb show').output).toMatch(/52:54:00:e7:00:1e dev swp8 vlan 30 master br0/);
    expect(lab.run('sw01', 'root', 'tcpdump -e -n -i swp7 icmp').output).toMatch(/vlan 30/);
  });
  it('a port in the wrong VLAN or a pruned trunk cuts the host off; runtime fixes are lost on reboot', () => {
    const lab = new Lab();
    lab.run('sw01', 'root', 'bridge vlan del dev swp7 vid 30');
    expect(lab.run('dev01', 'erin', 'ping -4 -c 1 10.0.30.1').output).toMatch(/From 10\.0\.30\.25 icmp_seq=1 Destination Host Unreachable/);
    lab.run('sw01', 'root', 'bridge vlan add dev swp7 vid 30');
    expect(lab.run('dev01', 'erin', 'ping -4 -c 1 10.0.30.1').output).toMatch(/1 received/);
    lab.run('sw01', 'root', 'bridge vlan add dev swp8 vid 10 pvid untagged');
    lab.run('sw01', 'root', 'bridge vlan del dev swp8 vid 30');
    expect(lab.world.hosts.dev01.ifaces[1].segment).toBe('lan10');
    expect(lab.run('dev01', 'erin', 'ping -4 -c 1 10.0.30.1').output).toMatch(/Destination Host Unreachable/);
    lab.run('sw01', 'root', 'reboot');
    expect(lab.world.hosts.dev01.ifaces[1].segment).toBe('dev30');
  });
  it('ip link add creates a working VLAN sub-interface', () => {
    const lab = new Lab();
    lab.run('rtr01', 'root', 'ip link add link eth3 name eth3.31 type vlan id 31');
    lab.run('rtr01', 'root', 'ip link set eth3.31 up');
    expect(lab.world.hosts.rtr01.ifaces.find((i) => i.name === 'eth3.31')!.segment).toBeNull(); // VLAN 31 not on the trunk
    lab.run('sw01', 'root', 'bridge vlan add dev swp7 vid 31');
    expect(lab.world.hosts.rtr01.ifaces.find((i) => i.name === 'eth3.31')!.segment).toBe('vlan31');
    expect(lab.run('rtr01', 'root', 'ip link add link eth9 name eth9.5 type vlan id 5').output).toMatch(/Cannot find device "eth9"/);
  });
});

describe('IPv6 in the lab', () => {
  it('dev01 autoconfigures by SLAAC; srv01 is static; both are reachable over IPv6', () => {
    const lab = new Lab();
    expect(lab.run('dev01', 'erin', 'ip -6 addr show eth0').output).toMatch(/inet6 2001:db8:30:0:5054:ff:fee7:1e\/64 scope global dynamic mngtmpaddr/);
    expect(lab.run('dev01', 'erin', 'ip -6 route').output).toMatch(/default via fe80::5054:ff:fea1:4 dev eth0 proto ra/);
    expect(lab.run('ws01', 'alice', 'ip -6 addr show eth0').output).toMatch(/inet6 fe80::5054:ff:fed4:19\/64 scope link/);
    expect(lab.run('dev01', 'erin', 'ping -6 -c 1 srv01.corp.lab').output).toMatch(/64 bytes from 2001:db8:20::10: icmp_seq=1 ttl=63/);
    expect(lab.run('dev01', 'erin', 'curl -6 -I http://srv01.corp.lab/').output).toMatch(/200 OK/);
    expect(lab.run('dev01', 'erin', 'curl -I http://[2001:db8:20::10]/').output).toMatch(/200 OK/);
    expect(lab.run('rtr01', 'root', 'ip -6 neigh').output).toMatch(/2001:db8:20::10 dev eth1 lladdr 52:54:00:c3:00:0a REACHABLE/);
    expect(lab.run('srv01', 'root', 'ss -tln').output).toMatch(/\[::\]:80/);
  });
  it('address selection: AAAA only with a global IPv6 address; IPv6 first; ws01 stays IPv4', () => {
    const lab = new Lab();
    expect(lab.run('dev01', 'erin', 'getent ahosts srv01.corp.lab').output.split('\n')[0]).toMatch(/^2001:db8:20::10 +STREAM srv01\.corp\.lab/);
    expect(lab.run('ws01', 'alice', 'getent hosts srv01.corp.lab').output).toMatch(/^10\.0\.20\.10 /);
    expect(lab.run('ws01', 'alice', 'ping -6 -c 1 srv01.corp.lab').output).toMatch(/Network is unreachable/);
    expect(lab.run('ws01', 'alice', 'dig AAAA srv01.corp.lab +short').output).toBe('2001:db8:20::10');
    expect(lab.run('ws01', 'alice', 'curl -6 -I http://srv01.corp.lab/').code).not.toBe(0);
  });
  it('ICMPv6 blocked on the server breaks NDP: address unreachable; curl falls back, ssh -6 fails', () => {
    const lab = new Lab();
    lab.run('srv01', 'root', "sed -i '/ipv6-icmp/d' /etc/nftables.conf");
    lab.run('srv01', 'root', 'systemctl reload nftables');
    expect(lab.run('dev01', 'erin', 'ping -6 -c 1 srv01.corp.lab').output).toMatch(/From 2001:db8:20::1 icmp_seq=1 Destination unreachable: Address unreachable|From 2001:db8:30::1 icmp_seq=1 Destination unreachable: Address unreachable/);
    expect(lab.run('rtr01', 'root', 'ip -6 neigh').output).toMatch(/2001:db8:20::10 dev eth1 FAILED/);
    const v = lab.run('dev01', 'erin', 'curl -v -I http://srv01.corp.lab/').output;
    expect(v).toMatch(/Trying \[2001:db8:20::10\]:80[\s\S]*No route to host[\s\S]*Connected to srv01\.corp\.lab \(10\.0\.20\.10\)/);
    expect(lab.run('srv01', 'root', 'tcpdump -n -i eth0 icmp6').output).toMatch(/ICMP6, neighbor solicitation, who has 2001:db8:20::10/);
  });
  it('IPv6 forwarding is separate from IPv4 and drops silently; radvd warns', () => {
    const lab = new Lab();
    lab.run('rtr01', 'root', 'sysctl -w net.ipv6.conf.all.forwarding=0');
    expect(lab.run('dev01', 'erin', 'curl -6 -I -m 3 http://srv01.corp.lab/').output).toMatch(/curl: \(28\)/);
    expect(lab.run('dev01', 'erin', 'curl -4 -I http://srv01.corp.lab/').output).toMatch(/200 OK/);
    lab.run('rtr01', 'root', 'systemctl restart radvd');
    expect(lab.run('rtr01', 'root', 'journalctl -u radvd').output).toMatch(/IPv6 forwarding seems to be disabled, but continuing anyway/);
  });
  it('rdisc6 shows the advertisement; tcpdump and PCAP show IPv6 / ICMPv6 with valid checksums', () => {
    const lab = new Lab();
    expect(lab.run('dev01', 'root', 'rdisc6 eth0').output).toMatch(/Prefix {19}: 2001:db8:30::\/64[\s\S]*from fe80::5054:ff:fea1:4/);
    expect(lab.run('ws01', 'root', 'rdisc6 eth0').code).toBe(2);
    const cap = runCapture('ipv6-slaac-ndp');
    const ns = cap.frames.find((f) => f.ip?.icmp?.type === 135)!;
    const bytes = frameBytes(ns);
    expect([bytes[12], bytes[13]]).toEqual([0x86, 0xdd]);
    expect(bytes[20]).toBe(58); // next header ICMPv6
    expect(bytes[21]).toBe(255); // hop limit
    // ICMPv6 checksum over pseudo-header + message must verify to 0
    const src = [...bytes.slice(22, 38)], dst = [...bytes.slice(38, 54)], msg = [...bytes.slice(54)];
    const len = msg.length;
    expect(checksum([...src, ...dst, 0, 0, (len >> 8) & 255, len & 255, 0, 0, 0, 58, ...msg])).toBe(0);
    const tagged = runCapture('vlan-trunk').frames.find((f) => f.ip)!;
    const tb = frameBytes(tagged);
    expect([tb[12], tb[13], tb[14] & 0x0f, tb[15], tb[16], tb[17]]).toEqual([0x81, 0x00, 0, 30, 0x08, 0x00]);
    expect(buildPcap(cap.frames).length).toBeGreaterThan(24);
  });
});

describe('VLAN/IPv6 visual runs, lessons and assessments', () => {
  const expected: Record<string, RegExp> = {
    'same-vlan': /ttl=64/, 'inter-vlan': /ttl=63/, 'wrong-access': /Destination Host Unreachable/, 'trunk-pruned': /Destination Host Unreachable/,
    slaac: /^$/, 'ndp-ping': /icmp_seq=1 ttl=63/, 'dual-stack': /Connected to srv01\.corp\.lab \(2001:db8:20::10\)/,
    'icmpv6-blocked': /Address unreachable/, 'happy-eyeballs': /Connected to srv01\.corp\.lab \(10\.0\.20\.10\)/, 'no-forwarding': /curl: \(28\)/,
  };
  it.each([...VLAN_RUNS, ...IPV6_RUNS].map((r) => r.id))('run %s', (id) => {
    const run = [...VLAN_RUNS, ...IPV6_RUNS].find((r) => r.id === id)!;
    const v = runVisual(run);
    expect(v.output).toMatch(expected[id]);
    expect(v.trace.length).toBeGreaterThan(0);
  });
  it('the inter-VLAN run shows the 802.1Q tag on the trunk hop; NDP precedes the packet that needed it', () => {
    const v = runVisual(VLAN_RUNS.find((r) => r.id === 'inter-vlan')!);
    const req = v.trace.find((e) => e.packet?.icmp?.type === 8)!;
    expect(req.hops!.map((h) => h.note).join(' ')).toMatch(/in swp8 \(untagged\) → VLAN 30 → out swp7 \(tagged 30\)/);
    const n = runVisual(IPV6_RUNS.find((r) => r.id === 'ndp-ping')!);
    const titles = n.trace.map((e) => e.title);
    expect(titles.findIndex((t) => /Neighbor Solicitation: who has fe80::5054:ff:fea1:4/.test(t))).toBeLessThan(titles.findIndex((t) => /Echo \(ping\) request/.test(t)));
  });
  it('lessons and assessments are registered', () => {
    for (const id of ['vlan', 'ipv6']) {
      const L = LESSONS.find((l) => l.id === id)!;
      expect(ASSESSMENTS[L.assessmentId]).toBeDefined();
      for (const s of L.scenarioIds) expect(findScenario(s), s).toBeDefined();
    }
    const q = (a: typeof VLAN_ASSESSMENT, id: string) => a.questions.find((x) => x.id === id)!;
    expect(gradeQuestion(q(VLAN_ASSESSMENT, 'vlan-q-tag'), '0x8100').correct).toBe(true);
    expect(gradeQuestion(q(VLAN_ASSESSMENT, 'vlan-q-subif'), 'sudo ip link add link eth3 name eth3.40 type vlan id 40').correct).toBe(true);
    expect(gradeQuestion(q(IPV6_ASSESSMENT, 'v6-q-compress'), '2001:db8::20:10').correct).toBe(true);
    expect(gradeQuestion(q(IPV6_ASSESSMENT, 'v6-q-eui64'), '2001:db8:30::5054:ff:fee7:1e').correct).toBe(true);
    expect(gradeQuestion(q(IPV6_ASSESSMENT, 'v6-q-firewall'), 0).correct).toBe(true);
  });
});
