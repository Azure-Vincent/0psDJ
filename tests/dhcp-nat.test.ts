import { describe, expect, it } from 'vitest';
import { DHCP_ASSESSMENT, NAT_ASSESSMENT } from '../src/content/network/assessments';
import { ASSESSMENTS, LESSONS } from '../src/content/lessons';
import { DhcpConfigError, parseDhcpdConf, parseLeases } from '../src/engine/config/dhcpd';
import { DHCP_RUNS, NAT_RUNS, runVisual } from '../src/engine/lab/visualRuns';
import { DHCPD_CONF } from '../src/engine/lab/sshLab';
import { findScenario } from '../src/engine/scenarios';
import { chooseAddress } from '../src/engine/sim/dhcp';
import { gradeQuestion } from '../src/learning/grading';
import { Lab } from './helpers';

describe('dhcpd.conf and allocation', () => {
  const conf = parseDhcpdConf(DHCPD_CONF);
  const subnet = conf.subnets[0];
  const now = Date.UTC(2026, 9, 19);

  it('parses the lab configuration', () => {
    expect(subnet).toMatchObject({ network: '10.0.10.0', prefix: 24, range: ['10.0.10.100', '10.0.10.150'] });
    expect(subnet.options.routers).toEqual(['10.0.10.1']);
    expect(conf.options.domainNameServers).toEqual(['10.0.10.53']);
    expect(conf.hosts[0]).toMatchObject({ name: 'printer01', mac: '52:54:00:e5:00:21', fixedAddress: '10.0.10.21' });
  });

  it('reports errors with file and line', () => {
    expect(() => parseDhcpdConf('subnet 10.0.10.0 netmask 255.255.255.0 {\n  range 10.0.10.100;\n}\n')).toThrow(DhcpConfigError);
    try {
      parseDhcpdConf('option routers 10.0.10.1\nsubnet 10.0.10.0 netmask 255.255.255.0 { }\n');
    } catch (e) {
      expect((e as Error).message).toMatch(/^\/etc\/dhcp\/dhcpd\.conf line \d+:/);
    }
  });

  it('allocates reservation, previous lease, then first free address', () => {
    expect(chooseAddress(conf, subnet, [], '52:54:00:e5:00:21', now)).toEqual({ ip: '10.0.10.21', reason: 'fixed-address' });
    const leases = [{ ip: '10.0.10.100', mac: 'aa:aa:aa:aa:aa:01', hostname: 'a', starts: now, ends: now + 600_000, state: 'active' as const }];
    expect(chooseAddress(conf, subnet, leases, 'aa:aa:aa:aa:aa:01', now)).toEqual({ ip: '10.0.10.100', reason: 'previous lease' });
    expect(chooseAddress(conf, subnet, leases, 'aa:aa:aa:aa:aa:02', now)).toEqual({ ip: '10.0.10.101', reason: 'pool' });
    // An expired lease frees its address for others.
    expect(chooseAddress(conf, subnet, leases, 'aa:aa:aa:aa:aa:02', now + 601_000)?.ip).toBe('10.0.10.100');
    const tiny = { ...subnet, range: ['10.0.10.100', '10.0.10.100'] as [string, string] };
    expect(chooseAddress(conf, tiny, leases, 'aa:aa:aa:aa:aa:02', now)).toBeNull();
  });
});

describe('DHCP in the lab', () => {
  it('ws02 boots with a lease: address, default route, resolv.conf, server lease file', () => {
    const lab = new Lab();
    expect(lab.run('ws02', 'dana', 'ip -4 addr show eth0').output).toMatch(/inet 10\.0\.10\.100\/24/);
    expect(lab.run('ws02', 'dana', 'ip route').output).toMatch(/default via 10\.0\.10\.1 dev eth0/);
    expect(lab.run('ws02', 'dana', 'cat /etc/resolv.conf').output).toMatch(/nameserver 10\.0\.10\.53/);
    const leases = parseLeases(lab.run('ns1', 'root', 'cat /var/lib/dhcp/dhcpd.leases').output);
    expect(leases).toEqual([expect.objectContaining({ ip: '10.0.10.100', mac: '52:54:00:d4:00:42', hostname: 'ws02', state: 'active' })]);
    expect(lab.run('ws02', 'dana', 'curl -I http://srv01.corp.lab/').output).toMatch(/200 OK/);
  });

  it('release and re-acquire logs DORA on both sides; stopped server leaves the client without address', () => {
    const lab = new Lab();
    expect(lab.run('ws02', 'root', 'dhclient -r eth0').code).toBe(0);
    expect(lab.run('ws02', 'root', 'ip -4 addr show eth0').output).not.toMatch(/inet 10\.0\.10/);
    expect(lab.run('ws02', 'root', 'dhclient -v eth0').output).toMatch(/DHCPACK of 10\.0\.10\.100 from 10\.0\.10\.53\nbound to 10\.0\.10\.100/);
    const log = lab.run('ns1', 'root', 'journalctl -u isc-dhcp-server').output;
    expect(log).toMatch(/DHCPRELEASE of 10\.0\.10\.100 from 52:54:00:d4:00:42/);
    expect(log).toMatch(/DHCPACK on 10\.0\.10\.100 to 52:54:00:d4:00:42 \(ws02\) via eth0/);
    lab.run('ws02', 'root', 'dhclient -r eth0');
    lab.run('ns1', 'root', 'systemctl stop isc-dhcp-server');
    expect(lab.run('ws02', 'root', 'dhclient -v eth0').output).toMatch(/No DHCPOFFERS received\./);
    expect(lab.run('ws02', 'dana', 'ping -c 1 10.0.10.53').output).toMatch(/Network is unreachable/);
  });

  it('a server firewall without udp/67 silently blocks DHCP', () => {
    const lab = new Lab();
    lab.run('ws02', 'root', 'dhclient -r eth0');
    expect(lab.run('ns1', 'root', 'nft insert rule inet filter input udp dport 67 drop').code).toBe(0);
    expect(lab.run('ws02', 'root', 'dhclient -v eth0').output).toMatch(/No DHCPOFFERS received\./);
  });

  it('dhcpd -t reports configuration errors; a bad INTERFACESv4 keeps the server from serving', () => {
    const lab = new Lab();
    lab.run('ns1', 'root', "sed -i 's/range 10.0.10.100 10.0.10.150;/range 10.0.10.100;/' /etc/dhcp/dhcpd.conf");
    const t = lab.run('ns1', 'root', 'dhcpd -t');
    expect(t.code).not.toBe(0);
    expect(t.output).toMatch(/dhcpd\.conf line \d+/);
    const lab2 = new Lab();
    lab2.run('ns1', 'root', "sed -i 's/INTERFACESv4=\"eth0\"/INTERFACESv4=\"ens18\"/' /etc/default/isc-dhcp-server");
    lab2.run('ns1', 'root', 'systemctl restart isc-dhcp-server');
    expect(lab2.run('ns1', 'root', 'journalctl -u isc-dhcp-server').output).toMatch(/Not configured to listen on any interfaces!/);
  });

  it('DHCP packets export to PCAP as BOOTP on UDP 67/68', () => {
    const v = runVisual(DHCP_RUNS.find((r) => r.id === 'dora')!);
    const pkts = v.trace.filter((e) => e.packet?.app?.protocol === 'DHCP').map((e) => e.packet!);
    expect(pkts.map((p) => p.udp!.dport)).toEqual([67, 68, 67, 68]);
    expect(pkts[0].src).toBe('0.0.0.0');
    expect(pkts[0].dst).toBe('255.255.255.255');
    const bytes = pkts[0].app!.bytes!;
    expect(bytes[0]).toBe(1); // op = BOOTREQUEST
    expect([...bytes.slice(236, 240)]).toEqual([99, 130, 83, 99]); // magic cookie
  });
});

describe('NAT in the lab', () => {
  it('masquerades office traffic to the Internet and shows one conntrack entry per flow', () => {
    const lab = new Lab();
    expect(lab.run('ws01', 'alice', 'curl -I http://203.0.113.80/').output).toMatch(/200 OK/);
    expect(lab.run('rtr01', 'root', 'tcpdump -n -i eth2 -c 1 tcp').output).toMatch(/IP 203\.0\.113\.2\.\d+ > 203\.0\.113\.80\.80/);
    expect(lab.run('rtr01', 'root', 'tcpdump -n -i eth0 -c 1 tcp').output).toMatch(/IP 10\.0\.10\.25\.\d+ > 203\.0\.113\.80\.80/);
    expect(lab.run('ext01', 'root', 'tcpdump -n -i eth0 tcp').output).not.toMatch(/10\.0\.10\.25/);
    const ct = lab.run('rtr01', 'root', 'conntrack -L').output.split('\n').filter((l) => l.startsWith('tcp') && l.includes('dport=80 '));
    expect(ct).toHaveLength(1);
    expect(ct[0]).toMatch(/src=10\.0\.10\.25 dst=203\.0\.113\.80 sport=(\d+) dport=80 src=203\.0\.113\.80 dst=203\.0\.113\.2 sport=80 dport=\1/);
  });

  it('publishes srv01:80 on 203.0.113.2 via DNAT; srv01 sees the real client address', () => {
    const lab = new Lab();
    expect(lab.run('ext01', 'guest', 'curl -I http://203.0.113.2/').output).toMatch(/200 OK/);
    expect(lab.run('srv01', 'root', 'tcpdump -n -i eth0 -c 1 tcp').output).toMatch(/IP 203\.0\.113\.80\.\d+ > 10\.0\.20\.10\.80/);
    expect(lab.run('rtr01', 'root', 'conntrack -L').output).toMatch(/src=203\.0\.113\.80 dst=203\.0\.113\.2 sport=\d+ dport=80 src=10\.0\.20\.10 dst=203\.0\.113\.80 sport=80/);
    // SSH is not published.
    expect(lab.run('ext01', 'guest', 'nc -zv -w 3 203.0.113.2 22').output).toMatch(/timed out|refused/);
    // Private addresses are not reachable from the Internet.
    expect(lab.run('ext01', 'guest', 'ping -c 1 -W 1 10.0.20.10').output).toMatch(/100% packet loss|Unreachable/);
  });

  it('ICMP echo is translated and listed with type/code/id', () => {
    const lab = new Lab();
    expect(lab.run('ws01', 'alice', 'ping -c 1 203.0.113.80').output).toMatch(/1 received/);
    expect(lab.run('rtr01', 'root', 'conntrack -L').output).toMatch(/^icmp +1 \d+ src=10\.0\.10\.25 dst=203\.0\.113\.80 type=8 code=0 id=\d+ src=203\.0\.113\.80 dst=203\.0\.113\.2 type=0 code=0/m);
  });

  it('without masquerade, private sources leak to the uplink and connections time out', () => {
    const lab = new Lab();
    lab.run('rtr01', 'root', "sed -i '/oifname \"eth2\" masquerade/d' /etc/nftables.conf");
    lab.run('rtr01', 'root', 'systemctl reload nftables');
    expect(lab.run('ws01', 'alice', 'curl -I -m 5 http://203.0.113.80/').output).toMatch(/\(28\)/);
    expect(lab.run('rtr01', 'root', 'tcpdump -n -i eth2 -c 1 tcp').output).toMatch(/IP 10\.0\.10\.25\.\d+ > 203\.0\.113\.80\.80/);
  });

  it('conntrack -F empties the table; sysctl --system and tee work', () => {
    const lab = new Lab();
    lab.run('ws01', 'alice', 'curl -I http://203.0.113.80/');
    expect(lab.run('rtr01', 'root', 'conntrack -F').output).toMatch(/emptied/);
    expect(lab.run('rtr01', 'root', 'conntrack -L').output).toMatch(/0 flow entries/);
    lab.run('rtr01', 'root', 'sysctl -w net.ipv4.ip_forward=0');
    expect(lab.run('rtr01', 'root', 'sysctl --system').output).toMatch(/Applying \/etc\/sysctl\.d\/99-router\.conf[\s\S]*net\.ipv4\.ip_forward = 1/);
    expect(lab.run('rtr01', 'root', 'sysctl net.ipv4.ip_forward').output).toBe('net.ipv4.ip_forward = 1');
    expect(lab.run('ws01', 'alice', 'echo hi | tee /etc/x.conf').output).toMatch(/Permission denied/);
    expect(lab.run('ws01', 'root', 'echo hi | tee -a /tmp/x.txt').output).toBe('hi');
    expect(lab.run('ws01', 'root', 'cat /tmp/x.txt').output).toBe('hi');
  });
});

describe('visual runs, lessons and assessments', () => {
  const expected: Record<string, RegExp> = {
    dora: /bound to 10\.0\.10\.100/, 'wrong-router': /Destination Host Unreachable/, 'no-server': /No DHCPOFFERS received/, exhausted: /No DHCPOFFERS received/,
    masquerade: /200 OK/, dnat: /200 OK/, 'no-masquerade': /\(28\)/, 'filter-after-dnat': /\(28\)/,
  };
  it.each([...DHCP_RUNS, ...NAT_RUNS].map((r) => r.id))('run %s', (id) => {
    const run = [...DHCP_RUNS, ...NAT_RUNS].find((r) => r.id === id)!;
    const v = runVisual(run);
    expect(v.output).toMatch(expected[id]);
    expect(v.trace.length).toBeGreaterThan(0);
  });
  it('the filter-after-dnat hop note shows the rewrite before the forward drop', () => {
    const v = runVisual(NAT_RUNS.find((r) => r.id === 'filter-after-dnat')!);
    const syn = v.trace.find((e) => e.kind === 'packet')!;
    const note = syn.hops!.map((h) => h.note).join(' | ');
    expect(note).toMatch(/rewritten to 10\.0\.20\.10:80; nft inet filter forward: no rule matched, chain policy drop/);
  });
  it('lessons are registered with existing scenarios and assessments', () => {
    for (const id of ['dhcp', 'nat']) {
      const L = LESSONS.find((l) => l.id === id)!;
      expect(L).toBeDefined();
      expect(ASSESSMENTS[L.assessmentId]).toBeDefined();
      for (const s of L.scenarioIds) expect(findScenario(s), s).toBeDefined();
    }
  });
  it('grades key answers', () => {
    const q = (a: typeof DHCP_ASSESSMENT, id: string) => a.questions.find((x) => x.id === id)!;
    expect(gradeQuestion(q(DHCP_ASSESSMENT, 'dhcp-q-router'), 0).correct).toBe(true);
    expect(gradeQuestion(q(DHCP_ASSESSMENT, 'dhcp-q-interfaces'), 'interfacesv4').correct).toBe(true);
    expect(gradeQuestion(q(DHCP_ASSESSMENT, 'dhcp-q-renew'), '300').correct).toBe(true);
    expect(gradeQuestion(q(NAT_ASSESSMENT, 'nat-q-filter'), 1).correct).toBe(true);
    expect(gradeQuestion(q(NAT_ASSESSMENT, 'nat-q-private'), [0, 1, 2]).correct).toBe(true);
  });
});
