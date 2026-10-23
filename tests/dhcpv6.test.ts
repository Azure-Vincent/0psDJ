import { describe, expect, it } from 'vitest';
import { parseDhcpd6Conf, parseLeases6 } from '../src/engine/config/dhcpd6';
import { DHCPD6_CONF } from '../src/engine/lab/sshLab';
import { IPV6_RUNS, runVisual } from '../src/engine/lab/visualRuns';
import { DEV02_HARDENED_NFT } from '../src/engine/scenarios/dhcpv6Scenarios';
import { writeFile } from '../src/engine/fs';
import { Lab } from './helpers';

describe('DHCPv6', () => {
  it('dev02 gets a /128 from dhcpd -6 on rtr01, its routes from the RA and DNS from DHCPv6', () => {
    const lab = new Lab();
    expect(lab.run('rtr01', 'root', 'journalctl -u isc-dhcp-server').output).toMatch(/Launching IPv6 server only\.[\s\S]*Bound to \*:547\n.*Listening on Socket\/eth3\.30\/2001:db8:30::\/64/);
    const addr = lab.run('dev02', 'root', 'ip -6 addr show eth0').output;
    expect(addr).toMatch(/inet6 2001:db8:30::1[0-9a-f]{3}\/128 scope global dynamic \n {7}valid_lft \d+sec preferred_lft \d+sec/);
    expect(addr).not.toMatch(/mngtmpaddr/); // autoconf 0: no SLAAC address
    expect(lab.run('dev02', 'root', 'ip -6 route').output).toMatch(/2001:db8:30::\/64 dev eth0 proto ra[\s\S]*default via fe80::5054:ff:fea1:4 dev eth0 proto ra/);
    expect(lab.run('dev02', 'jordan', 'curl -6 -I http://srv01.corp.lab/').output).toMatch(/^HTTP\/1\.1 200 OK/);
    expect(lab.run('ns1', 'root', 'ss -ulnp').output).toMatch(/\[::\]:53/);
    // a fresh exchange shows the full message flow
    lab.run('dev02', 'root', 'dhclient -6 -r eth0');
    expect(lab.run('dev02', 'root', 'dhclient -6 -v eth0').output).toMatch(/XMT: Solicit on eth0[\s\S]*RCV: Advertise message on eth0 from fe80::5054:ff:fea1:4\.[\s\S]*XMT: Request on eth0[\s\S]*PRC: Bound to lease 00:01:00:01:/);
    expect(lab.run('dev02', 'root', 'cat /etc/resolv.conf').output).toBe('search corp.lab.\nnameserver 2001:db8:10::53');
    expect(lab.run('dev02', 'root', 'tcpdump -n -i eth0 -c 4 port 547').output).toMatch(/IP6 fe80::5054:ff:fee7:2a\.546 > ff02::1:2\.547: dhcp6 solicit\n.*IP6 fe80::5054:ff:fea1:4\.547 > fe80::5054:ff:fee7:2a\.546: dhcp6 advertise\n.*dhcp6 request\n.*dhcp6 reply/);
    const log = lab.run('rtr01', 'root', 'journalctl -u isc-dhcp-server -n 4').output;
    expect(log).toMatch(/Request message from fe80::5054:ff:fee7:2a port 546, transaction ID 0x[0-9A-F]{6}\n.*Reply NA: address 2001:db8:30::[0-9a-f]+ to client with duid 00:01:00:01:[0-9a-f:]+:52:54:00:e7:00:2a iaid = 15138858 valid for 600 seconds\n.*Sending Reply to fe80::5054:ff:fee7:2a port 546/);
    const leases = parseLeases6(lab.run('rtr01', 'root', 'cat /var/lib/dhcp/dhcpd6.leases').output);
    expect(leases.at(-1)).toMatchObject({ iaid: '00:e7:00:2a', state: 'active', valid: 600, preferred: 375 });
  });

  it('dhcpd6.conf: the lab file parses; DHCPv4 names and missing subnet6 matches are reported', () => {
    expect(parseDhcpd6Conf(DHCPD6_CONF).subnets[0]).toMatchObject({ prefix: '2001:db8:30::/64', range: ['2001:db8:30::1000', '2001:db8:30::1fff'] });
    expect(() => parseDhcpd6Conf('option domain-name-servers 10.0.10.53;\n')).toThrow(/line 1: domain-name-servers is an IPv4 \(DHCPv4\) option/);
    expect(() => parseDhcpd6Conf('subnet6 2001:db8:30::/64 { range6 2001:db8:31::1 2001:db8:31::9; }\n')).toThrow(/range6 address 2001:db8:31::1 is not in subnet6 2001:db8:30::\/64/);
    const lab = new Lab();
    lab.run('rtr01', 'root', `sed -i 's/INTERFACESv6="eth3.30"/INTERFACESv6="eth3"/' /etc/default/isc-dhcp-server`);
    expect(lab.run('rtr01', 'root', 'systemctl restart isc-dhcp-server').code).not.toBe(0);
    expect(lab.run('rtr01', 'root', 'journalctl -u isc-dhcp-server -n 10').output).toMatch(/No subnet6 declaration for eth3 \(fe80::5054:ff:fea1:4\)\.[\s\S]*Not configured to listen on any interfaces![\s\S]*dhcpd6check syslog for diagnostics\. \.\.\. failed!/);
  });

  it('nftables applies on both ends (unlike ISC DHCPv4)', () => {
    let lab = new Lab();
    writeFile(lab.world.hosts.dev02, '/etc/nftables.conf', DEV02_HARDENED_NFT, lab.world.clock);
    lab.run('dev02', 'root', 'systemctl restart nftables');
    lab.run('dev02', 'root', 'dhclient -6 -r eth0');
    expect(lab.run('dev02', 'root', 'dhclient -6 -v eth0').output).not.toMatch(/RCV:/);
    expect(lab.run('rtr01', 'root', 'journalctl -u isc-dhcp-server -n 1').output).toMatch(/Sending Advertise to fe80::5054:ff:fee7:2a port 546/);
    // DHCPv4 still works through the same firewall
    lab.run('dev02', 'root', 'dhclient -r eth0');
    expect(lab.run('dev02', 'root', 'dhclient -v eth0').output).toMatch(/bound to 10\.0\.30\.100/);
    // without a global address the router refuses to forward the link-local source
    expect(lab.run('dev02', 'jordan', 'ping -6 -c 1 2001:db8:20::10').output).toMatch(/From fe80::5054:ff:fea1:4 icmp_seq=1 Destination unreachable: Beyond scope/);
    expect(lab.run('dev02', 'jordan', 'curl -6 -I http://srv01.corp.lab/').output).toMatch(/No route to host/);

    lab = new Lab();
    lab.run('rtr01', 'root', "sed -i '/udp dport 547/d' /etc/nftables.conf");
    lab.run('rtr01', 'root', 'systemctl reload nftables');
    lab.run('dev02', 'root', 'dhclient -6 -r eth0');
    const before = lab.run('rtr01', 'root', 'journalctl -u isc-dhcp-server').output.split('\n').length;
    lab.run('dev02', 'root', 'dhclient -6 eth0');
    expect(lab.run('rtr01', 'root', 'journalctl -u isc-dhcp-server').output.split('\n').length).toBe(before);
    expect(lab.run('rtr01', 'root', 'tcpdump -n -i eth3.30 -c 1 port 547').output).toMatch(/dhcp6 solicit/);
  });

  it('renews at T1, drops the address at the end of the valid lifetime, and recovers', () => {
    const lab = new Lab();
    lab.run('rtr01', 'root', 'systemctl stop isc-dhcp-server');
    lab.run('dev02', 'root', 'sleep 11m');
    expect(lab.run('dev02', 'root', 'journalctl -t dhclient').output).toMatch(/XMT: Renew on eth0[\s\S]*XMT: Rebind on eth0[\s\S]*PRC: Discarding expired lease 2001:db8:30::/);
    expect(lab.run('dev02', 'root', 'ip -6 addr show eth0').output).not.toMatch(/scope global/);
    lab.run('rtr01', 'root', 'systemctl start isc-dhcp-server');
    lab.run('dev02', 'root', 'sleep 3m');
    expect(lab.run('dev02', 'root', 'ip -6 addr show eth0').output).toMatch(/\/128 scope global dynamic/);
  });

  it('RA flags and stateless DHCPv6', () => {
    const lab = new Lab();
    expect(lab.run('dev01', 'root', 'rdisc6 eth0').output).toMatch(/Stateful address conf\. {4}: {10}Yes\nStateful other conf\. {6}: {10}Yes/);
    expect(lab.run('dev01', 'root', 'dhclient -6 -S -v eth0').output).toMatch(/Info-Request on eth0[\s\S]*RCV: Reply message on eth0 from fe80::5054:ff:fea1:4\./);
    expect(lab.run('dev01', 'root', 'cat /etc/resolv.conf').output).toMatch(/nameserver 2001:db8:10::53/);
    expect(lab.run('dev01', 'root', 'ip -6 addr show eth0').output).not.toMatch(/\/128/);
  });

  it('visual runs trace the exchange and the firewall drop', () => {
    const run = (id: string) => runVisual(IPV6_RUNS.find((r) => r.id === id)!);
    const ok = run('dhcpv6');
    expect(ok.trace.some((e) => e.packet?.app?.protocol === 'DHCPv6' && /Advertise/.test(e.packet.app.info))).toBe(true);
    const fw = run('dhcpv6-client-fw');
    expect(fw.trace.some((e) => !e.delivered && (e.hops ?? []).some((h) => /input chain dropped it/.test(h.note ?? '')))).toBe(true);
  });
});
