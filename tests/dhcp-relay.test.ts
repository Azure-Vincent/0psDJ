import { describe, expect, it } from 'vitest';
import { DHCP_RUNS, runVisual } from '../src/engine/lab/visualRuns';
import { Lab } from './helpers';

describe('DHCP relay', () => {
  it('dev02 on VLAN 30 gets a lease from ns1 through the relay on rtr01', () => {
    const lab = new Lab();
    expect(lab.run('dev02', 'jordan', 'ip -4 addr show eth0').output).toMatch(/inet 10\.0\.30\.100\/24 brd 10\.0\.30\.255 scope global dynamic eth0\n {7}valid_lft \d+sec/);
    expect(lab.run('dev02', 'jordan', 'ip route').output).toMatch(/default via 10\.0\.30\.1 dev eth0/);
    expect(lab.run('dev02', 'jordan', 'curl -I http://srv01.corp.lab/').output).toMatch(/^HTTP\/1\.1 200 OK/);
    expect(lab.run('rtr01', 'root', 'journalctl -u isc-dhcp-relay').output).toMatch(/Listening on LPF\/eth3\.30\/52:54:00:a1:00:04[\s\S]*Listening on LPF\/eth0\//);
    lab.run('dev02', 'root', 'dhclient -r eth0');
    lab.run('dev02', 'root', 'rm /var/lib/dhcp/dhclient.eth0.leases');
    expect(lab.run('dev02', 'root', 'dhclient -v eth0').output).toMatch(/DHCPOFFER of 10\.0\.30\.100 from 10\.0\.30\.1\nDHCPREQUEST[^\n]*\nDHCPACK of 10\.0\.30\.100 from 10\.0\.30\.1/);
    expect(lab.run('ns1', 'root', 'journalctl -u isc-dhcp-server -n 4').output).toMatch(/DHCPDISCOVER from 52:54:00:e7:00:2a \(dev02\) via 10\.0\.30\.1/);
    const td = lab.run('rtr01', 'root', 'tcpdump -n -i eth0 -c 4 port 67').output;
    expect(td).toMatch(/IP 10\.0\.10\.1\.67 > 10\.0\.10\.53\.67: BOOTP\/DHCP, Request from 52:54:00:e7:00:2a/);
    expect(td).toMatch(/IP 10\.0\.10\.53\.67 > 10\.0\.30\.1\.67: BOOTP\/DHCP, Reply/);
  });

  it('the relay does not relay the server LAN (-id/-iu), and a missing subnet is "unknown network segment"', () => {
    const lab = new Lab();
    lab.run('ws02', 'root', 'dhclient -r eth0');
    lab.run('ws02', 'root', 'dhclient -v eth0');
    expect(lab.run('ns1', 'root', 'journalctl -u isc-dhcp-server -n 4').output).not.toMatch(/via 10\.0\.10\.1/);
    lab.run('ns1', 'root', "sed -i '/^# Development VLAN 30/,/^}/d' /etc/dhcp/dhcpd.conf");
    lab.run('ns1', 'root', 'systemctl restart isc-dhcp-server');
    lab.run('dev02', 'root', 'dhclient -r eth0');
    lab.run('dev02', 'root', 'rm /var/lib/dhcp/dhclient.eth0.leases');
    expect(lab.run('dev02', 'root', 'dhclient -v eth0').output).toMatch(/No DHCPOFFERS received/);
    expect(lab.run('ns1', 'root', 'journalctl -u isc-dhcp-server -n 2').output).toMatch(/DHCPDISCOVER from 52:54:00:e7:00:2a via 10\.0\.30\.1: unknown network segment/);
  });

  it('without -iu the replies hit the relay\'s fallback socket and rtr01\'s input chain drops them', () => {
    const lab = new Lab();
    lab.run('rtr01', 'root', "sed -i 's/-id eth3.30 -iu eth0/-id eth3.30/' /etc/default/isc-dhcp-relay");
    lab.run('rtr01', 'root', 'systemctl restart isc-dhcp-relay');
    lab.run('dev02', 'root', 'dhclient -r eth0');
    lab.run('dev02', 'root', 'rm /var/lib/dhcp/dhclient.eth0.leases');
    expect(lab.run('dev02', 'root', 'dhclient -v eth0').output).toMatch(/No DHCPOFFERS received/);
    expect(lab.run('ns1', 'root', 'journalctl -u isc-dhcp-server -n 2').output).toMatch(/DHCPOFFER on 10\.0\.30\.100 to 52:54:00:e7:00:2a \(dev02\) via 10\.0\.30\.1/);
    // An explicit firewall rule for the replies is the other valid fix.
    lab.run('rtr01', 'root', 'nft insert rule inet filter input ip saddr 10.0.10.53 udp sport 67 udp dport 67 accept');
    expect(lab.run('dev02', 'root', 'dhclient -v eth0').output).toMatch(/DHCPACK of 10\.0\.30\.100 from 10\.0\.30\.1/);
  });
});

describe('DHCP lease timers', () => {
  it('renews by unicast at T1, rebinds by broadcast at T2, drops the address at expiry, retries every 5 minutes', () => {
    const lab = new Lab();
    lab.run('ws02', 'root', 'sleep 300');
    expect(lab.run('ws02', 'root', 'journalctl -t dhclient -n 3').output).toMatch(/DHCPREQUEST for 10\.0\.10\.100 on eth0 to 10\.0\.10\.53 port 67\n.*DHCPACK of 10\.0\.10\.100 from 10\.0\.10\.53\n.*bound to 10\.0\.10\.100 -- renewal in 300 seconds\./);
    expect(lab.run('ws02', 'root', 'cat /var/lib/dhcp/dhclient.eth0.leases').output).toMatch(/renew \d \d{4}\/\d\d\/\d\d [\d:]+;\n  rebind .*;\n  expire .*;/);
    lab.run('ns1', 'root', 'systemctl stop isc-dhcp-server');
    lab.run('ws02', 'root', 'sleep 650');
    const j = lab.run('ws02', 'root', 'journalctl -t dhclient -n 16').output;
    // RENEWING retries by unicast until T2, REBINDING retries by broadcast until expiry.
    expect(j).toMatch(/08:44:08 .*DHCPREQUEST for 10\.0\.10\.100 on eth0 to 10\.0\.10\.53 port 67\n.*08:45:08 .*to 10\.0\.10\.53 port 67\n.*08:46:08 .*to 10\.0\.10\.53 port 67\n.*08:46:53 .*DHCPREQUEST for 10\.0\.10\.100 on eth0 to 255\.255\.255\.255 port 67\n(.*to 255\.255\.255\.255 port 67\n)+.*No DHCPOFFERS received\.\n.*No working leases in persistent database - sleeping\.\n.*DHCPDISCOVER on eth0/);
    expect(j).not.toMatch(/Internet Systems Consortium/);
    expect(lab.run('ws02', 'root', 'ip -4 addr show eth0').output).toBe('');
    expect(lab.run('ws02', 'dana', 'ping -c 1 10.0.10.53').output).toMatch(/Network is unreachable/);
    lab.run('ns1', 'root', 'systemctl start isc-dhcp-server');
    lab.run('ws02', 'root', 'sleep 300');
    expect(lab.run('ws02', 'root', 'ip -4 addr show eth0').output).toMatch(/inet 10\.0\.10\.100\/24/);
  });

  it('INIT-REBOOT: a remembered lease is requested directly; a wrong network gets a NAK', () => {
    const lab = new Lab();
    expect(lab.run('ws02', 'root', 'dhclient -v eth0').output).toMatch(/DHCPREQUEST for 10\.0\.10\.100 on eth0 to 255\.255\.255\.255 port 67\nDHCPACK of 10\.0\.10\.100/);
    lab.run('dev02', 'root', 'dhclient -r eth0');
    lab.run('dev02', 'root', "sed -i 's/fixed-address 10.0.30.100;/fixed-address 10.0.10.104;/' /var/lib/dhcp/dhclient.eth0.leases");
    const out = lab.run('dev02', 'root', 'dhclient -v eth0').output;
    expect(out).toMatch(/DHCPREQUEST for 10\.0\.10\.104[^\n]*\nDHCPNAK from 10\.0\.30\.1\nDHCPDISCOVER/);
    expect(out).toMatch(/bound to 10\.0\.30\.100/);
    expect(lab.run('ns1', 'root', 'journalctl -u isc-dhcp-server').output).toMatch(/DHCPREQUEST for 10\.0\.10\.104 from 52:54:00:e7:00:2a \(dev02\) via 10\.0\.30\.1: wrong network\.\n.*DHCPNAK on 10\.0\.10\.104/);
  });

  it('the DHCP visual runs show the relay, INIT-REBOOT, NAK and renewal', () => {
    const out = (id: string) => runVisual(DHCP_RUNS.find((r) => r.id === id)!);
    expect(out('relay').trace.some((e) => e.packet?.app?.fields.some((f) => f.name === 'Relay agent IP (giaddr)' && f.value === '10.0.30.1'))).toBe(true);
    expect(out('init-reboot').output).not.toMatch(/DHCPDISCOVER/);
    expect(out('nak').output).toMatch(/DHCPNAK from 10\.0\.30\.1/);
    expect(out('renew').trace.filter((e) => e.packet?.app?.protocol === 'DHCP').length).toBeGreaterThanOrEqual(2);
  });
});

describe('sed address ranges', () => {
  it('supports /re/,/re/, line numbers, $ and addresses in front of s', () => {
    const lab = new Lab();
    lab.run('ws01', 'alice', "echo 'a\nb\nc\nd\ne' > f.txt");
    const t = (c: string) => lab.run('ws01', 'alice', `sed '${c}' f.txt`).output;
    expect(t('/b/,/d/d')).toBe('a\ne');
    expect(t('2,3d')).toBe('a\nd\ne');
    expect(t('$d')).toBe('a\nb\nc\nd');
    expect(t('/c/s/c/X/')).toBe('a\nb\nX\nd\ne');
    expect(t('2,$s/^/-/')).toBe('a\n-b\n-c\n-d\n-e');
    expect(t('/^b$/d;s/d/D/g')).toBe('a\nc\nD\ne');
    expect(lab.run('ws01', 'alice', "sed 's/a/' f.txt").output).toMatch(/unterminated/);
  });
});

describe('DHCP lease timer review fixes', () => {
  it('rejects a non-numeric lease time and survives a zero lease time without NaN', () => {
    const lab = new Lab();
    lab.run('ns1', 'root', "sed -i 's/default-lease-time [0-9]*;/default-lease-time 1h;/' /etc/dhcp/dhcpd.conf");
    expect(lab.run('ns1', 'root', 'dhcpd -t -cf /etc/dhcp/dhcpd.conf').output).toMatch(/expecting number/);
    lab.run('ns1', 'root', "sed -i 's/default-lease-time 1h;/default-lease-time 0;/' /etc/dhcp/dhcpd.conf");
    lab.run('ns1', 'root', 'systemctl restart isc-dhcp-server');
    lab.run('ws02', 'root', 'dhclient -v eth0');
    lab.run('ws02', 'root', 'sleep 20');
    const a = lab.run('ws02', 'root', 'ip -4 addr show eth0').output;
    expect(a).not.toMatch(/NaN/);
    expect(lab.run('ws02', 'root', 'cat /var/lib/dhcp/dhclient.eth0.leases').output).not.toMatch(/NaN/);
  });

  it('removing the leased address by hand ends the binding; a static address is not "dynamic"', () => {
    const lab = new Lab();
    lab.run('ws02', 'root', 'ip addr flush dev eth0');
    lab.run('ws02', 'root', 'ip addr add 10.0.10.77/24 dev eth0');
    const a = lab.run('ws02', 'root', 'ip -4 addr show eth0').output;
    expect(a).toMatch(/inet 10\.0\.10\.77\/24 brd 10\.0\.10\.255 scope global eth0\n +valid_lft forever/);
    lab.run('ws02', 'root', 'sleep 700');
    expect(lab.run('ws02', 'root', 'ip -4 addr show eth0').output).toMatch(/10\.0\.10\.77/);
    expect(lab.run('ws02', 'root', 'journalctl -t dhclient').output).not.toMatch(/null/);
  });

  it('keeps every journal in time order across hosts over a long gap', () => {
    const lab = new Lab();
    lab.run('ws02', 'root', 'sleep 1h');
    const times = lab.run('ns1', 'root', 'journalctl -u isc-dhcp-server').output.split('\n').map((l) => l.slice(7, 15));
    for (let i = 1; i < times.length; i++) expect(times[i] >= times[i - 1], `line ${i}`).toBe(true);
  });

  it('a renewal retried between T1 and T2 succeeds once the server is back', () => {
    const lab = new Lab();
    lab.run('ns1', 'root', 'systemctl stop isc-dhcp-server');
    lab.run('ws02', 'root', 'sleep 320'); // past T1: the first renewal fails
    lab.run('ns1', 'root', 'systemctl start isc-dhcp-server');
    lab.run('ws02', 'root', 'sleep 90'); // still before T2
    const j = lab.run('ws02', 'root', 'journalctl -t dhclient -n 3').output;
    expect(j).toMatch(/to 10\.0\.10\.53 port 67\n.*DHCPACK of 10\.0\.10\.100 from 10\.0\.10\.53\n.*bound to 10\.0\.10\.100/);
  });
});

