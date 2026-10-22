import { describe, expect, it } from 'vitest';
import { findScenario } from '../src/engine/scenarios';
import { Lab } from './helpers';

describe('network interfaces', () => {
  it('shows admin state, carrier and kernel attributes', () => {
    const lab = new Lab();
    expect(lab.run('srv01', 'root', 'ip link show eth0').output).toMatch(/2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 .*state UP[\s\S]*altname enp1s0/);
    expect(lab.run('srv01', 'root', 'cat /sys/class/net/eth0/operstate /sys/class/net/eth0/carrier /sys/class/net/eth0/type').output).toBe('up\n1\n1');
    expect(lab.run('srv01', 'root', 'ls /sys/class/net').output).toBe('eth0  lo');
    lab.run('srv01', 'root', 'ip link set eth0 down');
    expect(lab.run('srv01', 'root', 'ip -br link').output).toMatch(/eth0 +DOWN +52:54:00:c3:00:0a <BROADCAST,MULTICAST>/);
    expect(lab.run('srv01', 'root', 'cat /sys/class/net/eth0/carrier').output).toBe('cat: /sys/class/net/eth0/carrier: Invalid argument');
    expect(lab.run('srv01', 'root', 'cat /sys/class/net/eth0/operstate').output).toBe('down');
  });

  it('creates and deletes dummy interfaces; other types explain they are not simulated', () => {
    const lab = new Lab();
    lab.run('srv01', 'root', 'ip link add dummy0 type dummy');
    lab.run('srv01', 'root', 'ip addr add 192.0.2.1/32 dev dummy0');
    lab.run('srv01', 'root', 'ip link set dummy0 up');
    const out = lab.run('srv01', 'root', 'ip addr show dummy0').output;
    expect(out).toMatch(/dummy0: <BROADCAST,NOARP,UP,LOWER_UP> .*state UNKNOWN/);
    expect(out).toMatch(/inet 192\.0\.2\.1\/32 scope global dummy0/);
    lab.run('srv01', 'root', 'ip link del dummy0');
    expect(lab.run('srv01', 'root', 'ip link show dummy0').output).toBe('Device "dummy0" does not exist.');
    expect(lab.run('srv01', 'root', 'ip link add br9 type bridge').output).toMatch(/not simulated/);
  });

  it('lists the bridge device and its members on sw01', () => {
    const lab = new Lab();
    expect(lab.run('sw01', 'root', 'ip -br link').output).toMatch(/\nbr0 +UP/);
    expect(lab.run('sw01', 'root', 'ip -d link show br0').output).toMatch(/stp_state 1 .*vlan_filtering 1/);
    expect(lab.run('sw01', 'root', 'ip -d link show swp6').output).toMatch(/master br0[\s\S]*bridge_slave state forwarding/);
  });

  it('renamed NIC: ifupdown fails with "Cannot find device", and the host is unreachable', () => {
    const lab = new Lab();
    findScenario('netif-renamed-nic')!.setup(lab.world);
    expect(lab.run('srv01', 'root', 'ip -br link').output).toMatch(/ens18 +DOWN/);
    expect(lab.run('srv01', 'root', 'journalctl -u networking -b').output).toMatch(/ifup: Cannot find device "eth0"[\s\S]*Failed to start networking\.service/);
    expect(lab.run('ws01', 'alice', 'curl -I http://srv01.corp.lab/').output).toMatch(/No route to host/);
    lab.run('srv01', 'root', "sed -i 's/eth0/ens18/g' /etc/network/interfaces");
    lab.run('srv01', 'root', 'systemctl restart networking');
    expect(lab.run('srv01', 'root', 'ip -br addr').output).toMatch(/ens18 +UP +10\.0\.20\.10\/24/);
    expect(lab.run('ws01', 'alice', 'curl -I http://srv01.corp.lab/').output).toMatch(/^HTTP\/1\.1 200 OK/);
  });

  it('a port missing from bridge-ports has carrier but is switched nowhere', () => {
    const lab = new Lab();
    findScenario('netif-bridge-port')!.setup(lab.world);
    expect(lab.run('sw01', 'root', 'bridge link').output).not.toMatch(/swp6/);
    expect(lab.run('sw01', 'root', 'ip -d link show swp6').output).not.toMatch(/master br0/);
    expect(lab.run('srv01', 'root', 'ip -br link').output).toMatch(/eth0 +UP/);
    lab.run('srv01', 'root', 'ping -c 1 10.0.20.1');
    expect(lab.run('srv01', 'root', 'ip neigh').output).toMatch(/10\.0\.20\.1 dev eth0 FAILED/);
  });
});
