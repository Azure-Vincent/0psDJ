import { describe, expect, it } from 'vitest';
import { readFile, writeFile } from '../src/engine/fs';
import { buildSshLab } from '../src/engine/lab/sshLab';
import { checkGoal, rebootAll, script } from '../src/engine/scenarios/engine';
import { parseChronyConf, chronyAllows, ntpSettle } from '../src/engine/sim/ntp';
import { Lab } from './helpers';

const lab = () => new Lab(buildSshLab());

describe('NTP chain: ext01 (stratum 1) → rtr01 chrony (stratum 2) → timesyncd clients', () => {
  it('the baseline converges: rtr01 follows ext01, every client is synchronized through rtr01', () => {
    const l = lab();
    expect(l.run('rtr01', 'root', 'chronyc tracking').output).toMatch(/^Reference ID {4}: CB007150 \(203\.0\.113\.80\)\nStratum {9}: 2\n[\s\S]*Leap status {5}: Normal$/);
    expect(l.run('rtr01', 'root', 'chronyc sources').output).toMatch(/^\^\* 203\.0\.113\.80 +1 +6 +377 /m);
    expect(l.run('ext01', 'guest', 'chronyc tracking').output).toMatch(/^Reference ID {4}: 47505300 \(GPS\)\nStratum {9}: 1/);
    for (const h of ['ws01', 'srv01', 'dev01', 'dev02', 'ns1', 'dock01']) {
      expect(checkGoal(l.world, { kind: 'time', host: h, description: '' }).ok, h).toBe(true);
    }
    expect(l.run('ws01', 'alice', 'timedatectl timesync-status').output).toMatch(/Server: 10\.0\.10\.1 \(rtr01\.corp\.lab\)\n[\s\S]*Leap: normal\n[\s\S]*Stratum: 2/);
    expect(l.run('srv01', 'root', 'journalctl -u systemd-timesyncd').output).toMatch(/Contacted time server 10\.0\.10\.1:123 \(rtr01\.corp\.lab\)\.\n.*Initial clock synchronization to/);
  });

  it('real datagrams: tcpdump on rtr01 shows client requests and server replies on UDP 123', () => {
    const l = lab();
    l.run('ws01', 'root', 'systemctl restart systemd-timesyncd');
    const dump = l.run('rtr01', 'root', 'tcpdump -n -i eth0 -c 2 udp port 123').output;
    expect(dump).toMatch(/IP 10\.0\.10\.25\.\d+ > 10\.0\.10\.1\.123: NTPv4, Client, length 48\n.*IP 10\.0\.10\.1\.123 > 10\.0\.10\.25\.\d+: NTPv4, Server, length 48/);
  });

  it('a client follows the server\'s clock, including its error (time comes from upstream)', () => {
    const l = lab();
    l.world.hosts.ws01.clockOffset = 7 * 60_000;
    ntpSettle(l.world);
    expect(l.world.hosts.ws01.clockOffset).toBeLessThan(5);
  });

  it('chronyd drops clients outside its allow list silently and counts them', () => {
    const l = lab();
    const conf = readFile(l.world.hosts.rtr01, '/etc/chrony/chrony.conf')!.replace('allow 10.0.30.0/24\n', '');
    writeFile(l.world.hosts.rtr01, '/etc/chrony/chrony.conf', conf, l.world.clock);
    script(l.world, 'rtr01', ['systemctl restart chrony']);
    l.run('dev01', 'root', 'systemctl restart systemd-timesyncd');
    expect(l.run('dev01', 'root', 'journalctl -u systemd-timesyncd').output).toMatch(/Timed out waiting for reply from 10\.0\.10\.1:123 \(rtr01\.corp\.lab\)\.$/m);
    expect(l.run('rtr01', 'root', 'chronyc clients').output).toMatch(/^10\.0\.30\.25 +0 +[1-9]/m);
  });

  it('an unsynchronized server answers with leap 3 / stratum 16 and clients reject it without logging', () => {
    const l = lab();
    const conf = readFile(l.world.hosts.rtr01, '/etc/chrony/chrony.conf')!.replace('server 203.0.113.80', 'server 203.0.113.8');
    writeFile(l.world.hosts.rtr01, '/etc/chrony/chrony.conf', conf, l.world.clock);
    script(l.world, 'rtr01', ['systemctl restart chrony']);
    l.run('ws01', 'root', 'systemctl restart systemd-timesyncd');
    expect(l.run('ws01', 'root', 'timedatectl timesync-status').output).toMatch(/Leap: not synchronized\n[\s\S]*Stratum: 16/);
    expect(l.run('ws01', 'root', 'timedatectl').output).toMatch(/System clock synchronized: no\n {14}NTP service: active/);
    expect(l.run('rtr01', 'root', 'chronyc sources').output).toMatch(/^\^\? 203\.0\.113\.8 +0 +6 +0 +-/m);
    expect(l.run('rtr01', 'root', 'journalctl -u chrony').output).toMatch(/Can't synchronise: no selectable sources/);
    // "local stratum" makes rtr01 serve its own clock again (the workaround the tickets forbid).
    writeFile(l.world.hosts.rtr01, '/etc/chrony/chrony.conf', `${conf}local stratum 10\n`, l.world.clock);
    script(l.world, 'rtr01', ['systemctl restart chrony']);
    l.run('ws01', 'root', 'systemctl restart systemd-timesyncd');
    expect(l.run('ws01', 'root', 'timedatectl timesync-status').output).toMatch(/Stratum: 10\n {4}Reference: 7F7F0101/);
  });

  it('an invalid chrony.conf stops chronyd; clients get port unreachable', () => {
    const l = lab();
    writeFile(l.world.hosts.rtr01, '/etc/chrony/chrony.conf', 'server 203.0.113.80 iburst\nalow 10.0.10.0/24\n', l.world.clock);
    expect(l.run('rtr01', 'root', 'systemctl restart chrony').code).not.toBe(0);
    expect(l.run('rtr01', 'root', 'journalctl -u chrony').output).toMatch(/Fatal error : Invalid directive at line 2 in file \/etc\/chrony\/chrony\.conf/);
    expect(l.run('rtr01', 'root', 'chronyc tracking').output).toBe('506 Cannot talk to daemon');
  });

  it('time sync survives a reboot of every machine', () => {
    const w = rebootAll(buildSshLab());
    expect(checkGoal(w, { kind: 'time', host: 'ws01', description: '' }).ok).toBe(true);
  });

  it('chrony.conf parsing and access rules', () => {
    const p = parseChronyConf('pool 2.debian.pool.ntp.org iburst\nallow 10.0.0.0/16\ndeny 10.0.30.0/24\nmakestep 1 3\n');
    expect(p.loaded!.sources[0].name).toBe('2.debian.pool.ntp.org');
    expect(chronyAllows(p.loaded!, '10.0.10.25')).toBe(true);
    expect(chronyAllows(p.loaded!, '10.0.30.25')).toBe(false);
    expect(chronyAllows(p.loaded!, '192.0.2.1')).toBe(false);
    expect(parseChronyConf('allow 10.0.0.0/33\n').error).toBe('Fatal error : Could not parse allow directive at line 1 in file /etc/chrony/chrony.conf');
  });
});
