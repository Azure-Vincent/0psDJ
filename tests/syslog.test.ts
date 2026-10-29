import { describe, expect, it } from 'vitest';
import { writeFile } from '../src/engine/fs';
import { FORWARD_CONF, LOG01_REMOTE_CONF } from '../src/engine/lab/logLab';
import { buildSshLab } from '../src/engine/lab/sshLab';
import { checkGoal, rebootAll, script } from '../src/engine/scenarios/engine';
import { loadRsyslog, processMessage, type SyslogMessage } from '../src/engine/sim/syslog';
import { Lab } from './helpers';

const lab = () => new Lab(buildSshLab());
const goal = (fromHost: string, priority?: string) => ({ kind: 'syslog' as const, description: '', fromHost, server: 'log01', priority, path: `/var/log/remote/${fromHost}/%PROGRAMNAME%.log` });

describe('rsyslog: local rules', () => {
  it('Debian\'s rules split by facility: auth to auth.log, the rest to syslog', () => {
    const l = lab();
    l.run('srv01', 'root', 'logger -t app "plain message"');
    l.run('srv01', 'root', 'logger -p authpriv.notice -t pamtest "auth message"');
    const syslog = l.run('srv01', 'root', 'cat /var/log/syslog').output;
    const auth = l.run('srv01', 'root', 'cat /var/log/auth.log').output;
    expect(syslog).toMatch(/^Oct 19 \d\d:\d\d:\d\d srv01 app: plain message$/m);
    expect(syslog).not.toMatch(/auth message/);
    expect(auth).toMatch(/srv01 pamtest: auth message$/m);
    expect(auth).toMatch(/srv01 sshd\[\d+\]: /);
    expect(l.run('srv01', 'root', 'cat /var/log/user.log').output).toMatch(/app: plain message/);
  });

  it('selectors: ;FAC.none excludes, later parts override, =PRIO is exact', () => {
    const host = buildSshLab().hosts.srv01;
    writeFile(host, '/etc/rsyslog.conf', '*.*;auth,authpriv.none /var/log/a\nkern.=warning /var/log/b\n*.err;cron.none /var/log/c\n', 0);
    const l = loadRsyslog(host);
    expect(l.errors).toEqual([]);
    const m = (facility: string, severity: SyslogMessage['severity']): SyslogMessage => ({ time: 0, hostname: 'srv01', program: 'x', pid: null, facility, severity, text: `${facility}.${severity}`, fromIp: '127.0.0.1' });
    for (const msg of [m('auth', 'info'), m('daemon', 'info'), m('kern', 'warning'), m('kern', 'err'), m('cron', 'crit'), m('user', 'crit')]) processMessage(host, l, msg);
    expect(host.fs['/var/log/a'].content).not.toMatch(/auth\.info/);
    expect(host.fs['/var/log/a'].content).toMatch(/daemon\.info/);
    expect(host.fs['/var/log/b'].content.trim().split('\n').map((x) => x.split(': ')[1])).toEqual(['kern.warning']);
    expect(host.fs['/var/log/c'].content.trim().split('\n').map((x) => x.split(': ')[1])).toEqual(['kern.err', 'user.crit']);
  });

  it('rsyslogd -N1 reports skipped lines the way rsyslog does', () => {
    const l = lab();
    writeFile(l.world.hosts.srv01, '/etc/rsyslog.d/90-bad.conf', '$FooBar on\ninput(type="imtcp" port="514")\n', l.world.clock);
    const r = l.run('srv01', 'root', 'rsyslogd -N1');
    expect(r.code).toBe(1);
    expect(r.output).toMatch(/invalid or yet-unknown config file command 'FooBar' - have you forgotten to load a module\?/);
    expect(r.output).toMatch(/input module name 'imtcp' is unknown/);
  });
});

describe('rsyslog: central logging to log01', () => {
  it('every sender reaches log01 over TCP and is filed per host and program', () => {
    const l = lab();
    expect(l.run('log01', 'root', 'ls /var/log/remote').output.split(/\s+/)).toEqual(['dock01', 'fs01', 'mail01', 'ns1', 'rtr01', 'srv01']);
    for (const h of ['srv01', 'ns1', 'rtr01', 'dock01', 'fs01', 'mail01']) expect(checkGoal(l.world, goal(h)).ok, h).toBe(true);
    expect(checkGoal(l.world, goal('srv01', 'authpriv.notice')).ok).toBe(true);
    // log01 keeps remote messages out of its own files ("& stop").
    l.run('srv01', 'root', 'logger -t marker "only remote"');
    l.run('log01', 'root', 'true');
    expect(l.run('log01', 'root', 'cat /var/log/syslog').output).not.toMatch(/only remote/);
    expect(l.run('log01', 'root', 'cat /var/log/remote/srv01/marker.log').output).toMatch(/^Oct 19 \d\d:\d\d:\d\d srv01 marker: only remote$/);
  });

  it('a firewall drop suspends the action, the queue keeps the messages, and they arrive after the fix', () => {
    const l = lab();
    l.run('log01', 'root', 'nft insert rule inet filter input tcp dport 514 drop');
    l.run('srv01', 'root', 'logger -t during "logged during the outage"');
    l.run('srv01', 'root', 'true');
    expect(l.run('srv01', 'root', 'journalctl -u rsyslog').output).toMatch(/cannot connect to log01\.corp\.lab:514: Connection timed out[\s\S]*action 'action-1-builtin:omfwd' suspended/);
    l.run('log01', 'root', 'systemctl restart nftables');
    l.run('srv01', 'root', 'true');
    expect(l.run('log01', 'root', 'cat /var/log/remote/srv01/during.log').output).toMatch(/logged during the outage/);
    expect(l.run('srv01', 'root', 'journalctl -u rsyslog').output).toMatch(/action 'action-1-builtin:omfwd' resumed/);
  });

  it('without a queue, messages logged while the action is suspended are lost', () => {
    const l = lab();
    writeFile(l.world.hosts.srv01, '/etc/rsyslog.d/50-central.conf', '*.* @@log01.corp.lab:514\n', l.world.clock);
    script(l.world, 'srv01', ['systemctl restart rsyslog']);
    l.run('log01', 'root', 'systemctl stop rsyslog');
    l.run('srv01', 'root', 'logger -t lost "first"');
    l.run('srv01', 'root', 'logger -t lost "second"');
    l.run('log01', 'root', 'systemctl start rsyslog');
    l.run('srv01', 'root', 'logger -t lost "third"');
    l.run('log01', 'root', 'true');
    const got = l.run('log01', 'root', 'cat /var/log/remote/srv01/lost.log').output;
    expect(got).not.toMatch(/second/);
    expect(got).toMatch(/third/);
  });

  it('UDP to a closed port is lost silently, with ICMP port unreachable on the wire', () => {
    const l = lab();
    writeFile(l.world.hosts.ns1, '/etc/rsyslog.d/50-central.conf', '*.* @log01.corp.lab:514\n', l.world.clock);
    script(l.world, 'ns1', ['systemctl restart rsyslog']);
    writeFile(l.world.hosts.log01, '/etc/rsyslog.d/10-remote.conf', LOG01_REMOTE_CONF.replace('module(load="imudp")\ninput(type="imudp" port="514")\n', ''), l.world.clock);
    script(l.world, 'log01', ['systemctl restart rsyslog']);
    l.run('ns1', 'root', 'logger -t udp "datagram"');
    l.run('log01', 'root', 'true');
    expect(l.run('ns1', 'root', 'journalctl -u rsyslog').output).not.toMatch(/suspended/);
    const dump = l.run('log01', 'root', 'tcpdump -n -i eth0 udp port 514 or icmp').output;
    expect(dump).toMatch(/IP 10\.0\.10\.53\.\d+ > 10\.0\.20\.50\.514: SYSLOG user\.notice, length: \d+/);
    expect(dump).toMatch(/ICMP 10\.0\.20\.50 udp port 514 unreachable/);
  });

  it('logger -n sends straight to the server; forwarding survives a reboot', () => {
    const l = lab();
    l.run('ws01', 'alice', 'logger -n log01.corp.lab "direct over udp"');
    expect(l.run('log01', 'root', 'cat /var/log/remote/ws01/alice.log').output).toMatch(/ws01 alice: direct over udp/);
    const w = rebootAll(l.world);
    expect(checkGoal(w, goal('srv01')).ok).toBe(true);
    expect(FORWARD_CONF).toMatch(/queue\.type="LinkedList"/);
  });
});
