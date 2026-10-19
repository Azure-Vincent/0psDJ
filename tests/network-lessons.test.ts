import { describe, expect, it } from 'vitest';
import { IP_ASSESSMENT, TRANSPORT_ASSESSMENT } from '../src/content/network/assessments';
import { LESSONS } from '../src/content/lessons';
import { CONCEPTS } from '../src/content/concepts';
import { IP_RUNS, TRANSPORT_RUNS, runVisual } from '../src/engine/lab/visualRuns';
import { gradeQuestion } from '../src/learning/grading';
import { Lab } from './helpers';

describe('module A content', () => {
  it('registers both lessons and every concept review link points to an existing lesson', () => {
    expect(LESSONS.map((l) => l.id)).toEqual(expect.arrayContaining(['ipnet', 'transport']));
    for (const c of Object.values(CONCEPTS)) {
      const [, id] = c.review.split('/');
      expect(LESSONS.some((l) => l.id === id), c.review).toBe(true);
    }
  });
  it('grades subnet and transport answers', () => {
    const q = (a: typeof IP_ASSESSMENT, id: string) => a.questions.find((x) => x.id === id)!;
    expect(gradeQuestion(q(IP_ASSESSMENT, 'ip-q-broadcast'), '172.16.5.191').correct).toBe(true);
    expect(gradeQuestion(q(IP_ASSESSMENT, 'ip-q-hosts'), '30').correct).toBe(true);
    expect(gradeQuestion(q(IP_ASSESSMENT, 'ip-q-lpm'), 2).correct).toBe(true);
    expect(gradeQuestion(q(IP_ASSESSMENT, 'ip-q-cmd'), 'ip r get 10.0.20.10').correct).toBe(true);
    expect(gradeQuestion(q(TRANSPORT_ASSESSMENT, 'tr-q-ack'), '1201').correct).toBe(true);
    expect(gradeQuestion(q(TRANSPORT_ASSESSMENT, 'tr-q-timeout'), '127').correct).toBe(true);
  });
});

describe('module A visual runs', () => {
  const expected: Record<string, RegExp> = {
    onlink: /ttl=64/, routed: /ttl=63/, traceroute: /^ 2 {2}10\.0\.20\.10 /m, 'wrong-mask': /From 10\.0\.10\.25 icmp_seq=1 Destination Host Unreachable/,
    'wrong-gw': /From 10\.0\.10\.25 .*Unreachable/, 'no-forward': /From 10\.0\.10\.1 icmp_seq=1 Destination Host Unreachable/, 'no-return': /100% packet loss/,
    'tcp-life': /200 OK/, 'tcp-refused': /Couldn't connect/, 'tcp-timeout': /timed out/, 'udp-dns': /CNAME/, 'udp-unreach': /connection refused/,
    'search-list': /^$/, 'loopback-bind': /Couldn't connect/,
  };
  it.each([...IP_RUNS, ...TRANSPORT_RUNS].map((r) => r.id))('%s', (id) => {
    const run = [...IP_RUNS, ...TRANSPORT_RUNS].find((r) => r.id === id)!;
    const v = runVisual(run);
    expect(v.output).toMatch(expected[id]);
    expect(v.trace.length).toBeGreaterThan(0);
  });
  it('routed ping shows ARP for the gateway, not for the destination, and a new frame per hop', () => {
    const v = runVisual(IP_RUNS.find((r) => r.id === 'routed')!);
    const arps = v.trace.filter((e) => e.kind === 'arp' && e.arp?.op === 'request').map((e) => `${e.from}:${e.arp!.targetIp}`);
    expect(arps).toEqual(['ws01:10.0.10.1', 'rtr01:10.0.20.10']);
    const req = v.trace.find((e) => e.packet?.icmp?.type === 8)!;
    const macs = req.hops!.filter((h) => h.srcMac).map((h) => `${h.srcMac}>${h.dstMac}`);
    expect(macs).toEqual(['52:54:00:d4:00:19>52:54:00:a1:00:01', '52:54:00:a1:00:02>52:54:00:c3:00:0a']);
  });
  it('the search-list run queries corp.lab first, then the bare name', () => {
    const v = runVisual(TRANSPORT_RUNS.find((r) => r.id === 'search-list')!);
    const qs = v.trace.filter((e) => e.packet?.app?.protocol === 'DNS' && e.from === 'ws01').map((e) => e.title);
    expect(qs[0]).toBe('DNS query: A nosuchhost.corp.lab.');
    expect(qs.some((t) => t === 'DNS query: A nosuchhost.')).toBe(true);
  });
});

describe('new shell features', () => {
  it('ip addr add/del changes reachability; nginx -t validates listen directives', () => {
    const lab = new Lab();
    lab.run('ws01', 'root', 'ip addr del 10.0.10.25/24 dev eth0');
    expect(lab.run('ws01', 'alice', 'ping -c 1 10.0.10.53').output).toMatch(/Network is unreachable/);
    lab.run('ws01', 'root', 'ip addr add 10.0.10.25/24 dev eth0');
    lab.run('ws01', 'root', 'ip route add default via 10.0.10.1');
    expect(lab.run('ws01', 'alice', 'ping -c 1 10.0.20.10').output).toMatch(/1 received/);
    lab.run('srv01', 'root', "sed -i 's/listen 80 default_server;/listen 80x default_server;/' /etc/nginx/nginx.conf");
    expect(lab.run('srv01', 'root', 'nginx -t').output).toMatch(/invalid port in "80x"/);
    expect(lab.run('srv01', 'root', 'systemctl reload nginx').code).toBe(1);
    expect(lab.run('srv01', 'root', 'ss -tln').output).toMatch(/0\.0\.0\.0:80/);
  });
  it('sudo nano saves with root permissions', () => {
    const lab = new Lab();
    const sh = lab.shell('ws01', 'alice');
    const r = sh.execute('sudo nano /etc/resolv.conf', ['ws01-alice']);
    expect(r.editor?.user).toBe('root');
    expect(sh.saveFile(r.editor!, 'nameserver 10.0.10.53\n')).toBeNull();
  });
});
