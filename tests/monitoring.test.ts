import { describe, expect, it } from 'vitest';
import { MONITORING_LESSON } from '../src/content/ops/monitoring';
import { parseYaml } from '../src/engine/config/yaml';
import { buildSshLab } from '../src/engine/lab/sshLab';
import { findScenario } from '../src/engine/scenarios';
import { script, verifyScenario } from '../src/engine/scenarios/engine';
import { monitoringAdvance } from '../src/engine/sim/monitor';
import { evaluate, parsePromQL, type Series } from '../src/engine/sim/promql';
import { Lab } from './helpers';

const lab = () => new Lab(buildSshLab());
const PQ = (e: string) => `promtool query instant http://localhost:9090 '${e}'`;

describe('PromQL', () => {
  const s = (labels: Record<string, string>, samples: [number, number][]): Series => ({ labels, samples });
  const ds = {
    series: () => [
      s({ __name__: 'up', instance: 'a:9100', job: 'node' }, [[60_000, 1]]),
      s({ __name__: 'up', instance: 'b:9100', job: 'node' }, [[60_000, 0]]),
      s({ __name__: 'bytes_total', instance: 'a:9100' }, [[0, 0], [15_000, 1500], [30_000, 3000], [45_000, 4500], [60_000, 6000]]),
    ],
  };
  const q = (e: string) => evaluate(ds, parsePromQL(e), 60_000);

  it('filters with comparisons, keeps the name, aggregates by label', () => {
    const v = q('up == 0');
    expect(v.kind === 'vector' && v.samples.map((x) => x.labels.instance)).toEqual(['b:9100']);
    expect(v.kind === 'vector' && v.samples[0].labels.__name__).toBe('up');
    const c = q('count by (job) (up)');
    expect(c.kind === 'vector' && c.samples).toEqual([{ labels: { job: 'node' }, value: 2, t: 60_000 }]);
  });

  it('rate() of a steady counter is its slope; absent() gives the matcher labels', () => {
    const r = q('rate(bytes_total[1m])');
    expect(r.kind === 'vector' && Math.round(r.samples[0].value)).toBe(100);
    const a = q('absent(up{job="windows"})');
    expect(a.kind === 'vector' && a.samples[0].labels).toEqual({ job: 'windows' });
  });

  it('parse errors carry line:column like Prometheus', () => {
    expect(() => parsePromQL('up ==')).toThrow(/^1:6: parse error: unexpected end of input$/);
    expect(() => parsePromQL('rate(up)')).toThrow(/expected type range vector in call to function "rate"/);
    expect(() => parsePromQL('1 > 2')).toThrow(/comparisons between scalars must use BOOL modifier/);
  });
});

describe('YAML', () => {
  it('block scalars and flow maps', () => {
    const y = parseYaml('a:\n  expr: |\n    up\n      == 0\n  labels: {severity: page, team: ops}\n') as Record<string, Record<string, unknown>>;
    expect(y.a.expr).toBe('up\n  == 0\n');
    expect(y.a.labels).toEqual({ severity: 'page', team: 'ops' });
  });
});

describe('Monitoring stack in the lab', () => {
  it('every target is up at the start, and no alert fires', () => {
    const l = lab();
    expect(l.run('mon01', 'root', PQ('count(up == 1)')).output).toMatch(/^\{\} => 9 @/);
    expect(l.run('mon01', 'root', 'curl -s http://localhost:9090/api/v1/alerts').output).toBe('{"status":"success","data":{"alerts":[]}}');
  });

  it('a stopped exporter: refused, InstanceDown fires after 2 minutes and pages oncall', () => {
    const l = lab();
    script(l.world, 'srv01', ['systemctl stop prometheus-node-exporter']);
    monitoringAdvance(l.world, 4 * 60_000);
    expect(l.run('mon01', 'root', 'curl -s http://localhost:9090/api/v1/targets').output).toMatch(/"lastError":"Get \\"http:\/\/srv01\.corp\.lab:9100\/metrics\\": dial tcp 10\.0\.20\.10:9100: connect: connection refused"/);
    expect(l.run('mon01', 'root', 'amtool alert').output).toMatch(/InstanceDown +\S+ \S+ UTC +srv01\.corp\.lab:9100 of job node is down +active/);
    expect(l.run('mail01', 'root', 'grep -h "^Subject:" /home/ops/Maildir/new/*').output).toBe('Subject: [FIRING:1] InstanceDown srv01.corp.lab:9100 (node page corp)');
  });

  it('a reload with a broken file keeps the old configuration; a restart stops Prometheus', () => {
    const l = lab();
    l.run('mon01', 'root', "sed -i 's/^  scrape_interval: 15s$/  scrape_interval: 15/' /etc/prometheus/prometheus.yml");
    expect(l.run('mon01', 'root', 'promtool check config /etc/prometheus/prometheus.yml').output).toMatch(/FAILED: parsing YAML file \/etc\/prometheus\/prometheus\.yml: not a valid duration string: "15"/);
    l.run('mon01', 'root', 'systemctl reload prometheus');
    expect(l.run('mon01', 'root', 'journalctl -u prometheus -n 2').output).toMatch(/msg="Error reloading config"/);
    expect(l.run('mon01', 'root', 'systemctl is-active prometheus').output).toBe('active');
    l.run('mon01', 'root', 'systemctl restart prometheus');
    expect(l.run('mon01', 'root', 'systemctl is-active prometheus').output).toBe('failed');
  });

  it('SNMP: Debian\'s defaults on the agent, numeric OIDs without MIBs, names with -m ALL', () => {
    const l = lab();
    expect(l.run('mon01', 'root', 'snmpget -v2c -c corp-mon rtr01.corp.lab .1.3.6.1.2.1.1.5.0').output).toBe('iso.3.6.1.2.1.1.5.0 = STRING: "rtr01"');
    expect(l.run('mon01', 'root', 'snmpget -v2c -c corp-mon -m ALL rtr01.corp.lab SNMPv2-MIB::sysName.0').output).toBe('SNMPv2-MIB::sysName.0 = STRING: rtr01');
    expect(l.run('mon01', 'root', 'snmpget -v2c -c public rtr01.corp.lab .1.3.6.1.2.1.1.5.0').output).toBe('Timeout: No Response from rtr01.corp.lab');
    expect(l.run('rtr01', 'root', 'snmpget -v2c -c corp-mon localhost .1.3.6.1.2.1.1.5.0').output).toMatch(/Timeout/);
  });
});

describe('Review fixes', () => {
  it('an invalid regex in a silence or route is refused, and commands keep working', () => {
    const l = lab();
    expect(l.run('mon01', 'root', `amtool silence add 'instance=~"srv(01"' --comment=x`).output).toMatch(/error parsing regexp/);
    l.run('mon01', 'root', `sed -i 's/severity="ticket"/severity=~"tick(et"/' /etc/prometheus/alertmanager.yml`);
    expect(l.run('mon01', 'root', 'amtool check-config /etc/prometheus/alertmanager.yml').output).toMatch(/FAILED: error parsing regexp/);
    expect(l.run('mon01', 'root', 'echo still-fine').output).toBe('still-fine');
  });

  it('reloads read the --config.file the server started with; recording rules keep their samples', () => {
    const l = lab();
    l.run('mon01', 'root', 'cp /etc/prometheus/prometheus.yml /etc/prometheus/custom.yml');
    l.run('mon01', 'root', `printf 'ARGS="--config.file=/etc/prometheus/custom.yml"\\n' > /etc/default/prometheus; systemctl restart prometheus`);
    l.run('mon01', 'root', `printf '%s\\n' 'groups:' '  - name: rec' '    rules:' '      - record: job:up:sum' '        expr: sum by (job) (up)' > /etc/prometheus/rules/rec.yml`);
    l.run('mon01', 'root', "sed -i 's/^  scrape_interval: 15s$/  scrape_interval: 15s/' /etc/prometheus/custom.yml; systemctl reload prometheus");
    expect(l.run('mon01', 'root', 'journalctl -u prometheus -n 2').output).toMatch(/filename=\/etc\/prometheus\/custom\.yml/);
    l.run('mon01', 'root', 'sleep 60');
    expect(l.run('mon01', 'root', PQ('count_over_time(job:up:sum{job="node"}[5m]) > 1')).output).toMatch(/=> \d+ @/);
  });

  it('a POST to a static nginx page is 405 Not Allowed', () => {
    const l = lab();
    expect(l.run('ws01', 'alice', 'curl -s -o /dev/null -w "%{http_code}" -X POST http://srv01.corp.lab/').output).toBe('405');
  });
});

describe('Monitoring lesson: commands marked as runnable in the sandbox', () => {
  it('Deploy steps run in order (srv01 for "On srv01" steps, mon01 otherwise)', () => {
    const l = lab();
    for (const g of MONITORING_LESSON.deployment) for (const s of g.steps) {
      if (!s.simulated || !s.command) continue;
      const host = /^On srv01/.test(s.title) ? 'srv01' : 'mon01';
      const sh = l.shell(host, 'root');
      for (const c of s.command.split('\n').filter((x) => !x.startsWith('#'))) {
        const r = sh.execute(c);
        expect(r.code, `${s.title}: ${c}\n${r.output}`).toBe(0);
      }
    }
    expect(l.run('mon01', 'root', 'curl -s http://localhost:9090/api/v1/rules').output).toMatch(/"name":"RootFilesystemFillingUp"/);
  });

  it('Operate and workflow commands run without errors (each task on a fresh lab)', () => {
    const g = MONITORING_LESSON.guide!;
    const tasks = [
      ...g.management.flatMap((m) => m.tasks.filter((t) => t.sim).map((t) => ({ name: t.task, host: /srv01\)/.test(m.platform) ? 'srv01' : 'mon01', command: t.command, diagnostic: false }))),
      // Workflow commands are diagnostics: an empty answer or a refusal can be what they look for.
      ...g.workflow.filter((w) => w.sim).map((w) => ({ name: w.question, host: 'mon01', command: w.command, diagnostic: true })),
    ];
    for (const t of tasks) {
      const l = lab();
      const sh = l.shell(t.host, 'root');
      for (const c of t.command.split('\n').filter((x) => !x.startsWith('#'))) {
        const r = sh.execute(c);
        if (t.diagnostic) expect(r.output, `${t.name}: ${t.host}# ${c}`).not.toMatch(/command not found|invalid option|Invalid option|unknown long flag|syntax error|Usage:|parse error/);
        else expect(r.code, `${t.name}: ${t.host}# ${c}\n${r.output}`).toBe(0);
      }
    }
  });
});

describe('Monitoring tickets: wrong fixes are rejected', () => {
  const broken = (id: string) => {
    const s = findScenario(id)!;
    const world = buildSshLab();
    s.setup(world);
    return { s, l: new Lab(world) };
  };

  it('opening TCP 9100 on fs01 to everyone is rejected', () => {
    const { s, l } = broken('mon-fs01-firewall');
    l.run('fs01', 'root', "sed -i 's/^\\t\\tiif \"lo\" accept$/\\t\\tiif \"lo\" accept\\n\\t\\ttcp dport 9100 accept/' /etc/nftables.conf; nft -f /etc/nftables.conf");
    const v = verifyScenario(l.world, s);
    expect(v.now[0].ok).toBe(true);
    expect(v.constraints.find((c) => c.id === 'mon-port-restricted')?.ok).toBe(false);
  });

  it('removing the rule files to get Prometheus started is rejected', () => {
    const { s, l } = broken('mon-prom-timeout');
    l.run('mon01', 'root', "sed -i 's/^  scrape_timeout: 20s$/  scrape_interval: 30s\\n  scrape_timeout: 20s/; s/^  scrape_interval: 15s$//' /etc/prometheus/prometheus.yml; systemctl start prometheus");
    const v = verifyScenario(l.world, s);
    expect(v.constraints.find((c) => c.id === 'mon-config-intact')?.ok).toBe(false);
  });

  it('switching STARTTLS off for the notifications is rejected', () => {
    const { s, l } = broken('mon-am-submission');
    l.run('mon01', 'root', "sed -i 's/mail01.corp.lab:587/mail01.corp.lab:25/; s/^  smtp_hello: .*$/  smtp_hello: mon01.corp.lab\\n  smtp_require_tls: false/' /etc/prometheus/alertmanager.yml; systemctl reload prometheus-alertmanager");
    const v = verifyScenario(l.world, s);
    expect(v.constraints.find((c) => c.id === 'mon-tls-kept')?.ok).toBe(false);
  });

  it('silencing BackupTooOld instead of fixing the backups is rejected', () => {
    const { s, l } = broken('mon-backup-alert');
    l.run('mon01', 'root', 'amtool silence add alertname=BackupTooOld --duration=720h --comment="false alarm"');
    const v = verifyScenario(l.world, s);
    expect(v.passed).toBe(false);
    expect(v.constraints.find((c) => c.id === 'mon-no-broad-silence')?.ok).toBe(false);
  });

  it('answering "public" again on rtr01 is rejected', () => {
    const { s, l } = broken('snmp-dpkg-default');
    l.run('rtr01', 'root', "sed -i 's/^agentaddress  127.0.0.1,\\[::1\\]$/agentaddress udp:161/; s/^rocommunity  public default -V systemonly$/rocommunity public default\\nrocommunity corp-mon 10.0.20.55/' /etc/snmp/snmpd.conf; systemctl restart snmpd");
    const v = verifyScenario(l.world, s);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(v.constraints.find((c) => c.id === 'snmp-no-public')?.ok).toBe(false);
  });
});
