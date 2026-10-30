// Lab 9: Monitoring a Server. A new web server, web02 (the status page), went
// into production unmonitored. The learner brings it under the same monitoring
// as the other servers: node_exporter with the systemd collector, the scrape
// port open to mon01 only, a Prometheus target added safely (check, reload), an
// alert rule for nginx, an end-to-end test of the page, SNMPv3 polling without
// the public community, and a reboot test.

import { mkdir, writeFile } from '../fs';
import { addUser, createHost, staticInterfaces } from '../lab/builder';
import { TIMESYNCD_CONF } from '../lab/krbLab';
import { installRsyslog } from '../lab/logLab';
import { installNodeExporter, MON01_IP, PROMETHEUS_YML, SNMP_V3 } from '../lab/monLab';
import { trustCorpRoot } from '../lab/pkiLab';
import { buildSshLab, CORP_ZONE, DEBIAN_SSHD_CONFIG, installHostKeys, SW01_INTERFACES } from '../lab/sshLab';
import { script } from '../scenarios/engine';
import { recomputeL2 } from '../sim/l2';
import type { PromLoaded } from '../sim/monitor';
import { bootHost } from '../sim/services';
import { DEBIAN_SNMPD_CONF } from '../sim/snmp';
import { Shell } from '../shell/shell';
import type { World } from '../types';
import { NO, OK, printfTo, probe } from './engine';
import type { GuidedLab, LabCheck } from './types';

export const WEB02_IP = '10.0.20.12';
export const WEB02_ALICE = 'web02-alice';
const TARGET = 'web02.corp.lab:9100';
const PROM = 'http://localhost:9090';

const LAB9_ZONE = CORP_ZONE.replace('2026101901 ; serial', '2026101904 ; serial').replace('srv01   IN AAAA 2001:db8:20::10\n', `srv01   IN AAAA 2001:db8:20::10\nweb02   IN A    ${WEB02_IP}\nstatus  IN CNAME web02\n`);

const WEB02_NFT = `#!/usr/sbin/nft -f

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iif "lo" accept
		meta l4proto icmp accept
		tcp dport { 22, 80 } accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

const WEB02_NGINX = `user www-data;
worker_processes auto;
http {
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name status.corp.lab web02.corp.lab;
        root /var/www/html;
    }
}
`;

export function buildLab9World(): World {
  const world = buildSshLab();
  const t = world.clock;
  const sw = world.hosts.sw01;
  sw.ifaces.push({ name: 'swp21', mac: '52:54:00:5e:00:15', segment: null, address: null, prefix: null, up: false, staticSegment: null, addrs6: [] });
  writeFile(sw, '/etc/network/interfaces', SW01_INTERFACES
    .replace('auto br0\n', 'auto swp21\niface swp21\n    alias web02 (status page)\n    bridge-access 20\n\nauto br0\n')
    .replace(/(bridge-ports .*)\n/, '$1 swp21\n'), t);
  world.links = [...(world.links ?? []), { a: { host: 'web02', iface: 'eth0' }, b: { host: 'sw01', iface: 'swp21' } }];
  writeFile(world.hosts.ns1, '/etc/bind/db.corp.lab', LAB9_ZONE, t, { group: 'bind' });

  const h = createHost(world, {
    id: 'web02', hostname: 'web02', domain: 'corp.lab', role: 'Status page web server (new: not monitored yet)',
    ifaces: [{ name: 'eth0', mac: '52:54:00:3b:00:0c', segment: null }],
    services: ['rsyslog', 'systemd-timesyncd', 'nftables', 'ssh', 'nginx', 'snmpd'],
  });
  writeFile(h, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: `${WEB02_IP}/24`, gateway: '10.0.20.1' }]), t);
  writeFile(h, '/etc/resolv.conf', 'search corp.lab\nnameserver 10.0.10.53\n', t);
  writeFile(h, '/etc/ssh/sshd_config', DEBIAN_SSHD_CONFIG, t);
  writeFile(h, '/etc/nftables.conf', WEB02_NFT, t, { mode: 0o755 });
  mkdir(h, '/etc/systemd', t);
  writeFile(h, '/etc/systemd/timesyncd.conf', TIMESYNCD_CONF, t);
  installHostKeys(h, t);
  trustCorpRoot(h, t);
  installRsyslog(h, t, true);
  addUser(h, { name: 'alice', uid: 1000, gid: 1000, primaryGroup: 'alice', groups: ['sudo', 'adm'], home: '/home/alice', shell: '/bin/bash', gecos: 'Alice Admin', password: WEB02_ALICE }, t);
  mkdir(h, '/etc/nginx', t);
  writeFile(h, '/etc/nginx/nginx.conf', WEB02_NGINX, t);
  for (const d of ['/var/www', '/var/www/html']) if (!h.fs[d]) mkdir(h, d, t);
  writeFile(h, '/var/www/html/index.html', '<!doctype html>\n<title>corp.lab status</title>\n<h1>All systems operational</h1>\n', t);
  // The packages are installed with Debian's defaults: node_exporter without the systemd
  // collector (and no firewall opening), snmpd listening on localhost with "public".
  if (!h.fs['/var/lib']) mkdir(h, '/var/lib', t);
  installNodeExporter(h, t);
  writeFile(h, '/etc/default/prometheus-node-exporter', '# Set the command-line arguments to pass to the server.\n# Due to shell escaping, to pass backslashes for regexes, you need to double\n# them (\\\\d for \\d). If running under systemd, you need to double them again\n# (\\\\\\\\d to mean \\d), and escape newlines too.\nARGS=""\n', t);
  writeFile(h, '/etc/nftables.conf', WEB02_NFT, t, { mode: 0o755 });
  mkdir(h, '/etc/snmp', t);
  mkdir(h, '/etc/snmp/snmpd.conf.d', t);
  writeFile(h, '/etc/snmp/snmpd.conf', DEBIAN_SNMPD_CONF, t, { mode: 0o600 });
  mkdir(h, '/var/lib/snmp', t, { mode: 0o755, owner: 'root', group: 'root' });

  recomputeL2(world);
  script(world, 'sw01', ['ifreload -a']);
  script(world, 'ns1', ['rndc reload']);
  bootHost(world, h);
  world.clock += 5 * 60_000;
  return world;
}

// ---------------------------------------------------------------- checks

/** Several command lines on one copy of the world (time passes between them, as for the learner). */
function steps(world: World, lines: [string, string][]): { output: string; code: number } {
  let w = structuredClone(world);
  let last = { output: '', code: 0 };
  for (const [host, line] of lines) {
    const sh = new Shell(() => w, (n) => (w = n), { hostId: host, user: 'root', cwd: w.hosts[host].users.root?.home ?? '/root' });
    const r = sh.execute(line);
    last = { output: r.output, code: r.code };
  }
  return last;
}

const exporterReady: LabCheck = {
  id: 'exporter', description: 'node_exporter on web02 runs with the systemd collector, enabled at boot',
  check(w) {
    const rt = w.hosts.web02.services['prometheus-node-exporter'];
    if (!rt || rt.state !== 'active') return NO('prometheus-node-exporter is not running on web02 (systemctl status prometheus-node-exporter).');
    if (!rt.enabled) return NO('prometheus-node-exporter is not enabled at boot.');
    const m = probe(w, 'web02', 'root', 'curl -s localhost:9100/metrics').output;
    if (!/node_systemd_unit_state\{name="nginx\.service"/.test(m)) return NO('The metrics have no node_systemd_unit_state: add --collector.systemd to ARGS in /etc/default/prometheus-node-exporter and restart the exporter.');
    return OK('node_exporter serves the systemd unit states on :9100.');
  },
};

const scrapeOpen: LabCheck = {
  id: 'firewall', description: 'web02\'s firewall lets mon01 (and only mon01) reach TCP 9100',
  check(w) {
    const fromMon = probe(w, 'mon01', 'root', 'curl -s -m 5 http://web02.corp.lab:9100/metrics');
    if (fromMon.code !== 0 || !/node_/.test(fromMon.output)) return NO(`mon01 cannot fetch http://web02.corp.lab:9100/metrics (${fromMon.output.trim().split('\n').pop()}): add "ip saddr ${MON01_IP} tcp dport 9100 accept" to web02's /etc/nftables.conf and load it.`);
    const fromWs = probe(w, 'ws01', 'alice', 'curl -s -m 5 http://web02.corp.lab:9100/metrics');
    if (fromWs.code === 0) return NO('ws01 can read web02\'s metrics too: allow TCP 9100 from mon01 only.');
    return OK('mon01 reaches :9100; the office does not.');
  },
};

const targetAdded: LabCheck = {
  id: 'target', description: `Prometheus scrapes ${TARGET} in the node job, and it is up`,
  check(w) {
    const l = w.hosts.mon01.services.prometheus?.loaded as PromLoaded | null;
    if (!l) return NO('Prometheus is not running on mon01 (systemctl status prometheus, journalctl -u prometheus).');
    const job = l.config.scrapes.find((s) => s.targets.some((t) => t.address === TARGET));
    if (!job) return NO(`Prometheus's running configuration has no target ${TARGET}: add it to the node job in /etc/prometheus/prometheus.yml, promtool check config, then systemctl reload prometheus.`);
    if (job.job !== 'node') return NO(`${TARGET} is in the job "${job.job}": put it in the node job, where the alert rules expect node_exporter targets.`);
    if (!l.reloadOk) return NO('The last reload failed (journalctl -u prometheus): Prometheus still runs an older configuration.');
    const up = steps(w, [['mon01', 'sleep 20'], ['mon01', `promtool query instant ${PROM} 'up{instance="${TARGET}"}'`]]);
    if (!/=> 1 @/.test(up.output)) return NO(`up{instance="${TARGET}"} is not 1: ${up.output.trim() || 'no data'} (curl -s localhost:9090/api/v1/targets shows the error).`);
    return OK(`${TARGET} is scraped (up = 1).`);
  },
};

function nginxRule(w: World) {
  const l = w.hosts.mon01.services.prometheus?.loaded as PromLoaded | null;
  return l?.config.rules.find((r) => r.kind === 'alert' && /nginx\.service/.test(r.expr));
}

const ruleWritten: LabCheck = {
  id: 'rule', description: 'An alert rule pages (severity=page) when nginx stops on web02, after at most 5 minutes',
  check(w) {
    const r = nginxRule(w);
    if (!r) return NO('Prometheus has no loaded alert rule about nginx.service: write it in /etc/prometheus/rules/web.yml, promtool check rules, systemctl reload prometheus.');
    if (r.labels.severity !== 'page') return NO(`The rule ${r.name} has severity "${r.labels.severity ?? ''}": a stopped status page should page (severity: page).`);
    if (r.forMs > 5 * 60_000) return NO(`for: ${r.forMs / 60_000}m is too long for a page; 1–5 minutes avoids flapping without hiding outages.`);
    const firing = steps(w, [['web02', 'systemctl stop nginx'], ['mon01', 'sleep 30'], ['mon01', `sleep ${Math.ceil(r.forMs / 1000) + 60}`], ['mon01', `promtool query instant ${PROM} 'ALERTS{alertname="${r.name}",alertstate="firing"}'`]]);
    if (!firing.output.includes('web02')) return NO(`With nginx stopped on web02 the rule ${r.name} does not fire for web02 (test the expression: promtool query instant ${PROM} '${r.expr}').`);
    const quiet = probe(w, 'mon01', 'root', `promtool query instant ${PROM} 'ALERTS{alertname="${r.name}"}'`);
    if (quiet.output.includes('web02') && w.hosts.web02.services.nginx?.state === 'active') return NO(`${r.name} is active although nginx runs: check the expression.`);
    return OK(`${r.name} fires when nginx stops on web02.`);
  },
};

const pageTested: LabCheck = {
  id: 'test-page', description: 'The page was tested end to end: a firing mail for the nginx alert reached the ops mailbox, and nginx runs again',
  check(w) {
    const r = nginxRule(w);
    if (!r) return NO('Write the alert rule first.');
    const box = Object.entries(w.hosts.mail01.fs).filter(([p, n]) => p.startsWith('/home/ops/Maildir/') && n.type === 'file');
    if (!box.some(([, n]) => n.content.includes(`[FIRING:1] ${r.name}`))) return NO(`No "[FIRING:1] ${r.name}" mail in the ops mailbox on mail01 yet: stop nginx on web02, wait until the alert fires and Alertmanager sends it (2–3 minutes: sleep 180), then look in /home/ops/Maildir/new.`);
    if (w.hosts.web02.services.nginx?.state !== 'active') return NO('nginx is still stopped on web02: start it again (systemctl start nginx).');
    return OK('The page arrived; nginx runs again.');
  },
};

const snmpReady: LabCheck = {
  id: 'snmp', description: 'mon01 polls web02 with SNMPv3 (user monitor, authPriv); the public community and other hosts get nothing',
  check(w) {
    const v3 = `snmpget -v3 -l authPriv -u ${SNMP_V3.user} -a SHA -A ${SNMP_V3.auth} -x AES -X ${SNMP_V3.priv} web02.corp.lab .1.3.6.1.2.1.1.5.0`;
    const ok = probe(w, 'mon01', 'root', v3);
    if (!/STRING: "web02"/.test(ok.output)) return NO(`From mon01, "${v3}" gives: ${ok.output.trim().split('\n').pop()}`);
    const walk = probe(w, 'mon01', 'root', v3.replace('snmpget', 'snmpwalk').replace('.1.3.6.1.2.1.1.5.0', '.1.3.6.1.2.1.2.2.1.2'));
    if (!/STRING: "eth0"/.test(walk.output)) return NO('SNMPv3 works, but the interface table (IF-MIB, .1.3.6.1.2.1.2) is not visible: give the user a view that includes it (e.g. view all included .1; rouser monitor authpriv -V all).');
    const pub = probe(w, 'mon01', 'root', 'snmpget -v2c -c public web02.corp.lab .1.3.6.1.2.1.1.5.0');
    if (pub.code === 0) return NO('web02 still answers the community "public" from the network: remove the rocommunity public lines (SNMPv3 only).');
    const ws = probe(w, 'ws01', 'root', v3);
    if (ws.code === 0) return NO('ws01 can poll web02 by SNMP too: allow UDP 161 from mon01 only in the firewall.');
    return OK('SNMPv3 authPriv from mon01 only; no public community.');
  },
};

// ---------------------------------------------------------------- the lab

const NFT_DONE = WEB02_NFT.replace('\t\ttcp dport { 22, 80 } accept\n', `\t\ttcp dport { 22, 80 } accept\n\t\t# Monitoring from mon01 (CHG-2650): node_exporter and SNMP\n\t\tip saddr ${MON01_IP} tcp dport 9100 accept\n\t\tip saddr ${MON01_IP} udp dport 161 accept\n`);
const PROM_DONE = PROMETHEUS_YML.replace("          - 'log01.corp.lab:9100'\n", "          - 'log01.corp.lab:9100'\n          - 'web02.corp.lab:9100'\n");
const WEB_RULES = `groups:
  - name: web
    rules:
      - alert: NginxDown
        expr: node_systemd_unit_state{instance="web02.corp.lab:9100",name="nginx.service",state="active"} == 0
        for: 1m
        labels:
          severity: page
        annotations:
          summary: "nginx is not running on {{ $labels.instance }} (status page down)"
`;
const SNMPD_DONE = `# web02: SNMPv3 only, for mon01 (CHG-2650)
sysLocation    Server room, rack 2 (corp.lab)
sysContact     IT operations <oncall@corp.lab>
agentaddress   udp:161
view   all     included   .1
rouser ${SNMP_V3.user} authpriv -V all
createUser ${SNMP_V3.user} SHA "${SNMP_V3.auth}" AES "${SNMP_V3.priv}"
includeDir /etc/snmp/snmpd.conf.d
`;

export const LAB9: GuidedLab = {
  id: 'lab9',
  title: 'Lab 9: Monitoring a Server',
  level: 'intermediate',
  duration: '60–90 min',
  summary: 'Bring a new server under monitoring the way the others are: node_exporter with the systemd collector, the scrape port open to mon01 only, a Prometheus target added safely, an alert rule that pages, an end-to-end test of the page, SNMPv3 polling without the public community, and a reboot test.',
  brief: `The status page moved to a new server, **web02** (${WEB02_IP}, status.corp.lab), and nobody added it to monitoring. Every other server is scraped by **Prometheus on mon01** (${MON01_IP}) and pages **oncall@corp.lab** through Alertmanager (change CHG-2610). Do the same for web02 (CHG-2650):

- **node_exporter** is installed with Debian's defaults: enable the **systemd collector**, so unit states are reported.
- Its port **TCP 9100** must be reachable **from mon01 only**.
- Add **${TARGET}** to the **node** job in /etc/prometheus/prometheus.yml. Check before reloading: a broken file must not take monitoring down.
- An alert rule that **pages** (severity: page) when **nginx** stops on web02, within a few minutes.
- **Test the page**: stop nginx, see the alert fire and the mail arrive in the ops mailbox on mail01 (/home/ops/Maildir), start nginx again.
- **SNMP**: snmpd is installed with Debian's default configuration. mon01 must poll web02 with **SNMPv3** only: user **${SNMP_V3.user}**, SHA with **${SNMP_V3.auth}**, AES with **${SNMP_V3.priv}**, authPriv, the whole tree (including the interface table). No "public" community, UDP 161 from mon01 only.

Everything must keep working after every machine restarts.`,
  objectives: [
    'Enable an exporter collector and read the metrics an exporter serves.',
    'Open a monitoring port to the monitoring server only.',
    'Add a scrape target safely: promtool check config, then reload, then the target page.',
    'Write an alert rule (expr, for, labels, annotations) and test it with promtool and a real failure.',
    'Follow an alert from Prometheus through Alertmanager to the mailbox.',
    'Configure SNMPv3 (createUser, rouser, views) and remove the default community.',
  ],
  prerequisites: [
    { label: 'Linux service administration', link: 'lesson/systemd/what' },
    { label: 'Host firewalls', link: 'lesson/nftables/what' },
    { label: 'Monitoring and alerting', link: 'lesson/monitoring/what' },
  ],
  setupNote: `This lab adds **web02** (${WEB02_IP}) on sw01 port swp21 (VLAN 20; web02.corp.lab and status.corp.lab are in DNS). **mon01** runs Prometheus and Alertmanager; the other servers are already monitored.`,
  terminals: [
    { hostId: 'web02', user: 'root', label: 'web02 console (root)', banner: 'web02 console, logged in as root. nginx serves the status page; node_exporter and snmpd are installed with Debian\'s defaults. Try: systemctl status prometheus-node-exporter, curl -s localhost:9100/metrics | head, cat /etc/snmp/snmpd.conf.' },
    { hostId: 'mon01', user: 'root', label: 'mon01 (monitoring)', banner: 'mon01: Prometheus (:9090) and Alertmanager (:9093). Try: promtool query instant http://localhost:9090 \'up\', cat /etc/prometheus/prometheus.yml, ls /etc/prometheus/rules, amtool alert.' },
    { hostId: 'mail01', user: 'root', label: 'mail01 (ops mailbox)', banner: 'mail01: pages for oncall@corp.lab land in /home/ops/Maildir. Try: ls /home/ops/Maildir/new.' },
  ],
  build: buildLab9World,
  steps: [
    {
      id: 'exporter', title: 'Report the systemd units',
      objective: 'Enable node_exporter\'s systemd collector on web02 and make sure the exporter starts at boot.',
      background: 'An **exporter** turns a system\'s state into metrics that Prometheus can read over HTTP. node_exporter reports CPU, memory, filesystems and network by default; the **systemd collector** (off by default) adds `node_systemd_unit_state`, one series per unit and state, which is what an alert like "nginx stopped" needs.\n\nDebian passes the exporter\'s flags through **ARGS** in /etc/default/prometheus-node-exporter. A misspelled flag stops the exporter from starting: check `systemctl status` after every change.',
      tasks: [
        'Look at what is reported now: `curl -s localhost:9100/metrics | head -40` and `curl -s localhost:9100/metrics | grep -c node_`.',
        'Set `ARGS="--collector.systemd"` in /etc/default/prometheus-node-exporter, then `systemctl restart prometheus-node-exporter` and `systemctl status prometheus-node-exporter`.',
        'Confirm: `curl -s localhost:9100/metrics | grep \'unit_state{name="nginx.service"\'`.',
      ],
      hints: ['"unknown long flag" in the journal: a typo in ARGS.', 'systemctl is-enabled prometheus-node-exporter should say enabled (the package enables it).'],
      checks: [exporterReady],
      solution: [{ host: 'web02', user: 'root', commands: ["sed -i 's/^ARGS=\"\"$/ARGS=\"--collector.systemd\"/' /etc/default/prometheus-node-exporter", 'systemctl restart prometheus-node-exporter', 'systemctl enable prometheus-node-exporter'] }],
      learn: [{ label: 'Exporters and metrics', link: 'lesson/monitoring/internals' }],
      concepts: ['mon.metrics'],
    },
    {
      id: 'firewall', title: 'Open the scrape port to mon01',
      objective: `Allow TCP 9100 from mon01 (${MON01_IP}) only in web02's nftables configuration, and load it.`,
      background: 'Prometheus **pulls**: mon01 connects to every target\'s exporter. web02\'s firewall drops everything it does not allow, so the scrape would time out ("context deadline exceeded"). Metrics reveal a lot (versions, users, units, disks), so the port is opened to the monitoring server only, the same rule every other server has.',
      tasks: [
        `Add \`ip saddr ${MON01_IP} tcp dport 9100 accept\` to the input chain in /etc/nftables.conf, then \`nft -f /etc/nftables.conf\` and \`nft list ruleset\`.`,
        'From mon01: `curl -s -m 5 http://web02.corp.lab:9100/metrics | head -3` works; from ws01 the same command times out.',
      ],
      hints: ['Edit the file (it survives a reboot), not only the running ruleset.', 'nftables evaluates rules in order; an accept before the policy drop is enough.'],
      checks: [scrapeOpen],
      solution: [{ host: 'web02', user: 'root', commands: [printfTo(NFT_DONE.replace(`\t\tip saddr ${MON01_IP} udp dport 161 accept\n`, ''), '/etc/nftables.conf'), 'nft -f /etc/nftables.conf'] }],
      learn: [{ label: 'Firewall rules', link: 'lesson/nftables/config' }],
      concepts: ['mon.metrics', 'fw.stateful'],
    },
    {
      id: 'target', title: 'Add the target to Prometheus',
      objective: `Add ${TARGET} to the node job in /etc/prometheus/prometheus.yml on mon01, check the file, reload Prometheus, and see the target up.`,
      background: 'Prometheus scrapes what its **scrape_configs** list: a **job** (here node) with its **targets** (host:port). Every series it stores gets the labels **job** and **instance**, and the synthetic metric **up** says whether the last scrape worked.\n\nA reload (`systemctl reload prometheus`) applies the file without a restart; if the file is invalid, Prometheus logs "Error reloading config" and **keeps the old configuration**. A restart with an invalid file stops monitoring altogether. So: `promtool check config` first, then reload, then look.',
      tasks: [
        `Edit /etc/prometheus/prometheus.yml: add \`- '${TARGET}'\` to the targets of the node job (same indentation as the others; YAML does not allow tabs).`,
        '`promtool check config /etc/prometheus/prometheus.yml`, then `systemctl reload prometheus` and `journalctl -u prometheus -n 3`.',
        `After a scrape interval: \`promtool query instant ${PROM} 'up{instance="${TARGET}"}'\` gives 1; \`curl -s ${PROM}/api/v1/targets\` shows its health and lastError.`,
      ],
      hints: ['"Error reloading config … yaml: line N": the indentation is off.', 'Health down with "context deadline exceeded": go back to the firewall step.'],
      checks: [targetAdded],
      solution: [{ host: 'mon01', user: 'root', commands: [printfTo(PROM_DONE, '/etc/prometheus/prometheus.yml'), 'promtool check config /etc/prometheus/prometheus.yml', 'systemctl reload prometheus'] }],
      learn: [{ label: 'Scraping and PromQL', link: 'lesson/monitoring/internals' }, { label: 'prometheus.yml', link: 'reference?id=file:prometheus-yml' }],
      concepts: ['mon.metrics'],
    },
    {
      id: 'rule', title: 'An alert rule for nginx',
      objective: 'Write an alert rule in /etc/prometheus/rules/web.yml that pages (severity: page) when nginx stops on web02, with for: of 1–5 minutes.',
      background: 'An **alert rule** is a PromQL expression that returns the series in trouble, a **for:** duration the condition must hold (avoiding pages for a few seconds of trouble), **labels** (severity decides the route in Alertmanager) and **annotations** (the text of the page, with templates like `{{ $labels.instance }}`).\n\nWhile the condition holds for less than for:, the alert is **pending**; then it is **firing** and Prometheus sends it to Alertmanager. Test the expression first with promtool query: it should return nothing now.',
      tasks: [
        `Try the expression: \`promtool query instant ${PROM} 'node_systemd_unit_state{instance="${TARGET}",name="nginx.service",state="active"}'\` (1 now).`,
        'Write /etc/prometheus/rules/web.yml: a group "web" with an alert NginxDown, expr `node_systemd_unit_state{instance="web02.corp.lab:9100",name="nginx.service",state="active"} == 0`, for: 1m, labels severity: page, and a summary annotation.',
        '`promtool check rules /etc/prometheus/rules/web.yml`, `promtool check config /etc/prometheus/prometheus.yml` (it includes rules/*.yml), then `systemctl reload prometheus`; `curl -s localhost:9090/api/v1/rules` lists it.',
      ],
      hints: ['The rule file is a YAML list: groups → rules → alert/expr/for/labels/annotations.', 'promtool check rules names the line and the parse error.'],
      checks: [ruleWritten],
      solution: [{ host: 'mon01', user: 'root', commands: [printfTo(WEB_RULES, '/etc/prometheus/rules/web.yml'), 'promtool check rules /etc/prometheus/rules/web.yml', 'systemctl reload prometheus'] }],
      learn: [{ label: 'Alert rules', link: 'lesson/monitoring/config' }, { label: 'promtool', link: 'reference?id=promtool' }],
      concepts: ['mon.alerting'],
    },
    {
      id: 'test-page', title: 'Test the page end to end',
      objective: 'Stop nginx on web02, watch the alert go pending → firing, find the page in the ops mailbox on mail01, then start nginx again.',
      background: 'An alert path has many links: the exporter, the scrape, the rule, Alertmanager\'s route and receiver, the mail server, the mailbox. A rule that never fired has never been tested. **Breaking it on purpose** (in a quiet moment, announced) is how you know the page will come.\n\nAlertmanager waits **group_wait** (30 s here) before the first notification of a group, to collect related alerts into one mail.',
      tasks: [
        'On web02: `systemctl stop nginx`.',
        `On mon01: \`curl -s ${PROM}/api/v1/alerts\` (pending, then firing after for:), then \`amtool alert\`. Waiting: \`sleep 60\` advances the clock.`,
        'On mail01: `ls /home/ops/Maildir/new` and read the newest message: "[FIRING:1] NginxDown …".',
        'On web02: `systemctl start nginx`. Since the oncall receiver has send_resolved, a "[RESOLVED] NginxDown" mail follows.',
      ],
      hints: ['Nothing in amtool alert after 2 minutes? Check the rule\'s state with curl -s localhost:9090/api/v1/rules.', 'Alertmanager\'s log (journalctl -u prometheus-alertmanager) shows notification failures.'],
      checks: [pageTested],
      solution: [
        { host: 'web02', user: 'root', commands: ['systemctl stop nginx'] },
        { host: 'mon01', user: 'root', commands: ['sleep 60', 'sleep 60', 'sleep 60'] },
        { host: 'mail01', user: 'root', commands: ['ls /home/ops/Maildir/new'] },
        { host: 'web02', user: 'root', commands: ['systemctl start nginx'] },
      ],
      learn: [{ label: 'Alertmanager', link: 'lesson/monitoring/operate' }],
      concepts: ['mon.alerting'],
    },
    {
      id: 'snmp', title: 'SNMPv3 for mon01',
      objective: `Configure snmpd on web02 for SNMPv3 only: user ${SNMP_V3.user} (SHA/AES, authPriv) with a view of the whole tree, listening on the network, no public community; allow UDP 161 from mon01 only.`,
      background: '**SNMP** is how network devices (and many servers) are polled: the manager (mon01) asks the **agent** (snmpd) for values identified by **OIDs** (1.3.6.1.2.1.1.5.0 is the system name). SNMPv1/v2c authenticate with a **community** string sent in clear text; **SNMPv3** has users with authentication (SHA) and privacy (AES encryption).\n\nDebian\'s snmpd.conf listens on **localhost only** and answers the community **public** with a small view. For monitoring from mon01: `agentaddress udp:161`, a view including the tree you poll, `createUser` and `rouser … authpriv`, and no rocommunity lines.',
      tasks: [
        'Read /etc/snmp/snmpd.conf (agentaddress, view, rocommunity, rouser).',
        `Change it: \`agentaddress udp:161\`, \`view all included .1\`, \`rouser ${SNMP_V3.user} authpriv -V all\`, \`createUser ${SNMP_V3.user} SHA "${SNMP_V3.auth}" AES "${SNMP_V3.priv}"\`, and comment out both rocommunity public lines. Then \`systemctl restart snmpd\` and \`ss -ulnp | grep 161\`.`,
        `Add \`ip saddr ${MON01_IP} udp dport 161 accept\` to /etc/nftables.conf and load it.`,
        `From mon01: \`snmpget -v3 -l authPriv -u ${SNMP_V3.user} -a SHA -A ${SNMP_V3.auth} -x AES -X ${SNMP_V3.priv} web02.corp.lab .1.3.6.1.2.1.1.5.0\`, then snmpwalk the interface table .1.3.6.1.2.1.2.2.1.2.`,
      ],
      hints: ['"Timeout: No Response" from mon01: snmpd still listens on 127.0.0.1, or the firewall drops UDP 161.', '"authorizationError": the user\'s security level or view does not allow the request.', 'Debian\'s documentation puts createUser in /var/lib/snmp/snmpd.conf (stop snmpd first); snmpd.conf works too.'],
      checks: [snmpReady],
      solution: [{ host: 'web02', user: 'root', commands: [printfTo(SNMPD_DONE, '/etc/snmp/snmpd.conf'), 'systemctl restart snmpd', printfTo(NFT_DONE, '/etc/nftables.conf'), 'nft -f /etc/nftables.conf'] }],
      learn: [{ label: 'SNMP', link: 'lesson/monitoring/internals' }, { label: 'snmpd.conf', link: 'reference?id=file:snmpd-conf' }],
      concepts: ['mon.snmp'],
    },
    {
      id: 'reboot', title: 'Reboot test',
      objective: 'Every check of the earlier steps still passes after all machines restart.',
      background: 'The exporter and snmpd are enabled services; the firewall loads /etc/nftables.conf at boot; Prometheus reads its files at start. Anything only changed at runtime (nft add rule, a flag passed by hand) is gone after a restart.',
      tasks: ['Run the check: it reboots every host on a copy of the lab and runs all checks again.'],
      hints: ['A failing firewall check after the reboot usually means the rule was added with nft add rule but not to /etc/nftables.conf.'],
      checks: [],
      solution: [],
      learn: [{ label: 'Monitoring and alerting', link: 'lesson/monitoring/operate' }],
      concepts: ['mon.metrics'],
      afterReboot: true,
    },
  ],
};

