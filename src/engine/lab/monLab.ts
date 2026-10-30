// Monitoring in the lab: mon01 (10.0.20.55, Debian 12, switch port swp20) runs
// Prometheus, Alertmanager and node_exporter from Debian's packages. The
// servers srv01, db01, fs01, mail01, bak01 and log01 run node_exporter (with
// the systemd collector) and let mon01 scrape TCP 9100. Alerts go by mail
// through mail01: pages to oncall@corp.lab, tickets to ops-tickets@corp.lab
// (both delivered to the operations mailbox, user ops).

import { mkdir, readFile, writeFile } from '../fs';
import { newaliases } from '../sim/mail';
import { installMonitoringDirs, TEXTFILE_DIR } from '../sim/monitor';
import { DEBIAN_SNMP_CONF, DEBIAN_SNMPD_CONF } from '../sim/snmp';
import type { Host, World } from '../types';
import { addUser, createHost, staticInterfaces } from './builder';
import { installRsyslog } from './logLab';
import { TIMESYNCD_CONF } from './krbLab';
import { trustCorpRoot } from './pkiLab';
import { DEBIAN_SSHD_CONFIG, installHostKeys } from './sshLab';

export const MON01_IP = '10.0.20.55';
export const MON01_PASSWORDS = { alice: 'mon01-alice' };
/** IMAP password of the shared operations mailbox on mail01 (where alerts arrive). */
export const OPS_MAIL_PASSWORD = 'Mail-ops-26';
/** The servers mon01 scrapes (node_exporter on 9100). */
export const NODE_TARGETS = ['srv01', 'db01', 'fs01', 'mail01', 'bak01', 'log01'] as const;

export const PROMETHEUS_YML = `# Prometheus on mon01 (CHG-2610). Debian package 2.42; reload with
# "systemctl reload prometheus" after checking with "promtool check config".
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  # scrape_timeout is set to the global default (10s).
  external_labels:
    site: corp

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['localhost:9093']

rule_files:
  - 'rules/*.yml'

scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ['localhost:9090']

  - job_name: alertmanager
    static_configs:
      - targets: ['localhost:9093']

  - job_name: node
    static_configs:
      - targets:
          - 'mon01.corp.lab:9100'
          - 'srv01.corp.lab:9100'
          - 'db01.corp.lab:9100'
          - 'fs01.corp.lab:9100'
          - 'mail01.corp.lab:9100'
          - 'bak01.corp.lab:9100'
          - 'log01.corp.lab:9100'
`;

export const CORP_RULES = `# Alert rules for the corp.lab servers (CHG-2610).
# severity=page mails oncall@corp.lab, severity=ticket mails ops-tickets@corp.lab.
groups:
  - name: availability
    rules:
      - alert: InstanceDown
        expr: up == 0
        for: 2m
        labels:
          severity: page
        annotations:
          summary: "{{ $labels.instance }} of job {{ $labels.job }} is down"
          description: "Prometheus could not scrape {{ $labels.instance }} for more than 2 minutes."

      - alert: SystemdUnitFailed
        expr: node_systemd_unit_state{state="failed"} == 1
        for: 5m
        labels:
          severity: ticket
        annotations:
          summary: "{{ $labels.name }} failed on {{ $labels.instance }}"

  - name: capacity
    rules:
      - alert: FilesystemAlmostFull
        expr: node_filesystem_avail_bytes{fstype="ext4"} / node_filesystem_size_bytes{fstype="ext4"} < 0.10
        for: 5m
        labels:
          severity: page
        annotations:
          summary: "{{ $labels.mountpoint }} on {{ $labels.instance }} has {{ $value | humanizePercentage }} space left"

      - alert: HighLoad
        expr: node_load5 > 3
        for: 15m
        labels:
          severity: ticket
        annotations:
          summary: "Load average {{ $value }} on {{ $labels.instance }}"

  - name: operations
    rules:
      - alert: ClockNotSynchronising
        expr: min_over_time(node_timex_sync_status[5m]) == 0
        for: 10m
        labels:
          severity: ticket
        annotations:
          summary: "The clock of {{ $labels.instance }} is not synchronised by NTP"

      - alert: BackupTooOld
        expr: time() - restic_backup_last_success_timestamp_seconds > 26 * 3600
        for: 10m
        labels:
          severity: ticket
        annotations:
          summary: "The last successful backup of {{ $labels.instance }} is {{ $value | humanizeDuration }} old"
`;

export const ALERTMANAGER_YML = `# Alertmanager on mon01 (CHG-2610): mail through mail01.
global:
  smtp_smarthost: 'mail01.corp.lab:25'
  smtp_from: 'alertmanager@corp.lab'
  smtp_hello: 'mon01.corp.lab'

route:
  receiver: oncall
  group_by: ['alertname', 'instance']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  routes:
    - matchers: ['severity="ticket"']
      receiver: tickets
      repeat_interval: 24h

receivers:
  - name: oncall
    email_configs:
      - to: 'oncall@corp.lab'
        send_resolved: true
  - name: tickets
    email_configs:
      - to: 'ops-tickets@corp.lab'

inhibit_rules:
  # A machine that is down does not also need its unit and backup alerts.
  - source_matchers: ['alertname="InstanceDown"']
    target_matchers: ['severity="ticket"']
    equal: ['instance']
`;

export const NODE_EXPORTER_DEFAULTS = `# Set the command-line arguments to pass to the server.
# Due to shell escaping, to pass backslashes for regexes, you need to double
# them (\\\\d for \\d). If running under systemd, you need to double them again
# (\\\\\\\\d to mean \\d), and escape newlines too.
#
# The systemd collector reports the state of every unit (CHG-2610).
ARGS="--collector.systemd"
`;

export const PROMETHEUS_DEFAULTS = `# Set the command-line arguments to pass to the server.
# Due to shell escaping, to pass backslashes for regexes, you need to double
# them (\\\\d for \\d). If running under systemd, you need to double them again
# (\\\\\\\\d to mean \\d), and escape newlines too.
ARGS=""
`;

export const ALERTMANAGER_DEFAULTS = `# Set the command-line arguments to pass to the server.
ARGS=""
`;

export const MON01_NFT = `#!/usr/sbin/nft -f

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iif "lo" accept
		meta l4proto icmp accept
		tcp dport 22 accept
		# Prometheus and Alertmanager web interfaces for the administrators (office)
		ip saddr 10.0.10.0/24 tcp dport { 9090, 9093 } accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

/** The rule a server's firewall needs so mon01 can scrape node_exporter. */
export const SCRAPE_RULE = `\t\t# Prometheus on mon01 scrapes node_exporter (CHG-2610)\n\t\tip saddr ${MON01_IP} tcp dport 9100 accept\n`;

/** Lines the backup script ends with: the time of its last success, for BackupTooOld. */
export const BACKUP_METRIC = `# Tell monitoring when the last backup succeeded (node_exporter textfile collector, CHG-2610).
date +'restic_backup_last_success_timestamp_seconds %s' > ${TEXTFILE_DIR}/restic_backup.prom.tmp
mv ${TEXTFILE_DIR}/restic_backup.prom.tmp ${TEXTFILE_DIR}/restic_backup.prom
`;

/** rtr01's snmpd.conf: Debian's file, changed for polling from mon01 (CHG-2611). */
export const RTR01_SNMPD_CONF = DEBIAN_SNMPD_CONF
  .replace('sysLocation    Sitting on the Dock of the Bay', 'sysLocation    Server room, rack 2 (corp.lab)')
  .replace('sysContact     Me <me@example.org>', 'sysContact     IT operations <oncall@corp.lab>')
  .replace('agentaddress  127.0.0.1,[::1]', '# Listen on every address (CHG-2611); the firewall only lets mon01 in.\nagentaddress  udp:161')
  .replace('view   systemonly  included   .1.3.6.1.2.1.25.1\n', 'view   systemonly  included   .1.3.6.1.2.1.25.1\n# Everything, for the monitoring server (CHG-2611)\nview   all         included   .1\n')
  .replace('rocommunity  public default -V systemonly\nrocommunity6 public default -V systemonly', '#rocommunity  public default -V systemonly\n#rocommunity6 public default -V systemonly\n# mon01 only, the whole tree (CHG-2611)\nrocommunity  corp-mon 10.0.20.55 -V all')
  .replace('rouser authPrivUser authpriv -V systemonly', 'rouser monitor authpriv -V all');

export const SNMP_V3 = { user: 'monitor', auth: 'Snmp-Auth-2611', priv: 'Snmp-Priv-2611', community: 'corp-mon' };

const addService = (host: Host, name: string) => { host.services[name] ??= { state: 'inactive', enabled: true, since: 0, pid: null, loaded: null, result: 'success' }; };

const PROMETHEUS_USER = { name: 'prometheus', uid: 110, gid: 118, primaryGroup: 'prometheus', groups: [], home: '/var/lib/prometheus', shell: '/usr/sbin/nologin', gecos: 'Prometheus daemon', password: null };

/** prometheus-node-exporter as Debian installs it, with the systemd collector, before the host boots. */
export function installNodeExporter(host: Host, t: number): void {
  if (!host.users.prometheus) addUser(host, PROMETHEUS_USER, t, false);
  if (!host.fs['/var/lib']) mkdir(host, '/var/lib', t);
  installMonitoringDirs(host, t);
  writeFile(host, '/etc/default/prometheus-node-exporter', NODE_EXPORTER_DEFAULTS, t);
  addService(host, 'prometheus-node-exporter');
  // Open TCP 9100 for mon01 in a default-drop firewall.
  const nft = readFile(host, '/etc/nftables.conf');
  if (nft && /policy drop/.test(nft) && !nft.includes('dport 9100')) writeFile(host, '/etc/nftables.conf', nft.replace(/(\t\tiif "lo" accept\n)/, `$1${SCRAPE_RULE}`), t, { mode: 0o755 });
}

/** mon01, its configuration, and node_exporter on the servers (before the lab boots). */
export function installMonitoring(world: World): Host {
  const t = world.clock;
  const h = createHost(world, {
    id: 'mon01', hostname: 'mon01', domain: 'corp.lab', role: 'Monitoring server (Prometheus, Alertmanager)',
    ifaces: [{ name: 'eth0', mac: '52:54:00:30:00:37', segment: null }],
    services: ['rsyslog', 'systemd-timesyncd', 'nftables', 'ssh', 'prometheus', 'prometheus-alertmanager'],
  });
  writeFile(h, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: `${MON01_IP}/24`, gateway: '10.0.20.1' }]), t);
  writeFile(h, '/etc/resolv.conf', 'search corp.lab\nnameserver 10.0.10.53\n', t);
  writeFile(h, '/etc/ssh/sshd_config', DEBIAN_SSHD_CONFIG, t);
  writeFile(h, '/etc/nftables.conf', MON01_NFT, t, { mode: 0o755 });
  mkdir(h, '/etc/systemd', t);
  writeFile(h, '/etc/systemd/timesyncd.conf', TIMESYNCD_CONF, t);
  installHostKeys(h, t);
  trustCorpRoot(h, t);
  installRsyslog(h, t, true);
  addUser(h, { name: 'alice', uid: 1000, gid: 1000, primaryGroup: 'alice', groups: ['sudo', 'adm'], home: '/home/alice', shell: '/bin/bash', gecos: 'Alice Admin', password: MON01_PASSWORDS.alice }, t);
  installNodeExporter(h, t);
  mkdir(h, '/etc/prometheus/rules', t);
  writeFile(h, '/etc/prometheus/prometheus.yml', PROMETHEUS_YML, t);
  writeFile(h, '/etc/prometheus/rules/corp.yml', CORP_RULES, t);
  writeFile(h, '/etc/prometheus/alertmanager.yml', ALERTMANAGER_YML, t);
  writeFile(h, '/etc/default/prometheus', PROMETHEUS_DEFAULTS, t);
  writeFile(h, '/etc/default/prometheus-alertmanager', ALERTMANAGER_DEFAULTS, t);
  mkdir(h, '/var/lib/prometheus/metrics2', t, { mode: 0o755, owner: 'prometheus', group: 'prometheus' });
  mkdir(h, '/var/lib/prometheus/alertmanager', t, { mode: 0o755, owner: 'prometheus', group: 'prometheus' });
  mkdir(h, '/etc/amtool', t);
  writeFile(h, '/etc/amtool/config.yml', '# amtool talks to the local Alertmanager\nalertmanager.url: http://localhost:9093\n', t);
  for (const id of NODE_TARGETS) installNodeExporter(world.hosts[id], t);
  // The nightly backups report their last success through the textfile collector.
  for (const id of NODE_TARGETS) {
    const b = world.hosts[id];
    const job = readFile(b, '/usr/local/sbin/restic-backup');
    if (job !== undefined && !job.includes('.prom')) writeFile(b, '/usr/local/sbin/restic-backup', job + BACKUP_METRIC, t, { mode: 0o755 });
  }
  // SNMP: rtr01 is polled from mon01 (net-snmp's tools are installed there, with snmp-mibs-downloader).
  const rtr = world.hosts.rtr01;
  mkdir(rtr, '/etc/snmp', t);
  mkdir(rtr, '/etc/snmp/snmpd.conf.d', t);
  writeFile(rtr, '/etc/snmp/snmpd.conf', RTR01_SNMPD_CONF, t, { mode: 0o600 });
  if (!rtr.fs['/var/lib/snmp']) mkdir(rtr, '/var/lib/snmp', t, { mode: 0o755, owner: 'Debian-snmp', group: 'Debian-snmp' });
  writeFile(rtr, '/var/lib/snmp/snmpd.conf', `createUser ${SNMP_V3.user} SHA "${SNMP_V3.auth}" AES "${SNMP_V3.priv}"\n`, t, { mode: 0o600 });
  addService(rtr, 'snmpd');
  const rnft = readFile(rtr, '/etc/nftables.conf') ?? '';
  writeFile(rtr, '/etc/nftables.conf', rnft.replace(/(\t\tiifname != "eth2" udp dport 123 accept\n)/, '$1\t\t# SNMP polling from mon01 (CHG-2611)\n\t\tip saddr 10.0.20.55 udp dport 161 accept\n'), t, { mode: 0o755 });
  for (const d of ['/etc/snmp', '/usr/share/snmp', '/usr/share/snmp/mibs']) mkdir(h, d, t);
  writeFile(h, '/etc/snmp/snmp.conf', DEBIAN_SNMP_CONF, t);
  // mail01: the shared mailbox the pages go to.
  const mail = world.hosts.mail01;
  addUser(mail, { name: 'ops', uid: 1003, gid: 1003, primaryGroup: 'ops', groups: [], home: '/home/ops', shell: '/usr/sbin/nologin', gecos: 'Operations mailbox (monitoring)', password: OPS_MAIL_PASSWORD }, t);
  writeFile(mail, '/etc/aliases', `${readFile(mail, '/etc/aliases') ?? ''}# Monitoring: pages and tickets go to the operations mailbox (CHG-2610)\noncall:        ops\nops-tickets:   ops\n`, t);
  newaliases(world, mail);
  return h;
}
