// Monitoring and alerting with Prometheus, Alertmanager, node_exporter and
// SNMP. Examples follow the lab: mon01 (10.0.20.55) runs Prometheus and
// Alertmanager, the servers run node_exporter, pages go by mail through
// mail01, and mon01 polls rtr01 by SNMP. Lab 9 brings a new server (web02)
// under monitoring. Zabbix, Nagios/Icinga, Windows and cloud monitoring are
// deployment notes.

import type { Assessment, Lesson, Primer, ServiceGuide } from '../types';

const PQ = (expr: string) => `promtool query instant http://localhost:9090 '${expr}'`;

// --- Operate & recover guide ---------------------------------------------------------

export const MONITORING_GUIDE: ServiceGuide = {
  purpose:
    'A **monitoring system** watches the machines and services of a network all the time, keeps a history of how they behaved (**metrics**: numbers over time), and tells a person when something needs attention (**alerts**), ideally before the users notice. An administrator decides what to measure, which conditions are worth waking someone for, who gets which alert and how, and makes sure the monitoring itself keeps working.',
  architecture: [
    { q: 'What does it accomplish?', a: 'Visibility (what is the state and the trend of every server and link), detection (a rule notices a problem), notification (the right person is told once, not a hundred times) and history (what happened before an incident, capacity planning, baselines).' },
    { q: 'How does it work internally?', a: '**Exporters** on each machine (node_exporter) present the machine\'s state as metrics on an HTTP page (/metrics). **Prometheus** fetches (**scrapes**) every target every 15 seconds, stores each value as a **time series** (a metric name plus labels such as instance and job), and evaluates **rules** written in PromQL. A rule that matches for its **for:** duration becomes a **firing alert** and is sent to **Alertmanager**, which groups, silences, routes and sends the **notifications** (mail, chat, pager).' },
    { q: 'Which protocols does it use?', a: 'HTTP for scrapes (GET /metrics, text exposition format) and for alerts (POST /api/v2/alerts to Alertmanager); SMTP (or webhooks) for notifications; **SNMP** over UDP for network devices (GET/GETNEXT/GETBULK, traps); syslog for log-based monitoring.' },
    { q: 'Which ports and transport?', a: 'TCP **9100** node_exporter, **9090** Prometheus, **9093** Alertmanager (9094 cluster); UDP **161** SNMP queries, UDP **162** SNMP traps; TCP 25/587 for mail notifications. Exporter ports should be reachable from the monitoring server only.' },
    { q: 'Which processes and OS components implement it?', a: 'prometheus.service, prometheus-alertmanager.service and prometheus-node-exporter.service (Debian packages, configuration in /etc/prometheus and /etc/default), snmpd.service on SNMP agents, the net-snmp tools (snmpget, snmpwalk) on the manager, promtool and amtool for checks and queries.' },
    { q: 'Which other services does it depend on?', a: 'DNS (target names), firewalls (scrape and SNMP ports), time synchronisation (every sample is time-stamped; a skewed clock confuses rate() and alerts), the mail server or chat service for notifications, and disk space for the time-series database.' },
    { q: 'How do requests travel?', a: 'Every 15 s Prometheus on mon01 opens TCP to srv01.corp.lab:9100 → GET /metrics → node_exporter reads /proc, /sys, systemd and the textfile directory and answers with a few hundred lines → Prometheus stores them with the labels job="node", instance="srv01.corp.lab:9100" and records up=1 → every 15 s the rules are evaluated → a firing alert is POSTed to Alertmanager on :9093 → after group_wait Alertmanager sends one mail per group through mail01:25.' },
    { q: 'How do authentication and authorisation work?', a: 'Scrapes are usually protected by the network: exporters answer only the monitoring server (firewall rules); exporters can also use TLS and basic auth (web.config.file). SNMPv1/v2c use a **community** string (sent in clear text) plus a source address restriction and a **view**; **SNMPv3** has users with authentication (SHA) and encryption (AES) and a security level (noAuthNoPriv, authNoPriv, authPriv).' },
    { q: 'How does it start at boot?', a: 'The three services are enabled by their Debian packages. Prometheus reads prometheus.yml and the rule files at start (an error stops it), Alertmanager reads alertmanager.yml and its stored silences, node_exporter reads its flags from ARGS in /etc/default/prometheus-node-exporter.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'Nothing is scraped and no rule is evaluated, so **no alert can fire**: monitoring fails silently. That is why the monitoring system is itself monitored (a second Prometheus, an external heartbeat, a "dead man\'s switch" alert that must always fire). Already stored data survives a restart; pending alerts start their for: again.' },
  ],
  ports: [
    { port: '9100', proto: 'TCP', purpose: 'node_exporter: /metrics of a machine' },
    { port: '9090', proto: 'TCP', purpose: 'Prometheus: web UI, HTTP API, its own /metrics' },
    { port: '9093', proto: 'TCP', purpose: 'Alertmanager: web UI and API (alerts, silences)' },
    { port: '161', proto: 'UDP', purpose: 'SNMP agent (snmpd): GET, GETNEXT, GETBULK' },
    { port: '162', proto: 'UDP', purpose: 'SNMP traps / informs sent by devices to the manager' },
  ],
  processes: [
    { name: 'prometheus', platform: 'Linux (prometheus.service)', role: 'Scrapes targets, stores time series, evaluates rules, sends alerts' },
    { name: 'prometheus-alertmanager', platform: 'Linux', role: 'Groups, silences, inhibits and routes alerts; sends notifications' },
    { name: 'prometheus-node-exporter', platform: 'Linux (every server)', role: 'Serves the machine\'s metrics on :9100' },
    { name: 'snmpd', platform: 'Linux, routers, switches, printers', role: 'SNMP agent answering on UDP 161' },
    { name: 'windows_exporter / WMI, Zabbix agent', platform: 'Windows and other platforms', role: 'The same role on other systems' },
  ],
  dependencies: {
    title: 'What "the on-call phone rings when srv01 goes down" depends on (top needs everything below it)',
    caption: 'Each link fails silently on its own: monitoring has to be tested end to end.',
    rows: [
      { label: 'Notification', nodes: [{ id: 'mail', label: 'mail01 / phone', sub: 'oncall@corp.lab', kind: 'service' }] },
      { label: 'Alertmanager', nodes: [{ id: 'am', label: 'Alertmanager', sub: 'route, receiver, silences', kind: 'service' }] },
      { label: 'Prometheus', nodes: [{ id: 'rules', label: 'Alert rules', sub: 'expr, for, labels', kind: 'data' }, { id: 'prom', label: 'Prometheus', sub: 'prometheus.yml, targets', kind: 'service' }] },
      { label: 'Path', nodes: [{ id: 'dns', label: 'DNS', sub: 'srv01.corp.lab', kind: 'network' }, { id: 'fw', label: 'srv01 firewall', sub: 'tcp 9100 from mon01', kind: 'network' }] },
      { label: 'Target', nodes: [{ id: 'exp', label: 'node_exporter', sub: ':9100, collectors', kind: 'service' }] },
    ],
    edges: [['mail', 'am'], ['am', 'rules'], ['rules', 'prom'], ['prom', 'dns'], ['prom', 'fw'], ['fw', 'exp']],
  },
  sequence: {
    title: 'srv01\'s exporter stops: from scrape to page',
    caption: 'Prometheus 2.42, Alertmanager 0.25, rule InstanceDown (up == 0 for 2m). Where each ticket breaks the chain is noted.',
    lanes: [{ id: 'p', label: 'mon01', sub: 'Prometheus' }, { id: 't', label: 'srv01', sub: 'node_exporter' }, { id: 'a', label: 'mon01', sub: 'Alertmanager' }, { id: 'm', label: 'mail01', sub: 'Postfix' }],
    steps: [
      { from: 'p', to: 't', label: 'GET /metrics (every 15 s)', note: 'Firewall drop → "context deadline exceeded"; exporter stopped → "connection refused". Either way up = 0.' },
      { from: 'p', to: 'p', label: 'evaluate rules: up == 0 → pending', note: 'Invalid prometheus.yml after a restart → Prometheus not running: nothing is evaluated at all.' },
      { from: 'p', to: 'p', label: 'still true after for: 2m → firing' },
      { from: 'p', to: 'a', label: 'POST /api/v2/alerts (re-sent every minute)' },
      { from: 'a', to: 'a', label: 'route → receiver oncall; silences? inhibition?', note: 'A broad silence suppresses the alert here: nothing is sent, and nothing is logged.' },
      { from: 'a', to: 'a', label: 'group_wait 30 s: collect related alerts' },
      { from: 'a', to: 'm', label: 'SMTP: STARTTLS, MAIL FROM, RCPT TO oncall@corp.lab', note: 'Wrong smarthost or port → "Notify for alerts failed" in Alertmanager\'s log.' },
      { from: 'm', to: 'm', label: 'delivered to the ops mailbox' },
    ],
  },
  files: [
    { path: '/etc/prometheus/prometheus.yml', platform: 'Debian (prometheus)', kind: 'config', perms: 'root:root 0644', contains: 'global (scrape_interval, evaluation_interval, external_labels), alerting.alertmanagers, rule_files, scrape_configs (job_name, static_configs targets, metrics_path).', accessed: 'At start and on reload (systemctl reload prometheus = SIGHUP).', problems: 'A restart with an invalid file stops Prometheus; a reload with one keeps the old configuration ("Error reloading config"). Always promtool check config first.' },
    { path: '/etc/prometheus/rules/*.yml', platform: 'Debian (lab convention)', kind: 'config', perms: 'root:root 0644', contains: 'groups → rules: alert or record, expr, for, labels, annotations.', accessed: 'With prometheus.yml (rule_files).', problems: 'An invalid expression fails the whole load. promtool check rules names the line.' },
    { path: '/etc/prometheus/alertmanager.yml', platform: 'Debian (prometheus-alertmanager)', kind: 'config', perms: 'root:root 0644', contains: 'global smtp_* settings, route (receiver, group_by, group_wait, group_interval, repeat_interval, child routes with matchers), receivers, inhibit_rules.', accessed: 'At start and reload.', problems: 'An undefined receiver or a typo stops the reload; amtool check-config validates it.' },
    { path: '/etc/default/prometheus-node-exporter', platform: 'Debian (every server)', kind: 'config', perms: 'root:root 0644', contains: 'ARGS="…": collector flags (--collector.systemd), listen address, textfile directory.', accessed: 'At each start of the exporter.', problems: 'An unknown flag makes the exporter exit at start: the target goes down with "connection refused".' },
    { path: '/var/lib/prometheus/node-exporter/*.prom', platform: 'Debian (textfile collector)', kind: 'data', perms: 'readable by prometheus', contains: 'Metrics written by scripts and jobs (here: restic_backup_last_success_timestamp_seconds).', accessed: 'At every scrape.', problems: 'Write to a .tmp file and rename it, or a half-written file causes a scrape error.' },
    { path: '/etc/snmp/snmpd.conf (+ snmpd.conf.d/, /var/lib/snmp/snmpd.conf)', platform: 'Debian (snmpd)', kind: 'config', perms: 'root:root 0600', contains: 'agentaddress, sysLocation/sysContact, view, rocommunity, rouser; createUser for v3 users.', accessed: 'At start and restart.', problems: 'Debian\'s default listens on localhost only and answers "public" with a small view. A package update can replace a modified file.' },
    { path: '/etc/snmp/snmp.conf', platform: 'Debian (snmp tools)', kind: 'config', perms: 'root:root 0644', contains: '"mibs :" disables MIB loading (MIB files are not shipped).', accessed: 'By snmpget/snmpwalk.', problems: 'Names like IF-MIB::ifDescr only work with MIBs installed (snmp-mibs-downloader) and loaded (comment out "mibs :" or use -m ALL).' },
  ],
  management: [
    {
      platform: 'Monitoring server (mon01): Prometheus',
      tasks: [
        { task: 'Which targets are up, and why not?', command: `${PQ('up == 0')}\ncurl -s http://localhost:9090/api/v1/targets`, explain: 'up is 1 or 0 per target; the targets API shows lastError (refused, deadline exceeded, HTTP status).', sim: true },
        { task: 'Ask a question in PromQL', command: `${PQ('100 * (1 - node_filesystem_avail_bytes{fstype="ext4"} / node_filesystem_size_bytes{fstype="ext4"})')}\n${PQ('topk(3, node_load1)')}`, explain: 'Disk usage in percent per filesystem; the three busiest machines.', sim: true },
        { task: 'Which alerts are pending or firing?', command: 'curl -s http://localhost:9090/api/v1/alerts\ncurl -s http://localhost:9090/api/v1/rules', explain: 'Alert state per rule; the rules with their health and last evaluation.', sim: true },
        { task: 'Change the configuration safely', command: 'promtool check config /etc/prometheus/prometheus.yml\nsystemctl reload prometheus\njournalctl -u prometheus -n 3', explain: 'Check, reload, and read the result: "Completed loading of configuration file" or "Error reloading config".', sim: true },
      ],
    },
    {
      platform: 'Monitoring server (mon01): Alertmanager',
      tasks: [
        { task: 'What has Alertmanager received?', command: 'amtool alert\namtool alert query -s', explain: 'Active alerts; with -s also those suppressed by silences.', sim: true },
        { task: 'Silence a server during maintenance', command: 'amtool silence add instance=srv01.corp.lab:9100 --duration=1h --comment="kernel update"\namtool silence query', explain: 'Name the instance and an end: a silence for job="node" for weeks hides every outage.', sim: true },
        { task: 'Where does an alert go?', command: 'amtool check-config /etc/prometheus/alertmanager.yml\namtool config routes test severity=ticket alertname=BackupTooOld', explain: 'Validate the file; show which receiver a set of labels reaches.', sim: true },
        { task: 'Did the notifications go out?', command: 'journalctl -u prometheus-alertmanager -n 5', explain: '"Notify for alerts failed" with the SMTP error, or nothing (success is not logged).', sim: true },
      ],
    },
    {
      platform: 'Monitored server (srv01)',
      tasks: [
        { task: 'Is the exporter running, and what does it report?', command: "systemctl status prometheus-node-exporter\ncurl -s localhost:9100/metrics | grep -c '^node_'", explain: 'The service and the number of node_ series it serves.', sim: true },
        { task: 'Which flags does it run with?', command: 'cat /etc/default/prometheus-node-exporter\nss -tlnp', explain: 'ARGS (collectors) and the listening port.', sim: true },
        { task: 'Publish a value from a script', command: 'cat /var/lib/prometheus/node-exporter/restic_backup.prom', explain: 'The textfile collector: here the backup job writes the time of its last success.', sim: true },
      ],
    },
    {
      platform: 'SNMP (mon01 → rtr01)',
      tasks: [
        { task: 'Read one value, walk a table', command: 'snmpget -v2c -c corp-mon rtr01.corp.lab .1.3.6.1.2.1.1.5.0\nsnmpwalk -v2c -c corp-mon rtr01.corp.lab .1.3.6.1.2.1.2.2.1.8', explain: 'sysName.0; ifOperStatus of every interface (1 = up, 2 = down).', sim: true },
        { task: 'With MIB names', command: 'snmpwalk -v2c -c corp-mon -m ALL rtr01.corp.lab IF-MIB::ifDescr', explain: '-m ALL loads the MIBs that snmp-mibs-downloader installed (Debian disables them in /etc/snmp/snmp.conf).', sim: true },
        { task: 'SNMPv3 (authenticated and encrypted)', command: 'snmpget -v3 -l authPriv -u monitor -a SHA -A Snmp-Auth-2611 -x AES -X Snmp-Priv-2611 rtr01.corp.lab .1.3.6.1.2.1.1.3.0', explain: 'User, security level, auth and privacy protocols and passphrases.', sim: true },
      ],
    },
  ],
  actions: [
    { action: 'systemctl reload prometheus', when: 'After changing prometheus.yml or rules (checked with promtool).', effect: 'New configuration; scrapes and alerts continue.', risk: 'An invalid file is rejected (old configuration kept): read the journal.' },
    { action: 'systemctl restart prometheus', when: 'Only when needed (flags in /etc/default/prometheus, upgrades).', effect: 'Prometheus stops and starts again.', risk: 'An invalid configuration now stops monitoring entirely; pending alerts restart their for:.' },
    { action: 'amtool silence add', when: 'Planned maintenance, a known problem being worked on.', effect: 'Matching alerts are not notified until the silence ends.', risk: 'A broad or long silence hides real outages: name the instance, set a short duration, write a comment.' },
    { action: 'Changing alert rules', when: 'False alarms, missed problems, new services.', effect: 'What wakes people up.', risk: 'Alerts that fire too often get ignored (alert fatigue); test new rules against history (promtool query) and with a real failure.' },
    { action: 'Opening exporter / SNMP ports', when: 'A new target.', effect: 'Monitoring can read the machine.', risk: 'Metrics and SNMP reveal versions, users, interfaces and load: open them to the monitoring server only.' },
  ],
  workflow: [
    { question: 'Is the monitoring system itself working?', why: 'A stopped Prometheus or Alertmanager means no alerts at all.', command: 'systemctl status prometheus prometheus-alertmanager\njournalctl -u prometheus -n 5', healthy: 'Both active; the last configuration load completed', broken: 'failed with "Error loading config"; "Error reloading config" (old configuration still running)', next: 'Then the targets.', sim: true },
    { question: 'Is the target scraped?', why: 'An alert about a server can be about the path to it.', command: `${PQ('up')}\ncurl -s http://localhost:9090/api/v1/targets`, healthy: 'up 1, lastError empty', broken: '"connection refused" (exporter not running); "context deadline exceeded" (firewall drop, host down); HTTP 404 (wrong port or path)', next: 'Fix the path or the exporter, then the rules.', sim: true },
    { question: 'Does the rule match what you think?', why: 'A rule that never matches never fires.', command: `${PQ('up == 0')}\ncurl -s http://localhost:9090/api/v1/rules`, healthy: 'The expression returns the series in trouble; the rule\'s state is pending/firing', broken: 'Empty result (wrong labels or metric name); rule health "err"', next: 'Then Alertmanager.', sim: true },
    { question: 'Did Alertmanager receive it, and is it suppressed?', why: 'Silences and inhibition hide alerts without any error.', command: 'amtool alert query -s\namtool silence query', healthy: 'The alert is active, no silence matches it', broken: 'Suppressed by a silence; not present (Prometheus cannot reach Alertmanager: its journal says "Error sending alert")', next: 'Then the notification.', sim: true },
    { question: 'Was the notification delivered?', why: 'The last link is outside the monitoring system.', command: 'journalctl -u prometheus-alertmanager -n 5', healthy: 'No "Notify for alerts failed"; the mail server logs the delivery', broken: 'SMTP errors (refused, relay denied, TLS); wrong receiver', next: 'Fix the receiver, then test end to end.', sim: true },
  ],
  failures: [
    { symptom: 'A server is "down" in monitoring but works for its users', causes: ['Firewall change removed the scrape rule', 'Exporter stopped or failed to start'], diagnose: ['lastError in the targets API', 'curl the exporter from mon01 and locally'], fix: 'Restore the rule (from mon01 only) or start/fix the exporter.', verify: 'up becomes 1; the alert resolves.' },
    { symptom: 'No alerts at all, the Prometheus page does not load', causes: ['Prometheus failed to start with an invalid configuration'], diagnose: ['systemctl status prometheus', 'promtool check config'], fix: 'Correct the file, check it, start Prometheus.', verify: 'All targets up; rules loaded.' },
    { symptom: 'A change to prometheus.yml has no effect', causes: ['The reload failed and the old configuration runs', 'Not reloaded at all'], diagnose: ['journalctl -u prometheus ("Error reloading config")', 'prometheus_config_last_reload_successful'], fix: 'Fix the file, promtool check config, reload.', verify: 'The new target or rule appears in the API.' },
    { symptom: 'The alert fires but nobody is notified', causes: ['Notification delivery fails (SMTP)', 'A silence or inhibition suppresses it', 'The route leads to another receiver'], diagnose: ['journalctl -u prometheus-alertmanager', 'amtool alert query -s; amtool silence query', 'amtool config routes test'], fix: 'Fix the receiver, expire the silence, correct the route.', verify: 'A test alert reaches the mailbox.' },
    { symptom: 'SNMP polling times out', causes: ['snmpd listens on localhost only', 'Wrong community or source not allowed', 'Firewall drops UDP 161'], diagnose: ['ss -ulnp on the agent', 'snmpget on the agent itself', 'snmpd.conf (agentaddress, rocommunity, rouser)'], fix: 'agentaddress udp:161, the right community/user for the manager, a firewall rule for the manager only.', verify: 'snmpget from the manager returns values.' },
  ],
  verification: [
    { check: 'Monitoring runs', command: 'systemctl is-active prometheus prometheus-alertmanager', expect: 'active, active' },
    { check: 'Every target is up', command: PQ('count(up == 0)'), expect: 'No result (no target down)' },
    { check: 'Rules are loaded', command: 'promtool check config /etc/prometheus/prometheus.yml', expect: 'SUCCESS for the file and every rule file' },
    { check: 'Notifications work', command: 'Stop a test service on purpose; wait for the mail', expect: '[FIRING:1] … in the on-call mailbox, then [RESOLVED]' },
    { check: 'Nothing silenced by accident', command: 'amtool silence query', expect: 'Only current, narrow maintenance silences' },
  ],
  refIds: ['promtool', 'amtool', 'snmpwalk', 'file:prometheus-yml', 'file:alert-rules', 'file:alertmanager-yml', 'file:snmpd-conf', 'proc:monitor-new-server', 'proc:alert-not-received'],
};

// --- Lesson -------------------------------------------------------------------------

export const MONITORING_LESSON: Lesson = {
  id: 'monitoring',
  moduleId: 'F',
  title: 'Monitoring and alerting (Prometheus, SNMP)',
  level: 'intermediate',
  summary: 'Watch servers and network devices and get told when something is wrong: metrics and exporters, Prometheus scrapes and PromQL, alert rules, Alertmanager routing, silences and notifications, SNMP v2c and v3, baselines and alert fatigue, and the failures of each link.',
  concepts: ['mon.metrics', 'mon.alerting', 'mon.snmp', 'fw.path'],
  what: `
A **monitoring system** keeps an eye on every machine and service, all the time, and tells a person when something needs attention. It answers questions like "is srv01 up?", "how full is bak01's backup disk, and when will it be full?", "did last night's backups run?", "which router interface went down?". Good monitoring finds problems **before** the users do, and keeps the **history** needed to understand an incident afterwards.

Monitoring reads the same things you would check by hand: services ([systemd](#/lesson/systemd/what)), disks, interfaces, logs ([central logging](#/lesson/logging/what) is its neighbour), backups ([restic](#/lesson/backup/what)). It just does it every few seconds, everywhere, and remembers the results.

### Metrics, logs and checks
- **Metrics**: numbers over time (free disk space, requests per second, a service's state). Cheap to collect and store, good for trends, thresholds and graphs.
- **Logs**: events with text (central logging). Good for the *why*.
- **Checks**: "is it working right now?" (ping, an HTTP request, SNMP): the oldest form, still how scoring engines and simple tools work.

:::practice
Q: Which kind of data tells you that the backup disk grows by about 2 GB a day: metrics or logs?
A: **Metrics**: values over time show the trend (and let you predict when the disk will be full).
Q: Why is "the users will tell us" not a monitoring strategy?
A: Users notice late, report vaguely, and nobody tells you about problems that have not hurt anyone yet (a disk at 85%, failing backups, a dying fan).
:::

### Pull and push
**Prometheus pulls**: it connects to every target and fetches (**scrapes**) its metrics. **SNMP** polling also pulls; **SNMP traps**, syslog and many agents **push** to a central server. Pulling means the monitoring server knows when a target stops answering (up = 0); pushing works through firewalls that only allow outgoing connections.

:::practice
Q: A target stops answering. Which model notices this directly: pull or push?
A: **Pull**: the scrape fails, so the monitoring server knows immediately (up = 0). With push, silence looks the same as "nothing to report".
Q: Which port does Prometheus connect to on a Linux server running node_exporter?
A: TCP **9100**.
:::

### The pieces
- **Exporters** on the targets: node_exporter serves a machine's metrics on :9100.
- **Prometheus**: scrapes, stores time series, evaluates **rules**.
- **Alertmanager**: turns firing alerts into notifications (group, silence, route, send).
- **SNMP** agents (snmpd) on devices, polled by a manager.
- **Dashboards** (Grafana) draw the time series; this lab uses PromQL from the command line.

> In the lab, **mon01** (10.0.20.55) runs **Prometheus** (:9090) and **Alertmanager** (:9093). **node_exporter** runs on srv01, db01, fs01, mail01, bak01, log01 and mon01; each server's firewall lets only mon01 reach TCP 9100. Six alert rules watch availability, disks, load, time, failed units and backup age (the backup jobs publish their last success through the textfile collector). Pages (severity=page) go to **oncall@corp.lab**, tickets to **ops-tickets@corp.lab**, both delivered by **mail01** into the ops mailbox. mon01 polls **rtr01** by **SNMP** (community corp-mon, or the v3 user monitor). **Lab 9** brings a new server under monitoring. Simulated: node_exporter 1.5 (cpu, meminfo, loadavg, filesystem with the backup disk, netdev, time, timex, uname, systemd with unit-include, textfile, flags from /etc/default), Prometheus 2.42 (prometheus.yml with global/scrape_configs/rule_files/alerting validated like the real loader, scrapes over the simulated network with Go's error texts, up and scrape_duration_seconds, external labels, reload versus restart, the HTTP API for query, targets, alerts, rules), a PromQL subset (selectors, offset, arithmetic and comparison with bool and on/ignoring, and/or/unless, sum/avg/min/max/count/topk by/without, rate, increase, irate, *_over_time, predict_linear, absent, time, label_replace, ALERTS), rules with for, labels and templated annotations, Alertmanager 0.25 (routes with matchers, group_by/group_wait/group_interval/repeat_interval, inhibit rules, silences kept across restarts, email through the smarthost with STARTTLS, logged failures), promtool and amtool, net-snmp 5.9.3 snmpd (agentaddress, views, rocommunity with source, createUser/rouser with security levels) with the system, IF-MIB and HOST-RESOURCES trees, snmpget/snmpwalk/snmpbulkwalk with Debian's MIB setting. Simplified: Prometheus keeps only the last few samples per series (range functions see minutes, not days); no Grafana, remote storage, service discovery, recording-rule chains or SNMP traps; SNMP values beyond the listed tables are absent.

:::practice
Q: In the lab, where does a page for "srv01 is down" end up?
A: Prometheus on mon01 fires **InstanceDown**, Alertmanager routes it to **oncall@corp.lab**, and mail01 delivers it to the **ops mailbox**.
Q: Which machine in the lab is polled by SNMP, and from where?
A: **rtr01**, polled from **mon01**.
:::

`,

  internals: `
### 1. Time series and labels
A **time series** is a metric name plus a set of **labels**, with a value at each point in time:
\`\`\`
node_filesystem_avail_bytes{instance="bak01.corp.lab:9100", job="node", mountpoint="/srv/backup", device="/dev/vdb1", fstype="ext4"}
\`\`\`
**instance** and **job** are added by Prometheus from the scrape configuration; the others come from the exporter. Labels let one query cover many machines (\`node_filesystem_avail_bytes{mountpoint="/"}\`) or pick one. Metric **types**: a **counter** only goes up (node_network_receive_bytes_total, reset at reboot): use rate(); a **gauge** goes up and down (node_load1, free bytes).

:::practice
Q: Is node_cpu_seconds_total a counter or a gauge, and how do you turn it into something useful?
A: A **counter** (it only grows). Use **rate(node_cpu_seconds_total[5m])** to get the CPU seconds used per second.
Q: Which labels does Prometheus itself attach to every scraped series?
A: **job** (the scrape_configs job_name) and **instance** (the target's host:port).
:::

### 2. Exporters and scrapes
An exporter answers \`GET /metrics\` with plain text:
\`\`\`
# HELP node_load1 1m load average.
# TYPE node_load1 gauge
node_load1 0.21
\`\`\`
node_exporter's **collectors** read /proc, /sys and friends; the **systemd collector** (off by default, \`--collector.systemd\`) reports every unit's state; the **textfile collector** reads *.prom files that scripts write (a backup job's last success, a certificate's expiry date).

Prometheus scrapes every target in **scrape_configs** each **scrape_interval** (15 s here), with a **scrape_timeout** (10 s, never longer than the interval). For every scrape it records **up** (1 = it worked) and **scrape_duration_seconds**. Errors come from Go's HTTP client: "connect: connection refused" (nothing listens), "context deadline exceeded" (no answer in time: a firewall drop or a hung host), "server returned HTTP status 404" (wrong port or path).

:::practice
Q: A target's lastError is "context deadline exceeded" while curl localhost:9100/metrics on the target works. What is the likely cause?
A: Something between the monitoring server and the target **drops** the packets, usually the target's **firewall**, so the scrape times out.
Q: Which node_exporter flag adds the state of every systemd unit?
A: \`--collector.systemd\` (in ARGS of /etc/default/prometheus-node-exporter on Debian).
:::

### 3. PromQL
PromQL selects series and computes with them:
- \`up == 0\`: targets that are down (a comparison **filters**).
- \`node_filesystem_avail_bytes / node_filesystem_size_bytes < 0.10\`: filesystems with less than 10% free (series are matched by their labels).
- \`rate(node_network_receive_bytes_total[5m])\`: bytes per second over the last 5 minutes (a **range vector** \`[5m]\` fed to a function).
- \`sum by (instance) (rate(node_cpu_seconds_total{mode!="idle"}[5m]))\`: busy CPU per machine (**aggregation** with by/without).
- \`predict_linear(node_filesystem_avail_bytes[6h], 24*3600) < 0\`: will be full within a day (a **trend**, not a threshold).
- \`time() - restic_backup_last_success_timestamp_seconds > 26*3600\`: the last good backup is older than 26 hours.
- \`absent(up{job="node"})\`: the job is gone entirely.

:::practice
Q: Why is "disk will be full in 4 hours" often a better alert than "disk is 90% full"?
A: A 90% threshold fires on big, slow-growing disks that are fine for months and too late on small fast-filling ones; **predict_linear** looks at the rate of change and gives time to act.
Q: What does \`sum by (instance) (…)\` do to the labels?
A: It adds up the series and keeps **only the instance label**: one result per machine.
:::

### 4. Alert rules
\`\`\`
- alert: InstanceDown
  expr: up == 0
  for: 2m
  labels:
    severity: page
  annotations:
    summary: "{{ $labels.instance }} of job {{ $labels.job }} is down"
\`\`\`
Every **evaluation_interval** Prometheus runs the expression. Each returned series becomes an alert, **pending** at first; if it is still returned after **for:**, the alert is **firing** and goes to Alertmanager (re-sent every minute while it lasts). When the series disappears, the alert is **resolved**. Labels (severity) steer routing; annotations are the text of the notification. Prometheus also exposes the alerts as the series **ALERTS{alertname, alertstate}**.

Good rules are about **symptoms users feel** or that will hurt soon (down, full, failed backups), have a **for:** long enough to skip blips, and lead to an action. Rules that fire often and need no action teach people to ignore pages (**alert fatigue**).

:::practice
Q: A rule has for: 5m. The condition is true for 3 minutes, then false. Is anyone notified?
A: **No.** The alert was **pending** for 3 minutes and then resolved without ever firing.
Q: Which part of a rule decides whether an alert goes to the on-call phone or to the ticket queue?
A: Its **labels** (here severity), which Alertmanager's routes match on.
:::

### 5. Alertmanager
Alertmanager receives firing alerts and decides what to send, to whom, and how often:
- **Routing**: a tree of **routes**; each matches labels (\`severity="ticket"\`) and names a **receiver** (oncall: email to oncall@corp.lab). The first matching child wins; otherwise the parent's receiver.
- **Grouping** (\`group_by: [alertname, instance]\`): related alerts become one notification; **group_wait** (30 s) collects them first, **group_interval** (5 m) spaces updates, **repeat_interval** (4 h) re-sends while still firing.
- **Inhibition**: a source alert mutes target alerts (a machine that is down needs no "backup too old" ticket as well).
- **Silences**: muted on purpose for a time (maintenance), created with \`amtool silence add\`; stored so they survive restarts.
- **Receivers**: email (smtp_smarthost, STARTTLS by default), chat webhooks, pager services; \`send_resolved\` sends "[RESOLVED]" too.

Failures to notify are only visible in Alertmanager's log and its alertmanager_notifications_failed_total metric: test the path.

:::practice
Q: Ten servers go down at once (a switch failed). With group_by [alertname], how many mails does oncall get first?
A: **One**: all InstanceDown alerts share the group (alertname) and are sent together after group_wait.
Q: An alert is visible in Prometheus as firing, but \`amtool alert\` does not list it, and \`amtool alert -s\` does. Why?
A: It is **suppressed**, by a **silence** or an **inhibition**: Alertmanager has it but does not notify.
:::

### 6. SNMP
**SNMP** (Simple Network Management Protocol) is how routers, switches, printers, UPSs and many servers are monitored. A **manager** (mon01) sends requests over **UDP 161** to an **agent** (snmpd); devices can also send **traps** to the manager on **UDP 162**. Values are addressed by **OIDs** (object identifiers), numbers in a tree defined by **MIBs**:
- \`1.3.6.1.2.1.1.5.0\` = SNMPv2-MIB::sysName.0 (the device name), \`.1.3.6.1.2.1.1.3.0\` sysUpTime;
- \`1.3.6.1.2.1.2.2.1\` = IF-MIB::ifTable: ifDescr (.2), ifOperStatus (.8: 1 up, 2 down), ifInOctets (.10), ifOutOctets (.16);
- \`1.3.6.1.2.1.25\` = HOST-RESOURCES-MIB (uptime, storage).

\`snmpget\` reads one OID, \`snmpwalk\` a subtree (GETNEXT after GETNEXT), \`snmpbulkwalk\` the same with fewer requests (v2c/v3).

**Versions and security**: v1/v2c authenticate with a **community** string, sent in **clear text**, limited by a **source** address and a **view** (\`rocommunity corp-mon 10.0.20.55 -V all\`). **SNMPv3** has **users** (createUser, rouser) with a **security level**: noAuthNoPriv, authNoPriv (SHA/MD5 authentication), **authPriv** (authentication plus AES/DES encryption). Never leave the default community **public** open, and prefer v3.

Debian's snmpd listens on **127.0.0.1** only and answers "public" with the **systemonly** view; the tools print numeric OIDs because MIB loading is off ("mibs :" in /etc/snmp/snmp.conf). A request that is not allowed is **ignored**: the manager only sees "Timeout: No Response", whether the port is closed, the community wrong, the source not allowed or a firewall dropped it.

:::practice
Q: snmpwalk from mon01 to a new switch says "Timeout: No Response". Name three possible causes.
A: The agent listens on **localhost only** (agentaddress), the **community or source** is not allowed (silently ignored), or a **firewall** drops UDP 161. (Also: wrong version or host.)
Q: Which SNMP security level authenticates the manager and encrypts the data?
A: **authPriv** (SNMPv3).
:::

### 7. Baselines, thresholds and what to watch
- **Baseline**: what is normal for this machine (load, traffic, error counts). Alert on deviation from the baseline or on user-visible symptoms, not on arbitrary numbers.
- **The four golden signals** for services: latency, traffic, errors, saturation. For machines (USE): utilisation, saturation, errors.
- **Watch the watcher**: monitor Prometheus and Alertmanager themselves, and send a heartbeat alert that must always fire to an external service.
- **Capacity**: trends of disk, bandwidth and memory, so upgrades are planned, not emergencies.

:::practice
Q: Why monitor the monitoring system with something outside it?
A: If Prometheus stops, **no alert can fire**, including "Prometheus is down": only an outside check (or a missing heartbeat) can notice.
Q: What is a baseline?
A: The **normal** behaviour of a system (typical load, traffic, error rate), against which unusual values are recognised.
:::

`,

  deployment: [
    {
      id: 'debian',
      platform: 'Debian 12: Prometheus, Alertmanager and node_exporter',
      summary: 'Install the stack, add targets and rules safely, route alerts, and test the whole path. Steps marked simulated can be tried in the sandbox: "On srv01" steps on srv01, the others on mon01. Lab 9 walks through bringing a new server under monitoring.',
      prerequisites: ['A monitoring server with a fixed address (mon01), DNS names for the targets.', 'A mail server (or chat webhook) for notifications.', 'Firewall rules: targets allow TCP 9100 from the monitoring server only.'],
      steps: [
        { title: 'Install', command: 'sudo apt install prometheus prometheus-alertmanager        # on mon01\nsudo apt install prometheus-node-exporter                    # on every server', what: 'Debian packages with units, users and default configuration in /etc/prometheus and /etc/default.', why: 'The packages enable and start the services; Prometheus already scrapes itself and the local exporter.', expected: '' },
        { title: 'On srv01: check the exporter', command: "systemctl status prometheus-node-exporter\ncat /etc/default/prometheus-node-exporter\ncurl -s localhost:9100/metrics | grep -c '^node_'", what: 'The exporter runs, with the systemd collector enabled in ARGS, and serves its metrics.', why: 'Always look at what a target serves before scraping it.', expected: '75', simulated: true },
        { title: 'Targets and a safe reload', command: `promtool check config /etc/prometheus/prometheus.yml\nsystemctl reload prometheus\njournalctl -u prometheus -n 2\n${PQ('up == 1')}`, what: 'The node job lists the servers (host:9100). Check the file, reload, read the result, then see the targets up.', why: 'A reload with a bad file keeps the old configuration; a restart with one stops monitoring.', expected: ' SUCCESS: /etc/prometheus/prometheus.yml is valid prometheus config file syntax', simulated: true },
        { title: 'A trend-based disk alert', command: `printf '%s\\n' 'groups:' '  - name: trends' '    rules:' '      - alert: RootFilesystemFillingUp' '        expr: predict_linear(node_filesystem_avail_bytes{mountpoint="/"}[6h], 24 * 3600) < 0' '        for: 30m' '        labels:' '          severity: ticket' '        annotations:' '          summary: "/ on {{ $labels.instance }} will be full within a day"' > /etc/prometheus/rules/trends.yml\npromtool check rules /etc/prometheus/rules/trends.yml\nsystemctl reload prometheus\n${PQ('predict_linear(node_filesystem_avail_bytes{mountpoint="/"}[30m], 24 * 3600) < 0')}`, what: 'A rule file with one alert, checked and loaded; the query shows that nothing matches today. (Write rule files with an editor; printf keeps the step runnable.)', why: 'Alerts on trends give time to act; a threshold alone fires too late or too often.', expected: '  SUCCESS: 1 rules found', simulated: true },
        { title: 'Routes and receivers', command: 'amtool check-config /etc/prometheus/alertmanager.yml\namtool config routes\namtool config routes test severity=ticket alertname=RootFilesystemFillingUp', what: 'The routing tree: pages to oncall, tickets to the ticket queue; test which receiver a set of labels reaches.', why: 'Route mistakes send pages nowhere, or wake people up for tickets.', expected: 'tickets', simulated: true },
        { title: 'Maintenance silences', command: 'amtool silence add instance=srv01.corp.lab:9100 --duration=1h --comment="kernel update CHG-2700"\namtool silence query', what: 'Silence one server for one hour, with a reason.', why: 'Planned work should not page anyone, but nothing else may be silenced.', expected: 'instance="srv01.corp.lab:9100"', simulated: true },
        { title: 'SNMP polling', command: 'snmpget -v3 -l authPriv -u monitor -a SHA -A Snmp-Auth-2611 -x AES -X Snmp-Priv-2611 rtr01.corp.lab .1.3.6.1.2.1.1.5.0\nsnmpwalk -v2c -c corp-mon -m ALL rtr01.corp.lab IF-MIB::ifOperStatus', what: 'SNMPv3 read of the router\'s name; the interface status table by MIB name.', why: 'Network devices are monitored by SNMP (or snmp_exporter, which turns the same OIDs into Prometheus metrics).', expected: 'IF-MIB::ifOperStatus.2 = INTEGER: up(1)', simulated: true },
        { title: 'Test the alert path', command: '# Stop a non-critical service on a test machine, wait for:+group_wait,\n# check the mailbox, start it again, and expect a [RESOLVED] mail.', what: 'An end-to-end test of rules, routing and delivery.', why: 'A page path that was never tested is not known to work (Lab 9 does exactly this).', expected: '' },
      ],
    },
    {
      id: 'rhel',
      platform: 'RHEL 9 / Rocky / Alma',
      summary: 'Prometheus and its exporters come as release binaries or from community repositories (EPEL ships golang-github-prometheus-node-exporter); the configuration files and concepts are identical. Remember SELinux contexts and firewall-cmd.',
      prerequisites: ['sudo dnf install golang-github-prometheus-node-exporter net-snmp net-snmp-utils'],
      steps: [
        { title: 'Open the ports', command: 'sudo firewall-cmd --permanent --add-rich-rule=\'rule family="ipv4" source address="10.0.20.55" port port="9100" protocol="tcp" accept\'\nsudo firewall-cmd --permanent --add-rich-rule=\'rule family="ipv4" source address="10.0.20.55" service name="snmp" accept\'\nsudo firewall-cmd --reload', what: 'Scrapes and SNMP from the monitoring server only.', why: 'Same rule as on Debian, in firewalld syntax.', expected: 'success' },
      ],
    },
    {
      id: 'windows',
      platform: 'Windows Server',
      summary: 'windows_exporter (port 9182) serves Windows metrics (CPU, memory, disks, services, IIS) to Prometheus; Windows also has an SNMP service feature (deprecated), Performance Monitor counters and Event Viewer subscriptions.',
      prerequisites: ['windows_exporter MSI installed as a service.'],
      steps: [
        { title: 'Firewall and scrape', command: 'New-NetFirewallRule -DisplayName "windows_exporter" -Direction Inbound -Protocol TCP -LocalPort 9182 -RemoteAddress 10.0.20.55 -Action Allow\n# prometheus.yml: - job_name: windows  static_configs: - targets: [\'win01.corp.lab:9182\']', what: 'Open the exporter port to mon01 and add a job.', why: 'Same pull model, different exporter.', expected: '' },
      ],
    },
    {
      id: 'other',
      platform: 'Other tools',
      summary: 'Zabbix (agent on 10050, server polls or agents push, built-in SNMP and templates), Nagios/Icinga (active checks returning OK/WARNING/CRITICAL), LibreNMS/Observium (SNMP-centric network monitoring), Grafana for dashboards on top of Prometheus, and cloud monitoring (CloudWatch, Azure Monitor). The same ideas apply: targets, checks or metrics, thresholds, notifications, maintenance windows.',
      prerequisites: [],
      steps: [
        { title: 'A Nagios-style check', command: '/usr/lib/nagios/plugins/check_http -H status.corp.lab -w 2 -c 5\n# HTTP OK: HTTP/1.1 200 OK - 512 bytes in 0.004 second response time', what: 'A check plugin returns a status (0 OK, 1 WARNING, 2 CRITICAL) and a line of text.', why: 'Check-based systems ask "is it OK now?"; metric systems keep the numbers and decide later.', expected: '' },
      ],
    },
  ],

  configIntro: `
Monitoring is configured in four places:
- **What is measured**: exporter flags (/etc/default/prometheus-node-exporter), textfile *.prom files, snmpd.conf on agents.
- **What is collected**: /etc/prometheus/prometheus.yml (scrape_configs, intervals, external_labels).
- **What is a problem**: rule files (rules/*.yml), referenced by rule_files.
- **Who is told, how**: /etc/prometheus/alertmanager.yml (route, receivers, inhibit_rules) and the silences.

### Check before you reload
- \`promtool check config /etc/prometheus/prometheus.yml\` (includes every rule file);
- \`promtool check rules FILE\`;
- \`amtool check-config /etc/prometheus/alertmanager.yml\`;
- then \`systemctl reload …\` and read the journal.

:::practice
Q: Which command validates prometheus.yml and every rule file it references?
A: \`promtool check config /etc/prometheus/prometheus.yml\`.
Q: You changed alertmanager.yml. How do you apply it without restarting?
A: \`amtool check-config\`, then \`systemctl reload prometheus-alertmanager\` (or POST /-/reload).
:::

`,

  configFiles: [
    { platform: 'Prometheus stack (Debian)', items: [
      { path: '/etc/prometheus/prometheus.yml', purpose: 'Scrape jobs and targets, intervals, rule files, Alertmanager address.' },
      { path: '/etc/prometheus/rules/*.yml', purpose: 'Alert and recording rules.' },
      { path: '/etc/prometheus/alertmanager.yml', purpose: 'Routes, receivers, inhibition, SMTP settings.' },
      { path: '/etc/default/prometheus, /etc/default/prometheus-alertmanager', purpose: 'Command-line flags (ARGS) of the servers.' },
      { path: '/etc/default/prometheus-node-exporter', purpose: 'Collector flags of the exporter.' },
      { path: '/var/lib/prometheus/node-exporter/*.prom', purpose: 'Metrics written by scripts (textfile collector).' },
      { path: '/var/lib/prometheus/metrics2, /var/lib/prometheus/alertmanager', purpose: 'Time-series database; Alertmanager state (silences).' },
    ] },
    { platform: 'SNMP (net-snmp)', items: [
      { path: '/etc/snmp/snmpd.conf, snmpd.conf.d/*.conf', purpose: 'Agent: listen address, views, communities, v3 users.' },
      { path: '/var/lib/snmp/snmpd.conf', purpose: 'Persistent agent data: createUser lines are turned into keys here.' },
      { path: '/etc/snmp/snmp.conf', purpose: 'Tools: MIB loading ("mibs :" disables it on Debian).' },
    ] },
  ],

  directives: [
    { name: 'scrape_interval / evaluation_interval', compiledDefault: '1m', recommended: '15s–60s', explanation: 'How often targets are scraped and rules evaluated.', security: '' },
    { name: 'scrape_timeout', compiledDefault: '10s', recommended: 'Below the interval', explanation: 'How long a scrape may take; longer than the interval is a configuration error.', security: '' },
    { name: 'for:', compiledDefault: '0 (fire at once)', recommended: 'A few minutes for pages', explanation: 'How long the condition must hold before the alert fires.', security: '' },
    { name: 'group_by / group_wait / group_interval / repeat_interval', compiledDefault: 'none / 30s / 5m / 4h', recommended: 'group_by alertname (+ cluster/instance)', explanation: 'How alerts are bundled and how often notifications are sent.', security: '' },
    { name: 'smtp_require_tls', compiledDefault: 'true', recommended: 'true', explanation: 'Use STARTTLS for notification mail.', security: 'Notifications reveal internal names and problems: keep them encrypted.' },
    { name: '--collector.systemd', compiledDefault: 'off', recommended: 'on for servers', explanation: 'Report systemd unit states (failed units, stopped services).', security: '' },
    { name: 'agentaddress (snmpd)', compiledDefault: 'Debian: 127.0.0.1,[::1]', recommended: 'udp:161 plus a firewall rule for the manager', explanation: 'Where snmpd listens.', security: 'Open to the monitoring server only.' },
    { name: 'rocommunity / rouser', compiledDefault: 'Debian: public with the systemonly view', recommended: 'SNMPv3 rouser … authpriv; no public', explanation: 'Who may read what.', security: 'Communities travel in clear text; "public" is the first thing scanners try.' },
  ],

  operateIntro: `
### Every day
- **Targets**: \`${PQ('up == 0')}\` should return nothing.
- **Alerts**: what is firing (\`amtool alert\`), what is silenced (\`amtool silence query\`): silences end with their maintenance.
- **Notifications**: Alertmanager's journal has no "Notify for alerts failed".
- **Trends**: disks, backup age, certificate expiry before they become alerts.

:::practice
Q: Which query lists every target that Prometheus cannot scrape?
A: \`up == 0\`.
Q: Why review the active silences every day?
A: A silence that is too broad or too long hides **real outages** without any error message.
:::

### Bringing a new server under monitoring
1. Install and configure the exporter (collectors you need, e.g. systemd).
2. Open its port to the monitoring server only.
3. Add the target to the right job; \`promtool check config\`, reload, check up.
4. Rules for what matters on this server (its service, its data); check, reload.
5. Test: break it on purpose, see the page arrive, repair it.
6. Network devices: SNMPv3 user, view, firewall for the manager.

:::practice
Q: After adding a target, Prometheus shows it with health "down" and lastError "connect: connection refused". What do you check on the target?
A: Whether the **exporter is running** and listening on the port (systemctl status, ss -tlnp): "refused" means nothing listens.
Q: Why test a new alert by breaking something on purpose?
A: Every link (rule, route, receiver, mail) can be wrong without any error; only a real alert proves the **whole path**.
:::

### Alert hygiene
Every alert should need a human action. If it does not, change the rule (a longer for:, a better expression, a ticket instead of a page) or delete it. Pages wake people; tickets wait for working hours. Write annotations that say **what is wrong and where**, and link the runbook.

:::practice
Q: An alert fires several times a day and resolves on its own within a minute. What should you do?
A: Fix the rule: a longer **for:**, a better expression or a lower severity. An alert nobody acts on trains people to ignore pages (**alert fatigue**).
Q: What is the difference between a page and a ticket?
A: A **page** needs someone now (it wakes the on-call person); a **ticket** can wait for working hours.
:::

`,
  troubleshootingIntro: `
### Follow the chain from the target to the inbox
1. **Is Prometheus running, with the configuration you think?** \`systemctl status prometheus\`, \`journalctl -u prometheus\`: "Error loading config" (stopped) or "Error reloading config" (old configuration).
2. **Is the target scraped?** \`up\` and the target's lastError: refused (exporter), deadline exceeded (firewall, host), 404 (port/path).
3. **Does the rule return what you expect?** Run its expression with promtool query; look at its state in api/v1/rules.
4. **Did Alertmanager get it, and is it suppressed?** \`amtool alert query -s\`, \`amtool silence query\`, inhibit_rules.
5. **Was it delivered?** Alertmanager's journal ("Notify for alerts failed") and the mail server's log.
6. **SNMP**: a timeout means the agent ignored or never got the request: listen address, community/user, source, firewall.

:::practice
Q: An alert is firing in Prometheus but the on-call person got nothing, and Alertmanager's log is clean. What do you check?
A: **Silences and inhibition** (amtool alert query -s, amtool silence query) and the **route** (amtool config routes test): suppression and routing are not logged as errors.
Q: snmpget on the agent itself works, but from the manager it times out. Where do you look first?
A: The agent's **listen address** (ss -ulnp, agentaddress) and its **firewall**; then the community/source in snmpd.conf.
:::

`,

  errorMap: [
    { message: 'Get "http://HOST:9100/metrics": context deadline exceeded', layer: 'Path (firewall / host)', meaning: 'No answer within scrape_timeout: dropped packets, a down host, a hung exporter.', firstCheck: 'curl -m 5 from mon01; nft list ruleset on the target' },
    { message: 'Get "…": dial tcp IP:9100: connect: connection refused', layer: 'Exporter', meaning: 'The host answered but nothing listens on the port.', firstCheck: 'systemctl status prometheus-node-exporter on the target' },
    { message: 'server returned HTTP status 404 Not Found', layer: 'Target address', meaning: 'Wrong port or metrics_path (another web server answered).', firstCheck: 'The target address and metrics_path in prometheus.yml' },
    { message: 'msg="Error loading config" … (prometheus failed)', layer: 'Prometheus start', meaning: 'Invalid prometheus.yml or rule file at start: Prometheus stopped.', firstCheck: 'promtool check config /etc/prometheus/prometheus.yml' },
    { message: 'msg="Error reloading config"', layer: 'Prometheus reload', meaning: 'The new file is invalid; the old configuration keeps running.', firstCheck: 'journalctl -u prometheus; promtool check config' },
    { message: 'field X not found in type config.GlobalConfig / ScrapeConfig', layer: 'Configuration', meaning: 'A misspelled or misplaced key in prometheus.yml.', firstCheck: 'The line named in the message (indentation)' },
    { message: 'unknown long flag \'--…\', try --help (node_exporter)', layer: 'Exporter start', meaning: 'A wrong flag in ARGS: the exporter exits.', firstCheck: 'cat /etc/default/prometheus-node-exporter' },
    { message: 'msg="Error sending alert" component=notifier', layer: 'Prometheus → Alertmanager', meaning: 'Prometheus cannot reach Alertmanager (down, wrong address).', firstCheck: 'systemctl status prometheus-alertmanager; alerting.alertmanagers' },
    { message: 'msg="Notify for alerts failed" … send RCPT TO: 554 5.7.1 … Relay access denied', layer: 'Notification (SMTP)', meaning: 'The mail server refused the notification (here: port 587 needs authentication).', firstCheck: 'smtp_smarthost and auth settings; the mail server\'s log' },
    { message: 'Timeout: No Response from AGENT', layer: 'SNMP', meaning: 'The agent did not answer: not listening there, wrong community/source, firewall, wrong version.', firstCheck: 'ss -ulnp and snmpd.conf on the agent; snmpget locally' },
    { message: 'Authentication failure (incorrect password, community or key)', layer: 'SNMPv3', meaning: 'Wrong auth passphrase or protocol for the user.', firstCheck: 'createUser line; -a/-A options' },
    { message: 'Error in packet / Reason: authorizationError (access denied to that object)', layer: 'SNMPv3 access', meaning: 'The user exists but the security level or view does not allow the request.', firstCheck: 'rouser level (authpriv) and view' },
    { message: 'IF-MIB::ifDescr: Unknown Object Identifier', layer: 'SNMP tools', meaning: 'MIBs are not loaded (Debian default) or not installed.', firstCheck: 'Use numeric OIDs, -m ALL, or comment out "mibs :" in /etc/snmp/snmp.conf' },
  ],

  scenarioIds: ['mon-fs01-firewall', 'mon-prom-timeout', 'mon-am-submission', 'mon-silence-log01', 'mon-backup-alert', 'snmp-dpkg-default', 'mon-exporter-flag'],
  assessmentId: 'monitoring',
  references: [
    { title: 'Prometheus documentation: Configuration', url: 'https://prometheus.io/docs/prometheus/latest/configuration/configuration/' },
    { title: 'Prometheus: Querying basics (PromQL)', url: 'https://prometheus.io/docs/prometheus/latest/querying/basics/' },
    { title: 'Prometheus: Alerting rules', url: 'https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/' },
    { title: 'Alertmanager documentation', url: 'https://prometheus.io/docs/alerting/latest/alertmanager/' },
    { title: 'node_exporter (GitHub)', url: 'https://github.com/prometheus/node_exporter' },
    { title: 'Net-SNMP documentation: snmpd.conf(5)', url: 'http://www.net-snmp.org/docs/man/snmpd.conf.html' },
    { title: 'Google SRE book: Monitoring Distributed Systems', url: 'https://sre.google/sre-book/monitoring-distributed-systems/' },
  ],
  guide: MONITORING_GUIDE,
};

// --- Primer -------------------------------------------------------------------------

export const MONITORING_PRIMER: Primer = {
  oneLiner: '**Monitoring** measures every machine and service all the time, keeps the numbers, and **alerts** a person when a rule says something needs attention, ideally before users notice.',
  analogy: `
A hospital ward. Every patient wears sensors (**exporters**) that show pulse, temperature and oxygen. A nurse walks the ward every few minutes and writes every value on the chart (**Prometheus scraping and storing**). Rules on the wall say when to call a doctor: "oxygen under 90% for more than two minutes" (**an alert rule with for:**).

The call does not go straight to every doctor: a dispatcher (**Alertmanager**) bundles calls from the same ward, sends them to the doctor on duty (**routing**), does not call about a patient in surgery (**silence**), and does not call about a patient's heart rate when the patient is already being resuscitated (**inhibition**). Some older machines in the building only answer when asked, in their own language (**SNMP**). And someone regularly checks that the nurse is still doing the rounds (**watching the watcher**).`,
  ideas: [
    {
      title: 'Metrics and labels',
      explain: 'Numbers over time, each with labels that say what they belong to.',
      example: '`node_filesystem_avail_bytes{instance="bak01.corp.lab:9100", mountpoint="/srv/backup"}`: free space on bak01\'s backup disk, every 15 seconds.',
    },
    {
      title: 'Exporters and scrapes',
      explain: 'Each machine serves its metrics over HTTP; Prometheus fetches them and records whether it worked (up).',
      example: 'On mon01: `curl -s http://srv01.corp.lab:9100/metrics | head`; `promtool query instant http://localhost:9090 \'up == 0\'` lists unreachable targets.',
    },
    {
      title: 'Alert rules',
      explain: 'A PromQL condition that must hold for a while (for:) before it fires, with labels that decide who is told.',
      example: 'InstanceDown: `up == 0` for 2 minutes, severity page → oncall@corp.lab.',
    },
    {
      title: 'Alertmanager',
      explain: 'Groups alerts, routes them to receivers, honours silences, and sends the notifications.',
      example: '`amtool alert` lists active alerts; `amtool silence add instance=srv01.corp.lab:9100 --duration=1h --comment="kernel update"` silences one server for an hour.',
    },
    {
      title: 'SNMP',
      explain: 'The protocol network devices are polled with: OIDs over UDP 161, communities (v2c) or users (v3).',
      example: '`snmpget -v2c -c corp-mon rtr01.corp.lab .1.3.6.1.2.1.1.5.0` returns `STRING: "rtr01"`.',
    },
  ],
  walkthrough: {
    title: 'srv01\'s exporter stops',
    steps: [
      { label: 'Scrape fails', detail: 'Prometheus on mon01 asks srv01:9100 for /metrics: "connection refused". up{instance="srv01.corp.lab:9100"} becomes 0.' },
      { label: 'Rule pending', detail: 'InstanceDown (up == 0) matches; the alert is pending while for: 2m runs.' },
      { label: 'Rule fires', detail: 'Still down after 2 minutes: the alert fires and is sent to Alertmanager.' },
      { label: 'Routed and grouped', detail: 'Alertmanager matches severity=page → receiver oncall, waits group_wait (30 s) for related alerts.' },
      { label: 'Notified', detail: 'One mail "[FIRING:1] InstanceDown srv01.corp.lab:9100" goes through mail01 to oncall@corp.lab; when the exporter is back, "[RESOLVED]" follows.' },
    ],
  },
  misconceptions: [
    { myth: 'If no alert fires, everything is fine.', truth: 'A stopped Prometheus, a broken route, a forgotten silence or a failing mail server all mean silence: monitor the monitoring and test the path.' },
    { myth: 'More alerts mean better monitoring.', truth: 'Alerts nobody acts on train people to ignore pages. Alert on symptoms that need action.' },
    { myth: 'An SNMP timeout means the device is down.', truth: 'It also means a wrong community, a source not allowed, an agent on localhost only or a firewall: SNMP never says "access denied" in v2c.' },
    { myth: 'An alert about a server always means the server is broken.', truth: 'It can be the monitoring path (a firewall change) or, as with BackupTooOld, a real problem nobody saw. Read the alert\'s expression.' },
  ],
  checks: [
    { q: 'Which metric tells whether Prometheus could scrape a target?', a: 'up (1 = yes, 0 = no).' },
    { q: 'What does for: 5m in an alert rule mean?', a: 'The condition must hold for 5 minutes before the alert fires (pending until then).' },
    { q: 'Which tool lists and creates silences?', a: 'amtool (amtool silence add / query / expire).' },
    { q: 'Which UDP ports does SNMP use?', a: '161 for requests to the agent, 162 for traps to the manager.' },
  ],
};

// --- Assessment -------------------------------------------------------------------------

export const MONITORING_ASSESSMENT: Assessment = {
  id: 'monitoring',
  title: 'Monitoring knowledge check',
  questions: [
    {
      id: 'mon-q-chain',
      kind: 'order',
      level: 'beginner',
      learn: ['lesson/monitoring/internals'],
      prompt: 'Order the steps from a stopped exporter to the on-call notification.',
      items: ['Prometheus\'s scrape fails and up becomes 0', 'The alert rule matches and the alert is pending', 'After for: the alert fires and is sent to Alertmanager', 'Alertmanager routes and groups it, waiting group_wait', 'The receiver sends the notification'],
      concepts: ['mon.alerting'],
      explanation: 'Each link can fail on its own: test the whole chain.',
    },
    {
      id: 'mon-q-deadline',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/monitoring/internals', 'lesson/monitoring/troubleshoot'],
      prompt: 'A target\'s lastError is "context deadline exceeded". On the target, curl localhost:9100/metrics works. What is the most likely cause?',
      options: [
        { text: 'A firewall drops the scrape from the monitoring server', correct: true },
        { text: 'node_exporter is not running', misconception: 'Then the target would answer "connection refused" (and curl localhost would fail).' },
        { text: 'The alert rule has a syntax error', misconception: 'Rules do not affect scrapes.' },
        { text: 'Alertmanager is down', misconception: 'Alertmanager has nothing to do with scraping.' },
      ],
      concepts: ['mon.metrics'],
      explanation: 'A timeout means no answer at all: dropped packets on the path or at the target.',
    },
    {
      id: 'mon-q-reload',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/monitoring/config'],
      prompt: 'You added a target with an indentation error to prometheus.yml and ran systemctl reload prometheus. What happens?',
      options: [
        { text: 'Prometheus logs "Error reloading config" and keeps running the old configuration', correct: true },
        { text: 'Prometheus stops', misconception: 'That happens on a restart with an invalid file, not on a reload.' },
        { text: 'Prometheus loads every valid part of the file', misconception: 'A configuration is applied completely or not at all.' },
      ],
      concepts: ['mon.alerting'],
      explanation: 'Check with promtool before reloading, and read the journal afterwards.',
    },
    {
      id: 'mon-q-for',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/monitoring/internals'],
      prompt: 'An alert rule has for: 10m. Its condition is true from 09:00 to 09:07. When is the alert sent to Alertmanager?',
      options: [
        { text: 'Never: it stayed pending and resolved before 10 minutes', correct: true },
        { text: 'At 09:00', misconception: 'for: delays firing until the condition held for 10 minutes.' },
        { text: 'At 09:10', misconception: 'The condition was no longer true at 09:10.' },
      ],
      concepts: ['mon.alerting'],
      explanation: 'for: filters short blips; choose it so real problems still page in time.',
    },
    {
      id: 'mon-q-silence',
      kind: 'multi',
      level: 'intermediate',
      learn: ['lesson/monitoring/operate'],
      prompt: 'Which make a maintenance silence safe? (choose all that apply)',
      options: [
        { text: 'It names the instance being worked on', correct: true },
        { text: 'It ends when the maintenance window ends', correct: true },
        { text: 'Its comment says what work and which change', correct: true },
        { text: 'It matches job="node" so nothing is missed', misconception: 'That silences every server: real outages elsewhere go unnoticed.' },
      ],
      concepts: ['mon.alerting'],
      explanation: 'Narrow, short, explained silences; review active ones daily.',
    },
    {
      id: 'mon-q-snmp-version',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/monitoring/internals'],
      prompt: 'Which SNMP version authenticates and encrypts the requests?',
      options: [
        { text: 'SNMPv3 with the authPriv security level', correct: true },
        { text: 'SNMPv2c with a long community string', misconception: 'The community travels in clear text, however long it is.' },
        { text: 'SNMPv1', misconception: 'v1 has only communities, in clear text.' },
      ],
      concepts: ['mon.snmp'],
      explanation: 'v3 users with SHA authentication and AES privacy; noAuthNoPriv and authNoPriv are weaker levels.',
    },
    {
      id: 'mon-q-snmp-timeout',
      kind: 'multi',
      level: 'intermediate',
      learn: ['lesson/monitoring/internals', 'lesson/monitoring/troubleshoot'],
      prompt: 'snmpwalk -v2c from the monitoring server to a switch prints "Timeout: No Response". Which causes fit? (choose all that apply)',
      options: [
        { text: 'The community string is wrong', correct: true },
        { text: 'The agent listens on 127.0.0.1 only', correct: true },
        { text: 'A firewall drops UDP 161', correct: true },
        { text: 'The OID is outside the view', misconception: 'Then the agent answers, with "No Such Object" or nothing below the OID: not a timeout.' },
      ],
      concepts: ['mon.snmp'],
      explanation: 'SNMPv2c agents ignore requests they do not accept, so many causes look the same.',
    },
    {
      id: 'mon-q-promql',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/monitoring/internals'],
      prompt: 'Which expression gives the network bytes received per second over the last 5 minutes?',
      options: [
        { text: 'rate(node_network_receive_bytes_total[5m])', correct: true },
        { text: 'node_network_receive_bytes_total[5m]', misconception: 'That selects the raw counter samples; it is not a per-second value.' },
        { text: 'sum(node_network_receive_bytes_total)', misconception: 'A counter\'s total since boot, not a rate.' },
      ],
      concepts: ['mon.metrics'],
      explanation: 'Counters only grow; rate() turns them into per-second values and handles resets.',
    },
    {
      id: 'mon-q-port',
      kind: 'text',
      level: 'beginner',
      learn: ['lesson/monitoring/what'],
      prompt: 'On which TCP port does node_exporter serve its metrics by default?',
      accept: ['9100'],
      placeholder: 'port',
      concepts: ['mon.metrics'],
      explanation: 'node_exporter 9100, Prometheus 9090, Alertmanager 9093; SNMP UDP 161/162.',
    },
    {
      id: 'mon-q-watch',
      kind: 'single',
      level: 'advanced',
      learn: ['lesson/monitoring/internals'],
      prompt: 'How do you get told when Prometheus itself stops?',
      options: [
        { text: 'A heartbeat alert that always fires, checked by an outside service that alerts when it stops arriving', correct: true },
        { text: 'An alert rule "Prometheus is down" in Prometheus', misconception: 'A stopped Prometheus evaluates no rules.' },
        { text: 'Lower the scrape interval', misconception: 'A stopped server scrapes nothing at any interval.' },
      ],
      concepts: ['mon.alerting'],
      explanation: 'The "dead man\'s switch" pattern, or a second Prometheus monitoring the first.',
    },
  ],
};
