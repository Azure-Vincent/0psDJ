// Monitoring tickets: Prometheus on mon01 scrapes node_exporter on the servers,
// Alertmanager mails pages through mail01, and mon01 polls rtr01 by SNMP. Each
// ticket breaks something an administrator meets in real monitoring work: a
// firewall change that hides a healthy server, a configuration that stops
// Prometheus, notifications that cannot be delivered, a forgotten silence, an
// alert that is right, an snmpd package update and an exporter that will not
// start.

import { readFile, writeFile } from '../fs';
import { REPO_ROOT } from '../lab/backupLab';
import { DEBIAN_SNMPD_CONF, snmpExchange } from '../sim/snmp';
import { type AmLoaded, monitoringAdvance, type PromLoaded, SILENCES_FILE } from '../sim/monitor';
import { sha256Hex } from '../util/sha256';
import { tcpConnect } from '../sim/tcp';
import { nights } from './backupScenarios';
import { script } from './engine';
import type { Constraint, Goal, Scenario } from './types';

const BRIEFING = [
  'mon01 (10.0.20.55) runs Prometheus (:9090), Alertmanager (:9093) and node_exporter from Debian\'s packages; configuration in /etc/prometheus (prometheus.yml, rules/*.yml, alertmanager.yml) and /etc/default/prometheus*.',
  'node_exporter (:9100, with the systemd collector) runs on srv01, db01, fs01, mail01, bak01, log01 and mon01; each server\'s firewall lets only mon01 reach TCP 9100. Pages go to oncall@corp.lab, tickets to ops-tickets@corp.lab: both land in the ops mailbox on mail01 (/home/ops/Maildir).',
  'Ask Prometheus: promtool query instant http://localhost:9090 \'up\'; curl -s http://localhost:9090/api/v1/targets; curl -s http://localhost:9090/api/v1/alerts. Ask Alertmanager: amtool alert, amtool silence query. Check files before reloading: promtool check config, amtool check-config.',
  'rtr01 runs snmpd (net-snmp); mon01 polls it with the community corp-mon or the SNMPv3 user monitor. Policy: monitoring ports stay closed to everyone but mon01, no public SNMP community, and fixes must survive a reboot.',
];

const TERMINALS = [
  { hostId: 'mon01', user: 'root', label: 'mon01 (monitoring)', banner: 'mon01: Prometheus, Alertmanager. Try: promtool query instant http://localhost:9090 \'up\', amtool alert, journalctl -u prometheus -n 20, curl -s http://localhost:9090/api/v1/targets.' },
  { hostId: 'srv01', user: 'root', label: 'srv01 (web server)', banner: 'srv01: node_exporter on :9100. Try: curl -s localhost:9100/metrics | head, systemctl status prometheus-node-exporter.' },
  { hostId: 'mail01', user: 'root', label: 'mail01 (mail server)', banner: 'mail01: alerts arrive in the ops mailbox. Try: ls /home/ops/Maildir/new, tail -n 20 /var/log/mail.log.' },
  { hostId: 'rtr01', user: 'root', label: 'rtr01 (router, snmpd)', banner: 'rtr01: snmpd answers SNMP from mon01. Try: systemctl status snmpd, ss -ulnp, cat /etc/snmp/snmpd.conf.' },
];

const CANDIDATES = [
  'mon-scrape-blocked', 'mon-exporter-down', 'mon-config-invalid', 'mon-notify-failed', 'mon-silenced', 'mon-alert-true',
  'snmp-agent-localhost', 'snmp-access-denied', 'firewall-drop', 'bk-stale-lock', 'dns-wrong-record',
];

const PROM = 'http://localhost:9090';
/** Prometheus scraped the target again, and it is up. */
const targetUp = (host: string): Goal => ({
  kind: 'command',
  description: `Prometheus scrapes ${host}'s node_exporter successfully (up == 1).`,
  steps: [{ host: 'mon01', user: 'root', command: 'sleep 20' }, { host: 'mon01', user: 'root', command: `promtool query instant ${PROM} 'up{instance="${host}.corp.lab:9100"}'` }],
  expect: '=> 1 @',
});

/** TCP 9100 on HOST answers mon01 only (checked on a copy of the world). */
function scrapePortClosed(host: string): Constraint {
  return {
    id: 'mon-port-restricted', required: true,
    description: `${host}'s node_exporter port (TCP 9100) is reachable from mon01 only, not from the office (ws01).`,
    check(world) {
      const w = structuredClone(world);
      const ip = w.hosts[host].ifaces.find((i) => i.name === 'eth0')?.address ?? '';
      const c = tcpConnect(w, w.hosts.ws01, ip, 9100, { timeoutMs: 3000 });
      const ok = !c.ok;
      return { id: this.id, ok, required: true, message: ok ? 'Only mon01 reaches TCP 9100.' : `ws01 can reach ${host}:9100: open the port to mon01 (10.0.20.55) only. Metrics reveal a lot about a server.` };
    },
  };
}

/** Prometheus still runs the full configuration: 15 s scrapes and every alert rule. */
const configIntact: Constraint = {
  id: 'mon-config-intact', required: true,
  description: 'Prometheus keeps its 15 s scrape interval and all six alert rules (nothing removed to make it start).',
  check(world) {
    const l = world.hosts.mon01.services.prometheus?.loaded as PromLoaded | null;
    const rules = l?.config.rules.length ?? 0;
    const ok = !!l && l.config.scrapeInterval === 15_000 && rules >= 6;
    return { id: this.id, ok, required: true, message: ok ? 'Scrape interval and rules are as before.' : l ? `Prometheus now scrapes every ${l.config.scrapeInterval / 1000} s with ${rules} rules: keep 15 s and every rule (CHG-2610).` : 'Prometheus is not running.' };
  },
};

/** No silence hides alerts for the servers broadly (narrow, short ones for maintenance are fine). */
function noBroadSilence(alertname = 'InstanceDown'): Constraint {
  return {
    id: 'mon-no-broad-silence', required: true,
    description: `No active silence hides ${alertname} for servers nobody is working on.`,
    check(world) {
      const l = world.hosts.mon01.services['prometheus-alertmanager']?.loaded as AmLoaded | null;
      const silences = l?.silences ?? JSON.parse(readFile(world.hosts.mon01, SILENCES_FILE) ?? '[]') as AmLoaded['silences'];
      const probe = { alertname, instance: 'srv01.corp.lab:9100', job: 'node', severity: alertname === 'InstanceDown' ? 'page' : 'ticket', site: 'corp' };
      const hit = silences.find((s) => s.startsAt <= world.clock && s.endsAt > world.clock && s.matchers.every((m) => {
        const v = probe[m.name as keyof typeof probe] ?? '';
        if (m.op === '=') return v === m.value;
        if (m.op === '!=') return v !== m.value;
        const r = new RegExp(`^(?:${m.value})$`).test(v);
        return m.op === '=~' ? r : !r;
      }));
      return { id: this.id, ok: !hit, required: true, message: hit ? `The silence ${hit.id.slice(0, 8)} (${hit.matchers.map((m) => `${m.name}${m.op}"${m.value}"`).join(', ')}) still hides ${alertname} for srv01 too: expire it, and silence only what is under maintenance.` : 'No broad silence is active.' };
    },
  };
}

/** srv01's backups fail from Tuesday's run on (the stale lock is from Monday 02:31). */
const FAILING_SINCE = Date.parse('2026-10-20T03:00:00Z');
const BOB_SILENCE = (() => { const a = sha256Hex('bob-silence'); return `${a.slice(0, 8)}-${a.slice(8, 12)}-4${a.slice(13, 16)}-a${a.slice(17, 20)}-${a.slice(20, 32)}`; })();

export const MON_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'mon-fs01-firewall',
    title: 'fs01 is down, says monitoring',
    difficulty: 'beginner',
    ticket: 'On call (dana): "I was paged at 07:12: InstanceDown for fs01.corp.lab:9100. But the shares work, and I can log in to fs01. Yesterday evening the security team hardened fs01\'s firewall (CHG-2622)."',
    briefing: BRIEFING,
    goals: [targetUp('fs01')],
    terminals: [...TERMINALS.slice(0, 1), { hostId: 'fs01', user: 'root', label: 'fs01 (file server)', banner: 'fs01: NFS, Samba, node_exporter. Try: curl -s localhost:9100/metrics | head, nft list ruleset.' }],
    setup(world) {
      const fs = world.hosts.fs01;
      const nft = (readFile(fs, '/etc/nftables.conf') ?? '').replace(/\t\t# Prometheus on mon01 scrapes node_exporter \(CHG-2610\)\n\t\tip saddr 10\.0\.20\.55 tcp dport 9100 accept\n/, '').replace('flush ruleset\n', 'flush ruleset\n\n# CHG-2622: hardened; only NFS, SMB and SSH are needed on a file server.\n');
      writeFile(fs, '/etc/nftables.conf', nft, world.clock, { mode: 0o755 });
      script(world, 'fs01', ['nft -f /etc/nftables.conf']);
      monitoringAdvance(world, 12 * 60_000);
    },
    rootCauses: ['mon-scrape-blocked'],
    acceptable: { 'firewall-drop': 'Right mechanism: fs01\'s firewall drops the scrape. The precise cause is the monitoring rule that the hardening removed.' },
    candidates: CANDIDATES,
    feedback: {
      'mon-exporter-down': 'node_exporter runs on fs01: curl -s localhost:9100/metrics there answers. A stopped exporter would give "connection refused", not a timeout.',
      'mon-alert-true': 'fs01 itself is fine (shares, SSH); only Prometheus cannot reach it.',
      'dns-wrong-record': 'The target error names 10.0.20.60, fs01\'s address: the name resolves correctly.',
    },
    hints: [
      'What does Prometheus say about the target? curl -s http://localhost:9090/api/v1/targets on mon01: look at lastError for fs01.',
      '"context deadline exceeded": nothing answered within the scrape timeout. On fs01, curl -s localhost:9100/metrics works. Something between mon01 and fs01\'s port 9100 drops the packets.',
      'Compare fs01\'s /etc/nftables.conf with another server\'s (srv01): the rule "ip saddr 10.0.20.55 tcp dport 9100 accept" is gone. Put it back (mon01 only), then nft -f /etc/nftables.conf.',
    ],
    explanation: {
      rootCause: 'The hardening rewrote fs01\'s firewall with only NFS, SMB and SSH allowed, and removed the rule that lets mon01 scrape node_exporter. Prometheus\'s requests are dropped, so up becomes 0 and InstanceDown fires after 2 minutes.',
      manifestation: 'A page for a server that works for its users. The alert is about the monitoring path, not the server.',
      evidence: 'api/v1/targets: lastError "Get \\"http://fs01.corp.lab:9100/metrics\\": context deadline exceeded"; curl to fs01:9100 from mon01 times out, curl localhost:9100 on fs01 works; nft list ruleset on fs01 has no 9100 rule.',
      prevention: 'Treat the monitoring rules as part of a server\'s required access in hardening checklists; after any firewall change, check the target page; alert on up == 0 with an annotation that suggests checking the path.',
    },
    solution: [{ host: 'fs01', commands: ["sed -i 's/^\\t\\tiif \"lo\" accept$/\\t\\tiif \"lo\" accept\\n\\t\\tip saddr 10.0.20.55 tcp dport 9100 accept/' /etc/nftables.conf", 'nft -f /etc/nftables.conf'] }],
    constraints: [scrapePortClosed('fs01')],
    concepts: ['mon.metrics', 'fw.stateful'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'mon-prom-timeout',
    title: 'Monitoring is down after the change',
    difficulty: 'intermediate',
    ticket: 'Team lead: "Since this morning\'s change on mon01 (CHG-2630: give slow exporters more time to answer) the Prometheus web page does not load, and we have had no alerts for hours. Please get monitoring back as it was, with the longer timeout if that is possible."',
    briefing: BRIEFING,
    goals: [
      { kind: 'command', description: 'Prometheus is running.', steps: [{ host: 'mon01', user: 'root', command: 'systemctl is-active prometheus' }], expect: '^active$' },
      { kind: 'command', description: 'Prometheus scrapes all nine targets again.', steps: [{ host: 'mon01', user: 'root', command: 'sleep 20' }, { host: 'mon01', user: 'root', command: `promtool query instant ${PROM} 'count(up == 1)'` }], expect: '=> 9 @' },
    ],
    terminals: TERMINALS,
    setup(world) {
      const m = world.hosts.mon01;
      writeFile(m, '/etc/prometheus/prometheus.yml', (readFile(m, '/etc/prometheus/prometheus.yml') ?? '').replace('  # scrape_timeout is set to the global default (10s).\n', '  # CHG-2630: give slow exporters more time\n  scrape_timeout: 20s\n'), world.clock);
      script(world, 'mon01', ['systemctl restart prometheus']);
      monitoringAdvance(world, 3 * 3_600_000);
    },
    rootCauses: ['mon-config-invalid'],
    candidates: CANDIDATES,
    feedback: {
      'mon-scrape-blocked': 'Nothing is scraped at all: Prometheus itself is not running (systemctl status prometheus).',
      'mon-exporter-down': 'The exporters answer (curl from mon01 to srv01:9100 works); the server that scrapes them is down.',
      'mon-notify-failed': 'There are no alerts to deliver: Prometheus, which evaluates the rules, is not running.',
    },
    hints: [
      'systemctl status prometheus on mon01: it is failed. journalctl -u prometheus -n 10 says why.',
      '"Error loading config … global scrape timeout greater than scrape interval": a scrape must finish before the next one starts. promtool check config /etc/prometheus/prometheus.yml shows the same.',
      'Keep scrape_interval at 15s and set scrape_timeout to at most 15s (or remove the line), check with promtool, then systemctl start prometheus.',
    ],
    explanation: {
      rootCause: 'The change set the global scrape_timeout (20s) longer than the scrape_interval (15s). Prometheus refuses such a configuration, and because it was restarted rather than reloaded, it stopped instead of keeping the old configuration.',
      manifestation: 'No web page, no targets, no alerts: monitoring of every server is silently gone.',
      evidence: 'systemctl status prometheus: failed; journal: msg="Error loading config" err="… global scrape timeout greater than scrape interval"; promtool check config fails with the same text.',
      prevention: 'Run promtool check config before every change, prefer reload (a bad file is rejected and the old configuration kept), and monitor Prometheus itself from a second instance or with a heartbeat alert (a "dead man\'s switch").',
    },
    solution: [{ host: 'mon01', commands: ["sed -i 's/^  scrape_timeout: 20s$/  scrape_timeout: 14s/' /etc/prometheus/prometheus.yml", 'promtool check config /etc/prometheus/prometheus.yml', 'systemctl start prometheus'] }],
    constraints: [configIntact],
    concepts: ['mon.alerting', 'svc.systemd'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'mon-am-submission',
    title: 'Nobody was paged about bak01',
    difficulty: 'intermediate',
    ticket: 'Backup team: "bak01\'s backup disk crossed 90% last night. Prometheus shows FilesystemAlmostFull firing since 01:00, but the on-call phone (oncall@corp.lab) got nothing. Last week the mail team asked everyone to send mail through the submission port (CHG-2633)." Make sure pages reach oncall again; the disk itself is being handled by the backup team.',
    briefing: BRIEFING,
    goals: [{
      kind: 'command',
      description: 'Alertmanager delivers the FilesystemAlmostFull page for bak01 to oncall@corp.lab (the ops mailbox on mail01).',
      steps: [{ host: 'mon01', user: 'root', command: 'sleep 420' }, { host: 'mail01', user: 'root', command: 'grep -l "FIRING:1] FilesystemAlmostFull" /home/ops/Maildir/new/*' }],
      expect: '^/home/ops/Maildir/new/',
    }],
    terminals: TERMINALS,
    setup(world) {
      const m = world.hosts.mon01;
      writeFile(m, '/etc/prometheus/alertmanager.yml', (readFile(m, '/etc/prometheus/alertmanager.yml') ?? '').replace("  smtp_smarthost: 'mail01.corp.lab:25'", "  # CHG-2633: send mail through the submission port\n  smtp_smarthost: 'mail01.corp.lab:587'"), world.clock);
      script(world, 'mon01', ['systemctl reload prometheus-alertmanager']);
      // The backup disk fills up to 87%: under 10% left for the repositories.
      const b = world.hosts.bak01;
      writeFile(b, '/srv/backup/fs-old.img', '(disk image of the old file server, CHG-2488)\n', Date.parse('2026-09-21T15:12:00Z'), { mode: 0o600 });
      const disk = b.disks![0];
      b.fs['/srv/backup/fs-old.img'].size = Math.floor(disk.sizeKB * 0.87 - disk.baseKB) * 1024;
      monitoringAdvance(world, 7 * 3_600_000);
    },
    rootCauses: ['mon-notify-failed'],
    candidates: CANDIDATES,
    feedback: {
      'mon-silenced': 'amtool alert lists FilesystemAlmostFull as active, and amtool silence query is empty: nothing hides it.',
      'mon-alert-true': 'The alert is right (the disk is that full), but the ticket is about the page that never arrived.',
      'mon-config-invalid': 'Alertmanager runs with its configuration loaded; it fails when sending.',
    },
    hints: [
      'Is the alert in Alertmanager? amtool alert on mon01. Then: did Alertmanager try to notify? journalctl -u prometheus-alertmanager -n 10.',
      '"Notify for alerts failed … send RCPT TO: 554 5.7.1 <oncall@corp.lab>: Relay access denied": the submission port (587) only accepts mail from authenticated users. Alertmanager has no SMTP account. Look at mail01\'s mail.log too.',
      'Server-to-server mail goes to port 25 (mail01 accepts mail for its own domain there). Set smtp_smarthost back to mail01.corp.lab:25, amtool check-config, systemctl reload prometheus-alertmanager. Notifications are retried at the next group interval (5 minutes).',
    ],
    explanation: {
      rootCause: 'Alertmanager\'s smarthost was moved to the submission port 587. Postfix on mail01 requires SMTP AUTH there and rejects the unauthenticated recipient ("Relay access denied"), so every notification fails. Port 25 accepts mail for corp.lab from the servers.',
      manifestation: 'The alert fires correctly and is visible in Prometheus and Alertmanager, but no page is sent: the failure is only in Alertmanager\'s log and its notification metrics.',
      evidence: 'journalctl -u prometheus-alertmanager: "Notify for alerts failed … oncall/email[0]: notify retry canceled due to unrecoverable error after 1 attempts: send RCPT TO: 554 5.7.1 <oncall@corp.lab>: Relay access denied"; mail01 mail.log: NOQUEUE: reject from mon01; alertmanager_notifications_failed_total grows.',
      prevention: 'Test the notification path after changes (amtool alert add or a test rule), alert on alertmanager_notifications_failed_total, and give automated senders an account if they must use submission.',
    },
    solution: [{ host: 'mon01', commands: ["sed -i 's/mail01.corp.lab:587/mail01.corp.lab:25/' /etc/prometheus/alertmanager.yml", 'amtool check-config /etc/prometheus/alertmanager.yml', 'systemctl reload prometheus-alertmanager'] }],
    constraints: [{
      id: 'mon-tls-kept', required: true,
      description: 'Alertmanager still requires STARTTLS for its mail (smtp_require_tls not switched off).',
      check(world) {
        const l = world.hosts.mon01.services['prometheus-alertmanager']?.loaded as AmLoaded | null;
        const ok = !!l && l.config.receivers.every((r) => r.email.every((e) => e.requireTls));
        return { id: this.id, ok, required: true, message: ok ? 'Notifications are still sent over TLS.' : 'TLS was switched off for the notifications: they would cross the network in clear text.' };
      },
    }],
    concepts: ['mon.alerting'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'mon-silence-log01',
    title: 'log01 was down all weekend',
    difficulty: 'intermediate',
    ticket: 'Security: "We needed log01\'s logs from Saturday and found that monitoring has shown log01 as down since Friday afternoon, but nobody was paged. On Friday bob cleaned up services on log01 during a maintenance window (CHG-2637)." Get log01 monitored again and make sure outages page.',
    briefing: BRIEFING,
    goals: [
      targetUp('log01'),
      { kind: 'command', description: 'node_exporter on log01 starts at boot.', steps: [{ host: 'log01', user: 'root', command: 'systemctl is-enabled prometheus-node-exporter' }], expect: '^enabled$' },
    ],
    terminals: [...TERMINALS.slice(0, 1), { hostId: 'log01', user: 'root', label: 'log01 (log server)', banner: 'log01: central syslog. Try: systemctl status prometheus-node-exporter, ss -tlnp.' }, TERMINALS[2]],
    setup(world) {
      script(world, 'log01', ['systemctl disable --now prometheus-node-exporter']);
      const m = world.hosts.mon01;
      const am = m.services['prometheus-alertmanager'].loaded as AmLoaded;
      const created = world.clock - 3 * 86_400_000;
      am.silences.push({ id: BOB_SILENCE, matchers: [{ name: 'job', op: '=', value: 'node' }], startsAt: created, endsAt: created + 30 * 86_400_000, createdBy: 'bob', comment: 'CHG-2637 log01 cleanup' });
      writeFile(m, SILENCES_FILE, JSON.stringify(am.silences), world.clock, { mode: 0o644, owner: 'prometheus', group: 'prometheus' });
      monitoringAdvance(world, 6 * 3_600_000);
    },
    rootCauses: ['mon-exporter-down', 'mon-silenced'],
    candidates: CANDIDATES,
    feedback: {
      'mon-scrape-blocked': 'The target error is "connection refused": log01 answered, but nothing listens on 9100.',
      'mon-notify-failed': 'Alertmanager never tried to notify: the alert is suppressed (amtool alert -s), not failing.',
      'mon-config-invalid': 'Prometheus runs and scrapes the other targets.',
    },
    hints: [
      'Two questions: why is log01 down for Prometheus, and why was nobody paged? Start with the target error (api/v1/targets) and amtool alert.',
      'Target: "connect: connection refused" → is node_exporter running on log01? systemctl status prometheus-node-exporter (disabled, inactive). Page: amtool alert does not list InstanceDown; amtool alert -s does (suppressed); amtool silence query shows bob\'s silence.',
      'On log01: systemctl enable --now prometheus-node-exporter. On mon01: amtool silence expire ID. A maintenance silence should name the instance and end with the window.',
    ],
    explanation: {
      rootCause: 'During the cleanup node_exporter on log01 was disabled and stopped, and the maintenance silence was created for job="node" (every server) for 30 days instead of for log01 during the window. The outage alert fired, but Alertmanager suppressed it, and it would have suppressed any other server\'s too.',
      manifestation: 'Prometheus shows the problem, the alert fires, yet nobody hears about it. Silences fail silently.',
      evidence: 'Target error "dial tcp 10.0.20.50:9100: connect: connection refused"; systemctl is-enabled prometheus-node-exporter on log01: disabled; amtool alert -s shows InstanceDown as suppressed; amtool silence query: job="node", ends in 4 weeks, by bob.',
      prevention: 'Silences name the instance under maintenance and end when the window ends; review active silences in the daily check; never stop monitoring agents as "unneeded services".',
    },
    solution: [
      { host: 'log01', commands: ['systemctl enable --now prometheus-node-exporter'] },
      { host: 'mon01', commands: [`amtool silence expire ${BOB_SILENCE}`] },
    ],
    constraints: [noBroadSilence()],
    concepts: ['mon.alerting', 'mon.metrics'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'mon-backup-alert',
    title: 'BackupTooOld for srv01',
    difficulty: 'intermediate',
    ticket: 'ops-tickets mailbox: "[FIRING:1] BackupTooOld srv01.corp.lab:9100 (…)". The backup team thinks the alert is wrong: "bak01 has plenty of space and the other servers back up fine." Find out, and fix whatever is wrong.',
    briefing: BRIEFING,
    goals: [
      { kind: 'command', description: 'srv01\'s backup job runs successfully.', steps: [{ host: 'srv01', user: 'root', command: 'systemctl start restic-backup.service && echo BACKUP-OK' }], expect: '^BACKUP-OK$' },
      { kind: 'command', description: 'After a backup, BackupTooOld is no longer active for srv01.', steps: [{ host: 'srv01', user: 'root', command: 'systemctl start restic-backup.service' }, { host: 'mon01', user: 'root', command: 'sleep 30' }, { host: 'mon01', user: 'root', command: `promtool query instant ${PROM} 'absent(ALERTS{alertname="BackupTooOld",instance="srv01.corp.lab:9100"})'` }], expect: '=> 1 @' },
    ],
    terminals: TERMINALS,
    setup(world) {
      // srv01's prune was running when bak01 lost power on Monday: its lock stayed behind.
      const b = world.hosts.bak01;
      const at = Date.parse('2026-10-19T02:31:12Z');
      writeFile(b, `${REPO_ROOT}/srv01/locks/${sha256Hex('stale-lock-srv01')}`, JSON.stringify({ time: at, exclusive: true, hostname: 'srv01', username: 'root', pid: 2011, uid: 0, gid: 0 }), at, { mode: 0o600, owner: 'restic', group: 'restic' });
      nights(world, 2);
      monitoringAdvance(world, 20 * 60_000);
    },
    rootCauses: ['mon-alert-true', 'bk-stale-lock'],
    candidates: CANDIDATES,
    feedback: {
      'mon-config-invalid': 'The rule evaluates fine; its value is the real age of srv01\'s last successful backup.',
      'mon-silenced': 'Nothing is silenced: the alert arrived in the mailbox.',
      'mon-scrape-blocked': 'srv01 is scraped (up is 1); the backup metric comes with it.',
    },
    hints: [
      'What does the alert measure? Its rule (rules/corp.yml): time() - restic_backup_last_success_timestamp_seconds > 26h. Query that on mon01, then look at the file on srv01: /var/lib/prometheus/node-exporter/restic_backup.prom.',
      'The timestamp is from Monday: the job has not succeeded since. journalctl -u restic-backup.service on srv01.',
      '"repository is already locked exclusively by PID 2011 on srv01": a stale lock from the power cut. set -a; . /etc/restic/env; set +a; restic unlock, then systemctl start restic-backup.service. The job writes a new timestamp and the alert resolves.',
    ],
    explanation: {
      rootCause: 'The alert was right. srv01\'s nightly backups have failed since Monday because a prune interrupted by a power cut left an exclusive lock in the repository. The job only updates restic_backup_last_success_timestamp_seconds after a successful run, so its age grew past 26 hours.',
      manifestation: 'An alert that looks like a monitoring mistake ("the other servers are fine") but reports a real, silent failure. Without it, nobody would have known until a restore was needed.',
      evidence: 'Prometheus: time() - restic_backup_last_success_timestamp_seconds{instance="srv01…"} ≈ 2 days; the .prom file on srv01 holds Monday\'s time; journalctl -u restic-backup: "repository is already locked exclusively by PID 2011 on srv01".',
      prevention: 'Alert on the age of the last success (as here), not only on failed runs; treat alerts as true until proven otherwise; check backups after outages.',
    },
    solution: [{ host: 'srv01', commands: ['set -a; . /etc/restic/env; set +a; restic unlock', 'systemctl start restic-backup.service'] }],
    constraints: [noBroadSilence('BackupTooOld'), {
      id: 'mon-real-backup', required: true,
      description: 'srv01 really has a new snapshot (the timestamp was not just edited).',
      check(world) {
        const pre = `${REPO_ROOT}/srv01/snapshots/`;
        const newest = Object.keys(world.hosts.bak01.fs).filter((p) => p.startsWith(pre)).map((p) => { try { return (JSON.parse(world.hosts.bak01.fs[p].content) as { time: number }).time; } catch { return 0; } }).sort((a, b) => b - a)[0] ?? 0;
        const ok = newest > FAILING_SINCE;
        return { id: this.id, ok, required: true, message: ok ? 'srv01 has a fresh snapshot.' : 'srv01 has no snapshot since Monday: the alert was silenced or its metric edited, but the backups still fail.' };
      },
    }],
    concepts: ['mon.alerting', 'bk.operate'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'snmp-dpkg-default',
    title: 'Router graphs stopped after the update',
    difficulty: 'intermediate',
    ticket: 'Network team: "Since this morning\'s package updates on rtr01 our SNMP polling from mon01 gets nothing (snmpwalk -v2c -c corp-mon rtr01.corp.lab times out). The router routes fine." During the update, dpkg asked about /etc/snmp/snmpd.conf and the admin pressed Y.',
    briefing: BRIEFING,
    goals: [
      { kind: 'command', description: 'mon01 reads rtr01\'s name over SNMP v2c with the community corp-mon.', steps: [{ host: 'mon01', user: 'root', command: 'snmpget -v2c -c corp-mon rtr01.corp.lab .1.3.6.1.2.1.1.5.0' }], expect: 'STRING: "rtr01"' },
      { kind: 'command', description: 'mon01 reads rtr01\'s interface table (IF-MIB::ifDescr).', steps: [{ host: 'mon01', user: 'root', command: 'snmpwalk -v2c -c corp-mon rtr01.corp.lab .1.3.6.1.2.1.2.2.1.2' }], expect: 'STRING: "eth0"' },
    ],
    terminals: TERMINALS,
    setup(world) {
      const r = world.hosts.rtr01;
      writeFile(r, '/etc/snmp/snmpd.conf.dpkg-old', readFile(r, '/etc/snmp/snmpd.conf') ?? '', world.clock, { mode: 0o600 });
      writeFile(r, '/etc/snmp/snmpd.conf', DEBIAN_SNMPD_CONF, world.clock, { mode: 0o600 });
      writeFile(r, '/var/log/dpkg.log', `${readFile(r, '/var/log/dpkg.log') ?? ''}2026-10-19 07:31:02 upgrade snmpd:amd64 5.9.3+dfsg-2 5.9.3+dfsg-2+deb12u1\n2026-10-19 07:31:04 conffile /etc/snmp/snmpd.conf install\n2026-10-19 07:31:05 status installed snmpd:amd64 5.9.3+dfsg-2+deb12u1\n`, world.clock);
      script(world, 'rtr01', ['systemctl restart snmpd']);
    },
    rootCauses: ['snmp-agent-localhost', 'snmp-access-denied'],
    candidates: CANDIDATES,
    feedback: {
      'firewall-drop': 'rtr01\'s firewall still accepts UDP 161 from mon01: the packets reach the host, but nothing listens on its network addresses.',
      'mon-scrape-blocked': 'This is SNMP polling, not a Prometheus scrape.',
    },
    hints: [
      'Where does snmpd listen now? ss -ulnp on rtr01. Does it answer locally: snmpget -v2c -c public localhost .1.3.6.1.2.1.1.5.0?',
      '"Pressing Y" installed the package maintainer\'s snmpd.conf: agentaddress 127.0.0.1 and only the public community with the systemonly view. Your configuration was saved as /etc/snmp/snmpd.conf.dpkg-old (diff the two).',
      'Restore the site configuration (cp /etc/snmp/snmpd.conf.dpkg-old /etc/snmp/snmpd.conf, or edit agentaddress and the communities), then systemctl restart snmpd and test from mon01.',
    ],
    explanation: {
      rootCause: 'The snmpd update replaced the customised snmpd.conf with Debian\'s default (the admin chose the package maintainer\'s version). The default listens on 127.0.0.1 only and knows only the "public" community limited to the system view, so mon01\'s requests with corp-mon are not answered.',
      manifestation: 'A timeout, the only thing an SNMP manager ever sees for a closed port, a wrong community, a source not allowed or a firewall drop. The router works; only its management plane changed.',
      evidence: 'ss -ulnp: 127.0.0.1:161; /etc/snmp/snmpd.conf has "agentaddress 127.0.0.1,[::1]" and "rocommunity public default -V systemonly"; /var/log/dpkg.log: "conffile /etc/snmp/snmpd.conf install"; snmpd.conf.dpkg-old holds the old file.',
      prevention: 'Keep local settings in /etc/snmp/snmpd.conf.d/*.conf (includeDir), so package updates never conflict; answer dpkg\'s conffile prompt with D (diff) first; poll from monitoring and alert when SNMP stops answering.',
    },
    solution: [{ host: 'rtr01', commands: ['cp /etc/snmp/snmpd.conf.dpkg-old /etc/snmp/snmpd.conf', 'systemctl restart snmpd'] }],
    constraints: [{
      id: 'snmp-no-public', required: true,
      description: 'rtr01 does not answer the default community "public" from the network.',
      check(world) {
        const w = structuredClone(world);
        const r = snmpExchange(w, w.hosts.mon01, '10.0.10.1', 161, { version: '2c', community: 'public', op: 'get', oids: [[1, 3, 6, 1, 2, 1, 1, 5, 0]] });
        const ok = r.kind !== 'response';
        return { id: this.id, ok, required: true, message: ok ? '"public" is refused from the network.' : 'rtr01 answers the community "public" from mon01: everybody knows that community. Remove it or restrict it to localhost.' };
      },
    }],
    concepts: ['mon.snmp'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'mon-exporter-flag',
    title: 'db01 down in monitoring since CHG-2640',
    difficulty: 'beginner',
    ticket: 'DBA: "CHG-2640: we wanted node_exporter on db01 to report only the PostgreSQL units (the dashboard was cluttered). Since the change db01 is down in monitoring, but PostgreSQL works." Make the change work.',
    briefing: BRIEFING,
    goals: [
      targetUp('db01'),
      { kind: 'command', description: 'db01 reports the PostgreSQL unit, and only units matching postgresql.*', steps: [{ host: 'mon01', user: 'root', command: 'sleep 20' }, { host: 'mon01', user: 'root', command: `promtool query instant ${PROM} 'count(node_systemd_unit_state{instance="db01.corp.lab:9100",state="active",name=~"postgresql.*"}) == count(node_systemd_unit_state{instance="db01.corp.lab:9100",state="active"})'` }], expect: '=> 1 @' },
    ],
    terminals: [...TERMINALS.slice(0, 1), { hostId: 'db01', user: 'root', label: 'db01 (database server)', banner: 'db01: PostgreSQL 15, node_exporter. Try: systemctl status prometheus-node-exporter, cat /etc/default/prometheus-node-exporter.' }],
    setup(world) {
      const d = world.hosts.db01;
      writeFile(d, '/etc/default/prometheus-node-exporter', (readFile(d, '/etc/default/prometheus-node-exporter') ?? '').replace('ARGS="--collector.systemd"', '# CHG-2640: only the PostgreSQL units\nARGS="--collector.systemd --collector.sytemd.unit-include=postgresql.*"'), world.clock);
      script(world, 'db01', ['systemctl restart prometheus-node-exporter']);
      monitoringAdvance(world, 10 * 60_000);
    },
    rootCauses: ['mon-exporter-down'],
    candidates: CANDIDATES,
    feedback: {
      'mon-scrape-blocked': '"connection refused" (not a timeout): db01 answers, but nothing listens on 9100.',
      'mon-config-invalid': 'Prometheus\'s configuration did not change; the exporter on db01 did.',
    },
    hints: [
      'Target error for db01: "connect: connection refused". On db01: systemctl status prometheus-node-exporter.',
      'The journal: "prometheus-node-exporter: error: unknown long flag \'--collector.sytemd.unit-include\'". The flag name has a typo.',
      'Fix ARGS in /etc/default/prometheus-node-exporter: --collector.systemd.unit-include=postgresql.* (keep --collector.systemd), then systemctl restart prometheus-node-exporter and curl localhost:9100/metrics | grep unit_state.',
    ],
    explanation: {
      rootCause: 'The new flag was misspelled (--collector.sytemd.unit-include). node_exporter rejects unknown flags and exits, so nothing listens on 9100 and the target is down.',
      manifestation: 'A configuration change to "what is reported" took the whole exporter down; PostgreSQL itself is fine.',
      evidence: 'systemctl status prometheus-node-exporter: failed; journal: "unknown long flag \'--collector.sytemd.unit-include\', try --help"; target error "connection refused".',
      prevention: 'Restart the exporter by hand after editing its flags and look at its status, check the target page after the change, and keep flags in configuration management.',
    },
    solution: [{ host: 'db01', commands: ["sed -i 's/--collector.sytemd.unit-include/--collector.systemd.unit-include/' /etc/default/prometheus-node-exporter", 'systemctl restart prometheus-node-exporter'] }],
    constraints: [],
    concepts: ['mon.metrics', 'svc.systemd'],
  },
];
