// Central logging tickets. rtr01, ns1, srv01 and dock01 forward everything to
// log01 with rsyslog (TCP 514, /etc/rsyslog.d/50-central.conf); log01 files it
// under /var/log/remote/<host>/<program>.log. Each ticket breaks one link: the
// receiver's firewall, UDP forwarding to a TCP-only receiver, a selector that
// leaves out the authentication facilities, and an input without its module.

import { writeFile } from '../fs';
import { FORWARD_CONF, LOG01_NFT, LOG01_REMOTE_CONF } from '../lab/logLab';
import type { RsyslogLoaded } from '../sim/syslog';
import { syslogFlush } from '../sim/syslog';
import type { World } from '../types';
import { firewallStillRestrictive, script } from './engine';
import type { Constraint, Goal, Scenario } from './types';

const central = (host: string, priority?: string): Goal => ({
  kind: 'syslog', fromHost: host, server: 'log01', priority, path: `/var/log/remote/${host}/%PROGRAMNAME%.log`,
  description: `A message logged on ${host}${priority ? ` with priority ${priority}` : ''} (logger) arrives on log01 in /var/log/remote/${host}/.`,
});

/** Some days of normal activity, then rsyslog's background forwarding catches up. */
function activity(world: World, hosts: string[]): void {
  world.clock += 2 * 3600_000;
  for (const h of hosts) script(world, h, ['logger -t backup "nightly backup started"', 'logger -t backup "nightly backup finished: 0 errors"'], 600_000);
  syslogFlush(world);
}

function log01TcpOnly(): Constraint {
  return {
    id: 'log01-tcp-only', required: true,
    description: 'log01 keeps accepting syslog over TCP only (security decision SEC-141: no UDP input).',
    check(world) {
      const l = world.hosts.log01.services.rsyslog?.loaded as RsyslogLoaded | null | undefined;
      const ok = !!l && l.inputs.udp === undefined && l.inputs.tcp === 514;
      return { id: this.id, ok, required: true, message: ok ? 'log01: TCP 514 only.' : 'log01 must listen on TCP 514 and not on UDP (SEC-141): fix the sender, not the receiver.' };
    },
  };
}

const BRIEFING = [
  'log01 (10.0.20.50) is the central log server: rsyslog receives syslog on TCP 514 (imtcp) and files it per host and program under /var/log/remote/<host>/<program>.log (/etc/rsyslog.d/10-remote.conf).',
  'rtr01, ns1, srv01 and dock01 run rsyslog with Debian\'s rules (/etc/rsyslog.conf: /var/log/syslog, /var/log/auth.log, ...) plus /etc/rsyslog.d/50-central.conf, which forwards everything to log01.',
  'Tools: logger -t TAG "message" (writes a test message), journalctl -u rsyslog, rsyslogd -N1 (checks the configuration), ss -tulnp, nft list ruleset, tcpdump -n port 514, ls -l /var/log/remote/<host>/.',
  'Fixes must survive a reboot. Keep log01\'s firewall restrictive.',
];

const TERMINALS = [
  { hostId: 'log01', user: 'root', label: 'log01 console (root)', banner: 'log01 console: the central log server. Try: ls -l /var/log/remote/srv01/, journalctl -u rsyslog, ss -tulnp, nft list ruleset.' },
  { hostId: 'srv01', user: 'root', label: 'srv01 console (root)', banner: 'srv01 console: a sender. Try: logger -t test "hello", journalctl -u rsyslog, cat /etc/rsyslog.d/50-central.conf.' },
  { hostId: 'ns1', user: 'root', label: 'ns1 console (root)', banner: 'ns1 console: a sender (DNS, DHCP, KDC). Try: logger -t test "hello", cat /etc/rsyslog.d/50-central.conf.' },
];

const CANDIDATES = ['syslog-receiver-firewall', 'syslog-protocol-mismatch', 'syslog-selector-excludes', 'syslog-input-missing', 'dns-wrong-record', 'routing-server-gateway'];

export const LOG_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'log-firewall',
    title: 'The log server went quiet',
    difficulty: 'beginner',
    ticket: 'The SOC: "Since Tuesday\'s hardening of log01 (SEC-140) nothing new has arrived from any server: the newest file under /var/log/remote/srv01/ is from Tuesday morning. rsyslog is running on log01 and on the servers."',
    briefing: BRIEFING,
    goals: [central('srv01')],
    terminals: TERMINALS,
    setup(world) {
      writeFile(world.hosts.log01, '/etc/nftables.conf', LOG01_NFT.replace('\t\t# syslog from the corp.lab networks (CHG-2270)\n\t\tip saddr 10.0.0.0/16 tcp dport 514 accept\n\t\tip saddr 10.0.0.0/16 udp dport 514 accept\n', ''), world.clock, { mode: 0o755 });
      script(world, 'log01', ['systemctl restart nftables']);
      activity(world, ['srv01', 'ns1']);
    },
    rootCauses: ['syslog-receiver-firewall'],
    candidates: CANDIDATES,
    feedback: {
      'syslog-protocol-mismatch': 'The senders use TCP (@@ / protocol="tcp") and log01 listens on TCP 514 (ss -tlnp).',
      'syslog-selector-excludes': 'Nothing at all arrives, from any program; a selector would filter only some facilities.',
      'syslog-input-missing': 'rsyslogd on log01 listens on TCP 514 (ss -tlnp) and logged no configuration error.',
      'dns-wrong-record': 'log01.corp.lab resolves to 10.0.20.50 on the senders.',
      'routing-server-gateway': 'log01 and srv01 are on the same network; ping works between them.',
    },
    hints: [
      'Start on a sender: journalctl -u rsyslog on srv01. What does rsyslog say about its action towards log01?',
      '"cannot connect to log01.corp.lab:514: Connection timed out" and "action ... suspended": the SYNs get no answer. On log01, rsyslog listens (ss -tlnp). What happens to packets before they reach it? nft list ruleset.',
      'The hardening removed the syslog rules from the input chain. Put "ip saddr 10.0.0.0/16 tcp dport 514 accept" back in /etc/nftables.conf on log01 and restart nftables. The senders keep a queue: the backlog arrives once they reconnect.',
    ],
    explanation: {
      rootCause: 'The hardening of log01\'s firewall (input policy drop) dropped the rules accepting syslog on TCP/UDP 514 from the internal networks.',
      manifestation: 'Every sender\'s TCP connection attempt to log01:514 times out; rsyslog suspends the forwarding action and retries. Their queues (queue.type="LinkedList") keep the messages, so nothing is lost yet, but nothing arrives either.',
      evidence: 'journalctl -u rsyslog on srv01: "cannot connect to log01.corp.lab:514: Connection timed out" and "action \'action-1-builtin:omfwd\' suspended"; on log01: ss -tlnp shows rsyslogd on 514, nft list ruleset has no rule for it, tcpdump shows SYNs without replies; ls -l /var/log/remote/srv01/ shows nothing newer than the change.',
      prevention: 'Inventory what a server provides before hardening it (ss -tulnp), and monitor the log server for silence: "no message from host X for an hour" is an alert in itself.',
    },
    solution: [{ host: 'log01', commands: [`printf '${LOG01_NFT.replace(/\n/g, '\\n')}' > /etc/nftables.conf`, 'systemctl restart nftables'] }],
    constraints: [firewallStillRestrictive('log01')],
    concepts: ['logs.central', 'fw.path'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'log-udp-sender',
    title: 'ns1 is missing',
    difficulty: 'intermediate',
    ticket: 'Audit finding: there are no logs from ns1 (DNS, DHCP and the Kerberos KDC) on log01 for the last week, while the other servers are complete. Nobody touched ns1. Last week security switched log01 to TCP-only reception (SEC-141).',
    briefing: BRIEFING,
    goals: [central('ns1')],
    terminals: TERMINALS,
    setup(world) {
      writeFile(world.hosts.ns1, '/etc/rsyslog.d/50-central.conf', '# Forward everything to the central log server (set up in 2021, NET-12).\n*.* @log01.corp.lab:514\n', world.clock);
      script(world, 'ns1', ['systemctl restart rsyslog']);
      writeFile(world.hosts.log01, '/etc/rsyslog.d/10-remote.conf', LOG01_REMOTE_CONF.replace('module(load="imudp")\ninput(type="imudp" port="514")\n', '').replace('# Central log server (CHG-2270): receive syslog from the corp.lab servers.', '# Central log server (CHG-2270): receive syslog from the corp.lab servers.\n# TCP only since SEC-141 (no spoofable, lossy UDP).'), world.clock);
      script(world, 'log01', ['systemctl restart rsyslog']);
      activity(world, ['srv01', 'ns1']);
    },
    rootCauses: ['syslog-protocol-mismatch'],
    candidates: CANDIDATES,
    feedback: {
      'syslog-receiver-firewall': 'log01\'s firewall accepts 514 from 10.0.0.0/16, and srv01\'s logs arrive through it.',
      'syslog-selector-excludes': 'Nothing from ns1 arrives at all, whatever the facility.',
      'syslog-input-missing': 'log01 listens on TCP 514 and receives from the other servers.',
      'dns-wrong-record': 'log01.corp.lab resolves correctly on ns1.',
      'routing-server-gateway': 'ns1 reaches log01 (ping, and log01 answers its datagrams with ICMP).',
    },
    hints: [
      'Compare ns1 with a server that works: cat /etc/rsyslog.d/50-central.conf on both.',
      'ns1 forwards with a single "@": UDP. Since SEC-141 log01 listens on TCP only (ss -tulnp on log01). UDP is fire-and-forget: ns1 never learns that its datagrams are refused, so its journal shows no error. tcpdump -n port 514 on log01 shows them arriving.',
      'Use TCP like the other servers: "@@log01.corp.lab:514" (or the action(...) line from srv01, which also keeps a queue), then systemctl restart rsyslog on ns1.',
    ],
    explanation: {
      rootCause: 'ns1 still forwards over UDP ("@log01.corp.lab:514"), set up years ago. When log01 was switched to TCP-only reception, ns1\'s datagrams started hitting a closed port.',
      manifestation: 'log01\'s kernel answers each datagram with ICMP port unreachable and drops it. rsyslog on ns1 never sees an error (UDP has no connection), so the loss is completely silent on both sides.',
      evidence: 'cat /etc/rsyslog.d/50-central.conf on ns1: "@" (UDP) versus "@@"/protocol="tcp" elsewhere; ss -tulnp on log01: only tcp 514; tcpdump -n port 514 on log01: "SYSLOG daemon.info" UDP datagrams from 10.0.10.53 followed by ICMP port unreachable; journalctl -u rsyslog on ns1: no errors.',
      prevention: 'Use TCP (or RELP/TLS) for central logging, configure every sender the same way (configuration management), and alert on hosts that stop sending.',
    },
    solution: [{ host: 'ns1', commands: ['sed -i \'s/^\\*\\.\\* @log01/*.* @@log01/\' /etc/rsyslog.d/50-central.conf', 'systemctl restart rsyslog'] }],
    constraints: [log01TcpOnly()],
    concepts: ['logs.central'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'log-auth-filtered',
    title: 'Noise reduction',
    difficulty: 'intermediate',
    ticket: 'The SOC\'s SSH brute-force alert for srv01 has been silent for two weeks, and the SOC cannot find a single SSH login from srv01 on log01. Other srv01 messages arrive fine. Two weeks ago an engineer reduced "noisy" forwarding on srv01 (CHG-2281).',
    briefing: BRIEFING,
    goals: [central('srv01', 'authpriv.notice'), central('srv01', 'auth.info')],
    terminals: TERMINALS,
    setup(world) {
      writeFile(world.hosts.srv01, '/etc/rsyslog.d/50-central.conf', FORWARD_CONF.replace('*.* action(', '# CHG-2281: reduce noise sent to log01\n*.*;auth,authpriv.none action('), world.clock);
      script(world, 'srv01', ['systemctl restart rsyslog']);
      activity(world, ['srv01']);
    },
    rootCauses: ['syslog-selector-excludes'],
    candidates: CANDIDATES,
    feedback: {
      'syslog-receiver-firewall': 'Other srv01 messages arrive on log01, through the same firewall and port.',
      'syslog-protocol-mismatch': 'srv01 forwards over TCP and its other messages arrive.',
      'syslog-input-missing': 'log01 receives srv01\'s other messages.',
      'dns-wrong-record': 'Forwarding works for every program but sshd and sudo.',
      'routing-server-gateway': 'Forwarding works for every program but sshd and sudo.',
    },
    hints: [
      'Which programs from srv01 reach log01? ls /var/log/remote/srv01/ on log01, and compare with what srv01 logs locally (/var/log/auth.log).',
      'sshd logs to the "auth" facility, sudo and PAM to "authpriv". Read the selector in /etc/rsyslog.d/50-central.conf on srv01: what does ";auth,authpriv.none" do?',
      'Forward "*.*" again (remove ";auth,authpriv.none"), then systemctl restart rsyslog. Test with logger -p authpriv.notice -t test "auth test" and look on log01.',
    ],
    explanation: {
      rootCause: 'The forwarding selector was changed to "*.*;auth,authpriv.none": everything except the auth and authpriv facilities. Those are exactly the security-relevant messages (sshd, sudo, PAM, su).',
      manifestation: 'srv01 still writes them to its own /var/log/auth.log, and every other program\'s messages still reach log01, so the gap is only visible to someone looking for authentication events centrally.',
      evidence: '/etc/rsyslog.d/50-central.conf on srv01: "*.*;auth,authpriv.none action(...)"; ls /var/log/remote/srv01/ on log01 has no sshd.log updates since the change while srv01\'s /var/log/auth.log has new sshd lines.',
      prevention: 'Reduce noise on the log server (filters, retention), not by dropping facilities at the source; and test central collection of the events that matter (a login, a sudo) after every change.',
    },
    solution: [{ host: 'srv01', commands: ['sed -i \'s/^\\*\\.\\*;auth,authpriv\\.none /*.* /\' /etc/rsyslog.d/50-central.conf', 'systemctl restart rsyslog'] }],
    constraints: [],
    concepts: ['logs.central'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'log-imtcp-missing',
    title: 'Deduplicated',
    difficulty: 'intermediate',
    ticket: 'Nothing has reached log01 since its configuration was "cleaned up" yesterday (a colleague removed lines that looked duplicated). rsyslog on log01 is active and log01\'s own /var/log/syslog is still being written.',
    briefing: BRIEFING,
    goals: [central('srv01'), central('dock01')],
    terminals: TERMINALS,
    setup(world) {
      writeFile(world.hosts.log01, '/etc/rsyslog.d/10-remote.conf', LOG01_REMOTE_CONF.replace('module(load="imtcp")\n', '').replace('module(load="imudp")\n', ''), world.clock);
      script(world, 'log01', ['systemctl restart rsyslog']);
      activity(world, ['srv01', 'dock01']);
    },
    rootCauses: ['syslog-input-missing'],
    candidates: CANDIDATES,
    feedback: {
      'syslog-receiver-firewall': 'log01\'s firewall accepts 514, and the senders are refused (RST) rather than timing out: nothing listens.',
      'syslog-protocol-mismatch': 'The senders use TCP, which is what log01 is meant to receive.',
      'syslog-selector-excludes': 'Nothing arrives from any program or host.',
      'dns-wrong-record': 'The senders reach 10.0.20.50 and are refused by it.',
      'routing-server-gateway': 'The senders reach log01 (they get a refusal from it).',
    },
    hints: [
      'On log01: does anything listen on 514? ss -tulnp.',
      'rsyslogd is active but has no input. journalctl -u rsyslog on log01 and rsyslogd -N1 show why: "input module name \'imtcp\' is unknown".',
      'An input() needs its module loaded first: put module(load="imtcp") (and module(load="imudp")) back in /etc/rsyslog.d/10-remote.conf before the input lines, check with rsyslogd -N1, systemctl restart rsyslog.',
    ],
    explanation: {
      rootCause: 'The "duplicate" lines removed from 10-remote.conf were module(load="imtcp") and module(load="imudp"). Without the module, rsyslog does not know the input type and skips input(type="imtcp" ...), but starts anyway.',
      manifestation: 'rsyslogd runs and writes log01\'s own logs, but nothing listens on 514: every sender\'s connection is refused and its forwarding action is suspended (the senders queue in memory).',
      evidence: 'ss -tulnp on log01: nothing on 514; journalctl -u rsyslog and rsyslogd -N1 on log01: "input module name \'imtcp\' is unknown"; journalctl -u rsyslog on srv01: "cannot connect to log01.corp.lab:514: Connection refused".',
      prevention: 'Validate before restarting (rsyslogd -N1 must report no error), and check that the service does its job afterwards (ss -tulnp, a logger test from a client), not only that it is "active".',
    },
    solution: [{ host: 'log01', commands: ['echo \'module(load="imtcp")\' > /etc/rsyslog.d/05-input-modules.conf', 'echo \'module(load="imudp")\' >> /etc/rsyslog.d/05-input-modules.conf', 'rsyslogd -N1', 'systemctl restart rsyslog'] }],
    constraints: [firewallStillRestrictive('log01')],
    concepts: ['logs.central', 'svc.listening'],
  },
];
