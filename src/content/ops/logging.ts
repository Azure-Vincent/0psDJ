// Central logging (rsyslog). Examples follow the lab: rtr01, ns1, srv01 and
// dock01 forward everything to log01 (10.0.20.50) over TCP 514; log01 files it
// per host and program under /var/log/remote/. The sandbox and the tickets run
// there. RHEL, Windows (event forwarding) and pfSense (remote syslog) noted.

import type { Assessment, Lesson, Primer, ServiceGuide } from '../types';

// --- Operate & recover guide ---------------------------------------------------------

export const LOGGING_GUIDE: ServiceGuide = {
  purpose:
    'Central logging copies every server\'s log messages to a log server as they happen. It keeps evidence when a server is broken, rebuilt or compromised (an attacker deletes local logs first), lets you search one place instead of twenty, and lets you correlate events across machines (with synchronized clocks). On Linux the usual pipeline is: programs log to the journal, **rsyslog** reads it, applies its rules, writes local files and forwards to the log server over **syslog** (UDP or TCP port 514, or TLS on 6514).',
  architecture: [
    { q: 'What does it accomplish?', a: 'A durable, searchable copy of every host\'s logs on a dedicated server, organised per host and program, with retention and access separate from the machines that produce them.' },
    { q: 'How does it work internally?', a: 'Each message has a **facility** (who: kern, auth, authpriv, daemon, cron, user, local0–7) and a **priority**/severity (emerg … debug). rsyslog\'s **rules** are "selector action" lines: the selector picks messages (facility.priority, or property filters like :fromhost-ip), the action writes a file, forwards to another host, or stops processing. Rules are applied in order; every matching rule acts.' },
    { q: 'Which protocols does it use?', a: 'Syslog: RFC 3164 ("<PRI>Oct 19 08:31:12 srv01 sshd[431]: message") or RFC 5424 framing, over UDP 514 (one datagram per message, no acknowledgement), TCP 514 (a stream, octet-counted), TLS 6514, or RELP (with application-level acknowledgements).' },
    { q: 'Which ports and transport?', a: 'The log server listens on 514 (imudp and/or imtcp). Senders connect out to it; nothing listens on the senders. Firewalls must allow 514 to the log server from every sender.' },
    { q: 'Which processes and OS components implement it?', a: '`rsyslogd` (rsyslog.service) on senders and receiver; `systemd-journald` as the local source; `logger` to inject test messages. Alternatives: syslog-ng, Fluent Bit/Vector, and on the receiving side SIEMs (Graylog, Elastic, Splunk) that speak syslog.' },
    { q: 'Which other services does it depend on?', a: 'DNS (the log server\'s name, resolved when the sender connects), the network path and the receiver\'s firewall, disk space on the log server, and NTP: timestamps from unsynchronized hosts make correlation useless.' },
    { q: 'How do requests travel?', a: 'srv01: sshd → journal → rsyslogd (rules: /var/log/auth.log, and the forwarding rule) → TCP connection to log01:514 → log01\'s imtcp → its rules: template /var/log/remote/srv01/sshd.log, then stop.' },
    { q: 'How do authentication and authorisation work?', a: 'Plain syslog has none: anyone who can reach port 514 can write messages with any host name. Restrict the receiver\'s firewall to the sender networks, prefer TCP over UDP (harder to spoof), and use TLS with certificates where it matters. Log files are readable by root and the adm group.' },
    { q: 'How does it start at boot?', a: '`rsyslog.service` (WantedBy multi-user.target) reads its configuration once; journald buffers earlier boot messages. Forwarding actions connect when there is something to send.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'On a sender: local journal continues (journalctl still works), files and forwarding stop. On the receiver: senders cannot connect; with a queue (queue.type="LinkedList", or disk-assisted) they keep messages and send the backlog later, **without one the action is suspended and messages are discarded**. UDP senders never notice anything.' },
  ],
  ports: [
    { port: '514', proto: 'UDP', purpose: 'Classic syslog: fire-and-forget, no acknowledgement, easily spoofed' },
    { port: '514', proto: 'TCP', purpose: 'Syslog over TCP (rsyslog imtcp / @@)' },
    { port: '6514', proto: 'TCP (TLS)', purpose: 'Syslog over TLS (RFC 5425)' },
    { port: '2514', proto: 'TCP', purpose: 'RELP (Reliable Event Logging Protocol), common choice when loss is unacceptable' },
  ],
  processes: [
    { name: 'rsyslogd', platform: 'Linux (rsyslog.service)', role: 'Reads the journal/syslog socket, applies rules, writes files, forwards, receives (imudp/imtcp)' },
    { name: 'systemd-journald', platform: 'Linux', role: 'Collects messages from all programs and the kernel; the source rsyslog reads' },
    { name: 'syslog-ng', platform: 'Linux (alternative)', role: 'Same role as rsyslog with a different configuration language' },
    { name: 'Windows Event Log / WEF', platform: 'Windows', role: 'Event logs; Windows Event Forwarding (wecsvc) collects them centrally; syslog needs an agent (NXLog, Winlogbeat)' },
    { name: 'syslogd (clog)', platform: 'pfSense', role: 'Firewall, system and service logs; Status > System Logs > Settings sends them to remote syslog servers (UDP 514 by default)' },
  ],
  dependencies: {
    title: 'What "srv01\'s SSH logins are on log01" depends on (top needs everything below it)',
    caption: 'Each hop can lose messages silently: check them in order, and test with logger.',
    rows: [
      { label: 'Source', nodes: [{ id: 'sshd', label: 'sshd on srv01', sub: 'facility auth', kind: 'service' }, { id: 'journal', label: 'journald', sub: 'local journal', kind: 'os' }] },
      { label: 'Sender', nodes: [{ id: 'rs', label: 'rsyslogd on srv01', sub: 'rules, selector *.*', kind: 'service' }, { id: 'q', label: 'action queue', sub: 'LinkedList', kind: 'data' }] },
      { label: 'Path', nodes: [{ id: 'dns', label: 'DNS', sub: 'log01.corp.lab', kind: 'network' }, { id: 'fw', label: 'log01 firewall', sub: 'tcp dport 514', kind: 'network' }] },
      { label: 'Receiver', nodes: [{ id: 'in', label: 'imtcp on log01', sub: 'module + input', kind: 'service' }, { id: 'tpl', label: 'Template + stop', sub: '/var/log/remote/…', kind: 'data' }, { id: 'disk', label: 'Disk', sub: 'space, retention', kind: 'os' }] },
    ],
    edges: [['sshd', 'journal'], ['journal', 'rs'], ['rs', 'q'], ['q', 'dns'], ['q', 'fw'], ['fw', 'in'], ['in', 'tpl'], ['tpl', 'disk']],
  },
  sequence: {
    title: 'An SSH login on srv01 reaches log01',
    caption: 'rsyslog 8.2302 on both hosts; forwarding over TCP with a memory queue.',
    lanes: [{ id: 's', label: 'srv01', sub: 'sshd → rsyslogd' }, { id: 'l', label: 'log01', sub: 'rsyslogd (imtcp)' }],
    steps: [
      { from: 's', to: 's', label: 'sshd: "Accepted password for alice" (auth.info)', note: 'A selector like "*.*;auth,authpriv.none" on the forwarding rule drops it here, while /var/log/auth.log still gets it.' },
      { from: 's', to: 'l', label: 'TCP SYN to 10.0.20.50:514', note: 'Dropped by log01\'s firewall → timeout, "action … suspended". Nothing listening → RST, "Connection refused".' },
      { from: 'l', to: 's', label: 'SYN-ACK' },
      { from: 's', to: 'l', label: 'syslog message(s), octet-counted', note: 'UDP instead ("@") to a TCP-only receiver: datagrams answered by ICMP port unreachable, silently lost.' },
      { from: 'l', to: 'l', label: '/var/log/remote/srv01/sshd.log, stop' },
    ],
  },
  files: [
    { path: '/etc/rsyslog.conf, /etc/rsyslog.d/*.conf', platform: 'Debian / Ubuntu / RHEL', kind: 'config', perms: 'root:root 0644', contains: 'Modules and inputs, global directives, $IncludeConfig, and the rules (selectors and actions).', accessed: 'At rsyslogd start.', problems: 'Errors are skipped, not fatal: rsyslog runs without the broken part. Validate with rsyslogd -N1.' },
    { path: '/var/log/syslog, /var/log/auth.log, /var/log/kern.log, /var/log/cron.log', platform: 'Debian / Ubuntu (RHEL: /var/log/messages, /var/log/secure)', kind: 'log', perms: 'root:adm 0640', contains: 'Local copies by facility: everything except authentication → syslog; auth and authpriv → auth.log.', accessed: 'Written by rsyslogd; rotated weekly by logrotate.', problems: 'Readable by root and adm only. Deleted or rotated away on a compromised or rebuilt host: that is why logs are forwarded.' },
    { path: '/var/log/remote/HOST/PROGRAM.log', platform: 'Log server (this lab\'s template)', kind: 'log', perms: 'root:adm 0640', contains: 'Messages received from each sender, filed by the template in 10-remote.conf.', accessed: 'Written as messages arrive.', problems: 'The file names come from the HOSTNAME field the sender puts in the message: a misconfigured sender can write under another name.' },
    { path: 'journal: journalctl -u rsyslog', platform: 'Linux', kind: 'log', contains: 'rsyslog\'s own errors: configuration problems at start, "cannot connect to …", "action … suspended / resumed".', accessed: 'Continuously.', problems: 'Nobody reads the sender\'s rsyslog errors unless they are monitored: forwarding can be broken for weeks.' },
  ],
  management: [
    {
      platform: 'Debian / Ubuntu (senders)',
      tasks: [
        { task: 'Is rsyslog running?', command: 'systemctl status rsyslog', explain: 'active (running), and the start messages. Configuration errors appear here too.', sim: true },
        { task: 'Send a test message', command: 'logger -t test "central logging test"', explain: 'Then look for it locally (journalctl -t test, /var/log/syslog) and on the log server.', sim: true },
        { task: 'Test the authentication facility', command: 'logger -p authpriv.notice -t test "auth test"', explain: 'Goes to /var/log/auth.log locally, and to the server unless a selector excludes authpriv.', sim: true },
        { task: 'Is forwarding working?', command: 'journalctl -u rsyslog', explain: '"cannot connect to …: Connection timed out/refused", "action … suspended" mean the action cannot reach the server; "resumed" means it recovered.', sim: true },
        { task: 'What is configured?', command: 'cat /etc/rsyslog.d/50-central.conf\nrsyslogd -N1', explain: '@ = UDP, @@ or protocol="tcp" = TCP; the selector in front decides which messages go.', sim: true },
      ],
    },
    {
      platform: 'Log server (log01)',
      tasks: [
        { task: 'Is it listening?', command: 'ss -tulnp', explain: 'rsyslogd on 514/tcp (and 514/udp if accepted). Nothing → the input or its module is missing.', sim: true },
        { task: 'Is the configuration valid?', command: 'rsyslogd -N1', explain: 'Every line after the first is something rsyslog skips (an input that will never listen, a rule that never matches).', sim: true },
        { task: 'What arrives from a host?', command: 'ls -l /var/log/remote/srv01/\ntail -n 5 /var/log/remote/srv01/sshd.log', explain: 'Files per program; their modification times show when each host last sent something.', sim: true },
        { task: 'Watch it arrive', command: 'tcpdump -n -i eth0 port 514', explain: 'TCP connections from the senders; UDP datagrams show as "SYSLOG facility.priority".', sim: true },
        { task: 'Firewall', command: 'nft list ruleset', explain: 'The input chain must accept 514 from the sender networks (and nothing wider).', sim: true },
      ],
    },
    {
      platform: 'RHEL 9',
      tasks: [
        { task: 'Same rsyslog, different files', command: 'systemctl status rsyslog\ntail /var/log/messages /var/log/secure', explain: 'RHEL writes /var/log/messages (general) and /var/log/secure (authentication) instead of syslog and auth.log.' },
        { task: 'Receiver ports', command: 'firewall-cmd --add-port=514/tcp --permanent && firewall-cmd --reload\nsemanage port -l | grep syslog', explain: 'firewalld must open the port; SELinux allows rsyslogd on syslogd_port_t ports (514, 6514, 10514).' },
      ],
    },
    {
      platform: 'Windows',
      tasks: [
        { task: 'Event logs and forwarding', command: 'Get-WinEvent -LogName Security -MaxEvents 20\nwecutil es', explain: 'Windows keeps event logs; Windows Event Forwarding subscriptions (wecutil) collect them on a collector. For a syslog server, an agent (NXLog, Winlogbeat) converts events to syslog.' },
      ],
    },
    {
      platform: 'pfSense',
      tasks: [
        { task: 'Remote syslog', command: 'Status > System Logs > Settings > Remote Logging Options: Enable, Remote log servers 10.0.20.50:514, contents: Everything', explain: 'pfSense sends over UDP; the log server needs imudp (or a relay). Firewall logs (filterlog) are the most useful content.' },
      ],
    },
  ],
  actions: [
    { action: 'systemctl restart rsyslog', when: 'After changing rsyslog.conf or a file in rsyslog.d (after rsyslogd -N1).', effect: 'Re-reads the configuration, re-opens files and inputs, reconnects forwarding.', risk: 'Messages in a memory queue are lost on restart unless the queue is disk-assisted (queue.filename=...).' },
    { action: 'logger -t test "…"', when: 'After every change, on a sender.', effect: 'Proves the whole path end to end.', risk: 'None.' },
    { action: 'Fix the receiver\'s firewall / input', when: 'Senders are suspended (timeout / refused).', effect: 'Senders with a queue deliver their backlog when they reconnect; others resume with new messages only.', risk: 'Opening 514 wider than the sender networks lets anyone write fake log lines.' },
  ],
  workflow: [
    { question: 'Does the message reach the local log?', why: 'If the message does not even reach the local log, nothing can forward it. A test message made with logger shows exactly where it goes.', command: 'logger -t test "probe 1"\njournalctl -t test -n 1\ntail -n 1 /var/log/syslog', healthy: 'Oct 19 08:33:31 srv01 test: probe 1', broken: 'Not in the journal: logger or journald problem (rare). In the journal but not in /var/log/syslog: rsyslog is not running or its rules do not match.', next: 'Then check that it leaves the host.', sim: true },
    { question: 'Is the forwarding action healthy?', why: 'rsyslog logs its own problems with the forwarding action, and the selector decides which messages are forwarded at all.', command: 'journalctl -u rsyslog\ncat /etc/rsyslog.d/50-central.conf', healthy: '[origin software="rsyslogd" …] start (and no "suspended")', broken: '"cannot connect to log01.corp.lab:514: Connection timed out" → firewall/path. "Connection refused" → nothing listens on the server. "could not get addrinfo" → DNS. No error at all but nothing arrives → UDP (@) or a selector that excludes the message.', next: 'Look at the server side.', sim: true },
    { question: 'Is the server listening and reachable?', why: 'The receiver must listen on the right protocol and port, and its firewall must let the messages in. A capture proves whether they arrive.', command: 'ss -tulnp\nnft list ruleset\nrsyslogd -N1', healthy: 'LISTEN 0 511 0.0.0.0:514 … rsyslogd', broken: 'Nothing on 514: input or module missing (rsyslogd -N1 says which). Listening but no accept rule for 514 in a policy-drop input chain: the firewall.', next: 'Fix, restart, test with logger again.', sim: true },
    { question: 'Where did it end up?', why: 'A message can arrive and still land in an unexpected file, because the receiver files messages by host name and program.', command: 'ls -l /var/log/remote/srv01/\ngrep "probe 1" /var/log/remote/srv01/test.log', healthy: 'Oct 19 08:33:31 srv01 test: probe 1', broken: 'In log01\'s own /var/log/syslog instead: the remote rule (template + stop) does not match or comes too late. Under a different host directory: the sender\'s hostname.', next: 'Done when a fresh test message appears where the SOC looks.', sim: true },
  ],
  failures: [
    { symptom: 'Nothing arrives from any sender', causes: ['Receiver firewall drops 514', 'Receiver has no input (module not loaded, input removed)', 'Receiver rsyslog stopped'], diagnose: ['journalctl -u rsyslog on a sender (timeout vs refused)', 'ss -tulnp and rsyslogd -N1 on the receiver', 'nft list ruleset on the receiver'], fix: 'Allow 514 from the sender networks; load the module before the input; restart rsyslog.', verify: 'logger on a sender appears under /var/log/remote/HOST/.' },
    { symptom: 'One sender is missing, no errors anywhere', causes: ['It forwards over UDP (@) to a TCP-only receiver', 'Its forwarding file was never deployed or has a typo (rsyslog skipped the line)'], diagnose: ['cat /etc/rsyslog.d/*.conf on the sender', 'rsyslogd -N1 on the sender', 'tcpdump -n port 514 on the receiver (UDP datagrams + ICMP port unreachable)'], fix: 'Use the same TCP forwarding as the other servers.', verify: 'A test message from that sender arrives.' },
    { symptom: 'Some programs from a sender are missing (e.g. SSH logins)', causes: ['The forwarding selector excludes their facility ("*.*;auth,authpriv.none")', 'A filter or "& stop" earlier in the rules ends processing'], diagnose: ['The selector of the forwarding rule', 'logger -p authpriv.notice test'], fix: 'Forward *.* and filter on the server if needed.', verify: 'An authpriv test message arrives.' },
    { symptom: 'Messages lost during a log server outage', causes: ['Forwarding action without a queue: suspended actions discard messages', 'UDP forwarding (no delivery at all while the server is down)'], diagnose: ['The action options (queue.type)', 'Gaps in /var/log/remote/HOST/ matching the outage'], fix: 'TCP (or RELP) with queue.type="LinkedList" (or disk-assisted) and action.resumeRetryCount="-1".', verify: 'Stop the receiver briefly, log on a sender, start it: the messages arrive.' },
  ],
  verification: [
    { check: 'Receiver listening', command: 'ss -tulnp', expect: 'rsyslogd on 0.0.0.0:514 (tcp)' },
    { check: 'Configuration valid on both ends', command: 'rsyslogd -N1', expect: 'End of config validation run. Bye.' },
    { check: 'End-to-end test from each sender', command: 'logger -t test "probe"', expect: 'The line appears in /var/log/remote/HOST/test.log on log01' },
    { check: 'Authentication logs included', command: 'logger -p authpriv.notice -t test "auth probe"', expect: 'Also arrives on log01' },
    { check: 'Senders healthy', command: 'journalctl -u rsyslog', expect: 'No "suspended" without a later "resumed"' },
  ],
  refIds: ['logger', 'rsyslogd', 'file:rsyslog-conf', 'journalctl', 'file:var-log', 'ss', 'nft'],
};

// --- Lesson -------------------------------------------------------------------------

export const LOGGING_LESSON: Lesson = {
  id: 'logging',
  moduleId: 'F',
  title: 'Central logging (rsyslog)',
  level: 'intermediate',
  summary: 'How syslog messages are classified (facility and priority), how rsyslog rules route them to files and to a central server over UDP or TCP 514, and how to find the hop where messages silently disappear.',
  concepts: ['logs.central', 'logs.journal', 'fw.path', 'svc.listening'],

  what: `
**Central logging** sends a copy of every server's log messages to a dedicated **log server** as they are written.

Each server already keeps its own logs (in the systemd journal and in files under /var/log, see the [systemd lesson](#/lesson/systemd/what)). Central logging adds a copy elsewhere, sent over the network with the **syslog** protocol on port 514. So it depends on the same things as any network service: a route, open firewalls and a listening receiver ([Transport and DNS](#/lesson/transport/what)), and on synchronized [clocks](#/lesson/ntp/what) so that timestamps from different machines can be compared.

### Problems it solves
- **Evidence survives.** A crashed, rebuilt or compromised server loses or alters its local logs; the copy on the log server stays.
- **One place to look.** Searching "who logged in where last night" across 20 servers is one grep (or one SIEM query), not 20 SSH sessions.
- **Correlation.** Following an incident across a firewall, a proxy, an application and a database needs their logs side by side (and synchronized clocks).
- **Alerting.** A SIEM can only alert on what it receives: brute-force attempts, sudo use, service failures.

### The pieces
- **Messages** with a **facility** (kern, auth, authpriv, daemon, cron, user, local0–7) and a **priority** (emerg, alert, crit, err, warning, notice, info, debug).
- **rsyslog** on every server: reads the journal, applies **rules** (selector → action), writes local files (/var/log/syslog, /var/log/auth.log) and **forwards** to the log server.
- **The log server**: rsyslog with an **input** (imudp/imtcp on port 514) that files incoming messages per host.
- **Transport**: syslog over UDP or TCP 514 (TLS 6514, RELP 2514).

> In the lab, **log01** (10.0.20.50) is the log server: rsyslog receives on TCP and UDP 514 and writes /var/log/remote/HOST/PROGRAM.log. **rtr01, ns1, srv01 and dock01** run rsyslog with Debian's default rules plus /etc/rsyslog.d/50-central.conf, which forwards everything over TCP with a memory queue. Simulated: rsyslog.conf and its includes (module/input, legacy $ directives, selectors with ;, none, =, !, files, @/@@ and action(type="omfwd"), templates with %HOSTNAME%/%PROGRAMNAME%, property filters, & stop), facilities derived from the program (sshd: auth, sudo/PAM: authpriv), real syslog traffic on UDP/TCP 514 through routers and firewalls, suspended/resumed actions and queues, \`logger\` and \`rsyslogd -N1\`. Simplified: forwarding happens between commands (in the background) rather than continuously, one TCP connection per batch, no TLS/RELP, no rate limiting, no log rotation.
`,

  internals: `
### 1. Facility and priority
Every message carries a **facility** (where it comes from) and a **priority** (how serious). Programs choose them: sshd logs to **auth** by default, sudo and PAM to **authpriv**, the kernel to **kern**, cron to **cron**, most daemons to **daemon**, \`logger\` to **user** unless told otherwise (\`-p authpriv.notice\`). On the wire they are combined into PRI = facility × 8 + severity: \`<38>\` is auth.info.

:::practice
Q: A message from facility daemon (3) with severity err (3) is sent over the network. Which PRI value is at its start?
A: PRI = facility × 8 + severity = 3 × 8 + 3 = **27**, written \`<27>\`.
Q: A script logs with \`logger "backup done"\` and nothing else. Which facility and priority does the message get?
A: **user.notice** (logger's defaults). Use \`-p\` to choose another, for example \`-p local0.info\`.
:::

### 2. Rules: selector → action
\`/etc/rsyslog.conf\` (and files in /etc/rsyslog.d, included where \`$IncludeConfig\` appears) contains rules, applied **in order**; every matching rule acts.
| Selector | Matches |
|---|---|
| \`*.*\` | everything |
| \`auth,authpriv.*\` | the two authentication facilities, any priority |
| \`*.*;auth,authpriv.none\` | everything **except** them (later parts override earlier ones for the facilities they name) |
| \`kern.warning\` | kern at warning **or more severe** |
| \`mail.=info\` | exactly info |
| \`:fromhost-ip, !isequal, "127.0.0.1"\` | property filter: messages received from other hosts |

Actions: a file (\`-/var/log/syslog\`, the dash means "do not sync after every line"), a template file (\`?RemoteLogs\`), forwarding (\`@host:514\` UDP, \`@@host:514\` TCP, or \`action(type="omfwd" ...)\`), or \`stop\` (end processing for this message). \`&\` adds another action to the previous rule.

:::practice
Q: Which messages does \`kern.err\` match: kern.warning, kern.crit, mail.err?
A: Only **kern.crit**: the selector matches kern at err **or more severe**. warning is less severe, and mail is another facility.
Q: A rule is \`*.*;mail.none -/var/log/syslog\`. Do mail messages reach /var/log/syslog?
A: **No.** \`mail.none\` excludes the mail facility from that rule.
:::

### 3. Forwarding: UDP or TCP, and what happens on failure
- **UDP** (\`@\`): one datagram per message, no connection, no acknowledgement. If the server is down, blocked, or not listening on UDP, messages vanish and the sender never knows (the server may answer with ICMP port unreachable, which rsyslog ignores).
- **TCP** (\`@@\`, \`protocol="tcp"\`): the sender knows when it cannot connect. rsyslog logs "cannot connect to log01.corp.lab:514: Connection timed out" (dropped by a firewall) or "Connection refused" (nothing listening) and **suspends** the action, retrying later ("resumed" when it works again).
- **Queues**: by default an action has a "direct" queue: while it is suspended, messages for it are **discarded**. \`queue.type="LinkedList"\` (memory) or a disk-assisted queue (\`queue.filename=\`) keep them and deliver the backlog after the outage; \`action.resumeRetryCount="-1"\` retries forever.

:::practice
Q: A sender forwards with \`*.* @@log01:514\` (no queue settings). log01 is down for 10 minutes. What happens to the messages from those 10 minutes?
A: They are **discarded**: the action is suspended, and the default direct queue throws away messages while it is suspended. Add a LinkedList or disk-assisted queue to keep them.
Q: Which sender message tells you a firewall dropped the TCP connection to the log server, and which tells you nothing listens?
A: "cannot connect … **Connection timed out**" (dropped); "**Connection refused**" (nothing listening on that port).
:::

### 4. The receiver
The log server needs a **module and an input**: \`module(load="imtcp")\` then \`input(type="imtcp" port="514")\` (imudp for UDP). An input without its module is a configuration error that rsyslog reports and **skips**: the daemon runs, logs locally, and listens on nothing. A template names the files:
\`\`\`
template(name="RemoteLogs" type="string" string="/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log")
:fromhost-ip, !isequal, "127.0.0.1" ?RemoteLogs
& stop
\`\`\`
Without \`& stop\`, remote messages continue to the default rules and also land in the server's own /var/log/syslog.

:::practice
Q: log01 receives remote messages correctly into /var/log/remote/HOST/, but they also appear in log01's own /var/log/syslog. What is missing?
A: An \`& stop\` line after the template action, so remote messages stop there instead of continuing to the default rules.
Q: Which two lines does a log server need to receive syslog over UDP 514?
A: \`module(load="imudp")\` and \`input(type="imudp" port="514")\`.
:::

### 5. rsyslog is forgiving, which hides mistakes
A bad line does not stop rsyslog: it logs the error and runs without that part. A forwarding rule with a typo, an input without its module, a selector that excludes the facility you care about: all produce a running, "active" service that silently does less than intended. Always run \`rsyslogd -N1\` and test end to end with \`logger\`.

:::practice
Q: rsyslog is "active (running)" after you edited its configuration. Does that prove the new forwarding rule works?
A: **No.** rsyslog skips bad parts and keeps running. Check with \`rsyslogd -N1\` and test end to end with \`logger\` and the receiver's files.
Q: Which command checks the rsyslog configuration for errors without restarting it?
A: \`rsyslogd -N1\`.
:::

### 6. Security
Plain syslog is unauthenticated: anyone who reaches port 514 can send messages claiming to be any host. Limit the receiver's firewall to the sender networks, prefer TCP (UDP sources are trivially spoofed), use TLS for untrusted paths, keep the log server's access separate from the servers it protects, and keep clocks synchronized.

:::practice
Q: Why can a log line on log01 that claims to come from srv01 not be fully trusted with plain UDP syslog?
A: Syslog is **unauthenticated** and UDP sources are easy to spoof: anyone who can reach port 514 can send a message claiming to be srv01.
Q: Name two ways to limit who can write to the central log server.
A: Allow port 514 in the receiver's **firewall** only from the sender networks; use **TCP with TLS** (or at least TCP) instead of UDP.
:::

`,

  deployment: [
    {
      id: 'debian',
      platform: 'Debian 12 / Ubuntu (rsyslog sender and receiver)',
      summary: 'Turn one server into the log server and make the others forward to it over TCP with a queue. Steps marked simulated can be tried in the sandbox (log01 and the senders already run this setup).',
      prerequisites: ['A server with disk space for the logs (plan retention), and DNS name log01.corp.lab.', 'Firewall rules allowing TCP 514 from the server networks to it.'],
      steps: [
        { title: 'Install rsyslog', command: 'sudo apt install -y rsyslog\nsystemctl status rsyslog', what: 'Debian 12 installs only journald by default; rsyslog adds the classic files and forwarding.', why: 'journald alone has no simple network forwarding to a syslog server.', expected: 'Active: active (running)' },
        { title: 'Receiver: input and per-host files', command: 'module(load="imtcp")\ninput(type="imtcp" port="514")\ntemplate(name="RemoteLogs" type="string" string="/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log")\n:fromhost-ip, !isequal, "127.0.0.1" ?RemoteLogs\n& stop', what: 'In /etc/rsyslog.d/10-remote.conf on log01.', why: 'Module before input; "& stop" keeps remote messages out of log01\'s own files.', expected: '' },
        { title: 'Receiver: validate, restart, check the listener', command: 'rsyslogd -N1\nsystemctl restart rsyslog\nss -tulnp', what: 'Validate the configuration, apply it, confirm rsyslogd listens on 514.', why: 'An input error does not stop rsyslog: only ss proves the input works.', expected: 'rsyslogd: End of config validation run. Bye.\nLISTEN 0      511           0.0.0.0:514 0.0.0.0:*         users:(("rsyslogd",pid=407,fd=6))', simulated: true },
        { title: 'Receiver: firewall', command: 'nft list ruleset', what: 'The input chain needs "ip saddr 10.0.0.0/16 tcp dport 514 accept".', why: 'Only the sender networks may write logs.', expected: 'ip saddr 10.0.0.0/16 tcp dport 514 accept', simulated: true },
        { title: 'Senders: forward over TCP with a queue', command: '*.* action(type="omfwd" target="log01.corp.lab" port="514" protocol="tcp"\n           queue.type="LinkedList" action.resumeRetryCount="-1")', what: 'In /etc/rsyslog.d/50-central.conf on every server, then rsyslogd -N1 && systemctl restart rsyslog.', why: 'TCP reports failures; the queue keeps messages during an outage.', expected: '' },
        { title: 'Test end to end', command: 'logger -p authpriv.notice -t test "central logging test"\nls /var/log/remote/', what: 'On a sender, then on log01.', why: 'The only proof that the whole chain works, for the facility that matters most.', expected: 'dock01  ns1  rtr01  srv01', simulated: true },
      ],
    },
    {
      id: 'rhel',
      platform: 'RHEL 9',
      summary: 'Same rsyslog and syntax; files are /var/log/messages and /var/log/secure; firewalld and SELinux must allow the port.',
      prerequisites: ['rsyslog (installed by default).'],
      steps: [
        { title: 'Receiver', command: 'sudo firewall-cmd --add-port=514/tcp --permanent && sudo firewall-cmd --reload\nsudo systemctl restart rsyslog', what: 'Open TCP 514 after adding the same 10-remote.conf.', why: 'SELinux already allows rsyslogd on 514 (syslogd_port_t); other ports need semanage port -a.', expected: 'success' },
      ],
    },
    {
      id: 'windows',
      platform: 'Windows Server (Event Forwarding)',
      summary: 'Windows does not speak syslog natively. Windows Event Forwarding sends selected events to a collector (wecsvc); an agent such as NXLog or Winlogbeat forwards event logs to a syslog server or SIEM.',
      prerequisites: ['A collector server; WinRM enabled on the sources (Group Policy).'],
      steps: [
        { title: 'Collector subscription', command: 'wecutil qc\nwecutil cs subscription.xml', what: 'Configures the collector and creates a subscription (which events, from which computers).', why: 'Sources push events to the collector\'s "Forwarded Events" log.', expected: '' },
      ],
    },
    {
      id: 'pfsense',
      platform: 'pfSense',
      summary: 'Status > System Logs > Settings > Remote Logging: up to three remote servers (UDP 514 by default) and which log types to send (firewall, system, DHCP...). The log server needs a UDP input (imudp) and a firewall rule for UDP 514 from the firewall.',
      prerequisites: ['A log server reachable from the pfSense interface that faces it.'],
      steps: [
        { title: 'Enable remote logging', command: 'Status > System Logs > Settings: Enable Remote Logging, Remote log servers: 10.0.20.50:514, Remote Syslog Contents: Everything', what: 'pfSense\'s syslogd forwards over UDP.', why: 'Firewall decisions (filterlog) are among the most valuable logs to keep centrally.', expected: '' },
      ],
    },
  ],

  configIntro: `
Configuration lives at both ends:
- **On every sender**: the forwarding rule (selector + action), its transport (@ UDP, @@ / protocol="tcp" TCP) and its queue.
- **On the log server**: the modules and inputs (what it listens on), the template and filter that file remote messages, and the firewall.

Validate with \`rsyslogd -N1\` before every restart: rsyslog skips what it cannot parse and keeps running.
`,

  configFiles: [
    { platform: 'Debian / Ubuntu', items: [
      { path: '/etc/rsyslog.conf', purpose: 'Modules, global directives, $IncludeConfig, default rules.' },
      { path: '/etc/rsyslog.d/*.conf', purpose: 'Additions (forwarding on senders, inputs and templates on the server), read where $IncludeConfig appears.' },
      { path: '/var/log/syslog, auth.log, kern.log, cron.log', purpose: 'Local files written by the default rules.' },
    ] },
    { platform: 'RHEL', items: [
      { path: '/etc/rsyslog.conf, /etc/rsyslog.d/', purpose: 'Same; files /var/log/messages and /var/log/secure.' },
    ] },
    { platform: 'Windows', items: [
      { path: 'Event Viewer > Subscriptions; wecutil', purpose: 'Windows Event Forwarding.' },
    ] },
  ],

  directives: [
    { name: 'selector (facility.priority;...)', compiledDefault: '(per rule)', recommended: '*.* for forwarding (filter on the server)', explanation: 'Which messages a rule handles. ".none" excludes a facility; later parts override earlier ones.', security: 'Excluding auth/authpriv from forwarding removes exactly the evidence a SOC needs.' },
    { name: '@host:514 / @@host:514', compiledDefault: '(none)', recommended: 'TCP (@@) or RELP/TLS', explanation: 'Forward over UDP (@) or TCP (@@).', security: 'UDP loses messages silently and is easy to spoof.' },
    { name: 'queue.type / action.resumeRetryCount', compiledDefault: 'Direct / 0', recommended: 'LinkedList (or disk-assisted) / -1', explanation: 'Whether a suspended action keeps messages and how long it retries.', security: 'Without a queue, an outage of the log server is a gap in the evidence.' },
    { name: 'module(load="imtcp") + input(type="imtcp" port="514")', compiledDefault: 'not loaded', recommended: 'On the log server only', explanation: 'Makes rsyslog listen for remote messages. The module must be loaded before the input.', security: 'Restrict the port to the sender networks in the firewall.' },
    { name: 'template + ?Name + & stop', compiledDefault: '(none)', recommended: 'Per-host directories on the server', explanation: 'Files remote messages by host/program and stops further processing.', security: 'File names come from the message\'s HOSTNAME field, which senders control.' },
  ],

  operateIntro: `
### Before you change logging
- Validate (\`rsyslogd -N1\`), restart, then **prove** delivery with a \`logger\` test from a sender, for the facility that matters (authpriv).
- A restart of a sender drops what its memory queue holds; restart the log server only when the senders have queues.

`,
  troubleshootingIntro: `
### Follow one message from start to finish
The easiest way to troubleshoot logging is to create a test message yourself and follow it: into the local log, out of the sender, across the network, into the receiver, and into a file.

1. **Local.** Run \`logger -t test probe\` on the sending server. Does the message appear in the journal and in /var/log/syslog? If not, the problem is on the sender itself.
2. **The sender's forwarding.** \`journalctl -u rsyslog\` shows whether rsyslog suspended the forwarding action, and why (a timeout, or connection refused). Check the forwarding rule too: UDP or TCP? Does its selector include this kind of message?
3. **The receiver.** \`ss -tulnp\` (is rsyslog listening on 514?), \`rsyslogd -N1\` (are the input modules loaded and the configuration valid?), \`nft list ruleset\` (is port 514 allowed?), \`tcpdump -n port 514\` (do the messages arrive?).
4. **Filing.** \`ls -l /var/log/remote/HOST/\` shows where the message was written. It may have arrived and simply been filed under another name.

The usual symptom is **silence**, not an error: UDP gives no feedback, a selector can leave messages out, and rsyslog can skip a configuration line it does not understand. Messages can go missing **without any error anywhere**, so monitor for hosts that stop sending.
`,

  errorMap: [
    { message: 'cannot connect to log01.corp.lab:514: Connection timed out', layer: 'Path / receiver firewall', meaning: 'The sender\'s SYNs get no answer.', firstCheck: 'nft list ruleset and tcpdump on the receiver' },
    { message: 'cannot connect to log01.corp.lab:514: Connection refused', layer: 'Receiver input', meaning: 'Nothing listens on 514 on the receiver.', firstCheck: 'ss -tulnp and rsyslogd -N1 on the receiver' },
    { message: "action 'action-1-builtin:omfwd' suspended (module 'builtin:omfwd'), retry 0", layer: 'Sender', meaning: 'Forwarding is failing; rsyslog retries. Without a queue, messages are discarded meanwhile.', firstCheck: 'The preceding error line; the action\'s queue settings' },
    { message: "omfwd: could not get addrinfo for hostname 'log1.corp.lab':'514': Name or service not known", layer: 'DNS', meaning: 'The target name does not resolve.', firstCheck: 'getent hosts on the sender; the target in the rule' },
    { message: "input module name 'imtcp' is unknown", layer: 'Receiver configuration', meaning: 'input() before or without module(load="imtcp"): the input was skipped.', firstCheck: 'rsyslogd -N1; the module lines' },
    { message: "invalid or yet-unknown config file command 'X' - have you forgotten to load a module?", layer: 'Configuration', meaning: 'A legacy $ directive rsyslog does not know.', firstCheck: 'rsyslogd -N1; the named line' },
  ],

  scenarioIds: ['log-firewall', 'log-udp-sender', 'log-auth-filtered', 'log-imtcp-missing'],
  assessmentId: 'logging',
  references: [
    { title: 'rsyslog documentation: Configuration (actions, filters, templates, queues)', url: 'https://www.rsyslog.com/doc/configuration/index.html' },
    { title: 'rsyslog documentation: omfwd (forwarding output)', url: 'https://www.rsyslog.com/doc/configuration/modules/omfwd.html' },
    { title: 'rsyslog documentation: imtcp / imudp', url: 'https://www.rsyslog.com/doc/configuration/modules/imtcp.html' },
    { title: 'RFC 5424: The Syslog Protocol (RFC 3164 for the BSD format)', url: 'https://www.rfc-editor.org/rfc/rfc5424' },
    { title: 'RFC 5425: TLS Transport Mapping for Syslog', url: 'https://www.rfc-editor.org/rfc/rfc5425' },
    { title: 'Red Hat: Configuring a remote logging solution (RHEL 9)', url: 'https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/assembly_configuring-a-remote-logging-solution_security-hardening' },
    { title: 'Microsoft Learn: Use Windows Event Forwarding', url: 'https://learn.microsoft.com/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection' },
  ],
  guide: LOGGING_GUIDE,
  objectives: ['N10-009:3.2', 'N10-009:1.4', 'N10-009:5.3'],
};

// --- Primer -------------------------------------------------------------------------

export const LOGGING_PRIMER: Primer = {
  oneLiner: 'Every server writes log messages; **central logging** sends a copy of each one, as it happens, to a **log server**, so the evidence survives and can be searched in one place. On Linux, **rsyslog** decides which messages go where (rules) and forwards them over **syslog** (UDP or TCP port 514).',
  analogy: `
Each office keeps a logbook at its front desk. If a burglar tears pages out, or the office burns down, the record is gone: so every entry is also photocopied and mailed to head office's archive.

The front desk follows a sorting list ("security entries go in the red binder, everything else in the blue one; copies of everything to head office"). If the list says "everything except security", head office never sees a break-in. If the mail is sent as postcards (UDP), lost cards are simply gone; if it is sent by registered letter (TCP), the desk notices when head office stops signing for them.`,
  ideas: [
    {
      title: 'Facility and priority classify every message',
      explain: 'The facility says what kind of program sent it (auth, authpriv, kern, cron, daemon, user...), the priority how serious it is (emerg ... debug). Rules select on both.',
      example: 'sshd logs "Accepted password for alice" as auth.info, so it goes to /var/log/auth.log on srv01. `logger -p authpriv.notice -t test "hi"` creates a test message in the same family.',
    },
    {
      title: 'Rules: selector → action, in order',
      explain: 'Each line picks messages and does something with them: write a file, forward, or stop. All matching rules act.',
      example: 'Debian\'s "*.*;auth,authpriv.none -/var/log/syslog" sends everything except authentication to /var/log/syslog; srv01\'s 50-central.conf forwards "*.*" to log01.',
    },
    {
      title: 'UDP loses quietly, TCP complains',
      explain: '`@host` forwards over UDP: nobody notices lost messages. `@@host` (TCP) fails visibly: the sender logs "cannot connect" and suspends the action; with a queue it delivers the backlog later.',
      example: 'When log01\'s firewall dropped port 514, srv01 logged "cannot connect to log01.corp.lab:514: Connection timed out" and "action ... suspended"; after the fix, the queued messages arrived.',
    },
    {
      title: 'The server needs an input and a place to put things',
      explain: 'log01 listens because of `module(load="imtcp")` + `input(type="imtcp" port="514")`, and files remote messages with a template: /var/log/remote/HOST/PROGRAM.log.',
      example: '`ss -tulnp` on log01 shows rsyslogd on 514; `ls /var/log/remote/` lists dock01, ns1, rtr01, srv01.',
    },
  ],
  walkthrough: {
    title: 'Following one test message from srv01 to log01',
    steps: [
      { label: 'Write it', detail: 'On srv01: `logger -t test "central logging test"`.' },
      { label: 'Local copy', detail: '`tail -n 1 /var/log/syslog` on srv01 shows it (Debian\'s rules).' },
      { label: 'Forwarding', detail: '50-central.conf sends *.* to log01 over TCP; `journalctl -u rsyslog` shows no "suspended".' },
      { label: 'Arrival', detail: 'On log01, rsyslogd receives it on TCP 514 (`tcpdump -n port 514` shows the connection).' },
      { label: 'Filed', detail: '`tail /var/log/remote/srv01/test.log` on log01 shows the line with srv01\'s host name and time.' },
    ],
  },
  misconceptions: [
    { myth: 'If rsyslog is "active", logging works.', truth: 'rsyslog skips broken configuration lines and keeps running. Test end to end with logger.' },
    { myth: 'No error on the sender means the messages arrived.', truth: 'UDP forwarding and excluding selectors lose messages without any error.' },
    { myth: 'Central logs are trustworthy by default.', truth: 'Plain syslog is unauthenticated: restrict who can send, prefer TCP/TLS, and keep clocks synchronized.' },
  ],
  checks: [
    { q: 'Which facility does sshd log to on Debian, and which local file gets it?', a: 'auth; /var/log/auth.log.' },
    { q: 'What is the difference between "*.* @log01:514" and "*.* @@log01:514"?', a: 'One @ forwards over UDP, two @@ over TCP.' },
    { q: 'A sender logs "Connection refused" for log01:514. What is the first thing to check on log01?', a: 'Whether anything listens on 514 (ss -tulnp), and rsyslogd -N1 for a missing module/input.' },
    { q: 'What happens to messages while a TCP forwarding action without a queue is suspended?', a: 'They are discarded.' },
  ],
};

// --- Assessment -------------------------------------------------------------------------

export const LOGGING_ASSESSMENT: Assessment = {
  id: 'logging',
  title: 'Central logging knowledge check',
  questions: [
    {
      id: 'logging-q-path',
      kind: 'order',
      level: 'beginner',
      learn: ['lesson/logging/internals'],
      prompt: 'Order the path of an sshd message from srv01 to the central log server.',
      items: ['sshd writes the message (facility auth)', 'journald stores it', 'rsyslogd on srv01 applies its rules', 'the forwarding action sends it over TCP 514', 'rsyslogd on log01 receives it (imtcp)', 'the template files it under /var/log/remote/srv01/'],
      concepts: ['logs.central'],
      explanation: 'Program → journal → local rsyslog rules → network → receiver input → receiver rules and template.',
    },
    {
      id: 'logging-q-selector',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/logging/internals'],
      prompt: 'srv01 forwards with this rule. Which messages never reach log01?',
      exhibit: '*.*;auth,authpriv.none @@log01.corp.lab:514',
      options: [
        { text: 'Messages of the auth and authpriv facilities (sshd, sudo, PAM)', correct: true },
        { text: 'Nothing: *.* matches everything', misconception: 'The later part ";auth,authpriv.none" overrides *.* for those two facilities.' },
        { text: 'Only messages below priority none', misconception: '"none" is not a priority level here: it means "no priority of these facilities".' },
        { text: 'Everything, because @@ is wrong', misconception: '@@ is TCP forwarding, which is correct.' },
      ],
      concepts: ['logs.central'],
      explanation: 'In a selector list, later entries override earlier ones for the facilities they name; ".none" excludes them.',
    },
    {
      id: 'logging-q-udp',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/logging/internals'],
      prompt: 'One server forwards with "*.* @log01.corp.lab:514"; log01 listens on TCP 514 only. What do you see on that server?',
      options: [
        { text: 'No error at all: its messages are silently lost', correct: true },
        { text: '"cannot connect to log01.corp.lab:514: Connection refused"', misconception: 'That is what a TCP action reports; UDP has no connection to fail.' },
        { text: 'rsyslog refuses to start', misconception: 'The configuration is valid; it just uses the wrong transport.' },
      ],
      concepts: ['logs.central'],
      explanation: 'UDP is fire-and-forget: log01\'s ICMP port unreachable replies are ignored, so the loss is invisible on the sender.',
    },
    {
      id: 'logging-q-refused',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/logging/internals'],
      prompt: 'Every sender logs "cannot connect to log01.corp.lab:514: Connection refused". log01\'s rsyslog is active and writes its own /var/log/syslog. What is the likely cause?',
      options: [
        { text: 'log01 has no TCP input: the imtcp module or input line is missing (rsyslogd -N1 shows it)', correct: true },
        { text: 'log01\'s firewall drops 514', misconception: 'A drop produces timeouts; "refused" means log01\'s kernel answered with RST because nothing listens.' },
        { text: 'DNS for log01.corp.lab is wrong', misconception: 'The senders reach a host that answers; DNS failures say "could not get addrinfo".' },
      ],
      concepts: ['logs.central', 'svc.listening'],
      explanation: 'rsyslog skips an input whose module is not loaded and runs without it; ss -tulnp shows nothing on 514.',
    },
    {
      id: 'logging-q-port',
      kind: 'text',
      level: 'beginner',
      learn: ['lesson/logging/what'],
      prompt: 'Which port does classic syslog use (UDP and TCP)?',
      accept: ['514'],
      placeholder: 'port',
      concepts: ['logs.central'],
      explanation: 'Syslog uses 514 (TLS: 6514, RELP commonly 2514).',
    },
    {
      id: 'logging-q-queue',
      kind: 'multi',
      level: 'advanced',
      learn: ['lesson/logging/internals'],
      prompt: 'log01 is down for 30 minutes. Which sender configurations keep the messages logged meanwhile and deliver them afterwards? (choose all that apply)',
      options: [
        { text: 'TCP forwarding with queue.type="LinkedList" and action.resumeRetryCount="-1"', correct: true },
        { text: 'TCP forwarding with a disk-assisted queue (queue.filename set)', correct: true },
        { text: '"*.* @@log01:514" with default settings', misconception: 'The default "direct" queue discards messages while the action is suspended.' },
        { text: '"*.* @log01:514" (UDP)', misconception: 'UDP has no delivery feedback at all; messages sent while log01 is down are gone.' },
      ],
      concepts: ['logs.central'],
      explanation: 'Only a queued action buffers while suspended; retrying forever ensures it resumes. A disk-assisted queue also survives a sender restart.',
    },
  ],
};
