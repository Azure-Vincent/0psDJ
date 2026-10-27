// Time synchronisation (NTP). Examples follow the lab: ext01 (203.0.113.80)
// is the provider's stratum-1 server, rtr01 runs chrony 4.3 and serves the
// internal networks, and the Debian machines run systemd-timesyncd; the
// sandbox and the tickets run there. RHEL (chronyd everywhere), Windows (W32Time
// and the AD domain hierarchy) and pfSense (ntpd) are described.

import type { Assessment, Lesson, Primer, ServiceGuide } from '../types';

// --- Operate & recover guide ---------------------------------------------------------

export const NTP_GUIDE: ServiceGuide = {
  purpose:
    'NTP keeps every machine\'s clock within milliseconds of real time by asking time servers over UDP port 123. Clocks matter far beyond the time on screen: **Kerberos** refuses clocks more than 5 minutes apart, **TLS** rejects certificates that look not yet valid or expired, **logs** from different machines cannot be correlated, and scheduled jobs, caches and replication depend on time moving forward smoothly. In a typical network a few internal servers (here rtr01 with chrony) follow external sources, and every other machine follows them.',
  architecture: [
    { q: 'What does it accomplish?', a: 'A common, correct time on every machine: each client measures its offset from a server and corrects its clock, either by **stepping** (jumping) it or by **slewing** it (running it slightly faster or slower until the error is gone).' },
    { q: 'How does it work internally?', a: 'The client sends a 48-byte request containing its transmit time; the server stamps when it received and sent the reply. From the four timestamps the client computes the **round-trip delay** and its **offset** from the server, assuming the delay is symmetric. chronyd repeats this every poll interval (64 s up to 1024 s), filters the samples, selects the best source and also learns the clock\'s **frequency error** (drift file). systemd-timesyncd is a simpler SNTP client: one server at a time, no serving.' },
    { q: 'Which protocols does it use?', a: 'NTPv4 (RFC 5905) over UDP; NTS (Network Time Security, RFC 8915) adds authentication with a TLS key exchange on TCP 4460. Windows uses its own NTP implementation (W32Time) with domain-specific signing.' },
    { q: 'Which ports and transport?', a: 'UDP 123 on the server; clients use an ephemeral source port (chronyd, timesyncd) or 123 (classic ntpd). chronyc talks to chronyd on UDP 127.0.0.1:323 or a Unix socket. A firewall must allow UDP 123 **to** the server and the replies back (stateful rules do that automatically).' },
    { q: 'Which processes and OS components implement it?', a: '`chronyd` (chrony.service: client and server, RHEL default), `systemd-timesyncd` (client only, Debian/Ubuntu default), `ntpd`/`ntpsec` (older full implementation, pfSense), `W32Time` (Windows Time service). The kernel keeps the clock and applies slewing (adjtimex); the RTC (hardware clock) keeps time while the machine is off.' },
    { q: 'Which other services does it depend on?', a: 'The network path and firewalls to the server (UDP 123 both ways), DNS if servers are configured by name (at start), and for the servers themselves an upstream: Internet servers, a GPS/PTP reference clock, or the AD domain hierarchy.' },
    { q: 'How do requests travel?', a: 'ws01 → rtr01:123 ("NTPv4, Client") → rtr01 checks its allow list and answers with its own time, stratum and reference ("NTPv4, Server") → ws01 sets its clock. rtr01 does the same towards 203.0.113.80 to keep itself correct.' },
    { q: 'How do authentication and authorisation work?', a: 'By default NTP is unauthenticated: a client believes any reply that arrives (protect the path, use few trusted servers, or NTS/symmetric keys). The **server** decides who it serves with access rules: chrony serves nobody until an `allow` line is present and **silently drops** requests from addresses not allowed.' },
    { q: 'How does it start at boot?', a: 'The client starts early (timesyncd before time-set.target), and corrects the clock on its first successful reply; chronyd steps the clock at start only if `makestep` permits (Debian: error above 1 s, first 3 updates), afterwards it only slews. Services that need correct time can wait for `time-sync.target`.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'Nothing visible at first: the clock keeps running from the kernel, drifting a few ms to seconds per day (VMs after a pause or host suspend can be off by minutes at once). Problems appear days later as Kerberos "Clock skew too great", TLS "certificate is not yet valid", or logs out of order. If the **server** stops, all its clients drift together.' },
  ],
  ports: [
    { port: '123', proto: 'UDP', purpose: 'NTP requests to the server, replies back (clients use ephemeral source ports)' },
    { port: '323', proto: 'UDP (localhost)', purpose: 'chronyc monitoring requests to chronyd' },
    { port: '4460', proto: 'TCP (TLS)', purpose: 'NTS key exchange (Network Time Security), when configured' },
  ],
  processes: [
    { name: 'chronyd', platform: 'Linux (chrony.service)', role: 'NTP client and server: polls sources, selects the best, disciplines the clock (step/slew, frequency), serves allowed clients' },
    { name: 'systemd-timesyncd', platform: 'Debian / Ubuntu', role: 'SNTP client only: one server at a time from timesyncd.conf, steps or slews the clock' },
    { name: 'ntpd / ntpsec', platform: 'pfSense, older Linux', role: 'Reference NTP implementation (client and server)' },
    { name: 'W32Time (svchost)', platform: 'Windows', role: 'Windows Time service: domain members follow their DC, the PDC emulator follows external sources (w32tm)' },
  ],
  dependencies: {
    title: 'What "ws01\'s clock is right" depends on (top needs everything below it)',
    caption: 'Time flows down the strata: a broken link anywhere makes everything below it drift, quietly.',
    rows: [
      { label: 'Users of time', nodes: [{ id: 'krb', label: 'Kerberos', sub: '±5 min', kind: 'service' }, { id: 'tls', label: 'TLS validity', sub: 'notBefore/notAfter', kind: 'service' }, { id: 'logs', label: 'Logs', sub: 'correlation', kind: 'data' }] },
      { label: 'Client', nodes: [{ id: 'ts', label: 'systemd-timesyncd', sub: 'ws01, NTP=rtr01', kind: 'os' }] },
      { label: 'Path', nodes: [{ id: 'fw', label: 'rtr01 input chain', sub: 'udp dport 123', kind: 'network' }] },
      { label: 'Internal server', nodes: [{ id: 'chrony', label: 'chronyd on rtr01', sub: 'stratum 2, allow', kind: 'service' }] },
      { label: 'Upstream', nodes: [{ id: 'up', label: 'ntp.example.net', sub: '203.0.113.80, stratum 1', kind: 'external' }, { id: 'gps', label: 'GPS reference', sub: 'stratum 0', kind: 'external' }] },
    ],
    edges: [['krb', 'ts'], ['tls', 'ts'], ['logs', 'ts'], ['ts', 'fw'], ['fw', 'chrony'], ['chrony', 'up'], ['up', 'gps']],
  },
  sequence: {
    title: 'ws01 synchronizes from rtr01, which follows ext01',
    caption: 'chrony 4.3 on rtr01 and ext01, systemd-timesyncd on ws01. Each reply carries the server\'s stratum and leap indicator.',
    lanes: [{ id: 'c', label: 'ws01', sub: 'timesyncd' }, { id: 'r', label: 'rtr01', sub: 'chronyd, stratum 2' }, { id: 'u', label: 'ext01', sub: 'stratum 1 (GPS)' }],
    steps: [
      { from: 'r', to: 'u', label: 'NTPv4 client request', note: 'Wrong upstream address or blocked outbound → rtr01 unsynchronized ("Can\'t synchronise: no selectable sources").' },
      { from: 'u', to: 'r', label: 'reply: stratum 1, refid GPS' },
      { from: 'c', to: 'r', label: 'NTPv4 client request (UDP 123)', note: 'Dropped by rtr01\'s firewall or not covered by an allow line → no reply: "Timed out waiting for reply".' },
      { from: 'r', to: 'c', label: 'reply: stratum 2, refid CB007150', note: 'If rtr01 is unsynchronized it still answers, with leap 3 / stratum 16: the client must ignore it.' },
      { from: 'c', to: 'c', label: 'offset computed, clock corrected' },
    ],
  },
  files: [
    { path: '/etc/chrony/chrony.conf', platform: 'Debian 12 (RHEL 9: /etc/chrony.conf)', kind: 'config', perms: 'root:root 0644', contains: '`server`/`pool` upstreams, `allow`/`deny` (who may use this server), `makestep`, `local stratum`, `driftfile`, `rtcsync`.', accessed: 'At chronyd start (systemctl restart chrony).', problems: 'Unknown directive → chronyd does not start. Missing allow line → that network is silently not served. Wrong server → unsynchronized server, clients told "not synchronized".' },
    { path: '/etc/systemd/timesyncd.conf', platform: 'Debian / Ubuntu', kind: 'config', perms: 'root:root 0644', contains: '[Time] NTP= (servers in order), FallbackNTP=.', accessed: 'At systemd-timesyncd start.', problems: 'No NTP= on an internal machine → the Debian pool is used, usually unreachable → never synchronized.' },
    { path: '/var/lib/chrony/chrony.drift', platform: 'Linux (chrony)', kind: 'data', perms: '_chrony 0644', contains: 'The measured frequency error of this clock (ppm), so chronyd starts well disciplined.', accessed: 'Read at start, rewritten hourly.', problems: 'Copied between machines (cloned VMs) it gives a wrong start; harmless after a few hours.' },
    { path: 'journal: journalctl -u chrony / -u systemd-timesyncd', platform: 'Linux', kind: 'log', contains: 'chronyd: "Selected source …", "System clock wrong by N seconds", "System clock was stepped", "Can\'t synchronise: no selectable sources". timesyncd: "Contacted time server …", "Initial clock synchronization", "Timed out waiting for reply from …".', accessed: 'Continuously.', problems: 'timesyncd logs replies from an unsynchronized server only at debug level: a clean log does not prove the time is good.' },
  ],
  management: [
    {
      platform: 'Debian / Ubuntu clients (systemd-timesyncd)',
      tasks: [
        { task: 'Is the clock synchronized?', command: 'timedatectl', explain: '"System clock synchronized: yes" and "NTP service: active" is the healthy state. No with active means the client cannot get usable answers.', sim: true },
        { task: 'Which server, and what did it answer?', command: 'timedatectl timesync-status', explain: 'Server, Leap (normal / not synchronized), Stratum, Offset, Delay and Packet count of the last reply. "Leap: not synchronized, Stratum: 16" means the server itself has no good time.', sim: true },
        { task: 'What did the client log?', command: 'journalctl -u systemd-timesyncd', explain: '"Timed out waiting for reply from IP:123" means no answer at all (firewall, allow list, server down without ICMP).', sim: true },
        { task: 'Poll now', command: 'systemctl restart systemd-timesyncd', explain: 'Starts a new synchronization attempt immediately instead of waiting for the next poll (up to 34 min).', sim: true },
        { task: 'Turn NTP on/off', command: 'timedatectl set-ntp true', explain: 'Enables and starts the NTP client. Set the time by hand only with NTP off, and only to recover.', sim: true },
      ],
    },
    {
      platform: 'Time server (chrony, rtr01)',
      tasks: [
        { task: 'Is this server synchronized?', command: 'chronyc tracking', explain: 'Reference ID, Stratum, System time offset, "Leap status : Normal". "Not synchronised" means every client of this server will be told so.', sim: true },
        { task: 'Its upstreams', command: 'chronyc sources', explain: '"^*" selected; Reach 377 = all of the last 8 polls answered; "^?" with Reach 0 = never answered.', sim: true },
        { task: 'Who does it serve (and drop)?', command: 'chronyc clients', explain: 'NTP = answered requests, Drop = requests refused by allow/deny. A network with only drops is missing an allow line.', sim: true },
        { task: 'Is it listening, and does the firewall allow it?', command: 'ss -ulnp\nnft list ruleset', explain: 'chronyd on UDP 123 (only when an allow line exists) and an input rule accepting udp dport 123 from the client networks.', sim: true },
        { task: 'Watch the requests', command: 'tcpdump -n -i eth0 udp port 123', explain: '"NTPv4, Client" without a "Server" reply: dropped (firewall: chronyd never sees it; allow list: chronyc clients counts a drop).', sim: true },
        { task: 'Daemon log', command: 'journalctl -u chrony', explain: 'Start errors ("Fatal error : Invalid directive"), source selection, steps.', sim: true },
        { task: 'Step the clock now', command: 'chronyc makestep', explain: 'After fixing a large error that chronyd would otherwise slew for hours.', risk: 'Time jumps for every running program.', sim: true },
      ],
    },
    {
      platform: 'RHEL 9',
      tasks: [
        { task: 'chronyd everywhere', command: 'systemctl status chronyd\nchronyc sources -v', explain: 'RHEL uses chrony as client and server (unit chronyd.service, file /etc/chrony.conf); same commands.' },
        { task: 'Firewall on a server', command: 'firewall-cmd --add-service=ntp --permanent && firewall-cmd --reload', explain: 'Opens UDP 123 for clients.' },
      ],
    },
    {
      platform: 'Windows (W32Time)',
      tasks: [
        { task: 'Status and source', command: 'w32tm /query /status\nw32tm /query /source', explain: 'Domain members follow a DC (source: the DC\'s name); the PDC emulator follows external servers set with w32tm /config /manualpeerlist:"ntp.example.net" /syncfromflags:manual /reliable:yes /update.' },
        { task: 'Resynchronize', command: 'w32tm /resync /rediscover', explain: 'Polls now. "The computer did not resync because no time data was available" = no source reachable.' },
      ],
    },
    {
      platform: 'pfSense',
      tasks: [
        { task: 'NTP server on the firewall', command: 'Services > NTP: interfaces to listen on, time servers (pool/servers); Status > NTP shows peers', explain: 'pfSense runs ntpd and often serves the LANs. Clients still need a firewall rule allowing UDP 123 to the interface address.' },
      ],
    },
  ],
  actions: [
    { action: 'systemctl restart systemd-timesyncd', when: 'After fixing the server, path or timesyncd.conf, to poll at once.', effect: 'New attempt; the clock is corrected on the first good reply.', risk: 'Low; a step can make time jump.' },
    { action: 'systemctl restart chrony', when: 'After editing chrony.conf.', effect: 'Re-reads the file, polls sources (iburst: quickly), serves clients again.', risk: 'An invalid file leaves chronyd stopped: check systemctl status chrony.' },
    { action: 'chronyc makestep', when: 'A large error that slewing would take hours to remove (no makestep in the configuration, or after the first updates).', effect: 'The clock jumps to the source\'s time.', risk: 'Backwards jumps confuse logs, timers and databases.' },
    { action: 'date -s / timedatectl set-time', when: 'Only to recover a machine with no reachable NTP at all, with NTP turned off.', effect: 'Sets the clock by hand.', risk: 'It drifts again; Kerberos and TLS break when it does. Fix NTP instead.' },
  ],
  workflow: [
    { question: 'Is the client synchronized at all?', why: 'Start with the machine that has the wrong time: is it trying to synchronize at all, and does it think it succeeded?', command: 'timedatectl', healthy: 'System clock synchronized: yes\n              NTP service: active', broken: '"synchronized: no" with "NTP service: inactive" → NTP is turned off (timedatectl set-ntp true). With "active" → the client gets no usable answer: step 2.', next: 'Ask the client what it heard.', sim: true },
    { question: 'Did it get a reply, and what did the reply say?', why: 'A reply that arrives but says "not synchronized" is a different problem from no reply at all.', command: 'timedatectl timesync-status\njournalctl -u systemd-timesyncd', healthy: '         Leap: normal\n      Stratum: 2\n Packet count: 3', broken: '"Timed out waiting for reply" → no answer (step 3). Replies with "Leap: not synchronized" / "Stratum: 16" → the server has no good time itself (step 4).', next: 'Follow the request to the server.', sim: true },
    { question: 'Does the request reach the server, and does it answer?', why: 'If no reply comes back, the request is lost on the way, dropped by the server\'s firewall, or refused by chrony\'s allow list.', command: 'tcpdump -n -i eth0 udp port 123\nnft list ruleset\nchronyc clients', healthy: 'IP 10.0.10.25.35375 > 10.0.10.1.123: NTPv4, Client, length 48\nIP 10.0.10.1.123 > 10.0.10.25.35375: NTPv4, Server, length 48', broken: 'Requests without replies and chronyc clients does not count them → the firewall drops them before chronyd. chronyc clients shows them under Drop → chronyd\'s allow list. Nothing arrives → routing/path. ICMP port unreachable → chronyd not running.', next: 'Fix the server side, then restart the client (or wait for its next poll).', sim: true },
    { question: 'Is the server itself synchronized?', why: 'A server can only hand out good time if it has good time itself. If its own upstream is unreachable, all its clients go wrong with it.', command: 'chronyc tracking\nchronyc sources', healthy: 'Leap status     : Normal\n^* 203.0.113.80                  1   6   377', broken: '"Not synchronised" and "^?" with Reach 0 → its upstream is unreachable or wrong (address, DNS, outbound firewall). Do not paper over it with "local stratum".', next: 'Fix the upstream; clients recover at their next poll.', sim: true },
  ],
  failures: [
    { symptom: 'Clients time out ("Timed out waiting for reply from …:123")', causes: ['Firewall on the server (or on the path) drops UDP 123', 'chronyd has no allow line for the client\'s network (silent drop)', 'Server address/name wrong in timesyncd.conf'], diagnose: ['tcpdump -n udp port 123 on the server', 'nft list ruleset', 'chronyc clients (Drop column)'], fix: 'Allow UDP 123 from the internal networks in the input chain, or add the missing allow line to chrony.conf and restart chrony.', verify: 'timedatectl on the client: System clock synchronized: yes' },
    { symptom: 'Replies arrive but clients stay unsynchronized, logs are clean', causes: ['The server is not synchronized (no usable upstream) and answers with leap 3 / stratum 16'], diagnose: ['timedatectl timesync-status on a client', 'chronyc tracking and chronyc sources on the server', 'journalctl -u chrony ("Can\'t synchronise")'], fix: 'Repair the server\'s upstream (address, DNS, outbound path); add a second upstream.', verify: 'chronyc tracking: Leap status Normal; clients synchronized.' },
    { symptom: 'No client synchronizes; ICMP port unreachable from the server', causes: ['chronyd not running (configuration error, stopped, masked)'], diagnose: ['systemctl status chrony', 'journalctl -u chrony -n 20', 'ss -ulnp'], fix: 'Fix chrony.conf and start chrony.', verify: 'ss -ulnp shows chronyd on 123; chronyc tracking works.' },
    { symptom: 'Kerberos "Clock skew too great", TLS "certificate is not yet valid", logs out of order', causes: ['A client not synchronized for days (any of the above)', 'NTP turned off and the time set by hand', 'A VM restored from a snapshot or paused for a long time'], diagnose: ['date on the client and on the KDC/server', 'timedatectl'], fix: 'Restore synchronization (not a manual date): the clock is stepped on the first good reply.', verify: 'kinit works; date matches the servers.' },
  ],
  verification: [
    { check: 'Client synchronized', command: 'timedatectl', expect: 'System clock synchronized: yes / NTP service: active' },
    { check: 'Client uses the internal server', command: 'timedatectl timesync-status', expect: 'Server: 10.0.10.1 (rtr01.corp.lab), Leap: normal, Stratum: 2' },
    { check: 'Server synchronized to its upstream', command: 'chronyc tracking', expect: 'Reference ID : CB007150 (203.0.113.80), Leap status : Normal' },
    { check: 'Server serves every client network', command: 'chronyc clients', expect: 'Clients from 10.0.10.x, 10.0.20.x and 10.0.30.x with NTP > 0 and Drop 0' },
    { check: 'Survives a reboot', command: 'systemctl is-enabled chrony systemd-timesyncd', expect: 'enabled' },
  ],
  refIds: ['timedatectl', 'chronyc', 'file:chrony-conf', 'file:timesyncd-conf', 'journalctl', 'nft', 'ss', 'w32tm'],
};

// --- Lesson -------------------------------------------------------------------------

export const NTP_LESSON: Lesson = {
  id: 'ntp',
  moduleId: 'F',
  title: 'Time synchronisation (NTP)',
  level: 'intermediate',
  summary: 'How NTP clients and servers keep clocks right (strata, offset and delay, step and slew), how chrony and systemd-timesyncd are configured and checked, and how to find which link of the time chain broke.',
  concepts: ['ntp.sync', 'fw.path', 'svc.systemd', 'ad.kerberos'],

  what: `
**NTP** (Network Time Protocol) keeps computer clocks correct. Every computer has a clock that drifts: a few milliseconds to a few seconds per day, and often worse in virtual machines. NTP clients regularly ask a time server for the time and gently correct their own clock.

It may seem like a small thing, but many other services silently depend on correct time: [Kerberos](#/lesson/kerberos/what) refuses logons when clocks differ by more than 5 minutes, [TLS](#/lesson/tls/what) certificates are only valid between two dates, and logs from different machines are useless if their timestamps disagree. NTP itself is a simple UDP exchange on port 123, so it needs a route and open firewalls like any other service.

### Problems it solves
- **Authentication works.** Kerberos (and Active Directory logons) refuse clocks more than 5 minutes apart.
- **Certificates validate.** A clock in the past makes new certificates "not yet valid"; one in the future makes valid ones "expired".
- **Logs line up.** Following one request across a proxy, an application and a database is only possible if their timestamps agree.
- **Scheduled work and replication behave.** Cron, backups, caches, databases and directory replication assume time moves forward together everywhere.

### The pieces
- **Time servers** arranged in **strata**: stratum 1 servers have a reference clock (GPS, atomic); a server that follows a stratum-1 server is stratum 2, and so on. In the lab, ext01 is stratum 1, rtr01 stratum 2, the clients stratum 3.
- **Clients**: \`systemd-timesyncd\` (simple client, Debian/Ubuntu default), \`chronyd\` (client and server, RHEL default), Windows Time (W32Time).
- **The path**: UDP port 123 from client to server and back, through routers and firewalls.

> In the lab: **ext01** (203.0.113.80) stands in for the provider's stratum-1 server, **rtr01** runs chrony 4.3 and serves the office, server and VLAN 30 networks, and every Debian machine runs systemd-timesyncd with \`NTP=rtr01.corp.lab\`. Simulated: real NTP request/reply datagrams through routing, firewalls and NAT; chrony.conf (\`server\`, \`allow\`/\`deny\`, \`local stratum\`, \`refclock\`, \`makestep\`); chronyd as client and server (selection, leap/stratum in replies, silent drops, "Can't synchronise"); timesyncd (servers in order, timeouts, rejecting unsynchronized servers); \`chronyc\` and \`timedatectl timesync-status\`; Kerberos depending on the result. Simplified: one sample per poll (no filtering, frequency estimation or falseticker detection), corrections are applied at once (except a large error without makestep), and daemons poll at start and "a few minutes later" (before a check and after reboots) rather than on a timer.
`,

  internals: `
### 1. One exchange: offset and delay
The client sends a request stamped with its transmit time **T1**. The server notes when it received it (**T2**) and when it answered (**T3**); the client notes when the reply arrived (**T4**).
- Round-trip **delay** = (T4 − T1) − (T3 − T2): the time on the network.
- Clock **offset** = ((T2 − T1) + (T3 − T4)) / 2: how far the client is from the server, **assuming the path is symmetric**. An asymmetric path (a slow uplink, a queue in one direction) shows up as an offset error of up to half the asymmetry.

:::practice
Q: A client sends at T1 = 10.000 s (its clock). The server receives at T2 = 10.120 and answers at T3 = 10.121 (server clock). The reply arrives at T4 = 10.041 (client clock). Work out the delay and the offset.
A: Delay = (T4 − T1) − (T3 − T2) = 0.041 − 0.001 = **0.040 s**. Offset = ((T2 − T1) + (T3 − T4)) / 2 = (0.120 + 0.080) / 2 = **+0.100 s**: the client is 100 ms behind the server.
Q: Why can an asymmetric path (fast download, slow upload) make the calculated offset wrong?
A: The formula assumes the request and the reply take the **same time**. If one direction is slower, the difference shows up as an offset error of up to half the asymmetry.
:::

### 2. Strata and the reference chain
Each reply carries the server's **stratum**, its **reference ID** (the IPv4 address of its own source, or a name like \`GPS\` / \`LOCL\`), root delay/dispersion (the accumulated uncertainty) and a **leap indicator**. Leap indicator 3 ("alarm") with stratum 16 means **"I am not synchronized, do not use my time"**: a well-behaved client ignores such a server. That is why a time server that lost its upstream breaks all its clients *without* any timeout: they get answers, just useless ones.

:::practice
Q: A server follows a stratum-2 server. Which stratum does it announce to its own clients?
A: **Stratum 3**: one level further from the reference clock.
Q: All clients of a time server get replies, yet none of them is synchronized and nothing times out. What do the replies probably say?
A: Leap indicator 3 with **stratum 16**: "I am not synchronized". The server lost its own upstream, and clients correctly ignore its time.
:::

### 3. Step or slew
A client can correct its clock in two ways:
- **Step**: jump to the right time at once. Fast, but time can go backwards (logs, timers, databases notice).
- **Slew**: make the clock run slightly fast or slow until the error is gone (chronyd: at most 83 ms per second). Smooth, but a 10-minute error takes hours.

chrony's \`makestep 1 3\` (Debian default) steps when the error is above 1 s, but only during the first 3 updates (normally at boot); later it only slews. systemd-timesyncd steps large errors and slews small ones.

:::practice
Q: A server running chronyd with \`makestep 1 3\` has been up for a week and is suddenly 30 seconds off. Will chronyd step the clock?
A: **No.** makestep only allows steps during the first 3 updates (normally at boot). Now it slews at up to 83 ms per second, so about 6 minutes to fix 30 s.
Q: Why might a database administrator prefer slewing over stepping?
A: A step can make time go **backwards**, which can confuse transactions, logs and timers; slewing never jumps.
:::

### 4. Who may get time: chrony's allow list
chronyd serves **nobody** until a configuration line \`allow SUBNET\` (or \`allow all\`) exists; it then listens on UDP 123. Requests from addresses not covered are **dropped without a reply** (an error reply could be abused for reflection attacks). From the client this looks exactly like a firewall drop; on the server \`chronyc clients\` counts them in the Drop column, which is how you tell the two apart.

:::practice
Q: chrony.conf has \`allow 10.0.10.0/24\`. A client 10.0.20.15 asks for time. What does it get, and where can you see it?
A: **Nothing**: chronyd drops the request silently. \`chronyc clients\` on the server shows the request counted in the **Drop** column.
Q: From the client, how do a firewall drop and a chrony allow-list drop look different?
A: They look **identical** (a timeout). Only the server can tell: requests that reach chronyd appear in \`chronyc clients\`; requests dropped by the firewall never do.
:::

### 5. When the server has no good time
- \`chronyc tracking\` → "Leap status : Not synchronised", Reference ID 00000000, and the journal says "Can't synchronise: no selectable sources".
- Clients receive replies with leap 3 / stratum 16 and stay "System clock synchronized: no"; systemd-timesyncd logs this only at debug level.
- **\`local stratum 10\`** makes chronyd serve its own clock when it has no source. That hides the alarm and lets every client follow a clock nobody corrects: use it only for isolated networks that are designed to have no external time.

:::practice
Q: \`chronyc tracking\` on the time server shows Reference ID 00000000 and "Not synchronised". Which command shows why its sources are not usable?
A: \`chronyc sources\` (and the journal: "Can't synchronise: no selectable sources").
Q: Why is \`local stratum 10\` dangerous on a normal office time server?
A: When it loses its sources it serves its **own uncorrected clock** as if it were good, so every client follows a drifting clock without any alarm.
:::

### 6. Failure signatures at a glance
| What the client sees | Where to look |
|---|---|
| "Timed out waiting for reply" | server firewall (requests not seen by chronyd) or chrony allow list (chronyc clients: Drop) |
| Replies with Leap not synchronized / stratum 16 | the server's own upstream: chronyc tracking / sources |
| ICMP port unreachable, nothing logged | chronyd not running: systemctl status chrony |
| "synchronized: no" with "NTP service: inactive" | NTP turned off on the client: timedatectl set-ntp true |

:::practice
Q: A client's NTP requests to a server get ICMP port unreachable. What do you check on the server?
A: Whether **chronyd is running**: \`systemctl status chrony\`. Nothing listens on UDP 123.
Q: \`timedatectl\` shows "System clock synchronized: no" and "NTP service: inactive". Fix?
A: NTP is switched off on the client: \`timedatectl set-ntp true\`.
:::

### 7. Windows and Active Directory
Domain members synchronize from a domain controller (NT5DS hierarchy) and the **PDC emulator** follows external servers; Kerberos in AD has the same 5-minute tolerance. The commands are \`w32tm /query /status\`, \`/query /source\` and \`/resync\`. (W32Time is not simulated in the lab.)

:::practice
Q: Which Windows command shows where a machine currently gets its time from?
A: \`w32tm /query /source\`.
Q: In a domain, which time source should a normal member server use?
A: A **domain controller** (the NT5DS domain hierarchy), never an Internet server of its own.
:::

`,

  deployment: [
    {
      id: 'debian',
      platform: 'Debian 12 / Ubuntu (chrony server, timesyncd clients)',
      summary: 'Make one internal machine the time server for the networks (chrony), and point every other machine at it (systemd-timesyncd). Steps marked simulated can be tried in the sandbox (rtr01 already runs this setup).',
      prerequisites: ['A server with outbound UDP 123 to the provider\'s or a public pool\'s servers.', 'Firewall rules allowing UDP 123 from the internal networks to that server.'],
      steps: [
        { title: 'Install chrony on the server', command: 'sudo apt install -y chrony\nsystemctl status chrony', what: 'Installs chronyd (this removes systemd-timesyncd: only one may discipline the clock).', why: 'timesyncd cannot serve time; chrony can.', expected: 'Active: active (running)' },
        { title: 'Configure upstreams and clients', command: 'server 203.0.113.80 iburst\nallow 10.0.10.0/24\nallow 10.0.20.0/24\nallow 10.0.30.0/24\nmakestep 1 3', what: 'In /etc/chrony/chrony.conf: one or more upstreams (iburst: four quick polls at start), and every internal network allowed.', why: 'Without allow lines chronyd serves nobody; with "allow all" it serves the Internet too.', expected: '' },
        { title: 'Restart and check the server', command: 'systemctl restart chrony\nchronyc tracking\nchronyc sources', what: 'Re-reads the configuration and polls the upstream.', why: 'The server must be synchronized itself before clients can use it.', expected: 'Leap status     : Normal\n^* 203.0.113.80                  1   6   377', simulated: true },
        { title: 'Open the firewall on the server', command: 'nft list ruleset', what: 'The input chain needs `iifname != "eth2" udp dport 123 accept` (internal interfaces only).', why: 'With policy drop and no rule, requests never reach chronyd.', expected: 'iifname != "eth2" udp dport 123 accept', simulated: true },
        { title: 'Point the clients at it', command: '[Time]\nNTP=rtr01.corp.lab', what: 'In /etc/systemd/timesyncd.conf on every client, then systemctl restart systemd-timesyncd.', why: 'Without NTP= the clients use the Debian pool, which internal machines usually cannot reach.', expected: '' },
        { title: 'Verify on a client', command: 'timedatectl\ntimedatectl timesync-status', what: 'Synchronized, with the server, stratum and offset of the last reply.', why: 'Proves the whole chain: client, path, server, upstream.', expected: 'System clock synchronized: yes\n       Server: 10.0.10.1 (rtr01.corp.lab)\n      Stratum: 2', simulated: true },
      ],
    },
    {
      id: 'rhel',
      platform: 'RHEL 9 (chronyd)',
      summary: 'RHEL uses chronyd on clients and servers alike: /etc/chrony.conf, unit chronyd.service.',
      prerequisites: ['RHEL 9 with the chrony package (installed by default).'],
      steps: [
        { title: 'Client', command: 'echo "server rtr01.corp.lab iburst" | sudo tee /etc/chrony.d/corp.conf\nsudo systemctl restart chronyd\nchronyc sources', what: 'Adds the internal server (drop-in directory), restarts, checks it is selected (^*).', why: 'Remove or comment out the default "pool 2.rhel.pool.ntp.org" if it is not reachable.', expected: '^* rtr01.corp.lab' },
        { title: 'Server', command: 'echo "allow 10.0.0.0/16" | sudo tee -a /etc/chrony.conf\nsudo systemctl restart chronyd\nsudo firewall-cmd --add-service=ntp --permanent && sudo firewall-cmd --reload', what: 'Serves the internal networks and opens UDP 123.', why: 'Both are needed: chrony\'s allow and the host firewall.', expected: 'success' },
      ],
    },
    {
      id: 'windows',
      platform: 'Windows Server (W32Time, Active Directory)',
      summary: 'In a domain, members follow the DCs automatically; only the PDC emulator of the forest root domain is pointed at external NTP servers.',
      prerequisites: ['Domain Admin on the PDC emulator (netdom query fsmo).'],
      steps: [
        { title: 'Configure the PDC emulator', command: 'w32tm /config /manualpeerlist:"203.0.113.80,0x8" /syncfromflags:manual /reliable:yes /update\nRestart-Service w32time\nw32tm /resync /rediscover', what: 'External source for the domain\'s time hierarchy.', why: 'Every other DC and member follows it (NT5DS).', expected: 'The command completed successfully.' },
        { title: 'Check a member', command: 'w32tm /query /source\nw32tm /query /status', what: 'Source should be a DC; Leap Indicator 0.', why: 'A member showing "Local CMOS Clock" or "Free-running System Clock" is not synchronized.', expected: 'dc01.ad.corp.lab' },
      ],
    },
    {
      id: 'pfsense',
      platform: 'pfSense (ntpd)',
      summary: 'pfSense can be the internal time server (Services > NTP): choose the interfaces it listens on and its upstream servers; Status > NTP shows peers and the selected source (marked "Active Peer").',
      prerequisites: ['Firewall rules allowing UDP 123 from the LANs to the pfSense interface address.'],
      steps: [
        { title: 'Enable and check', command: 'Services > NTP > Interfaces: LAN, OPT1; Time Servers: 2.pfsense.pool.ntp.org (pool)\nStatus > NTP', what: 'ntpd serves the selected interfaces.', why: 'Clients then use the firewall\'s address as NTP server.', expected: 'Status: Active Peer, Stratum 2' },
      ],
    },
  ],

  configIntro: `
Two files matter, one per role:
- **The server's \`chrony.conf\`**: where it gets time (\`server\`/\`pool\`), who may use it (\`allow\`), how it corrects itself (\`makestep\`), and what it does without a source (\`local stratum\`, normally absent).
- **Each client's \`timesyncd.conf\`** (or chrony.conf with a \`server\` line): which server(s) to ask.

Plus the firewall on the server (UDP 123 in) and the path between them.
`,

  configFiles: [
    { platform: 'Debian / Ubuntu', items: [
      { path: '/etc/chrony/chrony.conf, /etc/chrony/conf.d/', purpose: 'chronyd: sources, allow/deny, makestep.' },
      { path: '/etc/systemd/timesyncd.conf', purpose: 'systemd-timesyncd: NTP= servers.' },
      { path: '/var/lib/chrony/chrony.drift', purpose: 'Learned frequency error.' },
    ] },
    { platform: 'RHEL', items: [
      { path: '/etc/chrony.conf, /etc/chrony.d/', purpose: 'chronyd on clients and servers.' },
    ] },
    { platform: 'Windows', items: [
      { path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters', purpose: 'Type (NT5DS / NTP), NtpServer.' },
    ] },
  ],

  directives: [
    { name: 'server HOST [iburst]', compiledDefault: '(none; Debian ships "pool 2.debian.pool.ntp.org iburst")', recommended: 'Two to four independent upstreams', explanation: 'An NTP source. iburst sends four quick requests at start so the first synchronization takes seconds.', security: 'Each source is trusted; use sources you control or a reputable pool, or NTS.' },
    { name: 'allow SUBNET / deny SUBNET', compiledDefault: 'serve nobody', recommended: 'Exactly the internal networks', explanation: 'Who may use this machine as an NTP server; others are dropped silently.', security: '"allow all" on an Internet-facing machine turns it into a public server (abuse, amplification).' },
    { name: 'makestep THRESHOLD LIMIT', compiledDefault: 'never step (slew only)', recommended: '1 3 (step at boot only)', explanation: 'Step instead of slew when the error is above THRESHOLD seconds, in the first LIMIT updates (-1: always).', security: 'Steps at any time make time jump backwards for running software.' },
    { name: 'local stratum N', compiledDefault: 'off', recommended: 'Off (only for deliberately isolated networks)', explanation: 'Serve the local clock as stratum N when no source is reachable.', security: 'Hides a lost upstream: clients happily follow an uncorrected clock.' },
    { name: 'NTP= (timesyncd.conf)', compiledDefault: 'empty → FallbackNTP (Debian pool)', recommended: 'The internal time servers', explanation: 'Servers systemd-timesyncd tries in order.', security: 'Internal machines should not depend on Internet NTP.' },
  ],

  operateIntro: `
### Before you change time settings
- Never fix a skew error by setting the time by hand on the client or by raising Kerberos' clockskew: find out why NTP is not working.
- Change the server carefully: every client follows it. After editing chrony.conf, restart chrony and check \`systemctl status chrony\` and \`chronyc tracking\` immediately.

`,
  troubleshootingIntro: `
### Follow the time chain
Time flows down a chain: the reference clock, the upstream server, your local time server, then each client. A client can only be right if every link above it works. Start at the client that is wrong and walk up the chain.

1. **The client.** \`timedatectl\` shows whether the clock is synchronized and whether the NTP service is active. \`timedatectl timesync-status\` shows which server it uses and the last result; \`journalctl -u systemd-timesyncd\` shows its log.
2. **The path.** Do the client's requests reach the server? Run \`tcpdump -n udp port 123\` on the server. Does the server's firewall accept them (\`nft list ruleset\`)?
3. **The server.** Is chronyd running (\`systemctl status chrony\`)? Does it agree to serve this client (\`chronyc clients\` lists who asked; an \`allow\` line must cover the client's network)? Is it synchronized itself (\`chronyc tracking\`, \`chronyc sources\`)?
4. **Upstream.** Can the server reach its own time sources? Look at the Reach column in \`chronyc sources\`, and for "Can't synchronise" in its log.

How to read the result: a **timeout** (no answer at all) points to steps 2 and 3. **Replies that say "not synchronized"** mean the path works but the server has no good time to give, which points to step 4.
`,

  errorMap: [
    { message: 'Timed out waiting for reply from 10.0.10.1:123 (rtr01.corp.lab).', layer: 'Path / server access', meaning: 'No reply: a firewall drops the request, or chrony\'s allow list does not cover the client.', firstCheck: 'tcpdump -n udp port 123 and chronyc clients on the server' },
    { message: 'System clock synchronized: no (NTP service: active)', layer: 'Client', meaning: 'The client runs but has no usable reply.', firstCheck: 'timedatectl timesync-status; journalctl -u systemd-timesyncd' },
    { message: 'Leap: not synchronized / Stratum: 16 (timesync-status)', layer: 'Server', meaning: 'The server answers but is not synchronized itself.', firstCheck: 'chronyc tracking and chronyc sources on the server' },
    { message: "Can't synchronise: no selectable sources", layer: 'Server upstream', meaning: 'chronyd reaches none of its sources (or none is acceptable).', firstCheck: 'chronyc sources (Reach); the server lines; outbound path' },
    { message: 'Fatal error : Invalid directive at line N in file /etc/chrony/chrony.conf', layer: 'Server configuration', meaning: 'chronyd refused to start.', firstCheck: 'The named line; systemctl start chrony after fixing' },
    { message: '506 Cannot talk to daemon', layer: 'Server', meaning: 'chronyc cannot reach chronyd: it is not running.', firstCheck: 'systemctl status chrony' },
    { message: 'kinit: Clock skew too great while getting initial credentials', layer: 'Consequence (Kerberos)', meaning: 'Client and KDC clocks differ by more than 5 minutes.', firstCheck: 'date on both; timedatectl on the client' },
    { message: 'The computer did not resync because no time data was available. (w32tm /resync)', layer: 'Windows client', meaning: 'W32Time reached no usable source.', firstCheck: 'w32tm /query /source; UDP 123 to the DC' },
  ],

  scenarioIds: ['ntp-blocked', 'ntp-vlan30-allow', 'ntp-upstream-lost', 'ntp-chronyd-dead', 'krb-clock-skew'],
  assessmentId: 'ntp',
  references: [
    { title: 'RFC 5905: Network Time Protocol Version 4', url: 'https://www.rfc-editor.org/rfc/rfc5905' },
    { title: 'chrony documentation: chrony.conf(5)', url: 'https://chrony-project.org/doc/4.3/chrony.conf.html' },
    { title: 'chrony documentation: chronyc(1)', url: 'https://chrony-project.org/doc/4.3/chronyc.html' },
    { title: 'systemd: timesyncd.conf(5)', url: 'https://www.freedesktop.org/software/systemd/man/latest/timesyncd.conf.html' },
    { title: 'Red Hat: Using the chrony suite to configure NTP (RHEL 9)', url: 'https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_basic_system_settings/configuring-time-synchronization_configuring-basic-system-settings' },
    { title: 'Microsoft Learn: How the Windows Time service works', url: 'https://learn.microsoft.com/windows-server/networking/windows-time-service/how-the-windows-time-service-works' },
    { title: 'RFC 8915: Network Time Security for NTP', url: 'https://www.rfc-editor.org/rfc/rfc8915' },
  ],
  guide: NTP_GUIDE,
  objectives: ['N10-009:1.4', 'N10-009:3.4', 'N10-009:5.3'],
};

// --- Primer -------------------------------------------------------------------------

export const NTP_PRIMER: Primer = {
  oneLiner: 'Every computer\'s clock drifts. **NTP** clients regularly ask a **time server** what time it is (UDP port 123) and correct their clock; time servers in turn follow better servers, up to a reference clock. If any link of that chain breaks, the machines below it drift apart quietly, until Kerberos, TLS or your logs notice.',
  analogy: `
Think of a railway network setting its station clocks. The national observatory (stratum 1) has the exact time; the main stations (stratum 2) phone the observatory, and the small stations (stratum 3) phone their main station.

If the line to the main station is cut, the small stations' calls go unanswered (**timeout**). If the main station has lost its own line to the observatory, it still picks up the phone but says "I'm not sure of the time myself" (**not synchronized**): the small stations must not copy it. Either way, nobody notices for days, until two trains are scheduled for the same platform.`,
  ideas: [
    {
      title: 'Strata: time flows down a chain',
      explain: 'A reference clock (GPS) is stratum 0, the server attached to it stratum 1, a server following that stratum 2, and so on. Each machine is only as good as its chain.',
      example: 'ext01 (GPS) is stratum 1, rtr01 follows it as stratum 2, ws01 follows rtr01. `chronyc tracking` on rtr01 shows "Reference ID : CB007150 (203.0.113.80)", "Stratum : 2".',
    },
    {
      title: '"Synchronized" is the thing to check',
      explain: '`timedatectl` tells you whether the clock is being corrected by NTP. "NTP service: active" only means the client runs; "System clock synchronized: yes" means it actually gets good time.',
      example: 'After rtr01\'s firewall stopped allowing UDP 123, ws01 showed "NTP service: active" but "synchronized: no", and its log said "Timed out waiting for reply from 10.0.10.1:123".',
    },
    {
      title: 'Timeout or "not synchronized" tells you where to look',
      explain: 'No reply means the request is blocked or ignored on the way or at the server. A reply that says "not synchronized" (leap 3, stratum 16) means the server works but has no good time itself.',
      example: '`timedatectl timesync-status` on ws01 showing "Leap: not synchronized", "Stratum: 16" sends you to rtr01\'s upstream (`chronyc sources`: "^? 203.0.113.8 … Reach 0").',
    },
    {
      title: 'A time server chooses whom it serves',
      explain: 'chrony serves only the networks in its `allow` lines and silently ignores everyone else. That looks exactly like a firewall drop from the client.',
      example: 'Removing `allow 10.0.30.0/24` from rtr01 made only VLAN 30 drift. `chronyc clients` on rtr01 listed 10.0.30.25 with NTP 0 and a growing Drop count.',
    },
  ],
  walkthrough: {
    title: 'Checking the time chain from a client to the reference',
    steps: [
      { label: 'Client status', detail: '`timedatectl` on ws01: "System clock synchronized: yes", "NTP service: active".' },
      { label: 'What the server said', detail: '`timedatectl timesync-status`: Server 10.0.10.1 (rtr01.corp.lab), Leap normal, Stratum 2, a small Offset.' },
      { label: 'The server itself', detail: '`chronyc tracking` on rtr01: Reference 203.0.113.80, Stratum 2, "Leap status : Normal".' },
      { label: 'Its upstream', detail: '`chronyc sources`: "^* 203.0.113.80 … 377": selected, every recent poll answered.' },
      { label: 'Its clients', detail: '`chronyc clients`: every internal network listed with NTP requests answered and no drops.' },
    ],
  },
  misconceptions: [
    { myth: 'If the clock looks right, NTP is fine.', truth: 'A clock drifts slowly: it looks right for days after synchronization stops. Check "System clock synchronized", not the clock.' },
    { myth: 'Setting the time by hand fixes a skew problem.', truth: 'Only until it drifts again. Find out why NTP is not working (client, path, server, upstream).' },
    { myth: 'No error in the client\'s log means the time server is healthy.', truth: 'A server that lost its own upstream still answers, saying "not synchronized"; simple clients ignore that silently.' },
  ],
  checks: [
    { q: 'Which UDP port must the time server accept from its clients?', a: '123.' },
    { q: 'A client shows "NTP service: active" but "System clock synchronized: no" and logs timeouts. Name two possible causes on the server side.', a: 'A firewall dropping UDP 123, or chrony not allowing the client\'s network (no allow line).' },
    { q: 'What does stratum 16 with "Leap: not synchronized" in a reply mean?', a: 'The server is not synchronized itself; clients must not use its time.' },
    { q: 'Why does a clock problem break Kerberos?', a: 'Kerberos rejects requests whose timestamps differ from the KDC\'s clock by more than 5 minutes.' },
  ],
};

// --- Assessment -------------------------------------------------------------------------

export const NTP_ASSESSMENT: Assessment = {
  id: 'ntp',
  title: 'Time synchronisation knowledge check',
  questions: [
    {
      id: 'ntp-q-chain',
      kind: 'order',
      level: 'beginner',
      learn: ['lesson/ntp/internals'],
      prompt: 'Order the lab\'s time chain from the most accurate source to the client.',
      items: ['GPS reference clock (stratum 0)', 'ext01, the provider\'s server (stratum 1)', 'rtr01 with chrony (stratum 2)', 'ws01 with systemd-timesyncd (stratum 3)'],
      concepts: ['ntp.sync'],
      explanation: 'Each level follows the one above and is one stratum further from the reference.',
    },
    {
      id: 'ntp-q-timeout',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/ntp/internals'],
      prompt: 'Only the hosts of VLAN 30 log "Timed out waiting for reply from 10.0.10.1:123". On rtr01, tcpdump shows their requests arriving, and this output. What is the cause?',
      exhibit: '# chronyc clients\nHostname                      NTP   Drop Int IntL Last     Cmd   Drop Int  Last\n===============================================================================\n10.0.10.25                     14      0   6   -    40       0      0   -     -\n10.0.30.25                      0     12   6   -    35       0      0   -     -',
      options: [
        { text: 'chrony.conf on rtr01 has no allow line covering 10.0.30.0/24', correct: true },
        { text: 'rtr01\'s firewall drops UDP 123 from VLAN 30', misconception: 'Then chronyd would never see the requests; it counts them as drops, so they passed the firewall.' },
        { text: 'rtr01 is not synchronized to its upstream', misconception: 'Then it would still answer (with "not synchronized"), and the office clients would be affected too.' },
        { text: 'dev01 has the wrong server in timesyncd.conf', misconception: 'The requests reach rtr01, which is the right server.' },
      ],
      concepts: ['ntp.sync'],
      explanation: 'Drop counts in chronyc clients mean chronyd received and refused the requests: its allow/deny rules do not permit that address.',
    },
    {
      id: 'ntp-q-leap',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/ntp/internals'],
      prompt: 'Every client shows "System clock synchronized: no" and timesyncd\'s log is clean. timedatectl timesync-status shows "Leap: not synchronized", "Stratum: 16" from rtr01. What do you check next?',
      options: [
        { text: 'chronyc tracking and chronyc sources on rtr01: its own upstream', correct: true },
        { text: 'The firewall on rtr01', misconception: 'Replies arrive, so the path works.' },
        { text: 'Kerberos on ns1', misconception: 'Kerberos is a consumer of time, not part of the chain.' },
        { text: 'Add "local stratum 10" on rtr01', misconception: 'That hides the alarm and lets clients follow an uncorrected clock; it does not fix anything.' },
      ],
      concepts: ['ntp.sync'],
      explanation: 'Stratum 16 / leap 3 is the server saying it has no good time. The fault is between rtr01 and its sources.',
    },
    {
      id: 'ntp-q-port',
      kind: 'text',
      level: 'beginner',
      learn: ['lesson/ntp/internals'],
      prompt: 'Which transport protocol and port does an NTP server listen on? (format: proto/port)',
      accept: [/^udp\s*\/\s*123$/i, /^123\s*\/\s*udp$/i],
      placeholder: 'udp/123',
      concepts: ['ntp.sync', 'fw.path'],
      explanation: 'NTP uses UDP port 123.',
    },
    {
      id: 'ntp-q-step',
      kind: 'multi',
      level: 'advanced',
      learn: ['lesson/ntp/internals'],
      prompt: 'Which statements about stepping and slewing are true? (choose all that apply)',
      options: [
        { text: 'Slewing corrects the clock by running it slightly faster or slower, so time never jumps', correct: true },
        { text: 'With "makestep 1 3", chronyd steps large errors only during its first three updates', correct: true },
        { text: 'Without makestep, chronyd can take hours to remove a 10-minute error', correct: true },
        { text: 'Stepping is always safe because programs use UTC', misconception: 'A step can make time go backwards; logs, timers and databases notice regardless of the time zone.' },
      ],
      concepts: ['ntp.sync'],
      explanation: 'chronyd slews at most 83 ms per second; makestep permits jumps under controlled conditions (usually at boot).',
    },
    {
      id: 'ntp-q-kerberos',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/ntp/internals', 'lesson/ntp/operate'],
      prompt: 'kinit fails with "Clock skew too great". What is the right fix?',
      options: [
        { text: 'Find out why the client is not synchronized by NTP and fix that', correct: true },
        { text: 'Set the time by hand with date -s', misconception: 'It will drift again; the cause remains.' },
        { text: 'Raise clockskew in krb5.conf to an hour', misconception: 'That weakens replay protection and hides the time problem from everything else.' },
      ],
      concepts: ['ntp.sync', 'ad.kerberos'],
      explanation: 'The 5-minute tolerance is a security feature. Repair the time chain; the client\'s clock is stepped on the first good reply.',
    },
  ],
};
