// Case studies A, B and G. They reproduce interactive tickets, and every
// command output below was produced by the simulator's Debian 12 lab in the
// ticket's broken (or repaired) state. Long outputs are trimmed with "..." only.

import type { CaseStudy } from '../types';

const SIM_SOURCE = (ticket: string) =>
  `All output on this page was produced by the simulator's Debian 12 lab (OpenSSH 9.2, BIND 9.18, nftables 1.0.6, systemd 252) in the state the ticket creates; only long listings are trimmed with "...". Open the **${ticket}** ticket to reproduce every command yourself.`;

export const CASES_LINUX: CaseStudy[] = [
  // ===========================================================================
  {
    id: 'ssh-refused',
    letter: 'A',
    title: 'SSH connection refused',
    level: 'beginner',
    platforms: ['Debian 12 (srv01)', 'OpenSSH 9.2', 'systemd 252'],
    scenarioId: 'ssh-config-typo',
    outputSource: SIM_SOURCE('"ssh-config-typo"'),
    symptoms: `Monday morning, alice (and everyone else) reports:

\`\`\`
alice@ws01:~$ ssh srv01.corp.lab
ssh: connect to host srv01.corp.lab port 22: Connection refused
\`\`\`

On Friday the platform team applied change CHG-1042 ("SSH hardening") to srv01. The intranet web site on the same server still works.`,
    environment: {
      title: 'ws01 → rtr01 → srv01 (SSH)',
      caption: 'The client and the server are on different subnets; rtr01 routes between them. srv01 runs sshd behind a default-deny nftables firewall.',
      rows: [
        { label: 'Client', nodes: [{ id: 'ws01', label: 'ws01', sub: 'alice, 10.0.10.25', kind: 'client' }] },
        { label: 'Network', nodes: [{ id: 'ns1', label: 'ns1', sub: 'DNS 10.0.10.53', kind: 'server' }, { id: 'rtr01', label: 'rtr01', sub: '10.0.10.1 / 10.0.20.1', kind: 'network' }] },
        { label: 'Server', nodes: [{ id: 'fw', label: 'nftables', sub: 'input: tcp/22 allowed', kind: 'network' }, { id: 'sshd', label: 'ssh.service', sub: 'sshd on :22', kind: 'service' }, { id: 'nginx', label: 'nginx', sub: ':80 (works)', kind: 'service' }] },
        { label: 'Config', nodes: [{ id: 'conf', label: 'sshd_config', sub: '+ sshd_config.d/*.conf', kind: 'data' }, { id: 'unit', label: 'ssh.service unit', sub: 'ExecStartPre=sshd -t', kind: 'os' }] },
      ],
      edges: [['ws01', 'ns1', 'resolve'], ['ws01', 'rtr01', 'route'], ['rtr01', 'fw'], ['fw', 'sshd', 'tcp/22'], ['fw', 'nginx', 'tcp/80'], ['sshd', 'conf', 'reads'], ['sshd', 'unit', 'started by']],
    },
    expected: 'alice runs `ssh srv01.corp.lab` and logs in with her ed25519 key. sshd listens on 0.0.0.0:22 and [::]:22, the firewall allows tcp/22, and policy CHG-1042 holds: key-only logins, no root logins.',
    dependencies: [
      'Name resolution of srv01.corp.lab (ns1)',
      'A route from ws01 to 10.0.20.0/24 and back (rtr01)',
      'srv01 firewall allowing tcp/22',
      '**sshd running and listening on port 22**: requires a valid configuration (`ExecStartPre=/usr/sbin/sshd -t`) and readable host keys',
      'Authentication (alice\'s key in `~/.ssh/authorized_keys`) and authorisation (no AllowUsers restriction blocking her)',
    ],
    investigation: [
      {
        title: 'Read the error precisely: refused, not timed out', host: 'ws01', command: 'nc -zv srv01.corp.lab 22',
        output: 'nc: connect to srv01.corp.lab (10.0.20.10) port 22 (tcp) failed: Connection refused',
        interpretation: '"Connection refused" means a TCP **RST** came back: some host received the SYN and answered that nothing accepts connections on that port. That proves name resolution (the name became 10.0.20.10) and routing in both directions work. A firewall that drops would give "timed out" instead. So investigate the **server**, starting with whether anything listens on port 22.',
      },
      {
        title: 'Confirm basic reachability (and that the right host answers)', host: 'ws01', command: 'ping -c 2 srv01.corp.lab',
        output: 'PING srv01.corp.lab (10.0.20.10) 56(84) bytes of data.\n64 bytes from 10.0.20.10: icmp_seq=1 ttl=63 time=1.350 ms\n64 bytes from 10.0.20.10: icmp_seq=2 ttl=63 time=1.350 ms\n\n--- srv01.corp.lab ping statistics ---\n2 packets transmitted, 2 received, 0% packet loss, time 1003ms',
        interpretation: 'The host is up. TTL 63 = 64 minus one router hop, as expected for a Linux server behind rtr01. Network layers 1–3 are fine; we move to the server console.',
      },
      {
        title: 'Is the service running?', host: 'srv01', command: 'systemctl status ssh',
        output: '× ssh.service - OpenBSD Secure Shell server\n     Loaded: loaded (/lib/systemd/system/ssh.service; enabled; preset: enabled)\n     Active: failed (Result: exit-code) since Mon 2026-10-19 08:34:26 UTC; 20min ago\n       Docs: man:sshd(8)\n             man:sshd_config(5)\n    Process: 498 ExecStartPre=/usr/sbin/sshd -t (code=exited, status=255/EXCEPTION)\n\n...\nOct 19 08:34:26 srv01 sshd[424]: /etc/ssh/sshd_config.d/10-hardening.conf line 6: Bad configuration option: PubkeyAuthentcation\nOct 19 08:34:26 srv01 sshd[424]: /etc/ssh/sshd_config.d/10-hardening.conf: terminating, 1 bad configuration options\nOct 19 08:34:26 srv01 systemd[1]: ssh.service: Control process exited, code=exited, status=255/EXCEPTION\nOct 19 08:34:26 srv01 systemd[1]: ssh.service: Failed with result \'exit-code\'.\nOct 19 08:34:26 srv01 systemd[1]: Failed to start ssh.service - OpenBSD Secure Shell server.',
        interpretation: '`Active: failed` and the **Process** line show which step failed: `ExecStartPre=/usr/sbin/sshd -t`, the configuration test the unit runs before starting the daemon, exited with 255. The daemon itself never started. `enabled` means it will be tried at every boot (and will fail every time). The journal lines below already name the file and line.',
      },
      {
        title: 'Confirm nothing listens on 22', host: 'srv01', command: 'ss -tlnp',
        output: 'State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0      511            0.0.0.0:80 0.0.0.0:*         users:(("nginx",pid=414,fd=6))\nLISTEN 0      511               [::]:80 [::]:*            users:(("nginx",pid=414,fd=6))',
        interpretation: 'Only nginx listens. With no socket on port 22, the kernel answers SYNs with RST, which is exactly the client\'s "Connection refused". Evidence chain complete from client to server.',
      },
      {
        title: 'Check the firewall anyway (rule it out with evidence)', host: 'srv01', command: 'nft list ruleset',
        output: 'table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\tct state established,related accept\n\t\tct state invalid drop\n\t\tiif "lo" accept\n\t\tmeta l4proto icmp accept\n\t\tmeta l4proto ipv6-icmp accept\n\t\ttcp dport 22 accept\n\t\ttcp dport { 80, 443 } accept\n\t}\n...',
        interpretation: 'tcp/22 is accepted, so the SYN reaches the (absent) socket. A dropping firewall would also not explain a refusal. Firewall ruled out.',
      },
      {
        title: 'Why did it fail? Logs for this boot', host: 'srv01', command: 'journalctl -u ssh -b -n 20',
        output: '...\nOct 19 08:34:26 srv01 systemd[1]: Stopping ssh.service - OpenBSD Secure Shell server...\nOct 19 08:34:26 srv01 systemd[1]: ssh.service: Deactivated successfully.\nOct 19 08:34:26 srv01 systemd[1]: Stopped ssh.service - OpenBSD Secure Shell server.\nOct 19 08:34:26 srv01 systemd[1]: Starting ssh.service - OpenBSD Secure Shell server...\nOct 19 08:34:26 srv01 sshd[424]: /etc/ssh/sshd_config.d/10-hardening.conf line 6: Bad configuration option: PubkeyAuthentcation\nOct 19 08:34:26 srv01 sshd[424]: /etc/ssh/sshd_config.d/10-hardening.conf: terminating, 1 bad configuration options\nOct 19 08:34:26 srv01 systemd[1]: ssh.service: Control process exited, code=exited, status=255/EXCEPTION\nOct 19 08:34:26 srv01 systemd[1]: ssh.service: Failed with result \'exit-code\'.\nOct 19 08:34:26 srv01 systemd[1]: Failed to start ssh.service - OpenBSD Secure Shell server.',
        interpretation: 'The timeline: sshd was running, someone **restarted** it at 08:34 (stop, then start), and the start failed. A restart applies a new configuration: had they used `systemctl reload ssh`, the reload would have run `sshd -t`, refused, and left the old daemon running. That is the difference between a failed reload (no outage) and a failed restart (outage).',
      },
      {
        title: 'Why didn\'t systemd restart it automatically?', host: 'srv01', command: 'systemctl cat ssh',
        output: '# /lib/systemd/system/ssh.service\n[Unit]\nDescription=OpenBSD Secure Shell server\n...\n[Service]\nEnvironmentFile=-/etc/default/ssh\nExecStartPre=/usr/sbin/sshd -t\nExecStart=/usr/sbin/sshd -D $SSHD_OPTS\nExecReload=/usr/sbin/sshd -t\nExecReload=/bin/kill -HUP $MAINPID\nKillMode=process\nRestart=on-failure\nRestartPreventExitStatus=255\n...',
        interpretation: '`Restart=on-failure` would normally restart a crashed sshd, but `RestartPreventExitStatus=255` excludes exit status 255, which is what sshd returns for a configuration error. Restarting would fail forever, so systemd stops trying: the service stays down until someone fixes the configuration. `KillMode=process` is why existing sessions survive a stop.',
      },
      {
        title: 'Validate the configuration and find the exact line', host: 'srv01', command: 'sshd -t',
        output: '/etc/ssh/sshd_config.d/10-hardening.conf line 6: Bad configuration option: PubkeyAuthentcation\n/etc/ssh/sshd_config.d/10-hardening.conf: terminating, 1 bad configuration options',
        interpretation: 'The error is not in `/etc/ssh/sshd_config` but in a drop-in included by its first line (`Include /etc/ssh/sshd_config.d/*.conf`). Line 6 misspells `PubkeyAuthentication`. sshd treats any unknown keyword as fatal.',
      },
      {
        title: 'Look at the file before editing it', host: 'srv01', command: 'cat /etc/ssh/sshd_config.d/10-hardening.conf',
        output: '# Managed by the platform team - see change ticket CHG-1042\n# Key-based logins only; no direct root logins.\nPermitRootLogin no\nPasswordAuthentication no\nMaxAuthTries 3\nPubkeyAuthentcation yes',
        interpretation: 'The rest of the hardening is correct and must stay (PermitRootLogin no, PasswordAuthentication no). Only the typo needs fixing. Do not "fix" SSH by deleting the drop-in: that would silently revert the security policy.',
      },
    ],
    rootCause: 'Change CHG-1042 added `/etc/ssh/sshd_config.d/10-hardening.conf` with the misspelt keyword **`PubkeyAuthentcation`**. The admin applied it with `systemctl restart ssh` without running `sshd -t` first. The unit\'s `ExecStartPre=/usr/sbin/sshd -t` rejected the configuration (exit 255), so sshd never started; `RestartPreventExitStatus=255` stopped systemd from retrying. With nothing listening on port 22, srv01\'s kernel answers every SYN with RST: **Connection refused**.',
    repair: [
      { title: '1. Back up the file you are about to change', host: 'srv01', commands: 'cp -a /etc/ssh/sshd_config.d/10-hardening.conf /root/10-hardening.conf.bak', why: '`-a` keeps mode, owner and timestamp. A backup outside the `.d` directory matters: a `*.conf.bak` copy inside sshd_config.d would not be included (wrong suffix), but other services include every file in their directory.' },
      { title: '2. Fix only the typo', host: 'srv01', commands: "sed -i 's/PubkeyAuthentcation/PubkeyAuthentication/' /etc/ssh/sshd_config.d/10-hardening.conf", why: 'A targeted change keeps the rest of the approved hardening intact. (`nano` works too; sed makes the change reviewable and repeatable.)' },
      { title: '3. Validate before touching the service', host: 'srv01', commands: 'sshd -t\n# (no output = valid)\nsshd -T | grep -E "^(port|pubkeyauthentication|passwordauthentication|permitrootlogin)"', why: '`sshd -t` is the same test systemd runs; silence means valid. `sshd -T` prints the **effective** values after all includes, proving the policy is what CHG-1042 intended: `port 22`, `permitrootlogin no`, `pubkeyauthentication yes`, `passwordauthentication no`.' },
      { title: '4. Start the daemon (restart, because reload is impossible)', host: 'srv01', commands: 'systemctl reload ssh\n# ssh.service is not active, cannot reload.\nsystemctl restart ssh', why: 'A reload sends SIGHUP to a running daemon; there is none, so systemd refuses. `restart` (or `start`) runs `sshd -t` again and then starts the listener.' },
    ],
    restart: `- **Restart \`ssh.service\`**: required here, because the daemon is not running. On a healthy server, prefer \`systemctl reload ssh\` for configuration changes: it validates first and keeps the old daemon if the new configuration is bad.
- **Nothing else**: the firewall, network and nginx were never involved. Restarting networking or rebooting would not have fixed this. A reboot would just fail the same way at boot, because the unit is enabled and the file is persistent.
- **Existing sessions**: none existed (nobody could log in). On a server where you are logged in over SSH, a restart does not end your session (KillMode=process), but keep it open until a **new** login from a second terminal works.`,
    verify: [
      { host: 'srv01', command: 'systemctl status ssh', output: '● ssh.service - OpenBSD Secure Shell server\n     Loaded: loaded (/lib/systemd/system/ssh.service; enabled; preset: enabled)\n     Active: active (running) since Mon 2026-10-19 08:54:29 UTC; 0s ago\n    Process: 429 ExecStartPre=/usr/sbin/sshd -t (code=exited, status=0/SUCCESS)\n   Main PID: 431 (sshd)\n...\nOct 19 08:54:29 srv01 sshd[431]: Server listening on 0.0.0.0 port 22.\nOct 19 08:54:29 srv01 sshd[431]: Server listening on :: port 22.\nOct 19 08:54:29 srv01 systemd[1]: Started ssh.service - OpenBSD Secure Shell server.', meaning: 'The pre-start test now exits 0/SUCCESS and sshd reports listening on both address families.' },
      { host: 'srv01', command: 'ss -tlnp', output: 'State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0      128            0.0.0.0:22 0.0.0.0:*         users:(("sshd",pid=431,fd=3))\nLISTEN 0      128               [::]:22 [::]:*            users:(("sshd",pid=431,fd=3))\n...', meaning: 'The kernel now has a socket for port 22, so SYNs get SYN-ACKs instead of RSTs.' },
      { host: 'ws01', command: 'nc -zv srv01.corp.lab 22', output: 'Connection to srv01.corp.lab (10.0.20.10) 22 port [tcp/ssh] succeeded!', meaning: 'Verified from the client\'s side of the network, through the router and the firewall.' },
      { host: 'ws01', command: 'ssh srv01.corp.lab hostname', output: 'srv01', meaning: 'A real key-based login and command execution: authentication, authorisation and session all work.' },
      { host: 'srv01', command: 'systemctl is-enabled ssh   # after rebooting every host', output: 'enabled', meaning: 'After a full reboot the login still works (the ticket verifies this): the fix is in the persistent file and the unit starts at boot.' },
    ],
    prevention: [
      'Always run `sshd -t` (and read `sshd -T`) before applying a change; make it part of the change procedure and of configuration management (e.g. Ansible `validate: /usr/sbin/sshd -t -f %s`).',
      'Apply sshd configuration changes with `systemctl reload ssh`, not restart: a failed reload keeps the old daemon running.',
      'Keep an existing session open and test a new login from a second terminal before ending the change; keep out-of-band console access for servers.',
      'Monitor the service from the network (a TCP check on port 22 or an SSH login probe), not just "the host pings".',
      'Peer review drop-in files: a single misspelt keyword in any included file stops the whole daemon.',
    ],
    lessonIds: ['ssh', 'systemd', 'recovery'],
    refIds: ['ssh-v', 'sshd-t', 'systemctl', 'journalctl', 'ss', 'nc', 'file:sshd_config', 'file:sshd_config.d', 'file:lib-systemd-system', 'proc:sshd-safe-restart', 'proc:recover-sshd-console', 'proc:systemd-unit-failed'],
  },
  // ===========================================================================
  {
    id: 'linux-no-internet',
    letter: 'B',
    title: 'Linux server has no Internet',
    level: 'intermediate',
    platforms: ['Debian 12 (srv01, rtr01)', 'nftables NAT', 'glibc resolver'],
    scenarioId: 'case-no-internet',
    outputSource: SIM_SOURCE('"case-no-internet"'),
    symptoms: `Ops reports: "srv01 cannot download security updates since yesterday afternoon: every connection to the mirror hangs. The office still has Internet. I already changed srv01's DNS to 8.8.8.8 in case it was DNS, but that did not help."

\`\`\`
root@srv01:~# curl -m 5 -I http://203.0.113.80/
curl: (28) Failed to connect to 203.0.113.80 port 80 after 5000 ms: Couldn't connect to server
\`\`\``,
    environment: {
      title: 'Server network → rtr01 (NAT) → Internet',
      caption: 'rtr01 is the default gateway of every internal network and hides them behind its public address 203.0.113.2 (masquerade on eth2). ext01 stands in for the update mirror.',
      rows: [
        { label: 'Internal', nodes: [{ id: 'srv01', label: 'srv01', sub: '10.0.20.10 (servers)', kind: 'server' }, { id: 'ws01', label: 'ws01', sub: '10.0.10.25 (office)', kind: 'client' }, { id: 'ns1', label: 'ns1', sub: 'DNS 10.0.10.53', kind: 'server' }] },
        { label: 'Router', nodes: [{ id: 'rtr01', label: 'rtr01', sub: 'routing + ip_forward', kind: 'network' }, { id: 'nat', label: 'nat postrouting', sub: 'masquerade on eth2', kind: 'service' }] },
        { label: 'Internet', nodes: [{ id: 'up', label: 'eth2 203.0.113.2', sub: 'public address', kind: 'network' }, { id: 'ext01', label: 'ext01 mirror', sub: '203.0.113.80:80', kind: 'external' }] },
      ],
      edges: [['srv01', 'rtr01', 'gw 10.0.20.1'], ['ws01', 'rtr01', 'gw 10.0.10.1'], ['srv01', 'ns1', 'DNS'], ['rtr01', 'nat'], ['nat', 'up', 'src → 203.0.113.2'], ['up', 'ext01']],
    },
    expected: 'srv01 reaches the mirror (`curl -I http://203.0.113.80/` → HTTP 200) with its traffic leaving rtr01 as 203.0.113.2, and resolves internal names through ns1. The office keeps its Internet access.',
    dependencies: [
      'srv01: interface up, address 10.0.20.10/24, default route via 10.0.20.1',
      'rtr01: forwarding enabled, filter rules allowing the traffic',
      '**rtr01: source NAT for every internal network on the uplink**: private addresses are not routable on the Internet, so replies can only come back to 203.0.113.2',
      'srv01 resolver (`/etc/resolv.conf`) pointing at a DNS server it can reach and that knows corp.lab (ns1)',
      'The mirror itself (proved healthy by the office)',
    ],
    investigation: [
      {
        title: 'Layer 1–3 on the server: interface and address', host: 'srv01', command: 'ip -br addr',
        output: 'lo               UNKNOWN        127.0.0.1/8 ::1/128 \neth0             UP             10.0.20.10/24 2001:db8:20::10/64 fe80::5054:ff:fec3:a/64 ',
        interpretation: 'Link UP, expected address and prefix. Start at the bottom and stop at the first check that fails: this one passes.',
      },
      {
        title: 'Default gateway', host: 'srv01', command: 'ip route',
        output: 'default via 10.0.20.1 dev eth0 onlink \n10.0.20.0/24 dev eth0 proto kernel scope link src 10.0.20.10 ',
        interpretation: 'A default route exists and points at rtr01\'s server-side address. Off-subnet traffic is sent to the router.',
      },
      {
        title: 'Can we reach the gateway, and a host beyond it, by IP?', host: 'srv01', command: 'ping -c 2 10.0.20.1\nping -c 2 203.0.113.80',
        output: '64 bytes from 10.0.20.1: icmp_seq=1 ttl=64 time=0.950 ms\n64 bytes from 10.0.20.1: icmp_seq=2 ttl=64 time=0.950 ms\n...\n--- 203.0.113.80 ping statistics ---\n2 packets transmitted, 0 received, 100% packet loss, time 1003ms',
        interpretation: 'The gateway answers; the Internet host does not, even **by IP address**. DNS is therefore not the (only) problem: the 8.8.8.8 change was aimed at the wrong layer. The fault is between rtr01 and the Internet, or on the way back.',
      },
      {
        title: 'How far do packets get?', host: 'srv01', command: 'tracepath -n 203.0.113.80',
        output: ' 1?: [LOCALHOST]                      pmtu 1500\n 1:  10.0.20.1                                        0.950ms\n 2:  no reply\n 3:  no reply\n...',
        interpretation: 'Hop 1 (rtr01) answers, nothing after it. Either rtr01 does not forward, or packets leave and replies never come back. Compare with a host that works.',
      },
      {
        title: 'Compare with a working client', host: 'ws01', command: 'curl -I http://203.0.113.80/',
        output: 'HTTP/1.1 200 OK\nServer: nginx/1.22.1\n...',
        interpretation: 'The office reaches the mirror through the same router and uplink. So rtr01 forwards and the Internet side works; the difference is something specific to the **server network**. Check rtr01\'s forwarding and NAT next.',
      },
      {
        title: 'Look at srv01\'s traffic on the uplink', host: 'rtr01', command: 'tcpdump -n -i eth2 -c 4 icmp',
        output: '...\n03:40:17.378796 IP 10.0.20.10 > 203.0.113.80: ICMP echo request, id 1052, seq 1, length 64\n03:40:20.379596 IP 10.0.20.10 > 203.0.113.80: ICMP echo request, id 1052, seq 2, length 64',
        interpretation: 'This is the evidence: srv01\'s packets **leave** the uplink, but with source **10.0.20.10**, a private RFC 1918 address. The mirror cannot route a reply to it (ext01 has no route to 10.0.20.0/24, and a real ISP drops such packets). Office traffic would appear here as 203.0.113.2. Masquerade is not being applied to the server network.',
      },
      {
        title: 'Read the NAT rules', host: 'rtr01', command: 'nft list table ip nat',
        output: 'table ip nat {\n\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n\t\tiifname "eth2" tcp dport 80 dnat to 10.0.20.10:80\n\t}\n\n\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\t\toifname "eth2" ip saddr 10.0.10.0/24 masquerade\n\t}\n}',
        interpretation: 'Root cause found: yesterday\'s "tidy-up" (CHG-2191) restricted masquerade to `ip saddr 10.0.10.0/24`, the office. Traffic from 10.0.20.0/24 (servers) and 10.0.30.0/24 (developers) leaves untranslated.',
      },
      {
        title: 'Confirm with the connection-tracking table', host: 'rtr01', command: 'conntrack -L',
        output: 'tcp  6 117 SYN_SENT src=10.0.20.10 dst=203.0.113.80 sport=43301 dport=80 [UNREPLIED] src=203.0.113.80 dst=10.0.20.10 sport=80 dport=43301 mark=0 use=1\nudp  17 117 src=10.0.20.10 dst=8.8.8.8 sport=33377 dport=53 [UNREPLIED] src=8.8.8.8 dst=10.0.20.10 sport=53 dport=33377 mark=0 use=1\n...',
        interpretation: 'Every srv01 flow to the Internet is `[UNREPLIED]`, and the expected reply tuple is addressed to `dst=10.0.20.10` rather than `dst=203.0.113.2`: no translation happened. The DNS queries to 8.8.8.8 fail for the **same** reason.',
      },
      {
        title: 'Check the "workaround" made during troubleshooting', host: 'srv01', command: 'cat /etc/resolv.conf\ngetent hosts ns1.corp.lab\ndig @10.0.10.53 ns1.corp.lab',
        output: '# changed while troubleshooting the update problem\nnameserver 8.8.8.8\n\n(no output)\n...\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 33387\n;; ANSWER SECTION:\nns1.corp.lab.\t\t3600\tIN\tA\t10.0.10.53',
        interpretation: 'The resolver change is a **second fault**: 8.8.8.8 is unreachable for the same NAT reason, and even if it were reachable it does not know `corp.lab`. Internal names now fail on srv01 too, while ns1 itself answers fine when asked directly. A workaround that does not help must be undone.',
      },
    ],
    rootCause: `Two faults:

1. **Primary**: change CHG-2191 restricted rtr01's masquerade rule to the office subnet (\`oifname "eth2" ip saddr 10.0.10.0/24 masquerade\`). Packets from the server network leave the uplink with their private source 10.0.20.10, and the Internet cannot reply to a private address.
2. **Secondary, introduced while troubleshooting**: srv01's \`/etc/resolv.conf\` was changed to \`nameserver 8.8.8.8\`. That server is unreachable through the broken NAT, and does not know \`corp.lab\` anyway, so internal name resolution on srv01 broke as well.`,
    repair: [
      { title: '1. Back up and fix the NAT rule in the persistent file', host: 'rtr01', commands: 'cp -a /etc/nftables.conf /root/nftables.conf.bak\nsed -i \'s/oifname "eth2" ip saddr 10.0.10.0\\/24 masquerade/oifname "eth2" masquerade/\' /etc/nftables.conf', why: 'Every internal network that needs Internet access must be translated on the uplink. The rule keeps `oifname "eth2"`, so traffic between internal subnets is still routed with real source addresses. Editing the file (not `nft add rule` at runtime) means the fix survives a reboot.' },
      { title: '2. Validate, then apply atomically', host: 'rtr01', commands: 'nft -c -f /etc/nftables.conf\nsystemctl reload nftables\nnft list table ip nat', why: '`nft -c` checks the whole file without applying it. `reload` runs `nft -f`, which replaces the ruleset in one transaction; the file starts with `flush ruleset`, so there is no window without rules. `restart` would first run `ExecStop=nft flush ruleset`, briefly leaving the router without any filtering or NAT.' },
      { title: '3. Undo the resolver workaround', host: 'srv01', commands: "sed -i 's/nameserver 8.8.8.8/search corp.lab\\nnameserver 10.0.10.53/' /etc/resolv.conf\ncat /etc/resolv.conf", why: 'Restore the documented configuration (search domain and ns1). On srv01, /etc/resolv.conf is a static file (no NetworkManager or systemd-resolved manages it), so editing it is correct and takes effect immediately for new lookups: there is no resolver service to restart.' },
    ],
    restart: `- **rtr01**: \`systemctl reload nftables\` (atomic). Do **not** restart nftables or networking on a router: restart flushes every rule for a moment, and restarting networking drops all routed traffic and any SSH session through it.
- **Existing broken flows**: the old \`[UNREPLIED]\` conntrack entries simply time out; new connections get translated. (\`conntrack -D\` could remove them, but nothing requires it.)
- **srv01**: nothing to restart. glibc reads /etc/resolv.conf for each new lookup. No reboot: rebooting srv01 could not have fixed a NAT rule on another machine.`,
    verify: [
      { host: 'rtr01', command: 'nft list table ip nat', output: '...\n\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\t\toifname "eth2" masquerade\n\t}\n}', meaning: 'The loaded ruleset matches the file.' },
      { host: 'srv01', command: 'curl -m 5 -I http://203.0.113.80/', output: 'HTTP/1.1 200 OK\nServer: nginx/1.22.1\n...', meaning: 'The original symptom is gone.' },
      { host: 'rtr01', command: 'tcpdump -n -i eth2 -c 4 tcp', output: '...\n03:40:10.882196 IP 203.0.113.80.80 > 203.0.113.2.46573: Flags [P.], seq 1:851, ack 79, win 509, length 850\n03:40:10.883295 IP 203.0.113.2.46573 > 203.0.113.80.80: Flags [F.], seq 79, ack 851, win 502, length 0\n...', meaning: 'On the uplink srv01\'s connection now appears as 203.0.113.2, and the mirror\'s replies come back to that address.' },
      { host: 'rtr01', command: 'conntrack -L', output: '...\ntcp  6 117 FIN_WAIT src=10.0.20.10 dst=203.0.113.80 sport=46573 dport=80 src=203.0.113.80 dst=203.0.113.2 sport=80 dport=46573 [ASSURED] mark=0 use=1   # NAT: masquerade\n...', meaning: 'The reply tuple now targets 203.0.113.2 and the flow is ASSURED (replies seen).' },
      { host: 'srv01', command: 'getent hosts ns1.corp.lab', output: '10.0.10.53      ns1.corp.lab', meaning: 'Internal resolution works again through ns1.' },
      { host: 'ws01', command: 'curl -I http://203.0.113.80/   # and both checks again after rebooting every host', output: 'HTTP/1.1 200 OK\n...', meaning: 'The office still works, and after a full reboot srv01 still reaches the mirror and resolves names: both fixes are persistent.' },
    ],
    prevention: [
      'Review NAT and firewall changes against the list of networks that need Internet access, and test from **every** subnet after the change, not just the admin\'s own.',
      'Monitor outbound connectivity from each network segment (e.g. a periodic `curl` to an external target from a server and an office host).',
      'Troubleshoot layer by layer and test by IP before blaming DNS; one ping by IP would have shown that DNS was not the problem.',
      'Record every change made during troubleshooting and roll back those that did not help: a failed workaround left in place becomes the next incident.',
    ],
    lessonIds: ['nat', 'netops', 'transport', 'recovery'],
    refIds: ['ip', 'ping-linux', 'tracepath', 'tcpdump', 'conntrack', 'nft', 'dig', 'getent', 'file:nftables.conf', 'file:resolv.conf', 'proc:nft-safe-reload', 'proc:dns-resolver-fix', 'proc:rollback'],
  },
  // ===========================================================================
  {
    id: 'shared-dependency',
    letter: 'G',
    title: 'Multiple services fail simultaneously',
    level: 'advanced',
    platforms: ['Debian 12 (ns1, srv01, ws01, ws02, dev01)', 'BIND 9.18', 'nftables'],
    scenarioId: 'case-dns-outage',
    outputSource: SIM_SOURCE('"case-dns-outage"'),
    symptoms: `Three tickets in ten minutes from three teams:

- Alice (office): \`ssh: Could not resolve hostname srv01.corp.lab: Temporary failure in name resolution\`
- Dana (office laptop, DHCP): "The intranet site is down": \`curl: (6) Could not resolve host: srv01.corp.lab\`
- Erin (developers, VLAN 30): "Our build cannot find www.corp.lab."

The web team says nginx on srv01 is running; the SSH team says sshd is fine. This morning change CHG-2207 "hardened" ns1 with a default-deny firewall.`,
    environment: {
      title: 'Three services, three networks, one shared dependency',
      caption: 'Every client, on every network, resolves names through ns1. Any failure of ns1 (or of the path to it) looks like a failure of whatever service the user happens to be using.',
      rows: [
        { label: 'Clients', nodes: [{ id: 'ws01', label: 'ws01 (SSH)', sub: '10.0.10.25 static', kind: 'client' }, { id: 'ws02', label: 'ws02 (web)', sub: '10.0.10.100 DHCP', kind: 'client' }, { id: 'dev01', label: 'dev01 (builds)', sub: '10.0.30.25 VLAN 30', kind: 'client' }] },
        { label: 'Shared', nodes: [{ id: 'ns1', label: 'ns1 DNS', sub: '10.0.10.53 named', kind: 'server' }, { id: 'fw', label: 'ns1 nftables', sub: 'CHG-2207', kind: 'network' }, { id: 'rtr01', label: 'rtr01', sub: 'routes 3 subnets', kind: 'network' }] },
        { label: 'Services', nodes: [{ id: 'sshd', label: 'srv01 sshd', sub: ':22 healthy', kind: 'service' }, { id: 'nginx', label: 'srv01 nginx', sub: ':80 healthy', kind: 'service' }] },
      ],
      edges: [['ws01', 'fw', 'DNS'], ['ws02', 'fw', 'DNS'], ['dev01', 'rtr01'], ['rtr01', 'fw'], ['fw', 'ns1'], ['ws01', 'sshd', 'by name'], ['ws02', 'nginx', 'by name'], ['dev01', 'nginx', 'www.corp.lab']],
    },
    expected: 'Every network resolves corp.lab names through ns1; SSH to srv01, the intranet web site and the builds work by name. CHG-2207 stays in place: ns1 has a default-drop input policy and answers DNS only for internal networks.',
    dependencies: [
      'Each client: a resolver configuration pointing at ns1 (static file, DHCP option, or VLAN host config)',
      'Network path to ns1 (local subnet for the office, via rtr01 for VLAN 30)',
      '**ns1 firewall allowing DNS (udp/tcp 53) from all internal networks**',
      'named running with the corp.lab zone loaded',
      'The target services themselves (sshd, nginx on srv01)',
    ],
    investigation: [
      {
        title: 'Find what the failures have in common', host: 'ws01', command: 'ssh srv01.corp.lab',
        output: 'ssh: Could not resolve hostname srv01.corp.lab: Temporary failure in name resolution',
        interpretation: 'All three messages are **name-resolution** errors ("Could not resolve"), from three different programs on three different networks. Before investigating SSH, the web server and the build system separately, test the shared hypothesis: name resolution is broken for everyone.',
      },
      {
        title: 'Do the services work by IP address?', host: 'ws02', command: 'curl -I http://10.0.20.10/',
        output: 'HTTP/1.1 200 OK\nServer: nginx/1.22.1\nDate: Mon, 19 Oct 2026 09:00:22 GMT\nContent-Type: text/html\nContent-Length: 615\nConnection: keep-alive',
        interpretation: 'The web server answers when DNS is bypassed. nginx, routing and srv01\'s firewall are fine.',
      },
      {
        title: 'Same for SSH', host: 'ws01', command: 'ssh 10.0.20.10 hostname',
        output: "The authenticity of host '10.0.20.10 (10.0.20.10)' can't be established.\nED25519 key fingerprint is SHA256:YYUWcycRPwFdoA8Iq2JSp28CvBA67hlB45ITKLNx/oE.\nThis key is not known by any other names.\nAre you sure you want to continue connecting (yes/no/[fingerprint])? yes\nWarning: Permanently added '10.0.20.10' (ED25519) to the list of known hosts.\nsrv01",
        interpretation: 'sshd works too. (alice\'s known_hosts only knew the name, so ssh asks about the IP; compare the fingerprint with the one on srv01\'s console before answering "yes".) Both "broken" services are healthy: the shared dependency is DNS.',
      },
      {
        title: 'Is the client configured correctly?', host: 'ws01', command: 'cat /etc/resolv.conf',
        output: '# Generated for corp.lab\nsearch corp.lab\nnameserver 10.0.10.53\noptions timeout:2 attempts:2',
        interpretation: 'Correct server. And three clients configured in three different ways (static file, DHCP, VLAN host) all failing at the same time makes a client-side cause very unlikely. Look at the server.',
      },
      {
        title: 'Is the DNS server answering with an error, or not answering at all?', host: 'ws01', command: 'dig srv01.corp.lab',
        output: '; <<>> DiG 9.18.28-1~deb12u2-Debian <<>> srv01.corp.lab\n;; global options: +cmd\n;; communications error to 10.0.10.53#53: timed out\n;; communications error to 10.0.10.53#53: timed out\n;; communications error to 10.0.10.53#53: timed out\n...\n;; no servers could be reached',
        interpretation: '**No answer at all**, not SERVFAIL or NXDOMAIN. A zone error would produce `status: SERVFAIL` (the server answers, it just cannot help). A timeout means the query or the reply is lost: named down, or something dropping packets. Yet `ping -c 2 10.0.10.53` from ws01 succeeds, so the host is up and reachable.',
      },
      {
        title: 'Is named running and listening?', host: 'ns1', command: 'systemctl status named\nss -ulnp',
        output: '● named.service - BIND Domain Name Server\n     Loaded: loaded (/lib/systemd/system/named.service; enabled; preset: enabled)\n     Active: active (running) since Mon 2026-10-19 07:58:04 UTC; 1h 2min ago\n...\nOct 19 07:58:04 ns1 named[407]: zone corp.lab/IN: loaded serial 2026101901\n...\nState  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nUNCONN 0      0              0.0.0.0:53 0.0.0.0:*         users:(("named",pid=407,fd=6))\nUNCONN 0      0              0.0.0.0:67 0.0.0.0:*         users:(("dhcpd",pid=414,fd=6))',
        interpretation: 'named has been running since boot, the zone loaded, and it listens on udp/53 on all addresses. "Is the service running" is answered: yes. Monitoring that only checks the process would show everything green.',
      },
      {
        title: 'Does named answer locally?', host: 'ns1', command: 'dig @127.0.0.1 srv01.corp.lab',
        output: ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32798\n;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0\n...\n;; ANSWER SECTION:\nsrv01.corp.lab.\t\t3600\tIN\tA\t10.0.20.10\n...\n;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)',
        interpretation: 'named answers correctly over loopback (which the firewall always allows: `iif "lo" accept`). The DNS service is healthy; queries from the network never reach it. Next: the firewall changed this morning.',
      },
      {
        title: 'Do the queries arrive?', host: 'ns1', command: 'tcpdump -n -i eth0 -c 4 port 53',
        output: '...\n09:00:16.929396 IP 10.0.30.25.41296 > 10.0.10.53.53: 24336+ A? www.corp.lab. (30)\n09:00:25.536695 IP 10.0.10.25.60243 > 10.0.10.53.53: 36109+ A? srv01.corp.lab. (32)\n09:00:30.537095 IP 10.0.10.25.40162 > 10.0.10.53.53: 1726+ A? srv01.corp.lab. (32)\n09:00:35.537495 IP 10.0.10.25.48081 > 10.0.10.53.53: 32879+ A? srv01.corp.lab. (32)',
        interpretation: 'Queries from the office (10.0.10.25) and from VLAN 30 (10.0.30.25) arrive on ns1\'s interface, and no reply is ever sent. tcpdump sees packets before the input filter: something on ns1 discards them between the NIC and named.',
      },
      {
        title: 'Read the new firewall', host: 'ns1', command: 'nft list ruleset',
        output: 'table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\tct state established,related accept\n\t\tct state invalid drop\n\t\tiif "lo" accept\n\t\tmeta l4proto icmp accept\n\t\tmeta l4proto ipv6-icmp accept\n\t\ttcp dport 22 accept\n\t\tudp dport 67 accept\n\t\tip saddr 10.0.0.0/24 udp dport 53 accept\n\t\tip saddr 10.0.0.0/24 tcp dport 53 accept\n\t}\n...',
        interpretation: 'The DNS rules accept `ip saddr 10.0.0.0/24`, which is only **10.0.0.0–10.0.0.255**. The internal networks are 10.0.10.0/24, 10.0.20.0/24 and 10.0.30.0/24; none of them match, so every query falls through to `policy drop`. ICMP (ping), SSH and DHCP (udp/67) are allowed, which is why ns1 looked healthy and ws02 still got its address. The intended prefix covering all internal networks is **10.0.0.0/16**.',
      },
    ],
    rootCause: 'Change CHG-2207 limited DNS on ns1 to `ip saddr 10.0.0.0/24` instead of `10.0.0.0/16`. Combined with the new default-drop input policy, every DNS query from every client network is silently dropped. ns1 is the shared dependency of SSH, the intranet web site and the developer builds, so one firewall mistake looked like three unrelated outages. All three services, and named itself, were healthy throughout.',
    repair: [
      { title: '1. Back up, then correct the prefix in the persistent file', host: 'ns1', commands: 'cp -a /etc/nftables.conf /root/nftables.conf.bak\nsed -i \'s#ip saddr 10.0.0.0/24#ip saddr 10.0.0.0/16#\' /etc/nftables.conf', why: 'Fix the mistake, not the change: the hardening (default drop, DNS only for internal sources) was approved and stays. Do not "fix" it by deleting the rules, adding a blanket `udp dport 53 accept`, or stopping nftables.' },
      { title: '2. Validate and reload atomically', host: 'ns1', commands: 'nft -c -f /etc/nftables.conf\nsystemctl reload nftables\nnft list chain inet filter input', why: '`nft -c` checks syntax without applying. `reload` swaps the ruleset in one transaction. `restart` would run `nft flush ruleset` first, leaving ns1 briefly with no firewall at all, and a broken file would then leave it open.' },
    ],
    restart: `- **ns1 firewall**: \`systemctl reload nftables\` only.
- **named: do not restart it.** It was healthy; restarting it would only add a short real outage and clear its cache. The same goes for sshd and nginx on srv01: restarting them, as each team was tempted to do, would not have changed anything.
- **Clients**: nothing to restart. glibc does not cache negative answers, so the next lookup works. (Hosts running nscd or systemd-resolved may need \`resolvectl flush-caches\`.)`,
    verify: [
      { host: 'ns1', command: 'nft list chain inet filter input', output: 'table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\t...\n\t\tudp dport 67 accept\n\t\tip saddr 10.0.0.0/16 udp dport 53 accept\n\t\tip saddr 10.0.0.0/16 tcp dport 53 accept\n\t}\n}', meaning: 'Default drop retained; DNS allowed for the whole internal /16 and nothing else.' },
      { host: 'ws01', command: 'dig +short srv01.corp.lab', output: '10.0.20.10', meaning: 'The office gets answers from ns1 again.' },
      { host: 'ws01', command: 'ssh srv01.corp.lab hostname', output: 'srv01', meaning: 'Ticket 1 (SSH) resolved by name.' },
      { host: 'ws02', command: 'curl -I http://srv01.corp.lab/', output: 'HTTP/1.1 200 OK\nServer: nginx/1.22.1\n...', meaning: 'Ticket 2 (intranet) resolved.' },
      { host: 'dev01', command: 'getent hosts www.corp.lab   # also after rebooting every host', output: '2001:db8:20::10 www.corp.lab', meaning: 'Ticket 3 (VLAN 30) resolved: dev01 is dual-stack and prefers srv01\'s IPv6 address. It still resolves after a full reboot, so the fix is persistent.' },
    ],
    prevention: [
      'When several services fail at once, look for the **shared dependency** (DNS, routing, authentication, time, storage) before investigating each service.',
      'Test firewall changes from every client network before closing the change; check prefixes with a calculator and peer review (10.0.0.0/24 vs /16).',
      'Monitor name resolution **from each network**, not only "is named running": the process was healthy for the whole outage.',
      'Keep ns1 reachable for administration (SSH and console were allowed): it made the investigation and the fix possible without a site visit.',
    ],
    lessonIds: ['transport', 'nftables', 'netops', 'recovery'],
    refIds: ['dig', 'getent', 'tcpdump', 'nft', 'ss', 'systemctl', 'file:nftables.conf', 'file:resolv.conf', 'file:named.conf', 'proc:nft-safe-reload', 'proc:incident-record'],
  },
];
