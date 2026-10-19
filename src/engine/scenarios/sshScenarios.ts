// SSH troubleshooting scenarios. Faults are injected with the same shell
// commands an administrator would have typed, so service state, journals,
// firewall counters and files all tell one consistent story.

import { mkdir, readFile, writeFile } from '../fs';
import { addUser } from '../lab/builder';
import { HARDENING_CONF, SRV01_NFT, CORP_ZONE, installHostKeys } from '../lab/sshLab';
import { makeKeyPair } from '../sim/keys';
import type { World } from '../types';
import { firewallStillRestrictive, modernKex, script, sessionStillWorks, sshdPolicy, zoneSerialBumped } from './engine';
import type { Goal, Scenario } from './types';

const ALICE_GOAL: Goal = {
  description: 'alice on ws01 can run "ssh srv01.corp.lab" and log in with her ed25519 key on port 22.',
  localUser: 'alice', user: 'alice', target: 'srv01.corp.lab', method: 'publickey',
};

const BOB_WS01_KEY = makeKeyPair('ed25519', 'bob-ws01-ed25519', 'bob@ws01');

const BRIEFING = [
  'Client: ws01 (10.0.10.25/24, gateway 10.0.10.1), user alice. Server: srv01.corp.lab (10.0.20.10/24, gateway 10.0.20.1).',
  'DNS: ns1 (10.0.10.53) is authoritative for corp.lab. Router rtr01 forwards between 10.0.10.0/24 and 10.0.20.0/24.',
  'You have a terminal on ws01 as alice, and out-of-band console access (root) to srv01, ns1 and rtr01.',
  'Security policy CHG-1042 on srv01: key-based logins only, no root login, default-deny firewall.',
];

const GENERIC_CANDIDATES = [
  'dns-wrong-record', 'routing-server-gateway', 'firewall-drop', 'firewall-reject', 'sshd-not-running',
  'sshd-config-error', 'sshd-wrong-port', 'host-key-changed', 'invalid-credentials', 'authorized-keys-missing',
  'server-file-permissions', 'user-not-allowed', 'server-down',
];

function writeAs(world: World, hostId: string, path: string, content: string, gapMs = 30_000) {
  world.clock += gapMs;
  writeFile(world.hosts[hostId], path, content, world.clock);
}

export const SSH_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'ssh-config-typo',
    title: 'Refused after a "quick change"',
    difficulty: 'beginner',
    ticket: 'alice: "Since about 20 minutes ago `ssh srv01.corp.lab` says Connection refused. Yesterday it was fine. Bob mentioned he tweaked something on srv01 this morning."',
    briefing: BRIEFING,
    goals: [ALICE_GOAL],
    setup(world) {
      writeAs(world, 'srv01', '/etc/ssh/sshd_config.d/10-hardening.conf', HARDENING_CONF + 'MaxAuthTries 3\nPubkeyAuthentcation yes\n');
      script(world, 'srv01', ['systemctl restart ssh']);
      world.clock += 20 * 60_000;
    },
    rootCauses: ['sshd-config-error'],
    acceptable: { 'sshd-not-running': 'Correct: sshd is not running. That is the immediate cause of "Connection refused". The underlying cause is why it could not start.' },
    candidates: [...GENERIC_CANDIDATES],
    feedback: {
      'firewall-drop': 'A DROP rule produces silence and a timeout. Here the client failed instantly with "Connection refused", which means an RST came back: the packet reached a host that answered.',
      'firewall-reject': 'Possible in principle ("reject with tcp reset" also gives "Connection refused"), but the server firewall (nft list ruleset) still accepts tcp dport 22. And ss -tlnp shows nothing listening on :22.',
    },
    hints: [
      'Classify the error first. "Connection refused" means a TCP RST came back. Which host sends an RST, and when?',
      'On the srv01 console, check whether anything is listening on port 22 (ss -tlnp) and what systemd thinks of ssh.service.',
      'systemctl status ssh shows status=255 from ExecStartPre (sshd -t). Run "sshd -t" or read "journalctl -u ssh" to see which file and line is wrong.',
    ],
    explanation: {
      rootCause: 'A typo ("PubkeyAuthentcation") was added to /etc/ssh/sshd_config.d/10-hardening.conf and sshd was restarted. On Debian, ssh.service runs "sshd -t" (ExecStartPre) before starting; the test failed, so the restart stopped the old daemon and the new one never started.',
      manifestation: 'With no process listening on 0.0.0.0:22, the server kernel answers every SYN with RST/ACK. The client reports "Connection refused" immediately. Ping still works and the firewall is irrelevant.',
      evidence: 'ss -tlnp shows no :22 listener; systemctl status ssh is "failed (Result: exit-code)"; journalctl -u ssh shows "/etc/ssh/sshd_config.d/10-hardening.conf line 6: Bad configuration option: PubkeyAuthentcation".',
      prevention: 'Always run "sshd -t" before restarting, and prefer "systemctl reload ssh": reload also runs sshd -t, but a failed reload leaves the running daemon (and your session) alive. Keep an existing session open while changing sshd, and manage config with version control and review.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i '/PubkeyAuthentcation/d' /etc/ssh/sshd_config.d/10-hardening.conf", 'sshd -t', 'systemctl restart ssh', 'systemctl status ssh'] }],
    constraints: [sshdPolicy(), firewallStillRestrictive()],
    concepts: ['svc.systemd', 'ssh.config', 'tcp.handshake', 'logs.journal'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'ssh-port-moved',
    title: 'Security through obscurity',
    difficulty: 'beginner',
    ticket: 'Monitoring alert: "SSH check on srv01.corp.lab:22 CRITICAL - Connection refused". A colleague wrote in chat: "I moved SSH off port 22 to reduce the bot noise, should be transparent".',
    briefing: [...BRIEFING, 'Company standard: SSH listens on port 22 on all servers (monitoring, bastions and automation depend on it).'],
    goals: [ALICE_GOAL],
    setup(world) {
      writeAs(world, 'srv01', '/etc/ssh/sshd_config.d/10-hardening.conf', HARDENING_CONF + '# reduce log noise from scanners\nPort 2222\n');
      script(world, 'srv01', ['systemctl restart ssh']);
      world.clock += 10 * 60_000;
    },
    rootCauses: ['sshd-wrong-port'],
    candidates: [...GENERIC_CANDIDATES, 'sshd-listen-address'],
    feedback: {
      'sshd-not-running': 'systemctl shows ssh.service active (running). sshd is up; the question is WHERE it listens.',
      'firewall-drop': 'Port 22 answers instantly with RST ("refused"), not a timeout. But try port 2222: that one IS dropped by the firewall, which only allows 22. Two separate effects.',
    },
    hints: [
      'Refused means the server answered with RST. Is sshd running? If so, which sockets does it own?',
      'Compare "ss -tlnp" with what the client is trying. Then look at the effective configuration: sshd -T | grep ^port.',
      'A drop-in file in /etc/ssh/sshd_config.d/ sets "Port 2222". Notice also that "ssh -p 2222" would time out: the firewall only allows 22. Fix the config (policy says 22) and restart/reload sshd.',
    ],
    explanation: {
      rootCause: '"Port 2222" in /etc/ssh/sshd_config.d/10-hardening.conf replaced the default port 22. Because Port is set in a drop-in included at the top of sshd_config, it applies even though sshd_config itself still shows "#Port 22".',
      manifestation: 'Nothing listens on :22, so connections to 22 are refused. Connections to 2222 would reach sshd\'s socket only if the firewall allowed them; srv01\'s nftables only accepts tcp dport 22, so 2222 times out.',
      evidence: 'ss -tlnp shows sshd on 0.0.0.0:2222 and [::]:2222; sshd -T reports "port 2222"; the journal shows "Server listening on 0.0.0.0 port 2222."',
      prevention: 'Changing ports does not add meaningful security (scanners find it) but breaks every client, firewall rule, monitoring check and SELinux port label. Use key-only auth, rate limiting and allow-listing instead. Change management should cover dependent systems.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i '/^Port 2222/d' /etc/ssh/sshd_config.d/10-hardening.conf", 'sshd -t', 'systemctl restart ssh', 'ss -tlnp'] }],
    constraints: [sshdPolicy(), firewallStillRestrictive()],
    concepts: ['svc.listening', 'ssh.config', 'fw.stateful'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'ssh-firewall-drop',
    title: 'Ping works, SSH hangs',
    difficulty: 'beginner',
    ticket: 'alice: "ssh to srv01 just hangs and eventually times out. The server is definitely up, I can ping it. Did someone change the network?"',
    briefing: [...BRIEFING, 'Change record CHG-1107 (yesterday): "restrict SSH on srv01 to the bastion subnet 10.0.99.0/24". The admin LAN 10.0.10.0/24 must keep SSH access.'],
    goals: [ALICE_GOAL],
    setup(world) {
      const conf = SRV01_NFT.replace('\t\ttcp dport 22 accept\n', '\t\tip saddr 10.0.99.0/24 tcp dport 22 accept comment "CHG-1107 bastion only"\n')
        .replace('\t\ttcp dport { 80, 443 } accept\n', '\t\ttcp dport { 80, 443 } accept\n\t\tlog prefix "nft-input-drop: " counter\n');
      writeAs(world, 'srv01', '/etc/nftables.conf', conf);
      script(world, 'srv01', ['systemctl restart nftables']);
      world.clock += 15 * 60_000;
    },
    rootCauses: ['firewall-drop'],
    candidates: [...GENERIC_CANDIDATES, 'firewall-not-persistent'],
    feedback: {
      'server-down': 'ping gets replies from 10.0.20.10, so the host is up and the path works for ICMP.',
      'routing-server-gateway': 'If srv01 could not route back, ping replies would not come back either. They do.',
      'sshd-not-running': 'If sshd were down you would get an instant "Connection refused" (RST), not a timeout.',
    },
    hints: [
      'A timeout means nothing came back at all, not even an RST or ICMP error. Ping works, so which layer differs between ping and SSH?',
      'Look at srv01\'s firewall: nft list ruleset. What is the input policy, and which rule would match a SYN from 10.0.10.25 to port 22? The kernel log may also have something (journalctl -k).',
      'The port-22 rule now only accepts source 10.0.99.0/24. Add an accept rule for 10.0.10.0/24 to /etc/nftables.conf (so it survives reboot) and reload it (nft -f /etc/nftables.conf or systemctl restart nftables).',
    ],
    explanation: {
      rootCause: 'CHG-1107 replaced "tcp dport 22 accept" with a rule that only accepts SSH from 10.0.99.0/24, dropping the admin LAN by accident. SYNs from 10.0.10.25 fall through to the input chain\'s "policy drop".',
      manifestation: 'The SYN is silently discarded. The client retransmits it with exponential backoff (1, 2, 4, 8, ... s) and finally reports "Connection timed out". ICMP is still accepted, so ping works and makes the server look healthy.',
      evidence: 'nft list ruleset shows the restricted rule; the "log prefix nft-input-drop" counter increases with every attempt and journalctl -k shows "nft-input-drop: IN=eth0 ... SRC=10.0.10.25 DST=10.0.20.10 ... DPT=22 ... SYN"; the sshd journal shows nothing for these attempts because sshd never saw them.',
      prevention: 'Express intent with explicit source sets (e.g. a named set of admin subnets), test from every client network after firewall changes, and log/count before the default-drop so drops are visible.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i 's|ip saddr 10.0.99.0/24 tcp dport 22 accept|ip saddr { 10.0.10.0/24, 10.0.99.0/24 } tcp dport 22 accept|' /etc/nftables.conf", 'nft -c -f /etc/nftables.conf', 'nft -f /etc/nftables.conf', 'nft list chain inet filter input'], note: 'Editing /etc/nftables.conf and reloading it makes the fix persistent; "nft add rule" alone would be lost at the next reboot.' }],
    constraints: [firewallStillRestrictive(), sshdPolicy()],
    concepts: ['fw.stateful', 'tcp.handshake', 'net.icmp', 'fw.persistence'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'ssh-firewall-reject',
    title: '"No route to host" but the route is fine',
    difficulty: 'intermediate',
    ticket: 'alice: "ssh srv01.corp.lab → No route to host. The network team says routing is fine. Who is right?"',
    briefing: BRIEFING,
    goals: [ALICE_GOAL],
    setup(world) {
      const conf = SRV01_NFT.replace('\t\ttcp dport 22 accept\n', '\t\tip saddr 10.0.10.0/24 tcp dport 22 reject with icmpx type admin-prohibited comment "INC-2231 temporary block"\n\t\ttcp dport 22 accept\n');
      writeAs(world, 'srv01', '/etc/nftables.conf', conf);
      script(world, 'srv01', ['systemctl restart nftables']);
      world.clock += 2 * 3600_000;
    },
    rootCauses: ['firewall-reject'],
    candidates: [...GENERIC_CANDIDATES, 'routing-client'],
    feedback: {
      'routing-client': 'ws01 has a default route via 10.0.10.1 and can ping 10.0.20.10. "ip route get 10.0.20.10" works. The words "No route to host" come from an ICMP message, not from the routing table.',
      'routing-server-gateway': 'srv01 answers pings, so it can route back. And a missing return route would cause a timeout, not an immediate error.',
      'server-down': 'Ping works. A down host behind a router produces "No route to host" after ~3 s of ARP failure, and ping would fail too.',
      'firewall-drop': 'A drop is silent and gives a timeout. Here the error is immediate, so something replied.',
    },
    hints: [
      '"No route to host" is the text for EHOSTUNREACH. Which events make a Linux TCP connect() fail with EHOSTUNREACH? (Hint: not only missing routes.)',
      'Capture on ws01 while connecting (run ssh, then sudo tcpdump -i eth0 -n icmp). What exactly comes back, and from which address?',
      'srv01 itself replies with "ICMP host unreachable - admin prohibited filter". Find the reject rule in nft -a list ruleset and remove it from /etc/nftables.conf (then reload) so it does not return after a reboot.',
    ],
    explanation: {
      rootCause: 'A temporary rule "ip saddr 10.0.10.0/24 tcp dport 22 reject with icmpx type admin-prohibited" (INC-2231) was left in srv01\'s /etc/nftables.conf, before the accept rule.',
      manifestation: 'srv01 answers each SYN with ICMP type 3 code 13 (communication administratively prohibited). Linux maps this ICMP error during SYN_SENT to EHOSTUNREACH, which ssh prints as "No route to host". The error is immediate, routing is fine, and ping works because ICMP echo is accepted.',
      evidence: 'tcpdump on ws01: "IP 10.0.20.10 > 10.0.10.25: ICMP host 10.0.20.10 unreachable - admin prohibited filter". The ICMP source is the server itself, not a router. nft -a list ruleset shows the reject rule with its comment.',
      prevention: 'Temporary rules need an owner and an expiry (track them in the ticket and remove them). Know the error mapping: RST → "Connection refused"; ICMP port-unreachable → "Connection refused"; ICMP host-unreachable/admin-prohibited → "No route to host"; silence → "Connection timed out".',
    },
    solution: [{ host: 'srv01', commands: ["sed -i '/INC-2231/d' /etc/nftables.conf", 'nft -f /etc/nftables.conf', 'nft -a list chain inet filter input'] }],
    constraints: [firewallStillRestrictive(), sshdPolicy()],
    concepts: ['net.icmp', 'fw.stateful', 'tcp.handshake'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'ssh-dns-stale',
    title: 'The server moved... or did it?',
    difficulty: 'intermediate',
    ticket: 'alice: "ssh srv01.corp.lab fails with No route to host after a few seconds. Funny thing: Bob says `ssh 10.0.20.10` works for him."',
    briefing: [...BRIEFING, 'Yesterday a new VM (srv02, planned address 10.0.20.11) was prepared but not deployed yet.'],
    goals: [ALICE_GOAL],
    setup(world) {
      const zone = CORP_ZONE.replace('2026101901', '2026101902').replace('srv01   IN A    10.0.20.10', 'srv01   IN A    10.0.20.11');
      writeAs(world, 'ns1', '/etc/bind/db.corp.lab', zone);
      script(world, 'ns1', ['rndc reload']);
      world.clock += 3 * 3600_000;
    },
    rootCauses: ['dns-wrong-record'],
    candidates: [...GENERIC_CANDIDATES, 'hosts-file-override', 'dns-client-config'],
    feedback: {
      'server-down': 'srv01 answers at 10.0.20.10 (ping 10.0.20.10 works; the console shows it up). Nothing answers at the address the NAME points to.',
      'routing-client': 'ws01 can reach 10.0.20.10 by IP, so its routes are fine.',
      'hosts-file-override': 'Check: dig (DNS only) and getent hosts (files + DNS) return the same wrong address, so /etc/hosts is not involved.',
      'dns-client-config': 'ws01 queries ns1 correctly and gets an authoritative answer. The answer itself is wrong.',
    },
    hints: [
      'If connecting by IP works but by name does not, which step differs? Write down what address the client actually connects to (ssh -v prints it).',
      'Compare "dig srv01.corp.lab" on ws01 with "ip -4 addr" on the srv01 console. Then look at who answered: ns1.',
      'The A record in /etc/bind/db.corp.lab on ns1 points to 10.0.20.11. Fix it, increment the SOA serial, validate with named-checkzone and run rndc reload.',
    ],
    explanation: {
      rootCause: 'While preparing srv02, the srv01 A record in the corp.lab zone was changed to 10.0.20.11 (an address nobody uses yet) and the zone was reloaded.',
      manifestation: 'ssh resolves srv01.corp.lab to 10.0.20.11. rtr01 tries to ARP for 10.0.20.11 on the server network, gets no answer for ~3 s and returns ICMP host unreachable, which the client reports as "No route to host". Using the IP address bypasses DNS, so it works.',
      evidence: 'ssh -v: "Connecting to srv01.corp.lab [10.0.20.11]"; dig shows "srv01.corp.lab. 3600 IN A 10.0.20.11" with the aa flag from 10.0.10.53; "ip neigh" on rtr01 shows "10.0.20.11 dev eth1 FAILED"; tcpdump on ws01 shows "ICMP host 10.0.20.11 unreachable" from 10.0.10.1.',
      prevention: 'Review zone changes, increment serials, validate with named-checkzone, and monitor that critical names resolve to expected addresses. Confirm the address a client actually uses before debugging the server.',
    },
    solution: [{ host: 'ns1', commands: ["sed -i 's/10.0.20.11/10.0.20.10/' /etc/bind/db.corp.lab", "sed -i 's/2026101902/2026101903/' /etc/bind/db.corp.lab", 'named-checkzone corp.lab /etc/bind/db.corp.lab', 'rndc reload'] }, { host: 'ws01', user: 'alice', commands: ['dig +short srv01.corp.lab', 'ssh srv01.corp.lab hostname'] }],
    constraints: [zoneSerialBumped(2026101902), firewallStillRestrictive()],
    concepts: ['dns.resolution', 'dns.zone', 'net.arp', 'net.icmp'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'ssh-missing-gateway',
    title: 'Half a conversation',
    difficulty: 'intermediate',
    ticket: 'alice: "ssh srv01 times out. Ping times out too. But the hypervisor console shows srv01 running and the web team says nginx is fine for the app servers on the same subnet."',
    briefing: [...BRIEFING, 'Last night an admin cleaned up /etc/network/interfaces on srv01 and restarted networking.'],
    goals: [ALICE_GOAL],
    setup(world) {
      const h = world.hosts.srv01;
      writeAs(world, 'srv01', '/etc/network/interfaces', (readFile(h, '/etc/network/interfaces') ?? '').replace('    gateway 10.0.20.1\n', ''));
      script(world, 'srv01', ['systemctl restart networking']);
      world.clock += 9 * 3600_000;
    },
    rootCauses: ['routing-server-gateway'],
    candidates: [...GENERIC_CANDIDATES, 'routing-client'],
    feedback: {
      'firewall-drop': 'Plausible from the client side (timeout). But tcpdump on srv01 shows the SYNs arriving AND the nft counters/conntrack show them accepted. The replies never leave. Check srv01\'s routing table.',
      'server-down': 'The console shows srv01 up, it answers ARP (rtr01 has a REACHABLE neighbour entry) and tcpdump on srv01 sees the incoming SYNs.',
      'routing-client': 'ws01\'s route to 10.0.20.0/24 via 10.0.10.1 works: packets arrive at srv01 (see tcpdump there).',
      'sshd-not-running': 'sshd is listening (ss -tlnp). If it were down, you would see an instant "refused", if the RST could get back.',
    },
    hints: [
      'A timeout means no reply reached the client. That can happen on the way there OR on the way back. Find out how far the SYN gets.',
      'On srv01, run the connection attempt from ws01 again, then "tcpdump -i eth0 -n port 22". Do SYNs arrive? Does a SYN-ACK leave? Then look at "ip route" on srv01.',
      'srv01 has no default route, so it cannot send replies to 10.0.10.0/24. Restore "gateway 10.0.20.1" in /etc/network/interfaces and apply it (ip route add default via 10.0.20.1, or systemctl restart networking).',
    ],
    explanation: {
      rootCause: 'The "gateway 10.0.20.1" line was removed from srv01\'s /etc/network/interfaces and networking was restarted, so srv01 lost its default route. It only knows its directly connected network 10.0.20.0/24.',
      manifestation: 'SYNs from 10.0.10.25 arrive and are accepted by the firewall; the kernel wants to answer with SYN-ACK but has no route to 10.0.10.25 (ENETUNREACH internally), so nothing is sent. The client retransmits SYNs until it times out. Hosts on 10.0.20.0/24 are unaffected because they are on-link, which is why "nginx is fine" for them.',
      evidence: 'tcpdump on srv01 shows only incoming [S] packets; "ip route" on srv01 shows only "10.0.20.0/24 dev eth0 proto kernel"; "ip route get 10.0.10.25" on srv01 says "Network is unreachable"; sshd logs nothing.',
      prevention: 'Validate network config changes from another subnet, keep configs in version control, and monitor reachability from multiple networks. When debugging timeouts, capture on BOTH ends: asymmetric failures are invisible from one side.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i 's|    address 10.0.20.10/24|    address 10.0.20.10/24\\n    gateway 10.0.20.1|' /etc/network/interfaces", 'ip route add default via 10.0.20.1', 'ip route'], note: 'Both steps matter: "ip route add" fixes it now, the interfaces file keeps it after reboot. "systemctl restart networking" would also apply the file.' }],
    constraints: [firewallStillRestrictive(), sshdPolicy()],
    concepts: ['net.routing', 'tcp.handshake', 'fw.persistence'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'ssh-perms-strictmodes',
    title: 'Keys stopped working',
    difficulty: 'intermediate',
    ticket: 'alice: "ssh srv01 → Permission denied (publickey). My key has not changed and it worked this morning. The backup team was installing their agent on srv01 today."',
    briefing: BRIEFING,
    goals: [ALICE_GOAL],
    setup(world) {
      script(world, 'srv01', ['chmod 777 /home/alice/.ssh']);
      world.clock += 2 * 3600_000;
    },
    rootCauses: ['server-file-permissions'],
    candidates: [...GENERIC_CANDIDATES, 'client-key-permissions', 'auth-method-disabled'],
    feedback: {
      'authorized-keys-missing': 'Compare fingerprints: alice\'s ws01 key IS in /home/alice/.ssh/authorized_keys on srv01. sshd refuses to READ the file; check the journal.',
      'auth-method-disabled': '"(publickey)" shows password auth is disabled, but that is the intended policy and it was already true when things worked.',
      'invalid-credentials': 'No password is involved; the server offers only publickey. The question is why a correct key is rejected.',
      'client-key-permissions': 'The client did not print an UNPROTECTED PRIVATE KEY warning and ls -l ~/.ssh/id_ed25519 on ws01 shows 600.',
    },
    hints: [
      'TCP, key exchange and host key verification all succeed; the failure is in user authentication. What does the server log say about this attempt?',
      'journalctl -u ssh on srv01 contains a line starting with "Authentication refused". What does it say about which path?',
      'StrictModes rejects authorized_keys if ~/.ssh is group/world-writable. chmod 700 /home/alice/.ssh (and keep authorized_keys 600 and owned by alice).',
    ],
    explanation: {
      rootCause: 'The backup agent installation ran "chmod 777 /home/alice/.ssh". With StrictModes yes (default), sshd refuses to use authorized_keys files when the file or any parent directory up to $HOME is writable by group/others or owned by another user.',
      manifestation: 'The client offers its key, the server does not accept it (no PK_OK), there is no other allowed method, so the client ends with "Permission denied (publickey)". Nothing on the client side changed.',
      evidence: 'srv01 journal: "Authentication refused: bad ownership or modes for directory /home/alice/.ssh"; ls -ld /home/alice/.ssh shows drwxrwxrwx; ssh -v shows "Offering public key" with no "Server accepts key".',
      prevention: 'Never "fix" access problems with 777. Agents should use their own accounts and groups. StrictModes exists because a writable ~/.ssh lets any local user plant a key and log in as alice: do not disable it.',
    },
    solution: [{ host: 'srv01', commands: ['chmod 700 /home/alice/.ssh', 'ls -ld /home/alice /home/alice/.ssh', 'ls -l /home/alice/.ssh/authorized_keys'] }],
    constraints: [sshdPolicy(), firewallStillRestrictive()],
    concepts: ['linux.permissions', 'ssh.authorized-keys', 'ssh.userauth', 'logs.journal'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'ssh-hostkey-changed',
    title: 'The rebuilt server',
    difficulty: 'beginner',
    ticket: 'alice: "ssh srv01 prints a huge WARNING about REMOTE HOST IDENTIFICATION HAS CHANGED and refuses to connect. Are we being hacked?" Note from the infra team: "srv01\'s OS disk was restored from the golden image last night; host keys were regenerated."',
    briefing: BRIEFING,
    goals: [ALICE_GOAL],
    setup(world) {
      world.clock += 60_000;
      installHostKeys(world.hosts.srv01, world.clock, 2);
      script(world, 'srv01', ['systemctl restart ssh']);
      world.clock += 8 * 3600_000;
    },
    rootCauses: ['host-key-changed'],
    candidates: [...GENERIC_CANDIDATES, 'kex-mismatch'],
    feedback: {
      'kex-mismatch': 'Key exchange completed: the client received and verified a signature from the server. It stopped afterwards, when comparing the key with known_hosts.',
      'dns-wrong-record': 'Worth ruling out, since a wrong A record pointing to another SSH server would cause exactly this warning! Here dig returns 10.0.20.10, the real srv01, and the server console shows the fingerprint the client received.',
    },
    hints: [
      'This message comes from the client AFTER the key exchange. What is the client comparing, and against what file?',
      'Do not blindly delete the known_hosts entry. Verify out-of-band: on the srv01 console run "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub" and compare with the fingerprint the client printed.',
      'If the fingerprints match, the change is legitimate. Remove the stale entry with ssh-keygen -R srv01.corp.lab on ws01, reconnect and accept the new key.',
    ],
    explanation: {
      rootCause: 'srv01 was restored from an image and its host keys were regenerated. alice\'s ~/.ssh/known_hosts still holds the old ED25519 key for srv01.corp.lab.',
      manifestation: 'The server proves possession of its NEW key during key exchange. The client finds a different key of the same type recorded for that name and, under StrictHostKeyChecking, aborts before authentication: a potential man-in-the-middle looks exactly like this.',
      evidence: 'Client: "Offending ED25519 key in /home/alice/.ssh/known_hosts:1"; the fingerprint printed by the client equals "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub" on the srv01 console; dig shows the correct IP; sshd logs "Connection closed by 10.0.10.25 port ... [preauth]".',
      prevention: 'Preserve host keys when rebuilding servers (back them up with the configuration), or use SSH host certificates (HostCertificate + @cert-authority in known_hosts) so clients trust the CA, not individual keys. Never train users to delete known_hosts entries without verification.',
    },
    solution: [{ host: 'srv01', commands: ['ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub'], note: 'Verify the new fingerprint out-of-band first.' }, { host: 'ws01', user: 'alice', commands: ['ssh-keygen -R srv01.corp.lab', 'ssh -o StrictHostKeyChecking=accept-new srv01.corp.lab hostname'] }],
    constraints: [sshdPolicy(), firewallStillRestrictive()],
    concepts: ['ssh.hostkeys', 'ssh.kex'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'ssh-allowusers',
    title: 'The new hire',
    difficulty: 'intermediate',
    ticket: 'HR onboarding ticket: "Carol (new SRE) cannot log into srv01. Her account and key were created by the onboarding script. She gets Permission denied (publickey)."',
    briefing: [...BRIEFING, 'Your ws01 terminal is logged in as carol for this ticket. Her key pair is ~carol/.ssh/id_ed25519(.pub).'],
    clientUser: 'carol',
    goals: [{ description: 'carol on ws01 can run "ssh srv01.corp.lab" and log in with her key.', localUser: 'carol', user: 'carol', target: 'srv01.corp.lab', method: 'publickey' }],
    setup(world) {
      const t = world.clock;
      const kp = makeKeyPair('ed25519', 'carol-ws01-ed25519', 'carol@ws01');
      const ws = world.hosts.ws01;
      addUser(ws, { name: 'carol', uid: 1001, gid: 1001, primaryGroup: 'carol', groups: [], home: '/home/carol', shell: '/bin/bash', gecos: 'Carol SRE', password: 'ws01-carol' }, t);
      mkdir(ws, '/home/carol/.ssh', t, { mode: 0o700, owner: 'carol', group: 'carol' });
      writeFile(ws, '/home/carol/.ssh/id_ed25519', kp.privateFile, t, { mode: 0o600, owner: 'carol', group: 'carol' });
      writeFile(ws, '/home/carol/.ssh/id_ed25519.pub', kp.publicLine + '\n', t, { mode: 0o644, owner: 'carol', group: 'carol' });
      writeFile(ws, '/home/carol/.ssh/known_hosts', readFile(ws, '/home/alice/.ssh/known_hosts') ?? '', t, { mode: 0o644, owner: 'carol', group: 'carol' });
      const srv = world.hosts.srv01;
      addUser(srv, { name: 'carol', uid: 1003, gid: 1003, primaryGroup: 'carol', groups: ['sre'], home: '/home/carol', shell: '/bin/bash', gecos: 'Carol SRE', password: null }, t);
      mkdir(srv, '/home/carol/.ssh', t, { mode: 0o700, owner: 'carol', group: 'carol' });
      writeFile(srv, '/home/carol/.ssh/authorized_keys', kp.publicLine + '\n', t, { mode: 0o600, owner: 'carol', group: 'carol' });
      writeAs(world, 'srv01', '/etc/ssh/sshd_config.d/10-hardening.conf', HARDENING_CONF + '# Only named administrators may log in (audit finding AF-77)\nAllowUsers alice bob\n', 5 * 24 * 3600_000);
      script(world, 'srv01', ['systemctl reload ssh']);
      world.clock += 3600_000;
    },
    rootCauses: ['user-not-allowed'],
    candidates: [...GENERIC_CANDIDATES, 'auth-method-disabled'],
    feedback: {
      'authorized-keys-missing': 'carol\'s key IS in /home/carol/.ssh/authorized_keys (compare fingerprints). sshd never even looked at it: the account is rejected before key checks.',
      'server-file-permissions': 'Permissions on /home/carol/.ssh (700) and authorized_keys (600) are correct, and there is no "Authentication refused" line in the log.',
      'invalid-credentials': 'The account exists ("id carol" on srv01). The log line for carol explains why she is treated as invalid.',
    },
    hints: [
      'The key is installed, permissions look right, yet the server rejects it. sshd decides several things before it looks at keys. Check the server log for carol.',
      'journalctl -u ssh on srv01: "User carol from 10.0.10.25 not allowed because ...". Where is that list defined? (sshd -T -C user=carol,addr=10.0.10.25 | grep -i allow)',
      'Add carol to AllowUsers in /etc/ssh/sshd_config.d/10-hardening.conf (or switch to an AllowGroups rule that includes her group), check with sshd -t, then systemctl reload ssh. Make sure alice can still log in.',
    ],
    explanation: {
      rootCause: 'An audit remediation (AF-77) added "AllowUsers alice bob" to sshd. AllowUsers is an allow-list: every account not listed is refused, including new hires. The onboarding script creates accounts and keys but does not update sshd.',
      manifestation: 'sshd treats carol as an invalid user for SSH: it continues the protocol (to avoid revealing which accounts exist) but no authentication can succeed. The client only sees "Permission denied (publickey)".',
      evidence: 'srv01 journal: "User carol from 10.0.10.25 not allowed because not listed in AllowUsers"; sshd -T shows "allowusers alice bob"; authorized_keys and permissions are correct.',
      prevention: 'Authorize by group (AllowGroups sre admins) so onboarding = group membership, and make onboarding automation include an end-to-end login test. Note the asymmetry: the client never learns why it was refused; only server logs explain authorization failures.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i 's/^AllowUsers alice bob$/AllowUsers alice bob carol/' /etc/ssh/sshd_config.d/10-hardening.conf", 'sshd -t', 'systemctl reload ssh', 'sshd -T -C user=carol,addr=10.0.10.25 | grep -i allowusers'], note: 'Better long-term: "AllowGroups admins sre" so that onboarding is a group membership.' }],
    constraints: [
      sessionStillWorks(ALICE_GOAL, 'alice-still-works', 'Existing administrators (alice) must keep access.'),
      sshdPolicy(),
      firewallStillRestrictive(),
    ],
    concepts: ['ssh.authz', 'ssh.userauth', 'logs.journal', 'ssh.config'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'ssh-kex-legacy',
    title: 'Compatibility mode',
    difficulty: 'advanced',
    ticket: 'alice: "ssh srv01 fails instantly: Unable to negotiate with 10.0.20.10 port 22: no matching key exchange method found." Context: the storage team added a setting so their old backup appliance can pull files from srv01 over SFTP.',
    briefing: [...BRIEFING, 'The legacy backup appliance only supports diffie-hellman-group14-sha1. Requirement: the appliance must keep working AND modern clients must connect with modern algorithms.'],
    goals: [ALICE_GOAL],
    setup(world) {
      writeAs(world, 'srv01', '/etc/ssh/sshd_config.d/10-hardening.conf', HARDENING_CONF + '# Needed by the backup appliance (STOR-55)\nKexAlgorithms diffie-hellman-group14-sha1\n');
      script(world, 'srv01', ['systemctl reload ssh']);
      world.clock += 2 * 3600_000;
    },
    rootCauses: ['kex-mismatch'],
    candidates: [...GENERIC_CANDIDATES, 'kex-mismatch'].filter((v, i, a) => a.indexOf(v) === i),
    feedback: {
      'host-key-changed': 'The client never got as far as checking the host key: negotiation failed right after KEXINIT.',
      'sshd-config-error': 'The configuration is syntactically valid (sshd -t is silent, reload succeeded). It is semantically too restrictive.',
    },
    hints: [
      'TCP worked and both sides exchanged identification strings. The failure is in the algorithm negotiation. Read the full client error: whose offer is listed?',
      'On srv01: sshd -T | grep kexalgorithms. Compare with what a modern OpenSSH client offers (ssh -v shows the negotiation).',
      'A KexAlgorithms value without a prefix REPLACES the default list. Use "KexAlgorithms +diffie-hellman-group14-sha1" to append the legacy algorithm to the defaults (or scope it with a Match Address block for the appliance), then sshd -t and reload.',
    ],
    explanation: {
      rootCause: '"KexAlgorithms diffie-hellman-group14-sha1" (no "+") replaced sshd\'s entire key-exchange list with one SHA-1 based algorithm. OpenSSH 9.x clients no longer offer it by default.',
      manifestation: 'After the KEXINIT exchange, no algorithm appears in both lists. Each side computes this independently; the client prints "Unable to negotiate ... Their offer: diffie-hellman-group14-sha1" and the server logs "no matching key exchange method found. Their offer: sntrup761x25519-sha512@openssh.com,...".',
      evidence: 'Client error lists the server\'s offer; sshd -T shows "kexalgorithms diffie-hellman-group14-sha1"; journalctl -u ssh shows "Unable to negotiate with 10.0.10.25 ..."; ssh -v shows TCP and banner exchange succeeded.',
      prevention: 'Use +, - and ^ list modifiers to adjust defaults rather than replacing them; scope legacy exceptions with "Match Address <appliance-ip>"; plan to retire devices that require SHA-1 key exchange.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i 's/^KexAlgorithms diffie-hellman-group14-sha1$/KexAlgorithms +diffie-hellman-group14-sha1/' /etc/ssh/sshd_config.d/10-hardening.conf", 'sshd -t', 'systemctl reload ssh', 'sshd -T | grep kexalgorithms'], note: 'The "+" appends the legacy algorithm to the defaults. Even better: put it inside "Match Address <appliance-ip>".' }],
    constraints: [modernKex(), sshdPolicy(), firewallStillRestrictive()],
    concepts: ['ssh.kex', 'ssh.config'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'ssh-client-key-perms',
    title: 'Restored from backup',
    difficulty: 'beginner',
    ticket: 'alice: "My laptop disk died, IT restored my home directory onto ws01. Now ssh to srv01 shows a warning about my key and then Permission denied."',
    briefing: BRIEFING,
    goals: [ALICE_GOAL],
    setup(world) {
      script(world, 'ws01', ['chmod 644 /home/alice/.ssh/id_ed25519']);
      world.clock += 3600_000;
    },
    rootCauses: ['client-key-permissions'],
    candidates: [...GENERIC_CANDIDATES, 'client-key-permissions'].filter((v, i, a) => a.indexOf(v) === i),
    feedback: {
      'server-file-permissions': 'The server side is unchanged and its journal shows no "Authentication refused". The warning comes from the ssh CLIENT about a file on ws01.',
      'authorized-keys-missing': 'ssh -v shows "Server accepts key": the server WOULD accept it. The client then refuses to use its own private key.',
    },
    hints: [
      'Read the warning carefully: which program prints it, and about which file?',
      'Run ls -l ~/.ssh on ws01. What should a private key\'s mode be?',
      'chmod 600 ~/.ssh/id_ed25519 on ws01. The restore kept file contents but not modes.',
    ],
    explanation: {
      rootCause: 'The restore set alice\'s private key ~/.ssh/id_ed25519 on ws01 to mode 0644 (readable by everyone).',
      manifestation: 'The client offers the PUBLIC key, the server answers PK_OK, then the client must load the PRIVATE key to sign. OpenSSH refuses keys readable by group/others ("UNPROTECTED PRIVATE KEY FILE"), so no signature is sent and authentication fails with "Permission denied (publickey)".',
      evidence: 'Client output: "Permissions 0644 for \'/home/alice/.ssh/id_ed25519\' are too open" and "Load key ...: bad permissions"; ssh -v: "Server accepts key"; server log at INFO level shows only "Connection closed by authenticating user alice".',
      prevention: 'Restore with permissions (tar -p / rsync -a), and treat private keys as secrets: 600, owned by the user. Consider ssh-agent and hardware-backed keys.',
    },
    solution: [{ host: 'ws01', user: 'alice', commands: ['chmod 600 ~/.ssh/id_ed25519', 'ls -l ~/.ssh'] }],
    constraints: [sshdPolicy(), firewallStillRestrictive()],
    concepts: ['linux.permissions', 'ssh.userauth'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'ssh-bob-password',
    title: 'The password is correct!',
    difficulty: 'beginner',
    ticket: 'bob (developer): "I need to deploy from ws01. ssh bob@srv01.corp.lab never even asks for my password, it just says Permission denied (publickey). HR confirmed my password is right."',
    briefing: [...BRIEFING, 'Your ws01 terminal is logged in as bob for this ticket. He has an ed25519 key pair (~bob/.ssh/id_ed25519.pub) on ws01. Until now he only used his old laptop.'],
    clientUser: 'bob',
    goals: [{ description: 'bob on ws01 can log into srv01.corp.lab as bob with his ws01 key (password logins stay disabled).', localUser: 'bob', user: 'bob', target: 'srv01.corp.lab', method: 'publickey' }],
    setup(world) {
      const t = world.clock;
      const ws = world.hosts.ws01;
      const kp = BOB_WS01_KEY;
      addUser(ws, { name: 'bob', uid: 1002, gid: 1002, primaryGroup: 'bob', groups: [], home: '/home/bob', shell: '/bin/bash', gecos: 'Bob Developer', password: 'ws01-bob' }, t);
      mkdir(ws, '/home/bob/.ssh', t, { mode: 0o700, owner: 'bob', group: 'bob' });
      writeFile(ws, '/home/bob/.ssh/id_ed25519', kp.privateFile, t, { mode: 0o600, owner: 'bob', group: 'bob' });
      writeFile(ws, '/home/bob/.ssh/id_ed25519.pub', kp.publicLine + '\n', t, { mode: 0o644, owner: 'bob', group: 'bob' });
      writeFile(ws, '/home/bob/.ssh/known_hosts', readFile(ws, '/home/alice/.ssh/known_hosts') ?? '', t, { mode: 0o644, owner: 'bob', group: 'bob' });
      world.clock += 3600_000;
    },
    rootCauses: ['authorized-keys-missing'],
    acceptable: { 'auth-method-disabled': 'Good observation: "(publickey)" proves the server does not allow passwords. But that is the intended policy (CHG-1042), not the fault to fix. The fault is that bob has no authorized key for this client.' },
    candidates: [...GENERIC_CANDIDATES, 'auth-method-disabled'],
    feedback: {
      'invalid-credentials': 'The password is never sent: the client is not even asked for one. The server only offers "publickey".',
      'user-not-allowed': 'There is no AllowUsers restriction in this scenario, and the log does not say "not allowed".',
    },
    hints: [
      'Why does ssh never ask for a password? Look at the method list in the error message and at "Authentications that can continue" in ssh -v.',
      'Password logins are disabled by policy. Which key does bob offer from ws01, and which keys does srv01 accept for bob? Compare fingerprints (ssh-keygen -lf on both sides).',
      'Append the contents of ws01:/home/bob/.ssh/id_ed25519.pub to srv01:/home/bob/.ssh/authorized_keys (via the srv01 console). ssh-copy-id cannot work here because it needs password logins.',
    ],
    explanation: {
      rootCause: 'bob\'s new ws01 key was never added to his authorized_keys on srv01 (which only contains his laptop key). Password authentication is disabled by policy, so there is no fallback.',
      manifestation: 'The server advertises only "publickey". The client offers bob\'s ws01 key, the server does not find it and answers USERAUTH_FAILURE, and the client has nothing else to try: "Permission denied (publickey)". It never prompts for a password because the server never offered that method.',
      evidence: 'ssh -v as bob: "Authentications that can continue: publickey", "Offering public key: /home/bob/.ssh/id_ed25519 ...", no "Server accepts key"; fingerprints differ between ws01:~bob/.ssh/id_ed25519.pub and srv01:~bob/.ssh/authorized_keys.',
      prevention: 'Provide a self-service or automated key enrollment process (or SSH certificates signed by a CA). Teach users that "Permission denied (publickey)" means password logins are not offered, so the password is irrelevant.',
    },
    solution: [{ host: 'ws01', user: 'bob', commands: ['cat ~/.ssh/id_ed25519.pub'] }, { host: 'srv01', commands: [`echo "${BOB_WS01_KEY.publicLine}" >> /home/bob/.ssh/authorized_keys`, 'ls -l /home/bob/.ssh/authorized_keys', 'ssh-keygen -lf /home/bob/.ssh/authorized_keys'], note: 'The file stays owned by bob with mode 600 because >> appends to the existing file.' }],
    constraints: [sshdPolicy(), firewallStillRestrictive()],
    concepts: ['ssh.userauth', 'ssh.authorized-keys'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'ssh-dns-zone-error',
    title: 'Nobody can resolve anything',
    difficulty: 'intermediate',
    ticket: 'Several users: "ssh: Could not resolve hostname srv01.corp.lab: Temporary failure in name resolution". Web access by IP is fine.',
    briefing: [...BRIEFING, 'This morning someone edited the corp.lab zone on ns1 to add a TXT record for a certificate request.'],
    goals: [ALICE_GOAL],
    setup(world) {
      const zone = CORP_ZONE.replace('2026101901', '2026101902').replace('srv01   IN A    10.0.20.10', 'srv01   IN A    10.0.20.1O') + '_acme-challenge IN TXT "x2Kq9"\n';
      writeAs(world, 'ns1', '/etc/bind/db.corp.lab', zone);
      script(world, 'ns1', ['rndc reload']);
      world.clock += 40 * 60_000;
    },
    rootCauses: ['dns-zone-error'],
    candidates: [...GENERIC_CANDIDATES, 'dns-client-config', 'dns-zone-error'].filter((v, i, a) => a.indexOf(v) === i),
    feedback: {
      'dns-client-config': 'Every client is affected, and ws01 does reach ns1 (dig gets an answer with status SERVFAIL). The resolver config is fine; the server cannot answer.',
      'dns-wrong-record': 'A wrong record would still RESOLVE (to a wrong address). Here nothing in corp.lab resolves: status SERVFAIL.',
      'server-down': 'srv01 is reachable by IP. The failure happens before any packet is sent to it.',
    },
    hints: [
      '"Temporary failure in name resolution" means the resolver got no usable answer. Is the DNS server unreachable, or answering with an error? Use dig and read the status field.',
      'dig srv01.corp.lab returns status: SERVFAIL from 10.0.10.53. On ns1, check named\'s log: journalctl -u named.',
      'The zone failed to load: "bad dotted quad". Run named-checkzone corp.lab /etc/bind/db.corp.lab, fix the typo (letter O vs zero), bump the serial again and rndc reload.',
    ],
    explanation: {
      rootCause: 'While adding a TXT record, the srv01 A record was accidentally changed to "10.0.20.1O" (letter O). On reload named rejected the whole zone file ("bad dotted quad") and stopped serving corp.lab.',
      manifestation: 'named is running and reachable, but it is no longer authoritative for corp.lab, so every query in the zone gets SERVFAIL. glibc turns SERVFAIL into EAI_AGAIN, which ssh prints as "Temporary failure in name resolution". Access by IP works because DNS is not involved.',
      evidence: 'dig: "status: SERVFAIL" from 10.0.10.53; journalctl -u named on ns1: "dns_master_load: /etc/bind/db.corp.lab:13: bad dotted quad" and "zone corp.lab/IN: not loaded due to errors."; named-checkzone reports the same line.',
      prevention: 'Always run named-checkzone before reloading (or use a CI pipeline / dynamic updates), keep zone files in version control, and monitor resolution of critical names.',
    },
    solution: [{ host: 'ns1', commands: ['named-checkzone corp.lab /etc/bind/db.corp.lab', "sed -i 's/10.0.20.1O/10.0.20.10/' /etc/bind/db.corp.lab", "sed -i 's/2026101902/2026101903/' /etc/bind/db.corp.lab", 'named-checkzone corp.lab /etc/bind/db.corp.lab', 'rndc reload'] }],
    constraints: [zoneSerialBumped(2026101902), firewallStillRestrictive()],
    concepts: ['dns.resolution', 'dns.zone', 'logs.journal'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'ssh-monday-reboot',
    title: 'Monday after patching (multiple faults)',
    difficulty: 'advanced',
    ticket: 'Monday 07:58: "Nobody can ssh to srv01 since the weekend patch reboot. It worked all last week." The patch window log says srv01 rebooted cleanly.',
    briefing: [...BRIEFING, 'Last Wednesday an admin rewrote /etc/nftables.conf and "fixed SSH quickly by hand". On Thursday someone experimented with socket activation for sshd.', 'There may be more than one fault.'],
    goals: [ALICE_GOAL],
    setup(world) {
      const conf = SRV01_NFT.replace('\t\ttcp dport 22 accept\n', '');
      writeAs(world, 'srv01', '/etc/nftables.conf', conf);
      script(world, 'srv01', ['nft -f /etc/nftables.conf', 'nft add rule inet filter input tcp dport 22 accept'], 120_000);
      world.clock += 24 * 3600_000;
      script(world, 'srv01', ['systemctl disable ssh']);
      world.clock += 3 * 24 * 3600_000;
      script(world, 'srv01', ['reboot']);
      world.clock += 2 * 3600_000;
    },
    rootCauses: ['firewall-not-persistent', 'service-not-enabled'],
    acceptable: {
      'firewall-drop': 'Correct: the firewall drops SSH. The deeper cause is that the allowing rule only ever existed at runtime and was lost on reboot.',
      'sshd-not-running': 'Correct: sshd is not running. The deeper cause is that the unit is disabled, so it did not start at boot.',
    },
    candidates: [...GENERIC_CANDIDATES, 'firewall-not-persistent', 'service-not-enabled'],
    feedback: {
      'routing-server-gateway': 'srv01 has its default route (ip route) and answers pings.',
    },
    hints: [
      'Start with the symptom: timeout or refused? Then remember that fixing one layer can reveal the next one. Re-test after every change.',
      'Compare the running firewall (nft list ruleset) with what is persistent (/etc/nftables.conf). Also check every service that must run: systemctl status ssh and systemctl is-enabled ssh.',
      'Two persistent fixes are needed: add "tcp dport 22 accept" to /etc/nftables.conf and reload it; "systemctl enable --now ssh". Then use the reboot test (Verify) to prove both survive a restart.',
    ],
    explanation: {
      rootCause: 'Two independent changes only showed up after the reboot: (1) /etc/nftables.conf was rewritten without the SSH rule; SSH was re-allowed with "nft add rule" at runtime, which is not persistent. (2) ssh.service was disabled during an experiment, so it did not start at boot.',
      manifestation: 'First layer: the SYN hits the input policy drop → timeout. After fixing the firewall, the second layer appears: nothing listens on :22 → "Connection refused". Either fix alone does not restore service.',
      evidence: 'nft list ruleset (after reboot) lacks dport 22 and matches /etc/nftables.conf; journalctl shows the Wednesday "nft add rule" was never saved; systemctl status ssh shows "inactive (dead)" with "disabled"; journalctl -b shows no ssh.service start.',
      prevention: 'Make every change in the persistent source of truth (config management), and include a reboot test in change validation. "Works now" is not "will work after reboot".',
    },
    solution: [{ host: 'srv01', commands: ['nft add rule inet filter input tcp dport 22 accept', "echo '#!/usr/sbin/nft -f' > /etc/nftables.conf", "echo 'flush ruleset' >> /etc/nftables.conf", 'nft list ruleset >> /etc/nftables.conf', 'systemctl enable --now ssh', 'systemctl is-enabled ssh nftables'], note: 'Saving the running ruleset with a "flush ruleset" header makes the runtime state persistent.' }],
    constraints: [firewallStillRestrictive(), sshdPolicy()],
    concepts: ['fw.persistence', 'svc.systemd', 'fw.stateful', 'tcp.handshake'],
  },
];

export function getScenario(id: string): Scenario | undefined {
  return SSH_SCENARIOS.find((s) => s.id === id);
}
