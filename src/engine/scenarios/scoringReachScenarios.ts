// Scored services, part 2: the scoring engine cannot reach SSH at all. Two
// families of results tell the causes apart before anyone logs in:
//   "Unable to dial the remote host ... dial tcp IP:22: connect: connection refused"
//     the host answered with a TCP reset: nothing listens on that address/port
//     (sshd stopped or masked, bound to loopback, moved to another port);
//   "Encountered an unexpected error during the check. / check timed out. this
//    is most likely due to services timing out"
//     no answer at all: a firewall drop, no route back, a host that is down.
// The last ticket reproduces the usual competition sequence: refused for a few
// rounds, then timeouts, because two different things were done to the box.

import { firewallStillRestrictive, script, sshdPolicy } from './engine';
import { aliceKeysStillWork, JOE_CHECK, SCORING_BRIEFING, SCORING_TERMINALS, scoringBaseline } from './scoringScenarios';
import type { Scenario } from './types';

const CANDIDATES = ['sshd-not-running', 'service-not-enabled', 'service-masked', 'sshd-listen-address', 'sshd-wrong-port', 'firewall-drop', 'routing-server-gateway', 'server-down', 'invalid-credentials'];

const TERMINALS = [
  { ...SCORING_TERMINALS[0], banner: 'srv01 console (hypervisor), logged in as root. Scored service: SSH. Try: systemctl status ssh, systemctl is-enabled ssh, ss -tlnp, nft list ruleset, ip route, journalctl -u ssh -n 20.' },
  { ...SCORING_TERMINALS[1], banner: 'ws01 (10.0.10.25): the scoring engine\'s checks come from this address. Test like the engine: nc -zv srv01.corp.lab 22 (refused = RST, timed out = no answer), ping srv01.corp.lab, traceroute srv01.corp.lab.' },
];

const DROP_RULE = "sed -i 's/^\\(\\s*\\)tcp dport 22 accept$/\\1tcp dport 22 drop\\n\\1tcp dport 22 accept/' /etc/nftables.conf";
const REFUSED = 'Unable to dial the remote host ... dial tcp 10.0.20.10:22: connect: connection refused';
const TIMED_OUT = 'Encountered an unexpected error during the check. / check timed out. this is most likely due to services timing out';

export const SCORING_REACH_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'score-sshd-masked',
    title: 'Who turned it off?',
    difficulty: 'beginner',
    ticket: `Scoring engine, SSH (srv01): "${REFUSED}" since round 388. Teammate: "I ran systemctl start ssh twice, it just prints an error. Something about masked?"`,
    briefing: SCORING_BRIEFING,
    goals: [JOE_CHECK],
    terminals: TERMINALS,
    setup(world) {
      scoringBaseline(world);
      world.clock += 2 * 3600_000;
      // Red team: stop sshd and make sure nobody can start it again.
      script(world, 'srv01', ['systemctl disable --now ssh', 'systemctl mask ssh'], 30_000);
    },
    rootCauses: ['sshd-not-running', 'service-masked'],
    acceptable: { 'service-not-enabled': 'True as well (disable --now came first), but masking is what stops start and enable from working.' },
    candidates: CANDIDATES,
    feedback: {
      'sshd-listen-address': 'Nothing listens on port 22 at all (ss -tlnp), not even on 127.0.0.1.',
      'sshd-wrong-port': 'sshd is not running on any port.',
      'firewall-drop': 'A firewall drop gives "check timed out" (no answer). "connection refused" means srv01 answered with a reset.',
      'routing-server-gateway': 'A missing route gives no answer at all ("check timed out"); srv01 answered.',
      'server-down': 'srv01 answers (ping works and the kernel sent a reset).',
      'invalid-credentials': 'The engine never got to send a password: the TCP connection itself was refused.',
    },
    hints: [
      '"connection refused" means srv01 itself answered "nobody here" (a TCP reset): the network path and firewall are fine, nothing listens on port 22. On srv01: ss -tlnp, systemctl status ssh.',
      '"Loaded: masked" and "Failed to start ssh.service: Unit ssh.service is masked." A masked unit is linked to /dev/null: it cannot be started, enabled, or started at boot. journalctl -u ssh shows when it stopped.',
      'systemctl unmask ssh, then systemctl enable --now ssh (enable too, or it is down again after the next reboot). Check with systemctl is-enabled ssh and ss -tlnp.',
    ],
    explanation: {
      rootCause: 'The red team ran "systemctl disable --now ssh" and "systemctl mask ssh": sshd was stopped, removed from boot, and its unit linked to /dev/null so that start and enable fail.',
      manifestation: 'Every check: "dial tcp 10.0.20.10:22: connect: connection refused". srv01 answers SYNs to port 22 with RST because no process listens there. A plain "systemctl start ssh" fails with "Unit ssh.service is masked."',
      evidence: 'srv01: ss -tlnp has no :22; systemctl status ssh → Loaded: masked, Active: inactive (dead); systemctl is-enabled ssh → masked; /etc/systemd/system/ssh.service → /dev/null; journal "Stopped ssh.service" at the time the checks started failing. From ws01: nc -zv srv01.corp.lab 22 → Connection refused (immediately).',
      prevention: 'Check scored services with systemctl is-enabled as well as is-active, alert on unit changes, and restrict who can run systemctl as root (sudo rules, separate admin accounts).',
    },
    solution: [{ host: 'srv01', commands: ['systemctl unmask ssh', 'systemctl enable --now ssh'] }],
    constraints: [sshdPolicy(), aliceKeysStillWork()],
    concepts: ['svc.systemd', 'svc.listening', 'tcp.handshake'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'score-sshd-loopback',
    title: 'It works from the console',
    difficulty: 'intermediate',
    ticket: `Scoring engine, SSH (srv01): "${REFUSED}". Teammate: "sshd is running, I can ssh localhost on the box. I reduced its attack surface this morning, nothing else."`,
    briefing: SCORING_BRIEFING,
    goals: [JOE_CHECK],
    terminals: TERMINALS,
    setup(world) {
      scoringBaseline(world);
      script(world, 'srv01', ["printf '# attack surface reduction (team checklist)\\nListenAddress 127.0.0.1\\n' >> /etc/ssh/sshd_config.d/10-hardening.conf", 'systemctl restart ssh'], 60_000);
    },
    rootCauses: ['sshd-listen-address'],
    candidates: CANDIDATES,
    feedback: {
      'sshd-not-running': 'systemctl status ssh: active (running). It is running, but on which address?',
      'service-not-enabled': 'systemctl is-enabled ssh: enabled.',
      'service-masked': 'The unit is loaded normally, not masked.',
      'sshd-wrong-port': 'It still uses port 22, but only on 127.0.0.1 (ss -tlnp).',
      'firewall-drop': 'A drop gives "check timed out"; srv01 answered with a reset.',
      'routing-server-gateway': 'A routing problem gives no answer; srv01 answered.',
      'server-down': 'srv01 answered.',
      'invalid-credentials': 'The TCP connection was refused before any login.',
    },
    hints: [
      'sshd runs and works locally, yet remote connections are refused. A reset comes back when nothing listens on the address the client connects to. On srv01: ss -tlnp | grep :22.',
      '127.0.0.1:22 only: sshd listens on loopback. Find the setting: sshd -T | grep -i listenaddress, grep -ri listenaddress /etc/ssh/.',
      'Remove "ListenAddress 127.0.0.1" from /etc/ssh/sshd_config.d/10-hardening.conf (no ListenAddress = all addresses), sshd -t, systemctl restart ssh, then ss -tlnp shows 0.0.0.0:22 and [::]:22.',
    ],
    explanation: {
      rootCause: '"ListenAddress 127.0.0.1" was added to the hardening file. sshd now binds only to the loopback address, so connections to 10.0.20.10:22 find no listening socket and the kernel resets them.',
      manifestation: 'Remote: "connection refused" immediately. Local: ssh localhost works, which makes "sshd is fine" look true.',
      evidence: 'srv01: ss -tlnp → LISTEN 127.0.0.1:22 only; sshd -T → listenaddress 127.0.0.1:22; the line in 10-hardening.conf. ws01: nc -zv srv01.corp.lab 22 → refused.',
      prevention: 'Limit who may connect with the firewall (or AllowUsers/Match Address), not by binding a scored service to loopback; test scored services from another machine after every change.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i '/^ListenAddress 127.0.0.1$/d' /etc/ssh/sshd_config.d/10-hardening.conf", 'sshd -t && systemctl restart ssh'] }],
    constraints: [sshdPolicy(), aliceKeysStillWork()],
    concepts: ['svc.listening', 'ssh.config'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'score-ssh-firewall-drop',
    title: 'Silence on port 22',
    difficulty: 'beginner',
    ticket: `Scoring engine, SSH (srv01): "${TIMED_OUT}". Teammate: "sshd is up and listening, and ping works. The web check on srv01 is green."`,
    briefing: SCORING_BRIEFING,
    goals: [JOE_CHECK],
    terminals: TERMINALS,
    setup(world) {
      scoringBaseline(world);
      world.clock += 3600_000;
      // Red team: a drop rule above the SSH accept rule, made persistent.
      script(world, 'srv01', [DROP_RULE, 'systemctl reload nftables'], 30_000);
    },
    rootCauses: ['firewall-drop'],
    candidates: CANDIDATES,
    feedback: {
      'sshd-not-running': 'sshd is active and listening on 0.0.0.0:22 (ss -tlnp). A stopped sshd gives "connection refused", not a timeout.',
      'service-not-enabled': 'ssh is enabled and running.',
      'service-masked': 'ssh is not masked.',
      'sshd-listen-address': 'It listens on 0.0.0.0:22, and a wrong address gives "connection refused".',
      'sshd-wrong-port': 'Port 22, as ss -tlnp shows; a wrong port gives "connection refused".',
      'routing-server-gateway': 'ping and the web check work: srv01 has a route back to the engine. Only port 22 is silent.',
      'server-down': 'srv01 answers ping and serves the web check.',
      'invalid-credentials': 'The engine never completed a TCP connection.',
    },
    hints: [
      '"check timed out" means the engine got no answer at all before its deadline: not a reset, not a password failure. From ws01: nc -zv srv01.corp.lab 22 (hangs, then times out) versus nc -zv srv01.corp.lab 80.',
      'Something drops packets to port 22 only. On srv01: nft -a list chain inet filter input. Rules are evaluated in order: what comes before "tcp dport 22 accept"?',
      'Delete the drop rule from /etc/nftables.conf (sed -i \'/tcp dport 22 drop/d\' /etc/nftables.conf), check with nft -c -f /etc/nftables.conf, reload nftables. Keep the input policy drop.',
    ],
    explanation: {
      rootCause: 'A "tcp dport 22 drop" rule was inserted above the SSH accept rule in /etc/nftables.conf and loaded. nftables evaluates rules in order, so every SYN to port 22 is dropped silently.',
      manifestation: 'The engine\'s SYNs get no answer; its check deadline expires: "Encountered an unexpected error during the check." / "check timed out". OpenSSH would say "Connection timed out" after its own timeout.',
      evidence: 'srv01: sshd listening on 0.0.0.0:22; nft -a list chain inet filter input shows "tcp dport 22 drop" before "tcp dport 22 accept" (its counter grows with each check); ping and HTTP work. ws01: nc -zv srv01.corp.lab 22 times out, port 80 succeeds.',
      prevention: 'Keep /etc/nftables.conf under version control (or at least diff it against a known good copy) and look at rule order and counters first when a scored port times out.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i '/tcp dport 22 drop/d' /etc/nftables.conf", 'nft -c -f /etc/nftables.conf && systemctl reload nftables'] }],
    constraints: [sshdPolicy(), firewallStillRestrictive(), aliceKeysStillWork()],
    concepts: ['fw.stateful', 'tcp.handshake'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'score-ssh-no-route-back',
    title: 'The packets arrive, the answers don\'t',
    difficulty: 'intermediate',
    ticket: `Scoring engine, SSH (srv01): "${TIMED_OUT}". The web check on srv01 fails too. Teammate: "I cleaned up /etc/network/interfaces and restarted networking. srv01 still has its address, I checked."`,
    briefing: SCORING_BRIEFING,
    goals: [JOE_CHECK],
    terminals: TERMINALS,
    setup(world) {
      scoringBaseline(world);
      script(world, 'srv01', ["sed -i '/^    gateway 10.0.20.1$/d' /etc/network/interfaces", 'systemctl restart networking'], 60_000);
    },
    rootCauses: ['routing-server-gateway'],
    candidates: CANDIDATES,
    feedback: {
      'sshd-not-running': 'sshd is active and listening (ss -tlnp); a stopped sshd would answer with a reset ("connection refused").',
      'service-not-enabled': 'ssh is enabled and running.',
      'service-masked': 'ssh is not masked.',
      'sshd-listen-address': 'sshd listens on 0.0.0.0:22.',
      'sshd-wrong-port': 'sshd listens on port 22.',
      'firewall-drop': 'The input chain accepts port 22 and its counter increases: the SYNs are accepted. The answers are what never leave.',
      'server-down': 'srv01 is up: its console works and it still has 10.0.20.10.',
      'invalid-credentials': 'No TCP connection was ever completed.',
    },
    hints: [
      'Both SSH and web time out, so this is not about one service. From ws01: ping srv01.corp.lab. On srv01: tcpdump -n -i eth0 tcp port 22 while ws01 runs nc -zv srv01.corp.lab 22: do SYNs arrive? Do SYN-ACKs leave?',
      'The SYNs arrive and nothing goes back. To answer 10.0.10.25, srv01 needs a route to it: ip route, ip route get 10.0.10.25.',
      'No default route. Put "gateway 10.0.20.1" back in the eth0 stanza of /etc/network/interfaces and add the route now: ip route add default via 10.0.20.1.',
    ],
    explanation: {
      rootCause: 'The "gateway 10.0.20.1" line was removed from /etc/network/interfaces and networking was restarted, so srv01 lost its default route. It still receives packets from other subnets but cannot send replies back to them.',
      manifestation: 'Every client outside 10.0.20.0/24, the scoring engine included, gets no answer: "check timed out" for SSH and the web check alike. Machines on the server subnet still work, which makes it look like a firewall problem.',
      evidence: 'srv01: ip route has only 10.0.20.0/24; ip route get 10.0.10.25 → "Network is unreachable"; tcpdump shows SYNs in, nothing out; nft counters on the accept rules increase.',
      prevention: 'Apply network changes from the console with a rollback plan, and test from another subnet (where the scoring engine is) before closing the change.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i 's|^    address 10.0.20.10/24$|    address 10.0.20.10/24\\n    gateway 10.0.20.1|' /etc/network/interfaces", 'ip route add default via 10.0.20.1'] }],
    constraints: [sshdPolicy(), firewallStillRestrictive(), aliceKeysStillWork()],
    concepts: ['net.routing', 'tcp.handshake'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'score-refused-then-timeout',
    title: 'Refused, then timed out',
    difficulty: 'advanced',
    ticket: `Scoring engine, SSH (srv01): rounds 388-389 "${REFUSED}", rounds 390-392 "${TIMED_OUT}". Teammate: "At 388 sshd was down, so I started it again. Now it times out instead. Is the engine broken?"`,
    briefing: SCORING_BRIEFING,
    goals: [JOE_CHECK],
    terminals: TERMINALS,
    setup(world) {
      scoringBaseline(world);
      world.clock += 3600_000;
      script(world, 'srv01', ['systemctl disable --now ssh'], 60_000); // red team, round 387
      world.clock += 5 * 60_000;
      script(world, 'srv01', ['systemctl start ssh'], 60_000); // teammate, round 389
      script(world, 'srv01', [DROP_RULE, 'systemctl reload nftables'], 60_000); // red team, round 390
    },
    rootCauses: ['firewall-drop', 'service-not-enabled'],
    acceptable: { 'sshd-not-running': 'It was the cause in rounds 388-389; your teammate started sshd since then. But it is still disabled: see the reboot test.' },
    candidates: CANDIDATES,
    feedback: {
      'service-masked': 'The unit is not masked: start worked for your teammate.',
      'sshd-listen-address': 'sshd listens on 0.0.0.0:22.',
      'sshd-wrong-port': 'sshd listens on port 22.',
      'routing-server-gateway': 'ping and the web check work: srv01 can answer the engine.',
      'server-down': 'srv01 is up.',
      'invalid-credentials': 'The engine never completed a TCP connection in any of these rounds.',
    },
    hints: [
      'Two different messages mean two different situations: "connection refused" (srv01 answered: nothing listened) then "check timed out" (no answer at all). What changed between round 389 and 390? Look at both the service and the firewall.',
      'On srv01: systemctl status ssh (running, but enabled?), journalctl -u ssh, and nft -a list chain inet filter input: is there a drop before the SSH accept rule?',
      'Fix both, persistently: remove the drop rule from /etc/nftables.conf and reload nftables, and systemctl enable ssh (your teammate only started it: the next reboot would bring back "connection refused").',
    ],
    explanation: {
      rootCause: 'Two changes by the red team. In round 387 "systemctl disable --now ssh" (refused); your teammate started sshd again but did not enable it. In round 390 a persistent "tcp dport 22 drop" rule was loaded (timeouts). The timeout hides the second problem: after the next reboot sshd would stay down.',
      manifestation: 'The results change from "connection refused" to "check timed out" though nobody "broke" anything new from the team\'s point of view. Fixing only the firewall makes the check pass until the next reboot.',
      evidence: 'srv01: journal "Stopped ssh.service" then "Started ssh.service"; systemctl is-enabled ssh → disabled; nft rules: "tcp dport 22 drop" before the accept rule; ws01: nc -zv srv01.corp.lab 22 times out.',
      prevention: 'When a check changes failure type, look for a second change rather than assuming the first fix broke something. Fix services persistently (enable, not only start), and re-check after every fix.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i '/tcp dport 22 drop/d' /etc/nftables.conf", 'nft -c -f /etc/nftables.conf && systemctl reload nftables', 'systemctl enable ssh'] }],
    constraints: [sshdPolicy(), firewallStillRestrictive(), aliceKeysStillWork()],
    concepts: ['svc.systemd', 'fw.stateful', 'tcp.handshake'],
  },
];
