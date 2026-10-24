// Primers for the service and operations lessons: SSH, firewalls (nftables,
// pfSense), systemd, network configuration and safe recovery. Plain language,
// each idea with an example from the lab.

import type { Primer } from '../types';

export const SSH_PRIMER: Primer = {
  oneLiner: '**SSH** gives you an encrypted remote shell. The client checks it reached the right server (the **host key**), then proves who you are, usually with a **key pair** instead of a password, and the server decides whether you may log in.',
  analogy: `
Entering an office building. First you check you are at the right building: the nameplate matches the one you noted on your first visit (the **host key** in known_hosts). Then the guard checks your badge (your key or password) against the list of people allowed in (authorized_keys, AllowUsers).

A key pair is a padlock and its key. You give copies of the open padlock (the **public key**) to every server; only your private key opens them. Losing a padlock copy is harmless; losing the private key is not.`,
  ideas: [
    {
      title: 'The connection goes through layers',
      explain: 'Name resolution → TCP to port 22 → version exchange and key exchange (encryption) → **host key** check → **user authentication** → authorisation → your shell. Each layer has its own error message, so the message tells you where to look.',
      example: '"Could not resolve hostname" = DNS. "Connection refused" = nothing on port 22. "Host key verification failed" = the server\'s identity changed. "Permission denied (publickey)" = authentication.',
    },
    {
      title: 'Host keys protect you from impostors',
      explain: 'The first time, ssh shows the server\'s key fingerprint and stores it in ~/.ssh/known_hosts. Afterwards a different key triggers a loud warning: maybe the server was reinstalled, maybe someone is in the middle.',
      example: 'srv01 is reinstalled and gets new host keys. alice\'s next `ssh srv01` refuses with "REMOTE HOST IDENTIFICATION HAS CHANGED". After confirming with the admin, she removes the old entry: `ssh-keygen -R srv01.corp.lab`.',
    },
    {
      title: 'Key-based login: authorized_keys',
      explain: 'You create a pair with `ssh-keygen`; the public half goes into ~/.ssh/authorized_keys on the server (`ssh-copy-id` does that). sshd only accepts it if the home directory, ~/.ssh and the file are not writable by others.',
      example: 'alice on ws01 logs in to srv01 without a password:\n```\n$ ssh -o BatchMode=yes alice@srv01.corp.lab hostname\nsrv01\n```\nIf ~/.ssh on srv01 were group-writable, sshd would ignore the key and ask for a password (or refuse).',
    },
    {
      title: 'sshd_config decides what is allowed',
      explain: 'The server\'s /etc/ssh/sshd_config sets the port, `PasswordAuthentication`, `PermitRootLogin`, `AllowUsers`/`AllowGroups`. Test it with `sshd -t` before reloading: a syntax error stops sshd from restarting.',
      example: 'Hardening srv01: `PasswordAuthentication no` and `PermitRootLogin no`, then `sshd -t && systemctl reload ssh`. Existing sessions stay open, so you can fix mistakes before logging out.',
    },
  ],
  walkthrough: {
    title: 'alice runs "ssh srv01"',
    steps: [
      { label: 'Resolve and connect', detail: 'srv01 → srv01.corp.lab (search domain) → 10.0.20.10. TCP handshake to port 22.' },
      { label: 'Versions and key exchange', detail: 'Both sides send "SSH-2.0-OpenSSH_9.2" banners, agree on algorithms and create session keys. From here on, everything is encrypted.' },
      { label: 'Host key check', detail: 'srv01 proves it holds its host key; ssh compares it with the line for srv01.corp.lab in ~/.ssh/known_hosts. Match: continue.' },
      { label: 'User authentication', detail: 'ssh offers alice\'s public key; sshd finds it in /home/alice/.ssh/authorized_keys and asks for a signature, which only her private key can make.' },
      { label: 'Session', detail: 'sshd checks the account is allowed (AllowUsers, shell exists), PAM opens the session, and alice gets a shell. The log on srv01 records it.', show: 'sshd[427]: Accepted publickey for alice from 10.0.10.25 port 53862 ssh2: ED25519 SHA256:...' },
    ],
  },
  misconceptions: [
    { myth: '"Permission denied" means the password is wrong.', truth: 'It means no offered method was accepted. The list in parentheses shows what the server allows; the server log (`journalctl -u ssh`) says why, e.g. bad permissions on authorized_keys or a user not in AllowUsers.' },
    { myth: 'The host key warning can always be bypassed by deleting known_hosts.', truth: 'Delete the entry only after confirming the server really changed. Otherwise you may be logging in to an impostor.' },
    { myth: 'Restarting sshd kicks everybody out.', truth: 'Existing sessions are separate processes and survive a reload/restart. A config error, however, can stop new logins, so test with `sshd -t` first.' },
  ],
  checks: [
    { q: 'Which file on the server lists the public keys allowed to log in as alice?', a: '/home/alice/.ssh/authorized_keys' },
    { q: 'ssh says "Connection refused". Which layer failed?', a: 'TCP: the server answered but nothing listens on that port (sshd stopped or on another port).' },
    { q: 'What command validates sshd_config before a reload?', a: '`sshd -t`' },
    { q: 'Why does ssh complain when the server\'s host key changes?', a: 'It cannot tell a reinstalled server from an impostor intercepting the connection.' },
  ],
};

export const NFTABLES_PRIMER: Primer = {
  oneLiner: 'A Linux firewall (**nftables**) checks every packet against ordered rules in **chains** attached to points in the kernel: the first rule that decides wins, the chain **policy** applies otherwise, and connection tracking lets replies through automatically.',
  analogy: `
Security checkpoints in a building. **input** is the checkpoint at the front door (traffic for this machine), **forward** is a checkpoint in a corridor that people only walk through (traffic routed through this machine), **output** is the exit (traffic this machine starts).

Each checkpoint has a list of rules read top to bottom, and a default: "nobody else gets in" (**policy drop**). A visitor's badge stamped at entry lets them leave and come back during the visit without being checked again (**ct state established**).`,
  ideas: [
    {
      title: 'Tables, chains, hooks and policies',
      explain: 'Rules live in **chains** inside **tables**. A base chain is attached to a **hook** (input, forward, output, prerouting, postrouting) and has a **policy** used when no rule decides.',
      example: 'srv01\'s ruleset (`nft list ruleset`):\n```\nchain input {\n  type filter hook input priority filter; policy drop;\n  ct state established,related accept\n  iif "lo" accept\n  meta l4proto icmp accept\n  tcp dport 22 accept\n  tcp dport { 80, 443 } accept\n}\n```',
    },
    {
      title: 'Rules are read in order; the first verdict wins',
      explain: '`accept`, `drop` and `reject` end the evaluation for that packet. A broad rule above a narrow one makes the narrow one useless.',
      example: 'If `tcp dport 22 drop` were inserted above `tcp dport 22 accept`, SSH would be blocked: the drop matches first. Use `nft -a list chain inet filter input` to see rule handles and positions.',
    },
    {
      title: 'Stateful filtering: allow the start, replies follow',
      explain: 'Connection tracking remembers allowed connections. `ct state established,related accept` lets their replies and related ICMP errors through, so you only write rules for the **first** packet.',
      example: 'srv01 starts an `apt update` to the Internet (output is allowed). The answers come back in **input**, where no rule mentions port 80 from outside, yet they pass: they are "established".',
    },
    {
      title: 'Drop vs reject, and persistence',
      explain: '**drop** discards silently (clients time out); **reject** answers with an error (clients see "refused" or "no route to host" at once). Rules typed with `nft add` live only in memory: save them in /etc/nftables.conf and enable the service to survive a reboot.',
      example: 'Opening port 8080 with `nft add rule inet filter input tcp dport 8080 accept` works until the next reboot. Adding the line to /etc/nftables.conf and `systemctl enable nftables` makes it permanent.',
    },
  ],
  walkthrough: {
    title: 'A web request reaches srv01 through its firewall',
    steps: [
      { label: 'SYN arrives on eth0', detail: 'From ws01, 10.0.10.25 → 10.0.20.10:443. It is for this machine, so it goes through the **input** chain.' },
      { label: 'Rule 1: established?', detail: 'No: it is a new connection. Continue.' },
      { label: 'Rules 2–5', detail: 'Not loopback, not ICMP, not port 22. Continue.' },
      { label: 'tcp dport { 80, 443 } accept', detail: 'Match: accepted. conntrack creates an entry for the connection.' },
      { label: 'Every later packet', detail: 'Matches rule 1 (established) and is accepted immediately. A packet to port 25 would match nothing and hit **policy drop**: the client times out.' },
    ],
  },
  misconceptions: [
    { myth: 'I need rules for the replies too.', truth: 'With `ct state established,related accept`, replies of allowed connections pass automatically.' },
    { myth: 'If `nft list ruleset` shows my rule, it will be there after a reboot.', truth: 'Only if it is in /etc/nftables.conf and the nftables service is enabled. Runtime changes are lost.' },
    { myth: 'Policy drop on input also blocks traffic routed through a router.', truth: 'Routed traffic uses the **forward** chain. Input only sees packets addressed to the machine itself.' },
  ],
  checks: [
    { q: 'Which chain sees packets that rtr01 routes from ws01 to srv01?', a: 'rtr01\'s forward chain.' },
    { q: 'A port is blocked by "policy drop". What does the client see?', a: 'A timeout (no answer).' },
    { q: 'What does `ct state established,related accept` save you from writing?', a: 'Rules for reply traffic and related ICMP errors.' },
    { q: 'How do you make an nftables change permanent on Debian?', a: 'Put it in /etc/nftables.conf (check with `nft -c -f`), and make sure the nftables service is enabled.' },
  ],
};

export const PFSENSE_PRIMER: Primer = {
  oneLiner: '**pfSense** is a firewall appliance: you configure interfaces, rules and NAT in a web interface, it saves everything in one file (**config.xml**) and turns it into **pf** rules that filter traffic as it **enters** each interface, first match wins.',
  analogy: `
A gatehouse with one guard per gate (WAN, LAN, DMZ). Each guard has their own list and only checks people **coming in through their gate**; whoever leaves through a gate is not checked again there. The first rule on the list that matches decides, and anyone not explicitly allowed is turned away and noted in the log book (the **default deny**).

The web interface is the office where you edit the lists. Edits are drafts until you press **Apply Changes**, which hands the new lists to the guards.`,
  ideas: [
    {
      title: 'Rules belong to the interface where traffic enters',
      explain: 'A rule on the DMZ tab controls what DMZ machines may open; a rule on WAN controls what the Internet may open. Replies pass automatically (state).',
      example: 'To stop dmz01 from reaching the inside, the block goes on the **DMZ** tab ("DMZ net → INTERNAL_NETS"), not on LAN. The office can still reach dmz01: that connection starts on LAN, and the replies leaving through the DMZ belong to its state.',
    },
    {
      title: 'Order matters: first match wins',
      explain: 'Put narrow exceptions first, then the block, then the broad pass. Everything not passed hits the logged **default deny**.',
      example: 'fw01\'s DMZ rules, in order:\n```\n1 pass  TCP/UDP DMZ net → 10.0.10.53 port 53   (DNS to ns1)\n2 block any     DMZ net → INTERNAL_NETS (logged)\n3 pass  any     DMZ net → any            (Internet)\n```\nSwap 1 and 2 and dmz01 loses DNS.',
    },
    {
      title: 'Aliases name groups of addresses and ports',
      explain: 'INTERNAL_NETS = 10.0.0.0/16, WEB_PORTS = 80, 443. Rules read like the policy, and changing an address means editing one alias.',
      example: '`pfctl -t INTERNAL_NETS -T show` on the console prints 10.0.0.0/16: the alias became a pf **table**.',
    },
    {
      title: 'A port forward translates; a rule must still allow it',
      explain: 'A port forward rewrites connections to the WAN address into an inside server **before** filtering. The WAN rule must allow the **translated** destination. "Add associated filter rule" creates it for you.',
      example: 'Forward WAN TCP WEB_PORTS → DMZ_WEB (172.16.50.10). Its associated WAN rule is "pass TCP any → DMZ_WEB port WEB_PORTS". Delete that rule and customers time out, though `pfctl -sn` still shows the forward.',
    },
    {
      title: 'Saved is not applied',
      explain: 'Saving a page writes config.xml; **Apply Changes** generates /tmp/rules.debug and loads it. If loading fails, pf keeps the previous rules and the log says why.',
      example: 'You add a rule and test immediately: no change. The yellow banner says "The changes must be applied". After Apply, `pfctl -sr` shows the new line.',
    },
  ],
  walkthrough: {
    title: 'A customer on the Internet opens the portal',
    intro: 'ext01 (203.0.113.80) opens http://portal.corp.lab/, which resolves to fw01\'s WAN address 203.0.113.10.',
    steps: [
      { label: 'SYN arrives on WAN (vtnet0)', detail: '203.0.113.80:50000 → 203.0.113.10:80.' },
      { label: 'Port forward (rdr)', detail: 'The forward for WEB_PORTS matches: the destination becomes 172.16.50.10:80.' },
      { label: 'WAN rules', detail: '"Block private networks" does not match (the source is public). "pass TCP any → DMZ_WEB port WEB_PORTS" matches the translated packet: passed, a state is created.' },
      { label: 'Out of the DMZ interface', detail: 'Routing sends it out of vtnet2 to dmz01. No rule on the DMZ tab is checked: rules apply on the way **in**.' },
      { label: 'The reply', detail: 'dmz01 answers 172.16.50.10:80 → 203.0.113.80. It matches the state, is translated back to come from 203.0.113.10, and leaves on WAN. `pfctl -ss` shows the translated state.', show: 'all tcp 172.16.50.10:80 (203.0.113.10:80) <- 203.0.113.80:50000       ESTABLISHED:ESTABLISHED' },
    ],
  },
  misconceptions: [
    { myth: 'To block traffic going **to** the DMZ I add a rule on the DMZ tab.', truth: 'The DMZ tab filters traffic **from** DMZ machines. Traffic to the DMZ is filtered where it enters: on LAN or WAN.' },
    { myth: 'A port forward is enough to publish a server.', truth: 'It only translates. Without a pass rule for the translated address, the default deny drops the traffic.' },
    { myth: '"LAN net" means everything behind the LAN interface.', truth: 'It is only the LAN interface\'s own subnet. Networks routed to the firewall through LAN (the office behind rtr01) need an alias.' },
  ],
  checks: [
    { q: 'On which tab do you put a rule that lets the DMZ query ns1?', a: 'The DMZ tab: that traffic enters fw01 on the DMZ interface.' },
    { q: 'The portal works from the office but not from the Internet; pfctl -sn shows the rdr. What do you look for?', a: 'A WAN pass rule to the translated address (DMZ_WEB, WEB_PORTS); the firewall log will show the default deny.' },
    { q: 'You saved a rule but nothing changed. Why?', a: 'The change was not applied: click Apply Changes (or run /etc/rc.filter_configure).' },
    { q: 'Where is the whole pfSense configuration stored?', a: '/conf/config.xml (/cf/conf/config.xml).' },
  ],
};

export const SYSTEMD_PRIMER: Primer = {
  oneLiner: '**systemd** starts and supervises the services on a Linux machine: each service is a **unit** you can start, stop, enable at boot and inspect, and its messages go to the **journal**, which is the first place to look when a service fails.',
  analogy: `
A theatre stage manager with a script for every actor (the **unit file**). The manager knows who must be on stage before whom (dependencies), calls each actor at curtain-up if they are on tonight's list (**enabled**), notices when one walks off stage (failure), and writes everything in the logbook (the **journal**).

"Started" means on stage now. "Enabled" means on tonight's list. They are independent: an actor can be on stage now but not on the list for the next performance.`,
  ideas: [
    {
      title: 'Active vs enabled',
      explain: '**active** = running now. **enabled** = will be started at boot. `systemctl start` changes the first, `systemctl enable` the second; `enable --now` does both.',
      example: 'On srv01 `systemctl status nginx` shows both:\n```\nLoaded: loaded (/lib/systemd/system/nginx.service; enabled; preset: enabled)\nActive: active (running) since Mon 2026-10-19 07:58:06 UTC; 37min ago\n```',
    },
    {
      title: 'The journal tells you why',
      explain: '`journalctl -u <unit>` shows a service\'s messages, including the error that made it fail. `-b` limits to this boot, `-n 20` the last lines, `-f` follows live.',
      example: 'After a failed restart of nginx, `journalctl -u nginx -n 5` shows the configuration error and the file and line number; `systemctl status` only says "failed".',
    },
    {
      title: 'Test configuration before restarting',
      explain: 'Most daemons can check their own configuration: `nginx -t`, `sshd -t`, `named-checkconf`, `nft -c -f`. A restart with a broken file stops a working service.',
      example: '`nginx -t && systemctl reload nginx`: the reload only happens if the test passes, and `reload` keeps existing connections.',
    },
    {
      title: 'Files and permissions matter',
      explain: 'Services run as specific users and read specific files. Wrong ownership or mode, a full disk, or a missing directory make a service fail even when its configuration is correct.',
      example: 'sshd refuses a user\'s key if ~/.ssh is writable by the group; nginx cannot read a certificate key owned by root with mode 600 if it was told to read it as www-data.',
    },
  ],
  walkthrough: {
    title: 'nginx does not come back after a configuration change',
    steps: [
      { label: 'See the state', detail: '`systemctl status nginx` → "failed (Result: exit-code)". The service is down.' },
      { label: 'Read why', detail: '`journalctl -u nginx -n 20`: the error names the file and line, for example an unknown directive at /etc/nginx/sites-enabled/default:12.' },
      { label: 'Fix and test', detail: 'Correct the line, then `nginx -t` until it says "syntax is ok" and "test is successful".' },
      { label: 'Start and verify', detail: '`systemctl start nginx`, then check the listener (`ss -tlnp | grep :80`) and a real request (`curl -I http://localhost/`).' },
      { label: 'Make sure it survives a reboot', detail: '`systemctl is-enabled nginx` → enabled. If it said "disabled", the service would be down again after the next restart.' },
    ],
  },
  misconceptions: [
    { myth: 'If a service runs now, it will run after a reboot.', truth: 'Only if it is **enabled**. A service started by hand and never enabled disappears at the next boot.' },
    { myth: '`systemctl status` shows all the details I need.', truth: 'It shows the last few log lines. The full error is in `journalctl -u <unit>`.' },
    { myth: 'Restart is the safe way to apply a change.', truth: 'Restart stops the service first. With a broken configuration it does not come back. Test first, and prefer reload when the service supports it.' },
  ],
  checks: [
    { q: 'Which command both enables and starts a service?', a: '`systemctl enable --now <unit>`' },
    { q: 'Where do you find why a unit failed?', a: '`journalctl -u <unit>` (and `systemctl status <unit>` for the summary).' },
    { q: 'nginx runs, but after a reboot it is down. What is the likely cause?', a: 'It is not enabled (`systemctl is-enabled nginx` → disabled).' },
    { q: 'What does `nginx -t` do?', a: 'Tests the configuration without changing the running service.' },
  ],
};

export const NETOPS_PRIMER: Primer = {
  oneLiner: 'Network configuration on a Linux server lives in **files** (on Debian /etc/network/interfaces and /etc/resolv.conf); commands like `ip addr add` only change the running state. Change the file, apply it carefully, and verify layer by layer.',
  analogy: `
Rearranging furniture in a rented flat versus changing the floor plan. \`ip addr add\` moves the furniture today: it works until someone resets the flat (a reboot). The file is the floor plan everyone uses after a reset.

Changing the network of a remote machine is like changing the locks while you are outside: do it in a way that lets you back in if it goes wrong (console access, a timed rollback).`,
  ideas: [
    {
      title: 'Runtime vs persistent configuration',
      explain: '`ip addr`, `ip route` and `ip link` change the kernel now. ifupdown reads /etc/network/interfaces at boot (or `ifup`). A fix done only at runtime is lost at reboot.',
      example: 'Adding a missing default route with `ip route add default via 10.0.20.1` brings srv01 back now. Without `gateway 10.0.20.1` in /etc/network/interfaces, it breaks again at the next reboot.',
    },
    {
      title: 'Know which tool manages the interface',
      explain: 'Debian servers often use ifupdown; desktops NetworkManager; Ubuntu netplan with systemd-networkd. Editing the files of a tool that is not in charge changes nothing.',
      example: '`systemctl status networking NetworkManager systemd-networkd` shows which one is active before you edit anything.',
    },
    {
      title: 'Verify from the bottom up',
      explain: 'Link → address → route → gateway reachable → DNS → the service. Each check is one command and rules out a layer.',
      example: 'On ws01: `ip -br addr` (10.0.10.25/24), `ip route` (default via 10.0.10.1), `ping -c 2 10.0.10.1`, `dig +short srv01.corp.lab` (10.0.20.10), `nc -zv srv01.corp.lab 22`.',
    },
    {
      title: 'Plan a way back before changing a remote machine',
      explain: 'Keep a copy of the file, use a console when possible, and keep your SSH session open while testing a new one. Applying a wrong address over SSH cuts the branch you are sitting on.',
      example: '`cp /etc/network/interfaces /root/interfaces.bak` before editing; from the hypervisor console, `cp /root/interfaces.bak /etc/network/interfaces && systemctl restart networking` restores it.',
    },
  ],
  walkthrough: {
    title: 'Moving srv01\'s gateway safely',
    steps: [
      { label: 'Record the working state', detail: '`ip -br addr; ip route; cat /etc/resolv.conf` saved to a file, and a backup of /etc/network/interfaces.' },
      { label: 'Edit the file', detail: 'Change `gateway 10.0.20.1` to the new address in the eth0 stanza.' },
      { label: 'Apply on the console', detail: '`ifdown eth0 && ifup eth0` (or `systemctl restart networking`), from a console rather than over SSH.' },
      { label: 'Verify layer by layer', detail: '`ip route` shows the new default; `ping` the gateway; reach a host on another subnet; resolve a name.' },
      { label: 'Reboot test', detail: 'Restart once in the change window: the file is now the only source of truth, so the reboot proves the change is complete.' },
    ],
  },
  misconceptions: [
    { myth: 'It works now, so the fix is done.', truth: 'Runtime fixes disappear at reboot. Check that the configuration file contains the change.' },
    { myth: 'Restarting networking over SSH is fine if the change is small.', truth: 'A typo can take the interface down and your session with it. Use a console or a timed rollback.' },
    { myth: '/etc/resolv.conf is always edited by hand.', truth: 'DHCP clients, NetworkManager or systemd-resolved may rewrite it. Find out who owns it before editing.' },
  ],
  checks: [
    { q: 'Which file holds static interface configuration on Debian with ifupdown?', a: '/etc/network/interfaces (and files in /etc/network/interfaces.d/).' },
    { q: 'You fixed a route with `ip route add`. What else must you do?', a: 'Add it to the persistent configuration (e.g. a gateway or `up ip route add …` line in /etc/network/interfaces).' },
    { q: 'List the bottom-up checks after a network change.', a: 'Link, address, routes, gateway ping, a remote host, DNS, the service itself.' },
    { q: 'Why keep the SSH session open while testing a new one?', a: 'If the change breaks access, the existing session lets you revert it.' },
  ],
};

export const RECOVERY_PRIMER: Primer = {
  oneLiner: 'Recovering infrastructure safely means **finding the cause before changing anything**, making the smallest fix that addresses it, verifying from a client\'s point of view, and proving it still works **after a reboot**, while keeping a record of what you did.',
  analogy: `
A doctor in an emergency room. First stabilise and observe (what are the symptoms, since when, what changed?), then diagnose (tests that rule causes in or out), then treat the cause, not the symptom (a painkiller hides the fever but does not cure the infection), then check the patient is really better, and write it in the chart.

"Restart everything" is the painkiller: sometimes it helps, often it hides the evidence.`,
  ideas: [
    {
      title: 'Start with what changed',
      explain: 'Most outages follow a change: an update, a configuration edit, a reboot, a certificate expiry. Ask, check logs and change records before guessing.',
      example: '"SSH to srv01 broke on Monday" + "srv01 was rebooted Sunday night for updates" points to something that was only configured at runtime, or a service not enabled.',
    },
    {
      title: 'Follow the dependency chain',
      explain: 'A user-visible service depends on a chain: name resolution, network path, firewall, the service running and listening, authentication, authorisation. Test the chain in order and stop at the first broken link.',
      example: 'Web page down from ws01: `dig` (DNS ok) → `ping` (path ok) → `nc -zv srv01 80` (timed out) → on srv01 `ss -tlnp` (nginx listening) → `nft list ruleset` (port 80 rule missing). The cause is the firewall, not nginx.',
    },
    {
      title: 'Smallest fix, then verify from the client',
      explain: 'Change one thing, then test exactly what the user does. Turning off a firewall or giving everyone admin rights "works" but creates a new problem.',
      example: 'Restore the single missing rule `tcp dport { 80, 443 } accept` instead of setting the policy to accept, then run the user\'s own request: `curl -I http://srv01.corp.lab/` from ws01.',
    },
    {
      title: 'The reboot test and the record',
      explain: 'A fix is complete only when it survives a restart. Write down the symptom, evidence, cause, fix and verification: the next person (or you) will need it.',
      example: 'After fixing, `systemctl is-enabled nftables` and a reboot of srv01 in the window. The ticket note: "port 80 rule missing from /etc/nftables.conf after CHG-1234; restored; verified from ws01 before and after reboot".',
    },
  ],
  walkthrough: {
    title: 'Ticket: "the intranet site is down"',
    steps: [
      { label: 'Reproduce', detail: 'From ws01: `curl -I http://srv01.corp.lab/` → "Connection timed out". Note the exact message.' },
      { label: 'Narrow it down', detail: 'Name resolves (dig), srv01 answers ping, port 22 works but port 80 times out: a filtering problem specific to port 80.' },
      { label: 'Confirm on the server', detail: 'nginx is active and listening on 0.0.0.0:80 (`ss -tlnp`). The input chain has no rule for port 80 (`nft list ruleset`). Change log: firewall template updated yesterday.' },
      { label: 'Fix minimally', detail: 'Add the rule back in /etc/nftables.conf, `nft -c -f /etc/nftables.conf`, reload nftables.' },
      { label: 'Verify and record', detail: 'curl from ws01 returns 200. Reboot test in the window. Record cause, fix and evidence in the ticket.' },
    ],
  },
  misconceptions: [
    { myth: 'Rebooting is a good first step.', truth: 'It destroys evidence (runtime state, logs in memory) and may make things worse (a disabled service stays down). Look first.' },
    { myth: 'If it works again, the problem is solved.', truth: 'Only if you know why. Otherwise it returns, often at a worse time.' },
    { myth: 'Turning off the firewall is a valid temporary fix.', truth: 'It removes all protection and hides the real cause. Fix the specific rule.' },
  ],
  checks: [
    { q: 'What is the first question to ask about a new outage?', a: 'What changed (and when did it start)?' },
    { q: 'Why test from the client and not only on the server?', a: 'The user experiences the whole path (DNS, network, firewall); the server may look fine locally.' },
    { q: 'What proves a fix is complete?', a: 'It still works after a restart of the affected machines (the reboot test).' },
    { q: 'Name three things a good incident record contains.', a: 'Symptom, evidence, root cause, the fix, how it was verified (and prevention).' },
  ],
};
