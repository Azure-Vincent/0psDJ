// Windows Defender Firewall tickets on win01. Each fault is one way the
// firewall's decision differs from what the admin meant: a Program condition
// that names the wrong process, a Block rule that beats every Allow rule, a
// RemoteAddress scope that no longer matches the sender, outbound filtering
// with a missing exception, and Group Policy that switches off local rules.
// The firewall log (pfirewall.log) and the rule's filters are the evidence.

import { AD_ALICE_PASSWORD, DC01_ADMIN_PASSWORD, WIN01_ALICE_PASSWORD } from '../lab/winLab';
import { FS01_SMB_PASSWORDS } from '../lab/nfsLab';
import type { World } from '../types';
import { findGpo } from '../win/gpo';
import { effectiveProfile, FW_PROFILES, type WinFwRule } from '../win/model';
import { joinWin01 } from './domainScenarios';
import { script } from './engine';
import type { Constraint, Goal, Scenario } from './types';

const DN = 'DC=ad,DC=corp,DC=lab';
const SERVERS = `OU=Servers,${DN}`;
const DANA = FS01_SMB_PASSWORDS.dana;

const WEB: Goal = { kind: 'http', description: 'From ws01, "curl -I http://win01.corp.lab/" (the intranet site on win01\'s IIS) returns HTTP 200.', fromHost: 'ws01', fromUser: 'alice', url: 'http://win01.corp.lab/' };
const RDP: Goal = { kind: 'rdp', description: 'From ws01, alice connects to win01.corp.lab with Remote Desktop and gets a desktop session.', fromHost: 'ws01', localUser: 'alice', target: 'win01.corp.lab', user: 'alice', password: WIN01_ALICE_PASSWORD };
const DOMAIN_RDP: Goal = { kind: 'rdp', description: 'alice still logs on to win01 with Remote Desktop (CORP\\alice).', fromHost: 'ws01', localUser: 'alice', target: 'win01.corp.lab', user: 'CORP\\alice', password: AD_ALICE_PASSWORD };
const PING: Goal = {
  kind: 'command',
  description: 'The monitoring check passes: from ws01 (10.0.10.25), ping win01.corp.lab gets a reply.',
  steps: [{ host: 'ws01', user: 'alice', command: 'ping -c 1 -W 1 win01.corp.lab' }],
  expect: '1 received',
};
const REPORT_COPY: Goal = {
  kind: 'command',
  description: 'win01 reaches the file share: "net use \\\\fs01\\office /user:dana ..." completes successfully (the nightly report job maps it, copies, and disconnects).',
  steps: [
    { host: 'win01', user: 'Administrator', command: `net use \\\\fs01\\office /user:dana ${DANA}` },
    { host: 'win01', user: 'Administrator', command: 'net use \\\\fs01\\office /delete' },
  ],
  expect: 'was deleted successfully',
};

const TERMINALS = [
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01, Alice\'s Debian workstation (10.0.10.25), also the monitoring host. Try: curl -I http://win01.corp.lab/, nc -zv -w 3 win01 3389, ping -c 1 win01.' },
  { hostId: 'win01', user: 'Administrator', label: 'win01 console (PowerShell)', banner: 'Windows PowerShell\nCopyright (C) Microsoft Corporation. All rights reserved.\n\nwin01 console (hypervisor), signed in as WIN01\\Administrator. Try: Get-NetFirewallProfile, Get-NetFirewallRule -Enabled True -Direction Inbound, Get-NetTCPConnection -State Listen, Get-Content C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log -Tail 20.' },
];

const BRIEFING = [
  'win01 (10.0.20.30) is a Windows Server 2022 member of the server VLAN (workgroup, local accounts). It runs IIS (the intranet site on port 80), Remote Desktop, SMB and WinRM. ws01 (10.0.10.25) is both an admin workstation and the monitoring host.',
  'Windows Defender Firewall is the only filter on the path that concerns these tickets: rtr01 forwards between the VLANs without filtering.',
  'Windows Defender Firewall must stay on for every profile with inbound traffic blocked by default. The firewall log is off by default: Set-NetFirewallProfile -All -LogBlocked True turns on logging of dropped packets to C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log. Fixes must survive a restart of win01.',
];

const CANDIDATES = ['wfw-program-mismatch', 'wfw-block-precedence', 'wfw-remote-scope', 'wfw-outbound-default', 'wfw-local-rules-ignored', 'win-rdp-firewall', 'win-rdp-profile'];

function ps(world: World, lines: string[], host = 'win01') {
  script(world, host, lines, 60_000);
}

/** Every profile on and blocking inbound by default, in the settings in force (local and Group Policy). */
function firewallOn(hosts = ['win01']): Constraint {
  return {
    id: 'wfw-firewall-on', required: true,
    description: 'Windows Defender Firewall stays enabled on every profile, blocking unsolicited inbound traffic by default.',
    check(world) {
      const bad = hosts.flatMap((h) => FW_PROFILES.filter((p) => { const e = effectiveProfile(world.hosts[h], p); return !e.enabled || e.defaultInbound !== 'Block'; }).map((p) => `${h} ${p}`));
      return { id: this.id, ok: !bad.length, required: true, message: bad.length ? `Firewall off or open by default: ${bad.join(', ')}. Every port is now reachable, not just the one the ticket needed.` : 'The firewall is on for all profiles, default inbound action Block.' };
    },
  };
}

const coversPort = (r: WinFwRule, port: string) => r.localPort === 'Any' || r.localPort.some((p) => { const [a, b] = p.split('-').map(Number); return Number(port) >= a && Number(port) <= (b ?? a); });
const inboundAllow = (r: WinFwRule) => r.enabled && r.direction === 'Inbound' && r.action === 'Allow';

function webRulesNamePrograms(): Constraint {
  return {
    id: 'wfw-web-program', required: true,
    description: 'SEC-44 stays in force: every enabled inbound allow rule for TCP 80 on win01 names the program that receives the traffic.',
    check(world) {
      const open = world.hosts.win01.win!.firewall.rules.filter((r) => inboundAllow(r) && (r.protocol === 'TCP' || r.protocol === 'Any') && coversPort(r, '80') && !r.program);
      return { id: this.id, ok: !open.length, required: true, message: open.length ? `Rule "${open[0].displayName}" allows TCP 80 for any program: SEC-44 asks for the program to be named (for IIS it is System, the owner of http.sys).` : 'The web rule names its program.' };
    },
  };
}

function rdpScoped(): Constraint {
  return {
    id: 'wfw-rdp-scoped', required: true,
    description: 'Remote Desktop stays limited to the internal networks (10.0.0.0/16): no enabled rule allows TCP 3389 from any address.',
    check(world) {
      const open = world.hosts.win01.win!.firewall.rules.filter((r) => inboundAllow(r) && (r.protocol === 'TCP' || r.protocol === 'Any') && coversPort(r, '3389') && r.remoteAddress === 'Any');
      return { id: this.id, ok: !open.length, required: true, message: open.length ? `Rule "${open[0].displayName}" allows RDP from any address: the logon screen is exposed to every network that reaches win01.` : 'RDP is allowed from 10.0.0.0/16 only.' };
    },
  };
}

function pingScoped(): Constraint {
  return {
    id: 'wfw-ping-scoped', required: true,
    description: 'Ping stays limited to the monitoring host or its subnet: no enabled rule allows ICMPv4 echo requests from any address.',
    check(world) {
      const open = world.hosts.win01.win!.firewall.rules.filter((r) => inboundAllow(r) && (r.protocol === 'ICMPv4' || r.protocol === 'Any') && r.remoteAddress === 'Any' && (r.protocol === 'Any' ? r.localPort === 'Any' : !r.icmpType || r.icmpType === 'Any' || r.icmpType.split(':')[0] === '8'));
      return { id: this.id, ok: !open.length, required: true, message: open.length ? `Rule "${open[0].displayName}" allows ping from any address (MON-12 allows the monitoring network only).` : 'Ping is allowed from the monitoring network only.' };
    },
  };
}

function egressKept(): Constraint {
  return {
    id: 'wfw-egress-block', required: true,
    description: 'SEC-60 stays in force: the default outbound action is Block on every profile, and no outbound allow rule opens every port to every address.',
    check(world) {
      const w = world.hosts.win01.win!;
      const bad = FW_PROFILES.filter((p) => effectiveProfile(world.hosts.win01, p).defaultOutbound !== 'Block');
      const wide = w.firewall.rules.find((r) => r.enabled && r.direction === 'Outbound' && r.action === 'Allow' && r.remoteAddress === 'Any' && (!r.remotePort || r.remotePort === 'Any') && r.localPort === 'Any' && !r.program);
      const ok = !bad.length && !wide;
      return { id: this.id, ok, required: true, message: bad.length ? `win01: the ${bad.join(', ')} profile allows outbound by default again: SEC-60 asks for outbound allow-listing.` : wide ? `win01: outbound rule "${wide.displayName}" allows everything, which undoes SEC-60.` : 'Outbound traffic is still allow-listed.' };
    },
  };
}

function policyFirewall(): Constraint {
  return {
    id: 'wfw-policy-only', required: true,
    description: 'CHG-2420 stays in force: "Server Firewall" applies to win01 and keeps AllowLocalFirewallRules False, so only rules from Group Policy count on servers.',
    check(world) {
      const g = findGpo(world.hosts.dc01.win!.ad!, 'Server Firewall');
      const gp = world.hosts.win01.win!.gp;
      const ok = !!g && g.firewallProfiles?.Domain?.allowLocalRules === false && !!gp?.applied.includes('Server Firewall');
      return { id: this.id, ok, required: true, message: ok ? '"Server Firewall" applies to win01; local rules stay switched off.' : '"Server Firewall" no longer applies to win01, or it lets local rules count again: any admin can open ports on the servers outside change control.' };
    },
  };
}

/** win01 joined and in OU=Servers, which "Server Firewall" (rules + AllowLocalFirewallRules False) is linked to. */
function serverFirewallGpo(world: World): void {
  joinWin01(world);
  const store = '-PolicyStore "ad.corp.lab\\Server Firewall"';
  ps(world, [
    `New-ADOrganizationalUnit -Name Servers -Path "${DN}" -Description "Member servers (CHG-2400)"`,
    'New-GPO -Name "Server Firewall" -Comment "CHG-2420: server firewall policy; local rules are not merged"',
    `New-NetFirewallRule ${store} -DisplayName "Remote Desktop (TCP-In)" -Protocol TCP -LocalPort 3389 -RemoteAddress 10.0.0.0/16 -Action Allow -Profile Domain`,
    `New-NetFirewallRule ${store} -DisplayName "SMB (TCP-In)" -Protocol TCP -LocalPort 445 -RemoteAddress 10.0.0.0/16 -Action Allow -Profile Domain`,
    `New-NetFirewallRule ${store} -DisplayName "WinRM (HTTP-In)" -Protocol TCP -LocalPort 5985 -RemoteAddress 10.0.0.0/16 -Action Allow -Profile Domain`,
    `New-NetFirewallRule ${store} -DisplayName "Monitoring - Echo Request (ICMPv4-In)" -Protocol ICMPv4 -IcmpType 8 -RemoteAddress 10.0.10.0/24 -Action Allow -Profile Domain`,
    `Set-NetFirewallProfile ${store} -Profile Domain -Enabled True -DefaultInboundAction Block -AllowLocalFirewallRules False`,
    `New-GPLink -Name "Server Firewall" -Target "${SERVERS}"`,
    `Move-ADObject -Identity "CN=WIN01,CN=Computers,${DN}" -TargetPath "${SERVERS}"`,
  ], 'dc01');
  ps(world, ['gpupdate /force']);
}

export const WFW_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'wfw-program-mismatch',
    title: 'The application-scoped rule',
    difficulty: 'intermediate',
    ticket: 'Web team: "The intranet site on win01 times out since this morning. IIS is running and the site loads fine on the server itself. Security rolled out SEC-44 overnight (\'every firewall allow rule must name its program\')."',
    briefing: [...BRIEFING, 'SEC-44: every inbound allow rule on the servers names the program that receives the traffic, so that a port opened for one application cannot be used by another.'],
    goals: [WEB],
    terminals: TERMINALS,
    setup(world) {
      ps(world, ['Set-NetFirewallRule -Name IIS-WebServerRole-HTTP-In-TCP -Program "%SystemRoot%\\system32\\inetsrv\\w3wp.exe"']);
    },
    rootCauses: ['wfw-program-mismatch'],
    candidates: CANDIDATES,
    feedback: {
      'wfw-block-precedence': 'There is no Block rule for port 80: Get-NetFirewallRule -Action Block -Enabled True returns nothing.',
      'wfw-remote-scope': 'The web rule allows any remote address (Get-NetFirewallAddressFilter shows RemoteAddress Any).',
      'wfw-outbound-default': 'The default outbound action is Allow, and the problem is with packets coming in: the SYN from ws01 is dropped.',
      'wfw-local-rules-ignored': 'win01 is not in a domain: no Group Policy applies, and the other local rules (RDP, SMB) work.',
      'win-rdp-firewall': 'RDP works; the problem is the web rule.',
      'win-rdp-profile': 'Get-NetConnectionProfile shows Private, and the web rule applies to every profile.',
    },
    hints: [
      'A timeout means dropped packets. Turn on the firewall log (Set-NetFirewallProfile -All -LogBlocked True), try the site from ws01 again, and read the end of C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log: DROP TCP ... 80 ... RECEIVE.',
      'The web rule is enabled and allows TCP 80, so one of its other conditions does not match. Look at all of them: Get-NetFirewallRule -Name IIS-WebServerRole-HTTP-In-TCP | Get-NetFirewallApplicationFilter (and the port and address filters).',
      'It names w3wp.exe. Which process owns the socket on port 80? Get-NetTCPConnection -LocalPort 80 -State Listen shows OwningProcess 4: System. IIS listens through http.sys, in the kernel. Set the rule\'s program to System: Set-NetFirewallRule -Name IIS-WebServerRole-HTTP-In-TCP -Program System.',
    ],
    explanation: {
      rootCause: 'SEC-44 set the IIS rule\'s Program to %SystemRoot%\\system32\\inetsrv\\w3wp.exe, the IIS worker process. But the socket on port 80 belongs to http.sys, the kernel HTTP listener, which Windows reports as the process System (PID 4): w3wp.exe only receives requests from http.sys. A program condition matches the owner of the listening socket, so the rule matches nothing and the default inbound action (Block) drops the SYN.',
      manifestation: 'curl from ws01 times out; on win01 itself the site loads (loopback traffic is always allowed). The rule looks right at first glance: enabled, Allow, TCP 80, every profile.',
      evidence: 'pfirewall.log: DROP TCP 10.0.10.25 10.0.20.30 <port> 80 ... RECEIVE. Get-NetFirewallApplicationFilter on the rule: Program %SystemRoot%\\system32\\inetsrv\\w3wp.exe. Get-NetTCPConnection -LocalPort 80 -State Listen: OwningProcess 4 (System).',
      prevention: 'Before scoping a rule to a program, check which process owns the socket (Get-NetTCPConnection, netstat -ano). Kernel listeners (http.sys for IIS and WinRM, SMB) are "System". Test a firewall change from a client, not from the server itself.',
    },
    solution: [{ host: 'win01', user: 'Administrator', commands: ['Set-NetFirewallRule -Name IIS-WebServerRole-HTTP-In-TCP -Program System'] }],
    constraints: [firewallOn(), webRulesNamePrograms()],
    concepts: ['win.firewall', 'svc.listening'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'wfw-block-precedence',
    title: 'Allow first, then block',
    difficulty: 'intermediate',
    ticket: 'Alice: "Nobody can Remote Desktop to win01 since the security team\'s change SEC-52 yesterday. They say they added an exception for the internal networks before they added the block, so we should be fine. We aren\'t."',
    briefing: [...BRIEFING, 'SEC-52: after password spraying against Internet-facing servers, Remote Desktop must be reachable from the internal networks (10.0.0.0/16) only.'],
    goals: [RDP],
    terminals: TERMINALS,
    setup(world) {
      ps(world, [
        'Disable-NetFirewallRule -DisplayGroup "Remote Desktop"',
        'New-NetFirewallRule -DisplayName "SEC-52 RDP from internal networks" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress 10.0.0.0/16 -Action Allow',
        'New-NetFirewallRule -DisplayName "SEC-52 Block RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block',
      ]);
    },
    rootCauses: ['wfw-block-precedence'],
    candidates: CANDIDATES,
    feedback: {
      'wfw-program-mismatch': 'The allow rule names no program (Get-NetFirewallApplicationFilter: Program Any).',
      'wfw-remote-scope': 'ws01 (10.0.10.25) is inside 10.0.0.0/16: the allow rule\'s scope matches. Something else wins over it.',
      'wfw-outbound-default': 'The default outbound action is Allow; the SYN is dropped on its way in.',
      'wfw-local-rules-ignored': 'win01 is not in a domain; local rules count (the IIS rule works).',
      'win-rdp-firewall': 'An allow rule for 3389 exists and is enabled. The built-in rules being disabled is part of SEC-52, not the fault.',
      'win-rdp-profile': 'The SEC-52 rules apply to every profile.',
    },
    hints: [
      'TCP to 3389 times out. List every enabled rule that mentions 3389, with its action: Get-NetFirewallRule -Enabled True -Direction Inbound | Where-Object { ($_ | Get-NetFirewallPortFilter).LocalPort -eq 3389 } | Format-Table DisplayName, Action, Profile.',
      'There is an Allow rule and a Block rule. Windows Defender Firewall does not use rule order: when an Allow rule and a Block rule both match a packet, the Block rule wins.',
      'The Block rule is not needed at all: the default inbound action already blocks everything the allow rule does not cover. Remove it: Remove-NetFirewallRule -DisplayName "SEC-52 Block RDP". Do not re-enable the built-in rules (they allow any address).',
    ],
    explanation: {
      rootCause: 'SEC-52 added an Allow rule for 3389 from 10.0.0.0/16 and then a Block rule for 3389 from any address, expecting the first rule to take precedence as in a router ACL. Windows Defender Firewall evaluates by action, not by order: a matching Block rule always wins over a matching Allow rule (only authenticated-bypass rules beat it). Every RDP packet matches the Block rule.',
      manifestation: 'RDP and nc to 3389 time out from every network, including the internal ones the change meant to keep.',
      evidence: 'Get-NetFirewallRule -Action Block -Enabled True: "SEC-52 Block RDP", LocalPort 3389, RemoteAddress Any. With LogBlocked on, pfirewall.log shows DROP TCP 10.0.10.25 ... 3389 although the allow rule matches that address.',
      prevention: 'Build Windows firewall policy as an allow list: default inbound Block, Allow rules scoped by RemoteAddress. Use Block rules only for a narrow exception inside a broader allow (and scope them so they cannot catch the traffic you want).',
    },
    solution: [{ host: 'win01', user: 'Administrator', commands: ['Remove-NetFirewallRule -DisplayName "SEC-52 Block RDP"'] }],
    constraints: [firewallOn(), rdpScoped()],
    concepts: ['win.firewall', 'fw.stateful'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'wfw-remote-scope',
    title: 'The new monitoring host',
    difficulty: 'beginner',
    ticket: 'Monitoring team (MON-12): "We moved the monitoring checks to the new host ws01 (10.0.10.25) on Monday. Every server is green except win01, which shows DOWN (no ping reply), although its site and RDP are fine."',
    briefing: [...BRIEFING, 'MON-12: servers allow ICMP echo requests from the monitoring network only, never from any address. The monitoring network used to be 10.0.1.0/24; it is now 10.0.10.0/24.'],
    goals: [PING, WEB],
    terminals: TERMINALS,
    setup(world) {
      ps(world, ['New-NetFirewallRule -DisplayName "Monitoring - Echo Request (ICMPv4-In)" -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -RemoteAddress 10.0.1.0/24 -Action Allow']);
    },
    rootCauses: ['wfw-remote-scope'],
    candidates: CANDIDATES,
    feedback: {
      'wfw-program-mismatch': 'The monitoring rule names no program; ICMP has no listening socket anyway.',
      'wfw-block-precedence': 'There is no enabled Block rule (Get-NetFirewallRule -Action Block -Enabled True).',
      'wfw-outbound-default': 'The default outbound action is Allow, and the echo request is what gets dropped, on its way in.',
      'wfw-local-rules-ignored': 'win01 is not in a domain; local rules count (the IIS and RDP rules work).',
      'win-rdp-firewall': 'RDP works; only ping fails.',
      'win-rdp-profile': 'The monitoring rule applies to every profile, and the connection is Private.',
    },
    hints: [
      'The site and RDP work, so the path and the server are fine: the firewall drops the echo requests. Turn on the log (Set-NetFirewallProfile -All -LogBlocked True), wait for the next check (or ping from ws01) and read pfirewall.log: which source address do the dropped ICMP packets have?',
      'Find the rule meant to allow them and check every condition: Get-NetFirewallRule -DisplayName "Monitoring*" | Get-NetFirewallAddressFilter.',
      'RemoteAddress is the old monitoring network. Point it at the new one: Set-NetFirewallRule -DisplayName "Monitoring - Echo Request (ICMPv4-In)" -RemoteAddress 10.0.10.0/24 (or the host, 10.0.10.25). Do not enable the built-in echo rule: it allows any address.',
    ],
    explanation: {
      rootCause: 'The monitoring rule on win01 allows echo requests from RemoteAddress 10.0.1.0/24, the old monitoring network. The new monitoring host sends from 10.0.10.25, so no rule matches and the default inbound action drops the requests. The other servers had their rule updated with MON-12; win01 was missed.',
      manifestation: 'Monitoring shows win01 DOWN; ping from ws01 gets no reply ("100% packet loss"), while HTTP and RDP from the same host work.',
      evidence: 'pfirewall.log (with LogBlocked on): DROP ICMP 10.0.10.25 10.0.20.30 - - ... 8 0 - RECEIVE. Get-NetFirewallAddressFilter on the monitoring rule: RemoteAddress 10.0.1.0/24.',
      prevention: 'When a client moves, list the rules scoped to its old address (Get-NetFirewallAddressFilter | Where-Object RemoteAddress -match "10.0.1.") on every server; better, deliver such rules from one place (Group Policy) so one change updates all servers.',
    },
    solution: [{ host: 'win01', user: 'Administrator', commands: ['Set-NetFirewallRule -DisplayName "Monitoring - Echo Request (ICMPv4-In)" -RemoteAddress 10.0.10.0/24'] }],
    constraints: [firewallOn(), pingScoped()],
    concepts: ['win.firewall'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'wfw-outbound-default',
    title: 'Egress allow-listing',
    difficulty: 'intermediate',
    ticket: 'Finance: "The nightly report from win01 never arrived in the office share on fs01. The job log says \'System error 53, the network path was not found\'. Nothing changed on the share." (Security completed SEC-60, outbound filtering on servers, the same day.)',
    briefing: [...BRIEFING, `SEC-60: servers block outbound traffic by default and allow only what their role needs (here: DNS, HTTP/HTTPS to update mirrors, NTP). The report job on win01 maps \\\\fs01\\office (fs01, 10.0.20.60) as dana (password ${DANA}), copies the report, and disconnects.`],
    goals: [REPORT_COPY, WEB],
    terminals: TERMINALS,
    setup(world) {
      ps(world, [
        'New-NetFirewallRule -DisplayName "SEC-60 DNS (UDP-Out)" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow',
        'New-NetFirewallRule -DisplayName "SEC-60 DNS (TCP-Out)" -Direction Outbound -Protocol TCP -RemotePort 53 -Action Allow',
        'New-NetFirewallRule -DisplayName "SEC-60 Web (TCP-Out)" -Direction Outbound -Protocol TCP -RemotePort 80,443 -Action Allow',
        'New-NetFirewallRule -DisplayName "SEC-60 NTP (UDP-Out)" -Direction Outbound -Protocol UDP -RemotePort 123 -Action Allow',
        'Set-NetFirewallProfile -All -DefaultOutboundAction Block',
      ]);
    },
    rootCauses: ['wfw-outbound-default'],
    candidates: CANDIDATES,
    feedback: {
      'wfw-program-mismatch': 'No inbound rule is involved: win01 is the client here, and its own connection attempt is stopped.',
      'wfw-block-precedence': 'There is no Block rule (Get-NetFirewallRule -Action Block -Enabled True); the default outbound action does the blocking.',
      'wfw-remote-scope': 'The inbound rules are fine (the site works). The connection that fails starts on win01.',
      'wfw-local-rules-ignored': 'win01 is not in a domain; local rules count.',
      'win-rdp-firewall': 'RDP works; the failing connection goes out of win01.',
      'win-rdp-profile': 'Get-NetConnectionProfile shows Private, as always.',
    },
    hints: [
      'Reproduce it on win01: Test-NetConnection fs01 -Port 445. Name resolution works (DNS is allowed), the TCP connection fails. Is it the network, fs01, or win01 itself? From ws01, smbclient -L //fs01 -N works.',
      'The firewall filters outbound too. Get-NetFirewallProfile | Format-Table Name, DefaultInboundAction, DefaultOutboundAction, then the outbound rules: Get-NetFirewallRule -Direction Outbound -Enabled True | Get-NetFirewallPortFilter.',
      'SEC-60 allows DNS, web and NTP out, but not SMB. Add the exception the role needs, scoped to the file server: New-NetFirewallRule -DisplayName "SEC-60 SMB to fs01 (TCP-Out)" -Direction Outbound -Protocol TCP -RemotePort 445 -RemoteAddress 10.0.20.60 -Action Allow. Keep the default outbound action at Block.',
    ],
    explanation: {
      rootCause: 'SEC-60 set the default outbound action to Block on every profile and allowed only DNS, HTTP/HTTPS and NTP out. The report job connects from win01 to fs01 on TCP 445 (SMB), which no outbound rule allows, so win01 drops its own SYN before it leaves the server.',
      manifestation: 'net use \\\\fs01\\office fails with "System error 53 has occurred. The network path was not found."; Test-NetConnection fs01 -Port 445 fails, while the same test from other machines works and inbound services on win01 are fine.',
      evidence: 'Get-NetFirewallProfile: DefaultOutboundAction Block. The outbound rules allow remote ports 53, 80, 443, 123 only. With LogBlocked on, pfirewall.log shows DROP TCP 10.0.20.30 10.0.20.60 <port> 445 ... SEND (SEND: an outbound packet).',
      prevention: 'Before switching outbound to Block, inventory what each server connects to (LogAllowed for a few days, or the role\'s documentation): file shares, domain controllers, backup, monitoring agents, update servers. Roll out with logging on and review the SEND drops.',
    },
    solution: [{ host: 'win01', user: 'Administrator', commands: ['New-NetFirewallRule -DisplayName "SEC-60 SMB to fs01 (TCP-Out)" -Direction Outbound -Protocol TCP -RemotePort 445 -RemoteAddress 10.0.20.60 -Action Allow'] }],
    constraints: [firewallOn(), egressKept()],
    concepts: ['win.firewall', 'fw.stateful'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'wfw-local-rules-ignored',
    title: 'The rule that is there',
    difficulty: 'advanced',
    ticket: 'Web team: "The intranet site on win01 times out since yesterday\'s change CHG-2420 (servers moved into OU=Servers). The IIS firewall rule is right there, enabled, we checked twice. RDP still works."',
    briefing: [
      'ad.corp.lab (NetBIOS CORP): dc01 is the domain controller; win01 is a member server and was moved into OU=Servers with CHG-2420. It runs IIS (the intranet site on port 80), Remote Desktop, SMB and WinRM.',
      'CHG-2420: the GPO "Server Firewall", linked to OU=Servers, holds the servers\' firewall policy for the Domain profile and sets AllowLocalFirewallRules to False: on servers, only rules delivered by Group Policy count, so that nobody opens ports outside change control.',
      `Tools: on dc01 (CORP\\Administrator, password ${DC01_ADMIN_PASSWORD}) Get-GPO, Get-NetFirewallRule -PolicyStore "ad.corp.lab\\Server Firewall", New-NetFirewallRule -PolicyStore ...; on win01 gpupdate /force, gpresult /r, Get-NetFirewallRule -PolicyStore ActiveStore, Get-NetFirewallProfile -PolicyStore ActiveStore.`,
      'Firewalls stay on everywhere; fixes must survive a restart of every machine.',
    ],
    goals: [WEB, DOMAIN_RDP],
    terminals: [
      { hostId: 'dc01', user: 'Administrator', label: 'dc01 console (PowerShell)', banner: 'Windows PowerShell\nCopyright (C) Microsoft Corporation. All rights reserved.\n\ndc01 console, signed in as CORP\\Administrator. Group Policy Management is installed. Try: Get-GPO -All, Get-NetFirewallRule -PolicyStore "ad.corp.lab\\Server Firewall".' },
      { hostId: 'win01', user: 'Administrator', label: 'win01 console (PowerShell)', banner: 'Windows PowerShell\nCopyright (C) Microsoft Corporation. All rights reserved.\n\nwin01 console, signed in as the local Administrator. Try: gpresult /r, Get-NetFirewallProfile -PolicyStore ActiveStore, Get-NetFirewallRule -PolicyStore RSOP.' },
      { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01. Try: curl -I http://win01.corp.lab/, nc -zv -w 3 win01 3389.' },
    ],
    setup(world) {
      serverFirewallGpo(world);
    },
    rootCauses: ['wfw-local-rules-ignored'],
    candidates: CANDIDATES,
    feedback: {
      'wfw-program-mismatch': 'The local IIS rule names no program; and it would not count even if it were perfect.',
      'wfw-block-precedence': 'No Block rule exists, locally or in the GPO.',
      'wfw-remote-scope': 'The local IIS rule allows any address. The rule is not the problem: whether it counts is.',
      'wfw-outbound-default': 'The default outbound action is Allow; the inbound SYN to port 80 is dropped.',
      'win-rdp-firewall': 'RDP works, through the GPO\'s rule.',
      'win-rdp-profile': 'The connection is in the Domain profile (win01 reaches its DC), which is where the policy applies.',
    },
    hints: [
      'The local rule is enabled and correct (Get-NetFirewallRule -Name IIS-WebServerRole-HTTP-In-TCP). So ask what is in force, not what is stored locally: Get-NetFirewallProfile -Name Domain -PolicyStore ActiveStore | Format-List Enabled, DefaultInboundAction, AllowLocalFirewallRules.',
      'AllowLocalFirewallRules False: Group Policy switched off every local rule. Only the GPO\'s rules count: Get-NetFirewallRule -PolicyStore RSOP | Format-Table DisplayName, Enabled, Action. Is there one for port 80?',
      'Add the rule where it counts, in the GPO, on dc01: New-NetFirewallRule -PolicyStore "ad.corp.lab\\Server Firewall" -DisplayName "Web (HTTP-In)" -Protocol TCP -LocalPort 80 -Action Allow -Profile Domain. Then gpupdate /force on win01. Do not re-enable local rules: that is the point of CHG-2420.',
    ],
    explanation: {
      rootCause: 'CHG-2420 moved win01 into OU=Servers, where the GPO "Server Firewall" applies. It sets AllowLocalFirewallRules False for the Domain profile: from then on only firewall rules delivered by Group Policy are enforced, and every local rule, including the IIS rule that allowed port 80, is ignored. The GPO carries rules for RDP, SMB, WinRM and monitoring, but none for the web site.',
      manifestation: 'HTTP to win01 times out while RDP works. On win01, Get-NetFirewallRule shows the IIS rule enabled with Action Allow, which makes the firewall look correct: the local store says nothing about whether local rules are merged.',
      evidence: 'gpresult /r: "Server Firewall" applied. Get-NetFirewallProfile -Name Domain -PolicyStore ActiveStore: AllowLocalFirewallRules False (the default PersistentStore view says NotConfigured). Get-NetFirewallRule -PolicyStore RSOP: no rule for TCP 80.',
      prevention: 'When local rule merging is off, every application port needs a rule in the GPO before the server moves into the OU: compare the server\'s listening ports (Get-NetTCPConnection -State Listen) with the GPO\'s rules as part of the change. Read firewall state with -PolicyStore ActiveStore, which shows what is enforced.',
    },
    solution: [
      { host: 'dc01', user: 'Administrator', commands: ['New-NetFirewallRule -PolicyStore "ad.corp.lab\\Server Firewall" -DisplayName "Web (HTTP-In)" -Protocol TCP -LocalPort 80 -Action Allow -Profile Domain'] },
      { host: 'win01', user: 'Administrator', commands: ['gpupdate /force'] },
    ],
    constraints: [firewallOn(['win01', 'dc01']), policyFirewall()],
    concepts: ['win.firewall', 'ad.gpo'],
  },
];
