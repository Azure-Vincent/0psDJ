// Group Policy tickets. win01 is a member of ad.corp.lab; the monitoring
// system (here: ws01) pings the servers, which Windows Defender Firewall blocks
// by default. The "Server Baseline" GPO carries a firewall rule that allows
// ICMP echo from 10.0.0.0/16. Each ticket breaks one step of policy
// processing: scope (the OU the computer is in), security filtering (the
// computer's token), inheritance (Block Inheritance), and the download from
// SYSVOL (SMB to the DC).

import { AD_ALICE_PASSWORD, DC01_ADMIN_PASSWORD } from '../lab/winLab';
import { findGpo, gpData } from '../win/gpo';
import { FW_PROFILES, type WinFwRule } from '../win/model';
import type { World } from '../types';
import { joinWin01 } from './domainScenarios';
import { script } from './engine';
import type { Constraint, Goal, Scenario } from './types';

const DN = 'DC=ad,DC=corp,DC=lab';
const SERVERS = `OU=Servers,${DN}`;

export const GPO_PING: Goal = {
  kind: 'command',
  description: 'The monitoring system pings win01: from ws01, ping win01.corp.lab gets a reply.',
  steps: [{ host: 'ws01', user: 'alice', command: 'ping -c 1 -W 1 win01.corp.lab' }],
  expect: '1 received',
};

const RDP: Goal = { kind: 'rdp', description: 'alice still logs on to win01 with Remote Desktop (CORP\\alice).', fromHost: 'ws01', localUser: 'alice', target: 'win01.corp.lab', user: 'CORP\\alice', password: AD_ALICE_PASSWORD };

/** The monitoring rule, as the Server Baseline GPO carries it (CHG-2401). */
export const PING_RULE = '-DisplayName "Monitoring - Echo Request (ICMPv4-In)" -Protocol ICMPv4 -IcmpType 8 -RemoteAddress 10.0.0.0/16 -Action Allow -Profile Domain';

const BRIEFING = [
  'ad.corp.lab (NetBIOS CORP): dc01 is the domain controller; win01 is a member server. Computers that are not moved elsewhere live in the default container CN=Computers; servers belong in OU=Servers (CHG-2400).',
  'Group Policy object "Server Baseline" (CHG-2401) allows ICMP echo requests from 10.0.0.0/16 in Windows Defender Firewall, so that the monitoring system can ping the servers. Members apply policy at startup and with gpupdate /force; gpresult /r shows what applied and why other GPOs did not.',
  `Tools: on dc01 (CORP\\Administrator, password ${DC01_ADMIN_PASSWORD}) Get-GPO, Get-GPInheritance, Get-GPPermission, Get-ADComputer, Move-ADObject, Set-GPLink, Set-GPInheritance; on win01 gpupdate /force, gpresult /r, Get-NetFirewallRule -PolicyStore RSOP, Get-WinEvent -LogName System.`,
  'Firewalls stay on everywhere; the rule must come from Group Policy (no local exception on win01); fixes must survive a restart of every machine.',
];

const TERMINALS = [
  { hostId: 'dc01', user: 'Administrator', label: 'dc01 console (PowerShell)', banner: 'Windows PowerShell\nCopyright (C) Microsoft Corporation. All rights reserved.\n\ndc01 console, signed in as CORP\\Administrator. Group Policy Management is installed. Try: Get-GPO -All, Get-GPInheritance -Target "OU=Servers,DC=ad,DC=corp,DC=lab", Get-ADComputer win01.' },
  { hostId: 'win01', user: 'Administrator', label: 'win01 console (PowerShell)', banner: 'Windows PowerShell\nCopyright (C) Microsoft Corporation. All rights reserved.\n\nwin01 console, signed in as the local Administrator. Try: gpresult /r, gpupdate /force, Get-NetFirewallRule -PolicyStore RSOP.' },
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01: the monitoring check. Try: ping -c 1 win01.corp.lab.' },
];

const CANDIDATES = ['gpo-wrong-ou', 'gpo-filter-token', 'gpo-blocked-inheritance', 'gpo-sysvol-unreachable', 'gpo-link-disabled', 'dom-member-dns'];

/** win01 joined; OU=Servers and the Server Baseline GPO with the monitoring rule. */
export function gpoBaseline(world: World, link = SERVERS): void {
  joinWin01(world);
  script(world, 'dc01', [
    `New-ADOrganizationalUnit -Name Servers -Path "${DN}" -Description "Member servers (CHG-2400)"`,
    'New-GPO -Name "Server Baseline" -Comment "CHG-2401: monitoring and hardening for member servers"',
    `New-NetFirewallRule -PolicyStore "ad.corp.lab\\Server Baseline" ${PING_RULE}`,
    `New-GPLink -Name "Server Baseline" -Target "${link}"`,
  ], 30_000);
}

export const moveWin01 = `Move-ADObject -Identity "CN=WIN01,CN=Computers,${DN}" -TargetPath "${SERVERS}"`;

/** A local (not policy) rule that lets ping in: an enabled inbound allow for ICMPv4 echo requests (type 8). */
const localPingRule = (r: WinFwRule) => r.enabled && r.action === 'Allow' && r.direction === 'Inbound' && (r.protocol === 'ICMPv4' || r.protocol === 'Any') && (r.icmpType === undefined || r.icmpType === 'Any' || r.icmpType.split(',').some((t) => t.split(':')[0] === '8'));

export function policyManaged(): Constraint {
  return {
    id: 'gpo-managed-firewall', required: true,
    description: 'Firewalls stay on (win01, dc01); win01 has no local rule allowing ping (it must come from "Server Baseline"), and the GPO\'s rule stays limited to 10.0.0.0/16.',
    check(world) {
      const bad: string[] = [];
      for (const h of ['win01', 'dc01']) for (const p of FW_PROFILES) { const pr = world.hosts[h].win!.firewall.profiles[p]; if (!pr.enabled || pr.defaultInbound !== 'Block') bad.push(`${h}: the ${p} profile is off or allows inbound by default`); }
      const local = world.hosts.win01.win!.firewall.rules.filter(localPingRule);
      if (local.length) bad.push(`win01: local rule "${local[0].displayName}" allows ping (policy should deliver it)`);
      const ad = world.hosts.dc01.win!.ad!;
      const g = findGpo(ad, 'Server Baseline');
      const rule = g?.firewallRules.find((r) => r.protocol === 'ICMPv4');
      if (!rule || rule.remoteAddress === 'Any') bad.push('"Server Baseline": its ICMP rule is missing or open to any address');
      return { id: this.id, ok: !bad.length, required: true, message: bad.length ? bad.join('; ') : 'Firewalls on; ping allowed by "Server Baseline" only, from 10.0.0.0/16.' };
    },
  };
}

function filteringKept(): Constraint {
  return {
    id: 'gpo-filtering-kept', required: true,
    description: '"Server Baseline" stays filtered to the group Baseline Servers (Authenticated Users keeps GpoRead only, as decided in CHG-2402).',
    check(world) {
      const g = findGpo(world.hosts.dc01.win!.ad!, 'Server Baseline');
      const p = g?.permissions ?? {};
      const au = Object.entries(p).find(([t]) => t.toLowerCase() === 'authenticated users')?.[1];
      const grp = Object.entries(p).find(([t]) => t.toLowerCase() === 'baseline servers')?.[1];
      const ok = au === 'GpoRead' && grp === 'GpoApply';
      return { id: this.id, ok, required: true, message: ok ? 'Server Baseline: Authenticated Users GpoRead, Baseline Servers GpoApply.' : `Server Baseline: security filtering changed (Authenticated Users ${au ?? 'none'}, Baseline Servers ${grp ?? 'none'}): fix the member, not the filter.` };
    },
  };
}

function lockdownStaysOff(): Constraint {
  return {
    id: 'gpo-servers-blocked', required: true,
    description: 'OU=Servers keeps Block Inheritance (Workstation Lockdown must not reach the servers) and Workstation Lockdown stays linked to the domain.',
    check(world) {
      const data = gpData(world.hosts.dc01.win!.ad!);
      const blocked = !!data.ous[SERVERS.toLowerCase()]?.blockInheritance;
      const lock = findGpo(world.hosts.dc01.win!.ad!, 'Workstation Lockdown');
      const linked = !!lock && (data.links[DN.toLowerCase()] ?? []).some((l) => l.gpoId === lock.id && l.enabled);
      const ok = blocked && linked;
      return { id: this.id, ok, required: true, message: ok ? 'OU=Servers blocks inheritance; Workstation Lockdown is linked to the domain.' : !blocked ? 'OU=Servers no longer blocks inheritance: Workstation Lockdown (no Remote Desktop) now reaches the servers.' : 'Workstation Lockdown was unlinked from the domain: the workstations lose their lockdown.' };
    },
  };
}

export const GPO_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'gpo-wrong-ou',
    title: 'Linked, but not to me',
    difficulty: 'beginner',
    ticket: 'Monitoring: "win01 shows DOWN since it was joined to the domain, but it is up and people use it. All the other servers answer our ping. The Server Baseline GPO (CHG-2401) should open ping for us; we ran gpupdate /force on win01 twice."',
    briefing: BRIEFING,
    goals: [GPO_PING],
    terminals: TERMINALS,
    setup(world) {
      gpoBaseline(world);
      script(world, 'win01', ['gpupdate /force', 'gpupdate /force']);
    },
    rootCauses: ['gpo-wrong-ou'],
    candidates: CANDIDATES,
    feedback: {
      'gpo-filter-token': 'Server Baseline keeps the default filtering (Authenticated Users: GpoApply), and gpresult does not even list it as filtered out.',
      'gpo-blocked-inheritance': 'Nothing blocks inheritance; and the GPO is linked to OU=Servers, not to the domain.',
      'gpo-sysvol-unreachable': 'gpupdate /force completes successfully on win01.',
      'gpo-link-disabled': 'The link on OU=Servers is enabled (Get-GPInheritance).',
      'dom-member-dns': 'win01 finds dc01 (gpupdate and gpresult name it as the source).',
    },
    hints: [
      'On win01, gpresult /r: which GPOs applied, and what is the computer\'s DN under COMPUTER SETTINGS?',
      'Server Baseline is linked to OU=Servers (Get-GPInheritance -Target "OU=Servers,DC=ad,DC=corp,DC=lab"), but WIN01 is in CN=Computers: GPOs apply to the objects in (or below) the OU they are linked to. CN=Computers is a container, not an OU: nothing can be linked to it.',
      `On dc01: ${moveWin01}; then on win01 gpupdate /force and gpresult /r.`,
    ],
    explanation: {
      rootCause: 'win01 was joined without -OUPath and stayed in the default CN=Computers container. Server Baseline is linked to OU=Servers, so it is not in win01\'s scope.',
      manifestation: 'gpupdate succeeds (there is nothing wrong with policy processing), but gpresult lists only Default Domain Policy; the firewall never gets the monitoring rule, so ping times out while everything else works.',
      evidence: 'gpresult /r on win01: CN=WIN01,CN=Computers,DC=ad,DC=corp,DC=lab and only Default Domain Policy applied; Get-ADComputer win01: the same DN; Get-GPInheritance -Target "OU=Servers,...": GpoLinks {Server Baseline}.',
      prevention: 'Join servers straight into their OU (Add-Computer -OUPath), or redirect the default computer container (redircmp) to an OU that has a baseline; check gpresult /r after every join.',
    },
    solution: [{ host: 'dc01', user: 'Administrator', commands: [moveWin01] }, { host: 'win01', user: 'Administrator', commands: ['gpupdate /force'] }],
    constraints: [policyManaged()],
    concepts: ['ad.gpo'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'gpo-filter-token',
    title: 'Member since yesterday',
    difficulty: 'intermediate',
    ticket: 'Windows team: "Since CHG-2402 Server Baseline only applies to the group Baseline Servers (some appliances must not get it). We added WIN01 to the group yesterday, and gpupdate /force runs without error, but gpresult still says Denied (Security) and monitoring still cannot ping it."',
    briefing: [...BRIEFING, 'CHG-2402: Server Baseline is filtered to the AD group "Baseline Servers": Authenticated Users keeps GpoRead (computers must be able to read every GPO), Baseline Servers has GpoApply.'],
    goals: [GPO_PING],
    terminals: TERMINALS,
    setup(world) {
      gpoBaseline(world);
      script(world, 'dc01', [
        moveWin01,
        'New-ADGroup -Name "Baseline Servers" -GroupScope Global -Description "Computers that get the Server Baseline GPO (CHG-2402)"',
        'Set-GPPermission -Name "Server Baseline" -TargetName "Baseline Servers" -TargetType Group -PermissionLevel GpoApply',
        'Set-GPPermission -Name "Server Baseline" -TargetName "Authenticated Users" -TargetType Group -PermissionLevel GpoRead -Replace',
      ], 30_000);
      script(world, 'win01', ['gpupdate /force']);
      world.clock += 3600_000;
      script(world, 'dc01', ['Add-ADGroupMember -Identity "Baseline Servers" -Members "WIN01$"']);
      script(world, 'win01', ['gpupdate /force', 'gpupdate /force']);
    },
    rootCauses: ['gpo-filter-token'],
    candidates: CANDIDATES,
    feedback: {
      'gpo-wrong-ou': 'WIN01 is in OU=Servers (gpresult shows the DN), and Server Baseline is in scope: it is listed as filtered out.',
      'gpo-blocked-inheritance': 'The GPO is linked to OU=Servers itself; inheritance is not involved.',
      'gpo-sysvol-unreachable': 'gpupdate /force completes without errors.',
      'gpo-link-disabled': 'The link is enabled, and gpresult lists the GPO as Denied (Security), not missing.',
      'dom-member-dns': 'win01 reaches dc01 for policy without problems.',
    },
    hints: [
      'gpresult /r on win01: Server Baseline is "Filtering: Denied (Security)". Look at the end: which security groups does gpresult say the computer belongs to?',
      'Baseline Servers is not in the list, although Get-ADGroupMember "Baseline Servers" on dc01 shows WIN01$. A computer\'s group memberships come from its Kerberos ticket, obtained when it starts; gpupdate does not get a new one.',
      'Restart win01 (Restart-Computer). Its new ticket carries Baseline Servers, and startup policy applies Server Baseline. Do not "fix" it by giving Authenticated Users GpoApply.',
    ],
    explanation: {
      rootCause: 'WIN01$ was added to Baseline Servers after win01 had started. Security filtering is evaluated with the groups in the computer\'s token (its Kerberos ticket from startup), which does not contain the new group until the computer obtains a new ticket.',
      manifestation: 'Policy processing works and finds Server Baseline in scope, but filters it out as Denied (Security); repeating gpupdate /force changes nothing, which makes the change look broken.',
      evidence: 'gpresult /r on win01: "Server Baseline - Filtering: Denied (Security)" and no CORP\\Baseline Servers among the computer\'s security groups; Get-ADGroupMember "Baseline Servers": WIN01$; Get-GPPermission -Name "Server Baseline" -All: Baseline Servers GpoApply.',
      prevention: 'Plan a restart after changing a computer\'s groups (or purge the computer\'s tickets: klist -li 0x3e7 purge), and keep Read for Authenticated Users or Domain Computers on every filtered GPO (MS16-072).',
    },
    solution: [{ host: 'win01', user: 'Administrator', commands: ['Restart-Computer -Force'] }],
    constraints: [policyManaged(), filteringKept()],
    concepts: ['ad.gpo', 'ad.kerberos'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'gpo-blocked-inheritance',
    title: 'Blocked too well',
    difficulty: 'intermediate',
    ticket: 'Monitoring: "win01 stopped answering ping after last night\'s patch reboot." Windows team: "Yesterday we blocked inheritance on OU=Servers so that Workstation Lockdown (it disables Remote Desktop) stops hitting the servers (CHG-2405). That was the only change, and Remote Desktop to win01 works again."',
    briefing: [...BRIEFING.slice(0, 1), 'The monitoring rule is in the GPO "Corp Security Baseline", linked to the domain root so that every computer gets it. "Workstation Lockdown" (Remote Desktop off) is also linked to the domain root, because the workstations still live in CN=Computers.', ...BRIEFING.slice(2)],
    goals: [GPO_PING, RDP],
    terminals: TERMINALS,
    setup(world) {
      joinWin01(world);
      script(world, 'dc01', [
        `New-ADOrganizationalUnit -Name Servers -Path "${DN}"`,
        moveWin01,
        'New-GPO -Name "Corp Security Baseline" -Comment "CHG-2401: monitoring for every computer"',
        `New-NetFirewallRule -PolicyStore "ad.corp.lab\\Corp Security Baseline" ${PING_RULE}`,
        `New-GPLink -Name "Corp Security Baseline" -Target "${DN}"`,
        'New-GPO -Name "Workstation Lockdown"',
        'Set-GPRegistryValue -Name "Workstation Lockdown" -Key "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -ValueName fDenyTSConnections -Type DWord -Value 1',
        `New-GPLink -Name "Workstation Lockdown" -Target "${DN}"`,
        `Set-GPInheritance -Target "${SERVERS}" -IsBlocked Yes`,
      ], 30_000);
      script(world, 'win01', ['Restart-Computer -Force']);
    },
    rootCauses: ['gpo-blocked-inheritance'],
    candidates: CANDIDATES,
    feedback: {
      'gpo-wrong-ou': 'WIN01 is in OU=Servers; and the monitoring GPO is linked to the domain root, which covers every OU.',
      'gpo-filter-token': 'Corp Security Baseline keeps the default filtering (Authenticated Users: GpoApply).',
      'gpo-sysvol-unreachable': 'gpupdate /force succeeds on win01.',
      'gpo-link-disabled': 'The domain link of Corp Security Baseline is enabled: it still applies to dc01.',
      'dom-member-dns': 'win01 finds dc01 and processes policy.',
    },
    hints: [
      'gpresult /r on win01: which domain-level GPOs are missing? Compare with Get-GPInheritance -Target "OU=Servers,DC=ad,DC=corp,DC=lab" (GpoInheritanceBlocked, InheritedGpoLinks).',
      'Block Inheritance stops every non-enforced link above the OU, the wanted one (Corp Security Baseline) as well as the unwanted one (Workstation Lockdown). Unblocking would bring Remote Desktop\'s lockdown back.',
      `Enforce the link of the GPO that must reach everything: Set-GPLink -Name "Corp Security Baseline" -Target "${DN}" -Enforced Yes (enforced links pass Block Inheritance); then gpupdate /force on win01.`,
    ],
    explanation: {
      rootCause: 'Block Inheritance on OU=Servers stops all non-enforced GPOs linked above it. It was meant for Workstation Lockdown but also stopped Corp Security Baseline, which carries the monitoring rule.',
      manifestation: 'At the next restart win01 processed policy without the domain GPOs and removed the rule they had delivered: ping times out. Remote Desktop works, which looks like the change succeeded.',
      evidence: 'Get-GPInheritance -Target "OU=Servers,...": GpoInheritanceBlocked Yes, InheritedGpoLinks without Corp Security Baseline; gpresult /r on win01: only GPOs linked at or below OU=Servers (and enforced ones); Get-NetFirewallRule -PolicyStore RSOP: no monitoring rule.',
      prevention: 'Prefer targeted links (link Workstation Lockdown to a Workstations OU) over Block Inheritance; mark baseline GPOs that must reach everything as Enforced; check gpresult on a sample computer after changing inheritance.',
    },
    solution: [{ host: 'dc01', user: 'Administrator', commands: [`Set-GPLink -Name "Corp Security Baseline" -Target "${DN}" -Enforced Yes`] }, { host: 'win01', user: 'Administrator', commands: ['gpupdate /force'] }],
    constraints: [lockdownStaysOff(), {
      id: 'gpo-managed-firewall-cs', required: true,
      description: 'Firewalls stay on; win01 has no local rule allowing ping (it must come from "Corp Security Baseline").',
      check(world) {
        const local = world.hosts.win01.win!.firewall.rules.some(localPingRule);
        const off = FW_PROFILES.some((p) => !world.hosts.win01.win!.firewall.profiles[p].enabled);
        const ok = !local && !off;
        return { id: this.id, ok, required: true, message: ok ? 'win01: firewall on, ping allowed by policy only.' : off ? 'win01: a firewall profile is off.' : 'win01: a local rule allows ping: the monitoring rule must come from Group Policy.' };
      },
    }],
    concepts: ['ad.gpo'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'gpo-sysvol-blocked',
    title: 'Policy that never arrives',
    difficulty: 'advanced',
    ticket: 'Windows team: "We added the monitoring rule to Server Baseline this morning (CHG-2406), but win01 does not get it. gpupdate /force on win01 now prints an error about gpt.ini. Logons with domain accounts work fine. Last week dc01 was hardened (SEC-152: domain controllers host no file shares)."',
    briefing: BRIEFING,
    goals: [GPO_PING],
    terminals: TERMINALS,
    setup(world) {
      joinWin01(world);
      script(world, 'dc01', [
        `New-ADOrganizationalUnit -Name Servers -Path "${DN}"`,
        moveWin01,
        'New-GPO -Name "Server Baseline" -Comment "CHG-2401: member server baseline"',
        `New-GPLink -Name "Server Baseline" -Target "${SERVERS}"`,
        'Disable-NetFirewallRule -Name FPS-SMB-In-TCP',
      ], 30_000);
      world.clock += 3 * 3600_000;
      script(world, 'dc01', [`New-NetFirewallRule -PolicyStore "ad.corp.lab\\Server Baseline" ${PING_RULE}`]);
      script(world, 'win01', ['gpupdate /force']);
    },
    rootCauses: ['gpo-sysvol-unreachable'],
    candidates: CANDIDATES,
    feedback: {
      'gpo-wrong-ou': 'WIN01 is in OU=Servers where Server Baseline is linked; processing fails before scope matters.',
      'gpo-filter-token': 'Filtering is the default (Authenticated Users: GpoApply), and processing fails before filtering.',
      'gpo-blocked-inheritance': 'The GPO is linked to the OU itself.',
      'gpo-link-disabled': 'The link is enabled; the error is about reading a file.',
      'dom-member-dns': 'win01 locates dc01 (logons work, and the error names dc01\'s SYSVOL path).',
    },
    hints: [
      'gpupdate /force on win01 and the System log (Get-WinEvent -LogName System -MaxEvents 5): event 1058, the gpt.ini path. How does a member read \\\\ad.corp.lab\\SYSVOL?',
      'SYSVOL is an SMB share on every DC: reading it needs TCP 445. Test-NetConnection dc01.ad.corp.lab -Port 445 from win01. On dc01: Get-NetFirewallRule -Name FPS-SMB-In-TCP.',
      'SEC-152 disabled "File and Printer Sharing (SMB-In)" on dc01. A DC must serve SYSVOL and NETLOGON: Enable-NetFirewallRule -Name FPS-SMB-In-TCP on dc01, then gpupdate /force on win01.',
    ],
    explanation: {
      rootCause: 'The hardening SEC-152 disabled the SMB-In firewall rule on dc01 ("no file shares on DCs"), but every DC shares SYSVOL (GPO files) and NETLOGON (logon scripts) over SMB.',
      manifestation: 'Members still find the DC (DNS, LDAP) and logons still work (Kerberos/NTLM), so the DC looks healthy. Policy processing fails when it reads the GPOs\' gpt.ini from SYSVOL: event 1058, and no GPO change reaches any member; settings applied before the hardening stay in place.',
      evidence: 'gpupdate /force on win01: "Windows attempted to read the file \\\\ad.corp.lab\\sysvol\\ad.corp.lab\\Policies\\{...}\\gpt.ini ... not successful"; System log: GroupPolicy 1058; Test-NetConnection dc01.ad.corp.lab -Port 445: TcpTestSucceeded False; dc01: FPS-SMB-In-TCP Enabled False.',
      prevention: 'Know which ports a DC must serve (53, 88, 135 + RPC, 389, 445, 464, 636, 3268) before hardening it; test gpupdate on a member after any DC firewall change; monitor GroupPolicy 1058/1030 events.',
    },
    solution: [{ host: 'dc01', user: 'Administrator', commands: ['Enable-NetFirewallRule -Name FPS-SMB-In-TCP'] }, { host: 'win01', user: 'Administrator', commands: ['gpupdate /force'] }],
    constraints: [policyManaged()],
    concepts: ['ad.gpo', 'fw.path'],
  },
];
