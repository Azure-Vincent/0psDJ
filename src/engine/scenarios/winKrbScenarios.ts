// Kerberos for Windows logons. Domain logons on win01 use Kerberos with dc01's
// KDC: NLA from ws01 is NTLM, but the logon itself (and Group Policy, which
// binds to LDAP as the computer) needs tickets. Two tickets break time (the
// member's clock leaves the 5-minute window: Windows Time disabled, NTP to the
// DC blocked); two break the KDC (port 88 blocked, the Kdc service stopped),
// where logons quietly fall back to NTLM and only Kerberos-only work fails.

import { AD_ALICE_PASSWORD, DC01_ADMIN_PASSWORD, DC01_IP } from '../lab/winLab';
import { ntpExchange, ntpSynced } from '../sim/ntp';
import type { World } from '../types';
import { FW_PROFILES } from '../win/model';
import { joinWin01 } from './domainScenarios';
import { script } from './engine';
import { GPO_PING, gpoBaseline, moveWin01, policyManaged } from './gpoScenarios';
import type { Constraint, Goal, Scenario } from './types';

const RDP: Goal = { kind: 'rdp', description: 'From ws01, alice logs on to win01 with her domain account ("xfreerdp /v:win01.corp.lab /u:CORP\\alice").', fromHost: 'ws01', localUser: 'alice', target: 'win01.corp.lab', user: 'CORP\\alice', password: AD_ALICE_PASSWORD };

const BRIEFING = [
  'ad.corp.lab (NetBIOS CORP): dc01 is the domain controller (AD DS, DNS, the Kerberos KDC) and the domain\'s time source; win01 is a member server. ws01 is Alice\'s workstation; she uses Remote Desktop to win01 with CORP\\alice.',
  'Domain logons use Kerberos: the member gets a ticket-granting ticket for the user from the KDC on dc01 (TCP/UDP 88), then a ticket for itself. Kerberos refuses clocks more than 5 minutes apart; members keep their time from the DC with the Windows Time service (W32Time, NTP on UDP 123). If no KDC answers, Windows falls back to NTLM where it can; Group Policy cannot.',
  `Tools: on dc01 (CORP\\Administrator, password ${DC01_ADMIN_PASSWORD}) Get-Service Kdc, Get-NetFirewallRule, Get-WinEvent -LogName Security (4768/4769/4771), klist, setspn; on win01 klist -li 0x3e7, w32tm /query /status, w32tm /stripchart /computer:dc01 /samples:1 /dataonly, w32tm /resync, Get-Date, gpupdate /force, Get-WinEvent -LogName System; on ws01 xfreerdp (+auth-only checks NLA only).`,
  'Firewalls stay on everywhere; time comes from dc01 through W32Time (no manually set clocks); fixes must survive a restart of every machine.',
];

const TERMINALS = [
  { hostId: 'dc01', user: 'Administrator', label: 'dc01 console (PowerShell)', banner: 'Windows PowerShell\nCopyright (C) Microsoft Corporation. All rights reserved.\n\ndc01 console, signed in as CORP\\Administrator. Domain controller, DNS server, KDC and time source of ad.corp.lab. Try: Get-Service Kdc, W32Time; Get-WinEvent -LogName Security -MaxEvents 5; klist.' },
  { hostId: 'win01', user: 'Administrator', label: 'win01 console (PowerShell)', banner: 'Windows PowerShell\nCopyright (C) Microsoft Corporation. All rights reserved.\n\nwin01 console, signed in as the local Administrator (no Kerberos tickets of its own; the computer\'s are in session 0x3e7). Try: klist -li 0x3e7, w32tm /query /status, Get-Date, gpupdate /force.' },
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: `ws01, Alice's Debian workstation. Her domain account is CORP\\alice (password ${AD_ALICE_PASSWORD}). Try: xfreerdp /v:win01.corp.lab /u:CORP\\\\alice, or with +auth-only to test NLA alone.` },
];

const CANDIDATES = ['krb-w32time-disabled', 'krb-dc-ntp-blocked', 'krb-dc-kdc-blocked', 'krb-kdc-stopped', 'dom-member-dns', 'dom-dc-firewall', 'dom-trust-broken', 'win-wrong-password', 'gpo-wrong-ou'];

function firewallsOn(): Constraint {
  return {
    id: 'krb-firewalls-on', required: true,
    description: 'Windows Defender Firewall stays enabled on win01 and dc01 for every profile, blocking unsolicited inbound traffic by default.',
    check(world) {
      const bad = ['win01', 'dc01'].flatMap((h) => FW_PROFILES.filter((p) => !world.hosts[h].win!.firewall.profiles[p].enabled || world.hosts[h].win!.firewall.profiles[p].defaultInbound !== 'Block').map((p) => `${h} ${p}`));
      return { id: this.id, ok: !bad.length, required: true, message: bad.length ? `Firewall off or open by default: ${bad.join(', ')}.` : 'win01 and dc01: the firewall is on for all profiles, default inbound action Block.' };
    },
  };
}

/** win01 keeps its time from dc01: W32Time automatic and running, and an NTP exchange with dc01 succeeds. */
function timeFromDc(): Constraint {
  return {
    id: 'krb-time-from-dc', required: true,
    description: 'win01 keeps its time from dc01: the Windows Time service starts automatically and runs, and win01 gets NTP answers from dc01 (a clock set by hand drifts again). dc01 keeps its own clock.',
    check(world) {
      const win01 = world.hosts.win01;
      const s = win01.win!.services.W32Time;
      const bad: string[] = [];
      if (!s || s.startType !== 'Automatic' || s.status !== 'Running') bad.push(`win01: W32Time is ${s?.status ?? 'missing'} (${s?.startType ?? '-'}), so nothing corrects the clock`);
      // One NTP exchange (ntpExchange restores the world clock afterwards).
      const x = ntpExchange(world, win01, DC01_IP);
      if (x.kind !== 'reply' || !ntpSynced(x.reply)) bad.push('win01 gets no NTP answer from dc01 (UDP 123)');
      if (Math.abs(world.hosts.dc01.clockOffset ?? 0) > 60_000) bad.push('dc01\'s clock was changed: it is the domain\'s time source');
      return { id: this.id, ok: !bad.length, required: true, message: bad.length ? bad.join('; ') : 'win01 synchronises with dc01 (W32Time automatic, NTP answers); dc01 keeps its clock.' };
    },
  };
}

/** The KDC is reachable from members: Kdc automatic and running, its firewall rules enabled. */
function kdcAvailable(): Constraint {
  return {
    id: 'krb-kdc-available', required: true,
    description: 'dc01 offers Kerberos: the Kdc service starts automatically and runs, and the "Kerberos Key Distribution Center" firewall rules (TCP and UDP 88) are enabled.',
    check(world) {
      const w = world.hosts.dc01.win!;
      const bad: string[] = [];
      const k = w.services.Kdc;
      if (!k || k.startType !== 'Automatic' || k.status !== 'Running') bad.push(`Kdc is ${k?.status ?? 'missing'} (${k?.startType ?? '-'})`);
      for (const n of ['KDC-TCP-In', 'KDC-UDP-In']) if (!w.firewall.rules.find((r) => r.name === n)?.enabled) bad.push(`rule ${n} disabled`);
      return { id: this.id, ok: !bad.length, required: true, message: bad.length ? `dc01: ${bad.join('; ')}.` : 'dc01: Kdc runs (Automatic) and both KDC firewall rules are enabled.' };
    },
  };
}

/** Time tickets: win01's clock is `minutes` ahead of the domain, and it restarted since. */
function skewWin01(world: World, minutes: number): void {
  world.hosts.win01.clockOffset = minutes * 60_000 + 23_000;
  script(world, 'win01', ['Restart-Computer -Force'], 60_000);
}

/** KDC tickets: win01 in OU=Servers with the monitoring GPO, then a DC change and a patch-night restart. */
function kdcBaseline(world: World, dcChange: string[]): void {
  gpoBaseline(world);
  script(world, 'dc01', dcChange, 30_000);
  script(world, 'dc01', [moveWin01], 30_000);
  script(world, 'win01', ['Restart-Computer -Force', 'gpupdate /force'], 60_000);
}

export const WIN_KRB_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'krb-w32time-disabled',
    title: 'In, and out again',
    difficulty: 'intermediate',
    ticket: 'Alice: "RDP to win01 takes my password, the session starts, and then it says \'There is a time and/or date difference between the client and server\' and logs me off." VM team (VM-77): "win01 moved to the new cluster on Friday; host time sync is off there, as agreed for domain members." A note from Friday\'s cleanup: "disabled services that were using CPU on win01".',
    briefing: BRIEFING,
    goals: [RDP],
    terminals: TERMINALS,
    setup(world) {
      joinWin01(world);
      script(world, 'win01', ['Set-Service W32Time -StartupType Disabled', 'Stop-Service W32Time']);
      skewWin01(world, 11);
    },
    rootCauses: ['krb-w32time-disabled'],
    candidates: CANDIDATES,
    feedback: {
      'krb-dc-ntp-blocked': 'NTP to dc01 works: w32tm /stripchart /computer:dc01 gets an answer (with the offset). win01 simply never asks: its time service is not running.',
      'krb-dc-kdc-blocked': 'The KDC answers: dc01 logs 4771 with failure code 0x25 (clock skew) for win01\'s requests, and klist -li 0x3e7 get krbtgt fails with 0xc0000133, not "no logon servers".',
      'krb-kdc-stopped': 'Kdc is running on dc01 and answers win01, with a clock skew error.',
      'dom-member-dns': 'win01 finds dc01 (NLA works, nltest /sc_verify succeeds).',
      'dom-dc-firewall': 'NLA succeeds: the NTLM pass-through to dc01 works.',
      'dom-trust-broken': 'The secure channel is fine (nltest /sc_verify:ad.corp.lab succeeds); the error is about time.',
      'win-wrong-password': 'xfreerdp +auth-only succeeds: the password is right.',
      'gpo-wrong-ou': 'This is not about which GPOs apply: gpupdate cannot even bind to the DC.',
    },
    hints: [
      'NLA works (xfreerdp +auth-only succeeds), the logon itself fails. Compare the clocks: Get-Date on win01 and dc01, or on win01 w32tm /stripchart /computer:dc01 /samples:1 /dataonly.',
      'win01 is 11 minutes ahead; Kerberos allows 5. Who should keep win01\'s clock right? w32tm /query /status and Get-Service W32Time on win01.',
      'Set-Service W32Time -StartupType Automatic; Start-Service W32Time (it synchronises from dc01 when it starts; w32tm /resync forces it). Do not set the time by hand: without the service it drifts again.',
    ],
    explanation: {
      rootCause: 'The Windows Time service on win01 was disabled, and win01 runs on a cluster without host time synchronisation. Its clock drifted 11 minutes ahead of dc01; Kerberos accepts at most 5 minutes.',
      manifestation: 'NLA uses NTLM, which does not depend on time, so the password is accepted. The logon then needs a Kerberos ticket: win01 sends AS-REQ with its own (wrong) time, and the KDC answers KRB_AP_ERR_SKEW. The logon screen shows "There is a time and/or date difference between the client and server." Group Policy fails the same way (LDAP bind, event 1006).',
      evidence: 'win01: Get-Date 11 minutes ahead of dc01; Get-Service W32Time Stopped/Disabled; w32tm /query: "The service has not been started"; System log 40960 (LsaSrv, 0xc0000133) and GroupPolicy 1006; klist -li 0x3e7 get krbtgt → 0xc0000133. dc01: Security 4771 with Failure Code 0x25 from 10.0.20.30.',
      prevention: 'Never disable W32Time on domain members; when VMs leave host time sync, check w32tm /query /source on each. Monitor clock offset against the DC (w32tm /stripchart, or the monitoring agent).',
    },
    solution: [{ host: 'win01', user: 'Administrator', commands: ['Set-Service W32Time -StartupType Automatic', 'Start-Service W32Time'] }],
    constraints: [firewallsOn(), timeFromDc()],
    concepts: ['ad.kerberos', 'ntp.sync', 'win.services'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'krb-dc-ntp-blocked',
    title: 'Time is not on the list',
    difficulty: 'advanced',
    ticket: 'Alice: "RDP to win01: the session opens, says there is a time and/or date difference between the client and server, and logs me off." Windows team: "W32Time runs on win01, we checked, and w32tm /resync says no time data was available." Security (SEC-35): "The DC firewall was aligned with the approved port list last week: DNS, Kerberos, LDAP, SMB, RPC."',
    briefing: BRIEFING,
    goals: [RDP],
    terminals: TERMINALS,
    setup(world) {
      joinWin01(world);
      script(world, 'dc01', ['Disable-NetFirewallRule -Name ADDS-W32Time-NTP-UDP-In']);
      skewWin01(world, 8);
    },
    rootCauses: ['krb-dc-ntp-blocked'],
    candidates: CANDIDATES,
    feedback: {
      'krb-w32time-disabled': 'W32Time runs on win01 (Get-Service W32Time); it tries, and gets no answer from dc01 (System log, Time-Service 47).',
      'krb-dc-kdc-blocked': 'The KDC answers (4771 with 0x25 on dc01; klist fails with 0xc0000133, the clock skew status).',
      'krb-kdc-stopped': 'Kdc runs on dc01 and answers, with a clock skew error.',
      'dom-member-dns': 'win01 finds dc01: NLA works and w32tm /query /source names dc01.ad.corp.lab.',
      'dom-dc-firewall': 'LDAP and Kerberos to dc01 work; only NTP (UDP 123) does not.',
      'dom-trust-broken': 'The secure channel works; the error is about time.',
      'win-wrong-password': 'NLA accepts the password (+auth-only succeeds).',
      'gpo-wrong-ou': 'Group Policy fails to bind at all; scope is not the question.',
    },
    hints: [
      'Compare the clocks (Get-Date on both, or w32tm /stripchart /computer:dc01 /samples:1 /dataonly on win01). Then: why does W32Time not correct it? w32tm /resync and the System log (Microsoft-Windows-Time-Service).',
      'Event 47: "No valid response has been received from domain controller dc01". The stripchart times out (0x800705B4). Which UDP port does W32Time use, and does dc01 let it in? Get-NetFirewallRule -DisplayName "*W32Time*" on dc01.',
      'On dc01: Enable-NetFirewallRule -Name ADDS-W32Time-NTP-UDP-In. Then on win01: w32tm /resync. NTP (UDP 123) belongs on a DC\'s approved port list.',
    ],
    explanation: {
      rootCause: 'The DC\'s firewall rule "Active Directory Domain Controller - W32Time (NTP-UDP-In)" was disabled because UDP 123 was missing from the approved port list. Members synchronise their clocks from a DC over NTP; win01 could not, and drifted 8 minutes.',
      manifestation: 'W32Time runs but gets no answers (Time-Service 47); w32tm /resync: "no time data was available". Once the drift exceeds 5 minutes, Kerberos fails with clock skew: the logon (after NTLM-based NLA) is refused with the time difference message, and Group Policy fails with 1006.',
      evidence: 'win01: Get-Date 8 minutes ahead; w32tm /stripchart /computer:dc01 → error 0x800705B4; System 47 and 40960 (0xc0000133). dc01: the W32Time NTP rule Enabled False; Security 4771 Failure Code 0x25.',
      prevention: 'A DC\'s port list includes NTP (UDP 123) next to DNS, Kerberos, LDAP, SMB and RPC; test time synchronisation (w32tm /stripchart) after firewall changes; alert on Time-Service event 47.',
    },
    solution: [
      { host: 'dc01', user: 'Administrator', commands: ['Enable-NetFirewallRule -Name ADDS-W32Time-NTP-UDP-In'] },
      { host: 'win01', user: 'Administrator', commands: ['w32tm /resync'] },
    ],
    constraints: [firewallsOn(), timeFromDc()],
    concepts: ['ad.kerberos', 'ntp.sync', 'fw.path'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'krb-dc-kdc-blocked',
    title: 'Logons work, policy does not',
    difficulty: 'advanced',
    ticket: 'Monitoring: "win01 still shows DOWN (no ping) after it was moved to OU=Servers yesterday (CHG-2400) and rebooted in last night\'s patch window. The other servers in OU=Servers answer." Windows team: "gpupdate on win01 fails with \'could not resolve the computer name\', but DNS works, nltest finds the DC, and Remote Desktop logons are fine." Security (SEC-36): "DC firewall review completed on Monday."',
    briefing: BRIEFING,
    goals: [GPO_PING, RDP],
    terminals: TERMINALS,
    setup(world) {
      kdcBaseline(world, ['Disable-NetFirewallRule -DisplayGroup "Kerberos Key Distribution Center"']);
    },
    rootCauses: ['krb-dc-kdc-blocked'],
    candidates: CANDIDATES,
    feedback: {
      'krb-kdc-stopped': 'Kdc is running on dc01 (Get-Service Kdc), and Test-NetConnection dc01 -Port 88 times out instead of being refused: something drops the packets.',
      'krb-w32time-disabled': 'The clocks agree (w32tm /stripchart shows a small offset); the KDC is not reached at all.',
      'krb-dc-ntp-blocked': 'Time synchronisation works (w32tm /resync succeeds).',
      'dom-member-dns': 'DNS works: nltest /dsgetdc:ad.corp.lab finds dc01.',
      'dom-dc-firewall': 'LDAP (389) to dc01 works: nltest /sc_verify succeeds and logons get through with NTLM. Only port 88 is blocked.',
      'dom-trust-broken': 'nltest /sc_verify:ad.corp.lab succeeds.',
      'win-wrong-password': 'Logons work.',
      'gpo-wrong-ou': 'WIN01 is in OU=Servers (Get-ADComputer win01). Policy processing fails before scope is evaluated.',
    },
    hints: [
      'gpupdate /force on win01, then Get-WinEvent -LogName System -MaxEvents 5: GroupPolicy 1055. The computer authenticates to LDAP with Kerberos. Does it have tickets? klist -li 0x3e7, then klist -li 0x3e7 get krbtgt.',
      '"There are currently no logon servers" (0xc000005e) although nltest finds dc01: the KDC is not reachable. Test-NetConnection dc01 -Port 88. Remote Desktop works because Negotiate falls back to NTLM (4624 on win01: Package Name NTLM V2); Group Policy does not fall back.',
      'On dc01: Get-NetFirewallRule -DisplayGroup "Kerberos Key Distribution Center" → Enable-NetFirewallRule -DisplayGroup "Kerberos Key Distribution Center". Then gpupdate /force on win01.',
    ],
    explanation: {
      rootCause: 'The DC firewall review disabled the "Kerberos Key Distribution Center" rules (TCP and UDP 88). Members find dc01 (DNS, LDAP) but cannot reach its KDC.',
      manifestation: 'Remote Desktop logons still work, because Negotiate falls back to NTLM when no KDC answers. Group Policy needs a Kerberos ticket for ldap/dc01 and fails with 1055 ("could not resolve the computer name"), so the Server Baseline firewall rule never arrives and monitoring cannot ping win01.',
      evidence: 'win01: gpupdate → "Windows could not resolve the computer name" (1055); klist -li 0x3e7 shows no tickets, klist -li 0x3e7 get krbtgt → 0xc000005e; Test-NetConnection dc01 -Port 88 → TcpTestSucceeded False; Security 4624 for alice with Package Name NTLM V2. dc01: KDC-TCP-In and KDC-UDP-In Enabled False; Get-Service Kdc Running.',
      prevention: 'Port reviews on DCs work from the list of AD ports (53, 88, 123, 135, 389, 445, 464, 636, 3268, RPC); test a member afterwards with klist get krbtgt and gpupdate; monitor GroupPolicy 1055 and NTLM usage (4624 with NTLM where Kerberos is expected).',
    },
    solution: [
      { host: 'dc01', user: 'Administrator', commands: ['Enable-NetFirewallRule -DisplayGroup "Kerberos Key Distribution Center"'] },
      { host: 'win01', user: 'Administrator', commands: ['gpupdate /force'] },
    ],
    constraints: [firewallsOn(), policyManaged(), kdcAvailable()],
    concepts: ['ad.kerberos', 'ad.gpo', 'fw.path'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'krb-kdc-stopped',
    title: 'One service too many',
    difficulty: 'advanced',
    ticket: 'Monitoring: "win01 shows DOWN (no ping) since the patch window, although it is up and people work on it." Windows team: "gpupdate on win01 fails: \'could not resolve the computer name\'. DNS works and nltest /dsgetdc finds dc01." Security (SEC-37): "Last night\'s service hardening script disabled services that are not on the member-server allow list, on all servers."',
    briefing: BRIEFING,
    goals: [GPO_PING, RDP],
    terminals: TERMINALS,
    setup(world) {
      kdcBaseline(world, ['Set-Service Kdc -StartupType Disabled', 'Stop-Service Kdc']);
    },
    rootCauses: ['krb-kdc-stopped'],
    candidates: CANDIDATES,
    feedback: {
      'krb-dc-kdc-blocked': 'The KDC firewall rules on dc01 are enabled, and Test-NetConnection dc01 -Port 88 fails at once (refused), not by timeout: nothing listens on 88.',
      'krb-w32time-disabled': 'The clocks agree; no KDC answers at all.',
      'krb-dc-ntp-blocked': 'Time synchronisation works.',
      'dom-member-dns': 'DNS works: nltest /dsgetdc:ad.corp.lab finds dc01.',
      'dom-dc-firewall': 'LDAP to dc01 works (nltest /sc_verify, NTLM logons).',
      'dom-trust-broken': 'nltest /sc_verify:ad.corp.lab succeeds.',
      'win-wrong-password': 'Logons work.',
      'gpo-wrong-ou': 'WIN01 is in OU=Servers; processing fails before scope matters.',
    },
    hints: [
      'gpupdate /force on win01 and the System log (1055). Does the computer get Kerberos tickets? klist -li 0x3e7 get krbtgt.',
      'No logon servers (0xc000005e) for Kerberos while NTLM logons work: is the KDC reachable? Test-NetConnection dc01 -Port 88 (refused or timed out?). On dc01: Get-Service Kdc; netstat -ano | findstr :88.',
      'The KDC is a separate service on a DC: Set-Service Kdc -StartupType Automatic; Start-Service Kdc on dc01. Then gpupdate /force on win01. A member-server allow list must not be applied to DCs.',
    ],
    explanation: {
      rootCause: 'A service hardening script built for member servers disabled the Kerberos Key Distribution Center (Kdc) service on dc01, the domain\'s only KDC.',
      manifestation: 'Nothing listens on port 88, so members get no Kerberos tickets. Logons fall back to NTLM and keep working, which hides the problem; Group Policy needs Kerberos and fails with 1055, so the monitoring rule from Server Baseline never reaches win01.',
      evidence: 'win01: gpupdate → 1055; klist -li 0x3e7 get krbtgt → 0xc000005e; Test-NetConnection dc01 -Port 88 → refused. dc01: Get-Service Kdc Stopped/Disabled; netstat shows no listener on :88; the KDC firewall rules are enabled.',
      prevention: 'Scope hardening by role: DCs get the DC baseline (Kdc, NTDS, DNS, Netlogon, W32Time, DFSR). After changes on a DC, check nltest /dsgetdc flags (KDC) and klist get krbtgt from a member.',
    },
    solution: [
      { host: 'dc01', user: 'Administrator', commands: ['Set-Service Kdc -StartupType Automatic', 'Start-Service Kdc'] },
      { host: 'win01', user: 'Administrator', commands: ['gpupdate /force'] },
    ],
    constraints: [firewallsOn(), policyManaged(), kdcAvailable()],
    concepts: ['ad.kerberos', 'ad.gpo', 'win.services'],
  },
];
