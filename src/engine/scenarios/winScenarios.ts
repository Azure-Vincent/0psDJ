// Windows tickets: Remote Desktop to win01, a Windows Server 2022 member of
// the server VLAN. Each fault is one of the stages an RDP connection passes
// (firewall and network profile, the listener and its service, the port,
// authentication, the logon right) and is repaired from win01's PowerShell
// console; the client side is xfreerdp on ws01.

import { WIN01_ALICE_PASSWORD } from '../lab/winLab';
import type { World } from '../types';
import { FW_PROFILES, RDP_TCP_KEY } from '../win/model';
import { userDisabled } from '../win/ps/cmdlets/system';
import { script } from './engine';
import type { Constraint, Goal, Scenario } from './types';

const RDP: Goal = { kind: 'rdp', description: 'From ws01, alice connects to win01.corp.lab with Remote Desktop ("xfreerdp /v:win01.corp.lab /u:alice") and gets a desktop session.', fromHost: 'ws01', localUser: 'alice', target: 'win01.corp.lab', user: 'alice', password: WIN01_ALICE_PASSWORD };

const TERMINALS = [
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: `ws01, Alice's Debian workstation. Her password on win01 is ${WIN01_ALICE_PASSWORD}. Try: xfreerdp /v:win01.corp.lab /u:alice, nc -zv win01 3389.` },
  { hostId: 'win01', user: 'Administrator', label: 'win01 console (PowerShell)', banner: 'Windows PowerShell\nCopyright (C) Microsoft Corporation. All rights reserved.\n\nwin01 console (hypervisor), signed in as WIN01\\Administrator. Windows PowerShell 5.1: Get-Service, Get-NetFirewallRule, Get-WinEvent, Get-Help <cmdlet>.' },
];

const BRIEFING = [
  'win01 (10.0.20.30) is a Windows Server 2022 member of the server VLAN. It runs IIS, Remote Desktop, SMB and WinRM, and is not joined to a domain: accounts are local (alice is a member of Remote Desktop Users, not of Administrators).',
  'Staff connect with Remote Desktop from their workstations (xfreerdp on the Debian machines). You have the server\'s console through the hypervisor: a PowerShell window signed in as Administrator.',
  'Windows Defender Firewall must stay on for every profile with inbound traffic blocked by default; fixes must survive a restart of win01 (Restart-Computer).',
];

const CANDIDATES = ['win-rdp-firewall', 'win-rdp-profile', 'win-rdp-disabled', 'win-termservice-disabled', 'win-rdp-port', 'win-rdp-rights', 'win-account-disabled', 'win-wrong-password'];

function ps(world: World, lines: string[]) {
  script(world, 'win01', lines, 60_000);
}

function firewallOn(): Constraint {
  return {
    id: 'win-firewall-on', required: true,
    description: 'Windows Defender Firewall stays enabled on every profile, blocking unsolicited inbound traffic by default.',
    check(world) {
      const p = world.hosts.win01.win!.firewall.profiles;
      const bad = FW_PROFILES.filter((x) => !p[x].enabled || p[x].defaultInbound !== 'Block');
      return { id: this.id, ok: !bad.length, required: true, message: bad.length ? `win01: the ${bad.join(', ')} profile${bad.length > 1 ? 's are' : ' is'} off or allows inbound by default: every port is now open, not just RDP.` : 'win01: the firewall is on for all profiles, default inbound action Block.' };
    },
  };
}

function aliceNotAdmin(): Constraint {
  return {
    id: 'alice-not-admin', required: true,
    description: 'alice gets Remote Desktop access through Remote Desktop Users, not by becoming an administrator.',
    check(world) {
      const u = world.hosts.win01.users.alice;
      const ok = !!u && !u.groups.includes('Administrators');
      return { id: this.id, ok, required: true, message: ok ? 'win01: alice is not an administrator.' : 'win01: alice was added to Administrators: she can log on now, but with full control of the server. Remote Desktop Users grants the logon right alone.' };
    },
  };
}

function rdpRulesNotPublic(): Constraint {
  return {
    id: 'rdp-not-public', required: true,
    description: 'The Remote Desktop firewall rules keep their scope: Domain and Private networks only, never Public.',
    check(world) {
      const rules = world.hosts.win01.win!.firewall.rules.filter((r) => r.group === 'Remote Desktop' && r.enabled);
      const ok = rules.every((r) => r.profiles !== 'Any' && !r.profiles.includes('Public')) && !world.hosts.win01.win!.firewall.rules.some((r) => r.group !== 'Remote Desktop' && r.enabled && r.action === 'Allow' && r.direction === 'Inbound' && r.localPort !== 'Any' && r.localPort.includes('3389'));
      return { id: this.id, ok, required: true, message: ok ? 'win01: Remote Desktop is still allowed on Domain and Private networks only.' : 'win01: RDP is now allowed on the Public profile too: if the server is ever moved to an untrusted network, its logon screen is exposed there.' };
    },
  };
}

function standardPort(): Constraint {
  return {
    id: 'rdp-port-3389', required: true,
    description: 'Remote Desktop listens on the documented port 3389 (clients, the firewall rules and monitoring all use it).',
    check(world) {
      const port = Number(world.hosts.win01.win!.registry[RDP_TCP_KEY]?.PortNumber ?? 3389);
      return { id: this.id, ok: port === 3389, required: true, message: port === 3389 ? 'win01: PortNumber is 3389.' : `win01: PortNumber is ${port}; the standard rules and every client expect 3389.` };
    },
  };
}

function termServiceNotDisabled(): Constraint {
  return {
    id: 'termservice-enabled', required: true,
    description: 'Remote Desktop Services (TermService) is not disabled, so it starts again after a restart.',
    check(world) {
      const s = world.hosts.win01.win!.services.TermService;
      const ok = s.startType !== 'Disabled';
      return { id: this.id, ok, required: true, message: ok ? `win01: TermService start type is ${s.startType}.` : 'win01: TermService is still Disabled: it will not start after the next restart.' };
    },
  };
}

function aliceEnabled(): Constraint {
  return {
    id: 'alice-enabled', required: true,
    description: 'alice\'s account is enabled and keeps its password (no reset: she knows hers).',
    check(world) {
      const h = world.hosts.win01;
      const ok = !!h.users.alice && !userDisabled(h, 'alice') && h.users.alice.password === WIN01_ALICE_PASSWORD;
      return { id: this.id, ok, required: true, message: ok ? 'win01: alice is enabled with her own password.' : 'win01: alice is disabled or her password was changed.' };
    },
  };
}

export const WIN_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'win-rdp-firewall',
    title: 'The hardening script',
    difficulty: 'beginner',
    ticket: 'Alice: "Remote Desktop to win01 just spins and then says it can\'t connect. It worked on Friday. Over the weekend the security team ran their hardening script on the servers (SEC-31)."',
    briefing: BRIEFING,
    goals: [RDP],
    terminals: TERMINALS,
    setup(world) {
      ps(world, ['Disable-NetFirewallRule -DisplayGroup "Remote Desktop"']);
    },
    rootCauses: ['win-rdp-firewall'],
    candidates: CANDIDATES,
    feedback: {
      'win-rdp-profile': 'Get-NetConnectionProfile shows Private, the profile the server has always used; the rules are disabled in every profile.',
      'win-rdp-disabled': 'fDenyTSConnections is 0 and the listener is up (Get-NetTCPConnection -LocalPort 3389 shows it); a disabled listener would refuse the connection at once, not time out.',
      'win-termservice-disabled': 'TermService is Running; on win01 itself Test-NetConnection localhost -Port 3389 succeeds.',
      'win-rdp-port': 'The listener is on 3389 (Get-NetTCPConnection -LocalPort 3389).',
      'win-rdp-rights': 'A rights problem shows up after authentication, with a clear "insufficient access privileges" message; here the TCP connection never completes.',
      'win-account-disabled': 'The client never gets to authentication: the TCP connection to 3389 times out.',
      'win-wrong-password': 'The client never gets to send a password: the TCP connection to 3389 times out.',
    },
    hints: [
      '"Spins, then fails" is a timeout: packets are dropped somewhere. From ws01, "nc -zv -w 3 win01 3389" tells you whether TCP gets through.',
      'On win01: is the listener up (Get-NetTCPConnection -LocalPort 3389 -State Listen)? It is. So look at what decides about inbound packets: Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Format-Table Name, Enabled, Profile, Action.',
      'Enable the built-in rules again: Enable-NetFirewallRule -DisplayGroup "Remote Desktop". Do not turn the firewall off.',
    ],
    explanation: {
      rootCause: 'The SEC-31 hardening script disabled the built-in firewall rules of the "Remote Desktop" group (RemoteDesktop-UserMode-In-TCP and -UDP). The firewall\'s default inbound action is Block, so with no rule allowing TCP 3389 the connection attempts are dropped.',
      manifestation: 'xfreerdp waits for its connection timeout and fails with ERRCONNECT_CONNECT_TRANSPORT_FAILED; nc -zv to port 3389 times out. On win01 itself everything looks healthy: TermService is running and listening on 3389.',
      evidence: 'Get-NetTCPConnection -LocalPort 3389 -State Listen: present. Get-NetFirewallRule -DisplayGroup "Remote Desktop": Enabled False for both rules. Get-WinEvent on the "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" log: event 2005 (rule modified) at the time of the script.',
      prevention: 'Hardening scripts must be tested against each server role and must keep the management paths the role needs (RDP, WinRM). Firewall rule changes are logged in the Firewall operational log (events 2004/2005/2006): alert on them.',
    },
    solution: [{ host: 'win01', user: 'Administrator', commands: ['Enable-NetFirewallRule -DisplayGroup "Remote Desktop"'] }],
    constraints: [firewallOn()],
    concepts: ['win.rdp', 'fw.stateful'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'win-rdp-profile',
    title: 'The new switch port',
    difficulty: 'intermediate',
    ticket: 'Network team (NET-118): "We moved win01\'s virtual NIC to the new port group on the virtualisation host this morning. Ping and the IIS site work, but nobody can RDP to it any more. The firewall rules for RDP haven\'t been touched, we checked."',
    briefing: [...BRIEFING, 'Change CHG-1610 (last year): the Remote Desktop rules on servers are limited to the Domain and Private profiles, so a server that ends up on an untrusted (Public) network does not expose its logon screen.'],
    goals: [RDP],
    terminals: TERMINALS,
    setup(world) {
      ps(world, ['Set-NetFirewallRule -DisplayGroup "Remote Desktop" -Profile Domain,Private', 'Enable-NetFirewallRule -Name FPS-ICMP4-ERQ-In']);
      // Windows identified the "new" network and filed it as Public.
      ps(world, ['Set-NetConnectionProfile -InterfaceAlias Ethernet0 -NetworkCategory Public']);
    },
    rootCauses: ['win-rdp-profile'],
    candidates: CANDIDATES,
    feedback: {
      'win-rdp-firewall': 'The Remote Desktop rules are enabled; they are scoped to Domain and Private, and the connection is now in the Public profile. The rules are right, the network category is wrong.',
      'win-rdp-disabled': 'The listener is up (Get-NetTCPConnection -LocalPort 3389), and connections time out rather than being refused.',
      'win-termservice-disabled': 'TermService is running.',
      'win-rdp-port': 'The listener is on 3389.',
      'win-rdp-rights': 'Authentication is never reached: TCP to 3389 times out.',
      'win-account-disabled': 'Authentication is never reached: TCP to 3389 times out.',
      'win-wrong-password': 'Authentication is never reached: TCP to 3389 times out.',
    },
    hints: [
      'TCP to 3389 times out, yet the Remote Desktop rules are enabled. Look at which profiles they apply to: Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Format-Table Name, Enabled, Profile.',
      'Which profile is in force? Get-NetConnectionProfile shows the network category of Ethernet0.',
      'The server is on a trusted network: set the category back with Set-NetConnectionProfile -InterfaceAlias Ethernet0 -NetworkCategory Private. Widening the rules to Public would violate CHG-1610.',
    ],
    explanation: {
      rootCause: 'After the NIC moved to a new port group, Windows\' Network Location Awareness treated the connection as a new network and gave it the Public category. The Remote Desktop rules are (by design, CHG-1610) limited to the Domain and Private profiles, so in the Public profile nothing allows TCP 3389.',
      manifestation: 'RDP times out (ERRCONNECT_CONNECT_TRANSPORT_FAILED). ICMP echo and HTTP still work because their rules apply to all profiles, which makes it look like "the firewall is fine".',
      evidence: 'Get-NetConnectionProfile: NetworkCategory Public. Get-NetFirewallRule -DisplayGroup "Remote Desktop": Enabled True, Profile Domain, Private. Get-NetFirewallProfile -Name Public: Enabled True, DefaultInboundAction Block.',
      prevention: 'Domain-joined servers authenticate to a DC and get the Domain profile automatically; standalone servers need their network category set deliberately (and checked after network changes). Monitor the active profile, not just the rules.',
    },
    solution: [{ host: 'win01', user: 'Administrator', commands: ['Set-NetConnectionProfile -InterfaceAlias Ethernet0 -NetworkCategory Private'] }],
    constraints: [firewallOn(), rdpRulesNotPublic()],
    concepts: ['win.rdp', 'fw.stateful'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'win-rdp-disabled',
    title: 'Remote Desktop: Off',
    difficulty: 'beginner',
    ticket: 'Alice: "win01 refuses Remote Desktop straight away since yesterday afternoon. The admin who was cleaning up the server settings is on holiday."',
    briefing: BRIEFING,
    goals: [RDP],
    terminals: TERMINALS,
    setup(world) {
      ps(world, ['Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -Name fDenyTSConnections -Value 1']);
    },
    rootCauses: ['win-rdp-disabled'],
    candidates: CANDIDATES,
    feedback: {
      'win-rdp-firewall': 'The firewall lets the SYN through: the server answers it with a reset (connection refused). A blocking firewall would drop it silently (timeout).',
      'win-rdp-profile': 'Packets reach the server and get an answer (a reset), so the firewall profile is not dropping them.',
      'win-termservice-disabled': 'TermService is running; but its listener is switched off.',
      'win-rdp-port': 'PortNumber is still 3389, and nothing listens on any other port either.',
      'win-rdp-rights': 'The connection is refused before any authentication.',
      'win-account-disabled': 'The connection is refused before any authentication.',
      'win-wrong-password': 'The connection is refused before any authentication.',
    },
    hints: [
      '"Refused at once" means the SYN reached win01 and nothing listens on 3389. On win01: Get-NetTCPConnection -LocalPort 3389 -State Listen.',
      'TermService is running (Get-Service TermService), yet there is no listener. Remote Desktop has a master switch: Get-ItemProperty "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" | Select-Object fDenyTSConnections.',
      'Turn Remote Desktop back on: Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -Name fDenyTSConnections -Value 0. TermService picks the change up immediately (event 1056).',
    ],
    explanation: {
      rootCause: 'Remote Desktop was switched off: fDenyTSConnections = 1 under HKLM\\System\\CurrentControlSet\\Control\\Terminal Server (what "Remote Desktop: Off" in Settings or sysdm.cpl writes). TermService keeps running but closes its RDP-Tcp listener.',
      manifestation: 'xfreerdp fails immediately with ERRCONNECT_CONNECT_FAILED; nc reports "Connection refused": the firewall rules allow 3389, the packet reaches TCP, and with no listener TCP answers RST.',
      evidence: 'Get-NetTCPConnection -LocalPort 3389: nothing found. Get-Service TermService: Running. Get-ItemProperty ...\\Terminal Server: fDenyTSConnections 1. Get-WinEvent -LogName System: TermService event 1056 when the value changed.',
      prevention: 'Configure Remote Desktop through policy (Group Policy: "Allow users to connect remotely by using Remote Desktop Services") so that ad-hoc changes are reverted, and monitor the listener with a TCP check on 3389.',
    },
    solution: [{ host: 'win01', user: 'Administrator', commands: ['Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -Name fDenyTSConnections -Value 0'] }],
    constraints: [firewallOn()],
    concepts: ['win.rdp'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'win-termservice-disabled',
    title: 'The brute-force response',
    difficulty: 'intermediate',
    ticket: 'SOC: "Last night we saw password spraying against RDP on several servers and the on-call admin \'switched RDP off\' on win01 as a precaution. Investigation done, no compromise. Please restore RDP for the staff. (He says he just stopped a service.)"',
    briefing: BRIEFING,
    goals: [RDP],
    terminals: TERMINALS,
    setup(world) {
      ps(world, ['Set-Service -Name TermService -StartupType Disabled', 'Stop-Service -Name TermService -Force']);
    },
    rootCauses: ['win-termservice-disabled'],
    candidates: CANDIDATES,
    feedback: {
      'win-rdp-firewall': 'The connection is refused, not dropped: the firewall lets it through and nothing listens.',
      'win-rdp-profile': 'The connection is refused, not dropped.',
      'win-rdp-disabled': 'fDenyTSConnections is still 0: Remote Desktop is allowed, but the service that would listen is stopped and disabled.',
      'win-rdp-port': 'PortNumber is 3389; nothing listens anywhere because the service is stopped.',
      'win-rdp-rights': 'The connection is refused before any authentication.',
      'win-account-disabled': 'The connection is refused before any authentication.',
      'win-wrong-password': 'The connection is refused before any authentication.',
    },
    hints: [
      'Refused immediately: nothing listens on 3389. Which service owns the RDP listener? Get-Service TermService.',
      'It is stopped, and "Start-Service TermService" fails. Why? Get-Service TermService | Select-Object Name, Status, StartType, and the System log: Get-WinEvent -LogName System -MaxEvents 10.',
      'Set the start type back to Manual (its default; it is trigger-started when Remote Desktop is enabled), then start it: Set-Service TermService -StartupType Manual; Start-Service TermService.',
    ],
    explanation: {
      rootCause: 'Remote Desktop Services (TermService) was stopped and its start type set to Disabled. Without the service there is no RDP-Tcp listener; "Disabled" also stops it from starting at boot and makes Start-Service fail.',
      manifestation: 'xfreerdp: ERRCONNECT_CONNECT_FAILED (connection refused). Start-Service TermService fails with "Cannot start service TermService on computer \'.\'" and the System log records event 7000 ("...because it is disabled...").',
      evidence: 'Get-Service TermService: Stopped, StartType Disabled. Get-WinEvent -LogName System: 7036 "The Remote Desktop Services service entered the stopped state" and 7040 (start type changed). netstat -ano | findstr 3389 shows nothing listening.',
      prevention: 'Respond to password spraying with controls that keep the service (account lockout policy, NLA, restricting RDP to management networks or a gateway, MFA), and record emergency changes so they are reverted. Restoring a service means restoring its start type, not just starting it.',
    },
    solution: [{ host: 'win01', user: 'Administrator', commands: ['Set-Service -Name TermService -StartupType Manual', 'Start-Service -Name TermService'] }],
    constraints: [firewallOn(), termServiceNotDisabled()],
    concepts: ['win.services', 'win.rdp'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'win-rdp-port',
    title: 'Security through obscurity',
    difficulty: 'intermediate',
    ticket: 'Alice: "RDP to win01 has said \'connection refused\' since Tuesday. A colleague mentioned someone wanted to \'move RDP away from the default port\' after a security audit, but nobody updated our connection settings or told us a new port."',
    briefing: BRIEFING,
    goals: [RDP],
    terminals: TERMINALS,
    setup(world) {
      ps(world, ['Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name PortNumber -Value 3390', 'Restart-Service -Name TermService -Force']);
    },
    rootCauses: ['win-rdp-port'],
    candidates: CANDIDATES,
    feedback: {
      'win-rdp-firewall': 'The firewall allows 3389 (connections to it are refused, not dropped). It does not allow 3390, which is why trying the new port times out: a symptom of the port change, not the cause.',
      'win-rdp-profile': 'Connections to 3389 reach the server and are refused: they are not dropped by the profile.',
      'win-rdp-disabled': 'fDenyTSConnections is 0 and TermService is listening, just not on 3389.',
      'win-termservice-disabled': 'TermService is running: Get-NetTCPConnection shows it listening on another port.',
      'win-rdp-rights': 'The connection is refused before any authentication.',
      'win-account-disabled': 'The connection is refused before any authentication.',
      'win-wrong-password': 'The connection is refused before any authentication.',
    },
    hints: [
      'Refused on 3389. Is TermService running? Where does it listen? Get-NetTCPConnection -State Listen (or netstat -ano) and compare the PID with Get-CimInstance Win32_Service.',
      'The port comes from the registry: Get-ItemProperty "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" | Select-Object PortNumber.',
      'Move it back (the firewall rules, the clients and monitoring all use 3389): Set-ItemProperty ...\\RDP-Tcp -Name PortNumber -Value 3389, then Restart-Service TermService -Force (the port is read when the service starts).',
    ],
    explanation: {
      rootCause: 'PortNumber in HKLM\\...\\Terminal Server\\WinStations\\RDP-Tcp was changed to 3390 and TermService restarted, so the listener moved. Nobody added a firewall rule for 3390 or told the clients: on 3389 nothing listens (refused) and 3390 is blocked by the firewall (timeout).',
      manifestation: 'xfreerdp /v:win01: ERRCONNECT_CONNECT_FAILED (refused). xfreerdp /v:win01:3390: ERRCONNECT_CONNECT_TRANSPORT_FAILED after a timeout.',
      evidence: 'Get-NetTCPConnection -State Listen: 3390 instead of 3389, OwningProcess = TermService\'s svchost. Registry PortNumber 3390. The Remote Desktop firewall rules still say LocalPort 3389.',
      prevention: 'A non-standard port is not a security control (port scans find it in seconds); use NLA, account lockout and network restrictions instead. If a port must change, change the listener, the firewall rule, the clients and monitoring in one documented change.',
    },
    solution: [{ host: 'win01', user: 'Administrator', commands: ['Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name PortNumber -Value 3389', 'Restart-Service -Name TermService -Force'] }],
    constraints: [firewallOn(), standardPort()],
    concepts: ['win.rdp', 'svc.listening'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'win-rdp-rights',
    title: 'The group clean-up',
    difficulty: 'beginner',
    ticket: 'Alice: "I can connect to win01 and my password is accepted, but then it says I am not authorized for remote login. The access review (IAM-77) finished on Monday."',
    briefing: BRIEFING,
    goals: [RDP],
    terminals: TERMINALS,
    setup(world) {
      ps(world, ['Remove-LocalGroupMember -Group "Remote Desktop Users" -Member alice']);
    },
    rootCauses: ['win-rdp-rights'],
    candidates: CANDIDATES,
    feedback: {
      'win-rdp-firewall': 'The connection, TLS and authentication all succeed: the network path is fine.',
      'win-rdp-profile': 'The connection, TLS and authentication all succeed: the network path is fine.',
      'win-rdp-disabled': 'The listener accepts the connection.',
      'win-termservice-disabled': 'The service answers and authenticates the user.',
      'win-rdp-port': 'The connection to 3389 succeeds.',
      'win-account-disabled': 'A disabled account fails during authentication (ERRCONNECT_ACCOUNT_DISABLED); here authentication succeeds and the logon is refused.',
      'win-wrong-password': 'The password is accepted: the Security log shows the failure at logon type 10 with status 0xC000015B, not 0xC000006D.',
    },
    hints: [
      'Authentication works; the logon is refused. Windows records why: Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625} -MaxEvents 1 | Format-List Message.',
      '"The user has not been granted the requested logon type": the right "Allow log on through Remote Desktop Services" belongs to Administrators and Remote Desktop Users. Get-LocalGroupMember -Group "Remote Desktop Users".',
      'Add her back: Add-LocalGroupMember -Group "Remote Desktop Users" -Member alice (not to Administrators).',
    ],
    explanation: {
      rootCause: 'The access review removed alice from the local group Remote Desktop Users. On a member server the user right "Allow log on through Remote Desktop Services" (SeRemoteInteractiveLogonRight) is granted to Administrators and Remote Desktop Users only.',
      manifestation: 'NLA (CredSSP) authentication succeeds, then the logon is refused: xfreerdp reports ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES; mstsc says "The connection was denied because the user account is not authorized for remote login".',
      evidence: 'Security log event 4625, Logon Type 10, Status 0xC000015B ("not been granted the requested logon type"). Get-LocalGroupMember "Remote Desktop Users": alice missing. +auth-only on the client succeeds.',
      prevention: 'Grant RDP access through a group that the access review knows about (in a domain, an AD group nested into Remote Desktop Users by Group Policy) and record why it is needed.',
    },
    solution: [{ host: 'win01', user: 'Administrator', commands: ['Add-LocalGroupMember -Group "Remote Desktop Users" -Member alice'] }],
    constraints: [aliceNotAdmin()],
    concepts: ['win.rdp'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'win-account-disabled',
    title: 'Locked out?',
    difficulty: 'beginner',
    ticket: 'Alice: "win01 says my logon failed, but I\'m sure of my password, I use it every day. The helpdesk had a look at my account yesterday after the SOC flagged failed logons."',
    briefing: BRIEFING,
    goals: [RDP],
    terminals: TERMINALS,
    setup(world) {
      ps(world, ['Disable-LocalUser -Name alice']);
    },
    rootCauses: ['win-account-disabled'],
    candidates: CANDIDATES,
    feedback: {
      'win-rdp-firewall': 'TLS and the NLA exchange happen: the path to 3389 is open.',
      'win-rdp-profile': 'TLS and the NLA exchange happen: the path to 3389 is open.',
      'win-rdp-disabled': 'The listener accepts the connection.',
      'win-termservice-disabled': 'The service answers.',
      'win-rdp-port': 'The connection to 3389 succeeds.',
      'win-rdp-rights': 'Logon rights are checked after authentication; authentication itself fails here.',
      'win-wrong-password': 'The Security log says Status 0xC0000072 ("account currently disabled"), not 0xC000006D (bad user name or password). Resetting her password would not help.',
    },
    hints: [
      'Authentication fails (ERRCONNECT_ACCOUNT_DISABLED). Ask the server why: Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625} -MaxEvents 1 | Format-List Message.',
      'Get-LocalUser alice: is it Enabled?',
      'Enable-LocalUser -Name alice. Keep her password: she knows it.',
    ],
    explanation: {
      rootCause: 'The helpdesk disabled alice\'s local account while looking into the failed logons (Disable-LocalUser), and did not enable it again.',
      manifestation: 'xfreerdp: ERRCONNECT_ACCOUNT_DISABLED during NLA; mstsc shows a generic logon failure. The Security log has event 4625 with Status 0xC0000072 and event 4725 (account disabled) from the day before.',
      evidence: 'Get-LocalUser alice: Enabled False. Get-WinEvent Security 4725 names the account and the time it was disabled.',
      prevention: 'Lockouts and disables during an investigation need a ticket and an owner who re-enables the account. Read the 4625 status code before resetting passwords: it says whether the problem is the password, the account or the logon right.',
    },
    solution: [{ host: 'win01', user: 'Administrator', commands: ['Enable-LocalUser -Name alice'] }],
    constraints: [aliceEnabled(), aliceNotAdmin()],
    concepts: ['win.rdp'],
  },
];
