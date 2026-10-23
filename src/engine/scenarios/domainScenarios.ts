// Domain tickets: win01 is a member of ad.corp.lab and staff log on with their
// domain accounts (CORP\alice) over Remote Desktop. Every logon is checked by
// the domain controller dc01, so the faults are the dependencies of a domain
// logon: finding a DC (DNS), reaching it (firewall), the member's secure
// channel, the account (lockout) and the group that grants the logon right.

import { AD_ALICE_PASSWORD, DC01_ADMIN_PASSWORD, DC01_IP } from '../lab/winLab';
import type { World } from '../types';
import { FW_PROFILES } from '../win/model';
import { script } from './engine';
import type { Constraint, Goal, Scenario } from './types';

const RDP: Goal = { kind: 'rdp', description: 'From ws01, alice logs on to win01.corp.lab with her domain account ("xfreerdp /v:win01.corp.lab /u:CORP\\alice").', fromHost: 'ws01', localUser: 'alice', target: 'win01.corp.lab', user: 'CORP\\alice', password: AD_ALICE_PASSWORD };

/** A PowerShell expression for the domain Administrator's credential (no prompt). */
export const ADMIN_CRED = `(New-Object System.Management.Automation.PSCredential("CORP\\Administrator", (ConvertTo-SecureString "${DC01_ADMIN_PASSWORD}" -AsPlainText -Force)))`;

const TERMINALS = [
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: `ws01, Alice's Debian workstation. Her domain account is CORP\\alice (password ${AD_ALICE_PASSWORD}). Try: xfreerdp /v:win01.corp.lab /u:CORP\\\\alice (in bash the backslash is typed twice).` },
  { hostId: 'win01', user: 'Administrator', label: 'win01 console (PowerShell)', banner: 'Windows PowerShell\nCopyright (C) Microsoft Corporation. All rights reserved.\n\nwin01 console (hypervisor), signed in as the local WIN01\\Administrator (not a domain account). Try: Test-ComputerSecureChannel, nltest /sc_query:ad.corp.lab, Get-WinEvent -LogName System -MaxEvents 10.' },
  { hostId: 'dc01', user: 'Administrator', label: 'dc01 console (PowerShell)', banner: `Windows PowerShell\nCopyright (C) Microsoft Corporation. All rights reserved.\n\ndc01 console, signed in as CORP\\Administrator (password ${DC01_ADMIN_PASSWORD}). Domain controller and DNS server for ad.corp.lab. Try: Get-ADUser alice -Properties LockedOut, Get-ADGroupMember RDP-Users, Get-DnsServerResourceRecord -ZoneName ad.corp.lab.` },
];

const BRIEFING = [
  `Active Directory domain ad.corp.lab (NetBIOS name CORP). Its only domain controller is dc01 (${DC01_IP}), which also runs the AD-integrated DNS zone ad.corp.lab and forwards other names to ns1 (10.0.10.53).`,
  'win01 is a domain member. Staff log on with domain accounts; the AD group CORP\\RDP-Users is a member of win01\'s local Remote Desktop Users group. Members must use dc01 for DNS: that is how they find the domain controller (SRV record _ldap._tcp.dc._msdcs.ad.corp.lab).',
  'Firewalls stay on (default inbound Block) on win01 and dc01; the domain lockout policy (5 bad passwords) stays; fixes must survive a restart of every machine.',
];

const CANDIDATES = ['dom-member-dns', 'dom-dc-firewall', 'dom-trust-broken', 'dom-account-locked', 'dom-group-membership', 'win-rdp-rights', 'win-rdp-firewall', 'win-wrong-password'];

/** The state these tickets start from: win01 joined to ad.corp.lab, RDP for CORP\RDP-Users. */
export function joinWin01(world: World): void {
  script(world, 'win01', [
    `Set-DnsClientServerAddress -InterfaceAlias Ethernet0 -ServerAddresses ${DC01_IP}`,
    `Add-Computer -DomainName ad.corp.lab -Credential ${ADMIN_CRED} -Restart`,
    'Add-LocalGroupMember -Group "Remote Desktop Users" -Member "CORP\\RDP-Users"',
  ], 60_000);
}

function firewallsOn(): Constraint {
  return {
    id: 'win-firewalls-on', required: true,
    description: 'Windows Defender Firewall stays enabled on win01 and dc01 for every profile, blocking unsolicited inbound traffic by default.',
    check(world) {
      const bad = ['win01', 'dc01'].flatMap((h) => FW_PROFILES.filter((p) => !world.hosts[h].win!.firewall.profiles[p].enabled || world.hosts[h].win!.firewall.profiles[p].defaultInbound !== 'Block').map((p) => `${h} ${p}`));
      return { id: this.id, ok: !bad.length, required: true, message: bad.length ? `Firewall off or open by default: ${bad.join(', ')}.` : 'win01 and dc01: the firewall is on for all profiles, default inbound action Block.' };
    },
  };
}

function memberUsesAdDns(): Constraint {
  return {
    id: 'member-ad-dns', required: true,
    description: 'win01 uses only the domain\'s DNS server (dc01); ns1 does not host the AD zone and must not be a member\'s DNS server.',
    check(world) {
      const dns = world.hosts.win01.win!.adapters.flatMap((a) => a.dns);
      const ok = dns.length > 0 && dns.every((d) => d === DC01_IP);
      return { id: this.id, ok, required: true, message: ok ? 'win01: DNS server is dc01.' : `win01: DNS servers are ${dns.join(', ') || '(none)'}: with a non-AD DNS server in the list, DC location fails whenever that server is asked.` };
    },
  };
}

function lockoutKept(): Constraint {
  return {
    id: 'lockout-policy', required: true,
    description: 'The domain account lockout policy stays at 5 bad passwords, and alice keeps her own password.',
    check(world) {
      const ad = world.hosts.dc01.win!.ad!;
      const ok = ad.lockoutThreshold === 5 && ad.users.alice?.password === AD_ALICE_PASSWORD;
      return { id: this.id, ok, required: true, message: ok ? 'dc01: lockout threshold 5; alice\'s password unchanged.' : 'dc01: the lockout policy was weakened or alice\'s password was reset: she knows her password, the account was only locked.' };
    },
  };
}

function aliceNotDomainAdmin(): Constraint {
  return {
    id: 'alice-not-domain-admin', required: true,
    description: 'alice gets Remote Desktop access through RDP-Users, not Domain Admins (and not the local Administrators group).',
    check(world) {
      const ad = world.hosts.dc01.win!.ad!;
      const admins = [...ad.groups['domain admins'].members, ...ad.groups.administrators.members].map((m) => m.toLowerCase());
      const local = (world.hosts.win01.win!.localDomainMembers?.Administrators ?? []).map((m) => m.toLowerCase());
      const ok = !admins.includes('alice') && !local.includes('corp\\alice');
      return { id: this.id, ok, required: true, message: ok ? 'alice has no administrative rights.' : 'alice was made an administrator: she can log on now, with control of the domain or the server.' };
    },
  };
}

export const DOMAIN_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'dom-member-dns',
    title: 'One DNS server for everything',
    difficulty: 'intermediate',
    ticket: 'Alice: "Since this morning RDP to win01 says an authentication error has occurred and the Local Security Authority cannot be contacted. My password works on other systems." Network team (NET-120): "Last night we standardised every server on ns1 (10.0.10.53) for DNS and restarted them."',
    briefing: BRIEFING,
    goals: [RDP],
    terminals: TERMINALS,
    setup(world) {
      joinWin01(world);
      script(world, 'win01', ['Set-DnsClientServerAddress -InterfaceAlias Ethernet0 -ServerAddresses 10.0.10.53', 'Restart-Computer -Force'], 60_000);
    },
    rootCauses: ['dom-member-dns'],
    candidates: CANDIDATES,
    feedback: {
      'dom-dc-firewall': 'dc01 answers LDAP and DNS: from dc01 itself and once win01 asks the right DNS server, the DC is found at once. win01 never gets as far as contacting it.',
      'dom-trust-broken': 'Test-ComputerSecureChannel cannot even find a DC (nltest /sc_query: ERROR_NO_LOGON_SERVERS). A broken trust shows ERROR_ACCESS_DENIED with the DC named.',
      'dom-account-locked': 'dc01 has no failed logons for alice (Search-ADAccount -LockedOut is empty): the request never reached a DC.',
      'dom-group-membership': 'The logon fails during authentication, before any group membership is evaluated.',
      'win-rdp-rights': 'The logon fails during authentication, before the logon right is checked.',
      'win-rdp-firewall': 'TCP to 3389 works and TLS completes: the failure comes after NLA starts.',
      'win-wrong-password': 'win01 logs 4625 with status 0xC000005E (no logon servers), not 0xC000006D, and dc01 never sees the attempt.',
    },
    hints: [
      'The error is about reaching the domain, not the password. On win01: nltest /sc_query:ad.corp.lab and Get-WinEvent -LogName System -MaxEvents 10 (look for NETLOGON 5719).',
      'How does a member find a domain controller? Ask the same question it asks: Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.ad.corp.lab. Which DNS server answers it (Get-DnsClientServerAddress)?',
      `ns1 does not host the AD zone. Point win01 back at the domain's DNS server: Set-DnsClientServerAddress -InterfaceAlias Ethernet0 -ServerAddresses ${DC01_IP} (dc01 forwards everything else to ns1).`,
    ],
    explanation: {
      rootCause: 'win01\'s DNS server was changed to ns1, which hosts corp.lab but not the Active Directory zone ad.corp.lab. Members locate domain controllers with the SRV record _ldap._tcp.dc._msdcs.ad.corp.lab, so win01 can no longer find any DC.',
      manifestation: 'Domain logons need the DC (NTLM pass-through over Netlogon): xfreerdp reports ERRCONNECT_AUTHENTICATION_FAILED, mstsc "The Local Security Authority cannot be contacted". At boot Netlogon logged 5719 and the network profile fell back from DomainAuthenticated to Private; gpupdate fails too.',
      evidence: 'win01: Get-DnsClientServerAddress → 10.0.10.53; Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.ad.corp.lab → DNS name does not exist; nltest /sc_query:ad.corp.lab → ERROR_NO_LOGON_SERVERS; System log 5719; Security 4625 Status 0xC000005E.',
      prevention: 'Domain members use domain DNS servers only; the AD DNS servers forward other names to the corporate resolvers. "Standardise DNS" changes must treat AD members as a separate class (DHCP option sets or GPO per class), and monitor nltest /sc_verify on members.',
    },
    solution: [{ host: 'win01', user: 'Administrator', commands: [`Set-DnsClientServerAddress -InterfaceAlias Ethernet0 -ServerAddresses ${DC01_IP}`] }],
    constraints: [firewallsOn(), memberUsesAdDns()],
    concepts: ['ad.dns', 'dns.resolution'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'dom-dc-firewall',
    title: 'The hardening script, part two',
    difficulty: 'intermediate',
    ticket: 'Service desk: "Several people can\'t RDP to win01 since 07:00: \'an authentication error has occurred\'. Local accounts still work." Security (SEC-31): "The hardening baseline was extended to the remaining servers overnight, including the new DC."',
    briefing: BRIEFING,
    goals: [RDP],
    terminals: TERMINALS,
    setup(world) {
      joinWin01(world);
      script(world, 'dc01', ['Disable-NetFirewallRule -DisplayGroup "Active Directory Domain Services"'], 60_000);
    },
    rootCauses: ['dom-dc-firewall'],
    candidates: CANDIDATES,
    feedback: {
      'dom-member-dns': 'win01 uses dc01 for DNS and the SRV record resolves (Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.ad.corp.lab): the DC is found, it just does not answer on LDAP.',
      'dom-trust-broken': 'nltest reports ERROR_NO_LOGON_SERVERS: no DC answers at all. A broken trust would name the DC and report ERROR_ACCESS_DENIED.',
      'dom-account-locked': 'dc01 sees no logon attempts for alice; her account is not locked (Search-ADAccount -LockedOut).',
      'dom-group-membership': 'Authentication fails before group memberships matter.',
      'win-rdp-rights': 'Authentication fails before the logon right is checked.',
      'win-rdp-firewall': 'win01\'s RDP port is open (TCP and TLS succeed). The firewall that matters here is between win01 and its DC.',
      'win-wrong-password': 'The password is never checked: no DC is reachable (status 0xC000005E).',
    },
    hints: [
      'Local accounts work, domain accounts do not: what does a domain logon need that a local one does not? On win01: nltest /dsgetdc:ad.corp.lab.',
      'DNS gives the DC\'s name and address (Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.ad.corp.lab). Can win01 reach it on LDAP? Test-NetConnection dc01.ad.corp.lab -Port 389.',
      'On dc01: Get-NetFirewallRule -DisplayGroup "Active Directory Domain Services" | Format-Table Name, Enabled. Enable the role\'s rules again: Enable-NetFirewallRule -DisplayGroup "Active Directory Domain Services".',
    ],
    explanation: {
      rootCause: 'The hardening baseline disabled the firewall rules of the "Active Directory Domain Services" group on dc01 (LDAP 389 TCP/UDP, LDAPS 636, Global Catalog 3268). DNS (53) and Kerberos (88) stayed open, so the DC can be found but not contacted for the DC locator\'s LDAP ping.',
      manifestation: 'The member cannot establish a session with any DC: domain logons fail with "authentication error" (ERRCONNECT_AUTHENTICATION_FAILED, 4625 status 0xC000005E); nltest /dsgetdc fails with ERROR_NO_SUCH_DOMAIN even though the SRV records resolve.',
      evidence: 'win01: Resolve-DnsName SRV works; Test-NetConnection dc01.ad.corp.lab -Port 389 → TcpTestSucceeded False; Test-NetConnection -Port 53 → True. dc01: the AD DS rules Enabled False; Firewall log event 2005 from the night.',
      prevention: 'Baselines for domain controllers must keep the ports AD needs (DNS 53, Kerberos 88/464, LDAP 389/636/3268, RPC 135 and the dynamic range, SMB 445). Test logons from a member after every baseline change.',
    },
    solution: [{ host: 'dc01', user: 'Administrator', commands: ['Enable-NetFirewallRule -DisplayGroup "Active Directory Domain Services"'] }],
    constraints: [firewallsOn()],
    concepts: ['ad.kerberos', 'fw.stateful'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'dom-trust-broken',
    title: 'Back from the snapshot',
    difficulty: 'advanced',
    ticket: 'Virtualisation team (CHG-1702): "win01\'s update failed last night, so we reverted the VM to Sunday\'s snapshot. It\'s back up." Alice, an hour later: "RDP to win01 says there was an authentication error. Everyone in my team has the same problem."',
    briefing: BRIEFING,
    goals: [RDP],
    terminals: TERMINALS,
    setup(world) {
      joinWin01(world);
      // Sunday's snapshot: the machine password win01 had then.
      const snapshot = world.hosts.win01.win!.domain!.machinePassword;
      // Monday: Netlogon's routine machine password change (every 30 days).
      script(world, 'win01', [`Reset-ComputerMachinePassword -Credential ${ADMIN_CRED}`], 60_000);
      // Tuesday night: revert to the snapshot and restart.
      world.clock += 86_400_000;
      world.hosts.win01.win!.domain!.machinePassword = snapshot;
      script(world, 'win01', ['Restart-Computer -Force'], 60_000);
    },
    rootCauses: ['dom-trust-broken'],
    candidates: CANDIDATES,
    feedback: {
      'dom-member-dns': 'win01 finds dc01 fine: nltest /sc_query names \\\\dc01.ad.corp.lab. The DC rejects win01\'s credentials.',
      'dom-dc-firewall': 'dc01 is reachable: nltest names it and Test-NetConnection dc01 -Port 389 succeeds.',
      'dom-account-locked': 'alice\'s account is fine (Get-ADUser alice -Properties LockedOut); every domain user fails on win01, and only on win01.',
      'dom-group-membership': 'Authentication fails before group memberships matter, and it fails for everyone.',
      'win-rdp-rights': 'Authentication fails before the logon right is checked.',
      'win-rdp-firewall': 'TCP and TLS to win01 work.',
      'win-wrong-password': 'Every domain user fails on win01 and the same passwords work elsewhere; win01 logs 0xC000018D (trust relationship failed), not 0xC000006D.',
    },
    hints: [
      'Every domain user fails, but only on win01: look at win01\'s own relationship with the domain. Test-ComputerSecureChannel; nltest /sc_verify:ad.corp.lab; Get-WinEvent -LogName System -MaxEvents 10 (NETLOGON 3210).',
      'A member authenticates to the DC with its machine account password, which it changes by itself every 30 days. A snapshot from before the last change holds the old password.',
      `Repair it with a domain administrator's credentials: Test-ComputerSecureChannel -Repair -Credential CORP\\Administrator (password ${DC01_ADMIN_PASSWORD}). No rejoin or restart is needed.`,
    ],
    explanation: {
      rootCause: 'The VM was reverted to a snapshot taken before win01\'s last automatic machine password change. win01 now holds the old password for its computer account WIN01$, while AD has the new one: the secure channel is broken.',
      manifestation: 'win01 cannot authenticate to the DC, so it cannot pass users\' credentials through: domain logons fail ("The trust relationship between this workstation and the primary domain failed"; FreeRDP: ERRCONNECT_AUTHENTICATION_FAILED; 4625 status 0xC000018D). Local accounts still work.',
      evidence: 'Test-ComputerSecureChannel → False; nltest /sc_verify:ad.corp.lab → ERROR_ACCESS_DENIED with \\\\dc01.ad.corp.lab as the trusted DC; NETLOGON 3210 in the System log; dc01 shows the password reset of WIN01$ (Security 4724) on Monday.',
      prevention: 'Avoid reverting domain members (and never DCs) to old snapshots; if you must, repair the channel right away (Test-ComputerSecureChannel -Repair or Reset-ComputerMachinePassword). Monitor nltest /sc_verify. Rejoining also works but recreates the account and loses group memberships.',
    },
    solution: [{ host: 'win01', user: 'Administrator', commands: [`Test-ComputerSecureChannel -Repair -Credential ${ADMIN_CRED}`] }],
    constraints: [firewallsOn(), memberUsesAdDns()],
    concepts: ['ad.kerberos', 'ad.dns'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'dom-account-locked',
    title: 'The old laptop',
    difficulty: 'beginner',
    ticket: 'Alice: "RDP to win01 says my account is locked. I changed my domain password last week, and I haven\'t mistyped it. Could you look? I still have my old laptop (ws02) on my desk, it was asking for my password this morning."',
    briefing: BRIEFING,
    goals: [RDP],
    terminals: TERMINALS,
    setup(world) {
      joinWin01(world);
      // The old laptop's saved RDP connection still uses the previous password and retries.
      script(world, 'ws02', Array.from({ length: 5 }, () => 'xfreerdp /v:win01.corp.lab /u:CORP\\\\alice /p:Ad-Alice-2025 /cert:ignore'), 20_000);
    },
    rootCauses: ['dom-account-locked'],
    candidates: CANDIDATES,
    feedback: {
      'dom-member-dns': 'win01 reaches the DC: the DC is counting alice\'s bad passwords.',
      'dom-dc-firewall': 'win01 reaches the DC: the DC is counting alice\'s bad passwords.',
      'dom-trust-broken': 'The secure channel is fine (Test-ComputerSecureChannel → True); the DC answers with "account locked out".',
      'dom-group-membership': 'Group memberships are only evaluated after a successful authentication.',
      'win-rdp-rights': 'The logon right is checked after authentication, which fails here.',
      'win-rdp-firewall': 'The RDP connection itself works.',
      'win-wrong-password': 'Her password is right: the DC rejects it because the account is locked (status 0xC0000234). The wrong passwords came from another computer.',
    },
    hints: [
      'FreeRDP says ERRCONNECT_ACCOUNT_LOCKED_OUT. On dc01: Get-ADUser alice -Properties LockedOut, BadLogonCount, or Search-ADAccount -LockedOut.',
      'Who locked it? dc01: Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4740} -MaxEvents 1 | Format-List Message names the computer that relayed the bad passwords; on win01 the 4625 events show the source address.',
      'Unlock the account on dc01 with Unlock-ADAccount alice (do not reset her password or weaken the lockout policy), and have the old laptop\'s saved credentials removed.',
    ],
    explanation: {
      rootCause: 'alice\'s old laptop ws02 still had an RDP connection saved with her previous password. Its retries were relayed by win01 to the DC as bad passwords; after 5, the domain\'s lockout policy locked CORP\\alice.',
      manifestation: 'Any logon with alice\'s correct password is now refused: FreeRDP ERRCONNECT_ACCOUNT_LOCKED_OUT, mstsc "the referenced account is currently locked out". The DC logged 4740 (account locked out) and 4776 failures with error 0xC000006A from WIN01.',
      evidence: 'dc01: Get-ADUser alice -Properties LockedOut → True; Security 4740 (Caller Computer Name WIN01). win01: Security 4625 events with Source Network Address 10.0.10.x of ws02 and the earlier 0xC000006D, then 0xC0000234.',
      prevention: 'After a password change, remove saved credentials everywhere (cmdkey, mapped drives, phones). Find lockout sources with 4740 on the PDC emulator and 4625 on the relaying server. Keep the lockout policy: it is what stops password guessing.',
    },
    solution: [{ host: 'dc01', user: 'Administrator', commands: ['Unlock-ADAccount -Identity alice'] }],
    constraints: [lockoutKept()],
    concepts: ['ad.kerberos'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'dom-group-membership',
    title: 'The access review, domain edition',
    difficulty: 'beginner',
    ticket: 'Alice: "My password is accepted when I connect to win01, then it says I\'m not authorized for remote login. IAM finished the quarterly review of AD groups yesterday (IAM-81)." win01\'s local groups have not been touched (CHG log).',
    briefing: BRIEFING,
    goals: [RDP],
    terminals: TERMINALS,
    setup(world) {
      joinWin01(world);
      script(world, 'dc01', ['Remove-ADGroupMember -Identity RDP-Users -Members alice -Confirm:$false'], 60_000);
    },
    rootCauses: ['dom-group-membership'],
    candidates: CANDIDATES,
    feedback: {
      'dom-member-dns': 'Authentication succeeds, so win01 reached the DC.',
      'dom-dc-firewall': 'Authentication succeeds, so win01 reached the DC.',
      'dom-trust-broken': 'Authentication succeeds through win01\'s secure channel.',
      'dom-account-locked': 'The password is accepted; a locked account fails during authentication.',
      'win-rdp-rights': 'win01\'s Remote Desktop Users group still contains CORP\\RDP-Users (Get-LocalGroupMember "Remote Desktop Users"). The membership that changed is in AD.',
      'win-rdp-firewall': 'The connection and TLS work.',
      'win-wrong-password': 'The password is accepted; the logon right is what is missing.',
    },
    hints: [
      'Authentication works, the logon is refused: the logon right. On win01: Get-LocalGroupMember "Remote Desktop Users". Which principal grants it?',
      'CORP\\RDP-Users is there. Is alice in that AD group? On dc01: Get-ADGroupMember RDP-Users, or Get-ADPrincipalGroupMembership alice.',
      'Add her back on dc01: Add-ADGroupMember -Identity RDP-Users -Members alice (not to Domain Admins).',
    ],
    explanation: {
      rootCause: 'The IAM review removed alice from the AD group RDP-Users. win01 grants "Allow log on through Remote Desktop Services" to its local Remote Desktop Users group, which contains CORP\\RDP-Users: without that membership alice has no logon right on win01.',
      manifestation: 'NLA succeeds (the DC validates her password), then win01 refuses the logon: ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES; Security 4625 on win01 with Logon Type 10 and status 0xC000015B.',
      evidence: 'win01: Get-LocalGroupMember "Remote Desktop Users" lists CORP\\RDP-Users. dc01: Get-ADGroupMember RDP-Users without alice; Security 4729 (member removed from a global group) from the review.',
      prevention: 'Access reviews should know what each group grants (document it in the group\'s description) and confirm with the owners before removing access. Nested groups make a local right depend on directory memberships: check both.',
    },
    solution: [{ host: 'dc01', user: 'Administrator', commands: ['Add-ADGroupMember -Identity RDP-Users -Members alice'] }],
    constraints: [aliceNotDomainAdmin()],
    concepts: ['win.rdp', 'ad.gpo'],
  },
];
