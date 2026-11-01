// Integrated Lab 3: Deploy an Active Directory Environment. Builds on the
// Windows Domain lab's machines and steps (role, promotion, accounts, member
// DNS, join, Remote Desktop) and adds what makes it an environment: an OU for
// the servers with a Group Policy that configures them, and verification that
// authentication, DNS and policy work together. The incident: a member's
// clock drifts and Kerberos logons fail.

import { checkGoal } from '../../scenarios/engine';
import { PING_RULE } from '../../scenarios/gpoScenarios';
import { AD_ALICE_PASSWORD, DC01_IP } from '../../lab/winLab';
import { NO, OK, probe } from '../engine';
import { LAB2 } from '../lab2';
import type { GuidedLab, LabCheck } from '../types';
import { cmdCheck, evidence, hop } from './common';
import { reuseStep, ticketFault } from './tickets';

const DN = 'DC=ad,DC=corp,DC=lab';
const SERVERS = `OU=Servers,${DN}`;

const rdpCheck: LabCheck = {
  id: 'rdp-domain', description: 'From ws01, alice logs on to win01 with Remote Desktop as CORP\\alice (Kerberos through the DC)',
  check(w) {
    const r = checkGoal(w, { kind: 'rdp', description: '', fromHost: 'ws01', localUser: 'alice', target: 'win01.corp.lab', user: 'CORP\\alice', password: AD_ALICE_PASSWORD });
    return r.ok ? OK('Domain logon over RDP works.') : NO(r.lines.filter(Boolean).slice(-2).join(' '));
  },
};

const policyApplied: LabCheck = {
  id: 'gpo', description: 'win01 is in OU=Servers, the GPO "Server Baseline" (linked there) allows ping from 10.0.0.0/16, and win01 has applied it',
  check(w) {
    const ad = w.hosts.dc01.win?.ad;
    if (!ad) return NO('dc01 is not a domain controller yet.');
    const ou = Object.values(ad.ous ?? {}).find((o) => o.dn.toLowerCase() === SERVERS.toLowerCase());
    if (!ou) return NO(`There is no OU ${SERVERS} (New-ADOrganizationalUnit -Name Servers -Path "${DN}").`);
    const c = ad.computers.win01;
    if (!c) return NO('win01 is not joined to the domain.');
    if ((c.ou ?? '').toLowerCase() !== SERVERS.toLowerCase()) return NO(`win01 is in ${c.ou ?? `CN=Computers,${DN}`}: move it to OU=Servers (Move-ADObject), or a GPO linked there never applies to it.`);
    const g = probe(w, 'win01', 'Administrator', 'gpresult /r');
    if (!/Server Baseline/.test(g.output)) return NO(`win01 has not applied "Server Baseline" (is it linked to OU=Servers? Then gpupdate /force on win01).\n${evidence('win01', 'Administrator', 'gpresult /r', g.output, g.code)}`);
    const p = probe(w, 'ws01', 'alice', 'ping -c 1 -W 2 win01.corp.lab');
    if (p.code !== 0) return NO(`win01 still does not answer ping from ws01: the policy's firewall rule is not in effect.\n${evidence('ws01', 'alice', 'ping -c 1 -W 2 win01.corp.lab', p.output, p.code)}`);
    const local = w.hosts.win01.win!.firewall.rules.some((r) => r.enabled && r.action === 'Allow' && r.direction === 'Inbound' && (r.protocol === 'ICMPv4' || r.protocol === 'Any') && (r.icmpType === undefined || r.icmpType === 'Any' || r.icmpType.split(',').some((t) => t.split(':')[0] === '8')));
    if (local) return NO('win01 has a local firewall rule for ping: the rule must come from the GPO (centrally managed), not from a local change.');
    return OK('Policy reaches win01 through its OU.');
  },
};

const verifyChecks: LabCheck[] = [
  rdpCheck,
  cmdCheck('srv', 'win01 finds the domain controller through DNS (SRV record _ldap._tcp.ad.corp.lab)', 'win01', 'Administrator', 'Resolve-DnsName -Type SRV _ldap._tcp.ad.corp.lab', (o) => (/dc01\.ad\.corp\.lab/i.test(o) ? null : 'win01 cannot find the DC\'s SRV record: check its DNS server.'), 'The DC locator works.'),
  cmdCheck('channel', 'win01\'s secure channel to the domain is healthy', 'win01', 'Administrator', 'Test-ComputerSecureChannel', (o) => (/^True/m.test(o) ? null : 'The secure channel is broken.'), 'Secure channel OK.'),
];

const GPO_COMMANDS = [
  `New-ADOrganizationalUnit -Name Servers -Path "${DN}" -Description "Member servers"`,
  `Move-ADObject -Identity "CN=WIN01,CN=Computers,${DN}" -TargetPath "${SERVERS}"`,
  'New-GPO -Name "Server Baseline" -Comment "Monitoring and hardening for member servers"',
  `New-NetFirewallRule -PolicyStore "ad.corp.lab\\Server Baseline" ${PING_RULE}`,
  `New-GPLink -Name "Server Baseline" -Target "${SERVERS}"`,
];

export const ILAB3: GuidedLab = {
  id: 'ilab3',
  title: 'Integrated Lab 3: Deploy an Active Directory Environment',
  level: 'intermediate',
  duration: '75–105 min',
  summary: 'Build centralised authentication and management for the Windows servers: a domain controller with AD-integrated DNS, accounts and groups, a member server joined through the domain\'s DNS, Remote Desktop through a domain group, and a Group Policy delivered through an OU. Then find out why logons fail after the member was moved to another host.',
  brief: `${LAB2.brief}

After the domain works, the servers must be **managed centrally**: create the OU **Servers**, move win01 into it, and deliver a firewall rule that lets monitoring ping the servers (ICMPv4 echo from 10.0.0.0/16, Domain profile) through a GPO **Server Baseline** linked to that OU, not by changing win01 by hand.`,
  objectives: [
    ...LAB2.objectives,
    'Deliver configuration through Group Policy: an OU, a GPO, a link, and the member applying it.',
    'Verify authentication, DNS (SRV records) and the secure channel together, and diagnose a Kerberos failure caused by time.',
  ],
  prerequisites: [...LAB2.prerequisites, { label: 'Group Policy', link: 'lesson/gpo/what' }],
  setupNote: LAB2.setupNote,
  terminals: LAB2.terminals,
  build: LAB2.build,
  steps: [
    reuseStep(LAB2, 'role', {
      commands: [{ host: 'dc01', command: 'Install-WindowsFeature AD-Domain-Services -IncludeManagementTools', what: 'Installs the AD DS binaries and the management tools (ActiveDirectory module, GPMC).', why: 'A server cannot be promoted without the role; without the tools you cannot administer the domain from PowerShell.', where: 'Get-WindowsFeature shows the installed roles and features.', success: 'Success True, Exit Code Success.', verify: 'Get-Command Install-ADDSForest exists.' }],
    }),
    reuseStep(LAB2, 'promote', {
      commands: [{ host: 'dc01', command: 'Install-ADDSForest -DomainName ad.corp.lab -DomainNetbiosName CORP -InstallDns', what: 'Creates a new forest with this server as its first domain controller, and a DNS server for the zone ad.corp.lab.', why: 'Members find DCs through DNS SRV records (_ldap._tcp, _kerberos._tcp) in the AD zone: AD and its DNS are deployed together.', where: 'The AD database (NTDS), SYSVOL, and the AD-integrated DNS zone.', success: 'The server restarts as a DC.', verify: 'Resolve-DnsName -Type SRV _ldap._tcp.ad.corp.lab on the DC; Get-ADDomain.' }],
    }),
    reuseStep(LAB2, 'accounts'),
    reuseStep(LAB2, 'member-dns', {
      commands: [{ host: 'win01', command: `Set-DnsClientServerAddress -InterfaceAlias Ethernet0 -ServerAddresses ${DC01_IP}`, what: 'Makes win01 ask dc01 for names.', why: 'Only the domain\'s DNS knows the SRV records that tell a member where the DCs are. ns1 does not have the AD zone (and forwards nothing to it): joining would fail with "domain could not be contacted".', where: 'Get-DnsClientServerAddress; the adapter\'s IPv4 settings.', success: 'No output.', verify: 'Resolve-DnsName ad.corp.lab and Resolve-DnsName www.corp.lab (the DC forwards other names to ns1).' }],
    }),
    reuseStep(LAB2, 'join', {
      commands: [{ host: 'win01', command: 'Add-Computer -DomainName ad.corp.lab -Credential CORP\\Administrator -Restart', what: 'Creates win01\'s computer account in AD, sets its machine password (the secure channel) and restarts.', why: 'Domain logons and Group Policy need the member to trust the domain.', where: 'The computer object CN=WIN01,CN=Computers,DC=ad,DC=corp,DC=lab.', success: 'The computer restarts.', verify: 'Test-ComputerSecureChannel → True; Get-NetConnectionProfile shows DomainAuthenticated.' }],
    }),
    reuseStep(LAB2, 'rdp'),
    {
      id: 'gpo', title: 'Manage the servers through Group Policy',
      objective: 'win01 is in OU=Servers, and the GPO "Server Baseline" linked to that OU delivers a firewall rule that lets monitoring ping it (ICMPv4 echo from 10.0.0.0/16).',
      background: 'Group Policy applies settings to the **computers (and users) in the containers a GPO is linked to**: the domain, or an **OU**. New computers land in the container CN=Computers, which cannot have GPOs linked: move them into an OU first.\n\nMembers fetch policy from the DC\'s **SYSVOL** over SMB at startup and every 90 minutes (or `gpupdate /force`). That is another dependency: DNS to find the DC, SMB (445) to read SYSVOL, LDAP to find the GPOs. `gpresult /r` on the member shows what applied and what was filtered.',
      tasks: [
        `On dc01: \`New-ADOrganizationalUnit -Name Servers -Path "${DN}"\` and \`Move-ADObject -Identity "CN=WIN01,CN=Computers,${DN}" -TargetPath "${SERVERS}"\`.`,
        '`New-GPO -Name "Server Baseline"`, then the rule in the GPO: `New-NetFirewallRule -PolicyStore "ad.corp.lab\\Server Baseline" -DisplayName "Monitoring - Echo Request (ICMPv4-In)" -Protocol ICMPv4 -IcmpType 8 -RemoteAddress 10.0.0.0/16 -Action Allow -Profile Domain`.',
        `\`New-GPLink -Name "Server Baseline" -Target "${SERVERS}"\`.`,
        'On win01: `gpupdate /force`, `gpresult /r`. From ws01: `ping -c 1 win01.corp.lab`.',
      ],
      hints: ['"Server Baseline" not in gpresult: is the GPO linked to the OU win01 is in (Get-ADComputer win01)?', 'A local rule on win01 would work too, but it is exactly what central management avoids.'],
      checks: [policyApplied],
      solution: [
        { host: 'dc01', user: 'Administrator', commands: GPO_COMMANDS },
        { host: 'win01', user: 'Administrator', commands: ['gpupdate /force'] },
      ],
      commands: [
        { host: 'win01', command: 'gpresult /r', what: 'Shows the Resultant Set of Policy: which GPOs applied to this computer (and user), and which were filtered out and why.', why: 'A GPO that "does not work" has usually not applied: wrong OU, link disabled, security filtering, or SYSVOL unreachable.', where: 'The member\'s policy state (registry, RSOP).', success: '"Applied Group Policy Objects" lists Server Baseline.', verify: 'The setting itself: Get-NetFirewallRule -PolicyStore RSOP, or the effect (ping from ws01).' },
      ],
      learn: [{ label: 'Group Policy', link: 'lesson/gpo/internals' }, { label: 'gpresult', link: 'reference?id=gpresult' }, { label: 'GPO troubleshooting', link: 'reference?id=proc:gpo-troubleshoot' }],
      concepts: ['ad.gpo'],
    },
    {
      id: 'verify', title: 'Verify authentication, DNS and policy, and after a reboot', stage: 'verify',
      objective: 'Domain logons over RDP, the DC locator (SRV records) and the secure channel work, and everything (including policy) still works after every machine restarts.',
      background: 'A domain is a web of dependencies: the member needs **DNS** (to find the DC), **time** within 5 minutes of the DC (**Kerberos**), its **secure channel** (machine password), and **SYSVOL** for policy. Test the services users rely on, not only the configuration.',
      tasks: ['From ws01: `xfreerdp /v:win01.corp.lab /u:CORP\\\\alice`.', 'On win01: `Resolve-DnsName -Type SRV _ldap._tcp.ad.corp.lab`, `Test-ComputerSecureChannel`, `w32tm /query /status`.', 'Run the check (reboots every machine on a copy and re-runs every check).'],
      hints: ['After a restart, GPOs are applied at startup: if ping fails only after the reboot, check gpresult again.'],
      checks: verifyChecks,
      solution: [],
      learn: [{ label: 'Kerberos for Windows logons', link: 'lesson/ad-kerberos/internals' }],
      concepts: ['ad.kerberos', 'ad.dns'],
      afterReboot: true,
    },
  ],
  integrated: {
    number: 3,
    scenario: {
      organisation: 'corp.lab: every Windows server has its own local accounts, and settings are changed by hand on each one.',
      situation: 'A fresh Windows Server 2022 (dc01) is waiting to become the first domain controller; win01 is a stand-alone member server to be.',
      goal: 'Central authentication (one account per person, groups for access) and central management (Group Policy) for the Windows servers.',
      whyItMatters: 'Active Directory is the heart of most company networks, and in competitions it is often the first thing attacked and the first thing that breaks: understanding its dependencies (DNS, time, the secure channel, SYSVOL) is what lets you fix it quickly.',
    },
    technologies: ['Windows Server roles', 'Active Directory Domain Services', 'AD-integrated DNS (SRV records, forwarders)', 'Kerberos and time', 'Group Policy (OUs, GPOs, links, SYSVOL)', 'Remote Desktop and logon rights'],
    systems: [
      { host: 'dc01', role: `${DC01_IP}: Windows Server 2022, becomes the DC of ad.corp.lab with DNS` },
      { host: 'win01', role: '10.0.20.30: Windows Server member (IIS, Remote Desktop)' },
      { host: 'ws01', role: 'alice\'s workstation: tests Remote Desktop and ping' },
      { host: 'ns1', role: 'The company DNS (corp.lab); the DC forwards other names to it' },
    ],
    startingState: [
      'dc01: fixed address, no roles installed, local Administrator only.',
      'win01: in a workgroup, DNS server ns1 (10.0.10.53), firewall on (ping blocked).',
      'No domain, no accounts, no GPOs.',
    ],
    tools: [
      { command: 'Install-WindowsFeature, Install-ADDSForest', platform: 'Windows', use: 'Role and promotion', refId: 'get-service' },
      { command: 'New-ADUser, New-ADGroup, Add-ADGroupMember, Get-ADComputer', platform: 'Windows', use: 'Accounts and groups', refId: 'move-adobject' },
      { command: 'Set-DnsClientServerAddress, Resolve-DnsName', platform: 'Windows', use: 'Member DNS and the DC locator records', refId: 'resolve-dnsname' },
      { command: 'Add-Computer, Test-ComputerSecureChannel, nltest /sc_query', platform: 'Windows', use: 'Joining and the secure channel', refId: 'nltest' },
      { command: 'New-GPO, New-GPLink, gpupdate, gpresult', platform: 'Windows', use: 'Group Policy', refId: 'gpresult' },
      { command: 'w32tm /query /status, klist', platform: 'Windows', use: 'Time and Kerberos tickets', refId: 'w32tm' },
      { command: 'xfreerdp /v:… /u:CORP\\alice', platform: 'Linux', use: 'Test a domain logon from the Linux workstation', refId: 'qwinsta' },
    ],
    dependencies: {
      explanation: `A domain logon to win01 ("CORP\\alice over RDP") depends on, in order:

1. **DNS on the member**: win01 asks dc01, which holds the AD zone with the SRV records (_ldap._tcp, _kerberos._tcp) that locate DCs. Asking ns1 instead finds nothing.
2. **Network and firewall** to the DC (LDAP 389, Kerberos 88, SMB 445 for SYSVOL).
3. **The secure channel**: win01's machine account and password, set at join time.
4. **Time**: Kerberos tickets are only valid if the clocks of client, member and DC are within 5 minutes.
5. **Authorisation**: alice in RDP-Users, which is in win01's local "Remote Desktop Users".

Group Policy adds: **the computer's OU** (a GPO linked elsewhere never applies) and **SYSVOL** over SMB.`,
      paths: [
        {
          id: 'rdp', label: 'alice logs on to win01 with Remote Desktop (CORP\\alice)',
          nodes: [
            hop('dns', 'win01.corp.lab resolves', 'ns1 has the record for the member server.', 'ws01', 'alice', 'getent hosts win01.corp.lab', (o) => /^10\.0\.20\.30\s/m.test(o)),
            hop('locator', 'win01 finds the DC', 'The SRV record _ldap._tcp.ad.corp.lab, from the DC\'s own DNS.', 'win01', 'Administrator', 'Resolve-DnsName -Type SRV _ldap._tcp.ad.corp.lab', (o) => /dc01\.ad\.corp\.lab/i.test(o)),
            hop('channel', 'Secure channel', 'win01\'s machine account in AD.', 'win01', 'Administrator', 'Test-ComputerSecureChannel', (o) => /^True/m.test(o)),
            hop('time', 'Clock in sync with the DC', 'W32Time on the member synchronizes from the domain hierarchy.', 'win01', 'Administrator', 'w32tm /query /status', (o, c) => c === 0 && !/not running|has not been started/i.test(o)),
            { id: 'logon', label: 'Kerberos logon over RDP', role: 'Ticket from the KDC on dc01; alice in RDP-Users.', host: 'ws01', probe: (w) => { const r = checkGoal(w, { kind: 'rdp', description: '', fromHost: 'ws01', localUser: 'alice', target: 'win01.corp.lab', user: 'CORP\\alice', password: AD_ALICE_PASSWORD }); return { ok: r.ok, evidence: r.lines.filter(Boolean).slice(-6).join('\n') }; } },
          ],
        },
        {
          id: 'policy', label: 'monitoring pings win01 (rule delivered by Group Policy)',
          nodes: [
            hop('ou', 'win01 is in OU=Servers', 'The GPO is linked to that OU.', 'dc01', 'Administrator', 'Get-ADComputer win01', (o) => /OU=Servers/i.test(o)),
            hop('applied', 'Policy applied on win01', 'Read from SYSVOL at startup or gpupdate.', 'win01', 'Administrator', 'gpresult /r', (o) => /Server Baseline/.test(o)),
            hop('ping', 'win01 answers ping', 'The policy\'s firewall rule in effect.', 'ws01', 'alice', 'ping -c 1 -W 2 win01.corp.lab', (_o, c) => c === 0),
          ],
        },
      ],
    },
    mistakes: [
      'Joining win01 while it still uses ns1 as DNS server ("the domain could not be contacted").',
      'Linking the GPO to the domain or an OU that win01 is not in, then wondering why gpresult does not show it.',
      'Creating the firewall rule locally on win01 "to make it work": the next policy refresh or rebuild loses it, and nobody knows it exists.',
      'Treating "logon failed" as a password problem when the evidence says time or the secure channel.',
    ],
    verification: 'Checks query the domain and the members directly (roles, SRV records, accounts, the computer\'s OU, gpresult, the secure channel) and test the results from a client (RDP logon as CORP\\alice, ping). The final check reboots every machine on a copy and repeats all checks. The incident is repaired when alice\'s domain logon works again, including after a reboot.',
    fault: ticketFault('krb-w32time-disabled', {
      title: 'Logons to win01 fail after the host migration',
      report: 'Alice (Wednesday): "RDP to win01 takes my password, then tells me there is a time difference between the client and server and logs me off." The virtualisation team: "We migrated win01 to the new host cluster last night; the VM was paused for a while."',
    }),
    review: [
      { id: 'q1', question: 'Why must win01 use dc01 (not ns1) as its DNS server before it can join the domain?', choices: ['Only the AD DNS zone has the SRV records that tell members where the domain controllers are', 'ns1 blocks Windows clients', 'Joining uses DNS to transfer the machine password', 'dc01 is the default gateway for win01'], answer: 0, explanation: 'Members locate DCs with SRV queries such as _ldap._tcp.ad.corp.lab. The DC answers them from the AD zone and forwards every other name to ns1.', concepts: ['ad.dns'] },
      { id: 'q2', question: 'The GPO "Server Baseline" exists and is linked to OU=Servers, but gpresult on win01 does not list it. What is the most likely reason?', choices: ['win01 is still in CN=Computers (or another OU)', 'GPOs need a reboot of the DC', 'The firewall rule in the GPO is disabled', 'alice is not in RDP-Users'], answer: 0, explanation: 'A GPO applies to objects in the containers it is linked to. CN=Computers is a container, not an OU, and cannot have links.', concepts: ['ad.gpo'] },
      { id: 'q3', question: 'Alice\'s password is right, the account is enabled, but her logon fails with a time-difference message. Which dependency failed?', choices: ['Kerberos: the member\'s clock is more than 5 minutes off', 'DNS: the SRV record is missing', 'The secure channel', 'RDP is disabled'], answer: 0, explanation: 'Kerberos tickets carry timestamps and are rejected when the clocks differ by more than the allowed skew (5 minutes). The fix is time synchronization, not the password.', concepts: ['ad.kerberos', 'ntp.sync'] },
      { id: 'q4', question: 'Why deliver the ping rule through a GPO instead of New-NetFirewallRule on win01?', choices: ['Central, documented and reapplied automatically to every server in the OU', 'Local rules do not work on member servers', 'GPO rules are faster', 'ping needs a domain profile'], answer: 0, explanation: 'Policy applies the same setting to every server in the OU, survives rebuilds and local changes, and is visible in one place.', concepts: ['ad.gpo'] },
      { id: 'q5', question: 'Which of these does a domain member need to read Group Policy at startup?', choices: ['DNS to find the DC, then SMB (445) to read SYSVOL', 'Only ICMP to the DC', 'RDP to the DC', 'A local copy of the GPO'], answer: 0, explanation: 'GPOs are found through LDAP and their files read from \\\\ad.corp.lab\\SYSVOL over SMB. A firewall that blocks 445 on the DC stops policy without breaking logons.', concepts: ['ad.gpo', 'ad.dns'] },
    ],
    after: ['windows-rdp', 'ad-kerberos', 'gpo', 'kerberos'],
  },
};

