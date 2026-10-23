// Lab 2: Windows Domain. Build the domain ad.corp.lab on a fresh Windows
// Server (dc01): install AD DS, promote the first domain controller with DNS,
// create the accounts, point the member server win01 at the domain's DNS, join
// it, grant Remote Desktop to a domain group, and prove it all survives a
// restart of every machine.

import { AD_ALICE_PASSWORD, DC01_ADMIN_PASSWORD, DC01_IP, installDc01 } from '../lab/winLab';
import { buildSshLab } from '../lab/sshLab';
import { checkGoal } from '../scenarios/engine';
import { bootHost } from '../sim/services';
import type { World } from '../types';
import { principalGroups } from '../win/ad';
import { probe } from './engine';
import type { GuidedLab, LabCheck } from './types';

const OK = (detail: string) => ({ ok: true, detail });
const NO = (detail: string) => ({ ok: false, detail });

export const LAB2_DSRM_PASSWORD = 'Dsrm-Lab2-2026';

export function buildLab2World(): World {
  const world = buildSshLab();
  // dc01 as the virtualisation team delivered it: Windows Server 2022, static address, no roles.
  delete world.hosts.dc01;
  const dc = installDc01(world, false);
  bootHost(world, dc);
  world.clock += 5 * 60_000;
  return world;
}

const ad = (w: World) => w.hosts.dc01.win!.ad;

// ---------------------------------------------------------------- checks

const roleInstalled: LabCheck = {
  id: 'adds-role', description: 'dc01: the Active Directory Domain Services role and its PowerShell module are installed',
  check(w) {
    const f = w.hosts.dc01.win!.features ?? [];
    if (!f.includes('AD-Domain-Services')) return NO('Get-WindowsFeature AD-Domain-Services: Available (not installed).');
    if (!f.includes('RSAT-AD-PowerShell')) return NO('AD DS is installed but not the management tools (RSAT-AD-PowerShell): use -IncludeManagementTools.');
    return OK('[X] Active Directory Domain Services, [X] Active Directory module for Windows PowerShell.');
  },
};

const isDcCheck: LabCheck = {
  id: 'dc-promoted', description: 'dc01 is the domain controller of ad.corp.lab (NetBIOS name CORP) and AD DS is running',
  check(w) {
    const a = ad(w);
    if (!a) return NO(w.hosts.dc01.win!.pendingDomain ? 'Promotion is configured but dc01 has not restarted yet.' : 'dc01 is not a domain controller (Install-ADDSForest).');
    if (a.domain !== 'ad.corp.lab' || a.netbios !== 'CORP') return NO(`dc01 hosts the domain ${a.domain} (NetBIOS ${a.netbios}); the plan is ad.corp.lab / CORP.`);
    if (w.hosts.dc01.win!.services.NTDS?.status !== 'Running') return NO('Active Directory Domain Services (NTDS) is not running: restart dc01 to finish the promotion.');
    return OK('Domain ad.corp.lab (CORP), NTDS running.');
  },
};

const dcSrv: LabCheck = {
  id: 'dc-srv', description: 'dc01\'s DNS server answers the DC locator record _ldap._tcp.dc._msdcs.ad.corp.lab',
  check(w) {
    const r = probe(w, 'dc01', 'Administrator', 'Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.ad.corp.lab -Server 127.0.0.1');
    return /SRV/.test(r.output) && r.code === 0 ? OK('_ldap._tcp.dc._msdcs.ad.corp.lab SRV 0 100 389 dc01.ad.corp.lab.') : NO(r.output.split('\n')[0] || 'no answer');
  },
};

const dcForwards: LabCheck = {
  id: 'dc-forwarder', description: 'dc01 resolves names outside the domain (srv01.corp.lab) by forwarding to ns1',
  check(w) {
    const r = probe(w, 'dc01', 'Administrator', 'Resolve-DnsName srv01.corp.lab -Type A -Server 127.0.0.1');
    if (/10\.0\.20\.10/.test(r.output)) return OK('srv01.corp.lab → 10.0.20.10 through the forwarder.');
    const f = w.hosts.dc01.win!.dnsServer?.forwarders ?? [];
    return NO(`srv01.corp.lab does not resolve on dc01 (forwarders: ${f.join(', ') || 'none'}). Add-DnsServerForwarder -IPAddress 10.0.10.53.`);
  },
};

const aliceAccount: LabCheck = {
  id: 'ad-alice', description: 'AD: the user CORP\\alice exists, is enabled and has the password from the plan',
  check(w) {
    const u = ad(w)?.users.alice;
    if (!u) return NO('Get-ADUser alice: not found.');
    if (!u.enabled) return NO('CORP\\alice is disabled (New-ADUser creates disabled accounts unless -Enabled $true and a password are given).');
    if (u.password !== AD_ALICE_PASSWORD) return NO('CORP\\alice\'s password is not the one in the plan.');
    return OK('alice: Enabled True.');
  },
};

const rdpGroup: LabCheck = {
  id: 'ad-rdp-group', description: 'AD: the global security group RDP-Users exists and alice is a member',
  check(w) {
    const a = ad(w);
    const g = a?.groups['rdp-users'];
    if (!a || !g) return NO('Get-ADGroup RDP-Users: not found.');
    if (g.scope !== 'Global') return NO(`RDP-Users is ${g.scope}; the plan is a Global group.`);
    if (!principalGroups(a, 'alice').includes('RDP-Users')) return NO('alice is not a member of RDP-Users.');
    return OK('RDP-Users (Global, Security): alice.');
  },
};

const memberDns: LabCheck = {
  id: 'member-dns', description: `win01 uses dc01 (${DC01_IP}) as its only DNS server and finds the domain controller`,
  check(w) {
    const dns = w.hosts.win01.win!.adapters.flatMap((a) => a.dns);
    if (dns.length !== 1 || dns[0] !== DC01_IP) return NO(`win01 DNS servers: ${dns.join(', ') || '(none)'}.`);
    const r = probe(w, 'win01', 'Administrator', 'Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.ad.corp.lab');
    return /SRV/.test(r.output) && r.code === 0 ? OK('win01 resolves _ldap._tcp.dc._msdcs.ad.corp.lab through dc01.') : NO(r.output.split('\n')[0] || 'no answer');
  },
};

const memberStillResolves: LabCheck = {
  id: 'member-dns-corp', description: 'win01 still resolves corp.lab names (srv01.corp.lab) through dc01',
  check(w) {
    const r = probe(w, 'win01', 'Administrator', 'Resolve-DnsName srv01.corp.lab -Type A');
    return /10\.0\.20\.10/.test(r.output) ? OK('srv01.corp.lab → 10.0.20.10.') : NO(r.output.split('\n')[0] || 'no answer');
  },
};

const joined: LabCheck = {
  id: 'member-joined', description: 'win01 is a member of ad.corp.lab (restarted after the join) with a working secure channel',
  check(w) {
    const win = w.hosts.win01.win!;
    if (!win.domain) return NO(win.pendingDomain ? 'The join is done but win01 has not restarted yet.' : 'win01 is in workgroup WORKGROUP (Add-Computer).');
    const r = probe(w, 'win01', 'Administrator', 'Test-ComputerSecureChannel');
    return r.output.trim() === 'True' ? OK('Member of ad.corp.lab; Test-ComputerSecureChannel: True.') : NO(`Test-ComputerSecureChannel: ${r.output.split('\n')[0]}`);
  },
};

const domainProfile: LabCheck = {
  id: 'member-profile', description: 'win01 is on its domain network (firewall profile DomainAuthenticated) and registered in AD DNS',
  check(w) {
    if (!w.hosts.win01.win!.domainNetwork) return NO('Get-NetConnectionProfile does not show DomainAuthenticated: win01 did not reach a DC when it started.');
    const zone = w.hosts.dc01.win!.dnsServer?.zones.find((z) => z.origin === 'ad.corp.lab.');
    const rec = zone?.records.find((r) => r.name === 'win01.ad.corp.lab.' && r.type === 'A');
    return rec ? OK(`DomainAuthenticated; win01.ad.corp.lab A ${rec.data}.`) : NO('win01.ad.corp.lab is not registered in the AD zone.');
  },
};

const rdpLocalGroup: LabCheck = {
  id: 'rdp-local-group', description: 'win01: CORP\\RDP-Users is a member of the local Remote Desktop Users group (and alice is not an administrator)',
  check(w) {
    const win = w.hosts.win01.win!;
    const members = (win.localDomainMembers?.['Remote Desktop Users'] ?? []).map((m) => m.toLowerCase());
    if (!members.includes('corp\\rdp-users')) return NO(`Remote Desktop Users contains: ${members.join(', ') || 'no domain principals'}.`);
    const admins = (win.localDomainMembers?.Administrators ?? []).map((m) => m.toLowerCase());
    if (admins.includes('corp\\alice') || admins.includes('corp\\rdp-users')) return NO('Domain users were added to the local Administrators group: Remote Desktop Users grants the logon right alone.');
    return OK('Remote Desktop Users: CORP\\RDP-Users.');
  },
};

const rdpWorks: LabCheck = {
  id: 'rdp-domain-logon', description: 'From ws01, alice logs on to win01 with Remote Desktop as CORP\\alice',
  check(w) {
    const r = checkGoal(w, { kind: 'rdp', description: '', fromHost: 'ws01', localUser: 'alice', target: 'win01.corp.lab', user: 'CORP\\alice', password: AD_ALICE_PASSWORD });
    return r.ok ? OK('xfreerdp: logged CORP\\alice on.') : NO(r.lines.filter(Boolean).slice(-2).join(' '));
  },
};

// ---------------------------------------------------------------- the lab

export const LAB2: GuidedLab = {
  id: 'lab2',
  title: 'Lab 2: Windows Domain',
  level: 'intermediate',
  duration: '60–90 min',
  summary: 'Create the Active Directory domain ad.corp.lab on a fresh Windows Server: install AD DS, promote the first domain controller with DNS, create accounts and a group, join the member server win01, grant Remote Desktop through a domain group, and prove it survives a restart.',
  brief: `The systems team wants central accounts for the Windows servers (CHG-1650). The virtualisation team delivered **dc01** (${DC01_IP}), a fresh Windows Server 2022 with a static address and no roles. Build the domain **ad.corp.lab** (NetBIOS name **CORP**) on it, with its own DNS forwarding everything else to ns1. Create **CORP\\alice** (password ${AD_ALICE_PASSWORD}) and a global group **RDP-Users** for Remote Desktop access. Then make **win01** a domain member and let RDP-Users log on to it with Remote Desktop. The change is only done when everything still works after a restart of every machine.`,
  objectives: [
    'Install a server role with Install-WindowsFeature and promote the first domain controller of a new forest.',
    'Understand AD-integrated DNS: the SRV records members use to find a DC, and forwarding to the corporate DNS.',
    'Create users and groups with the ActiveDirectory module.',
    'Point a member at the domain\'s DNS, join it, and verify the secure channel and the domain network profile.',
    'Grant a logon right through a domain group nested in a local group, and test it from a client.',
  ],
  prerequisites: [
    { label: 'Windows Server administration and RDP', link: 'lesson/windows-rdp/what' },
    { label: 'Active Directory, DNS and Kerberos', link: 'lesson/ad-kerberos/what' },
    { label: 'TCP, UDP and DNS', link: 'lesson/transport/what' },
  ],
  setupNote: `This lab uses **dc01** (${DC01_IP}, Windows Server 2022, no roles yet) and the member server **win01** (10.0.20.30), both on the server network.`,
  terminals: [
    { hostId: 'dc01', user: 'Administrator', label: 'dc01 console (PowerShell)', banner: `Windows PowerShell\nCopyright (C) Microsoft Corporation. All rights reserved.\n\ndc01 console (hypervisor), local Administrator (password ${DC01_ADMIN_PASSWORD}; after the promotion this is CORP\\Administrator). Fresh Windows Server 2022: Get-WindowsFeature, Get-NetIPConfiguration.` },
    { hostId: 'win01', user: 'Administrator', label: 'win01 console (PowerShell)', banner: 'Windows PowerShell\nCopyright (C) Microsoft Corporation. All rights reserved.\n\nwin01 console (hypervisor), local Administrator. Member server to be: IIS, Remote Desktop.' },
    { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'alice\'s Debian workstation. Test Remote Desktop with: xfreerdp /v:win01.corp.lab /u:CORP\\\\alice (in bash the backslash is typed twice).' },
  ],
  build: buildLab2World,
  steps: [
    {
      id: 'role', title: 'Install the AD DS role',
      objective: 'Install **Active Directory Domain Services** on dc01, with its management tools (the ActiveDirectory PowerShell module).',
      background: 'Windows Server adds capabilities as **roles and features** (Server Manager, or `Install-WindowsFeature`). Installing the AD DS role only copies the binaries and the deployment module (ADDSDeployment): the server is not a domain controller until it is **promoted**. `-IncludeManagementTools` adds the administration tools (RSAT: the ActiveDirectory module, Group Policy Management).',
      tasks: [
        'On dc01: `Get-WindowsFeature AD-Domain-Services, DNS` (both Available).',
        '`Install-WindowsFeature AD-Domain-Services -IncludeManagementTools`',
        'Check: `Get-WindowsFeature AD-Domain-Services, RSAT-AD-PowerShell` shows [X] Installed. `Get-Command Install-ADDSForest` now exists.',
      ],
      hints: ['Feature names, not display names: AD-Domain-Services.', 'Without -IncludeManagementTools the ActiveDirectory module (Get-ADUser...) is missing.'],
      checks: [roleInstalled],
      solution: [{ host: 'dc01', user: 'Administrator', commands: ['Install-WindowsFeature AD-Domain-Services -IncludeManagementTools'] }],
      learn: [{ label: 'Active Directory, DNS and Kerberos', link: 'lesson/ad-kerberos/internals' }],
      concepts: ['ad.dns'],
    },
    {
      id: 'promote', title: 'Promote dc01: a new forest with DNS',
      objective: 'Create the forest and domain **ad.corp.lab** (NetBIOS **CORP**) on dc01, with the DNS Server role, and let it restart. dc01 must then answer the DC locator SRV records and still resolve corp.lab names by forwarding to ns1.',
      background: '`Install-ADDSForest` turns the server into the first DC: it creates the directory database, makes the local Administrator the domain\'s **CORP\\Administrator** (same password), asks for the **Directory Services Restore Mode** (DSRM) password, installs DNS with the AD-integrated zone **ad.corp.lab** and the records members use to find a DC (`_ldap._tcp.dc._msdcs.ad.corp.lab`), points dc01\'s own DNS client at itself, and turns its previous DNS servers into **forwarders** for every other name. The promotion finishes with a restart. The warning about a DNS delegation is expected: ns1 (BIND) does not delegate ad.corp.lab, so only machines that use dc01 for DNS see the domain.',
      tasks: [
        `\`Install-ADDSForest -DomainName ad.corp.lab -DomainNetbiosName CORP -InstallDns -SafeModeAdministratorPassword (ConvertTo-SecureString '${LAB2_DSRM_PASSWORD}' -AsPlainText -Force) -Force\``,
        'After the restart: `Get-ADDomain`, `Get-Service NTDS, DNS, Kdc, Netlogon`, `Get-DnsServerResourceRecord -ZoneName ad.corp.lab -RRType SRV`.',
        'Forwarding: `Get-DnsServerForwarder` (10.0.10.53) and `Resolve-DnsName srv01.corp.lab -Server 127.0.0.1`.',
      ],
      hints: [
        'Without -SafeModeAdministratorPassword the cmdlet asks for it twice; without -Force it asks for confirmation.',
        'The forwarders come from dc01\'s DNS client settings before the promotion (ns1). If they are missing: Add-DnsServerForwarder -IPAddress 10.0.10.53.',
      ],
      checks: [isDcCheck, dcSrv, dcForwards],
      solution: [{ host: 'dc01', user: 'Administrator', commands: [`Install-ADDSForest -DomainName ad.corp.lab -DomainNetbiosName CORP -InstallDns -SafeModeAdministratorPassword (ConvertTo-SecureString '${LAB2_DSRM_PASSWORD}' -AsPlainText -Force) -Force`] }],
      learn: [{ label: 'Active Directory, DNS and Kerberos: how it works', link: 'lesson/ad-kerberos/internals' }, { label: 'Resolve-DnsName', link: 'reference?id=resolve-dnsname' }],
      concepts: ['ad.dns', 'dns.zone'],
    },
    {
      id: 'accounts', title: 'Create the user and the group',
      objective: `Create **CORP\\alice** (Alice Martin, password ${AD_ALICE_PASSWORD}, enabled) and the **global security group RDP-Users** with alice as a member.`,
      background: 'Accounts live in the directory now, not on each server. `New-ADUser` creates a **disabled** account unless it gets a password that meets the domain policy and `-Enabled $true`. Access is granted to **groups**, never to individual users: a global group (RDP-Users) collects the people, and each server grants rights to that group.',
      tasks: [
        `\`New-ADUser -Name "Alice Martin" -SamAccountName alice -UserPrincipalName alice@ad.corp.lab -AccountPassword (ConvertTo-SecureString '${AD_ALICE_PASSWORD}' -AsPlainText -Force) -Enabled $true\``,
        '`New-ADGroup -Name RDP-Users -GroupScope Global -Description "May log on to member servers with Remote Desktop"`',
        '`Add-ADGroupMember -Identity RDP-Users -Members alice`, then `Get-ADGroupMember RDP-Users` and `Get-ADUser alice`.',
      ],
      hints: ['If alice shows Enabled False: Set-ADAccountPassword -Identity alice -Reset -NewPassword (...), then Enable-ADAccount alice.', 'The password must meet the complexity rules (7+ characters, three character classes).'],
      checks: [aliceAccount, rdpGroup],
      solution: [{ host: 'dc01', user: 'Administrator', commands: [
        `New-ADUser -Name "Alice Martin" -SamAccountName alice -UserPrincipalName alice@ad.corp.lab -AccountPassword (ConvertTo-SecureString '${AD_ALICE_PASSWORD}' -AsPlainText -Force) -Enabled $true`,
        'New-ADGroup -Name RDP-Users -GroupScope Global -Description "May log on to member servers with Remote Desktop"',
        'Add-ADGroupMember -Identity RDP-Users -Members alice',
      ] }],
      learn: [{ label: 'Active Directory, DNS and Kerberos: operate', link: 'lesson/ad-kerberos/operate' }],
      concepts: ['ad.gpo'],
    },
    {
      id: 'member-dns', title: 'Point win01 at the domain\'s DNS',
      objective: `Make dc01 (${DC01_IP}) win01's only DNS server, so that it can find the domain controller, and check that corp.lab names still resolve.`,
      background: 'A member finds its domain controllers by asking **its own DNS servers** for `_ldap._tcp.dc._msdcs.<domain>`. ns1 does not host ad.corp.lab, so a member that asks ns1 cannot even start a join. Members therefore use the AD DNS servers only, and those forward other names (corp.lab, the Internet) to the corporate resolvers. Never mix an AD and a non-AD DNS server on a member: the second one is used when the first is slow, and then the domain "disappears".',
      tasks: [
        'On win01: `Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.ad.corp.lab` fails (ns1 does not know the zone).',
        `\`Set-DnsClientServerAddress -InterfaceAlias Ethernet0 -ServerAddresses ${DC01_IP}\``,
        'Check: the SRV lookup now answers dc01.ad.corp.lab, and `Resolve-DnsName srv01.corp.lab` still works (through dc01\'s forwarder).',
      ],
      hints: ['Get-DnsClientServerAddress -AddressFamily IPv4 shows the current setting.'],
      checks: [memberDns, memberStillResolves],
      solution: [{ host: 'win01', user: 'Administrator', commands: [`Set-DnsClientServerAddress -InterfaceAlias Ethernet0 -ServerAddresses ${DC01_IP}`] }],
      learn: [{ label: 'Active Directory, DNS and Kerberos: troubleshooting', link: 'lesson/ad-kerberos/troubleshoot' }],
      concepts: ['ad.dns', 'dns.resolution'],
    },
    {
      id: 'join', title: 'Join win01 to the domain',
      objective: 'Join win01 to **ad.corp.lab** with the domain Administrator\'s credentials and restart it. After the restart win01 must have a working secure channel, be on its domain network, and be registered in AD DNS.',
      background: 'Joining creates a **computer account** (WIN01$) in AD with a password that only the member and the DC know: the **secure channel**, which the member uses to authenticate itself and to pass users\' logons to a DC. The join takes effect at the restart: Netlogon starts, the member locates a DC, Network Location Awareness switches the firewall to the **Domain** profile, and the DNS client registers win01.ad.corp.lab in the AD zone. Domain Admins become members of the local Administrators group.',
      tasks: [
        '`Add-Computer -DomainName ad.corp.lab -Credential CORP\\Administrator -Restart` (it asks for the password).',
        'After the restart: `Test-ComputerSecureChannel` (True), `nltest /sc_query:ad.corp.lab`, `Get-NetConnectionProfile` (DomainAuthenticated), `Get-LocalGroupMember Administrators`.',
        'On dc01: `Get-ADComputer -Filter *` and `Get-DnsServerResourceRecord -ZoneName ad.corp.lab -Name win01`.',
      ],
      hints: [
        '"The specified domain either does not exist or could not be contacted": win01 cannot find a DC. Check the previous step (DNS).',
        'Without -Restart, the join waits for the next restart: Restart-Computer.',
      ],
      checks: [joined, domainProfile],
      solution: [{ host: 'win01', user: 'Administrator', commands: ['Add-Computer -DomainName ad.corp.lab -Credential CORP\\Administrator -Restart'], answers: [DC01_ADMIN_PASSWORD] }],
      learn: [{ label: 'nltest', link: 'reference?id=nltest' }, { label: 'Active Directory, DNS and Kerberos: operate', link: 'lesson/ad-kerberos/operate' }],
      concepts: ['ad.kerberos', 'ad.dns'],
    },
    {
      id: 'rdp', title: 'Grant Remote Desktop to RDP-Users',
      objective: 'Let members of **CORP\\RDP-Users** log on to win01 with Remote Desktop, without making anybody an administrator, and test it from ws01 as CORP\\alice.',
      background: 'The right "Allow log on through Remote Desktop Services" is granted on member servers to the local groups **Administrators** and **Remote Desktop Users**. Nest the domain group in the local group (here by hand; in production with Group Policy "Restricted Groups" or "Local Users and Groups"). The logon is then checked in two places: the DC validates the password (NTLM pass-through over the secure channel), win01 checks the logon right from the user\'s group memberships.',
      tasks: [
        'From ws01: `xfreerdp /v:win01.corp.lab /u:CORP\\\\alice` → insufficient access privileges (authentication works, the right is missing).',
        'On win01: `Add-LocalGroupMember -Group "Remote Desktop Users" -Member "CORP\\RDP-Users"`, then `Get-LocalGroupMember "Remote Desktop Users"`.',
        'From ws01 again: the session opens. On win01: `Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4624} -MaxEvents 1 | Format-List Message`.',
      ],
      hints: ['Add the group, not the user: the next person who joins RDP-Users gets access without touching the server.'],
      checks: [rdpLocalGroup, rdpWorks],
      solution: [{ host: 'win01', user: 'Administrator', commands: ['Add-LocalGroupMember -Group "Remote Desktop Users" -Member "CORP\\RDP-Users"'] }],
      learn: [{ label: 'Windows Server administration and RDP: troubleshooting', link: 'lesson/windows-rdp/troubleshoot' }],
      concepts: ['win.rdp'],
    },
    {
      id: 'reboot', title: 'Reboot test',
      objective: 'Restart every machine (dc01 first, then the members) and confirm everything above still holds.',
      background: 'Domain membership, DNS registration, the network profile and the logon path are all re-established at boot, in order: the DC must be up before members look for it. A member that boots without reaching a DC falls back to the Private/Public profile and logs NETLOGON 5719.',
      tasks: ['Run "Check" on this step: it restarts every machine on a copy of the lab and re-runs all checks.'],
      hints: ['If only the reboot test fails, something was configured at runtime only.'],
      checks: [],
      solution: [],
      learn: [{ label: 'Safe configuration change', link: 'reference?id=proc:safe-config-change' }],
      concepts: ['ops.recovery'],
      afterReboot: true,
    },
  ],
};
