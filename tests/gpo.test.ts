import { describe, expect, it } from 'vitest';
import { buildSshLab } from '../src/engine/lab/sshLab';
import { findScenario } from '../src/engine/scenarios';
import { joinWin01 } from '../src/engine/scenarios/domainScenarios';
import { rebootAll, verifyScenario } from '../src/engine/scenarios/engine';
import { PING_RULE } from '../src/engine/scenarios/gpoScenarios';
import type { World } from '../src/engine/types';
import { Lab } from './helpers';

const DN = 'DC=ad,DC=corp,DC=lab';
const SERVERS = `OU=Servers,${DN}`;

function domain(): Lab {
  const w = buildSshLab();
  joinWin01(w);
  const l = new Lab(w);
  for (const c of [`New-ADOrganizationalUnit -Name Servers -Path "${DN}"`, 'New-GPO -Name "Server Baseline"', `New-NetFirewallRule -PolicyStore "ad.corp.lab\\Server Baseline" ${PING_RULE}`, `New-GPLink -Name "Server Baseline" -Target "${SERVERS}"`]) l.run('dc01', 'Administrator', c);
  return l;
}
const ping = (l: Lab) => /1 received/.test(l.run('ws01', 'alice', 'ping -c 1 -W 1 win01.corp.lab').output);
const gpresult = (l: Lab) => l.run('win01', 'Administrator', 'gpresult /r').output;

describe('Group Policy: scope and precedence', () => {
  it('a GPO applies only below the OU it is linked to; joining with -OUPath puts the computer there', () => {
    const l = domain();
    l.run('win01', 'Administrator', 'gpupdate /force');
    expect(ping(l)).toBe(false);
    expect(gpresult(l)).toMatch(/CN=WIN01,CN=Computers,DC=ad,DC=corp,DC=lab[\s\S]*Applied Group Policy Objects\n {4}-+\n {8}Default Domain Policy\n\n/);
    l.run('dc01', 'Administrator', `Move-ADObject -Identity "CN=WIN01,CN=Computers,${DN}" -TargetPath "${SERVERS}"`);
    l.run('win01', 'Administrator', 'gpupdate /force');
    expect(ping(l)).toBe(true);
    expect(gpresult(l)).toMatch(/Applied Group Policy Objects\n {4}-+\n {8}Server Baseline\n {8}Default Domain Policy\n/);
    expect(l.run('win01', 'Administrator', 'Get-NetFirewallRule -PolicyStore RSOP | Format-List DisplayName,PolicyStoreSourceType,PolicyStoreSource').output).toMatch(/DisplayName +: Monitoring - Echo Request \(ICMPv4-In\)\nPolicyStoreSourceType : GroupPolicy\nPolicyStoreSource +: ad\.corp\.lab\\Server Baseline/);
    // Unlinking removes the setting at the next processing.
    l.run('dc01', 'Administrator', `Remove-GPLink -Name "Server Baseline" -Target "${SERVERS}"`);
    l.run('win01', 'Administrator', 'gpupdate /force');
    expect(ping(l)).toBe(false);
  });

  it('-OUPath at join time, and a disabled link or an empty GPO', () => {
    const w = buildSshLab();
    const l = new Lab(w);
    l.run('dc01', 'Administrator', `New-ADOrganizationalUnit -Name Servers -Path "${DN}"`);
    l.run('win01', 'Administrator', 'Set-DnsClientServerAddress -InterfaceAlias Ethernet0 -ServerAddresses 10.0.20.5');
    l.run('win01', 'Administrator', `Add-Computer -DomainName ad.corp.lab -OUPath "${SERVERS}" -Credential (New-Object System.Management.Automation.PSCredential("CORP\\Administrator", (ConvertTo-SecureString "${w.hosts.dc01.users.Administrator.password}" -AsPlainText -Force))) -Restart`);
    expect(l.run('dc01', 'Administrator', 'Get-ADComputer win01').output).toMatch(/DistinguishedName : CN=WIN01,OU=Servers,DC=ad,DC=corp,DC=lab/);
    l.run('dc01', 'Administrator', 'New-GPO -Name "Empty"');
    l.run('dc01', 'Administrator', `New-GPLink -Name "Empty" -Target "${SERVERS}"`);
    l.run('win01', 'Administrator', 'gpupdate /force');
    expect(gpresult(l)).toMatch(/ {8}Empty\n {12}Filtering: {2}Not Applied \(Empty\)/);
  });

  it('Block Inheritance stops domain links except enforced ones', () => {
    const l = domain();
    l.run('dc01', 'Administrator', `Move-ADObject -Identity "CN=WIN01,CN=Computers,${DN}" -TargetPath "${SERVERS}"`);
    for (const c of ['New-GPO -Name "Domain Ping"', `New-NetFirewallRule -PolicyStore "ad.corp.lab\\Domain Ping" ${PING_RULE.replace('Monitoring', 'Domain')}`, `New-GPLink -Name "Domain Ping" -Target "${DN}"`, `Remove-GPLink -Name "Server Baseline" -Target "${SERVERS}"`, `Set-GPInheritance -Target "${SERVERS}" -IsBlocked Yes`]) l.run('dc01', 'Administrator', c);
    l.run('win01', 'Administrator', 'gpupdate /force');
    expect(ping(l)).toBe(false);
    expect(l.run('dc01', 'Administrator', `Get-GPInheritance -Target "${SERVERS}"`).output).toMatch(/GpoInheritanceBlocked : Yes\nGpoLinks +: \{\}\nInheritedGpoLinks +: \{\}/);
    l.run('dc01', 'Administrator', `Set-GPLink -Name "Domain Ping" -Target "${DN}" -Enforced Yes`);
    l.run('win01', 'Administrator', 'gpupdate /force');
    expect(ping(l)).toBe(true);
  });
});

describe('Group Policy: filtering, SYSVOL and registry policy', () => {
  it('a computer\'s group membership counts only after a restart (its token)', () => {
    const l = domain();
    l.run('dc01', 'Administrator', `Move-ADObject -Identity "CN=WIN01,CN=Computers,${DN}" -TargetPath "${SERVERS}"`);
    for (const c of ['New-ADGroup -Name "Baseline Servers" -GroupScope Global', 'Set-GPPermission -Name "Server Baseline" -TargetName "Baseline Servers" -TargetType Group -PermissionLevel GpoApply', 'Set-GPPermission -Name "Server Baseline" -TargetName "Authenticated Users" -TargetType Group -PermissionLevel GpoRead -Replace', 'Add-ADGroupMember -Identity "Baseline Servers" -Members "WIN01$"']) l.run('dc01', 'Administrator', c);
    l.run('win01', 'Administrator', 'gpupdate /force');
    expect(gpresult(l)).toMatch(/Server Baseline\n {12}Filtering: {2}Denied \(Security\)/);
    l.run('win01', 'Administrator', 'Restart-Computer -Force');
    expect(gpresult(l)).toMatch(/Applied Group Policy Objects\n {4}-+\n {8}Server Baseline/);
    expect(gpresult(l)).toMatch(/ {8}CORP\\Baseline Servers/);
    // Without Read for the computer at all, the GPO is inaccessible (MS16-072).
    l.run('dc01', 'Administrator', 'Set-GPPermission -Name "Server Baseline" -TargetName "Authenticated Users" -TargetType Group -PermissionLevel None -Replace');
    l.run('dc01', 'Administrator', 'Set-GPPermission -Name "Server Baseline" -TargetName "Baseline Servers" -TargetType Group -PermissionLevel None -Replace');
    l.run('win01', 'Administrator', 'gpupdate /force');
    expect(gpresult(l)).toMatch(/Server Baseline\n {12}Filtering: {2}Inaccessible/);
  });

  it('SYSVOL over SMB: a blocked 445 on the DC fails processing with event 1058 and keeps the old settings', () => {
    const l = domain();
    l.run('dc01', 'Administrator', `Move-ADObject -Identity "CN=WIN01,CN=Computers,${DN}" -TargetPath "${SERVERS}"`);
    l.run('win01', 'Administrator', 'gpupdate /force');
    l.run('dc01', 'Administrator', 'Disable-NetFirewallRule -Name FPS-SMB-In-TCP');
    const r = l.run('win01', 'Administrator', 'gpupdate /force');
    expect(r.output).toMatch(/Computer policy could not be updated successfully\. The following errors were encountered:\n\nThe processing of Group Policy failed\. Windows attempted to read the file \\\\ad\.corp\.lab\\sysvol\\ad\.corp\.lab\\Policies\\\{[0-9A-F-]+\}\\gpt\.ini from a domain controller and was not successful\./);
    expect(l.run('win01', 'Administrator', 'Get-WinEvent -LogName System -MaxEvents 3 | Format-List Id,ProviderName').output).toMatch(/Id +: 1058\nProviderName : Microsoft-Windows-GroupPolicy/);
    expect(ping(l)).toBe(true);
  });

  it('registry policy: fDenyTSConnections from a GPO turns Remote Desktop off, and back on when it stops applying', () => {
    const l = domain();
    l.run('dc01', 'Administrator', `Move-ADObject -Identity "CN=WIN01,CN=Computers,${DN}" -TargetPath "${SERVERS}"`);
    l.run('dc01', 'Administrator', 'Set-GPRegistryValue -Name "Server Baseline" -Key "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -ValueName fDenyTSConnections -Type DWord -Value 1');
    expect(l.run('dc01', 'Administrator', 'Get-GPRegistryValue -Name "Server Baseline" -Key "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"').output).toMatch(/ValueName +: fDenyTSConnections/);
    l.run('win01', 'Administrator', 'gpupdate /force');
    expect(l.run('win01', 'Administrator', 'Get-Service TermService | Format-List Status').output).toMatch(/Status : Stopped/);
    l.run('dc01', 'Administrator', 'Remove-GPRegistryValue -Name "Server Baseline" -Key "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -ValueName fDenyTSConnections');
    l.run('win01', 'Administrator', 'gpupdate /force');
    expect(l.run('win01', 'Administrator', 'Get-Service TermService | Format-List Status').output).toMatch(/Status : Running/);
  });

  it('policy is processed at startup', () => {
    const l = domain();
    l.run('dc01', 'Administrator', `Move-ADObject -Identity "CN=WIN01,CN=Computers,${DN}" -TargetPath "${SERVERS}"`);
    const w: World = rebootAll(l.world);
    expect(ping(new Lab(w))).toBe(true);
  });
});

const TS = 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services';
const tsPolicy = (w: World) => Object.entries(w.hosts.win01.win!.registry).find(([k]) => /policies\\microsoft\\windows nt\\terminal services$/i.test(k))?.[1]?.fDenyTSConnections;

describe('Group Policy: review fixes', () => {
  it('enforced links: order 1 wins within a container, and a GPO linked twice keeps its enforced precedence', () => {
    const l = domain();
    const dc = (c: string) => l.run('dc01', 'Administrator', c);
    dc(`Move-ADObject -Identity "CN=WIN01,CN=Computers,${DN}" -TargetPath "${SERVERS}"`);
    for (const [n, v] of [['A', 0], ['B', 1]] as const) {
      dc(`New-GPO -Name ${n}`);
      dc(`Set-GPRegistryValue -Name ${n} -Key "${TS}" -ValueName fDenyTSConnections -Type DWord -Value ${v}`);
      dc(`New-GPLink -Name ${n} -Target "${DN}" -Enforced Yes`);
    }
    l.run('win01', 'Administrator', 'gpupdate /force');
    expect(tsPolicy(l.world)).toBe(0);
    // X is linked to the OU and enforced at the domain: it beats the conflicting OU GPO Y.
    dc(`Remove-GPLink -Name A -Target "${DN}"`); dc(`Remove-GPLink -Name B -Target "${DN}"`);
    dc('New-GPO -Name X'); dc(`Set-GPRegistryValue -Name X -Key "${TS}" -ValueName fDenyTSConnections -Type DWord -Value 0`);
    dc('New-GPO -Name Y'); dc(`Set-GPRegistryValue -Name Y -Key "${TS}" -ValueName fDenyTSConnections -Type DWord -Value 1`);
    dc(`New-GPLink -Name X -Target "${SERVERS}"`); dc(`New-GPLink -Name Y -Target "${SERVERS}" -Order 1`);
    dc(`New-GPLink -Name X -Target "${DN}" -Enforced Yes`);
    l.run('win01', 'Administrator', 'gpupdate /force');
    expect(tsPolicy(l.world)).toBe(0);
  });

  it('one registry key whatever the hive spelling', () => {
    const l = domain();
    l.run('dc01', 'Administrator', `Set-GPRegistryValue -Name "Server Baseline" -Key "${TS}" -ValueName fDenyTSConnections -Type DWord -Value 1`);
    l.run('dc01', 'Administrator', `Set-GPRegistryValue -Name "Server Baseline" -Key "${TS.replace('HKLM', 'HKLM:')}" -ValueName fDenyTSConnections -Type DWord -Value 0`);
    const out = l.run('dc01', 'Administrator', `Get-GPRegistryValue -Name "Server Baseline" -Key "${TS}"`).output;
    expect(out.match(/ValueName +: fDenyTSConnections/g)).toHaveLength(1);
    expect(out).toMatch(/Value +: 0/);
  });

  it('piped GPO rules change the GPO; RSOP is read-only; mandatory names', () => {
    const l = domain();
    const dc = (c: string) => l.run('dc01', 'Administrator', c);
    dc(`Move-ADObject -Identity "CN=WIN01,CN=Computers,${DN}" -TargetPath "${SERVERS}"`);
    const before = dc('(Get-GPO -Name "Server Baseline").ComputerVersion').output;
    dc('Get-NetFirewallRule -PolicyStore "ad.corp.lab\\Server Baseline" | Disable-NetFirewallRule');
    expect(dc('Get-NetFirewallRule -PolicyStore "ad.corp.lab\\Server Baseline" | Format-List Enabled').output).toMatch(/Enabled : False/);
    expect(dc('(Get-GPO -Name "Server Baseline").ComputerVersion').output).not.toBe(before);
    dc('Get-NetFirewallRule -PolicyStore "ad.corp.lab\\Server Baseline" | Enable-NetFirewallRule');
    l.run('win01', 'Administrator', 'gpupdate /force');
    expect(ping(l)).toBe(true);
    const rm = l.run('win01', 'Administrator', 'Remove-NetFirewallRule -PolicyStore RSOP -DisplayName "Monitoring*"').output;
    expect(rm).toMatch(/The request is not supported/);
    expect(ping(l)).toBe(true);
    // -WhatIf and a bad store change nothing and report once.
    const v = dc('(Get-GPO -Name "Server Baseline").ComputerVersion').output;
    dc('Disable-NetFirewallRule -PolicyStore "ad.corp.lab\\Server Baseline" -DisplayName "Monitoring*" -WhatIf');
    expect(dc('(Get-GPO -Name "Server Baseline").ComputerVersion').output).toBe(v);
    expect(dc('Enable-NetFirewallRule -PolicyStore "ad.corp.lab\\Typo" -DisplayName X').output.match(/cannot find the file/g)).toHaveLength(1);
    expect(l.run('dc01', 'Administrator', `New-ADOrganizationalUnit -Path "${DN}"`).needInput?.text).toMatch(/Supply values for the following parameters:\nName: $/);
    expect(l.run('dc01', 'Administrator', 'New-GPO').needInput?.text).toMatch(/Name: $/);
  });

  it('leaving the domain removes the settings Group Policy wrote', () => {
    const l = domain();
    l.run('dc01', 'Administrator', `Move-ADObject -Identity "CN=WIN01,CN=Computers,${DN}" -TargetPath "${SERVERS}"`);
    l.run('win01', 'Administrator', 'gpupdate /force');
    expect(ping(l)).toBe(true);
    l.run('win01', 'Administrator', `Remove-Computer -UnjoinDomainCredential (New-Object System.Management.Automation.PSCredential("CORP\\Administrator", (ConvertTo-SecureString "${l.world.hosts.dc01.users.Administrator.password}" -AsPlainText -Force))) -WorkgroupName WORKGROUP -Force -Restart`);
    expect(l.world.hosts.win01.win!.domain).toBeUndefined();
    expect(ping(l)).toBe(false);
    expect(l.run('win01', 'Administrator', 'Get-NetFirewallRule -PolicyStore RSOP').output.trim()).toBe('');
  });
});

describe('GPO tickets: wrong fixes are rejected', () => {
  const broken = (id: string) => {
    const s = findScenario(id)!;
    const world = buildSshLab();
    s.setup(world);
    return { s, l: new Lab(world) };
  };

  it('a local firewall exception instead of policy', () => {
    const { s, l } = broken('gpo-wrong-ou');
    l.run('win01', 'Administrator', 'Enable-NetFirewallRule -Name FPS-ICMP4-ERQ-In');
    const v = verifyScenario(l.world, s);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(v.passed).toBe(false);
  });

  it('dropping the security filter instead of restarting', () => {
    const { s, l } = broken('gpo-filter-token');
    l.run('dc01', 'Administrator', 'Set-GPPermission -Name "Server Baseline" -TargetName "Authenticated Users" -TargetType Group -PermissionLevel GpoApply');
    l.run('win01', 'Administrator', 'gpupdate /force');
    const v = verifyScenario(l.world, s);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(v.passed).toBe(false);
  });

  it('unblocking inheritance brings Workstation Lockdown to the servers', () => {
    const { s, l } = broken('gpo-blocked-inheritance');
    l.run('dc01', 'Administrator', `Set-GPInheritance -Target "${SERVERS}" -IsBlocked No`);
    l.run('win01', 'Administrator', 'gpupdate /force');
    const v = verifyScenario(l.world, s);
    expect(v.now.map((g) => g.ok)).toEqual([true, false]);
    expect(v.passed).toBe(false);
  });
});
