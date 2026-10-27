import { describe, expect, it } from 'vitest';
import { buildSshLab } from '../src/engine/lab/sshLab';
import { findScenario } from '../src/engine/scenarios';
import { joinWin01 } from '../src/engine/scenarios/domainScenarios';
import { verifyScenario } from '../src/engine/scenarios/engine';
import { Lab } from './helpers';

const LOG = 'C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log';

function win() {
  const lab = new Lab();
  const sh = lab.shell('win01', 'Administrator');
  return { lab, run: (line: string) => sh.execute(line, []) };
}
const web = (lab: Lab) => lab.run('ws01', 'alice', 'curl -s -m 2 -o /dev/null -w "%{http_code}" http://win01.corp.lab/');
const nc = (lab: Lab, port: number) => lab.run('ws01', 'alice', `nc -zv -w 2 win01 ${port}`);

describe('Windows Defender Firewall: logging', () => {
  it('pfirewall.log records drops only when LogBlocked is on', () => {
    const { lab, run } = win();
    lab.run('ws01', 'alice', 'ping -c 1 -W 1 win01');
    expect(run(`Test-Path ${LOG}`).output).toBe('False');
    run('Set-NetFirewallProfile -All -LogBlocked True');
    expect(run('(Get-NetFirewallProfile -Name Private).LogBlocked').output).toBe('True');
    lab.run('ws01', 'alice', 'ping -c 1 -W 1 win01');
    nc(lab, 8080);
    const log = run(`Get-Content ${LOG}`).output;
    expect(log).toContain('#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path');
    expect(log).toMatch(/DROP ICMP 10\.0\.\d+\.\d+ 10\.0\.20\.30 - - \d+ - - - - 8 0 - RECEIVE/);
    expect(log).toMatch(/DROP TCP 10\.0\.\d+\.\d+ 10\.0\.20\.30 \d+ 8080 \d+ S \d+ 0 \d+ - - - RECEIVE/);
    expect(log).not.toContain('ALLOW');
  });

  it('LogAllowed records new connections, not their replies; netsh sets both', () => {
    const { lab, run } = win();
    expect(run('netsh advfirewall set allprofiles logging allowedconnections enable').output).toBe('Ok.');
    const shown = run('netsh advfirewall show currentprofile logging').output;
    expect(shown).toMatch(/^Private Profile Settings: \n-+\nLogAllowedConnections\s+Enable\nLogDroppedConnections\s+Disable\n/m);
    expect(shown).not.toContain('Firewall Policy');
    expect(web(lab).output).toBe('200');
    const lines = run(`Get-Content ${LOG} | Select-String ALLOW`).output.split('\n').filter((l) => l.includes(' 80 '));
    expect(lines.length).toBe(1);
    expect(lines[0]).toMatch(/ALLOW TCP \S+ 10\.0\.20\.30 \d+ 80 .* RECEIVE/);
  });
});

describe('Windows Defender Firewall: log rollover', () => {
  it('the log moves to pfirewall.log.old at LogMaxSizeKilobytes', () => {
    const { lab, run } = win();
    run('Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 1');
    for (let i = 0; i < 15; i++) lab.run('ws01', 'alice', 'ping -c 1 -W 1 win01');
    expect(run(`Test-Path ${LOG}.old`).output).toBe('True');
    expect(run(`(Get-Content ${LOG})[0]`).output).toBe('#Version: 1.5');
    expect(run('Set-NetFirewallProfile -All -LogMaxSizeKilobytes 40000').output).toContain('maximum allowed range of 32767');
  });
});

describe('Windows Defender Firewall: rule conditions', () => {
  it('RemoteAddress, RemotePort and LocalAddress narrow a rule', () => {
    const { lab, run } = win();
    run('Enable-NetFirewallRule -Name FPS-ICMP4-ERQ-In');
    run('Set-NetFirewallRule -Name FPS-ICMP4-ERQ-In -RemoteAddress 10.0.99.0/24');
    expect(lab.run('ws01', 'alice', 'ping -c 1 -W 1 win01').code).toBe(1);
    run('Set-NetFirewallRule -Name FPS-ICMP4-ERQ-In -RemoteAddress 10.0.0.0/16 -LocalAddress 10.0.20.30');
    expect(lab.run('ws01', 'alice', 'ping -c 1 -W 1 win01').code).toBe(0);
    expect(run('Get-NetFirewallRule -Name FPS-ICMP4-ERQ-In | Get-NetFirewallAddressFilter').output).toMatch(/LocalAddress\s+: 10\.0\.20\.30\nRemoteAddress\s+: 10\.0\.0\.0\/16/);
    run('Set-NetFirewallRule -Name IIS-WebServerRole-HTTP-In-TCP -RemotePort 1-1023');
    expect(web(lab).output).not.toBe('200');
    expect(run('Get-NetFirewallRule -Name IIS-WebServerRole-HTTP-In-TCP | Get-NetFirewallPortFilter').output).toMatch(/RemotePort\s+: 1-1023/);
    run('Set-NetFirewallRule -Name IIS-WebServerRole-HTTP-In-TCP -RemotePort Any');
    expect(web(lab).output).toBe('200');
    expect(run('New-NetFirewallRule -DisplayName x -Protocol ICMPv4 -RemotePort 5').output).toContain('The port is invalid.');
  });

  it('Program matches the owner of the listening socket: http.sys is System, not w3wp.exe', () => {
    const { lab, run } = win();
    run('Set-NetFirewallRule -Name IIS-WebServerRole-HTTP-In-TCP -Program "%SystemRoot%\\system32\\inetsrv\\w3wp.exe"');
    expect(run('Get-NetFirewallRule -Name IIS-WebServerRole-HTTP-In-TCP | Get-NetFirewallApplicationFilter').output).toMatch(/Program\s+: %SystemRoot%\\system32\\inetsrv\\w3wp\.exe/);
    expect(web(lab).output).not.toBe('200');
    run('Set-NetFirewallRule -Name IIS-WebServerRole-HTTP-In-TCP -Program System');
    expect(web(lab).output).toBe('200');
    // The built-in RDP rule names svchost.exe (TermService): it keeps working.
    expect(nc(lab, 3389).code).toBe(0);
    // A program rule with LocalPort Any opens only that program's ports.
    run('Disable-NetFirewallRule -Name IIS-WebServerRole-HTTP-In-TCP');
    run('New-NetFirewallRule -DisplayName "Kernel listeners" -Program System -Protocol TCP');
    expect(web(lab).output).toBe('200');
    expect(nc(lab, 5985).code).toBe(0);
  });

  it('a Block rule wins over any Allow rule, whatever their order', () => {
    const { lab, run } = win();
    run('New-NetFirewallRule -DisplayName "Block web" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Block');
    run('New-NetFirewallRule -DisplayName "Allow web from office" -Direction Inbound -Protocol TCP -LocalPort 80 -RemoteAddress 10.0.0.0/8 -Action Allow');
    expect(web(lab).output).not.toBe('200');
    run('Set-NetFirewallRule -DisplayName "Block web" -RemoteAddress 203.0.113.0/24');
    expect(web(lab).output).toBe('200');
  });

  it('default outbound Block stops connections the server starts', () => {
    const { lab, run } = win();
    run('Set-NetFirewallProfile -All -DefaultOutboundAction Block');
    expect(run('Test-NetConnection 10.0.20.10 -Port 22 -InformationLevel Quiet').output.split('\n').pop()).toBe('False');
    // Inbound connections still get their replies (stateful).
    expect(web(lab).output).toBe('200');
    run('New-NetFirewallRule -DisplayName "SSH out" -Direction Outbound -Protocol TCP -RemotePort 22 -Action Allow');
    expect(run('Test-NetConnection 10.0.20.10 -Port 22 -InformationLevel Quiet').output.split('\n').pop()).toBe('True');
  });
});

describe('Windows Defender Firewall: Group Policy profile settings', () => {
  it('AllowLocalFirewallRules False in a GPO makes local rules count for nothing', () => {
    const w = buildSshLab();
    joinWin01(w);
    const l = new Lab(w);
    const dc = (c: string) => l.run('dc01', 'Administrator', c);
    dc('New-GPO -Name "Firewall Policy"');
    dc('New-NetFirewallRule -PolicyStore "ad.corp.lab\\Firewall Policy" -DisplayName "RDP (policy)" -Protocol TCP -LocalPort 3389 -Action Allow');
    dc('Set-NetFirewallProfile -PolicyStore "ad.corp.lab\\Firewall Policy" -Profile Domain -AllowLocalFirewallRules False -LogBlocked True');
    expect(dc('Get-NetFirewallProfile -PolicyStore "ad.corp.lab\\Firewall Policy" -Name Domain').output).toMatch(/AllowLocalFirewallRules\s+: False/);
    dc('New-GPLink -Name "Firewall Policy" -Target "DC=ad,DC=corp,DC=lab"');
    const curl = () => l.run('ws01', 'alice', 'curl -s -m 2 -o /dev/null -w "%{http_code}" http://win01.corp.lab/').output;
    expect(curl()).toBe('200');
    expect(l.run('win01', 'Administrator', 'gpupdate /force').output).toContain('Computer Policy update has completed successfully.');
    expect(curl()).not.toBe('200');
    expect(l.run('ws01', 'alice', 'nc -zv -w 2 win01 3389').code).toBe(0);
    const win01 = (c: string) => l.run('win01', 'Administrator', c).output;
    expect(win01('(Get-NetFirewallProfile -Name Domain).AllowLocalFirewallRules')).toBe('NotConfigured');
    expect(win01('(Get-NetFirewallProfile -Name Domain -PolicyStore ActiveStore).AllowLocalFirewallRules')).toBe('False');
    expect(win01('(Get-NetFirewallProfile -Name Domain -PolicyStore ActiveStore).LogBlocked')).toBe('True');
    expect(win01('(Get-NetFirewallProfile -Name Domain).LogBlocked')).toBe('False');
    expect(win01('Set-NetFirewallProfile -Name Domain -PolicyStore RSOP -LogBlocked False')).toContain('The request is not supported.');
    expect(win01(`Get-Content ${LOG}`)).toMatch(/DROP TCP \S+ 10\.0\.20\.30 \d+ 80 /);
    // The fix: the rule belongs in the GPO.
    dc('New-NetFirewallRule -PolicyStore "ad.corp.lab\\Firewall Policy" -DisplayName "Web (policy)" -Protocol TCP -LocalPort 80 -Action Allow');
    win01('gpupdate /force');
    expect(curl()).toBe('200');
  });
});

describe('Windows Defender Firewall tickets: workarounds are rejected', () => {
  const fixAndVerify = (id: string, cmds: [string, string][]) => {
    const s = findScenario(id)!;
    const w = buildSshLab();
    s.setup(w);
    const l = new Lab(w);
    for (const [host, c] of cmds) l.run(host, 'Administrator', c);
    return verifyScenario(l.world, s);
  };
  it('re-enabling the built-in RDP rules works but exposes RDP to any address', () => {
    const v = fixAndVerify('wfw-block-precedence', [['win01', 'Remove-NetFirewallRule -DisplayName "SEC-52 Block RDP"'], ['win01', 'Enable-NetFirewallRule -DisplayGroup "Remote Desktop"']]);
    expect(v.constraints.find((c) => c.id === 'wfw-rdp-scoped')?.ok).toBe(false);
  });
  it('removing the program condition from the web rule violates SEC-44', () => {
    const v = fixAndVerify('wfw-program-mismatch', [['win01', 'Set-NetFirewallRule -Name IIS-WebServerRole-HTTP-In-TCP -Program Any']]);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(v.constraints.find((c) => c.id === 'wfw-web-program')?.ok).toBe(false);
  });
  it('allowing all outbound traffic again violates SEC-60', () => {
    const v = fixAndVerify('wfw-outbound-default', [['win01', 'Set-NetFirewallProfile -All -DefaultOutboundAction Allow']]);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(v.constraints.find((c) => c.id === 'wfw-egress-block')?.ok).toBe(false);
  });
  it('letting local rules count again violates CHG-2420', () => {
    const v = fixAndVerify('wfw-local-rules-ignored', [['dc01', 'Set-NetFirewallProfile -PolicyStore "ad.corp.lab\\Server Firewall" -Profile Domain -AllowLocalFirewallRules True'], ['win01', 'gpupdate /force']]);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(v.constraints.find((c) => c.id === 'wfw-policy-only')?.ok).toBe(false);
  });
});
