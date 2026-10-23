import { describe, expect, it } from 'vitest';
import { parse } from '../src/engine/win/ps/parse';
import { Lab } from './helpers';

/** A Windows console session on win01 that keeps its PowerShell state between lines. */
function console01(user = 'Administrator') {
  const lab = new Lab();
  const sh = lab.shell('win01', user);
  return { lab, sh, run: (line: string, answers: string[] = []) => sh.execute(line, answers) };
}

describe('PowerShell language', () => {
  it('parses pipelines, script blocks, hashtables and command-mode arguments', () => {
    expect(() => parse('Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object Name, @{n="S";e={$_.StartType}}')).not.toThrow();
    expect(() => parse('netsh advfirewall firewall add rule name="Allow SSH" dir=in')).not.toThrow();
    expect(() => parse('"unterminated')).toThrow(/missing the terminator/);
  });

  it('evaluates expressions, variables, operators and format strings', () => {
    const { run } = console01();
    expect(run('$x = 5; $x * 3').output).toBe('15');
    expect(run('"{0} has {1,3}" -f "win01", 7').output).toBe('win01 has   7');
    expect(run('1..3 | % { $_ * 2 }').output).toBe('2\n4\n6');
    expect(run('"a,b" -split ","').output).toBe('a\nb');
    expect(run('$h = @{a=1; b="x"}; $h.b').output).toBe('x');
    expect(run('if ($env:COMPUTERNAME -eq "WIN01") { "yes" } else { "no" }').output).toBe('yes');
    expect(run('$PSVersionTable.PSVersion.Major').output).toBe('5');
  });

  it('reports errors in Windows PowerShell 5.1 format', () => {
    const { run } = console01();
    const nf = run('Get-Foo');
    expect(nf.code).toBe(1);
    expect(nf.output).toMatch(/^Get-Foo : The term 'Get-Foo' is not recognized as the name of a cmdlet/);
    expect(nf.output).toContain('    + FullyQualifiedErrorId : CommandNotFoundException');
    const bad = run('Get-Service -Nme x');
    expect(bad.output).toContain("A parameter cannot be found that matches parameter name 'Nme'.");
    expect(bad.output).toContain('NamedParameterNotFound,Microsoft.PowerShell.Commands.GetServiceCommand');
    expect(run('Get-Service -Name Nope').output).toContain("Cannot find any service with service name 'Nope'.");
    expect(run('Get-Service -Name Nope -ErrorAction SilentlyContinue').output).toBe('');
  });
});

describe('PowerShell formatting', () => {
  it('formats services with the ServiceController view', () => {
    const { run } = console01();
    const out = run('Get-Service -Name TermService,W3SVC').output.split('\n');
    expect(out.slice(1, 5)).toEqual([
      'Status   Name               DisplayName',
      '------   ----               -----------',
      'Running  TermService        Remote Desktop Services',
      'Running  W3SVC              World Wide Web Publishing Service',
    ]);
  });

  it('filters and selects objects through the pipeline', () => {
    const { run } = console01();
    expect(run('Get-Service | Where-Object Status -eq Stopped | Select-Object -ExpandProperty Name').output.split('\n')).toContain('RemoteRegistry');
    expect(run('(Get-Service | Where-Object { $_.StartType -eq "Disabled" }).Count').output).toBe('2');
    expect(run('Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet0 | Select-Object -ExpandProperty IPAddress').output).toBe('10.0.20.30');
  });

  it('prints ipconfig like Windows', () => {
    const { run } = console01();
    const out = run('ipconfig').output;
    expect(out).toContain('Ethernet adapter Ethernet0:');
    expect(out).toContain('   IPv4 Address. . . . . . . . . . . : 10.0.20.30');
    expect(out).toContain('   Subnet Mask . . . . . . . . . . . : 255.255.255.0');
    expect(out).toContain('   Default Gateway . . . . . . . . . : 10.0.20.1');
    expect(run('ipconfig /all').output).toContain('   DNS Servers . . . . . . . . . . . : 10.0.10.53');
  });
});

describe('Windows networking from PowerShell', () => {
  it('ping and Test-NetConnection use the simulated network', () => {
    const { run } = console01();
    const p = run('ping -n 2 srv01');
    expect(p.output).toMatch(/Pinging srv01\.corp\.lab \[[\d.]+\] with 32 bytes of data:/);
    expect(p.output).toContain('Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),');
    expect(run('Test-NetConnection srv01 -Port 22').output).toMatch(/TcpTestSucceeded : True/);
    const fail = run('Test-NetConnection srv01 -Port 3389');
    expect(fail.output).toMatch(/WARNING: TCP connect to \([\d.]+ : 3389\) failed/);
    expect(run('Test-NetConnection srv01 -Port 22 -InformationLevel Quiet').output).toBe('True');
    expect(run('ping -n 1 nosuchhost').output).toBe('Ping request could not find host nosuchhost. Please check the name and try again.');
  });

  it('Resolve-DnsName and nslookup query the adapter DNS servers', () => {
    const { run } = console01();
    expect(run('Resolve-DnsName srv01.corp.lab -Type A').output).toMatch(/srv01\.corp\.lab\s+A\s+\d+\s+Answer\s+[\d.]+/);
    expect(run('Resolve-DnsName nope.corp.lab').output).toContain('nope.corp.lab : DNS name does not exist');
    run('Set-DnsClientServerAddress -InterfaceAlias Ethernet0 -ServerAddresses 10.0.10.99');
    expect(run('Resolve-DnsName srv01.corp.lab').output).toContain('This operation returned because the timeout period expired');
    expect(run('nslookup srv01').output).toContain('*** Request to UnKnown timed-out');
  });

  it('IIS answers Invoke-WebRequest locally and curl from Linux', () => {
    const { lab, run } = console01();
    expect(run('(Invoke-WebRequest http://localhost/ -UseBasicParsing).StatusCode').output).toBe('200');
    expect(lab.run('ws01', 'alice', 'curl -sI http://win01/').output).toContain('Server: Microsoft-IIS/10.0');
    run('Stop-Service W3SVC');
    expect(lab.run('ws01', 'alice', 'curl -sS -m 3 http://win01/').output).toMatch(/Couldn't connect to server/);
  });
});

describe('Windows Defender Firewall', () => {
  it('blocks ping until the echo-request rule is enabled', () => {
    const { lab, run } = console01();
    expect(lab.run('ws01', 'alice', 'ping -c 1 -W 1 win01').code).toBe(1);
    expect(run('(Get-NetFirewallRule -Name FPS-ICMP4-ERQ-In).Enabled').output).toBe('False');
    expect(run('Enable-NetFirewallRule -Name FPS-ICMP4-ERQ-In').code).toBe(0);
    const p = lab.run('ws01', 'alice', 'ping -c 1 win01');
    expect(p.code).toBe(0);
    expect(p.output).toContain('ttl=127');
  });

  it('new rules open ports; netsh rules work too', () => {
    const { run } = console01();
    const r = run('New-NetFirewallRule -DisplayName "Web 8080" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow');
    expect(r.output).toContain('DisplayName           : Web 8080');
    expect(run('New-NetFirewallRule -DisplayName bad -LocalPort 80').output).toContain('The port is invalid.');
    expect(run('netsh advfirewall firewall add rule name="Allow SSH" dir=in action=allow protocol=TCP localport=22').output).toBe('Ok.\n'.trimEnd());
    expect(run('netsh advfirewall firewall show rule name="Allow SSH"').output).toContain('Rule Name:                            Allow SSH');
    expect(run('Get-WinEvent -LogName "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" -MaxEvents 1').output).toContain('2004');
  });

  it('the network category selects the profile and scoped rules', () => {
    const { lab, run } = console01();
    expect(lab.run('ws01', 'alice', 'nc -zv -w 2 win01 5985').code).toBe(0);
    run('Set-NetConnectionProfile -InterfaceAlias Ethernet0 -NetworkCategory Public');
    // WinRM on the Public profile only accepts the local subnet.
    expect(lab.run('ws01', 'alice', 'nc -zv -w 2 win01 5985').output).toContain('Connection timed out');
  });

  it('denies changes to standard users', () => {
    const { run } = console01('alice');
    const r = run('Enable-NetFirewallRule -Name FPS-ICMP4-ERQ-In');
    expect(r.output).toContain('Enable-NetFirewallRule : Access is denied.');
    expect(r.output).toContain('Windows System Error 5,Enable-NetFirewallRule');
  });
});

describe('Remote Desktop configuration', () => {
  it('fDenyTSConnections takes effect after TermService restarts', () => {
    const { lab, run } = console01();
    expect(lab.run('ws01', 'alice', 'nc -zv -w 2 win01 3389').code).toBe(0);
    run('Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -Name fDenyTSConnections -Value 1');
    expect(lab.run('ws01', 'alice', 'nc -zv -w 2 win01 3389').output).toContain('Connection refused');
    run('Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -Name fDenyTSConnections -Value 0');
    run('Restart-Computer -Force');
    expect(run('(Get-Service TermService).Status').output).toBe('Running');
    expect(lab.run('ws01', 'alice', 'nc -zv -w 2 win01 3389').code).toBe(0);
  });

  it('sc.exe and net manage services; plain "sc" is Set-Content', () => {
    const { run } = console01();
    expect(run('sc.exe qc TermService').output).toContain('START_TYPE         : 3   DEMAND_START');
    expect(run('sc.exe config TermService start= disabled').output).toBe('[SC] ChangeServiceConfig SUCCESS');
    const ask = run('net stop "Remote Desktop Services"');
    expect(ask.needInput?.text).toContain('The following services are dependent on the Remote Desktop Services service.');
    const stop = run('net stop "Remote Desktop Services"', ['Y']).output;
    expect(stop).toContain('The Remote Desktop Services UserMode Port Redirector service was stopped successfully.');
    expect(stop).toContain('The Remote Desktop Services service was stopped successfully.');
    expect(run('net start TermService').output).toContain('System error 1058 has occurred.');
    run('sc qc TermService');
    expect(run('Get-Content .\\qc').output).toBe('TermService');
  });
});

describe('Console behaviour', () => {
  it('keeps the location in the prompt and asks for confirmation', () => {
    const { sh, run } = console01();
    expect(sh.prompt()).toBe('PS C:\\Users\\Administrator> ');
    run('cd C:\\Windows');
    expect(sh.prompt()).toBe('PS C:\\Windows> ');
    run('New-Item C:\\Temp\\x -ItemType Directory | Out-Null; Set-Content C:\\Temp\\x\\a.txt hi');
    const q = run('Remove-Item C:\\Temp\\x');
    expect(q.needInput?.text).toContain('has children and the Recurse parameter was not specified');
    expect(run('Remove-Item C:\\Temp\\x', ['Y']).code).toBe(0);
    expect(run('Test-Path C:\\Temp\\x').output).toBe('False');
  });
});

describe('xfreerdp (Remote Desktop from Linux)', () => {
  it('asks to trust the certificate once, then logs on', () => {
    const { lab, run } = console01();
    const first = lab.run('ws01', 'alice', 'xfreerdp /v:win01.corp.lab /u:alice /p:Corp-Lab-2026');
    expect(first.needInput?.text).toContain('Do you trust the above certificate? (Y/T/N)');
    expect(lab.run('ws01', 'alice', 'xfreerdp /v:win01.corp.lab /u:alice /p:Corp-Lab-2026', ['Y']).code).toBe(0);
    const again = lab.run('ws01', 'alice', 'xfreerdp /v:win01.corp.lab /u:alice /p:Corp-Lab-2026');
    expect(again.needInput).toBeUndefined();
    expect(again.output).toContain('logged WIN01\\alice on');
    expect(run('(Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4624} -MaxEvents 1).Id').output).toBe('4624');
  });

  it('reports each failing stage with FreeRDP\'s error and exit code', () => {
    const { lab, run } = console01();
    const bad = lab.run('ws01', 'alice', 'xfreerdp /v:win01.corp.lab /u:alice /p:wrong /cert:ignore');
    expect(bad.code).toBe(132);
    expect(bad.output).toContain('ERRCONNECT_LOGON_FAILURE [0x00020014]');
    expect(run('Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625} -MaxEvents 1 | Format-List Message').output).toContain('0xC000006D');
    expect(lab.run('ws01', 'alice', 'xfreerdp /v:nosuch.corp.lab /u:alice /p:x').output).toContain('ERRCONNECT_DNS_NAME_NOT_FOUND');
    expect(lab.run('ws01', 'alice', 'xfreerdp /v:srv01 /u:alice /p:x').code).toBe(131);
  });
});
