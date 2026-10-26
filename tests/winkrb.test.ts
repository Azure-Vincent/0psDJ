import { describe, expect, it } from 'vitest';
import { buildSshLab } from '../src/engine/lab/sshLab';
import { AD_ALICE_PASSWORD } from '../src/engine/lab/winLab';
import { findScenario } from '../src/engine/scenarios';
import { joinWin01 } from '../src/engine/scenarios/domainScenarios';
import { verifyScenario } from '../src/engine/scenarios/engine';
import { Lab } from './helpers';

function domain(): Lab {
  const w = buildSshLab();
  joinWin01(w);
  return new Lab(w);
}
const rdp = (l: Lab) => l.run('ws01', 'alice', `xfreerdp /v:win01.corp.lab /u:CORP\\\\alice /p:${AD_ALICE_PASSWORD} /cert:ignore`);
const lastEvent = (l: Lab, host: string, log: string) => l.run(host, 'Administrator', `Get-WinEvent -LogName ${log} -MaxEvents 1 | Format-List Id,Message`).output;

describe('Kerberos for Windows logons', () => {
  it('a domain logon gets a TGT and a ticket to the member; the DC audits both', () => {
    const l = domain();
    expect(rdp(l).code).toBe(0);
    const sec = l.run('dc01', 'Administrator', 'Get-WinEvent -LogName Security -MaxEvents 3 | Format-List Id,Message').output;
    expect(sec).toMatch(/Id +: 4769[\s\S]*Account Name:\s+alice@AD\.CORP\.LAB[\s\S]*Service Name:\s+WIN01\$[\s\S]*Failure Code:\s+0x0/);
    expect(sec).toMatch(/Id +: 4768[\s\S]*Account Name:\s+alice[\s\S]*Result Code:\s+0x0/);
    expect(lastEvent(l, 'win01', 'Security')).toMatch(/Logon Type:\s+10[\s\S]*Authentication Package:\s+Negotiate\n\s+Package Name \(NTLM only\):\s+-/);
  });

  it('klist shows the computer\'s tickets; klist get and purge; local accounts have no Kerberos credentials', () => {
    const l = domain();
    l.run('win01', 'Administrator', 'gpupdate /force');
    const k = l.run('win01', 'Administrator', 'klist -li 0x3e7').output;
    expect(k).toMatch(/Targeted LogonId is 0:0x3e7\n\nCached Tickets: \(2\)/);
    expect(k).toMatch(/#0>\tClient: WIN01\$ @ AD\.CORP\.LAB\n\tServer: krbtgt\/AD\.CORP\.LAB @ AD\.CORP\.LAB/);
    expect(k).toMatch(/Server: ldap\/dc01\.ad\.corp\.lab @ AD\.CORP\.LAB[\s\S]*Kdc Called: dc01\.ad\.corp\.lab/);
    expect(l.run('win01', 'Administrator', 'klist -li 0x3e7 purge').output).toMatch(/Ticket\(s\) purged!/);
    expect(l.run('win01', 'Administrator', 'klist -li 0x3e7').output).toMatch(/Cached Tickets: \(0\)/);
    expect(l.run('win01', 'Administrator', 'klist -li 0x3e7 get krbtgt').output).toMatch(/A ticket to krbtgt has been retrieved successfully\.\n\nCached Tickets: \(1\)/);
    expect(l.run('win01', 'Administrator', 'klist get host/dc01').output).toMatch(/klist failed with 0x8009030e\/-2146893042: No credentials are available in the security package/);
    // The DC console is CORP\Administrator: cifs/ maps to the HOST/ SPN of WIN01$.
    expect(l.run('dc01', 'Administrator', 'klist get cifs/win01.ad.corp.lab').output).toMatch(/Client: Administrator @ AD\.CORP\.LAB\n\tServer: cifs\/win01\.ad\.corp\.lab @ AD\.CORP\.LAB/);
    expect(l.run('dc01', 'Administrator', 'klist get http/nowhere.ad.corp.lab').output).toMatch(/GetTicket substatus\): 0x6fb\n\nklist failed with 0xc000018b\/-1073741429/);
  });

  it('clock skew: NLA passes, the logon and Group Policy fail; W32Time synchronises from the DC', () => {
    const l = domain();
    l.run('win01', 'Administrator', 'Stop-Service W32Time');
    l.world.hosts.win01.clockOffset = 9 * 60_000;
    l.run('win01', 'Administrator', 'klist -li 0x3e7 purge');
    expect(l.run('ws01', 'alice', `xfreerdp /v:win01.corp.lab /u:CORP\\\\alice /p:${AD_ALICE_PASSWORD} /cert:ignore +auth-only`).code).toBe(0);
    const r = rdp(l);
    expect(r.code).not.toBe(0);
    expect(r.output).toMatch(/logon screen shows "There is a time and\/or date difference between the client and server\."/);
    expect(lastEvent(l, 'dc01', 'Security')).toMatch(/Id +: 4771[\s\S]*Failure Code:\s+0x25/);
    expect(l.run('win01', 'Administrator', 'gpupdate /force').output).toMatch(/LDAP Bind function call failed/);
    expect(l.run('win01', 'Administrator', 'w32tm /stripchart /computer:dc01.ad.corp.lab /samples:1 /dataonly').output).toMatch(/, -5[34]\d\.\d+s/);
    expect(l.run('win01', 'Administrator', 'w32tm /resync').output).toMatch(/The service has not been started/);
    l.run('win01', 'Administrator', 'Start-Service W32Time');
    expect(Math.abs(l.world.hosts.win01.clockOffset ?? 0)).toBeLessThan(1000);
    expect(rdp(l).code).toBe(0);
    expect(l.run('win01', 'Administrator', 'w32tm /query /status').output).toMatch(/Source: dc01\.ad\.corp\.lab/);
  });

  it('no KDC: logons fall back to NTLM, Group Policy fails with 1055', () => {
    const l = domain();
    l.run('dc01', 'Administrator', 'Disable-NetFirewallRule -DisplayGroup "Kerberos Key Distribution Center"');
    l.run('win01', 'Administrator', 'klist -li 0x3e7 purge');
    expect(rdp(l).code).toBe(0);
    expect(lastEvent(l, 'win01', 'Security')).toMatch(/Package Name \(NTLM only\):\s+NTLM V2/);
    expect(l.run('win01', 'Administrator', 'gpupdate /force').output).toMatch(/Windows could not resolve the computer name/);
    expect(l.run('win01', 'Administrator', 'klist -li 0x3e7 get krbtgt').output).toMatch(/klist failed with 0xc000005e\/-1073741730: There are currently no logon servers available/);
  });

  it('a new TGT carries the computer\'s new groups (klist -li 0x3e7 purge instead of a restart)', () => {
    const s = findScenario('gpo-filter-token')!;
    const world = buildSshLab();
    s.setup(world);
    const l = new Lab(world);
    l.run('win01', 'Administrator', 'gpupdate /force');
    expect(l.run('win01', 'Administrator', 'gpresult /r').output).toMatch(/Denied \(Security\)/);
    l.run('win01', 'Administrator', 'klist -li 0x3e7 purge');
    l.run('win01', 'Administrator', 'gpupdate /force');
    expect(l.run('win01', 'Administrator', 'gpresult /r').output).toMatch(/CORP\\Baseline Servers/);
  });

  it('setspn: list, query, add with the duplicate check, delete, and -X', () => {
    const l = domain();
    const dc = (c: string) => l.run('dc01', 'Administrator', c).output;
    expect(dc('setspn -L win01')).toMatch(/^Registered ServicePrincipalNames for CN=WIN01,CN=Computers,DC=ad,DC=corp,DC=lab:\n\tTERMSRV\/WIN01[\s\S]*\tHOST\/win01\.ad\.corp\.lab$/);
    expect(dc('setspn -S HOST/win01.ad.corp.lab alice')).toMatch(/Duplicate SPN found, aborting operation!/);
    expect(dc('setspn -A HOST/win01.ad.corp.lab alice')).toMatch(/not unique forest-wide/);
    expect(dc('setspn -S http/intranet.ad.corp.lab alice')).toMatch(/Registering ServicePrincipalNames for CN=Alice Martin,CN=Users,DC=ad,DC=corp,DC=lab\n\thttp\/intranet\.ad\.corp\.lab\nUpdated object/);
    expect(dc('setspn -Q http/intranet.ad.corp.lab')).toMatch(/Existing SPN found!/);
    // A service ticket for it is encrypted with alice's key (she is the service account now).
    expect(dc('klist get http/intranet.ad.corp.lab')).toMatch(/retrieved successfully/);
    expect(dc('setspn -D http/intranet.ad.corp.lab alice')).toMatch(/Updated object/);
    expect(dc('setspn -Q http/intranet.ad.corp.lab')).toMatch(/No such SPN found\./);
    expect(dc('setspn -X')).toMatch(/found 0 group of duplicate SPNs\./);
  });

  it('a Linux client can use the AD KDC (kinit against AD.CORP.LAB)', () => {
    const l = domain();
    l.run('ws01', 'root', `printf '[realms]\\n AD.CORP.LAB = {\\n  kdc = 10.0.20.5\\n }\\n' >> /etc/krb5.conf`);
    const k = l.run('ws01', 'alice', 'kinit alice@AD.CORP.LAB', [AD_ALICE_PASSWORD]);
    expect(k.code).toBe(0);
    expect(l.run('ws01', 'alice', 'klist').output).toMatch(/krbtgt\/AD\.CORP\.LAB@AD\.CORP\.LAB/);
    expect(l.run('ws01', 'alice', 'kinit alice@AD.CORP.LAB', ['wrong']).output).toMatch(/Password incorrect/);
  });
});

describe('Kerberos for Windows: review fixes', () => {
  it('an exact SPN wins over the HOST/ alias (no false duplicate)', () => {
    const l = domain();
    l.run('dc01', 'Administrator', 'setspn -S http/win01.ad.corp.lab alice');
    const out = l.run('dc01', 'Administrator', 'klist get http/win01.ad.corp.lab').output;
    expect(out).toMatch(/retrieved successfully/);
    expect(lastEvent(l, 'dc01', 'Security')).toMatch(/Service Name:\s+alice\b/);
    expect(l.run('dc01', 'Administrator', 'Get-WinEvent -LogName System -MaxEvents 3 | Format-List Id').output).not.toMatch(/Id : 11\b/);
  });

  it('klist -li with another session\'s logon id, and an unknown one', () => {
    const l = domain();
    expect(rdp(l).code).toBe(0);
    const id = Object.values(l.world.hosts.win01.win!.krb!).find((s) => s.client.startsWith('alice@'))!.logonId;
    expect(l.run('win01', 'Administrator', `klist -li ${id}`).output).toMatch(new RegExp(`Targeted LogonId is 0:${id}[\\s\\S]*Client: alice @ AD\\.CORP\\.LAB`));
    expect(l.run('win01', 'Administrator', 'klist -li 0x12345').output).toMatch(/0xc000005f\/-1073741729: A specified logon session does not exist/);
  });

  it('Group Policy needs its LDAP ticket: no ldap/ SPN on the DC means no policy', () => {
    const l = domain();
    l.run('dc01', 'Administrator', 'setspn -D ldap/dc01.ad.corp.lab dc01');
    l.run('win01', 'Administrator', 'klist -li 0x3e7 purge');
    expect(l.run('win01', 'Administrator', 'gpupdate /force').output).toMatch(/LDAP Bind function call failed/);
  });

  it('a TGT the KDC no longer accepts (new krbtgt key) is replaced once', () => {
    const l = domain();
    l.run('win01', 'Administrator', 'gpupdate /force');
    l.world.hosts.dc01.win!.ad!.users.krbtgt.password = 'rotated';
    l.run('win01', 'Administrator', 'klist -li 0x3e7 purge');
    l.run('win01', 'Administrator', 'gpupdate /force');
    // A stale TGT (cached before the rotation) is rejected with 31 and replaced.
    l.world.hosts.dc01.win!.ad!.users.krbtgt.password = 'rotated-again';
    const s = l.world.hosts.win01.win!.krb!['0x3e7'];
    s.tickets = s.tickets.filter((t) => t.server.startsWith('krbtgt/'));
    expect(l.run('win01', 'Administrator', 'gpupdate /force').output).toMatch(/Computer Policy update has completed successfully/);
  });
});

describe('Windows Kerberos tickets: wrong fixes are rejected', () => {
  const broken = (id: string) => {
    const s = findScenario(id)!;
    const world = buildSshLab();
    s.setup(world);
    return { s, l: new Lab(world) };
  };

  it('setting the clock by hand without the time service', () => {
    const { s, l } = broken('krb-w32time-disabled');
    l.world.hosts.win01.clockOffset = 0;
    const v = verifyScenario(l.world, s);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(v.passed).toBe(false);
  });

  it('turning off the DC firewall instead of allowing NTP', () => {
    const { s, l } = broken('krb-dc-ntp-blocked');
    l.run('dc01', 'Administrator', 'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False');
    l.run('win01', 'Administrator', 'w32tm /resync');
    const v = verifyScenario(l.world, s);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(v.passed).toBe(false);
  });

  it('a local ping rule on win01 instead of fixing the KDC path', () => {
    const { s, l } = broken('krb-dc-kdc-blocked');
    l.run('win01', 'Administrator', 'Enable-NetFirewallRule -Name FPS-ICMP4-ERQ-In');
    const v = verifyScenario(l.world, s);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(v.passed).toBe(false);
  });

  it('starting the KDC without making it automatic', () => {
    const { s, l } = broken('krb-kdc-stopped');
    l.run('dc01', 'Administrator', 'Set-Service Kdc -StartupType Manual');
    l.run('dc01', 'Administrator', 'Start-Service Kdc');
    l.run('win01', 'Administrator', 'gpupdate /force');
    const v = verifyScenario(l.world, s);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(v.passed).toBe(false);
  });
});
