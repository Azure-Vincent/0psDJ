import { describe, expect, it } from 'vitest';
import { FS01_SMB_PASSWORDS } from '../src/engine/lab/nfsLab';
import { buildSshLab } from '../src/engine/lab/sshLab';
import { findScenario } from '../src/engine/scenarios';
import { rebootAll, verifyScenario } from '../src/engine/scenarios/engine';
import { parseSmbConf, shareReadOnly } from '../src/engine/sim/smb';
import { Lab } from './helpers';

const lab = () => new Lab(buildSshLab());
const A = FS01_SMB_PASSWORDS.alice;
const D = FS01_SMB_PASSWORDS.dana;

describe('Samba: smb.conf', () => {
  it('parses sections, synonyms and unknown parameters; read only is the default', () => {
    const c = parseSmbConf('[global]\n  workgroup = CORP\n  bogus thing = 1\n[a]\n  path = /srv/a\n  writable = yes\n[b]\n  path = /srv/b\n; comment\n');
    expect(c.global.workgroup).toBe('CORP');
    expect(c.unknown.map((u) => u.name)).toEqual(['bogus thing']);
    expect(shareReadOnly(c.shares[0])).toBe(false);
    expect(shareReadOnly(c.shares[1])).toBe(true);
  });

  it('testparm reports unknown parameters and lists non-default settings', () => {
    const l = lab();
    l.run('fs01', 'root', "sed -i 's/load printers = no/load printers = no\\n   lod printers = no/' /etc/samba/smb.conf");
    l.run('fs01', 'root', "echo '   wrtable = yes' >> /etc/samba/smb.conf");
    const out = l.run('fs01', 'root', 'testparm -s').output;
    expect(out).toMatch(/Unknown parameter encountered: "wrtable"\nIgnoring unknown parameter "wrtable"/);
    expect(out).toMatch(/\[office\]\n\tcomment = Office documents \(staff\)[\s\S]*\tread only = No\n\tvalid users = @staff/);
    expect(out).not.toMatch(/\[software\][^[]*read only/);
  });
});

describe('Samba: smbclient from ws01', () => {
  it('lists shares and works with files as the server-side account', () => {
    const l = lab();
    expect(l.run('ws01', 'alice', `smbclient -L fs01 -U alice%${A}`).output).toMatch(/^\n\tSharename {7}Type {6}Comment\n\t-{9} {7}-{4} {6}-{7}\n\toffice {10}Disk {6}Office documents \(staff\)\n\tsoftware {8}Disk {6}Approved installers\n\tIPC\$ {12}IPC {7}IPC Service \(fs01 file server \(Samba 4\.17\.12-Debian\)\)\nSMB1 disabled -- no workgroup available$/);
    const ls = l.run('ws01', 'alice', `smbclient //fs01/office -U alice%${A} -c ls`).output;
    expect(ls).toMatch(/^ {2}budget-2025\.txt {21}N {7}50 {2}\w{3} Oct 19 07:58:00 \d{4}$/m);
    expect(l.run('ws01', 'alice', `smbclient //fs01/office -U alice%${A} -c 'put /etc/hostname notes.txt; mkdir reports'`).output).toBe('putting file /etc/hostname as \\notes.txt (2.0 kb/s) (average 2.0 kb/s)');
    const srv = l.run('fs01', 'root', 'ls -l /srv/office').output;
    expect(srv).toMatch(/^-rw-rw---- 1 alice +staff .* notes\.txt$/m);
    expect(srv).toMatch(/^drwxrwx--- 2 alice +staff .* reports$/m);
    l.run('ws01', 'alice', `smbclient //fs01/office -U alice%${A} -c 'get budget-2025.txt /tmp/b.txt'`);
    expect(l.run('ws01', 'alice', 'cat /tmp/b.txt').output).toMatch(/^Budget 2025/);
  });

  it('wrong password and unknown users fail at session setup, logged differently', () => {
    const l = lab();
    expect(l.run('ws01', 'alice', 'smbclient //fs01/office -U alice%nope -c ls').output).toBe('session setup failed: NT_STATUS_LOGON_FAILURE');
    expect(l.run('ws01', 'alice', 'smbclient //fs01/office -U erin%x -c ls').output).toBe('session setup failed: NT_STATUS_LOGON_FAILURE');
    const log = l.run('fs01', 'root', 'cat /var/log/samba/log.ws01').output;
    expect(log).toMatch(/Auth: \[SMB2,\(null\)\] user \[WORKGROUP\]\\\[alice\] .* status \[NT_STATUS_WRONG_PASSWORD\] workstation \[WS01\] remote host \[ipv4:10\.0\.10\.25:\d+\]/);
    expect(log).toMatch(/user \[WORKGROUP\]\\\[erin\] .* status \[NT_STATUS_NO_SUCH_USER\]/);
  });

  it('tree connect: unknown share, missing path, valid users; read-only shares refuse writes', () => {
    const l = lab();
    expect(l.run('ws01', 'alice', `smbclient //fs01/nothing -U alice%${A} -c ls`).output).toBe('tree connect failed: NT_STATUS_BAD_NETWORK_NAME');
    expect(l.run('ws01', 'alice', `smbclient //fs01/software -U alice%${A} -c 'put /etc/hostname x'`).output).toBe('NT_STATUS_ACCESS_DENIED opening remote file \\x');
    l.run('fs01', 'root', 'usermod -G dana dana');
    expect(l.run('ws01', 'alice', `smbclient //fs01/office -U dana%${D} -c ls`).output).toBe('tree connect failed: NT_STATUS_ACCESS_DENIED');
    expect(l.run('fs01', 'root', 'cat /var/log/samba/log.ws01').output).toMatch(/user 'dana' \(from session setup\) not permitted to access this share \(office\)/);
  });

  it('a firewall drop times out; a stopped smbd is refused', () => {
    const l = lab();
    l.run('fs01', 'root', 'nft insert rule inet filter input tcp dport 445 drop');
    expect(l.run('ws01', 'alice', `smbclient -L fs01 -U alice%${A}`).output).toBe('do_connect: Connection to fs01 failed (Error NT_STATUS_IO_TIMEOUT)');
    l.run('fs01', 'root', 'systemctl restart nftables');
    l.run('fs01', 'root', 'systemctl stop smbd');
    expect(l.run('ws01', 'alice', `smbclient -L fs01 -U alice%${A}`).output).toBe('do_connect: Connection to fs01 failed (Error NT_STATUS_CONNECTION_REFUSED)');
  });
});

describe('Samba: accounts and Windows clients', () => {
  it('smbpasswd -a needs the Unix account; pdbedit lists Samba users', () => {
    const l = lab();
    expect(l.run('fs01', 'root', "printf 'x\\nx\\n' | smbpasswd -a -s ghost").output).toBe('Failed to add entry for user ghost.');
    l.run('fs01', 'root', 'useradd -G staff carol');
    expect(l.run('fs01', 'root', "printf 'Pw-1\\nPw-1\\n' | smbpasswd -a -s carol").output).toBe('Added user carol.');
    expect(l.run('fs01', 'root', 'pdbedit -L').output).toMatch(/^alice:1000:Alice Admin\ncarol:\d+:\ndana:1002:Dana Sales$/);
    expect(l.run('ws01', 'alice', 'smbclient //fs01/office -U carol%Pw-1 -c ls').code).toBe(0);
    l.run('fs01', 'root', 'smbpasswd -d carol');
    expect(l.run('ws01', 'alice', 'smbclient //fs01/office -U carol%Pw-1 -c ls').output).toBe('session setup failed: NT_STATUS_ACCOUNT_DISABLED');
  });

  it('net use on win01 maps drives, reports Windows errors, and smbstatus shows the session', () => {
    const l = lab();
    expect(l.run('win01', 'Administrator', `net use O: \\\\fs01\\office /user:dana ${D}`).output).toMatch(/The command completed successfully\./);
    expect(l.run('win01', 'Administrator', `net use O: \\\\fs01\\office /user:dana ${D}`).output).toMatch(/System error 85 has occurred\.\n\nThe local device name is already in use\./);
    expect(l.run('win01', 'Administrator', 'net use S: \\\\fs01\\software /user:dana wrong').output).toMatch(/System error 1326 has occurred\.\n\nThe user name or password is incorrect\./);
    expect(l.run('win01', 'Administrator', `net use T: \\\\fs99\\x /user:dana ${D}`).output).toMatch(/System error 53 has occurred\.\n\nThe network path was not found\./);
    expect(l.run('win01', 'Administrator', 'net use').output).toMatch(/^OK {11}O: {8}\\\\fs01\\office {13}Microsoft Windows Network$/m);
    expect(l.run('fs01', 'root', 'smbstatus').output).toMatch(/^office +\d+ +10\.0\.20\.30 /m);
    expect(l.run('win01', 'Administrator', 'net use O: /delete').output).toMatch(/O: was deleted successfully\./);
  });

  it('Samba accounts and shares survive a reboot', () => {
    const w = rebootAll(buildSshLab());
    const l = new Lab(w);
    expect(l.run('ws01', 'alice', `smbclient //fs01/office -U dana%${D} -c ls`).code).toBe(0);
  });
});

describe('SMB tickets: wrong fixes are rejected', () => {
  const broken = (id: string) => {
    const s = findScenario(id)!;
    const world = buildSshLab();
    s.setup(world);
    return { s, l: new Lab(world) };
  };

  it('removing valid users from [office] is rejected', () => {
    const { s, l } = broken('smb-valid-users');
    l.run('fs01', 'root', "sed -i 's/valid users = @staff$/valid users = @staff dana/' /etc/samba/smb.conf");
    l.run('fs01', 'root', 'chmod 775 /srv/office');
    const v = verifyScenario(l.world, s);
    expect(v.passed).toBe(false);
  });

  it('an empty /srv/Software makes the share open but empty', () => {
    const { s, l } = broken('smb-share-path');
    l.run('fs01', 'root', 'mkdir /srv/Software');
    const v = verifyScenario(l.world, s);
    expect(v.now.map((g) => g.ok)).toEqual([true, false, true]);
  });

  it('a world-writable scans folder or guest access is rejected', () => {
    const { s, l } = broken('smb-read-only');
    l.run('fs01', 'root', "echo '   read only = no' >> /etc/samba/smb.conf");
    l.run('fs01', 'root', 'chmod 777 /srv/scans');
    expect(verifyScenario(l.world, s).passed).toBe(false);
  });
});
