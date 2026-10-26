// SMB file sharing tickets. Samba on fs01 shares /srv/office (read-write for
// the staff group) and /srv/software (read-only) over TCP 445; ws01 uses
// smbclient, win01 maps drives with net use. Each ticket breaks one step of an
// SMB connection: the logon (no Samba password), the share's user list, the
// share's path, and the share's read-only default.

import { writeFile } from '../fs';
import { FS01_SMB_CONF, FS01_SMB_PASSWORDS } from '../lab/nfsLab';
import { boolValue, findShare, loadSmbConf } from '../sim/smb';
import type { World } from '../types';
import { script } from './engine';
import type { Constraint, Goal, Scenario } from './types';

const ALICE = FS01_SMB_PASSWORDS.alice;
const DANA = FS01_SMB_PASSWORDS.dana;

const BRIEFING = [
  'fs01 (10.0.20.60) runs Samba (smbd, TCP 445) besides its NFS server. /etc/samba/smb.conf shares [office] (/srv/office, read-write for the Unix group staff) and [software] (/srv/software, read-only). Samba checks passwords against its own database (smbpasswd / pdbedit), not /etc/shadow.',
  'Clients: ws01 uses smbclient (smbclient -L fs01 -U alice, smbclient //fs01/office -U alice -c "ls"); win01 maps drives with net use O: \\\\fs01\\office /user:dana.',
  'Tools on fs01: testparm -s (the configuration as Samba reads it), pdbedit -L (Samba users), id USER, ls -l, smbstatus, and the per-client logs /var/log/samba/log.CLIENT (log level 2: failed logons and refused shares).',
  'Fixes must survive a reboot. Keep the shares restricted to the people who need them: no guest access, no world-writable directories.',
];

const TERMINALS = [
  { hostId: 'fs01', user: 'root', label: 'fs01 console (root)', banner: 'fs01 console: the Samba server. Try: testparm -s, pdbedit -L, ls /var/log/samba/, tail /var/log/samba/log.ws01, id dana.' },
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: `ws01 as alice (Samba password ${ALICE}). Try: smbclient -L fs01 -U alice, smbclient //fs01/office -U alice -c "ls".` },
  { hostId: 'win01', user: 'Administrator', label: 'win01 (Administrator)', banner: 'win01 PowerShell. Try: net use, net use O: \\\\fs01\\office /user:dana, Test-NetConnection fs01 -Port 445.' },
];

const CANDIDATES = ['smb-no-passdb', 'smb-wrong-password', 'smb-valid-users', 'smb-share-path', 'smb-read-only', 'server-file-permissions'];

/** The office share stays limited to staff, without guests, and its directory closed to others. */
function officeRestricted(): Constraint {
  return {
    id: 'smb-office-restricted', required: true,
    description: '[office] stays limited to the staff group: valid users = @staff, no guest access, /srv/office not accessible to others.',
    check(world) {
      const fs01 = world.hosts.fs01;
      const s = findShare(loadSmbConf(fs01), 'office');
      const valid = (s?.params['valid users'] ?? '').split(/[\s,]+/).filter(Boolean);
      const mode = fs01.fs['/srv/office']?.mode ?? 0o777;
      const ok = !!s && valid.length > 0 && valid.every((v) => v === '@staff' || v === '+staff') && !boolValue(s.params['guest ok']) && (mode & 0o007) === 0;
      return { id: this.id, ok, required: true, message: ok ? 'fs01: [office] is limited to @staff and /srv/office is closed to others.' : '[office] must keep "valid users = @staff", no guest access, and /srv/office without permissions for others: fix the account, not the share.' };
    },
  };
}

function scansRestricted(): Constraint {
  return {
    id: 'smb-scans-restricted', required: true,
    description: '[scans] stays for the scanner account only (valid users = scanner, no guests) and /srv/scans is not world-writable.',
    check(world) {
      const fs01 = world.hosts.fs01;
      const s = findShare(loadSmbConf(fs01), 'scans');
      const ok = !!s && (s.params['valid users'] ?? '').trim() === 'scanner' && !boolValue(s.params['guest ok']) && ((fs01.fs['/srv/scans']?.mode ?? 0o777) & 0o002) === 0;
      return { id: this.id, ok, required: true, message: ok ? 'fs01: [scans] is for the scanner account only.' : '[scans] must stay "valid users = scanner" without guest access, and /srv/scans must not be world-writable.' };
    },
  };
}

const smbLs = (share: string, user: string, password: string, expect: string): Goal => ({
  kind: 'command',
  description: `On ws01, smbclient //fs01/${share} -U ${user} lists the share.`,
  steps: [{ host: 'ws01', user: 'alice', command: `smbclient //fs01/${share} -U ${user}%${password} -c ls` }],
  expect,
});

const netUse = (drive: string, share: string, user: string, password: string): Goal => ({
  kind: 'command',
  description: `On win01, net use ${drive} \\\\fs01\\${share} /user:${user} maps the drive.`,
  steps: [{ host: 'win01', user: 'Administrator', command: `net use ${drive} \\\\fs01\\${share} /user:${user} ${password}` }],
  expect: 'The command completed successfully',
});

/** A few hours of normal use of the shares. */
function activity(world: World): void {
  world.clock += 2 * 3600_000;
  script(world, 'ws01', [`smbclient //fs01/office -U alice%${ALICE} -c ls`]);
}

export const SMB_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'smb-new-user',
    title: 'Account created',
    difficulty: 'beginner',
    ticket: 'HR: "Carol started today. IT created her account on the file server yesterday (CHG-2315: useradd -m -G staff carol, password Welcome-Carol1), but she cannot open the office share from ws01: smbclient says NT_STATUS_LOGON_FAILURE. We re-typed the password three times."',
    briefing: BRIEFING,
    goals: [smbLs('office', 'carol', 'Welcome-Carol1', 'budget-2025\\.txt')],
    terminals: TERMINALS,
    setup(world) {
      script(world, 'fs01', ['useradd -m -G staff -c "Carol Office" carol']);
      activity(world);
      script(world, 'ws01', ['smbclient //fs01/office -U carol%Welcome-Carol1 -c ls', 'smbclient //fs01/office -U carol%Welcome-Carol1 -c ls']);
    },
    rootCauses: ['smb-no-passdb'],
    candidates: CANDIDATES,
    feedback: {
      'smb-wrong-password': 'The server log says NT_STATUS_NO_SUCH_USER for carol, not NT_STATUS_WRONG_PASSWORD: Samba does not know the user at all.',
      'smb-valid-users': 'carol is in staff (id carol on fs01), and the failure happens at the logon (session setup), before any share is chosen.',
      'smb-share-path': 'alice opens the same share without problems.',
      'smb-read-only': 'carol cannot even log on; read-only would only stop writes.',
      'server-file-permissions': 'The logon fails before any file is touched.',
    },
    hints: [
      'Where does it fail: logon (session setup) or share (tree connect)? smbclient -L fs01 -U carol tests the logon alone. Then read fs01\'s log for ws01: tail /var/log/samba/log.ws01.',
      'The Auth: line says status [NT_STATUS_NO_SUCH_USER]. Samba has its own user database: pdbedit -L lists who it knows. Is carol there?',
      'Add her to Samba with the password from the ticket: smbpasswd -a carol on fs01 (it asks twice; in a script: printf \'PW\\nPW\\n\' | smbpasswd -a -s carol).',
    ],
    explanation: {
      rootCause: 'carol was created as a Unix user (useradd, passwd) but never added to Samba\'s password database (smbpasswd -a). SMB clients send an NTLM response that Samba checks against its own stored hash, not against /etc/shadow.',
      manifestation: 'Every logon fails with NT_STATUS_LOGON_FAILURE (Windows: "System error 1326: The user name or password is incorrect"), exactly like a wrong password, so people keep re-typing it.',
      evidence: '/var/log/samba/log.ws01 on fs01: "Auth: ... user [WORKGROUP]\\[carol] ... status [NT_STATUS_NO_SUCH_USER]"; pdbedit -L lists alice and dana but not carol; id carol shows the Unix account exists.',
      prevention: 'Make "smbpasswd -a" (or joining fs01 to the AD domain, where accounts come from AD) part of the account-creation procedure, and test the new account\'s access before handing it over.',
    },
    solution: [{ host: 'fs01', commands: ['printf \'Welcome-Carol1\\nWelcome-Carol1\\n\' | smbpasswd -a -s carol'] }],
    constraints: [officeRestricted()],
    concepts: ['files.smb'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'smb-valid-users',
    title: 'Reorganised',
    difficulty: 'intermediate',
    ticket: 'Dana (on win01): "Since yesterday my O: drive is gone. net use O: \\\\fs01\\office says System error 5, Access is denied. My password is right: it worked until yesterday and nobody changed it." Yesterday the finance team was set up on fs01 (CHG-2317: usermod -G finance dana).',
    briefing: BRIEFING,
    goals: [netUse('O:', 'office', 'dana', DANA)],
    terminals: TERMINALS,
    setup(world) {
      script(world, 'fs01', ['usermod -G finance dana']);
      activity(world);
      script(world, 'win01', [`net use O: \\\\fs01\\office /user:dana ${DANA}`]);
    },
    rootCauses: ['smb-valid-users'],
    candidates: CANDIDATES,
    feedback: {
      'smb-no-passdb': 'dana logs on fine (pdbedit -L lists her, and the logon succeeds: the error comes from the share).',
      'smb-wrong-password': 'The logon succeeds; the share refuses her afterwards.',
      'smb-share-path': 'The share works for alice; a missing path would fail for everybody with "network name cannot be found".',
      'smb-read-only': 'She cannot connect to the share at all, not only write.',
      'server-file-permissions': 'Close: the Unix group matters too, but here Samba refuses her before any file: the share\'s valid users list.',
    },
    hints: [
      'Error 5 (Access is denied) after a successful logon means the share refused her. On fs01: tail /var/log/samba/log.win01.',
      '"user \'dana\' (from session setup) not permitted to access this share (office)". testparm -s shows valid users = @staff. Is dana in staff? id dana.',
      'usermod -G replaces the supplementary groups; -a adds. Give dana staff back: usermod -aG staff dana on fs01, then net use again on win01.',
    ],
    explanation: {
      rootCause: '"usermod -G finance dana" replaced dana\'s supplementary groups instead of adding one (that needs -aG). She lost staff, and [office] has valid users = @staff.',
      manifestation: 'The logon still works (her Samba password is unchanged), so shares without a group restriction open, but the tree connect to [office] is refused: Windows shows "System error 5: Access is denied", smbclient "tree connect failed: NT_STATUS_ACCESS_DENIED".',
      evidence: '/var/log/samba/log.win01: "user \'dana\' (from session setup) not permitted to access this share (office)"; id dana: groups=dana,finance; testparm -s: valid users = @staff. The /srv/office directory (root:staff 0770) would refuse her too.',
      prevention: 'Always usermod -aG to add a group; check id USER after changes; manage group membership centrally (AD groups when fs01 joins the domain).',
    },
    solution: [{ host: 'fs01', commands: ['usermod -aG staff dana'] }],
    constraints: [officeRestricted()],
    concepts: ['files.smb', 'linux.permissions'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'smb-share-path',
    title: 'Listed but not found',
    difficulty: 'intermediate',
    ticket: 'Windows team: "We published the software repository over SMB as well (CHG-2318). The share is visible, but net use S: \\\\fs01\\software gives System error 67, The network name cannot be found. The Linux servers still get it over NFS."',
    briefing: BRIEFING,
    goals: [netUse('S:', 'software', 'dana', DANA), smbLs('software', 'alice', ALICE, 'agent-install\\.sh'), {
      kind: 'command',
      description: 'srv01 still sees the software repository over NFS (/opt/software).',
      steps: [{ host: 'srv01', user: 'root', command: 'ls /opt/software' }],
      expect: 'agent-install\\.sh',
    }],
    terminals: TERMINALS,
    setup(world) {
      writeFile(world.hosts.fs01, '/etc/samba/smb.conf', FS01_SMB_CONF.replace('   path = /srv/software\n', '   path = /srv/Software\n'), world.clock);
      activity(world);
      script(world, 'win01', [`net use S: \\\\fs01\\software /user:dana ${DANA}`]);
    },
    rootCauses: ['smb-share-path'],
    candidates: CANDIDATES,
    feedback: {
      'smb-no-passdb': 'dana logs on and maps O: (office) without problems.',
      'smb-wrong-password': 'The same credentials work for the office share.',
      'smb-valid-users': 'A refused user gets "Access is denied" (error 5), not "network name cannot be found" (67).',
      'smb-read-only': 'The share is meant to be read-only; here it cannot be opened at all.',
      'server-file-permissions': '/srv/software is world-readable; Samba fails before looking at files.',
    },
    hints: [
      'Error 67 means the server says the share does not exist. Yet smbclient -L fs01 -U alice lists "software". What does fs01 log for win01? tail /var/log/samba/log.win01.',
      '"canonicalize_connect_path failed for service software, path /srv/Software": the share exists in smb.conf but its directory does not. ls -ld /srv/software /srv/Software. Linux paths are case-sensitive.',
      'Fix the path in /etc/samba/smb.conf (path = /srv/software) and check with testparm -s; new connections pick it up. Do not rename the directory: NFS exports /srv/software to the Linux servers.',
    ],
    explanation: {
      rootCause: 'The [software] share was written with path = /srv/Software. The directory is /srv/software, and Linux file names are case-sensitive (Windows admins are used to case-insensitive paths).',
      manifestation: 'The share is announced (it is in smb.conf, so it shows in share lists), but every tree connect fails because smbd cannot enter its directory: Windows reports error 67, smbclient NT_STATUS_BAD_NETWORK_NAME, the same as for a share that does not exist.',
      evidence: '/var/log/samba/log.win01: "make_connection_snum: canonicalize_connect_path failed for service software, path /srv/Software"; testparm -s: path = /srv/Software; ls -ld /srv/Software: No such file or directory.',
      prevention: 'Copy paths from the server (ls, tab completion), not from documentation; test every new share from a client before announcing it.',
    },
    solution: [{ host: 'fs01', commands: ['sed -i \'s#path = /srv/Software#path = /srv/software#\' /etc/samba/smb.conf', 'testparm -s'] }],
    constraints: [officeRestricted()],
    concepts: ['files.smb'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'smb-read-only',
    title: 'The scanner cannot save',
    difficulty: 'intermediate',
    ticket: 'Facilities: "The new multifunction printer scans to \\\\fs01\\scans (account scanner, set up yesterday in CHG-2321). The printer logs in fine but every scan ends with \'Cannot write to destination\'. The folder belongs to the scanner account, we checked."',
    briefing: [...BRIEFING, 'fs01 also has a [scans] share (/srv/scans, owned by the Unix account scanner) for the printer; its Samba password is Scan-2024.'],
    goals: [{
      kind: 'command',
      description: 'The scanner account uploads a file to \\\\fs01\\scans and it lands in /srv/scans, owned by scanner.',
      steps: [{ host: 'ws01', user: 'alice', command: 'smbclient //fs01/scans -U scanner%Scan-2024 -c \'put /etc/hostname scan-0001.pdf\'' }, { host: 'fs01', user: 'root', command: 'ls -l /srv/scans/scan-0001.pdf' }],
      expect: '^\\S+ \\d+ scanner .*scan-0001\\.pdf$',
    }],
    terminals: [...TERMINALS.slice(0, 2), { hostId: 'ws01', user: 'root', label: 'ws01 console (root)', banner: 'ws01: test as the printer would: smbclient //fs01/scans -U scanner%Scan-2024 -c "put /etc/hostname test.pdf".' }],
    setup(world) {
      script(world, 'fs01', [
        'useradd -u 1003 -c "MFP scan-to-folder" -s /usr/sbin/nologin scanner',
        'mkdir -p /srv/scans', 'chown scanner:scanner /srv/scans', 'chmod 750 /srv/scans',
        'printf \'Scan-2024\\nScan-2024\\n\' | smbpasswd -a -s scanner',
      ]);
      writeFile(world.hosts.fs01, '/etc/samba/smb.conf', `${FS01_SMB_CONF}\n[scans]\n   comment = Scanner drop folder (CHG-2321)\n   path = /srv/scans\n   valid users = scanner\n   create mask = 0640\n`, world.clock);
      activity(world);
      script(world, 'ws01', ['smbclient //fs01/scans -U scanner%Scan-2024 -c \'put /etc/hostname scan-0000.pdf\'']);
    },
    rootCauses: ['smb-read-only'],
    candidates: CANDIDATES,
    feedback: {
      'smb-no-passdb': 'The scanner logs on and can list the share (smbclient ... -c ls works).',
      'smb-wrong-password': 'The logon succeeds.',
      'smb-valid-users': 'The share accepts the scanner account: listing works, only writing fails.',
      'smb-share-path': 'The share opens and lists /srv/scans.',
      'server-file-permissions': 'scanner owns /srv/scans with rwx: the Unix permissions allow the write. Samba refuses it before that.',
    },
    hints: [
      'Separate the layers: logon OK? (-c ls works) Share OK? Writing fails with NT_STATUS_ACCESS_DENIED. Who would refuse the write: Samba or the file system? ls -ld /srv/scans on fs01.',
      'The directory allows scanner to write. Look at the share as Samba reads it: testparm -s. What is missing compared with [office]?',
      'Samba shares are read-only unless they say otherwise. Add "read only = no" (or "writable = yes") to [scans] in /etc/samba/smb.conf, check with testparm -s, and test the upload again.',
    ],
    explanation: {
      rootCause: 'The [scans] share has no "read only = no" (or "writable = yes"). Samba\'s default is read only = yes, so every write is refused at the share level, whatever the directory\'s Unix permissions.',
      manifestation: 'The printer logs on and can browse the folder, but every file creation fails: smbclient "NT_STATUS_ACCESS_DENIED opening remote file \\scan-0001.pdf", the printer "Cannot write to destination".',
      evidence: 'testparm -s: [scans] has no "read only = No" ([office] has it); ls -ld /srv/scans: drwxr-x--- scanner scanner; the upload fails while ls works.',
      prevention: 'Both layers must allow a write: the share (read only / write list) and the file system (owner, group, mode). Test a write as the real account when creating a share.',
    },
    solution: [{ host: 'fs01', commands: ['echo \'   read only = no\' >> /etc/samba/smb.conf', 'testparm -s'] }],
    constraints: [scansRestricted()],
    concepts: ['files.smb', 'linux.permissions'],
  },
];
