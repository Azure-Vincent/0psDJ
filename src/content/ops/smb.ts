// File sharing with SMB (Samba). Examples follow the lab: fs01 (10.0.20.60)
// runs smbd with [office] (/srv/office, read-write for the staff group) and
// [software] (read-only); ws01 uses smbclient, win01 maps drives with net use.
// The sandbox and the tickets run there. Windows file servers, AD member
// servers and RHEL are noted.

import type { Assessment, Lesson, Primer, ServiceGuide } from '../types';

// --- Operate & recover guide ---------------------------------------------------------

export const SMB_GUIDE: ServiceGuide = {
  purpose:
    'SMB (Server Message Block, also called CIFS in its old version) is the file-sharing protocol of Windows, and Samba implements it on Linux. A server offers **shares** (named folders); clients connect over TCP 445, **log on** with a user name and password, and then use files in the share. Every Windows computer can map a share as a drive letter; Linux and macOS clients connect as well. Unlike NFS, the user is authenticated by password (or Kerberos), and the server then acts as that user\'s own account.',
  architecture: [
    { q: 'What does it accomplish?', a: 'Shared folders for Windows, macOS and Linux clients, with per-user authentication, per-share access lists and the server\'s file permissions.' },
    { q: 'How does it work internally?', a: 'A connection goes through four steps: **negotiate** (agree on a dialect: SMB 2.1, 3.0, 3.1.1), **session setup** (authenticate the user: NTLMv2 against Samba\'s password database, or Kerberos in a domain), **tree connect** (open a share: it must exist, its path must exist, the user must be allowed), then **file operations** (create, read, write, close), each checked against the share\'s settings and the Unix permissions of the account.' },
    { q: 'Which protocols does it use?', a: 'SMB2/SMB3 directly over TCP 445. NetBIOS over TCP (137-139, nmbd) is the legacy transport and browsing service; SMB1 is disabled by default in current Samba and Windows (WannaCry used SMB1).' },
    { q: 'Which ports and transport?', a: 'TCP 445 (TCP 139 only for old NetBIOS clients). Firewalls must allow 445 from the client networks; it should never be reachable from the Internet.' },
    { q: 'Which processes and OS components implement it?', a: 'Samba: `smbd` (file service, one child process per client), `nmbd` (NetBIOS names), `winbindd` (domain members). Windows: the Server service (LanmanServer) and Workstation service (LanmanWorkstation) on clients.' },
    { q: 'Which other services does it depend on?', a: 'DNS (or NetBIOS) for the server name, the network path and firewall to 445, Samba\'s user database (standalone) or the AD domain (member server, Kerberos, winbind), the Unix accounts and groups the users map to, and synchronized clocks for Kerberos.' },
    { q: 'How do requests travel?', a: 'dana on win01 runs net use O: \\\\fs01\\office → TCP 445 to fs01 → negotiate SMB 3.1.1 → session setup as WORKGROUP\\dana (NTLMv2, checked against passdb.tdb, mapped to the Unix user dana) → tree connect to office (valid users = @staff: is dana in staff?) → the drive appears; each file she saves is created on fs01 by smbd running as dana, with the share\'s create mask and force group.' },
    { q: 'How do authentication and authorisation work?', a: '**Authentication**: a standalone Samba server keeps its own password hashes (smbpasswd -a), separate from /etc/shadow; an AD member server asks the domain controllers. **Authorisation** has two layers: the share (valid users, read only / write list, guest ok) and the file system (owner, group, mode of each file and directory, as the user\'s Unix account).' },
    { q: 'How does it start at boot?', a: '`smbd.service` (and nmbd.service) start from multi-user.target. smbd re-reads smb.conf for new connections and periodically, so share changes need no restart; users and group membership are looked up at logon.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'Clients lose open files and mapped drives show as disconnected (red X on Windows); unsaved data in open documents can be lost. Windows reconnects persistent mappings when the server is back.' },
  ],
  ports: [
    { port: '445', proto: 'TCP', purpose: 'SMB2/SMB3 (direct hosting): everything a modern client needs' },
    { port: '139', proto: 'TCP', purpose: 'SMB over NetBIOS session service (legacy clients)' },
    { port: '137-138', proto: 'UDP', purpose: 'NetBIOS name service and datagrams (nmbd, network browsing)' },
    { port: '2049', proto: 'TCP', purpose: 'NFS, the Unix alternative on the same server' },
  ],
  processes: [
    { name: 'smbd', platform: 'Linux (Samba, smbd.service)', role: 'Serves shares: one child process per client connection, running as the logged-on user for file access' },
    { name: 'nmbd', platform: 'Linux (Samba)', role: 'NetBIOS name service and browsing (not needed for DNS and \\\\fs01\\share)' },
    { name: 'winbindd', platform: 'Linux (Samba AD member)', role: 'Maps domain users and groups to Unix IDs and checks domain logons' },
    { name: 'LanmanServer / LanmanWorkstation', platform: 'Windows', role: 'The SMB server and client services' },
  ],
  dependencies: {
    title: 'What "dana opens \\\\fs01\\office" depends on (top needs everything below it)',
    caption: 'Each step has its own error: connect (53), logon (1326), share (5 / 67), file (access denied).',
    rows: [
      { label: 'Client', nodes: [{ id: 'cli', label: 'net use / smbclient', sub: 'credentials', kind: 'service' }] },
      { label: 'Path', nodes: [{ id: 'dns', label: 'DNS', sub: 'fs01.corp.lab', kind: 'network' }, { id: 'fw', label: 'fs01 firewall', sub: 'tcp dport 445', kind: 'network' }] },
      { label: 'Logon', nodes: [{ id: 'smbd', label: 'smbd', sub: 'smbd.service', kind: 'service' }, { id: 'pdb', label: 'passdb.tdb', sub: 'smbpasswd -a', kind: 'data' }] },
      { label: 'Share', nodes: [{ id: 'conf', label: 'smb.conf [office]', sub: 'valid users, read only', kind: 'data' }, { id: 'grp', label: 'Unix group staff', sub: 'id dana', kind: 'os' }] },
      { label: 'Files', nodes: [{ id: 'perm', label: '/srv/office', sub: 'root:staff 0770', kind: 'os' }] },
    ],
    edges: [['cli', 'dns'], ['cli', 'fw'], ['fw', 'smbd'], ['smbd', 'pdb'], ['pdb', 'conf'], ['conf', 'grp'], ['grp', 'perm']],
  },
  sequence: {
    title: 'win01 maps \\\\fs01\\office as O:',
    caption: 'SMB 3.1.1 over TCP 445, NTLMv2 against Samba\'s password database. Where each ticket breaks the exchange is noted.',
    lanes: [{ id: 'c', label: 'win01', sub: 'net use (dana)' }, { id: 's', label: 'fs01', sub: 'smbd' }],
    steps: [
      { from: 'c', to: 's', label: 'TCP SYN to 10.0.20.60:445', note: 'Dropped → "System error 53: The network path was not found" (smbclient: NT_STATUS_IO_TIMEOUT).' },
      { from: 'c', to: 's', label: 'Negotiate Protocol Request (SMB 2.02 … 3.1.1)' },
      { from: 's', to: 'c', label: 'Negotiate Protocol Response (3.1.1)' },
      { from: 'c', to: 's', label: 'Session Setup (NTLMv2, WORKGROUP\\dana)', note: 'User not in passdb or wrong password → STATUS_LOGON_FAILURE ("System error 1326"). The server log tells NO_SUCH_USER from WRONG_PASSWORD.' },
      { from: 's', to: 'c', label: 'Session Setup Response (success)' },
      { from: 'c', to: 's', label: 'Tree Connect \\\\fs01\\office', note: 'Not in valid users → STATUS_ACCESS_DENIED (5). Share or its path missing → STATUS_BAD_NETWORK_NAME (67).' },
      { from: 's', to: 'c', label: 'Tree Connect Response: O: is mapped' },
      { from: 'c', to: 's', label: 'Create \\report.docx (write)', note: 'Share read only, or Unix permissions deny dana → STATUS_ACCESS_DENIED on the file.' },
    ],
  },
  files: [
    { path: '/etc/samba/smb.conf', platform: 'Samba server', kind: 'config', perms: 'root:root 0644', contains: '[global] settings and one section per share (path, valid users, read only, force group, masks).', accessed: 'At start and for new connections when changed.', problems: 'Shares default to read-only; typos are ignored; paths are case-sensitive.' },
    { path: '/var/lib/samba/private/passdb.tdb', platform: 'Samba standalone server', kind: 'auth', perms: 'root:root 0600', contains: 'Samba users and their NT password hashes (smbpasswd -a, pdbedit).', accessed: 'At each logon.', problems: 'A Unix account without an entry here cannot log on over SMB.' },
    { path: '/var/log/samba/log.CLIENT, log.smbd', platform: 'Samba server', kind: 'log', perms: 'root:adm 0644', contains: 'Per-client log (log file = /var/log/samba/log.%m): failed logons (auth_audit, with NO_SUCH_USER / WRONG_PASSWORD), refused shares, missing paths.', accessed: 'Written by smbd as clients connect.', problems: 'At the default log level 0 most refusals are not logged: raise log level (1-3) while troubleshooting.' },
    { path: 'Windows: net use / Get-SmbMapping; Event Viewer > SMBClient', platform: 'Windows client', kind: 'log', contains: 'Mapped drives and SMB client errors.', accessed: 'On connection.', problems: 'Windows shows only the system error number; the server log says why.' },
  ],
  management: [
    {
      platform: 'Linux client',
      tasks: [
        { task: 'Which shares does the server offer?', command: 'smbclient -L fs01 -U alice', explain: 'Tests DNS, port 445 and the logon in one go.', sim: true },
        { task: 'Use a share', command: 'smbclient //fs01/office -U alice -c "ls; get budget-2025.txt"', explain: 'Tests the tree connect and file access.', sim: true },
        { task: 'Write test', command: 'smbclient //fs01/office -U alice -c "put /etc/hostname test.txt"', explain: 'Writes need both a writable share and Unix permissions.', sim: true },
        { task: 'Mount a share', command: 'mount -t cifs //fs01/office /mnt/office -o credentials=/root/.smbcred,uid=alice', explain: 'cifs-utils mounts SMB shares; the credentials file holds username= and password=. Not simulated.' },
      ],
    },
    {
      platform: 'Samba server (fs01)',
      tasks: [
        { task: 'Check the configuration', command: 'testparm -s', explain: 'Unknown parameters and the effective share settings.', sim: true },
        { task: 'Samba users', command: 'pdbedit -L\nsmbpasswd -a carol', explain: 'Who can log on; add a user with a Samba password.', sim: true },
        { task: 'Who is connected?', command: 'smbstatus', explain: 'Sessions and connected shares (win01\'s mapped drives).', sim: true },
        { task: 'Why was someone refused?', command: 'tail /var/log/samba/log.ws01', explain: 'The per-client log names the failed step.', sim: true },
        { task: 'Group membership and directory permissions', command: 'id dana\nls -ld /srv/office', explain: 'The second layer of authorisation.', sim: true },
      ],
    },
    {
      platform: 'Windows client',
      tasks: [
        { task: 'Map and list drives', command: 'net use O: \\\\fs01\\office /user:dana *\nnet use', explain: 'The system error number identifies the failing step.', sim: true },
        { task: 'Is 445 reachable?', command: 'Test-NetConnection fs01 -Port 445', explain: 'TcpTestSucceeded : True means the network path and firewall are fine.', sim: true },
      ],
    },
    {
      platform: 'Windows Server (file server)',
      tasks: [
        { task: 'Shares', command: 'New-SmbShare -Name Office -Path D:\\Office -FullAccess "CORP\\Staff"\nGet-SmbShare\nGet-SmbShareAccess Office', explain: 'Share permissions plus NTFS permissions: the more restrictive wins, like Samba\'s two layers.' },
      ],
    },
  ],
  actions: [
    { action: 'smbpasswd -a USER', when: 'A new user must use SMB on a standalone Samba server.', effect: 'The user can log on with that password.', risk: 'The Samba password is separate from the Unix one: tell the user which is which.' },
    { action: 'Edit smb.conf, testparm -s', when: 'Changing a share.', effect: 'New connections use the new settings (no restart needed; smbcontrol all reload-config applies at once).', risk: 'Existing sessions keep the old share settings until they reconnect.' },
    { action: 'systemctl restart smbd', when: 'After [global] changes such as interfaces or protocol versions.', effect: 'Restarts the service.', risk: 'Every client loses its open files.' },
  ],
  workflow: [
    { question: '1. Can the client reach port 445?', command: 'smbclient -L fs01 -U alice\nTest-NetConnection fs01 -Port 445', healthy: 'The share list, or TcpTestSucceeded : True', broken: 'NT_STATUS_IO_TIMEOUT (dropped), NT_STATUS_CONNECTION_REFUSED (smbd down), system error 53.', next: 'Then the logon.', sim: true },
    { question: '2. Does the logon work?', command: 'smbclient -L fs01 -U carol\ntail /var/log/samba/log.ws01', healthy: 'The share list', broken: 'session setup failed: NT_STATUS_LOGON_FAILURE; the log says NO_SUCH_USER (smbpasswd -a missing) or WRONG_PASSWORD.', next: 'Then the share.', sim: true },
    { question: '3. Does the share let this user in?', command: 'smbclient //fs01/office -U dana -c ls\ntestparm -s\nid dana', healthy: 'The directory listing', broken: 'NT_STATUS_ACCESS_DENIED (valid users / group), NT_STATUS_BAD_NETWORK_NAME (no such share, or its path is missing).', next: 'Then writing.', sim: true },
    { question: '4. Can the user write?', command: 'smbclient //fs01/office -U dana -c "put /etc/hostname t.txt"\nls -ld /srv/office', healthy: 'putting file /etc/hostname as \\t.txt', broken: 'NT_STATUS_ACCESS_DENIED opening remote file: read only share (default!) or Unix permissions.', next: 'Fix the layer that refuses, test again as the real user.', sim: true },
  ],
  failures: [
    { symptom: 'NT_STATUS_LOGON_FAILURE / System error 1326 for one user', causes: ['No Samba password (smbpasswd -a never run)', 'Wrong password', 'Account disabled (smbpasswd -d)'], diagnose: ['pdbedit -L', 'The Auth: line in /var/log/samba/log.CLIENT'], fix: 'smbpasswd -a USER (or -e to enable).', verify: 'smbclient -L SERVER -U USER lists the shares.' },
    { symptom: 'Access is denied (5) / tree connect NT_STATUS_ACCESS_DENIED', causes: ['User not in the share\'s valid users (missing group)', 'Guest session on a share without guest ok', 'The directory cannot be entered by the user'], diagnose: ['testparm -s', 'id USER', 'The share log line "not permitted to access this share"'], fix: 'Fix the group membership (usermod -aG) rather than opening the share.', verify: 'The tree connect succeeds as that user.' },
    { symptom: 'The network name cannot be found (67) / NT_STATUS_BAD_NETWORK_NAME', causes: ['The share name is wrong', 'The share\'s path does not exist (typo, case)'], diagnose: ['smbclient -L SERVER', 'canonicalize_connect_path in the log', 'ls -ld PATH'], fix: 'Correct the path in smb.conf.', verify: 'The share lists its files.' },
    { symptom: 'Users can read but not write', causes: ['The share is read-only (default)', 'Unix permissions or ownership deny the user'], diagnose: ['testparm -s', 'ls -ld on the server'], fix: 'read only = no on the share, and correct group/mode on the directory.', verify: 'A write test as the real account.' },
  ],
  verification: [
    { check: 'Configuration valid', command: 'testparm -s', expect: 'Loaded services file OK. and no Unknown parameter lines' },
    { check: 'Listening', command: 'ss -tlnp', expect: 'smbd on 0.0.0.0:445' },
    { check: 'Logon and share', command: 'smbclient //fs01/office -U alice -c ls', expect: 'The share\'s files' },
    { check: 'Write test', command: 'smbclient //fs01/office -U alice -c "put /etc/hostname t.txt"', expect: 'putting file ... and the file on the server owned by the user, with the share\'s group' },
  ],
  refIds: ['smbclient', 'smbpasswd', 'testparm', 'file:smb-conf', 'net-use', 'ss', 'nft'],
};

// --- Lesson -------------------------------------------------------------------------

export const SMB_LESSON: Lesson = {
  id: 'smb',
  moduleId: 'F',
  title: 'File sharing (SMB and Samba)',
  level: 'intermediate',
  summary: 'How an SMB connection goes from TCP 445 through logon and share to file access, how Samba keeps its own users and shares, why shares are read-only by default, and how Windows error numbers and Samba\'s log tell the failing step apart.',
  concepts: ['files.smb', 'linux.permissions', 'fw.path'],

  what: `
**SMB** is the file-sharing protocol of Windows; **Samba** implements it on Linux. A server offers **shares** (named folders such as \\\\fs01\\office); a client logs on with a user name and password and then works with the files, often through a mapped drive letter.

### Problems it solves
- **Shared folders for every desktop.** Windows maps \\\\fs01\\office as O:; macOS and Linux connect too.
- **Per-user access.** Users log on; the server knows who reads and writes every file.
- **One place for data.** Backups, permissions and quotas are managed on the server.

### The pieces
- **smb.conf** on the server: one section per share (path, who may use it, read-only or writable).
- **Samba users**: on a standalone server Samba keeps its own password database (\`smbpasswd -a\`); in a domain, the domain controllers check passwords.
- **The Unix side**: every Samba user is a Unix account on the server, and file access is checked with its normal permissions.
- **Clients**: \`net use\` and Explorer on Windows, \`smbclient\` (and \`mount -t cifs\`) on Linux, over TCP 445.

> In the lab, **fs01** (10.0.20.60) runs Samba next to its NFS server: [office] is /srv/office (read-write for the Unix group staff), [software] is /srv/software (read-only). alice and dana have Samba passwords. **ws01** uses smbclient; **win01** maps drives with \`net use\`. Simulated: smb.conf (shares, valid users with @groups, read only / writable / write list, guest ok, force group, create and directory masks, unknown parameters), Samba's password database (\`smbpasswd\`, \`pdbedit\`), the connection steps over TCP 445 with SMB2 packets (negotiate, session setup, tree connect) and their NT_STATUS errors, file operations as the server-side Unix account, per-client logs with log level 2, \`testparm\`, \`smbstatus\`, \`net use\` with Windows system errors. Simplified: NTLMv2 only (no Kerberos or AD membership), smbclient runs with -c only, Windows does not browse mapped drives, no mount.cifs, no NetBIOS (nmbd).
`,

  internals: `
### 1. Four steps, four kinds of error
| Step | What is checked | Typical error (smbclient / Windows) |
|---|---|---|
| Connect | name, route, firewall, smbd listening on 445 | NT_STATUS_IO_TIMEOUT, NT_STATUS_CONNECTION_REFUSED / **53** |
| Session setup | user and password (Samba's passdb or the domain) | NT_STATUS_LOGON_FAILURE / **1326** |
| Tree connect | share exists, path exists, valid users, guest | NT_STATUS_BAD_NETWORK_NAME / **67**, NT_STATUS_ACCESS_DENIED / **5** |
| File operation | share writable, Unix permissions of the account | NT_STATUS_ACCESS_DENIED opening remote file |

\`smbclient -L server\` stops after session setup; \`smbclient //server/share -c ls\` adds the tree connect; a \`put\` tests writing. That is the whole troubleshooting method.

### 2. Samba's own users
A standalone Samba server cannot use /etc/shadow: SMB clients never send the password itself, only an NTLM response computed from its hash, so Samba stores NT hashes in **passdb.tdb**. \`smbpasswd -a carol\` adds carol (the Unix account must exist); \`pdbedit -L\` lists who can log on. A Unix user missing there gets exactly the same error as a wrong password: the server log tells them apart:
\`\`\`
Auth: [SMB2,(null)] user [WORKGROUP]\\[carol] ... status [NT_STATUS_NO_SUCH_USER] ...
\`\`\`
On an **AD member server** (security = ads, winbind), the domain controllers check passwords with Kerberos and no local Samba passwords are needed.

### 3. Shares
\`\`\`
[office]
   path = /srv/office
   valid users = @staff
   read only = no
   force group = staff
   create mask = 0660
   directory mask = 0770
\`\`\`
- **valid users**: names and @groups allowed to connect (missing → everybody who can log on).
- **read only** defaults to **yes**: a share is read-only unless it says \`read only = no\` (or \`writable = yes\`); **write list** names exceptions.
- **force group** makes new files belong to the group, **create mask** / **directory mask** limit their modes (Samba starts from 0666 / 0777).
- A path that does not exist (Linux paths are **case-sensitive**) makes the share unusable: NT_STATUS_BAD_NETWORK_NAME, as if it did not exist.

smbd reads smb.conf again for new connections, so share changes need no restart. \`testparm -s\` shows what Samba understood (and only non-default values: no "read only = No" means read-only).

### 4. Two layers of authorisation
After the share allows a write, smbd performs it **as the user's Unix account**: the directory must allow that user (owner, group, mode). The share can only restrict further, never grant what the file system refuses. This is the same idea as Windows share permissions plus NTFS permissions.

### 5. SMB compared with NFS
| | NFS (sec=sys) | SMB |
|---|---|---|
| Who is the user? | the number the client sends | authenticated by password / Kerberos |
| Access control | client list + Unix permissions | users/groups per share + Unix permissions |
| Typical clients | Linux/Unix servers | Windows, macOS, Linux desktops |
| Port | 2049 | 445 |

### 6. Security
Never expose 445 to the Internet; keep SMB1 disabled (server min protocol = SMB2_10 or higher); avoid guest access (\`map to guest = bad user\` silently turns unknown users into guests); require signing or encryption (\`server signing\`, \`smb encrypt\`) where the network is not trusted; limit shares to groups.
`,

  deployment: [
    {
      id: 'debian',
      platform: 'Debian 12 / Ubuntu (Samba standalone server)',
      summary: 'Share /srv/office with the staff group. Steps marked simulated can be tried in the sandbox (fs01 already runs this setup).',
      prerequisites: ['The directory and the Unix group: groupadd staff; mkdir /srv/office; chown root:staff /srv/office; chmod 0770 /srv/office.', 'Users as Unix accounts (they need no shell: -s /usr/sbin/nologin).'],
      steps: [
        { title: 'Install Samba', command: 'sudo apt install -y samba smbclient\nsystemctl status smbd', what: 'smbd, nmbd, testparm, smbpasswd, pdbedit.', why: 'smbclient tests the server from the command line.', expected: 'Active: active (running)' },
        { title: 'Define the share', command: '[office]\n   path = /srv/office\n   valid users = @staff\n   read only = no\n   force group = staff\n   create mask = 0660\n   directory mask = 0770', what: 'At the end of /etc/samba/smb.conf.', why: 'Only staff; read-write; files stay group-owned and closed to others.', expected: '' },
        { title: 'Check it', command: 'testparm -s', what: 'Validate and show what Samba understood.', why: 'Typos are ignored silently otherwise.', expected: '[office]\n\tpath = /srv/office\n\tread only = No\n\tvalid users = @staff', simulated: true },
        { title: 'Give users a Samba password', command: 'smbpasswd -a carol\npdbedit -L', what: 'Add each user to Samba\'s database.', why: 'The Unix password is not used for SMB logons.', expected: 'Added user carol.', simulated: true },
        { title: 'Firewall', command: 'nft list ruleset', what: 'Allow TCP 445 from the client networks only.', why: 'SMB must never be reachable from the Internet.', expected: 'ip saddr 10.0.0.0/16 tcp dport 445 accept', simulated: true },
        { title: 'Test from a client', command: 'smbclient //fs01/office -U alice -c "ls; put /etc/hostname test.txt"', what: 'Logon, share and write in one go.', why: 'Proves every layer as a real user.', expected: 'putting file /etc/hostname as \\test.txt (2.0 kb/s) (average 2.0 kb/s)', simulated: true },
      ],
    },
    {
      id: 'rhel',
      platform: 'RHEL 9',
      summary: 'Same smb.conf; package samba; firewalld service samba; SELinux needs the share directory labelled for Samba.',
      prerequisites: ['dnf install samba samba-client'],
      steps: [
        { title: 'Firewall and SELinux', command: 'sudo firewall-cmd --permanent --add-service=samba && sudo firewall-cmd --reload\nsudo semanage fcontext -a -t samba_share_t "/srv/office(/.*)?" && sudo restorecon -R /srv/office\nsudo systemctl enable --now smb', what: 'Open 445, label the directory, start smb.service.', why: 'Without the samba_share_t label SELinux denies smbd access, which looks like a permission problem.', expected: 'success' },
      ],
    },
    {
      id: 'windows',
      platform: 'Windows Server (file server)',
      summary: 'Windows Server shares folders natively (File and Storage Services). Share permissions and NTFS permissions both apply, the more restrictive wins; domain groups grant access.',
      prerequisites: ['A domain or local groups for access.'],
      steps: [
        { title: 'Create the share', command: 'New-SmbShare -Name Office -Path D:\\Office -ChangeAccess "CORP\\Staff"\nicacls D:\\Office /grant "CORP\\Staff:(OI)(CI)M"', what: 'Share permission Change plus NTFS Modify for the group.', why: 'Both layers must allow writing.', expected: '' },
        { title: 'Map it on clients', command: 'net use O: \\\\fs01\\office /persistent:yes', what: 'Or a Group Policy drive map.', why: 'Users get the same drive letter everywhere.', expected: 'The command completed successfully.' },
      ],
    },
  ],

  configIntro: `
Configuration lives on the server:
- **/etc/samba/smb.conf**: [global] (server role, logging, protocols, guest mapping) and one section per share.
- **Samba's user database** (passdb.tdb, managed with smbpasswd/pdbedit) on a standalone server.
- **Unix accounts, groups and directory permissions**: the second layer for every file.

Check with \`testparm -s\` after every edit.
`,

  configFiles: [
    { platform: 'Samba (Debian / Ubuntu / RHEL)', items: [
      { path: '/etc/samba/smb.conf', purpose: 'Global settings and shares.' },
      { path: '/var/lib/samba/private/passdb.tdb', purpose: 'Samba users and password hashes (smbpasswd -a).' },
      { path: '/var/log/samba/log.%m', purpose: 'Per-client logs (log level decides the detail).' },
    ] },
    { platform: 'Windows', items: [
      { path: 'Get-SmbShare / Get-SmbShareAccess; folder Properties > Security', purpose: 'Share and NTFS permissions.' },
    ] },
  ],

  directives: [
    { name: 'path', compiledDefault: '(none)', recommended: 'An existing directory with the right group', explanation: 'The directory the share exposes.', security: 'Never share / or system directories.' },
    { name: 'valid users', compiledDefault: '(everyone who can log on)', recommended: '@group', explanation: 'Who may connect to the share.', security: 'Without it, every Samba user can open the share (file permissions still apply).' },
    { name: 'read only / writable / write list', compiledDefault: 'read only = yes', recommended: 'read only = no only where needed', explanation: 'Whether the share allows writes, and for whom.', security: 'Read-only shares limit what a compromised account or ransomware can encrypt.' },
    { name: 'force group, create mask, directory mask', compiledDefault: '(none), 0744, 0755', recommended: 'force group = the share group, 0660 / 0770', explanation: 'Ownership and modes of new files.', security: 'Keeps new files closed to others.' },
    { name: 'guest ok / map to guest', compiledDefault: 'no / never', recommended: 'no / never', explanation: 'Access without a password; turning unknown users into guests.', security: 'Guest access is unauthenticated and blocked by current Windows clients.' },
    { name: 'server min protocol', compiledDefault: 'SMB2_02', recommended: 'SMB2_10 or SMB3', explanation: 'Oldest dialect accepted.', security: 'Never re-enable SMB1 (NT1).' },
  ],

  operateIntro: `
### Before you change a share
- Edit smb.conf, run \`testparm -s\`, then test as a real user from a client (\`smbclient ... -c "put ..."\`).
- New users: \`useradd\` **and** \`smbpasswd -a\`, then add them to the share's group with \`usermod -aG\`.
- Raise \`log level\` (2 is enough) while troubleshooting; the per-client log names the failing step.

`,
  troubleshootingIntro: `
### Connect, logon, share, file
1. **Connect**: \`smbclient -L fs01\` or \`Test-NetConnection fs01 -Port 445\` (timeout = firewall, refused = smbd).
2. **Logon**: "session setup failed" / 1326: \`pdbedit -L\` and the Auth: line in /var/log/samba/log.CLIENT.
3. **Share**: "tree connect failed" / 5 or 67: \`testparm -s\` (valid users, path), \`id USER\`, \`ls -ld PATH\`.
4. **File**: "ACCESS_DENIED opening remote file": read only (default!) or Unix permissions.

Windows only gives a number: 53, 1326, 5, 67. The server's log says why.
`,

  errorMap: [
    { message: 'do_connect: Connection to fs01 failed (Error NT_STATUS_IO_TIMEOUT)', layer: 'Network / firewall', meaning: 'No answer on TCP 445.', firstCheck: 'nft list ruleset on the server; Test-NetConnection -Port 445' },
    { message: 'do_connect: Connection to fs01 failed (Error NT_STATUS_CONNECTION_REFUSED)', layer: 'Service', meaning: 'smbd does not listen.', firstCheck: 'systemctl status smbd; ss -tlnp' },
    { message: 'session setup failed: NT_STATUS_LOGON_FAILURE', layer: 'Authentication', meaning: 'Wrong password or user unknown to Samba.', firstCheck: 'pdbedit -L; Auth: line in /var/log/samba/log.CLIENT' },
    { message: 'System error 1326 has occurred. The user name or password is incorrect.', layer: 'Authentication', meaning: 'Same, seen from Windows.', firstCheck: 'The server log' },
    { message: 'tree connect failed: NT_STATUS_ACCESS_DENIED / System error 5', layer: 'Share authorisation', meaning: 'The share refuses this user.', firstCheck: 'testparm -s (valid users); id USER' },
    { message: 'tree connect failed: NT_STATUS_BAD_NETWORK_NAME / System error 67', layer: 'Share definition', meaning: 'No such share, or its path does not exist.', firstCheck: 'smbclient -L; canonicalize_connect_path in the log; ls -ld PATH' },
    { message: 'NT_STATUS_ACCESS_DENIED opening remote file \\x', layer: 'Share or file system', meaning: 'Write refused: read only share, or Unix permissions.', firstCheck: 'testparm -s; ls -ld on the server' },
    { message: 'System error 53 has occurred. The network path was not found.', layer: 'Name / network', meaning: 'The client could not reach SMB on that name.', firstCheck: 'Resolve-DnsName fs01; Test-NetConnection fs01 -Port 445' },
  ],

  scenarioIds: ['smb-new-user', 'smb-valid-users', 'smb-share-path', 'smb-read-only'],
  assessmentId: 'smb',
  references: [
    { title: 'smb.conf(5) manual page (Samba)', url: 'https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html' },
    { title: 'Samba Wiki: Setting up Samba as a Standalone Server', url: 'https://wiki.samba.org/index.php/Setting_up_Samba_as_a_Standalone_Server' },
    { title: 'smbclient(1) manual page', url: 'https://www.samba.org/samba/docs/current/man-html/smbclient.1.html' },
    { title: 'Microsoft Learn: SMB overview (Windows Server)', url: 'https://learn.microsoft.com/windows-server/storage/file-server/file-server-smb-overview' },
    { title: 'Microsoft Learn: net use', url: 'https://learn.microsoft.com/windows-server/administration/windows-commands/net-use' },
    { title: 'Red Hat: Using Samba as a server (RHEL 9)', url: 'https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_and_using_network_file_services/assembly_using-samba-as-a-server_configuring-and-using-network-file-services' },
  ],
  guide: SMB_GUIDE,
  objectives: ['N10-009:1.4', 'N10-009:5.3'],
};

// --- Primer -------------------------------------------------------------------------

export const SMB_PRIMER: Primer = {
  oneLiner: 'A file server offers **shares** (\\\\fs01\\office); a client connects on TCP 445, **logs on** with a user name and password, opens the share, and then reads and writes files there as that user. **Samba** is the SMB server for Linux.',
  analogy: `
A company archive with a reception desk. At the door (port 445) you show your badge: the desk checks it against **its own visitor list**, not the HR database (that is why a new employee who was never added to the desk's list is turned away, with the same message as a forged badge).

Then you ask for a room (the share): the room has a list of departments allowed in, and some rooms are "reading only" unless a sign says otherwise. Inside, each drawer still has its own lock (Unix permissions): the room rules can only restrict, never open a locked drawer.`,
  ideas: [
    {
      title: 'Four steps: connect, log on, open the share, use files',
      explain: 'Each step fails with its own error, so the message tells you where to look.',
      example: '`smbclient -L fs01 -U alice` tests connect and logon; `smbclient //fs01/office -U alice -c ls` adds the share; `-c "put /etc/hostname t.txt"` tests writing.',
    },
    {
      title: 'Samba has its own users',
      explain: 'A Unix account is not enough: `smbpasswd -a` gives it a Samba password. `pdbedit -L` lists who can log on.',
      example: 'carol exists on fs01 (id carol) but not in pdbedit -L: every logon fails with NT_STATUS_LOGON_FAILURE.',
    },
    {
      title: 'Shares decide who and whether to write',
      explain: '`valid users = @staff` limits who may open the share; shares are read-only unless `read only = no`.',
      example: '[office] has valid users = @staff and read only = no; [software] is read-only.',
    },
    {
      title: 'Then the Unix permissions apply',
      explain: 'smbd works as the user\'s Unix account on the server: the directory\'s owner, group and mode must also allow it.',
      example: '/srv/office is root:staff 0770: dana writes there because she is in staff.',
    },
  ],
  walkthrough: {
    title: 'dana maps \\\\fs01\\office on win01',
    steps: [
      { label: 'Connect', detail: '`net use O: \\\\fs01\\office /user:dana` connects to fs01 on TCP 445.' },
      { label: 'Log on', detail: 'Samba checks dana\'s password against its database (smbpasswd) and maps her to the Unix user dana.' },
      { label: 'Open the share', detail: '[office] allows @staff; `id dana` on fs01 lists staff, so the tree connect succeeds.' },
      { label: 'Use files', detail: 'She saves a file: smbd creates it as dana, group staff (force group), mode 0660 (create mask).' },
      { label: 'Visible on the server', detail: '`smbstatus` on fs01 shows her session; `ls -l /srv/office` shows the file.' },
    ],
  },
  misconceptions: [
    { myth: 'A Linux user can log on to Samba with the Linux password.', truth: 'A standalone Samba server has its own password database: smbpasswd -a.' },
    { myth: 'If the share is writable, everyone in it can write.', truth: 'The Unix permissions of the directory must allow the user too.' },
    { myth: 'A new share is writable unless restricted.', truth: 'Samba shares are read-only by default.' },
    { myth: '"Access is denied" means a wrong password.', truth: 'A wrong password is error 1326; 5 means logged on, but the share refused.' },
  ],
  checks: [
    { q: 'Which TCP port does SMB use?', a: '445' },
    { q: 'A user exists on the Samba server but every SMB logon fails. What do you check first?', a: 'pdbedit -L: whether the user has a Samba password (smbpasswd -a).' },
    { q: 'What is a share\'s default for read only?', a: 'yes: shares are read-only unless they say read only = no.' },
    { q: 'Windows says System error 67. Which step failed?', a: 'The tree connect: the share or its path does not exist.' },
  ],
};

// --- Assessment -------------------------------------------------------------------------

export const SMB_ASSESSMENT: Assessment = {
  id: 'smb',
  title: 'SMB and Samba knowledge check',
  questions: [
    {
      id: 'smb-q-steps',
      kind: 'order',
      level: 'beginner',
      prompt: 'Order the steps of an SMB connection.',
      items: ['TCP connection to port 445', 'Negotiate the SMB dialect', 'Session setup (log on)', 'Tree connect (open the share)', 'Create / read / write files'],
      concepts: ['files.smb'],
      explanation: 'Connect → negotiate → authenticate → share → file operations; each step has its own errors.',
    },
    {
      id: 'smb-q-passdb',
      kind: 'single',
      level: 'beginner',
      prompt: 'carol was created on the Samba server with useradd and passwd. Her SMB logons fail; the server log says NT_STATUS_NO_SUCH_USER. What is missing?',
      options: [
        { text: 'smbpasswd -a carol', correct: true },
        { text: 'Adding carol to valid users', misconception: 'valid users is checked at the tree connect, after a successful logon.' },
        { text: 'read only = no', misconception: 'That concerns writes after the share is open.' },
        { text: 'Restarting smbd', misconception: 'The user database is read at each logon; it lacks carol.' },
      ],
      concepts: ['files.smb'],
      explanation: 'A standalone Samba server checks passwords against its own database; Unix passwords are not used.',
    },
    {
      id: 'smb-q-errors',
      kind: 'single',
      level: 'intermediate',
      prompt: 'net use O: \\\\fs01\\office /user:dana gives "System error 5: Access is denied." What does that tell you?',
      options: [
        { text: 'The logon worked; the share refused dana (valid users, group membership)', correct: true },
        { text: 'The password is wrong', misconception: 'A wrong password gives error 1326.' },
        { text: 'Port 445 is blocked', misconception: 'That gives error 53 (network path not found).' },
        { text: 'The share does not exist', misconception: 'That gives error 67.' },
      ],
      concepts: ['files.smb'],
      explanation: 'Error 5 comes after session setup: the share (or its directory) refuses this user.',
    },
    {
      id: 'smb-q-readonly',
      kind: 'single',
      level: 'intermediate',
      prompt: 'A new share has path = /srv/scans and valid users = scanner. /srv/scans is owned by scanner with mode 750. The scanner can list but not upload. Why?',
      options: [
        { text: 'The share is read-only: Samba\'s default is read only = yes', correct: true },
        { text: 'The Unix permissions deny scanner', misconception: 'scanner owns the directory with rwx.' },
        { text: 'scanner has no Samba password', misconception: 'Then it could not list either.' },
      ],
      concepts: ['files.smb'],
      explanation: 'Writes need both the share (read only = no) and the file system to allow them.',
    },
    {
      id: 'smb-q-port',
      kind: 'text',
      level: 'beginner',
      prompt: 'Which TCP port must a firewall allow for SMB2/SMB3?',
      accept: ['445'],
      placeholder: 'port',
      concepts: ['files.smb'],
      explanation: 'Direct SMB hosting uses TCP 445 (139 only for NetBIOS-era clients).',
    },
    {
      id: 'smb-q-secure',
      kind: 'multi',
      level: 'advanced',
      prompt: 'Which settings make a Samba file server safer? (choose all that apply)',
      options: [
        { text: 'valid users = @group on each share', correct: true },
        { text: 'server min protocol = SMB2_10 (no SMB1)', correct: true },
        { text: 'Allowing TCP 445 only from the internal client networks', correct: true },
        { text: 'map to guest = bad user', misconception: 'That turns unknown users into guests instead of refusing them.' },
      ],
      concepts: ['files.smb'],
      explanation: 'Limit who can connect (firewall, valid users), keep old protocols off, and never fall back to guest.',
    },
  ],
};
