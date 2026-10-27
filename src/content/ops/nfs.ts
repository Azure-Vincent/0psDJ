// File sharing with NFS. Examples follow the lab: fs01 (10.0.20.60) exports
// /srv/projects (rw, office and servers) and /srv/software (ro, every internal
// network); ws01 and srv01 mount them from /etc/fstab. The sandbox and the
// tickets run there. SMB/Samba, RHEL and Windows (Client for NFS) are noted.

import type { Assessment, Lesson, Primer, ServiceGuide } from '../types';

// --- Operate & recover guide ---------------------------------------------------------

export const NFS_GUIDE: ServiceGuide = {
  purpose:
    'NFS (Network File System) lets a Linux/Unix server share directories that clients mount into their own file tree: /mnt/projects on ws01 *is* /srv/projects on fs01. Programs use it like a local disk, so shared project data, home directories, installers and backup targets live in one place. The server decides who may mount what (/etc/exports) and checks every file access with the client\'s **numeric** UID and GID.',
  architecture: [
    { q: 'What does it accomplish?', a: 'One copy of the data on a file server, used by many clients as an ordinary directory, with Unix permissions enforced by the server.' },
    { q: 'How does it work internally?', a: 'The server\'s kernel (nfsd) serves the directories listed in its **export table**, loaded from /etc/exports at start or by `exportfs -ra`. A client mounts an export; afterwards every open, read, write and stat on that directory is an RPC to the server, which checks the export options (ro/rw, squashing) and then normal file permissions for the UID/GID the client sent.' },
    { q: 'Which protocols does it use?', a: 'NFS over ONC RPC. NFSv4 (4.0, 4.1, 4.2: current default) uses a single TCP connection to port 2049 and has locking built in. NFSv3 also needs rpcbind (111), mountd (20048 on Debian/RHEL when pinned), and lockd/statd on varying ports.' },
    { q: 'Which ports and transport?', a: 'TCP 2049 (nfsd) for v4. For v3 and showmount: TCP/UDP 111 (rpcbind) and mountd (pin it to 20048 so a firewall can allow it).' },
    { q: 'Which processes and OS components implement it?', a: 'Server: the kernel nfsd threads, `rpc.mountd`, `rpcbind`, `exportfs` (nfs-kernel-server.service, nfs-server.service). Client: the kernel NFS client, `mount.nfs4` (nfs-common / nfs-utils), and systemd .mount units generated from /etc/fstab.' },
    { q: 'Which other services does it depend on?', a: 'DNS (the server name in fstab, and host names in /etc/exports are resolved by the server), the network path and the server\'s firewall, **consistent UIDs/GIDs** on all hosts (or Kerberos with an ID mapping service), and for sec=krb5 a KDC and keytabs.' },
    { q: 'How do requests travel?', a: 'alice on ws01 runs `echo x > /mnt/projects/notes.txt` → the client kernel sends CREATE/WRITE over TCP to fs01:2049 with credentials uid=1000,gid=1000 → nfsd finds the export for /srv/projects, checks that 10.0.10.50 is in its client list with rw → checks /srv/projects allows uid 1000 to write → writes the file owned by uid 1000.' },
    { q: 'How do authentication and authorisation work?', a: 'Default **sec=sys** (AUTH_SYS): the client simply states the UID and GID; the server trusts it. The client list (by address or name) is the only real access control, and **root_squash** maps the client\'s root (uid 0) to nobody (65534) so a client\'s root is not root on the server. sec=krb5/krb5i/krb5p authenticates users with Kerberos tickets (and adds integrity/encryption).' },
    { q: 'How does it start at boot?', a: 'Server: nfs-server.service loads /etc/exports and starts nfsd. Client: systemd-fstab-generator turns each nfs line of /etc/fstab into a .mount unit (mnt-projects.mount) under remote-fs.target; `_netdev` waits for the network. A failed mount does not stop the boot when the entry has nofail (or is not needed for local-fs).' },
    { q: 'What happens if it terminates unexpectedly?', a: 'Clients with **hard** mounts (the default) block: processes touching the mount hang in state D until the server returns, then continue without data loss. **soft** mounts return I/O errors after retries (risking corrupted writes). If the server stops exporting a directory, clients get "Stale file handle".' },
  ],
  ports: [
    { port: '2049', proto: 'TCP', purpose: 'nfsd: all NFSv4 traffic (and NFSv3 data)' },
    { port: '111', proto: 'TCP/UDP', purpose: 'rpcbind (portmapper): NFSv3 and showmount find mountd through it' },
    { port: '20048', proto: 'TCP/UDP', purpose: 'rpc.mountd when pinned (NFSv3 mounts, showmount -e)' },
    { port: '445', proto: 'TCP', purpose: 'SMB (Samba / Windows file sharing), the alternative for Windows clients' },
  ],
  processes: [
    { name: 'nfsd (kernel threads)', platform: 'Linux server (nfs-kernel-server / nfs-server.service)', role: 'Serves file operations for exported directories' },
    { name: 'rpc.mountd, rpcbind', platform: 'Linux server', role: 'Answer mount requests and export lists for NFSv3 and showmount' },
    { name: 'exportfs', platform: 'Linux server', role: 'Loads /etc/exports into the kernel\'s export table, lists it' },
    { name: 'mount.nfs4 + kernel NFS client', platform: 'Linux client (nfs-common / nfs-utils)', role: 'Mounts exports; every file access on the mount becomes an RPC' },
    { name: 'smbd (Samba) / LanmanServer', platform: 'Linux / Windows', role: 'SMB file sharing, the usual choice for Windows clients' },
  ],
  dependencies: {
    title: 'What "alice on ws01 saves a file in /mnt/projects" depends on (top needs everything below it)',
    caption: 'The mount needs the path and the export list; every write needs matching UIDs and permissions.',
    rows: [
      { label: 'Client', nodes: [{ id: 'app', label: 'alice\'s program', sub: 'uid 1000 on ws01', kind: 'service' }, { id: 'mnt', label: 'mnt-projects.mount', sub: '/etc/fstab, nfs4', kind: 'os' }] },
      { label: 'Path', nodes: [{ id: 'dns', label: 'DNS', sub: 'fs01.corp.lab', kind: 'network' }, { id: 'fw', label: 'fs01 firewall', sub: 'tcp dport 2049', kind: 'network' }] },
      { label: 'Server', nodes: [{ id: 'nfsd', label: 'nfsd on fs01', sub: 'nfs-server.service', kind: 'service' }, { id: 'tab', label: 'Export table', sub: 'exportfs -ra', kind: 'data' }] },
      { label: 'Files', nodes: [{ id: 'ids', label: 'UID mapping', sub: '1000 = alice on both', kind: 'data' }, { id: 'perm', label: 'Permissions', sub: '/srv/projects 775 alice', kind: 'os' }] },
    ],
    edges: [['app', 'mnt'], ['mnt', 'dns'], ['mnt', 'fw'], ['fw', 'nfsd'], ['nfsd', 'tab'], ['tab', 'ids'], ['ids', 'perm']],
  },
  sequence: {
    title: 'ws01 mounts /srv/projects and alice writes a file',
    caption: 'NFS 4.2 over TCP, sec=sys. Where each ticket breaks the exchange is noted.',
    lanes: [{ id: 'c', label: 'ws01', sub: 'kernel NFS client' }, { id: 's', label: 'fs01', sub: 'nfsd' }],
    steps: [
      { from: 'c', to: 's', label: 'TCP SYN to 10.0.20.60:2049', note: 'Dropped by fs01\'s firewall → "mount.nfs4: Connection timed out" (two minutes at boot).' },
      { from: 's', to: 'c', label: 'SYN-ACK' },
      { from: 'c', to: 's', label: 'PUTROOTFH / LOOKUP srv/projects', note: 'Client not in the loaded export table → "access denied by server" (even if /etc/exports lists it but exportfs -ra was not run).' },
      { from: 's', to: 'c', label: 'file handle for /srv/projects' },
      { from: 'c', to: 's', label: 'OPEN notes.txt (CREATE), AUTH_SYS uid=1000 gid=1000', note: 'uid 0 is squashed to 65534 (root_squash); a different uid for alice on this client fails the permission check → "Permission denied".' },
      { from: 's', to: 'c', label: 'OK, file owned by 1000' },
    ],
  },
  files: [
    { path: '/etc/exports, /etc/exports.d/*.exports', platform: 'NFS server', kind: 'config', perms: 'root:root 0644', contains: 'Exported directories, their clients and options (rw/ro, root_squash, sec=...).', accessed: 'At server start and by exportfs -ra.', problems: 'Edits do nothing until exportfs -ra. A space before "(" exports to everyone.' },
    { path: '/etc/fstab', platform: 'NFS client', kind: 'startup', perms: 'root:root 0644', contains: 'SERVER:/PATH MOUNTPOINT nfs4 OPTIONS 0 0 lines, mounted at boot as .mount units.', accessed: 'At boot (systemd-fstab-generator), mount -a.', problems: 'Without _netdev/nofail an unreachable server can delay or block the boot.' },
    { path: '/etc/passwd, /etc/group', platform: 'Client and server', kind: 'auth', perms: 'root:root 0644', contains: 'User and group names ↔ numbers. NFS (sec=sys) only transmits the numbers.', accessed: 'Every ls -l (number → name) and login.', problems: 'The same name with different UIDs on two hosts means two different users on the share.' },
    { path: 'journal: journalctl -u mnt-projects.mount, journalctl -u nfs-server', platform: 'Client / server', kind: 'log', contains: 'Mount failures at boot ("mount.nfs4: Connection timed out", "Failed to mount ..."), export errors on the server.', accessed: 'Continuously.', problems: 'A failed boot-time mount leaves an empty directory that looks like an empty share.' },
  ],
  management: [
    {
      platform: 'Debian / Ubuntu (client)',
      tasks: [
        { task: 'What is mounted?', command: 'mount -t nfs4\ndf -h', explain: 'Source, mount point and options; df shows the server\'s size and usage. No line → the directory is just local.', sim: true },
        { task: 'Mount everything from fstab', command: 'mount -a', explain: 'Tests /etc/fstab without a reboot; errors show the reason.', sim: true },
        { task: 'What does the server export?', command: 'showmount -e fs01', explain: 'The server\'s export table and client lists (needs rpcbind/mountd reachable).', sim: true },
        { task: 'Which number am I?', command: 'id\nls -ln /mnt/projects', explain: 'Compare your uid with the numeric owners on the share (and with id USER on the server).', sim: true },
        { task: 'Boot-time mount errors', command: 'journalctl -b -u mnt-projects.mount', explain: 'Why the mount failed at boot.', sim: true },
      ],
    },
    {
      platform: 'Debian / Ubuntu (server)',
      tasks: [
        { task: 'Export table in use', command: 'exportfs -v', explain: 'Exports, clients and every option, as the kernel uses them.', sim: true },
        { task: 'Apply /etc/exports', command: 'exportfs -ra', explain: 'Re-reads the file; check with exportfs -v.', sim: true },
        { task: 'Is it running and listening?', command: 'systemctl status nfs-server\nss -tlnp', explain: 'nfsd on 2049, rpcbind on 111, mountd on 20048.', sim: true },
        { task: 'Firewall', command: 'nft list ruleset', explain: 'The input chain needs TCP 2049 (and 111/20048 for v3 and showmount) from the client networks.', sim: true },
        { task: 'Ownership as numbers', command: 'ls -ln /srv/projects\nid alice', explain: 'What the clients\' UIDs must match.', sim: true },
      ],
    },
    {
      platform: 'RHEL 9',
      tasks: [
        { task: 'Server', command: 'dnf install nfs-utils\nsystemctl enable --now nfs-server\nfirewall-cmd --permanent --add-service={nfs,rpc-bind,mountd} && firewall-cmd --reload', explain: 'Same /etc/exports and exportfs; firewalld service names; SELinux booleans (nfs_export_all_rw) for non-default paths.' },
      ],
    },
    {
      platform: 'Windows',
      tasks: [
        { task: 'SMB instead of NFS', command: 'New-SmbShare -Name Projects -Path D:\\Projects -ChangeAccess "CORP\\Staff"\nGet-SmbShare', explain: 'Windows clients use SMB (port 445) with domain authentication; "Client for NFS" (mount.exe) and "Server for NFS" exist but are rare.' },
      ],
    },
  ],
  actions: [
    { action: 'exportfs -ra', when: 'After every change to /etc/exports.', effect: 'The kernel serves the new table immediately.', risk: 'Clients removed from the list get errors on their existing mounts.' },
    { action: 'mount -a / umount DIR', when: 'Testing fstab; detaching a share for maintenance.', effect: 'Mounts what fstab lists / detaches.', risk: 'umount fails while anything (your shell\'s cwd too) uses the mount.' },
    { action: 'usermod -u UID USER', when: 'Aligning a user\'s UID with the file server.', effect: 'The account gets the new number; files on local disks must be re-owned (find / -uid OLD).', risk: 'Processes of that user should be stopped first; another user may already have the number.' },
  ],
  workflow: [
    { question: 'Is the share mounted at all?', why: 'Nothing else matters if the share is not mounted, and the mount error already points to the network, the server, or the export.', command: 'mount -t nfs4\ndf -h /mnt/projects', healthy: 'fs01.corp.lab:/srv/projects on /mnt/projects type nfs4 (rw,...)', broken: 'No line: you are looking at the local directory. mount -a shows why: timed out (path/firewall), refused (nfsd down), access denied by server (export list).', next: 'If mounted, check what the server thinks of you.', sim: true },
    { question: 'Does the server export it to this client?', why: 'The server only lets in the clients listed in its loaded export table, which may differ from /etc/exports until exportfs -ra runs.', command: 'showmount -e fs01\nexportfs -v   # on fs01', healthy: '/srv/projects  10.0.10.0/24,10.0.20.0/24', broken: 'The client\'s network is missing: add it to /etc/exports and run exportfs -ra (or it is in the file but not loaded).', next: 'Then the identity used for each access.', sim: true },
    { question: 'Who am I on the server?', why: 'The server checks permissions against user numbers. A different UID on the client, or root being squashed to nobody, changes who you are on the server.', command: 'id\nls -ln /mnt/projects', healthy: 'uid=1000(alice) and files owned by 1000', broken: 'root: squashed to nobody (65534). A different number than the owner on the server: a UID mismatch.', next: 'Then the permissions for that identity.', sim: true },
    { question: 'Do the permissions allow it, and is it read-only?', why: 'Even with the right identity, normal file permissions and read-only exports still apply.', command: 'ls -ld /srv/projects   # on fs01\nmount -t nfs4', healthy: 'drwxrwxr-x 2 alice alice ... /srv/projects', broken: '"Read-only file system": the export or the mount is ro. "Permission denied": the mode bits for the (mapped) uid.', next: 'Fix on the server, test the write from the client.', sim: true },
  ],
  failures: [
    { symptom: 'mount.nfs4: access denied by server while mounting', causes: ['Client not in the export\'s client list', 'Listed in /etc/exports but exportfs -ra not run', 'Listed by a host name that resolves to another address on the server'], diagnose: ['exportfs -v on the server vs cat /etc/exports', 'showmount -e SERVER on the client'], fix: 'Add the client network to the export and run exportfs -ra.', verify: 'mount -a succeeds; exportfs -v lists the client.' },
    { symptom: 'Mount hangs and fails with "Connection timed out"; showmount says "RPC: Timed out"', causes: ['Server firewall drops 2049/111', 'Routing between client and server', 'Server down'], diagnose: ['ss -tlnp and nft list ruleset on the server', 'tcpdump -n port 2049 on the server'], fix: 'Allow TCP 2049 (and 111, 20048) from the client networks.', verify: 'mount -a on the client.' },
    { symptom: 'root on a client gets "Permission denied" on a rw share', causes: ['root_squash: client root is nobody on the server'], diagnose: ['exportfs -v (root_squash)', 'ls -ld of the target directory on the server'], fix: 'Give nobody (or an anonuid account with all_squash) a directory to write in; avoid no_root_squash.', verify: 'The root job writes; its files belong to nobody on the server.' },
    { symptom: 'A user can read but not write; ls -l shows numbers as owners', causes: ['The user has a different UID on this client than on the server'], diagnose: ['id USER on client and server', 'ls -ln on both sides'], fix: 'Align UIDs (usermod -u on the odd host, or central identities via LDAP/sssd).', verify: 'ls -l shows the user as owner; writes succeed.' },
  ],
  verification: [
    { check: 'Exports loaded', command: 'exportfs -v', expect: 'Every export and client from /etc/exports' },
    { check: 'Mounted on the client', command: 'mount -t nfs4', expect: 'SERVER:/PATH on /MOUNTPOINT type nfs4 (rw,...)' },
    { check: 'Write test as the real user', command: 'touch /mnt/projects/test && ls -l /mnt/projects/test', expect: 'Owned by that user (not a number, not nobody)' },
    { check: 'Survives a reboot', command: 'mount -a after editing fstab; systemctl list-units -t mount', expect: 'mnt-projects.mount active' },
  ],
  refIds: ['mount', 'exportfs', 'showmount', 'file:exports', 'file:fstab', 'nft', 'ss'],
};

// --- Lesson -------------------------------------------------------------------------

export const NFS_LESSON: Lesson = {
  id: 'nfs',
  moduleId: 'F',
  title: 'File sharing (NFS)',
  level: 'intermediate',
  summary: 'How an NFS server exports directories, how clients mount them from /etc/fstab, why user IDs must match across hosts, what root_squash does, and how to tell a firewall, an export list and a permission problem apart.',
  concepts: ['files.nfs', 'linux.permissions', 'fw.path'],

  what: `
**NFS** (Network File System) shares directories from a **file server** so that other machines can **mount** them: the shared directory appears inside the client's own file tree (for example as /mnt/projects), and programs use it like a local disk.

NFS combines two things you have met before: a network service on TCP port 2049 (so routes and firewalls matter, see [Transport and DNS](#/lesson/transport/what)), and ordinary Linux file permissions based on user and group **numbers** (UID and GID). Most NFS surprises come from the second part.

### Problems it solves
- **One copy of the data.** Project files, home directories, installers and backups live on one server instead of being copied around.
- **Transparent access.** Any program can use /mnt/projects; nothing needs to know it is remote.
- **Central protection.** The file server is backed up, snapshotted and secured once.

### The pieces
- **Exports** on the server: /etc/exports lists each shared directory, the clients allowed to mount it, and options (read-write or read-only, how root is treated). The kernel uses the **export table** loaded from it by \`exportfs -ra\`.
- **Mounts** on the clients: \`mount -t nfs4 SERVER:/PATH DIR\`, or a line in /etc/fstab mounted at boot.
- **Identities**: with the default security (sec=sys) the client sends **numbers** (UID, GID), and the server checks normal Unix permissions against them.
- **Transport**: NFSv4 over TCP port 2049 (NFSv3 also needs rpcbind 111 and mountd).

> In the lab, **fs01** (10.0.20.60) is the file server: it exports /srv/projects read-write to the office (10.0.10.0/24) and server (10.0.20.0/24) networks and /srv/software read-only to 10.0.0.0/16. **ws01** mounts the project share on /mnt/projects and **srv01** the software share on /opt/software, both from /etc/fstab. Simulated: /etc/exports (client lists by network, address, name and wildcard; rw/ro, root_squash, no_root_squash, all_squash, anonuid/anongid), the export table and \`exportfs -v/-ra\`, \`showmount -e\`, \`mount\`/\`umount\`/\`mount -a\`/\`df\`, fstab mounts at boot with systemd's messages, TCP 2049/111 through routers and firewalls, numeric UID/GID mapping, root squashing, read-only exports and stale handles. Simplified: the mount is a synchronized view refreshed before and after each command (no partial I/O, locking or caching effects), NFSv4.2 only, sec=sys only, no Samba yet.
`,

  internals: `
### 1. Exports: who may mount what
Each line of /etc/exports is a directory followed by clients, each with its options:
\`\`\`
/srv/projects  10.0.10.0/24(rw,sync,no_subtree_check) 10.0.20.0/24(rw,sync,no_subtree_check)
/srv/software  10.0.0.0/16(ro,sync,no_subtree_check)
\`\`\`
A client is a network, an address, a host name (resolved by the server), a wildcard (\`*.corp.lab\`) or \`*\` (everyone). **No space** between client and options: \`host (rw)\` means "host with default options, and everyone else read-write".

The kernel does not read this file on its own. \`exportfs -ra\` (or starting/reloading nfs-server) loads it into the **export table**; \`exportfs -v\` shows that table. A client that is in the file but not in the table is refused: "access denied by server".

### 2. Mounting
\`mount -t nfs4 fs01.corp.lab:/srv/projects /mnt/projects\` connects to TCP 2049, asks for the export, and attaches it on the directory. From then on the server's files appear there; what was in the directory before is hidden until \`umount\`. In /etc/fstab:
\`\`\`
fs01.corp.lab:/srv/projects  /mnt/projects  nfs4  defaults,_netdev  0  0
\`\`\`
systemd turns the line into **mnt-projects.mount** at boot. If the mount fails, the directory stays empty and local: programs that write there fill the client's own disk.

### 3. Numbers, not names (sec=sys)
The client sends the caller's **UID and GID** with each request; the server compares them with the file's owner and group numbers. Names are only for display: \`ls -l\` on each host translates numbers with its own /etc/passwd. If alice is 1000 on fs01 and 1001 on srv01, srv01's alice is a stranger on the share and sees alice's files as owned by "1000". Keep UIDs identical everywhere (central directory: LDAP/FreeIPA/AD with sssd), or use Kerberos (sec=krb5), which identifies users by principal.

### 4. root_squash and friends
The server cannot trust a client's root: anyone with root on a laptop could claim uid 0. **root_squash** (the default) maps uid 0 to **nobody** (65534). Root on a client can then only do what nobody may: on a root-owned directory with mode 755, nothing. Options:
| Option | Effect |
|---|---|
| \`root_squash\` (default) | uid 0 → anonuid (65534, nobody) |
| \`no_root_squash\` | client root is root on the export: avoid, a compromised client owns the share |
| \`all_squash\` + \`anonuid=N,anongid=N\` | every user becomes N: shared drop boxes, service accounts |
| \`ro\` / \`rw\` | read-only (default) / read-write |

### 5. What failures look like
| Symptom | Layer |
|---|---|
| "Connection timed out" (mount), "RPC: Timed out" (showmount) | path / server firewall |
| "Connection refused" | nfsd not running |
| "access denied by server while mounting" | export table (client list) |
| "Permission denied" on a mounted share | identity (squash, UID) and mode bits |
| "Read-only file system" | ro export or ro mount |
| "Stale file handle" | the server stopped exporting what the client still has mounted |

### 6. Security
sec=sys trusts the client completely about who the user is: anyone with root on a listed client can become any UID. The export's client list and the network (firewall) are therefore the real access control: export to specific networks, never to \`*\`, keep root squashed, firewall 2049/111 to the client networks, and use sec=krb5p where clients are not trusted.
`,

  deployment: [
    {
      id: 'debian',
      platform: 'Debian 12 / Ubuntu (server and clients)',
      summary: 'Share /srv/projects from fs01 and mount it on the clients at boot. Steps marked simulated can be tried in the sandbox (fs01 and the clients already run this setup).',
      prerequisites: ['A server with the data on a local filesystem, and DNS name fs01.corp.lab.', 'The same UIDs/GIDs for the users on every host.'],
      steps: [
        { title: 'Install the server', command: 'sudo apt install -y nfs-kernel-server\nsystemctl status nfs-server', what: 'nfsd, mountd, rpcbind and exportfs.', why: 'The client tools (nfs-common) are installed with it.', expected: 'Active: active (exited)' },
        { title: 'Export the directory', command: '/srv/projects  10.0.10.0/24(rw,sync,no_subtree_check) 10.0.20.0/24(rw,sync,no_subtree_check)', what: 'In /etc/exports on fs01.', why: 'Only the networks that need the share; root stays squashed.', expected: '' },
        { title: 'Load and check the export table', command: 'exportfs -ra\nexportfs -v', what: 'Apply /etc/exports and see what the kernel serves.', why: 'Editing the file alone changes nothing.', expected: '/srv/projects \t10.0.10.0/24(sync,wdelay,hide,no_subtree_check,sec=sys,rw,secure,root_squash,no_all_squash)', simulated: true },
        { title: 'Firewall', command: 'nft list ruleset', what: 'The input chain needs "ip saddr 10.0.0.0/16 tcp dport { 111, 2049, 20048 } accept".', why: 'NFSv4 needs 2049; 111/20048 for showmount and NFSv3.', expected: 'ip saddr 10.0.0.0/16 tcp dport { 111, 2049, 20048 } accept', simulated: true },
        { title: 'Client: install and mount from fstab', command: 'sudo apt install -y nfs-common\necho "fs01.corp.lab:/srv/projects /mnt/projects nfs4 defaults,_netdev 0 0" | sudo tee -a /etc/fstab\nsudo mkdir -p /mnt/projects && sudo mount -a', what: 'On ws01.', why: 'mount -a tests the fstab line now instead of at the next boot.', expected: '' },
        { title: 'Test as the real user', command: 'mount -t nfs4\ntouch /mnt/projects/test && ls -l /mnt/projects/test', what: 'As alice on ws01.', why: 'Proves the export, the path, the UID mapping and the permissions together.', expected: '-rw-r--r-- 1 alice alice 0 Oct 19 08:40 /mnt/projects/test', simulated: true },
      ],
    },
    {
      id: 'rhel',
      platform: 'RHEL 9',
      summary: 'Same exports and fstab syntax; nfs-utils package; firewalld services nfs, rpc-bind and mountd; SELinux allows exporting most paths read-only by default (setsebool -P nfs_export_all_rw on for rw outside standard locations).',
      prerequisites: ['nfs-utils on server and clients.'],
      steps: [
        { title: 'Server', command: 'sudo dnf install -y nfs-utils\nsudo systemctl enable --now nfs-server\nsudo firewall-cmd --permanent --add-service={nfs,rpc-bind,mountd} && sudo firewall-cmd --reload', what: 'Install, start, open the firewall.', why: 'firewalld\'s "nfs" service is TCP 2049.', expected: 'success' },
      ],
    },
    {
      id: 'windows',
      platform: 'Windows (SMB)',
      summary: 'Windows clients normally use SMB rather than NFS: a share on a Windows server (New-SmbShare) or on Linux with Samba, authenticated with domain accounts over TCP 445. Windows also offers "Client for NFS" (mount.exe) and "Server for NFS" roles, mainly for mixed environments.',
      prerequisites: ['A domain or local accounts for access control.'],
      steps: [
        { title: 'Create an SMB share', command: 'New-SmbShare -Name Projects -Path D:\\Projects -ChangeAccess "CORP\\Staff"', what: 'Shares a folder with share and NTFS permissions.', why: 'SMB authenticates each user (Kerberos/NTLM) instead of trusting client UIDs.', expected: '' },
      ],
    },
  ],

  configIntro: `
Configuration lives at both ends:
- **On the server**: /etc/exports (what, to whom, how), loaded with \`exportfs -ra\`; the ownership and modes of the exported directories; the firewall.
- **On each client**: the /etc/fstab line (server, export path, mount point, options) and the users' UIDs/GIDs.
`,

  configFiles: [
    { platform: 'Debian / Ubuntu / RHEL', items: [
      { path: '/etc/exports, /etc/exports.d/', purpose: 'Server: exports, clients and options.' },
      { path: '/etc/fstab', purpose: 'Client: NFS mounts at boot (type nfs4, _netdev).' },
      { path: '/etc/nfs.conf', purpose: 'Server and client daemon settings (versions, mountd port, threads).' },
      { path: '/etc/passwd, /etc/group (or LDAP/sssd)', purpose: 'Name ↔ number mappings that must agree across hosts.' },
    ] },
    { platform: 'Windows', items: [
      { path: 'Get-SmbShare / Server Manager > File and Storage Services', purpose: 'SMB shares (the usual Windows equivalent).' },
    ] },
  ],

  directives: [
    { name: 'CLIENT(rw|ro)', compiledDefault: 'ro', recommended: 'rw only where clients must write', explanation: 'Read-write or read-only for that client.', security: 'Software repositories and reference data should be ro.' },
    { name: 'root_squash / no_root_squash', compiledDefault: 'root_squash', recommended: 'root_squash', explanation: 'Maps the client\'s uid 0 to anonuid (nobody).', security: 'no_root_squash lets any client root change any file on the export.' },
    { name: 'all_squash, anonuid=N, anongid=N', compiledDefault: 'no_all_squash, 65534', recommended: 'For drop boxes and service shares', explanation: 'Map every client user to one account.', security: 'Everyone shares one identity: no per-user accountability.' },
    { name: 'client specification', compiledDefault: '(required)', recommended: 'Networks or hosts that need it', explanation: 'Who may mount: 10.0.10.0/24, host, *.domain, *.', security: '"*" exports to anyone who can reach port 2049.' },
    { name: 'sec=sys|krb5|krb5i|krb5p', compiledDefault: 'sys', recommended: 'krb5p across untrusted networks', explanation: 'How users are identified: trusted numbers or Kerberos tickets (with integrity/encryption).', security: 'sec=sys trusts the client\'s claim of who the user is.' },
    { name: 'fstab: _netdev, nofail, hard/soft', compiledDefault: 'hard', recommended: 'defaults,_netdev (nofail for non-essential mounts)', explanation: 'Wait for the network; do not block boot; how I/O behaves when the server is gone.', security: 'soft mounts can silently corrupt writes.' },
  ],

  operateIntro: `
### Before you change a share
- After editing /etc/exports: \`exportfs -ra\`, then \`exportfs -v\`. Removing a client breaks its existing mounts.
- After editing /etc/fstab: \`mount -a\` now, not at the next reboot.
- Before adding a client or user: compare \`id USER\` on the client and the server.

`,
  troubleshootingIntro: `
### Mounted? Allowed? Who am I? May I?
NFS access passes four gates in order. Each question below matches one gate, and each fails with a different message.

1. **Is it mounted?** \`mount -t nfs4\` and \`df -h\` show active NFS mounts. If the share is not mounted, run \`mount -a\` and read the error: timed out (the network or a firewall), refused (nothing listens on port 2049) or access denied (the server does not export it to you).
2. **Is this client allowed?** On the server, \`exportfs -v\` (or \`showmount -e SERVER\` from the client) shows the export table that is actually loaded. Is the client's address covered? Remember that editing /etc/exports changes nothing until \`exportfs -ra\` loads it.
3. **Who am I on the server?** NFS sends user and group **numbers**, not names. Compare \`id\` on the client with \`ls -ln\` (numeric owners). root on the client is turned into "nobody" on the server (**root_squash**), and every other user must have the same number on both machines.
4. **May I?** Check \`ls -ld\` of the directory on the server for that number. "Read-only file system" means the export or the mount is read-only (ro).
`,

  errorMap: [
    { message: 'mount.nfs4: Connection timed out', layer: 'Path / server firewall', meaning: 'No answer from SERVER:2049.', firstCheck: 'nft list ruleset and ss -tlnp on the server' },
    { message: 'mount.nfs4: Connection refused', layer: 'Server', meaning: 'Nothing listens on 2049.', firstCheck: 'systemctl status nfs-server' },
    { message: 'mount.nfs4: access denied by server while mounting fs01.corp.lab:/srv/projects', layer: 'Export table', meaning: 'This client is not allowed for that export (in the loaded table).', firstCheck: 'exportfs -v vs /etc/exports on the server' },
    { message: 'mount.nfs4: mounting fs01.corp.lab:/srv/x failed, reason given by server: No such file or directory', layer: 'Export table', meaning: 'No export with that path.', firstCheck: 'showmount -e fs01' },
    { message: "touch: cannot touch '/mnt/projects/x': Permission denied", layer: 'Identity / permissions', meaning: 'The (mapped) UID may not write there: root squashed to nobody, or a UID mismatch.', firstCheck: 'id; ls -ln; exportfs -v (root_squash)' },
    { message: "touch: cannot touch '/opt/software/x': Read-only file system", layer: 'Export / mount options', meaning: 'The export is ro for this client, or the mount used -o ro.', firstCheck: 'mount -t nfs4; exportfs -v' },
    { message: 'Stale file handle', layer: 'Export table', meaning: 'The server no longer exports what this client has mounted (export removed or client dropped).', firstCheck: 'exportfs -v; umount and mount again' },
    { message: 'clnt_create: RPC: Timed out', layer: 'Path / firewall (rpcbind)', meaning: 'showmount cannot reach port 111.', firstCheck: 'Firewall rules for 111 on the server' },
  ],

  scenarioIds: ['nfs-exportfs', 'nfs-root-squash', 'nfs-firewall', 'nfs-uid-mismatch'],
  assessmentId: 'nfs',
  references: [
    { title: 'exports(5) manual page (Debian)', url: 'https://manpages.debian.org/bookworm/nfs-kernel-server/exports.5.en.html' },
    { title: 'nfs(5): fstab format and options for NFS mounts', url: 'https://manpages.debian.org/bookworm/nfs-common/nfs.5.en.html' },
    { title: 'RFC 7530: NFS version 4 protocol (RFC 7862 for 4.2)', url: 'https://www.rfc-editor.org/rfc/rfc7530' },
    { title: 'Debian Wiki: NFSServerSetup', url: 'https://wiki.debian.org/NFSServerSetup' },
    { title: 'Red Hat: Exporting NFS shares (RHEL 9)', url: 'https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_and_using_network_file_services/deploying-an-nfs-server_configuring-and-using-network-file-services' },
    { title: 'Microsoft Learn: SMB file sharing overview', url: 'https://learn.microsoft.com/windows-server/storage/file-server/file-server-smb-overview' },
  ],
  guide: NFS_GUIDE,
  objectives: ['N10-009:1.4', 'N10-009:5.3'],
};

// --- Primer -------------------------------------------------------------------------

export const NFS_PRIMER: Primer = {
  oneLiner: 'A file server **exports** directories; clients **mount** them so the server\'s files appear in their own file tree. With NFS the server checks each access against the user\'s **number** (UID), and treats the client\'s root as **nobody**.',
  analogy: `
A company archive lends out drawers. The archive keeps a list of which departments may borrow which drawer; adding a department to the list on paper does nothing until the archivist copies it into the register at the desk (\`exportfs -ra\`).

Staff don't show ID cards, they just say their staff number. If Alice is number 1000 at head office but 1001 in the branch office, the archive thinks the branch Alice is somebody else. And anyone who claims to be "the boss" (root) is treated as an anonymous visitor (nobody), because anyone could claim that.`,
  ideas: [
    {
      title: 'Exports: the server decides who may mount',
      explain: '/etc/exports lists directories, clients and options; `exportfs -ra` loads it, `exportfs -v` shows what is actually in force.',
      example: 'fs01 exports /srv/projects to 10.0.10.0/24 and 10.0.20.0/24 (rw) and /srv/software to 10.0.0.0/16 (ro).',
    },
    {
      title: 'Mounts: the client attaches it to a directory',
      explain: '`mount -t nfs4 SERVER:/PATH DIR`, or an /etc/fstab line mounted at boot. If it fails, the directory is just an empty local folder.',
      example: 'ws01\'s fstab mounts fs01.corp.lab:/srv/projects on /mnt/projects; `mount -t nfs4` shows it, `df -h` shows the server\'s disk.',
    },
    {
      title: 'Numbers, not names',
      explain: 'The client sends UID and GID; the server checks permissions with them. The same user needs the same number everywhere.',
      example: 'alice is uid 1000 on fs01 and ws01, so her files on the share show as "alice" on both. A host where alice is 1001 sees them as "1000".',
    },
    {
      title: 'root is nobody (root_squash)',
      explain: 'By default the server maps the client\'s root to nobody (65534), so root on a client cannot take over the server\'s files.',
      example: 'On ws01, `touch /mnt/projects/x` as root says "Permission denied"; as alice it works.',
    },
  ],
  walkthrough: {
    title: 'alice saves a file on the share',
    steps: [
      { label: 'Mounted', detail: 'At boot ws01 mounted fs01.corp.lab:/srv/projects on /mnt/projects (TCP 2049).' },
      { label: 'Allowed', detail: 'fs01\'s export table lists 10.0.10.0/24 with rw for /srv/projects.' },
      { label: 'Identity', detail: 'alice runs `echo draft > /mnt/projects/notes.txt`; the request carries uid 1000.' },
      { label: 'Permission', detail: 'fs01 checks /srv/projects (owner 1000, mode 775): the owner may write.' },
      { label: 'Result', detail: '`ls -l /srv/projects/notes.txt` on fs01 shows alice as owner.' },
    ],
  },
  misconceptions: [
    { myth: 'Editing /etc/exports takes effect immediately.', truth: 'Only after exportfs -ra (or restarting the NFS server).' },
    { myth: 'root can write anywhere, also on NFS.', truth: 'With root_squash (the default) root on a client is nobody on the server.' },
    { myth: 'The same user name means the same user.', truth: 'NFS (sec=sys) compares UIDs; names are only display.' },
    { myth: 'An empty mount point means the share is empty.', truth: 'Often the mount failed and you see the local directory: check mount -t nfs4.' },
  ],
  checks: [
    { q: 'Which command loads /etc/exports into the server\'s export table?', a: 'exportfs -ra' },
    { q: 'Which TCP port does NFSv4 use?', a: '2049' },
    { q: 'A root cron job on a client gets "Permission denied" writing to a rw NFS share. Why?', a: 'root_squash maps it to nobody, which may not write to the directory.' },
    { q: 'ls -l on a client shows "1000" as the owner of the share\'s files. What does that tell you?', a: 'The files belong to uid 1000 and no user on this client has that number: the UIDs differ between hosts.' },
  ],
};

// --- Assessment -------------------------------------------------------------------------

export const NFS_ASSESSMENT: Assessment = {
  id: 'nfs',
  title: 'NFS knowledge check',
  questions: [
    {
      id: 'nfs-q-exportfs',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/nfs/internals'],
      prompt: 'You added 10.0.30.0/24 to /srv/projects in /etc/exports on fs01. dev01 (10.0.30.20) still gets "access denied by server". What is missing?',
      options: [
        { text: 'exportfs -ra on fs01 to load the file into the export table', correct: true },
        { text: 'A firewall rule for dev01', misconception: 'A firewall drop gives "Connection timed out"; "access denied by server" is an answer from nfsd.' },
        { text: 'no_root_squash for dev01', misconception: 'Squashing affects file access after the mount, not whether the mount is allowed.' },
        { text: 'Restarting dev01', misconception: 'The decision is made on the server, from its loaded export table.' },
      ],
      concepts: ['files.nfs'],
      explanation: 'The NFS server reads /etc/exports at start or when exportfs -r runs; exportfs -v shows the table in use.',
    },
    {
      id: 'nfs-q-squash',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/nfs/internals'],
      prompt: 'A share is exported rw with default options. root on the client runs "touch /mnt/backup/x" and gets "Permission denied". /srv/backup on the server is root:root 755. Which fix keeps the export secure?',
      options: [
        { text: 'chown nobody:nogroup /srv/backup on the server', correct: true },
        { text: 'Add no_root_squash to the export', misconception: 'That works but makes every client\'s root root on the server\'s files.' },
        { text: 'chmod 777 /srv/backup', misconception: 'Anyone on any client could then write or delete backups.' },
        { text: 'Mount with -o rw', misconception: 'It is already mounted rw; the server maps root to nobody.' },
      ],
      concepts: ['files.nfs', 'linux.permissions'],
      explanation: 'root_squash maps uid 0 to nobody (65534); giving nobody the directory lets the root job write without trusting client root.',
    },
    {
      id: 'nfs-q-uid',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/nfs/internals'],
      prompt: 'On srv01, ls -l /mnt/projects shows the files as owned by "1000", and alice cannot write. On ws01 alice can. What do you check first?',
      exhibit: 'srv01$ id alice\nuid=1001(alice) gid=1001(alice) groups=1001(alice),27(sudo),4(adm)',
      options: [
        { text: 'id alice on the server: NFS compares UIDs, and alice is 1001 here', correct: true },
        { text: 'The export\'s client list', misconception: 'srv01 has the share mounted and can read it.' },
        { text: 'root_squash', misconception: 'alice is not root.' },
      ],
      concepts: ['files.nfs'],
      explanation: 'With sec=sys the server sees uid 1001, which is not the owner (1000). Align the UIDs.',
    },
    {
      id: 'nfs-q-port',
      kind: 'text',
      level: 'beginner',
      learn: ['lesson/nfs/internals'],
      prompt: 'Which TCP port must a firewall allow for NFSv4?',
      accept: ['2049'],
      placeholder: 'port',
      concepts: ['files.nfs'],
      explanation: 'NFSv4 uses TCP 2049 only; NFSv3 and showmount also need rpcbind (111) and mountd.',
    },
    {
      id: 'nfs-q-errors',
      kind: 'order',
      level: 'intermediate',
      learn: ['lesson/nfs/troubleshoot'],
      prompt: 'Order these checks from the first to the last when a share "is empty" on a client.',
      items: ['mount -t nfs4 (is it mounted at all?)', 'mount -a and read the error', 'exportfs -v on the server (is the client allowed?)', 'id and ls -ln (which number am I, who owns the files?)'],
      concepts: ['files.nfs'],
      explanation: 'Mounted → why not → allowed → identity and permissions.',
    },
    {
      id: 'nfs-q-secure',
      kind: 'multi',
      level: 'advanced',
      learn: ['lesson/nfs/internals'],
      prompt: 'Which choices limit what a compromised NFS client can do to the server\'s files? (choose all that apply)',
      options: [
        { text: 'Keep root_squash', correct: true },
        { text: 'Export to the networks that need it, never to *', correct: true },
        { text: 'Use sec=krb5 so users are authenticated by Kerberos', correct: true },
        { text: 'no_root_squash with sync', misconception: 'sync is about write safety; no_root_squash hands root on the client the export.' },
      ],
      concepts: ['files.nfs'],
      explanation: 'sec=sys trusts the client; root_squash, narrow client lists, firewalling and Kerberos limit the damage.',
    },
  ],
};
