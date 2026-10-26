// File sharing tickets. fs01 exports /srv/projects (read-write, office and
// server networks) and /srv/software (read-only) with the kernel NFS server;
// ws01 mounts the projects share, srv01 the software share, from /etc/fstab.
// Each ticket breaks one link: an export table that was never reloaded,
// root_squash, the server's firewall, and a UID that differs between hosts.

import { mkdir, writeFile } from '../fs';
import { FS01_EXPORTS, FS01_NFT, addNfsFstab } from '../lab/nfsLab';
import { mountFstabNfs, nfsReset, type NfsServerLoaded } from '../sim/nfs';
import type { World } from '../types';
import { firewallStillRestrictive, script } from './engine';
import type { Constraint, Goal, Scenario } from './types';

const BRIEFING = [
  'fs01 (10.0.20.60) is the file server: the kernel NFS server (nfs-kernel-server) exports the directories listed in /etc/exports. /srv/projects is read-write for the office (10.0.10.0/24) and the servers (10.0.20.0/24); /srv/software is read-only for every internal network.',
  'Clients mount the exports from /etc/fstab at boot: ws01 mounts fs01.corp.lab:/srv/projects on /mnt/projects, srv01 mounts fs01.corp.lab:/srv/software on /opt/software.',
  'Tools: on fs01 exportfs -v (the export table in use), exportfs -ra (reload /etc/exports), ss -tlnp, nft list ruleset; on a client mount, mount -a, umount, df -h, showmount -e fs01, id, ls -ln, journalctl -b.',
  'Fixes must survive a reboot. Keep fs01\'s firewall restrictive and its exports as narrow as they are.',
];

const TERMINALS = [
  { hostId: 'fs01', user: 'root', label: 'fs01 console (root)', banner: 'fs01 console: the NFS server. Try: cat /etc/exports, exportfs -v, ss -tlnp, nft list ruleset.' },
  { hostId: 'ws01', user: 'root', label: 'ws01 console (root)', banner: 'ws01 console: an NFS client. Try: mount -t nfs4, df -h, cat /etc/fstab, showmount -e fs01.' },
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01 as alice, a user of the project share. Try: id, ls -l /mnt/projects, touch /mnt/projects/test.' },
  { hostId: 'srv01', user: 'root', label: 'srv01 console (root)', banner: 'srv01 console: an NFS client. Try: mount -t nfs4, cat /etc/fstab, id alice, ls -ln /mnt.' },
];

const CANDIDATES = ['nfs-exports-not-loaded', 'nfs-root-squash', 'nfs-firewall', 'nfs-uid-mismatch', 'dns-wrong-record', 'server-file-permissions'];

/** No export may be widened to every host. */
function exportsNotOpen(): Constraint {
  return {
    id: 'nfs-exports-narrow', required: true,
    description: 'fs01 exports nothing to every host (no "*", no 0.0.0.0/0).',
    check(world) {
      const l = world.hosts.fs01.services['nfs-kernel-server']?.loaded as NfsServerLoaded | null | undefined;
      const open = (l?.exports ?? []).flatMap((e) => e.clients.filter((c) => c.spec === '*' || c.spec.endsWith('/0')).map((c) => `${e.path} ${c.spec}`));
      return { id: this.id, ok: !open.length, required: true, message: open.length ? `fs01 exports to everyone: ${open.join(', ')}. List the networks or hosts that need the share.` : 'fs01: every export names its clients.' };
    },
  };
}

function backupNotWideOpen(): Constraint {
  return {
    id: 'nfs-backup-root-squashed', required: true,
    description: 'The backup share keeps root squashed (no no_root_squash, no anonuid=0) and /srv/backup is not world-writable (SEC-77).',
    check(world) {
      const fs01 = world.hosts.fs01;
      const l = fs01.services['nfs-kernel-server']?.loaded as NfsServerLoaded | null | undefined;
      const ex = l?.exports.find((e) => e.path === '/srv/backup');
      const rootOk = !!ex && ex.clients.every((c) => c.options.squash !== 'none' && c.options.anonuid !== 0);
      const mode = fs01.fs['/srv/backup']?.mode ?? 0;
      const ok = rootOk && (mode & 0o002) === 0;
      return { id: this.id, ok, required: true, message: ok ? 'fs01: /srv/backup squashes root and is not world-writable.' : !rootOk ? 'srv01\'s root must not be root on fs01 (no_root_squash / anonuid=0): a compromised client would own the file server.' : '/srv/backup is world-writable: any user of any client could replace the backups.' };
    },
  };
}

const projectsAs = (host: string, user: string, file: string): Goal => ({
  kind: 'command',
  description: `${user} on ${host} saves a file in /mnt/projects, and it belongs to alice on fs01.`,
  steps: [{ host, user, command: `touch /mnt/projects/${file}` }, { host: 'fs01', user: 'root', command: `ls -l /srv/projects/${file}` }],
  // The owner column (not the group) must say alice.
  expect: `^\\S+ \\d+ alice .*${file.replace('.', '\\.')}$`,
});

/** Some days of normal use of the share. */
function activity(world: World): void {
  world.clock += 2 * 3600_000;
  script(world, 'fs01', ['logger -t backup "nightly snapshot of /srv finished"']);
}

/** As after a reboot of the clients: mounts are gone and fstab is mounted again (and logged). */
function remountClients(world: World, hosts: string[]): void {
  for (const id of hosts) {
    world.clock += 30_000;
    nfsReset(world.hosts[id]);
    mountFstabNfs(world, world.hosts[id]);
  }
}

export const NFS_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'nfs-exportfs',
    title: 'Added to the list',
    difficulty: 'beginner',
    ticket: 'Erin (dev01): "CHG-2295 gave the development network access to the project share. I added the fstab line from the wiki, but mount says \'access denied by server\'. The change is in fs01\'s /etc/exports, I checked."',
    briefing: BRIEFING,
    goals: [{
      kind: 'command',
      description: 'dev01 mounts the project share from /etc/fstab (mount -a) and erin reads /mnt/projects/plan.txt.',
      steps: [{ host: 'dev01', user: 'root', command: 'mount -a' }, { host: 'dev01', user: 'erin', command: 'cat /mnt/projects/plan.txt' }],
      expect: '^Q4 infrastructure plan',
    }],
    terminals: [TERMINALS[0], { hostId: 'dev01', user: 'root', label: 'dev01 console (root)', banner: 'dev01 console: the new client. Try: mount -a, cat /etc/fstab, showmount -e fs01.' }],
    setup(world) {
      writeFile(world.hosts.fs01, '/etc/exports', FS01_EXPORTS.replace('10.0.20.0/24(rw,sync,no_subtree_check)\n', '10.0.20.0/24(rw,sync,no_subtree_check) 10.0.30.0/24(rw,sync,no_subtree_check)\n').replace('# Project share for the office and the servers (CHG-2290)', '# Project share for the office, the servers and development (CHG-2290, CHG-2295)'), world.clock);
      addNfsFstab(world.hosts.dev01, 'fs01.corp.lab:/srv/projects /mnt/projects nfs4 defaults,_netdev 0 0', '/mnt/projects', world.clock);
      script(world, 'dev01', ['mount -a']);
      activity(world);
    },
    rootCauses: ['nfs-exports-not-loaded'],
    candidates: CANDIDATES,
    feedback: {
      'nfs-root-squash': 'The mount itself is refused, before any file is touched.',
      'nfs-firewall': 'fs01 answers dev01 ("access denied by server"): the connection to 2049 works.',
      'nfs-uid-mismatch': 'Nothing is mounted yet; owners do not matter until then.',
      'dns-wrong-record': 'fs01.corp.lab resolves to 10.0.20.60 on dev01, and that server answers.',
      'server-file-permissions': 'File permissions apply after the mount; this mount is refused.',
    },
    hints: [
      'The server decides who may mount. On fs01, compare what the file says (cat /etc/exports) with what the kernel uses (exportfs -v). showmount -e fs01 from dev01 shows the same table.',
      'exportfs -v does not list 10.0.30.0/24: the NFS server reads /etc/exports when it starts or when told to. Editing the file alone changes nothing.',
      'Run exportfs -ra on fs01 (reload all exports; systemctl reload nfs-server does the same), check with exportfs -v, then mount -a on dev01.',
    ],
    explanation: {
      rootCause: 'The development network was added to /srv/projects in /etc/exports, but nobody ran exportfs -ra: the kernel\'s export table still has the old client list.',
      manifestation: 'fs01 accepts dev01\'s connection and refuses the mount for that export: "mount.nfs4: access denied by server while mounting fs01.corp.lab:/srv/projects". The file looks right, so the change seems done.',
      evidence: 'cat /etc/exports on fs01 lists 10.0.30.0/24; exportfs -v (and showmount -e fs01) do not; the error on dev01 comes from the server ("by server").',
      prevention: 'After editing /etc/exports, run exportfs -ra and check exportfs -v; test the mount from the new client before closing the change.',
    },
    solution: [{ host: 'fs01', commands: ['exportfs -ra'] }],
    constraints: [exportsNotOpen()],
    concepts: ['files.nfs'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'nfs-root-squash',
    title: 'Root is nobody',
    difficulty: 'intermediate',
    ticket: 'Backups: "srv01\'s nightly configuration backup (it runs as root) fails since we moved it to the new backup share on fs01 (CHG-2297): cp: cannot create regular file \'/mnt/backup/...\': Permission denied. The share is mounted read-write and root can write everywhere. Security insists the share keeps its defaults (SEC-77)."',
    briefing: [...BRIEFING, 'fs01 also exports /srv/backup to srv01 (CHG-2297); srv01 mounts it on /mnt/backup.'],
    goals: [{
      kind: 'command',
      description: 'root on srv01 copies a file to /mnt/backup, and it arrives in /srv/backup on fs01.',
      steps: [{ host: 'srv01', user: 'root', command: 'cp /etc/hosts /mnt/backup/hosts.srv01' }, { host: 'fs01', user: 'root', command: 'ls -l /srv/backup/hosts.srv01' }],
      expect: 'hosts\\.srv01$',
    }],
    terminals: TERMINALS,
    setup(world) {
      const fs01 = world.hosts.fs01;
      mkdir(fs01, '/srv/backup', world.clock, { mode: 0o755 });
      writeFile(fs01, '/etc/exports', FS01_EXPORTS + '# Configuration backups from srv01 (CHG-2297)\n/srv/backup    srv01.corp.lab(rw,sync,no_subtree_check)\n', world.clock);
      script(world, 'fs01', ['exportfs -ra']);
      addNfsFstab(world.hosts.srv01, 'fs01.corp.lab:/srv/backup /mnt/backup nfs4 defaults,_netdev 0 0', '/mnt/backup', world.clock);
      script(world, 'srv01', ['mount -a', 'cp /etc/hosts /mnt/backup/hosts.srv01', 'logger -t config-backup "cp: cannot create regular file \'/mnt/backup/hosts.srv01\': Permission denied"']);
      activity(world);
    },
    rootCauses: ['nfs-root-squash'],
    candidates: CANDIDATES,
    feedback: {
      'nfs-exports-not-loaded': 'The share is mounted: the export table includes srv01 (exportfs -v).',
      'nfs-firewall': 'The share is mounted and readable from srv01.',
      'nfs-uid-mismatch': 'The job runs as root (uid 0), which is never matched to a user account: it is squashed.',
      'dns-wrong-record': 'The share is mounted from the right server.',
      'server-file-permissions': 'Close: the directory\'s permissions decide, but for whom? root on srv01 is not root on fs01.',
    },
    hints: [
      'The share is rw (mount -t nfs4) and alice could write if she owned the directory. What is different about root? On fs01: exportfs -v shows the options the export really has.',
      '"root_squash" is the default: requests from uid 0 on the client are handled as nobody (65534) on the server. ls -ld /srv/backup on fs01: who may write in it?',
      'Keep root_squash (SEC-77) and give the squashed identity the directory: chown nobody:nogroup /srv/backup on fs01 (mode 755: only it writes). The backup files then belong to nobody on fs01.',
    ],
    explanation: {
      rootCause: 'The export uses the default root_squash: root on srv01 is mapped to nobody (uid 65534) on fs01. /srv/backup is owned by root with mode 755, so nobody may not create files in it.',
      manifestation: 'The mount is read-write and ordinary users with permission can write, but every write by root (the backup job) is refused with "Permission denied", which looks impossible for root.',
      evidence: 'exportfs -v on fs01: "root_squash"; ls -ld /srv/backup: root root drwxr-xr-x; the same cp as a user who owns the target works; files root creates on other squashed shares belong to nobody.',
      prevention: 'Design NFS shares for the identity that will write: a dedicated directory owned by nobody (or an anonuid service account with all_squash) for root jobs, instead of no_root_squash, which hands the server\'s files to the client\'s root.',
    },
    solution: [{ host: 'fs01', commands: ['chown nobody:nogroup /srv/backup'] }],
    constraints: [backupNotWideOpen()],
    concepts: ['files.nfs', 'linux.permissions'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'nfs-firewall',
    title: 'Hardened and empty',
    difficulty: 'intermediate',
    ticket: 'Monday: "After the weekend patch reboot /mnt/projects on ws01 is empty and /opt/software on srv01 too. fs01 was hardened on Friday (SEC-142, default-deny firewall). The exports themselves look fine on fs01."',
    briefing: BRIEFING,
    goals: [{
      kind: 'command',
      description: 'ws01 mounts its fstab entries (mount -a) and alice sees the project files.',
      steps: [{ host: 'ws01', user: 'root', command: 'mount -a' }, { host: 'ws01', user: 'alice', command: 'ls /mnt/projects' }],
      expect: 'plan\\.txt',
    }, {
      kind: 'command',
      description: 'srv01 mounts its fstab entries (mount -a) and /opt/software has the installers.',
      steps: [{ host: 'srv01', user: 'root', command: 'mount -a' }, { host: 'srv01', user: 'root', command: 'ls /opt/software' }],
      expect: 'agent-install\\.sh',
    }],
    terminals: TERMINALS,
    setup(world) {
      writeFile(world.hosts.fs01, '/etc/nftables.conf', FS01_NFT.replace('\t\t# NFS for the corp.lab networks: nfsd, rpcbind (showmount), mountd (CHG-2290)\n\t\tip saddr 10.0.0.0/16 tcp dport { 111, 2049, 20048 } accept\n\t\tip saddr 10.0.0.0/16 udp dport 111 accept\n', ''), world.clock, { mode: 0o755 });
      script(world, 'fs01', ['systemctl restart nftables']);
      activity(world);
      remountClients(world, ['ws01', 'srv01']);
    },
    rootCauses: ['nfs-firewall'],
    candidates: CANDIDATES,
    feedback: {
      'nfs-exports-not-loaded': 'exportfs -v on fs01 lists both exports with the right clients.',
      'nfs-root-squash': 'Nothing is mounted at all; squashing applies to requests on a mounted share.',
      'nfs-uid-mismatch': 'Nothing is mounted at all.',
      'dns-wrong-record': 'fs01.corp.lab resolves to 10.0.20.60 on both clients.',
      'server-file-permissions': 'Nothing is mounted at all: the directories on the clients are just the empty mount points.',
    },
    hints: [
      'Is anything mounted? mount -t nfs4 and df -h on ws01. Then the boot log: journalctl -b -u mnt-projects.mount.',
      '"mount.nfs4: Connection timed out": the client never got an answer from fs01:2049. On fs01, nfsd listens (ss -tlnp). What happens to the packets first? nft list ruleset.',
      'Put the NFS rules back in /etc/nftables.conf on fs01 ("ip saddr 10.0.0.0/16 tcp dport { 111, 2049, 20048 } accept" and udp 111), systemctl restart nftables, then mount -a on the clients.',
    ],
    explanation: {
      rootCause: 'The hardening of fs01 (input policy drop) kept only SSH: nothing accepts NFS (TCP 2049) or rpcbind/mountd (111, 20048) any more.',
      manifestation: 'Existing mounts kept working until the reboot. At boot every client\'s mount of fs01 timed out after two minutes, systemd marked the mount unit failed, and the mount points show the empty local directories underneath. Programs writing there would silently write to the local disk.',
      evidence: 'journalctl -b on ws01: "mount.nfs4: Connection timed out" and "Failed to mount mnt-projects.mount"; showmount -e fs01: "RPC: Timed out"; on fs01: ss -tlnp shows 2049, nft list ruleset has no rule for it, tcpdump -n port 2049 shows SYNs without replies.',
      prevention: 'Inventory what a server provides (ss -tulnp) before hardening it, and test the clients after changing a firewall rather than waiting for a reboot to find out.',
    },
    solution: [{ host: 'fs01', commands: [`printf '${FS01_NFT.replace(/\n/g, '\\n').replace(/\t/g, '\\t')}' > /etc/nftables.conf`, 'systemctl restart nftables'] }],
    constraints: [firewallStillRestrictive('fs01'), exportsNotOpen()],
    concepts: ['files.nfs', 'fw.path'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'nfs-uid-mismatch',
    title: 'Same name, different number',
    difficulty: 'advanced',
    ticket: 'Alice: "I mounted the project share on srv01 too (CHG-2299) so the inventory scripts can update it. I can read everything but can\'t save anything there, and ls -l shows the files as owned by \'1000\' instead of me. From ws01 it all works."',
    briefing: [...BRIEFING, 'srv01 also mounts fs01.corp.lab:/srv/projects on /mnt/projects (CHG-2299).'],
    goals: [projectsAs('srv01', 'alice', 'srv01-check.txt'), projectsAs('ws01', 'alice', 'ws01-check.txt')],
    terminals: [...TERMINALS, { hostId: 'srv01', user: 'alice', label: 'srv01 (alice)', banner: 'srv01 as alice. Try: id, ls -l /mnt/projects, touch /mnt/projects/test.' }],
    setup(world) {
      addNfsFstab(world.hosts.srv01, 'fs01.corp.lab:/srv/projects /mnt/projects nfs4 defaults,_netdev 0 0', '/mnt/projects', world.clock);
      script(world, 'srv01', ['mount -a']);
      activity(world);
    },
    rootCauses: ['nfs-uid-mismatch'],
    candidates: CANDIDATES,
    feedback: {
      'nfs-exports-not-loaded': 'srv01 has the share mounted (mount -t nfs4) and can read it.',
      'nfs-root-squash': 'alice is not root; squashing root does not affect her.',
      'nfs-firewall': 'The share is mounted and readable from srv01.',
      'dns-wrong-record': 'The share is mounted from fs01 and shows its files.',
      'server-file-permissions': 'The permissions are right for alice (rw for the owner): ws01\'s alice can write. Who does fs01 think srv01\'s alice is?',
    },
    hints: [
      'NFS (sec=sys) does not send user names, only numbers. Compare id alice on srv01, ws01 and fs01, and ls -ln /mnt/projects with ls -ln /srv/projects on fs01.',
      'alice is uid 1001 on srv01 but 1000 on fs01 and ws01. fs01 sees requests from uid 1001: not the owner, not in the group, only "other" (r-x). srv01 has no user 1000, so ls -l prints the number.',
      'Make the numbers agree on the odd host: on srv01, usermod -u 1000 alice (check first that uid 1000 is free there: getent passwd 1000). Changing fs01 instead would break ws01.',
    ],
    explanation: {
      rootCause: 'alice has uid 1001 on srv01 (it was created after bob\'s test account years ago) and uid 1000 on fs01 and ws01. With AUTH_SYS, NFS identifies users by number, so on the share srv01\'s alice is a stranger.',
      manifestation: 'srv01 shows the project files as owned by "1000" (no such user there); alice may read (mode 664/775 gives others r) but fs01 refuses her writes as uid 1001 with "Permission denied". The same account works from ws01, which has the matching number.',
      evidence: 'id alice: uid=1001 on srv01, uid=1000 on fs01 and ws01; ls -ln /mnt/projects on srv01 and ls -ln /srv/projects on fs01 both show the owner 1000; touch as alice on srv01 gives "Permission denied" where alice on ws01 succeeds.',
      prevention: 'Keep UIDs and GIDs identical on every host that shares files: a central directory (LDAP, FreeIPA, Active Directory with sssd), or fixed UIDs in configuration management; or use NFSv4 with Kerberos (sec=krb5), which identifies users by principal.',
    },
    solution: [{ host: 'srv01', commands: ['usermod -u 1000 alice'] }],
    constraints: [exportsNotOpen()],
    concepts: ['files.nfs', 'linux.permissions'],
  },
];
