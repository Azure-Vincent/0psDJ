// File server: fs01 (10.0.20.60, Debian 12, switch port swp13) runs the kernel
// NFS server. It exports /srv/projects (read-write, office and server networks)
// and /srv/software (read-only, all internal networks). ws01 mounts the project
// share on /mnt/projects and srv01 the software share on /opt/software, both
// from /etc/fstab at boot.

import { mkdir, readFile, writeFile } from '../fs';
import type { Host, World } from '../types';
import { addUser, createHost, staticInterfaces } from './builder';
import { TIMESYNCD_CONF } from './krbLab';
import { installRsyslog } from './logLab';
import { trustCorpRoot } from './pkiLab';
import { DEBIAN_SSHD_CONFIG, installHostKeys } from './sshLab';

export const FS01_IP = '10.0.20.60';
export const FS01_ALICE_PASSWORD = 'fs01-alice';

export const FS01_EXPORTS = `# /etc/exports: the access control list for filesystems which may be exported
#		to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
# Project share for the office and the servers (CHG-2290)
/srv/projects  10.0.10.0/24(rw,sync,no_subtree_check) 10.0.20.0/24(rw,sync,no_subtree_check)
# Software repository, read-only for every internal network
/srv/software  10.0.0.0/16(ro,sync,no_subtree_check)
`;

export const FS01_NFT = `#!/usr/sbin/nft -f

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iif "lo" accept
		meta l4proto icmp accept
		tcp dport 22 accept
		# NFS for the corp.lab networks: nfsd, rpcbind (showmount), mountd (CHG-2290)
		ip saddr 10.0.0.0/16 tcp dport { 111, 2049, 20048 } accept
		ip saddr 10.0.0.0/16 udp dport 111 accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

const FSTAB_HEAD = `# /etc/fstab: static file system information.
#
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
UUID=8f1c2d3e-4a5b-4c6d-9e7f-0a1b2c3d4e5f /               ext4    errors=remount-ro 0       1
`;

/** Add an NFS line to a host's /etc/fstab (creating Debian's file if needed) and its mount point. */
export function addNfsFstab(host: Host, line: string, mountPoint: string, t: number): void {
  const cur = readFile(host, '/etc/fstab') ?? FSTAB_HEAD;
  writeFile(host, '/etc/fstab', cur + line + '\n', t);
  const parts = mountPoint.split('/').filter(Boolean);
  for (let i = 1; i <= parts.length; i++) {
    const p = '/' + parts.slice(0, i).join('/');
    if (!host.fs[p]) mkdir(host, p, t);
  }
}

/** Create fs01 (cabled to sw01 swp13) and the clients' fstab entries; buildSshLab boots it before them. */
export function installFs01(world: World): Host {
  const t = world.clock;
  const h = createHost(world, {
    id: 'fs01', hostname: 'fs01', domain: 'corp.lab', role: 'File server (NFS)',
    ifaces: [{ name: 'eth0', mac: '52:54:00:f5:00:3c', segment: null }],
    services: ['rsyslog', 'systemd-timesyncd', 'nftables', 'ssh', 'nfs-kernel-server'],
  });
  writeFile(h, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: `${FS01_IP}/24`, gateway: '10.0.20.1' }]), t);
  writeFile(h, '/etc/resolv.conf', 'search corp.lab\nnameserver 10.0.10.53\n', t);
  writeFile(h, '/etc/ssh/sshd_config', DEBIAN_SSHD_CONFIG, t);
  writeFile(h, '/etc/nftables.conf', FS01_NFT, t, { mode: 0o755 });
  writeFile(h, '/etc/exports', FS01_EXPORTS, t);
  mkdir(h, '/etc/systemd', t);
  writeFile(h, '/etc/systemd/timesyncd.conf', TIMESYNCD_CONF, t);
  installHostKeys(h, t);
  trustCorpRoot(h, t);
  installRsyslog(h, t, true);
  addUser(h, { name: 'alice', uid: 1000, gid: 1000, primaryGroup: 'alice', groups: ['sudo'], home: '/home/alice', shell: '/bin/bash', gecos: 'Alice Admin', password: FS01_ALICE_PASSWORD }, t);
  addUser(h, { name: 'nobody', uid: 65534, gid: 65534, primaryGroup: 'nogroup', groups: [], home: '/nonexistent', shell: '/usr/sbin/nologin', gecos: 'nobody', password: null }, t, false);
  if (!h.fs['/srv']) mkdir(h, '/srv', t);
  mkdir(h, '/srv/projects', t, { mode: 0o775, owner: 'alice', group: 'alice' });
  writeFile(h, '/srv/projects/plan.txt', 'Q4 infrastructure plan\n- central logging (done)\n- NFS file server (in progress)\n', t, { mode: 0o664, owner: 'alice', group: 'alice' });
  mkdir(h, '/srv/projects/inventory', t, { mode: 0o775, owner: 'alice', group: 'alice' });
  writeFile(h, '/srv/projects/inventory/servers.csv', 'host,ip,role\nsrv01,10.0.20.10,web\ndock01,10.0.20.40,containers\nlog01,10.0.20.50,logs\nfs01,10.0.20.60,files\n', t, { mode: 0o664, owner: 'alice', group: 'alice' });
  mkdir(h, '/srv/software', t, { mode: 0o755 });
  writeFile(h, '/srv/software/README', 'Approved installers. Read-only for clients: request changes with a ticket.\n', t);
  writeFile(h, '/srv/software/agent-install.sh', '#!/bin/sh\necho "installing monitoring agent 3.2"\n', t, { mode: 0o755 });

  addNfsFstab(world.hosts.ws01, 'fs01.corp.lab:/srv/projects /mnt/projects nfs4 defaults,_netdev 0 0', '/mnt/projects', t);
  addNfsFstab(world.hosts.srv01, 'fs01.corp.lab:/srv/software /opt/software nfs4 ro,_netdev 0 0', '/opt/software', t);
  return h;
}
