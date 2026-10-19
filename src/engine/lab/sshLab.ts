// Baseline environment for the SSH vertical slice:
//
//   ws01 (10.0.10.25) ──┐                       ┌── srv01 (10.0.20.10)  sshd, nginx
//   ns1  (10.0.10.53) ──┼── lan10 ── rtr01 ── srv20
//                       │        10.0.10.1  10.0.20.1
//
// Everything works in the baseline: alice@ws01 can `ssh srv01.corp.lab` with
// her ed25519 key. Scenarios break it in specific, realistic ways.

import { mkdir, writeFile } from '../fs';
import { bootHost } from '../sim/services';
import { endSession, runSsh } from '../sim/ssh';
import { makeKeyPair, type KeyType } from '../sim/keys';
import type { Host, World } from '../types';
import { addUser, createHost, newWorld, staticInterfaces } from './builder';

export const DEBIAN_SSHD_CONFIG = `
# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/local/bin:/usr/bin:/bin:/usr/games

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Include /etc/ssh/sshd_config.d/*.conf

#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
#PermitRootLogin prohibit-password
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

#PubkeyAuthentication yes

# Expect .ssh/authorized_keys2 to be disregarded by default in future.
#AuthorizedKeysFile	.ssh/authorized_keys .ssh/authorized_keys2

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
#PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
KbdInteractiveAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the KbdInteractiveAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via KbdInteractiveAuthentication may bypass
# the setting of "PermitRootLogin prohibit-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and KbdInteractiveAuthentication to 'no'.
UsePAM yes

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
X11Forwarding yes
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
PrintMotd no
#PrintLastLog yes
#TCPKeepAlive yes
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# override default of no subsystems
Subsystem	sftp	/usr/lib/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#	X11Forwarding no
#	AllowTcpForwarding no
#	PermitTTY no
#	ForceCommand cvs server
`.slice(1);

export const HARDENING_CONF = `# Managed by the platform team - see change ticket CHG-1042
# Key-based logins only; no direct root logins.
PermitRootLogin no
PasswordAuthentication no
`;

export const SRV01_NFT = `#!/usr/sbin/nft -f

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		ct state invalid drop
		iif "lo" accept
		meta l4proto icmp accept
		tcp dport 22 accept
		tcp dport { 80, 443 } accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

export const RTR01_NFT = `#!/usr/sbin/nft -f

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iif "lo" accept
		meta l4proto icmp accept
		iifname "eth0" tcp dport 22 accept
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

export const CORP_ZONE = `; corp.lab - authoritative zone, managed on ns1
$TTL 3600
$ORIGIN corp.lab.
@       IN SOA ns1.corp.lab. hostmaster.corp.lab. (
                2026101901 ; serial (YYYYMMDDnn)
                3600       ; refresh
                900        ; retry
                1209600    ; expire
                300 )      ; negative-caching TTL
@       IN NS   ns1.corp.lab.
ns1     IN A    10.0.10.53
rtr01   IN A    10.0.10.1
ws01    IN A    10.0.10.25
srv01   IN A    10.0.20.10
www     IN CNAME srv01
`;

export const NAMED_CONF_LOCAL = `//
// Do any local configuration here
//

zone "corp.lab" {
    type master;
    file "/etc/bind/db.corp.lab";
    allow-transfer { none; };
};
`;

export const ALICE_SERVER_PASSWORD = 'Corp-Lab-2026';
export const BOB_PASSWORD = 'Summer2026!';

export function hostKeyPair(host: string, type: KeyType, generation = 1) {
  return makeKeyPair(type, `${host}-hostkey-${type}-gen${generation}`, `root@${host}`);
}

export function aliceKey() {
  return makeKeyPair('ed25519', 'alice-ws01-ed25519', 'alice@ws01');
}

export function bobKey() {
  return makeKeyPair('ed25519', 'bob-laptop-ed25519', 'bob@laptop');
}

export function installHostKeys(host: Host, time: number, generation = 1): void {
  for (const type of ['rsa', 'ecdsa', 'ed25519'] as KeyType[]) {
    const kp = hostKeyPair(host.hostname, type, generation);
    writeFile(host, `/etc/ssh/ssh_host_${type}_key`, kp.privateFile, time, { mode: 0o600 });
    writeFile(host, `/etc/ssh/ssh_host_${type}_key.pub`, kp.publicLine + '\n', time, { mode: 0o644 });
  }
}

export function buildSshLab(): World {
  const world = newWorld('SSH lab', '2026-10-19T07:58:00Z');
  world.segments = {
    lan10: { id: 'lan10', name: 'Office LAN', cidr: '10.0.10.0/24', vlan: 10 },
    srv20: { id: 'srv20', name: 'Server network', cidr: '10.0.20.0/24', vlan: 20 },
  };
  const t = world.clock;

  // ---- rtr01 -------------------------------------------------------------
  const rtr = createHost(world, {
    id: 'rtr01', hostname: 'rtr01', domain: 'corp.lab', role: 'Router / inter-VLAN gateway', kind: 'router',
    ifaces: [
      { name: 'eth0', mac: '52:54:00:a1:00:01', segment: 'lan10' },
      { name: 'eth1', mac: '52:54:00:a1:00:02', segment: 'srv20' },
    ],
    services: ['nftables'],
  });
  writeFile(rtr, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: '10.0.10.1/24' }, { name: 'eth1', address: '10.0.20.1/24' }]), t);
  writeFile(rtr, '/etc/sysctl.d/99-router.conf', '# Enable IPv4 forwarding between eth0 (LAN) and eth1 (servers)\nnet.ipv4.ip_forward=1\n', t);
  writeFile(rtr, '/etc/nftables.conf', RTR01_NFT, t, { mode: 0o755 });
  writeFile(rtr, '/etc/resolv.conf', 'search corp.lab\nnameserver 10.0.10.53\n', t);

  // ---- ns1 ---------------------------------------------------------------
  const ns1 = createHost(world, {
    id: 'ns1', hostname: 'ns1', domain: 'corp.lab', role: 'DNS server (BIND 9, authoritative for corp.lab)',
    ifaces: [{ name: 'eth0', mac: '52:54:00:b2:00:35', segment: 'lan10' }],
    services: ['nftables', 'named'],
  });
  writeFile(ns1, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: '10.0.10.53/24', gateway: '10.0.10.1' }]), t);
  writeFile(ns1, '/etc/resolv.conf', 'search corp.lab\nnameserver 127.0.0.1\n', t);
  mkdir(ns1, '/etc/bind', t, { group: 'bind', mode: 0o2755 });
  writeFile(ns1, '/etc/bind/named.conf.local', NAMED_CONF_LOCAL, t, { group: 'bind' });
  writeFile(ns1, '/etc/bind/db.corp.lab', CORP_ZONE, t, { group: 'bind' });

  // ---- srv01 -------------------------------------------------------------
  const srv = createHost(world, {
    id: 'srv01', hostname: 'srv01', domain: 'corp.lab', role: 'Linux application server (sshd, nginx)',
    ifaces: [{ name: 'eth0', mac: '52:54:00:c3:00:0a', segment: 'srv20' }],
    services: ['nftables', 'ssh', 'nginx'],
  });
  writeFile(srv, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: '10.0.20.10/24', gateway: '10.0.20.1' }]), t);
  writeFile(srv, '/etc/resolv.conf', 'search corp.lab\nnameserver 10.0.10.53\n', t);
  writeFile(srv, '/etc/nftables.conf', SRV01_NFT, t, { mode: 0o755 });
  writeFile(srv, '/etc/ssh/sshd_config', DEBIAN_SSHD_CONFIG, t);
  writeFile(srv, '/etc/ssh/sshd_config.d/10-hardening.conf', HARDENING_CONF, t);
  installHostKeys(srv, t);
  mkdir(srv, '/etc/nginx', t);
  writeFile(srv, '/etc/nginx/nginx.conf', 'user www-data;\nworker_processes auto;\nhttp {\n    server {\n        listen 80 default_server;\n        listen [::]:80 default_server;\n        root /var/www/html;\n    }\n}\n', t);
  addUser(srv, { name: 'alice', uid: 1001, gid: 1001, primaryGroup: 'alice', groups: ['sudo', 'adm'], home: '/home/alice', shell: '/bin/bash', gecos: 'Alice Admin', password: ALICE_SERVER_PASSWORD }, t);
  addUser(srv, { name: 'bob', uid: 1002, gid: 1002, primaryGroup: 'bob', groups: ['developers'], home: '/home/bob', shell: '/bin/bash', gecos: 'Bob Developer', password: BOB_PASSWORD }, t);
  addUser(srv, { name: 'backup', uid: 34, gid: 34, primaryGroup: 'backup', groups: [], home: '/var/backups', shell: '/usr/sbin/nologin', gecos: 'backup', password: null }, t, false);
  mkdir(srv, '/var/backups', t);
  mkdir(srv, '/home/alice/.ssh', t, { mode: 0o700, owner: 'alice', group: 'alice' });
  writeFile(srv, '/home/alice/.ssh/authorized_keys', aliceKey().publicLine + '\n', t, { mode: 0o600, owner: 'alice', group: 'alice' });
  mkdir(srv, '/home/bob/.ssh', t, { mode: 0o700, owner: 'bob', group: 'bob' });
  writeFile(srv, '/home/bob/.ssh/authorized_keys', bobKey().publicLine + '\n', t, { mode: 0o600, owner: 'bob', group: 'bob' });

  // ---- ws01 --------------------------------------------------------------
  const ws = createHost(world, {
    id: 'ws01', hostname: 'ws01', domain: 'corp.lab', role: 'Administrator workstation (ssh client)',
    ifaces: [{ name: 'eth0', mac: '52:54:00:d4:00:19', segment: 'lan10' }],
    services: ['nftables'],
  });
  writeFile(ws, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: '10.0.10.25/24', gateway: '10.0.10.1' }]), t);
  writeFile(ws, '/etc/resolv.conf', '# Generated for corp.lab\nsearch corp.lab\nnameserver 10.0.10.53\noptions timeout:2 attempts:2\n', t);
  addUser(ws, { name: 'alice', uid: 1000, gid: 1000, primaryGroup: 'alice', groups: ['sudo'], home: '/home/alice', shell: '/bin/bash', gecos: 'Alice Admin', password: 'ws01-alice' }, t);
  mkdir(ws, '/home/alice/.ssh', t, { mode: 0o700, owner: 'alice', group: 'alice' });
  const ak = aliceKey();
  writeFile(ws, '/home/alice/.ssh/id_ed25519', ak.privateFile, t, { mode: 0o600, owner: 'alice', group: 'alice' });
  writeFile(ws, '/home/alice/.ssh/id_ed25519.pub', ak.publicLine + '\n', t, { mode: 0o644, owner: 'alice', group: 'alice' });

  // Boot everything (order matters only for log realism).
  for (const h of [rtr, ns1, srv, ws]) bootHost(world, h);

  // History: alice connected yesterday-style earlier today, accepting the host key.
  world.clock += 60_000;
  const first = runSsh(world, { clientHostId: 'ws01', localUser: 'alice', target: 'srv01.corp.lab', answers: ['yes'] });
  if (first.session) {
    world.clock += 240_000;
    endSession(world, first.session);
  }
  world.clock += 30 * 60_000;
  return world;
}

export function cloneWorld(world: World): World {
  return structuredClone(world);
}
