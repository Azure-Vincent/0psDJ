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
import { EXT01_NGINX_CONF, installExt01Web, installSrv01Pki, SRV01_NGINX_CONF, trustCorpRoot } from './pkiLab';

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
		meta l4proto ipv6-icmp accept
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
		meta l4proto ipv6-icmp accept
		iifname "eth0" tcp dport 22 accept
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}

# NAT towards the Internet (eth2): hide the private networks behind 203.0.113.2
# and publish the intranet web server on the public address (WEB-1).
table ip nat {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "eth2" tcp dport 80 dnat to 10.0.20.10:80
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "eth2" masquerade
	}
}
`;

export const DHCPD_CONF = `# dhcpd.conf - office LAN (ISC DHCP 4.4)
option domain-name "corp.lab";
option domain-name-servers 10.0.10.53;
default-lease-time 600;
max-lease-time 7200;
authoritative;

subnet 10.0.10.0 netmask 255.255.255.0 {
    range 10.0.10.100 10.0.10.150;
    option routers 10.0.10.1;
}

# Reservations
host printer01 {
    hardware ethernet 52:54:00:e5:00:21;
    fixed-address 10.0.10.21;
}
`;

/** sw01: VLAN-aware Linux bridge (ifupdown2 syntax, as on Debian with ifupdown2 or Cumulus Linux). */
export const SW01_INTERFACES = `# sw01 - access switch for the office and server networks (ifupdown2)
# VLAN 10 office, VLAN 20 servers, VLAN 30 development (IPv6 pilot)

auto lo
iface lo inet loopback

# Access ports
auto swp1
iface swp1
    alias ws01
    bridge-access 10

auto swp2
iface swp2
    alias ws02 (hot desk)
    bridge-access 10

auto swp3
iface swp3
    alias ns1
    bridge-access 10

auto swp4
iface swp4
    alias rtr01 eth0 (office gateway)
    bridge-access 10

auto swp5
iface swp5
    alias rtr01 eth1 (server gateway)
    bridge-access 20

auto swp6
iface swp6
    alias srv01
    bridge-access 20

# Trunk to rtr01 eth3: VLAN 30 tagged (router-on-a-stick)
auto swp7
iface swp7
    alias rtr01 eth3 (trunk)
    bridge-vids 30

auto swp8
iface swp8
    alias dev01
    bridge-access 30

auto br0
iface br0
    bridge-vlan-aware yes
    bridge-ports swp1 swp2 swp3 swp4 swp5 swp6 swp7 swp8
    bridge-vids 10 20 30
    bridge-pvid 1
    bridge-stp yes
`;

export const RADVD_CONF = `# /etc/radvd.conf - IPv6 router advertisements (NET-40: IPv6 pilot on the dev VLAN)
interface eth3.30 {
    AdvSendAdvert on;
    MinRtrAdvInterval 30;
    MaxRtrAdvInterval 100;
    prefix 2001:db8:30::/64 {
        AdvOnLink on;
        AdvAutonomous on;
    };
};
`;

export const RTR01_INTERFACES = `# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# eth0: office LAN (sw01 swp4, VLAN 10 untagged)
auto eth0
iface eth0 inet static
    address 10.0.10.1/24

# eth1: server network (sw01 swp5, VLAN 20 untagged)
auto eth1
iface eth1 inet static
    address 10.0.20.1/24
iface eth1 inet6 static
    address 2001:db8:20::1/64

# eth2: Internet uplink
auto eth2
iface eth2 inet static
    address 203.0.113.2/24
    gateway 203.0.113.1

# eth3: trunk to sw01 swp7; VLAN 30 (development) as sub-interface eth3.30
auto eth3
iface eth3 inet manual

auto eth3.30
iface eth3.30 inet static
    address 10.0.30.1/24
iface eth3.30 inet6 static
    address 2001:db8:30::1/64
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
dev01   IN A    10.0.30.25
rtr01   IN A    10.0.10.1
ws01    IN A    10.0.10.25
srv01   IN A    10.0.20.10
srv01   IN AAAA 2001:db8:20::10
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
    wan: { id: 'wan', name: 'Internet uplink (documentation range TEST-NET-3)', cidr: '203.0.113.0/24' },
    dev30: { id: 'dev30', name: 'Development VLAN (IPv6 pilot)', cidr: '10.0.30.0/24', cidr6: '2001:db8:30::/64', vlan: 30 },
  };
  world.segments.srv20.cidr6 = '2001:db8:20::/64';
  // Cabling: every office and server NIC goes to a port of the switch sw01.
  world.links = [
    ['ws01', 'eth0', 'swp1'], ['ws02', 'eth0', 'swp2'], ['ns1', 'eth0', 'swp3'], ['rtr01', 'eth0', 'swp4'],
    ['rtr01', 'eth1', 'swp5'], ['srv01', 'eth0', 'swp6'], ['rtr01', 'eth3', 'swp7'], ['dev01', 'eth0', 'swp8'],
  ].map(([host, iface, port]) => ({ a: { host, iface }, b: { host: 'sw01', iface: port } }));
  const t = world.clock;

  // ---- sw01: VLAN-aware switch ----------------------------------------------
  const sw = createHost(world, {
    id: 'sw01', hostname: 'sw01', domain: 'corp.lab', role: 'Access switch (Linux bridge with VLAN filtering)', kind: 'switch',
    ifaces: Array.from({ length: 8 }, (_, k) => ({ name: `swp${k + 1}`, mac: `52:54:00:5e:00:${(k + 1).toString(16).padStart(2, '0')}`, segment: null })),
    services: [],
  });
  writeFile(sw, '/etc/network/interfaces', SW01_INTERFACES, t);
  writeFile(sw, '/etc/resolv.conf', '', t);

  // ---- rtr01 -------------------------------------------------------------
  const rtr = createHost(world, {
    id: 'rtr01', hostname: 'rtr01', domain: 'corp.lab', role: 'Router / inter-VLAN gateway', kind: 'router',
    ifaces: [
      { name: 'eth0', mac: '52:54:00:a1:00:01', segment: null },
      { name: 'eth1', mac: '52:54:00:a1:00:02', segment: null },
      { name: 'eth2', mac: '52:54:00:a1:00:03', segment: 'wan' },
      { name: 'eth3', mac: '52:54:00:a1:00:04', segment: null },
    ],
    services: ['nftables', 'radvd'],
  });
  writeFile(rtr, '/etc/network/interfaces', RTR01_INTERFACES, t);
  writeFile(rtr, '/etc/sysctl.d/99-router.conf', '# Enable IPv4 forwarding between eth0 (LAN) and eth1 (servers)\nnet.ipv4.ip_forward=1\n# IPv6 routing for the pilot (NET-40)\nnet.ipv6.conf.all.forwarding=1\n', t);
  writeFile(rtr, '/etc/radvd.conf', RADVD_CONF, t);
  writeFile(rtr, '/etc/nftables.conf', RTR01_NFT, t, { mode: 0o755 });
  writeFile(rtr, '/etc/resolv.conf', 'search corp.lab\nnameserver 10.0.10.53\n', t);

  // ---- ns1 ---------------------------------------------------------------
  const ns1 = createHost(world, {
    id: 'ns1', hostname: 'ns1', domain: 'corp.lab', role: 'DNS server (BIND 9, authoritative for corp.lab)',
    ifaces: [{ name: 'eth0', mac: '52:54:00:b2:00:35', segment: null }],
    services: ['nftables', 'named', 'dhcpd'],
  });
  writeFile(ns1, '/etc/dhcp/dhcpd.conf', DHCPD_CONF, t);
  writeFile(ns1, '/etc/default/isc-dhcp-server', '# Defaults for isc-dhcp-server (sourced by /etc/init.d/isc-dhcp-server)\n\n# On what interfaces should the DHCP server (dhcpd) serve DHCP requests?\nINTERFACESv4="eth0"\nINTERFACESv6=""\n', t);
  writeFile(ns1, '/var/lib/dhcp/dhcpd.leases', '# The format of this file is documented in the dhcpd.leases(5) manual page.\n# This lease file was written by isc-dhcp-4.4.3-P1\n\n', t);
  writeFile(ns1, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: '10.0.10.53/24', gateway: '10.0.10.1' }]), t);
  writeFile(ns1, '/etc/resolv.conf', 'search corp.lab\nnameserver 127.0.0.1\n', t);
  mkdir(ns1, '/etc/bind', t, { group: 'bind', mode: 0o2755 });
  writeFile(ns1, '/etc/bind/named.conf.local', NAMED_CONF_LOCAL, t, { group: 'bind' });
  writeFile(ns1, '/etc/bind/db.corp.lab', CORP_ZONE, t, { group: 'bind' });

  // ---- srv01 -------------------------------------------------------------
  const srv = createHost(world, {
    id: 'srv01', hostname: 'srv01', domain: 'corp.lab', role: 'Linux application server (sshd, nginx)',
    ifaces: [{ name: 'eth0', mac: '52:54:00:c3:00:0a', segment: null }],
    services: ['nftables', 'ssh', 'nginx'],
  });
  writeFile(srv, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: '10.0.20.10/24', gateway: '10.0.20.1' }]) + 'iface eth0 inet6 static\n    address 2001:db8:20::10/64\n    gateway 2001:db8:20::1\n', t);
  writeFile(srv, '/etc/resolv.conf', 'search corp.lab\nnameserver 10.0.10.53\n', t);
  writeFile(srv, '/etc/nftables.conf', SRV01_NFT, t, { mode: 0o755 });
  writeFile(srv, '/etc/ssh/sshd_config', DEBIAN_SSHD_CONFIG, t);
  writeFile(srv, '/etc/ssh/sshd_config.d/10-hardening.conf', HARDENING_CONF, t);
  installHostKeys(srv, t);
  mkdir(srv, '/etc/nginx', t);
  writeFile(srv, '/etc/nginx/nginx.conf', SRV01_NGINX_CONF, t);
  installSrv01Pki(srv, t);
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
    ifaces: [{ name: 'eth0', mac: '52:54:00:d4:00:19', segment: null }],
    services: ['nftables'],
  });
  writeFile(ws, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: '10.0.10.25/24', gateway: '10.0.10.1' }]), t);
  writeFile(ws, '/etc/resolv.conf', '# Generated for corp.lab\nsearch corp.lab\nnameserver 10.0.10.53\noptions timeout:2 attempts:2\n', t);
  addUser(ws, { name: 'alice', uid: 1000, gid: 1000, primaryGroup: 'alice', groups: ['sudo'], home: '/home/alice', shell: '/bin/bash', gecos: 'Alice Admin', password: 'ws01-alice' }, t);
  mkdir(ws, '/home/alice/.ssh', t, { mode: 0o700, owner: 'alice', group: 'alice' });
  const ak = aliceKey();
  writeFile(ws, '/home/alice/.ssh/id_ed25519', ak.privateFile, t, { mode: 0o600, owner: 'alice', group: 'alice' });
  writeFile(ws, '/home/alice/.ssh/id_ed25519.pub', ak.publicLine + '\n', t, { mode: 0o644, owner: 'alice', group: 'alice' });

  // ---- ws02: DHCP client laptop -------------------------------------------
  const ws2 = createHost(world, {
    id: 'ws02', hostname: 'ws02', domain: 'corp.lab', role: 'Laptop (DHCP client)',
    ifaces: [{ name: 'eth0', mac: '52:54:00:d4:00:42', segment: null }],
    services: ['nftables'],
  });
  writeFile(ws2, '/etc/network/interfaces', '# The primary network interface\nauto lo\niface lo inet loopback\n\nauto eth0\niface eth0 inet dhcp\n', t);
  writeFile(ws2, '/etc/resolv.conf', '', t);
  addUser(ws2, { name: 'dana', uid: 1000, gid: 1000, primaryGroup: 'dana', groups: ['sudo'], home: '/home/dana', shell: '/bin/bash', gecos: 'Dana Sales', password: 'ws02-dana' }, t);

  // ---- ext01: a host on the Internet ---------------------------------------
  const ext = createHost(world, {
    id: 'ext01', hostname: 'ext01', domain: 'example.net', role: 'Internet host (stands in for any server or client on the Internet)',
    ifaces: [{ name: 'eth0', mac: '52:54:00:f0:00:50', segment: 'wan' }],
    services: ['nftables', 'nginx'],
  });
  writeFile(ext, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: '203.0.113.80/24', gateway: '203.0.113.1' }]), t);
  writeFile(ext, '/etc/resolv.conf', '', t);
  writeFile(ext, '/etc/nginx/nginx.conf', EXT01_NGINX_CONF, t);
  installExt01Web(ext, t);
  addUser(ext, { name: 'guest', uid: 1000, gid: 1000, primaryGroup: 'guest', groups: [], home: '/home/guest', shell: '/bin/bash', gecos: 'Internet user', password: 'ext01-guest' }, t);

  // ---- dev01: developer workstation on VLAN 30 (dual-stack, SLAAC) ---------
  const dev = createHost(world, {
    id: 'dev01', hostname: 'dev01', domain: 'corp.lab', role: 'Developer workstation (VLAN 30, IPv4 + IPv6 SLAAC)',
    ifaces: [{ name: 'eth0', mac: '52:54:00:e7:00:1e', segment: null }],
    services: ['nftables'],
  });
  writeFile(dev, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: '10.0.30.25/24', gateway: '10.0.30.1' }]) + '# IPv6: stateless autoconfiguration from the router advertisements\niface eth0 inet6 auto\n', t);
  writeFile(dev, '/etc/resolv.conf', 'search corp.lab\nnameserver 10.0.10.53\n', t);
  addUser(dev, { name: 'erin', uid: 1000, gid: 1000, primaryGroup: 'erin', groups: ['sudo'], home: '/home/erin', shell: '/bin/bash', gecos: 'Erin Developer', password: 'dev01-erin' }, t);

  // The internal root CA is deployed to every corp.lab machine.
  for (const h of [rtr, ns1, srv, ws, ws2, dev]) trustCorpRoot(h, t);

  // Boot everything. Order matters: the switch first (it creates the VLANs),
  // ns1 must serve DHCP before ws02 boots, rtr01 must advertise before dev01.
  for (const h of [sw, rtr, ns1, srv, ws, ws2, ext, dev]) bootHost(world, h);

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
