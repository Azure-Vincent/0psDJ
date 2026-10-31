// Directory services in the lab: dc01 answers LDAP and LDAPS (its certificate
// is issued by Corp Lab Issuing CA 1), with a read-only service account for
// applications (svc-ldap) and the group Network-Admins whose members may log
// in to network devices. Linux hosts that query AD get ldap-utils with
// /etc/ldap/ldap.conf pointing at dc01 over LDAPS.

import { mkdir, readFile, writeFile } from '../fs';
import { CORP_ISSUING, issueServerCert } from '../sim/pki';
import { AUTHORIZE_FILE, CLIENTS_CONF, LDAP_MODULE, PAM_RADIUS_CONF, RADDB } from '../sim/radius';
import { installUnits } from '../sim/units';
import type { Host, World } from '../types';
import { domainDn } from '../win/ad';
import { addUser, createHost, staticInterfaces } from './builder';
import { TIMESYNCD_CONF } from './krbLab';
import { installRsyslog } from './logLab';
import { trustCorpRoot } from './pkiLab';
import { DEBIAN_SSHD_CONFIG, installHostKeys } from './sshLab';

export const LDAP_SVC = { sam: 'svc-ldap', password: 'Svc-Ldap-2026!', dn: 'CN=svc-ldap,OU=Service Accounts,DC=ad,DC=corp,DC=lab' };
export const RADIUS_SVC = { sam: 'svc-radius', password: 'Svc-Radius-2026!', dn: 'CN=svc-radius,OU=Service Accounts,DC=ad,DC=corp,DC=lab' };
export const NETWORK_ADMINS = 'Network-Admins';

export const LDAP_CONF = `#
# LDAP Defaults
#

# See ldap.conf(5) for details
# This file should be world readable but not world writable.

# corp.lab: Active Directory on dc01 over LDAPS (CHG-2701)
BASE	DC=ad,DC=corp,DC=lab
URI	ldaps://dc01.ad.corp.lab

#SIZELIMIT	12
#TIMELIMIT	15
#DEREF		never

# TLS certificates (needed for GnuTLS)
TLS_CACERT	/etc/ssl/certs/ca-certificates.crt
`;

/** dc01: the LDAPS certificate and the directory objects applications use. */
export function installDirectory(world: World): void {
  const dc = world.hosts.dc01;
  const ad = dc.win?.ad;
  if (!ad) return;
  const fq = `${dc.hostname}.${ad.domain}`;
  const leaf = issueServerCert(CORP_ISSUING, [fq, ad.domain, dc.hostname], `ldaps-${dc.hostname}`, '2026-03-02T09:00:00Z', 730);
  dc.win!.certificates = [{ cert: leaf.cert, chain: [CORP_ISSUING.cert], hasKey: true }];
  const base = domainDn(ad.domain);
  const ouDn = `OU=Service Accounts,${base}`;
  ad.ous = ad.ous ?? {};
  ad.ous[ouDn.toLowerCase()] = { dn: ouDn, name: 'Service Accounts', description: 'Accounts used by applications (CHG-2701)', blockInheritance: false, protected: true };
  const svc = (sam: string, password: string, description: string) => {
    ad.users[sam] = { sam, name: sam, enabled: true, password, lockedOut: false, badCount: 0, description, rid: ad.nextRid++, ou: ouDn };
  };
  svc(LDAP_SVC.sam, LDAP_SVC.password, 'Read-only LDAP lookups for the intranet phone book (CHG-2701)');
  svc(RADIUS_SVC.sam, RADIUS_SVC.password, 'FreeRADIUS on rad01: looks up users and groups (CHG-2702)');
  ad.users.dana = { sam: 'dana', name: 'Dana Weber', enabled: true, password: DANA_PASSWORD, lockedOut: false, badCount: 0, description: 'Office, sales', rid: ad.nextRid++ };
  ad.groups['network-admins'] = { name: NETWORK_ADMINS, scope: 'Global', category: 'Security', description: 'May log in to routers and switches (RADIUS, CHG-2702)', members: ['alice'], rid: ad.nextRid++ };
}

/** ldap-utils on a Linux host, configured for AD over LDAPS. */
export function installLdapClient(host: Host, t: number): void {
  if (!host.fs['/etc/ldap']) mkdir(host, '/etc/ldap', t);
  writeFile(host, '/etc/ldap/ldap.conf', LDAP_CONF, t);
}

export const PHONEBOOK = '/usr/local/bin/phonebook';
export const PHONEBOOK_PW = '/etc/phonebook/bind.pw';
export const PHONEBOOK_SCRIPT = `#!/bin/sh
# phonebook NAME: the intranet phone book's lookup in Active Directory (CHG-2701).
# Binds as the read-only service account; server and CA come from /etc/ldap/ldap.conf.
ldapsearch -x -LLL -D "${LDAP_SVC.dn}" -y ${PHONEBOOK_PW} "(sAMAccountName=$1)" displayName mail
`;

/** srv01's phone book: a script that looks people up in AD as svc-ldap. */
export function installPhonebook(host: Host, t: number): void {
  mkdir(host, '/etc/phonebook', t, { mode: 0o750 });
  writeFile(host, PHONEBOOK_PW, LDAP_SVC.password, t, { mode: 0o640 });
  writeFile(host, PHONEBOOK, PHONEBOOK_SCRIPT, t, { mode: 0o755 });
}

// ---------------------------------------------------------------------------
// RADIUS: rad01 (10.0.20.65, switch port swp22) runs FreeRADIUS against AD;
// rtr01's sshd asks it through pam_radius_auth (CHG-2702).
// ---------------------------------------------------------------------------

export const RAD01_IP = '10.0.20.65';
export const RAD01_PASSWORDS = { alice: 'rad01-alice' };
/** The shared secret between rtr01 (the NAS) and rad01. */
export const RTR01_RADIUS_SECRET = 'Rtr01-Nas-Secret-2702';
/** rtr01's local break-glass account, for when RADIUS is down. */
export const RTR01_LOCAL = { user: 'netadmin', password: 'Rtr01-Breakglass-26' };
/** Passwords of the AD users the RADIUS logins use. */
export const DANA_PASSWORD = 'Sales-Corp-2026';

export const RADIUSD_CONF = `# -*- text -*-
##
## radiusd.conf	-- FreeRADIUS server configuration file (trimmed: Debian 12, 3.2.1).
##
prefix = /usr
exec_prefix = /usr
sysconfdir = /etc
localstatedir = /var
logdir = /var/log/freeradius
raddbdir = /etc/freeradius/3.0
radacctdir = \${logdir}/radacct

name = freeradius

log {
	destination = files
	file = \${logdir}/radius.log
	# Log authentication requests ("Login OK" / "Login incorrect")
	auth = yes
	auth_badpass = no
	auth_goodpass = no
}

security {
	user = freerad
	group = freerad
	allow_core_dumps = no
	max_attributes = 200
	reject_delay = 1
	status_server = yes
}

# Clients (NAS devices) are read at start-up only: restart after editing.
$INCLUDE clients.conf

modules {
	$INCLUDE mods-enabled/
}

instantiate {
}

policy {
	$INCLUDE policy.d/
}

$INCLUDE sites-enabled/
`;

export const CLIENTS_CONF_TEXT = `# -*- text -*-
##
## clients.conf -- client configuration directives
##
##	Define RADIUS clients (usually a NAS, Access Point, etc.).
##	Each client needs an address and the shared secret it uses.
##	Changes take effect at the next restart (systemctl restart freeradius).

#  Defines a RADIUS client: for radtest on this server.
client localhost {
	ipaddr = 127.0.0.1
	proto = *
	secret = testing123
	require_message_authenticator = no
	nas_type = other
}

# rtr01: SSH logins of the network administrators (CHG-2702).
# Its requests come from the address of its server-VLAN interface.
client rtr01 {
	ipaddr = 10.0.20.1
	secret = ${RTR01_RADIUS_SECRET}
	shortname = rtr01
	nas_type = other
}
`;

export const LDAP_MODULE_TEXT = `# -*- text -*-
##
##  rlm_ldap: users and groups from Active Directory on dc01 (CHG-2702).
##  (mods-enabled/ldap; Debian links it to mods-available/ldap)
ldap {
	server = 'ldaps://dc01.ad.corp.lab'
	port = 636

	# Read-only service account for the lookups
	identity = '${RADIUS_SVC.dn}'
	password = '${RADIUS_SVC.password}'

	base_dn = 'DC=ad,DC=corp,DC=lab'

	user {
		base_dn = "\${..base_dn}"
		filter = "(sAMAccountName=%{%{Stripped-User-Name}:-%{User-Name}})"
	}

	group {
		base_dn = "\${..base_dn}"
		filter = '(objectClass=group)'
		membership_attribute = 'memberOf'
	}

	tls {
		# The corp.lab root CA is in the system bundle (CHG-2701)
		ca_file = /etc/ssl/certs/ca-certificates.crt
		require_cert = 'demand'
	}

	pool {
		start = 0
		min = 0
		max = \${thread[pool].max_servers}
	}
}
`;

export const AUTHORIZE_TEXT = `#
# 	Configuration file for the rlm_files module.
# 	Please see rlm_files(5) manpage for more information.
#
#	The first entry that matches decides (unless it says Fall-Through = Yes).
#
# Network devices: only members of the AD group Network-Admins (CHG-2702).
DEFAULT	LDAP-Group == "Network-Admins"
	Reply-Message := "Welcome to the corp.lab network, %{User-Name}"

DEFAULT	Auth-Type := Reject
	Reply-Message := "Not a member of Network-Admins"
`;

export const PAM_RADIUS_CONF_TEXT = `#  pam_radius_auth configuration file.  Copy to: /etc/pam_radius_auth.conf
#
#  For proper security, this file SHOULD have permissions 0600,
#  that is readable by root, and NO ONE else.  If anyone other than
#  root can read this file, then they can spoof responses from the server!
#
#  There are 3 fields per line in this file.  There may be multiple
#  lines.  Blank lines or lines beginning with '#' are treated as
#  comments, and are ignored.  The fields are:
#
#  server[:port] secret [timeout]
#
#  the port name or number is optional.  The default port name is
#  "radius", and is looked up from /etc/services The timeout field is
#  optional.  The default timeout is 3 seconds.
#
#  If multiple RADIUS server lines exist, they are tried in order.  The
#  first server to return success or failure causes the module to return
#  success or failure.  Only if a server fails to response is it skipped,
#  and the next server in turn is used.
#
# server[:port]	shared_secret      timeout (s)
#127.0.0.1	secret             1
#other-server    other-secret       3

# rad01 (CHG-2702)
${RAD01_IP}	${RTR01_RADIUS_SECRET}	3
`;

export const RAD01_NFT = `#!/usr/sbin/nft -f

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iif "lo" accept
		meta l4proto icmp accept
		tcp dport 22 accept
		# RADIUS authentication from the NAS devices (CHG-2702)
		ip saddr 10.0.20.1 udp dport 1812 accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

const addService = (host: Host, name: string) => { host.services[name] ??= { state: 'inactive', enabled: true, since: 0, pid: null, loaded: null, result: 'success' }; };

/** rad01 with FreeRADIUS, and pam_radius_auth for sshd on rtr01 (before the lab boots). */
export function installRadius(world: World): Host {
  const t = world.clock;
  const h = createHost(world, {
    id: 'rad01', hostname: 'rad01', domain: 'corp.lab', role: 'RADIUS server (FreeRADIUS, users from Active Directory)',
    ifaces: [{ name: 'eth0', mac: '52:54:00:30:00:41', segment: null }],
    services: ['rsyslog', 'systemd-timesyncd', 'nftables', 'ssh', 'freeradius'],
  });
  writeFile(h, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: `${RAD01_IP}/24`, gateway: '10.0.20.1' }]), t);
  writeFile(h, '/etc/resolv.conf', 'search corp.lab\nnameserver 10.0.10.53\n', t);
  writeFile(h, '/etc/ssh/sshd_config', DEBIAN_SSHD_CONFIG, t);
  writeFile(h, '/etc/nftables.conf', RAD01_NFT, t, { mode: 0o755 });
  mkdir(h, '/etc/systemd', t);
  writeFile(h, '/etc/systemd/timesyncd.conf', TIMESYNCD_CONF, t);
  installHostKeys(h, t);
  trustCorpRoot(h, t);
  installRsyslog(h, t, true);
  addUser(h, { name: 'alice', uid: 1000, gid: 1000, primaryGroup: 'alice', groups: ['sudo', 'adm'], home: '/home/alice', shell: '/bin/bash', gecos: 'Alice Admin', password: RAD01_PASSWORDS.alice }, t);
  addUser(h, { name: 'freerad', uid: 111, gid: 119, primaryGroup: 'freerad', groups: [], home: '/etc/freeradius', shell: '/usr/sbin/nologin', gecos: '', password: null }, t, false);
  installLdapClient(h, t);
  const own = { owner: 'freerad', group: 'freerad' };
  for (const d of ['/etc/freeradius', RADDB, `${RADDB}/mods-available`, `${RADDB}/mods-enabled`, `${RADDB}/mods-config`, `${RADDB}/mods-config/files`, `${RADDB}/sites-enabled`, `${RADDB}/policy.d`]) mkdir(h, d, t, { mode: 0o755, ...own });
  mkdir(h, '/var/log/freeradius', t, { mode: 0o750, ...own });
  writeFile(h, `${RADDB}/radiusd.conf`, RADIUSD_CONF, t, { mode: 0o640, ...own });
  writeFile(h, CLIENTS_CONF, CLIENTS_CONF_TEXT, t, { mode: 0o640, ...own });
  writeFile(h, `${RADDB}/mods-available/ldap`, LDAP_MODULE_TEXT, t, { mode: 0o640, ...own });
  writeFile(h, LDAP_MODULE, LDAP_MODULE_TEXT, t, { mode: 0o640, ...own });
  writeFile(h, AUTHORIZE_FILE, AUTHORIZE_TEXT, t, { mode: 0o640, ...own });
  writeFile(h, '/var/log/freeradius/radius.log', '', t, { mode: 0o640, ...own });

  // rtr01: sshd for the administrators, asking RADIUS first.
  const rtr = world.hosts.rtr01;
  addService(rtr, 'ssh');
  installUnits(rtr, t);
  if (!rtr.fs['/etc/ssh']) mkdir(rtr, '/etc/ssh', t);
  writeFile(rtr, '/etc/ssh/sshd_config', DEBIAN_SSHD_CONFIG, t);
  installHostKeys(rtr, t);
  const pam = readFile(rtr, '/etc/pam.d/sshd') ?? '';
  writeFile(rtr, '/etc/pam.d/sshd', pam.replace('# Standard Un*x authentication.\n@include common-auth', '# RADIUS first (rad01, CHG-2702); if it rejects or is unreachable, the local\n# accounts below still work (break-glass).\nauth       sufficient   pam_radius_auth.so\n\n# Standard Un*x authentication.\n@include common-auth'), t);
  writeFile(rtr, PAM_RADIUS_CONF, PAM_RADIUS_CONF_TEXT, t, { mode: 0o600 });
  // RADIUS users need a local account (no local password); netadmin is the break-glass login.
  addUser(rtr, { name: 'alice', uid: 1000, gid: 1000, primaryGroup: 'alice', groups: ['sudo'], home: '/home/alice', shell: '/bin/bash', gecos: 'Alice Martin (RADIUS)', password: null }, t);
  addUser(rtr, { name: 'dana', uid: 1001, gid: 1001, primaryGroup: 'dana', groups: [], home: '/home/dana', shell: '/bin/bash', gecos: 'Dana Weber (RADIUS)', password: null }, t);
  addUser(rtr, { name: RTR01_LOCAL.user, uid: 1002, gid: 1002, primaryGroup: RTR01_LOCAL.user, groups: ['sudo'], home: `/home/${RTR01_LOCAL.user}`, shell: '/bin/bash', gecos: 'Local break-glass account', password: RTR01_LOCAL.password }, t);
  return h;
}
