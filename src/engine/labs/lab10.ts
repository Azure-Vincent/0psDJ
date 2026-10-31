// Lab 10: Network Logins with RADIUS. FreeRADIUS on rad01 and pam_radius_auth
// on rtr01 are installed with Debian's defaults. The learner connects them to
// Active Directory: the ldap module over LDAPS with the service account, a
// policy that admits Network-Admins only, rtr01 as a client with a strong
// secret (and the firewall opening), sshd on rtr01 asking RADIUS first with a
// local break-glass account, and a reboot test.

import { readFile, writeFile } from '../fs';
import { AD_ALICE_PASSWORD } from '../lab/winLab';
import { DANA_PASSWORD, RAD01_IP, RAD01_NFT, RADIUS_SVC, RTR01_LOCAL } from '../lab/identityLab';
import { buildSshLab } from '../lab/sshLab';
import { script } from '../scenarios/engine';
import { AUTHORIZE_FILE, CLIENTS_CONF, LDAP_MODULE, PAM_RADIUS_CONF, pamRadiusControl, pamRadiusServers, RADDB, radiusdCheck, type RadiusdLoaded } from '../sim/radius';
import type { World } from '../types';
import { NO, OK, printfTo, probe } from './engine';
import type { GuidedLab, LabCheck } from './types';

/** clients.conf as Debian 12 installs it (trimmed: the examples kept short). */
export const DEBIAN_CLIENTS_CONF = `# -*- text -*-
##
## clients.conf -- client configuration directives
##
##	$Id$

#######################################################################
#
#  Define RADIUS clients (usually a NAS, Access Point, etc.).

#
#  Defines a RADIUS client.
#
#  '127.0.0.1' is another name for 'localhost'.  It is enabled by default,
#  to allow testing of the server after an initial installation.  If you
#  are not going to be permitting RADIUS queries from localhost, we suggest
#  that you delete, or comment out, this entry.
#
client localhost {
	ipaddr = 127.0.0.1
	proto = *
	#  The shared secret use to "encrypt" and "sign" packets between
	#  the NAS and FreeRADIUS.  You MUST change this secret from the
	#  default, otherwise it's not a secret any more!
	#
	#  The secret can be any string, up to 8k characters in length.
	secret = testing123
	require_message_authenticator = no
	nas_type = other
}

# IPv6 Client
#client localhost_ipv6 {
#	ipv6addr	= ::1
#	secret		= testing123
#}

#client private-network-1 {
#	ipaddr		= 192.0.2.0/24
#	secret		= testing123-1
#}
`;

/** mods-available/ldap as Debian ships it (trimmed), not enabled. */
export const DEBIAN_LDAP_MODULE = `# -*- text -*-
#
#  $Id$

#
#  Lightweight Directory Access Protocol (LDAP)
#
ldap {
	#  Note that this needs to match the name(s) in the LDAP server
	#  certificate, if you're using ldaps.  See OpenLDAP documentation
	#  for the behavioral semantics of specifying more than one host.
	server = 'localhost'
#	server = 'ldap.rrdns.example.org'

	#  Port to connect on, defaults to 389, will be ignored for LDAP URIs.
#	port = 389

	#  Administrator account for searching and possibly modifying.
	#  If using SASL + KRB5 these should be commented out.
#	identity = 'cn=admin,dc=example,dc=org'
#	password = mypass

	#  Unless overridden in another section, the dn from which all
	#  searches will start from.
	base_dn = 'dc=example,dc=org'

	user {
		base_dn = "\${..base_dn}"
		filter = "(uid=%{%{Stripped-User-Name}:-%{User-Name}})"
	}

	group {
		base_dn = "\${..base_dn}"
		filter = '(objectClass=posixGroup)'
		membership_attribute = 'memberOf'
	}

	tls {
	#	ca_file = \${certdir}/cacert.pem
	#	require_cert = 'demand'
	}
}
`;

/** mods-config/files/authorize as Debian ships it (trimmed): only the old dial-up examples are active. */
export const DEBIAN_AUTHORIZE = `#
# 	Configuration file for the rlm_files module.
# 	Please see rlm_files(5) manpage for more information.
#
# 	This file contains authentication security and configuration
#	information for each user.  Accounting requests are NOT processed
#	through this file.  Instead, see 'accounting', in this directory.
#
#	The first field is the user's name and can be up to
#	253 characters in length.  This is followed (on the same line) with
#	the list of authentication requirements for that user.  This can
#	include password, comm server name, comm server port number, protocol
#	type (perhaps set by the "hints" file), and huntgroup name (set by
#	the "huntgroups" file).
#
#	If you are not sure why a particular reply is being sent by the
#	server, then run the server in debugging mode (radiusd -X), and
#	you will see which entries in this file are matched.
#
#	When an authentication request is received from the comm server,
#	these values are tested. Only the first match is used unless the
#	"Fall-Through" variable is set to "Yes".
#
#	A special user named "DEFAULT" matches on all usernames.
#
#bob	Cleartext-Password := "hello"
#	Reply-Message := "Hello, %{User-Name}"
#

#
# Default for PPP: dynamic IP address, PPP mode, VJ-compression.
#
DEFAULT	Framed-Protocol == PPP
	Framed-Protocol = PPP,
	Framed-Compression = Van-Jacobson-TCP-IP

DEFAULT	Hint == "SLIP"
	Framed-Protocol = SLIP
`;

/** /etc/pam_radius_auth.conf as libpam-radius-auth installs it: two example servers. */
export const DEBIAN_PAM_RADIUS_CONF = `#  pam_radius_auth configuration file.  Copy to: /etc/pam_radius_auth.conf
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
127.0.0.1	secret             1
other-server    other-secret       3
`;

/** rad01's firewall before the lab: SSH only. */
const RAD01_NFT_START = RAD01_NFT.replace('\t\t# RADIUS authentication from the NAS devices (CHG-2702)\n\t\tip saddr 10.0.20.1 udp dport 1812 accept\n', '');

export function buildLab10World(): World {
  const world = buildSshLab();
  const t = world.clock;
  const rad = world.hosts.rad01;
  const own = { owner: 'freerad', group: 'freerad' };
  writeFile(rad, CLIENTS_CONF, DEBIAN_CLIENTS_CONF, t, { mode: 0o640, ...own });
  writeFile(rad, `${RADDB}/mods-available/ldap`, DEBIAN_LDAP_MODULE, t, { mode: 0o640, ...own });
  delete rad.fs[LDAP_MODULE];
  writeFile(rad, AUTHORIZE_FILE, DEBIAN_AUTHORIZE, t, { mode: 0o640, ...own });
  writeFile(rad, '/etc/nftables.conf', RAD01_NFT_START, t, { mode: 0o755 });
  writeFile(rad, '/var/log/freeradius/radius.log', '', t, { mode: 0o640, ...own });
  const rtr = world.hosts.rtr01;
  writeFile(rtr, PAM_RADIUS_CONF, DEBIAN_PAM_RADIUS_CONF, t, { mode: 0o600 });
  const pam = readFile(rtr, '/etc/pam.d/sshd') ?? '';
  writeFile(rtr, '/etc/pam.d/sshd', pam.replace(/# RADIUS first[^\n]*\n[^\n]*\nauth +sufficient +pam_radius_auth\.so\n\n/, ''), t);
  script(world, 'rad01', ['nft -f /etc/nftables.conf', 'systemctl restart freeradius']);
  world.clock += 5 * 60_000;
  return world;
}

// ---------------------------------------------------------------- checks

const radtest = (user: string, password: string) => `radtest ${user} '${password}' localhost 0 testing123`;
const loaded = (w: World) => w.hosts.rad01.services.freeradius?.loaded as RadiusdLoaded | null;
const sshLogin = (w: World, user: string, password: string) => probe(w, 'ws01', 'alice', `sshpass -p '${password}' ssh -o StrictHostKeyChecking=accept-new ${user}@rtr01.corp.lab hostname`);

const ldapReady: LabCheck = {
  id: 'ldap-module', description: 'FreeRADIUS runs with the ldap module enabled: LDAPS to dc01.ad.corp.lab, bound as svc-radius, users found by sAMAccountName under DC=ad,DC=corp,DC=lab, certificate checked',
  check(w) {
    const c = radiusdCheck(w.hosts.rad01);
    if ('msg' in c) return NO(`freeradius -C fails: ${c.file}[${c.line}]: ${c.msg}`);
    if (!c.ldap) return NO(`${LDAP_MODULE} does not exist: enable the module (cp ${RADDB}/mods-available/ldap ${LDAP_MODULE}; Debian uses a symlink there).`);
    if (!/^ldaps:\/\/dc01\.ad\.corp\.lab/i.test(c.ldap.server)) return NO(`server = '${c.ldap.server}': use 'ldaps://dc01.ad.corp.lab' (the name in the DC's certificate; LDAPS so the password travels encrypted).`);
    if (c.ldap.identity.toLowerCase() !== RADIUS_SVC.dn.toLowerCase()) return NO(`identity is '${c.ldap.identity}': bind as the service account '${RADIUS_SVC.dn}'.`);
    if (c.ldap.baseDn.toLowerCase() !== 'dc=ad,dc=corp,dc=lab') return NO(`base_dn is '${c.ldap.baseDn}': the domain is DC=ad,DC=corp,DC=lab.`);
    if (!/samaccountname/i.test(c.ldap.userFilter)) return NO(`The user filter is ${c.ldap.userFilter}: Active Directory has no uid; users are found by sAMAccountName.`);
    if (c.ldap.requireCert !== 'demand' && c.ldap.requireCert !== 'hard') return NO('In the tls section, set require_cert = \'demand\' (and ca_file to the system bundle): without it the server would send svc-radius\'s password to anyone who answers on 636.');
    const l = loaded(w);
    if (!l?.ldap || l.ldap.server !== c.ldap.server || l.ldap.identity !== c.ldap.identity) return NO('The running server does not use this configuration yet: systemctl restart freeradius (and check radius.log).');
    const r = probe(w, 'rad01', 'root', radtest('alice', AD_ALICE_PASSWORD));
    if (!/Received Access-Accept/.test(r.output)) return NO(`radtest alice … on rad01 does not get an Access-Accept: ${r.output.trim().split('\n').pop()} (tail /var/log/freeradius/radius.log says why).`);
    return OK('radtest alice gets Access-Accept: the ldap module finds alice and checks her password by binding as her.');
  },
};

const policyReady: LabCheck = {
  id: 'policy', description: 'Only members of Network-Admins are accepted: alice gets Access-Accept, dana (right password, not a member) Access-Reject',
  check(w) {
    const a = probe(w, 'rad01', 'root', radtest('alice', AD_ALICE_PASSWORD));
    if (!/Received Access-Accept/.test(a.output)) return NO(`alice is not accepted: ${a.output.trim().split('\n').pop()}`);
    const d = probe(w, 'rad01', 'root', radtest('dana', DANA_PASSWORD));
    if (!/Received Access-Reject/.test(d.output)) return NO(`dana (not in Network-Admins) is ${/Accept/.test(d.output) ? 'accepted' : 'not answered'}: add a rule to ${AUTHORIZE_FILE} that accepts LDAP-Group == "Network-Admins" and rejects everyone else (DEFAULT Auth-Type := Reject), then systemctl reload freeradius.`);
    return OK('Members of Network-Admins get in; others with a valid password are rejected.');
  },
};

const clientReady: LabCheck = {
  id: 'client', description: 'rtr01 (10.0.20.1) is a client with its own strong secret (16+ characters), loaded by the running server; UDP 1812 is open to rtr01 only',
  check(w) {
    const l = loaded(w);
    const c = radiusdCheck(w.hosts.rad01);
    const conf = 'msg' in c ? null : c.clients.find((x) => x.ipaddr === '10.0.20.1' || x.ipaddr === '10.0.20.1/32');
    if (!conf) return NO(`clients.conf has no client for 10.0.20.1: rtr01 sends from its interface on the server VLAN (10.0.20.1), not from 10.0.10.1.`);
    if (conf.secret.length < 16 || /testing123|secret/i.test(conf.secret)) return NO('Give rtr01 a long random secret (16 characters or more), not an example value: the secret protects the passwords in every request.');
    if (!l?.clients.some((x) => x.ipaddr === conf.ipaddr && x.secret === conf.secret)) return NO('The running server does not know this client yet: clients.conf is read at start-up only, so systemctl restart freeradius (a reload is not enough).');
    const nft = readFile(w.hosts.rad01, '/etc/nftables.conf') ?? '';
    if (!/ip saddr 10\.0\.20\.1 udp dport (1812|\{[^}]*1812[^}]*\}) accept/.test(nft)) return NO('rad01\'s firewall does not let rtr01 in: add "ip saddr 10.0.20.1 udp dport 1812 accept" to /etc/nftables.conf and nft -f it.');
    const ws = probe(w, 'ws01', 'root', 'nc -zvu -w 2 rad01.corp.lab 1812');
    if (ws.code === 0 && /succeeded|open/.test(ws.output)) return NO('UDP 1812 is open to the office as well: allow rtr01 only.');
    return OK('rtr01 is a known client with a strong secret; the firewall admits it.');
  },
};

const nasReady: LabCheck = {
  id: 'nas', description: 'rtr01\'s sshd asks rad01 first (pam_radius_auth with the same secret, mode 600, no example servers): alice logs in with her AD password',
  check(w) {
    const rtr = w.hosts.rtr01;
    const servers = pamRadiusServers(rtr);
    if (servers.some((s) => s.host === '127.0.0.1' || s.host === 'other-server')) return NO('/etc/pam_radius_auth.conf still lists the example servers (127.0.0.1, other-server): each one costs a timeout on every login. Leave only rad01.');
    const srv = servers.find((s) => s.host === RAD01_IP || /^rad01(\.corp\.lab)?$/.test(s.host));
    if (!srv) return NO(`/etc/pam_radius_auth.conf has no line for rad01 (${RAD01_IP}  SECRET  3).`);
    const c = radiusdCheck(w.hosts.rad01);
    const client = 'msg' in c ? undefined : c.clients.find((x) => x.ipaddr.startsWith('10.0.20.1'));
    if (client && srv.secret !== client.secret) return NO('The secret in /etc/pam_radius_auth.conf differs from the one in rad01\'s clients.conf: they must be identical.');
    const mode = rtr.fs[PAM_RADIUS_CONF]?.mode ?? 0;
    if ((mode & 0o077) !== 0) return NO(`/etc/pam_radius_auth.conf has mode 0${(mode & 0o777).toString(8)}: chmod 600 (the secret lets anyone forge RADIUS answers).`);
    if (pamRadiusControl(rtr, 'sshd') !== 'sufficient') return NO('/etc/pam.d/sshd does not call pam_radius_auth: add "auth sufficient pam_radius_auth.so" before "@include common-auth".');
    const r = sshLogin(w, 'alice', AD_ALICE_PASSWORD);
    if (r.code !== 0 || !/^rtr01$/m.test(r.output)) return NO(`ssh alice@rtr01 with her AD password fails (journalctl -u ssh on rtr01, radius.log on rad01).`);
    return OK('alice logs in to rtr01 with her AD password.');
  },
};

const breakGlass: LabCheck = {
  id: 'break-glass', description: 'Tested: dana was refused on rtr01 through RADIUS, netadmin logged in while freeradius was stopped, and freeradius runs again',
  check(w) {
    const radLog = readFile(w.hosts.rad01, '/var/log/freeradius/radius.log') ?? '';
    if (!/Login incorrect[^\n]*: \[dana\] \(from client rtr01/.test(radLog)) return NO('radius.log on rad01 has no refused login of dana from rtr01 yet: try ssh dana@rtr01.corp.lab from ws01 with her AD password.');
    const j = w.hosts.rtr01.journal.filter((e) => e.unit === 'ssh.service').map((e) => e.message);
    const down = j.findIndex((m) => /pam_radius_auth: (RADIUS server \S+ failed to respond|All RADIUS servers failed to respond)/.test(m));
    if (down < 0 || !j.slice(down).some((m) => m.startsWith(`Accepted password for ${RTR01_LOCAL.user} `))) return NO(`No login of ${RTR01_LOCAL.user} while RADIUS was unreachable yet: stop freeradius on rad01, then ssh ${RTR01_LOCAL.user}@rtr01.corp.lab from ws01.`);
    if (w.hosts.rad01.services.freeradius?.state !== 'active') return NO('freeradius is still stopped on rad01: systemctl start freeradius.');
    if (sshLogin(w, 'dana', DANA_PASSWORD).code === 0) return NO('dana can log in to rtr01: the RADIUS policy must refuse users outside Network-Admins.');
    const off = structuredClone(w);
    script(off, 'rad01', ['systemctl stop freeradius']);
    if (sshLogin(off, 'alice', AD_ALICE_PASSWORD).code === 0) return NO('With RADIUS down, alice still logs in: she should only get in through RADIUS (no local password on rtr01).');
    if (sshLogin(off, RTR01_LOCAL.user, RTR01_LOCAL.password).code !== 0) return NO(`With freeradius stopped, ${RTR01_LOCAL.user} cannot log in to rtr01: pam_radius_auth must be "sufficient" (not required), so the local password still works.`);
    return OK('Refusal and break-glass tested; RADIUS runs again.');
  },
};

// ---------------------------------------------------------------- the lab

const SECRET = 'Rtr01-Lab10-9xQe4LmZ';
const LDAP_DONE = `# rlm_ldap: users and groups from Active Directory on dc01 (CHG-2702)
ldap {
	server = 'ldaps://dc01.ad.corp.lab'
	port = 636
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
		ca_file = /etc/ssl/certs/ca-certificates.crt
		require_cert = 'demand'
	}
}
`;
const AUTHORIZE_DONE = `# Network devices: only members of the AD group Network-Admins (CHG-2702).
DEFAULT	LDAP-Group == "Network-Admins"
	Reply-Message := "Welcome, %{User-Name}"

DEFAULT	Auth-Type := Reject
	Reply-Message := "Not a member of Network-Admins"
`;
const CLIENT_DONE = `
# rtr01: SSH logins of the network administrators (CHG-2702); it sends from 10.0.20.1.
client rtr01 {
	ipaddr = 10.0.20.1
	secret = ${SECRET}
	shortname = rtr01
}
`;

export const LAB10: GuidedLab = {
  id: 'lab10',
  title: 'Lab 10: Network Logins with RADIUS',
  level: 'intermediate',
  duration: '60–90 min',
  summary: 'Connect FreeRADIUS to Active Directory over LDAPS with a service account, admit only one AD group, register the router as a RADIUS client with a strong secret, make the router\'s sshd ask RADIUS with a local break-glass account, and test that it all survives a reboot.',
  brief: `Network administrators log in to every router and switch with a local password that nobody has changed in years. From now on they log in with their **Active Directory** account, and only members of **Network-Admins** may (CHG-2702). Start with **rtr01**.

- **rad01** (${RAD01_IP}) has **FreeRADIUS 3.2** installed with Debian's default configuration. The AD team created the service account **svc-radius** (\`${RADIUS_SVC.dn}\`, password \`${RADIUS_SVC.password}\`), read-only.
- Connect FreeRADIUS to AD with the **ldap module**: LDAPS to dc01.ad.corp.lab, certificate checked (the corp root CA is installed on rad01).
- Accept members of **Network-Admins** (alice) and **reject everyone else**, even with a valid password (dana).
- Register **rtr01** as a RADIUS client with its own long random secret. Its requests come from **10.0.20.1**. Open UDP 1812 to rtr01 only.
- On **rtr01**, \`libpam-radius-auth\` is installed: sshd must ask rad01 first. The local account **${RTR01_LOCAL.user}** (password \`${RTR01_LOCAL.password}\`) must keep working when rad01 is down.

Test with \`radtest USER PASSWORD localhost 0 testing123\` on rad01 before you involve the router: every failed login through RADIUS is a failed password in AD, and five lock the account.`,
  objectives: [
    'Read an LDAP module configuration: server URI, bind identity, base DN, user filter, TLS settings.',
    'Tell authentication (is the password right?) from authorisation (may this user log in here?).',
    'Register a RADIUS client: its source address, a strong shared secret, and why a restart is needed.',
    'Configure a NAS (pam_radius_auth) and a PAM stack with a break-glass fallback.',
    'Test RADIUS without locking accounts: radtest, radius.log, the NAS\'s journal.',
  ],
  prerequisites: [
    { label: 'TLS and certificates', link: 'lesson/tls/what' },
    { label: 'Active Directory domain', link: 'lesson/domain/what' },
    { label: 'Directory services and RADIUS', link: 'lesson/identity/what' },
  ],
  setupNote: `**rad01** (${RAD01_IP}, sw01 port swp22) runs FreeRADIUS with Debian's defaults (only the localhost client, the ldap module not enabled). **dc01** is the domain controller (LDAPS for dc01.ad.corp.lab). **rtr01** runs sshd; pam_radius_auth is installed but not used yet.`,
  terminals: [
    { hostId: 'rad01', user: 'root', label: 'rad01 console (root)', banner: 'rad01: FreeRADIUS in /etc/freeradius/3.0. Try: ls mods-available mods-enabled, freeradius -XC, radtest alice PASSWORD localhost 0 testing123, tail -f is not available: tail -n 20 /var/log/freeradius/radius.log.' },
    { hostId: 'rtr01', user: 'root', label: 'rtr01 (router, the NAS)', banner: 'rtr01: sshd with PAM. Try: cat /etc/pam.d/sshd /etc/pam_radius_auth.conf, journalctl -u ssh -n 20.' },
    { hostId: 'dc01', user: 'Administrator', label: 'dc01 (domain controller)', banner: 'dc01: Active Directory. Try: Get-ADGroupMember Network-Admins, Get-ADUser svc-radius, Get-ADUser alice -Properties LockedOut,BadLogonCount.' },
  ],
  build: buildLab10World,
  steps: [
    {
      id: 'ldap', title: 'Connect FreeRADIUS to Active Directory',
      objective: 'Enable and configure the ldap module so FreeRADIUS finds users in AD over LDAPS as svc-radius and checks their passwords; radtest alice gets Access-Accept.',
      background: 'FreeRADIUS does not store the users here: its **ldap module** asks the directory. For each request it binds as a **service account** (identity/password), **searches** for the user (base_dn and a filter: in AD the login name is **sAMAccountName**, not uid), then checks the password by **binding as the user** with it.\n\nModules live in **mods-available**; only those in **mods-enabled** are loaded (Debian links them). The connection must be **LDAPS**: the service password and every user\'s password cross it. `server` must be the name in the DC\'s certificate, and `require_cert = \'demand\'` makes the module refuse a certificate it cannot verify.',
      tasks: [
        `Check the directory from rad01 first: \`ldapwhoami -x -H ldaps://dc01.ad.corp.lab -D '${RADIUS_SVC.dn}' -w '${RADIUS_SVC.password}'\`.`,
        `Enable the module: \`cp ${RADDB}/mods-available/ldap ${LDAP_MODULE}\` (on a real system: \`ln -s ../mods-available/ldap\` in mods-enabled), then edit it: server = 'ldaps://dc01.ad.corp.lab', port = 636, identity and password of svc-radius, base_dn = 'DC=ad,DC=corp,DC=lab', the user filter on sAMAccountName, the group filter (objectClass=group), and in tls: ca_file = /etc/ssl/certs/ca-certificates.crt, require_cert = 'demand'.`,
        '`freeradius -XC` (configuration check), `systemctl restart freeradius`, then `radtest alice \'' + AD_ALICE_PASSWORD + '\' localhost 0 testing123`.',
      ],
      hints: ['"Can\'t contact LDAP server" in radius.log: the URI, the name or the CA file.', '"Invalid credentials … data 52e" for the service bind: identity or password. For the user bind: alice\'s password.'],
      checks: [ldapReady],
      solution: [{ host: 'rad01', user: 'root', commands: [printfTo(LDAP_DONE, LDAP_MODULE), 'freeradius -XC', 'systemctl restart freeradius'] }],
      learn: [{ label: 'LDAP binds and searches', link: 'lesson/identity/internals' }, { label: 'mods-enabled/ldap', link: 'reference?id=file:freeradius-ldap' }],
      concepts: ['id.ldap', 'id.radius'],
    },
    {
      id: 'policy', title: 'Only Network-Admins',
      objective: 'Add a policy to the files module: members of Network-Admins are accepted, everyone else is rejected even with the right password.',
      background: 'Right now **anyone** with an AD password could log in to the router: the ldap module **authenticates** (the password is right) but nothing **authorises** (may this person log in here?).\n\nThe files module reads **mods-config/files/authorize**: entries of a user name (or DEFAULT) with check items, followed by indented reply items. The first matching entry decides. With the ldap module loaded, `LDAP-Group == "Network-Admins"` compares against the user\'s group membership (memberOf). An entry with `Auth-Type := Reject` refuses the request, and **Reply-Message** tells the user why.',
      tasks: [
        'Read the active entries in /etc/freeradius/3.0/mods-config/files/authorize (only old dial-up examples are active).',
        'Add at the top: `DEFAULT LDAP-Group == "Network-Admins"` with a Reply-Message, then `DEFAULT Auth-Type := Reject` with Reply-Message "Not a member of Network-Admins".',
        '`freeradius -XC`, `systemctl reload freeradius` (modules are re-read on a reload), then radtest alice (Accept) and radtest dana \'' + DANA_PASSWORD + '\' (Reject, with the message).',
      ],
      hints: ['Check items go on the first line, reply items on the indented lines below it.', 'The order matters: the group rule must come before the default reject.'],
      checks: [policyReady],
      solution: [{ host: 'rad01', user: 'root', commands: [printfTo(AUTHORIZE_DONE, AUTHORIZE_FILE), 'freeradius -XC', 'systemctl reload freeradius'] }],
      learn: [{ label: 'Authentication and authorisation', link: 'lesson/identity/config' }],
      concepts: ['id.radius'],
    },
    {
      id: 'client', title: 'Register rtr01 as a client',
      objective: 'Add rtr01 (10.0.20.1) to clients.conf with a long random secret, restart FreeRADIUS, and open UDP 1812 to rtr01 only.',
      background: 'A RADIUS server answers only its **clients** (the NAS devices), recognised by the **source address** of the request. rtr01 reaches rad01 through its interface on the server VLAN, so its requests come from **10.0.20.1**, not from 10.0.10.1 (the address its DNS name points to).\n\nEach client has a **shared secret**: it hides the password in the request (MD5-based) and authenticates the reply (Response Authenticator). A short or default secret makes captured requests crackable. FreeRADIUS reads **clients.conf only at start-up**: after changing it, **restart** (a reload only re-reads the modules).',
      tasks: [
        'Generate a secret, e.g. `openssl rand -base64 18`, and keep it for the next step.',
        'Add a `client rtr01 { ipaddr = 10.0.20.1  secret = …  shortname = rtr01 }` section to /etc/freeradius/3.0/clients.conf; `freeradius -XC`; `systemctl restart freeradius`.',
        'Add `ip saddr 10.0.20.1 udp dport 1812 accept` to /etc/nftables.conf on rad01 and load it (`nft -f /etc/nftables.conf`).',
      ],
      hints: ['After a reload instead of a restart, radius.log shows "Ignoring request … from unknown client 10.0.20.1".'],
      checks: [clientReady],
      solution: [{ host: 'rad01', user: 'root', commands: [printfTo(CLIENT_DONE, CLIENTS_CONF, true), 'systemctl restart freeradius', printfTo(RAD01_NFT, '/etc/nftables.conf'), 'nft -f /etc/nftables.conf'] }],
      learn: [{ label: 'RADIUS clients and secrets', link: 'lesson/identity/internals' }, { label: 'clients.conf', link: 'reference?id=file:clients-conf' }],
      concepts: ['id.radius', 'fw.path'],
    },
    {
      id: 'nas', title: 'rtr01 asks RADIUS',
      objective: 'Configure pam_radius_auth on rtr01 (rad01 with the shared secret, nothing else, mode 600) and put it before common-auth in /etc/pam.d/sshd as "sufficient"; alice logs in with her AD password.',
      background: 'The router is the **NAS**: it receives the password over SSH and asks the RADIUS server. On Linux this is **pam_radius_auth**: /etc/pam_radius_auth.conf lists the servers (`server[:port] secret timeout`), tried in order, each that does not answer costing its timeout.\n\nIn **/etc/pam.d/sshd**, `auth sufficient pam_radius_auth.so` before `@include common-auth` means: if RADIUS says yes, the login succeeds; if it says no or does not answer, PAM goes on to the local passwords (pam_unix). That keeps a **break-glass** account working when RADIUS is down. The RADIUS users need a local account (without a password) so sshd knows their uid and home: alice and dana have one.',
      tasks: [
        `Edit /etc/pam_radius_auth.conf: comment out the two example servers and add \`${RAD01_IP}  SECRET  3\` with the secret from clients.conf; check \`ls -l /etc/pam_radius_auth.conf\` (600).`,
        'In /etc/pam.d/sshd add `auth sufficient pam_radius_auth.so` just before `@include common-auth`.',
        'From ws01: `ssh alice@rtr01.corp.lab` with her AD password. Then read `journalctl -u ssh -n 5` on rtr01 and radius.log on rad01 ("Login OK").',
      ],
      hints: ['"failed verification: The shared secret is probably incorrect": the secrets differ.', '"RADIUS server … failed to respond": the client entry, the firewall, or the restart.', 'Every failed attempt counts against alice in AD; if she is locked out: Unlock-ADAccount alice on dc01.'],
      checks: [nasReady],
      solution: [{ host: 'rtr01', user: 'root', commands: [`sed -i 's/^127.0.0.1\\tsecret/#127.0.0.1\\tsecret/; s/^other-server/#other-server/' ${PAM_RADIUS_CONF}`, `printf '${RAD01_IP}\\t${SECRET}\\t3\\n' >> ${PAM_RADIUS_CONF}`, "sed -i 's/^@include common-auth$/auth       sufficient   pam_radius_auth.so\\n@include common-auth/' /etc/pam.d/sshd"] }],
      learn: [{ label: 'pam_radius_auth', link: 'reference?id=file:pam-radius-auth-conf' }, { label: 'The PAM stack', link: 'lesson/identity/config' }],
      concepts: ['id.radius'],
    },
    {
      id: 'break-glass', title: 'Test refusal and break-glass',
      objective: 'Confirm that dana (valid password, not a member) is refused on rtr01, and that netadmin still logs in while freeradius is stopped; then start it again.',
      background: 'A central login is a single point of failure. Before relying on it, test both directions: the people who must **not** get in are refused, and when the RADIUS server is down the **local break-glass account** still works (with its password kept in a safe, and its use alerted on). Also check that RADIUS users have **no** local password, so they cannot bypass the policy.',
      tasks: [
        'From ws01: `ssh dana@rtr01.corp.lab` with her AD password: refused ("Not a member of Network-Admins" in radius.log).',
        `On rad01: \`systemctl stop freeradius\`; from ws01: \`ssh ${RTR01_LOCAL.user}@rtr01.corp.lab\` (password ${RTR01_LOCAL.password}): it works after the RADIUS timeout. Then \`systemctl start freeradius\`.`,
      ],
      hints: ['If netadmin is refused with RADIUS down, pam_radius_auth is "required" instead of "sufficient".'],
      checks: [breakGlass],
      solution: [
        { host: 'ws01', user: 'alice', commands: [`sshpass -p '${DANA_PASSWORD}' ssh -o StrictHostKeyChecking=accept-new dana@rtr01.corp.lab hostname`] },
        { host: 'rad01', user: 'root', commands: ['systemctl stop freeradius'] },
        { host: 'ws01', user: 'alice', commands: [`sshpass -p '${RTR01_LOCAL.password}' ssh -o StrictHostKeyChecking=accept-new ${RTR01_LOCAL.user}@rtr01.corp.lab hostname`] },
        { host: 'rad01', user: 'root', commands: ['systemctl start freeradius'] },
      ],
      learn: [{ label: 'Operating central authentication', link: 'lesson/identity/operate' }],
      concepts: ['id.radius'],
    },
    {
      id: 'reboot', title: 'Reboot test',
      objective: 'Every check of the earlier steps still passes after all machines restart.',
      background: 'FreeRADIUS reads its files at start, the firewall loads /etc/nftables.conf at boot, and PAM reads its files at every login. Anything only changed at runtime (nft add rule) is gone after a restart.',
      tasks: ['Run the check: it reboots every host on a copy of the lab and runs all checks again.'],
      hints: ['A failing client check after the reboot usually means the firewall rule was added with nft add rule only.'],
      checks: [],
      solution: [],
      learn: [{ label: 'Directory services and RADIUS', link: 'lesson/identity/operate' }],
      concepts: ['id.radius'],
      afterReboot: true,
    },
  ],
};
