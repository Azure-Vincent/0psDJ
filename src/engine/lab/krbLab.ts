// The Kerberos realm CORP.LAB: an MIT KDC and admin server on ns1, found by
// clients through DNS SRV records; krb5.conf and time synchronisation on every
// corp.lab machine; a host keytab on srv01.

import { deriveKey, ENCTYPES, formatKeytab, formatPrincipalDb, newPrincipal, type PrincipalEntry } from '../config/krb5';
import { mkdir, writeFile } from '../fs';
import type { Host, World } from '../types';

export const REALM = 'CORP.LAB';
export const ALICE_KRB_PASSWORD = 'Corp-Lab-2026';
export const ALICE_ADMIN_PASSWORD = 'Corp-Admin-2026';
export const BOB_KRB_PASSWORD = 'Summer2026!';

/** Records appended to db.corp.lab: how clients find the KDC and admin server. */
export const KRB_ZONE_RECORDS = `; Kerberos realm CORP.LAB (MIT KDC and kadmind on ns1). Clients have no KDC in
; krb5.conf: they find it with these SRV records (priority weight port target).
_kerberos               IN TXT  "CORP.LAB"
_kerberos._udp          IN SRV  0 0 88  ns1
_kerberos._tcp          IN SRV  0 0 88  ns1
_kerberos-master._udp   IN SRV  0 0 88  ns1
_kerberos-adm._tcp      IN SRV  0 0 749 ns1
_kpasswd._udp           IN SRV  0 0 464 ns1
`;

export const KRB5_CONF = `[libdefaults]
	default_realm = CORP.LAB
	# Find the KDC and admin server with DNS SRV records (_kerberos._udp.corp.lab ...)
	dns_lookup_kdc = true
	dns_lookup_realm = false
	rdns = false
	ticket_lifetime = 24h
	renew_lifetime = 7d
	forwardable = true

[realms]
	# CORP.LAB: no kdc/admin_server lines; the SRV records in corp.lab are used.

[domain_realm]
	.corp.lab = CORP.LAB
	corp.lab = CORP.LAB
`;

export const KDC_CONF = `[kdcdefaults]
    kdc_ports = 750,88

[realms]
    CORP.LAB = {
        database_name = /var/lib/krb5kdc/principal
        admin_keytab = FILE:/etc/krb5kdc/kadm5.keytab
        acl_file = /etc/krb5kdc/kadm5.acl
        key_stash_file = /etc/krb5kdc/stash
        kdc_ports = 750,88
        max_life = 10h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
        master_key_type = aes256-cts
        supported_enctypes = aes256-cts:normal aes128-cts:normal
        default_principal_flags = +preauth
    }
`;

export const KADM5_ACL = `# This file Is the access control list for krb5 administration.
# When this file is edited run service krb5-admin-server restart to activate
# One common way to set up Kerberos administration is to allow any principal
# ending in /admin  is given full administrative rights.
# To enable this, uncomment the following line:
*/admin@CORP.LAB    *
`;

export const TIMESYNCD_CONF = `#  This file is part of systemd.
#
# See timesyncd.conf(5) for details.

[Time]
# The lab's time source (rtr01)
NTP=rtr01.corp.lab
#FallbackNTP=0.debian.pool.ntp.org 1.debian.pool.ntp.org 2.debian.pool.ntp.org 3.debian.pool.ntp.org
#RootDistanceMaxSec=5
#PollIntervalMinSec=32
#PollIntervalMaxSec=2048
`;

/** host/srv01.corp.lab was created, then exported to srv01's keytab once (kvno 2). */
export const SRV01_HOST_PRINCIPAL = 'host/srv01.corp.lab@CORP.LAB';

export function hostPrincipalKey(kvno: number): string {
  return deriveKey(SRV01_HOST_PRINCIPAL, `lab-random-${kvno}`);
}

function initialDb(t: number): PrincipalEntry[] {
  const by = 'root/admin@CORP.LAB';
  const sys = (name: string) => ({ ...newPrincipal(name, `lab-random:${name}`, t, by, []), modifiedBy: 'db_creation@CORP.LAB' });
  const host = { ...newPrincipal(SRV01_HOST_PRINCIPAL, 'x', t, by, []), kvno: 2, key: hostPrincipalKey(2) };
  return [
    sys('K/M@CORP.LAB'),
    sys('krbtgt/CORP.LAB@CORP.LAB'),
    sys('kadmin/admin@CORP.LAB'),
    sys('kadmin/changepw@CORP.LAB'),
    sys('kadmin/ns1.corp.lab@CORP.LAB'),
    sys('kiprop/ns1.corp.lab@CORP.LAB'),
    newPrincipal('alice@CORP.LAB', ALICE_KRB_PASSWORD, t, by),
    newPrincipal('alice/admin@CORP.LAB', ALICE_ADMIN_PASSWORD, t, by),
    newPrincipal('bob@CORP.LAB', BOB_KRB_PASSWORD, t, by),
    host,
  ];
}

export function srv01Keytab(t: number, kvnos: number[] = [2]): string {
  return formatKeytab(kvnos.flatMap((kvno) => ENCTYPES.map((enctype) => ({ kvno, principal: SRV01_HOST_PRINCIPAL, enctype, key: hostPrincipalKey(kvno), timestamp: t }))));
}

/** Kerberos client configuration for a corp.lab machine. */
export function installKrbClient(host: Host, t: number): void {
  writeFile(host, '/etc/krb5.conf', KRB5_CONF, t);
  mkdir(host, '/etc/systemd', t);
  writeFile(host, '/etc/systemd/timesyncd.conf', TIMESYNCD_CONF, t);
}

export function installKdc(ns1: Host, t: number): void {
  mkdir(ns1, '/etc/krb5kdc', t, { mode: 0o700 });
  writeFile(ns1, '/etc/krb5kdc/kdc.conf', KDC_CONF, t);
  writeFile(ns1, '/etc/krb5kdc/kadm5.acl', KADM5_ACL, t);
  writeFile(ns1, '/etc/krb5kdc/stash', '(binary master key stash)\n', t, { mode: 0o600 });
  mkdir(ns1, '/var/lib/krb5kdc', t, { mode: 0o700 });
  writeFile(ns1, '/var/lib/krb5kdc/principal', formatPrincipalDb(initialDb(t)), t, { mode: 0o600 });
}

export function installKerberos(world: World): void {
  const t = world.clock;
  for (const id of ['rtr01', 'ns1', 'srv01', 'ws01', 'ws02', 'dev01', 'dev02']) if (world.hosts[id]) installKrbClient(world.hosts[id], t);
  installKdc(world.hosts.ns1, t);
  writeFile(world.hosts.srv01, '/etc/krb5.keytab', srv01Keytab(t), t, { mode: 0o600 });
}
