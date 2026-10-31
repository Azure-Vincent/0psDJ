import { describe, expect, it } from 'vitest';
import { buildSshLab } from '../src/engine/lab/sshLab';
import { findScenario } from '../src/engine/scenarios';
import { verifyScenario } from '../src/engine/scenarios/engine';
import { parseFilter, matchFilter, type LdapEntry } from '../src/engine/sim/ldap';
import { Lab } from './helpers';

const lab = () => new Lab(buildSshLab());
const SVC = "-D 'CN=svc-ldap,OU=Service Accounts,DC=ad,DC=corp,DC=lab' -y /etc/phonebook/bind.pw";
const NTDS = "'HKLM:\\System\\CurrentControlSet\\Services\\NTDS\\Parameters'";
const RT = (user: string, pw: string, secret = 'testing123') => `radtest ${user} '${pw}' localhost 0 ${secret}`;
const SSH = (user: string, pw: string) => `sshpass -p '${pw}' ssh -o StrictHostKeyChecking=accept-new ${user}@rtr01.corp.lab hostname`;

describe('LDAP filters', () => {
  const e: LdapEntry = { dn: 'CN=Alice Martin,CN=Users,DC=ad,DC=corp,DC=lab', attrs: { objectClass: ['top', 'person', 'user'], sAMAccountName: ['alice'], memberOf: ['CN=Network-Admins,CN=Users,DC=ad,DC=corp,DC=lab'] } };
  const m = (f: string) => matchFilter(e, parseFilter(f)!);

  it('matches equality, presence, substrings and boolean operators case-insensitively', () => {
    expect(m('(samaccountname=ALICE)')).toBe(true);
    expect(m('(&(objectClass=user)(sAMAccountName=al*))')).toBe(true);
    expect(m('(|(sAMAccountName=bob)(memberOf=CN=Network-Admins,CN=Users,DC=ad,DC=corp,DC=lab))')).toBe(true);
    expect(m('(!(objectClass=group))')).toBe(true);
    expect(m('(mail=*)')).toBe(false);
  });

  it('rejects malformed filters', () => {
    expect(parseFilter('(cn=alice')).toBeNull();
    expect(parseFilter('(&(cn=a)')).toBeNull();
  });
});

describe('LDAP against Active Directory', () => {
  it('a service account finds users over LDAPS; subtree searches at the root return AD\'s referrals', () => {
    const l = lab();
    const r = l.run('srv01', 'root', `ldapsearch -x ${SVC} -LLL '(sAMAccountName=alice)' mail memberOf`);
    expect(r.output).toMatch(/^dn: CN=Alice Martin,CN=Users,DC=ad,DC=corp,DC=lab\nmail: alice@corp\.lab\nmemberOf: CN=RDP-Users/);
    expect(r.output).toMatch(/memberOf: CN=Network-Admins,CN=Users,DC=ad,DC=corp,DC=lab/);
    expect(r.output).toMatch(/# refldap:\/\/ForestDnsZones\.ad\.corp\.lab\/DC=ForestDnsZones,DC=ad,DC=corp,DC=lab/);
    expect(l.run('srv01', 'root', `ldapsearch -x ${SVC} -LLL '(sAMAccountName=svc-*)' dn`).output).toMatch(/dn: CN=svc-ldap,OU=Service Accounts,DC=ad,DC=corp,DC=lab\n\ndn: CN=svc-radius,OU=Service Accounts/);
    expect(l.run('srv01', 'root', 'phonebook bob').output).toMatch(/^displayName: Bob Keller\nmail: bob@corp\.lab$/m);
    expect(l.run('srv01', 'root', `ldapwhoami -x ${SVC}`).output).toBe('u:CORP\\svc-ldap');
  });

  it('anonymous: only the rootDSE answers; searches need a bind; without -x the tools try SASL', () => {
    const l = lab();
    expect(l.run('srv01', 'alice', "ldapsearch -x -s base -b '' -LLL '(objectClass=*)' defaultNamingContext dnsHostName").output).toBe('dn:\ndefaultNamingContext: DC=ad,DC=corp,DC=lab\ndnsHostName: DC01.ad.corp.lab');
    const anon = l.run('srv01', 'alice', "ldapsearch -x -LLL '(sAMAccountName=alice)'");
    expect(anon.output).toMatch(/^Operations error \(1\)\nAdditional information: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection/);
    expect(anon.code).toBe(1);
    expect(l.run('srv01', 'alice', 'ldapwhoami -x').output).toBe('anonymous');
    expect(l.run('srv01', 'alice', 'ldapsearch -LLL').output).toMatch(/SASL\/GSS-SPNEGO authentication started\nldap_sasl_interactive_bind: Local error \(-2\)/);
    expect(l.run('srv01', 'alice', `ldapsearch -x ${SVC.replace('/etc/phonebook/bind.pw', '/nonexistent')} -LLL`).output).toMatch(/Could not open password file \/nonexistent/);
  });

  it('errors: bad filters, unknown bases with the matched DN, and the extended LDIF summary', () => {
    const l = lab();
    const bad = l.run('srv01', 'root', `ldapsearch -x ${SVC} -LLL '(cn=alice'`);
    expect(bad.output).toBe('ldapsearch: ldap_search_ext: Bad search filter (-7)');
    expect(bad.code).toBe(255);
    expect(l.run('srv01', 'root', `ldapsearch -x ${SVC} -LLL -b OU=Nope,DC=ad,DC=corp,DC=lab`).output).toMatch(/^No such object \(32\)\nMatched DN: DC=ad,DC=corp,DC=lab\nAdditional information: 0000208D: NameErr/);
    const full = l.run('srv01', 'root', `ldapsearch -x ${SVC} '(sAMAccountName=bob)' cn`).output;
    expect(full).toMatch(/^# extended LDIF\n#\n# LDAPv3\n# base <DC=ad,DC=corp,DC=lab> \(default\) with scope subtree\n# filter: \(sAMAccountName=bob\)\n# requesting: cn \n/);
    expect(full).toMatch(/# Bob Keller, Users, ad\.corp\.lab\ndn: CN=Bob Keller,CN=Users,DC=ad,DC=corp,DC=lab\ncn: Bob Keller/);
    expect(full).toMatch(/# search result\nsearch: 2\nresult: 0 Success\n\n# numResponses: 5\n# numEntries: 1\n# numReferences: 3$/);
  });

  it('TLS: the client needs the CA and the name in the certificate', () => {
    const l = lab();
    expect(l.run('srv01', 'root', `ldapwhoami -x -H ldaps://10.0.20.5 ${SVC}`).output).toBe("ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)\n\tadditional info: TLS: hostname does not match CN in peer certificate");
    l.run('srv01', 'root', "sed -i 's|^TLS_CACERT.*|TLS_CACERT /etc/ssl/certs/www.corp.lab.crt|' /etc/ldap/ldap.conf");
    expect(l.run('srv01', 'root', `ldapwhoami -x ${SVC}`).output).toMatch(/Can't contact LDAP server \(-1\)\n\tadditional info: error:0A000086:SSL routines::certificate verify failed \(unable to get issuer certificate\)/);
    // StartTLS failing with -ZZ is fatal; with -Z the tool goes on in clear text.
    expect(l.run('srv01', 'root', `ldapwhoami -x -H ldap://dc01.ad.corp.lab -ZZ ${SVC}`).output).toMatch(/^ldap_start_tls: Connect error \(-11\)/);
    expect(l.run('srv01', 'root', `ldapwhoami -x -H ldap://dc01.ad.corp.lab -Z ${SVC}`).output).toMatch(/^ldap_start_tls: Connect error \(-11\)[\s\S]*\nu:CORP\\svc-ldap$/);
  });

  it('the DC\'s signing requirement refuses clear-text simple binds, not LDAPS or StartTLS', () => {
    const l = lab();
    expect(l.run('dc01', 'Administrator', `(Get-ItemProperty ${NTDS}).LDAPServerIntegrity`).output).toBe('1');
    l.run('dc01', 'Administrator', `Set-ItemProperty -Path ${NTDS} -Name LDAPServerIntegrity -Value 2`);
    const plain = l.run('srv01', 'root', `ldapwhoami -x -H ldap://dc01.ad.corp.lab ${SVC}`);
    expect(plain.output).toMatch(/^ldap_bind: Strong\(er\) authentication required \(8\)\n\tadditional info: 00002028: LdapErr: DSID-0C090259/);
    expect(plain.code).toBe(8);
    expect(l.run('srv01', 'root', `ldapwhoami -x -H ldap://dc01.ad.corp.lab -ZZ ${SVC}`).output).toBe('u:CORP\\svc-ldap');
    expect(l.run('srv01', 'root', `ldapwhoami -x ${SVC}`).output).toBe('u:CORP\\svc-ldap');
  });

  it('bad passwords count in AD: five lock the account (data 775, event 4740) until it is unlocked', () => {
    const l = lab();
    const bad = l.run('srv01', 'root', "ldapwhoami -x -D svc-ldap@ad.corp.lab -w wrong");
    expect(bad.output).toMatch(/ldap_bind: Invalid credentials \(49\)\n\tadditional info: 80090308: LdapErr: DSID-0C090447, comment: AcceptSecurityContext error, data 52e, v4563/);
    for (let i = 0; i < 4; i++) l.run('srv01', 'root', 'ldapwhoami -x -D svc-ldap@ad.corp.lab -w wrong');
    expect(l.run('srv01', 'root', `ldapwhoami -x ${SVC}`).output).toMatch(/data 775, v4563/);
    expect(l.run('dc01', 'Administrator', 'Get-WinEvent -FilterHashtable @{LogName=\'Security\';Id=4740} -MaxEvents 1 | Format-List Message').output).toMatch(/Account Name:\s+svc-ldap[\s\S]*Caller Computer Name:\s+SRV01/);
    l.run('dc01', 'Administrator', 'Unlock-ADAccount svc-ldap');
    expect(l.run('srv01', 'root', `ldapwhoami -x ${SVC}`).output).toBe('u:CORP\\svc-ldap');
  });

  it('users in an OU keep their DN in AD cmdlets; group changes show in memberOf at once', () => {
    const l = lab();
    expect(l.run('dc01', 'Administrator', '(Get-ADUser svc-radius).DistinguishedName').output).toBe('CN=svc-radius,OU=Service Accounts,DC=ad,DC=corp,DC=lab');
    l.run('dc01', 'Administrator', 'Add-ADGroupMember -Identity Network-Admins -Members dana');
    expect(l.run('srv01', 'root', `ldapsearch -x ${SVC} -LLL '(sAMAccountName=dana)' memberOf`).output).toMatch(/memberOf: CN=Network-Admins,CN=Users,DC=ad,DC=corp,DC=lab/);
  });
});

describe('FreeRADIUS on rad01', () => {
  it('accepts Network-Admins, rejects others with the policy message, and logs both', () => {
    const l = lab();
    const ok = l.run('rad01', 'root', RT('alice', 'Office-Corp-2026'));
    expect(ok.output).toMatch(/^Sent Access-Request Id \d+ from 0\.0\.0\.0:\d+ to 127\.0\.0\.1:1812 length \d+\n\tUser-Name = "alice"\n\tUser-Password = "Office-Corp-2026"\n\tNAS-IP-Address = 127\.0\.0\.1\n\tNAS-Port = 0\n\tMessage-Authenticator = 0x00\n\tCleartext-Password = "Office-Corp-2026"\nReceived Access-Accept Id \d+ from 127\.0\.0\.1:1812 to 127\.0\.0\.1:\d+ length \d+\n\tReply-Message = "Welcome to the corp\.lab network, alice"$/);
    expect(ok.code).toBe(0);
    const dana = l.run('rad01', 'root', RT('dana', 'Sales-Corp-2026'));
    expect(dana.output).toMatch(/Received Access-Reject Id \d+ [^\n]*\n\tReply-Message = "Not a member of Network-Admins"\n\(0\) -: Expected Access-Accept got Access-Reject$/);
    expect(dana.code).toBe(1);
    expect(l.run('rad01', 'root', RT('alice', 'wrong')).output).not.toMatch(/Reply-Message/);
    const log = l.run('rad01', 'root', 'tail -n 4 /var/log/freeradius/radius.log').output;
    expect(log).toMatch(/: Auth: \(\d+\) Login OK: \[alice\] \(from client localhost port 0\)/);
    expect(log).toMatch(/: Auth: \(\d+\) Login incorrect: \[dana\] \(from client localhost port 0\)/);
    expect(log).toMatch(/: Error: \(\d+\) ldap: Bind as user "CN=Alice Martin,CN=Users,DC=ad,DC=corp,DC=lab" failed: Invalid credentials: 80090308: .* data 52e/);
    expect(log).toMatch(/: Auth: \(\d+\) Login incorrect \(ldap: Bind as user failed\): \[alice\]/);
  });

  it('a wrong secret with Message-Authenticator is dropped; unknown clients are ignored', () => {
    const l = lab();
    const r = l.run('rad01', 'root', RT('alice', 'Office-Corp-2026', 'nope'));
    expect(r.output).toMatch(/\(0\) No reply from server for ID \d+ socket 3$/);
    expect(l.run('rad01', 'root', 'tail -n 1 /var/log/freeradius/radius.log').output).toMatch(/Error: Dropping packet without response because of error: Received packet from 127\.0\.0\.1 with invalid Message-Authenticator!  \(Shared secret is incorrect\.\)$/);
    // srv01 is no client of rad01 (and its firewall would drop it anyway: open it to see the server's view).
    l.run('rad01', 'root', 'nft insert rule inet filter input udp dport 1812 accept');
    expect(l.run('srv01', 'root', "radtest alice x rad01.corp.lab 0 testing123").output).toMatch(/No reply from server/);
    expect(l.run('rad01', 'root', 'tail -n 1 /var/log/freeradius/radius.log').output).toMatch(/Error: Ignoring request to auth address \* port 1812 bound to server default from unknown client 10\.0\.20\.10 port \d+ proto udp$/);
  });

  it('clients.conf is read at start only: a reload keeps the old clients, a restart loads them; -XC checks the files', () => {
    const l = lab();
    l.run('rad01', 'root', "sed -i 's/secret = testing123/secret = changed-secret-123/' /etc/freeradius/3.0/clients.conf");
    l.run('rad01', 'root', 'systemctl reload freeradius');
    expect(l.run('rad01', 'root', RT('alice', 'Office-Corp-2026')).output).toMatch(/Received Access-Accept/);
    l.run('rad01', 'root', 'systemctl restart freeradius');
    expect(l.run('rad01', 'root', RT('alice', 'Office-Corp-2026')).output).toMatch(/No reply from server/);
    expect(l.run('rad01', 'root', RT('alice', 'Office-Corp-2026', 'changed-secret-123')).output).toMatch(/Received Access-Accept/);
    expect(l.run('rad01', 'root', 'freeradius -XC').output).toMatch(/Configuration appears to be OK$/);
    expect(l.run('rad01', 'root', 'freeradius -X').output).toMatch(/Failed binding to auth address \* port 1812 bound to server default: Address already in use/);
    l.run('rad01', 'root', "sed -i '/secret = changed-secret-123/d' /etc/freeradius/3.0/clients.conf");
    expect(l.run('rad01', 'root', 'freeradius -C').output).toMatch(/^\/etc\/freeradius\/3\.0\/clients\.conf\[\d+\]: Missing secret for client "localhost"\nErrors reading or parsing \/etc\/freeradius\/3\.0\/radiusd\.conf$/);
    l.run('rad01', 'root', 'systemctl restart freeradius');
    expect(l.run('rad01', 'root', 'systemctl is-active freeradius').output).toBe('failed');
  });

  it('the ldap module reports a DC it cannot trust, and logins fail', () => {
    const l = lab();
    l.run('rad01', 'root', "sed -i 's|ca_file = .*|ca_file = /etc/ssl/certs/none.pem|' /etc/freeradius/3.0/mods-enabled/ldap");
    l.run('rad01', 'root', 'systemctl reload freeradius');
    expect(l.run('rad01', 'root', RT('alice', 'Office-Corp-2026')).output).toMatch(/Access-Reject/);
    const log = l.run('rad01', 'root', 'tail -n 4 /var/log/freeradius/radius.log').output;
    expect(log).toMatch(/Error: \(\d+\) ldap: Bind with CN=svc-radius,OU=Service Accounts,DC=ad,DC=corp,DC=lab to ldaps:\/\/dc01\.ad\.corp\.lab:636 failed: Can't contact LDAP server/);
    expect(log).toMatch(/ldap: Server said: could not load CA certificate file \/etc\/ssl\/certs\/none\.pem/);
  });
});

describe('pam_radius_auth on rtr01', () => {
  it('RADIUS users log in with their AD password; the break-glass account works without RADIUS', () => {
    const l = lab();
    expect(l.run('ws01', 'alice', SSH('alice', 'Office-Corp-2026')).output).toMatch(/^Warning: Permanently added 'rtr01\.corp\.lab' \(ED25519\) to the list of known hosts\.\nrtr01$/);
    expect(l.run('rtr01', 'root', 'journalctl -u ssh -n 10').output).toMatch(/Accepted password for alice from 10\.0\.10\.25 port \d+ ssh2/);
    const dana = l.run('ws01', 'alice', SSH('dana', 'Sales-Corp-2026'));
    expect(dana.code).toBe(5);
    expect(dana.output).toBe('');
    l.run('rad01', 'root', 'systemctl stop freeradius');
    expect(l.run('ws01', 'alice', SSH('netadmin', 'Rtr01-Breakglass-26')).output).toBe('rtr01');
    expect(l.run('ws01', 'alice', SSH('alice', 'Office-Corp-2026')).code).toBe(5);
    expect(l.run('rtr01', 'root', 'journalctl -u ssh').output).toMatch(/pam_radius_auth: RADIUS server 10\.0\.20\.65 failed to respond\n.*pam_radius_auth: All RADIUS servers failed to respond\./);
  });

  it('a mismatched secret: replies fail verification, and AD counts bad passwords', () => {
    const l = lab();
    l.run('rtr01', 'root', "sed -i 's/Rtr01-Nas-Secret-2702/other/' /etc/pam_radius_auth.conf");
    expect(l.run('ws01', 'alice', SSH('alice', 'Office-Corp-2026')).code).toBe(5);
    expect(l.run('rtr01', 'root', 'journalctl -u ssh').output).toMatch(/pam_radius_auth: packet from RADIUS server 10\.0\.20\.65 failed verification: The shared secret is probably incorrect\./);
    expect(Number(l.run('dc01', 'Administrator', '(Get-ADUser alice -Properties BadLogonCount).BadLogonCount').output)).toBeGreaterThanOrEqual(2);
  });

  it('example servers are skipped with their log lines', () => {
    const l = lab();
    l.run('rtr01', 'root', "sed -i 's/^10.0.20.65/other-server other-secret 3\\n10.0.20.65/' /etc/pam_radius_auth.conf");
    expect(l.run('ws01', 'alice', SSH('alice', 'Office-Corp-2026')).output).toMatch(/\nrtr01$/);
    expect(l.run('rtr01', 'root', 'journalctl -u ssh').output).toMatch(/pam_radius_auth: Failed looking up IP address for RADIUS server other-server \(errcode=-2\)/);
  });
});

describe('shell additions', () => {
  it('scripts get positional parameters; sshpass exits 5 on a refused password', () => {
    const l = lab();
    l.run('srv01', 'root', `printf '#!/bin/sh\\necho "$# args: $1, $2 ($@)"\\n' > /usr/local/bin/args && chmod 755 /usr/local/bin/args`);
    expect(l.run('srv01', 'root', 'args one two').output).toBe('2 args: one, two (one two)');
    expect(l.run('srv01', 'root', 'sh /usr/local/bin/args x').output).toBe('1 args: x,  (x)');
    const r = l.run('ws01', 'alice', `${SSH('netadmin', 'wrong')}; echo "exit $?"`);
    expect(r.output).toBe('exit 5');
    expect(l.run('ws01', 'alice', 'sshpass -e ssh netadmin@rtr01.corp.lab true').output).toBe('sshpass: -e option given but SSHPASS environment variable not set');
  });
});

describe('identity tickets reject the tempting wrong fixes', () => {
  const broken = (id: string) => {
    const s = findScenario(id)!;
    const w = buildSshLab();
    s.setup(w);
    return { s, l: new Lab(w) };
  };
  const failed = (l: Lab, id: string, constraint: string) => verifyScenario(l.world, findScenario(id)!).constraints.find((c) => c.id === constraint)?.ok;

  it('signing: rolling back the DC hardening is rejected', () => {
    const { l } = broken('id-ldap-signing');
    l.run('dc01', 'Administrator', `Set-ItemProperty -Path ${NTDS} -Name LDAPServerIntegrity -Value 1`);
    const v = verifyScenario(l.world, findScenario('id-ldap-signing')!);
    expect(v.now[0].ok).toBe(true);
    expect(v.constraints.find((c) => c.id === 'id-ldap-signing-kept')?.ok).toBe(false);
  });

  it('anonymous: binding as a person, or with -w on the command line, is rejected', () => {
    const { l } = broken('id-phonebook-anonymous');
    l.run('srv01', 'root', `printf '#!/bin/sh\\nldapsearch -x -LLL -D alice@ad.corp.lab -w Office-Corp-2026 "(sAMAccountName=$1)" displayName mail\\n' > /usr/local/bin/phonebook`);
    expect(failed(l, 'id-phonebook-anonymous', 'id-phonebook-service-bind')).toBe(false);
  });

  it('locked service account: AD refuses the old password (history); resetting to another one is rejected', () => {
    const { l } = broken('id-svc-locked');
    expect(l.run('dc01', 'Administrator', "Set-ADAccountPassword svc-ldap -Reset -NewPassword (ConvertTo-SecureString 'Svc-Ldap-2026!' -AsPlainText -Force)").output).toMatch(/does not meet the length, complexity, or history requirement/);
    l.run('dc01', 'Administrator', "Set-ADAccountPassword svc-ldap -Reset -NewPassword (ConvertTo-SecureString 'Another-Pass-2026!' -AsPlainText -Force)");
    l.run('dc01', 'Administrator', 'Unlock-ADAccount svc-ldap');
    l.run('srv01', 'root', "printf '%s' 'Another-Pass-2026!' > /etc/phonebook/bind.pw");
    const v = verifyScenario(l.world, findScenario('id-svc-locked')!);
    expect(v.now[0].ok).toBe(true);
    expect(v.constraints.find((c) => c.id === 'id-svc-password-kept')?.ok).toBe(false);
  });

  it('CA: switching certificate checks off is rejected', () => {
    const { l } = broken('id-radius-ca');
    l.run('rad01', 'root', "sed -i \"s/require_cert = 'demand'/require_cert = 'never'/\" /etc/freeradius/3.0/mods-enabled/ldap");
    l.run('rad01', 'root', 'systemctl restart freeradius');
    const v = verifyScenario(l.world, findScenario('id-radius-ca')!);
    expect(v.now[0].ok).toBe(true);
    expect(v.constraints.find((c) => c.id === 'id-radius-cert-checked')?.ok).toBe(false);
  });

  it('group: dropping the group check, or making dana a Domain Admin, is rejected', () => {
    const { l } = broken('id-radius-group');
    l.run('rad01', 'root', "printf 'DEFAULT\\tAuth-Type := Accept\\n' > /etc/freeradius/3.0/mods-config/files/authorize");
    l.run('rad01', 'root', 'systemctl reload freeradius');
    expect(failed(l, 'id-radius-group', 'id-radius-policy-kept')).toBe(false);
    const b = broken('id-radius-group');
    b.l.run('dc01', 'Administrator', "Add-ADGroupMember -Identity 'Domain Admins' -Members dana");
    expect(failed(b.l, 'id-radius-group', 'id-least-privilege')).toBe(false);
  });

  it('secret: going back to the leaked secret is rejected', () => {
    const { l } = broken('id-radius-secret');
    l.run('rad01', 'root', "sed -i 's/secret = Rtr01-Nas-2026-Q4-5j7Q/secret = Rtr01-Nas-Secret-2702/' /etc/freeradius/3.0/clients.conf");
    l.run('rad01', 'root', 'systemctl restart freeradius');
    const v = verifyScenario(l.world, findScenario('id-radius-secret')!);
    expect(v.now[0].ok).toBe(true);
    expect(v.constraints.find((c) => c.id === 'id-radius-secret-rotated')?.ok).toBe(false);
  });

  it('unknown client: a reload is not enough, and a catch-all client is rejected', () => {
    const { l } = broken('id-radius-unknown-client');
    l.run('rad01', 'root', "sed -i 's/ipaddr = 10.0.10.1/ipaddr = 10.0.20.1/' /etc/freeradius/3.0/clients.conf");
    l.run('rad01', 'root', 'systemctl reload freeradius');
    expect(verifyScenario(l.world, findScenario('id-radius-unknown-client')!).now[0].ok).toBe(false);
    const b = broken('id-radius-unknown-client');
    b.l.run('rad01', 'root', "sed -i 's|ipaddr = 10.0.10.1|ipaddr = 10.0.0.0/16|' /etc/freeradius/3.0/clients.conf");
    b.l.run('rad01', 'root', 'systemctl restart freeradius');
    const v = verifyScenario(b.l.world, findScenario('id-radius-unknown-client')!);
    expect(v.now[0].ok).toBe(true);
    expect(v.constraints.find((c) => c.id === 'id-radius-clients-specific')?.ok).toBe(false);
  });
});

describe('identity lesson', () => {
  it('is registered with every identity ticket and its assessment', async () => {
    const { getLesson } = await import('../src/content/lessons');
    const { ID_SCENARIOS } = await import('../src/engine/scenarios/idScenarios');
    const L = getLesson('identity')!;
    expect(L).toBeDefined();
    expect([...L.scenarioIds].sort()).toEqual(ID_SCENARIOS.map((s) => s.id).sort());
    expect(L.assessmentId).toBe('identity');
  });
});
