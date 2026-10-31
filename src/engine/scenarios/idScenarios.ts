// Identity tickets: applications that look people up in Active Directory over
// LDAP/LDAPS (srv01's phone book), and network-device logins through RADIUS
// (rtr01's sshd → pam_radius_auth → FreeRADIUS on rad01 → AD). Each ticket is
// a failure administrators meet in real directory work: an anonymous search,
// a DC that starts requiring signing, a rotated service password that locks
// the account, a server without the internal CA, a missing group membership,
// a mismatched shared secret and a NAS the RADIUS server does not know.

import { readFile, writeFile } from '../fs';
import { AUTHORIZE_FILE, CLIENTS_CONF, LDAP_MODULE, PAM_RADIUS_CONF, radiusdCheck } from '../sim/radius';
import { CA_BUNDLE, certPem, PUBLIC_ROOTS } from '../sim/pki';
import { clientConf, NTDS_PARAMS } from '../sim/ldap';
import { CORP_ROOT_LOCAL } from '../lab/pkiLab';
import { AD_ALICE_PASSWORD } from '../lab/winLab';
import { DANA_PASSWORD, LDAP_SVC, PHONEBOOK, PHONEBOOK_PW, RTR01_RADIUS_SECRET } from '../lab/identityLab';
import { script } from './engine';
import type { Constraint, Goal, Scenario } from './types';

const BRIEFING = [
  'dc01 (10.0.20.5) is the domain controller of ad.corp.lab: LDAP on 389, LDAPS on 636 with a certificate for dc01.ad.corp.lab from Corp Lab Issuing CA 1. Applications bind as service accounts in OU=Service Accounts (svc-ldap for the phone book, svc-radius for RADIUS); anonymous searches are not allowed.',
  'srv01 runs the intranet phone book: /usr/local/bin/phonebook NAME runs ldapsearch as svc-ldap with the password in /etc/phonebook/bind.pw; server and CA come from /etc/ldap/ldap.conf (URI ldaps://dc01.ad.corp.lab).',
  'rad01 (10.0.20.65) runs FreeRADIUS 3.2 (/etc/freeradius/3.0: clients.conf, mods-enabled/ldap, mods-config/files/authorize; log in /var/log/freeradius/radius.log). Only members of the AD group Network-Admins may log in to network devices.',
  'rtr01\'s sshd asks rad01 first (pam_radius_auth, /etc/pam_radius_auth.conf, /etc/pam.d/sshd); the local account netadmin is the break-glass login. Test without locking anyone out: radtest USER PASSWORD localhost 0 testing123 on rad01.',
];

const TERMINALS = {
  srv01: { hostId: 'srv01', user: 'root', label: 'srv01 (phone book)', banner: 'srv01: the phone book. Try: phonebook bob, cat /usr/local/bin/phonebook /etc/ldap/ldap.conf, ldapwhoami -x -D … -y /etc/phonebook/bind.pw.' },
  dc01: { hostId: 'dc01', user: 'Administrator', label: 'dc01 (domain controller)', banner: 'dc01: Active Directory. Try: Get-ADUser svc-ldap -Properties LockedOut,BadLogonCount, Get-ADGroupMember Network-Admins, Get-WinEvent -FilterHashtable @{LogName=\'Security\';Id=4740}.' },
  rad01: { hostId: 'rad01', user: 'root', label: 'rad01 (RADIUS)', banner: 'rad01: FreeRADIUS. Try: tail -n 20 /var/log/freeradius/radius.log, freeradius -XC, radtest alice PASSWORD localhost 0 testing123.' },
  rtr01: { hostId: 'rtr01', user: 'root', label: 'rtr01 (router, the NAS)', banner: 'rtr01: sshd with pam_radius_auth. Try: journalctl -u ssh -n 20, cat /etc/pam_radius_auth.conf, grep radius /etc/pam.d/sshd.' },
};

const CANDIDATES = [
  'ldap-anonymous-bind', 'ldap-signing-required', 'ldap-tls-untrusted', 'ldap-svc-credentials',
  'radius-secret-mismatch', 'radius-unknown-client', 'radius-not-authorized', 'firewall-drop', 'dns-wrong-record',
];

/** The phone book finds bob (run as root on srv01). */
const phonebookWorks: Goal = {
  kind: 'command',
  description: 'The phone book on srv01 finds Bob Keller: phonebook bob prints his mail address.',
  steps: [{ host: 'srv01', user: 'root', command: 'phonebook bob' }],
  expect: '^mail: bob@corp\\.lab$',
};

/** USER logs in to rtr01 over SSH with the AD password (the account has no local password: only RADIUS can say yes). */
const rtrLogin = (user: string, password: string): Goal => ({
  kind: 'command',
  description: `${user} logs in to rtr01 over SSH with the Active Directory password (checked by RADIUS).`,
  steps: [{ host: 'ws01', user: 'alice', command: `sshpass -p '${password}' ssh -o StrictHostKeyChecking=accept-new ${user}@rtr01.corp.lab hostname || echo "${user}@rtr01.corp.lab: Permission denied (sshpass exit $?: the password was not accepted)"` }],
  expect: '^rtr01$',
});

/** The phone book still binds as svc-ldap, with the password from a file (not on the command line, not as a person). */
const phonebookBindsAsService: Constraint = {
  id: 'id-phonebook-service-bind', required: true,
  description: 'The phone book binds as svc-ldap with the password from /etc/phonebook/bind.pw (not as a person or an administrator, not with -w on the command line).',
  check(world) {
    const s = readFile(world.hosts.srv01, PHONEBOOK) ?? '';
    const lines = s.split('\n').filter((l) => !l.trim().startsWith('#'));
    const body = lines.join('\n');
    const bad = /administrator|cn=alice|cn=bob|alice@|bob@/i.test(body) ? 'it binds as a person or an administrator' : /\s-w\s/.test(body) ? 'the password is on the command line (-w), where ps shows it to every user' : !/svc-ldap/i.test(body) ? 'it no longer binds as svc-ldap' : null;
    return { id: this.id, ok: !bad, required: true, message: bad ? `The phone book script: ${bad}. Bind as the service account with -y /etc/phonebook/bind.pw.` : 'The phone book binds as svc-ldap with the password file.' };
  },
};

const bindPwPrivate: Constraint = {
  id: 'id-bindpw-private', required: true,
  description: '/etc/phonebook/bind.pw is not readable by other users.',
  check(world) {
    const n = world.hosts.srv01.fs[PHONEBOOK_PW];
    const ok = !!n && (n.mode & 0o004) === 0;
    return { id: this.id, ok, required: true, message: ok ? 'The password file is private.' : n ? `bind.pw has mode 0${(n.mode & 0o777).toString(8)}: chmod 640 (or 600) so other users cannot read the service password.` : 'bind.pw is missing.' };
  },
};

/** srv01 still verifies the DC's certificate. */
const ldapVerifies: Constraint = {
  id: 'id-ldap-verify', required: true,
  description: 'srv01 still verifies the DC\'s certificate (TLS_REQCERT is not never/allow).',
  check(world) {
    const c = clientConf(world.hosts.srv01);
    const ok = c.reqcert === 'demand' || c.reqcert === 'hard';
    return { id: this.id, ok, required: true, message: ok ? 'Certificate checks are on.' : `TLS_REQCERT ${c.reqcert} in /etc/ldap/ldap.conf turns certificate checks off: anyone who can intercept the connection would receive the service password.` };
  },
};

const signingKept: Constraint = {
  id: 'id-ldap-signing-kept', required: true,
  description: 'dc01 still requires signing or TLS for LDAP binds (LDAPServerIntegrity 2, CHG-2731).',
  check(world) {
    const v = Number(world.hosts.dc01.win?.registry[NTDS_PARAMS]?.LDAPServerIntegrity ?? 1);
    return { id: this.id, ok: v >= 2, required: true, message: v >= 2 ? 'The hardening is in place.' : `LDAPServerIntegrity is ${v}: the hardening (CHG-2731) was rolled back. Clear-text binds expose passwords; fix the client instead.` };
  },
};

/** The RADIUS server's policy still requires Network-Admins and rejects everyone else. */
const policyKept: Constraint = {
  id: 'id-radius-policy-kept', required: true,
  description: 'rad01 still lets only members of Network-Admins in (the authorize file keeps the group check and the default reject).',
  check(world) {
    const c = radiusdCheck(world.hosts.rad01);
    const ok = !('msg' in c) && c.entries.some((e) => e.name === 'DEFAULT' && e.checks.some((x) => /^ldap-group$/i.test(x.attr) && x.op === '==' && x.value.toLowerCase() === 'network-admins'))
      && c.entries.some((e) => e.name === 'DEFAULT' && e.checks.some((x) => /^auth-type$/i.test(x.attr) && /^reject$/i.test(x.value)))
      && !c.entries.some((e) => e.name !== 'DEFAULT');
    return { id: this.id, ok, required: true, message: ok ? 'The group policy is unchanged.' : `${AUTHORIZE_FILE} no longer limits logins to Network-Admins: put the policy back and fix the membership in AD.` };
  },
};

const noPrivilegedGroups = (sam: string): Constraint => ({
  id: 'id-least-privilege', required: true,
  description: `${sam} is not made a member of Domain Admins, Enterprise Admins or Administrators.`,
  check(world) {
    const ad = world.hosts.dc01.win?.ad;
    const g = ad ? Object.values(ad.groups).find((x) => /^(domain admins|enterprise admins|administrators)$/i.test(x.name) && x.members.some((m) => m.toLowerCase() === sam.toLowerCase())) : undefined;
    return { id: this.id, ok: !g, required: true, message: g ? `${sam} is in ${g.name}: far more rights than the job needs. Remove it.` : 'No extra privileges.' };
  },
});

/** The client entry for rtr01 is still specific (no catch-all clients with a guessable secret). */
const clientsSpecific: Constraint = {
  id: 'id-radius-clients-specific', required: true,
  description: 'clients.conf lists rtr01 by its address (no client for a whole network or for any address).',
  check(world) {
    const c = radiusdCheck(world.hosts.rad01);
    if ('msg' in c) return { id: this.id, ok: false, required: true, message: `clients.conf does not load: ${c.msg}` };
    const wide = c.clients.find((x) => x.ipaddr === '*' || (x.ipaddr.includes('/') && Number(x.ipaddr.split('/')[1]) < 32));
    return { id: this.id, ok: !wide, required: true, message: wide ? `client ${wide.name} (ipaddr = ${wide.ipaddr}) accepts requests from many addresses: list the NAS by its own address.` : 'Every client is a single address.' };
  },
};

const NEW_RADIUS_SECRET = 'Rtr01-Nas-2026-Q4-5j7Q';
const secretRotated: Constraint = {
  id: 'id-radius-secret-rotated', required: true,
  description: 'The old shared secret (it was on a wiki page) is used nowhere: not in clients.conf, not in /etc/pam_radius_auth.conf.',
  check(world) {
    const used = [readFile(world.hosts.rad01, CLIENTS_CONF) ?? '', readFile(world.hosts.rtr01, PAM_RADIUS_CONF) ?? ''].some((t) => t.split('\n').some((l) => !l.trim().startsWith('#') && l.includes(RTR01_RADIUS_SECRET)));
    return { id: this.id, ok: !used, required: true, message: used ? 'The leaked secret is back in use: keep the new one (CHG-2755) on both sides.' : 'Only the new secret is in use.' };
  },
};

const pamRadiusPrivate: Constraint = {
  id: 'id-pam-radius-private', required: true,
  description: '/etc/pam_radius_auth.conf on rtr01 stays readable by root only (it holds the shared secret).',
  check(world) {
    const n = world.hosts.rtr01.fs[PAM_RADIUS_CONF];
    const ok = !!n && (n.mode & 0o077) === 0;
    return { id: this.id, ok, required: true, message: ok ? 'Mode 600.' : n ? `Mode 0${(n.mode & 0o777).toString(8)}: anyone who can read the secret can forge RADIUS answers. chmod 600.` : 'The file is missing.' };
  },
};

const certChecked: Constraint = {
  id: 'id-radius-cert-checked', required: true,
  description: 'FreeRADIUS still checks the DC\'s certificate (require_cert = \'demand\' in mods-enabled/ldap).',
  check(world) {
    const c = radiusdCheck(world.hosts.rad01);
    const ok = !('msg' in c) && !!c.ldap && (c.ldap.requireCert === 'demand' || c.ldap.requireCert === 'hard') && /^ldaps:/i.test(c.ldap.server);
    return { id: this.id, ok, required: true, message: ok ? 'LDAPS with certificate checks.' : `${LDAP_MODULE}: keep server = 'ldaps://dc01.ad.corp.lab' and require_cert = 'demand'. Trust the internal CA instead of turning the check off.` };
  },
};

const SVC_NEW_PASSWORD = 'Svc-Ldap-2026-Q4!x9';

export const ID_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'id-phonebook-anonymous',
    title: 'The phone book finds nobody',
    difficulty: 'beginner',
    ticket: 'Reception (bob): "Since this morning the phone book on the intranet finds nobody, not even me. A contractor tidied up the lookup script yesterday (CHG-2760): he said the password was not needed because \'the directory is readable by everyone\'."',
    briefing: BRIEFING,
    goals: [phonebookWorks],
    terminals: [TERMINALS.srv01, TERMINALS.dc01],
    setup(world) {
      const srv = world.hosts.srv01;
      writeFile(srv, PHONEBOOK, `#!/bin/sh\n# phonebook NAME: the intranet phone book's lookup in Active Directory (CHG-2701).\n# CHG-2760: simplified, the directory is readable by everyone.\nldapsearch -x -LLL "(sAMAccountName=$1)" displayName mail\n`, world.clock, { mode: 0o755 });
    },
    rootCauses: ['ldap-anonymous-bind'],
    candidates: CANDIDATES,
    feedback: {
      'ldap-tls-untrusted': 'The connection works: the DC answers with an LDAP error ("Operations error"), which it can only send over an established TLS session.',
      'ldap-svc-credentials': 'There are no credentials to be wrong: the script does not bind at all (ldapwhoami without -D prints "anonymous").',
      'ldap-signing-required': 'That would refuse a bind ("Strong(er) authentication required"). Here no bind happens, and the search itself is refused.',
    },
    hints: [
      'Run phonebook bob on srv01 and read the error: "Operations error (1)" with "000004DC … a successful bind must be completed on the connection".',
      'Active Directory answers only the rootDSE without a bind (ldapsearch -x -s base -b \'\' works). Compare the script with the briefing: what happened to -D and -y?',
      'Put the bind back: ldapsearch -x -LLL -D "CN=svc-ldap,OU=Service Accounts,DC=ad,DC=corp,DC=lab" -y /etc/phonebook/bind.pw "(sAMAccountName=$1)" displayName mail.',
    ],
    explanation: {
      rootCause: 'The script searched without binding. Active Directory does not let anonymous users search the directory (only the rootDSE is readable), so every lookup failed with "Operations error".',
      manifestation: 'An empty phone book: the script prints an LDAP error instead of entries. Nothing is wrong with the DC, the network or TLS.',
      evidence: 'ldapsearch output "Operations error (1) … 000004DC … a successful bind must be completed"; ldapwhoami -x prints "anonymous"; the same search with -D and -y works.',
      prevention: 'Applications use a dedicated service account with read-only rights and a password file (-y), never anonymous binds and never a person\'s account; test lookups after every change.',
    },
    solution: [{ host: 'srv01', commands: [`printf '#!/bin/sh\\n# phonebook NAME: the intranet phone book lookup in Active Directory (CHG-2701).\\nldapsearch -x -LLL -D "${LDAP_SVC.dn}" -y /etc/phonebook/bind.pw "(sAMAccountName=$1)" displayName mail\\n' > ${PHONEBOOK}`, `chmod 755 ${PHONEBOOK}`] }],
    constraints: [phonebookBindsAsService, bindPwPrivate],
    concepts: ['id.ldap'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'id-ldap-signing',
    title: 'Hardening day: the phone book stopped',
    difficulty: 'intermediate',
    ticket: 'Security (CHG-2731): "Tonight we set \'Domain controller: LDAP server signing requirements\' to Require signing on dc01, as planned. This morning the intranet phone book on srv01 fails. Do NOT roll back the hardening: fix the client."',
    briefing: BRIEFING,
    goals: [phonebookWorks],
    terminals: [TERMINALS.srv01, TERMINALS.dc01],
    setup(world) {
      script(world, 'dc01', ["Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name LDAPServerIntegrity -Value 2"]);
      const srv = world.hosts.srv01;
      const conf = (readFile(srv, '/etc/ldap/ldap.conf') ?? '').replace('URI\tldaps://dc01.ad.corp.lab', '# INC-2290: LDAPS failed after the CA renewal in spring; plain LDAP until fixed\n#URI\tldaps://dc01.ad.corp.lab\nURI\tldap://dc01.ad.corp.lab');
      writeFile(srv, '/etc/ldap/ldap.conf', conf, world.clock);
    },
    rootCauses: ['ldap-signing-required'],
    candidates: CANDIDATES,
    feedback: {
      'ldap-svc-credentials': 'The password is right: the DC refuses the bind before it checks it ("Strong(er) authentication required", code 8, not 49).',
      'ldap-tls-untrusted': 'The client does not use TLS at all at the moment (ldap://). When you switch to LDAPS, the certificate is trusted: the CA problem of INC-2290 was solved long ago.',
    },
    hints: [
      'Run phonebook bob: "Strong(er) authentication required (8)" and "The server requires binds to turn on integrity checking if SSL\\TLS are not already active". Which URI does the client use?',
      'cat /etc/ldap/ldap.conf: a temporary change switched to ldap:// (port 389, clear text). With signing required, a simple bind needs TLS.',
      'Switch back to LDAPS: URI ldaps://dc01.ad.corp.lab in /etc/ldap/ldap.conf (or StartTLS with -ZZ). Check with ldapwhoami -x -D "CN=svc-ldap,OU=Service Accounts,DC=ad,DC=corp,DC=lab" -y /etc/phonebook/bind.pw.',
    ],
    explanation: {
      rootCause: 'The client did a simple bind over plain ldap://. With LDAPServerIntegrity = 2 the DC refuses binds that are neither signed (SASL) nor protected by TLS, so the service password is no longer accepted in clear text.',
      manifestation: 'Every application that binds in clear text breaks the moment the policy changes; the error is result code 8, strongAuthRequired.',
      evidence: 'ldap_bind: Strong(er) authentication required (8), 00002028 … integrity checking; LDAPServerIntegrity 2 in the NTDS Parameters key; the same bind over ldaps:// works.',
      prevention: 'Use LDAPS (or StartTLS) everywhere before enforcing signing; on the DC, event 2889 lists clients that still bind in clear text. Undo "temporary" workarounds once the cause is fixed.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i 's|^URI\\tldap://dc01.ad.corp.lab|URI\\tldaps://dc01.ad.corp.lab|' /etc/ldap/ldap.conf"] }],
    constraints: [signingKept, ldapVerifies, phonebookBindsAsService],
    concepts: ['id.ldap'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'id-svc-locked',
    title: 'The phone book after the password rotation',
    difficulty: 'advanced',
    ticket: 'Service desk: "The phone book says \'Invalid credentials\'. Yesterday was the quarterly rotation of service passwords (CHG-2744); the new password for svc-ldap is in /root/CHG-2744.txt on srv01. The account seems to be locked out too: the DC shows lockout events since the night."',
    briefing: BRIEFING,
    goals: [phonebookWorks],
    terminals: [TERMINALS.srv01, TERMINALS.dc01],
    setup(world) {
      const ad = world.hosts.dc01.win!.ad!;
      ad.users['svc-ldap'].password = SVC_NEW_PASSWORD;
      writeFile(world.hosts.srv01, '/root/CHG-2744.txt', `CHG-2744 quarterly rotation of service passwords\n\nsvc-ldap (phone book on srv01): ${SVC_NEW_PASSWORD}\nUpdate /etc/phonebook/bind.pw (no trailing spaces).\n`, world.clock, { mode: 0o600 });
      // The phone book kept trying with the old password through the night.
      script(world, 'srv01', ['phonebook alice', 'phonebook bob', 'phonebook dana', 'phonebook alice', 'phonebook bob', 'phonebook dana'], 20 * 60_000);
    },
    rootCauses: ['ldap-svc-credentials'],
    candidates: CANDIDATES,
    feedback: {
      'ldap-anonymous-bind': 'The script binds (-D and -y): the DC answers with "Invalid credentials", which is about a bind.',
      'ldap-signing-required': 'Code 8 would mean signing; here it is 49 with data 775: the account is locked out.',
    },
    hints: [
      'Run phonebook bob and read the additional info: "data 52e" means a wrong password, "data 775" a locked-out account.',
      'Compare /etc/phonebook/bind.pw with the new password in /root/CHG-2744.txt. On dc01: Get-ADUser svc-ldap -Properties LockedOut,BadLogonCount, and the 4740 events (Caller Computer Name: SRV01).',
      'Fix the file first (printf \'%s\' \'NEWPASSWORD\' > /etc/phonebook/bind.pw, keep it private), then unlock the account on dc01: Unlock-ADAccount svc-ldap. In the other order, the next lookup with the old password locks it again.',
    ],
    explanation: {
      rootCause: 'The password of svc-ldap was rotated in AD, but the phone book still used the old one. Its lookups failed with "data 52e" until the account reached the lockout threshold (5 bad passwords); since then every bind fails with "data 775", even with the new password.',
      manifestation: '"Invalid credentials (49)" in the application; lockout events 4740 on the DC naming SRV01 as the caller.',
      evidence: 'ldap_bind: Invalid credentials (49) … data 775; Get-ADUser svc-ldap shows LockedOut True; bind.pw differs from the rotated password.',
      prevention: 'Rotate service passwords together with every place that uses them (an inventory per account), test right after the change, and alert on lockouts of service accounts.',
    },
    solution: [
      { host: 'srv01', commands: [`printf '%s' '${SVC_NEW_PASSWORD}' > ${PHONEBOOK_PW}`, `chmod 640 ${PHONEBOOK_PW}`] },
      { host: 'dc01', user: 'Administrator', commands: ['Unlock-ADAccount -Identity svc-ldap'] },
    ],
    constraints: [
      {
        id: 'id-svc-password-kept', required: true,
        description: 'svc-ldap keeps the password from the rotation (CHG-2744): the record in the change is what other teams rely on.',
        check(world) {
          const u = world.hosts.dc01.win?.ad?.users['svc-ldap'];
          const ok = !!u && u.password === SVC_NEW_PASSWORD && u.enabled;
          return { id: this.id, ok, required: true, message: ok ? 'The rotation stands.' : !u ? 'svc-ldap is gone.' : !u.enabled ? 'svc-ldap is disabled.' : u.password === LDAP_SVC.password ? 'svc-ldap has its old password again: the rotation (CHG-2744) is undone.' : 'svc-ldap was reset to a password that is not the one recorded in CHG-2744: use the rotated password in bind.pw instead of resetting the account.' };
        },
      },
      bindPwPrivate, phonebookBindsAsService, noPrivilegedGroups('svc-ldap'),
    ],
    concepts: ['id.ldap', 'ad.kerberos'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'id-radius-ca',
    title: 'Nobody gets into rtr01 after the rad01 rebuild',
    difficulty: 'intermediate',
    ticket: 'Network team (alice): "rad01 was reinstalled from the standard Debian image last night (CHG-2766) and its configuration restored from the backup. Since then none of us can log in to rtr01 with our AD passwords; only the break-glass account works."',
    briefing: [...BRIEFING, 'The internal root CA certificate is published at http://srv01.corp.lab/pki/corp-lab-root-ca.crt.'],
    goals: [rtrLogin('alice', AD_ALICE_PASSWORD)],
    terminals: [TERMINALS.rad01, TERMINALS.rtr01, TERMINALS.dc01],
    setup(world) {
      const rad = world.hosts.rad01;
      // The standard image does not trust the internal CA.
      delete rad.fs[CORP_ROOT_LOCAL];
      writeFile(rad, CA_BUNDLE, PUBLIC_ROOTS.map((r) => certPem(r.cert)).join(''), world.clock);
      script(world, 'rad01', ['systemctl restart freeradius']);
    },
    rootCauses: ['ldap-tls-untrusted'],
    candidates: CANDIDATES,
    feedback: {
      'radius-secret-mismatch': 'rad01 answers rtr01 (radius.log has "Login incorrect" lines for rtr01\'s requests), so the client and the secret are fine. Read the error lines before them.',
      'radius-unknown-client': 'The requests are not ignored: radius.log shows them being processed for client rtr01.',
      'ldap-svc-credentials': 'The bind never happens: "Can\'t contact LDAP server" with a certificate error comes before any password is sent.',
    },
    hints: [
      'tail /var/log/freeradius/radius.log on rad01: what does the ldap module say before each "Login incorrect"?',
      '"certificate verify failed (unable to get local issuer certificate)": rad01 does not trust the issuer of dc01\'s certificate. Check with ldapsearch -x -H ldaps://dc01.ad.corp.lab -s base -b \'\' on rad01.',
      'Install the corp root the Debian way: curl -o /usr/local/share/ca-certificates/corp-lab-root-ca.crt http://srv01.corp.lab/pki/corp-lab-root-ca.crt, then update-ca-certificates. Do not set require_cert to never.',
    ],
    explanation: {
      rootCause: 'The fresh Debian image does not trust Corp Lab Root CA. FreeRADIUS\'s ldap module connects to dc01 over LDAPS with require_cert = demand, so the TLS handshake fails, the module cannot look users up, and every request ends in Access-Reject.',
      manifestation: 'All RADIUS logins fail at once after the rebuild; the NAS only sees rejects, and the break-glass account still works.',
      evidence: 'radius.log: "Bind with CN=svc-radius,… to ldaps://dc01.ad.corp.lab:636 failed: Can\'t contact LDAP server" and "certificate verify failed (unable to get local issuer certificate)"; /usr/local/share/ca-certificates is empty.',
      prevention: 'Make the internal root part of the server build (configuration management), not a manual step, and test a RADIUS login (radtest) before putting a rebuilt server back into service.',
    },
    solution: [{ host: 'rad01', commands: [`curl -s -o ${CORP_ROOT_LOCAL} http://srv01.corp.lab/pki/corp-lab-root-ca.crt`, 'update-ca-certificates'] }],
    constraints: [certChecked, policyKept],
    concepts: ['id.radius', 'tls.pki'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'id-radius-group',
    title: 'New network admin cannot log in to the router',
    difficulty: 'beginner',
    ticket: 'Dana: "I moved to the network team on Monday (HR-5521). IT added me to the Network Team list, but rtr01 still says \'Permission denied\' with my normal password. My password works everywhere else."',
    briefing: BRIEFING,
    goals: [rtrLogin('dana', DANA_PASSWORD)],
    terminals: [TERMINALS.rad01, TERMINALS.dc01, TERMINALS.rtr01],
    setup(world) {
      const ad = world.hosts.dc01.win!.ad!;
      ad.groups['network-team'] = { name: 'Network-Team', scope: 'Global', category: 'Distribution', description: 'Mailing list of the network team', members: ['alice', 'dana'], rid: ad.nextRid++ };
    },
    rootCauses: ['radius-not-authorized'],
    candidates: CANDIDATES,
    feedback: {
      'ldap-svc-credentials': 'Dana\'s password is right (her logins work elsewhere, and radius.log shows no bind failure for her).',
      'radius-secret-mismatch': 'alice can log in to rtr01 through RADIUS; the secret is shared by all users.',
    },
    hints: [
      'On rad01: radtest dana \'' + DANA_PASSWORD + '\' localhost 0 testing123. What does the Reply-Message say?',
      'The authorize file lets in members of Network-Admins only. Which groups is dana in? Get-ADUser dana -Properties MemberOf on dc01, or ldapsearch … memberOf on rad01. "Network-Team" is a distribution group (a mailing list), not Network-Admins.',
      'On dc01: Add-ADGroupMember -Identity Network-Admins -Members dana. RADIUS reads memberOf at every login: no restart needed.',
    ],
    explanation: {
      rootCause: 'dana was added to the mailing list Network-Team, not to the security group Network-Admins that the RADIUS policy checks. Authentication would succeed, but authorisation (the group check in the authorize file) rejects her.',
      manifestation: 'Permission denied on rtr01 although the password is right; radius.log shows "Login incorrect" without a bind error, and the reply carries "Not a member of Network-Admins".',
      evidence: 'radtest dana … → Access-Reject with Reply-Message "Not a member of Network-Admins"; dana\'s memberOf lacks CN=Network-Admins.',
      prevention: 'Grant access through documented security groups; make onboarding requests name the group, and check memberOf (not the mailing lists) when access fails.',
    },
    solution: [{ host: 'dc01', user: 'Administrator', commands: ['Add-ADGroupMember -Identity Network-Admins -Members dana'] }],
    constraints: [policyKept, noPrivilegedGroups('dana')],
    concepts: ['id.radius', 'id.ldap'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'id-radius-secret',
    title: 'After the secret rotation: Permission denied on rtr01',
    difficulty: 'intermediate',
    ticket: 'Security (CHG-2755): "The RADIUS shared secret for rtr01 was on a wiki page, so we rotated it on rad01 yesterday afternoon and restarted FreeRADIUS. The network team now says they cannot log in to rtr01." Alice adds: "careful, my account must not get locked out again".',
    briefing: [...BRIEFING, `The new secret (CHG-2755) is in rad01's clients.conf.`],
    goals: [rtrLogin('alice', AD_ALICE_PASSWORD)],
    terminals: [TERMINALS.rtr01, TERMINALS.rad01, TERMINALS.dc01],
    setup(world) {
      const rad = world.hosts.rad01;
      writeFile(rad, CLIENTS_CONF, (readFile(rad, CLIENTS_CONF) ?? '').replace(`secret = ${RTR01_RADIUS_SECRET}`, `# CHG-2755: rotated (the old secret was on a wiki page)\n\tsecret = ${NEW_RADIUS_SECRET}`), world.clock, { mode: 0o640, owner: 'freerad', group: 'freerad' });
      script(world, 'rad01', ['systemctl restart freeradius']);
    },
    rootCauses: ['radius-secret-mismatch'],
    candidates: CANDIDATES,
    feedback: {
      'radius-unknown-client': 'rad01 does not ignore rtr01: radius.log shows its requests being processed (as "Login incorrect"), so the client entry matches.',
      'ldap-svc-credentials': 'The service account binds fine; the user bind fails because the password rad01 decrypts is garbage, a symptom of the secret.',
      'radius-not-authorized': 'alice is a member of Network-Admins; nothing about the policy changed.',
    },
    hints: [
      'On rtr01: journalctl -u ssh. pam_radius_auth says "packet from RADIUS server 10.0.20.65 failed verification: The shared secret is probably incorrect."',
      'The NAS and the server must use the same secret: compare /etc/pam_radius_auth.conf on rtr01 with the client rtr01 section of /etc/freeradius/3.0/clients.conf on rad01. Every failed try is a bad password for alice in AD: check, do not retry.',
      'Put the new secret into /etc/pam_radius_auth.conf (keep mode 600). If alice got locked out meanwhile: Unlock-ADAccount alice on dc01.',
    ],
    explanation: {
      rootCause: 'The secret was changed on rad01 only. RADIUS hides the password with the shared secret, so rad01 decrypted rtr01\'s requests into garbage passwords (rejected by AD), and rtr01 could not verify rad01\'s replies either.',
      manifestation: 'RADIUS logins fail; pam_radius_auth reports failed verification; rad01 logs "Login incorrect (ldap: Bind as user failed)" and AD counts bad passwords for every user who tries, which can lock accounts out.',
      evidence: 'rtr01: "failed verification: The shared secret is probably incorrect"; rad01: Bind as user failed with data 52e for users whose passwords are right; the secrets differ between the two files.',
      prevention: 'Rotate a shared secret on both ends in one change, test with radtest from a host in the client list, and keep secrets in a vault rather than a wiki.',
    },
    solution: [{ host: 'rtr01', commands: [`sed -i 's/^10.0.20.65\\t${RTR01_RADIUS_SECRET}/10.0.20.65\\t${NEW_RADIUS_SECRET}/' ${PAM_RADIUS_CONF}`] }],
    constraints: [secretRotated, pamRadiusPrivate, policyKept],
    concepts: ['id.radius'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'id-radius-unknown-client',
    title: 'RADIUS server does not answer the router',
    difficulty: 'advanced',
    ticket: 'Network team: "Since the clean-up of the RADIUS configuration (CHG-2770: \'clients by their DNS address\') nobody can log in to rtr01 with an AD password; the login takes a few seconds and then fails. radtest on rad01 itself works fine."',
    briefing: BRIEFING,
    goals: [rtrLogin('alice', AD_ALICE_PASSWORD)],
    terminals: [TERMINALS.rad01, TERMINALS.rtr01],
    setup(world) {
      const rad = world.hosts.rad01;
      writeFile(rad, CLIENTS_CONF, (readFile(rad, CLIENTS_CONF) ?? '').replace('# Its requests come from the address of its server-VLAN interface.\n', '# CHG-2770: clients by their DNS address (rtr01.corp.lab)\n').replace('ipaddr = 10.0.20.1', 'ipaddr = 10.0.10.1'), world.clock, { mode: 0o640, owner: 'freerad', group: 'freerad' });
      script(world, 'rad01', ['systemctl restart freeradius']);
    },
    rootCauses: ['radius-unknown-client'],
    acceptable: { 'firewall-drop': 'A dropped request looks the same from rtr01 (no answer). But rad01 receives it: radius.log names the source address it ignores.' },
    candidates: CANDIDATES,
    feedback: {
      'radius-secret-mismatch': 'With a wrong secret the server would still answer (and pam_radius would report failed verification). Here there is no answer at all.',
      'dns-wrong-record': 'rtr01.corp.lab resolves to 10.0.10.1 correctly; the question is which address rtr01 sends from towards rad01.',
    },
    hints: [
      'rtr01: journalctl -u ssh says "RADIUS server 10.0.20.65 failed to respond". rad01: what does radius.log say about the requests?',
      '"Ignoring request … from unknown client 10.0.20.1": rtr01 sends from its interface on the server VLAN (10.0.20.1), not from the address its DNS name points to. Compare with ipaddr in clients.conf.',
      'Set ipaddr = 10.0.20.1 for client rtr01 and RESTART freeradius: a reload (HUP) re-reads the modules, not the client list.',
    ],
    explanation: {
      rootCause: 'A RADIUS server only answers clients listed in clients.conf, matched by the packet\'s source address. rtr01 reaches 10.0.20.65 through its server-VLAN interface, so its requests come from 10.0.20.1; the clean-up listed 10.0.10.1 (the office address that rtr01.corp.lab resolves to), so rad01 ignores every request.',
      manifestation: 'A few seconds of waiting, then a failed login; no answer at all from the RADIUS server, while radtest on the server works (it comes from 127.0.0.1, the localhost client).',
      evidence: 'radius.log: "Ignoring request to auth address * port 1812 bound to server default from unknown client 10.0.20.1 port … proto udp"; pam_radius_auth: "failed to respond".',
      prevention: 'Configure the NAS\'s source address explicitly where the device allows it, list clients by the address they send from, and remember that FreeRADIUS reads clients.conf only at start-up.',
    },
    solution: [{ host: 'rad01', commands: [`sed -i 's/ipaddr = 10.0.10.1/ipaddr = 10.0.20.1/' ${CLIENTS_CONF}`, 'systemctl restart freeradius'] }],
    constraints: [clientsSpecific, policyKept],
    concepts: ['id.radius', 'net.routing'],
  },
];
