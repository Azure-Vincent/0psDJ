// Directory services (LDAP/LDAPS against Active Directory) and RADIUS. Examples
// follow the lab: dc01 (10.0.20.5) is the domain controller of ad.corp.lab and
// answers LDAP on 389 and LDAPS on 636; srv01's phone book looks people up as
// the service account svc-ldap; rad01 (10.0.20.65) runs FreeRADIUS 3.2 with
// the ldap module (svc-radius) and a group policy (Network-Admins); rtr01 is
// the NAS: its sshd asks rad01 through pam_radius_auth, with the local
// break-glass account netadmin. Lab 10 builds the RADIUS side from Debian's
// defaults. OpenLDAP servers, Windows NPS, TACACS+ and 802.1X are deployment
// notes.

import type { Assessment, Lesson, Primer, ServiceGuide } from '../types';

const SVC_LDAP = 'CN=svc-ldap,OU=Service Accounts,DC=ad,DC=corp,DC=lab';
const SVC_RADIUS = 'CN=svc-radius,OU=Service Accounts,DC=ad,DC=corp,DC=lab';
/** The phone book's bind, as srv01's script does it. */
const AS_SVC = `-D '${SVC_LDAP}' -y /etc/phonebook/bind.pw`;
const RADDB = '/etc/freeradius/3.0';

// --- Operate & recover guide ---------------------------------------------------------

export const IDENTITY_GUIDE: ServiceGuide = {
  purpose:
    'A **directory** is the central list of the people, groups and computers of an organisation. Applications read it over **LDAP** (Lightweight Directory Access Protocol) to find a person, check a password or see group memberships, instead of keeping their own user lists. **RADIUS** (Remote Authentication Dial-In User Service) lets network devices (routers, switches, VPN gateways, Wi-Fi) ask one central server "may this person log in here?". An administrator connects applications and devices to the directory with least-privilege service accounts over encrypted connections, decides who may log in where (groups), keeps passwords and shared secrets in sync, and keeps a way in when the central service is down.',
  architecture: [
    { q: 'What does it accomplish?', a: 'One account per person for every system (no local passwords to forget or leave behind when someone leaves), central control of access by **group membership**, and one place that records logins. LDAP answers "who is this, and what groups is she in?"; RADIUS turns that into a yes or no for a device.' },
    { q: 'How does it work internally?', a: 'The directory is a **tree of entries**. Each entry has a unique name, the **DN** (distinguished name, e.g. CN=Bob Keller,CN=Users,DC=ad,DC=corp,DC=lab), and attributes (mail, memberOf, sAMAccountName). A client connects, **binds** (logs in to the directory, usually as a service account), and **searches** below a **base** DN with a **scope** and a **filter**. To check a password, the application binds again **as the user**. A RADIUS server receives an **Access-Request** from a known **client** (the NAS), looks the user up (here: in AD over LDAPS), applies its **policy** (here: member of Network-Admins), checks the password, and answers **Access-Accept** or **Access-Reject**.' },
    { q: 'Which protocols does it use?', a: 'LDAPv3 (RFC 4511) over TCP, protected by **TLS**: either **LDAPS** (TLS from the first byte, port 636) or **StartTLS** (plain LDAP that switches to TLS, port 389). RADIUS (RFC 2865) over **UDP**: the password is hidden with the **shared secret**, replies are signed with it, and the **Message-Authenticator** attribute (RFC 3579) signs whole requests. DNS finds the servers; Kerberos is the other way to authenticate against AD.' },
    { q: 'Which ports and transport?', a: 'TCP **389** LDAP (and StartTLS), TCP **636** LDAPS, TCP **3268**/3269 the AD global catalog (plain/TLS). UDP **1812** RADIUS authentication, UDP **1813** RADIUS accounting; FreeRADIUS also listens on 127.0.0.1:18120 (status). Old devices may still use 1645/1646.' },
    { q: 'Which processes and OS components implement it?', a: 'On the DC: Active Directory Domain Services (NTDS, inside lsass.exe) answers LDAP. On Linux clients: libldap with /etc/ldap/ldap.conf and the ldap-utils tools (ldapsearch, ldapwhoami). On rad01: the **freeradius** service (/etc/freeradius/3.0) with its ldap and files modules. On the NAS: sshd with PAM and **pam_radius_auth** (/etc/pam_radius_auth.conf). Windows Server has its own RADIUS server, NPS.' },
    { q: 'Which other services does it depend on?', a: 'DNS (dc01.ad.corp.lab must resolve, and the name must match the certificate), PKI (the client must trust the CA that issued the DC\'s certificate), time (certificates and Kerberos), routing and firewalls (TCP 636 to the DC, UDP 1812 from the NAS), and the directory\'s own health (accounts enabled, not locked out, the right group memberships).' },
    { q: 'How do requests travel?', a: 'alice runs ssh alice@rtr01.corp.lab → sshd on rtr01 hands the password to PAM → pam_radius_auth sends an Access-Request from 10.0.20.1 to 10.0.20.65:1812 (password hidden with the secret) → FreeRADIUS finds client rtr01 by the source address → the ldap module opens LDAPS to dc01:636, binds as svc-radius and searches (sAMAccountName=alice) → the files policy checks LDAP-Group == "Network-Admins" → the ldap module binds as alice with her password → Access-Accept goes back → pam_radius_auth checks the reply with the secret → sshd lets alice in.' },
    { q: 'How do authentication and authorisation work?', a: '**Authentication** (is the password right?) is a bind as the user: AD checks the password and its lockout counter. **Authorisation** (may this user log in here?) is a policy: the RADIUS server\'s authorize file checks group membership (memberOf); an application can filter by group in its search. The service accounts themselves get **read-only** rights. Between NAS and RADIUS server, both sides prove they know the **shared secret**.' },
    { q: 'How does it start at boot?', a: 'NTDS starts with the DC. freeradius.service reads radiusd.conf, **clients.conf**, mods-enabled/* and the policy files at start; an error stops it (the journal names the file and line). libldap and pam_radius_auth have no daemon: they read their files at every use, so a change there applies to the next lookup or login.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'If the DC is unreachable, applications cannot look anybody up and RADIUS rejects every login. If FreeRADIUS stops, the NAS gets no answer: pam_radius_auth waits for its timeout, logs "failed to respond" and PAM falls back to the **local** accounts. That is why every device keeps a local **break-glass** account, and why critical sites run two RADIUS servers and two DCs.' },
  ],
  ports: [
    { port: '389', proto: 'TCP', purpose: 'LDAP (clear text, or StartTLS to switch to TLS)' },
    { port: '636', proto: 'TCP', purpose: 'LDAPS: LDAP inside TLS from the first byte' },
    { port: '3268 / 3269', proto: 'TCP', purpose: 'AD global catalog (whole forest, fewer attributes), plain / TLS' },
    { port: '1812', proto: 'UDP', purpose: 'RADIUS authentication (Access-Request, Accept, Reject, Challenge)' },
    { port: '1813', proto: 'UDP', purpose: 'RADIUS accounting (session start, stop, interim updates)' },
    { port: '18120', proto: 'UDP (127.0.0.1)', purpose: 'FreeRADIUS status server (local only)' },
  ],
  processes: [
    { name: 'NTDS (lsass.exe)', platform: 'Windows Server domain controller', role: 'Active Directory: answers LDAP, LDAPS and the global catalog, checks binds' },
    { name: 'slapd', platform: 'Linux (OpenLDAP server)', role: 'A directory server outside AD; same protocol, different schema (uid instead of sAMAccountName)' },
    { name: 'ldapsearch / ldapwhoami (libldap)', platform: 'Linux (ldap-utils)', role: 'Test binds and searches; /etc/ldap/ldap.conf sets the defaults' },
    { name: 'freeradius', platform: 'Linux (rad01)', role: 'RADIUS server: clients, the ldap module (users and groups from AD), the files policy' },
    { name: 'sshd + pam_radius_auth', platform: 'Linux NAS (rtr01)', role: 'Sends the login to RADIUS; PAM falls back to local accounts' },
    { name: 'NPS (Network Policy Server)', platform: 'Windows Server', role: 'Microsoft\'s RADIUS server, with network policies on AD groups' },
  ],
  dependencies: {
    title: 'What "alice logs in to rtr01 with her AD password" depends on (top needs everything below it)',
    caption: 'Every layer can fail on its own; the user only ever sees "Permission denied".',
    rows: [
      { label: 'Login', nodes: [{ id: 'user', label: 'alice on ws01', sub: 'ssh alice@rtr01', kind: 'client' }] },
      { label: 'NAS', nodes: [{ id: 'nas', label: 'rtr01 sshd + PAM', sub: 'pam_radius_auth, netadmin', kind: 'server' }] },
      { label: 'Path', nodes: [{ id: 'secret', label: 'Shared secret', sub: 'same on both sides', kind: 'data' }, { id: 'fw', label: 'rad01 firewall', sub: 'udp 1812 from 10.0.20.1', kind: 'network' }] },
      { label: 'RADIUS', nodes: [{ id: 'clients', label: 'clients.conf', sub: 'rtr01 = 10.0.20.1', kind: 'data' }, { id: 'rad', label: 'FreeRADIUS', sub: 'rad01', kind: 'service' }, { id: 'policy', label: 'authorize', sub: 'LDAP-Group Network-Admins', kind: 'data' }] },
      { label: 'LDAP', nodes: [{ id: 'mod', label: 'ldap module', sub: 'svc-radius, LDAPS', kind: 'service' }, { id: 'dns', label: 'DNS', sub: 'dc01.ad.corp.lab', kind: 'network' }, { id: 'ca', label: 'CA trust', sub: 'Corp Lab Root CA', kind: 'data' }] },
      { label: 'Directory', nodes: [{ id: 'ad', label: 'dc01: Active Directory', sub: 'users, groups, lockout', kind: 'server' }] },
    ],
    edges: [['user', 'nas'], ['nas', 'secret'], ['nas', 'fw'], ['fw', 'rad'], ['secret', 'rad'], ['rad', 'clients'], ['rad', 'policy'], ['rad', 'mod'], ['mod', 'dns'], ['mod', 'ca'], ['mod', 'ad'], ['policy', 'ad']],
  },
  sequence: {
    title: 'alice logs in to rtr01: from SSH to Active Directory and back',
    caption: 'OpenSSH with pam_radius_auth, FreeRADIUS 3.2.1, AD on Windows Server. Where each ticket breaks the chain is noted.',
    lanes: [{ id: 'u', label: 'ws01', sub: 'alice (ssh)' }, { id: 'n', label: 'rtr01', sub: 'sshd, pam_radius_auth' }, { id: 'r', label: 'rad01', sub: 'FreeRADIUS' }, { id: 'd', label: 'dc01', sub: 'Active Directory' }],
    steps: [
      { from: 'u', to: 'n', label: 'SSH: user alice, password' },
      { from: 'n', to: 'r', label: 'Access-Request from 10.0.20.1 (password hidden with the secret)', note: 'Source address not in clients.conf → "Ignoring request … from unknown client": no answer, rtr01 logs "failed to respond".' },
      { from: 'r', to: 'r', label: 'client rtr01 found; decrypt the password with its secret', note: 'Wrong secret → the password decrypts to garbage, AD counts a bad password, rtr01 cannot verify the reply.' },
      { from: 'r', to: 'd', label: 'LDAPS :636, TLS handshake, bind as svc-radius', note: 'CA not trusted → "Can\'t contact LDAP server … certificate verify failed". Wrong service password → 49, data 52e.' },
      { from: 'r', to: 'd', label: 'search (sAMAccountName=alice) → DN, memberOf' },
      { from: 'r', to: 'r', label: 'files policy: LDAP-Group == "Network-Admins"?', note: 'Not a member → Access-Reject with "Not a member of Network-Admins", no password check.' },
      { from: 'r', to: 'd', label: 'bind as CN=Alice Martin,… with her password', note: 'Wrong password → 49 data 52e; five in a row → locked out (data 775, event 4740).' },
      { from: 'r', to: 'n', label: 'Access-Accept (Response Authenticator signed with the secret)' },
      { from: 'n', to: 'u', label: 'PAM success: shell on rtr01' },
    ],
  },
  files: [
    { path: '/etc/ldap/ldap.conf', platform: 'Debian (ldap-utils, every LDAP client)', kind: 'config', perms: 'root:root 0644', contains: 'BASE (default search base), URI (ldaps://dc01.ad.corp.lab), TLS_CACERT (CA bundle), TLS_REQCERT (demand by default).', accessed: 'By libldap at every ldapsearch and by applications that use libldap; ~/.ldaprc can override it per user.', problems: 'A "temporary" ldap:// URI that breaks when the DC requires signing; TLS_REQCERT never (no protection at all); a TLS_CACERT path that does not exist.' },
    { path: '/etc/phonebook/bind.pw', platform: 'srv01 (the phone book)', kind: 'auth', perms: 'root:root 0640', contains: 'The password of svc-ldap, nothing else (ldapsearch -y reads the whole file; a trailing newline is stripped).', accessed: 'At every lookup.', problems: 'World-readable (anyone on the server can read the directory as the service), out of date after a rotation (bind fails, then the account locks).' },
    { path: `${RADDB}/clients.conf`, platform: 'FreeRADIUS 3.x (Debian)', kind: 'config', perms: 'freerad:freerad 0640', contains: 'One client { } per NAS: ipaddr (the address requests come from), secret, shortname, require_message_authenticator.', accessed: 'Only when freeradius **starts**: a reload (HUP) does not re-read it.', problems: 'The NAS\'s DNS address instead of its source address; a short or default secret; a whole network or * as client; forgetting the restart.' },
    { path: `${RADDB}/mods-enabled/ldap`, platform: 'FreeRADIUS 3.x (link to mods-available/ldap on Debian)', kind: 'config', perms: 'freerad:freerad 0640', contains: 'server, port, identity and password (the service account), base_dn, user { filter }, group { filter, membership_attribute }, tls { ca_file, require_cert }.', accessed: 'At start and on reload (HUP).', problems: 'uid filters copied from OpenLDAP examples (AD uses sAMAccountName); ldap:// instead of ldaps://; require_cert never; the service password out of date.' },
    { path: `${RADDB}/mods-config/files/authorize`, platform: 'FreeRADIUS 3.x (files module)', kind: 'config', perms: 'freerad:freerad 0640', contains: 'Entries: a user name or DEFAULT with check items on the first line, indented reply items below. The first matching entry decides unless Fall-Through = Yes.', accessed: 'At start and on reload.', problems: 'The default reject placed before the group rule; a typo in the group name (every login rejected); check and reply items mixed up.' },
    { path: '/var/log/freeradius/radius.log', platform: 'FreeRADIUS (log { destination = files })', kind: 'log', perms: 'freerad:freerad 0640', contains: '"Login OK" and "Login incorrect" per request (with the reason in brackets), ldap module errors, ignored clients, bad Message-Authenticators, HUP messages.', accessed: 'Written for every request (auth = yes).', problems: 'The NAS only sees accept/reject/no answer: the reason is only here.' },
    { path: '/etc/pam_radius_auth.conf', platform: 'Linux NAS (libpam-radius-auth)', kind: 'auth', perms: 'root:root 0600', contains: 'One line per server: server[:port] secret [timeout]; tried in order.', accessed: 'At every login through PAM.', problems: 'Example servers left in (each one costs its timeout), the secret not matching clients.conf, readable by others (the secret lets anyone forge answers).' },
    { path: '/etc/pam.d/sshd', platform: 'Linux NAS', kind: 'config', perms: 'root:root 0644', contains: '"auth sufficient pam_radius_auth.so" before "@include common-auth": RADIUS first, local passwords after.', accessed: 'At every SSH login.', problems: '"required" instead of "sufficient" locks out the break-glass account when RADIUS is down; the line after common-auth is never reached for local users.' },
    { path: 'HKLM:\\System\\CurrentControlSet\\Services\\NTDS\\Parameters', platform: 'Windows domain controller', kind: 'registry', contains: 'LDAPServerIntegrity (1 = signing negotiated, 2 = required: simple binds need TLS), LdapEnforceChannelBinding.', accessed: 'By NTDS for each bind (set by the GPO "Domain controller: LDAP server signing requirements").', problems: 'Turning signing on breaks every client that binds in clear text over 389; event 2889 lists them beforehand.' },
  ],
  management: [
    {
      platform: 'Application server (srv01): LDAP client',
      tasks: [
        { task: 'Can the service account bind?', command: `ldapwhoami -x ${AS_SVC}`, explain: 'Prints u:CORP\\svc-ldap on success; otherwise the LDAP error (49 with a data code, 8, or -1 for TLS).', sim: true },
        { task: 'Look someone up the way the application does', command: `ldapsearch -x -LLL ${AS_SVC} '(sAMAccountName=bob)' displayName mail`, explain: 'Bind as the service, search below BASE from ldap.conf, return two attributes. The refldap lines at the end are AD\'s referrals: normal.', sim: true },
        { task: 'Read the client defaults', command: 'cat /etc/ldap/ldap.conf\nls -l /etc/phonebook/bind.pw', explain: 'URI, BASE and the CA file; the password file must not be readable by others.', sim: true },
        { task: 'What does the DC tell anyone? (no bind)', command: "ldapsearch -x -LLL -s base -b '' '(objectClass=*)' defaultNamingContext dnsHostName", explain: 'The rootDSE: the one entry AD answers without a bind. Proves the connection and TLS work.', sim: true },
      ],
    },
    {
      platform: 'Domain controller (dc01): Active Directory',
      tasks: [
        { task: 'Is the service account healthy?', command: 'Get-ADUser svc-ldap -Properties LockedOut,BadLogonCount\nSearch-ADAccount -LockedOut', explain: 'Enabled, not locked out, BadLogonCount 0; the list of every locked-out account.', sim: true },
        { task: 'Who may log in to network devices?', command: 'Get-ADGroupMember Network-Admins\nGet-ADUser dana -Properties MemberOf', explain: 'The group the RADIUS policy checks, and the groups of one user.', sim: true },
        { task: 'Who locked the account out, from where?', command: "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4740} -MaxEvents 5", explain: 'Event 4740 names the account and the Caller Computer Name (the machine that kept sending a bad password).', sim: true },
        { task: 'Is LDAP signing required?', command: "Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Services\\NTDS\\Parameters'", explain: 'LDAPServerIntegrity 2 = simple binds only over LDAPS or StartTLS.', sim: true },
        { task: 'Lockout policy', command: 'Get-ADDefaultDomainPasswordPolicy', explain: 'LockoutThreshold (5 here), LockoutDuration and the observation window.', sim: true },
      ],
    },
    {
      platform: 'RADIUS server (rad01): FreeRADIUS',
      tasks: [
        { task: 'Is the configuration valid?', command: 'freeradius -XC', explain: 'Reads every file like a start would, lists the clients and the ldap settings, ends with "Configuration appears to be OK".', sim: true },
        { task: 'Test a login without a router', command: "radtest alice 'Office-Corp-2026' localhost 0 testing123\ntail -n 3 /var/log/freeradius/radius.log", explain: 'From rad01 itself (the localhost client, secret testing123); radius.log says why a reject happened. Every wrong password counts against the user in AD.', sim: true },
        { task: 'Which settings does the ldap module use?', command: `grep -E '^\\s*(server|identity|base_dn|filter|require_cert)' ${RADDB}/mods-enabled/ldap\ngrep -v '^#' ${RADDB}/mods-config/files/authorize`, explain: 'Server URI, bind identity, base, filters, certificate checking; the group policy.', sim: true },
        { task: 'Is it listening and reachable?', command: 'ss -ulnp\nnft list ruleset', explain: 'UDP 1812/1813 (and 127.0.0.1:18120); the firewall admits UDP 1812 from the NAS addresses only.', sim: true },
        { task: 'Apply a change', command: 'systemctl reload freeradius\nsystemctl restart freeradius\njournalctl -u freeradius -n 3', explain: 'Reload re-reads the modules (ldap, files); clients.conf needs a restart.', sim: true },
      ],
    },
    {
      platform: 'Network device (rtr01): the NAS',
      tasks: [
        { task: 'Which RADIUS servers does it ask, with which secret?', command: "grep -v '^#' /etc/pam_radius_auth.conf\nls -l /etc/pam_radius_auth.conf", explain: 'server secret timeout lines, tried in order; mode 600.', sim: true },
        { task: 'Is RADIUS in the SSH login stack?', command: 'grep -n pam_radius /etc/pam.d/sshd', explain: '"auth sufficient pam_radius_auth.so" before "@include common-auth".', sim: true },
        { task: 'What did pam_radius_auth say?', command: 'journalctl -u ssh -n 20', explain: '"failed to respond" (no answer), "failed verification" (secret), or a normal "Accepted password".', sim: true },
        { task: 'Which address do requests come from?', command: 'ip route get 10.0.20.65', explain: 'The src address is what the RADIUS server must have in clients.conf (here 10.0.20.1, not the address rtr01.corp.lab resolves to).', sim: true },
      ],
    },
  ],
  actions: [
    { action: 'systemctl reload freeradius (HUP)', when: 'After changing mods-enabled/ldap or the authorize file.', effect: 'Modules are re-read; running requests and the client list stay.', risk: 'clients.conf changes are **not** applied: the new NAS stays "unknown".' },
    { action: 'systemctl restart freeradius', when: 'After changing clients.conf or radiusd.conf (check with freeradius -XC first).', effect: 'The server stops and reads everything again.', risk: 'An invalid file stops RADIUS: every NAS falls back to local accounts until it starts.' },
    { action: 'Unlock-ADAccount', when: 'A service or user account is locked out (data 775, event 4740).', effect: 'The account can bind again.', risk: 'Unlocking before fixing the source (old password in a file, a wrong RADIUS secret) locks it again within minutes.' },
    { action: 'Rotating a service account password', when: 'Planned rotation, a leak, a person who knew it leaving.', effect: 'Old copies stop working.', risk: 'Every place that uses it (bind.pw, mods-enabled/ldap) must change in the same change window, or the account locks out.' },
    { action: 'Rotating a RADIUS shared secret', when: 'The secret leaked or is old.', effect: 'Requests with the old secret fail.', risk: 'Change the NAS and clients.conf together and restart; a mismatch turns every login into a bad password in AD.' },
    { action: 'Requiring LDAP signing (LDAPServerIntegrity 2)', when: 'Hardening the DC.', effect: 'Clear-text simple binds are refused (code 8).', risk: 'Find clear-text clients first (event 2889) and move them to LDAPS.' },
  ],
  workflow: [
    { question: 'What does the NAS say?', why: 'The device knows whether it got no answer, an answer it could not verify, or a reject.', command: 'journalctl -u ssh -n 20', healthy: 'Accepted password for alice', broken: '"RADIUS server 10.0.20.65 failed to respond" (no answer: client entry, firewall, server down); "failed verification: The shared secret is probably incorrect"; "Failed password" after RADIUS rejected', next: 'Then the RADIUS server\'s log.', sim: true },
    { question: 'Did the RADIUS server get the request, and what did it decide?', why: 'radius.log has the reason for every decision.', command: 'tail -n 20 /var/log/freeradius/radius.log', healthy: 'Login OK: [alice] (from client rtr01 port 0 cli …)', broken: '"Ignoring request … from unknown client"; "invalid Message-Authenticator! (Shared secret is incorrect.)"; "Login incorrect (ldap: Bind as user failed)"; "Login incorrect: [dana]" (policy); ldap errors before it', next: 'Test the same login from rad01 itself.', sim: true },
    { question: 'Does the login work without the NAS?', why: 'radtest on the server separates the NAS (client, secret, firewall) from the server (LDAP, policy).', command: "radtest alice 'Office-Corp-2026' localhost 0 testing123", healthy: 'Received Access-Accept', broken: 'Access-Reject with a Reply-Message (policy); Access-Reject without one (password, LDAP); No reply (server down)', next: 'If radtest fails too: the LDAP side.', sim: true },
    { question: 'Can rad01 reach and trust the DC?', why: 'The ldap module fails before any password is checked if TLS or the service bind fails.', command: `ldapwhoami -x -H ldaps://dc01.ad.corp.lab -D '${SVC_RADIUS}' -W`, healthy: 'u:CORP\\svc-radius', broken: '"Can\'t contact LDAP server (-1)" with certificate verify failed / hostname does not match; "Invalid credentials (49)" data 52e or 775', next: 'Then the user and the groups.', sim: false },
    { question: 'Is the user allowed, and is the account healthy?', why: 'A right password is not enough: the policy wants a group, and a locked account refuses every password.', command: 'Get-ADUser dana -Properties MemberOf,LockedOut,BadLogonCount', healthy: 'MemberOf contains CN=Network-Admins; LockedOut False', broken: 'Only a distribution list (Network-Team); LockedOut True; BadLogonCount climbing', next: 'Fix the membership or the source of bad passwords, then test again.', sim: true },
  ],
  failures: [
    { symptom: 'An application finds nobody: "Operations error (1)", 000004DC', causes: ['The search runs without a bind (anonymous)'], diagnose: ['ldapwhoami -x (prints "anonymous")', 'The script or application configuration: -D and -y'], fix: 'Bind as the read-only service account with a password file.', verify: 'The lookup returns entries.' },
    { symptom: 'Binds fail after the DC was hardened: "Strong(er) authentication required (8)"', causes: ['The client binds in clear text over ldap:// and the DC requires signing'], diagnose: ['URI in ldap.conf or the application', 'LDAPServerIntegrity on the DC'], fix: 'Use ldaps:// (or StartTLS with -ZZ); keep the hardening.', verify: 'ldapwhoami over ldaps:// works.' },
    { symptom: '"Invalid credentials (49)" for a service account', causes: ['Old password after a rotation (data 52e)', 'Locked out by repeated failures (data 775)', 'Disabled (data 533)'], diagnose: ['The data code', 'Get-ADUser -Properties LockedOut,BadLogonCount; event 4740'], fix: 'Update every copy of the password first, then Unlock-ADAccount.', verify: 'The bind works and BadLogonCount stays 0.' },
    { symptom: 'Every RADIUS login fails after a rebuild; radius.log: certificate verify failed', causes: ['The server does not trust the CA of the DC\'s certificate'], diagnose: ['ldapsearch -x -H ldaps://dc01.ad.corp.lab … on rad01', 'ls /usr/local/share/ca-certificates'], fix: 'Install the internal root and run update-ca-certificates; keep require_cert = demand.', verify: 'radtest gets Access-Accept.' },
    { symptom: 'One user is refused, others work, the password is right', causes: ['Not in the group the policy checks'], diagnose: ['radtest: Reply-Message "Not a member of Network-Admins"', 'Get-ADUser -Properties MemberOf'], fix: 'Add the user to the security group (not a mailing list).', verify: 'radtest and ssh succeed.' },
    { symptom: 'NAS: "failed verification: The shared secret is probably incorrect"', causes: ['The secret differs between the NAS and clients.conf'], diagnose: ['Compare /etc/pam_radius_auth.conf with the client section'], fix: 'Put the same secret on both sides (restart freeradius if clients.conf changed); unlock users who got locked out.', verify: 'Login works; radius.log shows Login OK.' },
    { symptom: 'NAS: "failed to respond", but radtest on the server works', causes: ['The NAS sends from an address no client entry covers', 'Firewall drops UDP 1812', 'clients.conf changed without a restart'], diagnose: ['radius.log: "Ignoring request … from unknown client"', 'ip route get on the NAS; nft list ruleset on the server'], fix: 'ipaddr = the real source address, restart; firewall rule for that address.', verify: 'radius.log shows the request from client rtr01.' },
  ],
  verification: [
    { check: 'The application can bind and search', command: `ldapsearch -x -LLL ${AS_SVC} '(sAMAccountName=bob)' mail`, expect: 'mail: bob@corp.lab' },
    { check: 'RADIUS accepts a member and refuses a non-member', command: "radtest alice '…' localhost 0 testing123; radtest dana '…' localhost 0 testing123", expect: 'Access-Accept; Access-Reject with "Not a member of Network-Admins"' },
    { check: 'The configuration loads', command: 'freeradius -XC', expect: 'Configuration appears to be OK' },
    { check: 'Secrets and passwords are private', command: 'ls -l /etc/pam_radius_auth.conf /etc/phonebook/bind.pw', expect: '-rw------- and -rw-r----- (nothing for others)' },
    { check: 'Break-glass works with RADIUS down', command: 'systemctl stop freeradius (rad01); ssh netadmin@rtr01; systemctl start freeradius', expect: 'netadmin logs in after the RADIUS timeout' },
  ],
  refIds: ['ldapsearch', 'ldapwhoami', 'radtest', 'freeradius', 'file:ldap-conf', 'file:clients-conf', 'file:freeradius-ldap', 'file:freeradius-authorize', 'file:pam-radius-auth-conf', 'proc:ldap-app-lookup-fails', 'proc:radius-login-fails'],
};

// --- Lesson -------------------------------------------------------------------------

export const IDENTITY_LESSON: Lesson = {
  id: 'identity',
  moduleId: 'F',
  title: 'Directory services (LDAP/LDAPS) and RADIUS',
  level: 'intermediate',
  summary: 'Use Active Directory from applications and network devices: the LDAP tree, DNs, binds and searches, service accounts, LDAPS, StartTLS and the DC\'s signing policy, AD\'s error codes and lockouts; then RADIUS: NAS and server, shared secrets, FreeRADIUS with an LDAP back end and a group policy, pam_radius_auth, and a break-glass account.',
  concepts: ['id.ldap', 'id.radius', 'tls.pki', 'fw.path'],
  what: `
A company has one list of its people: who they are, their mail address, their phone number, which team they are in, their password. That list is the **directory**. In most companies it is **Active Directory** (AD), the directory of a Windows domain (see [Active Directory and Kerberos](#/lesson/ad-kerberos/what)). Windows logons use it through Kerberos. Everything else (a Linux web application, a phone book, a VPN gateway, a router) reads it through two protocols: **LDAP** and **RADIUS**.

### Directories and LDAP
**LDAP** (Lightweight Directory Access Protocol) is how a program asks a directory questions: "find the entry whose login name is bob and give me his mail address", "is this alice's password?", "which groups is dana in?". It runs over TCP 389, or **LDAPS** on 636, which is LDAP inside **TLS** (encrypted, with the server proving its identity by a certificate; see [TLS](#/lesson/tls/what)).

Applications use the directory instead of keeping their own user lists, so a person has **one** password, and disabling one account in AD locks the person out everywhere.

:::practice
Q: Why should an intranet application look people up in AD instead of keeping its own user table?
A: One account and password per person, kept current in one place: when someone leaves or changes team, every application sees it at once.
Q: Which TCP ports do LDAP and LDAPS use?
A: **389** for LDAP (clear text, or StartTLS) and **636** for LDAPS.
:::

### RADIUS and network devices
Routers, switches, VPN gateways and Wi-Fi access points are not part of the domain and do not speak LDAP well. They use **RADIUS** (Remote Authentication Dial-In User Service): the device, called the **NAS** (network access server), sends the user name and password to a **RADIUS server** in one UDP packet and gets back **accept** or **reject**. The RADIUS server does the real work: it asks the directory, applies a policy ("only the network team"), and answers.

:::practice
Q: In RADIUS, what is the NAS?
A: The device the user logs in to (router, switch, VPN gateway, access point). It forwards the login to the RADIUS server and acts on the answer.
Q: Which transport and port does RADIUS authentication use?
A: **UDP 1812** (accounting: UDP 1813).
:::

### Authentication, authorisation and accounting
Three questions, often called **AAA**:
- **Authentication**: is this really alice? (the password is right)
- **Authorisation**: may alice do this, here? (she is in Network-Admins, so she may log in to routers)
- **Accounting**: what did she do, and when? (session start and stop records)

A login can fail at either of the first two: dana's password is right (authentication succeeds), but she is not in the group (authorisation fails). Telling them apart is half of troubleshooting.

:::practice
Q: Dana's password works on her PC but the router refuses her. Which of the three A's is the likely problem?
A: **Authorisation**: her password is fine (authentication), but the policy does not allow her on that device.
Q: Which A records when a session started and stopped?
A: **Accounting**.
:::

### In the lab
> **dc01** (10.0.20.5) is the domain controller of **ad.corp.lab** (NetBIOS name CORP). It answers LDAP on 389, LDAPS on 636 and the global catalog on 3268. Its LDAPS certificate is for **dc01.ad.corp.lab**, issued by **Corp Lab Issuing CA 1** (root: Corp Lab Root CA); ns1 has the record for that name. **OU=Service Accounts** holds **svc-ldap** (the phone book) and **svc-radius** (RADIUS); the group **Network-Admins** has alice as its member; users include alice, bob and dana. **srv01** runs the intranet phone book: \`/usr/local/bin/phonebook NAME\` runs ldapsearch as svc-ldap with the password in /etc/phonebook/bind.pw. **rad01** (10.0.20.65) runs **FreeRADIUS 3.2.1** with the ldap module (svc-radius, LDAPS) and a policy that admits Network-Admins only. **rtr01** is the NAS: its sshd asks rad01 first (pam_radius_auth) and keeps the local account **netadmin** for emergencies. **Lab 10** builds the RADIUS side from Debian's defaults. Simulated: OpenLDAP 2.5 ldapsearch and ldapwhoami (simple binds with -x, -H, -D, -w/-W/-y, -b, -s, -LLL, -Z/-ZZ, ldap.conf with BASE, URI, TLS_CACERT, TLS_REQCERT), AD's answers (rootDSE without a bind, "Operations error" for anonymous searches, bind errors 49 with data 52e/775/533/532, the signing policy LDAPServerIntegrity, referrals, the lockout threshold with events 4625 and 4740), certificate checks for LDAPS and StartTLS, FreeRADIUS (clients.conf read at start, ldap and files modules re-read on reload, radius.log, freeradius -C/-XC), radtest with a Message-Authenticator, pam_radius_auth in sshd's PAM stack with timeouts, verification of replies and fallback to local accounts. Simplified: no writes to the directory (ldapmodify), no SASL/Kerberos binds, no OpenLDAP server, no RADIUS accounting, EAP/802.1X, CHAP or vendor attributes, no NPS.

:::practice
Q: In the lab, which account does the phone book bind as, and where is its password?
A: **svc-ldap** (CN=svc-ldap,OU=Service Accounts,DC=ad,DC=corp,DC=lab); the password is in **/etc/phonebook/bind.pw** on srv01.
Q: Which machine is the NAS in the lab, and which is the RADIUS server?
A: **rtr01** is the NAS; **rad01** (10.0.20.65) is the RADIUS server.
:::

`,

  internals: `
### 1. Entries, DNs and the tree
A directory is a **tree**. Every entry has a **distinguished name (DN)**: its own name (the **RDN**) followed by the names of its parents, up to the root:
\`\`\`
CN=Bob Keller,CN=Users,DC=ad,DC=corp,DC=lab
CN=svc-ldap,OU=Service Accounts,DC=ad,DC=corp,DC=lab
\`\`\`
- **DC=** (domain component): the domain ad.corp.lab becomes DC=ad,DC=corp,DC=lab, the root of the tree (the **naming context**).
- **OU=** (organisational unit): a folder you create (Service Accounts).
- **CN=** (common name): an object, or a built-in container such as CN=Users.

Each entry has **attributes**: objectClass (user, group, computer), sAMAccountName (the login name, alice), userPrincipalName (alice@ad.corp.lab), displayName, mail, **memberOf** (the groups of a user) and **member** (the members of a group), userAccountControl (disabled or not), badPwdCount, lockoutTime. An OpenLDAP server uses other names for the same ideas (uid instead of sAMAccountName), which is why examples copied from the Internet often do not work against AD.

:::practice
Q: What is the DN of the domain root for the domain ad.corp.lab?
A: **DC=ad,DC=corp,DC=lab**.
Q: Which attribute holds a user's login name in Active Directory, and which one lists her groups?
A: **sAMAccountName** for the login name; **memberOf** for her groups.
:::

### 2. Binds and service accounts
Before a client can read the directory it **binds**: it logs in to the LDAP connection. A **simple bind** sends a DN (or alice@ad.corp.lab, or CORP\\alice) and a password; the OpenLDAP tools do a simple bind with **-x** (without it they try SASL/GSS-SPNEGO, which needs a Kerberos ticket). A bind with no name or no password is **anonymous**.

Active Directory lets anonymous clients read **only the rootDSE** (the server's own description: naming contexts, dnsHostName, supported features). Any other anonymous search gets **"Operations error (1)"** with 000004DC "a successful bind must be completed".

Applications therefore bind as a **service account**: a dedicated, read-only account (svc-ldap) whose password lives in a file only the application can read (\`-y /etc/phonebook/bind.pw\`). Never a person's account (it breaks when the person leaves or changes the password) and never an administrator (far too much power).

A failed bind is **"Invalid credentials (49)"**; AD puts the real reason in the **data** code of the additional info:
- **52e** wrong password (or unknown user),
- **775** account **locked out**,
- **533** account disabled,
- **532** password expired.

Every wrong password raises the account's bad-password count. At the domain's **lockout threshold** (5 here) AD locks the account (event **4740** on the DC, with the name of the calling computer) and from then on every bind fails with 775, **even with the right password**.

:::practice
Q: A bind fails with "Invalid credentials (49)" and "data 775". The password in the file is correct. Why does it still fail?
A: **775** means the account is **locked out**: AD refuses every bind until it is unlocked (or the lockout duration ends), whatever the password.
Q: Why does ldapsearch without -x fail against AD with a SASL/GSS-SPNEGO error?
A: Without **-x** the tools try a **SASL** bind, which needs Kerberos credentials; **-x** asks for a simple bind with a DN and password.
:::

### 3. Searches: base, scope, filter
A search has four parts:
- **base**: where to start (\`-b 'DC=ad,DC=corp,DC=lab'\`, or BASE in ldap.conf);
- **scope**: \`-s base\` (only the base entry), \`one\` (its direct children), \`sub\` (the base and everything below, the default), \`children\` (everything below, not the base);
- **filter** (RFC 4515), always in brackets: \`(sAMAccountName=bob)\`, \`(&(objectClass=user)(memberOf=CN=Network-Admins,CN=Users,DC=ad,DC=corp,DC=lab))\`, \`(|(mail=*)(telephoneNumber=*))\`, \`(!(userAccountControl=514))\`; \`*\` alone means "has the attribute";
- **attributes** to return (\`displayName mail\`; none means all).

\`\`\`
$ ldapsearch -x -LLL -D 'CN=svc-ldap,…' -y /etc/phonebook/bind.pw '(sAMAccountName=bob)' displayName mail
dn: CN=Bob Keller,CN=Users,DC=ad,DC=corp,DC=lab
displayName: Bob Keller
mail: bob@corp.lab

# refldap://ForestDnsZones.ad.corp.lab/DC=ForestDnsZones,DC=ad,DC=corp,DC=lab
\`\`\`
The **refldap** lines are **referrals**: a subtree search from the domain root tells the client that other partitions (DNS zones, Configuration) exist elsewhere. They are normal; the global catalog (port 3268) answers without them. A base that does not exist gives **"No such object (32)"** with the closest existing DN ("Matched DN").

:::practice
Q: You want only the entries directly inside OU=Service Accounts, not the OU itself. Which scope?
A: **one** (\`-s one\` with that OU as the base).
Q: Write a filter for user objects whose login name is dana.
A: \`(&(objectClass=user)(sAMAccountName=dana))\`
:::

### 4. LDAPS, StartTLS and LDAP signing
A simple bind sends the password as it is. On plain LDAP (389) anyone on the path can read it. Two ways to protect it:
- **LDAPS**: \`ldaps://dc01.ad.corp.lab\` (port 636), TLS from the first byte;
- **StartTLS**: \`ldap://\` on 389, then the client asks to switch to TLS (\`-ZZ\`: TLS is required; \`-Z\`: try it, continue without).

Either way, the client checks the DC's **certificate**: it must chain to a CA in **TLS_CACERT** (Debian: /etc/ssl/certs/ca-certificates.crt, where update-ca-certificates puts the internal root) and its name must match the name in the URI. libldap reports TLS problems as **"Can't contact LDAP server (-1)"**, with the reason in the additional info: "certificate verify failed (unable to get local issuer certificate)", "could not load CA certificate file", "hostname does not match CN in peer certificate" (for example when you connect by IP address). **TLS_REQCERT** decides what happens: demand (the default: refuse), never/allow (no protection at all: anyone can pretend to be the DC and collect passwords).

Domain controllers can **require signing**: with **LDAPServerIntegrity = 2** (the policy "LDAP server signing requirements: Require signing") a simple bind over plain LDAP is refused with **"Strong(er) authentication required (8)"**; over LDAPS or StartTLS it works. Turning this on is good hardening; the fix for a client that breaks is TLS, not rolling back.

:::practice
Q: ldapwhoami -H ldaps://10.0.20.5 fails with "hostname does not match CN in peer certificate", while ldaps://dc01.ad.corp.lab works. Why?
A: The certificate is issued for **dc01.ad.corp.lab**; connecting by IP address gives a name the certificate does not contain.
Q: What is the difference between -Z and -ZZ?
A: **-Z** tries StartTLS and continues without TLS if it fails; **-ZZ** requires it and stops if TLS cannot be set up.
:::

### 5. RADIUS packets and the shared secret
A RADIUS exchange is one UDP request and one reply:
- **Access-Request** (NAS → server, UDP 1812): User-Name, User-Password, NAS-IP-Address, NAS-Port, Calling-Station-Id (where the user comes from);
- **Access-Accept** or **Access-Reject** (server → NAS), optionally with a **Reply-Message** and other attributes; **Access-Challenge** asks for more (one-time codes, EAP).

The NAS and the server share a **shared secret**. It is used three ways:
- the **User-Password** is hidden with it (XOR with an MD5 hash of the secret and the request's random authenticator): not strong encryption, but not clear text;
- the reply carries a **Response Authenticator** (MD5 over the reply and the secret), so the NAS can tell the answer is genuine;
- the **Message-Authenticator** attribute (HMAC-MD5 with the secret) signs the whole request. radtest sends it; pam_radius_auth does not.

The server accepts requests only from its **clients**, recognised by the **source IP address** of the packet. A request from an unknown address is **ignored**: no reply at all, only a log line on the server. With a wrong secret, a request with a Message-Authenticator is dropped ("invalid Message-Authenticator"); one without it is processed, but the password decrypts to garbage, so the user's bind fails and AD counts a bad password, and the NAS cannot verify the reply. A wrong secret can therefore **lock users out**.

:::practice
Q: A NAS sends its requests from 10.0.20.1, but clients.conf lists it as 10.0.10.1. What does the NAS see?
A: **No answer at all**: the server ignores requests from unknown clients (it only logs them), so the NAS times out.
Q: Why can a wrong shared secret lock a user's AD account?
A: The server decrypts the password with the wrong secret into **garbage**, binds as the user with it, and AD counts each attempt as a **bad password** until the lockout threshold.
:::

### 6. Inside FreeRADIUS
FreeRADIUS (Debian: /etc/freeradius/3.0, service freeradius) handles each request in steps:
1. **Client lookup** in **clients.conf** by source address; check the secret.
2. **ldap module** (mods-enabled/ldap): connect to \`server\` (ldaps://dc01.ad.corp.lab), bind as \`identity\` (svc-radius), search below \`base_dn\` with the user filter \`(sAMAccountName=%{User-Name})\` and read memberOf.
3. **files module** (mods-config/files/authorize): the first matching entry decides. \`DEFAULT LDAP-Group == "Network-Admins"\` matches members; \`DEFAULT Auth-Type := Reject\` with Reply-Message "Not a member of Network-Admins" refuses everyone else, without even checking the password.
4. **Authenticate**: bind to the DC **as the user** with the password from the request.
5. Answer Access-Accept or Access-Reject and log **"Login OK"** or **"Login incorrect (reason)"** in /var/log/freeradius/radius.log.

Modules live in **mods-available**; only those linked into **mods-enabled** are loaded. clients.conf is read only at **start**: \`systemctl reload\` (HUP) re-reads the modules and policy, but a new or changed client needs \`systemctl restart\`. \`freeradius -XC\` checks the configuration without starting; \`freeradius -X\` runs the server in the foreground with full debug output, which fails with "Address already in use" while the service is running.

:::practice
Q: You added a new client to clients.conf and ran systemctl reload freeradius. Requests from it are still ignored. Why?
A: clients.conf is read only when the server **starts**; a reload re-reads modules only. **Restart** it.
Q: In which order does the lab's FreeRADIUS check group membership and the password?
A: It finds the user (service bind and search), checks the **group policy**, and only then binds **as the user** to check the password.
:::

### 7. The NAS: pam_radius_auth and PAM
On a Linux NAS, sshd asks RADIUS through **PAM** (see the PAM stack in [SSH](#/lesson/ssh/internals)). /etc/pam_radius_auth.conf lists servers as \`server[:port] secret [timeout]\`, tried in order; a server that does not answer costs its whole timeout. In /etc/pam.d/sshd:
\`\`\`
auth       sufficient   pam_radius_auth.so
@include common-auth
\`\`\`
**sufficient** means: if RADIUS accepts, the login succeeds at once; if it rejects or does not answer, PAM goes on to the local passwords (pam_unix). RADIUS users need a **local account without a password** (so sshd knows their uid and home), and the device keeps one local **break-glass** account (netadmin) for when RADIUS is down. pam_radius_auth logs to the sshd journal: "RADIUS server 10.0.20.65 failed to respond", "packet from RADIUS server … failed verification: The shared secret is probably incorrect.", "All RADIUS servers failed to respond."

:::practice
Q: What happens to the break-glass account if pam_radius_auth is "required" instead of "sufficient" and RADIUS is down?
A: The RADIUS step fails for everyone, and **required** makes the whole login fail even when the local password is right: the break-glass account is locked out too.
Q: Why do RADIUS users on rtr01 have a local account with no password?
A: sshd needs a local **uid, home and shell**; having **no** local password means they can only get in through RADIUS, so the policy cannot be bypassed.
:::

### 8. Beyond the lab: accounting, TACACS+ and 802.1X
- **RADIUS accounting** (UDP 1813): the NAS sends Accounting-Request Start/Stop/Interim-Update records (who, how long, how much traffic).
- **TACACS+** (TCP 49, Cisco): separates authentication, authorisation and accounting, encrypts the whole packet, and can authorise **each command** on a device. Common for administrator logins on network gear.
- **802.1X**: switches and access points use RADIUS with **EAP** to admit devices to the network (EAP-TLS with certificates, PEAP with passwords); the switch is the NAS.
- **Two of everything**: a second RADIUS server in pam_radius_auth.conf and a second DC in the ldap module's server list.

:::practice
Q: Which protocol can authorise each command an administrator types on a router?
A: **TACACS+** (TCP 49).
Q: In 802.1X, what plays the role of the NAS?
A: The **switch** or **access point** the device connects to.
:::

`,

  deployment: [
    {
      id: 'debian',
      platform: 'Debian 12: LDAP clients, FreeRADIUS with Active Directory, pam_radius_auth on a device',
      summary: 'Test the directory from the client, connect FreeRADIUS to AD over LDAPS, admit one group, register the NAS, and make the NAS ask RADIUS with a break-glass account, as in Lab 10. Steps marked simulated can be tried in the sandbox, on the machine named in the title ("On rad01", "On rtr01", "On srv01").',
      prerequisites: ['A read-only service account per application (svc-ldap, svc-radius) in its own OU.', 'The internal root CA installed on every client (update-ca-certificates).', 'A security group for the people who may log in to network devices (Network-Admins).', 'The NAS\'s real source address towards the RADIUS server, and a firewall rule for it.'],
      steps: [
        { title: 'Install', command: 'sudo apt install ldap-utils                                    # every LDAP client\nsudo apt install freeradius freeradius-ldap freeradius-utils  # rad01\nsudo apt install libpam-radius-auth                           # the NAS', what: 'The client tools, the RADIUS server with its LDAP module and radtest, and the PAM module for the device.', why: 'Debian starts freeradius with only the localhost client and no ldap module enabled.', expected: '' },
        { title: 'On srv01: test the directory as the service account', command: `cat /etc/ldap/ldap.conf\nldapwhoami -x ${AS_SVC}\nldapsearch -x -LLL ${AS_SVC} '(sAMAccountName=bob)' displayName mail`, what: 'ldap.conf points at ldaps://dc01.ad.corp.lab with the CA bundle; the service account binds and finds bob.', why: 'Test the bind and the search by hand before configuring an application: the errors are clearer here.', expected: 'mail: bob@corp.lab', simulated: true },
        { title: 'On rad01: test LDAPS as svc-radius', command: `ldapsearch -x -LLL -H ldaps://dc01.ad.corp.lab -s base -b '' '(objectClass=*)' dnsHostName\nldapwhoami -x -H ldaps://dc01.ad.corp.lab -D '${SVC_RADIUS}' -w 'Svc-Radius-2026!'`, what: 'The rootDSE over LDAPS (proves TCP 636, the certificate and the CA), then a bind as the RADIUS service account. (-w shows the password to ps: use -W or -y outside a test.)', why: 'If this fails, FreeRADIUS will fail the same way, with less detail.', expected: 'u:CORP\\svc-radius', simulated: true },
        { title: 'On rad01: enable and check the ldap module', command: `ls -l ${RADDB}/mods-enabled/\ngrep -E '^\\s*(server|identity|base_dn|filter|require_cert)' ${RADDB}/mods-enabled/ldap\nfreeradius -XC`, what: 'Link mods-available/ldap into mods-enabled (ln -s ../mods-available/ldap) and set server = \'ldaps://dc01.ad.corp.lab\', identity/password of svc-radius, base_dn, the user filter on sAMAccountName, the group filter (objectClass=group), and in tls: ca_file and require_cert = \'demand\'. Then check the whole configuration.', why: 'AD has no uid attribute; without require_cert the service password would go to anyone answering on 636.', expected: 'Configuration appears to be OK', simulated: true },
        { title: 'On rad01: the group policy', command: `grep -v '^#' ${RADDB}/mods-config/files/authorize\nsystemctl reload freeradius\nradtest alice 'Office-Corp-2026' localhost 0 testing123\nradtest dana 'Sales-Corp-2026' localhost 0 testing123`, what: 'DEFAULT LDAP-Group == "Network-Admins" first, DEFAULT Auth-Type := Reject with a Reply-Message second; reload re-reads the policy; alice gets Access-Accept, dana (right password, not a member) Access-Reject.', why: 'Without a policy, anyone with an AD password could log in to the router.', expected: 'Reply-Message = "Not a member of Network-Admins"', simulated: true },
        { title: 'On rad01: register the NAS, restart, open the firewall', command: `grep -v '^#' ${RADDB}/clients.conf\nsystemctl restart freeradius\nss -ulnp\nnft list ruleset`, what: 'A client rtr01 { ipaddr = 10.0.20.1  secret = (openssl rand -base64 18)  shortname = rtr01 } section, a restart (clients are read at start), and "ip saddr 10.0.20.1 udp dport 1812 accept" in /etc/nftables.conf (loaded with nft -f).', why: 'The server answers only known clients, by the address they send from; the firewall should admit only those.', expected: 'ip saddr 10.0.20.1 udp dport 1812 accept', simulated: true },
        { title: 'On rtr01: the NAS side', command: "grep -v '^#' /etc/pam_radius_auth.conf\nls -l /etc/pam_radius_auth.conf\ngrep -n pam_radius /etc/pam.d/sshd\nip route get 10.0.20.65", what: 'One line "10.0.20.65 SECRET 3" (the example servers commented out), mode 600; "auth sufficient pam_radius_auth.so" before "@include common-auth"; the source address rad01 will see.', why: 'Each example server left in costs a timeout per login; "sufficient" keeps the local break-glass account working.', expected: '10.0.20.65 dev eth1 src 10.0.20.1', simulated: true },
        { title: 'Test refusal and break-glass', command: '# from ws01: ssh alice@rtr01.corp.lab (AD password) → works\n# from ws01: ssh dana@rtr01.corp.lab → refused ("Not a member" in radius.log)\n# on rad01: systemctl stop freeradius; from ws01: ssh netadmin@rtr01.corp.lab → works after the timeout\n# on rad01: systemctl start freeradius', what: 'Both directions of the policy, and the emergency path.', why: 'A central login nobody tested is a single point of failure. Every failed test with a real user counts against that user in AD.', expected: '' },
      ],
    },
    {
      id: 'rhel',
      platform: 'RHEL 9 / Rocky / Alma',
      summary: 'The same packages under other names: openldap-clients (/etc/openldap/ldap.conf), freeradius, freeradius-ldap and freeradius-utils (configuration in /etc/raddb, service radiusd), pam_radius from EPEL. The internal root goes to /etc/pki/ca-trust/source/anchors/ followed by update-ca-trust.',
      prerequisites: ['sudo dnf install openldap-clients freeradius freeradius-ldap freeradius-utils'],
      steps: [
        { title: 'Firewall and SELinux', command: "sudo firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"10.0.20.1\" service name=\"radius\" accept'\nsudo firewall-cmd --reload\nsudo radiusd -XC", what: 'UDP 1812/1813 from the NAS only; a configuration check.', why: 'Same rule as on Debian; SELinux already allows radiusd to connect to LDAP ports.', expected: 'success' },
      ],
    },
    {
      id: 'windows',
      platform: 'Windows Server: AD for LDAP clients, and NPS as the RADIUS server',
      summary: 'Domain controllers answer LDAPS as soon as they have a certificate with their name (from AD CS auto-enrolment or installed by hand). Before requiring signing, enable LDAP interface event logging and look for event 2889 (clients binding in clear text). NPS (Network Policy Server) is Microsoft\'s RADIUS server: RADIUS clients with secrets, and network policies with Windows-group conditions.',
      prerequisites: ['A DC certificate for its FQDN in the Local Computer Personal store.', 'NPS role installed and registered in AD (netsh nps add registeredserver).'],
      steps: [
        { title: 'Find clear-text binds, then require signing', command: "Get-WinEvent -FilterHashtable @{LogName='Directory Service';Id=2889} -MaxEvents 20\nSet-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name LDAPServerIntegrity -Value 2", what: 'The clients that still bind without TLS; then the hardening (normally set by GPO).', why: 'Requiring signing without moving clients to LDAPS breaks them all at once.', expected: '' },
        { title: 'NPS: a RADIUS client and a policy', command: 'New-NpsRadiusClient -Name rtr01 -Address 10.0.20.1 -SharedSecret (Read-Host)\n# Network policy: condition Windows Groups = CORP\\Network-Admins, grant access, PAP for this client only', what: 'The same pieces as FreeRADIUS: client by address and secret, policy by group.', why: 'NPS checks the password directly against AD, no service account needed.', expected: '' },
      ],
    },
    {
      id: 'other',
      platform: 'Other directories and devices',
      summary: 'OpenLDAP (slapd) and FreeIPA use the same protocol with other attribute names (uid, memberOf through an overlay, cn=users,cn=accounts,dc=… in FreeIPA). Network operating systems configure RADIUS or TACACS+ directly (Cisco IOS "aaa new-model", "radius server", "aaa authentication login default group radius local"). Cloud directories (Entra ID) offer LDAP only through an add-on (Entra Domain Services) and RADIUS through the NPS extension.',
      prerequisites: [],
      steps: [
        { title: 'A Cisco IOS device as NAS', command: 'aaa new-model\nradius server RAD01\n address ipv4 10.0.20.65 auth-port 1812 acct-port 1813\n key <shared secret>\nip radius source-interface Vlan20\naaa authentication login default group radius local', what: 'RADIUS first, the local user database if no server answers; a fixed source interface so the server knows the address.', why: '"local" is the break-glass path; source-interface avoids the unknown-client problem.', expected: '' },
      ],
    },
  ],

  configIntro: `
Directory and RADIUS settings live in five places:
- **The LDAP client**: /etc/ldap/ldap.conf (URI, BASE, TLS_CACERT, TLS_REQCERT) and the application's own settings (bind DN, password file).
- **The RADIUS clients**: clients.conf (which NAS, from which address, with which secret).
- **The directory back end**: mods-enabled/ldap (server, service account, base, filters, TLS).
- **The policy**: mods-config/files/authorize (who may log in).
- **The NAS**: /etc/pam_radius_auth.conf and /etc/pam.d/sshd.

### Check before you restart
- \`freeradius -XC\`: reads every file like a start and ends with "Configuration appears to be OK", or names the file and line;
- \`ldapwhoami -x -H URI -D DN -W\`: tests the URI, TLS and the account before you put them in a configuration file;
- after the change: \`radtest\` on the server, then one real login from the NAS.

:::practice
Q: Which command checks the whole FreeRADIUS configuration without starting the server?
A: \`freeradius -XC\` (or -C); it ends with "Configuration appears to be OK" or names the failing file and line.
Q: After editing only the authorize file, is a reload enough?
A: **Yes**: a reload (HUP) re-reads the modules and policy files. Only clients.conf needs a restart.
:::

`,

  configFiles: [
    { platform: 'LDAP clients (Debian, OpenLDAP libldap)', items: [
      { path: '/etc/ldap/ldap.conf', purpose: 'System defaults: URI, BASE, TLS_CACERT, TLS_REQCERT.' },
      { path: '~/.ldaprc', purpose: 'Per-user overrides of ldap.conf.' },
      { path: '/etc/phonebook/bind.pw', purpose: 'The service account\'s password for the lab\'s phone book (-y).' },
      { path: '/usr/local/share/ca-certificates/*.crt', purpose: 'Internal root CAs, added to the bundle by update-ca-certificates.' },
    ] },
    { platform: 'FreeRADIUS 3.x (Debian: /etc/freeradius/3.0)', items: [
      { path: `${RADDB}/radiusd.conf`, purpose: 'Server settings: log, security, includes.' },
      { path: `${RADDB}/clients.conf`, purpose: 'NAS clients: address, secret, shortname (read at start only).' },
      { path: `${RADDB}/mods-available/, mods-enabled/`, purpose: 'Module configurations; only linked ones are loaded.' },
      { path: `${RADDB}/mods-enabled/ldap`, purpose: 'Directory back end: server, identity, base_dn, filters, TLS.' },
      { path: `${RADDB}/mods-config/files/authorize`, purpose: 'Per-user and DEFAULT policy entries.' },
      { path: '/var/log/freeradius/radius.log', purpose: 'Decisions and errors.' },
    ] },
    { platform: 'Linux NAS (pam_radius_auth)', items: [
      { path: '/etc/pam_radius_auth.conf', purpose: 'RADIUS servers, secrets and timeouts (mode 600).' },
      { path: '/etc/pam.d/sshd', purpose: 'Where pam_radius_auth sits in the SSH login stack.' },
    ] },
    { platform: 'Windows domain controller', items: [
      { path: 'HKLM:\\System\\CurrentControlSet\\Services\\NTDS\\Parameters', purpose: 'LDAPServerIntegrity (signing), LdapEnforceChannelBinding.' },
    ] },
  ],

  directives: [
    { name: 'URI (ldap.conf)', compiledDefault: 'ldap://localhost', recommended: 'ldaps://dc01.ad.corp.lab (the name in the certificate)', explanation: 'Which server and scheme the tools use when -H is not given.', security: 'ldap:// sends simple-bind passwords in clear text.' },
    { name: 'TLS_REQCERT (ldap.conf)', compiledDefault: 'demand', recommended: 'demand', explanation: 'What to do with a certificate that cannot be verified: demand/hard refuse, try continues if none is sent, allow/never accept anything.', security: 'never/allow let anyone impersonate the DC and collect passwords.' },
    { name: 'TLS_CACERT (ldap.conf)', compiledDefault: 'none (OpenSSL default paths)', distroDefault: 'Debian: /etc/ssl/certs/ca-certificates.crt', recommended: 'The system bundle with the internal root added', explanation: 'The CAs the client trusts for LDAPS and StartTLS.', security: '' },
    { name: 'tls { require_cert } (FreeRADIUS ldap)', compiledDefault: 'allow', recommended: "'demand'", explanation: 'Whether the ldap module refuses a DC certificate it cannot verify.', security: 'The service account\'s and every user\'s password cross this connection.' },
    { name: 'user { filter } (FreeRADIUS ldap)', compiledDefault: '(uid=%{%{Stripped-User-Name}:-%{User-Name}})', recommended: '(sAMAccountName=%{%{Stripped-User-Name}:-%{User-Name}}) for AD', explanation: 'How the login name is found in the directory.', security: 'FreeRADIUS escapes special characters in the name, so a filter cannot be injected.' },
    { name: 'secret (clients.conf, pam_radius_auth.conf)', compiledDefault: 'testing123 (localhost client)', recommended: '16+ random characters, different per NAS', explanation: 'Hides passwords and authenticates replies.', security: 'A captured request plus a weak secret lets an attacker recover the password offline.' },
    { name: 'require_message_authenticator (clients.conf)', compiledDefault: 'no', recommended: 'yes where every NAS sends it', explanation: 'Drop requests without a Message-Authenticator.', security: 'Protects against forged requests (BlastRADIUS); pam_radius_auth 2.0 does not send it.' },
    { name: 'timeout (pam_radius_auth.conf)', compiledDefault: '3 s', recommended: '3 s, two servers', explanation: 'How long the NAS waits for each server.', security: 'Long timeouts times many dead servers make break-glass logins slow.' },
    { name: 'LDAPServerIntegrity (DC)', compiledDefault: '1 (negotiate signing)', recommended: '2 (require signing)', explanation: 'Whether simple binds without TLS are refused.', security: 'Stops clear-text passwords and LDAP relay on 389.' },
    { name: 'Account lockout threshold (domain policy)', compiledDefault: '0 (never)', distroDefault: 'lab: 5', recommended: '5–10 with a lockout duration', explanation: 'Bad passwords before AD locks an account.', security: 'Slows password guessing, but a wrong stored password (service, RADIUS secret) locks real users out.' },
  ],

  operateIntro: `
### Every day
- **Lockouts**: \`Search-ADAccount -LockedOut\` should not list service accounts; event 4740 tells you which machine keeps sending a bad password.
- **radius.log**: a run of "Login incorrect" for many users at once points at the system (secret, LDAP, certificate), not at the users.
- **Certificates**: the DC's LDAPS certificate and the internal CA expire; renew before, and test LDAPS from every client afterwards.
- **Group membership**: who is in Network-Admins, reviewed like any other privilege.

:::practice
Q: radius.log shows "Login incorrect" for every user since 02:00. Is this more likely a user problem or a system problem?
A: A **system** problem (secret, LDAP connection, certificate, service account): users do not all forget their passwords at the same moment.
Q: Which event on the DC tells you which machine locked an account out?
A: Event **4740** (Caller Computer Name).
:::

### Rotating passwords and secrets
A service account password or a shared secret exists in at least two places. Change them in **one** change: first the place that uses it (bind.pw, mods-enabled/ldap, pam_radius_auth.conf), then the directory or the server, then test at once. Changing only one side means every attempt is a wrong password, and five of them lock the account. If it happened: fix the stored copy **first**, then unlock.

:::practice
Q: svc-ldap is locked out because the phone book kept the old password. In which order do you fix it?
A: Put the **new password** into bind.pw first, then **Unlock-ADAccount**; the other way round, the next lookup with the old password locks it again.
Q: Why test a RADIUS change with radtest on the server before a real login on the router?
A: radtest isolates the server side, and every failed real login counts as a **bad password** in AD for that person.
:::

### Break-glass and outages
A central login is a single point of failure. Keep on every device one **local break-glass account** with a long password stored in a safe, alert when it is used, and test it after every change (stop RADIUS, log in, start RADIUS). Use pam_radius_auth as **sufficient**, keep the timeout short, and run a second RADIUS server and a second DC where devices matter.

:::practice
Q: What must be true of /etc/pam.d/sshd for the break-glass account to work while RADIUS is down?
A: pam_radius_auth must be **sufficient** (not required) and come before **common-auth**, so a failure falls through to the local password check.
Q: Why alert when the break-glass account is used?
A: It bypasses the central policy and logging; every use should be an emergency someone knows about.
:::

`,
  troubleshootingIntro: `
### Follow the login from the NAS to the directory
1. **What does the NAS say?** \`journalctl -u ssh\` on rtr01: "failed to respond" (no answer: unknown client, firewall, server down), "failed verification" (secret), or a plain "Failed password" after a reject.
2. **What did the RADIUS server decide, and why?** \`tail /var/log/freeradius/radius.log\`: "Ignoring request … from unknown client" (source address), "invalid Message-Authenticator" (secret), ldap errors before "Login incorrect" (TLS, service account), "Login incorrect: [user]" without an error (policy), "Bind as user failed" (password or lockout).
3. **Does it work without the NAS?** \`radtest USER PASSWORD localhost 0 testing123\` on the server.
4. **Can the server reach and trust the DC?** \`ldapwhoami -x -H ldaps://dc01.ad.corp.lab -D … -W\` on the server: TLS errors appear as "Can't contact LDAP server (-1)".
5. **Is the account healthy and in the group?** On the DC: Get-ADUser -Properties LockedOut,BadLogonCount,MemberOf; event 4740.

:::practice
Q: radtest on rad01 gets Access-Accept, but the same user's SSH login on rtr01 fails after a few seconds of waiting. Which part do you suspect?
A: The **NAS side**: its client entry (source address), the firewall for UDP 1812, or the secret. The server, LDAP and policy work.
Q: radius.log shows "Bind with CN=svc-radius,… failed: Can't contact LDAP server" and "Server said: … certificate verify failed". Is the svc-radius password wrong?
A: **No**: the TLS handshake failed before any password was sent. rad01 does not trust the DC's certificate (CA missing).
:::

### Reading LDAP errors
LDAP errors have a **name and number**, and AD adds a hex code with the detail:
- **Operations error (1)**, 000004DC: no bind, anonymous search refused.
- **Strong(er) authentication required (8)**, 00002028: simple bind without TLS while signing is required.
- **Invalid credentials (49)**, 80090308 … **data 52e / 775 / 533 / 532**: wrong password / locked out / disabled / expired.
- **No such object (32)**: the base DN does not exist ("Matched DN" shows how far it got).
- **Can't contact LDAP server (-1)**: TCP or TLS failed; read the additional info.
- **Bad search filter (-7)**: brackets or syntax in the filter.

:::practice
Q: Which data code in an AD bind error means the password is wrong?
A: **52e**.
Q: ldapsearch prints "No such object (32)" with Matched DN DC=ad,DC=corp,DC=lab. What is wrong?
A: The **base DN** (or an OU in it) does not exist; the DC found only the domain root.
:::

`,

  errorMap: [
    { message: 'Operations error (1) … 000004DC … a successful bind must be completed on the connection', layer: 'LDAP (no bind)', meaning: 'An anonymous search: AD only answers the rootDSE without a bind.', firstCheck: 'ldapwhoami -x (anonymous?); -D and -y in the application' },
    { message: 'ldap_bind: Strong(er) authentication required (8) … 00002028 … integrity checking', layer: 'LDAP signing', meaning: 'The DC requires signing; a simple bind over plain ldap:// is refused.', firstCheck: 'The URI (ldaps://) in ldap.conf or the application; LDAPServerIntegrity' },
    { message: 'ldap_bind: Invalid credentials (49) … AcceptSecurityContext error, data 52e', layer: 'Account', meaning: 'Wrong password (or unknown user).', firstCheck: 'The stored password (bind.pw, mods-enabled/ldap) against the current one' },
    { message: 'ldap_bind: Invalid credentials (49) … data 775', layer: 'Account', meaning: 'The account is locked out; every password is refused.', firstCheck: 'Get-ADUser -Properties LockedOut,BadLogonCount; event 4740' },
    { message: 'ldap_bind: Invalid credentials (49) … data 533 / 532', layer: 'Account', meaning: 'Account disabled / password expired.', firstCheck: 'Get-ADUser -Properties Enabled,PasswordExpired' },
    { message: "ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1) … certificate verify failed (unable to get local issuer certificate)", layer: 'TLS (trust)', meaning: 'The client does not trust the CA of the DC\'s certificate.', firstCheck: 'TLS_CACERT / ca_file; ls /usr/local/share/ca-certificates' },
    { message: "Can't contact LDAP server (-1) … could not load CA certificate file", layer: 'TLS (client file)', meaning: 'The CA file named in the configuration does not exist.', firstCheck: 'The TLS_CACERT or ca_file path' },
    { message: "Can't contact LDAP server (-1) … hostname does not match CN in peer certificate", layer: 'TLS (name)', meaning: 'The URI names the DC differently from its certificate (IP address, short name).', firstCheck: 'Use the FQDN from the certificate: ldaps://dc01.ad.corp.lab' },
    { message: 'SASL/GSS-SPNEGO authentication started … No Kerberos credentials available', layer: 'LDAP tools', meaning: 'ldapsearch/ldapwhoami without -x tried a Kerberos bind.', firstCheck: 'Add -x for a simple bind (or kinit for SASL)' },
    { message: 'Ignoring request to auth address * port 1812 bound to server default from unknown client 10.0.20.1 port … proto udp', layer: 'RADIUS client list', meaning: 'No client entry covers the source address; the NAS gets no reply.', firstCheck: 'ipaddr in clients.conf; restart after editing' },
    { message: 'Dropping packet without response because of error: Received packet from … with invalid Message-Authenticator!  (Shared secret is incorrect.)', layer: 'RADIUS secret', meaning: 'The request was signed with another secret; dropped.', firstCheck: 'The secret on the NAS against clients.conf' },
    { message: 'pam_radius_auth: packet from RADIUS server 10.0.20.65 failed verification: The shared secret is probably incorrect.', layer: 'RADIUS secret (NAS)', meaning: 'The NAS cannot verify the reply; the server also saw a garbage password.', firstCheck: '/etc/pam_radius_auth.conf against clients.conf; AD lockouts' },
    { message: 'pam_radius_auth: RADIUS server 10.0.20.65 failed to respond', layer: 'RADIUS path', meaning: 'No reply: unknown client, firewall, server stopped, wrong port.', firstCheck: 'radius.log on the server; nft list ruleset; systemctl status freeradius' },
    { message: 'Login incorrect (ldap: Bind as user failed): [alice] (from client rtr01 …)', layer: 'Authentication', meaning: 'The user\'s bind failed: wrong password, locked out, or a garbage password from a wrong secret.', firstCheck: 'The ldap error line before it (data code)' },
    { message: 'Login incorrect: [dana] (from client rtr01 …)', layer: 'Authorisation (policy)', meaning: 'Rejected by the authorize file (no error line): not in the group.', firstCheck: 'radtest: Reply-Message; Get-ADUser -Properties MemberOf' },
    { message: "ldap: Bind with CN=svc-radius,… to ldaps://dc01.ad.corp.lab:636 failed: Can't contact LDAP server", layer: 'RADIUS → LDAP', meaning: 'The ldap module cannot connect; "Server said:" gives the TLS reason.', firstCheck: 'ldapsearch -x -H ldaps://dc01.ad.corp.lab … on the RADIUS server' },
    { message: 'Failed binding to auth address * port 1812 … Address already in use', layer: 'FreeRADIUS', meaning: 'freeradius -X started while the service is running.', firstCheck: 'systemctl stop freeradius before debug mode (or use -XC)' },
  ],

  scenarioIds: ['id-phonebook-anonymous', 'id-ldap-signing', 'id-svc-locked', 'id-radius-ca', 'id-radius-group', 'id-radius-secret', 'id-radius-unknown-client'],
  assessmentId: 'identity',
  references: [
    { title: 'RFC 4511: LDAP, the protocol', url: 'https://www.rfc-editor.org/rfc/rfc4511' },
    { title: 'RFC 4515: LDAP search filters', url: 'https://www.rfc-editor.org/rfc/rfc4515' },
    { title: 'ldap.conf(5) (OpenLDAP)', url: 'https://www.openldap.org/software/man.cgi?query=ldap.conf' },
    { title: 'Microsoft: How to enable LDAP signing in Windows Server', url: 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server' },
    { title: 'RFC 2865: RADIUS', url: 'https://www.rfc-editor.org/rfc/rfc2865' },
    { title: 'RFC 3579: RADIUS support for EAP (Message-Authenticator)', url: 'https://www.rfc-editor.org/rfc/rfc3579' },
    { title: 'FreeRADIUS documentation', url: 'https://www.freeradius.org/documentation/' },
    { title: 'pam_radius (GitHub)', url: 'https://github.com/FreeRADIUS/pam_radius' },
  ],
  guide: IDENTITY_GUIDE,
};

// --- Primer -------------------------------------------------------------------------

export const IDENTITY_PRIMER: Primer = {
  oneLiner: 'A **directory** (here Active Directory) is the company\'s one list of people, passwords and groups. Applications read it with **LDAP**; network devices ask a **RADIUS** server, which reads it for them and answers "yes" or "no".',
  analogy: `
A large office building. Reception has the **staff directory** (Active Directory): every employee, their department, their badge. A department that wants to check someone does not keep its own list: it phones reception (**LDAP**). Reception only answers callers who say who they are (**bind**), and the canteen calls with its own staff number (**service account**), not the boss's. The line is private (**LDAPS**), and the canteen checks that it really is reception answering (**the certificate**).

The doors to the server rooms (**routers**, the **NAS**) do not phone reception themselves. They call the security desk (**RADIUS server**) with a code word they share (**shared secret**). Security looks the person up in the directory, checks the rule on the wall ("server rooms: network team only", the **group policy**) and says yes or no. Each door also has a key in a sealed box for when the security desk is unreachable (**break-glass account**).

Where it stops being accurate: RADIUS does not phone back with a voice but sends one small UDP packet; and the "code word" also scrambles the password on the way.`,
  ideas: [
    {
      title: 'Entries and DNs',
      explain: 'The directory is a tree; each entry has a full path name (DN) and attributes.',
      example: '`CN=Bob Keller,CN=Users,DC=ad,DC=corp,DC=lab` has `sAMAccountName: bob`, `mail: bob@corp.lab` and its groups in `memberOf`.',
    },
    {
      title: 'Bind, then search',
      explain: 'A client logs in to the directory (bind) with a service account, then searches below a base with a filter. AD refuses searches without a bind.',
      example: "On srv01: `ldapsearch -x -LLL -D 'CN=svc-ldap,OU=Service Accounts,DC=ad,DC=corp,DC=lab' -y /etc/phonebook/bind.pw '(sAMAccountName=bob)' mail` prints `mail: bob@corp.lab`.",
    },
    {
      title: 'LDAPS and trust',
      explain: 'Binds send passwords, so they go over TLS (ldaps:// on 636). The client checks the DC\'s certificate against the CAs it trusts.',
      example: 'If rad01 lacks the Corp Lab root, its ldap module logs "Can\'t contact LDAP server" and "certificate verify failed (unable to get local issuer certificate)".',
    },
    {
      title: 'RADIUS: NAS, server, secret',
      explain: 'The device (NAS) sends one Access-Request over UDP 1812 to the RADIUS server; both know a shared secret, and the server answers only clients it knows by address.',
      example: 'On rad01: `radtest alice \'Office-Corp-2026\' localhost 0 testing123` prints "Received Access-Accept".',
    },
    {
      title: 'Authentication is not authorisation',
      explain: 'A right password proves who you are; a policy decides whether you may log in here (in the lab: member of Network-Admins).',
      example: 'dana\'s password is right, but radtest dana gets Access-Reject with Reply-Message "Not a member of Network-Admins".',
    },
  ],
  walkthrough: {
    title: 'alice logs in to rtr01 with her AD password',
    steps: [
      { label: 'SSH', detail: 'alice runs ssh alice@rtr01.corp.lab on ws01 and types her AD password. sshd on rtr01 asks PAM; the first auth line is pam_radius_auth.' },
      { label: 'Access-Request', detail: 'pam_radius_auth sends a UDP packet from 10.0.20.1 to rad01 (10.0.20.65) port 1812: User-Name alice, the password hidden with the shared secret.' },
      { label: 'Known client?', detail: 'FreeRADIUS finds client rtr01 (ipaddr = 10.0.20.1) in clients.conf and decrypts the password with its secret.' },
      { label: 'Look her up', detail: 'The ldap module opens LDAPS to dc01.ad.corp.lab, checks the certificate, binds as svc-radius and searches (sAMAccountName=alice): her DN and memberOf.' },
      { label: 'Policy', detail: 'The authorize file: LDAP-Group == "Network-Admins" matches (alice is a member).' },
      { label: 'Check the password', detail: 'The ldap module binds as CN=Alice Martin,CN=Users,… with her password: AD says yes.' },
      { label: 'Accept', detail: 'rad01 sends Access-Accept and logs "Login OK: [alice] (from client rtr01 port 0 cli 10.0.10.25)"; pam_radius_auth verifies the reply and alice gets her shell.' },
    ],
  },
  misconceptions: [
    { myth: 'The directory is readable by everyone, so applications do not need to log in.', truth: 'Active Directory answers only the rootDSE without a bind. Applications bind as a read-only service account.' },
    { myth: 'If LDAPS fails, switching to ldap:// or TLS_REQCERT never is a fine fix.', truth: 'That sends passwords in clear text or to anyone pretending to be the DC, and a DC that requires signing refuses it anyway. Install the CA instead.' },
    { myth: '"Permission denied" on the router means the user typed the wrong password.', truth: 'It can be the group policy, a wrong secret, an unknown client, a certificate problem on the RADIUS server or a locked account. radius.log says which.' },
    { myth: 'A reload applies every FreeRADIUS change.', truth: 'clients.conf is read only at start: a new or changed NAS needs a restart.' },
    { myth: 'With central logins, local accounts on devices should all be removed.', truth: 'Keep one local break-glass account (and pam_radius_auth "sufficient"), or a RADIUS outage locks everyone out of the network.' },
  ],
  checks: [
    { q: 'Which ports do LDAPS and RADIUS authentication use?', a: 'TCP 636 for LDAPS; UDP 1812 for RADIUS authentication.' },
    { q: 'What does "data 775" in an AD bind error mean?', a: 'The account is locked out.' },
    { q: 'How does a RADIUS server decide whether a request comes from a known NAS?', a: 'By the source IP address of the packet, matched against the client entries in clients.conf.' },
    { q: 'Where does FreeRADIUS write why it rejected a login?', a: '/var/log/freeradius/radius.log ("Login incorrect" with the reason, and ldap errors before it).' },
  ],
};

// --- Assessment -------------------------------------------------------------------------

export const IDENTITY_ASSESSMENT: Assessment = {
  id: 'identity',
  title: 'Directory services and RADIUS knowledge check',
  questions: [
    {
      id: 'id-q-chain',
      kind: 'order',
      level: 'intermediate',
      learn: ['lesson/identity/internals'],
      prompt: 'Order what FreeRADIUS in the lab does with an Access-Request from rtr01.',
      items: ['Find the client by the source address and check the secret', 'Bind to the DC as the service account svc-radius', 'Search for the user by sAMAccountName and read memberOf', 'Apply the group policy in the authorize file', 'Bind as the user with the password from the request', 'Send Access-Accept or Access-Reject'],
      concepts: ['id.radius'],
      explanation: 'The policy comes before the user bind: a non-member is rejected without the password being checked.',
    },
    {
      id: 'id-q-anon',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/identity/internals', 'lesson/identity/troubleshoot'],
      prompt: 'A script runs `ldapsearch -x -LLL "(sAMAccountName=bob)" mail` against Active Directory and gets "Operations error (1)" with 000004DC. What is wrong?',
      options: [
        { text: 'It searches without binding; AD refuses anonymous searches', correct: true },
        { text: 'bob\'s account is locked out', misconception: 'Bob\'s account state does not matter for a search; a lockout shows up as code 49 data 775 on a bind as bob.' },
        { text: 'The DC\'s certificate is not trusted', misconception: 'A TLS failure is "Can\'t contact LDAP server (-1)"; here the DC answered with an LDAP error.' },
        { text: 'The filter syntax is wrong', misconception: 'A bad filter is "Bad search filter (-7)", reported by the client before anything is sent.' },
      ],
      concepts: ['id.ldap'],
      explanation: 'Without -D and a password the bind is anonymous, and AD only answers the rootDSE.',
    },
    {
      id: 'id-q-datacode',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/identity/internals'],
      prompt: 'After a password rotation a service account\'s bind fails with "Invalid credentials (49)" and "data 775", even with the new password. What do you do?',
      options: [
        { text: 'Put the new password into every place that uses the account, then unlock it', correct: true },
        { text: 'Unlock the account first, then update the password file', misconception: 'The next lookup with the old password counts again and locks it within minutes.' },
        { text: 'Set the old password back in AD', misconception: 'That undoes the rotation; the account is still locked out anyway.' },
        { text: 'Turn on TLS_REQCERT never', misconception: '775 is an account state, not a TLS problem.' },
      ],
      concepts: ['id.ldap'],
      explanation: '775 = locked out. Remove the source of bad passwords first, then unlock.',
    },
    {
      id: 'id-q-signing',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/identity/internals', 'lesson/identity/troubleshoot'],
      prompt: 'After the DC was set to require LDAP signing, a client using URI ldap://dc01.ad.corp.lab gets "Strong(er) authentication required (8)". What is the right fix?',
      options: [
        { text: 'Switch the client to ldaps://dc01.ad.corp.lab (or StartTLS with -ZZ)', correct: true },
        { text: 'Set LDAPServerIntegrity back to 1', misconception: 'That rolls back the hardening and keeps passwords in clear text.' },
        { text: 'Give the service account a new password', misconception: 'The DC refuses before checking the password (code 8, not 49).' },
        { text: 'Connect to ldaps://10.0.20.5', misconception: 'The certificate is for dc01.ad.corp.lab: the name check fails with an IP address.' },
      ],
      concepts: ['id.ldap', 'tls.pki'],
      explanation: 'With signing required, a simple bind needs TLS around it.',
    },
    {
      id: 'id-q-tls',
      kind: 'multi',
      level: 'intermediate',
      learn: ['lesson/identity/internals'],
      prompt: 'ldapwhoami -H ldaps://… fails with "Can\'t contact LDAP server (-1)". Which causes fit? (choose all that apply)',
      options: [
        { text: 'The client does not trust the CA that issued the DC\'s certificate', correct: true },
        { text: 'The URI uses a name that is not in the certificate', correct: true },
        { text: 'TCP 636 is blocked or the name does not resolve', correct: true },
        { text: 'The bind password is wrong', misconception: 'A wrong password is "Invalid credentials (49)": the connection worked.' },
      ],
      concepts: ['id.ldap', 'tls.pki'],
      explanation: 'Code -1 covers every failure before LDAP itself: TCP, DNS and TLS. Read the additional info.',
    },
    {
      id: 'id-q-unknown-client',
      kind: 'single',
      level: 'advanced',
      learn: ['lesson/identity/internals', 'lesson/identity/troubleshoot'],
      exhibit: 'rad01: Error: Ignoring request to auth address * port 1812 bound to server default from unknown client 10.0.20.1 port 41213 proto udp',
      prompt: 'clients.conf lists rtr01 as 10.0.10.1, the address rtr01.corp.lab resolves to. What is the fix?',
      options: [
        { text: 'Set ipaddr = 10.0.20.1 for rtr01 and restart freeradius', correct: true },
        { text: 'Set ipaddr = 10.0.20.1 and reload freeradius', misconception: 'clients.conf is read only at start; a reload keeps the old client list.' },
        { text: 'Change the shared secret on both sides', misconception: 'The request is ignored before the secret is looked at.' },
        { text: 'Add client any { ipaddr = * }', misconception: 'That answers any machine that guesses the secret.' },
      ],
      concepts: ['id.radius', 'fw.path'],
      explanation: 'The server matches clients by the packet\'s source address, which is the NAS\'s interface towards the server.',
    },
    {
      id: 'id-q-secret',
      kind: 'multi',
      level: 'intermediate',
      learn: ['lesson/identity/internals', 'lesson/identity/operate'],
      prompt: 'The shared secret was changed on the RADIUS server only. The NAS uses pam_radius_auth. What happens? (choose all that apply)',
      options: [
        { text: 'The server decrypts each password into garbage and the user bind fails', correct: true },
        { text: 'AD counts bad passwords and can lock users out', correct: true },
        { text: 'The NAS logs that the reply failed verification', correct: true },
        { text: 'The server ignores the requests silently', misconception: 'That is what happens to unknown clients; a known client with a wrong secret is processed (pam_radius_auth sends no Message-Authenticator).' },
      ],
      concepts: ['id.radius'],
      explanation: 'Rotate secrets on both ends in one change and test with radtest from the server first.',
    },
    {
      id: 'id-q-authz',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/identity/what', 'lesson/identity/config'],
      prompt: 'radtest dana \'…\' localhost 0 testing123 returns Access-Reject with Reply-Message "Not a member of Network-Admins". Dana was added to the mailing list Network-Team. What is wrong?',
      options: [
        { text: 'Authorisation: she is not in the security group the policy checks', correct: true },
        { text: 'Authentication: her password is wrong', misconception: 'The reply message comes from the policy, which is applied before the password is checked.' },
        { text: 'The RADIUS secret is wrong', misconception: 'radtest from the server with the localhost secret got an answer.' },
      ],
      concepts: ['id.radius'],
      explanation: 'Add her to Network-Admins in AD; RADIUS reads memberOf at every login, so no restart is needed.',
    },
    {
      id: 'id-q-breakglass',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/identity/internals', 'lesson/identity/operate'],
      prompt: 'Which /etc/pam.d/sshd line keeps the local netadmin account working while the RADIUS server is down?',
      options: [
        { text: 'auth sufficient pam_radius_auth.so, before @include common-auth', correct: true },
        { text: 'auth required pam_radius_auth.so, before @include common-auth', misconception: 'required makes the whole login fail when RADIUS fails, local password or not.' },
        { text: 'auth sufficient pam_radius_auth.so, after @include common-auth', misconception: 'Then RADIUS users (no local password) fail in pam_unix before RADIUS is asked.' },
      ],
      concepts: ['id.radius'],
      explanation: 'sufficient: an accept ends the stack with success; a reject or timeout falls through to the local passwords.',
    },
    {
      id: 'id-q-ports',
      kind: 'text',
      level: 'beginner',
      learn: ['lesson/identity/what'],
      prompt: 'On which UDP port does a RADIUS server receive authentication requests?',
      accept: ['1812'],
      placeholder: 'port',
      concepts: ['id.radius'],
      explanation: 'UDP 1812 authentication, 1813 accounting; LDAP 389 and LDAPS 636 are TCP.',
    },
    {
      id: 'id-q-scope',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/identity/internals'],
      prompt: 'Which ldapsearch scope returns the base entry and everything below it?',
      options: [
        { text: 'sub', correct: true },
        { text: 'one', misconception: 'one returns only the direct children of the base.' },
        { text: 'base', misconception: 'base returns only the base entry itself.' },
        { text: 'children', misconception: 'children returns everything below the base, but not the base.' },
      ],
      concepts: ['id.ldap'],
      explanation: 'sub is the default scope of ldapsearch.',
    },
  ],
};
