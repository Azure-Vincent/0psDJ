// Reference entries for directory services and RADIUS: the OpenLDAP client
// tools (ldapsearch, ldapwhoami), radtest and the freeradius binary, the LDAP
// client, FreeRADIUS and pam_radius_auth configuration files, and the
// procedures for an application whose directory lookups fail and for a
// network-device login that RADIUS refuses.

import type { CommandRef, FileRef, Procedure } from '../types';

const SVC = "'CN=svc-ldap,OU=Service Accounts,DC=ad,DC=corp,DC=lab'";

export const ID_COMMAND_REFS: CommandRef[] = [
  {
    id: 'ldapsearch', name: 'ldapsearch', platform: 'Linux', category: 'Identity', simulator: 'ldapsearch',
    purpose: 'Search an LDAP directory (Active Directory, OpenLDAP, FreeIPA) from the shell: bind as an account, search below a base with a scope and a filter, print the entries as LDIF. The standard way to test what an application will see.',
    syntax: 'ldapsearch -x [-H URI] [-D BINDDN] [-w PASSWORD | -W | -y FILE] [-Z | -ZZ] [-b BASE] [-s base|one|sub|children] [-LLL] FILTER [ATTRIBUTE…]',
    args: [
      { arg: '-x', meaning: 'Simple bind (DN and password). Without it the tools try SASL (GSS-SPNEGO/Kerberos)' },
      { arg: '-H URI', meaning: 'Server: ldaps://dc01.ad.corp.lab (636, TLS) or ldap://… (389); default: URI in /etc/ldap/ldap.conf' },
      { arg: '-D BINDDN', meaning: 'Who to bind as: a DN, user@domain or DOMAIN\\user. Without -D the bind is anonymous' },
      { arg: '-w PW / -W / -y FILE', meaning: 'The password on the command line (visible in ps) / asked for / read from a file (the whole file, a trailing newline is dropped)' },
      { arg: '-Z / -ZZ', meaning: 'StartTLS on ldap://: try it / require it' },
      { arg: '-b BASE', meaning: 'Where the search starts (default: BASE in ldap.conf); -b \'\' with -s base reads the rootDSE' },
      { arg: '-s SCOPE', meaning: 'base (the entry), one (its children), sub (everything, default), children (everything below)' },
      { arg: '-LLL', meaning: 'Plain LDIF: no comments, no version line' },
      { arg: 'FILTER ATTRS', meaning: 'An RFC 4515 filter in brackets, then the attributes to return (none: all)' },
    ],
    example: { command: `ldapsearch -x -LLL -D ${SVC} -y /etc/phonebook/bind.pw '(sAMAccountName=bob)' displayName mail`, output: 'dn: CN=Bob Keller,CN=Users,DC=ad,DC=corp,DC=lab\ndisplayName: Bob Keller\nmail: bob@corp.lab\n\n# refldap://ForestDnsZones.ad.corp.lab/DC=ForestDnsZones,DC=ad,DC=corp,DC=lab\n\n# refldap://DomainDnsZones.ad.corp.lab/DC=DomainDnsZones,DC=ad,DC=corp,DC=lab\n\n# refldap://ad.corp.lab/CN=Configuration,DC=ad,DC=corp,DC=lab' },
    interpretation: 'Entries come as "dn:" followed by attribute lines. refldap/ref lines are referrals to other partitions after a subtree search at the domain root: normal for AD (the global catalog on 3268 has none). Errors print the result name and code: Operations error (1) = no bind; Invalid credentials (49) with AD\'s data code; Strong(er) authentication required (8) = signing; No such object (32) = base does not exist; Can\'t contact LDAP server (-1) = TCP or TLS. The exit status is the LDAP result code.',
    limitations: 'Simulated: simple binds against AD on dc01 (LDAP, LDAPS, StartTLS, the global catalog), -H -D -w -W -y -b -s -L/-LL/-LLL -Z/-ZZ, ldap.conf and ~/.ldaprc, filters with &, |, !, =, >=, <=, ~=, presence and substrings, referrals, rootDSE. No SASL binds, paging (-E pr=), sorting, ldapmodify/ldapadd, OpenLDAP servers.',
    errors: [
      { message: 'Operations error (1)\nAdditional information: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection.', meaning: 'Anonymous search: AD answers only the rootDSE without a bind. Add -D and a password.' },
      { message: 'ldap_bind: Invalid credentials (49)\n\tadditional info: 80090308: LdapErr: DSID-0C090447, comment: AcceptSecurityContext error, data 52e, v4563', meaning: 'data 52e wrong password, 775 locked out, 533 disabled, 532 expired.' },
      { message: 'ldap_bind: Strong(er) authentication required (8)', meaning: 'The DC requires signing: use ldaps:// or -ZZ.' },
      { message: "ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)\n\tadditional info: error:0A000086:SSL routines::certificate verify failed (unable to get local issuer certificate)", meaning: 'The CA of the DC\'s certificate is not trusted (TLS_CACERT).' },
      { message: 'SASL/GSS-SPNEGO authentication started\nldap_sasl_interactive_bind: Local error (-2)', meaning: '-x is missing: the tool tried Kerberos.' },
      { message: 'ldapsearch: ldap_search_ext: Bad search filter (-7)', meaning: 'Unbalanced brackets, or an attribute name given where the filter was expected.' },
    ],
    permissions: 'Any user; the directory decides what the bound account may read.',
    risks: '-w puts the password in the process list and shell history: use -W or -y with a private file.',
    compat: 'Debian/Ubuntu: ldap-utils; RHEL: openldap-clients (/etc/openldap/ldap.conf). Windows: ldp.exe, Get-ADUser, dsquery.',
    services: ['LDAP', 'Active Directory'], protocols: ['LDAP', 'LDAPS', 'TLS'], symptoms: ['Directory lookup fails', 'Invalid credentials', 'Account locked out'],
  },
  {
    id: 'ldapwhoami', name: 'ldapwhoami', platform: 'Linux', category: 'Identity', simulator: 'ldapwhoami',
    purpose: 'Bind to an LDAP server and print who the server thinks you are. The quickest test of a URI, TLS settings and an account\'s password.',
    syntax: 'ldapwhoami -x [-H URI] [-D BINDDN] [-w PASSWORD | -W | -y FILE] [-Z | -ZZ]',
    args: [
      { arg: '-x', meaning: 'Simple bind' },
      { arg: '-H URI', meaning: 'Server and scheme (default: URI in ldap.conf)' },
      { arg: '-D BINDDN', meaning: 'Account to bind as (none: anonymous)' },
      { arg: '-w / -W / -y FILE', meaning: 'Password on the command line / asked for / from a file' },
      { arg: '-ZZ', meaning: 'Require StartTLS on ldap://' },
    ],
    example: { command: `ldapwhoami -x -D ${SVC} -y /etc/phonebook/bind.pw`, output: 'u:CORP\\svc-ldap' },
    interpretation: '"u:DOMAIN\\name" means the bind worked as that account; "anonymous" means no bind happened (no -D or no password). The errors are the same as ldapsearch\'s bind errors.',
    limitations: 'Simulated: simple binds against AD on dc01 over LDAP, LDAPS and StartTLS. No SASL.',
    errors: [
      { message: 'ldap_bind: Invalid credentials (49) … data 775', meaning: 'Locked out: fix the source of the bad passwords, then unlock.' },
      { message: "ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)\n\tadditional info: TLS: hostname does not match CN in peer certificate", meaning: 'Connected by IP or a short name: use the FQDN in the certificate.' },
    ],
    permissions: 'Any user.',
    compat: 'Debian: ldap-utils.',
    services: ['LDAP', 'Active Directory'], protocols: ['LDAP', 'LDAPS', 'TLS'], symptoms: ['Invalid credentials', 'Account locked out'],
  },
  {
    id: 'radtest', name: 'radtest', platform: 'Linux', category: 'Identity', simulator: 'radtest',
    purpose: 'Send one RADIUS Access-Request (PAP) and print the answer: test a RADIUS server, its LDAP back end and its policy without a router.',
    syntax: 'radtest [-t pap] USER PASSWORD SERVER[:PORT] NAS-PORT SECRET',
    args: [
      { arg: 'USER PASSWORD', meaning: 'The login to test (a real attempt: a wrong password counts against the user in AD)' },
      { arg: 'SERVER[:PORT]', meaning: 'RADIUS server; localhost from the server itself (port 1812 by default)' },
      { arg: 'NAS-PORT', meaning: 'Any number (0)' },
      { arg: 'SECRET', meaning: 'The shared secret of the client entry that matches the source address (testing123 for the localhost client)' },
    ],
    example: { command: "radtest dana 'Sales-Corp-2026' localhost 0 testing123", output: 'Sent Access-Request Id 93 from 0.0.0.0:47383 to 127.0.0.1:1812 length 70\n\tUser-Name = "dana"\n\tUser-Password = "Sales-Corp-2026"\n\tNAS-IP-Address = 127.0.0.1\n\tNAS-Port = 0\n\tMessage-Authenticator = 0x00\n\tCleartext-Password = "Sales-Corp-2026"\nReceived Access-Reject Id 93 from 127.0.0.1:1812 to 127.0.0.1:47383 length 52\n\tReply-Message = "Not a member of Network-Admins"\n(0) -: Expected Access-Accept got Access-Reject' },
    interpretation: '"Received Access-Accept": the login works. "Access-Reject" with a Reply-Message: the policy refused it; without one: the password, the account or the LDAP back end (radius.log has the reason). "No reply from server": the server ignored or dropped the request (unknown client, wrong secret: radtest sends a Message-Authenticator, so a wrong secret is dropped) or is not running. Exit status 1 for anything but an accept.',
    limitations: 'Simulated: PAP (-t pap), IPv4, the reply attributes. No CHAP/MS-CHAP/EAP, no accounting (use radclient on a real system).',
    errors: [
      { message: '(0) No reply from server for ID 244 socket 3', meaning: 'Three tries without an answer: client unknown, wrong secret, firewall, or freeradius stopped. Read radius.log.' },
      { message: '(0) -: Expected Access-Accept got Access-Reject', meaning: 'The server answered no; the reason is in radius.log.' },
    ],
    permissions: 'Any user; the source address and secret must match a client entry.',
    risks: 'Each failed test with a real account is a bad password in AD: five lock the account.',
    compat: 'Debian: freeradius-utils (a wrapper around radclient). Windows NPS: test with a real NAS or NTRadPing.',
    services: ['RADIUS'], protocols: ['RADIUS', 'UDP'], symptoms: ['Login refused', 'No RADIUS reply'],
  },
  {
    id: 'freeradius', name: 'freeradius -C / -XC / -X', platform: 'Linux', category: 'Identity', simulator: 'freeradius',
    purpose: 'The FreeRADIUS server binary: check the configuration (-C), check it with the debug listing (-XC), or run the server in the foreground with full debug output (-X).',
    syntax: 'freeradius -C | freeradius -XC | freeradius -X   (RHEL: radiusd)',
    args: [
      { arg: '-C', meaning: 'Read every configuration file and exit: "Configuration appears to be OK" or the file and line of the error' },
      { arg: '-XC', meaning: 'The same with the debug listing (files read, clients, module settings; secrets hidden)' },
      { arg: '-X', meaning: 'Run in the foreground with debug output for every request (stop the service first)' },
    ],
    example: { command: 'freeradius -XC', output: 'FreeRADIUS Version 3.2.1\n…\nclient rtr01 {\n\tipaddr = 10.0.20.1\n\trequire_message_authenticator = no\n\tsecret = <<< secret >>>\n\tshortname = "rtr01"\n}\nrlm_ldap (ldap): server = "ldaps://dc01.ad.corp.lab"\nrlm_ldap (ldap): identity = "CN=svc-radius,OU=Service Accounts,DC=ad,DC=corp,DC=lab"\nrlm_ldap (ldap): base_dn = "DC=ad,DC=corp,DC=lab"\nConfiguration appears to be OK' },
    interpretation: 'Run -C before every restart: a configuration error stops the service and every NAS falls back to local accounts. "Address already in use" with -X means the service is still running.',
    limitations: 'Simulated: -C and -XC check clients.conf, mods-enabled/ldap and the authorize file. -X does not keep a debug server running: use the service and radius.log.',
    errors: [
      { message: '/etc/freeradius/3.0/clients.conf[19]: Missing secret for client "rtr01"', meaning: 'A client without secret: the server would not start.' },
      { message: 'Failed binding to auth address * port 1812 bound to server default: Address already in use', meaning: '-X while freeradius.service runs.' },
    ],
    permissions: 'root (the files are owned by freerad, mode 640).',
    compat: 'Debian: freeradius; RHEL: radiusd -XC.',
    services: ['RADIUS'], protocols: ['RADIUS'], symptoms: ['RADIUS does not start'],
  },
];

export const ID_FILE_REFS: FileRef[] = [
  {
    id: 'file:ldap-conf', path: '/etc/ldap/ldap.conf', platform: 'OpenLDAP libldap (Debian ldap-utils; RHEL: /etc/openldap/ldap.conf)', kind: 'config',
    services: ['LDAP', 'Active Directory'],
    purpose: 'System-wide defaults for every program that uses libldap: which server, which base, which CAs to trust and how strictly.',
    contents: 'BASE (default search base), URI (one or more ldap:// or ldaps:// URIs), BINDDN (default bind DN), TLS_CACERT (CA bundle file), TLS_REQCERT never|allow|try|demand|hard (default demand), SIZELIMIT, TIMELIMIT. ~/.ldaprc and the LDAP* environment variables override it per user.',
    accessed: 'At every ldapsearch/ldapwhoami and by applications linked to libldap.',
    permissions: 'root:root 644 (no secrets here).',
    problems: 'A "temporary" ldap:// URI (clear-text binds, refused once the DC requires signing); TLS_REQCERT never (no protection at all); a TLS_CACERT path that does not exist ("could not load CA certificate file"); a URI with an IP address (name check fails).',
    example: '# corp.lab: Active Directory on dc01 over LDAPS\nBASE\tDC=ad,DC=corp,DC=lab\nURI\tldaps://dc01.ad.corp.lab\nTLS_CACERT\t/etc/ssl/certs/ca-certificates.crt',
    relatedCommands: ['ldapsearch', 'ldapwhoami', 'update-ca-certificates'],
  },
  {
    id: 'file:clients-conf', path: '/etc/freeradius/3.0/clients.conf', platform: 'FreeRADIUS 3.x (Debian; RHEL: /etc/raddb/clients.conf)', kind: 'config',
    services: ['RADIUS'],
    purpose: 'Which NAS devices may send requests, recognised by their source address, and the shared secret of each.',
    contents: 'client NAME { ipaddr = ADDRESS[/PREFIX]; secret = …; shortname = …; require_message_authenticator = yes|no; nas_type = other }. The Debian default has client localhost (127.0.0.1, secret testing123) for radtest.',
    accessed: 'Only when freeradius starts. systemctl reload (HUP) does not re-read it: restart after every change.',
    permissions: 'freerad:freerad 640 (it holds the secrets).',
    problems: 'The NAS listed by the address its DNS name resolves to instead of the address it sends from ("Ignoring request … from unknown client"); default or short secrets; ipaddr = * or a whole network; edits without a restart.',
    example: 'client rtr01 {\n\tipaddr = 10.0.20.1\n\tsecret = Rtr01-Nas-Secret-2702\n\tshortname = rtr01\n}',
    relatedCommands: ['freeradius', 'radtest', 'systemctl'],
  },
  {
    id: 'file:freeradius-ldap', path: '/etc/freeradius/3.0/mods-enabled/ldap', platform: 'FreeRADIUS 3.x rlm_ldap (Debian: link to mods-available/ldap)', kind: 'config',
    services: ['RADIUS', 'LDAP', 'Active Directory'],
    purpose: 'The directory back end: how FreeRADIUS finds users and groups and checks passwords by binding as the user.',
    contents: "ldap { server = 'ldaps://dc01.ad.corp.lab'; port = 636; identity = (service account DN); password; base_dn; user { base_dn; filter = \"(sAMAccountName=%{%{Stripped-User-Name}:-%{User-Name}})\" }; group { filter = '(objectClass=group)'; membership_attribute = 'memberOf' }; tls { ca_file; require_cert = 'demand' }; pool { … } }.",
    accessed: 'At start and on reload (HUP). Only modules in mods-enabled are loaded.',
    permissions: 'freerad:freerad 640 (it holds the service password).',
    problems: 'The OpenLDAP default filter (uid=…) finds nobody in AD; ldap:// instead of ldaps://; a server name that is not in the DC\'s certificate; require_cert never; the service password not updated after a rotation (Bind … failed: Invalid credentials, then lockout).',
    example: "ldap {\n\tserver = 'ldaps://dc01.ad.corp.lab'\n\tidentity = 'CN=svc-radius,OU=Service Accounts,DC=ad,DC=corp,DC=lab'\n\tpassword = '…'\n\tbase_dn = 'DC=ad,DC=corp,DC=lab'\n\tuser {\n\t\tfilter = \"(sAMAccountName=%{%{Stripped-User-Name}:-%{User-Name}})\"\n\t}\n\ttls {\n\t\tca_file = /etc/ssl/certs/ca-certificates.crt\n\t\trequire_cert = 'demand'\n\t}\n}",
    relatedCommands: ['freeradius', 'ldapsearch', 'radtest'],
  },
  {
    id: 'file:freeradius-authorize', path: '/etc/freeradius/3.0/mods-config/files/authorize', platform: 'FreeRADIUS 3.x rlm_files', kind: 'config',
    services: ['RADIUS'],
    purpose: 'Per-user and DEFAULT policy: who is accepted or rejected, and which attributes the reply carries.',
    contents: 'Entries: a user name or DEFAULT followed by check items on the same line (LDAP-Group == "Network-Admins", Auth-Type := Reject), then indented reply items (Reply-Message := "…"). The first matching entry decides unless it sets Fall-Through = Yes.',
    accessed: 'At start and on reload (HUP).',
    permissions: 'freerad:freerad 640.',
    problems: 'The default reject before the group rule (everyone refused); a misspelled group name; the old dial-up examples still active; check items written on the reply line.',
    example: 'DEFAULT\tLDAP-Group == "Network-Admins"\n\tReply-Message := "Welcome, %{User-Name}"\n\nDEFAULT\tAuth-Type := Reject\n\tReply-Message := "Not a member of Network-Admins"',
    relatedCommands: ['freeradius', 'radtest'],
  },
  {
    id: 'file:pam-radius-auth-conf', path: '/etc/pam_radius_auth.conf', platform: 'Linux NAS (libpam-radius-auth)', kind: 'auth',
    services: ['RADIUS', 'SSH'],
    purpose: 'The RADIUS servers pam_radius_auth asks, with the shared secret and timeout for each.',
    contents: 'One line per server: server[:port] shared_secret [timeout]. Tried in order; a server that does not answer costs its timeout and the next one is asked. Used by every PAM service with "auth … pam_radius_auth.so" (here /etc/pam.d/sshd).',
    accessed: 'At every login through PAM.',
    permissions: 'root:root 600: anyone who can read the secret can forge RADIUS answers.',
    problems: 'The package\'s example servers (127.0.0.1, other-server) left active; a secret that differs from clients.conf ("failed verification: The shared secret is probably incorrect", and bad passwords counted in AD); world-readable.',
    example: '# server[:port]\tshared_secret\ttimeout (s)\n10.0.20.65\tRtr01-Nas-Secret-2702\t3',
    relatedCommands: ['journalctl', 'radtest'],
  },
];

export const ID_PROCEDURES: Procedure[] = [
  {
    id: 'proc:ldap-app-lookup-fails', title: 'An application\'s directory lookups fail', platform: 'Linux LDAP client against Active Directory',
    services: ['LDAP', 'Active Directory'],
    symptoms: ['Directory lookup fails', 'Invalid credentials', 'Account locked out'],
    purpose: 'Reproduce the application\'s lookup by hand and read the LDAP error, from the connection to the account.',
    steps: [
      { title: 'Run the same lookup by hand', command: `cat /etc/ldap/ldap.conf\nldapsearch -x -LLL -D ${SVC} -y /etc/phonebook/bind.pw '(sAMAccountName=bob)' mail`, why: 'The tool prints the LDAP result name, code and AD\'s detail the application may hide.' },
      { title: 'Connection and TLS', command: "ldapsearch -x -LLL -H ldaps://dc01.ad.corp.lab -s base -b '' '(objectClass=*)' dnsHostName", why: 'The rootDSE needs no bind: if this fails ("Can\'t contact LDAP server"), the problem is DNS, TCP 636 or the certificate (CA, name).' },
      { title: 'The bind', command: `ldapwhoami -x -D ${SVC} -y /etc/phonebook/bind.pw`, why: '"anonymous" = no bind configured (Operations error 000004DC on searches); 49 with data 52e/775/533 = password, lockout, disabled; 8 = signing requires TLS.' },
      { title: 'The account on the DC', command: "Get-ADUser svc-ldap -Properties LockedOut,BadLogonCount\nGet-WinEvent -FilterHashtable @{LogName='Security';Id=4740} -MaxEvents 5", why: 'A locked-out account refuses the right password too; 4740 names the machine sending bad passwords.' },
      { title: 'Fix in the right order', command: "printf '%s' 'NEW-PASSWORD' > /etc/phonebook/bind.pw\nchmod 640 /etc/phonebook/bind.pw\n# then on dc01: Unlock-ADAccount -Identity svc-ldap", why: 'Update every stored copy before unlocking, or the next attempt locks the account again.' },
    ],
    risks: 'Do not "fix" with TLS_REQCERT never, ldap:// or by rolling back LDAP signing; do not bind as an administrator or a person. Each test with a wrong password counts towards the lockout.',
    verify: 'The lookup returns the entry, ldapwhoami prints the service account, BadLogonCount stays 0.',
  },
  {
    id: 'proc:radius-login-fails', title: 'A login on a network device through RADIUS fails', platform: 'pam_radius_auth NAS + FreeRADIUS + Active Directory',
    services: ['RADIUS', 'LDAP', 'Active Directory', 'SSH'],
    symptoms: ['Login refused', 'No RADIUS reply', 'Account locked out'],
    purpose: 'Find which link fails: NAS, path, client entry and secret, LDAP back end, policy or account. Test on the server before retrying real logins.',
    steps: [
      { title: 'What did the NAS see?', command: 'journalctl -u ssh -n 20', why: '"failed to respond" = no reply (client, firewall, server down); "failed verification" = secret; a plain "Failed password" after a reject.' },
      { title: 'What did the server decide?', command: 'tail -n 20 /var/log/freeradius/radius.log', why: 'Ignored unknown client, invalid Message-Authenticator, ldap errors (TLS, service bind), Login incorrect with or without a reason (password vs policy).' },
      { title: 'Test on the server itself', command: "radtest USER 'PASSWORD' localhost 0 testing123", why: 'Accept here but not on the NAS: the problem is between NAS and server (address, secret, firewall, restart).' },
      { title: 'Client entry, source address, firewall', command: "grep -v '^#' /etc/freeradius/3.0/clients.conf\nnft list ruleset\n# on the NAS: ip route get 10.0.20.65; grep -v '^#' /etc/pam_radius_auth.conf", why: 'ipaddr must be the address the NAS sends from; the secrets must match; clients.conf needs a restart.' },
      { title: 'LDAP back end and account', command: "ldapsearch -x -H ldaps://dc01.ad.corp.lab -s base -b '' '(objectClass=*)' dnsHostName\n# on dc01: Get-ADUser USER -Properties MemberOf,LockedOut,BadLogonCount", why: 'TLS trust from the RADIUS server; the group the policy checks; lockouts caused by the failed attempts.' },
    ],
    risks: 'Every failed real login is a bad password in AD. Do not widen clients to * or turn off require_cert; keep the break-glass account and the group policy.',
    verify: 'radtest and a real login get Access-Accept; radius.log shows "Login OK … (from client rtr01 …)"; a non-member is still refused.',
  },
];
