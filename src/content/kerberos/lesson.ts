import type { Lesson } from '../types';
import { KERBEROS_GUIDE } from './guide';

export const KERBEROS_LESSON: Lesson = {
  id: 'kerberos',
  moduleId: 'C',
  title: 'Kerberos and DNS service records',
  level: 'intermediate',
  summary: 'How Kerberos single sign-on works on Linux with MIT krb5: realms and principals, the KDC found through DNS SRV records, the AS and TGS exchanges, pre-authentication, tickets and keytabs, clock skew, and Kerberos logins over SSH (GSSAPI). The same protocol is the core of Active Directory logons.',
  concepts: ['ad.kerberos', 'ad.dns', 'dns.zone', 'ssh.userauth'],
  mode: 'simulated',

  what: `
**Kerberos** is a way of proving who you are to the services on a network without sending your password to each of them. It relies on a trusted third party, the **KDC** (Key Distribution Center).

It works like a festival wristband. You show your ID **once** at the entrance (you prove your password to the KDC) and get a wristband, the **ticket-granting ticket (TGT)**. After that, for each stage you want to visit, you show the wristband at the ticket office and get a ticket for that stage, a **service ticket**, without showing your ID again. That is **single sign-on**. Your password never crosses the network, and the servers you use never see it.

Kerberos depends on things from earlier lessons: [DNS](#/lesson/transport/what) to find the KDC and to name services, [time synchronisation](#/lesson/ntp/what) because tickets carry timestamps, and network access to the KDC on port 88.

Kerberos is everywhere identity matters: every **Active Directory** logon and file share access, FreeIPA/IdM in Linux estates, SSH logins with GSSAPI, web single sign-on (SPNEGO), NFSv4 with sec=krb5, databases, Hadoop.

### Names
- **Realm**: the administrative domain, by convention the DNS domain in capitals: \`CORP.LAB\`. (In AD the realm is the AD domain.)
- **Principal**: an identity in the realm. Users: \`alice@CORP.LAB\`, admins: \`alice/admin@CORP.LAB\`. Services: \`host/srv01.corp.lab@CORP.LAB\` (SSH and general host services), \`HTTP/www.corp.lab\`, \`nfs/...\`. AD calls service principal names **SPNs**.
- **KDC**: the server holding every principal's long-term key. MIT: \`krb5kdc\` (Authentication Service + Ticket-Granting Service) and \`kadmind\` (administration). In AD every domain controller is a KDC.
- **Keytab**: a file with a service's long-term keys (\`/etc/krb5.keytab\`): the service's password.
- **Credential cache**: where your tickets live (\`/tmp/krb5cc_UID\`); \`klist\` shows it.

### Finding the KDC
Clients either list KDCs in \`/etc/krb5.conf\` or look them up in **DNS SRV records**: \`_kerberos._udp.corp.lab\` → "priority 0, weight 0, port 88, host ns1.corp.lab". SRV records are the same mechanism Active Directory clients use to find domain controllers (\`_ldap._tcp.dc._msdcs.DOMAIN\`, \`_kerberos._tcp.DOMAIN\`): **broken DNS = broken logons**.

### Why it is a troubleshooting topic
Kerberos depends on four things that belong to other teams: **DNS** (to find the KDC and to build service names), **time** (5 minutes of skew is fatal), **the network** (UDP/TCP 88 to the KDC) and **keys** that must match on the KDC and in each server's keytab. Error messages are precise once you know what each one means.

### In the lab
corp.lab is the realm **CORP.LAB**. ns1 runs the MIT KDC and kadmind; the corp.lab zone has the SRV records; every corp.lab machine has \`/etc/krb5.conf\` (no KDC listed: DNS is used) and systemd-timesyncd. srv01 has a keytab for \`host/srv01.corp.lab\`. alice's Kerberos password is \`Corp-Lab-2026\`; the admin principal \`alice/admin\` has \`Corp-Admin-2026\`.

> The simulator implements krb5.conf and kdc.conf parsing, SRV-based KDC location, AS exchange with encrypted-timestamp pre-authentication, TGS exchange, ticket lifetimes (max_life), 300 s clock skew, kadmind ACLs, keytabs with key version numbers, \`kinit\`/\`klist\`/\`kvno\`/\`kdestroy\`/\`kadmin\`/\`kadmin.local\`, per-host clocks (\`date\`, \`timedatectl\`), and sshd \`GSSAPIAuthentication\` with \`.k5login\`. Requests are UDP/TCP packets through the lab network, so DNS, routing and firewalls affect them. Simplified: cryptography is synthetic, no cross-realm trust, ticket renewal, forwarding/delegation, NTP packets, or Windows clients.
`,

  internals: `
### The three exchanges
\`\`\`
alice (ws01)                     KDC (ns1)                       srv01
  | 1 AS-REQ  alice → krbtgt         |                               |
  |---------------------------------->|                               |
  | KRB-ERROR: PREAUTH_REQUIRED       |                               |
  |<----------------------------------|                               |
  | AS-REQ + {timestamp}K_alice       |                               |
  |---------------------------------->|  checks key and clock         |
  | AS-REP: TGT {..}K_krbtgt          |                               |
  |         + session key {..}K_alice |                               |
  |<----------------------------------|                               |
  | 2 TGS-REQ: TGT + authenticator    |                               |
  |---------------------------------->|                               |
  | TGS-REP: ticket {..}K_host/srv01  |                               |
  |<----------------------------------|                               |
  | 3 AP-REQ: ticket + authenticator (inside SSH: gssapi-with-mic)    |
  |------------------------------------------------------------------>|
  |                                    srv01 decrypts with its keytab |
\`\`\`
1. **AS exchange** (Authentication Service, \`kinit\`): the client asks for a TGT. With pre-authentication (the default, \`+preauth\`) the KDC first answers *KDC_ERR_PREAUTH_REQUIRED*; the client then sends its current time **encrypted with the key derived from the password**. If the KDC can decrypt it with its copy of the key, the password was right, and the timestamp must be within 5 minutes of the KDC's clock. The reply contains the TGT (encrypted with the **krbtgt** key, which only the KDC knows) and a session key encrypted for the client.
2. **TGS exchange** (Ticket-Granting Service, \`kvno\`, or automatically when you use a service): the client presents the TGT plus an **authenticator** (timestamp encrypted with the session key) and names the service. The KDC returns a **service ticket** encrypted with the **service's** long-term key, with the key version number (**kvno**).
3. **AP exchange** (the application): the client hands the service ticket to the server. The server decrypts it **with the key in its keytab**: if the keytab lacks that kvno, it cannot. No KDC is involved in this step; servers never talk to the KDC to verify a user.

### Why time matters
Kerberos uses timestamps instead of challenges to stop replays: every authenticator carries the client's time, and KDCs and servers reject anything more than **clockskew** (300 s) away from their own clock, plus they remember recently seen authenticators. A client 6 minutes off can type the right password and still fail ("Clock skew too great").

### How names become principals
For \`ssh srv01.corp.lab\` the client needs a ticket for \`host/<name>@<REALM>\`:
- **Name**: the host name canonicalised through DNS (CNAMEs followed: \`www.corp.lab\` → \`srv01.corp.lab\`). With \`rdns = false\` no reverse lookup is done, so connecting to an **IP address** asks for \`host/10.0.20.10\`, which does not exist.
- **Realm**: from \`[domain_realm]\` (\`.corp.lab = CORP.LAB\`), else the default realm.
- On the server, sshd maps the client principal to a local account: \`alice@CORP.LAB\` → \`alice\` in the default realm, or whatever \`~/.k5login\` lists.

### Keys and key version numbers
Every principal has a key and a **kvno** that increases when the key changes (\`cpw\`, \`ktadd\`). The KDC always encrypts with the current key; the keytab must have that kvno. **ktadd** in kadmin randomises the key and writes it to the local keytab in one step: run it **on the server that uses the keytab**. Running ktadd elsewhere, or \`cpw -randkey\` on the KDC, silently breaks the server until its keytab is replaced. Clients may hold service tickets for the old kvno until they expire, which is why keeping old keytab entries for a while is common practice.

`,

  deployment: [
    {
      id: 'mit-client',
      platform: 'Debian/Ubuntu: Kerberos client',
      summary: 'Join a Linux machine to an existing realm as a client and log in with tickets. Steps marked "simulated" work in the sandbox (ws01 is already configured).',
      prerequisites: ['The realm name and DNS SRV records for the KDC (or the KDC host names).', 'Working DNS and NTP.'],
      steps: [
        { title: 'Install the client tools', command: 'sudo apt install krb5-user', what: 'kinit, klist, kvno, kdestroy, kadmin and /etc/krb5.conf.', why: 'The installer asks for the default realm; RHEL: dnf install krb5-workstation.', expected: '' },
        { title: 'Check how the KDC will be found', command: 'host -t SRV _kerberos._udp.corp.lab\nhost -t SRV _kerberos._tcp.corp.lab', what: 'The SRV records the library uses when krb5.conf lists no KDC.', why: 'Without them (and without kdc lines) every kinit fails with "Cannot find KDC".', expected: '_kerberos._udp.corp.lab has SRV record 0 0 88 ns1.corp.lab.', simulated: true },
        { title: 'Configure the realm', command: 'sudoedit /etc/krb5.conf\n\n[libdefaults]\n\tdefault_realm = CORP.LAB\n\tdns_lookup_kdc = true\n\trdns = false\n\n[domain_realm]\n\t.corp.lab = CORP.LAB', what: 'Default realm, KDC discovery through DNS, host-to-realm mapping.', why: 'rdns = false avoids depending on reverse DNS (PTR records) to build service names.', expected: '', simulated: true },
        { title: 'Keep the clock right', command: 'timedatectl\nsudo timedatectl set-ntp true', what: 'NTP must be active.', why: 'More than 5 minutes of skew and every Kerberos request fails.', expected: 'System clock synchronized: yes', simulated: true },
        { title: 'Get and inspect a ticket', command: 'kinit alice\nklist\nkvno host/srv01.corp.lab', what: 'TGT, then a service ticket.', why: 'Proves the AS and TGS exchanges; kvno shows the service key version.', expected: 'host/srv01.corp.lab@CORP.LAB: kvno = 2', simulated: true },
      ],
    },
    {
      id: 'mit-ssh-sso',
      platform: 'Debian: Kerberos logins for sshd',
      summary: 'Give a server a host principal and keytab, and enable GSSAPI in sshd.',
      prerequisites: ['An admin principal allowed by kadm5.acl (alice/admin in the lab).', 'The server is a Kerberos client (krb5.conf, NTP).'],
      steps: [
        { title: 'Create the host principal (once, if missing)', command: 'kadmin -p alice/admin -q "addprinc -randkey host/srv01.corp.lab"', what: 'Registers the service with a random key.', why: 'Service principals have no password; their key lives only in the keytab.', expected: 'Principal "host/srv01.corp.lab@CORP.LAB" created.', simulated: true },
        { title: 'Write the key into the server\'s keytab, on the server', command: 'sudo kadmin -p alice/admin -q "ktadd host/srv01.corp.lab"\nsudo klist -ke', what: 'Creates a new key (kvno + 1) and stores it in /etc/krb5.keytab.', why: 'Running it on the server keeps the KDC and the keytab in step. Note "sudo kadmin" would default to root/admin: name your admin principal.', expected: '   3 host/srv01.corp.lab@CORP.LAB (aes256-cts-hmac-sha1-96)', simulated: true },
        { title: 'Enable GSSAPI in sshd', command: 'echo "GSSAPIAuthentication yes" | sudo tee /etc/ssh/sshd_config.d/20-kerberos.conf\nsudo sshd -t && sudo systemctl reload ssh\nsudo sshd -T | grep gssapi', what: 'sshd now offers gssapi-keyex and gssapi-with-mic.', why: 'Debian\'s sshd default is no; the client side (ssh_config) already says yes.', expected: 'gssapiauthentication yes', simulated: true },
        { title: 'Test from a client', command: 'kinit\nssh -v -o PubkeyAuthentication=no -o PasswordAuthentication=no srv01.corp.lab hostname', what: 'Forces Kerberos as the only method.', why: 'Otherwise a fallback to keys or passwords hides a broken Kerberos setup.', expected: 'debug1: Authenticated to srv01.corp.lab ([10.0.20.10]:22) using "gssapi-with-mic".', simulated: true },
      ],
    },
    {
      id: 'mit-kdc',
      platform: 'Debian: MIT KDC (overview)',
      summary: 'What setting up a KDC involves (ns1 in the lab is already a KDC).',
      prerequisites: ['A dedicated, well-protected host; working DNS and NTP.'],
      steps: [
        { title: 'Install and create the realm', command: 'sudo apt install krb5-kdc krb5-admin-server\nsudo krb5_newrealm', what: 'Creates the database (/var/lib/krb5kdc/principal) and the stash file with the master key.', why: 'The database holds every key of the realm: whoever reads it can impersonate anyone.', expected: '' },
        { title: 'Check the KDC configuration and ACL', command: 'cat /etc/krb5kdc/kdc.conf\ncat /etc/krb5kdc/kadm5.acl', what: 'Ports, lifetimes, database path; who may administer.', why: '"*/admin@CORP.LAB *" gives every /admin principal full rights.', expected: '*/admin@CORP.LAB    *', simulated: true },
        { title: 'Create users and admins', command: 'sudo kadmin.local -q "addprinc alice"\nsudo kadmin.local -q "addprinc alice/admin"', what: 'kadmin.local works directly on the database as root.', why: 'Keep admin principals separate from everyday user principals.', expected: 'Principal "alice@CORP.LAB" created.', simulated: true },
        { title: 'Publish the KDC in DNS and open the firewall', command: '_kerberos._udp      IN SRV 0 0 88  kdc1\n_kerberos._tcp      IN SRV 0 0 88  kdc1\n_kerberos-adm._tcp  IN SRV 0 0 749 kdc1\n\nnft: udp dport { 88, 464 } accept; tcp dport { 88, 464, 749 } accept', what: 'Clients find the KDC; the ports are reachable.', why: 'Port 88 for tickets, 464 for password changes, 749 for kadmin.', expected: '', simulated: true },
      ],
    },
    {
      id: 'ad-kerberos-linux',
      platform: 'Active Directory with Linux clients',
      summary: 'The same protocol with AD as the KDC.',
      prerequisites: ['An AD domain; DNS on the Linux host pointing to the domain controllers.'],
      steps: [
        { title: 'Discover and join', command: 'realm discover corp.example.com\nsudo realm join -U Administrator corp.example.com', what: 'realmd finds the domain through SRV records, creates a computer account and a keytab, and configures sssd.', why: 'Creates host/ and RestrictedKrbHost/ SPNs for the machine automatically.', expected: 'corp.example.com\n  type: kerberos\n  realm-name: CORP.EXAMPLE.COM' },
        { title: 'Check from Windows', command: 'klist\nsetspn -L SRV01\nw32tm /query /status', what: 'Windows tickets, the SPNs of a computer account, time sync.', why: 'The same failure classes: SPN missing or duplicated, time skew, DNS SRV.', expected: '' },
      ],
    },
  ],

  configIntro: `
Kerberos configuration is small, but every line matters: the client file decides how the KDC is found and how names map to realms; the KDC files decide lifetimes and who may administer; the keytab is the service's secret.
`,

  configFiles: [
    {
      platform: 'Linux client (MIT krb5)',
      items: [
        { path: '/etc/krb5.conf', purpose: 'Default realm, KDC location (kdc lines or DNS SRV), lifetimes, domain → realm mapping.' },
        { path: '/tmp/krb5cc_UID', purpose: 'Your credential cache (tickets). Some systems use KEYRING: or KCM: caches.' },
        { path: '~/.k5login', purpose: 'Principals allowed to log in as this account (instead of the default name mapping).' },
        { path: '/etc/krb5.keytab', purpose: 'Long-term keys of the host\'s service principals (servers only). root 600.' },
        { path: '/etc/ssh/sshd_config(.d/*.conf): GSSAPIAuthentication', purpose: 'Kerberos logins for sshd.' },
      ],
    },
    {
      platform: 'MIT KDC (Debian)',
      items: [
        { path: '/etc/krb5kdc/kdc.conf', purpose: 'Realms served, ports, database, max_life/max_renewable_life.' },
        { path: '/etc/krb5kdc/kadm5.acl', purpose: 'kadmind permissions (read at start).' },
        { path: '/var/lib/krb5kdc/principal', purpose: 'The principal database (binary; use kadmin).' },
        { path: '/etc/krb5kdc/stash', purpose: 'Master key stash, lets the KDC start unattended.' },
        { path: 'DNS zone: _kerberos._udp / _kerberos._tcp / _kerberos-adm._tcp SRV', purpose: 'How clients find the KDC and kadmind.' },
      ],
    },
  ],

  directives: [
    { name: 'default_realm (krb5.conf)', compiledDefault: 'none', recommended: 'Your realm (CORP.LAB)', explanation: 'Realm appended to names without @REALM.', security: 'A wrong default realm sends credentials to the wrong KDC (or none).' },
    { name: 'dns_lookup_kdc', compiledDefault: 'true', recommended: 'true with SRV records (or explicit kdc lines)', explanation: 'Find KDCs through _kerberos._udp/_tcp SRV records when the realm has no kdc entries.', security: 'DNS answers are not authenticated, but a fake KDC cannot produce valid tickets without the keys; mutual authentication still protects the user.' },
    { name: 'rdns', compiledDefault: 'true', recommended: 'false', explanation: 'Use reverse DNS (PTR) to canonicalise server names. false avoids failures from missing or wrong PTR records.', security: 'Reverse DNS is easy to spoof; forward canonicalisation is safer.' },
    { name: 'ticket_lifetime / max_life', compiledDefault: '1 day / 1 day', recommended: '10 h (Debian KDC default) / workday', explanation: 'The client asks for ticket_lifetime; the KDC grants at most max_life.', security: 'Shorter lifetimes limit the use of a stolen ticket cache.' },
    { name: 'clockskew', compiledDefault: '300 (s)', recommended: '300', explanation: 'Allowed time difference.', security: 'Raising it widens the replay window. Fix NTP instead.' },
    { name: 'default_principal_flags = +preauth (kdc.conf)', compiledDefault: 'no preauth', recommended: '+preauth', explanation: 'Require encrypted-timestamp pre-authentication for new principals.', security: 'Without it anyone can request an AS-REP for a user and try passwords offline ("AS-REP roasting").' },
    { name: 'GSSAPIAuthentication (sshd)', compiledDefault: 'no', recommended: 'yes on Kerberos-joined servers', explanation: 'Accept Kerberos tickets for SSH logins (gssapi-with-mic).', security: 'Authentication strength = the user\'s Kerberos password; no keys on disk to steal.' },
  ],

  troubleshootingIntro: `
### Read the error, then follow the chain
Kerberos error messages are precise once you know what each one means. A login with Kerberos goes through three stages: getting a TGT (kinit), getting a ticket for the service (kvno), and the service accepting it. Find which stage fails.

1. **Does kinit fail?** The message says where:
- *Cannot find KDC*: the client does not know where the KDC is (krb5.conf, or the DNS SRV records).
- *Cannot contact any KDC*: the KDC was found but does not answer (network, firewall, or the KDC is down). A slow failure means packets are dropped; a fast one means nothing listens.
- *Clock skew too great*: the client's clock is more than 5 minutes off the KDC's.
- *Password incorrect* or *not found in Kerberos database*: the account or the password.
2. **kinit works, but the service does not?** Run \`kvno host/NAME\`. *Server not found* means the service's principal is missing, or the name is wrong: Kerberos needs the full name (FQDN), not a CNAME alias or an IP address, and the right realm.
3. **kvno works, but the login does not?** The problem is on the server: the keytab is missing or holds an older key version (compare \`klist -ke\` with \`kvno\`), the service is not configured for Kerberos (GSSAPIAuthentication), the user mapping is wrong (\`.k5login\`), or the server's clock is off.
4. **Always check the KDC's log.** \`journalctl -u krb5-kdc\` shows every request and its result.
5. **Prove the fix with a login that cannot fall back** to another method: \`ssh -o PubkeyAuthentication=no -o PasswordAuthentication=no\`.

### Where to look
- Client: \`kinit\`, \`klist\`, \`kvno host/NAME\`, \`ssh -v\`, \`date\` or \`timedatectl\`, \`host -t SRV _kerberos._udp.DOMAIN\`.
- KDC: \`journalctl -u krb5-kdc\` (one line per request: AS_REQ or TGS_REQ, the client, the service and the result: ISSUE, NEEDED_PREAUTH, PREAUTH_FAILED, CLIENT_NOT_FOUND, LOOKING_UP_SERVER ...), and \`kadmin.local -q "getprinc NAME"\`.
- Server: \`klist -ke\` (the keytab), \`sshd -T | grep gssapi\`, the sshd log (GSSAPI errors only appear at LogLevel DEBUG1).

`,

  errorMap: [
    { message: 'kinit: Cannot find KDC for realm "CORP.LAB" while getting initial credentials', layer: 'Configuration / DNS', meaning: 'No kdc line and no SRV records: nothing to ask.', firstCheck: 'host -t SRV _kerberos._udp.corp.lab; /etc/krb5.conf [realms]' },
    { message: "kinit: Cannot contact any KDC for realm 'CORP.LAB' while getting initial credentials", layer: 'Network / KDC', meaning: 'KDCs known but no answer: firewall (slow) or KDC down (fast).', firstCheck: 'ss -ulnp on the KDC; tcpdump port 88; nft list ruleset' },
    { message: 'kinit: Clock skew too great while getting initial credentials', layer: 'Time', meaning: 'Client and KDC clocks differ by more than 5 minutes.', firstCheck: 'date on both; timedatectl' },
    { message: 'kinit: Password incorrect while getting initial credentials', layer: 'Account', meaning: 'Pre-authentication failed (KDC log: PREAUTH_FAILED).', firstCheck: 'journalctl -u krb5-kdc; getprinc (failed attempts)' },
    { message: "kinit: Client 'bob@CORP.LAB' not found in Kerberos database while getting initial credentials", layer: 'Account', meaning: 'No such principal.', firstCheck: 'kadmin.local -q "listprincs"' },
    { message: 'kvno: Server not found in Kerberos database while getting credentials for host/www.corp.lab@CORP.LAB', layer: 'Service principal', meaning: 'Principal missing or the name differs from what was registered.', firstCheck: 'host -t CNAME the name; listprincs host/*' },
    { message: 'Permission denied (publickey,gssapi-keyex,gssapi-with-mic).', layer: 'Server', meaning: 'GSSAPI was offered but the server rejected the ticket (or the client had none).', firstCheck: 'klist on the client; kvno vs klist -ke on the server' },
    { message: 'Key version number for principal in key table is incorrect (sshd, LogLevel DEBUG1)', layer: 'Keytab', meaning: 'The server\'s keytab is behind the KDC.', firstCheck: 'kvno host/NAME vs sudo klist -ke' },
  ],

  scenarioIds: ['krb-clock-skew', 'krb-missing-srv', 'krb-kdc-firewall', 'krb-stale-keytab'],
  assessmentId: 'kerberos',
  references: [
    { title: 'RFC 4120: The Kerberos Network Authentication Service (V5)', url: 'https://www.rfc-editor.org/rfc/rfc4120' },
    { title: 'RFC 2782: A DNS RR for specifying the location of services (DNS SRV)', url: 'https://www.rfc-editor.org/rfc/rfc2782' },
    { title: 'RFC 4462: GSS-API authentication for SSH', url: 'https://www.rfc-editor.org/rfc/rfc4462' },
    { title: 'MIT Kerberos documentation: krb5.conf, kdc.conf, kadmin', url: 'https://web.mit.edu/kerberos/krb5-latest/doc/admin/index.html' },
    { title: 'Debian Wiki: Kerberos', url: 'https://wiki.debian.org/Kerberos' },
    { title: 'Microsoft Learn: Kerberos authentication overview', url: 'https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview' },
  ],
  guide: KERBEROS_GUIDE,
  caseStudyIds: ['domain-login'],
  objectives: ['N10-009:1.4', 'N10-009:4.1', 'N10-009:5.3'],
};
