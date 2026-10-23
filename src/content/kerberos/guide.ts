// Operate & recover guide: MIT Kerberos (KDC on ns1, clients, keytabs) and
// Kerberos logins over SSH.

import type { ServiceGuide } from '../types';

export const KERBEROS_GUIDE: ServiceGuide = {
  purpose:
    'Kerberos lets users prove their password **once** to a trusted **KDC** and then use tickets to log in to any service of the realm without the password crossing the network. In the lab the realm **CORP.LAB** is served by an MIT KDC on **ns1**, clients find it through **DNS SRV records**, and **srv01** accepts Kerberos SSH logins with the key in **/etc/krb5.keytab**. Operationally Kerberos fails where it depends on others: DNS, time, the network path to port 88, and keys that must match on the KDC and on each server.',
  architecture: [
    { q: 'What does it accomplish?', a: 'Single sign-on with mutual authentication: one password entry per day, tickets for every service, no passwords stored on or sent to servers.' },
    { q: 'How does it work internally?', a: 'The KDC stores a long-term key for every principal. The AS exchange gives a client a TGT after pre-authentication (a timestamp encrypted with the password-derived key). The TGS exchange turns the TGT into service tickets encrypted with each service\'s key. The service decrypts the ticket with its keytab: it never contacts the KDC to verify a user.' },
    { q: 'Which protocols does it use?', a: 'Kerberos V5 (RFC 4120) over UDP and TCP 88; kpasswd on 464; MIT kadmin (RPCSEC_GSS) on TCP 749; DNS SRV (RFC 2782) to find KDCs; GSS-API (RFC 2743) to carry tickets inside other protocols: SSH gssapi-with-mic (RFC 4462), HTTP Negotiate/SPNEGO, NFS, LDAP SASL/GSSAPI.' },
    { q: 'Which ports and transport?', a: 'KDC: UDP 88 (and 750 on Debian) for small requests, TCP 88 for large ones and as fallback. kpasswd: 464 UDP/TCP. kadmind: TCP 749. Services use their own ports (SSH 22).' },
    { q: 'Which processes and OS components implement it?', a: 'KDC: krb5kdc (krb5-kdc.service) and kadmind (krb5-admin-server.service) on ns1. Clients: the krb5 library used by kinit, ssh, sshd, sssd, browsers. Tools: kinit, klist, kvno, kdestroy, kadmin, kadmin.local. Active Directory: every domain controller runs the KDC (lsass, "Kerberos Key Distribution Center" service).' },
    { q: 'Which other services does it depend on?', a: 'DNS (SRV records to find the KDC, forward lookups to canonicalise server names), NTP (clocks within 5 minutes), network reachability of port 88, and correct keys in each server\'s keytab.' },
    { q: 'How do requests travel?', a: 'ws01 → (DNS SRV query to ns1) → AS-REQ/AS-REP with ns1:88 → TGS-REQ/TGS-REP with ns1:88 → AP-REQ to srv01 inside the SSH userauth request. Only the last step involves srv01.' },
    { q: 'How do authentication and authorisation work?', a: 'Authentication: knowledge of the principal\'s key (password or keytab). Authorisation is up to each service: sshd maps alice@CORP.LAB to the local user alice (or uses ~/.k5login); kadmind uses kadm5.acl; AD uses group SIDs carried in the ticket (PAC).' },
    { q: 'How does it start at boot?', a: 'krb5-kdc and krb5-admin-server are enabled systemd units on the KDC; they read kdc.conf, open the database with the stashed master key, and listen. Clients need nothing running: tickets are fetched on demand. systemd-timesyncd keeps clocks right.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'If the KDC stops, nobody can get new tickets (existing ones keep working until they expire, typically 10 h). Production realms run several KDCs (replicas, all listed in SRV records). If kadmind stops, administration fails but logins continue.' },
  ],
  ports: [
    { port: '88', proto: 'UDP, TCP', purpose: 'KDC: AS and TGS exchanges' },
    { port: '750', proto: 'UDP', purpose: 'KDC (Debian default extra port)' },
    { port: '464', proto: 'UDP, TCP', purpose: 'kpasswd: password changes' },
    { port: '749', proto: 'TCP', purpose: 'kadmind: remote administration (kadmin)' },
    { port: '53', proto: 'UDP, TCP', purpose: 'DNS: SRV records that locate the KDC' },
  ],
  processes: [
    { name: 'krb5kdc', platform: 'MIT KDC (ns1)', role: 'Authentication Service and Ticket-Granting Service; logs every request.' },
    { name: 'kadmind', platform: 'MIT KDC (ns1)', role: 'Remote administration (kadmin) with ACL checks; also kpasswd.' },
    { name: 'krb5 library (libkrb5, libgssapi_krb5)', platform: 'Every client and service', role: 'Reads krb5.conf, locates KDCs, manages caches and keytabs.' },
    { name: 'sshd / ssh', platform: 'srv01 / ws01', role: 'GSSAPI authentication (gssapi-with-mic) with host/NAME tickets.' },
    { name: 'systemd-timesyncd', platform: 'All corp.lab machines', role: 'Keeps clocks within the allowed skew.' },
  ],
  dependencies: {
    title: 'What a Kerberos SSH login from ws01 to srv01 needs',
    rows: [
      { label: 'Client', nodes: [{ id: 'conf', label: 'krb5.conf', sub: 'default_realm, dns_lookup_kdc', kind: 'os' }, { id: 'time', label: 'Clock', sub: 'NTP, < 5 min skew', kind: 'os' }] },
      { label: 'DNS', nodes: [{ id: 'srv', label: 'SRV _kerberos._udp', sub: '→ ns1:88', kind: 'service' }, { id: 'a', label: 'A / CNAME', sub: 'srv01.corp.lab', kind: 'service' }] },
      { label: 'KDC', nodes: [{ id: 'kdc', label: 'krb5kdc (ns1)', sub: 'port 88 reachable', kind: 'server' }, { id: 'db', label: 'Principal database', sub: 'alice, host/srv01', kind: 'data' }] },
      { label: 'Server', nodes: [{ id: 'kt', label: '/etc/krb5.keytab', sub: 'kvno matches KDC', kind: 'data' }, { id: 'sshd', label: 'sshd', sub: 'GSSAPIAuthentication yes', kind: 'service' }] },
    ],
    edges: [['conf', 'srv'], ['srv', 'kdc'], ['time', 'kdc'], ['kdc', 'db'], ['a', 'sshd'], ['sshd', 'kt'], ['kt', 'db', 'same key']],
  },
  sequence: {
    title: 'kinit and a Kerberos SSH login',
    lanes: [{ id: 'c', label: 'ws01', sub: 'alice' }, { id: 'd', label: 'ns1', sub: 'DNS' }, { id: 'k', label: 'ns1', sub: 'KDC :88' }, { id: 's', label: 'srv01', sub: 'sshd' }],
    steps: [
      { from: 'c', to: 'd', label: 'SRV _kerberos._udp.corp.lab?' },
      { from: 'd', to: 'c', label: '0 0 88 ns1.corp.lab', note: 'Missing record → "Cannot find KDC for realm".' },
      { from: 'c', to: 'k', label: 'AS-REQ (no pre-auth)' },
      { from: 'k', to: 'c', label: 'KDC_ERR_PREAUTH_REQUIRED' },
      { from: 'c', to: 'k', label: 'AS-REQ + {timestamp}K_alice', note: 'Clock > 5 min off → KRB_AP_ERR_SKEW.' },
      { from: 'k', to: 'c', label: 'AS-REP: TGT' },
      { from: 'c', to: 'k', label: 'TGS-REQ host/srv01.corp.lab' },
      { from: 'k', to: 'c', label: 'TGS-REP: ticket (kvno 2)' },
      { from: 'c', to: 's', label: 'SSH userauth gssapi-with-mic: AP-REQ' },
      { from: 's', to: 'c', label: 'USERAUTH_SUCCESS', note: 'Keytab without kvno 2 → USERAUTH_FAILURE, ssh falls back to keys/passwords.' },
    ],
  },
  files: [
    { path: '/etc/krb5.conf', platform: 'All clients and servers', kind: 'config', contains: 'default_realm, dns_lookup_kdc, rdns, lifetimes, [realms] (kdc, admin_server), [domain_realm].', accessed: 'When any Kerberos program starts.', problems: 'Syntax error → every Kerberos program fails. Hard-coded kdc lines → break when the KDC moves; no kdc lines → SRV records required.', perms: 'root:root 644' },
    { path: '/tmp/krb5cc_UID', platform: 'Clients', kind: 'runtime', contains: 'The user\'s TGT and service tickets.', accessed: 'kinit writes it; every Kerberos client reads it.', problems: 'Stale service tickets after a key change (kdestroy fixes). Readable by others = stolen identity.', perms: 'user 600' },
    { path: '/etc/krb5.keytab', platform: 'Servers (srv01)', kind: 'auth', contains: 'host/srv01.corp.lab keys with their kvno.', accessed: 'sshd at every GSSAPI login; kinit -k.', problems: 'kvno behind the KDC; missing principal for the name clients use; mode wider than 600.', perms: 'root:root 600' },
    { path: '/etc/krb5kdc/kdc.conf', platform: 'KDC (ns1)', kind: 'config', contains: 'Realms, ports, database path, max_life, max_renewable_life, ACL file.', accessed: 'At KDC/kadmind start.', problems: 'Wrong database path → KDC fails to start.', perms: 'root:root 644 (directory 700)' },
    { path: '/etc/krb5kdc/kadm5.acl', platform: 'KDC (ns1)', kind: 'auth', contains: '*/admin@CORP.LAB *', accessed: 'kadmind start only.', problems: 'Edited without restarting kadmind → no effect. Too broad → anyone with /admin can do everything.', perms: 'root:root 644' },
    { path: '/var/lib/krb5kdc/principal, /etc/krb5kdc/stash', platform: 'KDC (ns1)', kind: 'data', contains: 'All principals and keys; the master key.', accessed: 'Continuously by krb5kdc and kadmind.', problems: 'Exposure compromises the whole realm; back it up (kdb5_util dump) and protect it.', perms: 'root 600' },
    { path: 'corp.lab zone: _kerberos._udp, _kerberos._tcp, _kerberos-adm._tcp, _kerberos TXT', platform: 'DNS (ns1: /etc/bind/db.corp.lab)', kind: 'config', contains: 'Where the KDC and kadmind are.', accessed: 'By clients at every kinit/kvno (no caching in the library).', problems: 'Dropped when a zone is regenerated from an inventory that does not know SRV records.' },
    { path: 'journalctl -u krb5-kdc / -u krb5-admin-server', platform: 'KDC (ns1)', kind: 'log', contains: 'One line per request: AS_REQ/TGS_REQ, client IP, principals, result (ISSUE, NEEDED_PREAUTH, PREAUTH_FAILED, CLIENT_NOT_FOUND, LOOKING_UP_SERVER).', accessed: 'Read when diagnosing.', problems: 'No line for a client = its requests never reached krb5kdc (DNS, routing, firewall).' },
  ],
  management: [
    {
      platform: 'Client (ws01)',
      tasks: [
        { task: 'Get a ticket', command: 'kinit\nklist', explain: 'TGT for alice@CORP.LAB.', sim: true },
        { task: 'Test a service principal', command: 'kvno host/srv01.corp.lab', explain: 'Service ticket and key version.', sim: true },
        { task: 'Start fresh', command: 'kdestroy', explain: 'After key changes or to test kinit again.', sim: true },
        { task: 'Find the KDC', command: 'host -t SRV _kerberos._udp.corp.lab\ndig +short _kerberos-adm._tcp.corp.lab SRV', explain: 'What the library will use.', sim: true },
        { task: 'Check the clock', command: 'timedatectl\nsudo timedatectl set-ntp true', explain: 'NTP active, clock synchronised.', sim: true },
      ],
    },
    {
      platform: 'KDC (ns1)',
      tasks: [
        { task: 'Service state and log', command: 'systemctl status krb5-kdc krb5-admin-server\njournalctl -u krb5-kdc -n 20', explain: 'Is it running, and what did it answer?', sim: true },
        { task: 'Listening sockets', command: 'ss -ulnp | grep -E ":(88|750)"\nss -tlnp | grep -E ":(88|749|464)"', explain: 'krb5kdc and kadmind ports.', sim: true },
        { task: 'Inspect principals', command: 'kadmin.local -q "listprincs"\nkadmin.local -q "getprinc host/srv01.corp.lab"', explain: 'Existence, key version, failed attempts.', sim: true },
        { task: 'Add a user / reset a password', command: 'kadmin.local -q "addprinc carol"\nkadmin.local -q "cpw carol"', explain: 'Prompts for the password twice.', risk: 'cpw on a service principal breaks its keytab.', sim: true },
        { task: 'Apply ACL changes', command: 'systemctl restart krb5-admin-server', explain: 'kadmind reads kadm5.acl only at start.', sim: true },
      ],
    },
    {
      platform: 'Server (srv01)',
      tasks: [
        { task: 'Inspect the keytab', command: 'sudo klist -ke', explain: 'Principals and kvno the server can decrypt.', sim: true },
        { task: 'Refresh the key', command: 'sudo kadmin -p alice/admin -q "ktadd host/srv01.corp.lab"', explain: 'New key on the KDC and in the keytab in one step.', risk: 'Clients holding old tickets keep working only while the old kvno stays in the keytab.', sim: true },
        { task: 'Enable Kerberos SSH', command: 'echo "GSSAPIAuthentication yes" | sudo tee /etc/ssh/sshd_config.d/20-kerberos.conf\nsudo sshd -t && sudo systemctl reload ssh', explain: 'Offers gssapi-with-mic.', sim: true },
      ],
    },
  ],
  actions: [
    { action: 'kdestroy + kinit (client)', when: 'After a key change, or to retest from scratch.', effect: 'Drops all cached tickets; the next requests go to the KDC.', risk: 'None.' },
    { action: 'systemctl restart krb5-kdc', when: 'After kdc.conf changes.', effect: 'A second of unavailability; existing tickets stay valid.', risk: 'A broken kdc.conf keeps the KDC down: check journalctl.' },
    { action: 'systemctl restart krb5-admin-server', when: 'After kadm5.acl changes.', effect: 'kadmind re-reads the ACL.', risk: 'Low.' },
    { action: 'ktadd (on the server)', when: 'New server, scheduled rotation, keytab out of step.', effect: 'New random key (kvno + 1) on the KDC and in the local keytab.', risk: 'Running it on the wrong machine changes the key without fixing the server.' },
    { action: 'cpw -randkey (on the KDC)', when: 'Only if the new key is distributed to the server in the same change.', effect: 'New key on the KDC only.', risk: 'Breaks every keytab with the old key immediately.' },
  ],
  workflow: [
    { question: '1. Does kinit work?', command: 'kdestroy; kinit; klist', healthy: 'Default principal: alice@CORP.LAB\n... krbtgt/CORP.LAB@CORP.LAB', broken: 'The message names the layer: Cannot find KDC (config/DNS), Cannot contact any KDC (network/KDC), Clock skew too great (time), Password incorrect / not found (account).', next: 'kinit OK → step 4. Otherwise steps 2–3.', sim: true },
    { question: '2. Is the KDC found and reachable?', command: 'host -t SRV _kerberos._udp.corp.lab\nss -ulnp | grep :88   # on ns1\nsudo tcpdump -n -i eth0 port 88   # on ns1', healthy: '_kerberos._udp.corp.lab has SRV record 0 0 88 ns1.corp.lab.', broken: 'NXDOMAIN = SRV records missing. Requests arrive but no KDC log line = KDC host firewall. Nothing listening = krb5-kdc down.', next: 'Fix DNS, firewall or service; retry kinit.', sim: true },
    { question: '3. Are the clocks within 5 minutes?', command: 'date\ntimedatectl\ndate   # on ns1 as well', healthy: 'System clock synchronized: yes', broken: 'Minutes apart and NTP inactive → Clock skew too great.', next: 'timedatectl set-ntp true.', sim: true },
    { question: '4. Can I get a ticket for the service?', command: 'kvno host/srv01.corp.lab', healthy: 'host/srv01.corp.lab@CORP.LAB: kvno = 2', broken: 'Server not found = principal missing or another name (CNAME, IP address, realm mapping).', next: 'Note the kvno → step 5.', sim: true },
    { question: '5. Does the server have that key?', command: 'sudo klist -ke   # on srv01', healthy: 'The same kvno as step 4.', broken: 'Older kvno only = keytab out of step (key changed on the KDC). No entry = keytab never created.', next: 'ktadd on the server; kdestroy/kinit on the client.', sim: true },
    { question: '6. Does sshd offer and accept GSSAPI?', command: 'sudo sshd -T | grep gssapi\nssh -v -o PubkeyAuthentication=no -o PasswordAuthentication=no srv01.corp.lab', healthy: 'debug1: Authenticated ... using "gssapi-with-mic".', broken: 'gssapiauthentication no → not offered. Offered but rejected → keytab, clock or account mapping (.k5login).', next: 'sshd log at LogLevel DEBUG1 shows the GSSAPI error.', sim: true },
  ],
  failures: [
    { symptom: 'kinit: Cannot find KDC for realm', causes: ['SRV records missing from the zone', 'krb5.conf has no kdc lines and dns_lookup_kdc = false', 'default_realm misspelled'], diagnose: ['host -t SRV _kerberos._udp.corp.lab', 'grep -n "kdc\\|realm" /etc/krb5.conf'], fix: 'Restore the SRV records (and bump the zone serial) or list KDCs in krb5.conf.', verify: 'kinit' },
    { symptom: "kinit: Cannot contact any KDC for realm 'CORP.LAB'", causes: ['Firewall on the KDC or the path drops port 88 (slow failure)', 'krb5-kdc not running (fast failure: ICMP port unreachable)', 'SRV records point to the wrong host'], diagnose: ['ss -ulnp | grep :88 (KDC)', 'journalctl -u krb5-kdc', 'tcpdump -n -i eth0 port 88', 'nft list ruleset'], fix: 'Allow UDP/TCP 88 (464, 749) or start the KDC.', verify: 'kinit; KDC log shows AS_REQ ... ISSUE' },
    { symptom: 'Clock skew too great', causes: ['NTP disabled on the client (or KDC, or server)', 'Clock set by hand', 'VM resumed from suspend'], diagnose: ['date on both sides', 'timedatectl', 'systemctl status systemd-timesyncd'], fix: 'timedatectl set-ntp true; keep NTP enabled everywhere.', verify: 'timedatectl shows synchronized; kinit works' },
    { symptom: 'Kerberos login to a server fails, kinit and kvno work', causes: ['Keytab kvno behind the KDC', 'Keytab missing or lacks the principal for the name used', 'GSSAPIAuthentication not enabled', 'Principal not mapped to the account (.k5login)'], diagnose: ['kvno host/NAME (client)', 'sudo klist -ke (server)', 'sshd -T | grep gssapi', 'ssh -v ...'], fix: 'ktadd on the server; enable GSSAPI; fix .k5login.', verify: 'ssh -o PubkeyAuthentication=no -o PasswordAuthentication=no NAME' },
    { symptom: 'kvno: Server not found in Kerberos database', causes: ['Service principal never created', 'Connecting by IP or alias: the principal name differs', 'Wrong realm mapping in [domain_realm]'], diagnose: ['kadmin.local -q "listprincs host/*"', 'host NAME (CNAME?)'], fix: 'addprinc -randkey host/FQDN and ktadd on the server; connect by the canonical name.', verify: 'kvno host/FQDN' },
  ],
  verification: [
    { check: 'KDC located through DNS', command: 'host -t SRV _kerberos._udp.corp.lab', expect: 'SRV record 0 0 88 ns1.corp.lab.' },
    { check: 'TGT obtained', command: 'kinit && klist', expect: 'krbtgt/CORP.LAB@CORP.LAB with an expiry ~10 h ahead' },
    { check: 'Service ticket and keytab agree', command: 'kvno host/srv01.corp.lab; sudo klist -k (srv01)', expect: 'Same kvno' },
    { check: 'Kerberos-only SSH login', command: 'ssh -o PubkeyAuthentication=no -o PasswordAuthentication=no srv01.corp.lab hostname', expect: 'srv01' },
    { check: 'Clocks synchronised', command: 'timedatectl', expect: 'System clock synchronized: yes' },
  ],
  refIds: ['kinit', 'klist-linux', 'kvno', 'kdestroy', 'kadmin', 'timedatectl', 'dig', 'file:krb5.conf', 'file:kdc.conf', 'file:kadm5.acl', 'file:krb5.keytab', 'proc:kerberos-diagnose', 'proc:keytab-rotate', 'klist', 'w32tm', 'setspn'],
};
