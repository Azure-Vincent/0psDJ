// Email with Postfix and Dovecot. Examples follow the lab: mail01 (10.0.20.25)
// receives mail for corp.lab (MX record), lets staff send on port 587,
// delivers into ~/Maildir/ and relays outside mail through the provider's
// relay (ext01, 203.0.113.80); Dovecot serves IMAP and checks logins for
// Postfix. The sandbox and the tickets run there. Exchange and RHEL are noted.

import type { Assessment, Lesson, Primer, ServiceGuide } from '../types';

// --- Operate & recover guide ---------------------------------------------------------

export const EMAIL_GUIDE: ServiceGuide = {
  purpose:
    'Email is two services working together. A **mail transfer agent** (MTA) such as Postfix accepts messages over SMTP, queues them and delivers them: into a local mailbox, or onward to the next server. A **mail store** such as Dovecot lets people read their mailbox over IMAP. Between organisations, DNS **MX records** say which server receives mail for a domain. Users send through the **submission** port (587) after logging in over TLS, and read over **IMAPS** (993).',
  architecture: [
    { q: 'What does it accomplish?', a: 'Reliable store-and-forward messaging: a message is accepted, written to a queue on disk, and retried until it is delivered or, after days, returned to the sender (a bounce).' },
    { q: 'How does it work internally?', a: 'Postfix is a set of small daemons run by `master`: **smtpd** receives SMTP connections and checks each recipient, **cleanup** writes the message into the queue, **qmgr** schedules deliveries, **local** delivers to mailboxes on this machine (after looking up **aliases**), **smtp** sends to other servers. Dovecot\'s **imap-login** accepts IMAP connections and checks the password (PAM); the user\'s **imap** process then reads the mailbox where `mail_location` says.' },
    { q: 'Which protocols does it use?', a: '**SMTP** (RFC 5321) between servers and from clients to the submission port, with **STARTTLS** to upgrade the connection to TLS and **AUTH** (SASL) to log in. **IMAP** (RFC 9051) to read mail; POP3 is its older, simpler cousin. **DNS MX** records find the receiving server for a domain.' },
    { q: 'Which ports and transport?', a: 'TCP **25** (SMTP between servers), **587** (submission: clients send, STARTTLS + login required), **465** (submission over implicit TLS), **143** (IMAP, STARTTLS) and **993** (IMAPS). Port 25 must be reachable from the Internet for incoming mail; 587/993 only from users.' },
    { q: 'Which processes and OS components implement it?', a: 'Postfix: `master` and its children (smtpd, cleanup, qmgr, local, smtp, pickup), the queue in /var/spool/postfix. Dovecot: `dovecot` (master), imap-login, imap, auth. Windows: Exchange Server (transport, mailbox and client access roles) or Microsoft 365.' },
    { q: 'Which other services does it depend on?', a: 'DNS (MX and A records; reverse DNS for reputation), TLS certificates, the firewall (25 in, 587/993 from users, 25 out to the relay), the user accounts and their passwords (PAM), disk space for the queue and mailboxes, and correct time (TLS, logs).' },
    { q: 'How do requests travel?', a: 'alice sends to partner@example.net: her client connects to mail01:587 → STARTTLS → AUTH as alice (Postfix asks Dovecot through /var/spool/postfix/private/auth) → MAIL FROM, RCPT TO, DATA → `250 Ok: queued as 3F2A81C0D4` → qmgr hands the message to smtp → relayhost [203.0.113.80]:25 → the relay delivers to example.net. Mail to dana@corp.lab instead goes to **local**: aliases, then ~dana/Maildir/new/.' },
    { q: 'How do authentication and authorisation work?', a: 'Port 25 needs no login, but only accepts mail **for its own domains** (mydestination) or from trusted networks (mynetworks); anything else is "Relay access denied": that is what stops the server becoming an **open relay**. On port 587 the client must use TLS and log in (SMTP AUTH): Postfix delegates the password check to Dovecot. IMAP logins are checked by Dovecot (PAM: the Unix passwords here).' },
    { q: 'How does it start at boot?', a: '`postfix@-.service` and `dovecot.service` from multi-user.target. Postfix re-reads main.cf and master.cf on `postfix reload`, except the listening addresses (inet_interfaces: stop and start). Lookup tables such as aliases.db are opened on each use. Dovecot reloads on `doveadm reload` / systemctl reload.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'Nothing is lost that was acknowledged: a message is on disk before smtpd answers 250. Senders retry for days when the receiving server is down, so a short outage only delays mail. Deferred mail waits in the queue and is retried (or flushed with postqueue -f).' },
  ],
  ports: [
    { port: '25', proto: 'TCP', purpose: 'SMTP between mail servers (incoming mail from the Internet; outgoing to the relay)' },
    { port: '587', proto: 'TCP', purpose: 'Submission: clients send mail after STARTTLS and a login' },
    { port: '465', proto: 'TCP', purpose: 'Submission over implicit TLS (smtps / submissions)' },
    { port: '143', proto: 'TCP', purpose: 'IMAP (STARTTLS before login)' },
    { port: '993', proto: 'TCP', purpose: 'IMAPS: IMAP over TLS' },
    { port: '110 / 995', proto: 'TCP', purpose: 'POP3 / POP3S (older download-and-delete access)' },
  ],
  processes: [
    { name: 'master, smtpd, cleanup, qmgr, local, smtp', platform: 'Linux (Postfix, postfix@-.service)', role: 'master starts the others on demand: smtpd receives, cleanup queues, qmgr schedules, local and smtp deliver' },
    { name: 'dovecot, imap-login, imap, auth', platform: 'Linux (Dovecot, dovecot.service)', role: 'IMAP service and the authentication service Postfix uses for SMTP AUTH' },
    { name: 'MSExchangeTransport, MSExchangeIS', platform: 'Windows (Exchange Server)', role: 'The SMTP transport service and the mailbox store' },
  ],
  dependencies: {
    title: 'What "alice sends mail to dana and dana reads it" depends on (top needs everything below it)',
    caption: 'Sending and reading meet in one place: the mailbox that Postfix writes and Dovecot reads.',
    rows: [
      { label: 'Clients', nodes: [{ id: 'mua', label: 'Mail client', sub: 'swaks, Thunderbird', kind: 'service' }, { id: 'imapc', label: 'IMAP client', sub: 'curl imaps://', kind: 'service' }] },
      { label: 'Path', nodes: [{ id: 'dns', label: 'DNS', sub: 'MX corp.lab, A mail01', kind: 'network' }, { id: 'fw', label: 'mail01 firewall', sub: '25, 587, 143, 993', kind: 'network' }] },
      { label: 'Services', nodes: [{ id: 'pf', label: 'Postfix', sub: 'smtpd 25/587', kind: 'service' }, { id: 'dc', label: 'Dovecot', sub: 'imap, auth', kind: 'service' }, { id: 'tls', label: 'Certificate + key', sub: 'mail01.corp.lab', kind: 'data' }] },
      { label: 'Data', nodes: [{ id: 'alias', label: 'aliases.db', sub: 'newaliases', kind: 'data' }, { id: 'queue', label: 'Queue', sub: '/var/spool/postfix', kind: 'data' }, { id: 'box', label: '~/Maildir', sub: 'home_mailbox = mail_location', kind: 'os' }] },
    ],
    edges: [['mua', 'dns'], ['mua', 'fw'], ['imapc', 'fw'], ['fw', 'pf'], ['fw', 'dc'], ['pf', 'tls'], ['dc', 'tls'], ['pf', 'dc'], ['pf', 'alias'], ['pf', 'queue'], ['queue', 'box'], ['dc', 'box']],
  },
  sequence: {
    title: 'alice submits a message for dana on port 587',
    caption: 'Postfix 3.7 and Dovecot 2.3 on mail01. Where each ticket breaks the exchange is noted.',
    lanes: [{ id: 'c', label: 'ws01', sub: 'swaks (alice)' }, { id: 's', label: 'mail01', sub: 'Postfix smtpd' }, { id: 'd', label: 'mail01', sub: 'Dovecot auth' }],
    steps: [
      { from: 'c', to: 's', label: 'TCP SYN to 10.0.20.25:587', note: 'inet_interfaces = loopback-only → Connection refused.' },
      { from: 's', to: 'c', label: '220 mail01.corp.lab ESMTP Postfix' },
      { from: 'c', to: 's', label: 'EHLO ws01.corp.lab' },
      { from: 's', to: 'c', label: '250-STARTTLS …', note: 'Certificate and key do not match → no STARTTLS in the list ("Host did not advertise STARTTLS").' },
      { from: 'c', to: 's', label: 'STARTTLS, TLS handshake, EHLO again' },
      { from: 's', to: 'd', label: 'connect private/auth (SASL)', note: 'Socket missing → "SASL: Connect to private/auth failed", smtpd exits: the client loses the connection.' },
      { from: 'c', to: 's', label: 'AUTH PLAIN …' },
      { from: 's', to: 'd', label: 'check alice\'s password (PAM)' },
      { from: 's', to: 'c', label: '235 Authentication successful' },
      { from: 'c', to: 's', label: 'MAIL FROM, RCPT TO:<sales@corp.lab>', note: 'Alias missing from aliases.db → 550 User unknown in local recipient table.' },
      { from: 'c', to: 's', label: 'DATA … .' },
      { from: 's', to: 'c', label: '250 2.0.0 Ok: queued as 3F2A81C0D4', note: 'Then local delivery: home_mailbox decides Maildir or /var/mail (Dovecot must read the same place).' },
    ],
  },
  files: [
    { path: '/etc/postfix/main.cf', platform: 'Postfix', kind: 'config', perms: 'root:root 0644', contains: 'Parameters: myhostname, mydestination, mynetworks, relayhost, inet_interfaces, TLS files, SASL, home_mailbox, alias_maps.', accessed: 'At start and on postfix reload (inet_interfaces only on stop/start).', problems: 'Edit with postconf -e; check with postconf -n and postfix check. Typos become "unused parameter" warnings.' },
    { path: '/etc/postfix/master.cf', platform: 'Postfix', kind: 'config', perms: 'root:root 0644', contains: 'The services master runs: smtp (25), submission (587) with its -o overrides (TLS required, SASL on, relay only when logged in).', accessed: 'At start and reload.', problems: 'An -o override silently wins over main.cf for that service only.' },
    { path: '/etc/aliases and /etc/aliases.db', platform: 'Postfix', kind: 'config', perms: 'root:root 0644', contains: 'name: target, target. Postfix reads the compiled .db file.', accessed: 'On every lookup (no reload needed), but only after newaliases rebuilt the .db.', problems: 'Edited text file without newaliases: the change does not exist for Postfix.' },
    { path: '/var/spool/postfix', platform: 'Postfix', kind: 'data', perms: 'postfix (queues 0700)', contains: 'The queue: incoming, active, deferred messages; private/ holds sockets such as private/auth.', accessed: 'Constantly.', problems: 'Never edit by hand: use mailq, postqueue, postsuper.' },
    { path: '/var/log/mail.log', platform: 'Debian (rsyslog, facility mail)', kind: 'log', perms: 'root:adm 0640', contains: 'One line per event, the queue ID linking smtpd, cleanup, qmgr and delivery lines; Dovecot logins.', accessed: 'Written by rsyslog.', problems: 'Follow one message by its queue ID: grep 3F2A81C0D4 /var/log/mail.log.' },
    { path: '/etc/dovecot/dovecot.conf and conf.d/*.conf', platform: 'Dovecot', kind: 'config', perms: 'root:root 0644', contains: 'protocols, listen, 10-auth (disable_plaintext_auth, mechanisms), 10-mail (mail_location), 10-master (listeners, the auth socket for Postfix), 10-ssl (certificate and key).', accessed: 'At start and reload.', problems: 'doveconf -n prints what Dovecot actually uses; an unknown setting stops it from starting.' },
    { path: '~/Maildir/{new,cur,tmp} and /var/mail/USER', platform: 'Mailboxes', kind: 'data', perms: 'USER 0700 / USER:mail 0600', contains: 'Maildir: one file per message. mbox: one file with all messages.', accessed: 'Written by Postfix local, read by Dovecot.', problems: 'Both programs must agree on the format and place.' },
  ],
  management: [
    {
      platform: 'Client (ws01)',
      tasks: [
        { task: 'Send a test message', command: 'swaks --to dana@corp.lab --server mail01.corp.lab', explain: 'Prints the whole SMTP dialogue: the line where it fails names the step.', sim: true },
        { task: 'Send like a mail client (587)', command: 'swaks --to partner@example.net --server mail01.corp.lab:587 --tls --auth-user alice --auth-password Mail-alice-26', explain: 'STARTTLS, login, relay to the outside.', sim: true },
        { task: 'Read a mailbox', command: "curl -s 'imaps://mail01.corp.lab/INBOX?ALL' -u dana:Mail-dana-26\ncurl -s 'imaps://mail01.corp.lab/INBOX;UID=1' -u dana:Mail-dana-26", explain: 'SEARCH lists message numbers; ;UID=n prints one message.', sim: true },
        { task: 'Look at the certificate', command: 'openssl s_client -connect mail01.corp.lab:587 -starttls smtp', explain: 'Which certificate does port 587 present after STARTTLS?', sim: true },
        { task: 'Where does mail for a domain go?', command: 'dig +short MX corp.lab', explain: 'The MX record names the receiving server.', sim: true },
      ],
    },
    {
      platform: 'Mail server (mail01)',
      tasks: [
        { task: 'Changed settings and checks', command: 'postconf -n\npostfix check', explain: 'Only what main.cf sets; warnings such as an outdated aliases.db.', sim: true },
        { task: 'Change a parameter', command: "postconf -e 'relayhost = [203.0.113.80]'\nsystemctl reload postfix", explain: 'Edits main.cf safely; reload applies it.', sim: true },
        { task: 'The queue', command: 'mailq\npostqueue -f\npostsuper -d QUEUE_ID', explain: 'What waits and why; retry now; delete one message.', sim: true },
        { task: 'Aliases', command: 'newaliases', explain: 'Rebuild /etc/aliases.db after editing /etc/aliases.', sim: true },
        { task: 'Dovecot', command: 'doveconf -n\ndoveadm auth test dana\ndoveadm mailbox status -u dana messages unseen INBOX', explain: 'Effective settings, a password check, a mailbox count.', sim: true },
        { task: 'Follow one message', command: 'grep 3F2A81C0D4 /var/log/mail.log', explain: 'All lines of one message share its queue ID.', sim: true },
      ],
    },
    {
      platform: 'Windows (Exchange Server)',
      tasks: [
        { task: 'Queues and message tracking', command: 'Get-Queue\nGet-MessageTrackingLog -Recipients dana@corp.lab -Start (Get-Date).AddHours(-2)', explain: 'The Exchange equivalents of mailq and following a queue ID in mail.log.' },
      ],
    },
  ],
  actions: [
    { action: 'postfix reload (systemctl reload postfix)', when: 'After editing main.cf or master.cf.', effect: 'New processes use the new settings; queued mail is untouched.', risk: 'inet_interfaces and inet_protocols need postfix stop; postfix start.' },
    { action: 'newaliases', when: 'After editing /etc/aliases.', effect: 'Rebuilds aliases.db; Postfix sees the change on the next lookup.', risk: 'None.' },
    { action: 'postqueue -f', when: 'After fixing the cause of deferred mail.', effect: 'Retries every queued message now.', risk: 'A large queue all at once can trip the receiver\'s rate limits.' },
    { action: 'postsuper -d ID|ALL', when: 'Removing spam or a message that must not be delivered.', effect: 'Deletes from the queue, without a bounce.', risk: 'Irreversible: the sender is never told.' },
    { action: 'systemctl restart dovecot', when: 'After listener or socket changes.', effect: 'Recreates the listeners and sockets.', risk: 'Open IMAP sessions are disconnected (clients reconnect).' },
  ],
  workflow: [
    { question: 'Does the server answer on the port?', why: 'Nothing else matters if TCP does not connect. Refused and timed out point to different causes.', command: 'swaks --to dana@corp.lab --server mail01.corp.lab:587 --quit-after banner\nss -tlnp', healthy: '<-  220 mail01.corp.lab ESMTP Postfix', broken: 'connect: Connection refused (not listening on that address: inet_interfaces, service down); timeout (firewall).', next: 'Then the dialogue.', sim: true },
    { question: 'Where does the SMTP dialogue stop?', why: 'Each command is checked separately: TLS, login, sender, each recipient, the data.', command: 'swaks --to dana@corp.lab --server mail01.corp.lab:587 --tls --auth-user alice --auth-password Mail-alice-26', healthy: '<~  250 2.0.0 Ok: queued as …', broken: 'No STARTTLS (certificate/key), connection lost after STARTTLS (SASL socket), 535 (password), 550 User unknown (aliases), 454 Relay access denied (not logged in).', next: 'Read the server side.', sim: true },
    { question: 'What does the server log say?', why: 'mail.log has the reason the client never sees: warnings, fatal errors, and every delivery with its status.', command: 'tail -n 30 /var/log/mail.log', healthy: 'status=sent (delivered to maildir)', broken: 'NOQUEUE: reject …, warning: SASL …, cannot get RSA private key, status=deferred (…)', next: 'If accepted but not delivered: the queue.', sim: true },
    { question: 'Was it accepted but not delivered?', why: 'Deferred mail waits silently for days; mailq says why.', command: 'mailq', healthy: 'Mail queue is empty', broken: '(connect to …: Connection timed out) / (Host or domain name not found …) / (maildir delivery failed …)', next: 'Fix, then postqueue -f.', sim: true },
    { question: 'Delivered, but can the user read it?', why: 'Postfix writes the mailbox, Dovecot reads it: they must agree on where.', command: "postconf home_mailbox\ndoveconf mail_location\ncurl -s 'imaps://mail01.corp.lab/INBOX?ALL' -u dana:Mail-dana-26", healthy: 'home_mailbox = Maildir/, mail_location = maildir:~/Maildir, SEARCH lists the message', broken: 'delivered to mailbox (/var/mail) while Dovecot reads Maildir', next: 'Align them and test end to end.', sim: true },
  ],
  failures: [
    { symptom: '550 5.1.1 User unknown in local recipient table', causes: ['/etc/aliases edited without newaliases', 'The address really does not exist'], diagnose: ['postfix check', 'grep NAME /etc/aliases; getent passwd NAME'], fix: 'newaliases (or create the account).', verify: 'swaks to the address: 250 queued.' },
    { symptom: 'Connection refused on 25/587', causes: ['inet_interfaces = loopback-only', 'Postfix stopped'], diagnose: ['ss -tlnp | grep master', 'postconf inet_interfaces'], fix: 'inet_interfaces = all, then postfix stop; postfix start.', verify: 'ss shows 0.0.0.0:25 and :587.' },
    { symptom: 'Sending through 587 fails, reading works', causes: ['Dovecot auth socket missing (SASL)', 'Certificate/key mismatch: no STARTTLS', 'Wrong password'], diagnose: ['swaks with --tls --auth-user', 'tail /var/log/mail.log', 'ls -l /var/spool/postfix/private/'], fix: 'Restore the unix_listener in 10-master.conf; point Postfix at the matching key.', verify: 'swaks shows 235 and 250 queued.' },
    { symptom: 'Mail accepted, never arrives outside', causes: ['relayhost does not resolve or does not answer', 'Firewall blocks outgoing 25'], diagnose: ['mailq', 'grep status=deferred /var/log/mail.log'], fix: 'Correct relayhost; postqueue -f.', verify: 'mailq empty; the recipient has the message.' },
    { symptom: 'Sender sees success, recipient sees nothing', causes: ['Postfix delivers to mbox, Dovecot reads Maildir (or the reverse)'], diagnose: ['delivered to mailbox vs maildir in mail.log', 'doveconf mail_location'], fix: 'home_mailbox = Maildir/ (or change both consistently).', verify: 'Send, then read over IMAP.' },
  ],
  verification: [
    { check: 'Configuration', command: 'postfix check && doveconf -n >/dev/null', expect: 'No output from postfix check' },
    { check: 'Listening', command: 'ss -tlnp', expect: 'master on 0.0.0.0:25 and :587, dovecot on :143 and :993' },
    { check: 'Send', command: 'swaks --to dana@corp.lab --server mail01.corp.lab:587 --tls --auth-user alice --auth-password Mail-alice-26', expect: '250 2.0.0 Ok: queued as …' },
    { check: 'Read', command: "curl -s 'imaps://mail01.corp.lab/INBOX?ALL' -u dana:Mail-dana-26", expect: '* SEARCH 1 2 …' },
    { check: 'Queue', command: 'mailq', expect: 'Mail queue is empty' },
  ],
  refIds: ['swaks', 'postconf', 'mailq', 'doveadm', 'file:postfix-main-cf', 'file:dovecot-conf', 'proc:mail-not-delivered', 'ss', 'dig'],
};

// --- Lesson -------------------------------------------------------------------------

export const EMAIL_LESSON: Lesson = {
  id: 'email',
  moduleId: 'F',
  title: 'Email (Postfix and Dovecot)',
  level: 'advanced',
  summary: 'How a message travels: the MX record, the SMTP dialogue on ports 25 and 587, relay rules and logins, the queue, aliases and local delivery, and reading it back over IMAP. With Postfix\'s and Dovecot\'s logs, and the six classic ways it breaks.',
  concepts: ['mail.smtp', 'mail.imap', 'tls.pki', 'dns.zone'],
  what: `
**Email** moves a message from a sender to a mailbox, possibly through several servers, and lets the owner read it later. Two kinds of server do the work:
- a **mail transfer agent** (MTA, here **Postfix**) receives messages over **SMTP**, keeps them in a **queue** on disk, and delivers them: into a mailbox on the same machine, or onward to the next server;
- a **mail store** (here **Dovecot**) lets people read their mailbox over **IMAP**.

Which server receives mail for a domain is published in DNS as an **MX record** ([DNS zones](#/lesson/transport/internals) work the same way for every record type). Everything is TCP, so the [ports and firewalls](#/lesson/transport/what) you already know decide who can talk to whom, and the [TLS lesson](#/lesson/tls/what) explains the certificates.

### Problems it solves
- **Store and forward.** A message is accepted, written to disk, and retried until it is delivered: a server that is down for an hour only delays mail.
- **One address, many people.** Aliases (sales@ → dana and alice) without extra accounts.
- **Reading from anywhere.** IMAP keeps the mailbox on the server; every device sees the same folders.

### The pieces
- **MX record**: \`corp.lab. IN MX 10 mail01.corp.lab.\`, where mail for corp.lab is delivered.
- **Ports**: 25 (server to server), 587 (users send, after TLS and a login), 993 (users read, IMAP over TLS).
- **Postfix**: main.cf (the settings), master.cf (the services on 25 and 587), the queue, /etc/aliases.
- **Dovecot**: IMAP, and the password check Postfix borrows for logins on 587.
- **The mailbox**: ~/Maildir (one file per message) or /var/mail/USER (mbox, one file per user).

> In the lab, **mail01** (10.0.20.25) is the corp.lab mail server: the MX record points at it. Postfix delivers into ~/Maildir/ and sends outside mail through the provider's relay, **ext01** (203.0.113.80), which also receives mail for example.net. Dovecot serves the Maildirs over IMAP. **ws01** sends with \`swaks\` and reads with \`curl imaps://\`. Simulated: main.cf (with \$name expansion) and master.cf (-o overrides), the SMTP dialogue with real replies (EHLO, STARTTLS, AUTH through Dovecot's socket, relay and recipient checks, DATA), the queue (mailq, postqueue -f, postsuper -d), aliases.db (newaliases), Maildir and mbox delivery, relaying to the relayhost or the MX, deferred mail and bounces, mail.log lines, Dovecot's configuration (!include, sections, doveconf -n), PAM logins, IMAP over TLS and STARTTLS (curl), openssl s_client -starttls smtp|imap. Simplified: no DKIM/SPF/DMARC, spam filters, milters, virtual domains, quotas or POP3; one INBOX per user; Postfix applies configuration on reload only (real smtpd processes also pick up changes when they are recycled).

:::practice
Q: Which DNS record tells other servers where to deliver mail for corp.lab?
A: The **MX record** of corp.lab (here: 10 mail01.corp.lab.).
Q: Which port does a mail client use to send, and which to read over TLS?
A: **587** (submission, with STARTTLS and a login) to send, **993** (IMAPS) to read.
:::

`,

  internals: `
### 1. The SMTP dialogue
SMTP is a conversation of text commands, each answered with a three-digit code: 2xx done, 3xx go on, **4xx try again later**, **5xx refused for good**.
\`\`\`
<-  220 mail01.corp.lab ESMTP Postfix (Debian/GNU)
 -> EHLO ws01.corp.lab
<-  250-mail01.corp.lab ... 250-STARTTLS ... 250-AUTH PLAIN LOGIN
 -> MAIL FROM:<alice@corp.lab>
<-  250 2.1.0 Ok
 -> RCPT TO:<dana@corp.lab>
<-  250 2.1.5 Ok
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> (headers, empty line, body, then a line with a single dot)
<-  250 2.0.0 Ok: queued as 3F2A81C0D4
\`\`\`
The **envelope** (MAIL FROM, RCPT TO) decides delivery; the From: and To: **headers** inside DATA are only what the reader sees. \`swaks\` prints exactly this dialogue, so the line where it stops is the step that failed.

:::practice
Q: A server answers a recipient with a 4xx code. What will a sending server do?
A: Keep the message and **retry later**: 4xx is a temporary failure. 5xx would make it give up and bounce.
Q: Which part decides where a message is delivered: the To: header or RCPT TO?
A: **RCPT TO** (the envelope). The headers are only displayed.
:::

### 2. Who may send what: relaying
A server that forwarded anyone's mail to anywhere would be an **open relay**, abused by spammers within hours. Postfix accepts a recipient only if:
- the domain is its own (**mydestination**: then it is local delivery), or
- the client is trusted (**mynetworks**) or **logged in** (permit_sasl_authenticated).

Everything else gets **454 4.7.1 Relay access denied**. That is why mail clients send through **587**: master.cf turns on TLS, login and \`smtpd_relay_restrictions = permit_sasl_authenticated,reject\` for that service only. Port 25 stays open to the world, but only for mail *to* corp.lab.

:::practice
Q: From ws01, \`swaks --to x@example.org --server mail01\` (port 25, no login) gets 454 Relay access denied. Is mail01 broken?
A: **No.** example.org is not mail01's own domain and ws01 is neither in mynetworks nor logged in: refusing to relay is correct. Send through 587 with a login.
Q: Why is mynetworks = 0.0.0.0/0 dangerous?
A: It trusts **every** address on the Internet to relay: mail01 becomes an **open relay**.
:::

### 3. Logging in: STARTTLS and SMTP AUTH
On 587, the client first sends **STARTTLS** and repeats the handshake inside TLS; only then does Postfix offer **AUTH** (\`smtpd_tls_auth_only = yes\`). Postfix does not check passwords itself: it asks **Dovecot** over the UNIX socket \`/var/spool/postfix/private/auth\` (smtpd_sasl_type = dovecot, smtpd_sasl_path = private/auth). Dovecot creates that socket only if its \`service auth\` has a matching \`unix_listener\`. Two things break this in practice:
- the certificate and key in main.cf do not belong together: Postfix disables TLS and **stops offering STARTTLS** ("cannot get RSA private key ... key values mismatch");
- the socket is missing: smtpd logs "SASL: Connect to private/auth failed" and **exits**, so the client loses the connection right after STARTTLS.

:::practice
Q: swaks on port 587 shows "TLS started", then "Remote host closed connection unexpectedly" after EHLO. Which component should you look at?
A: The **SASL** link to Dovecot: smtpd starts SASL right after TLS, and dies when it cannot connect to private/auth.
Q: Where does Postfix check the password of a user who sends on 587 in this lab?
A: It asks **Dovecot's auth service** through the socket /var/spool/postfix/private/auth; Dovecot checks it with PAM.
:::

### 4. The queue and delivery
After 250 the message is on disk. **qmgr** then hands each recipient to a delivery agent:
- **local** for mydestination addresses: first **aliases** (from /etc/aliases.db, rebuilt with \`newaliases\`), then the account's mailbox: \`home_mailbox = Maildir/\` writes ~/Maildir/new/ (one file per message); without it, mail goes to the mbox file /var/mail/USER;
- **smtp** for other domains: to the **relayhost** if set (\`[203.0.113.80]\`: brackets mean no MX lookup), else to the recipient domain's MX.

Each step is a line in /var/log/mail.log with the **queue ID**:
\`\`\`
postfix/local[812]: 3F2A81C0D4: to=<dana@corp.lab>, orig_to=<sales@corp.lab>, relay=local, ..., status=sent (delivered to maildir)
postfix/smtp[815]: 4B9C02D11E: to=<partner@example.net>, relay=none, ..., status=deferred (Host or domain name not found. ...)
\`\`\`
**deferred** mail stays in the queue (\`mailq\` shows the reason) and is retried for up to 5 days; \`postqueue -f\` retries now. **bounced** mail is returned to the sender.

:::practice
Q: You added "sales: dana, alice" to /etc/aliases. What else must you run before Postfix knows the alias?
A: \`newaliases\`: Postfix reads the compiled /etc/aliases.db, not the text file.
Q: mail.log says status=deferred for a message to example.net. Where is the message now, and how do you retry it after fixing the cause?
A: In the **queue** (mailq lists it with the reason). \`postqueue -f\` retries it now.
:::

### 5. Reading: IMAP and the mailbox
Dovecot does not receive mail; it **reads** the mailbox Postfix wrote. \`mail_location = maildir:~/Maildir\` must match Postfix's \`home_mailbox = Maildir/\`. If they disagree, Postfix reports "delivered" and the user sees nothing new: the classic "lost mail" that is not lost at all.

IMAP logins: on port 993 TLS starts at once; on 143 the client must send STARTTLS first, because \`disable_plaintext_auth = yes\` refuses passwords over an unencrypted connection (the server announces LOGINDISABLED). curl then fails with "(67) Login denied" unless you use imaps:// or --ssl-reqd.

:::practice
Q: mail.log says "status=sent (delivered to mailbox)" for dana, but her IMAP client shows nothing new. Dovecot uses mail_location = maildir:~/Maildir. Where did the mail go?
A: To the **mbox file /var/mail/dana**: "delivered to mailbox" means mbox. Postfix lacks home_mailbox = Maildir/.
Q: Why does \`curl imap://mail01.corp.lab/ -u dana:PW\` fail with Login denied while imaps:// works?
A: Dovecot refuses passwords without TLS (\`disable_plaintext_auth = yes\`, LOGINDISABLED). Use imaps:// (993) or --ssl-reqd (STARTTLS).
:::

### 6. Security
- Never an open relay: keep mynetworks to localhost, relay only for logged-in users.
- Passwords only over TLS (587 with smtpd_tls_security_level = encrypt, IMAP with disable_plaintext_auth).
- Restrict the auth socket to postfix (mode 0660), not the package's 0666.
- On the Internet, publish **SPF**, sign with **DKIM** and set a **DMARC** policy so others can tell your mail from forgeries (not simulated).

:::practice
Q: Which two SMTP settings keep a server from being an open relay?
A: **mynetworks** limited to trusted addresses (here only localhost) and **smtpd_relay_restrictions** that relay only for permit_mynetworks / permit_sasl_authenticated and defer or reject the rest.
Q: Name the three DNS-published mechanisms that help receivers detect forged mail from your domain.
A: **SPF**, **DKIM** and **DMARC**.
:::

`,

  deployment: [
    {
      id: 'debian',
      platform: 'Debian 12 / Ubuntu (Postfix + Dovecot)',
      summary: 'A mail server for corp.lab: receive on 25, submission on 587 with Dovecot SASL, Maildir delivery, IMAPS. Steps marked simulated can be tried in the sandbox (mail01 already runs this setup).',
      prerequisites: ['A DNS A record and an MX record for the domain.', 'A certificate for the server name (here from the corp CA).', 'Firewall: 25 from anywhere, 587/993 from users.'],
      steps: [
        { title: 'Install', command: 'sudo apt install -y postfix dovecot-imapd swaks\n# debconf: "Internet Site", mail name corp.lab', what: 'Postfix with Debian\'s questions; Dovecot\'s IMAP server.', why: '"Local only" would set inet_interfaces = loopback-only.', expected: 'postfix@-.service and dovecot.service active' },
        { title: 'Core settings', command: "postconf -e 'myhostname = mail01.corp.lab' 'mydestination = $myhostname, $mydomain, localhost.$mydomain, localhost' 'home_mailbox = Maildir/' 'relayhost = [203.0.113.80]'", what: 'Who we are, which domains are local, where mail is stored, where outside mail goes.', why: 'mydestination decides local delivery; brackets skip the MX lookup for the relay.', expected: '', simulated: true },
        { title: 'TLS and SASL', command: "postconf -e 'smtpd_tls_cert_file = /etc/ssl/certs/mail01.corp.lab.crt' 'smtpd_tls_key_file = /etc/ssl/private/mail01.corp.lab.key' 'smtpd_sasl_type = dovecot' 'smtpd_sasl_path = private/auth'", what: 'Certificate and key (a matching pair), and Dovecot as the password checker.', why: 'STARTTLS and logins on 587 depend on both.', expected: '', simulated: true },
        { title: 'Enable submission', command: 'submission inet n - y - - smtpd\n  -o syslog_name=postfix/submission\n  -o smtpd_tls_security_level=encrypt\n  -o smtpd_sasl_auth_enable=yes\n  -o smtpd_tls_auth_only=yes\n  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject', what: 'Uncomment in /etc/postfix/master.cf.', why: 'Port 587 for users: TLS required, login required.', expected: '' },
        { title: 'Dovecot: mailbox and auth socket', command: '# 10-mail.conf\nmail_location = maildir:~/Maildir\n# 10-master.conf, inside service auth { }\n  unix_listener /var/spool/postfix/private/auth {\n    mode = 0660\n    user = postfix\n    group = postfix\n  }', what: 'Read the same Maildir; give Postfix (only) the auth socket.', why: 'Mismatched locations "lose" mail; a missing socket breaks 587.', expected: '' },
        { title: 'Apply and test', command: 'postfix check && systemctl reload postfix\nsystemctl restart dovecot\nswaks --to dana@corp.lab --server mail01.corp.lab:587 --tls --auth-user alice --auth-password Mail-alice-26', what: 'Check, apply, send end to end.', why: 'Every layer as a real user.', expected: '<~  250 2.0.0 Ok: queued as …', simulated: true },
      ],
    },
    {
      id: 'rhel',
      platform: 'RHEL 9',
      summary: 'Same Postfix and Dovecot; the package defaults to inet_interfaces = localhost; firewalld services smtp, smtp-submission and imaps; SELinux labels for the spool and mailboxes are set by the packages.',
      prerequisites: ['dnf install postfix dovecot'],
      steps: [
        { title: 'Open and enable', command: "sudo postconf -e 'inet_interfaces = all'\nsudo firewall-cmd --permanent --add-service={smtp,smtp-submission,imaps} && sudo firewall-cmd --reload\nsudo systemctl enable --now postfix dovecot", what: 'Listen on the network, open the ports, start both.', why: 'RHEL\'s main.cf listens on localhost only.', expected: 'success' },
      ],
    },
    {
      id: 'windows',
      platform: 'Exchange Server / Microsoft 365',
      summary: 'Exchange combines transport (SMTP, queues) and mailbox store; receive connectors play the role of master.cf services, accepted domains of mydestination, and relay is limited per connector.',
      prerequisites: ['Active Directory; an MX record pointing to Exchange or to Microsoft 365 (Exchange Online Protection).'],
      steps: [
        { title: 'Check queues and connectors', command: 'Get-Queue\nGet-ReceiveConnector | Format-List Name,Bindings,PermissionGroups\nGet-AcceptedDomain', what: 'The equivalents of mailq, master.cf and mydestination.', why: 'Same model, different tools.', expected: '' },
      ],
    },
  ],

  configIntro: `
Configuration is split between the two servers:
- **Postfix**: /etc/postfix/main.cf (parameters; \`postconf -n\` shows what you changed), /etc/postfix/master.cf (services and their -o overrides), /etc/aliases (+ \`newaliases\`).
- **Dovecot**: /etc/dovecot/dovecot.conf includes conf.d/*.conf; \`doveconf -n\` prints the result.
- **Both**: the certificate and key, and the mailbox location they must agree on.

### Reading main.cf like Postfix does
Values can refer to other parameters: \`mydestination = $myhostname, localhost\` is expanded when used (\`postconf -x mydestination\` shows the result). A parameter missing from main.cf has a built-in default (\`postconf -d NAME\`). master.cf **-o** options override main.cf for one service only, which is how submission requires TLS while port 25 does not.

:::practice
Q: main.cf says smtpd_tls_security_level = may, but port 587 still refuses MAIL FROM before STARTTLS. Why?
A: master.cf overrides it for the submission service: \`-o smtpd_tls_security_level=encrypt\`.
Q: Which command shows the value of mydestination with every $name replaced?
A: \`postconf -x mydestination\`.
:::

`,

  configFiles: [
    { platform: 'Postfix (Debian / Ubuntu / RHEL)', items: [
      { path: '/etc/postfix/main.cf', purpose: 'Parameters: names, domains, networks, relayhost, TLS, SASL, mailbox.' },
      { path: '/etc/postfix/master.cf', purpose: 'Services (smtp 25, submission 587, smtps 465) and per-service -o overrides.' },
      { path: '/etc/aliases (+ aliases.db)', purpose: 'Local aliases; rebuild the .db with newaliases.' },
      { path: '/var/log/mail.log', purpose: 'Every connection, rejection and delivery, by queue ID.' },
    ] },
    { platform: 'Dovecot', items: [
      { path: '/etc/dovecot/dovecot.conf, conf.d/10-auth.conf, 10-mail.conf, 10-master.conf, 10-ssl.conf', purpose: 'Logins, mailbox location, listeners and sockets, TLS.' },
    ] },
    { platform: 'Exchange', items: [
      { path: 'Receive/Send connectors, Accepted domains (Exchange admin center or PowerShell)', purpose: 'The equivalents of master.cf services, relayhost and mydestination.' },
    ] },
  ],

  directives: [
    { name: 'mydestination', compiledDefault: '$myhostname, localhost.$mydomain, localhost', recommended: 'Every domain delivered on this server', explanation: 'Mail for these domains is delivered locally.', security: 'A missing domain makes Postfix treat it as remote (relay rules apply).' },
    { name: 'mynetworks', compiledDefault: '127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 (Debian)', recommended: 'localhost only', explanation: 'Clients trusted to relay without logging in.', security: 'Too wide = open relay.' },
    { name: 'smtpd_relay_restrictions', compiledDefault: 'permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination', recommended: 'the default', explanation: 'Who may send to outside domains.', security: 'Never "permit" alone.' },
    { name: 'inet_interfaces', compiledDefault: 'all', recommended: 'all on a mail server', explanation: 'Addresses Postfix listens on.', security: 'loopback-only for machines that only send their own mail. Needs stop/start.' },
    { name: 'relayhost', compiledDefault: '(empty: MX lookups)', recommended: '[provider relay] when outgoing 25 is filtered', explanation: 'Next hop for all outside mail.', security: 'Use brackets for a host name or address (no MX lookup).' },
    { name: 'home_mailbox / mail_location', compiledDefault: '(empty: /var/mail/USER) / (autodetect)', recommended: 'Maildir/ and maildir:~/Maildir', explanation: 'Where Postfix writes and Dovecot reads.', security: 'Both must match.' },
    { name: 'smtpd_tls_cert_file / smtpd_tls_key_file', compiledDefault: '(none)', recommended: 'A matching pair from a trusted CA', explanation: 'Certificate and key for STARTTLS.', security: 'A mismatch silently disables TLS.' },
    { name: 'disable_plaintext_auth (Dovecot)', compiledDefault: 'yes', recommended: 'yes', explanation: 'No passwords over unencrypted connections.', security: 'Keep it on.' },
  ],

  operateIntro: `
### Following one message
Every line about a message in mail.log carries its **queue ID**: \`grep 3F2A81C0D4 /var/log/mail.log\` shows reception (smtpd), queuing (cleanup, qmgr), delivery (local or smtp, with status=) and removal. Rejected messages never get an ID: look for **NOQUEUE: reject** lines instead.

:::practice
Q: A user says their message was rejected and gives you the error text. Will grep for a queue ID find it?
A: **No.** Rejected messages are refused before they are queued: search for "NOQUEUE: reject" and the address.
Q: Which log line tells you that a message really reached the mailbox?
A: The **local** delivery line with status=sent (delivered to maildir / mailbox) for that queue ID.
:::

### Safe changes
- \`postconf -e\` instead of hand edits, \`postfix check\`, then \`systemctl reload postfix\` (restart for inet_interfaces).
- After /etc/aliases: \`newaliases\`. After Dovecot listeners: \`systemctl restart dovecot\`.
- After any change: send with swaks and read back over IMAP.
- Watch the queue: \`mailq | tail -1\` in monitoring catches a stuck relay before users do.

:::practice
Q: You changed inet_interfaces and ran postfix reload, but ss still shows 127.0.0.1:25. What is missing?
A: A **stop and start** (systemctl restart postfix): master only binds its sockets at start.
Q: After fixing a wrong relayhost, the old messages still sit in mailq. How do you send them now?
A: \`postqueue -f\` (flush the queue).
:::

`,
  troubleshootingIntro: `
### Find the step that fails
1. **Connect.** \`swaks --server mail01.corp.lab:587 --quit-after banner\`. Refused: nothing listens there (\`ss -tlnp\`, inet_interfaces, service down). Timeout: firewall.
2. **TLS.** No STARTTLS in the EHLO reply: Postfix could not load its certificate and key (mail.log says which).
3. **Login.** Connection lost after STARTTLS: the SASL socket to Dovecot. 535: wrong password (\`doveadm auth test USER\`).
4. **Recipient.** 550 User unknown: not an account and not in aliases.db (\`postfix check\`, \`newaliases\`). 454/554 Relay access denied: not logged in or not allowed to relay.
5. **Delivery.** Accepted but not arrived: \`mailq\` (deferred, with the reason) and the delivery line in mail.log.
6. **Reading.** Delivered but invisible: home_mailbox versus mail_location.

:::practice
Q: swaks gets "250 2.0.0 Ok: queued as 7A1B2C3D4E", but the recipient at another company never receives it. What do you check first on your server?
A: \`mailq\` and the mail.log lines for 7A1B2C3D4E: the message is probably **deferred**, with the reason (DNS, connection, remote refusal).
Q: The EHLO reply on 587 has no STARTTLS line. Which two settings and which log lines do you look at?
A: \`smtpd_tls_cert_file\` and \`smtpd_tls_key_file\` (do they match?), and the "cannot get RSA private key ... disabling TLS support" warnings in mail.log.
:::

`,

  errorMap: [
    { message: 'IO::Socket::INET6: connect: Connection refused', layer: 'Service / listening address', meaning: 'Nothing listens on that address and port.', firstCheck: 'ss -tlnp; postconf inet_interfaces; systemctl status postfix' },
    { message: '550 5.1.1 <x@corp.lab>: Recipient address rejected: User unknown in local recipient table', layer: 'Recipient lookup', meaning: 'Not a Unix account and not in aliases.db.', firstCheck: 'postfix check (aliases.db older than /etc/aliases?); getent passwd' },
    { message: '454 4.7.1 <x@example.org>: Relay access denied', layer: 'Relay authorisation', meaning: 'Outside recipient from a client that is not trusted and not logged in.', firstCheck: 'Send on 587 with a login; postconf mynetworks smtpd_relay_restrictions' },
    { message: '530 5.7.0 Must issue a STARTTLS command first', layer: 'TLS policy', meaning: 'This service (587) requires TLS before mail.', firstCheck: 'Use --tls (swaks) / STARTTLS in the client' },
    { message: '*** Host did not advertise STARTTLS', layer: 'TLS', meaning: 'Postfix has no usable certificate/key.', firstCheck: 'mail.log: cannot get RSA private key / key values mismatch' },
    { message: 'warning: SASL: Connect to private/auth failed: No such file or directory', layer: 'SASL (Dovecot auth)', meaning: 'Dovecot does not provide the socket; smtpd exits.', firstCheck: 'ls -l /var/spool/postfix/private/; doveconf -n (service auth)' },
    { message: '535 5.7.8 Error: authentication failed: authentication failure', layer: 'Password', meaning: 'Dovecot rejected the user name or password.', firstCheck: 'doveadm auth test USER' },
    { message: 'status=deferred (Host or domain name not found. Name service error for name=… type=A)', layer: 'Next hop (DNS)', meaning: 'The relayhost or MX name does not resolve.', firstCheck: 'postconf relayhost; dig NAME' },
    { message: 'status=deferred (connect to …:25: Connection timed out)', layer: 'Next hop (network)', meaning: 'The relay or remote server does not answer.', firstCheck: 'Firewall for outgoing 25; is the relay up?' },
    { message: 'status=sent (delivered to mailbox) but nothing in IMAP', layer: 'Mailbox location', meaning: 'mbox in /var/mail while Dovecot reads Maildir.', firstCheck: 'postconf home_mailbox; doveconf mail_location' },
    { message: 'curl: (67) Login denied', layer: 'IMAP login', meaning: 'Wrong password, or no TLS while plaintext logins are disabled.', firstCheck: 'imaps:// or --ssl-reqd; doveadm auth test' },
  ],

  scenarioIds: ['mail-alias-newaliases', 'mail-loopback-only', 'mail-mbox-maildir', 'mail-sasl-socket', 'mail-tls-keypair', 'mail-relayhost'],
  assessmentId: 'email',
  references: [
    { title: 'Postfix Basic Configuration', url: 'https://www.postfix.org/BASIC_CONFIGURATION_README.html' },
    { title: 'Postfix SMTP relay and access control', url: 'https://www.postfix.org/SMTPD_ACCESS_README.html' },
    { title: 'Postfix SASL Howto (Dovecot SASL)', url: 'https://www.postfix.org/SASL_README.html' },
    { title: 'Postfix TLS support', url: 'https://www.postfix.org/TLS_README.html' },
    { title: 'Dovecot documentation: Postfix SASL and mail location', url: 'https://doc.dovecot.org/' },
    { title: 'RFC 5321: Simple Mail Transfer Protocol', url: 'https://www.rfc-editor.org/rfc/rfc5321' },
    { title: 'swaks: Swiss Army Knife for SMTP', url: 'https://jetmore.org/john/code/swaks/' },
  ],
  guide: EMAIL_GUIDE,
};

// --- Primer -------------------------------------------------------------------------

export const EMAIL_PRIMER: Primer = {
  oneLiner: 'Email is **store and forward**: an SMTP server (Postfix) accepts a message, keeps it in a queue and delivers it into a mailbox (or to the next server); an IMAP server (Dovecot) lets the owner read that mailbox.',
  analogy: `
A post office. The **MX record** is the address of the post office that serves a town. Anyone may drop letters *for this town* at its counter (port 25), but to send letters elsewhere you must show your badge (log in on port 587): otherwise anybody could ship junk mail through it (an **open relay**).

Letters wait in the back room (the **queue**) until they are delivered: to a PO box in this office (local delivery), or onto the van to the next office (the relay). A letter for "Sales" goes to the people on the Sales list (**aliases**), but only once the clerk's printed copy of the list is updated (**newaliases**). Owners pick up their mail at a different window (IMAP), and that window must look in the same PO boxes the clerk fills.`,
  ideas: [
    {
      title: 'MX records and ports',
      explain: 'DNS says which server receives mail for a domain; 25 is server to server, 587 is users sending (TLS + login), 993 is users reading.',
      example: '`dig +short MX corp.lab` → 10 mail01.corp.lab. On mail01, `ss -tlnp` shows master on 25 and 587, dovecot on 143 and 993.',
    },
    {
      title: 'The SMTP dialogue',
      explain: 'EHLO, (STARTTLS, AUTH), MAIL FROM, RCPT TO, DATA: each command gets a code, and 4xx means "later", 5xx "never".',
      example: '`swaks --to dana@corp.lab --server mail01.corp.lab` prints every command and reply; "250 2.0.0 Ok: queued as 3F2A81C0D4" means accepted.',
    },
    {
      title: 'Relaying only for trusted or logged-in senders',
      explain: 'Mail for its own domains is accepted from anyone; mail for other domains only from mynetworks or after a login.',
      example: 'On port 25 without login, `swaks --to x@example.org` gets "454 4.7.1 Relay access denied"; on 587 with --auth-user it is queued.',
    },
    {
      title: 'Queue, aliases, mailbox',
      explain: 'Accepted mail is queued; local addresses go through aliases.db to ~/Maildir; outside mail goes to the relay. Problems leave it deferred in the queue.',
      example: '`mailq` lists waiting mail with the reason; `newaliases` rebuilds /etc/aliases.db; mail.log says "delivered to maildir".',
    },
    {
      title: 'Reading where it was written',
      explain: 'Dovecot reads the mailbox Postfix writes; home_mailbox and mail_location must agree. Logins need TLS.',
      example: "`curl -s 'imaps://mail01.corp.lab/INBOX?ALL' -u dana:PW` → * SEARCH 1 2. Without TLS (imap://) Dovecot refuses the password.",
    },
  ],
  walkthrough: {
    title: 'alice writes to sales@corp.lab, and dana reads it',
    steps: [
      { label: 'Find the server', detail: 'alice\'s client sends through mail01.corp.lab:587 (her settings); other companies would look up the MX of corp.lab.' },
      { label: 'Log in over TLS', detail: 'EHLO, STARTTLS, then AUTH PLAIN: Postfix asks Dovecot through private/auth; "235 Authentication successful".' },
      { label: 'Recipient check', detail: 'RCPT TO:<sales@corp.lab>: corp.lab is local, and sales is in aliases.db, so "250 2.1.5 Ok".' },
      { label: 'Queued', detail: 'After DATA: "250 2.0.0 Ok: queued as 3F2A81C0D4". The message is on disk.' },
      { label: 'Delivered', detail: 'local expands sales → dana, alice and writes ~dana/Maildir/new/…: mail.log "orig_to=<sales@corp.lab> … status=sent (delivered to maildir)".' },
      { label: 'Read', detail: 'dana\'s client logs in to Dovecot on 993 and sees the new message in INBOX.' },
    ],
  },
  misconceptions: [
    { myth: '"Relay access denied" means the mail server is broken.', truth: 'It is refusing to forward mail for someone who has not logged in: send on 587 with a login.' },
    { myth: 'Editing /etc/aliases takes effect at once.', truth: 'Postfix reads /etc/aliases.db: run newaliases.' },
    { myth: 'If the sender got "queued", the recipient has the mail.', truth: 'It may be deferred in the queue (mailq), or delivered where the reader does not look.' },
    { myth: 'postfix reload applies every setting.', truth: 'inet_interfaces needs stop/start.' },
  ],
  checks: [
    { q: 'Which DNS record names the server that receives mail for a domain?', a: 'The MX record.' },
    { q: 'Which ports: send as a user, receive from other servers, read over TLS?', a: '587, 25, 993.' },
    { q: 'What do you run after editing /etc/aliases?', a: 'newaliases.' },
    { q: 'Where do you see mail that was accepted but not delivered yet?', a: 'In the queue: mailq (with the reason).' },
  ],
};

// --- Assessment -------------------------------------------------------------------------

export const EMAIL_ASSESSMENT: Assessment = {
  id: 'email',
  title: 'Email knowledge check',
  questions: [
    {
      id: 'email-q-order',
      kind: 'order',
      level: 'beginner',
      learn: ['lesson/email/internals'],
      prompt: 'Order the commands of an authenticated submission on port 587.',
      items: ['EHLO', 'STARTTLS', 'EHLO (again, inside TLS)', 'AUTH PLAIN', 'MAIL FROM', 'RCPT TO', 'DATA'],
      concepts: ['mail.smtp'],
      explanation: 'TLS comes first, then the login, then the envelope and the message.',
    },
    {
      id: 'email-q-ports',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/email/what'],
      prompt: 'A user\'s mail client should send mail through the company server. Which port and settings are correct?',
      options: [
        { text: '587 with STARTTLS and a login', correct: true },
        { text: '25 without a login', misconception: 'Port 25 is for server-to-server mail; without a login the server refuses to relay to outside domains.' },
        { text: '993', misconception: '993 is IMAPS, for reading.' },
        { text: '143', misconception: '143 is IMAP, for reading.' },
      ],
      concepts: ['mail.smtp'],
      explanation: 'Submission (587) requires TLS and authentication; 25 is for MX traffic.',
    },
    {
      id: 'email-q-aliases',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/email/internals'],
      prompt: 'After adding "support: alice" to /etc/aliases, mail to support@corp.lab is rejected with 550 5.1.1 User unknown in local recipient table. What fixes it?',
      options: [
        { text: 'newaliases', correct: true },
        { text: 'systemctl reload postfix', misconception: 'Postfix reads aliases.db on every lookup; the .db file itself is outdated.' },
        { text: 'useradd support', misconception: 'That creates a separate mailbox instead of the alias.' },
        { text: 'Adding corp.lab to mynetworks', misconception: 'mynetworks lists client addresses allowed to relay; it has nothing to do with local recipients.' },
      ],
      concepts: ['mail.smtp'],
      explanation: 'hash:/etc/aliases means Postfix reads the compiled /etc/aliases.db, which newaliases rebuilds.',
    },
    {
      id: 'email-q-relay',
      kind: 'multi',
      level: 'advanced',
      learn: ['lesson/email/internals', 'lesson/email/config'],
      prompt: 'Which settings would turn a Postfix server into an open relay? (choose all that apply)',
      options: [
        { text: 'mynetworks = 0.0.0.0/0', correct: true },
        { text: 'smtpd_relay_restrictions = permit', correct: true },
        { text: '-o smtpd_relay_restrictions=permit_sasl_authenticated,reject on submission', misconception: 'That relays only for logged-in users: the correct setting for 587.' },
        { text: 'relayhost = [203.0.113.80]', misconception: 'relayhost is where this server sends outside mail; it does not decide who may send.' },
      ],
      concepts: ['mail.smtp'],
      explanation: 'Relaying must be limited to trusted networks (localhost) and authenticated users.',
    },
    {
      id: 'email-q-queue',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/email/operate'],
      prompt: 'mailq shows a message "(Host or domain name not found. Name service error for name=smtp-relay.example.net type=A: Host not found)". After correcting relayhost and reloading Postfix, how do you deliver it now?',
      options: [
        { text: 'postqueue -f', correct: true },
        { text: 'postsuper -d ALL', misconception: 'That deletes the messages without delivering them.' },
        { text: 'newaliases', misconception: 'Aliases are unrelated to the next hop.' },
        { text: 'Nothing: deferred mail is lost', misconception: 'Deferred mail stays in the queue and is retried for days.' },
      ],
      concepts: ['mail.smtp', 'dns.resolution'],
      explanation: 'postqueue -f (postfix flush) retries every queued message at once.',
    },
    {
      id: 'email-q-mailbox',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/email/internals', 'lesson/email/troubleshoot'],
      prompt: 'mail.log shows "status=sent (delivered to mailbox)" for dana, but her IMAP client shows nothing new. Dovecot has mail_location = maildir:~/Maildir. What is wrong?',
      options: [
        { text: 'Postfix writes the mbox /var/mail/dana: home_mailbox = Maildir/ is missing', correct: true },
        { text: 'dana\'s password is wrong', misconception: 'She can log in and sees her older mail.' },
        { text: 'The firewall blocks 993', misconception: 'Then she could not connect at all.' },
      ],
      concepts: ['mail.imap'],
      explanation: '"delivered to mailbox" is mbox delivery; Dovecot reads Maildir. The two must agree.',
    },
    {
      id: 'email-q-starttls',
      kind: 'single',
      level: 'advanced',
      learn: ['lesson/email/internals'],
      prompt: 'After a certificate renewal, the EHLO reply on 587 no longer contains STARTTLS and mail.log says "cannot get RSA private key from file …: disabling TLS support". What is the most likely cause?',
      options: [
        { text: 'smtpd_tls_key_file does not match the new smtpd_tls_cert_file', correct: true },
        { text: 'The clients do not trust the CA', misconception: 'Trust is checked by clients after the server presents a certificate; here none is offered.' },
        { text: 'Dovecot is down', misconception: 'Dovecot is only needed for AUTH, which comes after STARTTLS.' },
      ],
      concepts: ['mail.smtp', 'tls.pki'],
      explanation: 'Postfix silently disables TLS when it cannot load a matching certificate and key.',
    },
    {
      id: 'email-q-port-imaps',
      kind: 'text',
      level: 'beginner',
      learn: ['lesson/email/what'],
      prompt: 'Which TCP port does IMAP over TLS (IMAPS) use?',
      accept: ['993'],
      placeholder: 'port',
      concepts: ['mail.imap'],
      explanation: 'IMAPS is 993; plain IMAP with STARTTLS is 143.',
    },
  ],
};
