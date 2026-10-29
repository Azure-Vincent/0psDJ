// Email tickets on mail01 (Postfix + Dovecot). Each breaks one step of the
// path a message takes: the address lookup (aliases.db), the listening
// sockets (inet_interfaces), local delivery versus where Dovecot reads
// (home_mailbox / mail_location), SMTP AUTH through Dovecot's socket, the
// STARTTLS certificate/key pair, and the next hop for outside mail.

import { certPem, keyPem } from '../sim/pki';
import { MAIL_CERT_RENEWED, MAIL_PASSWORDS } from '../lab/mailLab';
import { inMynetworks, loadMainCf, mailState, parseMasterCf, relayDecision } from '../sim/mail';
import { readFile } from '../fs';
import type { World } from '../types';
import { script } from './engine';
import type { Constraint, Goal, Scenario } from './types';

const ALICE = MAIL_PASSWORDS.alice;
const DANA = MAIL_PASSWORDS.dana;

const BRIEFING = [
  'mail01 (10.0.20.25) is the corp.lab mail server: the MX record of corp.lab points at it. Postfix receives mail on port 25 and lets staff send on port 587 (submission: STARTTLS first, then a login). It delivers into ~/Maildir/ and passes outside mail to the provider\'s relay, 203.0.113.80 (contract ISP-7731). Dovecot serves the Maildirs over IMAP (143 with STARTTLS, 993 with TLS) and checks the logins for Postfix through the socket /var/spool/postfix/private/auth.',
  'Logins are the Unix passwords on mail01: alice / ' + ALICE + ', dana / ' + DANA + '.',
  'Test from ws01: swaks --to dana@corp.lab --server mail01.corp.lab (port 25), swaks ... --server mail01.corp.lab:587 --tls --auth-user alice --auth-password ' + ALICE + ' (submission), curl -s imaps://mail01.corp.lab/INBOX?ALL -u dana:' + DANA + ' (IMAP).',
  'Tools on mail01: /var/log/mail.log, mailq, postconf -n, postfix check, doveconf -n, doveadm auth test, ss -tlnp. Fixes must survive a reboot, and mail01 must never become an open relay.',
];

const TERMINALS = [
  { hostId: 'mail01', user: 'root', label: 'mail01 console (root)', banner: 'mail01 console: Postfix and Dovecot. Try: tail -n 20 /var/log/mail.log, mailq, postconf -n, postfix check, doveconf -n, ss -tlnp.' },
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: `ws01 as alice. Try: swaks --to dana@corp.lab --server mail01.corp.lab, or the submission port: swaks --to dana@corp.lab --server mail01.corp.lab:587 --tls --auth-user alice --auth-password ${ALICE}. Read mail: curl -s 'imaps://mail01.corp.lab/INBOX?ALL' -u dana:${DANA}.` },
];

const CANDIDATES = [
  'mail-aliases-not-rebuilt', 'mail-unknown-recipient', 'mail-relay-denied', 'mail-inet-interfaces', 'firewall-drop', 'mail-service-down',
  'mail-mailbox-location', 'mail-maildir-permissions', 'mail-sasl-socket', 'mail-wrong-password', 'mail-tls-keypair', 'tls-untrusted-root', 'mail-relayhost-unresolvable', 'mail-relay-unreachable',
];

const submit = (to: string, subject: string) =>
  `swaks --to ${to} --from alice@corp.lab --server mail01.corp.lab:587 --tls --auth-user alice --auth-password ${ALICE} --header "Subject: ${subject}"`;
/** dana's INBOX holds a message with this subject (IMAP SEARCH over TLS). */
const inDanasInbox = (subject: string) => `curl -s imaps://mail01.corp.lab/INBOX -u dana:${DANA} -X 'SEARCH SUBJECT "${subject}"'`;

const sendAndRead = (description: string, send: string, subject: string): Goal => ({
  kind: 'command', description,
  steps: [{ host: 'ws01', user: 'alice', command: send }, { host: 'ws01', user: 'alice', command: inDanasInbox(subject) }],
  expect: '^\\* SEARCH \\d',
});

/** mail01 relays for nobody it does not know: port 25 needs mynetworks (localhost only), 587 a login. */
function noOpenRelay(): Constraint {
  return {
    id: 'mail-no-open-relay', required: true,
    description: 'mail01 is not an open relay: a client on the Internet cannot send outside mail through it on port 25 or 587 without logging in.',
    check(world) {
      const h = world.hosts.mail01;
      const cf = loadMainCf(h);
      const services = parseMasterCf(readFile(h, '/etc/postfix/master.cf') ?? '').services.filter((s) => s.type === 'inet' && s.command === 'smtpd');
      const outsider = '198.51.100.23';
      const open = services.some((s) => relayDecision(h, cf, s.overrides, outsider, false, 'victim@example.org') === 'permit') || inMynetworks(h, cf, outsider);
      return { id: this.id, ok: !open, required: true, message: open ? 'mail01 would relay mail for anyone (check mynetworks and smtpd_relay_restrictions, also the -o overrides in master.cf): spammers find open relays within hours.' : 'mail01 only relays for localhost and for logged-in users.' };
    },
  };
}

/** Submission keeps requiring TLS and a login. */
function submissionProtected(): Constraint {
  return {
    id: 'mail-submission-protected', required: true,
    description: 'Port 587 still requires STARTTLS (smtpd_tls_security_level=encrypt) and a login before mail is accepted for relay.',
    check(world) {
      const h = world.hosts.mail01;
      const sub = parseMasterCf(readFile(h, '/etc/postfix/master.cf') ?? '').services.find((s) => s.name === 'submission' && s.type === 'inet');
      const ok = !!sub && sub.overrides.smtpd_tls_security_level === 'encrypt' && sub.overrides.smtpd_sasl_auth_enable === 'yes' && /permit_sasl_authenticated[\s,]+reject/.test(sub.overrides.smtpd_relay_restrictions ?? '');
      return { id: this.id, ok, required: true, message: ok ? 'Submission (587) requires TLS and a login.' : 'The submission service in master.cf must keep -o smtpd_tls_security_level=encrypt, -o smtpd_sasl_auth_enable=yes and -o smtpd_relay_restrictions=permit_sasl_authenticated,reject: passwords must not cross the network in clear text, and nobody may relay without logging in.' };
    },
  };
}

/** A few minutes of normal mail. */
function activity(world: World): void {
  world.clock += 20 * 60_000;
  script(world, 'ws01', [submit('dana@corp.lab', 'Standup notes')]);
}

export const MAIL_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'mail-alias-newaliases',
    title: 'Shared mailbox',
    difficulty: 'beginner',
    ticket: 'Sales: "Yesterday IT created our shared address sales@corp.lab (CHG-2410: it should reach Dana and Alice). Customers who write to it get their mail back: Recipient address rejected: User unknown in local recipient table. Mail to dana@corp.lab works."',
    briefing: BRIEFING,
    goals: [sendAndRead('Mail to sales@corp.lab is accepted and arrives in Dana\'s INBOX (she reads it over IMAP).', 'swaks --to sales@corp.lab --from customer@example.net --server mail01.corp.lab --header "Subject: Quote request goal-check"', 'Quote request goal-check')],
    terminals: TERMINALS,
    setup(world) {
      script(world, 'mail01', ["printf '# Shared mailbox for the sales team (CHG-2410)\\nsales:         dana, alice\\n' >> /etc/aliases"]);
      activity(world);
      script(world, 'ws01', ['swaks --to sales@corp.lab --from customer@example.net --server mail01.corp.lab --header "Subject: Quote request"']);
    },
    rootCauses: ['mail-aliases-not-rebuilt'],
    candidates: CANDIDATES,
    feedback: {
      'mail-unknown-recipient': 'sales is in /etc/aliases, spelled right. The question is whether Postfix sees that file at all.',
      'mail-relay-denied': 'corp.lab is mail01\'s own domain (mydestination), so there is no relaying: the reply is "User unknown", not "Relay access denied".',
      'mail-service-down': 'Postfix answers and accepts mail for dana@corp.lab.',
      'firewall-drop': 'The SMTP dialogue gets as far as RCPT TO: the network is fine.',
    },
    hints: [
      'The rejection comes at RCPT TO, with 550 5.1.1 "User unknown in local recipient table". Postfix checks local addresses against the Unix accounts and the alias maps (postconf local_recipient_maps alias_maps).',
      'alias_maps = hash:/etc/aliases: Postfix reads /etc/aliases.db, a compiled copy, not the text file. Compare ls -l --time-style=full-iso /etc/aliases /etc/aliases.db, and run postfix check.',
      'Rebuild the database: newaliases (no reload needed: Postfix opens aliases.db on every lookup). Then send again with swaks.',
    ],
    explanation: {
      rootCause: 'The alias was added to /etc/aliases, but newaliases was never run. Postfix looks aliases up in /etc/aliases.db (hash:/etc/aliases), which still has the old content without sales.',
      manifestation: 'smtpd rejects sales@corp.lab at RCPT TO because the address is neither a Unix account nor a key in aliases.db: 550 5.1.1 User unknown in local recipient table, and the sender gets a bounce.',
      evidence: 'mail.log: "NOQUEUE: reject: RCPT from ...: 550 5.1.1 <sales@corp.lab>: Recipient address rejected: User unknown in local recipient table"; postfix check: "warning: database /etc/aliases.db is older than source file /etc/aliases".',
      prevention: 'After editing /etc/aliases, always run newaliases (the same for every hash: or lmdb: table: postmap after editing). Test a new address with swaks before announcing it.',
    },
    solution: [{ host: 'mail01', commands: ['newaliases'] }],
    constraints: [noOpenRelay(), {
      id: 'mail-sales-alias', required: true,
      description: 'sales@corp.lab stays an alias for dana and alice (no new mailbox account).',
      check(world) {
        const h = world.hosts.mail01;
        const t = mailState(h).aliasDb?.sales ?? [];
        const ok = !h.users.sales && t.includes('dana') && t.includes('alice');
        return { id: this.id, ok, required: true, message: ok ? 'sales is an alias for dana and alice.' : 'sales@corp.lab must stay an alias that reaches both dana and alice (CHG-2410), not a separate account.' };
      },
    }],
    concepts: ['mail.smtp'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'mail-loopback-only',
    title: 'Hardened',
    difficulty: 'intermediate',
    ticket: 'Alice: "Since this morning nobody can send mail: Thunderbird says it cannot connect to mail01.corp.lab on port 587, and a partner says our MX refuses connections. Reading mail works. Last night CHG-2415 \'Postfix hardening\' was applied to mail01."',
    briefing: BRIEFING,
    goals: [sendAndRead('Alice can send from ws01 through the submission port (587) and the message reaches Dana.', submit('dana@corp.lab', 'Budget goal-check'), 'Budget goal-check')],
    terminals: TERMINALS,
    setup(world) {
      script(world, 'mail01', ["postconf -e 'inet_interfaces = loopback-only' 'disable_vrfy_command = yes'", 'systemctl restart postfix']);
      activity(world);
    },
    rootCauses: ['mail-inet-interfaces'],
    candidates: CANDIDATES,
    feedback: {
      'firewall-drop': 'The connection is refused at once (RST), not timed out: something answers, but nothing listens. nft list ruleset still allows 25 and 587.',
      'mail-service-down': 'systemctl status postfix says active, and mailq answers.',
      'mail-sasl-socket': 'The connection fails before any SMTP dialogue, so authentication never starts.',
      'mail-tls-keypair': 'No TLS happens: the TCP connection itself is refused.',
    },
    hints: [
      '"Connection refused" means the TCP SYN reached mail01 and nothing listens on that address and port. On mail01: ss -tlnp | grep master.',
      'Postfix listens on 127.0.0.1 and ::1 only. Which parameter decides the listening addresses? postconf -n | grep inet.',
      'Set inet_interfaces back to all (postconf -e \'inet_interfaces = all\'). A reload is not enough for this parameter: postfix stop; postfix start, or systemctl restart postfix. Check with ss -tlnp.',
    ],
    explanation: {
      rootCause: 'The hardening change set inet_interfaces = loopback-only (the Debian "Local only" profile): Postfix opens its smtp and submission sockets on 127.0.0.1 and ::1, so other machines cannot connect at all.',
      manifestation: 'Every client and every remote server gets "Connection refused" on ports 25 and 587, while Postfix runs normally and IMAP (Dovecot) still works.',
      evidence: 'ss -tlnp on mail01: 127.0.0.1:25 and 127.0.0.1:587 owned by master; postconf inet_interfaces → loopback-only; swaks on ws01: "connect: Connection refused". After postfix reload the sockets stay the same: master only re-binds on stop/start.',
      prevention: 'Review hardening changes against the service\'s purpose; test from a client (swaks) after every change; know which Postfix parameters need a restart (inet_interfaces, inet_protocols).',
    },
    solution: [{ host: 'mail01', commands: ["postconf -e 'inet_interfaces = all'", 'systemctl restart postfix'] }],
    constraints: [noOpenRelay(), submissionProtected()],
    concepts: ['mail.smtp', 'svc.listening'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'mail-mbox-maildir',
    title: 'Delivered, not received',
    difficulty: 'intermediate',
    ticket: 'Dana: "Alice sent me the Q4 numbers at 9:00 and her mail program shows it as sent. I have nothing new since yesterday, the old mails are still there. Did the mail server lose it?" On Monday, CHG-2420 tidied mail01\'s main.cf to match the Debian template.',
    briefing: BRIEFING,
    goals: [
      sendAndRead('New mail for Dana appears in her INBOX over IMAP.', submit('dana@corp.lab', 'Forecast goal-check'), 'Forecast goal-check'),
      { kind: 'command', description: 'Dana\'s earlier mail (the welcome message in ~/Maildir) is still in her INBOX.', steps: [{ host: 'ws01', user: 'alice', command: inDanasInbox('Welcome to the new mail server') }], expect: '^\\* SEARCH \\d' },
    ],
    terminals: TERMINALS,
    setup(world) {
      script(world, 'mail01', ["sed -i 's/^home_mailbox = Maildir\\//#home_mailbox = Maildir\\//' /etc/postfix/main.cf", 'systemctl reload postfix']);
      activity(world);
      script(world, 'ws01', [submit('dana@corp.lab', 'Q4 numbers')]);
    },
    rootCauses: ['mail-mailbox-location'],
    candidates: CANDIDATES,
    feedback: {
      'mail-maildir-permissions': 'Nothing is deferred: mail.log says status=sent for dana. The mail was written, just not where Dovecot looks.',
      'mail-wrong-password': 'Dana logs in fine and sees her older mail.',
      'mail-service-down': 'Both Postfix and Dovecot answer.',
      'mail-aliases-not-rebuilt': 'The mail is accepted and delivered: an alias problem would reject it at RCPT TO.',
    },
    hints: [
      'Follow one message in /var/log/mail.log: the local delivery line ends with status=sent (delivered to ...). Delivered to what?',
      'Postfix writes "delivered to mailbox" (an mbox file, /var/mail/dana) or "delivered to maildir" (~/Maildir/). Dovecot reads from doveconf mail_location. Do they agree? Compare with postconf home_mailbox.',
      'Restore home_mailbox = Maildir/ in main.cf (postconf -e) and reload Postfix. The messages already in /var/mail/dana stay there: tell Dana, or move them into her Maildir.',
    ],
    explanation: {
      rootCause: 'The tidy-up commented out home_mailbox = Maildir/. Without it Postfix\'s local delivery appends to the mbox spool file /var/mail/dana, while Dovecot (mail_location = maildir:~/Maildir) only reads ~/Maildir.',
      manifestation: 'Senders see success and mail.log says status=sent, but nothing new appears in the mail client. Old mail (already in ~/Maildir) is still there, so it looks like the server "loses" new mail.',
      evidence: 'mail.log: "to=<dana@corp.lab>, relay=local, ... status=sent (delivered to mailbox)" instead of "(delivered to maildir)"; /var/mail/dana exists and grows; postconf home_mailbox is empty; doveconf mail_location = maildir:~/Maildir.',
      prevention: 'Postfix (where mail is written) and Dovecot (where mail is read) must agree on the mailbox format and location: document it in both files, and test delivery end to end (send, then read over IMAP) after every change.',
    },
    solution: [{ host: 'mail01', commands: ["postconf -e 'home_mailbox = Maildir/'", 'systemctl reload postfix'] }],
    constraints: [noOpenRelay()],
    concepts: ['mail.imap', 'mail.smtp'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'mail-sasl-socket',
    title: 'Read but not send',
    difficulty: 'advanced',
    ticket: 'Alice: "After this morning\'s Dovecot update (CHG-2431: 10-master.conf replaced with the new package version) I can read mail, but sending fails: Thunderbird says the connection to the outgoing server (SMTP) was lost. Mail from outside still arrives."',
    briefing: BRIEFING,
    goals: [sendAndRead('Alice can log in on port 587 and send; the message reaches Dana.', submit('dana@corp.lab', 'Invoice goal-check'), 'Invoice goal-check')],
    terminals: TERMINALS,
    setup(world) {
      const pkg = (readFile(world.hosts.mail01, '/etc/dovecot/conf.d/10-master.conf') ?? '').replace(
        /  # Postfix smtp-auth \(CHG-2401\)[^\n]*\n  unix_listener \/var\/spool\/postfix\/private\/auth \{\n[\s\S]*?\n  \}\n/,
        '  # Postfix smtp-auth\n  #unix_listener /var/spool/postfix/private/auth {\n  #  mode = 0666\n  #}\n',
      );
      script(world, 'mail01', [`printf '${pkg.replace(/\\/g, '\\\\').replace(/\n/g, '\\n')}' > /etc/dovecot/conf.d/10-master.conf`, 'systemctl restart dovecot']);
      activity(world);
    },
    rootCauses: ['mail-sasl-socket'],
    candidates: CANDIDATES,
    feedback: {
      'mail-wrong-password': 'The password is never checked: the connection drops right after STARTTLS, before AUTH is even offered. doveadm auth test alice works.',
      'mail-tls-keypair': 'STARTTLS works (swaks shows "TLS started"); the server drops the connection after it.',
      'firewall-drop': 'The connection opens and TLS starts: the network is fine.',
      'mail-service-down': 'Postfix and Dovecot are both active.',
    },
    hints: [
      'Run the submission dialogue by hand: swaks --to dana@corp.lab --server mail01.corp.lab:587 --tls --auth-user alice --auth-password ... Where does it stop?',
      'mail.log on mail01: "warning: SASL: Connect to private/auth failed: No such file or directory" then "fatal: no SASL authentication mechanisms". Postfix (smtpd_sasl_type = dovecot, smtpd_sasl_path = private/auth) asks Dovecot through the socket /var/spool/postfix/private/auth. Does it exist (ls -l /var/spool/postfix/private/)?',
      'Dovecot creates that socket only if service auth has the unix_listener for it (doveconf -n | grep -A5 "service auth"). Put it back in /etc/dovecot/conf.d/10-master.conf with mode = 0660, user = postfix, group = postfix (not the package\'s 0666), then systemctl restart dovecot.',
    ],
    explanation: {
      rootCause: 'The packaged 10-master.conf has the Postfix listener commented out. Dovecot no longer creates /var/spool/postfix/private/auth, so Postfix\'s submission service cannot reach the authentication service.',
      manifestation: 'Port 587 accepts the connection and STARTTLS, then smtpd activates SASL, cannot connect to the socket, logs a fatal error and exits: the client sees the connection drop. Port 25 (no AUTH) and IMAP keep working.',
      evidence: 'mail.log: "postfix/submission/smtpd: warning: SASL: Connect to private/auth failed: No such file or directory", "fatal: no SASL authentication mechanisms", "master: warning: process ... smtpd pid ... exit status 1"; the socket is missing; doveconf -n shows no unix_listener under service auth.',
      prevention: 'When a package offers a new configuration file, merge your local changes into it (or keep them in a separate file such as local.conf). Keep auth sockets restricted to the service that needs them (0660 postfix:postfix).',
    },
    solution: [{ host: 'mail01', commands: ["sed -i 's|^  #unix_listener /var/spool/postfix/private/auth {|  unix_listener /var/spool/postfix/private/auth {|; s|^  #  mode = 0666|    mode = 0660\\n    user = postfix\\n    group = postfix|; s|^  #}|  }|' /etc/dovecot/conf.d/10-master.conf", 'systemctl restart dovecot'] }],
    constraints: [noOpenRelay(), submissionProtected(), {
      id: 'mail-auth-socket-private', required: true,
      description: 'Dovecot\'s auth socket for Postfix is not usable by every local user (no mode 0666).',
      check(world) {
        const n = world.hosts.mail01.fs['/var/spool/postfix/private/auth'];
        const ok = !!n && (n.mode & 0o006) === 0;
        return { id: this.id, ok, required: true, message: ok ? 'The auth socket is restricted to postfix.' : 'Restrict the auth socket (mode = 0660, user = postfix, group = postfix): with 0666 any local program could use it to test passwords.' };
      },
    }],
    concepts: ['mail.smtp', 'mail.imap'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'mail-tls-keypair',
    title: 'Renewed',
    difficulty: 'advanced',
    ticket: 'Helpdesk: "Since yesterday\'s certificate renewal on mail01 (CHG-2440) nobody can send: Outlook says the server does not support a secure connection. Reading mail is fine." The change note: new key and certificate installed as /etc/ssl/private/mail01-2027.key and /etc/ssl/certs/mail01-2027.crt, Postfix pointed at the new certificate; Dovecot follows next week.',
    briefing: BRIEFING,
    goals: [
      sendAndRead('Alice can send through port 587 with STARTTLS and a login.', submit('dana@corp.lab', 'Contract goal-check'), 'Contract goal-check'),
      { kind: 'command', description: 'Postfix presents the renewed certificate (valid until November 2027) on port 587.', steps: [{ host: 'ws01', user: 'alice', command: 'openssl s_client -connect mail01.corp.lab:587 -starttls smtp' }], expect: 'NotAfter: Nov 16 08:00:00 2027 GMT' },
    ],
    terminals: TERMINALS,
    setup(world) {
      const t = world.clock;
      const h = world.hosts.mail01;
      // The renewal as the change note describes it: new files in place, Postfix pointed at the new certificate only.
      h.fs['/etc/ssl/certs/mail01-2027.crt'] = { type: 'file', mode: 0o644, owner: 'root', group: 'root', content: certPem(MAIL_CERT_RENEWED.cert) + readFile(h, '/etc/ssl/certs/mail01.corp.lab.crt')!.replace(/^[\s\S]*?-----END CERTIFICATE-----\n/, ''), mtime: t };
      h.fs['/etc/ssl/private/mail01-2027.key'] = { type: 'file', mode: 0o640, owner: 'root', group: 'ssl-cert', content: keyPem(MAIL_CERT_RENEWED.key), mtime: t };
      script(world, 'mail01', ["postconf -e 'smtpd_tls_cert_file = /etc/ssl/certs/mail01-2027.crt'", 'systemctl reload postfix']);
      activity(world);
    },
    rootCauses: ['mail-tls-keypair'],
    candidates: CANDIDATES,
    feedback: {
      'tls-untrusted-root': 'No certificate is presented at all: the server does not even offer STARTTLS, so no client gets to verify anything.',
      'mail-sasl-socket': 'The dialogue stops before STARTTLS, and the logs talk about the private key, not SASL.',
      'mail-wrong-password': 'No login is attempted: the client needs TLS first.',
      'firewall-drop': 'The SMTP dialogue runs (banner, EHLO): the network is fine.',
    },
    hints: [
      'swaks with --tls on port 587: "Host did not advertise STARTTLS". Compare the EHLO answer with the one on port 25.',
      'mail.log: "warning: cannot get RSA private key from file ...: disabling TLS support" and "key values mismatch". Which certificate and which key does Postfix use (postconf smtpd_tls_cert_file smtpd_tls_key_file)?',
      'A certificate and a key belong together when their public keys match: openssl x509 -noout -modulus -in CERT | openssl md5 versus openssl rsa -noout -modulus -in KEY | openssl md5. Point smtpd_tls_key_file at the new key (postconf -e), reload Postfix, and check with openssl s_client -connect mail01.corp.lab:587 -starttls smtp.',
    ],
    explanation: {
      rootCause: 'Postfix was given the renewed certificate (smtpd_tls_cert_file) but still the old private key (smtpd_tls_key_file). The key does not match the certificate, so each smtpd process disables TLS.',
      manifestation: 'Without TLS, Postfix stops advertising STARTTLS. Port 587 requires TLS (smtpd_tls_security_level=encrypt), so clients cannot log in or send. Port 25 still accepts mail without TLS, and Dovecot (old pair, still consistent) keeps working.',
      evidence: 'mail.log: "warning: cannot get RSA private key from file \\"/etc/ssl/private/mail01.corp.lab.key\\": disabling TLS support" and "TLS library problem: ... key values mismatch"; swaks: no 250-STARTTLS in the EHLO reply; the moduli of the new certificate and the configured key differ.',
      prevention: 'Change certificate and key together (or use smtpd_tls_chain_files with both in one place), check the pair before reloading, and test STARTTLS afterwards with openssl s_client -starttls smtp.',
    },
    solution: [{ host: 'mail01', commands: ["postconf -e 'smtpd_tls_key_file = /etc/ssl/private/mail01-2027.key'", 'systemctl reload postfix'] }],
    constraints: [noOpenRelay(), submissionProtected()],
    concepts: ['mail.smtp', 'tls.pki'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'mail-relayhost',
    title: 'Stuck in the queue',
    difficulty: 'intermediate',
    ticket: 'Purchasing: "Our order to the partner (partner@example.net, sent yesterday at 16:10) never arrived, and neither did anything since. Internal mail works and nothing bounced." The provider says its relay is up. Yesterday CHG-2450 changed mail01 to use the relay\'s name from the provider\'s new onboarding letter instead of its address.',
    briefing: [...BRIEFING, 'ext01 (203.0.113.80) plays the provider\'s relay and the example.net mail server: on its console, mail for partner@example.net lands in /var/mail/partner.'],
    goals: [
      { kind: 'command', description: 'The order sent yesterday (Subject: Order 4471) reaches partner@example.net.', steps: [{ host: 'ext01', user: 'root', command: 'cat /var/mail/partner' }], expect: 'Subject: Order 4471' },
      { kind: 'command', description: 'Nothing is left waiting in mail01\'s queue.', steps: [{ host: 'mail01', user: 'root', command: 'mailq' }], expect: '^Mail queue is empty$' },
    ],
    terminals: [...TERMINALS, { hostId: 'ext01', user: 'root', label: 'ext01 console (root)', banner: 'ext01: the provider\'s relay and the example.net mail server. Try: cat /var/mail/partner, journalctl -n 20.' }],
    setup(world) {
      script(world, 'mail01', ["postconf -e 'relayhost = [smtp-relay.example.net]'", 'systemctl reload postfix']);
      world.clock += 60 * 60_000;
      script(world, 'ws01', [submit('partner@example.net', 'Order 4471')]);
      activity(world);
    },
    rootCauses: ['mail-relayhost-unresolvable'],
    candidates: CANDIDATES,
    feedback: {
      'mail-relay-denied': 'mail01 accepted the message (250 ... queued as): the problem is after the queue, on the way out.',
      'mail-relay-unreachable': 'Postfix never tries to connect: it cannot even find the relay\'s address (look at the reason in mailq).',
      'mail-service-down': 'Postfix runs and accepted the message; it waits in the deferred queue.',
      'firewall-drop': 'Nothing was sent to the network yet: the name of the next hop does not resolve.',
    },
    hints: [
      'Nothing bounced and nothing arrived: look in the queue. mailq on mail01 shows each waiting message with the reason of its last attempt.',
      '"Host or domain name not found. Name service error for name=smtp-relay.example.net type=A". Can mail01 resolve that name (dig smtp-relay.example.net)? Which DNS does it use, and is example.net in it? Note: Postfix\'s SMTP client asks DNS directly and ignores /etc/hosts.',
      'Use the documented relay address (contract ISP-7731): postconf -e \'relayhost = [203.0.113.80]\', reload Postfix, then postqueue -f to retry the queue now instead of waiting for the next retry.',
    ],
    explanation: {
      rootCause: 'relayhost was changed to [smtp-relay.example.net], a name that the corp.lab DNS server cannot resolve (ns1 only knows corp.lab). Every outside message waits in the deferred queue.',
      manifestation: 'Internal mail is delivered locally and does not use the relay, so only outside mail stops. Nothing bounces: a DNS failure is temporary for Postfix, which keeps retrying for days (maximal_queue_lifetime = 5d) before it gives up.',
      evidence: 'mailq: the message with "(Host or domain name not found. Name service error for name=smtp-relay.example.net type=A: Host not found)"; mail.log: "status=deferred (Host or domain name not found ...)"; dig smtp-relay.example.net on mail01: NXDOMAIN or no answer.',
      prevention: 'Check that a next hop resolves (and connects: swaks --server NAME --quit-after rcpt) before switching to it; monitor the queue size (mailq | tail -1) and alert on deferred mail.',
    },
    solution: [{ host: 'mail01', commands: ["postconf -e 'relayhost = [203.0.113.80]'", 'systemctl reload postfix', 'postqueue -f'] }],
    constraints: [noOpenRelay()],
    concepts: ['mail.smtp', 'dns.resolution'],
  },
];
