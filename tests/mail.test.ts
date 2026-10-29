import { describe, expect, it } from 'vitest';
import { MAIL_PASSWORDS } from '../src/engine/lab/mailLab';
import { buildSshLab } from '../src/engine/lab/sshLab';
import { findScenario } from '../src/engine/scenarios';
import { rebootAll, verifyScenario } from '../src/engine/scenarios/engine';
import { expandParam, parseAliases, parseMainCf, parseMasterCf, relayDecision } from '../src/engine/sim/mail';
import { Lab } from './helpers';

const lab = () => new Lab(buildSshLab());
const A = MAIL_PASSWORDS.alice;
const D = MAIL_PASSWORDS.dana;
const submit = (to: string, extra = '') => `swaks --to ${to} --server mail01.corp.lab:587 --tls --auth-user alice --auth-password ${A} ${extra}`;

describe('Postfix configuration', () => {
  it('main.cf: continuation lines, $name expansion, master.cf -o overrides and relay decisions', () => {
    const lab0 = buildSshLab();
    const h = lab0.hosts.mail01;
    const cf = parseMainCf('myhostname = mx.corp.lab\nmydestination = $myhostname,\n   localhost\n# comment\nmynetworks = 127.0.0.0/8 10.0.10.0/24\n');
    expect(cf.params.mydestination).toBe('$myhostname, localhost');
    expect(expandParam(h, cf, '${myhostname} ESMTP $mail_name')).toBe('mx.corp.lab ESMTP Postfix');
    const mc = parseMasterCf('smtp inet n - y - - smtpd\nsubmission inet n - y - - smtpd\n  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject\n');
    expect(mc.services[1].overrides.smtpd_relay_restrictions).toBe('permit_sasl_authenticated,reject');
    expect(relayDecision(h, cf, {}, '10.0.10.25', false, 'x@example.org')).toBe('permit');
    expect(relayDecision(h, cf, {}, '10.0.30.25', false, 'x@example.org')).toBe('defer');
    expect(relayDecision(h, cf, {}, '10.0.30.25', false, 'x@mx.corp.lab')).toBe('permit');
    expect(relayDecision(h, cf, mc.services[1].overrides, '10.0.10.25', false, 'x@example.org')).toBe('reject');
    expect(relayDecision(h, cf, mc.services[1].overrides, '10.0.30.25', true, 'x@example.org')).toBe('permit');
    expect(parseAliases('root: alice\nteam: a,\n  b\nbroken line\n')).toEqual({ db: { root: ['alice'], team: ['a', 'b'] }, warnings: ['postalias: warning: /etc/aliases, line 4: need name:value pair'] });
  });

  it('postconf -n/-e/-x/-d, postfix check and a fatal configuration error at start', () => {
    const l = lab();
    expect(l.run('mail01', 'root', 'postconf -x mydestination').output).toBe('mydestination = mail01.corp.lab, corp.lab, localhost.corp.lab, localhost');
    expect(l.run('mail01', 'root', 'postconf -d relayhost smtpd_sasl_type').output).toBe('relayhost = \nsmtpd_sasl_type = cyrus');
    expect(l.run('mail01', 'alice', "postconf -e 'relayhost ='").output).toMatch(/Permission denied/);
    l.run('mail01', 'root', "postconf -e 'message_size_limit = 10M' 'smtpd_tls_cert = /x'");
    expect(l.run('mail01', 'root', 'postconf -n').output).toMatch(/^\/usr\/sbin\/postconf: warning: \/etc\/postfix\/main\.cf: unused parameter: smtpd_tls_cert=\/x$/m);
    expect(l.run('mail01', 'root', 'postfix check').output).toMatch(/fatal: bad numerical configuration: message_size_limit = 10M/);
    const r = l.run('mail01', 'root', 'systemctl restart postfix');
    expect(r.code).not.toBe(0);
    expect(l.run('mail01', 'root', 'journalctl -u postfix -n 5').output).toMatch(/postfix\/postfix-script\[\d+\]: fatal: bad numerical configuration/);
  });
});

describe('SMTP dialogue and delivery', () => {
  it('port 25 accepts local mail without login, refuses relaying, and rejects unknown users', () => {
    const l = lab();
    const ok = l.run('ws01', 'alice', 'swaks --to dana@corp.lab --server mail01.corp.lab');
    expect(ok.code).toBe(0);
    expect(ok.output).toMatch(/^<- {2}250 2\.0\.0 Ok: queued as [0-9A-F]{10}$/m);
    expect(l.run('ws01', 'alice', 'swaks --to x@example.org --server mail01.corp.lab').output).toMatch(/^<\*\* 454 4\.7\.1 <x@example\.org>: Relay access denied$/m);
    expect(l.run('ws01', 'alice', 'swaks --to ghost@corp.lab --server mail01.corp.lab').code).toBe(24);
    const log = l.run('mail01', 'root', 'cat /var/log/mail.log').output;
    expect(log).toMatch(/postfix\/local\[\d+\]: [0-9A-F]{10}: to=<dana@corp\.lab>, relay=local, delay=[\d.]+, delays=[\d./]+, dsn=2\.0\.0, status=sent \(delivered to maildir\)/);
    expect(log).toMatch(/NOQUEUE: reject: RCPT from ws01\.corp\.lab\[10\.0\.10\.25\]: 550 5\.1\.1 <ghost@corp\.lab>: Recipient address rejected: User unknown in local recipient table; from=<alice@ws01\.corp\.lab> to=<ghost@corp\.lab> proto=ESMTP helo=<ws01\.corp\.lab>/);
  });

  it('the MX record finds the server when swaks gets no --server', () => {
    const l = lab();
    expect(l.run('ws01', 'alice', 'dig +short MX corp.lab').output).toBe('10 mail01.corp.lab.');
    expect(l.run('ws01', 'alice', 'swaks --to dana@corp.lab').output).toMatch(/^=== Trying mail01\.corp\.lab:25\.\.\.$/m);
  });

  it('submission needs STARTTLS, then a login; wrong passwords fail with 535', () => {
    const l = lab();
    expect(l.run('ws01', 'alice', 'swaks --to dana@corp.lab --server mail01.corp.lab:587').output).toMatch(/<\*\* 530 5\.7\.0 Must issue a STARTTLS command first/);
    const noAuth = l.run('ws01', 'alice', 'swaks --to x@example.org --server mail01.corp.lab:587 --tls');
    expect(noAuth.output).toMatch(/<~\* 554 5\.7\.1 <x@example\.org>: Relay access denied/);
    const bad = l.run('ws01', 'alice', 'swaks --to x@example.org --server mail01.corp.lab:587 --tls -au alice -ap nope');
    expect(bad.code).toBe(28);
    expect(bad.output).toMatch(/<~\* 535 5\.7\.8 Error: authentication failed: authentication failure\n\*\*\* No authentication type succeeded/);
    const good = l.run('ws01', 'alice', submit('partner@example.net'));
    expect(good.code).toBe(0);
    expect(good.output).toMatch(/=== TLS started with cipher TLSv1\.3:TLS_AES_256_GCM_SHA384:256\n=== TLS no local certificate set\n=== TLS peer DN="\/CN=mail01\.corp\.lab"\n ~> EHLO ws01\.corp\.lab/);
    expect(good.output).toMatch(/<~ {2}250-AUTH PLAIN LOGIN/);
    // The relay (ext01) received it.
    expect(l.run('ext01', 'root', 'cat /var/mail/partner').output).toMatch(/^From alice@ws01\.corp\.lab {2}Mon Oct 19 \d\d:\d\d:\d\d 2026\n[\s\S]*by mail01\.corp\.lab \(Postfix\) with ESMTPSA id [0-9A-F]{10}/);
  });

  it('a dead relay defers mail; mailq shows why; postqueue -f retries; postsuper -d deletes', () => {
    const l = lab();
    l.run('ext01', 'root', 'systemctl stop postfix');
    l.run('ws01', 'alice', submit('partner@example.net'));
    const q = l.run('mail01', 'root', 'mailq').output;
    expect(q).toMatch(/^-Queue ID- {2}--Size-- ----Arrival Time---- -Sender\/Recipient-------\n[0-9A-F]{10} +\d+ Mon Oct 19 \d\d:\d\d:\d\d {2}alice@ws01\.corp\.lab\n\(connect to 203\.0\.113\.80\[203\.0\.113\.80\]:25: Connection refused\)\n {41}partner@example\.net\n\n-- 1 Kbytes in 1 Request\.$/);
    l.run('ext01', 'root', 'systemctl start postfix');
    l.run('mail01', 'root', 'postqueue -f');
    expect(l.run('mail01', 'root', 'mailq').output).toBe('Mail queue is empty');
    l.run('ext01', 'root', 'systemctl stop postfix');
    l.run('ws01', 'alice', submit('partner@example.net'));
    const id = /^([0-9A-F]{10})/m.exec(l.run('mail01', 'root', 'mailq').output.split('\n')[1])![1];
    expect(l.run('mail01', 'alice', `postsuper -d ${id}`).output).toBe('postsuper: fatal: use of this command is reserved for the superuser');
    expect(l.run('mail01', 'root', `postsuper -d ${id}`).output).toBe(`postsuper: ${id}: removed\npostsuper: Deleted: 1 message`);
  });

  it('the queue survives a reboot; aliases expand to several mailboxes', () => {
    const l = lab();
    l.run('ext01', 'root', 'systemctl stop postfix');
    l.run('ws01', 'alice', submit('partner@example.net'));
    l.world = rebootAll(l.world);
    expect(l.run('mail01', 'root', 'mailq').output).toMatch(/1 Request\./);
    l.run('mail01', 'root', "echo 'team: alice, dana' >> /etc/aliases && newaliases");
    l.run('ws01', 'alice', 'swaks --to team@corp.lab --server mail01.corp.lab');
    const log = l.run('mail01', 'root', 'tail -n 6 /var/log/mail.log').output;
    expect(log).toMatch(/to=<alice@corp\.lab>, orig_to=<team@corp\.lab>, relay=local/);
    expect(log).toMatch(/to=<dana@corp\.lab>, orig_to=<team@corp\.lab>, relay=local/);
  });

  it('a Maildir the user cannot write defers delivery', () => {
    const l = lab();
    l.run('mail01', 'root', 'chown root:root /home/dana/Maildir/tmp /home/dana/Maildir/new');
    l.run('ws01', 'alice', 'swaks --to dana@corp.lab --server mail01.corp.lab');
    expect(l.run('mail01', 'root', 'mailq').output).toMatch(/\(maildir delivery failed: create maildir file \/home\/dana\/Maildir\/tmp\/[^:]+: Permission denied\)/);
  });
});

describe('Dovecot and IMAP', () => {
  it('reads mail over imaps; plain IMAP refuses logins without TLS; STARTTLS fixes it', () => {
    const l = lab();
    expect(l.run('ws01', 'alice', `curl -s imaps://mail01.corp.lab/ -u dana:${D}`).output).toBe('* LIST (\\HasNoChildren) "." INBOX');
    expect(l.run('ws01', 'alice', `curl -s 'imaps://mail01.corp.lab/INBOX?ALL' -u dana:${D}`).output).toBe('* SEARCH 1');
    expect(l.run('ws01', 'alice', `curl -s 'imaps://mail01.corp.lab/INBOX;UID=1' -u dana:${D}`).output).toMatch(/^Return-Path: <alice@corp\.lab>\n[\s\S]*Subject: Welcome to the new mail server/);
    const plain = l.run('ws01', 'alice', `curl imap://mail01.corp.lab/ -u dana:${D}`);
    expect([plain.code, plain.output]).toEqual([67, 'curl: (67) Login denied']);
    expect(l.run('ws01', 'alice', `curl -s --ssl-reqd imap://mail01.corp.lab/INBOX -u dana:${D} -X 'STATUS INBOX (MESSAGES UNSEEN)'`).output).toBe('* STATUS INBOX (MESSAGES 1 UNSEEN 1)');
    const log = l.run('mail01', 'root', 'cat /var/log/mail.log').output;
    expect(log).toMatch(/dovecot: imap-login: Login: user=<dana>, method=PLAIN, rip=10\.0\.10\.25, lip=10\.0\.20\.25, mpid=\d+, TLS, session=<[\w+/]{16}>/);
    expect(log).toMatch(/dovecot: imap-login: Disconnected: Aborted login by logging out \(no auth attempts in \d+ secs\): user=<>, rip=10\.0\.10\.25, lip=10\.0\.20\.25, session=<[\w+/]{16}>/);
  });

  it('the certificate is verified: an unknown CA fails with (60) unless -k', () => {
    const l = lab();
    expect(l.run('ws01', 'alice', `curl -s --cacert /etc/ssl/certs/ssl-cert-snakeoil.pem imaps://mail01.corp.lab/ -u dana:${D}`).code).toBe(77);
    const l2 = lab();
    l2.run('ws01', 'root', 'rm /usr/local/share/ca-certificates/corp-lab-root-ca.crt && update-ca-certificates --fresh');
    const r = l2.run('ws01', 'alice', `curl -s imaps://mail01.corp.lab/ -u dana:${D}`);
    expect(r.code).toBe(60);
    expect(l2.run('ws01', 'alice', `curl -sk imaps://mail01.corp.lab/ -u dana:${D}`).code).toBe(0);
  });

  it('doveconf -n, doveadm auth test, and a configuration error that stops Dovecot', () => {
    const l = lab();
    const n = l.run('mail01', 'root', 'doveconf -n').output;
    expect(n).toMatch(/^# 2\.3\.19\.1 \(9b53102964\): \/etc\/dovecot\/dovecot\.conf$/m);
    expect(n).toMatch(/^service auth \{\n {2}unix_listener \/var\/spool\/postfix\/private\/auth \{\n {4}group = postfix\n {4}mode = 0660\n {4}user = postfix\n {2}\}\n\}$/m);
    expect(n).toMatch(/^ssl_key = # hidden, use -P to show it$/m);
    expect(l.run('mail01', 'root', `doveadm auth test dana ${D}`).output).toBe('passdb: dana auth succeeded\nextra fields:\n  user=dana');
    expect(l.run('mail01', 'root', 'doveadm auth test dana nope').code).toBe(77);
    expect(l.run('mail01', 'root', 'ls -l /var/spool/postfix/private/').output).toMatch(/^srw-rw---- 1 postfix postfix +0 .* auth$/m);
    l.run('mail01', 'root', "echo 'ssl_cert_file = /x' >> /etc/dovecot/conf.d/10-ssl.conf");
    expect(l.run('mail01', 'root', 'systemctl restart dovecot').code).not.toBe(0);
    expect(l.run('mail01', 'root', 'journalctl -u dovecot -n 5').output).toMatch(/doveconf: Fatal: Error in configuration file \/etc\/dovecot\/conf\.d\/10-ssl\.conf line \d+: Unknown setting: ssl_cert_file/);
    // Stopping Dovecot removes its sockets: submission then dies after STARTTLS.
    expect(l.run('mail01', 'root', 'ls /var/spool/postfix/private/').output).toBe('');
    expect(l.run('ws01', 'alice', submit('dana@corp.lab')).output).toMatch(/ ~> EHLO ws01\.corp\.lab\n\*\*\* Remote host closed connection unexpectedly\./);
  });

  it('openssl s_client speaks STARTTLS for smtp and imap, and TLS on 993', () => {
    const l = lab();
    expect(l.run('ws01', 'alice', 'openssl s_client -connect mail01.corp.lab:143 -starttls imap').output).toMatch(/Verify return code: 0 \(ok\)/);
    expect(l.run('ws01', 'alice', 'openssl s_client -connect mail01.corp.lab:993').output).toMatch(/subject=CN = mail01\.corp\.lab/);
    expect(l.run('ws01', 'alice', 'openssl s_client -connect mail01.corp.lab:25').output).toMatch(/wrong version number/);
    l.run('mail01', 'root', "postconf -e 'smtpd_tls_security_level ='; postfix reload");
    expect(l.run('ws01', 'alice', 'openssl s_client -connect mail01.corp.lab:25 -starttls smtp').output).toMatch(/^Didn't find STARTTLS in server response, trying anyway\.\.\.$/m);
  });
});

describe('Email tickets: wrong fixes are rejected', () => {
  const broken = (id: string) => {
    const s = findScenario(id)!;
    const world = buildSshLab();
    s.setup(world);
    return { s, l: new Lab(world) };
  };

  it('a "sales" account instead of the alias is rejected', () => {
    const { s, l } = broken('mail-alias-newaliases');
    l.run('mail01', 'root', 'useradd -m sales');
    expect(verifyScenario(l.world, s).passed).toBe(false);
  });

  it('postfix reload does not apply inet_interfaces', () => {
    const { s, l } = broken('mail-loopback-only');
    l.run('mail01', 'root', "postconf -e 'inet_interfaces = all'; postfix reload");
    expect(verifyScenario(l.world, s).now[0].ok).toBe(false);
  });

  it('an open relay (mynetworks 0.0.0.0/0) is rejected', () => {
    const { s, l } = broken('mail-loopback-only');
    l.run('mail01', 'root', "postconf -e 'inet_interfaces = all' 'mynetworks = 0.0.0.0/0'; systemctl restart postfix");
    const v = verifyScenario(l.world, s);
    expect(v.now[0].ok).toBe(true);
    expect(v.constraints.find((c) => c.id === 'mail-no-open-relay')?.ok).toBe(false);
  });

  it('pointing Dovecot at the mbox hides the older Maildir mail', () => {
    const { s, l } = broken('mail-mbox-maildir');
    l.run('mail01', 'root', "sed -i 's|^mail_location = maildir:~/Maildir|mail_location = mbox:~/mail:INBOX=/var/mail/%u|' /etc/dovecot/conf.d/10-mail.conf; systemctl restart dovecot");
    expect(verifyScenario(l.world, s).now.map((g) => g.ok)).toEqual([true, false]);
  });

  it('the package\'s 0666 auth socket is rejected; turning SMTP AUTH off is rejected', () => {
    const { s, l } = broken('mail-sasl-socket');
    l.run('mail01', 'root', "sed -i 's|^  #unix_listener /var/spool/postfix/private/auth {|  unix_listener /var/spool/postfix/private/auth {|; s|^  #  mode = 0666|    mode = 0666|; s|^  #}|  }|' /etc/dovecot/conf.d/10-master.conf; systemctl restart dovecot");
    const v = verifyScenario(l.world, s);
    expect(v.now[0].ok).toBe(true);
    expect(v.constraints.find((c) => c.id === 'mail-auth-socket-private')?.ok).toBe(false);
    const b = broken('mail-sasl-socket');
    b.l.run('mail01', 'root', "sed -i 's/-o smtpd_sasl_auth_enable=yes/-o smtpd_sasl_auth_enable=no/' /etc/postfix/master.cf; postfix reload");
    expect(verifyScenario(b.l.world, b.s).passed).toBe(false);
  });

  it('going back to the old certificate is rejected; dropping TLS on 587 is rejected', () => {
    const { s, l } = broken('mail-tls-keypair');
    l.run('mail01', 'root', "postconf -e 'smtpd_tls_cert_file = /etc/ssl/certs/mail01.corp.lab.crt'; postfix reload");
    expect(verifyScenario(l.world, s).now.map((g) => g.ok)).toEqual([true, false]);
    const b = broken('mail-tls-keypair');
    b.l.run('mail01', 'root', "sed -i 's/-o smtpd_tls_security_level=encrypt/-o smtpd_tls_security_level=may/; s/-o smtpd_tls_auth_only=yes/-o smtpd_tls_auth_only=no/' /etc/postfix/master.cf; postfix reload");
    expect(verifyScenario(b.l.world, b.s).passed).toBe(false);
  });

  it('/etc/hosts does not help Postfix find the relay; deleting the queued order is rejected', () => {
    const { s, l } = broken('mail-relayhost');
    l.run('mail01', 'root', "echo '203.0.113.80 smtp-relay.example.net' >> /etc/hosts; postqueue -f");
    expect(l.run('mail01', 'root', 'mailq').output).toMatch(/Name service error for name=smtp-relay\.example\.net type=A/);
    l.run('mail01', 'root', 'postsuper -d ALL');
    expect(verifyScenario(l.world, s).now.map((g) => g.ok)).toEqual([false, true]);
  });
});
