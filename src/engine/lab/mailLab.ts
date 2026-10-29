// Mail server: mail01 (10.0.20.25, Debian 12, switch port swp15) runs Postfix
// and Dovecot for corp.lab. Postfix receives mail for corp.lab on port 25
// (the MX record points at it), lets staff send through port 587 (STARTTLS,
// then a login checked by Dovecot's auth service), delivers into ~/Maildir/
// and passes outside mail to the provider's relay on ext01. Dovecot serves
// the Maildirs over IMAP (143 with STARTTLS, 993 with TLS). ext01 runs a
// small Postfix of its own that accepts mail for example.net.

import { mkdir, writeFile } from '../fs';
import { CORP_ISSUING, issueServerCert, keyPem } from '../sim/pki';
import { newaliases, smtpConversation } from '../sim/mail';
import { tcpConnect } from '../sim/tcp';
import type { Host, World } from '../types';
import { addUser, createHost, staticInterfaces } from './builder';
import { TIMESYNCD_CONF } from './krbLab';
import { installRsyslog } from './logLab';
import { fullchain, trustCorpRoot } from './pkiLab';
import { DEBIAN_SSHD_CONFIG, installHostKeys } from './sshLab';

export const MAIL01_IP = '10.0.20.25';
/** Unix passwords on mail01: they are also the IMAP and SMTP (submission) passwords. */
export const MAIL_PASSWORDS: Record<string, string> = { alice: 'Mail-alice-26', dana: 'Mail-dana-26' };

/** mail01's certificate (from the corp issuing CA), and the renewal a ticket installs. */
export const MAIL_CERT = issueServerCert(CORP_ISSUING, ['mail01.corp.lab', 'mail.corp.lab'], 'mail01-2026', '2026-07-01T08:00:00Z', 397);
export const MAIL_CERT_RENEWED = issueServerCert(CORP_ISSUING, ['mail01.corp.lab', 'mail.corp.lab'], 'mail01-2027', '2026-10-15T08:00:00Z', 397);
export const MAIL_CERT_PATH = '/etc/ssl/certs/mail01.corp.lab.crt';
export const MAIL_KEY_PATH = '/etc/ssl/private/mail01.corp.lab.key';

export const MAIL01_MAIN_CF = `# See /usr/share/postfix/main.cf.dist for a commented, more complete version

# mail01: mail server for corp.lab (CHG-2401). Postfix receives mail for
# corp.lab on port 25, lets staff send through port 587 (STARTTLS, then a
# login checked by Dovecot), delivers to ~/Maildir/ (Dovecot serves it over
# IMAP) and hands outside mail to the provider's relay.
# After a change: postfix check, then systemctl reload postfix.

smtpd_banner = $myhostname ESMTP $mail_name (Debian/GNU)
biff = no

# appending .domain is the MUA's job.
append_dot_mydomain = no

readme_directory = no

# See http://www.postfix.org/COMPATIBILITY_README.html -- default to 3.6 on
# fresh installs.
compatibility_level = 3.6

# TLS parameters
smtpd_tls_cert_file = ${MAIL_CERT_PATH}
smtpd_tls_key_file = ${MAIL_KEY_PATH}
smtpd_tls_security_level = may

smtp_tls_CApath = /etc/ssl/certs
smtp_tls_security_level = may
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache

smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
myhostname = mail01.corp.lab
mydomain = corp.lab
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = $mydomain
mydestination = $myhostname, $mydomain, localhost.$mydomain, localhost
# Outside mail goes through the provider's relay (contract ISP-7731)
relayhost = [203.0.113.80]
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all

# Delivery into ~/Maildir/, where Dovecot reads it (mail_location = maildir:~/Maildir)
home_mailbox = Maildir/

# SMTP AUTH on port 587: Postfix asks Dovecot's auth service (socket private/auth)
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
`;

export const MASTER_CF = `#
# Postfix master process configuration file.  For details on the format
# of the file, see the master(5) manual page (command: "man 5 master" or
# on-line: http://www.postfix.org/master.5.html).
#
# Do not forget to execute "postfix reload" after editing this file.
#
# ==========================================================================
# service type  private unpriv  chroot  wakeup  maxproc command + args
#               (yes)   (yes)   (no)    (never) (100)
# ==========================================================================
smtp      inet  n       -       y       -       -       smtpd
#smtp      inet  n       -       y       -       1       postscreen
#smtpd     pass  -       -       y       -       -       smtpd
#dnsblog   unix  -       -       y       -       0       dnsblog
#tlsproxy  unix  -       -       y       -       0       tlsproxy
# Choose one: enable submission for loopback clients only, or for any client.
#127.0.0.1:submission inet n -   y       -       -       smtpd
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
#smtps     inet  n       -       y       -       -       smtpd
#  -o syslog_name=postfix/smtps
#  -o smtpd_tls_wrapper_mode=yes
#  -o smtpd_sasl_auth_enable=yes
#  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
#628       inet  n       -       y       -       -       qmqpd
pickup    unix  n       -       y       60      1       pickup
cleanup   unix  n       -       y       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
#qmgr     unix  n       -       n       300     1       oqmgr
tlsmgr    unix  -       -       y       1000?   1       tlsmgr
rewrite   unix  -       -       y       -       -       trivial-rewrite
bounce    unix  -       -       y       -       0       bounce
defer     unix  -       -       y       -       0       bounce
trace     unix  -       -       y       -       0       bounce
verify    unix  -       -       y       -       1       verify
flush     unix  n       -       y       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       y       -       -       smtp
relay     unix  -       -       y       -       -       smtp
        -o syslog_name=postfix/$service_name
showq     unix  n       -       y       -       -       showq
error     unix  -       -       y       -       -       error
retry     unix  -       -       y       -       -       error
discard   unix  -       -       y       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       y       -       -       lmtp
anvil     unix  -       -       y       -       1       anvil
scache    unix  -       -       y       -       1       scache
postlog   unix-dgram n  -       n       -       1       postlogd
`;

export const MAIL01_ALIASES = `# See man 5 aliases for format
postmaster:    root
abuse:         root
root:          alice
# Shared mailboxes (CHG-2401)
helpdesk:      alice
`;

export const MAIL01_NFT = `#!/usr/sbin/nft -f

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iif "lo" accept
		meta l4proto icmp accept
		tcp dport 22 accept
		# SMTP: mail for corp.lab arrives from anywhere (MX record)
		tcp dport 25 accept
		# Submission and IMAP for the corp.lab networks (CHG-2401)
		ip saddr 10.0.0.0/16 tcp dport { 587, 143, 993 } accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

export const DOVECOT_CONF_MAIN = `## Dovecot configuration file

# If you're in a hurry, see http://wiki2.dovecot.org/QuickConfiguration

# "doveconf -n" command gives a clean output of the changed settings. Use it
# instead of copy&pasting files when posting to the Dovecot mailing list.

# Enable installed protocols
!include_try /usr/share/dovecot/protocols.d/*.protocol

# A comma separated list of IPs or hosts where to listen in for connections.
listen = *, ::

# Most of the actual configuration gets included below. The filenames are
# first sorted by their ASCII value and parsed in that order. The 00-prefixes
# in filenames are intended to make it easier to understand the ordering.
!include conf.d/*.conf

# A config file can also tried to be included without giving an error if
# it's not found:
!include_try local.conf
`;

export const DOVECOT_10_AUTH = `##
## Authentication processes
##

# Disable LOGIN command and all other plaintext authentications unless
# SSL/TLS is used (LOGINDISABLED capability).
disable_plaintext_auth = yes

# Space separated list of wanted authentication mechanisms:
#   plain login digest-md5 cram-md5 ntlm rpa apop anonymous gssapi otp
#   gss-spnego
auth_mechanisms = plain login

##
## Password and user databases
##

!include auth-system.conf.ext
`;

export const DOVECOT_AUTH_SYSTEM = `# Authentication for system users. Included from 10-auth.conf.

# PAM authentication. Preferred nowadays by most systems.
passdb {
  driver = pam
}

userdb {
  driver = passwd
}
`;

export const DOVECOT_10_MAIL = `##
## Mailbox locations and namespaces
##

# Location for users' mailboxes. The default is empty, which means that Dovecot
# tries to find the mailboxes automatically.
#
#   mail_location = maildir:~/Maildir
#   mail_location = mbox:~/mail:INBOX=/var/mail/%u
#
# Postfix delivers to ~/Maildir/ (home_mailbox = Maildir/), CHG-2401.
mail_location = maildir:~/Maildir

namespace inbox {
  inbox = yes
}

mail_privileged_group = mail
`;

export const DOVECOT_10_MASTER = `service imap-login {
  inet_listener imap {
    #port = 143
  }
  inet_listener imaps {
    #port = 993
    #ssl = yes
  }
}

service imap {
}

service auth {
  # auth_socket_path points to this userdb socket by default.
  unix_listener auth-userdb {
    #mode = 0666
    #user =
    #group =
  }

  # Postfix smtp-auth (CHG-2401): Postfix's smtpd_sasl_path = private/auth
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}

service auth-worker {
}
`;

export const DOVECOT_10_SSL = `##
## SSL settings
##

# SSL/TLS support: yes, no, required. <doc/wiki/SSL.txt>
ssl = yes

# PEM encoded X.509 SSL/TLS certificate and private key. They're opened before
# dropping root privileges, so keep the key file unreadable by anyone but
# root.
ssl_cert = <${MAIL_CERT_PATH}
ssl_key = <${MAIL_KEY_PATH}

# Minimum SSL protocol version to use.
ssl_min_protocol = TLSv1.2
`;

export const DOVECOT_10_LOGGING = `##
## Log destination.
##

# Log file to use for error messages. "syslog" logs to syslog,
# /dev/stderr logs to stderr.
#log_path = syslog

# Log unsuccessful authentication attempts and the reasons why they failed.
#auth_verbose = no
`;

export const DOVECOT_15_MAILBOXES = `namespace inbox {
  mailbox Drafts {
    special_use = \\Drafts
  }
  mailbox Junk {
    special_use = \\Junk
  }
  mailbox Trash {
    special_use = \\Trash
  }
  mailbox Sent {
    special_use = \\Sent
  }
}
`;

export const EXT01_MAIN_CF = `# ext01: the provider's mail relay and the example.net mail server
smtpd_banner = $myhostname ESMTP $mail_name (Debian/GNU)
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 3.6
myhostname = ext01.example.net
mydomain = example.net
myorigin = $mydomain
mydestination = $myhostname, example.net, localhost
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
mynetworks = 127.0.0.0/8 [::1]/128
relayhost =
inet_interfaces = all
inet_protocols = ipv4
`;

const EXT01_MASTER_CF = MASTER_CF.replace(/^submission inet[\s\S]*?milter_macro_daemon_name=ORIGINATING\n/m, '');

/** Debian's postfix and dovecot packages: system accounts, spool and runtime directories. */
function installMailPackages(h: Host, t: number, dovecot: boolean): void {
  addUser(h, { name: 'postfix', uid: 105, gid: 112, primaryGroup: 'postfix', groups: [], home: '/var/spool/postfix', shell: '/usr/sbin/nologin', gecos: '', password: null }, t, false);
  for (const d of ['/etc/postfix', '/var/spool', '/var/lib/postfix', '/var/mail']) if (!h.fs[d]) mkdir(h, d, t);
  h.fs['/var/mail'].mode = 0o2775;
  h.fs['/var/mail'].group = 'mail';
  mkdir(h, '/var/spool/postfix', t);
  for (const d of ['active', 'deferred', 'incoming', 'maildrop', 'private', 'public']) mkdir(h, `/var/spool/postfix/${d}`, t, { mode: d === 'public' || d === 'maildrop' ? 0o730 : 0o700, owner: 'postfix', group: d === 'public' || d === 'maildrop' ? 'postdrop' : 'root' });
  writeFile(h, '/etc/postfix/master.cf', dovecot ? MASTER_CF : EXT01_MASTER_CF, t);
  writeFile(h, '/etc/mailname', `${h.hostname}.${h.domain}\n`, t);
  if (!dovecot) return;
  addUser(h, { name: 'dovecot', uid: 106, gid: 113, primaryGroup: 'dovecot', groups: [], home: '/usr/lib/dovecot', shell: '/usr/sbin/nologin', gecos: 'Dovecot mail server', password: null }, t, false);
  addUser(h, { name: 'dovenull', uid: 107, gid: 114, primaryGroup: 'dovenull', groups: [], home: '/nonexistent', shell: '/usr/sbin/nologin', gecos: 'Dovecot login user', password: null }, t, false);
  for (const d of ['/usr/share', '/usr/share/dovecot', '/usr/share/dovecot/protocols.d', '/etc/dovecot', '/etc/dovecot/conf.d']) if (!h.fs[d]) mkdir(h, d, t);
  writeFile(h, '/usr/share/dovecot/protocols.d/imapd.protocol', 'protocols = $protocols imap\n', t);
  writeFile(h, '/etc/dovecot/dovecot.conf', DOVECOT_CONF_MAIN, t);
  writeFile(h, '/etc/dovecot/conf.d/10-auth.conf', DOVECOT_10_AUTH, t);
  writeFile(h, '/etc/dovecot/conf.d/auth-system.conf.ext', DOVECOT_AUTH_SYSTEM, t);
  writeFile(h, '/etc/dovecot/conf.d/10-logging.conf', DOVECOT_10_LOGGING, t);
  writeFile(h, '/etc/dovecot/conf.d/10-mail.conf', DOVECOT_10_MAIL, t);
  writeFile(h, '/etc/dovecot/conf.d/10-master.conf', DOVECOT_10_MASTER, t);
  writeFile(h, '/etc/dovecot/conf.d/10-ssl.conf', DOVECOT_10_SSL, t);
  writeFile(h, '/etc/dovecot/conf.d/15-mailboxes.conf', DOVECOT_15_MAILBOXES, t);
}

/** Create mail01 (cabled to sw01 swp15) and ext01's Postfix; buildSshLab boots them. */
export function installMail01(world: World): Host {
  const t = world.clock;
  const h = createHost(world, {
    id: 'mail01', hostname: 'mail01', domain: 'corp.lab', role: 'Mail server (Postfix SMTP, Dovecot IMAP)',
    ifaces: [{ name: 'eth0', mac: '52:54:00:a1:00:19', segment: null }],
    services: ['rsyslog', 'systemd-timesyncd', 'nftables', 'ssh', 'dovecot', 'postfix'],
  });
  writeFile(h, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: `${MAIL01_IP}/24`, gateway: '10.0.20.1' }]), t);
  writeFile(h, '/etc/resolv.conf', 'search corp.lab\nnameserver 10.0.10.53\n', t);
  writeFile(h, '/etc/ssh/sshd_config', DEBIAN_SSHD_CONFIG, t);
  writeFile(h, '/etc/nftables.conf', MAIL01_NFT, t, { mode: 0o755 });
  mkdir(h, '/etc/systemd', t);
  writeFile(h, '/etc/systemd/timesyncd.conf', TIMESYNCD_CONF, t);
  installHostKeys(h, t);
  trustCorpRoot(h, t);
  installRsyslog(h, t, true);
  if (!h.fs['/etc/ssl/private']) mkdir(h, '/etc/ssl/private', t, { mode: 0o710, group: 'ssl-cert' });
  writeFile(h, MAIL_CERT_PATH, fullchain(MAIL_CERT.cert, CORP_ISSUING.cert), t);
  writeFile(h, MAIL_KEY_PATH, keyPem(MAIL_CERT.key), t, { mode: 0o640, group: 'ssl-cert' });
  addUser(h, { name: 'alice', uid: 1000, gid: 1000, primaryGroup: 'alice', groups: ['sudo', 'adm'], home: '/home/alice', shell: '/bin/bash', gecos: 'Alice Admin', password: MAIL_PASSWORDS.alice }, t);
  addUser(h, { name: 'dana', uid: 1002, gid: 1002, primaryGroup: 'dana', groups: [], home: '/home/dana', shell: '/usr/sbin/nologin', gecos: 'Dana Sales', password: MAIL_PASSWORDS.dana }, t);
  installMailPackages(h, t, true);
  writeFile(h, '/etc/postfix/main.cf', MAIL01_MAIN_CF, t);
  writeFile(h, '/etc/aliases', MAIL01_ALIASES, t);
  newaliases(world, h);

  // ext01: the provider's relay, which also receives mail for example.net.
  const ext = world.hosts.ext01;
  ext.services.postfix = { state: 'inactive', enabled: true, since: t, pid: null, loaded: null, result: 'success' };
  installMailPackages(ext, t, false);
  writeFile(ext, '/etc/postfix/main.cf', EXT01_MAIN_CF, t);
  writeFile(ext, '/etc/aliases', 'postmaster:    root\n', t);
  addUser(ext, { name: 'partner', uid: 1001, gid: 1001, primaryGroup: 'partner', groups: [], home: '/home/partner', shell: '/bin/bash', gecos: 'Partner Contact', password: 'ext01-partner' }, t);
  newaliases(world, ext);
  return h;
}

/** A morning of normal mail, sent from ws01 through mail01 once the lab has booted. */
export function seedMail(world: World): void {
  const send = (from: string, to: string[], subject: string, body: string, port = 25, auth?: string) => {
    world.clock += 47_000;
    const c = tcpConnect(world, world.hosts.ws01, MAIL01_IP, port, { timeoutMs: 10_000 });
    if (!c.ok) return;
    const date = new Date(Math.floor(world.clock)).toUTCString().replace('GMT', '+0000');
    const content = `Date: ${date}\nTo: ${to.join(', ')}\nFrom: ${from}\nSubject: ${subject}\nMessage-Id: <${Math.floor(world.clock)}.${world.counter}@ws01.corp.lab>\n\n${body}\n`;
    smtpConversation(world, c.conn, { helo: 'ws01.corp.lab', from, to, content, tls: port === 587 ? 'required' : 'opportunistic', auth: auth ? { mech: 'PLAIN', user: auth, password: MAIL_PASSWORDS[auth] } : undefined });
    c.conn.close('client');
  };
  send('alice@corp.lab', ['dana@corp.lab'], 'Welcome to the new mail server', 'Hi Dana,\n\nYour mailbox moved to mail01. Read it over IMAP (mail01.corp.lab, port 993).\n\nAlice', 587, 'alice');
  send('dana@corp.lab', ['helpdesk@corp.lab'], 'Printer on floor 2', 'The printer on floor 2 is out of toner again.', 587, 'dana');
}
