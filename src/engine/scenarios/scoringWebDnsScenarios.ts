// Scored services, part 3: the scoring engine's web and DNS checks. The web
// check is one GET with Go's net/http client (no redirects, no certificate
// checks) that must return 200 and the expected page; the DNS check is one UDP
// query to the team's DNS server that must return the expected address. The
// result tells the layer before anyone logs in:
//   connection refused / check timed out   → service or network (as for SSH)
//   unexpected status code 403             → nginx answered: permissions
//   page content did not match             → nginx answered 200: the content changed
//   DNS: SERVFAIL / wrong answer           → named answered: the zone itself

import { mkdir, writeFile } from '../fs';
import { checkGoal, firewallStillRestrictive, script, sessionStillWorks, zoneSerialBumped } from './engine';
import { scoredWebCheck } from './scoring';
import type { Constraint, HttpGoal, Scenario, ScoredDnsGoal, ScoredWebGoal } from './types';
import type { World } from '../types';

const SCORER = '10.0.10.25';

export const INTRANET_PAGE = `<!DOCTYPE html>
<html>
<head><title>Corp Lab Intranet</title></head>
<body>
<h1>Corp Lab Intranet</h1>
<p>Welcome to the Corp Lab intranet. Phone list, IT requests and the PKI downloads (/pki/).</p>
</body>
</html>
`;

export const WEB_CHECK: ScoredWebGoal = {
  kind: 'scored-web', fromHost: 'ws01', url: 'http://www.corp.lab/', content: 'Corp Lab Intranet',
  description: `The scoring engine's web check passes again: GET http://www.corp.lab/ from ${SCORER} returns 200 with the intranet page ("Corp Lab Intranet").`,
};

export const DNS_CHECK: ScoredDnsGoal = {
  kind: 'scored-dns', fromHost: 'ws01', server: '10.0.10.53', name: 'www.corp.lab', expect: '10.0.20.10',
  description: 'The scoring engine\'s DNS check passes again: ns1 (10.0.10.53) answers "www.corp.lab A" with 10.0.20.10.',
};

const BRIEFING = [
  `Competition: the white team's scoring engine checks your services every few minutes from ${SCORER}. Its results table shows a status and the raw error of its Go client.`,
  'Scored web service (srv01): GET http://www.corp.lab/ must return 200 and the intranet page (the engine looks for "Corp Lab Intranet"). The engine does not follow redirects and does not check certificates.',
  'Scored DNS service (ns1): a query for "www.corp.lab A" sent to 10.0.10.53 must return 10.0.20.10.',
  'Fixes must survive a restart of every machine. Keep firewalls default-deny, keep HTTPS working with its certificate, and do not make web files writable to make a check pass.',
];

const WEB_TERMINALS = [
  { hostId: 'srv01', user: 'root', label: 'srv01 console (root)', banner: 'srv01 console (hypervisor), logged in as root. Scored service: web (nginx). Try: systemctl status nginx, nginx -t, ss -tlnp, tail /var/log/nginx/access.log /var/log/nginx/error.log, namei -l /var/www/html/index.html, nft list ruleset.' },
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: `ws01 (${SCORER}): the scoring engine's checks come from this address. Reproduce the web check: curl -sS -i http://www.corp.lab/ (no -L: the engine does not follow redirects).` },
];

const DNS_TERMINALS = [
  { hostId: 'ns1', user: 'root', label: 'ns1 console (root)', banner: 'ns1 console (hypervisor), logged in as root. Scored service: DNS (BIND). Try: systemctl status named, journalctl -u named -n 20, named-checkzone corp.lab /etc/bind/db.corp.lab, cat /etc/bind/db.corp.lab, nft list ruleset.' },
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: `ws01 (${SCORER}): the scoring engine's checks come from this address. Reproduce the DNS check: dig @10.0.10.53 www.corp.lab A.` },
];

const WEB_CANDIDATES = ['web-not-running', 'web-config-error', 'web-file-permissions', 'web-content-changed', 'firewall-drop', 'listen-loopback', 'routing-server-gateway', 'dns-wrong-record', 'tls-cert-expired'];
const DNS_CANDIDATES = ['dns-wrong-record', 'dns-zone-error', 'firewall-drop', 'hosts-file-override', 'dns-client-config', 'listen-loopback', 'routing-server-gateway', 'server-down'];

/** The intranet page on srv01, its backup, and a few passing engine rounds in the logs. */
export function webBaseline(world: World): void {
  const srv = world.hosts.srv01;
  writeFile(srv, '/var/www/html/index.html', INTRANET_PAGE, world.clock);
  for (const d of ['/var/backups', '/var/backups/www']) if (!srv.fs[d]) mkdir(srv, d, world.clock);
  writeFile(srv, '/var/backups/www/index.html', INTRANET_PAGE, world.clock);
  engineRounds(world, 3);
}

/** Earlier rounds of the web check, made against the world itself so they appear in nginx's logs. */
function engineRounds(world: World, n: number): void {
  for (let i = 0; i < n; i++) {
    world.clock += 180_000;
    scoredWebCheck(world, WEB_CHECK, true);
  }
}

const HTTPS: HttpGoal = { kind: 'http', description: '', fromHost: 'ws01', fromUser: 'alice', url: 'https://www.corp.lab/' };
const httpsStillWorks = () => sessionStillWorks(HTTPS, 'https-still-works', 'HTTPS to www.corp.lab still works from ws01 with a verified certificate (curl without -k).');

/** Web content must not be writable by others or by the nginx workers. */
function webFilesProtected(): Constraint {
  return {
    id: 'web-files-protected', required: true,
    description: 'The web root and the page are not writable by www-data or by other users (whoever can write them can deface the site).',
    check(world) {
      const srv = world.hosts.srv01;
      const bad = ['/var/www', '/var/www/html', '/var/www/html/index.html'].filter((p) => {
        const n = srv.fs[p];
        return n && ((n.mode & 0o002) !== 0 || n.owner === 'www-data' || (n.group === 'www-data' && (n.mode & 0o020) !== 0));
      });
      return bad.length
        ? { id: this.id, ok: false, required: true, message: `Writable by www-data or by everyone: ${bad.join(', ')}.` }
        : { id: this.id, ok: true, required: true, message: 'Web root and page: owned by root, not writable by www-data or others.' };
    },
  };
}

function mailRecordKept(): Constraint {
  return {
    id: 'mail-record-kept', required: true,
    description: 'Keep your teammate\'s new record: mail.corp.lab must resolve to 10.0.20.40 (fix the typo, do not delete the line).',
    check(world) {
      const r = checkGoal(world, { kind: 'resolve', description: '', fromHost: 'ws01', name: 'mail.corp.lab', expect: '10.0.20.40' });
      return { id: this.id, ok: r.ok, required: true, message: r.ok ? 'mail.corp.lab resolves to 10.0.20.40.' : `mail.corp.lab: ${r.lines.at(-1) ?? 'no answer'}` };
    },
  };
}

const NS1_TEMPLATE = `#!/usr/sbin/nft -f
# Team firewall template (applied to every Linux box, round 1)

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iif "lo" accept
		meta l4proto icmp accept
		meta l4proto ipv6-icmp accept
		tcp dport 22 accept
		# DNS
		tcp dport 53 accept
		# DHCP server
		udp dport 67 accept
		# Kerberos KDC and kadmin
		tcp dport { 88, 749 } accept
		udp dport 88 accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

const forbidden = 'Received an unexpected status code / expected status code 200, got 403 (403 Forbidden)';

export const SCORING_WEB_DNS_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'score-web-forbidden',
    title: '403 for everyone',
    difficulty: 'beginner',
    ticket: `Scoring engine, web (srv01): "${forbidden}" since round 212. Teammate: "I locked down the web files so other users cannot read them. nginx runs as its own user, so it should not care."`,
    briefing: BRIEFING,
    goals: [WEB_CHECK],
    terminals: WEB_TERMINALS,
    setup(world) {
      webBaseline(world);
      script(world, 'srv01', ['chmod -R o-rwx /var/www'], 60_000);
      engineRounds(world, 2);
    },
    rootCauses: ['web-file-permissions'],
    candidates: WEB_CANDIDATES,
    feedback: {
      'web-not-running': 'nginx answered: a 403 is a response from the web server. A stopped nginx gives "connection refused".',
      'web-config-error': 'nginx -t is clean and nginx is running: it answered with 403.',
      'web-content-changed': 'The engine never received a page: the status was 403, not 200 with the wrong content.',
      'firewall-drop': 'A drop gives "check timed out". The engine got an HTTP answer.',
      'listen-loopback': 'The engine reached nginx on 10.0.20.10:80 and got a response.',
      'routing-server-gateway': 'The response came back to the engine, so srv01 can reach it.',
      'dns-wrong-record': 'The request reached srv01\'s nginx (see its access log): the name resolved correctly.',
      'tls-cert-expired': 'The check uses plain HTTP, and engines do not verify certificates anyway.',
    },
    hints: [
      'A 403 comes from nginx itself: the network, firewall and service are fine. nginx explains every 403 in /var/log/nginx/error.log (tail it on srv01), and access.log shows the engine\'s requests ("Go-http-client/1.1").',
      '"(13: Permission denied)": the nginx workers run as www-data, which is "other" for files owned by root:root. To serve /var/www/html/index.html it needs x on every directory and r on the file. namei -l /var/www/html/index.html shows each one.',
      'Give "other" read on files and traverse on directories back, without write: chmod -R o+rX /var/www (capital X: x only on directories). Check with namei -l and curl from ws01.',
    ],
    explanation: {
      rootCause: '"chmod -R o-rwx /var/www" removed every permission for "other" users. nginx\'s worker processes run as www-data, which is neither the owner (root) nor in the group (root), so they can no longer enter /var/www or read the page.',
      manifestation: 'nginx is up and answers every request with 403 Forbidden. The engine reports "expected status code 200, got 403". From srv01 itself as root, the files look fine.',
      evidence: 'srv01: error.log "\\"/var/www/html/index.html\\" is forbidden (13: Permission denied)"; access.log: 10.0.10.25 "GET / HTTP/1.1" 403 "Go-http-client/1.1"; namei -l shows drwxr-x--- on /var/www and /var/www/html.',
      prevention: 'Know which account a service runs as (ps, the "user" directive) before tightening permissions, and re-run the scored check after every hardening step.',
    },
    solution: [{ host: 'srv01', commands: ['chmod -R o+rX /var/www'] }],
    constraints: [webFilesProtected(), httpsStillWorks(), firewallStillRestrictive()],
    concepts: ['linux.permissions', 'svc.listening'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'score-web-defaced',
    title: 'The page is up, the points are not',
    difficulty: 'beginner',
    ticket: `Scoring engine, web (srv01): "Page content did not match / expected content "Corp Lab Intranet" not found in the page (page title: "owned")". Teammate: "The site loads, I get 200 OK with curl. Is the engine broken?"`,
    briefing: BRIEFING,
    goals: [WEB_CHECK],
    terminals: WEB_TERMINALS,
    setup(world) {
      webBaseline(world);
      // Red team: replaced the page and left it writable by anyone, to rewrite it later from any account.
      script(world, 'srv01', ["printf '<html><head><title>owned</title></head>\\n<body><h1>owned by the red team</h1></body></html>\\n' > /var/www/html/index.html", 'chmod 666 /var/www/html/index.html'], 30_000);
      engineRounds(world, 2);
    },
    rootCauses: ['web-content-changed'],
    acceptable: { 'web-file-permissions': 'Yes: mode 666 lets any account rewrite the page. It is not why this check fails, but it must be fixed too (see the constraints).' },
    candidates: WEB_CANDIDATES,
    feedback: {
      'web-not-running': 'nginx answers 200: it is running.',
      'web-config-error': 'nginx serves the page; the configuration is fine.',
      'firewall-drop': 'The engine got a full HTTP response.',
      'listen-loopback': 'The engine reached nginx on 10.0.20.10.',
      'routing-server-gateway': 'The response reached the engine.',
      'dns-wrong-record': 'srv01\'s access log shows the engine\'s requests: it reached the right server.',
      'tls-cert-expired': 'The check uses HTTP, without certificates.',
    },
    hints: [
      'Status 200 means nginx served a page; the engine then looks for "Corp Lab Intranet" in it. Look at what it gets: curl -sS http://www.corp.lab/ from ws01.',
      'The page was replaced. On srv01: ls -l /var/www/html/ (time, mode), and compare with the backup: diff /var/backups/www/index.html /var/www/html/index.html.',
      'Restore the page (cp /var/backups/www/index.html /var/www/html/index.html) and fix its mode: cp onto an existing file keeps the old mode 666, so chmod 644 /var/www/html/index.html.',
    ],
    explanation: {
      rootCause: 'The red team overwrote /var/www/html/index.html with their own page and made it world-writable (mode 666), so any account on srv01 could change it again.',
      manifestation: 'nginx serves the defaced page with 200 OK. The engine\'s status check passes but its content check fails: "expected content "Corp Lab Intranet" not found". A quick curl that only looks at the status says "it works".',
      evidence: 'srv01: ls -l /var/www/html/index.html → -rw-rw-rw-, new modification time; diff against /var/backups/www/index.html; curl from ws01 shows <title>owned</title>.',
      prevention: 'Keep known-good copies of scored content, check content as well as status, and keep the web root owned by root and read-only for www-data. Then find out how the attacker got in (accounts, keys, web shells).',
    },
    solution: [{ host: 'srv01', commands: ['cp /var/backups/www/index.html /var/www/html/index.html', 'chmod 644 /var/www/html/index.html'] }],
    constraints: [webFilesProtected(), httpsStillWorks()],
    concepts: ['linux.permissions', 'svc.listening'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'score-web-cert-renamed',
    title: 'Renamed for the new naming scheme',
    difficulty: 'intermediate',
    ticket: 'Scoring engine, web (srv01): "Web request failed / Get "http://www.corp.lab/": dial tcp 10.0.20.10:80: connect: connection refused". Teammate: "I renamed the certificate files to our new naming scheme (www.corp.lab-2026.*) and restarted nginx to be sure. The site is plain HTTP for the engine anyway."',
    briefing: BRIEFING,
    goals: [WEB_CHECK],
    terminals: WEB_TERMINALS,
    setup(world) {
      webBaseline(world);
      script(world, 'srv01', [
        'mv /etc/ssl/certs/www.corp.lab.crt /etc/ssl/certs/www.corp.lab-2026.crt',
        'mv /etc/ssl/private/www.corp.lab.key /etc/ssl/private/www.corp.lab-2026.key',
        'systemctl restart nginx',
      ], 30_000);
    },
    rootCauses: ['web-config-error'],
    acceptable: { 'web-not-running': 'True, and it is why the connection is refused. The cause is why it cannot start: nginx -t.' },
    candidates: WEB_CANDIDATES,
    feedback: {
      'web-file-permissions': 'Permissions give a 403 from a running nginx; here nothing listens on port 80.',
      'web-content-changed': 'No page was served at all.',
      'firewall-drop': 'A drop gives "check timed out". "connection refused" is srv01\'s kernel answering: nothing listens on port 80.',
      'listen-loopback': 'ss -tlnp shows nothing on port 80 on any address.',
      'routing-server-gateway': 'srv01 answered (with a reset).',
      'dns-wrong-record': 'The address in the error is srv01\'s (10.0.20.10).',
      'tls-cert-expired': 'The certificate is valid; nginx cannot find it.',
    },
    hints: [
      '"connection refused" on port 80: nothing listens. On srv01: systemctl status nginx, ss -tlnp.',
      'nginx failed at the restart. nginx -t (or journalctl -u nginx) names the problem: [emerg] cannot load certificate "/etc/ssl/certs/www.corp.lab.crt". One nginx process serves both sites: an error in the HTTPS server block stops port 80 too.',
      'Point nginx.conf at the new names (ssl_certificate and ssl_certificate_key), check with nginx -t, then systemctl restart nginx. Check HTTPS too: curl -I https://www.corp.lab/ from ws01 (without -k).',
    ],
    explanation: {
      rootCause: 'The certificate and key were renamed, but /etc/nginx/nginx.conf still refers to the old file names. At the restart nginx could not load the certificate, failed its configuration test and did not start at all.',
      manifestation: 'Both port 80 and 443 are closed, so the plain-HTTP check is refused even though only the HTTPS server block is wrong. A reload instead of a restart would have kept the old nginx running and hidden the problem until the next reboot.',
      evidence: 'srv01: systemctl status nginx → failed; journalctl -u nginx / nginx -t → nginx: [emerg] cannot load certificate "/etc/ssl/certs/www.corp.lab.crt": BIO_new_file() failed; ls /etc/ssl/certs/www.corp.lab*.',
      prevention: 'Run nginx -t after every change to files nginx reads (configuration, certificates, keys) and before any restart; prefer reload, which keeps the running server if the new configuration fails.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i 's|/etc/ssl/certs/www.corp.lab.crt|/etc/ssl/certs/www.corp.lab-2026.crt|; s|/etc/ssl/private/www.corp.lab.key|/etc/ssl/private/www.corp.lab-2026.key|' /etc/nginx/nginx.conf", 'nginx -t && systemctl restart nginx'] }],
    constraints: [httpsStillWorks(), webFilesProtected(), firewallStillRestrictive()],
    concepts: ['svc.systemd', 'tls.pki'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'score-web-https-only',
    title: 'HTTPS only',
    difficulty: 'intermediate',
    ticket: 'Scoring engine, web (srv01): "Encountered an unexpected error during the check. / check timed out. this is most likely due to services timing out". Teammate: "Plain HTTP is insecure, so I closed port 80 in the firewall. https://www.corp.lab works fine."',
    briefing: BRIEFING,
    goals: [WEB_CHECK],
    terminals: WEB_TERMINALS,
    setup(world) {
      webBaseline(world);
      script(world, 'srv01', ["sed -i 's/^\\(\\s*\\)tcp dport { 80, 443 } accept$/\\1# HTTPS only (team checklist)\\n\\1tcp dport 443 accept/' /etc/nftables.conf", 'systemctl reload nftables'], 30_000);
    },
    rootCauses: ['firewall-drop'],
    candidates: WEB_CANDIDATES,
    feedback: {
      'web-not-running': 'nginx is running and listening on 0.0.0.0:80 (ss -tlnp); a stopped nginx gives "connection refused".',
      'web-config-error': 'nginx -t is clean and nginx is running.',
      'web-file-permissions': 'Permissions give a 403; here the engine got no answer at all.',
      'web-content-changed': 'No page was received.',
      'listen-loopback': 'nginx listens on 0.0.0.0:80, and a loopback bind gives "connection refused".',
      'routing-server-gateway': 'HTTPS from ws01 works, so srv01 can answer that subnet: only port 80 is silent.',
      'dns-wrong-record': 'www.corp.lab resolves to 10.0.20.10, srv01.',
      'tls-cert-expired': 'The check is plain HTTP; HTTPS works.',
    },
    hints: [
      '"check timed out" means no answer at all before the engine\'s deadline. From ws01: nc -zv www.corp.lab 80 versus nc -zv www.corp.lab 443.',
      'nginx listens on port 80 (ss -tlnp on srv01), so something drops the packets: nft list chain inet filter input. Which ports does the accept rule allow now?',
      'The scored service is HTTP: allow port 80 again in /etc/nftables.conf (tcp dport { 80, 443 } accept), check with nft -c -f /etc/nftables.conf and reload nftables. A redirect to HTTPS would not help: the engine does not follow redirects and would see 301 instead of 200.',
    ],
    explanation: {
      rootCause: 'The accept rule for { 80, 443 } was replaced with one for 443 only. With the input policy drop, SYNs to port 80 are dropped silently.',
      manifestation: 'The engine\'s HTTP check gets no answer and hits its deadline ("check timed out"). HTTPS and SSH keep working, so the server "looks fine" to the team.',
      evidence: 'srv01: nginx listening on 0.0.0.0:80; nft list ruleset → "tcp dport 443 accept" only; ws01: nc -zv www.corp.lab 80 times out, port 443 connects.',
      prevention: 'Read the competition\'s scored-service list before hardening: a scored service must stay reachable in the form the engine checks. Secure it in ways the check tolerates.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i 's/^\\(\\s*\\)tcp dport 443 accept$/\\1tcp dport { 80, 443 } accept/' /etc/nftables.conf", 'nft -c -f /etc/nftables.conf && systemctl reload nftables'] }],
    constraints: [firewallStillRestrictive(), httpsStillWorks()],
    concepts: ['fw.stateful', 'tcp.handshake'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'score-dns-hijack',
    title: 'www points somewhere else',
    difficulty: 'beginner',
    ticket: 'Scoring engine, DNS (ns1): "Incorrect DNS answer / www.corp.lab. A: expected 10.0.20.10, got 10.0.30.66". The web check fails as well. Teammate: "I added www to /etc/hosts on my workstation and it resolves fine for me."',
    briefing: BRIEFING,
    goals: [DNS_CHECK],
    terminals: DNS_TERMINALS,
    setup(world) {
      world.clock += 3600_000;
      script(world, 'ns1', ["sed -i 's/^www     IN CNAME srv01$/www     IN A    10.0.30.66/' /etc/bind/db.corp.lab", 'rndc reload'], 30_000);
    },
    rootCauses: ['dns-wrong-record'],
    candidates: DNS_CANDIDATES,
    feedback: {
      'dns-zone-error': 'The zone is loaded and answers (a wrong answer, not SERVFAIL).',
      'firewall-drop': 'ns1 answered the query.',
      'hosts-file-override': 'The engine asks ns1 directly; /etc/hosts on any machine is not involved. Your teammate\'s /etc/hosts entry only hides the problem on their workstation.',
      'dns-client-config': 'The engine queries 10.0.10.53 directly, whatever resolv.conf says.',
      'listen-loopback': 'named answered on 10.0.10.53.',
      'routing-server-gateway': 'The answer reached the engine.',
      'server-down': 'ns1 answered.',
    },
    hints: [
      'An "incorrect answer" means ns1 answered, with data the engine does not expect. Compare: dig @10.0.10.53 www.corp.lab A on ws01 and the zone file on ns1.',
      'In /etc/bind/db.corp.lab, www should be an alias of srv01 (CNAME), as in the original zone. Who changed it? ls -l and journalctl -u named show when the zone was last reloaded.',
      'Restore the record (www IN CNAME srv01), increase the SOA serial, named-checkzone corp.lab /etc/bind/db.corp.lab, then rndc reload. Check with dig @10.0.10.53 www.corp.lab.',
    ],
    explanation: {
      rootCause: 'The red team replaced "www IN CNAME srv01" with "www IN A 10.0.30.66" (a machine they control) in the corp.lab zone and reloaded named.',
      manifestation: 'ns1 answers authoritatively with the attacker\'s address. The engine\'s DNS check fails with "expected 10.0.20.10, got 10.0.30.66"; the web check, which resolves www.corp.lab through ns1 too, now tries to reach 10.0.30.66 and fails as well. Fixing the web server would not help.',
      evidence: 'ws01: dig @10.0.10.53 www.corp.lab → A 10.0.30.66 (no CNAME); ns1: the record in /etc/bind/db.corp.lab, journal "received control channel command \'reload\'" at the time the check started failing.',
      prevention: 'Keep zone files under version control and compare them with the known-good copy; restrict who can write /etc/bind and run rndc. Increase the serial on every change.',
    },
    solution: [{ host: 'ns1', commands: ["sed -i 's/^www     IN A    10.0.30.66$/www     IN CNAME srv01/; s/2026101901 ; serial/2026102401 ; serial/' /etc/bind/db.corp.lab", 'named-checkzone corp.lab /etc/bind/db.corp.lab && rndc reload'] }],
    constraints: [zoneSerialBumped(2026101901)],
    concepts: ['dns.zone', 'dns.resolution'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'score-dns-servfail',
    title: 'One typo, every name',
    difficulty: 'intermediate',
    ticket: 'Scoring engine, DNS (ns1): "DNS query failed / www.corp.lab. A: server answered SERVFAIL". The web check fails too ("lookup www.corp.lab on 10.0.10.53:53: server misbehaving"). Teammate: "I only added the record for the new mail server (10.0.20.40) and restarted bind."',
    briefing: BRIEFING,
    goals: [DNS_CHECK],
    terminals: DNS_TERMINALS,
    setup(world) {
      world.clock += 3600_000;
      script(world, 'ns1', [
        "sed -i 's/^ns1     IN A    10.0.10.53$/&\\nmail    IN A    10.0.20.400/; s/2026101901 ; serial/2026102401 ; serial/' /etc/bind/db.corp.lab",
        'systemctl restart named',
      ], 30_000);
    },
    rootCauses: ['dns-zone-error'],
    candidates: DNS_CANDIDATES,
    feedback: {
      'dns-wrong-record': 'The answer is not a wrong address: it is SERVFAIL, no answer at all, for every name in the zone (try dig @10.0.10.53 srv01.corp.lab).',
      'firewall-drop': 'ns1 answered (SERVFAIL is an answer).',
      'hosts-file-override': 'The engine queries ns1 directly.',
      'dns-client-config': 'The engine queries 10.0.10.53 directly, and it answered.',
      'listen-loopback': 'named answered on 10.0.10.53.',
      'routing-server-gateway': 'The answer reached the engine.',
      'server-down': 'ns1 and named are up: they answered.',
    },
    hints: [
      'SERVFAIL means named is running and responsible for the zone but cannot answer from it. Try other names (dig @10.0.10.53 srv01.corp.lab): if all fail, the whole zone is not loaded.',
      'On ns1: journalctl -u named -n 20, or named-checkzone corp.lab /etc/bind/db.corp.lab. Which line, and what is wrong with it?',
      'The new record has an impossible address (10.0.20.400). Correct it to 10.0.20.40 (keep the record), check with named-checkzone, then rndc reload. The serial was already increased.',
    ],
    explanation: {
      rootCause: 'The new line "mail IN A 10.0.20.400" is not a valid IPv4 address. BIND rejects the whole zone file ("bad dotted quad"), and after the restart it has no data for corp.lab.',
      manifestation: 'Every name under corp.lab answers SERVFAIL, so the DNS check and anything that resolves names in the zone fail. A reload instead of a restart would have kept serving the previous version of the zone and hidden the error until the next restart.',
      evidence: 'ns1: journalctl -u named → "dns_master_load: /etc/bind/db.corp.lab:12: bad dotted quad" and "zone corp.lab/IN: not loaded due to errors"; named-checkzone gives the same; dig on ws01 → status: SERVFAIL for every name.',
      prevention: 'Run named-checkzone before every reload or restart; prefer rndc reload, which keeps the old zone if the new one fails to load.',
    },
    solution: [{ host: 'ns1', commands: ["sed -i 's/10.0.20.400/10.0.20.40/' /etc/bind/db.corp.lab", 'named-checkzone corp.lab /etc/bind/db.corp.lab && rndc reload'] }],
    constraints: [mailRecordKept()],
    concepts: ['dns.zone', 'logs.journal'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'score-dns-firewall',
    title: 'DNS is TCP, right?',
    difficulty: 'intermediate',
    ticket: 'Scoring engine, DNS (ns1): "Encountered an unexpected error during the check. / check timed out. this is most likely due to services timing out" since the team firewall template went on ns1. Teammate: "The template allows DNS, port 53. I checked with nc, port 53 is open."',
    briefing: BRIEFING,
    goals: [DNS_CHECK],
    terminals: DNS_TERMINALS,
    setup(world) {
      world.clock += 3600_000;
      writeFile(world.hosts.ns1, '/etc/nftables.conf', NS1_TEMPLATE, world.clock, { mode: 0o755 });
      script(world, 'ns1', ['nft -f /etc/nftables.conf'], 30_000);
    },
    rootCauses: ['firewall-drop'],
    candidates: DNS_CANDIDATES,
    feedback: {
      'dns-wrong-record': 'No answer arrived at all, so no record was wrong.',
      'dns-zone-error': 'The zone is loaded (dig @127.0.0.1 www.corp.lab on ns1 itself works). A broken zone answers SERVFAIL; here nothing comes back.',
      'hosts-file-override': 'The engine queries ns1 directly.',
      'dns-client-config': 'The engine queries 10.0.10.53 directly.',
      'listen-loopback': 'named listens on 0.0.0.0:53 (ss -ulnp), and a loopback bind would give "connection refused" (ICMP port unreachable).',
      'routing-server-gateway': 'ping and SSH to ns1 work from ws01: ns1 can answer that subnet.',
      'server-down': 'ns1 answers ping and SSH.',
    },
    hints: [
      'A timeout means the query got no answer at all. On ns1, named is running (systemctl status named) and answers locally: dig @127.0.0.1 www.corp.lab. So what is between the engine and named?',
      'nc -zv tests TCP. A DNS query is a UDP datagram to port 53 (TCP is only used for large answers and zone transfers). Read the input chain on ns1: nft list chain inet filter input.',
      'The template accepts "tcp dport 53" only. Add "udp dport 53 accept" next to it in /etc/nftables.conf, nft -c -f /etc/nftables.conf, then systemctl reload nftables. Keep the policy drop.',
    ],
    explanation: {
      rootCause: 'The team\'s firewall template allows TCP port 53 but not UDP port 53. DNS queries travel over UDP, so the default-drop policy silently drops every query.',
      manifestation: 'The engine\'s query gets no answer and its deadline fires ("check timed out"). nc -zv ns1 53 succeeds (TCP), which makes the template look right.',
      evidence: 'ns1: named listening on udp and tcp 53 (ss -ulnp, ss -tlnp); nft list ruleset: "tcp dport 53 accept", no udp rule; ws01: dig @10.0.10.53 www.corp.lab → "communications error ... timed out" while nc -zv 10.0.10.53 53 (TCP) succeeds.',
      prevention: 'List each scored service with its protocol and port (DNS: UDP and TCP 53) when writing firewall templates, and test with the real client (dig), not only with nc.',
    },
    solution: [{ host: 'ns1', commands: ["sed -i 's/^\\(\\s*\\)tcp dport 53 accept$/\\1tcp dport 53 accept\\n\\1udp dport 53 accept/' /etc/nftables.conf", 'nft -c -f /etc/nftables.conf && systemctl reload nftables'] }],
    constraints: [firewallStillRestrictive('ns1')],
    concepts: ['fw.stateful', 'dns.resolution'],
  },
];
