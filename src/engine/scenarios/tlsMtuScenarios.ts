// TLS and MTU tickets. srv01 serves https://www.corp.lab/ with a certificate from
// Corp Lab Issuing CA 1 (signed by Corp Lab Root CA, which every corp.lab
// machine trusts). rtr01's eth2 is the Internet uplink to ext01, which offers a
// large download over HTTP and a public HTTPS site.

import { readFile, writeFile } from '../fs';
import { parseNginxServers } from '../config/nginx';
import { CORP_ROOT_LOCAL, fullchain, SRV01_ONLY_CERT, WWW_CERT, WWW_CERT_2025 } from '../lab/pkiLab';
import { CA_BUNDLE, certPem, CORP_ISSUING, csrPem, CORP_ROOT, fingerprint, keyPem, PUBLIC_ROOTS, trustStore } from '../sim/pki';
import type { World } from '../types';
import { script } from './engine';
import type { Constraint, Goal, Scenario } from './types';

const WWW_HTTPS: Goal = { kind: 'http', description: 'From ws01, "curl -I https://www.corp.lab/" succeeds with certificate verification (no -k).', fromHost: 'ws01', fromUser: 'alice', url: 'https://www.corp.lab/' };
const SRV_HTTPS: Goal = { kind: 'http', description: 'From ws01, "curl -I https://srv01.corp.lab/" also succeeds with verification.', fromHost: 'ws01', fromUser: 'alice', url: 'https://srv01.corp.lab/' };
const DANA_HTTPS: Goal = { kind: 'http', description: 'On ws02, "curl -I https://www.corp.lab/" succeeds with certificate verification (no -k).', fromHost: 'ws02', fromUser: 'dana', url: 'https://www.corp.lab/' };
const DOWNLOAD: Goal = { kind: 'http', download: true, description: 'From ws01, downloading http://203.0.113.80/downloads/tools-2.4.1.tar.gz (4.5 MB) completes.', fromHost: 'ws01', fromUser: 'alice', url: 'http://203.0.113.80/downloads/tools-2.4.1.tar.gz' };
const EXT_HTTPS: Goal = { kind: 'http', description: 'From ws01, "curl -I https://203.0.113.80/" (a public HTTPS site) succeeds.', fromHost: 'ws01', fromUser: 'alice', url: 'https://203.0.113.80/' };

export const CORP_ROOT_FINGERPRINT = fingerprint(CORP_ROOT.cert, 'sha256');

const TLS_TERMINALS = [
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01, administrator workstation. It trusts the Corp Lab Root CA. sudo password: ws01-alice.' },
  { hostId: 'srv01', user: 'root', label: 'srv01 console', banner: 'Console on srv01 (root): nginx serves http:// and https://www.corp.lab/ (also reachable as srv01.corp.lab).' },
];

const TLS_BRIEFING = [
  'https://www.corp.lab/ (www is a CNAME for srv01) is served by nginx on srv01. Its certificate is issued by "Corp Lab Issuing CA 1", which is signed by "Corp Lab Root CA".',
  'Every corp.lab machine trusts Corp Lab Root CA (/usr/local/share/ca-certificates/corp-lab-root-ca.crt, built into /etc/ssl/certs/ca-certificates.crt by update-ca-certificates). The intermediate is NOT in the clients\' trust stores: servers must send it.',
  'Clients must keep verifying certificates: "curl -k" or disabling verification is not a fix. Fixes must survive a reboot of every machine.',
];

const TLS_CANDIDATES = ['tls-cert-expired', 'tls-key-mismatch', 'tls-name-mismatch', 'tls-chain-incomplete', 'tls-untrusted-root', 'web-not-running', 'firewall-drop', 'dns-wrong-record'];

function edit(world: World, host: string, path: string, fn: (s: string) => string, gapMs = 60_000) {
  world.clock += gapMs;
  const h = world.hosts[host];
  writeFile(h, path, fn(readFile(h, path) ?? ''), world.clock);
}

function put(world: World, host: string, path: string, content: string, mode?: number) {
  world.clock += 20_000;
  writeFile(world.hosts[host], path, content, world.clock, mode !== undefined ? { mode } : undefined);
}

/** The private keys nginx uses must not be readable by everyone. */
function keysProtected(): Constraint {
  return {
    id: 'tls-key-protected', required: true,
    description: 'Private keys used by nginx on srv01 must not be world-readable (mode 0600 or 0640 root:ssl-cert).',
    check(world) {
      const h = world.hosts.srv01;
      const keys = parseNginxServers(readFile(h, '/etc/nginx/nginx.conf') ?? '').flatMap((s) => (s.key ? [s.key.path] : []));
      const open = keys.find((k) => h.fs[k] && (h.fs[k].mode & 0o007) !== 0);
      return { id: this.id, ok: !open, required: true, message: open ? `${open} is readable by every user (mode ${h.fs[open].mode.toString(8)}).` : 'The private keys are protected.' };
    },
  };
}

/** A client's trust store holds only legitimate roots: no intermediates, no self-signed server certificates. */
function trustStoreClean(hostId: string): Constraint {
  return {
    id: `trust-clean-${hostId}`, required: true,
    description: `${hostId} must trust only root CAs (the public roots and Corp Lab Root CA). Adding the intermediate or the server certificate to the client is a workaround that breaks at the next renewal.`,
    check(world) {
      const allowed = [...PUBLIC_ROOTS.map((r) => r.cert), CORP_ROOT.cert].map((c) => c.keyId);
      const extra = trustStore(world.hosts[hostId]).filter((c) => !allowed.includes(c.keyId));
      return { id: this.id, ok: extra.length === 0, required: true, message: extra.length ? `${hostId} now also trusts "${extra[0].subject.map(([k, v]) => `${k}=${v}`).join(', ')}".` : `${hostId}'s trust store contains only root CAs.` };
    },
  };
}

function clientMtuDefault(): Constraint {
  return {
    id: 'client-mtu', required: true,
    description: 'Do not work around the problem on the clients: ws01 keeps the standard MTU of 1500.',
    check(world) {
      const m = world.hosts.ws01.ifaces.find((i) => i.name === 'eth0')?.mtu ?? 1500;
      return { id: this.id, ok: m === 1500, required: true, message: m === 1500 ? 'ws01 uses MTU 1500.' : `ws01's MTU was lowered to ${m}: every client would need the same change.` };
    },
  };
}

/** Put an expired (2025) certificate/key pair in place and load it, as if nobody renewed in time. */
function serveExpired(world: World) {
  put(world, 'srv01', '/etc/ssl/certs/www.corp.lab.crt', fullchain(WWW_CERT_2025.cert, CORP_ISSUING.cert));
  put(world, 'srv01', '/etc/ssl/private/www.corp.lab.key', keyPem(WWW_CERT_2025.key), 0o640);
  world.hosts.srv01.fs['/etc/ssl/private/www.corp.lab.key'].group = 'ssl-cert';
  script(world, 'srv01', ['systemctl restart nginx']);
}

const RENEWAL_README = 'CHG-1240  Renewal of www.corp.lab (Corp Lab Issuing CA 1)\n\nwww.corp.lab-2026.key   new private key (generated on srv01)\nwww.corp.lab-2026.csr   request sent to the PKI team\nwww.corp.lab-2026.crt   issued certificate + intermediate (full chain)\n\nInstall on srv01 nginx, test, reload.\n';

function deliverRenewal(world: World) {
  world.clock += 60_000;
  const h = world.hosts.srv01;
  if (!h.fs['/root/renewal']) h.fs['/root/renewal'] = { type: 'dir', mode: 0o700, owner: 'root', group: 'root', content: '', mtime: world.clock };
  put(world, 'srv01', '/root/renewal/README', RENEWAL_README);
  put(world, 'srv01', '/root/renewal/www.corp.lab-2026.key', keyPem(WWW_CERT.key), 0o600);
  put(world, 'srv01', '/root/renewal/www.corp.lab-2026.csr', csrPem({ subject: WWW_CERT.cert.subject, san: WWW_CERT.cert.san, keyId: WWW_CERT.key.keyId, bits: 2048 }));
  put(world, 'srv01', '/root/renewal/www.corp.lab-2026.crt', fullchain(WWW_CERT.cert, CORP_ISSUING.cert));
}

export const TLS_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'tls-expired',
    title: 'Your connection is not private',
    difficulty: 'beginner',
    ticket: 'Helpdesk: "Since this morning everyone gets a certificate warning on the intranet https://www.corp.lab/. Scripts that call the intranet API fail too." PKI team: "We issued the renewal for www.corp.lab last week (CHG-1240) and put it on srv01 in /root/renewal. Did anyone install it?"',
    briefing: TLS_BRIEFING,
    goals: [WWW_HTTPS, SRV_HTTPS],
    terminals: TLS_TERMINALS,
    setup(world) {
      serveExpired(world);
      deliverRenewal(world);
      world.clock += 3600_000;
    },
    rootCauses: ['tls-cert-expired'],
    candidates: TLS_CANDIDATES,
    feedback: {
      'tls-untrusted-root': 'ws01 trusts Corp Lab Root CA and the chain verifies (s_client shows depth=2, depth=1 with "verify return:1"). The only error is at depth 0: num=10, certificate has expired.',
      'tls-key-mismatch': 'nginx -t is successful and nginx is serving the certificate that belongs to the configured key. The problem is the certificate\'s date.',
    },
    hints: [
      'Reproduce from ws01 with "curl -v -I https://www.corp.lab/". Which TLS alert does curl send, and what is the exact verification error?',
      'Look at what the server presents: "openssl s_client -connect www.corp.lab:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -dates". Compare notAfter with "date". Then look at /root/renewal on srv01.',
      'On srv01: check the new pair belongs together (compare "-modulus | openssl md5" of the .crt and the .key), copy www.corp.lab-2026.crt to /etc/ssl/certs/www.corp.lab.crt and the key to /etc/ssl/private/www.corp.lab.key (keep the key mode 0640 or 0600), then "nginx -t" and "systemctl reload nginx".',
    ],
    explanation: {
      rootCause: 'The www.corp.lab certificate expired on 17 October 2026 (notAfter). A renewed certificate had been issued but never installed.',
      manifestation: 'TCP connects normally; the client receives the certificate in the TLS handshake, finds now > notAfter and aborts with the "certificate expired" alert. curl reports (60) "SSL certificate problem: certificate has expired"; browsers show NET::ERR_CERT_DATE_INVALID. Every client fails at once, regardless of network.',
      evidence: 's_client: "depth=0 CN = www.corp.lab / verify error:num=10:certificate has expired / notAfter=Oct 17 08:02:00 2026 GMT"; openssl x509 -noout -enddate on /etc/ssl/certs/www.corp.lab.crt shows the same date; /root/renewal holds a certificate valid until July 2027 whose modulus matches the new key.',
      prevention: 'Monitor expiry from the outside (openssl x509 -checkend 2592000 against what the server serves, alert at 30 days), send renewal reminders to a team mailbox, automate issuance and deployment (ACME, certbot/step-ca) with a post-deploy check, and record certificate owners.',
    },
    solution: [{
      host: 'srv01',
      commands: [
        'openssl x509 -in /root/renewal/www.corp.lab-2026.crt -noout -subject -enddate',
        'cp /root/renewal/www.corp.lab-2026.crt /etc/ssl/certs/www.corp.lab.crt',
        'cp /root/renewal/www.corp.lab-2026.key /etc/ssl/private/www.corp.lab.key',
        'nginx -t',
        'systemctl reload nginx',
      ],
    }],
    constraints: [keysProtected(), trustStoreClean('ws01')],
    concepts: ['tls.pki'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'tls-key-mismatch',
    title: 'Renewed, but still expired',
    difficulty: 'intermediate',
    ticket: 'Sam (junior admin): "I installed the renewed certificate for www.corp.lab yesterday evening: copied the new .crt over the old one and reloaded nginx. Browsers STILL say the certificate expired. I double-checked the file, it is valid until 2027!"',
    briefing: [...TLS_BRIEFING, 'Sam worked from the renewal files in /root/renewal on srv01 (CHG-1240).'],
    goals: [WWW_HTTPS, SRV_HTTPS],
    terminals: TLS_TERMINALS,
    setup(world) {
      serveExpired(world);
      deliverRenewal(world);
      world.clock += 2 * 3600_000;
      script(world, 'srv01', ['cp /root/renewal/www.corp.lab-2026.crt /etc/ssl/certs/www.corp.lab.crt', 'systemctl reload nginx']);
      world.clock += 14 * 3600_000;
    },
    rootCauses: ['tls-key-mismatch'],
    acceptable: { 'tls-cert-expired': 'True for what clients see: nginx still serves the old certificate from memory. But the reason the renewal did not take effect is the key mismatch, and fixing only the date is impossible without the matching key.' },
    candidates: TLS_CANDIDATES,
    feedback: {
      'tls-chain-incomplete': 'The served chain has two certificates (s_client "Certificate chain" 0 and 1) and the new file is a full chain too. The served certificate is simply the old one.',
      'web-not-running': 'nginx is running (the old configuration stays loaded when a reload fails). But beware: a restart or reboot now would take HTTPS down.',
    },
    hints: [
      'Compare what is served ("openssl s_client -connect www.corp.lab:443 </dev/null | openssl x509 -noout -dates" from ws01) with what is on disk on srv01 (openssl x509 -noout -dates -in /etc/ssl/certs/www.corp.lab.crt). Why would nginx serve something other than its file?',
      'nginx reads certificates only at start/reload, and a failed reload keeps the old configuration. Run "nginx -t" and "journalctl -u nginx" on srv01.',
      'The new certificate was issued for the new key in /root/renewal. Install that key as /etc/ssl/private/www.corp.lab.key (compare moduli first), "nginx -t", then reload.',
    ],
    explanation: {
      rootCause: 'Only the certificate was replaced. /etc/ssl/private/www.corp.lab.key is still the 2025 key, which does not match the 2026 certificate\'s public key, so nginx refuses the new configuration.',
      manifestation: '"systemctl reload nginx" failed ("key values mismatch") but nginx kept running with the configuration loaded before, including the old certificate held in memory. Clients therefore still see the expired certificate even though the file on disk is new. A restart or a reboot would fail outright and take the site down.',
      evidence: 'nginx -t: "SSL_CTX_use_PrivateKey("/etc/ssl/private/www.corp.lab.key") failed (SSL: error:05800074:x509 certificate routines::key values mismatch)"; journalctl -u nginx shows the failed reload; "openssl x509 -noout -modulus | openssl md5" and "openssl rsa -noout -modulus | openssl md5" differ; the served certificate (s_client) has notAfter 17 Oct 2026, the file on disk July 2027.',
      prevention: 'Always run "nginx -t" (or "systemctl reload" and check its result) after changing certificates; deploy certificate and key together as one unit; check what is served from outside after every change (s_client or monitoring), not just the file.',
    },
    solution: [{
      host: 'srv01',
      commands: [
        'nginx -t',
        'cp /root/renewal/www.corp.lab-2026.key /etc/ssl/private/www.corp.lab.key',
        'nginx -t',
        'systemctl reload nginx',
      ],
    }],
    constraints: [keysProtected(), trustStoreClean('ws01')],
    concepts: ['tls.pki', 'svc.systemd'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'tls-wrong-cert',
    title: 'The certificate is for the wrong name',
    difficulty: 'beginner',
    ticket: 'Helpdesk: "The intranet https://www.corp.lab/ shows a certificate error since yesterday\'s maintenance (CHG-1252: \'switch nginx to the new certificate\'). Strangely https://srv01.corp.lab/ works fine."',
    briefing: [...TLS_BRIEFING, 'CHG-1252 added a certificate for the host name srv01.corp.lab (for the new management console) in /etc/ssl/certs/srv01.corp.lab.crt.'],
    goals: [WWW_HTTPS, SRV_HTTPS],
    terminals: TLS_TERMINALS,
    setup(world) {
      put(world, 'srv01', '/etc/ssl/certs/srv01.corp.lab.crt', fullchain(SRV01_ONLY_CERT.cert, CORP_ISSUING.cert));
      put(world, 'srv01', '/etc/ssl/private/srv01.corp.lab.key', keyPem(SRV01_ONLY_CERT.key), 0o640);
      world.hosts.srv01.fs['/etc/ssl/private/srv01.corp.lab.key'].group = 'ssl-cert';
      edit(world, 'srv01', '/etc/nginx/nginx.conf', (s) => s.replace('ssl_certificate /etc/ssl/certs/www.corp.lab.crt;', 'ssl_certificate /etc/ssl/certs/srv01.corp.lab.crt;').replace('ssl_certificate_key /etc/ssl/private/www.corp.lab.key;', 'ssl_certificate_key /etc/ssl/private/srv01.corp.lab.key;'));
      script(world, 'srv01', ['nginx -t', 'systemctl reload nginx']);
      world.clock += 18 * 3600_000;
    },
    rootCauses: ['tls-name-mismatch'],
    candidates: TLS_CANDIDATES,
    feedback: {
      'dns-wrong-record': 'www.corp.lab resolves to srv01 (it is a CNAME) and the TLS handshake completes; the client rejects the name in the certificate, not the address.',
      'tls-untrusted-root': 'The chain verifies (https://srv01.corp.lab/ works from the same client with the same trust store). Only the host name check fails.',
    },
    hints: [
      'Run "curl -v -I https://www.corp.lab/" on ws01 and read the "Server certificate" block: subject, and the subjectAltName line.',
      'Which names does the served certificate cover? "openssl s_client -connect www.corp.lab:443 </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName". Compare with /etc/ssl/certs/www.corp.lab.crt on srv01.',
      'nginx.conf now points ssl_certificate/ssl_certificate_key at the srv01.corp.lab files, which only cover srv01.corp.lab. Point the site back at www.corp.lab.crt/.key (it covers both names), nginx -t, reload.',
    ],
    explanation: {
      rootCause: 'The HTTPS server block was switched to a certificate whose subjectAltName contains only srv01.corp.lab. Clients connecting as www.corp.lab cannot match the name.',
      manifestation: 'The chain is valid and trusted, so the handshake completes, but curl/browsers compare the requested host name with the certificate\'s SAN entries: curl (60) "SSL: no alternative certificate subject name matches target host name \'www.corp.lab\'", browsers NET::ERR_CERT_COMMON_NAME_INVALID. Users of the srv01.corp.lab name are unaffected, which makes it look selective.',
      evidence: 'curl -v: "subject: CN=srv01.corp.lab" and "subjectAltName does not match www.corp.lab"; openssl x509 -ext subjectAltName on the served certificate: only DNS:srv01.corp.lab; nginx.conf ssl_certificate /etc/ssl/certs/srv01.corp.lab.crt.',
      prevention: 'Request certificates with every name users and services use (all SANs); after changing ssl_certificate, test every published name ("curl -I https://NAME/" or s_client -servername NAME); keep an inventory of names per site.',
    },
    solution: [{
      host: 'srv01',
      commands: [
        "sed -i 's#ssl_certificate /etc/ssl/certs/srv01.corp.lab.crt;#ssl_certificate /etc/ssl/certs/www.corp.lab.crt;#; s#ssl_certificate_key /etc/ssl/private/srv01.corp.lab.key;#ssl_certificate_key /etc/ssl/private/www.corp.lab.key;#' /etc/nginx/nginx.conf",
        'nginx -t',
        'systemctl reload nginx',
      ],
    }],
    constraints: [keysProtected(), trustStoreClean('ws01')],
    concepts: ['tls.pki'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'tls-missing-intermediate',
    title: 'Works in my browser, fails in scripts',
    difficulty: 'intermediate',
    ticket: 'Developer: "Since the certificate renewal, our deployment scripts fail with \'unable to get local issuer certificate\' when they call https://www.corp.lab/. In my browser the site is fine! Can you add the CA to the build servers?"',
    briefing: [...TLS_BRIEFING, 'The renewal (CHG-1240) delivered three files in /root/renewal on srv01: cert.pem (server certificate only), chain.pem (Corp Lab Issuing CA 1) and the key.'],
    goals: [WWW_HTTPS, SRV_HTTPS],
    terminals: TLS_TERMINALS,
    setup(world) {
      world.clock += 60_000;
      const h = world.hosts.srv01;
      h.fs['/root/renewal'] = { type: 'dir', mode: 0o700, owner: 'root', group: 'root', content: '', mtime: world.clock };
      put(world, 'srv01', '/root/renewal/cert.pem', certPem(WWW_CERT.cert));
      put(world, 'srv01', '/root/renewal/chain.pem', certPem(CORP_ISSUING.cert));
      put(world, 'srv01', '/root/renewal/privkey.pem', keyPem(WWW_CERT.key), 0o600);
      script(world, 'srv01', ['cp /root/renewal/cert.pem /etc/ssl/certs/www.corp.lab.crt', 'nginx -t', 'systemctl reload nginx']);
      world.clock += 6 * 3600_000;
    },
    rootCauses: ['tls-chain-incomplete'],
    candidates: TLS_CANDIDATES,
    feedback: {
      'tls-untrusted-root': 'ws01 already trusts Corp Lab Root CA (see /usr/local/share/ca-certificates). The failure is at depth 0: the client cannot even find the intermediate that signed the server certificate, because the server does not send it.',
      'tls-cert-expired': 'The served certificate is valid until July 2027. Read the verification error number: 20 at depth 0, not 10.',
    },
    hints: [
      'Do not add CAs to clients yet. Look at the chain the server sends: "openssl s_client -connect www.corp.lab:443 </dev/null" on ws01. How many entries are under "Certificate chain"?',
      'On srv01: "grep -c BEGIN /etc/ssl/certs/www.corp.lab.crt" and "openssl verify -untrusted /root/renewal/chain.pem /etc/ssl/certs/www.corp.lab.crt". A server certificate file for nginx must contain the server certificate followed by the intermediate(s).',
      'Build the full chain into a new file (bash truncates the target of > before cat reads it, so never cat into one of the input files): "cat /root/renewal/cert.pem /root/renewal/chain.pem > /root/renewal/fullchain.pem", copy it to /etc/ssl/certs/www.corp.lab.crt, "nginx -t", reload.',
    ],
    explanation: {
      rootCause: 'During the renewal only cert.pem (the server certificate alone) was installed as the nginx certificate file. nginx therefore sends a chain of one certificate and omits Corp Lab Issuing CA 1.',
      manifestation: 'Clients trust only the root. To connect the server certificate to it they need the intermediate, which the server must send: OpenSSL reports error 20 "unable to get local issuer certificate" at depth 0 (and 21 "unable to verify the first certificate"). Browsers often hide the problem because they cache intermediates from earlier visits or download them via the AIA extension, so "works in my browser" is a classic symptom.',
      evidence: 's_client: "Certificate chain" lists only "0 s:CN = www.corp.lab"; "Verify return code: 21 (unable to verify the first certificate)"; grep -c BEGIN on the nginx certificate file returns 1; openssl verify succeeds only with -untrusted chain.pem.',
      prevention: 'Always deploy the full chain (fullchain.pem); after a renewal test with a client that has a clean cache (curl, s_client, SSL Labs); never "fix" it by adding intermediates to clients, which breaks again when the CA changes intermediates.',
    },
    solution: [{
      host: 'srv01',
      commands: [
        'cat /root/renewal/cert.pem /root/renewal/chain.pem > /root/renewal/fullchain.pem',
        'cp /root/renewal/fullchain.pem /etc/ssl/certs/www.corp.lab.crt',
        'nginx -t',
        'systemctl reload nginx',
      ],
    }],
    constraints: [keysProtected(), trustStoreClean('ws01')],
    concepts: ['tls.pki'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'tls-untrusted-root',
    title: 'Certificate error on the new laptop',
    difficulty: 'beginner',
    ticket: `Dana (sales): "IT re-imaged my laptop ws02 yesterday. Now the intranet https://www.corp.lab/ says the certificate is not trusted. My colleagues on other machines have no problem." Note: the Corp Lab Root CA is published at http://www.corp.lab/pki/corp-lab-root-ca.crt; its SHA-256 fingerprint is ${CORP_ROOT_FINGERPRINT}.`,
    briefing: [
      'https://www.corp.lab/ is served by srv01 with a certificate from Corp Lab Issuing CA 1 (signed by Corp Lab Root CA). The server sends its certificate and the intermediate.',
      'Debian manages trust with the ca-certificates package: local CAs go in /usr/local/share/ca-certificates/ as PEM files ending in .crt, then "update-ca-certificates" rebuilds /etc/ssl/certs/ca-certificates.crt (used by curl, OpenSSL, apt, Python...).',
      `Verify a downloaded root before trusting it: its SHA-256 fingerprint must be ${CORP_ROOT_FINGERPRINT}. Clients must keep verifying certificates (no -k).`,
    ],
    goals: [DANA_HTTPS, WWW_HTTPS],
    terminals: [
      { hostId: 'ws02', user: 'dana', label: 'ws02 (dana)', banner: 'ws02, Dana\'s freshly re-imaged laptop (DHCP). sudo password: ws02-dana.' },
      { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01, a working machine for comparison.' },
      { hostId: 'srv01', user: 'root', label: 'srv01 console', banner: 'Console on srv01 (root), the web server.' },
    ],
    setup(world) {
      world.clock += 3600_000;
      const h = world.hosts.ws02;
      delete h.fs[CORP_ROOT_LOCAL];
      writeFile(h, CA_BUNDLE, PUBLIC_ROOTS.map((r) => certPem(r.cert)).join(''), world.clock);
      world.clock += 20 * 3600_000;
    },
    rootCauses: ['tls-untrusted-root'],
    candidates: TLS_CANDIDATES,
    feedback: {
      'tls-chain-incomplete': 'The server sends the intermediate: s_client on ws02 shows a chain of 2 and the error is at depth=1 (the intermediate\'s issuer is unknown), not depth 0. ws01 verifies the same chain fine.',
      'tls-cert-expired': 'The certificate is valid until 2027; the error is number 20, "unable to get local issuer certificate".',
    },
    hints: [
      'Compare ws02 with ws01: same URL, same server. When only some clients fail, look at what is different on the client.',
      'On ws02, "openssl s_client -connect www.corp.lab:443 </dev/null" shows at which depth verification fails. Then check the trust store: "ls /usr/local/share/ca-certificates" and "grep -c BEGIN /etc/ssl/certs/ca-certificates.crt" on both machines.',
      'Download the root over HTTP ("curl -o corp-lab-root-ca.crt http://www.corp.lab/pki/corp-lab-root-ca.crt"), compare "openssl x509 -noout -fingerprint -sha256" with the published value, then "sudo cp corp-lab-root-ca.crt /usr/local/share/ca-certificates/" and "sudo update-ca-certificates". The file name must end in .crt.',
    ],
    explanation: {
      rootCause: 'The re-imaged laptop was installed from a stock image without the company\'s root CA. Its trust store contains only the public roots.',
      manifestation: 'The server sends the correct chain (server certificate + Corp Lab Issuing CA 1), but ws02 has no trusted certificate for the intermediate\'s issuer, Corp Lab Root CA. OpenSSL reports error 20 at depth 1; curl (60) "unable to get local issuer certificate". Every other client works, so the server is not the problem.',
      evidence: 'ws02: s_client "depth=1 C = US, O = Corp Lab, CN = Corp Lab Issuing CA 1 / verify error:num=20"; /usr/local/share/ca-certificates is empty and ca-certificates.crt holds 3 certificates, versus 4 on ws01.',
      prevention: 'Deploy internal roots with configuration management or the base image (and to browsers that use their own store, like Firefox policies); verify fingerprints out of band; document the root for BYOD/new devices.',
    },
    solution: [{
      host: 'ws02',
      user: 'root',
      commands: [
        'curl -o /root/corp-lab-root-ca.crt http://www.corp.lab/pki/corp-lab-root-ca.crt',
        'openssl x509 -in /root/corp-lab-root-ca.crt -noout -subject -fingerprint -sha256',
        'cp /root/corp-lab-root-ca.crt /usr/local/share/ca-certificates/corp-lab-root-ca.crt',
        'update-ca-certificates',
      ],
      note: 'As dana, prefix the cp and update-ca-certificates with sudo.',
    }],
    constraints: [trustStoreClean('ws02')],
    concepts: ['tls.pki'],
  },
];

export const MTU_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'mtu-uplink-mismatch',
    title: 'Small things work, downloads hang',
    difficulty: 'advanced',
    ticket: 'Alice: "Since last night\'s router change, downloads from the Internet hang at 0 bytes and some HTTPS sites never load. ping works, DNS works, I can even get the HTTP headers with curl -I." Change NET-61: "rtr01: prepare uplink for the ISP\'s PPPoE migration". ISP: "Your circuit is still plain Ethernet, MTU 1500. The PPPoE migration is next quarter."',
    briefing: [
      'rtr01 eth2 (203.0.113.2) is the Internet uplink; ext01 (203.0.113.80) stands in for any Internet server. Inside hosts reach it through masquerade.',
      'MTU = largest IP packet a link carries (Ethernet 1500). TCP announces MSS = MTU - 40 in its SYN; ping -M do -s N sends N bytes of data + 28 bytes of headers with "don\'t fragment" set.',
      'Fixes must survive a reboot of every machine. Do not lower the MTU on clients.',
    ],
    goals: [DOWNLOAD, EXT_HTTPS],
    terminals: [
      { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01 in the office. sudo password: ws01-alice.' },
      { hostId: 'rtr01', user: 'root', label: 'rtr01 console', banner: 'Console on rtr01 (root): eth2 is the Internet uplink.' },
      { hostId: 'ext01', user: 'guest', label: 'ext01 (Internet)', banner: 'ext01 = a server on the Internet (203.0.113.80). You can look, but it belongs to someone else.' },
    ],
    setup(world) {
      edit(world, 'rtr01', '/etc/network/interfaces', (s) => s.replace('    gateway 203.0.113.1\n', '    gateway 203.0.113.1\n    # NET-61: PPPoE needs 8 bytes of overhead\n    mtu 1492\n'));
      script(world, 'rtr01', ['ifreload -a']);
      world.clock += 9 * 3600_000;
    },
    rootCauses: ['mtu-mismatch'],
    candidates: ['mtu-mismatch', 'pmtud-blackhole', 'nat-missing-masquerade', 'firewall-drop', 'fw-router-forward', 'dns-client-config', 'web-not-running'],
    feedback: {
      'pmtud-blackhole': 'Path MTU discovery works where it can: ping -M do -s 1472 from ws01 gets "Frag needed and DF set (mtu = 1492)" back from rtr01. The frames that vanish are the ones ext01 sends: they are 1500 bytes and rtr01\'s eth2 only accepts 1492, which no ICMP message can report.',
      'nat-missing-masquerade': 'Masquerade works: the TCP handshake and small responses (curl -I, the start of the TLS handshake) come back. Only full-size packets get lost.',
      'firewall-drop': 'A firewall would drop by address/port, not by size. Here the same connection works for small packets and fails for large ones.',
    },
    hints: [
      'What do the working things have in common? Compare "curl -I" (headers only) with a real download ("curl -m 20 -o /dev/null URL"). Then find the largest packet that passes: "ping -M do -s 1472 203.0.113.80", then smaller sizes.',
      'On rtr01 run "ip link" and compare the MTU of eth2 with ext01\'s ("ip link" on ext01). Both ends of a link must use the same MTU: a frame larger than the receiver\'s MTU is dropped without any error message.',
      'NET-61 set "mtu 1492" on eth2 in /etc/network/interfaces too early. Remove that line and run "ifreload -a" (or "ip link set dev eth2 mtu 1500" plus the file change).',
    ],
    explanation: {
      rootCause: 'rtr01\'s eth2 was set to MTU 1492 in preparation for PPPoE, but the uplink (ext01\'s side and the ISP) still uses 1500. The two ends of the link disagree.',
      manifestation: 'Anything that fits in 1492 bytes works: ping, DNS, TCP handshakes, small HTTP responses. ext01 sends full 1500-byte segments (ws01 announced MSS 1460), and rtr01 silently discards every frame larger than its eth2 MTU, so downloads stall at 0 bytes and the TLS handshake (whose certificate flight fills full segments) never completes. Outgoing large packets are handled correctly by PMTUD (rtr01 answers "fragmentation needed, mtu 1492"), which makes the problem one-directional and confusing.',
      evidence: 'curl -I works, curl -o times out with "0 out of 4718592 bytes received"; tcpdump on rtr01 eth2 shows the request but no data; "ip link" shows mtu 1492 on rtr01 eth2 and 1500 on ext01; tracepath from ws01 reports "pmtu 1492".',
      prevention: 'Change MTU on both ends of a link in the same change window; test with ping -M do at the full size after link changes; on real PPPoE/VPN links clamp the TCP MSS ("tcp flags syn tcp option maxseg size set rt mtu") so endpoints never need path MTU discovery.',
    },
    solution: [{ host: 'rtr01', commands: ["sed -i '/mtu 1492/d' /etc/network/interfaces", 'ifreload -a', 'ip link show eth2'] }],
    constraints: [clientMtuDefault()],
    concepts: ['net.mtu', 'tcp.handshake'],
  },
];
