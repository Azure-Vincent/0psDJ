// Operate & recover guide: TLS certificates on servers (nginx) and trust on
// clients (ca-certificates), with the lab's internal PKI.

import type { ServiceGuide } from '../types';

export const TLS_GUIDE: ServiceGuide = {
  purpose:
    'TLS protects a TCP connection and proves the server\'s identity with an **X.509 certificate**. Operating it means managing three things that expire or drift independently: the **server certificate and its private key** (renewed every year or more often), the **chain** of intermediate CAs the server must send, and the **trust stores** of every client. Almost every TLS incident is one of: expired certificate, certificate for the wrong name, missing intermediate, untrusted root on some clients, or a certificate/key mismatch that keeps an old certificate loaded. In the lab, srv01\'s nginx serves https://www.corp.lab/ with a certificate from Corp Lab Issuing CA 1 (root: Corp Lab Root CA), and clients trust the root through Debian\'s ca-certificates.',
  architecture: [
    { q: 'What does it accomplish?', a: 'Confidentiality and integrity of the data on the wire, and authentication of the server (optionally the client) by name. It does not protect data at rest or prove the server is "good", only that it holds the key for the names in its certificate.' },
    { q: 'How does it work internally?', a: 'After TCP connects, the client sends a ClientHello with SNI (the name it wants); the server answers with ServerHello and a key share (both derive session keys by Diffie-Hellman), then its **Certificate** message (leaf + intermediates), a **CertificateVerify** signature made with its private key, and Finished. The client builds and verifies the chain to a trusted root, checks validity dates and that the requested name is in the subjectAltName, then sends Finished and application data. Failure = TLS alert and close.' },
    { q: 'Which protocols does it use?', a: 'TLS 1.3 (RFC 8446) and 1.2 (RFC 5246) over TCP; X.509 certificates (RFC 5280); name checks (RFC 6125); OCSP/CRL for revocation; ACME (RFC 8555) for automated issuance. STARTTLS upgrades plain protocols (SMTP 587, IMAP 143, LDAP 389) in place.' },
    { q: 'Which ports and transport?', a: 'HTTPS 443/tcp (HTTP/3 uses QUIC on 443/udp), SMTPS 465, IMAPS 993, LDAPS 636, plus STARTTLS on the plain ports. ACME http-01 validation needs port 80.' },
    { q: 'Which processes and OS components implement it?', a: 'Libraries: OpenSSL (nginx, curl, Python, most Linux software), GnuTLS (some Debian tools), NSS (Firefox), Schannel (Windows, IIS, curl.exe), Java JSSE. Servers: nginx, Apache, HAProxy, IIS. Trust: ca-certificates (Debian), ca-certificates/p11-kit (RHEL), the Windows certificate store. Issuance: certbot/acme.sh, step-ca, AD Certificate Services.' },
    { q: 'Which other services does it depend on?', a: 'DNS (the name the client uses must be on the certificate and resolve to the server), **time** (validity checks use the client clock: NTP failures look like expired certificates), a working TCP path (and full-size packets: the certificate flight fills several segments, so MTU problems break handshakes), the CA (renewals), and OCSP/CRL endpoints for clients that enforce revocation.' },
    { q: 'How do requests travel?', a: 'curl https://www.corp.lab/ → DNS (CNAME www → srv01 → 10.0.20.10) → TCP 443 → ClientHello with SNI www.corp.lab → nginx picks the server block whose server_name matches → sends ssl_certificate content → client verifies → encrypted HTTP request → response.' },
    { q: 'How do authentication and authorisation work?', a: 'The server proves possession of the private key matching the certificate; the CA vouches that the key belongs to the names. Clients decide which CAs to trust (trust store). Mutual TLS adds a client certificate (ssl_verify_client in nginx). Private keys are the crown jewels: root:ssl-cert 0640 or 0600, never in tickets or repositories.' },
    { q: 'How does it start at boot?', a: 'nginx.service runs `nginx -t` (ExecStartPre), which loads every certificate and key: a missing file or key mismatch stops nginx from starting at all. At runtime nginx keeps the loaded certificates in memory: new files take effect only on reload, and a failed reload keeps the old ones.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'HTTPS clients get "Connection refused". If it cannot restart because of a certificate/key problem, `systemctl status nginx` and `journalctl -u nginx` show the [emerg] line; the site stays down until the files are fixed.' },
  ],
  ports: [
    { port: '443', proto: 'TCP', purpose: 'HTTPS (nginx on srv01 and ext01)' },
    { port: '80', proto: 'TCP', purpose: 'HTTP: redirects to HTTPS, ACME http-01, the lab\'s /pki/ download' },
    { port: '636 / 993 / 465', proto: 'TCP', purpose: 'LDAPS, IMAPS, SMTPS (TLS from the first byte)' },
  ],
  processes: [
    { name: 'nginx (master + workers)', platform: 'Debian/Ubuntu/RHEL (srv01, ext01)', role: 'Terminates TLS; the master loads certificates at start/reload' },
    { name: 'update-ca-certificates', platform: 'Debian/Ubuntu', role: 'Rebuilds /etc/ssl/certs/ca-certificates.crt from enabled roots and /usr/local/share/ca-certificates/*.crt' },
    { name: 'update-ca-trust', platform: 'RHEL/Fedora', role: 'Same for /etc/pki/ca-trust' },
    { name: 'certbot.timer / acme.sh cron', platform: 'Linux', role: 'Automatic renewal (twice daily check, renew 30 days before expiry), deploy hook reloads the server' },
    { name: 'Schannel / certificate store', platform: 'Windows', role: 'TLS for IIS, RDP, LDAPS, PowerShell; certlm.msc manages machine certificates' },
  ],
  dependencies: {
    title: 'What a verified HTTPS request to www.corp.lab needs',
    rows: [
      { label: 'Client', nodes: [{ id: 'curl', label: 'curl / browser', sub: 'verifies', kind: 'client' }, { id: 'store', label: 'Trust store', sub: 'Corp Lab Root CA', kind: 'data' }, { id: 'clock', label: 'Correct time', sub: 'NTP', kind: 'os' }] },
      { label: 'Network', nodes: [{ id: 'dns', label: 'DNS', sub: 'www → srv01', kind: 'network' }, { id: 'tcp', label: 'TCP 443', sub: 'firewall, MTU', kind: 'network' }] },
      { label: 'Server', nodes: [{ id: 'nginx', label: 'nginx', sub: 'listen 443 ssl', kind: 'service' }, { id: 'chain', label: 'Full chain file', sub: 'leaf + intermediate', kind: 'data' }, { id: 'key', label: 'Private key', sub: 'matches leaf', kind: 'data' }] },
      { label: 'PKI', nodes: [{ id: 'ca', label: 'Corp Lab Issuing CA 1', sub: 'renewals', kind: 'external' }] },
    ],
    edges: [['curl', 'store'], ['curl', 'clock'], ['curl', 'dns'], ['curl', 'tcp'], ['tcp', 'nginx'], ['nginx', 'chain'], ['nginx', 'key'], ['chain', 'ca']],
  },
  sequence: {
    title: 'TLS 1.3 handshake for https://www.corp.lab/ and where it fails',
    lanes: [{ id: 'c', label: 'ws01', sub: 'curl' }, { id: 's', label: 'srv01', sub: 'nginx :443' }],
    steps: [
      { from: 'c', to: 's', label: 'TCP SYN / SYN-ACK / ACK', note: 'Refused or timeout here is not TLS: listener, firewall, routing.' },
      { from: 'c', to: 's', label: 'ClientHello, SNI www.corp.lab', note: 'Plain-HTTP port answers garbage → "wrong version number".' },
      { from: 's', to: 'c', label: 'ServerHello + Certificate (leaf, intermediate) + CertificateVerify + Finished', note: 'Full-size packets: an MTU black hole stalls the handshake here.' },
      { from: 'c', to: 'c', label: 'verify chain → root, dates, name', note: 'Expired, unknown issuer, wrong name: curl sends an alert.', fail: true },
      { from: 'c', to: 's', label: 'Alert (unknown CA / certificate expired)', fail: true },
      { from: 'c', to: 's', label: 'Finished, GET / (encrypted)' },
      { from: 's', to: 'c', label: 'HTTP/1.1 200 OK (encrypted)' },
    ],
  },
  files: [
    { path: '/etc/ssl/certs/<site>.crt', platform: 'Debian (srv01)', kind: 'cert', perms: 'root:root 0644', contains: 'PEM: the server certificate followed by the intermediate CA certificate(s).', accessed: 'By nginx at start/reload only.', problems: 'Leaf only → clients cannot build the chain (error 20 at depth 0). Wrong order (intermediate first) → nginx uses the intermediate as its certificate and key mismatch follows. Replacing the file without reloading changes nothing.' },
    { path: '/etc/ssl/private/<site>.key', platform: 'Debian (srv01)', kind: 'cert', perms: 'root:ssl-cert 0640 (directory 0710)', contains: 'PEM private key (unencrypted for unattended start).', accessed: 'By nginx at start/reload (as root).', problems: 'Not matching the certificate → nginx -t "key values mismatch". World-readable → anyone on the host can impersonate the site. Passphrase-protected → nginx asks at start and hangs/fails at boot.' },
    { path: '/etc/ssl/certs/ca-certificates.crt', platform: 'Debian clients', kind: 'cert', contains: 'Bundle of every trusted root (generated).', accessed: 'By OpenSSL-based clients on every connection.', problems: 'Edited by hand → overwritten by the next update-ca-certificates. Missing your internal root → "unable to get local issuer certificate" on that client only.' },
    { path: '/usr/local/share/ca-certificates/', platform: 'Debian clients', kind: 'config-dir', contains: 'Local roots as PEM files ending in .crt.', accessed: 'By update-ca-certificates.', problems: 'Files ending in .pem or containing DER are ignored or rejected ("does not contain a certificate or CRL"). Adding an intermediate or a server certificate here works until it changes: add roots only.' },
    { path: '/etc/nginx/nginx.conf, sites-enabled/*', platform: 'Linux', kind: 'config', contains: '`listen 443 ssl;`, `server_name`, `ssl_certificate`, `ssl_certificate_key`, `ssl_protocols`.', accessed: 'nginx -t, start, reload.', problems: 'ssl_certificate pointing at the wrong certificate → name mismatch; "ssl" missing on listen → plain HTTP on 443.' },
    { path: '/etc/letsencrypt/live/<name>/{fullchain,privkey}.pem', platform: 'certbot', kind: 'cert', contains: 'Symlinks to the current certificate version.', accessed: 'By the web server; renewed by certbot.timer.', problems: 'Using cert.pem instead of fullchain.pem → missing intermediate. Renewals without a deploy hook that reloads the server → the new certificate is never loaded.' },
    { path: 'journalctl -u nginx, /var/log/nginx/error.log', platform: 'Linux', kind: 'log', contains: '[emerg] lines for certificate/key problems at start/reload; handshake errors at info level.', accessed: 'On failures.', problems: 'A failed reload is only visible here (and in systemctl\'s exit code).' },
  ],
  management: [
    {
      platform: 'Debian (srv01, ws01, ws02: the lab)',
      tasks: [
        { task: 'What does the server send?', command: 'openssl s_client -connect www.corp.lab:443 -servername www.corp.lab </dev/null', explain: 'Chain (s:/i: per certificate), verify errors with depth, and "Verify return code". The ground truth, regardless of files on disk.', sim: true },
        { task: 'Dates, names and issuer of the served certificate', command: 'openssl s_client -connect www.corp.lab:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName', explain: 'Pipe the served leaf into x509.', sim: true },
        { task: 'Inspect a certificate file', command: 'openssl x509 -in /etc/ssl/certs/www.corp.lab.crt -noout -text\ngrep -c BEGIN /etc/ssl/certs/www.corp.lab.crt', explain: 'Full decode; the count shows whether the file holds the chain.', sim: true },
        { task: 'Does the key match the certificate?', command: 'openssl x509 -in /etc/ssl/certs/www.corp.lab.crt -noout -modulus | openssl md5\nopenssl rsa -in /etc/ssl/private/www.corp.lab.key -noout -modulus | openssl md5', explain: 'Equal hashes = matching pair. Reading the key needs root.', sim: true },
        { task: 'Verify a chain offline', command: 'openssl verify -untrusted /etc/ssl/certs/corp-lab-issuing-ca-1.crt /etc/ssl/certs/www.corp.lab.crt', explain: 'Uses the system trust store; -CAfile replaces it.', sim: true },
        { task: 'Expiry check for monitoring', command: 'openssl x509 -in /etc/ssl/certs/www.corp.lab.crt -noout -checkend 2592000', explain: 'Exit code 1 if it expires within 30 days.', sim: true },
        { task: 'Test and apply nginx changes', command: 'nginx -t\nsystemctl reload nginx\njournalctl -u nginx -n 20', explain: 'Reload keeps connections; check its result.', sim: true },
        { task: 'Client with a verifying request', command: 'curl -v -I https://www.corp.lab/', explain: 'TLS lines, subject/issuer/dates and the exact error.', sim: true },
        { task: 'Test a name/IP without DNS changes', command: 'curl -I --resolve www.corp.lab:443:10.0.20.10 https://www.corp.lab/', explain: 'Connects to the given address but checks the certificate against the name.', sim: true },
        { task: 'Trust an internal root', command: 'cp corp-lab-root-ca.crt /usr/local/share/ca-certificates/\nupdate-ca-certificates', explain: 'Run as root; the file must end in .crt.', sim: true },
      ],
    },
    {
      platform: 'Certbot / ACME (public certificates)',
      tasks: [
        { task: 'Issue and renew', command: 'sudo certbot certonly --webroot -w /var/www/html -d www.example.net\nsudo certbot renew --dry-run\nsystemctl list-timers certbot.timer', explain: 'Renewal runs twice a day; add `--deploy-hook "systemctl reload nginx"`.' },
        { task: 'List certificates and expiry', command: 'sudo certbot certificates', explain: 'Shows names, expiry and paths per lineage.' },
      ],
    },
    {
      platform: 'Windows Server 2019/2022',
      tasks: [
        { task: 'Machine certificates and expiry', command: 'Get-ChildItem Cert:\\LocalMachine\\My | Sort NotAfter | Format-Table Subject, NotAfter, HasPrivateKey, Thumbprint', explain: 'HasPrivateKey False = imported without the key (.cer instead of .pfx).' },
        { task: 'IIS bindings', command: 'Get-WebBinding -Protocol https\nnetsh http show sslcert', explain: 'Which certificate (thumbprint) is bound to which IP:port / host name.' },
        { task: 'Chain check', command: 'certutil -verify -urlfetch .\\www.cer', explain: 'Builds the chain and checks revocation like Schannel.' },
      ],
    },
  ],
  actions: [
    { action: 'systemctl reload nginx', when: 'After installing a renewed certificate/key.', effect: 'Master re-reads config and certificates; new workers use them, existing connections finish.', risk: 'If the new files are broken the reload fails and the OLD certificate stays: check the exit code and nginx -t.' },
    { action: 'systemctl restart nginx', when: 'Only when reload is not enough (binary upgrade, stuck workers).', effect: 'Drops all connections.', risk: 'With broken certificate files nginx does not come back: always nginx -t first.' },
    { action: 'update-ca-certificates', when: 'After adding/removing a local root.', effect: 'Rebuilds the bundle; affects every OpenSSL application on the host immediately.', risk: 'Removing a root breaks every site it issued for.' },
    { action: 'Certificate renewal', when: 'Before notAfter (automate: 30 days before).', effect: 'New certificate, often a new key.', risk: 'Install certificate, chain AND key together; test from outside afterwards.' },
  ],
  workflow: [
    { question: '1. Is it TLS at all?', command: 'curl -v -I https://www.corp.lab/', healthy: '* Connected to www.corp.lab (10.0.20.10) port 443 (#0)\n*  SSL certificate verify ok.', broken: 'No "Connected": TCP problem (refused = no listener, timeout = firewall/routing). Connected, then "(60)" or "(35)": TLS → step 2.', next: 'Step 2 for TLS errors.', sim: true },
    { question: '2. What exactly does the server send?', command: 'openssl s_client -connect www.corp.lab:443 -servername www.corp.lab </dev/null', healthy: ' 0 s:CN = www.corp.lab\n 1 s:C = US, O = Corp Lab, CN = Corp Lab Issuing CA 1\nVerify return code: 0 (ok)', broken: 'Error 10 → expired (step 3). Error 20 at depth 0 with a chain of 1 → missing intermediate (step 4). Error 20 at depth 1 → client lacks the root (step 5). Wrong subject → step 6.', next: 'Follow the error.', sim: true },
    { question: '3. Is the served certificate the one on disk?', command: 'openssl x509 -in /etc/ssl/certs/www.corp.lab.crt -noout -subject -enddate\nnginx -t', healthy: 'Same dates as served; test is successful.', broken: 'File newer than what is served → nginx did not load it: nginx -t shows why (key mismatch, missing file).', next: 'Fix files, nginx -t, reload.', sim: true },
    { question: '4. Does the certificate file contain the chain?', command: 'grep -c BEGIN /etc/ssl/certs/www.corp.lab.crt', healthy: '2', broken: '1 → append the intermediate (cat cert.pem chain.pem > fullchain.pem).', next: 'Install the full chain, reload.', sim: true },
    { question: '5. Does this client trust the root?', command: 'ls /usr/local/share/ca-certificates/\ngrep -c BEGIN /etc/ssl/certs/ca-certificates.crt', healthy: 'corp-lab-root-ca.crt', broken: 'Missing on this client only → install the root (verify its fingerprint first) and update-ca-certificates.', next: 'Retest with curl.', sim: true },
    { question: '6. Does the certificate cover the name?', command: 'openssl s_client -connect www.corp.lab:443 </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName', healthy: 'DNS:www.corp.lab, DNS:srv01.corp.lab', broken: 'Name missing → wrong certificate configured (ssl_certificate) or the certificate was requested without that SAN.', next: 'Point nginx at the right certificate or reissue with all names.', sim: true },
    { question: '7. Is the client clock right?', command: 'date', healthy: 'Current date and time', broken: 'Years off → every certificate is "not yet valid" or "expired" on this client.', next: 'Fix NTP.', sim: true },
  ],
  failures: [
    { symptom: 'Everyone: certificate has expired', causes: ['Renewal not done or not installed', 'Renewed file installed but nginx not reloaded'], diagnose: ['s_client | x509 -dates (served)', 'openssl x509 -enddate -in FILE (on disk)', 'nginx -t'], fix: 'Install the renewed certificate + chain + key, nginx -t, reload; automate renewal and expiry monitoring.', verify: 'curl -I https://NAME/ from a client; s_client Verify return code: 0' },
    { symptom: 'Renewed, but the old certificate is still served', causes: ['New certificate with the old key: reload failed (key values mismatch)'], diagnose: ['nginx -t', 'journalctl -u nginx', 'compare moduli'], fix: 'Install the key that belongs to the new certificate, nginx -t, reload.', verify: 'Served notAfter = new date' },
    { symptom: 'Scripts/curl fail with "unable to get local issuer certificate", browsers fine', causes: ['Server sends the leaf without the intermediate'], diagnose: ['s_client: chain length 1, error 21', 'grep -c BEGIN on the certificate file'], fix: 'Serve the full chain (leaf + intermediate).', verify: 'curl from a clean client succeeds' },
    { symptom: 'One client fails, others fine', causes: ['Root missing from that client\'s trust store (new install, own store like Java/Firefox)', 'Client clock wrong'], diagnose: ['s_client on that client: error depth', 'ls /usr/local/share/ca-certificates', 'date'], fix: 'Install the root (fingerprint checked) and update-ca-certificates; fix NTP.', verify: 'curl -I https://NAME/ on that client' },
    { symptom: 'Name mismatch for one name, others work', causes: ['ssl_certificate points at a certificate without that SAN', 'Certificate requested without all names'], diagnose: ['curl -v (subjectAltName lines)', 'openssl x509 -ext subjectAltName'], fix: 'Use/request a certificate with every published name.', verify: 'curl -I for each name' },
    { symptom: 'nginx does not start after a change', causes: ['Certificate/key file missing or wrong path', 'Key mismatch', 'Passphrase-protected key'], diagnose: ['nginx -t', 'journalctl -u nginx -b'], fix: 'Fix paths/files; use an unencrypted key protected by permissions.', verify: 'systemctl is-active nginx; curl' },
  ],
  verification: [
    { check: 'Verified request', command: 'curl -I https://www.corp.lab/', expect: 'HTTP/1.1 200 OK (no -k)' },
    { check: 'Chain served', command: 'openssl s_client -connect www.corp.lab:443 </dev/null', expect: '2 certificates; Verify return code: 0 (ok)' },
    { check: 'Expiry headroom', command: 'openssl x509 -noout -checkend 2592000 -in /etc/ssl/certs/www.corp.lab.crt', expect: 'Certificate will not expire' },
    { check: 'Config valid for the next restart', command: 'nginx -t', expect: 'test is successful' },
    { check: 'Key protected', command: 'ls -l /etc/ssl/private/', expect: '-rw-r----- root ssl-cert (or 0600)' },
  ],
  refIds: ['openssl', 'curl', 'update-ca-certificates', 'file:nginx-conf', 'file:ssl-certs', 'file:ssl-private', 'file:ca-certificates', 'proc:tls-renewal', 'proc:tls-diagnose', 'journalctl', 'systemctl'],
};
