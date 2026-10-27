import type { Lesson } from '../types';

export const TLS_LESSON: Lesson = {
  id: 'tls',
  moduleId: 'A',
  title: 'TLS and certificates',
  level: 'intermediate',
  summary: 'What TLS protects, the TLS 1.3 handshake, X.509 certificates and chains, trust stores, how clients verify names and dates, deploying a certificate in nginx, and diagnosing the classic failures: expired, wrong name, missing intermediate, untrusted root, key mismatch.',
  concepts: ['tls.pki', 'tcp.handshake'],
  mode: 'simulated',

  what: `
**TLS (Transport Layer Security)** adds encryption and identity checks on top of an ordinary [TCP connection](#/lesson/transport/what). It is the "S" in HTTPS (the padlock in your browser), and it also protects mail (SMTP and IMAP with STARTTLS), directory lookups (LDAPS), database connections, VPNs and APIs. TLS gives you three things:
- **Confidentiality**: nobody on the path can read the data.
- **Integrity**: nobody can change it unnoticed.
- **Server authentication**: the client knows it talks to the real www.corp.lab and not to an impostor. This part is done with **certificates**, and it is where almost every operational problem comes from.

### Certificates, step by step
Encryption alone is not enough: you also need to know **who** you are encrypting for. That is the job of a **certificate**.

- A certificate (format X.509) is a small file that ties a **public key** to one or more **names** (listed in its *subjectAltName*, for example www.corp.lab and srv01.corp.lab), for a limited **period** (from *notBefore* to *notAfter*).
- It is signed by a **certificate authority (CA)**, an organisation (or an internal server) whose job is to vouch that the key really belongs to that name. Think of a passport: it is only trusted because a government you trust issued it.
- Every client keeps a **trust store**: a list of root CA certificates it trusts. Your operating system and browser ship with one.
- Root CAs usually sign through one or more **intermediate CAs**, so a server sends its own certificate plus the intermediates. Together they form a **chain** up to a root.

A server certificate is accepted only when all of these are true: the client can build a chain from it, through the intermediates, to a root in its trust store; every certificate in the chain is within its validity period; and the name the client asked for appears in the server's certificate.

### The four questions a client asks
| Question | Fails as (curl / OpenSSL) |
|---|---|
| Can I build a chain to a root I trust? | (60) unable to get local issuer certificate (error 20), self-signed certificate (18/19) |
| Is every certificate in its validity period? | (60) certificate has expired (10), not yet valid (9) |
| Does the certificate cover the name I asked for? | (60) no alternative certificate subject name matches target host name |
| Does the server own the private key? | Handshake failure: the server cannot sign. In practice the server refuses to start (key mismatch) |

### In the lab
srv01 serves **https://www.corp.lab/** (www is a CNAME for srv01) with nginx. Its certificate comes from the internal PKI: **Corp Lab Root CA** → **Corp Lab Issuing CA 1** → **www.corp.lab** (subjectAltName www.corp.lab and srv01.corp.lab). Every corp.lab machine trusts the root through Debian's ca-certificates. ext01 (203.0.113.80) is an Internet site whose certificate comes from a (fictitious) public CA in the default trust store.

> The simulator implements X.509 certificates, keys and CSRs as PEM files, chain building and verification with OpenSSL's error codes, Debian's trust store (update-ca-certificates), nginx \`listen ... ssl\` with ssl_certificate/ssl_certificate_key (loaded at start/reload; key mismatch and missing files fail \`nginx -t\`), SNI-based server selection, \`curl\` HTTPS with verification, \`-k\`, \`--cacert\`, \`--resolve\` and verbose TLS output, and \`openssl x509 / verify / s_client / req / genrsa / rsa\`. Simplified: the cryptography is synthetic (PEM bodies are readable data, not DER), TLS 1.3 only, no OCSP/CRL revocation, no client certificates, no ECDSA keys, no HTTP/2.
`,

  internals: `
### The TLS 1.3 handshake (RFC 8446)
After the TCP handshake:
1. **ClientHello** (client → server): supported versions and cipher suites, a key share (X25519), and **SNI**: the host name the client wants. SNI is how one IP address serves many certificates.
2. **ServerHello** + key share: both sides now derive the same secret (Diffie-Hellman); everything after this is encrypted.
3. **Certificate**: the server sends its certificate **and the intermediates**. Not the root: the client must already have it.
4. **CertificateVerify**: a signature over the handshake with the server's **private key**, proving it owns the key in the certificate.
5. **Finished** messages from both sides; then application data (the HTTP request).

The client verifies the certificate between steps 3 and 5. If verification fails it sends an **alert** (unknown CA, certificate expired, bad certificate) and closes. Note what this means for troubleshooting: a TCP connection that opens and closes after ~3 packets of TLS is a certificate or protocol problem, never a firewall.

:::practice
Q: A capture shows the TCP handshake, a ClientHello, the server's reply, an alert from the client, then the connection closes. Is a firewall to blame?
A: **No.** The TCP connection worked and TLS started; the client then rejected something (typically the certificate) and sent an alert. Look at the certificate and the client's error message.
Q: Which handshake message proves the server owns the private key that belongs to its certificate?
A: **CertificateVerify**: a signature over the handshake made with the server's private key.
:::

### Anatomy of a certificate
\`\`\`
Subject: CN = www.corp.lab
Issuer: C = US, O = Corp Lab, CN = Corp Lab Issuing CA 1
Validity  Not Before: Jun  2 09:14:00 2026 GMT   Not After : Jul  4 09:14:00 2027 GMT
Subject Public Key Info: rsaEncryption 2048 bit (modulus, exponent)
X509v3 Basic Constraints: critical  CA:FALSE
X509v3 Key Usage / Extended Key Usage: Digital Signature, TLS Web Server Authentication
X509v3 Subject Alternative Name: DNS:www.corp.lab, DNS:srv01.corp.lab
Signature Algorithm: sha256WithRSAEncryption (made with the ISSUER's private key)
\`\`\`
- **subjectAltName (SAN)** is what clients match against. The CN is ignored when a SAN is present (all modern clients). Wildcards match exactly one label: *.corp.lab matches www.corp.lab, not corp.lab or a.b.corp.lab. IP addresses must be listed as IP: entries.
- **Basic Constraints CA:TRUE** marks a CA certificate. A leaf certificate cannot sign others (error 24 "invalid CA certificate").
- Publicly trusted certificates are short-lived: since March 2026 at most 200 days, falling to 100 days in March 2027 and 47 days in March 2029 (CA/Browser Forum ballot SC-081). Renewal must be automated. Internal CAs set their own limits (the lab certificate is valid for 397 days).

:::practice
Q: A certificate has SAN \`DNS:*.shop.example\`. Which of these names does it cover: shop.example, www.shop.example, img.cdn.shop.example?
A: Only **www.shop.example**. A wildcard matches exactly one label: not the bare shop.example, and not two labels (img.cdn).
Q: Users connect to \`https://10.0.20.10/\`. The certificate lists only DNS names. Will the name check pass?
A: **No.** IP addresses must be listed as **IP:** entries in the subjectAltName; a DNS entry does not match an address.
:::

### Chains and trust stores
\`\`\`
Corp Lab Root CA            self-signed, in the client's trust store
   └─ Corp Lab Issuing CA 1  intermediate: sent by the SERVER
        └─ www.corp.lab      leaf: sent by the server
\`\`\`
The client builds the chain from the certificates the server sent (untrusted) up to an anchor in its trust store. Debian keeps the store in **/etc/ssl/certs/ca-certificates.crt** (a bundle used by OpenSSL, curl, wget, Python requests, apt). It is generated by **update-ca-certificates** from \`/usr/share/ca-certificates/\` (selected in \`/etc/ca-certificates.conf\`) plus every **\`.crt\`** file under **/usr/local/share/ca-certificates/**. RHEL uses \`/etc/pki/ca-trust/source/anchors/\` and \`update-ca-trust\`; Windows the certificate store (certlm.msc); Firefox and Java keep their own stores.

**Why roots are not sent and intermediates must be:** a root sent by the server would prove nothing (anyone can make one). Intermediates connect the server certificate to the root; a server that sends only its own certificate produces "unable to get local issuer certificate" at depth 0 on clean clients, while browsers that cached the intermediate keep working. That combination is the classic "works in my browser, fails in curl".

**Reading \`openssl s_client\` output.** Two parts tell you where a chain breaks:
- Under **Certificate chain**, each certificate the server sent is listed with its subject (\`s:\`) and its issuer (\`i:\`). Number 0 is the server's own certificate; each next one should be the issuer of the one before it. Count them: a single entry means the server sent no intermediate.
- The **depth=N** lines show the verification, from the top of the chain down. A \`verify error\` at a depth tells you which certificate's issuer could not be found.

Then decide by looking at the **last \`i:\` line**, the issuer of the last certificate the server sent:
- It names a **root CA** (the top of the PKI, such as Corp Lab Root CA, which signs itself): the server sent everything it should. If verification still fails with "unable to get local issuer certificate" (error 20), **this client does not trust that root**: install the root on the client.
- It names an **intermediate CA** (a CA that was itself issued by another CA): the server stopped too early and the client cannot climb to a root. The **intermediate is missing**: fix the server so it sends the full chain. A clean client will usually report this as error 20 at depth 0 when only the leaf was sent.

Telling the two apart needs one fact about your PKI: which CAs are roots. Your PKI documentation (or \`openssl x509 -noout -subject -issuer\` on the CA certificate: a root has the same subject and issuer) tells you.

Example: a server sends \`0 s:CN = shop.example\` / \`i:CN = Example Issuing CA\` and \`1 s:CN = Example Issuing CA\` / \`i:CN = Example Root\`, and the error is at depth=1: the server did its job; the client lacks Example Root.

:::practice
Q: \`s_client\` shows one certificate: \`0 s:CN = intranet.example\` / \`i:CN = Example Issuing CA 2\`, and error 20 at depth 0. Example Issuing CA 2 is an intermediate. Who must fix what?
A: The **server** sent only its leaf and its issuer is an intermediate, so the intermediate is missing. Configure the server to send the full chain (leaf + Example Issuing CA 2).
Q: You copy \`company-root.crt\` into /usr/local/share/ca-certificates/. Which command adds it to the Debian trust store, and which file is updated?
A: \`update-ca-certificates\`; it regenerates **/etc/ssl/certs/ca-certificates.crt**.
:::

### Keys, CSRs and issuance
1. Generate a key pair on the server: the **private key never leaves it** (mode 0600/0640, /etc/ssl/private/).
2. Create a **CSR** (certificate signing request): public key + requested subject and SANs, signed with the private key.
3. The CA checks you control the names (ACME http-01/dns-01 for public CAs, a ticket for internal ones) and returns the certificate (+ chain).
4. Install certificate **and** chain, and the matching key. The certificate's public key and the private key must belong together: compare moduli (\`openssl x509 -noout -modulus | openssl md5\` vs \`openssl rsa -noout -modulus | openssl md5\`).

:::practice
Q: Where is the private key created, and who else ever sees it during issuance?
A: On the **server** itself, and **nobody** else sees it: the CSR contains only the public key and the requested names.
Q: After a renewal, how do you prove that the new certificate and the key file belong together?
A: Compare the moduli: \`openssl x509 -noout -modulus -in CERT | openssl md5\` and \`openssl rsa -noout -modulus -in KEY | openssl md5\` must print the same hash.
:::

### What servers do with the files
nginx reads ssl_certificate (leaf followed by intermediates) and ssl_certificate_key **at start and reload only** and keeps them in memory. Consequences:
- Replacing the files changes nothing until \`systemctl reload nginx\`.
- If the new files are broken (missing, key mismatch), \`nginx -t\` fails, the reload fails and **the old certificate keeps being served**; a restart or reboot would take the site down.
- Always check what is actually served from outside: \`openssl s_client -connect host:443 -servername host </dev/null\`.

:::practice
Q: You replaced the certificate file an hour ago but clients still see the old certificate. You have not run anything else. Why?
A: nginx reads certificates only at **start and reload**. Until \`nginx -t && systemctl reload nginx\`, it keeps serving the copy in memory.
Q: Why is a reload safer than a restart after changing certificate files?
A: If the new files are broken, the reload fails and the **old certificate keeps being served**. A restart with broken files would stop nginx and take the site down.
:::

### Time
Validity checks use the client's clock. A client whose clock is years off rejects every certificate (not yet valid / expired); NTP problems surface as TLS errors.

:::practice
Q: A freshly installed VM gets "certificate is not yet valid" for every HTTPS site. What do you check first?
A: The **VM's clock** (\`timedatectl\`): it is probably set to a date before the certificates' Not Before. Fix time synchronisation (see the [NTP lesson](#/lesson/ntp/internals)).
Q: Whose clock decides whether a certificate has expired: the server's or the client's?
A: The **client's**: validity is checked by the client that verifies the certificate.
:::

`,

  deployment: [
    {
      id: 'nginx-tls',
      platform: 'Debian/Ubuntu: HTTPS with nginx',
      summary: 'Request a certificate from the internal CA and serve it. Steps marked "simulated" work on srv01 in the sandbox.',
      prerequisites: ['nginx installed and serving HTTP.', 'DNS names for the site (www.corp.lab).', 'Access to a CA (internal CA team, step-ca, or a public ACME CA).'],
      steps: [
        { title: 'Generate a key and a CSR with all names', command: 'sudo openssl req -new -newkey rsa:2048 -nodes -keyout /root/www.corp.lab.key -out /root/www.corp.lab.csr -subj "/CN=www.corp.lab" -addext "subjectAltName=DNS:www.corp.lab,DNS:srv01.corp.lab"\nopenssl req -in /root/www.corp.lab.csr -noout -text', what: 'Creates the private key (mode 0600) and the request.', why: 'Every name users type must be in subjectAltName; the CN alone is ignored by clients. -nodes: no passphrase, so nginx can start unattended.', expected: 'X509v3 Subject Alternative Name: \n    DNS:www.corp.lab, DNS:srv01.corp.lab', simulated: true },
        { title: 'Get the certificate and the chain', command: '# Internal CA: send the CSR, receive cert.pem and chain.pem\n# Public CA (ACME): sudo certbot certonly --webroot -w /var/www/html -d www.example.net', what: 'The CA signs the request.', why: 'You receive the leaf and the intermediate(s). certbot writes fullchain.pem (leaf + intermediates) and privkey.pem under /etc/letsencrypt/live/NAME/.', expected: '' },
        { title: 'Build the full chain', command: 'cat cert.pem chain.pem > /root/fullchain.pem\ngrep -c BEGIN /root/fullchain.pem\nopenssl verify -untrusted chain.pem cert.pem', what: 'Leaf first, then intermediates.', why: 'nginx sends exactly the file content. Do not cat into one of the input files: the shell truncates the target first.', expected: '2\ncert.pem: OK', simulated: true },
        { title: 'Configure nginx', command: 'server {\n    listen 443 ssl;\n    listen [::]:443 ssl;\n    server_name www.corp.lab srv01.corp.lab;\n    ssl_certificate     /etc/ssl/certs/www.corp.lab.crt;   # full chain\n    ssl_certificate_key /etc/ssl/private/www.corp.lab.key;\n    root /var/www/html;\n}', what: 'An HTTPS server block.', why: 'ssl on the listen line enables TLS on the socket; server_name selects the block by SNI/Host.', expected: '', simulated: true },
        { title: 'Test, reload, check from outside', command: 'sudo nginx -t && sudo systemctl reload nginx\ncurl -v -I https://www.corp.lab/\nopenssl s_client -connect www.corp.lab:443 -servername www.corp.lab </dev/null', what: 'Validates the config (including the key match), applies it without dropping connections, then verifies what clients see.', why: 'A failed reload keeps serving the old certificate silently.', expected: 'nginx: configuration file /etc/nginx/nginx.conf test is successful\n*  SSL certificate verify ok.\nVerify return code: 0 (ok)', simulated: true },
        { title: 'Optional: redirect HTTP to HTTPS', command: 'server {\n    listen 80;\n    server_name www.corp.lab;\n    return 301 https://$host$request_uri;\n}', what: 'Sends browsers to HTTPS.', why: 'Keep port 80 open for the redirect and for ACME http-01 challenges.', expected: 'HTTP/1.1 301 Moved Permanently\nLocation: https://www.corp.lab/', simulated: true },
      ],
    },
    {
      id: 'trust-linux',
      platform: 'Linux clients: trust an internal root CA',
      summary: 'Add your organisation\'s root to the system trust store.',
      prerequisites: ['The root certificate in PEM format and its fingerprint from a trusted channel.'],
      steps: [
        { title: 'Get and check the root', command: 'curl -o corp-lab-root-ca.crt http://www.corp.lab/pki/corp-lab-root-ca.crt\nopenssl x509 -in corp-lab-root-ca.crt -noout -subject -fingerprint -sha256', what: 'Downloads the root and prints its fingerprint.', why: 'A root may be fetched over plain HTTP only because you then compare its fingerprint with one published out of band. Trusting the wrong root lets its owner impersonate every site.', expected: 'subject=C = US, O = Corp Lab, CN = Corp Lab Root CA\nsha256 Fingerprint=...', simulated: true },
        { title: 'Debian/Ubuntu', command: 'sudo cp corp-lab-root-ca.crt /usr/local/share/ca-certificates/\nsudo update-ca-certificates', what: 'Adds the root to /etc/ssl/certs/ca-certificates.crt.', why: 'Only files ending in .crt (PEM content) are picked up.', expected: 'Updating certificates in /etc/ssl/certs...\n1 added, 0 removed; done.', simulated: true },
        { title: 'RHEL/Fedora', command: 'sudo cp corp-lab-root-ca.crt /etc/pki/ca-trust/source/anchors/\nsudo update-ca-trust', what: 'Same on Red Hat systems.', why: 'Builds /etc/pki/tls/certs/ca-bundle.crt.', expected: '' },
        { title: 'Applications with their own store', command: '# Firefox: policies.json "Certificates": {"ImportEnterpriseRoots": true}\n# Java: keytool -importcert -cacerts -alias corp-root -file corp-lab-root-ca.crt\n# Python venvs (certifi): export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt', what: 'Some software ignores the system store.', why: 'Explains "curl works but the Java app fails".', expected: '' },
      ],
    },
    {
      id: 'windows-tls',
      platform: 'Windows / IIS',
      summary: 'Certificate store and bindings.',
      prerequisites: ['Windows Server 2019/2022 with IIS, or any Windows client.'],
      steps: [
        { title: 'Trust a root (machine store)', command: 'Import-Certificate -FilePath .\\corp-lab-root-ca.crt -CertStoreLocation Cert:\\LocalMachine\\Root\n# Domain-wide: GPO Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies > Trusted Root Certification Authorities', what: 'Adds the root to Trusted Root Certification Authorities.', why: 'In AD environments an Enterprise CA root is distributed automatically.', expected: '' },
        { title: 'Inspect and bind', command: 'Get-ChildItem Cert:\\LocalMachine\\My | Format-List Subject, DnsNameList, NotAfter, HasPrivateKey\nNew-WebBinding -Name "Default Web Site" -Protocol https -Port 443 -HostHeader www.corp.lab -SslFlags 1', what: 'Lists machine certificates (HasPrivateKey must be True) and adds an SNI binding.', why: 'IIS binds a certificate from the store to IP:port or host name (SNI).', expected: 'HasPrivateKey : True' },
        { title: 'Test', command: 'Test-NetConnection www.corp.lab -Port 443\ncurl.exe -v https://www.corp.lab/', what: 'Port and TLS test (curl.exe uses Schannel and the Windows store).', why: 'Test-NetConnection proves the TCP port is open; curl.exe -v then shows whether Windows (Schannel and the Windows certificate store) trusts the chain, which can differ from Linux clients and from browsers with their own store.', expected: '' },
      ],
    },
  ],

  configIntro: `
TLS configuration is mostly about **which files** a server loads and **which roots** a client trusts. The chain inspector below verifies the lab's certificates the way OpenSSL does: pick a server certificate, the chain the server sends and the client's trust store, and see each step and the resulting error.
`,

  configFiles: [
    {
      platform: 'Linux (Debian/Ubuntu)',
      items: [
        { path: '/etc/ssl/certs/ca-certificates.crt', purpose: 'The system trust bundle used by OpenSSL, curl, wget, apt, Python. Generated: do not edit.' },
        { path: '/usr/local/share/ca-certificates/*.crt', purpose: 'Local roots to trust (PEM, .crt extension), applied by update-ca-certificates.' },
        { path: '/etc/ca-certificates.conf', purpose: 'Which distribution roots (/usr/share/ca-certificates) are enabled ("!" disables one).' },
        { path: '/etc/ssl/certs/<site>.crt', purpose: 'Server certificate followed by the intermediate(s) (full chain).' },
        { path: '/etc/ssl/private/<site>.key', purpose: 'Server private key: root:ssl-cert 0640 or root 0600, directory 0710.' },
        { path: '/etc/nginx/nginx.conf, sites-enabled/*', purpose: 'listen 443 ssl; ssl_certificate; ssl_certificate_key; ssl_protocols.' },
        { path: '/etc/letsencrypt/live/<name>/', purpose: 'certbot: fullchain.pem, privkey.pem (symlinks to the current version), renewal config in /etc/letsencrypt/renewal/.' },
      ],
    },
    {
      platform: 'RHEL / Windows',
      items: [
        { path: '/etc/pki/ca-trust/source/anchors/ (+ update-ca-trust)', purpose: 'Local roots on RHEL; bundle in /etc/pki/tls/certs/ca-bundle.crt.' },
        { path: 'Cert:\\LocalMachine\\Root, Cert:\\LocalMachine\\My', purpose: 'Windows trusted roots and machine (server) certificates with private keys.' },
      ],
    },
  ],

  directives: [
    { name: 'listen 443 ssl', compiledDefault: '—', recommended: 'listen 443 ssl; listen [::]:443 ssl;', explanation: 'Enables TLS on the socket. Without "ssl" nginx speaks plain HTTP on 443 and clients report "wrong version number".', security: 'Listen on 443 only with ssl; serving the same content over plain HTTP on another port undermines HTTPS (redirect port 80 instead).' },
    { name: 'ssl_certificate', compiledDefault: '—', recommended: 'Full chain: leaf, then intermediates', explanation: 'Sent to clients exactly as in the file. Leaf only = "unable to get local issuer certificate" on clean clients.', security: 'Public data; mode 0644 is fine.' },
    { name: 'ssl_certificate_key', compiledDefault: '—', recommended: 'Matching private key, 0600/0640', explanation: 'Must match the leaf\'s public key, otherwise nginx -t: "key values mismatch".', security: 'Anyone who reads it can impersonate the site: keep it unreadable for other users, never copy it into tickets or repositories.' },
    { name: 'ssl_protocols', compiledDefault: 'TLSv1.2 TLSv1.3 (nginx ≥ 1.23.4); TLSv1 TLSv1.1 TLSv1.2 TLSv1.3 in 1.22', recommended: 'TLSv1.2 TLSv1.3', explanation: 'Protocol versions offered.', security: 'Disable TLS 1.0/1.1 (RFC 8996).' },
    { name: 'server_name', compiledDefault: '"" (matches requests without a name)', recommended: 'All names on the certificate', explanation: 'Selects the server block by SNI (TLS) and Host header (HTTP).', security: 'Requests whose SNI/Host matches no server_name go to the default server: make that a block that returns an error or redirect, not an unintended site with a mismatching certificate.' },
    { name: 'curl -k / --insecure', compiledDefault: 'off', recommended: 'Never in scripts', explanation: 'Skips chain and name verification.', security: 'Turns TLS into encryption without authentication: any on-path attacker can impersonate the server.' },
  ],

  troubleshootingIntro: `
### Read the error, then look at what the server actually sends
TLS errors are precise: the error number tells you which of the four checks failed. The method is to reproduce the error with a client that shows details, then compare what the server sends with what you expected.

1. **Reproduce with a client that verifies.** Run \`curl -v -I https://NAME/\`. The last lines name the failure, and the error number tells you which check failed (see the table in "What is it").
2. **See what the server actually sends.** Run \`openssl s_client -connect NAME:443 -servername NAME </dev/null\`. Count the certificates under "Certificate chain", and read the "depth" of the error and the "Verify return code". To inspect the server's own certificate, pipe the output into \`openssl x509 -noout -subject -dates -ext subjectAltName\`.
3. **Compare with the files on the server.** \`openssl x509 -noout -subject -enddate -in /etc/ssl/certs/...\` shows what is on disk. If the served certificate differs, nginx has not loaded the new files yet: check \`nginx -t\` and \`journalctl -u nginx\`, then reload.
4. **Only some clients fail?** Then the server is probably fine. Compare the clients' trust stores and their clocks (a wrong clock makes valid certificates look expired or not yet valid).
5. **No TLS at all** (connection refused, timeout)? That is a TCP problem, not TLS: check the listener (\`ss -tlnp\`), the firewall and routing. A handshake that stalls right after the ClientHello, on one network path only, can be an [MTU](#/lesson/mtu/what) problem, because the server's certificate message fills full-size packets.

How to read the depth of an OpenSSL error (depth 0 is the server's own certificate, higher numbers go up the chain):

| depth of the error | usually means |
|---|---|
| 0, error 20 + 21 | the server does not send the intermediate certificate |
| 1 (or the top of the chain), error 20 | the client does not trust the root |
| 0, error 10 | the server certificate has expired; at another depth, that CA's certificate expired |
| 0, error 18 | the server uses a self-signed certificate |

`,

  errorMap: [
    { message: 'curl: (60) SSL certificate problem: certificate has expired', layer: 'Certificate validity', meaning: 'A certificate in the chain is past notAfter (or the client clock is wrong).', firstCheck: 's_client | openssl x509 -noout -dates; date on the client' },
    { message: 'curl: (60) SSL certificate problem: unable to get local issuer certificate', layer: 'Chain / trust store', meaning: 'Cannot reach a trusted root: intermediate not sent (depth 0) or root not trusted (depth 1+).', firstCheck: 's_client: chain length and error depth' },
    { message: "curl: (60) SSL: no alternative certificate subject name matches target host name 'www.corp.lab'", layer: 'Name check', meaning: 'The certificate\'s SANs do not include the requested name.', firstCheck: 'openssl x509 -noout -ext subjectAltName on the served certificate; server_name/ssl_certificate in nginx' },
    { message: 'curl: (60) SSL certificate problem: self-signed certificate', layer: 'Trust', meaning: 'The server sent a self-signed leaf (default/snakeoil certificate, test setup).', firstCheck: 'Which server block / certificate answered (SNI)?' },
    { message: 'nginx: [emerg] SSL_CTX_use_PrivateKey(...) failed (... key values mismatch)', layer: 'Server configuration', meaning: 'ssl_certificate_key is not the key of the certificate. Reload fails, old certificate stays loaded.', firstCheck: 'Compare moduli of cert and key' },
    { message: 'nginx: [emerg] cannot load certificate "...": BIO_new_file() failed (... No such file or directory ...)', layer: 'Server configuration', meaning: 'Path in ssl_certificate does not exist.', firstCheck: 'ls -l the path; nginx -t' },
    { message: 'curl: (35) OpenSSL/3.0.11: error:0A00010B:SSL routines::wrong version number', layer: 'Protocol', meaning: 'TLS spoken to a plain-HTTP port (or "ssl" missing on the listen line).', firstCheck: 'Port and listen directive; curl http:// on that port' },
    { message: '400 The plain HTTP request was sent to HTTPS port', layer: 'Protocol', meaning: 'Plain HTTP spoken to a TLS port.', firstCheck: 'Use https:// for that port' },
  ],

  scenarioIds: ['tls-expired', 'tls-wrong-cert', 'tls-missing-intermediate', 'tls-untrusted-root', 'tls-key-mismatch', 'score-web-cert-renamed'],
  assessmentId: 'tls',
  references: [
    { title: 'RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3', url: 'https://www.rfc-editor.org/rfc/rfc8446' },
    { title: 'RFC 5280: Internet X.509 Public Key Infrastructure Certificate and CRL Profile', url: 'https://www.rfc-editor.org/rfc/rfc5280' },
    { title: 'RFC 6125: Representation and Verification of Domain-Based Application Service Identity', url: 'https://www.rfc-editor.org/rfc/rfc6125' },
    { title: 'RFC 8555: Automatic Certificate Management Environment (ACME)', url: 'https://www.rfc-editor.org/rfc/rfc8555' },
    { title: 'nginx: Configuring HTTPS servers', url: 'https://nginx.org/en/docs/http/configuring_https_servers.html' },
    { title: 'update-ca-certificates(8)', url: 'https://manpages.debian.org/bookworm/ca-certificates/update-ca-certificates.8.en.html' },
    { title: 'openssl-s_client(1ssl), openssl-x509(1ssl), openssl-verify(1ssl)', url: 'https://www.openssl.org/docs/man3.0/man1/' },
    { title: 'Mozilla SSL Configuration Generator', url: 'https://ssl-config.mozilla.org/' },
  ],
};
