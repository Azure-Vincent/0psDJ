// Certificates and trust stores of the lab. Every Debian host gets the
// ca-certificates layout with the (fictitious) public roots; corp.lab machines
// also trust the internal Corp Lab Root CA, which signs Corp Lab Issuing CA 1,
// which signs srv01's web certificate.

import { mkdir, writeFile } from '../fs';
import {
  CA_BUNDLE, caCertificatesConf, type Cert, certPem, CORP_ISSUING, CORP_ROOT, issueServerCert, keyPem, PUBLIC_ISSUING, PUBLIC_ROOTS,
} from '../sim/pki';
import { NGINX_WELCOME } from '../sim/http';
import type { Host } from '../types';

export const CORP_ROOT_LOCAL = '/usr/local/share/ca-certificates/corp-lab-root-ca.crt';

/** srv01's current web certificate (valid June 2026 - July 2027) and two variants used by tickets. */
export const WWW_CERT = issueServerCert(CORP_ISSUING, ['www.corp.lab', 'srv01.corp.lab'], 'www-2026', '2026-06-02T09:14:00Z', 397);
export const WWW_CERT_2025 = issueServerCert(CORP_ISSUING, ['www.corp.lab', 'srv01.corp.lab'], 'www-2025', '2025-10-14T08:02:00Z', 368);
export const SRV01_ONLY_CERT = issueServerCert(CORP_ISSUING, ['srv01.corp.lab'], 'srv01-mgmt', '2026-09-28T13:40:00Z', 397);
export const EXT_CERT = issueServerCert(PUBLIC_ISSUING, ['www.example.net', 'ext01.example.net', '203.0.113.80'], 'ext01-web', '2026-08-20T00:00:00Z', 90);

export const fullchain = (leaf: Cert, ...rest: Cert[]) => [leaf, ...rest].map(certPem).join('');

/** Debian's /etc/ssl and ca-certificates layout, with `extra` local CAs trusted. */
export function installTrustStore(host: Host, t: number, extra: Cert[] = []): void {
  for (const d of ['/etc/ssl', '/etc/ssl/certs', '/usr/share', '/usr/share/ca-certificates', '/usr/share/ca-certificates/mozilla', '/usr/local', '/usr/local/share', '/usr/local/share/ca-certificates']) {
    if (!host.fs[d]) mkdir(host, d, t);
  }
  mkdir(host, '/etc/ssl/private', t, { mode: 0o710, group: 'ssl-cert' });
  for (const r of PUBLIC_ROOTS) writeFile(host, `/usr/share/ca-certificates/${r.file}`, certPem(r.cert), t);
  writeFile(host, '/etc/ca-certificates.conf', caCertificatesConf(), t);
  writeFile(host, CA_BUNDLE, [...PUBLIC_ROOTS.map((r) => r.cert), ...extra].map(certPem).join(''), t);
}

/** Trust the internal root the way an administrator does: copy it to /usr/local/share/ca-certificates and rebuild the bundle. */
export function trustCorpRoot(host: Host, t: number): void {
  writeFile(host, CORP_ROOT_LOCAL, certPem(CORP_ROOT.cert), t);
  writeFile(host, CA_BUNDLE, [...PUBLIC_ROOTS.map((r) => r.cert), CORP_ROOT.cert].map(certPem).join(''), t);
}

/** Debian's nginx package: web root with the default page. */
export function installWebRoot(host: Host, t: number): void {
  mkdir(host, '/var/www', t);
  mkdir(host, '/var/www/html', t);
  writeFile(host, '/var/www/html/index.nginx-debian.html', NGINX_WELCOME, t);
}

export const SRV01_NGINX_CONF = `user www-data;
worker_processes auto;
http {
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        root /var/www/html;
    }
    # Intranet site over HTTPS (certificate from Corp Lab Issuing CA 1, CHG-1187)
    server {
        listen 443 ssl default_server;
        listen [::]:443 ssl default_server;
        server_name www.corp.lab srv01.corp.lab;
        ssl_certificate /etc/ssl/certs/www.corp.lab.crt;
        ssl_certificate_key /etc/ssl/private/www.corp.lab.key;
        root /var/www/html;
    }
}
`;

export const EXT01_NGINX_CONF = `user www-data;
worker_processes auto;
http {
    server {
        listen 80 default_server;
        root /var/www/html;
    }
    server {
        listen 443 ssl default_server;
        server_name www.example.net ext01.example.net;
        ssl_certificate /etc/ssl/certs/www.example.net.crt;
        ssl_certificate_key /etc/ssl/private/www.example.net.key;
        root /var/www/html;
    }
}
`;

/** srv01: web certificate + key, the intermediate, and the root published for download. */
export function installSrv01Pki(host: Host, t: number): void {
  writeFile(host, '/etc/ssl/certs/www.corp.lab.crt', fullchain(WWW_CERT.cert, CORP_ISSUING.cert), t);
  writeFile(host, '/etc/ssl/private/www.corp.lab.key', keyPem(WWW_CERT.key), t, { mode: 0o640, group: 'ssl-cert' });
  writeFile(host, '/etc/ssl/certs/corp-lab-issuing-ca-1.crt', certPem(CORP_ISSUING.cert), t);
  mkdir(host, '/var/www/html/pki', t);
  writeFile(host, '/var/www/html/pki/corp-lab-root-ca.crt', certPem(CORP_ROOT.cert), t);
  writeFile(host, '/var/www/html/pki/corp-lab-issuing-ca-1.crt', certPem(CORP_ISSUING.cert), t);
}

/** ext01: public website with a certificate from a public CA, and a large download. */
export function installExt01Web(host: Host, t: number): void {
  writeFile(host, '/etc/ssl/certs/www.example.net.crt', fullchain(EXT_CERT.cert, PUBLIC_ISSUING.cert), t);
  writeFile(host, '/etc/ssl/private/www.example.net.key', keyPem(EXT_CERT.key), t, { mode: 0o640, group: 'ssl-cert' });
  mkdir(host, '/var/www/html/downloads', t);
  writeFile(host, '/var/www/html/downloads/tools-2.4.1.tar.gz', '\x1f\x8b\x08\x00 (gzip data)', t);
  host.fs['/var/www/html/downloads/tools-2.4.1.tar.gz'].size = 4_718_592;
  writeFile(host, '/var/www/html/downloads/README.txt', 'tools 2.4.1 - SHA256SUMS available on request\n', t);
}
